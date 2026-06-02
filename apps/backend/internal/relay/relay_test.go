package relay

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// startTestServer starts a relay server on a random free port and returns
// the server, its address, and a cancel func to shut it down.
func startTestServer(t *testing.T) (*Server, string, context.CancelFunc) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // release so the relay server can bind to it

	srv := NewServer(addr, filepath.Join(t.TempDir(), "relay.db"), 0) // maxAge=0 means no eviction
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		if err := srv.Run(ctx); err != nil && ctx.Err() == nil {
			t.Errorf("relay server error: %v", err)
		}
	}()

	// Give the server time to start listening.
	time.Sleep(20 * time.Millisecond)
	return srv, addr, cancel
}

func TestRelayPushAndPullInProcess(t *testing.T) {
	srv := NewServer(":0", filepath.Join(t.TempDir(), "relay.db"), 0)
	if err := srv.Init(); err != nil { t.Fatal(err) }
	defer srv.Close()

	data := []byte("encrypted-chunk-data")
	if err := srv.Push("peer-bob", "hash-abc", data); err != nil {
		t.Fatalf("Push: %v", err)
	}

	chunks := srv.Pull("peer-bob")
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(chunks))
	}
	if chunks[0].ChunkHash != "hash-abc" {
		t.Errorf("ChunkHash: got %q", chunks[0].ChunkHash)
	}
	if string(chunks[0].Data) != string(data) {
		t.Errorf("Data mismatch")
	}
}

func TestRelayPullDrains(t *testing.T) {
	srv := NewServer(":0", filepath.Join(t.TempDir(), "relay.db"), 0)
	if err := srv.Init(); err != nil { t.Fatal(err) }
	defer srv.Close()

	_ = srv.Push("peer-x", "h1", []byte("d1"))
	_ = srv.Push("peer-x", "h2", []byte("d2"))

	chunks := srv.Pull("peer-x")
	if len(chunks) != 2 {
		t.Fatalf("expected 2, got %d", len(chunks))
	}
	// Second pull should return nothing.
	chunks = srv.Pull("peer-x")
	if len(chunks) != 0 {
		t.Errorf("expected empty after drain, got %d", len(chunks))
	}
}

func TestRelayInboxSize(t *testing.T) {
	srv := NewServer(":0", filepath.Join(t.TempDir(), "relay.db"), 0)
	if err := srv.Init(); err != nil { t.Fatal(err) }
	defer srv.Close()
	_ = srv.Push("peer-s", "h1", []byte("x"))
	_ = srv.Push("peer-s", "h2", []byte("y"))

	if srv.InboxSize("peer-s") != 2 {
		t.Errorf("expected inbox size 2, got %d", srv.InboxSize("peer-s"))
	}
}

func TestRelayPing(t *testing.T) {
	_, addr, cancel := startTestServer(t)
	defer cancel()

	client := NewClient(addr)
	if err := client.Ping(); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestRelayPushPullOverNetwork(t *testing.T) {
	_, addr, cancel := startTestServer(t)
	defer cancel()

	sender := NewClient(addr)
	receiver := NewClient(addr)

	payload := []byte("secret-encrypted-bytes")
	if err := sender.PushChunk("peer-recv", "hash-xyz", payload); err != nil {
		t.Fatalf("PushChunk: %v", err)
	}

	chunks, err := receiver.PullChunks("peer-recv")
	if err != nil {
		t.Fatalf("PullChunks: %v", err)
	}
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk over network, got %d", len(chunks))
	}
	if string(chunks[0].Data) != string(payload) {
		t.Errorf("payload mismatch: got %q", chunks[0].Data)
	}
}

func TestRelayPullEmptyInbox(t *testing.T) {
	_, addr, cancel := startTestServer(t)
	defer cancel()

	client := NewClient(addr)
	chunks, err := client.PullChunks("nobody")
	if err != nil {
		t.Fatalf("PullChunks on empty inbox: %v", err)
	}
	if len(chunks) != 0 {
		t.Errorf("expected 0 chunks, got %d", len(chunks))
	}
}

func TestRelayMultiplePeers(t *testing.T) {
	_, addr, cancel := startTestServer(t)
	defer cancel()

	c := NewClient(addr)
	_ = c.PushChunk("alice", "ha1", []byte("for alice"))
	_ = c.PushChunk("bob", "hb1", []byte("for bob"))
	_ = c.PushChunk("alice", "ha2", []byte("also for alice"))

	alice, _ := c.PullChunks("alice")
	bob, _ := c.PullChunks("bob")

	if len(alice) != 2 {
		t.Errorf("alice: expected 2, got %d", len(alice))
	}
	if len(bob) != 1 {
		t.Errorf("bob: expected 1, got %d", len(bob))
	}
}

func TestRelayChunkTooLarge(t *testing.T) {
	srv := NewServer(":0", filepath.Join(t.TempDir(), "relay.db"), 0)
	if err := srv.Init(); err != nil { t.Fatal(err) }
	defer srv.Close()
	huge := make([]byte, MaxChunkSize+1)
	err := srv.Push("peer-big", "hash-big", huge)
	if err == nil {
		t.Error("expected error for oversized chunk")
	}
}

func TestRelayEviction(t *testing.T) {
	srv := NewServer(":0", filepath.Join(t.TempDir(), "relay.db"), 50*time.Millisecond) // very short maxAge
	if err := srv.Init(); err != nil { t.Fatal(err) }
	defer srv.Close()
	_ = srv.Push("peer-ev", "old-hash", []byte("old data"))

	if srv.InboxSize("peer-ev") != 1 {
		t.Fatalf("expected 1 before eviction")
	}

	// Wait for eviction to run.
	time.Sleep(120 * time.Millisecond)
	srv.evict()

	if srv.InboxSize("peer-ev") != 0 {
		t.Errorf("expected 0 after eviction, got %d", srv.InboxSize("peer-ev"))
	}
}

// Ensure test port helper doesn't fail silently.
var _ = fmt.Sprintf
