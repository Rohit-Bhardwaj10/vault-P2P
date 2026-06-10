package rendezvous_test

import (
	"context"
	"net"
	"testing"
	"time"

	"vault-backend/internal/rendezvous"
)

// startServer spins up a rendezvous server on a free port and returns the
// base URL and a cancel func to shut it down.
func startServer(t *testing.T) (string, context.CancelFunc) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	srv := rendezvous.NewServer(addr, 0)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if err := srv.Run(ctx); err != nil && ctx.Err() == nil {
			t.Errorf("rendezvous server error: %v", err)
		}
	}()
	// Give the server a moment to bind.
	time.Sleep(30 * time.Millisecond)
	return "http://" + addr, cancel
}

func TestRendezvous_RegisterAndLookup(t *testing.T) {
	base, cancel := startServer(t)
	defer cancel()

	c := rendezvous.NewClient(base)

	if err := c.Register("peer-alice", "1.2.3.4:9000"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	addr, err := c.Lookup("peer-alice")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if addr != "1.2.3.4:9000" {
		t.Errorf("expected 1.2.3.4:9000, got %q", addr)
	}
}

func TestRendezvous_LookupMissing(t *testing.T) {
	base, cancel := startServer(t)
	defer cancel()

	c := rendezvous.NewClient(base)
	addr, err := c.Lookup("nobody")
	if err != nil {
		t.Fatalf("Lookup on missing peer should not error: %v", err)
	}
	if addr != "" {
		t.Errorf("expected empty addr for missing peer, got %q", addr)
	}
}

func TestRendezvous_OverwriteRegistration(t *testing.T) {
	base, cancel := startServer(t)
	defer cancel()

	c := rendezvous.NewClient(base)
	_ = c.Register("peer-bob", "10.0.0.1:4000")
	_ = c.Register("peer-bob", "10.0.0.2:5000") // overwrite

	addr, err := c.Lookup("peer-bob")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if addr != "10.0.0.2:5000" {
		t.Errorf("expected updated addr, got %q", addr)
	}
}

func TestRendezvous_Ping(t *testing.T) {
	base, cancel := startServer(t)
	defer cancel()

	c := rendezvous.NewClient(base)
	if err := c.Ping(); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestRendezvous_Eviction(t *testing.T) {
	// Use a very short TTL.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	srv := rendezvous.NewServer(addr, 80*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Run(ctx)
	time.Sleep(30 * time.Millisecond)

	c := rendezvous.NewClient("http://" + addr)
	if err := c.Register("peer-ev", "5.5.5.5:1234"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Should still be there immediately.
	a, _ := c.Lookup("peer-ev")
	if a == "" {
		t.Fatal("expected peer-ev to be registered")
	}

	// Wait past TTL + eviction interval.
	time.Sleep(250 * time.Millisecond)

	a, _ = c.Lookup("peer-ev")
	if a != "" {
		t.Errorf("expected peer-ev to be evicted, still got %q", a)
	}
}

func TestRendezvous_MultiplePeers(t *testing.T) {
	base, cancel := startServer(t)
	defer cancel()

	c := rendezvous.NewClient(base)
	_ = c.Register("alice", "1.1.1.1:1111")
	_ = c.Register("bob", "2.2.2.2:2222")
	_ = c.Register("carol", "3.3.3.3:3333")

	for _, tc := range []struct{ id, want string }{
		{"alice", "1.1.1.1:1111"},
		{"bob", "2.2.2.2:2222"},
		{"carol", "3.3.3.3:3333"},
	} {
		addr, err := c.Lookup(tc.id)
		if err != nil {
			t.Fatalf("Lookup(%s): %v", tc.id, err)
		}
		if addr != tc.want {
			t.Errorf("%s: got %q, want %q", tc.id, addr, tc.want)
		}
	}
}
