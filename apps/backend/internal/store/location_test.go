package store

import (
	"path/filepath"
	"testing"
)

func newTestSQLite(t *testing.T) *SQLiteStore {
	t.Helper()
	dir := t.TempDir()
	s := NewSQLiteStore(filepath.Join(dir, "test.db"))
	if err := s.Init(); err != nil {
		t.Fatalf("SQLiteStore.Init: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestUpsertAndGetPeer(t *testing.T) {
	s := newTestSQLite(t)

	err := s.UpsertPeer("peer-1", "pubkey-abc", "192.168.1.1:9000", 12)
	if err != nil {
		t.Fatalf("UpsertPeer: %v", err)
	}

	pubkey, addrs, latency, err := s.GetPeer("peer-1")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if pubkey != "pubkey-abc" {
		t.Errorf("pubkey: got %q", pubkey)
	}
	if addrs != "192.168.1.1:9000" {
		t.Errorf("addresses: got %q", addrs)
	}
	if latency != 12 {
		t.Errorf("latency: got %d", latency)
	}
}

func TestUpsertPeerUpdate(t *testing.T) {
	s := newTestSQLite(t)

	_ = s.UpsertPeer("peer-upd", "old-key", "1.2.3.4:9", 5)
	_ = s.UpsertPeer("peer-upd", "new-key", "5.6.7.8:9", 20)

	pubkey, addrs, latency, err := s.GetPeer("peer-upd")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if pubkey != "new-key" {
		t.Errorf("expected updated pubkey, got %q", pubkey)
	}
	if addrs != "5.6.7.8:9" {
		t.Errorf("expected updated addresses, got %q", addrs)
	}
	if latency != 20 {
		t.Errorf("expected updated latency, got %d", latency)
	}
}

func TestRecordAndGetChunkLocation(t *testing.T) {
	s := newTestSQLite(t)

	_ = s.RecordChunkLocation("hash-aaa", "peer-1")
	_ = s.RecordChunkLocation("hash-aaa", "peer-2")
	_ = s.RecordChunkLocation("hash-bbb", "peer-1")

	peers, err := s.GetChunkPeers("hash-aaa")
	if err != nil {
		t.Fatalf("GetChunkPeers: %v", err)
	}
	if len(peers) != 2 {
		t.Errorf("expected 2 peers for hash-aaa, got %d", len(peers))
	}
}

func TestGetPeerChunks(t *testing.T) {
	s := newTestSQLite(t)

	_ = s.RecordChunkLocation("hash-x", "peer-A")
	_ = s.RecordChunkLocation("hash-y", "peer-A")
	_ = s.RecordChunkLocation("hash-z", "peer-B")

	chunks, err := s.GetPeerChunks("peer-A")
	if err != nil {
		t.Fatalf("GetPeerChunks: %v", err)
	}
	if len(chunks) != 2 {
		t.Errorf("expected 2 chunks for peer-A, got %d", len(chunks))
	}
}

func TestRemoveChunkLocation(t *testing.T) {
	s := newTestSQLite(t)

	_ = s.RecordChunkLocation("hash-rem", "peer-R")
	_ = s.RemoveChunkLocation("hash-rem", "peer-R")

	peers, err := s.GetChunkPeers("hash-rem")
	if err != nil {
		t.Fatalf("GetChunkPeers: %v", err)
	}
	if len(peers) != 0 {
		t.Errorf("expected 0 peers after removal, got %d", len(peers))
	}
}

func TestChunkLocationIdempotent(t *testing.T) {
	s := newTestSQLite(t)

	// Recording the same (chunk, peer) twice should not create duplicates.
	_ = s.RecordChunkLocation("hash-idem", "peer-I")
	_ = s.RecordChunkLocation("hash-idem", "peer-I")

	peers, err := s.GetChunkPeers("hash-idem")
	if err != nil {
		t.Fatalf("GetChunkPeers: %v", err)
	}
	if len(peers) != 1 {
		t.Errorf("expected 1 unique peer, got %d", len(peers))
	}
}
