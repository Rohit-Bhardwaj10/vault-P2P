package node

import (
	"path/filepath"
	"testing"

	"vault-backend/internal/api"
)

func TestNodeStatusSnapshot(t *testing.T) {
	dir := t.TempDir()
	n := New(Config{
		DBPath:       filepath.Join(dir, "v.db"),
		WALPath:      filepath.Join(dir, "w.db"),
		ChunkPath:    filepath.Join(dir, "chunks"),
		IdentityPath: filepath.Join(dir, "id.key"),
		OutputDir:    filepath.Join(dir, "inbox"),
		PeerID:       "test-peer",
	})
	if err := n.Init(); err != nil {
		t.Fatal(err)
	}
	defer n.Engine().Close()

	st := n.StatusSnapshot()
	if st.PeerID != "test-peer" {
		t.Fatalf("peer %q", st.PeerID)
	}
	if st.IdentityPubKey == "" {
		t.Fatal("missing pubkey")
	}
}

func TestNodeInitCreatesIdentity(t *testing.T) {
	dir := t.TempDir()
	n := New(Config{
		DBPath:       filepath.Join(dir, "v.db"),
		WALPath:      filepath.Join(dir, "w.db"),
		ChunkPath:    filepath.Join(dir, "chunks"),
		IdentityPath: filepath.Join(dir, "id.key"),
		OutputDir:    filepath.Join(dir, "inbox"),
	})
	if err := n.Init(); err != nil {
		t.Fatal(err)
	}
	defer n.Engine().Close()
	if n.Identity() == nil {
		t.Fatal("expected identity")
	}
}

var _ api.StatusProvider = (*Node)(nil)
