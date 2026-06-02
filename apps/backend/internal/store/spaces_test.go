package store

import (
	"path/filepath"
	"testing"

	"encoding/hex"

	"vault-backend/internal/crypto"
)

func TestSaveAndGetSpace(t *testing.T) {
	dir := t.TempDir()
	engine := NewEngineWithChunkDir(
		filepath.Join(dir, "v.db"),
		filepath.Join(dir, "w.db"),
		filepath.Join(dir, "chunks"),
	)
	if err := engine.Init(); err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	id, _ := crypto.GenerateIdentity()
	space, err := crypto.NewSpace("my-files")
	if err != nil {
		t.Fatal(err)
	}

	if err := engine.SaveSpace(space, hex.EncodeToString(id.PublicKey)); err != nil {
		t.Fatal(err)
	}

	loaded, owner, err := engine.GetSpace(space.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Name != space.Name {
		t.Fatalf("name %q", loaded.Name)
	}
	if string(loaded.SymmetricKey) != string(space.SymmetricKey) {
		t.Fatal("symmetric key mismatch")
	}
	if owner != hex.EncodeToString(id.PublicKey) {
		t.Fatalf("owner %q", owner)
	}
}
