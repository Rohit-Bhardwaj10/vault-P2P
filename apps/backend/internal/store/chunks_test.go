package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEngine_WriteReadVerifyChunk(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "vault.db")
	walPath := filepath.Join(tmpDir, "wal.db")
	chunkDir := filepath.Join(tmpDir, "chunks")

	engine := NewEngineWithChunkDir(dbPath, walPath, chunkDir)
	if err := engine.Init(); err != nil {
		t.Fatalf("Init() failed: %v", err)
	}
	t.Cleanup(func() {
		_ = engine.Close()
	})

	payload := []byte("hello chunk store")
	stored, err := engine.WriteChunk("source.txt", payload)
	if err != nil {
		t.Fatalf("WriteChunk() failed: %v", err)
	}
	if stored.Hash == "" {
		t.Fatal("WriteChunk() returned empty hash")
	}

	got, err := engine.ReadChunk(stored.Hash)
	if err != nil {
		t.Fatalf("ReadChunk() failed: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("ReadChunk() mismatch: got %q want %q", string(got), string(payload))
	}

	ok, err := engine.VerifyChunk(stored.Hash)
	if err != nil {
		t.Fatalf("VerifyChunk() failed: %v", err)
	}
	if !ok {
		t.Fatal("VerifyChunk() returned false for valid chunk")
	}
}

func TestEngine_VerifyChunkDetectsTamper(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "vault.db")
	walPath := filepath.Join(tmpDir, "wal.db")
	chunkDir := filepath.Join(tmpDir, "chunks")

	engine := NewEngineWithChunkDir(dbPath, walPath, chunkDir)
	if err := engine.Init(); err != nil {
		t.Fatalf("Init() failed: %v", err)
	}
	t.Cleanup(func() {
		_ = engine.Close()
	})

	stored, err := engine.WriteChunk("source.txt", []byte("original payload"))
	if err != nil {
		t.Fatalf("WriteChunk() failed: %v", err)
	}

	if err := os.WriteFile(stored.Path, []byte("tampered payload"), 0o644); err != nil {
		t.Fatalf("failed to tamper chunk file: %v", err)
	}

	ok, err := engine.VerifyChunk(stored.Hash)
	if err != nil {
		t.Fatalf("VerifyChunk() failed: %v", err)
	}
	if ok {
		t.Fatal("VerifyChunk() did not detect tampering")
	}
}
