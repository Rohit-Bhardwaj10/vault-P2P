package network

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vault-backend/internal/crypto"
	"vault-backend/internal/store"
)

func TestTransportSecureRoundtrip(t *testing.T) {
	issuer, _ := crypto.GenerateIdentity()
	grantee, _ := crypto.GenerateIdentity()
	space, _ := crypto.NewSpace("secure-transfer")
	token, err := crypto.IssueToken(issuer, grantee.PublicKey, space.ID, crypto.PermWrite, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "vault.db")
	walPath := filepath.Join(tempDir, "wal.db")
	chunkPath := filepath.Join(tempDir, "chunks")
	outDir := filepath.Join(tempDir, "out")

	testFile := filepath.Join(tempDir, "secret.txt")
	want := []byte("encrypted payload test")
	if err := os.WriteFile(testFile, want, 0o644); err != nil {
		t.Fatal(err)
	}

	engine := store.NewEngineWithChunkDir(dbPath, walPath, chunkPath)
	if err := engine.Init(); err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	transport := NewTransport()
	ready := make(chan string)
	done := make(chan error)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	go func() {
		err := transport.ReceiveOnceWithOptions(ctx, "127.0.0.1:0", outDir, engine, ReceiveOptions{
			Resume:      true,
			RequireAuth: true,
			Identity:    grantee,
			SpaceKey:    space.SymmetricKey,
			OnListening: func(addr string) { ready <- addr },
		})
		done <- err
	}()

	addr := <-ready
	err = transport.SendFileWithOptions(ctx, addr, testFile, engine, SendOptions{
		Parallelism: 1,
		Resume:      true,
		AuthToken:   token,
		SpaceKey:    space.SymmetricKey,
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("receive: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(outDir, "secret.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestTransportRejectsMissingAuth(t *testing.T) {
	grantee, _ := crypto.GenerateIdentity()
	space, _ := crypto.NewSpace("secure")

	tempDir := t.TempDir()
	engine := store.NewEngineWithChunkDir(
		filepath.Join(tempDir, "v.db"),
		filepath.Join(tempDir, "w.db"),
		filepath.Join(tempDir, "chunks"),
	)
	if err := engine.Init(); err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	testFile := filepath.Join(tempDir, "f.txt")
	_ = os.WriteFile(testFile, []byte("x"), 0o644)

	transport := NewTransport()
	ready := make(chan string)
	done := make(chan error)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		done <- transport.ReceiveOnceWithOptions(ctx, "127.0.0.1:0", tempDir, nil, ReceiveOptions{
			RequireAuth: true,
			Identity:    grantee,
			SpaceKey:    space.SymmetricKey,
			OnListening: func(addr string) { ready <- addr },
		})
	}()

	addr := <-ready
	err := transport.SendFileWithOptions(ctx, addr, testFile, nil, SendOptions{Parallelism: 1, Resume: true})
	if err == nil {
		t.Fatal("expected send without auth to fail on secured receiver")
	}
	<-done
}
