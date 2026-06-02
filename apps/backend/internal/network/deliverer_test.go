package network

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vault-backend/internal/crypto"
)

func TestDelivererDirectQUIC(t *testing.T) {
	issuer, _ := crypto.GenerateIdentity()
	grantee, _ := crypto.GenerateIdentity()
	space, _ := crypto.NewSpace("direct")
	token, _ := crypto.IssueToken(issuer, grantee.PublicKey, space.ID, crypto.PermWrite, time.Hour)

	tempDir := t.TempDir()
	src := filepath.Join(tempDir, "direct.txt")
	_ = os.WriteFile(src, []byte("direct ok"), 0o644)
	outDir := filepath.Join(tempDir, "out")

	transport := NewTransport()
	ready := make(chan string)
	done := make(chan error)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	go func() {
		done <- transport.ReceiveOnceWithOptions(ctx, "127.0.0.1:0", outDir, nil, ReceiveOptions{
			RequireAuth: true,
			Identity:    grantee,
			SpaceKey:    space.SymmetricKey,
			OnListening: func(a string) { ready <- a },
		})
	}()

	addr := <-ready
	d := &Deliverer{
		Transport: transport,
		AuthToken: token,
		SpaceKey:  space.SymmetricKey,
		PeerAddr:  addr,
	}
	if err := d.SendFile(ctx, src, nil, DeliverOptions{Parallelism: 1}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
