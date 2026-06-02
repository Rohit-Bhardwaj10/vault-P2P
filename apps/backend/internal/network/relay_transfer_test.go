package network

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vault-backend/internal/crypto"
	"vault-backend/internal/relay"
)

func startRelayForTest(t *testing.T) (addr string, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = ln.Addr().String()
	_ = ln.Close()

	srv := relay.NewServer(addr, filepath.Join(t.TempDir(), "relay.db"), 0)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = srv.Run(ctx)
	}()
	time.Sleep(50 * time.Millisecond)
	return addr, cancel
}

func TestRelayTransferRoundtrip(t *testing.T) {
	relayAddr, stopRelay := startRelayForTest(t)
	defer stopRelay()

	issuer, _ := crypto.GenerateIdentity()
	grantee, _ := crypto.GenerateIdentity()
	space, _ := crypto.NewSpace("relay-test")
	token, _ := crypto.IssueToken(issuer, grantee.PublicKey, space.ID, crypto.PermWrite, time.Hour)
	sk, _ := DeriveTransferSessionKey(space.SymmetricKey, token)

	tempDir := t.TempDir()
	src := filepath.Join(tempDir, "payload.bin")
	want := []byte("relay encrypted file content")
	if err := os.WriteFile(src, want, 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(tempDir, "out")

	client := relay.NewClient(relayAddr)
	rt := &RelayTransfer{Client: client, SessionKey: sk}

	recipientID := "peer-recipient"
	if _, err := rt.SendFile(context.Background(), recipientID, src, space.ID); err != nil {
		t.Fatalf("send via relay: %v", err)
	}

	outPath, err := rt.ReceiveFile(context.Background(), recipientID, outDir, nil)
	if err != nil {
		t.Fatalf("receive via relay: %v", err)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestDelivererRelayFallback(t *testing.T) {
	relayAddr, stopRelay := startRelayForTest(t)
	defer stopRelay()

	issuer, _ := crypto.GenerateIdentity()
	grantee, _ := crypto.GenerateIdentity()
	space, _ := crypto.NewSpace("deliverer")
	token, _ := crypto.IssueToken(issuer, grantee.PublicKey, space.ID, crypto.PermWrite, time.Hour)

	tempDir := t.TempDir()
	src := filepath.Join(tempDir, "f.txt")
	_ = os.WriteFile(src, []byte("fallback"), 0o644)

	d := &Deliverer{
		Transport:   NewTransport(),
		Relay:       relay.NewClient(relayAddr),
		AuthToken:   token,
		SpaceKey:    space.SymmetricKey,
		PeerAddr:    "127.0.0.1:59999", // nothing listening — forces relay
		RecipientID: "peer-b",
	}

	if err := d.SendFile(context.Background(), src, nil, DeliverOptions{Parallelism: 1, Resume: true}); err != nil {
		t.Fatalf("deliverer: %v", err)
	}

	sk, _ := DeriveTransferSessionKey(space.SymmetricKey, token)
	rt := &RelayTransfer{Client: relay.NewClient(relayAddr), SessionKey: sk}
	out, err := rt.ReceiveFile(context.Background(), "peer-b", filepath.Join(tempDir, "out"), nil)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	got, _ := os.ReadFile(out)
	if string(got) != "fallback" {
		t.Fatalf("got %q", got)
	}
	_ = grantee
}
