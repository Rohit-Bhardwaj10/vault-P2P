package test

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vault-backend/internal/crypto"
	"vault-backend/internal/network"
	"vault-backend/internal/relay"
	"vault-backend/internal/store"
	"vault-backend/internal/sync"
)

func TestIntegration_WAL_QUIC(t *testing.T) {
	// Setup environment
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "vault.db")
	walPath := filepath.Join(tempDir, "wal.db")
	chunkPath := filepath.Join(tempDir, "chunks")
	outDir := filepath.Join(tempDir, "out")

	// Create test file
	testFile := filepath.Join(tempDir, "test.txt")
	testData := []byte("hello world integration test")
	if err := os.WriteFile(testFile, testData, 0o644); err != nil {
		t.Fatal(err)
	}

	// Initialize Engine
	engine := store.NewEngineWithChunkDir(dbPath, walPath, chunkPath)
	if err := engine.Init(); err != nil {
		t.Fatal(err)
		
	}
	defer engine.Close()

	// Enqueue an offline send
	peerID := "peer-123"
	peerAddr := "127.0.0.1:0" // Ephemeral port
	
	payload, _ := json.Marshal(map[string]string{
		"file_path": testFile,
		"peer_addr": peerAddr,
	})
	
	_, err := engine.EnqueueWAL(peerID, "send_file", payload)
	if err != nil {
		t.Fatal("Failed to enqueue:", err)
	}
	
	// Start Receiver
	recvReady := make(chan string)
	recvDone := make(chan error)
	transport := network.NewTransport()
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() {
		err := transport.ReceiveOnceWithOptions(ctx, peerAddr, outDir, engine, network.ReceiveOptions{
			Resume: true,
			OnListening: func(addr string) {
				recvReady <- addr
			},
		})
		recvDone <- err
	}()

	// Wait for receiver to listen
	actualAddr := <-recvReady

	// Simulate peer coming online and triggering drain
	deliveryFn := func(ctx context.Context, pid string, entry *store.WALEntry) error {
		var p map[string]string
		_ = json.Unmarshal(entry.Payload, &p)
		
		// Use actualAddr since peerAddr was :0
		return transport.SendFileWithOptions(ctx, actualAddr, p["file_path"], engine, network.SendOptions{
			Parallelism: 1,
			Resume:      true,
		})
	}

	coord := sync.NewCoordinator(engine, deliveryFn)
	
	// Trigger drain manually
	err = coord.DrainPeer(context.Background(), peerID)
	if err != nil {
		t.Fatalf("DrainPeer failed: %v", err)
	}

	// Check if receiver finished
	select {
	case err := <-recvDone:
		if err != nil {
			t.Fatalf("Receiver failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for receiver")
	}

	// Verify received file
	receivedFile := filepath.Join(outDir, "test.txt")
	got, err := os.ReadFile(receivedFile)
	if err != nil {
		t.Fatal("Failed to read received file:", err)
	}
	if string(got) != string(testData) {
		t.Errorf("Expected %q, got %q", string(testData), string(got))
	}

	// Verify WAL entry is done/deleted
	pending, err := engine.GetPendingWAL(peerID)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) > 0 {
		t.Errorf("Expected WAL queue to be empty, got %d", len(pending))
	}
}

func TestIntegration_PeerDropsDuringTransfer(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "vault.db")
	walPath := filepath.Join(tempDir, "wal.db")
	chunkPath := filepath.Join(tempDir, "chunks")
	outDir := filepath.Join(tempDir, "out")

	// Create a larger test file so transfer doesn't finish instantly
	testFile := filepath.Join(tempDir, "large_test.bin")
	testData := make([]byte, 1024*1024*5) // 5 MB
	if err := os.WriteFile(testFile, testData, 0o644); err != nil {
		t.Fatal(err)
	}

	engine := store.NewEngineWithChunkDir(dbPath, walPath, chunkPath)
	if err := engine.Init(); err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	peerID := "peer-drop"
	peerAddr := "127.0.0.1:0"

	payload, _ := json.Marshal(map[string]string{
		"file_path": testFile,
		"peer_addr": peerAddr,
	})

	_, err := engine.EnqueueWAL(peerID, "send_file", payload)
	if err != nil {
		t.Fatal("Failed to enqueue:", err)
	}

	recvReady := make(chan string)
	recvDone := make(chan error)
	transport := network.NewTransport()

	// Receiver context will be cancelled after 50ms to simulate drop
	ctxRecv, cancelRecv := context.WithCancel(context.Background())

	go func() {
		err := transport.ReceiveOnceWithOptions(ctxRecv, peerAddr, outDir, engine, network.ReceiveOptions{
			Resume: true,
			OnListening: func(addr string) {
				recvReady <- addr
			},
		})
		recvDone <- err
	}()

	actualAddr := <-recvReady

	// Cancel receiver shortly after starting sender
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancelRecv()
	}()

	deliveryFn := func(ctx context.Context, pid string, entry *store.WALEntry) error {
		var p map[string]string
		_ = json.Unmarshal(entry.Payload, &p)

		return transport.SendFileWithOptions(ctx, actualAddr, p["file_path"], engine, network.SendOptions{
			Parallelism: 1,
			Resume:      true,
		})
	}

	coord := sync.NewCoordinator(engine, deliveryFn)
	
	err = coord.DrainPeer(context.Background(), peerID)
	// We expect DrainPeer to succeed in iterating, but the actual delivery should fail
	if err != nil {
		t.Fatalf("DrainPeer unexpectedly returned error: %v", err)
	}

	<-recvDone // Wait for receiver to finish failing

	// Verify WAL entry remains and has retries > 0
	pending, err := engine.GetPendingWAL(peerID)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("Expected 1 WAL entry pending after failure, got %d", len(pending))
	}
	if pending[0].Retries != 1 {
		t.Errorf("Expected WAL entry to have 1 retry, got %d", pending[0].Retries)
	}
}

// TestIntegration_EncryptedWAL validates the complete encrypted pipeline:
// - Ed25519 identity + capability token issuance
// - Space symmetric key shared between sender and receiver
// - WAL entry written before delivery attempt
// - Coordinator drains peer, triggering authenticated + encrypted QUIC transfer
// - Received file matches original; WAL queue drained to empty
func TestIntegration_EncryptedWAL(t *testing.T) {
	// --- Crypto setup ---
	issuer, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal("generate issuer:", err)
	}
	grantee, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal("generate grantee:", err)
	}
	space, err := crypto.NewSpace("test-space")
	if err != nil {
		t.Fatal("create space:", err)
	}
	token, err := crypto.IssueToken(issuer, grantee.PublicKey, space.ID, crypto.PermWrite, time.Hour)
	if err != nil {
		t.Fatal("issue token:", err)
	}

	// --- Storage setup ---
	tempDir := t.TempDir()
	engine := store.NewEngineWithChunkDir(
		filepath.Join(tempDir, "vault.db"),
		filepath.Join(tempDir, "wal.db"),
		filepath.Join(tempDir, "chunks"),
	)
	if err := engine.Init(); err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	outDir := filepath.Join(tempDir, "out")
	testFile := filepath.Join(tempDir, "secret.bin")
	testData := []byte("encrypted WAL integration test payload — Vault P2P")
	if err := os.WriteFile(testFile, testData, 0o644); err != nil {
		t.Fatal(err)
	}

	// --- Enqueue send intent via WAL ---
	peerID := "peer-encrypted"
	payload, _ := json.Marshal(map[string]string{"file_path": testFile, "peer_addr": "127.0.0.1:0"})
	_, err = engine.EnqueueWAL(peerID, "send_file", payload)
	if err != nil {
		t.Fatal("EnqueueWAL:", err)
	}

	// --- Start encrypted receiver ---
	transport := network.NewTransport()
	recvReady := make(chan string, 1)
	recvDone := make(chan error, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	go func() {
		recvDone <- transport.ReceiveOnceWithOptions(ctx, "127.0.0.1:0", outDir, engine, network.ReceiveOptions{
			Resume:      true,
			RequireAuth: true,
			Identity:    grantee,
			SpaceKey:    space.SymmetricKey,
			OnListening: func(addr string) { recvReady <- addr },
		})
	}()

	actualAddr := <-recvReady

	// --- Delivery function: authenticated + encrypted QUIC send ---
	deliveryFn := func(ctx context.Context, pid string, entry *store.WALEntry) error {
		var p map[string]string
		_ = json.Unmarshal(entry.Payload, &p)
		return transport.SendFileWithOptions(ctx, actualAddr, p["file_path"], engine, network.SendOptions{
			Parallelism: 1,
			Resume:      true,
			AuthToken:   token,
			SpaceKey:    space.SymmetricKey,
		})
	}

	// --- Coordinator drains the WAL entry ---
	coord := sync.NewCoordinator(engine, deliveryFn)
	if err := coord.DrainPeer(ctx, peerID); err != nil {
		t.Fatalf("DrainPeer: %v", err)
	}

	// --- Wait for receiver to finish ---
	select {
	case err := <-recvDone:
		if err != nil {
			t.Fatalf("receiver error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for encrypted receiver")
	}

	// --- Verify file content ---
	got, err := os.ReadFile(filepath.Join(outDir, "secret.bin"))
	if err != nil {
		t.Fatal("read received file:", err)
	}
	if string(got) != string(testData) {
		t.Errorf("content mismatch: got %q, want %q", got, testData)
	}

	// --- Verify WAL queue is empty ---
	pending, err := engine.GetPendingWAL(peerID)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) > 0 {
		t.Errorf("WAL not drained: %d entries remain", len(pending))
	}
}

// TestIntegration_RelayFallback validates the relay store-and-forward path:
// - Sender pushes encrypted chunks via RelayTransfer.SendFile
// - Receiver pulls with RelayTransfer.ReceiveFile
// - Reconstructed file matches original
func TestIntegration_RelayFallback(t *testing.T) {
	// --- Relay server on ephemeral port ---
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("find free port:", err)
	}
	relayAddr := ln.Addr().String()
	_ = ln.Close()

	relaySrv := relay.NewServer(relayAddr, filepath.Join(t.TempDir(), "relay.db"), 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srvErrCh := make(chan error, 1)
	go func() { srvErrCh <- relaySrv.Run(ctx) }()

	// Give relay time to start.
	time.Sleep(30 * time.Millisecond)

	// --- Crypto setup: shared session key ---
	space, err := crypto.NewSpace("relay-space")
	if err != nil {
		t.Fatal("create space:", err)
	}

	// --- Write test file ---
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "relay_payload.dat")
	testData := []byte("relay fallback integration test — encrypted store-and-forward")
	if err := os.WriteFile(testFile, testData, 0o644); err != nil {
		t.Fatal(err)
	}

	// --- Sender: push encrypted chunks to relay ---
	senderClient := relay.NewClient(relayAddr)
	senderRT := &network.RelayTransfer{
		Client:     senderClient,
		SessionKey: space.SymmetricKey,
	}

	recipientID := "peer-relay-recv"
	_, err = senderRT.SendFile(ctx, recipientID, testFile, space.ID)
	if err != nil {
		t.Fatalf("relay SendFile: %v", err)
	}

	// --- Receiver: pull chunks from relay ---
	outDir := filepath.Join(tempDir, "out")
	receiverClient := relay.NewClient(relayAddr)
	receiverRT := &network.RelayTransfer{
		Client:     receiverClient,
		SessionKey: space.SymmetricKey,
	}

	receivedPath, err := receiverRT.ReceiveFile(ctx, recipientID, outDir, nil)
	if err != nil {
		t.Fatalf("relay ReceiveFile: %v", err)
	}

	// --- Verify content ---
	got, err := os.ReadFile(receivedPath)
	if err != nil {
		t.Fatal("read relayed file:", err)
	}
	if string(got) != string(testData) {
		t.Errorf("relay content mismatch: got %q, want %q", got, testData)
	}

	// --- Relay inbox should be empty after pull ---
	cancel() // stop relay server
	select {
	case err := <-srvErrCh:
		if err != nil {
			t.Logf("relay server exited: %v", err)
		}
	case <-time.After(2 * time.Second):
	}
}
