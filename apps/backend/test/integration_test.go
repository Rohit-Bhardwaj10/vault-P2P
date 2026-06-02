package test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vault-backend/internal/network"
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
