package sync

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"vault-backend/internal/store"
)

func newTestEngine(t *testing.T) *store.Engine {
	t.Helper()
	dir := t.TempDir()
	engine := store.NewEngineWithChunkDir(
		filepath.Join(dir, "vault.db"),
		filepath.Join(dir, "wal.db"),
		filepath.Join(dir, "chunks"),
	)
	if err := engine.Init(); err != nil {
		t.Fatalf("engine.Init: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	return engine
}

func TestCoordinatorEnqueue(t *testing.T) {
	engine := newTestEngine(t)
	coord := NewCoordinator(engine, func(_ context.Context, _ string, _ *store.WALEntry) error {
		return nil
	})

	payload := map[string]string{"file": "test.txt"}
	entry, err := coord.Enqueue("peer-1", "send_file", payload)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if entry.ID == "" {
		t.Error("expected non-empty entry ID")
	}

	pending, err := engine.GetPendingWAL("peer-1")
	if err != nil {
		t.Fatalf("GetPendingWAL: %v", err)
	}
	if len(pending) != 1 {
		t.Errorf("expected 1 pending entry, got %d", len(pending))
	}
}

func TestCoordinatorDeliverySuccess(t *testing.T) {
	engine := newTestEngine(t)

	var delivered atomic.Int32
	coord := NewCoordinator(engine, func(_ context.Context, _ string, _ *store.WALEntry) error {
		delivered.Add(1)
		return nil
	})

	payload := map[string]string{"x": "y"}
	_, _ = coord.Enqueue("peer-ok", "op", payload)
	_, _ = coord.Enqueue("peer-ok", "op", payload)

	coord.MarkOnline(context.Background(), "peer-ok")
	// Give the goroutine time to drain.
	time.Sleep(50 * time.Millisecond)

	if delivered.Load() != 2 {
		t.Errorf("expected 2 deliveries, got %d", delivered.Load())
	}

	// Queue should now be empty.
	pending, _ := engine.GetPendingWAL("peer-ok")
	if len(pending) != 0 {
		t.Errorf("expected 0 pending after delivery, got %d", len(pending))
	}
}

func TestCoordinatorDeliveryFailureRetries(t *testing.T) {
	engine := newTestEngine(t)

	var attempts atomic.Int32
	coord := NewCoordinator(engine, func(_ context.Context, _ string, _ *store.WALEntry) error {
		attempts.Add(1)
		return errors.New("peer unreachable")
	})

	payload := map[string]string{"op": "fail"}
	entry, _ := coord.Enqueue("peer-fail", "op", payload)

	// Manually deliver (simulating a poll cycle).
	coord.MarkOnline(context.Background(), "peer-fail")
	time.Sleep(50 * time.Millisecond)

	// Entry should still be pending with retries=1.
	pending, _ := engine.GetPendingWAL("peer-fail")
	if len(pending) == 0 {
		t.Errorf("expected entry to remain pending after failure")
	}
	if pending[0].ID == entry.ID && pending[0].Retries < 1 {
		t.Errorf("expected Retries >= 1, got %d", pending[0].Retries)
	}
	_ = attempts
}

func TestCoordinatorOfflinePeerNotDelivered(t *testing.T) {
	engine := newTestEngine(t)

	var delivered atomic.Int32
	coord := NewCoordinator(engine, func(_ context.Context, _ string, _ *store.WALEntry) error {
		delivered.Add(1)
		return nil
	}).WithPollInterval(20 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go coord.Run(ctx)

	payload := map[string]string{"file": "offline.txt"}
	_, _ = coord.Enqueue("peer-offline", "send_file", payload)

	// Peer is never marked online — delivery should not happen.
	time.Sleep(80 * time.Millisecond)

	if delivered.Load() != 0 {
		t.Errorf("expected 0 deliveries for offline peer, got %d", delivered.Load())
	}
	pending, _ := engine.GetPendingWAL("peer-offline")
	if len(pending) != 1 {
		t.Errorf("expected entry to remain pending, got %d", len(pending))
	}
}

func TestCoordinatorOnlineTriggersDrain(t *testing.T) {
	engine := newTestEngine(t)

	delivered := make(chan string, 10)
	coord := NewCoordinator(engine, func(_ context.Context, peerID string, entry *store.WALEntry) error {
		delivered <- peerID
		return nil
	})

	payload, _ := json.Marshal("test")
	_, _ = coord.Enqueue("peer-late", "op", payload)
	_, _ = coord.Enqueue("peer-late", "op", payload)

	coord.MarkOnline(context.Background(), "peer-late")

	// Collect results with a timeout.
	var count int
	timeout := time.After(200 * time.Millisecond)
	for {
		select {
		case <-delivered:
			count++
		case <-timeout:
			goto done
		}
	}
done:
	if count != 2 {
		t.Errorf("expected 2 deliveries on MarkOnline, got %d", count)
	}
}

func TestCoordinatorMarkOnlineOffline(t *testing.T) {
	engine := newTestEngine(t)
	coord := NewCoordinator(engine, func(_ context.Context, _ string, _ *store.WALEntry) error {
		return nil
	})

	if coord.IsPeerOnline("p") {
		t.Error("new peer should be offline by default")
	}
	coord.MarkOnline(context.Background(), "p")
	// IsPeerOnline should now return true (set synchronously before goroutine).
	if !coord.IsPeerOnline("p") {
		t.Error("peer should be online after MarkOnline")
	}
	coord.MarkOffline("p")
	if coord.IsPeerOnline("p") {
		t.Error("peer should be offline after MarkOffline")
	}
}
