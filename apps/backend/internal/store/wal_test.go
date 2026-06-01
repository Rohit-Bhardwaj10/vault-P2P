package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func newTestBolt(t *testing.T) *BoltStore {
	t.Helper()
	dir := t.TempDir()
	s := NewBoltStore(filepath.Join(dir, "wal.db"))
	if err := s.Init(); err != nil {
		t.Fatalf("BoltStore.Init: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestWALEnqueueAndPending(t *testing.T) {
	s := newTestBolt(t)

	payload, _ := json.Marshal(map[string]string{"file": "foo.txt"})
	e1, err := s.EnqueueEntry("peer-a", "send_file", payload)
	if err != nil {
		t.Fatalf("EnqueueEntry: %v", err)
	}
	if e1.ID == "" {
		t.Error("expected non-empty entry ID")
	}
	if e1.Status != WALStatusPending {
		t.Errorf("expected status pending, got %s", e1.Status)
	}

	_, err = s.EnqueueEntry("peer-a", "send_chunk", payload)
	if err != nil {
		t.Fatalf("EnqueueEntry 2: %v", err)
	}
	_, err = s.EnqueueEntry("peer-b", "send_file", payload)
	if err != nil {
		t.Fatalf("EnqueueEntry 3: %v", err)
	}

	entries, err := s.GetPendingEntries("peer-a")
	if err != nil {
		t.Fatalf("GetPendingEntries: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries for peer-a, got %d", len(entries))
	}
}

func TestWALGetAllPending(t *testing.T) {
	s := newTestBolt(t)

	payload := json.RawMessage(`{}`)
	_, _ = s.EnqueueEntry("peer-1", "op", payload)
	_, _ = s.EnqueueEntry("peer-2", "op", payload)
	_, _ = s.EnqueueEntry("peer-1", "op", payload)

	all, err := s.GetAllPendingEntries()
	if err != nil {
		t.Fatalf("GetAllPendingEntries: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("expected 3 pending entries, got %d", len(all))
	}
}

func TestWALStatusTransitions(t *testing.T) {
	s := newTestBolt(t)

	payload := json.RawMessage(`{"x":1}`)
	entry, _ := s.EnqueueEntry("peer-x", "test_op", payload)

	if err := s.MarkInFlight(entry.ID); err != nil {
		t.Fatalf("MarkInFlight: %v", err)
	}
	// In-flight entries should not appear in pending list.
	pending, _ := s.GetPendingEntries("peer-x")
	if len(pending) != 0 {
		t.Errorf("expected 0 pending after marking inflight, got %d", len(pending))
	}

	if err := s.MarkDone(entry.ID); err != nil {
		t.Fatalf("MarkDone: %v", err)
	}
}

func TestWALMarkFailed(t *testing.T) {
	s := newTestBolt(t)

	payload := json.RawMessage(`{}`)
	entry, _ := s.EnqueueEntry("peer-fail", "op", payload)

	_ = s.MarkInFlight(entry.ID)
	_ = s.MarkFailed(entry.ID) // should increment retries and reset to pending

	entries, _ := s.GetPendingEntries("peer-fail")
	if len(entries) != 1 {
		t.Errorf("expected 1 pending entry after MarkFailed, got %d", len(entries))
	}
	if entries[0].Retries != 1 {
		t.Errorf("expected Retries=1, got %d", entries[0].Retries)
	}
}

func TestWALDeleteEntry(t *testing.T) {
	s := newTestBolt(t)

	payload := json.RawMessage(`{}`)
	entry, _ := s.EnqueueEntry("peer-del", "op", payload)

	_ = s.DeleteEntry(entry.ID)

	pending, _ := s.GetPendingEntries("peer-del")
	if len(pending) != 0 {
		t.Errorf("expected 0 entries after delete, got %d", len(pending))
	}
}

func TestWALFIFOOrdering(t *testing.T) {
	s := newTestBolt(t)

	payload := json.RawMessage(`{}`)
	var ids []string
	for i := 0; i < 5; i++ {
		e, _ := s.EnqueueEntry("peer-ord", "op", payload)
		ids = append(ids, e.ID)
	}

	entries, _ := s.GetPendingEntries("peer-ord")
	if len(entries) != 5 {
		t.Fatalf("expected 5, got %d", len(entries))
	}
	for i, e := range entries {
		if e.ID != ids[i] {
			t.Errorf("FIFO violation at index %d: want %s, got %s", i, ids[i], e.ID)
		}
	}
}

// Prevent unused import of os.
var _ = os.DevNull
