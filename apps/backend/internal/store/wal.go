package store

import (
	"encoding/json"
	"fmt"
	"time"

	"go.etcd.io/bbolt"
)

// WALStatus represents the lifecycle state of a queued operation.
type WALStatus string

const (
	WALStatusPending    WALStatus = "pending"
	WALStatusInFlight   WALStatus = "inflight"
	WALStatusDone       WALStatus = "done"
	WALStatusFailed     WALStatus = "failed"
)

var (
	bucketWAL    = []byte("wal_entries")
	bucketSeq    = []byte("wal_seq")
)

// WALEntry is a single durable operation record.
type WALEntry struct {
	// ID is the sequence-based key used in BoltDB ("0000000001", etc.)
	ID string `json:"id"`
	// PeerID identifies the target peer for this operation.
	PeerID string `json:"peer_id"`
	// Op is the operation type (e.g. "send_chunk", "send_file").
	Op string `json:"op"`
	// Payload carries op-specific data (serialised as JSON).
	Payload json.RawMessage `json:"payload"`
	// Status is the current lifecycle state.
	Status WALStatus `json:"status"`
	// Retries counts how many delivery attempts have been made.
	Retries int `json:"retries"`
	// CreatedAt is the Unix timestamp of when the entry was created.
	CreatedAt int64 `json:"created_at"`
	// UpdatedAt is the Unix timestamp of the last status transition.
	UpdatedAt int64 `json:"updated_at"`
}

// EnqueueEntry adds a new WALEntry with status=pending.
// It is written inside a single BoltDB transaction for durability.
func (s *BoltStore) EnqueueEntry(peerID, op string, payload json.RawMessage) (*WALEntry, error) {
	if s.db == nil {
		return nil, fmt.Errorf("bolt store not initialized")
	}

	var entry *WALEntry
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketWAL)
		if b == nil {
			return fmt.Errorf("wal bucket not found")
		}

		seq, err := b.NextSequence()
		if err != nil {
			return fmt.Errorf("next sequence: %w", err)
		}

		id := fmt.Sprintf("%010d", seq)
		now := time.Now().Unix()
		entry = &WALEntry{
			ID:        id,
			PeerID:    peerID,
			Op:        op,
			Payload:   payload,
			Status:    WALStatusPending,
			Retries:   0,
			CreatedAt: now,
			UpdatedAt: now,
		}

		data, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("marshal WAL entry: %w", err)
		}

		return b.Put([]byte(id), data)
	})
	if err != nil {
		return nil, err
	}
	return entry, nil
}

// GetPendingEntries returns all WAL entries for peerID with status=pending,
// ordered by their sequence ID (FIFO).
func (s *BoltStore) GetPendingEntries(peerID string) ([]*WALEntry, error) {
	if s.db == nil {
		return nil, fmt.Errorf("bolt store not initialized")
	}

	var entries []*WALEntry
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketWAL)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var e WALEntry
			if err := json.Unmarshal(v, &e); err != nil {
				return fmt.Errorf("unmarshal WAL entry %s: %w", k, err)
			}
			if e.PeerID == peerID && e.Status == WALStatusPending {
				entries = append(entries, &e)
			}
			return nil
		})
	})
	return entries, err
}

// GetAllPendingEntries returns every pending entry across all peers.
func (s *BoltStore) GetAllPendingEntries() ([]*WALEntry, error) {
	if s.db == nil {
		return nil, fmt.Errorf("bolt store not initialized")
	}

	var entries []*WALEntry
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketWAL)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var e WALEntry
			if err := json.Unmarshal(v, &e); err != nil {
				return fmt.Errorf("unmarshal WAL entry %s: %w", k, err)
			}
			if e.Status == WALStatusPending {
				entries = append(entries, &e)
			}
			return nil
		})
	})
	return entries, err
}

// MarkInFlight transitions a WAL entry from pending → inflight.
func (s *BoltStore) MarkInFlight(id string) error {
	return s.updateStatus(id, WALStatusInFlight)
}

// MarkDone transitions a WAL entry to done (terminal).
func (s *BoltStore) MarkDone(id string) error {
	return s.updateStatus(id, WALStatusDone)
}

// MarkFailed increments the retry counter and transitions to pending
// (so the worker will retry on the next poll cycle).
func (s *BoltStore) MarkFailed(id string) error {
	if s.db == nil {
		return fmt.Errorf("bolt store not initialized")
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketWAL)
		if b == nil {
			return fmt.Errorf("wal bucket not found")
		}
		data := b.Get([]byte(id))
		if data == nil {
			return fmt.Errorf("WAL entry %s not found", id)
		}
		var e WALEntry
		if err := json.Unmarshal(data, &e); err != nil {
			return err
		}
		e.Status = WALStatusPending
		e.Retries++
		e.UpdatedAt = time.Now().Unix()
		updated, err := json.Marshal(&e)
		if err != nil {
			return err
		}
		return b.Put([]byte(id), updated)
	})
}

// DeleteEntry removes a WAL entry permanently (call after successful delivery).
func (s *BoltStore) DeleteEntry(id string) error {
	if s.db == nil {
		return fmt.Errorf("bolt store not initialized")
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketWAL)
		if b == nil {
			return fmt.Errorf("wal bucket not found")
		}
		return b.Delete([]byte(id))
	})
}

// updateStatus is a shared helper for simple status transitions.
func (s *BoltStore) updateStatus(id string, status WALStatus) error {
	if s.db == nil {
		return fmt.Errorf("bolt store not initialized")
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketWAL)
		if b == nil {
			return fmt.Errorf("wal bucket not found")
		}
		data := b.Get([]byte(id))
		if data == nil {
			return fmt.Errorf("WAL entry %s not found", id)
		}
		var e WALEntry
		if err := json.Unmarshal(data, &e); err != nil {
			return err
		}
		e.Status = status
		e.UpdatedAt = time.Now().Unix()
		updated, err := json.Marshal(&e)
		if err != nil {
			return err
		}
		return b.Put([]byte(id), updated)
	})
}
