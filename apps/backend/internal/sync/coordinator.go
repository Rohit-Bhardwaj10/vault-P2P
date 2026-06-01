package sync

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"vault-backend/internal/store"
)

const (
	// DefaultPollInterval is how often the background worker checks for pending WAL entries.
	DefaultPollInterval = 5 * time.Second
	// MaxRetries is the number of attempts before a WAL entry is permanently failed.
	MaxRetries = 10
)

// DeliveryFunc is the function the coordinator calls to actually deliver a WAL entry.
// Implementations should attempt to connect to the peer and send the payload.
// Return nil on success, or an error if delivery failed.
type DeliveryFunc func(ctx context.Context, peerID string, entry *store.WALEntry) error

// Coordinator manages offline-first per-peer sync queues.
// It writes every send intent to the WAL before attempting delivery, so that
// no operation is silently lost if the peer is offline or the process crashes.
type Coordinator struct {
	engine       *store.Engine
	deliveryFunc DeliveryFunc
	pollInterval time.Duration

	mu      sync.Mutex
	online  map[string]bool // peerID → is peer currently reachable?
}

// NewCoordinator creates a Coordinator backed by the given storage Engine.
// deliveryFn is called to actually send a queued operation to a peer.
func NewCoordinator(engine *store.Engine, deliveryFn DeliveryFunc) *Coordinator {
	return &Coordinator{
		engine:       engine,
		deliveryFunc: deliveryFn,
		pollInterval: DefaultPollInterval,
		online:       make(map[string]bool),
	}
}

// WithPollInterval overrides the default background poll interval (useful in tests).
func (c *Coordinator) WithPollInterval(d time.Duration) *Coordinator {
	c.pollInterval = d
	return c
}

// Enqueue durably writes an operation for a peer into the WAL.
// The operation will be delivered when the peer is reachable.
// peerID   — target peer identifier
// op       — operation type string (e.g. "send_chunk", "send_file")
// payload  — JSON-serialisable data for the operation
func (c *Coordinator) Enqueue(peerID, op string, payload any) (*store.WALEntry, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	entry, err := c.engine.EnqueueWAL(peerID, op, raw)
	if err != nil {
		return nil, fmt.Errorf("enqueue WAL entry: %w", err)
	}
	return entry, nil
}

// MarkOnline tells the coordinator that a peer is now reachable.
// This triggers an immediate drain of any pending WAL entries for that peer.
func (c *Coordinator) MarkOnline(ctx context.Context, peerID string) {
	c.mu.Lock()
	c.online[peerID] = true
	c.mu.Unlock()

	go func() {
		if err := c.drainPeer(ctx, peerID); err != nil {
			log.Printf("[coordinator] drain peer %s: %v", peerID, err)
		}
	}()
}

// MarkOffline marks a peer as unreachable.
func (c *Coordinator) MarkOffline(peerID string) {
	c.mu.Lock()
	c.online[peerID] = false
	c.mu.Unlock()
}

// IsPeerOnline returns whether the peer was last seen as reachable.
func (c *Coordinator) IsPeerOnline(peerID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.online[peerID]
}

// Run starts the background worker that polls for pending WAL entries.
// It blocks until ctx is cancelled.
func (c *Coordinator) Run(ctx context.Context) {
	ticker := time.NewTicker(c.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.pollAndDeliver(ctx); err != nil {
				log.Printf("[coordinator] poll error: %v", err)
			}
		}
	}
}

// DrainPeer immediately processes all pending WAL entries for the given peer.
// This is exported so callers (e.g. mDNS on peer-found events) can trigger
// an immediate sync without waiting for the next poll cycle.
func (c *Coordinator) DrainPeer(ctx context.Context, peerID string) error {
	return c.drainPeer(ctx, peerID)
}

// drainPeer delivers every pending WAL entry for a single peer.
func (c *Coordinator) drainPeer(ctx context.Context, peerID string) error {
	entries, err := c.engine.GetPendingWAL(peerID)
	if err != nil {
		return fmt.Errorf("get pending entries: %w", err)
	}

	for _, entry := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		c.deliver(ctx, entry)
	}
	return nil
}

// pollAndDeliver checks every pending WAL entry across all peers.
// It only attempts delivery for peers currently marked online.
func (c *Coordinator) pollAndDeliver(ctx context.Context) error {
	entries, err := c.engine.GetAllPendingWAL()
	if err != nil {
		return fmt.Errorf("get all pending entries: %w", err)
	}

	for _, entry := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		c.mu.Lock()
		isOnline := c.online[entry.PeerID]
		c.mu.Unlock()

		if !isOnline {
			continue // peer is offline; leave entry pending
		}
		c.deliver(ctx, entry)
	}
	return nil
}

// deliver attempts a single delivery and updates the WAL entry status.
func (c *Coordinator) deliver(ctx context.Context, entry *store.WALEntry) {
	if entry.Retries >= MaxRetries {
		log.Printf("[coordinator] entry %s exceeded max retries (%d), giving up", entry.ID, MaxRetries)
		if err := c.engine.MarkWALFailed(entry.ID); err != nil {
			log.Printf("[coordinator] mark failed %s: %v", entry.ID, err)
		}
		return
	}

	if err := c.engine.MarkWALInFlight(entry.ID); err != nil {
		log.Printf("[coordinator] mark inflight %s: %v", entry.ID, err)
		return
	}

	err := c.deliveryFunc(ctx, entry.PeerID, entry)
	if err != nil {
		log.Printf("[coordinator] delivery failed for entry %s (peer %s, op %s, retry %d): %v",
			entry.ID, entry.PeerID, entry.Op, entry.Retries, err)
		if markErr := c.engine.MarkWALFailed(entry.ID); markErr != nil {
			log.Printf("[coordinator] mark failed %s: %v", entry.ID, markErr)
		}
		return
	}

	if err := c.engine.MarkWALDone(entry.ID); err != nil {
		log.Printf("[coordinator] mark done %s: %v", entry.ID, err)
	}
	// Delete from WAL once successfully delivered.
	if err := c.engine.DeleteWALEntry(entry.ID); err != nil {
		log.Printf("[coordinator] delete entry %s: %v", entry.ID, err)
	}
}
