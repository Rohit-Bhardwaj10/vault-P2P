package store

// Engine-level helpers that proxy chunk location tracking to SQLiteStore.
// This keeps callers decoupled from the underlying store implementation.

// RecordChunkLocation records that a peer holds a specific chunk.
func (e *Engine) RecordChunkLocation(chunkHash, peerID string) error {
	return e.sqlite.RecordChunkLocation(chunkHash, peerID)
}

// GetChunkPeers returns all peer IDs known to hold the given chunk.
func (e *Engine) GetChunkPeers(chunkHash string) ([]string, error) {
	return e.sqlite.GetChunkPeers(chunkHash)
}

// GetPeerChunks returns all chunk hashes known to be held by a peer.
func (e *Engine) GetPeerChunks(peerID string) ([]string, error) {
	return e.sqlite.GetPeerChunks(peerID)
}

// RemoveChunkLocation removes a peer→chunk mapping.
func (e *Engine) RemoveChunkLocation(chunkHash, peerID string) error {
	return e.sqlite.RemoveChunkLocation(chunkHash, peerID)
}

// UpsertPeer records or updates a peer's connection information.
func (e *Engine) UpsertPeer(id, pubkey, addresses string, latencyMs int64) error {
	return e.sqlite.UpsertPeer(id, pubkey, addresses, latencyMs)
}

// GetPeer looks up a peer by ID.
func (e *Engine) GetPeer(id string) (pubkey, addresses string, latencyMs int64, err error) {
	return e.sqlite.GetPeer(id)
}

// WAL proxy methods so callers only depend on *Engine.

// EnqueueWAL adds a new pending operation to the write-ahead log.
func (e *Engine) EnqueueWAL(peerID, op string, payload []byte) (*WALEntry, error) {
	return e.bolt.EnqueueEntry(peerID, op, payload)
}

// GetPendingWAL returns pending WAL entries for a given peer.
func (e *Engine) GetPendingWAL(peerID string) ([]*WALEntry, error) {
	return e.bolt.GetPendingEntries(peerID)
}

// GetAllPendingWAL returns every pending WAL entry across all peers.
func (e *Engine) GetAllPendingWAL() ([]*WALEntry, error) {
	return e.bolt.GetAllPendingEntries()
}

// MarkWALInFlight transitions an entry to in-flight.
func (e *Engine) MarkWALInFlight(id string) error {
	return e.bolt.MarkInFlight(id)
}

// MarkWALDone marks an entry as successfully completed.
func (e *Engine) MarkWALDone(id string) error {
	return e.bolt.MarkDone(id)
}

// MarkWALFailed increments the retry counter and resets to pending.
func (e *Engine) MarkWALFailed(id string) error {
	return e.bolt.MarkFailed(id)
}

// DeleteWALEntry permanently removes a WAL entry.
func (e *Engine) DeleteWALEntry(id string) error {
	return e.bolt.DeleteEntry(id)
}
