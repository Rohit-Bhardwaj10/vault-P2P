package store

import (
	"context"
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	dbPath string
	db     *sql.DB
}

func NewSQLiteStore(path string) *SQLiteStore {
	return &SQLiteStore{dbPath: path}
}

func (s *SQLiteStore) Init() error {
	var err error
	s.db, err = sql.Open("sqlite", s.dbPath)
	if err != nil {
		return err
	}

	// Create tables schema based on buildplan.md
	schema := `
	CREATE TABLE IF NOT EXISTS chunks (
		hash TEXT PRIMARY KEY,
		file_path TEXT,
		size INTEGER,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS manifests (
		id TEXT PRIMARY KEY,
		space_id TEXT,
		file_path TEXT,
		chunk_hashes TEXT,
		vector_clock TEXT
	);
	CREATE TABLE IF NOT EXISTS spaces (
		id TEXT PRIMARY KEY,
		owner_pubkey TEXT,
		sym_key_enc TEXT,
		replication_factor INTEGER
	);
	CREATE TABLE IF NOT EXISTS peers (
		id TEXT PRIMARY KEY,
		pubkey TEXT,
		addresses TEXT,
		last_seen DATETIME,
		latency_ms INTEGER
	);
	CREATE TABLE IF NOT EXISTS conflicts (
		id TEXT PRIMARY KEY,
		file_path TEXT,
		manifest_a TEXT,
		manifest_b TEXT,
		detected_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS chunk_locations (
		chunk_hash TEXT NOT NULL,
		peer_id    TEXT NOT NULL,
		confirmed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (chunk_hash, peer_id)
	);
	CREATE INDEX IF NOT EXISTS idx_chunk_locations_hash ON chunk_locations(chunk_hash);
	CREATE INDEX IF NOT EXISTS idx_chunk_locations_peer ON chunk_locations(peer_id);`

	_, err = s.db.ExecContext(context.Background(), schema)
	if err != nil {
		return err
	}
	// MVP: add human-readable space name (ignore error if column already exists).
	_, _ = s.db.ExecContext(context.Background(), `ALTER TABLE spaces ADD COLUMN name TEXT DEFAULT ''`)
	return nil
}

func (s *SQLiteStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *SQLiteStore) UpsertChunk(hash, filePath string, size int64) error {
	if s.db == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	_, err := s.db.ExecContext(
		context.Background(),
		`INSERT OR REPLACE INTO chunks (hash, file_path, size) VALUES (?, ?, ?)`,
		hash,
		filePath,
		size,
	)
	return err
}

func (s *SQLiteStore) GetChunkPath(hash string) (string, error) {
	if s.db == nil {
		return "", fmt.Errorf("sqlite not initialized")
	}
	var path string
	err := s.db.QueryRowContext(
		context.Background(),
		`SELECT file_path FROM chunks WHERE hash = ?`,
		hash,
	).Scan(&path)
	if err != nil {
		return "", err
	}
	return path, nil
}

// UpsertPeer records or updates a known peer's addresses and last-seen time.
func (s *SQLiteStore) UpsertPeer(id, pubkey, addresses string, latencyMs int64) error {
	if s.db == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	_, err := s.db.ExecContext(
		context.Background(),
		`INSERT INTO peers (id, pubkey, addresses, last_seen, latency_ms)
		 VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   pubkey=excluded.pubkey,
		   addresses=excluded.addresses,
		   last_seen=CURRENT_TIMESTAMP,
		   latency_ms=excluded.latency_ms`,
		id, pubkey, addresses, latencyMs,
	)
	return err
}

// GetPeer looks up a peer by its ID. Returns sql.ErrNoRows if not found.
func (s *SQLiteStore) GetPeer(id string) (pubkey, addresses string, latencyMs int64, err error) {
	if s.db == nil {
		return "", "", 0, fmt.Errorf("sqlite not initialized")
	}
	err = s.db.QueryRowContext(
		context.Background(),
		`SELECT pubkey, addresses, latency_ms FROM peers WHERE id = ?`,
		id,
	).Scan(&pubkey, &addresses, &latencyMs)
	return
}

// RecordChunkLocation records that a given peer holds a specific chunk.
func (s *SQLiteStore) RecordChunkLocation(chunkHash, peerID string) error {
	if s.db == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	_, err := s.db.ExecContext(
		context.Background(),
		`INSERT INTO chunk_locations (chunk_hash, peer_id, confirmed_at)
		 VALUES (?, ?, CURRENT_TIMESTAMP)
		 ON CONFLICT(chunk_hash, peer_id) DO UPDATE SET confirmed_at=CURRENT_TIMESTAMP`,
		chunkHash, peerID,
	)
	return err
}

// GetChunkPeers returns the IDs of all peers known to hold a given chunk.
func (s *SQLiteStore) GetChunkPeers(chunkHash string) ([]string, error) {
	if s.db == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	rows, err := s.db.QueryContext(
		context.Background(),
		`SELECT peer_id FROM chunk_locations WHERE chunk_hash = ? ORDER BY confirmed_at DESC`,
		chunkHash,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var peers []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		peers = append(peers, p)
	}
	return peers, rows.Err()
}

// GetPeerChunks returns all chunk hashes known to be held by a given peer.
func (s *SQLiteStore) GetPeerChunks(peerID string) ([]string, error) {
	if s.db == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	rows, err := s.db.QueryContext(
		context.Background(),
		`SELECT chunk_hash FROM chunk_locations WHERE peer_id = ? ORDER BY confirmed_at DESC`,
		peerID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hashes []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		hashes = append(hashes, h)
	}
	return hashes, rows.Err()
}

// RemoveChunkLocation removes the record that a peer holds a chunk
// (e.g. after confirming the peer has evicted it).
func (s *SQLiteStore) RemoveChunkLocation(chunkHash, peerID string) error {
	if s.db == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	_, err := s.db.ExecContext(
		context.Background(),
		`DELETE FROM chunk_locations WHERE chunk_hash = ? AND peer_id = ?`,
		chunkHash, peerID,
	)
	return err
}
