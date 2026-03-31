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
	);`

	_, err = s.db.ExecContext(context.Background(), schema)
	return err
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
