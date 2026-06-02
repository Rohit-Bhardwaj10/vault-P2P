package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"

	"vault-backend/internal/crypto"
)

// SaveSpace persists a space and its symmetric key (hex-encoded at rest for MVP).
func (e *Engine) SaveSpace(space *crypto.Space, ownerPubkey string) error {
	if e.sqlite.db == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	keyHex := hex.EncodeToString(space.SymmetricKey)
	_, err := e.sqlite.db.ExecContext(
		context.Background(),
		`INSERT INTO spaces (id, owner_pubkey, sym_key_enc, replication_factor, name)
		 VALUES (?, ?, ?, 1, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   owner_pubkey=excluded.owner_pubkey,
		   sym_key_enc=excluded.sym_key_enc,
		   name=excluded.name`,
		space.ID, ownerPubkey, keyHex, space.Name,
	)
	return err
}

// GetSpace loads a space by ID.
func (e *Engine) GetSpace(id string) (*crypto.Space, string, error) {
	if e.sqlite.db == nil {
		return nil, "", fmt.Errorf("sqlite not initialized")
	}
	var ownerPub, keyHex, name string
	var rf int
	err := e.sqlite.db.QueryRowContext(
		context.Background(),
		`SELECT owner_pubkey, sym_key_enc, replication_factor, COALESCE(name, '') FROM spaces WHERE id = ?`,
		id,
	).Scan(&ownerPub, &keyHex, &rf, &name)
	if err == sql.ErrNoRows {
		return nil, "", fmt.Errorf("space not found: %s", id)
	}
	if err != nil {
		return nil, "", err
	}
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, "", fmt.Errorf("decode space key: %w", err)
	}
	if len(keyBytes) != crypto.SpaceKeySize {
		return nil, "", fmt.Errorf("invalid stored key length %d", len(keyBytes))
	}
	space := &crypto.Space{
		ID:           id,
		Name:         name,
		SymmetricKey: keyBytes,
	}
	return space, ownerPub, nil
}

// ListSpaces returns all space IDs.
func (e *Engine) ListSpaces() ([]string, error) {
	if e.sqlite.db == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	rows, err := e.sqlite.db.QueryContext(context.Background(), `SELECT id FROM spaces ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
