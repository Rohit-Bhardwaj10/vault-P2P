package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"vault-backend/internal/chunk"
)

// StoredChunk captures metadata for a persisted chunk.
type StoredChunk struct {
	Hash string
	Path string
	Size int64
}

func (e *Engine) WriteChunk(sourcePath string, data []byte) (*StoredChunk, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("chunk data is empty")
	}
	if e.sqlite == nil {
		return nil, fmt.Errorf("sqlite store not configured")
	}
	if e.chunkDir == "" {
		return nil, fmt.Errorf("chunk directory is not configured")
	}

	hash := chunk.HashChunk(data)
	chunkPath := filepath.Join(e.chunkDir, hash+".chunk")

	if err := os.MkdirAll(e.chunkDir, 0o755); err != nil {
		return nil, fmt.Errorf("create chunk directory: %w", err)
	}

	// Chunks are content-addressed, so existing files can be reused safely.
	if _, err := os.Stat(chunkPath); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("stat chunk file: %w", err)
		}
		tmpFile, err := os.CreateTemp(e.chunkDir, hash+"-*.tmp")
		if err != nil {
			return nil, fmt.Errorf("create temporary chunk file: %w", err)
		}
		tmpName := tmpFile.Name()
		if _, err := tmpFile.Write(data); err != nil {
			_ = tmpFile.Close()
			_ = os.Remove(tmpName)
			return nil, fmt.Errorf("write temporary chunk file: %w", err)
		}
		if err := tmpFile.Close(); err != nil {
			_ = os.Remove(tmpName)
			return nil, fmt.Errorf("close temporary chunk file: %w", err)
		}
		if err := os.Rename(tmpName, chunkPath); err != nil {
			_ = os.Remove(tmpName)
			if !os.IsExist(err) {
				return nil, fmt.Errorf("commit chunk file: %w", err)
			}
		}
	}

	if err := e.sqlite.UpsertChunk(hash, chunkPath, int64(len(data))); err != nil {
		return nil, fmt.Errorf("persist chunk metadata: %w", err)
	}

	return &StoredChunk{Hash: hash, Path: chunkPath, Size: int64(len(data))}, nil
}

func (e *Engine) ReadChunk(hash string) ([]byte, error) {
	if e.sqlite == nil {
		return nil, fmt.Errorf("sqlite store not configured")
	}
	chunkPath, err := e.sqlite.GetChunkPath(hash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("chunk %s not found", hash)
		}
		return nil, fmt.Errorf("lookup chunk metadata: %w", err)
	}
	data, err := os.ReadFile(chunkPath)
	if err != nil {
		return nil, fmt.Errorf("read chunk file: %w", err)
	}
	return data, nil
}

func (e *Engine) VerifyChunk(hash string) (bool, error) {
	data, err := e.ReadChunk(hash)
	if err != nil {
		return false, err
	}
	return chunk.HashChunk(data) == hash, nil
}
