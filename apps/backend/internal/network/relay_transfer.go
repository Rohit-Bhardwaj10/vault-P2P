package network

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"vault-backend/internal/chunk"
	"vault-backend/internal/crypto"
	"vault-backend/internal/relay"
	"vault-backend/internal/store"
)

const relayManifestPrefix = "manifest:"

// RelayManifest describes a file transfer buffered on the relay.
type RelayManifest struct {
	TransferID string `json:"transfer_id"`
	FileName   string `json:"file_name"`
	TotalSize  int64  `json:"total_size"`
	ChunkCount int    `json:"chunk_count"`
	SpaceID    string `json:"space_id,omitempty"`
}

// RelayTransfer sends a file via the store-and-forward relay (encrypted chunks).
type RelayTransfer struct {
	Client     *relay.Client
	SessionKey []byte
}

// SendFile chunks filePath, encrypts each chunk, and pushes to the relay inbox for recipientID.
func (rt *RelayTransfer) SendFile(ctx context.Context, recipientID, filePath, spaceID string) (transferID string, err error) {
	if rt.Client == nil {
		return "", fmt.Errorf("relay client is nil")
	}

	f, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("stat file: %w", err)
	}

	transferID, err = randomTransferID()
	if err != nil {
		return "", err
	}

	chunker := chunk.NewBufferedChunker(f)
	idx := 0
	for {
		if ctx.Err() != nil {
			return transferID, ctx.Err()
		}
		c, err := chunker.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return transferID, fmt.Errorf("chunk file: %w", err)
		}

		data := c.Data
		if len(rt.SessionKey) > 0 {
			data, err = ProtectChunk(rt.SessionKey, data)
			if err != nil {
				return transferID, fmt.Errorf("encrypt chunk %d: %w", idx, err)
			}
		}

		hashKey := relayChunkKey(transferID, idx, c.Hash)
		if err := rt.Client.PushChunk(recipientID, hashKey, data); err != nil {
			return transferID, fmt.Errorf("relay push chunk %d: %w", idx, err)
		}
		idx++
	}

	manifest := RelayManifest{
		TransferID: transferID,
		FileName:   filepath.Base(filePath),
		TotalSize:  info.Size(),
		ChunkCount: idx,
		SpaceID:    spaceID,
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return transferID, err
	}
	if len(rt.SessionKey) > 0 {
		manifestBytes, err = ProtectChunk(rt.SessionKey, manifestBytes)
		if err != nil {
			return transferID, fmt.Errorf("encrypt manifest: %w", err)
		}
	}
	manifestKey := relayManifestPrefix + transferID
	if err := rt.Client.PushChunk(recipientID, manifestKey, manifestBytes); err != nil {
		return transferID, fmt.Errorf("relay push manifest: %w", err)
	}

	return transferID, nil
}

// ReceiveFile pulls relayed chunks for myPeerID and writes the first complete transfer to outputDir.
// When engine is provided, chunk decryption uses the space key from the manifest SpaceID.
func (rt *RelayTransfer) ReceiveFile(ctx context.Context, myPeerID, outputDir string, engine *store.Engine) (string, error) {
	if rt.Client == nil {
		return "", fmt.Errorf("relay client is nil")
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", err
	}

	chunks, err := rt.Client.PullChunks(myPeerID)
	if err != nil {
		return "", fmt.Errorf("relay pull: %w", err)
	}
	if len(chunks) == 0 {
		return "", fmt.Errorf("relay inbox empty for peer %s", myPeerID)
	}

	manifests := make(map[string]*RelayManifest)
	rawChunks := make(map[string]map[int][]byte) // transferID -> index -> encrypted data

	for _, rc := range chunks {
		if strings.HasPrefix(rc.ChunkHash, relayManifestPrefix) {
			transferID := strings.TrimPrefix(rc.ChunkHash, relayManifestPrefix)
			raw := rc.Data
			if len(rt.SessionKey) > 0 {
				raw, err = UnprotectChunk(rt.SessionKey, raw)
				if err != nil {
					return "", fmt.Errorf("decrypt manifest: %w", err)
				}
			}
			var m RelayManifest
			if err := json.Unmarshal(raw, &m); err != nil {
				return "", fmt.Errorf("parse manifest: %w", err)
			}
			manifests[transferID] = &m
			continue
		}

		transferID, index, _, perr := parseRelayChunkKey(rc.ChunkHash)
		if perr != nil {
			continue
		}
		if rawChunks[transferID] == nil {
			rawChunks[transferID] = make(map[int][]byte)
		}
		rawChunks[transferID][index] = rc.Data
	}

	if len(manifests) == 0 {
		return "", fmt.Errorf("no relay manifest found in inbox")
	}

	decryptKey := func(m *RelayManifest) ([]byte, error) {
		if len(rt.SessionKey) > 0 {
			return rt.SessionKey, nil
		}
		if engine != nil && m.SpaceID != "" {
			space, _, err := engine.GetSpace(m.SpaceID)
			if err != nil {
				return nil, err
			}
			return space.SymmetricKey, nil
		}
		return nil, nil
	}

	// Pick the first transfer with a complete set of chunks.
	var ids []string
	for id := range manifests {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		m := manifests[id]
		encrypted := rawChunks[id]
		if len(encrypted) < m.ChunkCount {
			continue
		}
		key, err := decryptKey(m)
		if err != nil {
			return "", err
		}

		outPath := filepath.Join(outputDir, filepath.Base(m.FileName))
		f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return "", err
		}
		for i := 0; i < m.ChunkCount; i++ {
			if ctx.Err() != nil {
				_ = f.Close()
				return "", ctx.Err()
			}
			enc, ok := encrypted[i]
			if !ok {
				_ = f.Close()
				return "", fmt.Errorf("missing chunk %d for transfer %s", i, id)
			}
			plain := enc
			if len(key) > 0 {
				plain, err = UnprotectChunk(key, enc)
				if err != nil {
					_ = f.Close()
					return "", fmt.Errorf("decrypt chunk %d: %w", i, err)
				}
			}
			if _, err := f.Write(plain); err != nil {
				_ = f.Close()
				return "", err
			}
		}
		if err := f.Close(); err != nil {
			return "", err
		}
		return outPath, nil
	}

	return "", fmt.Errorf("no complete relay transfer in inbox")
}

func relayChunkKey(transferID string, index int, hash string) string {
	return transferID + ":" + strconv.Itoa(index) + ":" + hash
}

func parseRelayChunkKey(key string) (transferID string, index int, hash string, err error) {
	parts := strings.SplitN(key, ":", 3)
	if len(parts) != 3 {
		return "", 0, "", fmt.Errorf("invalid relay chunk key %q", key)
	}
	index, err = strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, "", err
	}
	return parts[0], index, parts[2], nil
}

func randomTransferID() (string, error) {
	return crypto.RandomHex(16)
}
