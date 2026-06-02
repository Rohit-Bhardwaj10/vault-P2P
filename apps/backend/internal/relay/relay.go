// Package relay implements a minimal store-and-forward relay server.
//
// When two peers cannot reach each other directly (offline peer, firewall, etc.),
// the sender can push encrypted chunks to the relay. When the recipient comes
// online, it connects and drains its inbox.
//
// Protocol (over plain TCP, intentionally simple):
//
//	Client → Server: JSON request line
//	Server → Client: JSON response line
//
// Supported operations:
//   - {"op":"push","peer_id":"<recipient>","chunk_hash":"<hash>","data":"<base64>"}
//   - {"op":"pull","peer_id":"<my_id>"}
//   - {"op":"ping"}
package relay

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"sync"
	"time"
	"os"

	"go.etcd.io/bbolt"
)

// MaxChunkSize is the largest chunk payload (bytes) the relay will buffer per message.
const MaxChunkSize = 8 * 1024 * 1024 // 8 MiB

var bucketInbox = []byte("inbox")

// RelayedChunk is a buffered chunk waiting for a recipient to pull it.
type RelayedChunk struct {
	ChunkHash string    `json:"chunk_hash"`
	Data      []byte    `json:"data"`
	PushedAt  time.Time `json:"pushed_at"`
}

// Server is a lightweight relay that buffers encrypted chunks for offline peers.
type Server struct {
	addr   string
	dbPath string
	db     *bbolt.DB

	mu     sync.Mutex
	maxAge time.Duration // how long to keep buffered chunks
}

// NewServer creates a relay Server that listens on addr.
// maxAge is how long chunks are kept before being evicted (0 = keep forever).
func NewServer(addr, dbPath string, maxAge time.Duration) *Server {
	return &Server{
		addr:   addr,
		dbPath: dbPath,
		maxAge: maxAge,
	}
}

// Init creates the database and buckets.
func (s *Server) Init() error {
	if s.db != nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.dbPath), 0o755); err != nil {
		return fmt.Errorf("create relay db dir: %w", err)
	}
	db, err := bbolt.Open(s.dbPath, 0o600, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return fmt.Errorf("open relay db: %w", err)
	}
	s.db = db

	if err := s.db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketInbox)
		return err
	}); err != nil {
		return fmt.Errorf("create relay bucket: %w", err)
	}
	return nil
}

// Close gracefully closes the database.
func (s *Server) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Run starts the relay server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	if err := s.Init(); err != nil {
		return err
	}
	// We handle DB Close() manually in cmd or here if we want, but it's safe to defer it here for simple lifecycle.
	defer s.Close()

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("relay listen %s: %w", s.addr, err)
	}
	log.Printf("[relay] listening on %s, db %s", s.addr, s.dbPath)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	// Eviction goroutine.
	if s.maxAge > 0 {
		go s.runEviction(ctx)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("[relay] accept error: %v", err)
				continue
			}
		}
		go s.handleConn(conn)
	}
}

// Push inserts a chunk into a peer's inbox.
func (s *Server) Push(recipientID, chunkHash string, data []byte) error {
	if len(data) > MaxChunkSize {
		return fmt.Errorf("chunk too large: %d bytes", len(data))
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketInbox)
		peerBucket, err := b.CreateBucketIfNotExists([]byte(recipientID))
		if err != nil {
			return err
		}
		seq, _ := peerBucket.NextSequence()
		key := []byte(fmt.Sprintf("%010d", seq))
		
		chunk := &RelayedChunk{
			ChunkHash: chunkHash,
			Data:      data,
			PushedAt:  time.Now(),
		}
		encoded, err := json.Marshal(chunk)
		if err != nil {
			return err
		}
		return peerBucket.Put(key, encoded)
	})
}

// Pull drains and returns all buffered chunks for a given peer.
func (s *Server) Pull(peerID string) []*RelayedChunk {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	var chunks []*RelayedChunk
	
	_ = s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketInbox)
		peerBucket := b.Bucket([]byte(peerID))
		if peerBucket == nil {
			return nil // no inbox for peer
		}
		
		_ = peerBucket.ForEach(func(k, v []byte) error {
			var chunk RelayedChunk
			if err := json.Unmarshal(v, &chunk); err == nil {
				chunks = append(chunks, &chunk)
			}
			return nil
		})
		
		// Drain by deleting the bucket
		return b.DeleteBucket([]byte(peerID))
	})
	
	return chunks
}

// InboxSize returns how many chunks are buffered for a given peer.
func (s *Server) InboxSize(peerID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	var count int
	_ = s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketInbox)
		peerBucket := b.Bucket([]byte(peerID))
		if peerBucket == nil {
			return nil
		}
		count = peerBucket.Stats().KeyN
		return nil
	})
	return count
}

// -- Wire protocol -------------------------------------------------------

type request struct {
	Op        string `json:"op"`
	PeerID    string `json:"peer_id"`
	ChunkHash string `json:"chunk_hash,omitempty"`
	Data      string `json:"data,omitempty"` // base64-encoded
}

type response struct {
	OK     bool          `json:"ok"`
	Error  string        `json:"error,omitempty"`
	Chunks []wireChunk   `json:"chunks,omitempty"`
}

type wireChunk struct {
	ChunkHash string `json:"chunk_hash"`
	Data      string `json:"data"` // base64-encoded
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	enc := json.NewEncoder(conn)

	for scanner.Scan() {
		var req request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			_ = enc.Encode(response{OK: false, Error: "invalid JSON"})
			continue
		}

		var resp response
		switch req.Op {
		case "ping":
			resp = response{OK: true}

		case "push":
			if req.PeerID == "" || req.ChunkHash == "" || req.Data == "" {
				resp = response{OK: false, Error: "push requires peer_id, chunk_hash, data"}
				break
			}
			data, err := base64.StdEncoding.DecodeString(req.Data)
			if err != nil {
				resp = response{OK: false, Error: "invalid base64 data"}
				break
			}
			if err := s.Push(req.PeerID, req.ChunkHash, data); err != nil {
				resp = response{OK: false, Error: err.Error()}
				break
			}
			resp = response{OK: true}

		case "pull":
			if req.PeerID == "" {
				resp = response{OK: false, Error: "pull requires peer_id"}
				break
			}
			chunks := s.Pull(req.PeerID)
			wc := make([]wireChunk, len(chunks))
			for i, c := range chunks {
				wc[i] = wireChunk{
					ChunkHash: c.ChunkHash,
					Data:      base64.StdEncoding.EncodeToString(c.Data),
				}
			}
			resp = response{OK: true, Chunks: wc}

		default:
			resp = response{OK: false, Error: fmt.Sprintf("unknown op %q", req.Op)}
		}

		if err := enc.Encode(resp); err != nil {
			log.Printf("[relay] encode response: %v", err)
			return
		}
	}
}

func (s *Server) runEviction(ctx context.Context) {
	ticker := time.NewTicker(s.maxAge / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.evict()
		}
	}
}

func (s *Server) evict() {
	cutoff := time.Now().Add(-s.maxAge)
	s.mu.Lock()
	defer s.mu.Unlock()

	_ = s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketInbox)
		if b == nil {
			return nil
		}

		// Find all peer buckets
		c := b.Cursor()
		var peers [][]byte
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if v == nil { // bucket
				peers = append(peers, k)
			}
		}

		for _, peer := range peers {
			peerBucket := b.Bucket(peer)
			if peerBucket == nil {
				continue
			}

			// Find expired chunks
			pc := peerBucket.Cursor()
			var expired [][]byte
			for k, v := pc.First(); k != nil; k, v = pc.Next() {
				var chunk RelayedChunk
				if err := json.Unmarshal(v, &chunk); err == nil {
					if chunk.PushedAt.Before(cutoff) {
						expired = append(expired, k)
					}
				}
			}

			// Delete expired chunks
			for _, k := range expired {
				_ = peerBucket.Delete(k)
			}

			// Delete bucket if empty
			if peerBucket.Stats().KeyN == 0 {
				_ = b.DeleteBucket(peer)
			}
		}
		return nil
	})
}
