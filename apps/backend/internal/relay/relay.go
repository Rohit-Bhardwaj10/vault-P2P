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
	"sync"
	"time"
)

// MaxChunkSize is the largest chunk payload (bytes) the relay will buffer per message.
const MaxChunkSize = 8 * 1024 * 1024 // 8 MiB

// RelayedChunk is a buffered chunk waiting for a recipient to pull it.
type RelayedChunk struct {
	ChunkHash string
	Data      []byte
	PushedAt  time.Time
}

// Server is a lightweight relay that buffers encrypted chunks for offline peers.
// Each peer has an inbox (a FIFO queue of RelayedChunks).
type Server struct {
	addr string

	mu     sync.Mutex
	inbox  map[string][]*RelayedChunk // peerID → pending chunks
	maxAge time.Duration              // how long to keep buffered chunks
}

// NewServer creates a relay Server that listens on addr.
// maxAge is how long chunks are kept before being evicted (0 = keep forever).
func NewServer(addr string, maxAge time.Duration) *Server {
	return &Server{
		addr:   addr,
		inbox:  make(map[string][]*RelayedChunk),
		maxAge: maxAge,
	}
}

// Run starts the relay server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("relay listen %s: %w", s.addr, err)
	}
	log.Printf("[relay] listening on %s", s.addr)

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

// Push directly inserts a chunk into a peer's inbox (useful for tests / same-process embedding).
func (s *Server) Push(recipientID, chunkHash string, data []byte) error {
	if len(data) > MaxChunkSize {
		return fmt.Errorf("chunk too large: %d bytes", len(data))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inbox[recipientID] = append(s.inbox[recipientID], &RelayedChunk{
		ChunkHash: chunkHash,
		Data:      data,
		PushedAt:  time.Now(),
	})
	return nil
}

// Pull drains and returns all buffered chunks for a given peer.
func (s *Server) Pull(peerID string) []*RelayedChunk {
	s.mu.Lock()
	defer s.mu.Unlock()
	chunks := s.inbox[peerID]
	delete(s.inbox, peerID)
	return chunks
}

// InboxSize returns how many chunks are buffered for a given peer.
func (s *Server) InboxSize(peerID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.inbox[peerID])
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
	for peer, chunks := range s.inbox {
		var keep []*RelayedChunk
		for _, c := range chunks {
			if c.PushedAt.After(cutoff) {
				keep = append(keep, c)
			}
		}
		if len(keep) == 0 {
			delete(s.inbox, peer)
		} else {
			s.inbox[peer] = keep
		}
	}
}
