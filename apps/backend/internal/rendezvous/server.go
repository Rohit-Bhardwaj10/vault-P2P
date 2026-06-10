// Package rendezvous implements a lightweight peer-address registry.
// Peers POST their public QUIC address on start-up and GET the address of
// a target peer when they want to initiate a direct connection.
//
// This replaces Kademlia DHT for the 90% case: two peers that share a
// rendezvous server on the internet can discover each other's routable
// address and attempt NAT hole punching.  The relay remains the fallback.
package rendezvous

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

const defaultTTL = 5 * time.Minute

// record is one registered peer entry.
type record struct {
	Addr      string    `json:"addr"`       // public QUIC address (host:port)
	ExpiresAt time.Time `json:"expires_at"` // evicted after this
}

// Server is the rendezvous HTTP server.
type Server struct {
	addr string
	ttl  time.Duration

	mu    sync.RWMutex
	peers map[string]*record // peerID → record
}

// NewServer creates a rendezvous server that listens on addr.
// ttl is how long a registration lasts before expiry (0 → defaultTTL).
func NewServer(addr string, ttl time.Duration) *Server {
	if ttl == 0 {
		ttl = defaultTTL
	}
	return &Server{
		addr:  addr,
		ttl:   ttl,
		peers: make(map[string]*record),
	}
}

// Run starts the HTTP server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /peers/{id}", s.handleRegister)
	mux.HandleFunc("GET /peers/{id}", s.handleLookup)
	mux.HandleFunc("GET /peers", s.handleList)
	mux.HandleFunc("GET /health", s.handleHealth)

	srv := &http.Server{
		Addr:    s.addr,
		Handler: mux,
	}

	// Background eviction loop.
	go s.evictLoop(ctx)

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

// Register registers a peer in-process (useful for the embedded case).
func (s *Server) Register(peerID, addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peers[peerID] = &record{Addr: addr, ExpiresAt: time.Now().Add(s.ttl)}
}

// Lookup returns the QUIC address for peerID, or "" if not found / expired.
func (s *Server) Lookup(peerID string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.peers[peerID]
	if !ok || time.Now().After(r.ExpiresAt) {
		return ""
	}
	return r.Addr
}

// --- HTTP handlers ---

// POST /peers/{id}   body: {"addr":"1.2.3.4:5000"}
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	peerID := r.PathValue("id")
	if peerID == "" {
		http.Error(w, "missing peer id", http.StatusBadRequest)
		return
	}

	var req struct {
		Addr string `json:"addr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Addr == "" {
		http.Error(w, "invalid body: need {\"addr\":\"host:port\"}", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	s.peers[peerID] = &record{Addr: req.Addr, ExpiresAt: time.Now().Add(s.ttl)}
	s.mu.Unlock()

	log.Printf("[rendezvous] registered peer %s at %s", peerID, req.Addr)
	w.WriteHeader(http.StatusCreated)
}

// GET /peers/{id}   → {"addr":"1.2.3.4:5000","expires_at":"..."}
func (s *Server) handleLookup(w http.ResponseWriter, r *http.Request) {
	peerID := r.PathValue("id")
	s.mu.RLock()
	rec, ok := s.peers[peerID]
	s.mu.RUnlock()

	if !ok || time.Now().After(rec.ExpiresAt) {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rec)
}

// GET /peers   → [{"id":"...","addr":"..."},...]
func (s *Server) handleList(w http.ResponseWriter, _ *http.Request) {
	type entry struct {
		ID   string `json:"id"`
		Addr string `json:"addr"`
	}
	now := time.Now()
	s.mu.RLock()
	out := make([]entry, 0, len(s.peers))
	for id, rec := range s.peers {
		if now.Before(rec.ExpiresAt) {
			out = append(out, entry{ID: id, Addr: rec.Addr})
		}
	}
	s.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "ok")
}

// evictLoop removes expired records every ttl/2.
func (s *Server) evictLoop(ctx context.Context) {
	tick := time.NewTicker(s.ttl / 2)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.evict()
		}
	}
}

func (s *Server) evict() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, rec := range s.peers {
		if now.After(rec.ExpiresAt) {
			log.Printf("[rendezvous] evicted expired peer %s", id)
			delete(s.peers, id)
		}
	}
}
