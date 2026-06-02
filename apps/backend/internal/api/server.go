package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

// StatusProvider supplies live node status for API handlers.
type StatusProvider interface {
	StatusSnapshot() StatusSnapshot
}

// StatusSnapshot mirrors node status for the HTTP API.
type StatusSnapshot struct {
	Online         bool   `json:"online"`
	Version        string `json:"version"`
	PeerID         string `json:"peer_id"`
	PendingQueue   int    `json:"pending_queue"`
	RelayAddr      string `json:"relay_addr,omitempty"`
	IdentityPubKey string `json:"identity_pubkey,omitempty"`
}

// QueueProvider optionally exposes pending WAL entries.
type QueueProvider interface {
	PendingQueueCount() int
}

// Server handles HTTP connections for the UI dashboard.
type Server struct {
	port     int
	provider StatusProvider
}

func NewServer(port int, provider StatusProvider) *Server {
	return &Server{port: port, provider: provider}
}

// Handler returns the HTTP mux for testing.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/queue", s.handleQueue)
	return mux
}

func (s *Server) Start() error {
	port := s.port
	if port <= 0 {
		port = 8080
	}
	return http.ListenAndServe(fmt.Sprintf(":%d", port), s.Handler())
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.provider != nil {
		_ = json.NewEncoder(w).Encode(s.provider.StatusSnapshot())
		return
	}
	_ = json.NewEncoder(w).Encode(StatusSnapshot{Online: true, Version: "1.0.0"})
}

func (s *Server) handleQueue(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	pending := 0
	if s.provider != nil {
		pending = s.provider.StatusSnapshot().PendingQueue
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"pending": pending})
}

func formatPort(port int) string {
	return strconv.Itoa(port)
}
