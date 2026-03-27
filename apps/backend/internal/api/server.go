package api

import (
	"encoding/json"
	"net/http"
)

// Server handles HTTP and WebSocket connections for the UI dashboard
type Server struct {
	port int
}

func NewServer(port int) *Server {
	return &Server{port: port}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
	
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "online",
			"version": "1.0.0",
		})
	})

	// TODO: Add WebSocket endpoint for real-time updates

	return http.ListenAndServe(":8080", mux)
}
