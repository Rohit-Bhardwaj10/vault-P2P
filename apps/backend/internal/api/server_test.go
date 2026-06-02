package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type mockStatus struct {
	snap StatusSnapshot
}

func (m *mockStatus) StatusSnapshot() StatusSnapshot { return m.snap }

func TestStatusEndpoint(t *testing.T) {
	srv := NewServer(0, &mockStatus{snap: StatusSnapshot{
		Online:         true,
		Version:        "test",
		PeerID:         "api-peer",
		PendingQueue:   2,
		IdentityPubKey: "abc123",
	}})

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status code %d", rr.Code)
	}
	var st StatusSnapshot
	if err := json.Unmarshal(rr.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.PeerID != "api-peer" {
		t.Fatalf("peer id %q", st.PeerID)
	}
	if st.PendingQueue != 2 {
		t.Fatalf("pending %d", st.PendingQueue)
	}
}

func TestQueueEndpoint(t *testing.T) {
	srv := NewServer(0, &mockStatus{snap: StatusSnapshot{PendingQueue: 3}})
	req := httptest.NewRequest(http.MethodGet, "/api/queue", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code)
	}
}
