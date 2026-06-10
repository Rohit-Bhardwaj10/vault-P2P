package rendezvous

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client talks to a remote rendezvous server over HTTP.
type Client struct {
	base string       // e.g. "http://rendezvous.example.com:8080"
	http *http.Client
}

// NewClient creates a Client targeting the given base URL.
func NewClient(baseURL string) *Client {
	return &Client{
		base: baseURL,
		http: &http.Client{Timeout: 10 * time.Second},
	}
}

// Register posts this peer's public QUIC address to the rendezvous server.
func (c *Client) Register(peerID, quicAddr string) error {
	body, _ := json.Marshal(map[string]string{"addr": quicAddr})
	resp, err := c.http.Post(c.base+"/peers/"+peerID, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("rendezvous register: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("rendezvous register: server returned %d: %s", resp.StatusCode, b)
	}
	return nil
}

// Lookup retrieves the public QUIC address of peerID.
// Returns ("", nil) if the peer is not registered.
func (c *Client) Lookup(peerID string) (string, error) {
	resp, err := c.http.Get(c.base + "/peers/" + peerID)
	if err != nil {
		return "", fmt.Errorf("rendezvous lookup: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("rendezvous lookup: server returned %d: %s", resp.StatusCode, b)
	}
	var rec struct {
		Addr string `json:"addr"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rec); err != nil {
		return "", fmt.Errorf("rendezvous lookup decode: %w", err)
	}
	return rec.Addr, nil
}

// Ping checks if the rendezvous server is reachable.
func (c *Client) Ping() error {
	resp, err := c.http.Get(c.base + "/health")
	if err != nil {
		return fmt.Errorf("rendezvous ping: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rendezvous ping: unexpected status %d", resp.StatusCode)
	}
	return nil
}
