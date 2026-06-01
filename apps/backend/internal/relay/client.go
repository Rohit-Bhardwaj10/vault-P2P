package relay

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

const defaultDialTimeout = 10 * time.Second

// Client is a thin TCP client for the relay Server.
type Client struct {
	relayAddr string
}

// NewClient creates a relay Client that talks to relayAddr.
func NewClient(relayAddr string) *Client {
	return &Client{relayAddr: relayAddr}
}

// Ping checks whether the relay is reachable.
func (c *Client) Ping() error {
	conn, scanner, enc, err := c.connect()
	if err != nil {
		return err
	}
	defer conn.Close()
	return c.doRequest(scanner, enc, request{Op: "ping"})
}

// PushChunk sends an encrypted chunk to the relay for a recipient peer.
func (c *Client) PushChunk(recipientID, chunkHash string, data []byte) error {
	conn, scanner, enc, err := c.connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	return c.doRequest(scanner, enc, request{
		Op:        "push",
		PeerID:    recipientID,
		ChunkHash: chunkHash,
		Data:      base64.StdEncoding.EncodeToString(data),
	})
}

// PullChunks retrieves (and removes from relay inbox) all chunks buffered for myPeerID.
func (c *Client) PullChunks(myPeerID string) ([]*RelayedChunk, error) {
	conn, scanner, _, err := c.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	req := request{Op: "pull", PeerID: myPeerID}
	reqBytes, _ := json.Marshal(req)
	if _, err := fmt.Fprintf(conn, "%s\n", reqBytes); err != nil {
		return nil, fmt.Errorf("write pull request: %w", err)
	}

	var resp response
	if !scanner.Scan() {
		return nil, fmt.Errorf("no response from relay")
	}
	if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("decode pull response: %w", err)
	}
	if !resp.OK {
		return nil, fmt.Errorf("relay error: %s", resp.Error)
	}

	chunks := make([]*RelayedChunk, len(resp.Chunks))
	for i, wc := range resp.Chunks {
		data, err := base64.StdEncoding.DecodeString(wc.Data)
		if err != nil {
			return nil, fmt.Errorf("decode chunk %s: %w", wc.ChunkHash, err)
		}
		chunks[i] = &RelayedChunk{
			ChunkHash: wc.ChunkHash,
			Data:      data,
			PushedAt:  time.Now(),
		}
	}
	return chunks, nil
}

func (c *Client) connect() (net.Conn, *bufio.Scanner, *json.Encoder, error) {
	conn, err := net.DialTimeout("tcp", c.relayAddr, defaultDialTimeout)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("dial relay %s: %w", c.relayAddr, err)
	}
	return conn, bufio.NewScanner(conn), json.NewEncoder(conn), nil
}

func (c *Client) doRequest(scanner *bufio.Scanner, enc *json.Encoder, req request) error {
	if err := enc.Encode(req); err != nil {
		return fmt.Errorf("write request: %w", err)
	}
	if !scanner.Scan() {
		return fmt.Errorf("no response from relay")
	}
	var resp response
	if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if !resp.OK {
		return fmt.Errorf("relay error: %s", resp.Error)
	}
	return nil
}
