package node

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"vault-backend/internal/api"
	"vault-backend/internal/crypto"
	"vault-backend/internal/network"
	"vault-backend/internal/relay"
	"vault-backend/internal/store"
	syncpkg "vault-backend/internal/sync"
)

const defaultRelayPoll = 15 * time.Second

// Config holds runtime settings for a Vault node.
type Config struct {
	DBPath       string
	WALPath      string
	ChunkPath    string
	IdentityPath string
	OutputDir    string
	PeerID       string
	APIPort      int
	MDNSPort     int
	RelayAddr    string
	SpaceID      string
}

// Node wires storage, sync coordinator, discovery, and API together.
type Node struct {
	cfg       Config
	engine    *store.Engine
	identity  *crypto.Identity
	space     *crypto.Space
	transport *network.Transport
	relay     *relay.Client
	coord     *syncpkg.Coordinator
	discovery *network.Discovery

	mu     sync.RWMutex
	online bool
}

// New creates a Node from config. Call Run to start background workers.
func New(cfg Config) *Node {
	return &Node{
		cfg:       cfg,
		transport: network.NewTransport(),
		discovery: network.NewDiscovery(),
	}
}

// Init opens storage and loads identity/space.
func (n *Node) Init() error {
	if err := os.MkdirAll(filepath.Dir(n.cfg.DBPath), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(n.cfg.WALPath), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(n.cfg.OutputDir, 0o755); err != nil {
		return err
	}

	n.engine = store.NewEngineWithChunkDir(n.cfg.DBPath, n.cfg.WALPath, n.cfg.ChunkPath)
	if err := n.engine.Init(); err != nil {
		return err
	}

	id, err := loadOrGenerateIdentity(n.cfg.IdentityPath)
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	n.identity = id

	if n.cfg.SpaceID != "" {
		space, _, err := n.engine.GetSpace(n.cfg.SpaceID)
		if err != nil {
			return fmt.Errorf("load space: %w", err)
		}
		n.space = space
	}

	if n.cfg.RelayAddr != "" {
		n.relay = relay.NewClient(n.cfg.RelayAddr)
	}

	n.coord = syncpkg.NewCoordinator(n.engine, n.makeDeliveryFunc())
	return nil
}

// Run starts coordinator, mDNS, relay polling, and the HTTP API until ctx is cancelled.
func (n *Node) Run(ctx context.Context) error {
	if n.engine == nil {
		if err := n.Init(); err != nil {
			return err
		}
	}

	n.mu.Lock()
	n.online = true
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		n.online = false
		n.mu.Unlock()
	}()

	errCh := make(chan error, 3)

	go func() {
		n.coord.Run(ctx)
	}()

	if n.cfg.MDNSPort > 0 && n.cfg.PeerID != "" {
		go func() {
			srv, err := n.discovery.StartmDNS(ctx, n.cfg.PeerID, n.cfg.MDNSPort)
			if err != nil {
				errCh <- fmt.Errorf("mdns register: %w", err)
				return
			}
			defer srv.Shutdown()
			if err := n.discovery.BrowsePeers(ctx, n.coord); err != nil && ctx.Err() == nil {
				errCh <- fmt.Errorf("mdns browse: %w", err)
			}
		}()
	}

	if n.relay != nil && n.cfg.PeerID != "" {
		go n.relayPollLoop(ctx)
	}

	apiSrv := api.NewServer(n.cfg.APIPort, n)
	go func() {
		if err := apiSrv.Start(); err != nil && ctx.Err() == nil {
			errCh <- fmt.Errorf("api: %w", err)
		}
	}()

	log.Printf("[node] running peer=%s api=:%d relay=%s", n.cfg.PeerID, n.cfg.APIPort, n.cfg.RelayAddr)

	select {
	case <-ctx.Done():
		_ = n.engine.Close()
		return ctx.Err()
	case err := <-errCh:
		_ = n.engine.Close()
		return err
	}
}

func (n *Node) relayPollLoop(ctx context.Context) {
	ticker := time.NewTicker(defaultRelayPoll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rt := &network.RelayTransfer{Client: n.relay}
			out, err := rt.ReceiveFile(ctx, n.cfg.PeerID, n.cfg.OutputDir, n.engine)
			if err != nil {
				continue
			}
			log.Printf("[node] received file via relay: %s", out)
		}
	}
}

func (n *Node) makeDeliveryFunc() syncpkg.DeliveryFunc {
	return func(ctx context.Context, peerID string, entry *store.WALEntry) error {
		var payload map[string]string
		if err := json.Unmarshal(entry.Payload, &payload); err != nil {
			return fmt.Errorf("bad WAL payload: %w", err)
		}

		filePath := payload["file_path"]
		peerAddr := payload["peer_addr"]
		if peerAddr == "" {
			peerAddr = peerID
		}

		token, spaceKey, recipientID, err := n.loadTransferAuth(payload)
		if err != nil {
			return err
		}

		d := &network.Deliverer{
			Transport:   n.transport,
			Relay:       n.relay,
			AuthToken:   token,
			SpaceKey:    spaceKey,
			PeerAddr:    peerAddr,
			RecipientID: recipientID,
		}
		return d.SendFile(ctx, filePath, n.engine, network.DeliverOptions{
			Parallelism: 1,
			Resume:      true,
		})
	}
}

func (n *Node) loadTransferAuth(payload map[string]string) (*crypto.SignedToken, []byte, string, error) {
	recipientID := payload["recipient_id"]
	if recipientID == "" {
		recipientID = payload["peer_addr"]
	}

	if tokJSON := payload["auth_token"]; tokJSON != "" {
		tok, err := crypto.UnmarshalToken([]byte(tokJSON))
		if err != nil {
			return nil, nil, "", err
		}
		var ct crypto.CapabilityToken
		_ = json.Unmarshal(tok.Payload, &ct)
		space, _, err := n.engine.GetSpace(ct.SpaceID)
		if err != nil {
			if n.space != nil && n.space.ID == ct.SpaceID {
				return tok, n.space.SymmetricKey, recipientID, nil
			}
			return nil, nil, "", err
		}
		return tok, space.SymmetricKey, recipientID, nil
	}

	if n.space != nil {
		if n.identity == nil {
			return nil, n.space.SymmetricKey, recipientID, nil
		}
		// Self-issued token for local space transfers.
		tok, err := crypto.IssueToken(n.identity, n.identity.PublicKey, n.space.ID, crypto.PermWrite, 24*time.Hour)
		if err != nil {
			return nil, nil, "", err
		}
		return tok, n.space.SymmetricKey, recipientID, nil
	}

	return nil, nil, recipientID, nil
}

func loadOrGenerateIdentity(path string) (*crypto.Identity, error) {
	if _, err := os.Stat(path); err == nil {
		return crypto.LoadIdentity(path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	id, err := crypto.GenerateIdentity()
	if err != nil {
		return nil, err
	}
	if err := crypto.SaveIdentity(path, id); err != nil {
		return nil, err
	}
	return id, nil
}

// Engine exposes the storage engine (for CLI helpers).
func (n *Node) Engine() *store.Engine { return n.engine }

// Coordinator exposes the sync coordinator.
func (n *Node) Coordinator() *syncpkg.Coordinator { return n.coord }

// Identity returns the node identity.
func (n *Node) Identity() *crypto.Identity { return n.identity }

// Space returns the configured default space.
func (n *Node) Space() *crypto.Space { return n.space }

// StatusSnapshot returns current node status for the dashboard API.
func (n *Node) StatusSnapshot() api.StatusSnapshot {
	n.mu.RLock()
	online := n.online
	n.mu.RUnlock()

	pending := 0
	if n.engine != nil {
		entries, err := n.engine.GetAllPendingWAL()
		if err == nil {
			pending = len(entries)
		}
	}

	st := api.StatusSnapshot{
		Online:       online,
		Version:      "1.0.0-mvp",
		PeerID:       n.cfg.PeerID,
		PendingQueue: pending,
		RelayAddr:    n.cfg.RelayAddr,
	}
	if n.identity != nil {
		st.IdentityPubKey = hex.EncodeToString(n.identity.PublicKey)
	}
	return st
}
