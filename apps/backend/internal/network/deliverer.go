package network

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"vault-backend/internal/crypto"
	"vault-backend/internal/holepunch"
	"vault-backend/internal/relay"
	"vault-backend/internal/rendezvous"
	"vault-backend/internal/store"
)

// Deliverer sends files with a three-tier priority:
//  1. Direct QUIC (if PeerAddr is known)
//  2. NAT hole punching via the rendezvous server (primary WAN path)
//  3. Relay store-and-forward (fallback only)
type Deliverer struct {
	Transport   *Transport
	Relay       *relay.Client
	Rendezvous  *rendezvous.Client // optional; enables hole punching
	AuthToken   *crypto.SignedToken
	SpaceKey    []byte
	PeerAddr    string // last-known direct address (may be empty)
	RecipientID string // peer's ID used for relay and rendezvous lookup
}

// DeliverOptions configures a single delivery attempt.
type DeliverOptions struct {
	Parallelism int
	Resume      bool
	ForceRelay  bool                         // skip direct + hole punch, go straight to relay
	OnProgress  func(sent, total int64)      // optional progress callback
}

// SendFile delivers filePath to the configured peer using the best available path.
func (d *Deliverer) SendFile(ctx context.Context, filePath string, engine *store.Engine, opts DeliverOptions) error {
	if opts.Parallelism < 1 {
		opts.Parallelism = 1
	}

	sessionKey, err := d.sessionKey()
	if err != nil {
		return err
	}
	relayKey := sessionKey
	if len(relayKey) == 0 {
		relayKey = d.SpaceKey
	}

	sendOpts := SendOptions{
		Parallelism: opts.Parallelism,
		Resume:      opts.Resume,
		AuthToken:   d.AuthToken,
		SpaceKey:    d.SpaceKey,
		OnProgress:  opts.OnProgress,
	}

	if d.Transport == nil {
		d.Transport = NewTransport()
	}

	if !opts.ForceRelay {
		// --- Tier 1: direct QUIC (address already known) ---
		if d.PeerAddr != "" {
			err := d.Transport.SendFileWithOptions(ctx, d.PeerAddr, filePath, engine, sendOpts)
			if err == nil {
				return nil
			}
			log.Printf("[deliverer] direct QUIC to %s failed: %v — trying hole punch", d.PeerAddr, err)
		}

		// --- Tier 2: NAT hole punching via rendezvous ---
		if d.Rendezvous != nil && d.RecipientID != "" {
			addr, lookupErr := d.Rendezvous.Lookup(d.RecipientID)
			if lookupErr != nil {
				log.Printf("[deliverer] rendezvous lookup for %s: %v", d.RecipientID, lookupErr)
			} else if addr != "" {
				puncher := holepunch.NewPuncher(":0", nil)
				qConn, punchErr := puncher.Punch(ctx, addr)
				if punchErr == nil {
					// We have a direct QUIC connection — use it.
					defer qConn.CloseWithError(0, "done")
					// Upgrade the punched connection into a file transfer.
					err := d.Transport.SendFileOverConn(ctx, qConn, filePath, engine, sendOpts)
					if err == nil {
						return nil
					}
					log.Printf("[deliverer] file send over punched conn failed: %v — falling back to relay", err)
				} else {
					log.Printf("[deliverer] hole punch to %s failed: %v — falling back to relay", addr, punchErr)
				}
			}
		}

		// No relay configured — surface the error.
		if d.Relay == nil {
			return fmt.Errorf("all direct paths failed and no relay configured")
		}
	}

	// --- Tier 3: relay store-and-forward ---
	if d.Relay == nil {
		return fmt.Errorf("relay not configured")
	}
	recipient := d.RecipientID
	if recipient == "" {
		recipient = d.PeerAddr
	}

	spaceID := ""
	if d.AuthToken != nil {
		var tok crypto.CapabilityToken
		_ = json.Unmarshal(d.AuthToken.Payload, &tok)
		spaceID = tok.SpaceID
	}

	log.Printf("[deliverer] using relay for peer %s", recipient)
	rt := &RelayTransfer{Client: d.Relay, SessionKey: relayKey}
	_, err = rt.SendFile(ctx, recipient, filePath, spaceID)
	if err != nil {
		return fmt.Errorf("relay transfer: %w", err)
	}
	return nil
}

func (d *Deliverer) sessionKey() ([]byte, error) {
	if d.AuthToken == nil || len(d.SpaceKey) == 0 {
		return nil, nil
	}
	return DeriveTransferSessionKey(d.SpaceKey, d.AuthToken)
}
