package network

import (
	"context"
	"encoding/json"
	"fmt"

	"vault-backend/internal/crypto"
	"vault-backend/internal/relay"
	"vault-backend/internal/store"
)

// Deliverer sends files over QUIC first, then falls back to the relay when direct transfer fails.
type Deliverer struct {
	Transport   *Transport
	Relay       *relay.Client
	AuthToken   *crypto.SignedToken
	SpaceKey    []byte
	PeerAddr    string
	RecipientID string
}

// DeliverOptions configures a single delivery attempt.
type DeliverOptions struct {
	Parallelism int
	Resume      bool
	ForceRelay  bool
}

// SendFile attempts direct QUIC transfer; on failure uses the relay if configured.
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

	if !opts.ForceRelay {
		sendOpts := SendOptions{
			Parallelism: opts.Parallelism,
			Resume:      opts.Resume,
			AuthToken:   d.AuthToken,
			SpaceKey:    d.SpaceKey,
		}
		if d.Transport == nil {
			d.Transport = NewTransport()
		}
		err := d.Transport.SendFileWithOptions(ctx, d.PeerAddr, filePath, engine, sendOpts)
		if err == nil {
			return nil
		}
		if d.Relay == nil {
			return fmt.Errorf("direct transfer failed and no relay configured: %w", err)
		}
	}

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
