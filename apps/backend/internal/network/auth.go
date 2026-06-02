package network

import (
	"encoding/gob"
	"fmt"

	"vault-backend/internal/crypto"
)

// runClientAuth sends a signed capability token and waits for auth_ok.
func runClientAuth(enc *gob.Encoder, dec *gob.Decoder, token *crypto.SignedToken) error {
	if token == nil {
		return nil
	}
	tokBytes, err := crypto.MarshalToken(token)
	if err != nil {
		return fmt.Errorf("marshal auth token: %w", err)
	}
	if err := enc.Encode(packet{Type: "auth", Data: tokBytes}); err != nil {
		return fmt.Errorf("send auth packet: %w", err)
	}
	var ack packet
	if err := dec.Decode(&ack); err != nil {
		return fmt.Errorf("read auth ack: %w", err)
	}
	if ack.Type != "auth_ok" {
		if ack.Type == "auth_fail" {
			return fmt.Errorf("authentication rejected: %s", string(ack.Data))
		}
		return fmt.Errorf("unexpected auth response: %q", ack.Type)
	}
	return nil
}

// serverAuthHandshake reads the first packet. If it is auth, verifies and returns session key.
// If auth is not required and the first packet is not auth, it is returned as pending.
func serverAuthHandshake(
	dec *gob.Decoder,
	enc *gob.Encoder,
	localIdentity *crypto.Identity,
	requireAuth bool,
	spaceKey []byte,
) (signed *crypto.SignedToken, sessionKey []byte, pending *packet, err error) {
	var first packet
	if err := dec.Decode(&first); err != nil {
		return nil, nil, nil, fmt.Errorf("read first packet: %w", err)
	}

	if first.Type != "auth" {
		if requireAuth {
			return nil, nil, nil, fmt.Errorf("expected auth packet, got %q", first.Type)
		}
		return nil, nil, &first, nil
	}

	if localIdentity == nil {
		_ = enc.Encode(packet{Type: "auth_fail", Data: []byte("no local identity configured")})
		return nil, nil, nil, fmt.Errorf("local identity required for auth")
	}

	st, err := crypto.UnmarshalToken(first.Data)
	if err != nil {
		_ = enc.Encode(packet{Type: "auth_fail", Data: []byte(err.Error())})
		return nil, nil, nil, fmt.Errorf("unmarshal auth token: %w", err)
	}

	if _, err := crypto.VerifyToken(st, localIdentity.PublicKey); err != nil {
		_ = enc.Encode(packet{Type: "auth_fail", Data: []byte(err.Error())})
		return nil, nil, nil, fmt.Errorf("verify auth token: %w", err)
	}

	if err := enc.Encode(packet{Type: "auth_ok"}); err != nil {
		return nil, nil, nil, fmt.Errorf("send auth_ok: %w", err)
	}

	if len(spaceKey) > 0 {
		sk, derr := DeriveTransferSessionKey(spaceKey, st)
		if derr != nil {
			return st, nil, nil, derr
		}
		sessionKey = sk
	}
	return st, sessionKey, nil, nil
}
