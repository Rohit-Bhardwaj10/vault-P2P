package crypto

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Permission defines what a capability token authorises.
type Permission string

const (
	PermRead  Permission = "read"
	PermWrite Permission = "write"
	PermAdmin Permission = "admin"
)

// CapabilityToken is the plaintext payload that gets signed.
// It is serialised as JSON, then signed with the issuer's Ed25519 key.
type CapabilityToken struct {
	// PeerPubKey is the hex-encoded Ed25519 public key of the peer being granted access.
	PeerPubKey string `json:"peer_pubkey"`
	// SpaceID identifies the shared space this token grants access to.
	SpaceID string `json:"space_id"`
	// Permission is the access level being granted.
	Permission Permission `json:"permission"`
	// IssuedAt is a Unix timestamp (seconds) recording when the token was created.
	IssuedAt int64 `json:"issued_at"`
	// Expiry is a Unix timestamp (seconds) after which this token is no longer valid.
	// A zero value means the token never expires.
	Expiry int64 `json:"expiry,omitempty"`
}

// SignedToken wraps a CapabilityToken payload together with the issuer's signature.
type SignedToken struct {
	// Payload is the JSON-encoded CapabilityToken bytes that were signed.
	Payload []byte `json:"payload"`
	// IssuerPubKey is the hex-encoded Ed25519 public key of the signing peer.
	IssuerPubKey string `json:"issuer_pubkey"`
	// Signature is the raw Ed25519 signature over Payload.
	Signature []byte `json:"signature"`
}

// IssueToken creates a signed capability token.
//
//   - issuer  — the peer whose identity signs the grant.
//   - grantee — the Ed25519 public key of the peer being granted access.
//   - spaceID — the space this token covers.
//   - perm    — the permission level.
//   - ttl     — how long the token is valid; use 0 for no expiry.
func IssueToken(issuer *Identity, grantee ed25519.PublicKey, spaceID string, perm Permission, ttl time.Duration) (*SignedToken, error) {
	now := time.Now().UTC()
	tok := CapabilityToken{
		PeerPubKey: encodeKey(grantee),
		SpaceID:    spaceID,
		Permission: perm,
		IssuedAt:   now.Unix(),
	}
	if ttl != 0 {
		tok.Expiry = now.Add(ttl).Unix()
	}

	payload, err := json.Marshal(tok)
	if err != nil {
		return nil, fmt.Errorf("marshal token payload: %w", err)
	}

	sig := ed25519.Sign(issuer.PrivateKey, payload)

	return &SignedToken{
		Payload:      payload,
		IssuerPubKey: encodeKey(issuer.PublicKey),
		Signature:    sig,
	}, nil
}

// VerifyToken validates a SignedToken.
// It checks:
//  1. The issuer's signature over the payload is valid.
//  2. The token has not expired (if an expiry is set).
//  3. Optionally, that the token was granted to the expected grantee key.
//
// Returns the decoded CapabilityToken on success.
func VerifyToken(signed *SignedToken, expectedGrantee ed25519.PublicKey) (*CapabilityToken, error) {
	issuerKey, err := decodeKey(signed.IssuerPubKey)
	if err != nil {
		return nil, fmt.Errorf("decode issuer key: %w", err)
	}

	if !ed25519.Verify(issuerKey, signed.Payload, signed.Signature) {
		return nil, errors.New("capability token: invalid signature")
	}

	var tok CapabilityToken
	if err := json.Unmarshal(signed.Payload, &tok); err != nil {
		return nil, fmt.Errorf("unmarshal token payload: %w", err)
	}

	if tok.Expiry != 0 && time.Now().Unix() > tok.Expiry {
		return nil, errors.New("capability token: expired")
	}

	if expectedGrantee != nil {
		if tok.PeerPubKey != encodeKey(expectedGrantee) {
			return nil, errors.New("capability token: grantee mismatch")
		}
	}

	return &tok, nil
}

// MarshalToken serialises a SignedToken to JSON bytes suitable for transmission.
func MarshalToken(st *SignedToken) ([]byte, error) {
	return json.Marshal(st)
}

// UnmarshalToken deserialises a SignedToken from JSON bytes.
func UnmarshalToken(data []byte) (*SignedToken, error) {
	var st SignedToken
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("unmarshal signed token: %w", err)
	}
	return &st, nil
}
