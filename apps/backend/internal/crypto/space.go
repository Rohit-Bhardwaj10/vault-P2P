package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	// SpaceKeySize is the size of the AES-256 symmetric key used per space.
	SpaceKeySize = 32
	// InviteTokenTTL is the default time-to-live for invite tokens.
	InviteTokenTTL = 7 * 24 * time.Hour
)

// Space holds the identity of a shared folder and the symmetric key
// used to encrypt all chunks belonging to it.
type Space struct {
	// ID is a random, globally-unique identifier for this space.
	ID string `json:"id"`
	// Name is a human-readable label (not used in cryptography).
	Name string `json:"name"`
	// SymmetricKey is the 32-byte AES-256-GCM key for this space.
	// It must never leave the local node in plaintext.
	SymmetricKey []byte `json:"symmetric_key"`
	// CreatedAt records when this space was created (Unix seconds).
	CreatedAt int64 `json:"created_at"`
}

// NewSpace creates a new Space with a freshly generated symmetric key.
func NewSpace(name string) (*Space, error) {
	id, err := randomHex(16)
	if err != nil {
		return nil, fmt.Errorf("generate space ID: %w", err)
	}

	key := make([]byte, SpaceKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate space key: %w", err)
	}

	return &Space{
		ID:           id,
		Name:         name,
		SymmetricKey: key,
		CreatedAt:    time.Now().Unix(),
	}, nil
}

// DeriveChunkKey derives a per-chunk AES-256 key from the space's symmetric key
// and the chunk's BLAKE3 hash. This prevents key reuse across chunks without
// storing a separate key per chunk.
//
// KDF: HKDF-SHA256(space_key, salt="vault-chunk-v1", info=chunk_hash)
func (s *Space) DeriveChunkKey(chunkHash string) ([]byte, error) {
	info := []byte("vault-chunk-v1:" + chunkHash)
	salt := []byte("vault-chunk-v1")
	r := hkdf.New(sha256.New, s.SymmetricKey, salt, info)
	key := make([]byte, SpaceKeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("derive chunk key: %w", err)
	}
	return key, nil
}

// EncryptChunk encrypts chunk data using the space's derived per-chunk key.
func (s *Space) EncryptChunk(chunkHash string, data []byte) ([]byte, error) {
	key, err := s.DeriveChunkKey(chunkHash)
	if err != nil {
		return nil, err
	}
	return Encrypt(data, key)
}

// DecryptChunk decrypts chunk data using the space's derived per-chunk key.
func (s *Space) DecryptChunk(chunkHash string, ciphertext []byte) ([]byte, error) {
	key, err := s.DeriveChunkKey(chunkHash)
	if err != nil {
		return nil, err
	}
	return Decrypt(ciphertext, key)
}

// InvitePayload is the plaintext content of an invite token.
type InvitePayload struct {
	// SpaceID identifies the space the invitee is being added to.
	SpaceID string `json:"space_id"`
	// SpaceName is the human-readable name of the space.
	SpaceName string `json:"space_name"`
	// SymmetricKey is the base64-encoded space key being transferred.
	// It is included in the signed envelope so the receiver can decrypt space chunks.
	SymmetricKeyHex string `json:"symmetric_key_hex"`
	// GrantedPermission is the access level being granted.
	GrantedPermission Permission `json:"permission"`
	// InviterPubKey is the hex-encoded Ed25519 public key of the sender.
	InviterPubKey string `json:"inviter_pubkey"`
	// IssuedAt is a Unix timestamp (seconds).
	IssuedAt int64 `json:"issued_at"`
	// Expiry is a Unix timestamp (seconds). Zero means no expiry.
	Expiry int64 `json:"expiry,omitempty"`
}

// SignedInvite is an invite token ready for transmission.
type SignedInvite struct {
	// Payload is the JSON-encoded InvitePayload bytes that were signed.
	Payload []byte `json:"payload"`
	// Signature is the raw Ed25519 signature over Payload by the inviter.
	Signature []byte `json:"signature"`
}

// CreateInvite creates a signed invite token that transfers space membership.
// The invitee receives this and can join the space by calling AcceptInvite.
func CreateInvite(issuer *Identity, space *Space, perm Permission, ttl time.Duration) (*SignedInvite, error) {
	if ttl == 0 {
		ttl = InviteTokenTTL
	}
	now := time.Now().UTC()

	payload := InvitePayload{
		SpaceID:           space.ID,
		SpaceName:         space.Name,
		SymmetricKeyHex:   hex.EncodeToString(space.SymmetricKey),
		GrantedPermission: perm,
		InviterPubKey:     encodeKey(issuer.PublicKey),
		IssuedAt:          now.Unix(),
		Expiry:            now.Add(ttl).Unix(),
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal invite payload: %w", err)
	}

	sig := ed25519.Sign(issuer.PrivateKey, payloadBytes)

	return &SignedInvite{
		Payload:   payloadBytes,
		Signature: sig,
	}, nil
}

// AcceptInvite verifies a SignedInvite and returns the Space the invitee should join.
//
// Callers must supply the known-good issuerPubKey (obtained out-of-band, e.g. via
// QR code or the rendezvous server's peer registry). The function rejects the invite
// if the signature does not match or the invite has expired.
func AcceptInvite(signed *SignedInvite, issuerPubKey ed25519.PublicKey) (*Space, *InvitePayload, error) {
	if !ed25519.Verify(issuerPubKey, signed.Payload, signed.Signature) {
		return nil, nil, errors.New("invite: invalid signature")
	}

	var inv InvitePayload
	if err := json.Unmarshal(signed.Payload, &inv); err != nil {
		return nil, nil, fmt.Errorf("unmarshal invite payload: %w", err)
	}

	if inv.Expiry != 0 && time.Now().Unix() > inv.Expiry {
		return nil, nil, errors.New("invite: expired")
	}

	keyBytes, err := hex.DecodeString(inv.SymmetricKeyHex)
	if err != nil {
		return nil, nil, fmt.Errorf("decode space key: %w", err)
	}
	if len(keyBytes) != SpaceKeySize {
		return nil, nil, fmt.Errorf("invite: unexpected key length %d", len(keyBytes))
	}

	space := &Space{
		ID:           inv.SpaceID,
		Name:         inv.SpaceName,
		SymmetricKey: keyBytes,
		CreatedAt:    time.Now().Unix(),
	}

	return space, &inv, nil
}

// MarshalInvite serialises a SignedInvite to JSON for wire transmission.
func MarshalInvite(si *SignedInvite) ([]byte, error) {
	return json.Marshal(si)
}

// UnmarshalInvite deserialises a SignedInvite from JSON.
func UnmarshalInvite(data []byte) (*SignedInvite, error) {
	var si SignedInvite
	if err := json.Unmarshal(data, &si); err != nil {
		return nil, fmt.Errorf("unmarshal signed invite: %w", err)
	}
	return &si, nil
}
