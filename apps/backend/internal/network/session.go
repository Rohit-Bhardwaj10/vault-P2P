package network

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"

	"vault-backend/internal/crypto"

	"golang.org/x/crypto/hkdf"
)

const transferSessionInfo = "vault-transfer-v1"

// DeriveTransferSessionKey derives a 32-byte AES key for encrypting chunks on the wire.
// Both peers must use the same space symmetric key and signed capability token.
func DeriveTransferSessionKey(spaceKey []byte, signed *crypto.SignedToken) ([]byte, error) {
	if len(spaceKey) != crypto.SpaceKeySize {
		return nil, fmt.Errorf("invalid space key length %d", len(spaceKey))
	}
	var tok crypto.CapabilityToken
	if err := json.Unmarshal(signed.Payload, &tok); err != nil {
		return nil, fmt.Errorf("parse token payload: %w", err)
	}
	info := []byte(transferSessionInfo + ":" + tok.SpaceID + ":" + signed.IssuerPubKey + ":" + tok.PeerPubKey)
	salt := []byte(transferSessionInfo)
	r := hkdf.New(sha256.New, spaceKey, salt, info)
	key := make([]byte, crypto.SpaceKeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("derive session key: %w", err)
	}
	return key, nil
}

// ProtectChunk encrypts plaintext chunk bytes for wire transfer.
func ProtectChunk(sessionKey, plaintext []byte) ([]byte, error) {
	if len(sessionKey) != crypto.SpaceKeySize {
		return nil, fmt.Errorf("invalid session key length %d", len(sessionKey))
	}
	return crypto.Encrypt(plaintext, sessionKey)
}

// UnprotectChunk decrypts wire chunk bytes.
func UnprotectChunk(sessionKey, ciphertext []byte) ([]byte, error) {
	if len(sessionKey) != crypto.SpaceKeySize {
		return nil, fmt.Errorf("invalid session key length %d", len(sessionKey))
	}
	return crypto.Decrypt(ciphertext, sessionKey)
}
