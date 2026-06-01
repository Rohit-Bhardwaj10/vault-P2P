package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Identity represents a peer's Ed25519 keypair
type Identity struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

func GenerateIdentity() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{PublicKey: pub, PrivateKey: priv}, nil
}

// Encrypt encrypts a chunk using AES-256-GCM
func Encrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypt decrypts a chunk using AES-256-GCM
func Decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, cipher := ciphertext[:nonceSize], ciphertext[nonceSize:]
	data, err := gcm.Open(nil, nonce, cipher, nil)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Sign signs data with the identity's private key.
func (id *Identity) Sign(data []byte) []byte {
	return ed25519.Sign(id.PrivateKey, data)
}

// Verify checks whether sig is a valid Ed25519 signature over data by this identity.
func (id *Identity) Verify(data, sig []byte) bool {
	return ed25519.Verify(id.PublicKey, data, sig)
}

// encodeKey encodes an Ed25519 public key as a lowercase hex string.
func encodeKey(key ed25519.PublicKey) string {
	return hex.EncodeToString(key)
}

// decodeKey decodes a hex-encoded Ed25519 public key.
func decodeKey(encoded string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode pubkey hex: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid pubkey length: %d", len(b))
	}
	return ed25519.PublicKey(b), nil
}

// randomHex generates n random bytes and returns them as a hex string.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
