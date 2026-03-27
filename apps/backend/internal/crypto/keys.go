package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/aes"
	"crypto/cipher"
	"errors"
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
