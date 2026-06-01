package crypto

import (
	"bytes"
	"testing"
	"time"
)

func TestNewSpace(t *testing.T) {
	space, err := NewSpace("my-files")
	if err != nil {
		t.Fatalf("NewSpace: %v", err)
	}
	if space.ID == "" {
		t.Error("expected non-empty space ID")
	}
	if space.Name != "my-files" {
		t.Errorf("Name: got %q", space.Name)
	}
	if len(space.SymmetricKey) != SpaceKeySize {
		t.Errorf("SymmetricKey length: want %d, got %d", SpaceKeySize, len(space.SymmetricKey))
	}
}

func TestDeriveChunkKeyDeterminism(t *testing.T) {
	space, _ := NewSpace("test")

	key1, err := space.DeriveChunkKey("hash-abc")
	if err != nil {
		t.Fatalf("DeriveChunkKey 1: %v", err)
	}
	key2, err := space.DeriveChunkKey("hash-abc")
	if err != nil {
		t.Fatalf("DeriveChunkKey 2: %v", err)
	}
	if !bytes.Equal(key1, key2) {
		t.Error("derived keys for same hash must be equal")
	}
}

func TestDeriveChunkKeyUniqueness(t *testing.T) {
	space, _ := NewSpace("test")

	key1, _ := space.DeriveChunkKey("hash-aaa")
	key2, _ := space.DeriveChunkKey("hash-bbb")
	if bytes.Equal(key1, key2) {
		t.Error("different chunk hashes should yield different derived keys")
	}
}

func TestSpaceEncryptDecrypt(t *testing.T) {
	space, _ := NewSpace("encrypt-test")

	plaintext := []byte("the quick brown fox jumps over the lazy dog")
	chunkHash := "blake3-deadbeef"

	ciphertext, err := space.EncryptChunk(chunkHash, plaintext)
	if err != nil {
		t.Fatalf("EncryptChunk: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("ciphertext must differ from plaintext")
	}

	recovered, err := space.DecryptChunk(chunkHash, ciphertext)
	if err != nil {
		t.Fatalf("DecryptChunk: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("DecryptChunk: got %q, want %q", recovered, plaintext)
	}
}

func TestSpaceWrongHashDecryptFails(t *testing.T) {
	space, _ := NewSpace("bad-hash-test")

	plaintext := []byte("secret data")
	ciphertext, _ := space.EncryptChunk("hash-correct", plaintext)

	// Decrypt with the wrong chunk hash (different derived key).
	_, err := space.DecryptChunk("hash-wrong", ciphertext)
	if err == nil {
		t.Error("expected decryption failure with wrong chunk hash")
	}
}

func TestCreateAndAcceptInvite(t *testing.T) {
	issuer, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("generate issuer: %v", err)
	}

	space, err := NewSpace("shared-docs")
	if err != nil {
		t.Fatalf("NewSpace: %v", err)
	}

	invite, err := CreateInvite(issuer, space, PermWrite, 24*time.Hour)
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}

	joinedSpace, inv, err := AcceptInvite(invite, issuer.PublicKey)
	if err != nil {
		t.Fatalf("AcceptInvite: %v", err)
	}

	if joinedSpace.ID != space.ID {
		t.Errorf("SpaceID: want %q, got %q", space.ID, joinedSpace.ID)
	}
	if !bytes.Equal(joinedSpace.SymmetricKey, space.SymmetricKey) {
		t.Error("symmetric key mismatch after accepting invite")
	}
	if inv.GrantedPermission != PermWrite {
		t.Errorf("Permission: want %q, got %q", PermWrite, inv.GrantedPermission)
	}
}

func TestInviteExpiry(t *testing.T) {
	issuer, _ := GenerateIdentity()
	space, _ := NewSpace("expiry-test")

	// Create a very short-lived invite that is already expired.
	invite, err := CreateInvite(issuer, space, PermRead, -time.Second)
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}

	_, _, err = AcceptInvite(invite, issuer.PublicKey)
	if err == nil {
		t.Error("expected error for expired invite")
	}
}

func TestInviteTamperedSignature(t *testing.T) {
	issuer, _ := GenerateIdentity()
	space, _ := NewSpace("tamper-test")

	invite, _ := CreateInvite(issuer, space, PermRead, time.Hour)
	invite.Signature[0] ^= 0xFF

	_, _, err := AcceptInvite(invite, issuer.PublicKey)
	if err == nil {
		t.Error("expected invalid signature error")
	}
}

func TestInviteMarshalRoundtrip(t *testing.T) {
	issuer, _ := GenerateIdentity()
	space, _ := NewSpace("roundtrip-space")

	invite, err := CreateInvite(issuer, space, PermAdmin, time.Hour)
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}

	data, err := MarshalInvite(invite)
	if err != nil {
		t.Fatalf("MarshalInvite: %v", err)
	}

	restored, err := UnmarshalInvite(data)
	if err != nil {
		t.Fatalf("UnmarshalInvite: %v", err)
	}

	joinedSpace, inv, err := AcceptInvite(restored, issuer.PublicKey)
	if err != nil {
		t.Fatalf("AcceptInvite after roundtrip: %v", err)
	}
	if joinedSpace.ID != space.ID {
		t.Errorf("SpaceID after roundtrip: got %q", joinedSpace.ID)
	}
	if inv.GrantedPermission != PermAdmin {
		t.Errorf("Permission after roundtrip: got %q", inv.GrantedPermission)
	}
}

func TestTwoSpacesHaveDifferentKeys(t *testing.T) {
	s1, _ := NewSpace("space-1")
	s2, _ := NewSpace("space-2")
	if bytes.Equal(s1.SymmetricKey, s2.SymmetricKey) {
		t.Error("two independently created spaces should not share a symmetric key")
	}
}
