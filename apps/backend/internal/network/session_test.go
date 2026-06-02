package network

import (
	"testing"
	"time"

	"vault-backend/internal/crypto"
)

func TestDeriveTransferSessionKeyDeterministic(t *testing.T) {
	issuer, _ := crypto.GenerateIdentity()
	grantee, _ := crypto.GenerateIdentity()
	space, _ := crypto.NewSpace("test")

	signed, err := crypto.IssueToken(issuer, grantee.PublicKey, space.ID, crypto.PermWrite, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	k1, err := DeriveTransferSessionKey(space.SymmetricKey, signed)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := DeriveTransferSessionKey(space.SymmetricKey, signed)
	if err != nil {
		t.Fatal(err)
	}
	if string(k1) != string(k2) {
		t.Fatal("session keys should be deterministic")
	}
}

func TestProtectUnprotectRoundtrip(t *testing.T) {
	issuer, _ := crypto.GenerateIdentity()
	grantee, _ := crypto.GenerateIdentity()
	space, _ := crypto.NewSpace("test")
	signed, _ := crypto.IssueToken(issuer, grantee.PublicKey, space.ID, crypto.PermWrite, time.Hour)

	key, err := DeriveTransferSessionKey(space.SymmetricKey, signed)
	if err != nil {
		t.Fatal(err)
	}

	plain := []byte("chunk payload data")
	ct, err := ProtectChunk(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnprotectChunk(key, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plain) {
		t.Fatalf("got %q want %q", got, plain)
	}
}

func TestDeriveSessionKeyDifferentSpaces(t *testing.T) {
	issuer, _ := crypto.GenerateIdentity()
	grantee, _ := crypto.GenerateIdentity()
	s1, _ := crypto.NewSpace("a")
	s2, _ := crypto.NewSpace("b")

	tok1, _ := crypto.IssueToken(issuer, grantee.PublicKey, s1.ID, crypto.PermWrite, time.Hour)
	tok2, _ := crypto.IssueToken(issuer, grantee.PublicKey, s2.ID, crypto.PermWrite, time.Hour)

	k1, _ := DeriveTransferSessionKey(s1.SymmetricKey, tok1)
	k2, _ := DeriveTransferSessionKey(s2.SymmetricKey, tok2)
	if string(k1) == string(k2) {
		t.Fatal("different spaces should produce different session keys")
	}
}
