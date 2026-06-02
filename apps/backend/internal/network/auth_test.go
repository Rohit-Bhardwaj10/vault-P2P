package network

import (
	"bytes"
	"encoding/gob"
	"testing"
	"time"

	"vault-backend/internal/crypto"
)

func TestAuthHandshakeSuccess(t *testing.T) {
	issuer, _ := crypto.GenerateIdentity()
	grantee, _ := crypto.GenerateIdentity()
	space, _ := crypto.NewSpace("auth-test")

	token, err := crypto.IssueToken(issuer, grantee.PublicKey, space.ID, crypto.PermWrite, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	tokBytes, err := crypto.MarshalToken(token)
	if err != nil {
		t.Fatal(err)
	}

	// Client → server wire
	var c2s bytes.Buffer
	if err := gob.NewEncoder(&c2s).Encode(packet{Type: "auth", Data: tokBytes}); err != nil {
		t.Fatal(err)
	}

	// Server verifies and responds
	var s2c bytes.Buffer
	signed, sk, pending, err := serverAuthHandshake(
		gob.NewDecoder(&c2s),
		gob.NewEncoder(&s2c),
		grantee,
		true,
		space.SymmetricKey,
	)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	if pending != nil || signed == nil || len(sk) != crypto.SpaceKeySize {
		t.Fatalf("unexpected server result pending=%v signed=%v sk=%d", pending, signed, len(sk))
	}

	var ack packet
	if err := gob.NewDecoder(&s2c).Decode(&ack); err != nil || ack.Type != "auth_ok" {
		t.Fatalf("auth_ok: %v type=%q", err, ack.Type)
	}
}

func TestAuthHandshakeRejectsBadToken(t *testing.T) {
	issuer, _ := crypto.GenerateIdentity()
	grantee, _ := crypto.GenerateIdentity()
	other, _ := crypto.GenerateIdentity()
	space, _ := crypto.NewSpace("auth-test")

	token, _ := crypto.IssueToken(issuer, other.PublicKey, space.ID, crypto.PermWrite, time.Hour)

	var wire bytes.Buffer
	enc := gob.NewEncoder(&wire)
	dec := gob.NewDecoder(&wire)

	tokBytes, _ := crypto.MarshalToken(token)
	_ = enc.Encode(packet{Type: "auth", Data: tokBytes})

	respEnc := gob.NewEncoder(&wire)
	_, _, _, err := serverAuthHandshake(dec, respEnc, grantee, true, space.SymmetricKey)
	if err == nil {
		t.Fatal("expected auth failure for wrong grantee")
	}
}
