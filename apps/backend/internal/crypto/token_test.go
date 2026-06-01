package crypto

import (
	"testing"
	"time"
)

func TestIssueAndVerifyToken(t *testing.T) {
	issuer, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("generate issuer identity: %v", err)
	}
	grantee, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("generate grantee identity: %v", err)
	}

	spaceID := "space-abc-123"
	signed, err := IssueToken(issuer, grantee.PublicKey, spaceID, PermWrite, time.Hour)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	tok, err := VerifyToken(signed, grantee.PublicKey)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}

	if tok.SpaceID != spaceID {
		t.Errorf("SpaceID: want %q, got %q", spaceID, tok.SpaceID)
	}
	if tok.Permission != PermWrite {
		t.Errorf("Permission: want %q, got %q", PermWrite, tok.Permission)
	}
	if tok.PeerPubKey != encodeKey(grantee.PublicKey) {
		t.Errorf("PeerPubKey mismatch")
	}
}

func TestTokenExpiry(t *testing.T) {
	issuer, _ := GenerateIdentity()
	grantee, _ := GenerateIdentity()

	// Issue token that expired 1 second ago.
	signed, err := IssueToken(issuer, grantee.PublicKey, "space-x", PermRead, -time.Second)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	// Expiry is set in the payload; manually force it to a past timestamp.
	// Re-issue with a very short TTL to simulate natural expiry in this test.
	// (The token issued with a negative TTL will have expiry in the past.)
	_, err = VerifyToken(signed, grantee.PublicKey)
	if err == nil {
		t.Error("expected error for expired token, got nil")
	}
}

func TestTokenGranteeMismatch(t *testing.T) {
	issuer, _ := GenerateIdentity()
	grantee, _ := GenerateIdentity()
	other, _ := GenerateIdentity()

	signed, err := IssueToken(issuer, grantee.PublicKey, "space-y", PermRead, time.Hour)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	// Verify with wrong public key.
	_, err = VerifyToken(signed, other.PublicKey)
	if err == nil {
		t.Error("expected grantee mismatch error, got nil")
	}
}

func TestTokenTamperedSignature(t *testing.T) {
	issuer, _ := GenerateIdentity()
	grantee, _ := GenerateIdentity()

	signed, err := IssueToken(issuer, grantee.PublicKey, "space-z", PermAdmin, time.Hour)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	// Tamper with signature.
	signed.Signature[0] ^= 0xFF

	_, err = VerifyToken(signed, grantee.PublicKey)
	if err == nil {
		t.Error("expected invalid signature error, got nil")
	}
}

func TestTokenMarshalRoundtrip(t *testing.T) {
	issuer, _ := GenerateIdentity()
	grantee, _ := GenerateIdentity()

	signed, err := IssueToken(issuer, grantee.PublicKey, "space-roundtrip", PermRead, time.Hour)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	data, err := MarshalToken(signed)
	if err != nil {
		t.Fatalf("MarshalToken: %v", err)
	}

	restored, err := UnmarshalToken(data)
	if err != nil {
		t.Fatalf("UnmarshalToken: %v", err)
	}

	tok, err := VerifyToken(restored, grantee.PublicKey)
	if err != nil {
		t.Fatalf("VerifyToken after roundtrip: %v", err)
	}
	if tok.SpaceID != "space-roundtrip" {
		t.Errorf("SpaceID after roundtrip: got %q", tok.SpaceID)
	}
}

func TestTokenNoExpiry(t *testing.T) {
	issuer, _ := GenerateIdentity()
	grantee, _ := GenerateIdentity()

	// TTL=0 means no expiry.
	signed, err := IssueToken(issuer, grantee.PublicKey, "space-noexp", PermRead, 0)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	tok, err := VerifyToken(signed, grantee.PublicKey)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if tok.Expiry != 0 {
		t.Errorf("expected no expiry (0), got %d", tok.Expiry)
	}
}
