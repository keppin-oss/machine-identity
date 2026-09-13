package identityproof

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

func TestSignAndVerifyRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challenge := []byte("server-fresh-challenge")
	signature, err := Sign(key, challenge)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := Verify(&key.PublicKey, challenge, signature); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsWrongChallenge(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := Sign(key, []byte("challenge-a"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(&key.PublicKey, []byte("challenge-b"), signature); err != ErrInvalidProof {
		t.Fatalf("Verify = %v, want ErrInvalidProof", err)
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	signing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challenge := []byte("challenge")
	signature, err := Sign(signing, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(&other.PublicKey, challenge, signature); err != ErrInvalidProof {
		t.Fatalf("Verify = %v, want ErrInvalidProof", err)
	}
}

func TestVerifyRejectsModifiedSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challenge := []byte("challenge")
	signature, err := Sign(key, challenge)
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 0xFF
	if err := Verify(&key.PublicKey, challenge, signature); err != ErrInvalidProof {
		t.Fatalf("Verify = %v, want ErrInvalidProof", err)
	}
}

func TestVerifyRejectsUnsupportedKeyType(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	challenge := []byte("challenge")
	if err := Verify(&rsaKey.PublicKey, challenge, nil); err == nil {
		t.Fatal("Verify = nil, want unsupported public key type error")
	}
}

func TestDigestIsDomainSeparated(t *testing.T) {
	a := Digest([]byte("x"))
	b := Digest([]byte("y"))
	if string(a) == string(b) {
		t.Fatal("different challenges must produce different digests")
	}
	// The digest must differ from a plain SHA-256 of the challenge (domain
	// separation prevents cross-protocol confusion).
	h := sha256.New()
	h.Write([]byte("x"))
	plain := h.Sum(nil)
	if string(a) == string(plain) {
		t.Fatal("domain-separated digest must differ from plain SHA-256")
	}
}

// TestDigestIsDeterministic asserts the domain-separated digest is stable for
// the same challenge.
func TestDigestIsDeterministic(t *testing.T) {
	a := Digest([]byte("challenge"))
	b := Digest([]byte("challenge"))
	if string(a) != string(b) {
		t.Fatal("identical challenges must produce identical digests")
	}
}

// TestProtocolConstantsExact locks the proof-of-possession protocol profile
// constants so the signer/verifier interoperability contract cannot drift.
func TestProtocolConstantsExact(t *testing.T) {
	if Domain != "Keppin.MachineIdentity.ProofOfPossession.v1" {
		t.Errorf("Domain = %q, want %q", Domain, "Keppin.MachineIdentity.ProofOfPossession.v1")
	}
	if KeyAlgorithmECDSA256 != "ecdsa-p256" {
		t.Errorf("KeyAlgorithmECDSA256 = %q, want %q", KeyAlgorithmECDSA256, "ecdsa-p256")
	}
}
