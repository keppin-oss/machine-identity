// Package identityproof implements the Keppin Machine Identity
// domain-separated proof-of-possession primitive.
//
// It is the single source of truth for the challenge-signing profile used by
// the machine identity (which signs challenges) and any party that verifies
// them. It is intentionally free of platform and transport dependencies, and
// signs through crypto.Signer so future CNG/KSP-backed signers can be used
// without coupling the proof protocol to Windows APIs.
package identityproof

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

// Domain is the domain-separation prefix applied before hashing/signing a
// proof-of-possession challenge. It is a protocol compatibility contract and
// MUST NOT change without a coordinated version bump across signers and
// verifiers.
const Domain = "Keppin.MachineIdentity.ProofOfPossession.v1"

// KeyAlgorithmECDSA256 labels the ECDSA P-256 proof key algorithm profile used
// for machine identity proofs.
const KeyAlgorithmECDSA256 = "ecdsa-p256"

// ErrInvalidProof is returned when a proof-of-possession signature is invalid.
var ErrInvalidProof = errors.New("identityproof: invalid proof-of-possession signature")

// Digest returns the domain-separated digest of a challenge:
// SHA-256(Domain || 0x00 || challenge).
func Digest(challenge []byte) []byte {
	h := sha256.New()
	h.Write([]byte(Domain))
	h.Write([]byte{0x00})
	h.Write(challenge)
	return h.Sum(nil)
}

// Sign signs a challenge with domain separation using the given signer.
func Sign(signer crypto.Signer, challenge []byte) ([]byte, error) {
	signature, err := signer.Sign(rand.Reader, Digest(challenge), crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("sign proof challenge: %w", err)
	}
	return signature, nil
}

// Verify verifies a domain-separated proof-of-possession signature against the
// given public key.
func Verify(pub crypto.PublicKey, challenge, signature []byte) error {
	digest := Digest(challenge)
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, digest, signature) {
			return ErrInvalidProof
		}
		return nil
	default:
		return fmt.Errorf("identityproof: unsupported public key type %T", pub)
	}
}
