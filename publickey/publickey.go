// Package publickey owns the canonical public-key reference for the Keppin
// Machine Identity: the standard uncompressed ECDSA P-256 point encoding and the
// stable SHA-256 fingerprint derived from it.
//
// It is the single authoritative contract for serializing, parsing and
// fingerprinting a Machine Identity public key, shared by Agent-side production
// and Server-side verification. Consumers such as Keppin-Suite must not define
// their own encoding, parsing or fingerprinting of the Machine Identity public
// key.
//
// The package operates on public material only, is platform-independent, and
// introduces no Windows dependency. Key custody remains in the CNG module and
// proof-of-possession remains in identityproof; this package owns only the
// representation and reference derivation of the public key.
package publickey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// Curve is the single supported Machine Identity public-key curve profile. It
// must match the proof-of-possession profile accepted by identityproof
// (identityproof.KeyAlgorithmECDSA256, ECDSA P-256). No other curve or algorithm
// is supported by this contract.
var Curve = elliptic.P256()

// EncodedKeyLength is the exact length in bytes of the canonical public-key
// encoding: one 0x04 prefix byte plus 32-byte X and 32-byte Y coordinates.
const EncodedKeyLength = 65

// coordinateSize is the byte width of a single P-256 coordinate.
const coordinateSize = 32

// ErrInvalidPublicKey is returned when a public key or its canonical encoding is
// malformed, on an unsupported curve, or not a valid point on the supported
// curve.
var ErrInvalidPublicKey = errors.New("publickey: invalid machine identity public key")

// Encode returns the canonical encoding of pub: the standard uncompressed ECDSA
// P-256 point (0x04 || X || Y, 65 bytes), with X and Y each left-padded to 32
// bytes.
//
// It rejects a nil key, a key on a curve other than P-256, missing coordinates,
// or a point that is not on the curve. It reads public material only and never
// returns private-key material. The returned slice is freshly allocated and
// safe for the caller to mutate.
func Encode(pub *ecdsa.PublicKey) ([]byte, error) {
	if !validPublicKey(pub) {
		return nil, ErrInvalidPublicKey
	}
	out := make([]byte, EncodedKeyLength)
	out[0] = 0x04
	pub.X.FillBytes(out[1 : 1+coordinateSize])
	pub.Y.FillBytes(out[1+coordinateSize:])
	return out, nil
}

// Parse decodes a canonical public-key encoding into an ECDSA P-256 public key.
//
// It accepts only the exact canonical uncompressed form (0x04 || X || Y, 65
// bytes) and rejects any other length, any other prefix (including compressed
// points), and any point that is not on the supported curve. The returned key is
// public material only and can be passed directly to identityproof.Verify.
func Parse(encoding []byte) (*ecdsa.PublicKey, error) {
	if len(encoding) != EncodedKeyLength || encoding[0] != 0x04 {
		return nil, ErrInvalidPublicKey
	}
	x, y := elliptic.Unmarshal(Curve, encoding)
	if x == nil || y == nil || !Curve.IsOnCurve(x, y) {
		return nil, ErrInvalidPublicKey
	}
	return &ecdsa.PublicKey{Curve: Curve, X: x, Y: y}, nil
}

// Fingerprint returns the stable reference fingerprint of pub: the lower-case
// hexadecimal SHA-256 digest of its exact canonical encoding.
//
// It derives the canonical encoding first and hashes that, so the fingerprint is
// always the fingerprint of the canonical representation and never of any
// alternate encoding. It returns ErrInvalidPublicKey if pub is not a supported
// key.
func Fingerprint(pub *ecdsa.PublicKey) (string, error) {
	encoding, err := Encode(pub)
	if err != nil {
		return "", err
	}
	return fingerprintOf(encoding), nil
}

// FingerprintOfEncoding returns the stable reference fingerprint of a canonical
// public-key encoding: the lower-case hexadecimal SHA-256 digest of the exact
// bytes.
//
// It validates the encoding first and returns ErrInvalidPublicKey for any
// encoding that is not exactly the canonical form.
func FingerprintOfEncoding(encoding []byte) (string, error) {
	if _, err := Parse(encoding); err != nil {
		return "", err
	}
	return fingerprintOf(encoding), nil
}

func fingerprintOf(encoding []byte) string {
	sum := sha256.Sum256(encoding)
	return hex.EncodeToString(sum[:])
}

func validPublicKey(pub *ecdsa.PublicKey) bool {
	return pub != nil &&
		pub.Curve == Curve &&
		pub.X != nil && pub.Y != nil &&
		Curve.IsOnCurve(pub.X, pub.Y)
}
