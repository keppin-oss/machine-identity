package publickey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/keppin-oss/machine-identity/identityproof"
)

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

// TestEncodeProducesCanonicalRepresentation asserts the encoding is exactly the
// standard uncompressed P-256 point: 0x04 || X || Y with 32-byte coordinates.
func TestEncodeProducesCanonicalRepresentation(t *testing.T) {
	key := newTestKey(t)
	enc, err := Encode(&key.PublicKey)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(enc) != EncodedKeyLength {
		t.Fatalf("encoding length = %d, want %d", len(enc), EncodedKeyLength)
	}
	if enc[0] != 0x04 {
		t.Fatalf("encoding prefix = 0x%02x, want 0x04", enc[0])
	}
	wantX := make([]byte, coordinateSize)
	wantY := make([]byte, coordinateSize)
	key.PublicKey.X.FillBytes(wantX)
	key.PublicKey.Y.FillBytes(wantY)
	if !bytes.Equal(enc[1:1+coordinateSize], wantX) {
		t.Fatalf("encoding X = %x, want %x", enc[1:1+coordinateSize], wantX)
	}
	if !bytes.Equal(enc[1+coordinateSize:], wantY) {
		t.Fatalf("encoding Y = %x, want %x", enc[1+coordinateSize:], wantY)
	}
}

// TestEncodeParseRoundTrip asserts encode -> parse preserves the same public key.
func TestEncodeParseRoundTrip(t *testing.T) {
	key := newTestKey(t)
	enc, err := Encode(&key.PublicKey)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	parsed, err := Parse(enc)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.Curve != Curve {
		t.Fatalf("parsed curve = %v, want P-256", parsed.Curve)
	}
	if parsed.X.Cmp(key.PublicKey.X) != 0 || parsed.Y.Cmp(key.PublicKey.Y) != 0 {
		t.Fatal("parsed public key must match original point")
	}
}

// TestFingerprintDeterministic asserts the fingerprint is stable for the same key.
func TestFingerprintDeterministic(t *testing.T) {
	key := newTestKey(t)
	a, err := Fingerprint(&key.PublicKey)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	b, err := Fingerprint(&key.PublicKey)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if a != b {
		t.Fatal("fingerprint must be stable for the same key")
	}
}

// TestDifferentKeysProduceDifferentFingerprints asserts fingerprint uniqueness.
func TestDifferentKeysProduceDifferentFingerprints(t *testing.T) {
	a, err := Fingerprint(&newTestKey(t).PublicKey)
	if err != nil {
		t.Fatalf("Fingerprint a: %v", err)
	}
	b, err := Fingerprint(&newTestKey(t).PublicKey)
	if err != nil {
		t.Fatalf("Fingerprint b: %v", err)
	}
	if a == b {
		t.Fatal("different keys must produce different fingerprints")
	}
}

// TestFingerprintDerivedFromCanonicalEncoding asserts the fingerprint equals the
// lower-case hex SHA-256 of the canonical encoding.
func TestFingerprintDerivedFromCanonicalEncoding(t *testing.T) {
	key := newTestKey(t)
	enc, err := Encode(&key.PublicKey)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	fp, err := Fingerprint(&key.PublicKey)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	sum := sha256.Sum256(enc)
	if fp != hex.EncodeToString(sum[:]) {
		t.Fatal("fingerprint must be the SHA-256 of the canonical encoding")
	}
	if fpOfEnc, err := FingerprintOfEncoding(enc); err != nil || fpOfEnc != fp {
		t.Fatalf("FingerprintOfEncoding = %q, %v; want %q", fpOfEnc, err, fp)
	}
}

// TestParseRejectsMalformedLength asserts non-65-byte encodings are rejected.
func TestParseRejectsMalformedLength(t *testing.T) {
	key := newTestKey(t)
	good, err := Encode(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, enc := range map[string][]byte{
		"empty":     nil,
		"too short": good[:EncodedKeyLength-1],
		"too long":  append(append([]byte(nil), good...), 0x00),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(enc); err != ErrInvalidPublicKey {
				t.Fatalf("Parse = %v, want ErrInvalidPublicKey", err)
			}
		})
	}
}

// TestParseRejectsInvalidPrefix asserts any non-0x04 prefix (including compressed
// points) is rejected.
func TestParseRejectsInvalidPrefix(t *testing.T) {
	key := newTestKey(t)
	good, err := Encode(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []byte{0x00, 0x02, 0x03, 0x05, 0xFF} {
		enc := append([]byte(nil), good...)
		enc[0] = prefix
		if _, err := Parse(enc); err != ErrInvalidPublicKey {
			t.Fatalf("Parse prefix 0x%02x = %v, want ErrInvalidPublicKey", prefix, err)
		}
	}
}

// TestParseRejectsOffCurvePoint asserts a point not on P-256 is rejected.
func TestParseRejectsOffCurvePoint(t *testing.T) {
	key := newTestKey(t)
	good, err := Encode(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	off := append([]byte(nil), good...)
	off[EncodedKeyLength-1] ^= 0xFF
	if _, err := Parse(off); err != ErrInvalidPublicKey {
		t.Fatalf("Parse(off-curve) = %v, want ErrInvalidPublicKey", err)
	}
}

// TestEncodeRejectsUnsupportedCurve asserts a non-P256 key is rejected.
func TestEncodeRejectsUnsupportedCurve(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Encode(&key.PublicKey); err != ErrInvalidPublicKey {
		t.Fatalf("Encode(P384) = %v, want ErrInvalidPublicKey", err)
	}
	if _, err := Fingerprint(&key.PublicKey); err != ErrInvalidPublicKey {
		t.Fatalf("Fingerprint(P384) = %v, want ErrInvalidPublicKey", err)
	}
}

// TestEncodeRejectsNil asserts a nil key is rejected.
func TestEncodeRejectsNil(t *testing.T) {
	if _, err := Encode(nil); err != ErrInvalidPublicKey {
		t.Fatalf("Encode(nil) = %v, want ErrInvalidPublicKey", err)
	}
	if _, err := Fingerprint(nil); err != ErrInvalidPublicKey {
		t.Fatalf("Fingerprint(nil) = %v, want ErrInvalidPublicKey", err)
	}
}

// TestNoPrivateKeyMaterial asserts encoding and fingerprint never contain private
// key material.
func TestNoPrivateKeyMaterial(t *testing.T) {
	key := newTestKey(t)
	enc, err := Encode(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := Fingerprint(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	d := key.D.Bytes()
	if len(d) > 0 && (bytes.Contains(enc, d) || bytes.Contains([]byte(fp), d)) {
		t.Fatal("encoding/fingerprint must not contain private key material")
	}
}

// TestParseResultVerifiesWithIdentityproof asserts a parsed public reference can
// be passed to identityproof.Verify and successfully verify a valid proof.
func TestParseResultVerifiesWithIdentityproof(t *testing.T) {
	key := newTestKey(t)
	enc, err := Encode(&key.PublicKey)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	parsed, err := Parse(enc)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	challenge := []byte("server-fresh-challenge")
	sig, err := identityproof.Sign(key, challenge)
	if err != nil {
		t.Fatalf("identityproof.Sign: %v", err)
	}
	if err := identityproof.Verify(parsed, challenge, sig); err != nil {
		t.Fatalf("identityproof.Verify with parsed reference: %v", err)
	}
}
