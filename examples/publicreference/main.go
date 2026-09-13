// Command publicreference demonstrates the platform-independent public-key
// reference and proof-of-possession contract of the Keppin Machine Identity:
// canonical encoding, stable fingerprint, round-trip parsing, and
// domain-separated signing/verification.
//
// It uses a synthetic in-memory ECDSA P-256 key so it runs on any platform
// without Windows/elevation and without touching the persisted machine key. In
// production the Machine Identity key is obtained from the keystore package
// (see examples/machineidentity) and is never exported.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"

	"github.com/keppin-oss/machine-identity/identityproof"
	"github.com/keppin-oss/machine-identity/publickey"
)

func main() {
	// Synthetic, in-memory ECDSA P-256 key for demonstration only; it exists
	// solely to make this platform-independent example runnable. In production
	// the Machine Identity key comes from the keystore package (see
	// examples/machineidentity) and is never exported.
	//
	// publickey operations read public material only. identityproof.Sign uses
	// the private key through the crypto.Signer boundary. This example never
	// exports, serializes, prints, or persists private key material.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generate synthetic key: %v", err)
	}

	// Canonical public identity reference: uncompressed P-256 point and its
	// stable SHA-256 fingerprint.
	encoded, err := publickey.Encode(&key.PublicKey)
	if err != nil {
		log.Fatalf("encode: %v", err)
	}
	fingerprint, err := publickey.Fingerprint(&key.PublicKey)
	if err != nil {
		log.Fatalf("fingerprint: %v", err)
	}
	fmt.Printf("canonical reference: %x\n", encoded)
	fmt.Printf("fingerprint:        %s\n", fingerprint)

	// The canonical reference round-trips through Parse, and the fingerprint of
	// the encoding matches the fingerprint derived from the key.
	parsed, err := publickey.Parse(encoded)
	if err != nil {
		log.Fatalf("parse: %v", err)
	}
	fpFromEncoding, err := publickey.FingerprintOfEncoding(encoded)
	if err != nil {
		log.Fatalf("fingerprint of encoding: %v", err)
	}
	fmt.Printf("round-trip fingerprint matches: %v\n", fpFromEncoding == fingerprint)

	// Prove possession and verify through the module's intended verification
	// boundary, using the parsed public reference as the verifier's key.
	challenge := []byte("server-fresh-challenge")
	signature, err := identityproof.Sign(key, challenge)
	if err != nil {
		log.Fatalf("sign: %v", err)
	}
	if err := identityproof.Verify(parsed, challenge, signature); err != nil {
		log.Fatalf("verify: %v", err)
	}
	fmt.Println("proof of possession verified")
}
