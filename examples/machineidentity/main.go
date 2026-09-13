//go:build windows

// Command machineidentity demonstrates the full persisted Machine Identity flow
// on Windows: load-or-create the machine-scoped identity key, obtain the
// canonical public reference and fingerprint, prove possession of the key by
// signing a challenge, verify that proof, then re-open the existing key.
//
// The first run must be performed from an elevated (Administrator) process
// because creating a machine-scoped CNG key requires administrative rights.
// Opening an existing key and signing does not require elevation.
//
// This example is non-destructive: it never calls keystore.Delete. Deleting the
// identity destroys the prior proof capability and should only be done by a
// higher-level uninstall/reset flow.
package main

import (
	"crypto/ecdsa"
	"fmt"
	"log"

	"github.com/keppin-oss/cng/windowscng"
	"github.com/keppin-oss/machine-identity/identityproof"
	"github.com/keppin-oss/machine-identity/keystore"
	"github.com/keppin-oss/machine-identity/publickey"
)

func main() {
	// LoadOrCreate opens the existing persisted Machine Identity key or creates
	// it (non-exportable, machine-scoped ECDSA P-256) if it does not exist.
	signer, err := keystore.LoadOrCreate()
	if err != nil {
		log.Fatalf("LoadOrCreate: %v", err)
	}
	// The signer owns the underlying CNG provider and key handles. Release them
	// via the windowscng.Signer Close contract before the program exits.
	defer func() {
		if err := signer.(windowscng.Signer).Close(); err != nil {
			log.Printf("close signer: %v", err)
		}
	}()

	// The public material is an *ecdsa.PublicKey; the canonical reference and
	// fingerprint are derived exclusively from it (no private key material).
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		log.Fatalf("Public() = %T, want *ecdsa.PublicKey", signer.Public())
	}
	encoded, err := publickey.Encode(pub)
	if err != nil {
		log.Fatalf("Encode: %v", err)
	}
	fingerprint, err := publickey.Fingerprint(pub)
	if err != nil {
		log.Fatalf("Fingerprint: %v", err)
	}
	fmt.Printf("canonical reference: %x\n", encoded)
	fmt.Printf("fingerprint:        %s\n", fingerprint)

	// Prove possession and verify through the module's verification boundary.
	challenge := []byte("server-fresh-challenge")
	signature, err := identityproof.Sign(signer, challenge)
	if err != nil {
		log.Fatalf("Sign: %v", err)
	}
	if err := identityproof.Verify(signer.Public(), challenge, signature); err != nil {
		log.Fatalf("Verify: %v", err)
	}
	fmt.Println("proof of possession verified")

	// Open opens the existing persisted key only (never creates), confirming the
	// identity is stable across separate handles.
	opened, err := keystore.Open()
	if err != nil {
		log.Fatalf("Open: %v", err)
	}
	defer func() {
		if err := opened.(windowscng.Signer).Close(); err != nil {
			log.Printf("close opened signer: %v", err)
		}
	}()

	if !pubEqual(signer.Public(), opened.Public()) {
		log.Fatal("Open returned a different persisted key than LoadOrCreate")
	}
	fmt.Println("persisted identity key is stable across Open")
}

func pubEqual(a, b any) bool {
	ea, ok := a.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	eb, ok := b.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	return ea.Curve == eb.Curve && ea.X.Cmp(eb.X) == 0 && ea.Y.Cmp(eb.Y) == 0
}
