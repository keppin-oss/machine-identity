//go:build windows

// Command machineidentity demonstrates the persisted Machine Identity flow on
// Windows: open the machine-scoped identity key, obtain the canonical public
// reference and fingerprint, prove possession of the key by signing a
// challenge, and verify that proof.
//
// The key policy is the ServicePolicy of the Windows service that uses the
// key, named with -service. The service does not need to exist for the policy
// to be built, but only that service, SYSTEM and Administrators are granted
// access to the key.
//
// By default the example only opens the existing key and never creates one: a
// key that cannot be opened is an error, never a reason to create it. With
// -create it creates the key instead, which requires an elevated
// (Administrator) or LocalSystem process and fails if a key already exists.
// The SubjectPublicKeyInfo of the new key is printed in base64 immediately
// after the create, before any other step that can fail: it is the identity
// that a later delete requires and the caller must record it durably. This
// output is not a durable record. If it cannot be written, the example stops
// before signing and reports that the key was already created.
//
// This example is non-destructive: it never deletes the key. Deleting the
// identity destroys the prior proof capability and is a decision for a
// higher-level, authorized flow.
package main

import (
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"

	"github.com/keppin-oss/cng/windowscng"
	"github.com/keppin-oss/machine-identity/identityproof"
	"github.com/keppin-oss/machine-identity/keystore"
	"github.com/keppin-oss/machine-identity/publickey"
)

func main() {
	service := flag.String("service", "", "name of the Windows service that uses the key (required)")
	create := flag.Bool("create", false, "create the key instead of opening it (elevated; fails if a key exists)")
	flag.Parse()
	if err := run(*service, *create); err != nil {
		log.Fatal(err)
	}
}

// run returns every error instead of exiting, so the deferred Close always
// releases the signer handles.
func run(service string, create bool) (err error) {
	if service == "" {
		return errors.New("-service is required")
	}
	policy, err := windowscng.NewServicePolicy(service)
	if err != nil {
		return fmt.Errorf("service policy: %w", err)
	}

	var signer windowscng.Signer
	if create {
		signer, err = keystore.Create(policy)
		if err != nil {
			return fmt.Errorf("Create: %w", err)
		}
	} else {
		signer, err = keystore.Open(policy)
		if err != nil {
			return fmt.Errorf("Open: %w", err)
		}
	}
	// The signer owns the underlying CNG provider and key handles. Release them
	// before returning; the persisted key stays.
	defer func() {
		if cerr := signer.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("close signer: %w", cerr))
		}
	}()

	if create {
		spki, err := keystore.SPKI(signer.Public())
		if err != nil {
			return fmt.Errorf("the key was created and persists, but its SPKI could not be encoded: %w", err)
		}
		if _, err := fmt.Printf("created key SPKI (DER, base64): %s\n", base64.StdEncoding.EncodeToString(spki)); err != nil {
			return fmt.Errorf("the key was created and persists, but its SPKI could not be written; stopping before signing: %w", err)
		}
	}

	// The public material is an *ecdsa.PublicKey; the canonical reference and
	// fingerprint are derived exclusively from it (no private key material).
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("Public() = %T, want *ecdsa.PublicKey", signer.Public())
	}
	encoded, err := publickey.Encode(pub)
	if err != nil {
		return fmt.Errorf("Encode: %w", err)
	}
	fingerprint, err := publickey.Fingerprint(pub)
	if err != nil {
		return fmt.Errorf("Fingerprint: %w", err)
	}
	fmt.Printf("canonical reference: %x\n", encoded)
	fmt.Printf("fingerprint:        %s\n", fingerprint)

	// Prove possession and verify through the module's verification boundary.
	challenge := []byte("server-fresh-challenge")
	signature, err := identityproof.Sign(signer, challenge)
	if err != nil {
		return fmt.Errorf("Sign: %w", err)
	}
	if err := identityproof.Verify(signer.Public(), challenge, signature); err != nil {
		return fmt.Errorf("Verify: %w", err)
	}
	fmt.Println("proof of possession verified")
	return nil
}
