//go:build windows && keystore_smoke

package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"testing"

	"github.com/keppin-oss/cng/windowscng"
	"github.com/keppin-oss/machine-identity/identityproof"
)

// TestSmokeMachineIdentityKeyCustody exercises the real persisted machine-scoped
// Machine Identity key end to end: create/open, sign, verify, and confirm the
// two operations return the same persisted key.
//
// It is gated behind the keystore_smoke build tag and requires an elevated
// (Administrator) process because NCryptCreatePersistedKey with machine scope
// needs administrative rights. It is never run by `go test ./...`.
func TestSmokeMachineIdentityKeyCustody(t *testing.T) {
	signer, err := LoadOrCreate()
	if err != nil {
		t.Skipf("skipping machine-identity smoke test (LoadOrCreate requires an elevated process): %v", err)
	}
	defer signer.(windowscng.Signer).Close()

	if _, ok := signer.Public().(*ecdsa.PublicKey); !ok {
		t.Fatalf("Public() = %T, want *ecdsa.PublicKey", signer.Public())
	}

	challenge := []byte("keppin-machine-identity-smoke-challenge")
	sig, err := identityproof.Sign(signer, challenge)
	if err != nil {
		t.Fatalf("identityproof.Sign: %v", err)
	}
	if err := identityproof.Verify(signer.Public(), challenge, sig); err != nil {
		t.Fatalf("identityproof.Verify: %v", err)
	}

	opened, err := Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer opened.(windowscng.Signer).Close()

	if !pubEqual(signer.Public(), opened.Public()) {
		t.Fatal("Open returned a different persisted key than LoadOrCreate")
	}
}

func pubEqual(a, b crypto.PublicKey) bool {
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

// testLifecycleKeyName is a dedicated test-namespace key used by the delete
// lifecycle smoke test. It must never equal the production key name.
const testLifecycleKeyName = "Keppin.Test.MachineIdentity.Cleanup.Lifecycle.v1"

// TestSmokeDeleteKeyLifecycle exercises the full destructive lifecycle against
// a dedicated test-namespace key: create (same profile), open/sign, close,
// delete exact key, verify absent, and repeat. It never touches the production
// Machine Identity key.
//
// Gated behind keystore_smoke and requires an elevated process.
func TestSmokeDeleteKeyLifecycle(t *testing.T) {
	if testLifecycleKeyName == machineIdentityKeyName {
		t.Fatal("test key name collides with production key name")
	}

	// Probe elevation by creating the test key once; skip if not elevated.
	signer, err := loadOrCreateKey(testLifecycleKeyName)
	if err != nil {
		t.Skipf("skipping delete lifecycle smoke test (requires elevated process): %v", err)
	}
	signer.(windowscng.Signer).Close()

	for i := 1; i <= 2; i++ {
		if err := runDeleteLifecycle(testLifecycleKeyName); err != nil {
			t.Fatalf("lifecycle iteration %d: %v", i, err)
		}
	}
}

func runDeleteLifecycle(name string) error {
	// 1. create persisted test key using the same production profile.
	signer, err := loadOrCreateKey(name)
	if err != nil {
		return fmt.Errorf("loadOrCreateKey: %w", err)
	}

	// 2. open/sign successfully.
	challenge := []byte("keppin-cleanup-lifecycle-challenge")
	sig, err := identityproof.Sign(signer, challenge)
	if err != nil {
		signer.(windowscng.Signer).Close()
		return fmt.Errorf("sign: %w", err)
	}
	if err := identityproof.Verify(signer.Public(), challenge, sig); err != nil {
		signer.(windowscng.Signer).Close()
		return fmt.Errorf("verify: %w", err)
	}

	// 3. close signer (documented ownership contract: close before delete).
	if err := signer.(windowscng.Signer).Close(); err != nil {
		return err
	}

	// 4. delete the exact key.
	if err := deleteKey(name); err != nil {
		return fmt.Errorf("deleteKey: %w", err)
	}

	// 5. verify open-only fails because the key is absent.
	if _, err := openKey(name); err == nil {
		return fmt.Errorf("openKey succeeded after delete: key still present")
	}

	// 5b. a repeated delete is idempotent and returns ErrKeyNotFound.
	if err := deleteKey(name); !errors.Is(err, ErrKeyNotFound) {
		return fmt.Errorf("second deleteKey = %v, want ErrKeyNotFound", err)
	}

	return nil
}
