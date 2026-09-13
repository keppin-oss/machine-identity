//go:build windows

package keystore

import (
	"errors"
	"testing"

	"github.com/keppin-oss/machine-identity/identity"
)

// TestDeleteTargetsExactKeyName locks the exact production key name that
// Delete() removes. No wildcard/prefix deletion is permitted.
func TestDeleteTargetsExactKeyName(t *testing.T) {
	if machineIdentityKeyName != "Keppin.Agent.MachineIdentity.v1" {
		t.Errorf("machineIdentityKeyName = %q, want %q", machineIdentityKeyName, "Keppin.Agent.MachineIdentity.v1")
	}
	if machineIdentityKeyName != identity.ProdMachineIdentityKeyName {
		t.Errorf("machineIdentityKeyName = %q, want identity.ProdMachineIdentityKeyName %q", machineIdentityKeyName, identity.ProdMachineIdentityKeyName)
	}
}

// TestErrKeyNotFoundSentinel asserts the not-found sentinel exists and is a
// distinct error so callers can treat idempotent cleanup explicitly.
func TestErrKeyNotFoundSentinel(t *testing.T) {
	if ErrKeyNotFound == nil {
		t.Fatal("ErrKeyNotFound must be non-nil")
	}
	if errors.Is(ErrKeyNotFound, ErrKeyNotFound) != true {
		t.Fatal("ErrKeyNotFound must be matchable via errors.Is with itself")
	}
}

// TestDeleteMissingKeyReturnsNotFound verifies the not-found contract: deleting
// an already-absent key returns ErrKeyNotFound rather than creating replacement
// state or returning a generic failure. This does not require elevation because
// opening an absent machine key fails before any mutation.
func TestDeleteMissingKeyReturnsNotFound(t *testing.T) {
	name := "Keppin.Test.MachineIdentity.Cleanup.DoesNotExist.v1"
	err := deleteKey(name)
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("deleteKey(missing) = %v, want ErrKeyNotFound", err)
	}
}
