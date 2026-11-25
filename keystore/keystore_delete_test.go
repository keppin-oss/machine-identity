//go:build windows

package keystore

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/keppin-oss/cng/windowscng"
	"github.com/keppin-oss/machine-identity/identity"
)

// TestDeleteTargetsExactKeyName locks the exact production key name that Open,
// Create and Delete operate on. No wildcard/prefix deletion is permitted.
func TestDeleteTargetsExactKeyName(t *testing.T) {
	if machineIdentityKeyName != "Keppin.Agent.MachineIdentity.v1" {
		t.Errorf("machineIdentityKeyName = %q, want %q", machineIdentityKeyName, "Keppin.Agent.MachineIdentity.v1")
	}
	if machineIdentityKeyName != identity.ProdMachineIdentityKeyName {
		t.Errorf("machineIdentityKeyName = %q, want identity.ProdMachineIdentityKeyName %q", machineIdentityKeyName, identity.ProdMachineIdentityKeyName)
	}
}

// TestErrKeyNotFoundSentinel asserts the sentinel exists, is distinct from the
// shared windowscng sentinel, and that its text states it is not proof of
// absence. It does not assert idempotent cleanup: the sentinel only means
// "not found or not accessible".
func TestErrKeyNotFoundSentinel(t *testing.T) {
	if ErrKeyNotFound == nil {
		t.Fatal("ErrKeyNotFound must be non-nil")
	}
	if !errors.Is(ErrKeyNotFound, ErrKeyNotFound) {
		t.Fatal("ErrKeyNotFound must be matchable via errors.Is with itself")
	}
	if errors.Is(ErrKeyNotFound, windowscng.ErrKeyNotFound) {
		t.Fatal("ErrKeyNotFound must be distinct from the shared sentinel")
	}
	if !strings.Contains(ErrKeyNotFound.Error(), "not accessible") {
		t.Fatalf("ErrKeyNotFound text %q must say the key may be not accessible", ErrKeyNotFound.Error())
	}
}

// TestMapCNGErrorDeleteShapedNotFound verifies, synthetically and without any
// CNG call, that mapCNGError classifies an error shaped like the one the shared
// Delete returns for a missing or inaccessible key as ErrKeyNotFound while
// keeping the native status. It tests the mapper only: it does not call Delete,
// does not prove that Delete routes its error through mapCNGError (that wiring
// is in deleteKey), and says nothing about whether the key is absent. The
// native Delete of a real key is covered only by the opt-in keystore_smoke
// tests.
func TestMapCNGErrorDeleteShapedNotFound(t *testing.T) {
	native := &windowscng.NCryptError{Op: "NCryptOpenKey", Code: windowscng.NTEBadKeyset}
	shared := fmt.Errorf("delete key: %w: %w", windowscng.ErrKeyNotFound, native)

	err := mapCNGError(shared)
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("mapCNGError = %v, want ErrKeyNotFound", err)
	}
	var ne *windowscng.NCryptError
	if !errors.As(err, &ne) || ne.Code != windowscng.NTEBadKeyset {
		t.Fatalf("native status lost: %v", err)
	}
}
