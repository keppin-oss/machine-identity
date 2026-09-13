package identity

import (
	"strings"
	"testing"
)

// TestExactCurrentValues asserts the byte-for-byte identity of every
// persisted / compatibility-contract constant. These tests are the safety net
// for the machine identity naming contract — they fail and require explicit
// review if the persisted identity changes.
func TestExactCurrentValues(t *testing.T) {
	t.Run("prod machine identity key name", func(t *testing.T) {
		if ProdMachineIdentityKeyName != "Keppin.Agent.MachineIdentity.v1" {
			t.Errorf("ProdMachineIdentityKeyName = %q, want %q", ProdMachineIdentityKeyName, "Keppin.Agent.MachineIdentity.v1")
		}
	})
}

// TestNoWonderWandNamespace asserts the production machine identity does not
// use the inherited WonderWand namespace.
func TestNoWonderWandNamespace(t *testing.T) {
	if strings.Contains(ProdMachineIdentityKeyName, "WonderWand") {
		t.Fatalf("ProdMachineIdentityKeyName = %q must not contain the WonderWand namespace", ProdMachineIdentityKeyName)
	}
}
