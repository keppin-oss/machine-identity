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

// TestProdKeyNameUsesKeppinAgentNamespace asserts the production machine
// identity key lives in the Keppin Agent key namespace and carries an explicit
// version suffix.
func TestProdKeyNameUsesKeppinAgentNamespace(t *testing.T) {
	const namespace = "Keppin.Agent."
	if !strings.HasPrefix(ProdMachineIdentityKeyName, namespace) {
		t.Fatalf("ProdMachineIdentityKeyName = %q must be in the %q namespace", ProdMachineIdentityKeyName, namespace)
	}
	if !strings.HasSuffix(ProdMachineIdentityKeyName, ".v1") {
		t.Fatalf("ProdMachineIdentityKeyName = %q must carry the .v1 version suffix", ProdMachineIdentityKeyName)
	}
}
