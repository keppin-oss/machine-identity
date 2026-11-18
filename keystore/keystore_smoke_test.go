//go:build windows && keystore_smoke

package keystore

// Native keystore smoke tests (opt-in, tag keystore_smoke).
//
// These tests create, use and delete REAL persisted machine-scoped CNG keys.
// They never touch the production Machine Identity key: every test key name is
// generated per run and checked against machineIdentityKeyName before any CNG
// operation. The production LoadOrCreate/Open/Delete entry points are not
// called here.
//
// Preconditions (see docs/README.md, "Native smoke tests"):
//   - a sacrificial, exclusive test VM: no production identity, no concurrent
//     runs, no other writer on the Keppin.Test. key namespace;
//   - an elevated (Administrator) process, or LocalSystem.
//
// Elevation is read from the process token before any CNG call. Only a caller
// the token reports as certainly not elevated produces SKIP; a failure to read
// the token is a FAIL. With KEPPIN_KEYSTORE_SMOKE_REQUIRED=1 a non-elevated
// caller is a FAIL too. Every unexpected error (provider, DACL, export policy,
// provisioning, rollback) is a FAIL, and no CNG error is ever turned into a
// SKIP. The only CNG errors accepted are the expected ErrKeyNotFound outcomes
// of the pre-check, the post-delete readback and the repeated delete.
//
// Key ownership (operational isolation, not atomic exclusivity): the name gets
// a 128-bit crypto/rand suffix, and a pre-check with Open must report
// ErrKeyNotFound before the key is created. ErrKeyNotFound is not proof of
// absence, LoadOrCreate does not certify that it created the key, and a key
// appearing between the pre-check and LoadOrCreate is not excluded (TOCTOU).
// The isolation preconditions above are what make the created key attributable
// to this run. If the pre-check opens a key, the signer is closed and the test
// fails for collision without signing, changing or deleting that key.
//
// Cleanup: t.Cleanup is registered before the pre-check, so before any attempt
// by the smoke to create a key (this does not prove that no key exists); every
// signer is closed before deletion, and Close and Delete errors are reported. A Close error is reported, not proof that the native handle
// was released, and a successful recovery delete does not clear an earlier
// FAIL. A recovery delete
// that returns ErrKeyNotFound is reported as an uncertain state, never as
// successful cleanup. If the process is killed and t.Cleanup does not run,
// keep the test output as evidence and restore or dispose of the sacrificial
// VM; do not use wildcard deletion and never act on the production key name.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"github.com/keppin-oss/cng/windowscng"
	"github.com/keppin-oss/machine-identity/identityproof"
)

const (
	// smokeRequiredEnv makes a non-elevated caller a FAIL instead of a SKIP.
	smokeRequiredEnv = "KEPPIN_KEYSTORE_SMOKE_REQUIRED"

	// testKeyPrefix is the only namespace the smoke tests may create or delete.
	testKeyPrefix = "Keppin.Test.MachineIdentity."

	// tokenElevationClass is TOKEN_INFORMATION_CLASS TokenElevation.
	tokenElevationClass = 20

	// localSystemSID is the well-known LocalSystem account SID.
	localSystemSID = "S-1-5-18"
)

// requireNativeSmoke decides, from the process token and before any CNG call,
// whether the native scenarios run.
func requireNativeSmoke(t *testing.T) {
	t.Helper()
	privileged, who, err := processPrivilege()
	if err != nil {
		t.Fatalf("cannot determine process elevation: %v", err)
	}
	if !privileged {
		if os.Getenv(smokeRequiredEnv) == "1" {
			t.Fatalf("process is not elevated (%s) and %s=1 requires the native smoke to run", who, smokeRequiredEnv)
		}
		t.Skipf("process is not elevated (%s); native smoke not run (set %s=1 to make this a failure)", who, smokeRequiredEnv)
	}
	t.Logf("native smoke running as %s", who)
}

// processPrivilege reports whether the current process token is elevated or
// belongs to LocalSystem. LocalSystem is accepted explicitly as a privileged
// context.
func processPrivilege() (privileged bool, who string, err error) {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return false, "", err
	}
	defer func() {
		// A failure to close the token handle is reported, so the gate never
		// hides it; it makes the elevation result a FAIL, not a SKIP.
		if cerr := token.Close(); cerr != nil {
			privileged, who = false, ""
			err = errors.Join(err, fmt.Errorf("close process token: %w", cerr))
		}
	}()

	user, err := token.GetTokenUser()
	if err != nil {
		return false, "", err
	}
	sid, err := user.User.Sid.String()
	if err != nil {
		return false, "", err
	}
	if sid == localSystemSID {
		return true, "LocalSystem", nil
	}

	var elevated uint32
	var returned uint32
	err = syscall.GetTokenInformation(token, tokenElevationClass,
		(*byte)(unsafe.Pointer(&elevated)), uint32(unsafe.Sizeof(elevated)), &returned)
	if err != nil {
		return false, "", err
	}
	if returned != uint32(unsafe.Sizeof(elevated)) {
		return false, "", errors.New("unexpected TokenElevation size")
	}
	if elevated != 0 {
		return true, "elevated token " + sid, nil
	}
	return false, "non-elevated token " + sid, nil
}

// newTestKeyName returns a per-run key name with a 128-bit random suffix.
func newTestKeyName(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	name := testKeyPrefix + hex.EncodeToString(b[:])
	guardTestKeyName(t, name)
	return name
}

// guardTestKeyName must run before any CNG operation on name.
func guardTestKeyName(t *testing.T, name string) {
	t.Helper()
	if name == machineIdentityKeyName || strings.EqualFold(name, machineIdentityKeyName) {
		t.Fatalf("test key name %q collides with the production key name", name)
	}
	if !strings.HasPrefix(name, testKeyPrefix) {
		t.Fatalf("test key name %q is outside the %q namespace", name, testKeyPrefix)
	}
}

// precheckUnused requires that name cannot be opened before creation. It does
// not prove absence: see the package-level ownership note.
func precheckUnused(t *testing.T, name string) {
	t.Helper()
	guardTestKeyName(t, name)
	s, err := openKey(name)
	if err == nil {
		cerr := closeSigner(s)
		t.Fatalf("pre-check opened an existing key %q (collision); not signing, changing or deleting it; close error: %v", name, cerr)
	}
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("pre-check of %q failed with an unclassified error, not creating: %v", name, err)
	}
}

// closeSigner closes a signer returned by the keystore helpers.
func closeSigner(s crypto.Signer) error {
	c, ok := s.(windowscng.Signer)
	if !ok {
		return errors.New("signer does not implement windowscng.Signer")
	}
	return c.Close()
}

// sessionKey tracks a test key created by this run.
type sessionKey struct {
	name    string
	created bool // LoadOrCreate succeeded since the last confirmed delete
	signers []crypto.Signer
}

// newSessionKey generates and guards a fresh name and registers the recovery
// cleanup before any CNG call; the pre-check runs later, in create. Cleanup
// closes every tracked signer and deletes the key only if it was created and
// not already deleted by the test itself.
func newSessionKey(t *testing.T) *sessionKey {
	t.Helper()
	k := &sessionKey{name: newTestKeyName(t)}
	t.Cleanup(func() { k.recover(t) })
	return k
}

// create pre-checks and creates the key with the production profile.
func (k *sessionKey) create(t *testing.T) crypto.Signer {
	t.Helper()
	precheckUnused(t, k.name)
	s, err := loadOrCreateKey(k.name)
	if err != nil {
		if errors.Is(err, windowscng.ErrCleanupFailed) {
			t.Fatalf("loadOrCreateKey(%q): rollback failed, a residual key may persist (follow the recovery procedure): %v", k.name, err)
		}
		t.Fatalf("loadOrCreateKey(%q): %v", k.name, err)
	}
	k.created = true
	k.track(s)
	return s
}

// open opens the existing key and tracks the signer.
func (k *sessionKey) open(t *testing.T) crypto.Signer {
	t.Helper()
	guardTestKeyName(t, k.name)
	s, err := openKey(k.name)
	if err != nil {
		t.Fatalf("openKey(%q): %v", k.name, err)
	}
	k.track(s)
	return s
}

func (k *sessionKey) track(s crypto.Signer) { k.signers = append(k.signers, s) }

// closeAll closes every tracked signer and reports each failure. Close is
// idempotent, so signers already closed by the test report nil here.
func (k *sessionKey) closeAll(t *testing.T) bool {
	t.Helper()
	ok := true
	for i, s := range k.signers {
		if err := closeSigner(s); err != nil {
			t.Errorf("close signer %d of %q: %v", i, k.name, err)
			ok = false
		}
	}
	k.signers = nil
	return ok
}

// deleteAndConfirm closes all signers, deletes the exact key (must return nil)
// and reads back that it no longer opens for this caller. ErrKeyNotFound on
// the readback is the expected outcome; it is not proof of absence.
func (k *sessionKey) deleteAndConfirm(t *testing.T) bool {
	t.Helper()
	guardTestKeyName(t, k.name)
	if !k.closeAll(t) {
		return false
	}
	if err := deleteKey(k.name); err != nil {
		t.Errorf("deleteKey(%q) = %v, want nil", k.name, err)
		return false
	}
	k.created = false
	s, err := openKey(k.name)
	if err == nil {
		cerr := closeSigner(s)
		t.Errorf("openKey(%q) after delete succeeded: key still present (close error: %v)", k.name, cerr)
		return false
	}
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("openKey(%q) after delete = %v, want ErrKeyNotFound", k.name, err)
		return false
	}
	return true
}

// recover runs as t.Cleanup. A key already deleted by the test is not deleted
// again; a key left behind by a failure is deleted and the outcome reported.
func (k *sessionKey) recover(t *testing.T) {
	k.closeAll(t)
	if !k.created {
		return
	}
	guardTestKeyName(t, k.name)
	err := deleteKey(k.name)
	switch {
	case err == nil:
		k.created = false
		t.Logf("recovery cleanup deleted test key %q", k.name)
	case errors.Is(err, ErrKeyNotFound):
		t.Errorf("recovery cleanup of %q deleted nothing (not found or not accessible): key state uncertain, follow the recovery procedure: %v", k.name, err)
	default:
		t.Errorf("recovery cleanup of %q failed, a key may persist: %v", k.name, err)
	}
}

// TestSmokeMachineIdentityKeyCustody exercises custody end to end on a per-run
// test key with the production profile: create, sign, verify, reopen, confirm
// the same persisted key, sign with the reopened handle, then delete it.
func TestSmokeMachineIdentityKeyCustody(t *testing.T) {
	requireNativeSmoke(t)
	k := newSessionKey(t)

	signer := k.create(t)
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

	opened := k.open(t)
	if !pubEqual(signer.Public(), opened.Public()) {
		t.Fatal("openKey returned a different persisted key than loadOrCreateKey")
	}
	sig2, err := identityproof.Sign(opened, challenge)
	if err != nil {
		t.Fatalf("identityproof.Sign (reopened): %v", err)
	}
	if err := identityproof.Verify(signer.Public(), challenge, sig2); err != nil {
		t.Fatalf("identityproof.Verify (reopened): %v", err)
	}

	if !k.deleteAndConfirm(t) {
		t.FailNow()
	}
	t.Log("scenarios run: create, sign/verify, reopen, same key, sign/verify reopened, delete, readback")
}

// TestSmokeDeleteKeyLifecycle exercises the destructive lifecycle twice on the
// same per-run test key name: pre-check, create, sign/verify, close, exact
// delete, readback, repeated delete.
func TestSmokeDeleteKeyLifecycle(t *testing.T) {
	requireNativeSmoke(t)
	k := newSessionKey(t)

	for i := 1; i <= 2; i++ {
		signer := k.create(t)

		challenge := []byte("keppin-cleanup-lifecycle-challenge")
		sig, err := identityproof.Sign(signer, challenge)
		if err != nil {
			t.Fatalf("iteration %d: sign: %v", i, err)
		}
		if err := identityproof.Verify(signer.Public(), challenge, sig); err != nil {
			t.Fatalf("iteration %d: verify: %v", i, err)
		}

		// Close before delete (documented ownership contract).
		if err := closeSigner(signer); err != nil {
			t.Fatalf("iteration %d: close: %v", i, err)
		}

		if !k.deleteAndConfirm(t) {
			t.Fatalf("iteration %d: delete/readback failed", i)
		}

		// A repeated delete returns ErrKeyNotFound: this call deleted nothing.
		// It is not an additional proof of cleanup.
		if err := deleteKey(k.name); !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("iteration %d: second deleteKey = %v, want ErrKeyNotFound", i, err)
		}
	}
	t.Log("scenarios run: 2x (pre-check, create, sign/verify, close, delete, readback, repeated delete)")
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
