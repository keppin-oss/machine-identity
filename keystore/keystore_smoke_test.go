//go:build windows && keystore_smoke

package keystore

// Native keystore smoke tests (opt-in, tag keystore_smoke).
//
// These tests create, use and delete REAL persisted machine-scoped CNG keys.
// They never touch the production Machine Identity key: every test key name is
// generated per run and checked against machineIdentityKeyName before any CNG
// operation. The production Open/Create/Delete entry points are not called
// here; the tests use the same unexported helpers with a per-run name and a
// ServicePolicy for a test service name that does not need to exist.
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
// SKIP. The only errors accepted are the expected outcomes each scenario
// checks: ErrKeyNotFound after a delete, ErrKeyExists for a second create,
// ErrDeleteVerificationFailed for a wrong SubjectPublicKeyInfo and
// ErrKeyPolicyMismatch for another policy.
//
// Key ownership (operational isolation, not atomic exclusivity): the name gets
// a 128-bit crypto/rand suffix and is created with Create, which never adopts
// an existing key (ErrKeyExists, and the test fails without touching it). Create
// does not reserve the name: the isolation preconditions above are what make
// the created key attributable to this run.
//
// Identity: the SubjectPublicKeyInfo of every created key is recorded from the
// signer Create returns, and every delete uses that recorded value, never one
// read by opening the key. If a create fails with an uncertain rollback
// (windowscng.ErrCleanupFailed), or its SubjectPublicKeyInfo cannot be
// recorded, the test fails naming the key and its uncertain state and deletes
// nothing by name.
//
// Cleanup: t.Cleanup is registered before any CNG call; every signer is closed
// before deletion, and Close and Delete errors are reported. A Close error is
// reported, not proof that the native handle was released, and a successful
// recovery delete does not clear an earlier FAIL. A recovery delete that
// returns ErrKeyNotFound is reported as an uncertain state, never as successful
// cleanup. This is fixture cleanup, not product recovery. If the process is
// killed and t.Cleanup does not run, keep the test output as evidence and
// restore or dispose of the sacrificial VM; do not use wildcard deletion and
// never act on the production key name.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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

	// smokeServiceName and otherServiceName name test services for the key
	// policy. The services do not need to exist; the elevated test process
	// opens the keys as a member of Administrators.
	smokeServiceName = "KeppinMachineIdentitySmoke"
	otherServiceName = "KeppinMachineIdentitySmokeOther"

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

// servicePolicy builds the ServicePolicy of a test service name.
func servicePolicy(t *testing.T, service string) windowscng.ServicePolicy {
	t.Helper()
	p, err := windowscng.NewServicePolicy(service)
	if err != nil {
		t.Fatalf("NewServicePolicy(%q): %v", service, err)
	}
	return p
}

// closeSigner closes a signer returned by the keystore helpers.
func closeSigner(s windowscng.Signer) error {
	if s == nil {
		return errors.New("nil signer")
	}
	return s.Close()
}

// sessionKey tracks a test key created by this run.
type sessionKey struct {
	name    string
	policy  windowscng.ServicePolicy
	spki    []byte // SubjectPublicKeyInfo recorded from the last successful Create
	created bool   // Create succeeded since the last confirmed delete
	signers []windowscng.Signer
}

// newSessionKey generates and guards a fresh name and registers the recovery
// cleanup before any CNG call. Cleanup closes every tracked signer and deletes
// the key with its recorded SubjectPublicKeyInfo only if it was created and
// not already deleted by the test itself.
func newSessionKey(t *testing.T) *sessionKey {
	t.Helper()
	k := &sessionKey{name: newTestKeyName(t), policy: servicePolicy(t, smokeServiceName)}
	t.Cleanup(func() { k.recover(t) })
	return k
}

// create creates the key with Create and records its SubjectPublicKeyInfo
// from the returned signer.
func (k *sessionKey) create(t *testing.T) windowscng.Signer {
	t.Helper()
	guardTestKeyName(t, k.name)
	s, err := createKey(k.name, k.policy)
	if err != nil {
		switch {
		case errors.Is(err, windowscng.ErrCleanupFailed):
			t.Fatalf("createKey(%q): rollback failed, the key may persist and its state is uncertain; nothing is deleted by name (follow the recovery procedure): %v", k.name, err)
		case errors.Is(err, ErrKeyExists):
			t.Fatalf("createKey(%q): a key already exists under the per-run name (collision); not signing, changing or deleting it: %v", k.name, err)
		}
		t.Fatalf("createKey(%q): %v", k.name, err)
	}
	k.created = true
	k.spki = nil
	k.track(s)
	spki, err := SPKI(s.Public())
	if err != nil {
		t.Fatalf("SPKI of the key created as %q: %v; no identity recorded, its state is uncertain and it is not deleted by name (follow the recovery procedure)", k.name, err)
	}
	k.spki = spki
	return s
}

// open opens the existing key under the session policy and tracks the signer.
func (k *sessionKey) open(t *testing.T) windowscng.Signer {
	t.Helper()
	guardTestKeyName(t, k.name)
	s, err := openKey(k.name, k.policy)
	if err != nil {
		t.Fatalf("openKey(%q): %v", k.name, err)
	}
	k.track(s)
	return s
}

// requireIntact reopens the key and checks that its SubjectPublicKeyInfo is
// still the recorded one.
func (k *sessionKey) requireIntact(t *testing.T) {
	t.Helper()
	s := k.open(t)
	got, err := SPKI(s.Public())
	if err != nil {
		t.Fatalf("SPKI of reopened %q: %v", k.name, err)
	}
	if !bytes.Equal(got, k.spki) {
		t.Fatalf("reopened %q has a different SubjectPublicKeyInfo than the recorded one", k.name)
	}
}

func (k *sessionKey) track(s windowscng.Signer) { k.signers = append(k.signers, s) }

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

// deleteAndConfirm closes all signers, deletes the exact key with its recorded
// SubjectPublicKeyInfo (must return nil) and reads back that it no longer
// opens for this caller. ErrKeyNotFound on the readback is the expected
// outcome; it is not proof of absence. The recorded value is kept, so a
// repeated delete of the same key can use it.
func (k *sessionKey) deleteAndConfirm(t *testing.T) bool {
	t.Helper()
	guardTestKeyName(t, k.name)
	if !k.closeAll(t) {
		return false
	}
	if err := deleteKey(k.name, k.policy, k.spki); err != nil {
		t.Errorf("deleteKey(%q) = %v, want nil", k.name, err)
		return false
	}
	k.created = false
	s, err := openKey(k.name, k.policy)
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
// again; a key left behind by a failure is deleted with its recorded
// SubjectPublicKeyInfo and the outcome reported. Without a recorded value
// nothing is deleted.
func (k *sessionKey) recover(t *testing.T) {
	k.closeAll(t)
	if !k.created {
		return
	}
	guardTestKeyName(t, k.name)
	if len(k.spki) == 0 {
		t.Errorf("recovery cleanup of %q: no recorded SubjectPublicKeyInfo, nothing deleted; key state uncertain, follow the recovery procedure", k.name)
		return
	}
	err := deleteKey(k.name, k.policy, k.spki)
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

// signAndVerify proves possession through the Machine Identity proof contract.
func signAndVerify(t *testing.T, s crypto.Signer, pub crypto.PublicKey, label string) {
	t.Helper()
	challenge := []byte("keppin-machine-identity-smoke-challenge")
	sig, err := identityproof.Sign(s, challenge)
	if err != nil {
		t.Fatalf("%s: identityproof.Sign: %v", label, err)
	}
	if err := identityproof.Verify(pub, challenge, sig); err != nil {
		t.Fatalf("%s: identityproof.Verify: %v", label, err)
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
	signAndVerify(t, signer, signer.Public(), "created")

	opened := k.open(t)
	if !pubEqual(signer.Public(), opened.Public()) {
		t.Fatal("openKey returned a different persisted key than createKey")
	}
	signAndVerify(t, opened, signer.Public(), "reopened")

	if !k.deleteAndConfirm(t) {
		t.FailNow()
	}
	t.Log("scenarios run: create, sign/verify, reopen, same key, sign/verify reopened, delete, readback")
}

// TestSmokeDeleteKeyLifecycle exercises the destructive lifecycle twice on the
// same per-run test key name: create, sign/verify, close, exact delete with the
// recorded SubjectPublicKeyInfo, readback, repeated delete with the same value.
func TestSmokeDeleteKeyLifecycle(t *testing.T) {
	requireNativeSmoke(t)
	k := newSessionKey(t)

	for i := 1; i <= 2; i++ {
		signer := k.create(t)
		signAndVerify(t, signer, signer.Public(), fmt.Sprintf("iteration %d", i))

		// Close before delete (documented ownership contract).
		if err := closeSigner(signer); err != nil {
			t.Fatalf("iteration %d: close: %v", i, err)
		}

		if !k.deleteAndConfirm(t) {
			t.Fatalf("iteration %d: delete/readback failed", i)
		}

		// A repeated delete with the SubjectPublicKeyInfo of this iteration
		// returns ErrKeyNotFound: this call deleted nothing. It is not an
		// additional proof of cleanup.
		if err := deleteKey(k.name, k.policy, k.spki); !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("iteration %d: second deleteKey = %v, want ErrKeyNotFound", i, err)
		}
	}
	t.Log("scenarios run: 2x (create, sign/verify, close, delete, readback, repeated delete)")
}

// TestSmokeCreateExistingKeyNotAdopted proves a second Create on an existing
// key returns ErrKeyExists without a signer and leaves the key intact.
func TestSmokeCreateExistingKeyNotAdopted(t *testing.T) {
	requireNativeSmoke(t)
	k := newSessionKey(t)
	k.create(t)

	s, err := createKey(k.name, k.policy)
	if err == nil {
		k.track(s)
		t.Fatalf("second createKey(%q) succeeded, want ErrKeyExists", k.name)
	}
	if s != nil {
		t.Fatal("second createKey returned a signer with an error")
	}
	if !errors.Is(err, ErrKeyExists) {
		t.Fatalf("second createKey(%q) = %v, want ErrKeyExists", k.name, err)
	}
	var ne *windowscng.NCryptError
	if !errors.As(err, &ne) || ne.Code != windowscng.NTEExists {
		t.Fatalf("second createKey(%q): native status NTE_EXISTS not reachable: %v", k.name, err)
	}
	k.requireIntact(t)

	if !k.deleteAndConfirm(t) {
		t.FailNow()
	}
	t.Log("scenarios run: create, second create refused (ErrKeyExists), key intact, delete, readback")
}

// TestSmokeDeleteWrongSPKIRefused proves a delete with the SubjectPublicKeyInfo
// of another valid P-256 key is refused and deletes nothing.
func TestSmokeDeleteWrongSPKIRefused(t *testing.T) {
	requireNativeSmoke(t)
	k := newSessionKey(t)
	k.create(t)

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := SPKI(other.Public())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(wrong, k.spki) {
		t.Fatal("generated key has the same SubjectPublicKeyInfo as the test key")
	}
	if !k.closeAll(t) {
		t.FailNow()
	}
	if err := deleteKey(k.name, k.policy, wrong); !errors.Is(err, ErrDeleteVerificationFailed) {
		t.Fatalf("deleteKey(%q) with another key's SubjectPublicKeyInfo = %v, want ErrDeleteVerificationFailed", k.name, err)
	}
	k.requireIntact(t)

	if !k.deleteAndConfirm(t) {
		t.FailNow()
	}
	t.Log("scenarios run: create, delete with another P-256 SPKI refused, key intact, delete, readback")
}

// TestSmokeOpenOtherPolicyMismatch proves an open under another service's
// policy returns ErrKeyPolicyMismatch and leaves the key intact.
func TestSmokeOpenOtherPolicyMismatch(t *testing.T) {
	requireNativeSmoke(t)
	k := newSessionKey(t)
	k.create(t)

	s, err := openKey(k.name, servicePolicy(t, otherServiceName))
	if err == nil {
		k.track(s)
		t.Fatalf("openKey(%q) under another service policy succeeded, want ErrKeyPolicyMismatch", k.name)
	}
	if !errors.Is(err, ErrKeyPolicyMismatch) {
		t.Fatalf("openKey(%q) under another service policy = %v, want ErrKeyPolicyMismatch", k.name, err)
	}
	k.requireIntact(t)

	if !k.deleteAndConfirm(t) {
		t.FailNow()
	}
	t.Log("scenarios run: create, open under another policy refused, key intact, delete, readback")
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
	return ea.Equal(eb)
}
