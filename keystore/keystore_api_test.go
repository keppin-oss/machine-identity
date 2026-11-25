//go:build windows

package keystore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"testing"

	"github.com/keppin-oss/cng/windowscng"
)

// These tests exercise Open, Create and Delete through the cngKeyAPI seam with
// in-memory fakes. They prove that the keystore forwards the exact name,
// policy and expected SubjectPublicKeyInfo to the shared layer, makes no
// fallback call, and maps the outcome. They do not re-implement the CNG
// checks, which belong to windowscng, and they never touch a machine key.

// testPolicy returns a valid ServicePolicy for a service that does not need to
// exist.
func testPolicy(t *testing.T) windowscng.ServicePolicy {
	t.Helper()
	p, err := windowscng.NewServicePolicy("KeppinMachineIdentityUnitTest")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// fakeSigner is a windowscng.Signer over an in-memory key.
type fakeSigner struct {
	pub    crypto.PublicKey
	closed int
}

func (s *fakeSigner) Public() crypto.PublicKey { return s.pub }
func (s *fakeSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("fake signer does not sign")
}
func (s *fakeSigner) Close() error { s.closed++; return nil }

// recordingAPI records every call made through the seam.
type recordingAPI struct {
	opens, creates, deletes []call
	openRet, createRet      windowscng.Signer
	openErr, createErr      error
	deleteErr               error
}

type call struct {
	name   string
	policy windowscng.ServicePolicy
	spki   []byte
}

func (r *recordingAPI) api() cngKeyAPI {
	return cngKeyAPI{
		open: func(name string, p windowscng.ServicePolicy) (windowscng.Signer, error) {
			r.opens = append(r.opens, call{name: name, policy: p})
			return r.openRet, r.openErr
		},
		create: func(name string, p windowscng.ServicePolicy) (windowscng.Signer, error) {
			r.creates = append(r.creates, call{name: name, policy: p})
			return r.createRet, r.createErr
		},
		delete: func(name string, p windowscng.ServicePolicy, spki []byte) error {
			r.deletes = append(r.deletes, call{name: name, policy: p, spki: bytes.Clone(spki)})
			return r.deleteErr
		},
	}
}

func (r *recordingAPI) requireCalls(t *testing.T, opens, creates, deletes int) {
	t.Helper()
	if len(r.opens) != opens || len(r.creates) != creates || len(r.deletes) != deletes {
		t.Fatalf("calls: open=%d create=%d delete=%d, want open=%d create=%d delete=%d",
			len(r.opens), len(r.creates), len(r.deletes), opens, creates, deletes)
	}
}

func requireCall(t *testing.T, got call, name string, policy windowscng.ServicePolicy) {
	t.Helper()
	if got.name != name {
		t.Fatalf("name = %q, want %q", got.name, name)
	}
	if got.policy != policy {
		t.Fatalf("policy = %v, want %v", got.policy, policy)
	}
}

func newP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestOpenForwardsExactNameAndPolicy(t *testing.T) {
	p := testPolicy(t)
	want := &fakeSigner{pub: newP256(t).Public()}
	r := &recordingAPI{openRet: want}
	s, err := openKeyWith(r.api(), machineIdentityKeyName, p)
	if err != nil {
		t.Fatal(err)
	}
	if s != want {
		t.Fatalf("signer = %v, want the signer returned by the shared layer", s)
	}
	r.requireCalls(t, 1, 0, 0)
	requireCall(t, r.opens[0], machineIdentityKeyName, p)
}

// TestOpenNotFoundNeverCreates proves a failed open is reported, not repaired:
// no create follows ErrKeyNotFound or ErrKeyPolicyMismatch.
func TestOpenNotFoundNeverCreates(t *testing.T) {
	for _, upstream := range []error{windowscng.ErrKeyNotFound, windowscng.ErrPolicyMismatch} {
		r := &recordingAPI{openErr: fmt.Errorf("open: %w", upstream)}
		s, err := openKeyWith(r.api(), machineIdentityKeyName, testPolicy(t))
		if s != nil {
			t.Fatalf("%v: signer returned on error", upstream)
		}
		if !errors.Is(err, upstream) {
			t.Fatalf("%v: upstream sentinel lost: %v", upstream, err)
		}
		r.requireCalls(t, 1, 0, 0)
	}
}

// TestOpenRejectsZeroPolicyBeforeNativeCall uses the real shared layer on a
// synthetic name that is neither the production name nor in the smoke test
// namespace: the zero ServicePolicy is rejected as input, before any native
// call, with an error that matches no sentinel. The test observes the error;
// it does not count native calls.
func TestOpenRejectsZeroPolicyBeforeNativeCall(t *testing.T) {
	const name = "Keppin.UnitTest.MachineIdentity.ZeroPolicy"
	if name == machineIdentityKeyName {
		t.Fatal("synthetic name collides with the production key name")
	}
	s, err := openKey(name, windowscng.ServicePolicy{})
	if err == nil {
		_ = s.Close()
		t.Fatal("Open with the zero ServicePolicy succeeded")
	}
	for _, sentinel := range []error{ErrKeyNotFound, ErrKeyExists, ErrKeyPolicyMismatch, ErrPrivilegeRequired, ErrDeleteVerificationFailed} {
		if errors.Is(err, sentinel) {
			t.Fatalf("zero policy error %v matches %v", err, sentinel)
		}
	}
}

func TestCreateForwardsExactNameAndPolicy(t *testing.T) {
	p := testPolicy(t)
	want := &fakeSigner{pub: newP256(t).Public()}
	r := &recordingAPI{createRet: want}
	s, err := createKeyWith(r.api(), machineIdentityKeyName, p)
	if err != nil {
		t.Fatal(err)
	}
	if s != want {
		t.Fatalf("signer = %v, want the signer returned by the shared layer", s)
	}
	r.requireCalls(t, 0, 1, 0)
	requireCall(t, r.creates[0], machineIdentityKeyName, p)
}

// TestCreateExistingKeyIsNotAdopted proves ErrKeyExists is reported with the
// native status and that no open, delete or retry follows.
func TestCreateExistingKeyIsNotAdopted(t *testing.T) {
	native := &windowscng.NCryptError{Op: "NCryptCreatePersistedKey", Code: windowscng.NTEExists}
	r := &recordingAPI{createErr: fmt.Errorf("create key: %w: %w", windowscng.ErrKeyExists, native)}
	s, err := createKeyWith(r.api(), machineIdentityKeyName, testPolicy(t))
	if s != nil {
		t.Fatal("signer returned on ErrKeyExists")
	}
	if !errors.Is(err, ErrKeyExists) || !errors.Is(err, windowscng.ErrKeyExists) {
		t.Fatalf("err = %v, want local and shared ErrKeyExists", err)
	}
	var ne *windowscng.NCryptError
	if !errors.As(err, &ne) || ne.Code != windowscng.NTEExists {
		t.Fatalf("native status lost: %v", err)
	}
	r.requireCalls(t, 0, 1, 0)
}

// TestCreateCleanupFailedKeepsEveryCause proves that a create whose new key
// failed its checks and whose rollback also failed keeps every cause: the
// policy mismatch, the cleanup failure (the key may persist) and the native
// status. No signer is returned and no delete is attempted.
func TestCreateCleanupFailedKeepsEveryCause(t *testing.T) {
	native := &windowscng.NCryptError{Op: "NCryptDeleteKey", Code: windowscng.NTEPerm}
	r := &recordingAPI{createErr: errors.Join(windowscng.ErrPolicyMismatch, windowscng.ErrCleanupFailed, native)}
	s, err := createKeyWith(r.api(), machineIdentityKeyName, testPolicy(t))
	if s != nil {
		t.Fatal("signer returned on a failed create")
	}
	if !errors.Is(err, ErrKeyPolicyMismatch) || !errors.Is(err, windowscng.ErrPolicyMismatch) {
		t.Fatalf("policy mismatch lost: %v", err)
	}
	if !errors.Is(err, windowscng.ErrCleanupFailed) {
		t.Fatalf("cleanup failure lost (the key may persist): %v", err)
	}
	if !errors.Is(err, native) {
		t.Fatalf("native cause lost: %v", err)
	}
	r.requireCalls(t, 0, 1, 0)
}

// TestCreateCleanupFailedAlonePassesThrough proves a cleanup failure without
// another classified cause is returned unchanged.
func TestCreateCleanupFailedAlonePassesThrough(t *testing.T) {
	upstream := fmt.Errorf("finalize: %w", windowscng.ErrCleanupFailed)
	r := &recordingAPI{createErr: upstream}
	_, err := createKeyWith(r.api(), machineIdentityKeyName, testPolicy(t))
	if err != upstream {
		t.Fatalf("err = %v, want the upstream error unchanged", err)
	}
}

func TestCreatePrivilegeRequired(t *testing.T) {
	r := &recordingAPI{createErr: fmt.Errorf("create: %w", windowscng.ErrPrivilegeRequired)}
	_, err := createKeyWith(r.api(), machineIdentityKeyName, testPolicy(t))
	if !errors.Is(err, ErrPrivilegeRequired) || !errors.Is(err, windowscng.ErrPrivilegeRequired) {
		t.Fatalf("err = %v, want local and shared ErrPrivilegeRequired", err)
	}
}

func TestDeleteForwardsExactNamePolicyAndSPKI(t *testing.T) {
	p := testPolicy(t)
	spki, err := SPKI(newP256(t).Public())
	if err != nil {
		t.Fatal(err)
	}
	r := &recordingAPI{}
	if err := deleteKeyWith(r.api(), machineIdentityKeyName, p, spki); err != nil {
		t.Fatal(err)
	}
	r.requireCalls(t, 0, 0, 1)
	requireCall(t, r.deletes[0], machineIdentityKeyName, p)
	if !bytes.Equal(r.deletes[0].spki, spki) {
		t.Fatal("expected SubjectPublicKeyInfo not forwarded unchanged")
	}
}

// TestDeleteVerificationFailedTakesPrecedence proves a delete refused for a
// policy mismatch is classified as a failed verification (nothing deleted):
// the shared mismatch stays reachable, the local mismatch is not the result.
func TestDeleteVerificationFailedTakesPrecedence(t *testing.T) {
	r := &recordingAPI{deleteErr: errors.Join(windowscng.ErrDeleteVerificationFailed, windowscng.ErrPolicyMismatch)}
	err := deleteKeyWith(r.api(), machineIdentityKeyName, testPolicy(t), []byte{1})
	if !errors.Is(err, ErrDeleteVerificationFailed) || !errors.Is(err, windowscng.ErrDeleteVerificationFailed) {
		t.Fatalf("err = %v, want local and shared ErrDeleteVerificationFailed", err)
	}
	if !errors.Is(err, windowscng.ErrPolicyMismatch) {
		t.Fatalf("shared policy mismatch lost: %v", err)
	}
	if errors.Is(err, ErrKeyPolicyMismatch) {
		t.Fatalf("a refused delete must not be classified as the local policy mismatch: %v", err)
	}
	r.requireCalls(t, 0, 0, 1)
}

// TestDeleteNativeFailurePassesThrough proves a failure of the native delete
// after a passed verification is returned unchanged with its native status.
func TestDeleteNativeFailurePassesThrough(t *testing.T) {
	native := &windowscng.NCryptError{Op: "NCryptDeleteKey", Code: windowscng.NTEPerm}
	r := &recordingAPI{deleteErr: native}
	err := deleteKeyWith(r.api(), machineIdentityKeyName, testPolicy(t), []byte{1})
	if err != error(native) {
		t.Fatalf("err = %v, want the native error unchanged", err)
	}
}

// TestDeleteOpenFailureIsNotFound proves an open failure inside the delete is
// ErrKeyNotFound: nothing was deleted, and the key is not proven absent.
func TestDeleteOpenFailureIsNotFound(t *testing.T) {
	native := &windowscng.NCryptError{Op: "NCryptOpenKey", Code: windowscng.NTEBadKeyset}
	r := &recordingAPI{deleteErr: fmt.Errorf("delete: %w: %w", windowscng.ErrKeyNotFound, native)}
	err := deleteKeyWith(r.api(), machineIdentityKeyName, testPolicy(t), []byte{1})
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("err = %v, want ErrKeyNotFound", err)
	}
	var ne *windowscng.NCryptError
	if !errors.As(err, &ne) || ne.Code != windowscng.NTEBadKeyset {
		t.Fatalf("native status lost: %v", err)
	}
}

// TestDeleteInvalidInputIsNotVerificationFailure proves an input error (empty,
// malformed or non-P-256 SubjectPublicKeyInfo, zero policy) is returned
// unchanged and never classified as a failed verification.
func TestDeleteInvalidInputIsNotVerificationFailure(t *testing.T) {
	input := errors.New("windowscng: invalid expected SubjectPublicKeyInfo")
	for _, spki := range [][]byte{nil, {}, {0x30, 0x00}} {
		r := &recordingAPI{deleteErr: input}
		err := deleteKeyWith(r.api(), machineIdentityKeyName, testPolicy(t), spki)
		if err != input {
			t.Fatalf("spki %x: err = %v, want the input error unchanged", spki, err)
		}
		if errors.Is(err, ErrDeleteVerificationFailed) {
			t.Fatalf("spki %x: input error classified as a failed verification", spki)
		}
	}
}

func TestSPKIMatchesPKIXForP256(t *testing.T) {
	pub := newP256(t).Public()
	got, err := SPKI(pub)
	if err != nil {
		t.Fatal(err)
	}
	want, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("SPKI differs from x509.MarshalPKIXPublicKey")
	}
	parsed, err := x509.ParsePKIXPublicKey(got)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.(*ecdsa.PublicKey).Equal(pub) {
		t.Fatal("SPKI does not round-trip to the same key")
	}
}

func TestSPKIRejectsOtherKeys(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	offCurve := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}
	var nilECDSA *ecdsa.PublicKey
	cases := map[string]crypto.PublicKey{
		"rsa":       rsaKey.Public(),
		"p384":      p384.Public(),
		"off-curve": offCurve,
		"nil ecdsa": nilECDSA,
		"nil":       nil,
	}
	for name, pub := range cases {
		if spki, err := SPKI(pub); err == nil {
			t.Errorf("%s: SPKI accepted the key: %x", name, spki)
		}
	}
}

func TestSPKIIsNotTheCanonicalReference(t *testing.T) {
	spki, err := SPKI(newP256(t).Public())
	if err != nil {
		t.Fatal(err)
	}
	if len(spki) == 65 || spki[0] == 0x04 {
		t.Fatalf("SPKI looks like the 65-byte uncompressed point: %x", spki)
	}
}

func TestMapCNGErrorEachSentinel(t *testing.T) {
	cases := []struct {
		upstream, local error
	}{
		{windowscng.ErrDeleteVerificationFailed, ErrDeleteVerificationFailed},
		{windowscng.ErrKeyExists, ErrKeyExists},
		{windowscng.ErrKeyNotFound, ErrKeyNotFound},
		{windowscng.ErrPolicyMismatch, ErrKeyPolicyMismatch},
		{windowscng.ErrPrivilegeRequired, ErrPrivilegeRequired},
	}
	locals := []error{ErrDeleteVerificationFailed, ErrKeyExists, ErrKeyNotFound, ErrKeyPolicyMismatch, ErrPrivilegeRequired}
	for _, c := range cases {
		err := mapCNGError(fmt.Errorf("ctx: %w", c.upstream))
		if !errors.Is(err, c.local) || !errors.Is(err, c.upstream) {
			t.Fatalf("%v: got %v, want local %v and upstream", c.upstream, err, c.local)
		}
		for _, other := range locals {
			if other != c.local && errors.Is(err, other) {
				t.Fatalf("%v: also matches unrelated %v", c.upstream, other)
			}
		}
	}
}
