//go:build windows

package keystore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keppin-oss/cng/windowscng"
)

// keystoreImplFiles returns the non-test .go files in the keystore package.
// Implementation files must not duplicate the native CNG layer that now lives
// in github.com/keppin-oss/cng/windowscng.
func keystoreImplFiles(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		out[file] = string(data)
	}
	if len(out) == 0 {
		t.Fatal("no keystore implementation files found")
	}
	return out
}

// forbiddenNativeCNG are tokens that must not appear in the Machine Identity
// keystore implementation: the native CNG/KSP/ACL implementation has been
// migrated to github.com/keppin-oss/cng/windowscng and must not be duplicated here.
var forbiddenNativeCNG = []string{
	"ncrypt.dll",
	"NCryptOpenStorageProvider",
	"NCryptCreatePersistedKey",
	"NCryptSetProperty",
	"NCryptGetProperty",
	"NCryptFinalizeKey",
	"NCryptExportKey",
	"NCryptSignHash",
	"NCryptDeleteKey",
	"NCryptFreeObject",
	"advapi32",
	"ConvertStringSecurityDescriptorToSecurityDescriptor",
	"GetSecurityDescriptorDacl",
	"GetAclInformation",
	"GetAce",
	"EqualSid",
	"ConvertStringSidToSid",
	"ECCPUBLICBLOB",
	"ECDSA_P256",
	"keySecuritySDDL",
}

// TestNoDuplicatedNativeCNGImplementation proves no native NCrypt implementation
// remains in the Machine Identity keystore. All native CNG/KSP custody now lives
// in github.com/keppin-oss/cng/windowscng.
func TestNoDuplicatedNativeCNGImplementation(t *testing.T) {
	for file, src := range keystoreImplFiles(t) {
		for _, tok := range forbiddenNativeCNG {
			if strings.Contains(src, tok) {
				t.Errorf("keystore implementation file %s contains duplicated native CNG token %q", file, tok)
			}
		}
	}
}

// TestUsesSharedWindowscngPackage proves the keystore implementation depends on
// the shared github.com/keppin-oss/cng/windowscng package for CNG custody.
func TestUsesSharedWindowscngPackage(t *testing.T) {
	found := false
	for _, src := range keystoreImplFiles(t) {
		if strings.Contains(src, "github.com/keppin-oss/cng/windowscng") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("keystore implementation does not import github.com/keppin-oss/cng/windowscng")
	}
}

// TestNoLocalOrEnterpriseTLSIdentity proves no Local-TLS or Enterprise-TLS
// identity or policy is introduced in the Machine Identity keystore.
func TestNoLocalOrEnterpriseTLSIdentity(t *testing.T) {
	forbidden := []string{
		"Keppin.Agent.LocalHTTPS",
		"Keppin.Agent.EnterpriseTLS",
		"keppin-enterprise-tls",
		"LocalTLS",
		"EnterpriseTLS",
	}
	for file, src := range keystoreImplFiles(t) {
		for _, tok := range forbidden {
			if strings.Contains(src, tok) {
				t.Errorf("keystore implementation file %s references forbidden identity/policy %q", file, tok)
			}
		}
	}
}

// TestMapCNGErrorNotFound verifies the shared missing-key sentinel is mapped to
// the Machine Identity ErrKeyNotFound contract so callers never need to know
// windowscng's sentinel.
func TestMapCNGErrorNotFound(t *testing.T) {
	err := mapCNGError(windowscng.ErrKeyNotFound)
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("mapCNGError(windowscng.ErrKeyNotFound) = %v, want ErrKeyNotFound", err)
	}
	if errors.Is(err, windowscng.ErrKeyNotFound) {
		t.Fatal("mapped error must not leak the windowscng sentinel")
	}
}

// TestMapCNGErrorNotFoundWrapped verifies a wrapped shared missing-key error is
// still mapped (the shared package wraps with key-name context).
func TestMapCNGErrorNotFoundWrapped(t *testing.T) {
	underlying := wrapErr(windowscng.ErrKeyNotFound)
	if !errors.Is(underlying, windowscng.ErrKeyNotFound) {
		t.Fatalf("precondition: wrapErr result must retain windowscng.ErrKeyNotFound")
	}
	if !errors.Is(mapCNGError(underlying), ErrKeyNotFound) {
		t.Fatalf("mapCNGError(wrapped) must map to ErrKeyNotFound")
	}
}

// TestMapCNGErrorPassThrough verifies non-not-found failures are never converted
// into not-found.
func TestMapCNGErrorPassThrough(t *testing.T) {
	sentinel := errors.New("keystore: permission denied")
	err := mapCNGError(sentinel)
	if err != sentinel {
		t.Fatalf("mapCNGError(pass-through) = %v, want original error", err)
	}
	if errors.Is(err, ErrKeyNotFound) {
		t.Fatal("a permission error must not be converted into ErrKeyNotFound")
	}
}

func wrapErr(err error) error {
	return &wrappedError{inner: err}
}

type wrappedError struct{ inner error }

func (w *wrappedError) Error() string { return w.inner.Error() }
func (w *wrappedError) Unwrap() error { return w.inner }
