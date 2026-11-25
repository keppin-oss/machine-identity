//go:build windows

package keystore

import (
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
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

// TestUsesSharedWindowscngPackage proves the keystore implementation actually
// imports the shared keppin-oss/cng/windowscng package for CNG custody, and
// that it is the only CNG module imported: any other import path that looks
// like a CNG package (for example another module's windowscng) is rejected.
// It inspects the import declarations, not the raw source text, so a comment
// cannot satisfy it.
func TestUsesSharedWindowscngPackage(t *testing.T) {
	const want = "github.com/keppin-oss/cng/windowscng"
	const sharedModule = "github.com/keppin-oss/cng/"
	found := false
	for file := range keystoreImplFiles(t) {
		f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("%s: bad import path %s: %v", file, imp.Path.Value, err)
			}
			if path == want {
				found = true
			}
			if strings.Contains(strings.ToLower(path), "cng") && !strings.HasPrefix(path, sharedModule) {
				t.Errorf("%s imports %q; the only CNG module allowed is %s", file, path, sharedModule)
			}
		}
	}
	if !found {
		t.Fatalf("keystore implementation does not import %s", want)
	}
}

// TestNoLoadOrCreateInModuleSource keeps the removed load-or-create entry
// point out of the module: no non-test Go file of the module, examples
// included, may contain the term in any letter case, in code or in comments.
// Opening and creating are separate operations; a failed open must never lead
// to a create. Test files and historical release notes are not scanned: they
// name the term on purpose.
func TestNoLoadOrCreateInModuleSource(t *testing.T) {
	const forbidden = "loadorcreate"
	scanned := 0
	err := filepath.WalkDir("..", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != ".." && (strings.HasPrefix(name, ".") || name == "graphify-out" || name == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		if strings.Contains(strings.ToLower(string(data)), forbidden) {
			t.Errorf("%s contains the removed load-or-create term", filepath.ToSlash(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned == 0 {
		t.Fatal("no module Go source files scanned")
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
// the Machine Identity ErrKeyNotFound contract. The original error is kept in
// the error tree, so the windowscng sentinel stays observable with errors.Is.
func TestMapCNGErrorNotFound(t *testing.T) {
	err := mapCNGError(windowscng.ErrKeyNotFound)
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("mapCNGError(windowscng.ErrKeyNotFound) = %v, want ErrKeyNotFound", err)
	}
	if !errors.Is(err, windowscng.ErrKeyNotFound) {
		t.Fatal("mapped error must keep the windowscng sentinel reachable")
	}
	var ne *windowscng.NCryptError
	if errors.As(err, &ne) {
		t.Fatalf("a bare sentinel carries no native cause, got %v", ne)
	}
}

// TestMapCNGErrorNotFoundWrapped verifies a wrapped shared missing-key error is
// still mapped (the shared package wraps with key-name context).
func TestMapCNGErrorNotFoundWrapped(t *testing.T) {
	underlying := wrapErr(windowscng.ErrKeyNotFound)
	if !errors.Is(underlying, windowscng.ErrKeyNotFound) {
		t.Fatalf("precondition: wrapErr result must retain windowscng.ErrKeyNotFound")
	}
	mapped := mapCNGError(underlying)
	if !errors.Is(mapped, ErrKeyNotFound) {
		t.Fatalf("mapCNGError(wrapped) must map to ErrKeyNotFound")
	}
	if !errors.Is(mapped, windowscng.ErrKeyNotFound) {
		t.Fatalf("mapCNGError(wrapped) must keep the windowscng sentinel")
	}
	if !errors.Is(mapCNGError(wrapErr(mapped)), ErrKeyNotFound) {
		t.Fatalf("a nested mapped error must still match ErrKeyNotFound")
	}
}

// TestMapCNGErrorPreservesNativeCause verifies the native status of a
// not-found or not-accessible open is still reachable after mapping, for both
// statuses the shared layer classifies, and that the full context is kept.
func TestMapCNGErrorPreservesNativeCause(t *testing.T) {
	for _, code := range []uint32{windowscng.NTENotFound, windowscng.NTEBadKeyset} {
		native := &windowscng.NCryptError{Op: "NCryptOpenKey", Code: code}
		shared := fmt.Errorf("open key %q: %w: %w", "k", windowscng.ErrKeyNotFound, native)

		mapped := mapCNGError(shared)
		if !errors.Is(mapped, ErrKeyNotFound) || !errors.Is(mapped, windowscng.ErrKeyNotFound) {
			t.Fatalf("code 0x%x: sentinels not both reachable in %v", code, mapped)
		}
		var ne *windowscng.NCryptError
		if !errors.As(mapped, &ne) || ne.Code != code {
			t.Fatalf("code 0x%x: native cause lost, As=%v err=%v", code, ne, mapped)
		}
		if !strings.Contains(mapped.Error(), shared.Error()) {
			t.Fatalf("code 0x%x: context lost: %q does not contain %q", code, mapped.Error(), shared.Error())
		}
		if errors.Unwrap(mapped) != nil {
			t.Fatal("errors.Unwrap must not traverse the multi-error tree")
		}
	}
}

// TestMapCNGErrorKeepsMultipleCauses verifies a tree with several native causes
// stays intact after mapping: every cause remains reachable with errors.Is,
// and errors.As returns the first cause of the requested type in visit order.
func TestMapCNGErrorKeepsMultipleCauses(t *testing.T) {
	first := &windowscng.NCryptError{Op: "NCryptOpenKey", Code: windowscng.NTEBadKeyset}
	second := &windowscng.NCryptError{Op: "NCryptDeleteKey", Code: windowscng.NTEPerm}
	shared := errors.Join(fmt.Errorf("%w: %w", windowscng.ErrKeyNotFound, first), second)

	mapped := mapCNGError(shared)
	if !errors.Is(mapped, ErrKeyNotFound) {
		t.Fatalf("mapped = %v, want ErrKeyNotFound", mapped)
	}
	if !errors.Is(mapped, first) {
		t.Fatal("first native cause is not reachable after mapping")
	}
	if !errors.Is(mapped, second) {
		t.Fatal("second native cause is not reachable after mapping")
	}
	var ne *windowscng.NCryptError
	if !errors.As(mapped, &ne) || ne != first {
		t.Fatalf("errors.As = %v, want the first native cause", ne)
	}
}

// TestMapCNGErrorNil verifies a nil error stays nil.
func TestMapCNGErrorNil(t *testing.T) {
	if err := mapCNGError(nil); err != nil {
		t.Fatalf("mapCNGError(nil) = %v, want nil", err)
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

// TestMapCNGErrorPassThroughNativeStatus verifies a native error without the
// not-found sentinel is returned unchanged, even for a status that the shared
// layer classifies as not found elsewhere: the code alone is never re-classified.
func TestMapCNGErrorPassThroughNativeStatus(t *testing.T) {
	for _, code := range []uint32{windowscng.NTEPerm, windowscng.NTEBadKeyset} {
		native := &windowscng.NCryptError{Op: "NCryptSignHash", Code: code}
		err := mapCNGError(native)
		if err != error(native) {
			t.Fatalf("code 0x%x: mapCNGError = %v, want the original error", code, err)
		}
		if errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("code 0x%x: must not become ErrKeyNotFound without the sentinel", code)
		}
	}
}

func wrapErr(err error) error {
	return &wrappedError{inner: err}
}

type wrappedError struct{ inner error }

func (w *wrappedError) Error() string { return w.inner.Error() }
func (w *wrappedError) Unwrap() error { return w.inner }
