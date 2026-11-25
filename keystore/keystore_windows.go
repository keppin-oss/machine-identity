//go:build windows

// Package keystore provides Windows CNG/KSP key custody for the Keppin Machine
// Identity key.
//
// The machine identity key is a non-exportable, machine-scoped ECDSA P-256 key
// persisted in the Microsoft Software Key Storage Provider, protected by the
// DACL of a windowscng.ServicePolicy, and exposed to callers through
// windowscng.Signer (a crypto.Signer with Close) so the identityproof
// primitives can consume it without Windows-specific coupling.
//
// Opening, creating and deleting are separate operations and none of them
// performs another as a side effect:
//
//   - Open opens the existing key only and never creates one;
//   - Create creates a new key only and never opens, adopts, modifies or
//     deletes an existing one;
//   - Delete deletes the key only after the shared layer has verified, on the
//     handle it deletes, the policy and the expected SubjectPublicKeyInfo.
//
// The policy is a windowscng.ServicePolicy supplied by the caller, built from
// the name of the Windows service that uses the key: its DACL grants SYSTEM and
// Administrators full control and that service's own SID read and execute. The
// service must run with its service SID enabled in its token. This package does
// not choose or embed the service name.
//
// The native Windows CNG/KSP operations (open, create, delete, machine scope,
// non-exportability, DACL provisioning and exact DACL validation, privilege
// checks and CNG handle lifecycle) are supplied by the shared
// github.com/keppin-oss/cng/windowscng package. Its validation classifies the
// DACL exactly against the requested policy (owner, group and SACL are not
// checked); it does not establish Windows effective access. This package owns
// only the Machine Identity policy: the production key name, the
// not-found-or-not-accessible contract, the error contract and the public
// Machine Identity API.
//
// Callers own the decision of when to create or delete the key, the durable
// record of its SubjectPublicKeyInfo and the serialization of every lifecycle
// operation on the key, also across processes. Create does not reserve the key
// name.
package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/keppin-oss/cng/windowscng"
	"github.com/keppin-oss/machine-identity/identity"
	"github.com/keppin-oss/machine-identity/publickey"
)

// machineIdentityKeyName is the persisted CNG machine identity key name. It is
// a compatibility contract owned by the identity package and MUST NOT move into
// the CNG module.
const machineIdentityKeyName = identity.ProdMachineIdentityKeyName

// ErrKeyNotFound is returned when the persisted Machine Identity key was not
// found OR is not accessible to the caller. The Microsoft Software KSP can
// report a key that exists but whose DACL does not grant the caller as not
// found, so this error does NOT prove that the key is absent.
//
// Callers must never use it, by itself, to create, reset, regenerate,
// overwrite or replace the identity key, nor to conclude that cleanup
// succeeded. For Delete it means only that this call deleted nothing. Classify
// it with errors.Is: the returned error also keeps the shared windowscng error
// and any native cause (errors.As with *windowscng.NCryptError) in its tree.
var ErrKeyNotFound = errors.New("keystore: machine identity key not found or not accessible")

// ErrKeyExists is returned by Create when a key is already persisted under the
// Machine Identity key name. The existing key was not opened, adopted,
// modified or deleted, and no signer is returned. It covers only a key that
// is already persisted: it does not reserve the name, and two overlapping
// creates can both succeed with different keys. Callers must serialize every
// lifecycle operation on the key.
var ErrKeyExists = errors.New("keystore: machine identity key already exists")

// ErrKeyPolicyMismatch is returned when the persisted key exists but is not
// exactly in the state required by the requested policy: its DACL is not the
// exact form of the policy or its public key is not a valid ECDSA P-256 key.
// Open never modifies the key. A key created by an earlier release with the
// service-signer DACL (LOCAL SERVICE) does not match a ServicePolicy and is
// reported either with this error or, if the caller cannot open it at all,
// with ErrKeyNotFound. Neither outcome authorizes a Create.
var ErrKeyPolicyMismatch = errors.New("keystore: machine identity key does not match the requested policy")

// ErrPrivilegeRequired is returned when the operation needs a caller running as
// LocalSystem or as an elevated member of BUILTIN\Administrators and the caller
// is not one, or its privilege could not be determined. Create and Delete
// always require it. No key was opened, created, modified or deleted on that
// basis.
var ErrPrivilegeRequired = errors.New("keystore: operation requires a privileged caller (LocalSystem or elevated Administrators)")

// ErrDeleteVerificationFailed is returned by Delete when the key was opened but
// not deleted, because a check on the handle it opened did not pass or could
// not be completed: the key is exportable, is not ECDSA P-256, its DACL is not
// exactly the requested policy, or its public key is not the expected
// SubjectPublicKeyInfo. It does not prove that the key belongs to someone else.
// Nothing was deleted or modified.
var ErrDeleteVerificationFailed = errors.New("keystore: machine identity key verification failed before delete; nothing was deleted")

// Open opens the existing persisted Machine Identity key under policy. It never
// creates, modifies or deletes a key.
//
// It returns ErrKeyNotFound if the key was not found or is not accessible (the
// two are not distinguished) and ErrKeyPolicyMismatch if the key is not exactly
// in the policy state. Opening under a ServicePolicy does not require an
// elevated caller, but that does not guarantee access: the caller's token must
// be granted by the key DACL. An invalid policy (for example the zero
// ServicePolicy) returns an input error that matches no sentinel. The caller
// owns the returned signer and must Close it.
func Open(policy windowscng.ServicePolicy) (windowscng.Signer, error) {
	return openKey(machineIdentityKeyName, policy)
}

// Create creates a new persisted Machine Identity key (non-exportable,
// machine-scoped ECDSA P-256) with the DACL of policy and returns its signer.
// It never opens, adopts, modifies or deletes an existing key: a key already
// persisted under the name returns ErrKeyExists.
//
// Invalid input is rejected first; then a privileged caller is required
// (ErrPrivilegeRequired). If the key created by this call fails its
// post-create checks, the shared layer deletes it through the same handle; if
// that delete fails too, the error also matches windowscng.ErrCleanupFailed and
// the new key may persist and must be inspected. On any error no signer is
// returned and the caller must not delete the key by name.
//
// Create does not reserve the name. The caller must serialize every lifecycle
// operation on the key, also across processes, and must record the
// SubjectPublicKeyInfo of the returned key (see SPKI) durably before using it.
// The caller owns the returned signer and must Close it.
func Create(policy windowscng.ServicePolicy) (windowscng.Signer, error) {
	return createKey(machineIdentityKeyName, policy)
}

// Delete deletes the persisted Machine Identity key only after the shared
// layer has verified, on the handle it then deletes, that the key is
// non-exportable ECDSA P-256, that its DACL is exactly policy and that its
// SubjectPublicKeyInfo is byte-for-byte expectedSPKI.
//
// expectedSPKI must be the DER SubjectPublicKeyInfo recorded when the key was
// created (see SPKI), never one derived by opening the key just before the
// delete. An empty or malformed value or an invalid policy returns an input
// error that matches no sentinel, before any native call. Otherwise:
//
//   - ErrPrivilegeRequired: the caller is not privileged; nothing was opened;
//   - ErrKeyNotFound: nothing was deleted; the key is not proven absent;
//   - ErrDeleteVerificationFailed: a check did not pass or could not be
//     completed; nothing was deleted (windowscng.ErrPolicyMismatch is also
//     reachable when the cause is the policy);
//   - a failure of the native delete itself, with its *windowscng.NCryptError.
//
// Deleting the key destroys the prior Machine Identity proof capability. A
// key created afterwards is a new identity.
func Delete(policy windowscng.ServicePolicy, expectedSPKI []byte) error {
	return deleteKey(machineIdentityKeyName, policy, expectedSPKI)
}

// SPKI returns the DER SubjectPublicKeyInfo of a Machine Identity public key,
// x509.MarshalPKIXPublicKey(pub): the identity that Delete expects and that a
// caller records after Create. Only a valid ECDSA P-256 public key is accepted;
// any other key type, curve, a nil key or a point that is not on the curve is
// rejected.
//
// This is not the canonical public-key reference of the publickey package,
// which is the uncompressed point (0x04 || X || Y, 65 bytes): the two encodings
// are not interchangeable.
func SPKI(pub crypto.PublicKey) ([]byte, error) {
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("keystore: SPKI requires an ECDSA P-256 public key, got %T", pub)
	}
	if _, err := publickey.Encode(ec); err != nil {
		return nil, fmt.Errorf("keystore: SPKI: %w", err)
	}
	return x509.MarshalPKIXPublicKey(ec)
}

// cngKeyAPI is the seam between the keystore and windowscng. It is typed on the
// concrete windowscng.ServicePolicy, although windowscng accepts any KeyPolicy,
// so the keystore can only ever pass a service policy. Production uses
// nativeCNGKeyAPI; unit tests pass fakes to the *With functions so no machine
// key is touched.
type cngKeyAPI struct {
	open   func(name string, p windowscng.ServicePolicy) (windowscng.Signer, error)
	create func(name string, p windowscng.ServicePolicy) (windowscng.Signer, error)
	delete func(name string, p windowscng.ServicePolicy, expectedSPKI []byte) error
}

var nativeCNGKeyAPI = cngKeyAPI{
	open: func(name string, p windowscng.ServicePolicy) (windowscng.Signer, error) {
		return windowscng.Open(name, p)
	},
	create: func(name string, p windowscng.ServicePolicy) (windowscng.Signer, error) {
		return windowscng.Create(name, p)
	},
	delete: func(name string, p windowscng.ServicePolicy, expectedSPKI []byte) error {
		return windowscng.Delete(name, p, expectedSPKI)
	},
}

// openKey opens the exact named key under policy. It never creates a key.
func openKey(name string, policy windowscng.ServicePolicy) (windowscng.Signer, error) {
	return openKeyWith(nativeCNGKeyAPI, name, policy)
}

func openKeyWith(api cngKeyAPI, name string, policy windowscng.ServicePolicy) (windowscng.Signer, error) {
	signer, err := api.open(name, policy)
	if err != nil {
		return nil, mapCNGError(err)
	}
	return signer, nil
}

// createKey creates the exact named key under policy. It never opens or adopts
// an existing key and never retries.
func createKey(name string, policy windowscng.ServicePolicy) (windowscng.Signer, error) {
	return createKeyWith(nativeCNGKeyAPI, name, policy)
}

func createKeyWith(api cngKeyAPI, name string, policy windowscng.ServicePolicy) (windowscng.Signer, error) {
	signer, err := api.create(name, policy)
	if err != nil {
		return nil, mapCNGError(err)
	}
	return signer, nil
}

// deleteKey deletes exactly the named key after verification of policy and
// expectedSPKI by the shared layer. It never creates a key and never performs
// wildcard/prefix deletion.
func deleteKey(name string, policy windowscng.ServicePolicy, expectedSPKI []byte) error {
	return deleteKeyWith(nativeCNGKeyAPI, name, policy, expectedSPKI)
}

func deleteKeyWith(api cngKeyAPI, name string, policy windowscng.ServicePolicy, expectedSPKI []byte) error {
	return mapCNGError(api.delete(name, policy, expectedSPKI))
}

// mapCNGError translates the shared windowscng sentinels into the Machine
// Identity contract, keeping the windowscng error in the chain so that its
// sentinels and any native *windowscng.NCryptError it carries stay reachable
// with errors.Is and errors.As:
//
//   - verification before a delete failed → ErrDeleteVerificationFailed. It
//     takes precedence over a policy mismatch, which it may also carry: the
//     result then matches windowscng.ErrPolicyMismatch but not the local
//     ErrKeyPolicyMismatch;
//   - create found an existing key → ErrKeyExists;
//   - not found or not accessible → ErrKeyNotFound;
//   - key not in the policy state → ErrKeyPolicyMismatch;
//   - privileged caller required → ErrPrivilegeRequired.
//
// An error that matches none of these (invalid input, a native delete failure,
// windowscng.ErrCleanupFailed on its own, other unexpected failures) is
// returned unchanged and is never converted into not-found. A nil error stays
// nil. errors.Unwrap does not traverse the multi-error tree: classify with
// errors.Is and errors.As.
func mapCNGError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, windowscng.ErrDeleteVerificationFailed):
		return fmt.Errorf("%w: %w", ErrDeleteVerificationFailed, err)
	case errors.Is(err, windowscng.ErrKeyExists):
		return fmt.Errorf("%w: %w", ErrKeyExists, err)
	case errors.Is(err, windowscng.ErrKeyNotFound):
		return fmt.Errorf("%w: %w", ErrKeyNotFound, err)
	case errors.Is(err, windowscng.ErrPolicyMismatch):
		return fmt.Errorf("%w: %w", ErrKeyPolicyMismatch, err)
	case errors.Is(err, windowscng.ErrPrivilegeRequired):
		return fmt.Errorf("%w: %w", ErrPrivilegeRequired, err)
	default:
		return err
	}
}
