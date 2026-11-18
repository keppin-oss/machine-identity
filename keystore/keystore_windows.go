//go:build windows

// Package keystore provides Windows CNG/KSP key custody for the Keppin Machine
// Identity key.
//
// The machine identity key is a non-exportable, machine-scoped ECDSA P-256 key
// persisted in the Microsoft Software Key Storage Provider, created with a
// restrictive DACL, and exposed to callers through crypto.Signer so the
// identityproof primitives can consume it without Windows-specific coupling.
//
// The native Windows CNG/KSP operations (open, create-or-open, delete, machine
// scope, non-exportability, DACL provisioning and validation, and CNG handle
// lifecycle) are supplied by the shared github.com/keppin-oss/cng/windowscng
// package. Its DACL validation checks that the required principals are present
// and rejects specific disallowed ones; it is not an exclusive allow-list and
// does not establish Windows effective access. This package owns only the Machine Identity policy: the production
// key name and the decision to create/open/delete it, the not-found-or-not-accessible contract,
// and the public Machine Identity API.
package keystore

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/keppin-oss/cng/windowscng"
	"github.com/keppin-oss/machine-identity/identity"
)

// machineIdentityKeyName is the persisted CNG machine identity key name. It is
// a compatibility contract owned by the identity package and MUST NOT move into
// the CNG module.
const machineIdentityKeyName = identity.ProdMachineIdentityKeyName

// ErrKeyNotFound is returned by Delete and Open (and by LoadOrCreate, when the
// failure carries the shared sentinel) when the persisted Machine Identity key
// was not found OR is not accessible to the caller. The Microsoft Software KSP
// can report a key that exists but whose DACL does not grant the caller as
// not found, so this error does NOT prove that the key is absent.
//
// Callers must never use it, by itself, to reset, regenerate, overwrite or
// replace the identity key, nor to conclude that cleanup succeeded. For Delete
// it means only that this call deleted nothing. Classify it with errors.Is:
// the returned error also keeps the shared windowscng error and any native
// cause (errors.As with *windowscng.NCryptError) in its tree.
var ErrKeyNotFound = errors.New("keystore: machine identity key not found or not accessible")

// LoadOrCreate opens the existing persisted Machine Identity key or creates it
// (non-exportable, machine-scoped ECDSA P-256) if it does not yet exist.
func LoadOrCreate() (crypto.Signer, error) {
	return loadOrCreateKey(machineIdentityKeyName)
}

// Open opens the existing persisted Machine Identity key only and never silently
// creates a replacement. It fails with ErrKeyNotFound if the key was not found
// or is not accessible (the two are not distinguished), and with another error
// for other failures.
func Open() (crypto.Signer, error) {
	return openKey(machineIdentityKeyName)
}

// Delete removes the persisted Machine Identity key by exact name.
//
// Deleting the key destroys the prior Machine Identity proof capability. After
// a successful deletion the prior identity must be considered gone; any future
// identity created through LoadOrCreate is a new identity unless a higher-level
// migration/recovery protocol exists.
//
// Delete never creates a key. It returns ErrKeyNotFound when the key was not
// found or is not accessible, and deletes nothing in that case. That means
// "nothing was deleted by this call"; it does not prove the key is absent, so
// callers must not treat it as successful or idempotent cleanup on its own.
func Delete() error {
	return deleteKey(machineIdentityKeyName)
}

// loadOrCreateKey delegates the exact named key open-or-create to the shared
// CNG layer, preserving Machine Identity semantics (Microsoft Software KSP,
// machine scope, ECDSA P-256, non-exportable, shared DACL).
func loadOrCreateKey(name string) (crypto.Signer, error) {
	signer, err := windowscng.LoadOrCreate(name)
	if err != nil {
		return nil, mapCNGError(err)
	}
	return signer, nil
}

// openKey delegates the exact named key open-only operation to the shared CNG
// layer. It never creates a replacement key.
func openKey(name string) (crypto.Signer, error) {
	signer, err := windowscng.Open(name)
	if err != nil {
		return nil, mapCNGError(err)
	}
	return signer, nil
}

// deleteKey delegates the exact named key deletion to the shared CNG layer. It
// never creates a key and never performs wildcard/prefix deletion.
func deleteKey(name string) error {
	return mapCNGError(windowscng.Delete(name))
}

// mapCNGError translates the shared windowscng not-found-or-not-accessible
// sentinel into the Machine Identity ErrKeyNotFound contract while keeping the original error in
// the error tree. The result matches both ErrKeyNotFound and, through
// errors.Is, windowscng.ErrKeyNotFound, and any native cause the shared layer
// attached (for example *windowscng.NCryptError, reachable with errors.As) is
// preserved. Callers must classify the result with errors.Is and errors.As:
// errors.Unwrap does not traverse the multi-error tree and a direct comparison
// with ErrKeyNotFound no longer holds.
//
// The sentinel means "not found or not accessible", not proof of absence.
// Other errors (permission, corruption, incompatible-key, unexpected failures)
// are passed through unchanged and are never converted into not-found, and a
// nil error stays nil. The native code is not re-classified here: only an
// error that already carries the windowscng sentinel is mapped.
func mapCNGError(err error) error {
	if errors.Is(err, windowscng.ErrKeyNotFound) {
		return fmt.Errorf("%w: %w", ErrKeyNotFound, err)
	}
	return err
}
