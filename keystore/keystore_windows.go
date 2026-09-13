//go:build windows

// Package keystore provides Windows CNG/KSP key custody for the Keppin Machine
// Identity key.
//
// The machine identity key is a non-exportable, machine-scoped ECDSA P-256 key
// persisted in the Microsoft Software Key Storage Provider, protected by a
// least-privilege DACL, and exposed to callers through crypto.Signer so the
// identityproof primitives can consume it without Windows-specific coupling.
//
// The native Windows CNG/KSP operations (open, create-or-open, delete, machine
// scope, non-exportability, DACL enforcement, and CNG handle lifecycle) are
// supplied by the shared github.com/keppin-oss/cng/windowscng
// package. This package owns only the Machine Identity policy: the production
// key name and the decision to create/open/delete it, the missing-key contract,
// and the public Machine Identity API.
package keystore

import (
	"crypto"
	"errors"

	"github.com/keppin-oss/cng/windowscng"
	"github.com/keppin-oss/machine-identity/identity"
)

// machineIdentityKeyName is the persisted CNG machine identity key name. It is
// a compatibility contract owned by the identity package and MUST NOT move into
// the CNG module.
const machineIdentityKeyName = identity.ProdMachineIdentityKeyName

// ErrKeyNotFound is returned by Delete (and Open) when the persisted Machine
// Identity key does not exist. It is a sentinel so uninstall/reset callers can
// treat an already-absent key as success (idempotent cleanup). It is the
// Machine Identity contract: callers must not need to know windowscng's
// sentinel.
var ErrKeyNotFound = errors.New("keystore: machine identity key not found")

// LoadOrCreate opens the existing persisted Machine Identity key or creates it
// (non-exportable, machine-scoped ECDSA P-256) if it does not yet exist.
func LoadOrCreate() (crypto.Signer, error) {
	return loadOrCreateKey(machineIdentityKeyName)
}

// Open opens the existing persisted Machine Identity key only and never silently
// creates a replacement. It fails if the key does not exist or is inaccessible.
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
// Delete never creates a key. It returns ErrKeyNotFound if the key is already
// absent, allowing idempotent uninstall/reset cleanup.
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

// mapCNGError translates the shared windowscng missing-key sentinel into the
// Machine Identity ErrKeyNotFound contract. Other errors (permission,
// corruption, incompatible-key, unexpected failures) are passed through
// unchanged and are never converted into not-found.
func mapCNGError(err error) error {
	if errors.Is(err, windowscng.ErrKeyNotFound) {
		return ErrKeyNotFound
	}
	return err
}
