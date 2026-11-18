# Keppin Machine Identity — Technical Documentation

This document is the authoritative technical reference for
`github.com/keppin-oss/machine-identity`. It records the module's contracts and
behavior, labeling each claim by its nature so readers can distinguish what is
guaranteed from what is incidental.

This document describes v0.2.0. For the changes from v0.1.x, see
[Upgrading from v0.1.x](#upgrading-from-v01x) and the
[v0.2.0 release notes](release-notes-v0.2.0.md).

### Claim legend

- **contract** — a compatibility/persisted contract that must not change without
  a coordinated migration.
- **verified** — behavior backed by this repository's code and tests.
- **platform** — a requirement imposed by the operating system or build
  constraints.
- **caller responsibility** — an obligation on the caller that this module does
  not enforce.
- **policy** — intended behavior or an assumption not directly enforced by this
  module's code (for example, behavior owned by the shared CNG dependency).

## Purpose

The module solves one problem: giving a Windows machine a stable, durable
identity it can prove it holds. It owns four things:

- the persisted **identity key name** (a compatibility contract),
- the **key custody** for that key (create/open/delete in the Windows Microsoft
  Software Key Storage Provider),
- the **canonical public-key reference** (uncompressed P-256 point encoding and
  its stable SHA-256 fingerprint),
- the **proof-of-possession** primitive (domain-separated challenge signing and
  verification).

Consumers should integrate through the documented public API here rather than
re-deriving any of its representations or protocol details.

## Non-goals / boundary

This module deliberately does **not** own:

- Keppin **Tenant / Invitation / Installation** authorization semantics — those
  are owned elsewhere and must not be re-derived here.
- **X.509, certificate stores, enrollment, trust stores, or TLS** — no
  certificate behavior is implemented here.
- **Native Windows CNG/KSP syscalls and DACL handling** — those live in the
  shared [`cng`](https://github.com/keppin-oss/cng) module's `windowscng`
  package; this module owns only the Machine Identity policy on top of it.
- **Local-TLS or Enterprise-TLS identities** — those are separate products and
  must not leak into the machine identity key namespace.
- **Transport, networking, or orchestration** — proof-of-possession is a pure
  signing/verification primitive with no transport coupling.

## Packages and responsibilities

| Package | Responsibility | Platform |
| --- | --- | --- |
| `identity` | Owns the persisted identity key name and profile naming contract. | Any |
| `keystore` | Windows CNG/KSP key custody: create/open/delete and the not-found-or-not-accessible contract. | Windows only |
| `publickey` | Canonical public-key encoding, parsing, and fingerprinting. | Any |
| `identityproof` | Domain-separated proof-of-possession signing and verification. | Any |

## Requirements

- **platform** — Go 1.26.8 (see `go.mod`; required by the CNG dependency).
- **verified** — dependency: [`github.com/keppin-oss/cng`](https://github.com/keppin-oss/cng)
  v0.3.1 (`windowscng`), resolved from the public module; no `replace`
  directive is used.

## Persisted identity key contract

- **contract** — `identity.ProdMachineIdentityKeyName` is
  `Keppin.Agent.MachineIdentity.v1`. It is the full persisted production CNG key
  name. It is Keppin-owned and must not use any other product namespace.
- **contract** — this value must not change after the first external release
  without an explicit migration/cleanup procedure; changing it would create a
  parallel identity.
- **verified** — the value is locked byte-for-byte by `identity` tests, and the
  `keystore` package tests assert that `Delete` targets exactly this name.

## Key custody lifecycle

`keystore` exposes the machine identity key through `crypto.Signer`, so
`identityproof` can consume it without Windows-specific coupling.

- **Create / load-or-create** — `keystore.LoadOrCreate()` opens the existing
  persisted key or creates it (non-exportable, machine-scoped ECDSA P-256) if it
  does not yet exist.
- **Open** — `keystore.Open()` opens the existing key only and never creates a
  replacement. It fails with `ErrKeyNotFound` when the key was not found **or is
  not accessible** to the caller; the two cases are not distinguished.
- **Delete** — `keystore.Delete()` removes the exact key by name, never by
  wildcard.

The non-exportability, machine scope, Microsoft Software KSP, and restrictive
DACL of the key are the *intended profile* (policy), enforced by the shared CNG
dependency; this module delegates those operations and does not re-implement
them (verified by `keystore` tests).

### Load-or-create behavior note

`LoadOrCreate` is documented at the load-or-create contract level only: it
returns the persisted key, creating it when it does not yet exist. This module
does **not** provide a stronger guarantee that an existing key which fails to
open for other reasons (for example, an inaccessible or incompatible key) is
preserved rather than recreated. The underlying CNG dependency may attempt
creation on an arbitrary open failure; that behavior is **not** a Machine
Identity guarantee. The creation does not request overwriting an existing key.

`Open` cannot tell "absent" from "present but inaccessible" either: the
Microsoft Software KSP can report a key that exists but whose DACL does not
grant the caller as not found, and `Open` returns `ErrKeyNotFound` in both
cases. Callers that must not risk acting on an inaccessible key should first
check the caller's privileges and inspect the native status (see
[Error / failure semantics](#error--failure-semantics)), and must never treat
`ErrKeyNotFound` alone as permission to create a new identity.

## Public-key reference: canonical encoding and fingerprint

- **verified** — the canonical encoding is the standard uncompressed ECDSA P-256
  point `0x04 || X || Y` (65 bytes), with `X` and `Y` left-padded to 32 bytes.
  `publickey.Encode` returns this form and rejects a nil key, an unsupported
  curve, missing coordinates, or an off-curve point.
- **verified** — `publickey.Parse` accepts only the exact canonical form and
  rejects any other length, any other prefix (including compressed points), and
  any off-curve point, returning `publickey.ErrInvalidPublicKey`.
- **verified** — the fingerprint is the lowercase hexadecimal SHA-256 digest of
  the exact 65-byte canonical encoding. `publickey.Fingerprint` derives the
  canonical encoding first, so the fingerprint is never of an alternate
  encoding. `publickey.FingerprintOfEncoding` validates the encoding first.
- **verified** — encoding and fingerprinting operate on public material only and
  never contain private-key material.

## Proof of possession

### Machine Identity proof profile

- **contract** — `identityproof.Domain` is
  `Keppin.MachineIdentity.ProofOfPossession.v1`; it is the domain-separation
  prefix and must not change without a coordinated version bump across signers
  and verifiers.
- **contract** — `identityproof.KeyAlgorithmECDSA256` is `ecdsa-p256`, the
  algorithm label for the ECDSA P-256 proof profile.
- **contract** — the intended Machine Identity key profile is ECDSA P-256, and
  signatures from the intended ECDSA signer are ASN.1 (DER) ECDSA signatures.
- **verified** — `Domain` and `KeyAlgorithmECDSA256` are locked byte-for-byte by
  `identityproof` tests.

### `identityproof.Sign` / `Verify` API behavior

- **verified** — `identityproof.Digest(challenge)` is
  `SHA-256(Domain || 0x00 || challenge)`.
- **verified** — `identityproof.Sign` operates on a caller-supplied
  `crypto.Signer`: it hashes the challenge into the domain-separated digest and
  passes `crypto.SHA256` to the signer, returning whatever signature format the
  signer produces. The package does not itself guarantee that an arbitrary signer
  supplied to `Sign` is P-256 ECDSA or that its output is DER. CNG/KSP-backed
  signers work without platform coupling.
- **verified** — `identityproof.Verify` verifies ECDSA signatures for a supplied
  `*ecdsa.PublicKey` (a parsed public reference from `publickey.Parse` works
  directly) and returns `identityproof.ErrInvalidProof` on any mismatch, or a
  distinct error for an unsupported public-key type. `Verify` does not
  independently enforce P-256; callers using the Machine Identity profile are
  responsible for supplying profile-conforming key material, normally obtained
  from this module's canonical Machine Identity flow.

### Replay protection and challenge freshness

- **caller responsibility** — proof of possession alone does **not** provide
  replay protection. A protocol using these proofs should ensure, as appropriate
  to its design, that challenges are fresh/unpredictable, that they expire, and
  that an accepted challenge/nonce is not reused; that the proof is checked
  against the intended enrolled/trusted public key; and that the challenge (or
  the surrounding protocol) binds the proof to the intended
  operation/session/context when replay across contexts would matter.
- The fixed challenge strings in the examples and tests exist only to demonstrate
  the primitive. Production protocols must not treat a reusable fixed challenge
  as replay protection.

## Supported algorithm / profile

- **contract** — the Machine Identity key profile is ECDSA P-256 only. No other
  curve or algorithm is part of the Machine Identity contract.
- **verified** — `publickey` rejects any key on a curve other than P-256.
- `identityproof.Verify` does not independently enforce P-256; see
  [Proof of possession](#proof-of-possession).

## Error / failure semantics

- `publickey.ErrInvalidPublicKey` — malformed, unsupported, off-curve, or nil key
  or encoding.
- `identityproof.ErrInvalidProof` — the signature does not verify against the
  given key/challenge; `Verify` also returns a distinct error for an unsupported
  public-key type.
- `keystore.ErrKeyNotFound` — the persisted key was not found **or is not
  accessible** (returned by `Open` and `Delete`, and by `LoadOrCreate` when the
  failure carries the shared not-found error). It is **not** proof of absence
  and must never, by itself, trigger a reset, regeneration or overwrite of the
  identity key.
- **verified** — match `ErrKeyNotFound` with `errors.Is`, not `==`: the returned
  error also keeps the shared `windowscng.ErrKeyNotFound` and any native status,
  reachable with `errors.As` and `*windowscng.NCryptError`. `errors.Unwrap`
  does not traverse this error tree.
- **verified** — other `keystore` errors (permission, corruption, incompatible
  key, unexpected failure) are passed through unchanged and are **never**
  converted into not-found by `keystore`.
- **platform** — a permission denial that the Microsoft Software KSP itself
  reports as not found does arrive as `ErrKeyNotFound`.
- **verified** — existing keys that fail security validation on open fail
  closed: no signer is returned.

## Handle ownership / Close responsibility

- **caller responsibility** — the `crypto.Signer` returned by `keystore` owns the
  underlying CNG provider and key handles. To release them, type-assert to
  `windowscng.Signer` and call `Close`:

  ```go
  signer.(windowscng.Signer).Close()
  ```

- **caller responsibility** — close a signer before deleting the key it
  represents.

## Windows elevation requirements

- **platform** — creating or deleting the machine-scoped key requires an
  elevated (Administrator) process. Opening an existing key and signing does not
  require elevation for principals granted access by the key's DACL.

## Delete semantics

- **verified** — `Delete` removes the exact persisted key name and never performs
  wildcard/prefix deletion.
- **verified** — if the key is not found or not accessible, `Delete` returns
  `ErrKeyNotFound` and deletes nothing. That means only "this call deleted
  nothing": it does **not** prove that the key is absent, so callers must not
  treat it as proof of successful cleanup.
- **contract** — deleting the key destroys the prior identity's proof
  capability; a later `LoadOrCreate` produces a new identity unless a
  higher-level migration/recovery protocol exists.

## Examples

- [`examples/publicreference`](../examples/publicreference) — platform-independent;
  shows canonical encoding, fingerprint, round-trip parse, and
  proof-of-possession using a synthetic in-memory P-256 key. Use this to learn
  the reference and proof contract without Windows/elevation.
- [`examples/machineidentity`](../examples/machineidentity) — Windows only; the
  full realistic flow: `LoadOrCreate`, encode/fingerprint the public reference,
  sign a challenge, verify it, `Open` the existing key, and close signers.
  Requires an elevated process for first creation.

The examples use synthetic/non-sensitive data and only supported public APIs;
they expose no private key material and contain no re-implementation of the
module's crypto.

`examples/machineidentity` operates on the real production key name. It is not
a test or cleanup tool.

## Native smoke tests

`go test ./...` with the default build tags (no native tags in `GOFLAGS`) never
touches real CNG keys. The native tests in `keystore/keystore_smoke_test.go`
run only with the `keystore_smoke` build tag and create, use and delete real
persisted machine-scoped keys.

- **Key names.** Every run uses its own name, `Keppin.Test.MachineIdentity.`
  followed by a 128-bit random suffix. A guard rejects the production key name
  before any CNG call, and the tests never call the production
  `LoadOrCreate`/`Open`/`Delete`.
- **Machine.** Use a sacrificial, exclusive test VM: no production identity, no
  concurrent runs, no other writer on the `Keppin.Test.` namespace. Run from an
  elevated (Administrator) process or as LocalSystem.
- **SKIP and FAIL.** Elevation is read from the process token before any CNG
  call. Only a caller that is certainly not elevated is skipped; with
  `KEPPIN_KEYSTORE_SMOKE_REQUIRED=1` it fails instead. Any unexpected error
  fails the test, and no CNG error is ever turned into a SKIP; the only accepted
  CNG errors are the expected `ErrKeyNotFound` outcomes of the pre-check, the
  post-delete readback and the repeated delete. A SKIP is never a PASS: check
  the output for the scenarios actually run.
- **Ownership limit.** Before creating, a pre-check with `Open` must report
  `ErrKeyNotFound`. If it opens a key, the test closes it and fails for
  collision without signing, changing or deleting it. `ErrKeyNotFound` does not
  prove absence, `LoadOrCreate` does not certify that it created the key, and a
  key appearing between the pre-check and the creation is not excluded (TOCTOU).
  The exclusive VM is what makes the key attributable to the run.
- **Cleanup.** Signers are closed before deletion and Close/Delete errors are
  reported. A reported Close error is not proof that the native handle was
  released. A recovery delete that returns `ErrKeyNotFound` is reported as an
  uncertain state, not as success, and a successful recovery delete does not
  clear an earlier failure.
- **Recovery after interruption.** If the process is killed and cleanup does not
  run, keep the test output as evidence and restore or dispose of the VM. Do not
  use wildcard deletion and never act on the production key name.

A PASS of `go vet -tags keystore_smoke ./keystore` only checks the code
statically; it is not a native validation.

Only on a VM that meets the conditions above (PowerShell):

```powershell
$env:KEPPIN_KEYSTORE_SMOKE_REQUIRED = '1'
go test -count=1 -v -tags keystore_smoke ./keystore -run '^TestSmoke(MachineIdentityKeyCustody|DeleteKeyLifecycle)$'
```

Both scenarios must run and PASS with zero SKIP. Do not retry automatically to
turn a failure green.

## Caller responsibilities

- Treat the identity name, canonical encoding, and fingerprint as contracts you
  must not alter.
- Run create/delete from an elevated context.
- Close signers when done, and before delete.
- Never ship or log private key material (the public reference contains none).

## Security invariants

- **policy** — the identity key is non-exportable and machine-scoped; private key
  material is never returned by this module's API. The non-exportability and
  machine scope are enforced by the shared CNG dependency.
- **verified** — `publickey` operates on public material only; the encoding and
  fingerprint contain no private-key material. `identityproof` verification uses
  public-key material, while `identityproof.Sign` exercises a private signing
  capability through `crypto.Signer`; the package does not require or expose raw
  private-key bytes.
- **verified** — the key is ECDSA P-256 only; `publickey` rejects any other
  curve.
- **policy** — the persisted key is created with a restrictive DACL (SYSTEM and
  Administrators get `GENERIC_ALL`, LOCAL SERVICE gets read/open) with no access
  requested for ordinary interactive or authenticated users; enforcement lives
  in the shared CNG dependency, not in this module.
- **policy** — every open re-validates the persisted key's export policy and
  checks the DACL as implemented by the CNG dependency: the required principals
  must be present and specific disallowed principals are rejected. This is
  **not** an exclusive allow-list (additional entries are accepted) and does not
  establish Windows effective access.
- **verified** — the fingerprint is always the SHA-256 of the canonical
  encoding — never of an alternate encoding.
- **verified** — proof-of-possession is domain-separated to prevent
  cross-protocol confusion.
- **contract** — the identity key name, domain separator, and key algorithm are
  compatibility contracts locked by tests.

## Platform boundaries

- **platform** — `keystore` is Windows-only and carries a `windows` build
  constraint; it uses the Windows CNG/KSP.
- **verified** — `identity`, `identityproof`, and `publickey` are
  platform-independent and build and run on any supported Go platform.

## Troubleshooting

- **`keystore.LoadOrCreate`/`Delete` fails with an access/permission error** —
  run from an elevated (Administrator) process; machine-scoped key creation and
  deletion require it.
- **`keystore.Open` or `keystore.Delete` returns `ErrKeyNotFound`** — the key
  was not found **or is not accessible** to this caller; the two look the same.
  First check the caller's privileges (run from an elevated or otherwise
  authorized process) and inspect the native status with `errors.As` and
  `*windowscng.NCryptError`. Do **not** call `LoadOrCreate` or reset the
  identity, and do not treat the error as successful cleanup, on this error
  alone.
- **"not supported on this platform"** — the persisted Machine Identity custody
  (`keystore`) is Windows-only; run key custody on Windows. The
  `publickey`/`identityproof` primitives are platform-independent.
- **`Verify` returns `ErrInvalidProof`** — the challenge, key, or signature do
  not match; ensure the signature was produced by `identityproof.Sign` for the
  exact challenge and that the public key is the signer's own (parsed via
  `publickey.Parse`).

## Upgrading from v0.1.x

- **`ErrKeyNotFound` means "not found or not accessible".** Its text is now
  `keystore: machine identity key not found or not accessible`. Code that
  treated it as proof that the key is absent (for example to call
  `LoadOrCreate`, to regenerate the identity, or to report successful cleanup
  after `Delete`) must be changed: check the caller's privileges and the native
  status instead.
- **Match with `errors.Is`, not `==`.** The returned error now wraps both
  `keystore.ErrKeyNotFound` and the original shared error, so a direct
  comparison `err == keystore.ErrKeyNotFound` no longer holds and
  `errors.Unwrap` returns nil. Use `errors.Is(err, keystore.ErrKeyNotFound)`;
  use `errors.As` with `*windowscng.NCryptError` to read the native status.
- **`Delete` is no longer described as idempotent.** `ErrKeyNotFound` from
  `Delete` means only that the call deleted nothing.
- **CNG dependency v0.3.1.** `github.com/keppin-oss/cng` moves from v0.1.1 to
  v0.3.1. The newer dependency rejects malformed security descriptors and
  export-policy values that the older one accepted (fail closed). Go stays at
  1.26.8.
- No exported identifier was added or removed.
