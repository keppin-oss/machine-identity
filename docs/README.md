# Keppin Machine Identity — Technical Documentation

This document is the authoritative technical reference for
`github.com/keppin-oss/machine-identity`. It records the module's contracts and
behavior, labeling each claim by its nature so readers can distinguish what is
guaranteed from what is incidental.

This document describes v0.3.0. For the changes from v0.2.0, see
[Upgrading from v0.2.0](#upgrading-from-v020) and the
[v0.3.0 release notes](release-notes-v0.3.0.md); for the changes from v0.1.x, see
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
- the **key custody** for that key (separate open, create and delete in the
  Windows Microsoft Software Key Storage Provider),
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
| `keystore` | Windows CNG/KSP key custody: separate open, create and delete under a service policy, the SubjectPublicKeyInfo helper and the error contract. | Windows only |
| `publickey` | Canonical public-key encoding, parsing, and fingerprinting. | Any |
| `identityproof` | Domain-separated proof-of-possession signing and verification. | Any |

## Requirements

- **platform** — Go 1.26.8 (see `go.mod`; required by the CNG dependency).
- **verified** — dependency: [`github.com/keppin-oss/cng`](https://github.com/keppin-oss/cng)
  v0.5.1 (`windowscng`), resolved from the public module; no `replace`
  directive is used.

## Persisted identity key contract

- **contract** — `identity.ProdMachineIdentityKeyName` is
  `Keppin.Agent.MachineIdentity.v1`. It is the full persisted production CNG key
  name. It is Keppin-owned and must not use any other product namespace.
- **contract** — this value must not change after the first external release
  without an explicit migration/cleanup procedure; changing it would create a
  parallel identity.
- **verified** — the value is locked byte-for-byte by `identity` tests, and the
  `keystore` package tests assert that the keystore operates on exactly this
  name.

## Key custody lifecycle

`keystore` exposes the machine identity key through `windowscng.Signer`, a
`crypto.Signer` with `Close`, so `identityproof` can consume it without
Windows-specific coupling. Opening, creating and deleting are separate
operations; none performs another as a side effect.

- **Policy** — every operation takes a `windowscng.ServicePolicy`, built by
  the caller with `windowscng.NewServicePolicy(serviceName)` from the name of
  the Windows service that uses the key. Its protected DACL grants SYSTEM and
  Administrators `GENERIC_ALL` and that service's own SID (`NT SERVICE\<name>`)
  read and execute. The service must run with its service SID enabled in its
  token (`sc.exe sidtype <name> unrestricted`, or `restricted`). This module
  does not choose or embed the service name.
- **Open** — `keystore.Open(policy)` opens the existing key only and never
  creates, modifies or deletes a key. It fails with `ErrKeyNotFound` when the
  key was not found **or is not accessible** to the caller (the two cases are
  not distinguished), and with `ErrKeyPolicyMismatch` when the key is not
  exactly in the policy state.
- **Create** — `keystore.Create(policy)` creates a new non-exportable,
  machine-scoped ECDSA P-256 key and never opens, adopts, modifies or deletes an
  existing one: a key already persisted under the name returns `ErrKeyExists`.
  It requires an elevated (Administrator) process or LocalSystem.
- **Identity** — `keystore.SPKI(signer.Public())` returns the DER
  SubjectPublicKeyInfo of the key (`x509.MarshalPKIXPublicKey`, ECDSA P-256
  only). The caller records it durably right after `Create` and before using
  the key.
- **Delete** — `keystore.Delete(policy, expectedSPKI)` deletes the exact key
  only after the shared CNG dependency has verified, on the handle it then
  deletes, the policy and that the key's SubjectPublicKeyInfo is
  `expectedSPKI`. It requires an elevated process or LocalSystem.

The non-exportability, machine scope, Microsoft Software KSP and the exact DACL
of the key are the *intended profile* (policy), enforced by the shared CNG
dependency; this module delegates those operations and does not re-implement
them (verified by `keystore` tests).

### Creating is an explicit decision

- **caller responsibility** — a failed open is never a reason to create a key.
  `ErrKeyNotFound` does not prove that the key is absent: the Microsoft Software
  KSP can report a key that exists but whose DACL does not grant the caller as
  not found. `ErrKeyPolicyMismatch` means a key exists in another state. Neither
  outcome authorizes `Create`; creation belongs to an authorized first
  installation or recovery flow owned by the caller.
- **caller responsibility** — `Create` does not reserve the key name:
  `ErrKeyExists` covers only a key already persisted, and two overlapping
  creates can both succeed with different keys. The caller serializes every
  lifecycle operation on the key (create, delete, recovery), also across
  processes, from before the create until the new key's SubjectPublicKeyInfo
  is recorded.
- **caller responsibility** — compare the recorded SubjectPublicKeyInfo with
  the opened key's at every later open; a difference is a conflict to report,
  never a key to adopt or to delete by name.
- **verified** — when the key created by `Create` fails its post-create checks,
  the shared layer deletes it through the same handle; if that delete fails too,
  the error also matches `windowscng.ErrCleanupFailed` and the key may persist.
  No signer is returned on any error, and the caller must not delete the key by
  name.

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
  accessible** (`Open`, `Delete`). It is **not** proof of absence and must
  never, by itself, trigger a create, reset, regeneration or overwrite of the
  identity key. From `Delete` it means only that the call deleted nothing.
- `keystore.ErrKeyExists` — `Create` found a key already persisted under the
  name; the existing key was not opened, adopted, modified or deleted.
- `keystore.ErrKeyPolicyMismatch` — the key exists but its DACL is not exactly
  the requested policy, or its public key is not a valid ECDSA P-256 key. Open
  never modifies the key.
- `keystore.ErrPrivilegeRequired` — `Create` or `Delete` was called by a process
  that is not elevated (Administrators) or LocalSystem, or the privilege could
  not be established; nothing was opened, created or deleted.
- `keystore.ErrDeleteVerificationFailed` — `Delete` opened the key but a check
  on that handle did not pass or could not be completed (export policy, curve,
  DACL or SubjectPublicKeyInfo); nothing was deleted. It does not prove that
  the key belongs to someone else. It takes precedence over a policy mismatch:
  the result then matches `windowscng.ErrPolicyMismatch` but not
  `keystore.ErrKeyPolicyMismatch`.
- **verified** — match every sentinel with `errors.Is`, not `==`: the returned
  error also keeps the shared `windowscng` error and, when it carries one, the
  native status, reachable with `errors.As` and `*windowscng.NCryptError`.
  `errors.Unwrap` does not traverse this error tree.
- **verified** — an error that matches none of the shared sentinels above
  (invalid input such as an empty or malformed SubjectPublicKeyInfo or the zero
  `ServicePolicy`, a failure of the native delete itself, a create rollback
  failure `windowscng.ErrCleanupFailed` on its own, other unexpected failures)
  is returned unchanged and is **never** converted into not-found or into a
  failed verification.
- **platform** — a permission denial that the Microsoft Software KSP itself
  reports as not found does arrive as `ErrKeyNotFound`.
- **verified** — existing keys that fail the exact policy validation on open
  fail closed: no signer is returned.

## Handle ownership / Close responsibility

- **caller responsibility** — the `windowscng.Signer` returned by `Open` and
  `Create` owns the underlying CNG provider and key handles. Release them with
  `Close` when done; the persisted key stays:

  ```go
  defer signer.Close()
  ```

  Code that only signs can receive the signer as a `crypto.Signer`.
- **caller responsibility** — close a signer before deleting the key it
  represents. Signers opened before a change keep the access they were opened
  with until they are closed.

## Windows elevation requirements

- **platform** — `Create` and `Delete` require an elevated (Administrator)
  process or LocalSystem, whatever the policy; otherwise they return
  `ErrPrivilegeRequired`. Invalid input is rejected before that check.
- **platform** — `Open` under a `ServicePolicy` does not require elevation, but
  that does not guarantee access: the caller's token must be granted by the key
  DACL (SYSTEM, Administrators, or the service SID of the policy).

## Delete semantics

- **verified** — `Delete` removes the exact persisted key name and never performs
  wildcard/prefix deletion.
- **verified** — `Delete` deletes only after the shared CNG dependency has
  verified, on the handle it then deletes, the export policy, the curve, the
  exact DACL of the policy and that the key's SubjectPublicKeyInfo is
  byte-for-byte `expectedSPKI`. Otherwise it returns
  `ErrDeleteVerificationFailed` and deletes nothing.
- **caller responsibility** — `expectedSPKI` is the value recorded after
  `Create` (see `keystore.SPKI`), never one derived by opening the key just
  before the delete. A key whose SubjectPublicKeyInfo was never recorded cannot
  be deleted through this module.
- **verified** — the SubjectPublicKeyInfo is the DER PKIX encoding, not the
  canonical 65-byte reference of `publickey.Encode`: the two are not
  interchangeable.
- **verified** — if the key is not found or not accessible, `Delete` returns
  `ErrKeyNotFound` and deletes nothing. That means only "this call deleted
  nothing": it does **not** prove that the key is absent, so callers must not
  treat it as proof of successful cleanup.
- **contract** — deleting the key destroys the prior identity's proof
  capability; a key created afterwards is a new identity unless a higher-level
  migration/recovery protocol exists.

## Examples

- [`examples/publicreference`](../examples/publicreference) — platform-independent;
  shows canonical encoding, fingerprint, round-trip parse, and
  proof-of-possession using a synthetic in-memory P-256 key. Use this to learn
  the reference and proof contract without Windows/elevation.
- [`examples/machineidentity`](../examples/machineidentity) — Windows only; the
  realistic flow under the `ServicePolicy` of `-service <name>`: `Open` the
  existing key, encode/fingerprint the public reference, sign a challenge,
  verify it, and close the signer. It never creates a key unless run with
  `-create`, which requires an elevated process, fails if a key exists, and
  prints the new key's SubjectPublicKeyInfo (DER, base64) right after the
  create. That output is not a durable record. The example never deletes the
  key.

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

- **Key names and policy.** Every run uses its own name,
  `Keppin.Test.MachineIdentity.` followed by a 128-bit random suffix, and the
  `ServicePolicy` of a test service name that does not need to exist. A guard
  rejects the production key name before any CNG call, and the tests never call
  the production `Open`/`Create`/`Delete`.
- **Machine.** Use a sacrificial, exclusive test VM: no production identity, no
  concurrent runs, no other writer on the `Keppin.Test.` namespace. Run from an
  elevated (Administrator) process or as LocalSystem.
- **SKIP and FAIL.** Elevation is read from the process token before any CNG
  call. Only a caller that is certainly not elevated is skipped; with
  `KEPPIN_KEYSTORE_SMOKE_REQUIRED=1` it fails instead. Any unexpected error
  fails the test, and no CNG error is ever turned into a SKIP; the only accepted
  errors are the outcomes each scenario expects (`ErrKeyNotFound` after a
  delete, `ErrKeyExists` for a second create, `ErrDeleteVerificationFailed` for
  another key's SubjectPublicKeyInfo, `ErrKeyPolicyMismatch` for another
  service's policy). A SKIP is never a PASS: check the output for the scenarios
  actually run.
- **Scenarios.** Custody (create, sign/verify, reopen the same key, delete,
  readback); the delete lifecycle twice on one name, with a repeated delete
  using the SubjectPublicKeyInfo of the same iteration; a second create refused
  with `ErrKeyExists`; a delete with the SubjectPublicKeyInfo of another valid
  P-256 key refused; an open under another service's policy refused. After each
  refusal the key is reopened and its SubjectPublicKeyInfo compared with the
  recorded one.
- **Ownership limit.** Keys are created with `Create`, which never adopts an
  existing key: a collision fails the test without signing, changing or
  deleting that key. `Create` does not reserve the name; the exclusive VM is
  what makes the key attributable to the run.
- **Identity.** The SubjectPublicKeyInfo of every created key is recorded from
  the signer `Create` returns, and every cleanup delete uses it, never one read
  by opening the key. The only delete with another value is the negative
  scenario, which uses another key's SubjectPublicKeyInfo on purpose. If a create fails with an uncertain rollback
  (`windowscng.ErrCleanupFailed`) or the value cannot be recorded, the test
  fails naming the key and its uncertain state and deletes nothing by name.
- **Cleanup.** Signers are closed before deletion and Close/Delete errors are
  reported. A reported Close error is not proof that the native handle was
  released. A recovery delete that returns `ErrKeyNotFound` is reported as an
  uncertain state, not as success, and a successful recovery delete does not
  clear an earlier failure. This is fixture cleanup, not product recovery.
- **Recovery after interruption.** If the process is killed and cleanup does not
  run, keep the test output as evidence and restore or dispose of the VM. Do not
  use wildcard deletion and never act on the production key name.

`go vet -tags keystore_smoke ./keystore` analyzes the tagged code statically;
`go test -c -tags keystore_smoke ./keystore` compiles **and links** the smoke
test binary. Neither runs the smoke tests, so a PASS of either is not a native
validation.

Only on a VM that meets the conditions above (PowerShell):

```powershell
$env:KEPPIN_KEYSTORE_SMOKE_REQUIRED = '1'
go test -count=1 -v -tags keystore_smoke ./keystore -run '^TestSmoke(MachineIdentityKeyCustody|DeleteKeyLifecycle|CreateExistingKeyNotAdopted|DeleteWrongSPKIRefused|OpenOtherPolicyMismatch)$'
```

All five scenarios must run and PASS with zero SKIP. Do not retry
automatically to turn a failure green.

## Caller responsibilities

- Treat the identity name, canonical encoding, and fingerprint as contracts you
  must not alter.
- Build the `ServicePolicy` from the name of the service that actually uses the
  key, and run that service with its service SID enabled.
- Create the key only in an authorized first installation or recovery flow,
  never after a failed open; serialize every lifecycle operation on the key.
- Record the SubjectPublicKeyInfo returned for a created key durably, compare
  it at every open, and pass it to `Delete`.
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
- **policy** — the persisted key is created with the protected DACL of its
  `ServicePolicy` (SYSTEM and Administrators get `GENERIC_ALL`, the one service
  SID gets read/execute), with no access for LOCAL SERVICE as a whole or for
  ordinary interactive or authenticated users; enforcement lives in the shared
  CNG dependency, not in this module.
- **policy** — every open and every delete re-validates the persisted key's
  export policy, curve and DACL as implemented by the CNG dependency: the DACL
  must be exactly the form of the requested policy (a protected DACL with
  exactly the expected entries and masks; owner, group and SACL are not
  checked). Any other DACL is rejected, never repaired. This does not establish
  Windows effective access.
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

- **`keystore.Create`/`Delete` returns `ErrPrivilegeRequired`** — run from an
  elevated (Administrator) process or as LocalSystem; machine-scoped key
  creation and deletion require it.
- **`keystore.Open` or `keystore.Delete` returns `ErrKeyNotFound`** — the key
  was not found **or is not accessible** to this caller; the two look the same.
  First check the caller's privileges and that the service runs with its
  service SID enabled, and inspect the native status with `errors.As` and
  `*windowscng.NCryptError`. Do **not** call `Create` or reset the identity, and
  do not treat the error as successful cleanup, on this error alone.
- **`keystore.Open` returns `ErrKeyPolicyMismatch`** — the key exists but its
  DACL is not exactly the requested `ServicePolicy`: for example a key created
  by v0.2.0 or earlier with the LOCAL SERVICE DACL, a policy built for another
  service name, or a DACL changed by hand. The key was not modified. Do not
  create, delete or adopt it from this error; see
  [Upgrading from v0.2.0](#upgrading-from-v020).
- **`keystore.Create` returns `ErrKeyExists`** — a key is already persisted
  under the name. It was not opened or changed. Open it, or follow an
  authorized recovery flow; never delete it by name to make room.
- **`keystore.Delete` returns `ErrDeleteVerificationFailed`** — the key is not
  the recorded one (SubjectPublicKeyInfo), or not in the policy state. Nothing
  was deleted.
- **"not supported on this platform"** — the persisted Machine Identity custody
  (`keystore`) is Windows-only; run key custody on Windows. The
  `publickey`/`identityproof` primitives are platform-independent.
- **`Verify` returns `ErrInvalidProof`** — the challenge, key, or signature do
  not match; ensure the signature was produced by `identityproof.Sign` for the
  exact challenge and that the public key is the signer's own (parsed via
  `publickey.Parse`).

## Upgrading from v0.2.0

v0.3.0 is a **breaking** release with no compatibility layer.

- **CNG dependency v0.5.1.** `github.com/keppin-oss/cng` moves from v0.3.1 to
  v0.5.1. Go stays at 1.26.8.
- **Load-or-create is removed.** The v0.2.0 entry point that opened the key
  and, after any failed open, attempted to create it is gone. Use `Open(policy)` for ordinary use
  and `Create(policy)` only in an authorized first installation or recovery
  flow. A key that cannot be opened is an error to handle, never a reason to
  create one.
- **Open, Create and Delete take a policy.** `Open()`, `Delete()` become
  `Open(policy)`, `Delete(policy, expectedSPKI)`; `Create(policy)` is new. The
  policy is a `windowscng.ServicePolicy` built from the name of the service that
  uses the key; keys are created with its DACL instead of the v0.2.0 DACL that
  granted LOCAL SERVICE as a whole.
- **Delete needs the recorded identity.** `Delete` requires the key's DER
  SubjectPublicKeyInfo recorded after `Create` (`keystore.SPKI`, new), and
  deletes only after verifying it on the handle it deletes.
- **Signers are `windowscng.Signer`.** `Open` and `Create` return
  `windowscng.Signer`; call `Close` directly instead of type-asserting a
  `crypto.Signer`.
- **New sentinels.** `ErrKeyExists`, `ErrKeyPolicyMismatch`,
  `ErrPrivilegeRequired` and `ErrDeleteVerificationFailed`, each wrapping the
  shared `windowscng` error. `ErrKeyNotFound` is unchanged.
- **Exact DACL validation.** The tolerant check of v0.2.0 is gone: `Open` and
  `Delete` accept only the exact DACL of the policy.
- **Existing keys do not open.** A key created by v0.2.0 or earlier carries the
  LOCAL SERVICE DACL, which is not a `ServicePolicy`: `Open(policy)` returns
  `ErrKeyPolicyMismatch`, or `ErrKeyNotFound` if the caller cannot open it at
  all. `Delete` refuses it with `ErrDeleteVerificationFailed` even with the
  right SubjectPublicKeyInfo, because its DACL is not the exact form of the
  policy; without a recorded SubjectPublicKeyInfo it cannot be deleted at all.
  This release provides no migration path for those keys. Before rolling out
  to existing installations, stop at this condition explicitly: do not create,
  delete, adopt or re-permission the key from this module's errors.

## Upgrading from v0.1.x

This section describes only the move from v0.1.x to v0.2.0 (see the
[v0.2.0 release notes](release-notes-v0.2.0.md)). The API it refers to is the
v0.2.0 one; for v0.3.0, continue with
[Upgrading from v0.2.0](#upgrading-from-v020).

- **`ErrKeyNotFound` means "not found or not accessible".** Its text is now
  `keystore: machine identity key not found or not accessible`. Code that
  treated it as proof that the key is absent (for example to create a new
  key, to regenerate the identity, or to report successful cleanup after a
  delete) must be changed: check the caller's privileges and the native status
  instead.
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
- v0.2.0 added or removed no exported identifier.
