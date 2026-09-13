# Keppin Machine Identity — Technical Documentation

This document is the authoritative technical reference for
`github.com/keppin-oss/machine-identity`. It records the module's contracts and
behavior, labeling each claim by its nature so readers can distinguish what is
guaranteed from what is incidental.

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
| `keystore` | Windows CNG/KSP key custody: create/open/delete and the missing-key contract. | Windows only |
| `publickey` | Canonical public-key encoding, parsing, and fingerprinting. | Any |
| `identityproof` | Domain-separated proof-of-possession signing and verification. | Any |

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
  replacement. It fails if the key is absent (`ErrKeyNotFound`) or inaccessible.
- **Delete** — `keystore.Delete()` removes the exact key by name, never by
  wildcard.

The non-exportability, machine scope, Microsoft Software KSP, and
least-privilege DACL of the key are the *intended profile* (policy), enforced by
the shared CNG dependency; this module delegates those operations and does not
re-implement them (verified by `keystore` tests).

### Load-or-create behavior note

`LoadOrCreate` is documented at the load-or-create contract level only: it
returns the persisted key, creating it when it does not yet exist. This module
does **not** provide a stronger guarantee that an existing key which fails to
open for other reasons (for example, an inaccessible or incompatible key) is
preserved rather than recreated. The underlying CNG dependency may attempt
creation on an arbitrary open failure; that behavior is **not** a Machine
Identity guarantee. Callers that must distinguish "absent" from "present but
inaccessible" should call `Open` first.

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

- **contract** — `identityproof.Domain` is
  `Keppin.MachineIdentity.ProofOfPossession.v1`; it is the domain-separation
  prefix and must not change without a coordinated version bump across signers
  and verifiers.
- **contract** — `identityproof.KeyAlgorithmECDSA256` is `ecdsa-p256`, the
  algorithm label for the ECDSA P-256 proof profile.
- **verified** — `identityproof.Digest(challenge)` is
  `SHA-256(Domain || 0x00 || challenge)`.
- **verified** — `identityproof.Sign` signs the domain-separated digest through
  `crypto.Signer` (so CNG/KSP-backed signers work without platform coupling) and
  returns an ASN.1 (DER) ECDSA signature.
- **verified** — `identityproof.Verify` accepts `*ecdsa.PublicKey` (a parsed
  public reference from `publickey.Parse` works directly) and returns
  `identityproof.ErrInvalidProof` on any mismatch, or a distinct error for an
  unsupported public-key type.
- **verified** — `Domain` and `KeyAlgorithmECDSA256` are locked byte-for-byte by
  `identityproof` tests.

## Supported algorithm / profile

- **contract** — ECDSA P-256 only. No other curve or algorithm is supported.
- **verified** — `publickey` rejects any key on a curve other than P-256.

## Error / failure semantics

- `publickey.ErrInvalidPublicKey` — malformed, unsupported, off-curve, or nil key
  or encoding.
- `identityproof.ErrInvalidProof` — the signature does not verify against the
  given key/challenge; `Verify` also returns a distinct error for an unsupported
  public-key type.
- `keystore.ErrKeyNotFound` — the persisted key does not exist (returned by
  `Open` and by `Delete` on an already-absent key). Match with `errors.Is`.
- **verified** — other `keystore` errors (permission, corruption, incompatible
  key, unexpected failure) are passed through unchanged and are **never**
  converted into not-found.

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
- **verified** — deleting an already-absent key returns `ErrKeyNotFound`, so
  uninstall/reset callers can treat it as idempotent cleanup.
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
- **verified** — `publickey` and `identityproof` operate on public material only;
  the encoding and fingerprint contain no private-key material.
- **verified** — the key is ECDSA P-256 only; `publickey` rejects any other
  curve.
- **policy** — the persisted key carries a least-privilege DACL; enforcement
  lives in the shared CNG dependency, not in this module.
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
- **`keystore.Open` returns `ErrKeyNotFound`** — the key has not been created
  yet, or was deleted; call `LoadOrCreate` first (or treat as idempotent cleanup
  when using `Delete`).
- **"not supported on this platform"** — the persisted Machine Identity custody
  (`keystore`) is Windows-only; run key custody on Windows. The
  `publickey`/`identityproof` primitives are platform-independent.
- **`Verify` returns `ErrInvalidProof`** — the challenge, key, or signature do
  not match; ensure the signature was produced by `identityproof.Sign` for the
  exact challenge and that the public key is the signer's own (parsed via
  `publickey.Parse`).
