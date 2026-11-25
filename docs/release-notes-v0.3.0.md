# Keppin Machine Identity v0.3.0

v0.3.0 moves to `github.com/keppin-oss/cng` v0.5.1 and separates opening,
creating and deleting the Machine Identity key. A key is never created as a
side effect of an open, never adopted by a create, and never deleted without
verifying its public key against a recorded identity. This is a **breaking**
release with no compatibility layer.

```
go get github.com/keppin-oss/machine-identity@v0.3.0
```

## Key custody: open, create and delete are separate

`Open`, `Create` and `Delete` take a `windowscng.ServicePolicy`, built by the
caller with `windowscng.NewServicePolicy(serviceName)` from the name of the
Windows service that uses the key. Its protected DACL grants SYSTEM and
Administrators full control and only that service's own SID read and execute.
The service must run with its service SID enabled.

| v0.2.0 | v0.3.0 |
|---|---|
| load-or-create entry point | **removed**: `Open`, and `Create` only where creating is intended |
| `Open() (crypto.Signer, error)` | `Open(policy) (windowscng.Signer, error)`: opens only, never creates |
| — | `Create(policy) (windowscng.Signer, error)`: creates only; an existing key returns `ErrKeyExists` and is not opened, adopted, modified or deleted |
| `Delete() error` | `Delete(policy windowscng.ServicePolicy, expectedSPKI []byte) error`: deletes only after the shared CNG layer verifies the policy and that the key's SubjectPublicKeyInfo is `expectedSPKI`, on the handle it deletes |
| — | `SPKI(pub crypto.PublicKey) ([]byte, error)`: the DER SubjectPublicKeyInfo of an ECDSA P-256 key, the identity `Delete` expects |

- `Open` and `Create` return `windowscng.Signer`; call `Close` directly.
- A failed open is never a reason to create a key: `ErrKeyNotFound` does not
  prove absence and `ErrKeyPolicyMismatch` means a key exists in another
  state. Create the key only in an authorized first installation or recovery
  flow.
- `Create` does not reserve the name: callers serialize every lifecycle
  operation on the key, also across processes, and record the
  SubjectPublicKeyInfo of a created key durably before using it. That value is
  not the canonical 65-byte reference of `publickey.Encode`.

## Errors

- New sentinels, each wrapping the shared `windowscng` error so that
  `errors.Is` matches both and `errors.As` reaches any native
  `*windowscng.NCryptError`:
  - `ErrKeyExists`: `Create` found a key already persisted under the name;
  - `ErrKeyPolicyMismatch`: the key's DACL is not exactly the requested policy
    or its public key is not a valid P-256 key;
  - `ErrPrivilegeRequired`: `Create` or `Delete` called by a process that is
    not elevated or LocalSystem;
  - `ErrDeleteVerificationFailed`: `Delete` refused to delete because a check
    on the handle did not pass or could not be completed. It takes precedence
    over a policy mismatch.
- `ErrKeyNotFound` is unchanged: "not found or not accessible".
- Invalid input (for example an empty or malformed SubjectPublicKeyInfo or the
  zero `ServicePolicy`) is returned unchanged and matches no sentinel.

## Behavior changes

- **Exact DACL validation.** `Open` and `Delete` accept only the exact DACL of
  the requested policy (owner, group and SACL are not checked); the tolerant
  check of v0.2.0 is gone.
- **Existing keys do not open.** A key created by v0.2.0 or earlier carries the
  LOCAL SERVICE DACL, which is not a `ServicePolicy`: `Open` returns
  `ErrKeyPolicyMismatch`, or `ErrKeyNotFound` if the caller cannot open it at
  all. `Delete` refuses it with `ErrDeleteVerificationFailed` even with the
  right SubjectPublicKeyInfo, because its DACL is not the exact form of the
  policy; without a recorded SubjectPublicKeyInfo it cannot be deleted at all.
  This release provides no migration path for those keys; before rolling out
  to existing installations, stop at this condition explicitly.
- **Privilege.** `Create` and `Delete` always require an elevated
  (Administrator) process or LocalSystem. `Open` under a `ServicePolicy` does
  not, but the caller's token must be granted by the key DACL.

## Dependency

- `github.com/keppin-oss/cng` moves from v0.3.1 to **v0.5.1**. Go stays at
  1.26.8.

## Tests and CI

- Default-tag tests use in-memory fakes and perform no operations on real CNG
  keys. A source scan keeps the removed load-or-create entry point out of the
  module.
- The native smoke tests (`keystore_smoke` build tag) now cover five
  scenarios: custody; the delete lifecycle twice with verified deletes; a
  second create refused with `ErrKeyExists`; a delete with another key's
  SubjectPublicKeyInfo refused; an open under another service's policy
  refused. After each refusal the key is reopened and found intact.
- New GitHub Actions workflow: build, vet (amd64, 386, smoke tag), build of the
  smoke test binary without running it, and the default tests on Windows;
  gofmt, build, vet and tests on Linux.

## Validation

- **Validated live:** all five native smoke scenarios passed, with zero SKIP,
  on Windows 11 Pro 25H2 (build 26200.9457) from an elevated administrator
  process and on Windows Server 2025 Standard 24H2 (build 26100.33822) as an
  elevated domain administrator over a remote session, with the Microsoft
  Software KSP and Go 1.26.8. The run was performed on the source tree before
  publication; the published tree differs only in the module path, import
  order and documentation (no production code change).
- **Default-tag checks:** `go build`, `go vet` (Windows amd64 and 386, Linux)
  and `go test ./...` pass.
- **Not validated:** key storage providers other than the Microsoft Software
  KSP; a real Windows service opening the key with its service SID (the smoke
  tests open the keys as an administrator); a medium-integrity token on
  Windows Server; Linux beyond the platform-independent packages.

## Upgrading

See [Upgrading from v0.2.0](https://github.com/keppin-oss/machine-identity/blob/v0.3.0/docs/README.md#upgrading-from-v020).
