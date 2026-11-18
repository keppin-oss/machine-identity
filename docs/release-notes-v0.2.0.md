# Keppin Machine Identity v0.2.0

v0.2.0 makes the `keystore` error contract honest about what the Windows key
storage provider can tell a caller, and moves to `github.com/keppin-oss/cng`
v0.3.1.

## Behavior changes

- **`keystore.ErrKeyNotFound` now means "not found or not accessible".** The
  Microsoft Software KSP can report a key that exists but whose DACL does not
  grant the caller as not found. `Open`, `Delete` and, when the failure carries
  the shared not-found error, `LoadOrCreate` return `ErrKeyNotFound` in both
  cases. It is not proof of absence and must never, by itself, trigger a reset,
  regeneration or overwrite of the identity key. The error text changed to
  `keystore: machine identity key not found or not accessible`.
- **The native cause is preserved.** The returned error wraps both
  `keystore.ErrKeyNotFound` and the original error from the CNG layer, so
  `errors.Is` matches `keystore.ErrKeyNotFound` and `windowscng.ErrKeyNotFound`,
  and `errors.As` with `*windowscng.NCryptError` exposes the native status.
  **A direct comparison `err == keystore.ErrKeyNotFound` no longer holds**, and
  `errors.Unwrap` returns nil for this error.
- **`Delete` is no longer described as idempotent.** `ErrKeyNotFound` from
  `Delete` means only that the call deleted nothing; it is not proof of
  successful cleanup.
- Errors without the not-found sentinel (permission, corruption, incompatible
  key, unexpected failure) are still passed through unchanged and are never
  converted into not-found.

No exported identifier was added or removed.

## Dependency

- `github.com/keppin-oss/cng` moves from v0.1.1 to **v0.3.1**. Go stays at
  1.26.8. See the cng release notes for its full changes. Among them, it
  rejects security descriptors reported with zero bytes and export-policy
  values whose size is not four bytes (fail closed), and documents its DACL
  check as requiring the expected principals and rejecting specific disallowed
  ones, not as an exclusive allow-list.

## Tests

- The native smoke tests (`keystore_smoke` build tag) were rewritten. They use
  a per-run test key name with a 128-bit random suffix and never touch the
  production key name. Elevation is read from the process token before any
  CNG call; `KEPPIN_KEYSTORE_SMOKE_REQUIRED=1` turns a non-elevated run into a
  failure. A pre-check refuses to adopt a key that already opens under the test
  name, and cleanup and Close errors are reported.
- Tests with the default build tags perform no operations on real CNG keys.

## Documentation

- `docs/README.md` updates the error, delete, lifecycle, security and
  troubleshooting sections, adds requirements, a native smoke test section and
  [Upgrading from v0.1.x](README.md#upgrading-from-v01x).

## Upgrading

See [Upgrading from v0.1.x](README.md#upgrading-from-v01x). In short: replace
`err == keystore.ErrKeyNotFound` with `errors.Is(err, keystore.ErrKeyNotFound)`,
and do not treat `ErrKeyNotFound` alone as permission to create a new identity
or as successful cleanup.

## Validation

- **Validated live:** the two native smoke tests passed on Windows 11 25H2
  (10.0.26200), AMD64, Microsoft Software KSP, from an elevated administrator
  process, with Go 1.26.8 and `github.com/keppin-oss/cng` v0.3.1. The run was
  performed on the source tree before publication; the published tree differs
  only in the module path, comment wording, documentation, and two default-tag
  tests (no production code change).
- **Default-tag checks:** `go build`, `go vet` (Windows and Linux) and
  `go test ./...` pass.
- **Not validated:** other Windows builds or key storage providers, a
  non-privileged caller facing an existing inaccessible key, concurrent use,
  failure paths (collision, denied privilege, rollback), and Linux beyond
  build/vet of the platform-independent packages. There is no remote CI.
