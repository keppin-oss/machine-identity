# Keppin Machine Identity

`github.com/keppin-oss/machine-identity` is the authoritative Go module for the
Keppin Windows machine identity: a single persisted, non-exportable,
machine-scoped ECDSA P-256 signing key, together with the canonical public-key
reference and the domain-separated proof-of-possession primitive used to prove a
machine holds that identity.

## What it does

The module owns the four pieces every integration needs to name, locate,
describe, and prove a machine identity:

- the persisted **identity key name** (a compatibility contract);
- the **key custody** for that key (create/open/delete on Windows);
- the **canonical public-key reference** (uncompressed P-256 point and its
  SHA-256 fingerprint);
- the **proof-of-possession** primitive (domain-separated challenge signing and
  verification).

## Packages

| Package | Responsibility | Platform |
| --- | --- | --- |
| `identity` | The persisted identity key name contract. | Any |
| `identityproof` | Domain-separated proof-of-possession signing and verification. | Any |
| `publickey` | Canonical public-key encoding, parsing, and fingerprinting. | Any |
| `keystore` | Windows CNG/KSP key custody (create/open/delete). | Windows only |

## Install

```sh
go get github.com/keppin-oss/machine-identity
```

```go
import (
    "github.com/keppin-oss/machine-identity/identity"
    "github.com/keppin-oss/machine-identity/identityproof"
    "github.com/keppin-oss/machine-identity/keystore"
    "github.com/keppin-oss/machine-identity/publickey"
)
```

## Quick start

The shortest correct machine-identity flow on Windows (elevated for first
creation):

```go
import (
    "crypto/ecdsa"
    "log"

    "github.com/keppin-oss/cng/windowscng"
    "github.com/keppin-oss/machine-identity/identityproof"
    "github.com/keppin-oss/machine-identity/keystore"
    "github.com/keppin-oss/machine-identity/publickey"
)

signer, err := keystore.LoadOrCreate()
if err != nil {
    log.Fatal(err)
}
defer signer.(windowscng.Signer).Close()

encoded, err := publickey.Encode(signer.Public().(*ecdsa.PublicKey))
if err != nil {
    log.Fatal(err)
}
fingerprint, err := publickey.Fingerprint(signer.Public().(*ecdsa.PublicKey))
if err != nil {
    log.Fatal(err)
}

challenge := []byte("server-fresh-challenge")
signature, err := identityproof.Sign(signer, challenge)
if err != nil {
    log.Fatal(err)
}
if err := identityproof.Verify(signer.Public(), challenge, signature); err != nil {
    log.Fatal(err)
}

_ = encoded
_ = fingerprint
```

See `examples/` for complete, compilable programs.

## Platform boundary

- `keystore` is **Windows-only** (it uses the Windows CNG/KSP). Creating or
  deleting the persisted key requires an elevated (Administrator) process.
- `identity`, `identityproof`, and `publickey` are **platform-independent**.

## Documentation

The full technical specification — contracts, key custody lifecycle, encoding and
fingerprint rules, proof-of-possession semantics, error handling, and security
invariants — lives in [docs/README.md](docs/README.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
