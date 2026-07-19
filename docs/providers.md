# Cryptographic providers

Kryptering 0.5 selects document cryptography and network TLS independently at
compile time. It never falls back from one provider to another.

## Selection contract

| Domain | Features | Rule |
|---|---|---|
| Document crypto | `rustcrypto`, `aws-lc` | exactly one |
| Network TLS | `tls-ring`, `tls-aws-lc` | at most one |
| Compliance | `fips` | incompatible with `rustcrypto` and `tls-ring` |
| HSM | `pkcs11` | orthogonal to the software provider |

AWS-LC is initially gated to Linux x86_64/aarch64.
`--all-features` is an expected compile failure.

## Non-FIPS capability registry

This table describes provider operations implemented and exercised by the
backend test matrix. A parameter combination outside the row returns
`UnsupportedAlgorithm` before key material is parsed or used.

| Operation | RustCrypto | AWS-LC |
|---|---|---|
| RNG | yes | yes |
| SHA-2 / HMAC-SHA-2 | yes | yes |
| RSA PKCS#1/PSS signatures | broad legacy + modern set | SHA-256/384/512 signing |
| ECDSA | broad curve/hash set | stable AWS-LC curve/hash mappings |
| Ed25519 | yes | yes |
| AES-CBC/GCM | 128/192/256 | 128/192/256 |
| AES-KW | 128/192/256 | 128/256 |
| RSA-OAEP | SHA-1/224/256/384/512 with independent MGF1; MD5/RIPEMD160 with `legacy` | SHA-1/256/384/512 when OAEP and MGF hashes match |
| ECDH | P-256/P-384/P-521 | P-256/P-384/P-521 |
| X25519 | yes | yes |
| finite-field X9.42 DH | neutral hazmat parameters | unsupported |
| HKDF/PBKDF2/ConcatKDF | yes | SHA-1/SHA-2 family where the AWS API supports it |
| DSA signatures | with `legacy` | unsupported |
| 3DES-CBC / 3DES key wrap | with `legacy` | unsupported |
| ML-DSA / SLH-DSA | feature-dependent | unsupported by stable AWS-LC APIs |

The authoritative queries are `supports(Operation)` for a single fully
parameterized operation and `capabilities()` for the complete tested registry.
The latter is generated from the same parameter registry used by capability
tests, rather than from a separately maintained list.

## Initialization and FIPS

Non-FIPS builds initialize ergonomically on first use. In a `fips` build,
`initialize_backend()` must succeed first; cryptographic operations and TLS
configuration otherwise return `BackendNotInitialized`.

The `fips` feature selects AWS-LC for document cryptography. AWS-LC
initialization calls `try_fips_mode()`; when TLS is enabled, `tls-aws-lc` is
the only permitted TLS provider and must independently report active FIPS mode.

Stable AWS-LC APIs require RSA public keys of at least 1024 bits. They also do
not expose every non-default RSA-PSS salt-length combination. These cases are
reported as `UnsupportedAlgorithm` before signature verification uses the key.

FIPS capability reporting excludes unavailable or unapproved operations.
Building with the `fips` feature does not certify the consuming binary or its
deployment. AWS-LC FIPS builds additionally need the native toolchain required
by aws-lc-rs.

## Key migration

Provider-specific public key enums are replaced by the cloneable,
`Arc`-backed `SoftwareKey`. Import PKCS#8 private keys, SPKI public keys, raw
symmetric bytes, X25519 components, neutral finite-field DH parameters, or
post-quantum DER through its explicit
constructors. Use `algorithm()`, `has_private_key()`, and
`public_component()` for metadata; private export is explicit and returns a
zeroizing buffer. `Debug` never prints secret material.

Digest one-shot and streaming construction are fallible in 0.5 because
initialization or provider capability checks can fail.
