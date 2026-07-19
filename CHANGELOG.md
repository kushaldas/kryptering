# Changelog

## 0.5.0 - [unreleased]

### Added

- Compile-time RustCrypto and AWS-LC document providers, with independent
  ring/AWS-LC TLS provider selection.
- Provider identity, initialization, FIPS status, parameterized capability
  reporting, attested TLS configuration, opaque `SoftwareKey`, and structured
  initialization/unsupported-algorithm errors.
- Provider implementations for RNG, digest/HMAC, signatures, AES-CBC/GCM,
  AES-KW, RSA transport, ECDH/X25519, KDFs, and PKCS#12 primitives.
- A provider-wide known-answer/negative baseline, an enumerable capability
  registry, and active AWS-LC document/TLS FIPS attestation on x86_64 and
  aarch64 CI runners.

- ML-KEM (FIPS 203) support behind the `post-quantum` feature:
  `generate_ml_kem` for ML-KEM-512/768/1024 key generation, and
  `SoftwareEncapsulator` / `SoftwareDecapsulator` implementing the new
  `Encapsulator` / `Decapsulator` traits. Keys follow the ML-DSA
  conventions: SPKI DER public key, 64-byte FIPS 203 seed (`d || z`) as
  the stored private key with PKCS#8 DER (LAMPS seed-only form) also
  accepted on load. Encapsulation draws its FIPS 203 message `m` via
  `getrandom::fill` so OS-RNG failure surfaces as `Error::Crypto`
  instead of a panic (ADR 0001). Shared secrets are returned as
  `zeroize::Zeroizing<Vec<u8>>` so they are wiped on drop (DRR03-L-02).
  NIST ACVP known-answer vectors for key generation (all variants) and
  encapsulation (ML-KEM-768) pass byte-for-byte.

### Changed

- **Breaking:** digest and streaming digest creation are fallible, and software
  signing/key-transport APIs accept opaque provider keys.
- **Breaking:** finite-field DH agreement now accepts an opaque `SoftwareKey`;
  the private exponent is no longer exported to downstream callers.
- Exactly one document provider is required; `--all-features` is intentionally
  invalid. FIPS builds require explicit initialization.
- **Breaking:** `PqAlgorithm` gains an `MlKem` variant (affects
  downstream exhaustive matches).
- MSRV raised from 1.83 to 1.88 for the coordinated provider release and its
  resolved dependency graph.
- FIPS mode currently selects AWS-LC exclusively.

### Security

- PKCS#11 signing, verification, key transport, key wrap, and cipher
  operations now enforce the FIPS algorithm allowlist via
  `backend::require_fips_approved` before reaching the token. Previously the
  HSM path only checked process initialization, so SHA-1 RSA, Ed25519, and
  SHA-1 OAEP could proceed in `fips` builds.
- Bound PBKDF2 (`PBKDF2_MAX_ITERATIONS = 100_000_000`) and the PKCS#12 KDF
  (`iterations <= 100_000_000`) iteration counts, and capped
  `random_bytes` allocations at 1 MiB (`RANDOM_BYTES_MAX_LEN`), closing
  CPU/memory denial-of-service vectors from attacker-controlled parameters.
- The AWS-LC provider's streaming digest now wraps
  `aws_lc_rs::digest::Context` so input is hashed incrementally in constant
  memory, matching the RustCrypto provider; the previous `BufferedDigest`
  accumulated the entire input before hashing.
- The AWS-LC `SoftwareVerifier` now validates that the key family matches the
  signature algorithm at construction, matching the RustCrypto path and
  failing fast instead of relying on SPKI import to surface mismatches.
- The alternate-provider ECDSA/DSA DER signature parser now enforces DER
  canonicality (minimal length and integer encodings per X.690 §8.1.3.3 /
  §8.3.2), rejecting non-minimal encodings that yield a second, distinct
  byte string for the same r||s — a signature-malleability surface for
  consensus callers.
- The PKCS#12 KDF (`pkcs12::derive`, `decrypt_pbe_sha1_3des`) and the PBES2
  helper (`decrypt_pbes2_aes256cbc`) now take `&str` passwords and encode
  them as RFC 7292 Appendix B.1 BMPString (UTF-16BE + trailing NUL) before
  hashing; the previous `&[u8]` API hashed raw bytes and produced keys
  incompatible with standard `.p12` files.
- The AWS-LC RSA verification path's minimum modulus size is raised from
  1024 to 2048 bits to match the import path's `RSA_PKCS1_2048_8192_*`
  floor, removing an inconsistent threshold between the two code paths.

## 0.4.1 - [2026-07-01]

### Changed

- Bump the `cipher 0.5` wave to current stable finals: `aes 0.9`,
  `aes-gcm 0.11`, `aes-kw 0.3`, `cbc 0.2`, and `des 0.9` (legacy). Migrate
  the AES-CBC, AES-GCM, AES-KW, and 3DES-CBC/KW code to the new
  `BlockModeEncrypt`/`BlockModeDecrypt` traits, `AesKw`/`wrap_key`/`unwrap_key`
  API, and non-deprecated nonce construction. RFC 3394 / NIST SP 800-38F
  key-wrap known-answer vectors still pass byte-for-byte.
- Refresh compatible dependency versions in `Cargo.lock`.

### Security

- Update `crypto-bigint` `0.7.3 -> 0.7.5`, clearing a `cargo audit` warning
  for the yanked `0.7.3` release.

### Notes

- Pin `generic-array` to `0.14.7` (the last release without the
  `from_slice` deprecation) to keep `clippy -D warnings` clean while the
  `digest 0.11` wave remains blocked on stable `rsa 0.10` / `ecdsa 0.17`.
- Keep `rsa` on `0.9.10`; the `digest 0.11` / `signature 3` / `rand_core 0.10`
  wave has no stable finals yet (RSA, ECDSA, the P-curves, and the dalek
  crates are pre-release only). See `docs/ecosystem.md`.

## 0.4.0 - [2026-06-27]

### Security

- Reject ambiguous PKCS#11 token and object selection instead of silently using
  the first match.
- Add explicit PKCS#11 slot, token, and object-id selection helpers.
- Reject high-level PKCS#11 AES-CBC use; AES-GCM remains supported.
- Reject invalid finite-field DH subgroup order `q = 0`.
- Reject invalid HKDF and ConcatKDF output lengths before allocation or
  derivation.
- Reject 3DES-CBC IV-only ciphertext.

### Changed

- Refresh compatible dependency versions in `Cargo.lock`.
- Keep `rsa` on `0.9.10`; no stable patched upgrade is available for the tracked RustSec advisory.
