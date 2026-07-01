# Changelog

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
