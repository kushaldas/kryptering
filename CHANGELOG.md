# Changelog

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
