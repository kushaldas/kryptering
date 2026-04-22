# kryptering

Cryptographic operations library for Rust with software (RustCrypto) and HSM (PKCS#11) backends.

## Features

- **Trait-based key abstraction** -- `Signer`, `Verifier`, `Decryptor`, `Encryptor`, `KeyWrapper`, `KeyAgreement` traits that work with both software keys and HSM-backed keys
- **Software backend** -- in-memory keys using the RustCrypto ecosystem
- **PKCS#11 backend** -- HSM-backed keys via the `cryptoki` crate (SoftHSM2, Kryoptic, hardware HSMs)
- **Post-quantum** -- ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) support behind feature flag

## Supported algorithms

| Category | Algorithms |
|---|---|
| **Signatures** | RSA PKCS#1v1.5, RSA-PSS, ECDSA (P-256/P-384/P-521), Ed25519, HMAC, DSA (legacy), ML-DSA, SLH-DSA |
| **Ciphers** | AES-GCM, AES-CBC (hazmat, unauthenticated — `kryptering::hazmat::aes_cbc`), 3DES-CBC (legacy) |
| **Key wrap** | AES-KW (RFC 3394), 3DES-KW (legacy) |
| **Key transport** | RSA-OAEP, RSA PKCS#1v1.5 (legacy) |
| **Key agreement** | ECDH (P-256/P-384/P-521), X25519, DH (X9.42, hazmat — `kryptering::hazmat::dh`) |
| **KDFs** | ConcatKDF, PBKDF2, HKDF |
| **Digests** | SHA-1, SHA-2 (224/256/384/512), SHA-3, MD5 (legacy), RIPEMD-160 (legacy) |

## Feature flags

| Feature | Default | Description |
|---|---|---|
| `pkcs11` | Yes | PKCS#11 HSM support via `cryptoki` |
| `legacy` | No | MD5, RIPEMD-160, 3DES, DSA |
| `post-quantum` | No | ML-DSA (FIPS 204), SLH-DSA (FIPS 205) |

## Usage

```rust
use kryptering::{SoftwareKey, SoftwareSigner, SignatureAlgorithm, HashAlgorithm, Signer};

// Software signing
let key = SoftwareKey::Hmac(b"my-secret-key".to_vec());
let signer = SoftwareSigner::new(
    SignatureAlgorithm::Hmac(HashAlgorithm::Sha256),
    key,
).unwrap();
let signature = signer.sign(b"data to sign").unwrap();
```

```rust
// HSM signing (with pkcs11 feature)
use kryptering::pkcs11::{Pkcs11Provider, Pkcs11Signer};
use std::path::Path;

let provider = Pkcs11Provider::new(Path::new("/usr/lib/softhsm/libsofthsm2.so")).unwrap();
let session = provider.open_session("1234").unwrap();
let signer = Pkcs11Signer::new(
    &session,
    "my-key-label",
    kryptering::SignatureAlgorithm::RsaPkcs1v15(kryptering::HashAlgorithm::Sha256),
).unwrap();
let signature = signer.sign(b"data to sign").unwrap();
```

## License

BSD-2-Clause
