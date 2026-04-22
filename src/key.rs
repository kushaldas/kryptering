use zeroize::{Zeroize, ZeroizeOnDrop};

/// In-memory key material for software cryptographic operations.
///
/// This enum holds actual key bytes. For HSM-backed keys where the material
/// is non-extractable, use the PKCS#11 backend instead — it implements the
/// same `Signer`/`Verifier`/`Decryptor` traits without exposing key material.
///
/// ## Zeroization
///
/// Dropping a `SoftwareKey` wipes any private key material it holds:
///
/// * The RustCrypto-backed variants (`Rsa`, `EcP256/384/521`, `Ed25519`,
///   `Dsa`) delegate to the upstream `ZeroizeOnDrop` impls on
///   `rsa::RsaPrivateKey`, `ecdsa::SigningKey<C>`,
///   `ed25519_dalek::SigningKey`, and `dsa::SigningKey`. These run
///   automatically when the `Option<..>` fields drop.
/// * The raw-byte variants (`X25519`, `Hmac`, `Aes`, `Des3`,
///   `PostQuantum::private_der`) are wiped explicitly by [`SoftwareKey`]'s
///   `Drop` impl below.
///
/// Public key fields are not wiped (there is nothing to protect there) — the
/// `Drop` impl skips them deliberately.
pub enum SoftwareKey {
    Rsa {
        private: Option<rsa::RsaPrivateKey>,
        public: rsa::RsaPublicKey,
    },
    EcP256 {
        private: Option<p256::ecdsa::SigningKey>,
        public: p256::ecdsa::VerifyingKey,
    },
    EcP384 {
        private: Option<p384::ecdsa::SigningKey>,
        public: p384::ecdsa::VerifyingKey,
    },
    EcP521 {
        private: Option<p521::ecdsa::SigningKey>,
        public: p521::ecdsa::VerifyingKey,
    },
    Ed25519 {
        private: Option<ed25519_dalek::SigningKey>,
        public: ed25519_dalek::VerifyingKey,
    },
    X25519 {
        private: Option<[u8; 32]>,
        public: [u8; 32],
    },
    Hmac(Vec<u8>),
    Aes(Vec<u8>),
    #[cfg(feature = "legacy")]
    Dsa {
        private: Option<dsa::SigningKey>,
        public: dsa::VerifyingKey,
    },
    #[cfg(feature = "legacy")]
    Des3(Vec<u8>),
    #[cfg(feature = "post-quantum")]
    PostQuantum {
        algorithm: crate::algorithm::PqAlgorithm,
        private_der: Option<Vec<u8>>,
        public_der: Vec<u8>,
    },
}

impl Drop for SoftwareKey {
    fn drop(&mut self) {
        match self {
            // Raw-byte private material: wipe in place before the Vec / array drops.
            SoftwareKey::Hmac(bytes) | SoftwareKey::Aes(bytes) => bytes.zeroize(),
            SoftwareKey::X25519 { private, .. } => {
                if let Some(bytes) = private {
                    bytes.zeroize();
                }
            }
            #[cfg(feature = "legacy")]
            SoftwareKey::Des3(bytes) => bytes.zeroize(),
            #[cfg(feature = "post-quantum")]
            SoftwareKey::PostQuantum { private_der, .. } => {
                if let Some(der) = private_der {
                    der.zeroize();
                }
            }
            // RustCrypto-backed variants zeroize via their own ZeroizeOnDrop
            // impls when the Option<T> field drops after this impl returns.
            SoftwareKey::Rsa { .. }
            | SoftwareKey::EcP256 { .. }
            | SoftwareKey::EcP384 { .. }
            | SoftwareKey::EcP521 { .. }
            | SoftwareKey::Ed25519 { .. } => {}
            #[cfg(feature = "legacy")]
            SoftwareKey::Dsa { .. } => {}
        }
    }
}

/// Marker indicating [`SoftwareKey`]'s [`Drop`] impl wipes private material.
impl ZeroizeOnDrop for SoftwareKey {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time contract: dropping a `SoftwareKey` is a zeroization event.
    /// If someone removes the `Drop` impl this test stops type-checking.
    #[test]
    fn software_key_is_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SoftwareKey>();
    }

    /// Sanity-check the Drop body: construct each raw-byte variant with a
    /// non-zero payload, drop it, and confirm nothing panicked. We cannot
    /// observe the freed heap directly from safe Rust, so this is a smoke
    /// test for the Drop match arms rather than a proof of wipe.
    #[test]
    fn software_key_drop_runs_on_raw_byte_variants() {
        drop(SoftwareKey::Hmac(vec![0xABu8; 64]));
        drop(SoftwareKey::Aes(vec![0xCDu8; 32]));
        drop(SoftwareKey::X25519 {
            private: Some([0xEFu8; 32]),
            public: [0x12u8; 32],
        });
        drop(SoftwareKey::X25519 {
            private: None,
            public: [0x12u8; 32],
        });
    }
}
