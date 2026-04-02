/// In-memory key material for software cryptographic operations.
///
/// This enum holds actual key bytes. For HSM-backed keys where the material
/// is non-extractable, use the PKCS#11 backend instead — it implements the
/// same `Signer`/`Verifier`/`Decryptor` traits without exposing key material.
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
