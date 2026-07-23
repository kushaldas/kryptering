use std::sync::Arc;

use p521::elliptic_curve::sec1::ToEncodedPoint;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::backend::{require_supported, KeyAlgorithm, Operation};
use crate::error::{Error, Result};
use crate::parameters::DhParameters;

/// Opaque, shared software-key handle.
///
/// Cloning this value clones an [`Arc`], not private material. Provider
/// implementation types are intentionally absent from the public API. Secret
/// material is zeroized when the final handle is dropped; dropping one clone
/// does not invalidate or zeroize the allocation still shared by other clones.
#[derive(Clone)]
pub struct SoftwareKey(Arc<RustCryptoKey>);

impl std::fmt::Debug for SoftwareKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SoftwareKey")
            .field("algorithm", &self.algorithm())
            .field("has_private_key", &self.has_private_key())
            .finish_non_exhaustive()
    }
}

impl SoftwareKey {
    pub(crate) fn inner(&self) -> &RustCryptoKey {
        &self.0
    }

    pub(crate) fn from_rustcrypto(key: RustCryptoKey) -> Self {
        Self(Arc::new(key))
    }

    /// Import a private key encoded as PKCS#8 DER.
    pub fn from_pkcs8_der(algorithm: KeyAlgorithm, der: &[u8]) -> Result<Self> {
        require_supported(Operation::KeyImport(algorithm))?;
        let der = Zeroizing::new(der.to_vec());
        let key = match algorithm {
            KeyAlgorithm::Rsa => {
                use rsa::pkcs8::DecodePrivateKey;
                let private = rsa::RsaPrivateKey::from_pkcs8_der(&der)
                    .map_err(|e| Error::Key(format!("RSA PKCS#8 import failed: {e}")))?;
                let public = private.to_public_key();
                RustCryptoKey::Rsa {
                    private: Some(private),
                    public,
                }
            }
            KeyAlgorithm::Ec(crate::algorithm::EcCurve::P256) => {
                use p256::pkcs8::DecodePrivateKey;
                let private = p256::ecdsa::SigningKey::from_pkcs8_der(&der)
                    .map_err(|e| Error::Key(format!("P-256 PKCS#8 import failed: {e}")))?;
                let public = *private.verifying_key();
                RustCryptoKey::EcP256 {
                    private: Some(private),
                    public,
                }
            }
            KeyAlgorithm::Ec(crate::algorithm::EcCurve::P384) => {
                use p384::pkcs8::DecodePrivateKey;
                let private = p384::ecdsa::SigningKey::from_pkcs8_der(&der)
                    .map_err(|e| Error::Key(format!("P-384 PKCS#8 import failed: {e}")))?;
                let public = *private.verifying_key();
                RustCryptoKey::EcP384 {
                    private: Some(private),
                    public,
                }
            }
            KeyAlgorithm::Ec(crate::algorithm::EcCurve::P521) => {
                use p521::pkcs8::DecodePrivateKey;
                let secret = p521::SecretKey::from_pkcs8_der(&der)
                    .map_err(|e| Error::Key(format!("P-521 PKCS#8 import failed: {e}")))?;
                let private = p521::ecdsa::SigningKey::from_slice(secret.to_bytes().as_slice())
                    .map_err(|e| Error::Key(format!("P-521 signing key import failed: {e}")))?;
                let public = p521::ecdsa::VerifyingKey::from(&private);
                RustCryptoKey::EcP521 {
                    private: Some(private),
                    public,
                }
            }
            KeyAlgorithm::Ed25519 => {
                use ed25519_dalek::pkcs8::DecodePrivateKey;
                let private = ed25519_dalek::SigningKey::from_pkcs8_der(&der)
                    .map_err(|e| Error::Key(format!("Ed25519 PKCS#8 import failed: {e}")))?;
                let public = private.verifying_key();
                RustCryptoKey::Ed25519 {
                    private: Some(private),
                    public,
                }
            }
            #[cfg(feature = "legacy")]
            KeyAlgorithm::Dsa => {
                use dsa::pkcs8::DecodePrivateKey;
                let private = dsa::SigningKey::from_pkcs8_der(&der)
                    .map_err(|e| Error::Key(format!("DSA PKCS#8 import failed: {e}")))?;
                let public = private.verifying_key().clone();
                RustCryptoKey::Dsa {
                    private: Some(private),
                    public,
                }
            }
            _ => {
                return Err(Error::unsupported(
                    Operation::KeyImport(algorithm),
                    "PKCS#8 for requested key family",
                ))
            }
        };
        Ok(Self::from_rustcrypto(key))
    }

    /// Import a public key encoded as SubjectPublicKeyInfo DER.
    pub fn from_spki_der(algorithm: KeyAlgorithm, der: &[u8]) -> Result<Self> {
        require_supported(Operation::KeyImport(algorithm))?;
        let key = match algorithm {
            KeyAlgorithm::Rsa => {
                use rsa::pkcs8::DecodePublicKey;
                let public = rsa::RsaPublicKey::from_public_key_der(der)
                    .map_err(|e| Error::Key(format!("RSA SPKI import failed: {e}")))?;
                RustCryptoKey::Rsa {
                    private: None,
                    public,
                }
            }
            KeyAlgorithm::Ec(crate::algorithm::EcCurve::P256) => {
                use p256::pkcs8::DecodePublicKey;
                let public = p256::ecdsa::VerifyingKey::from_public_key_der(der)
                    .map_err(|e| Error::Key(format!("P-256 SPKI import failed: {e}")))?;
                RustCryptoKey::EcP256 {
                    private: None,
                    public,
                }
            }
            KeyAlgorithm::Ec(crate::algorithm::EcCurve::P384) => {
                use p384::pkcs8::DecodePublicKey;
                let public = p384::ecdsa::VerifyingKey::from_public_key_der(der)
                    .map_err(|e| Error::Key(format!("P-384 SPKI import failed: {e}")))?;
                RustCryptoKey::EcP384 {
                    private: None,
                    public,
                }
            }
            KeyAlgorithm::Ec(crate::algorithm::EcCurve::P521) => {
                use p521::pkcs8::DecodePublicKey;
                let public = p521::PublicKey::from_public_key_der(der)
                    .map_err(|e| Error::Key(format!("P-521 SPKI import failed: {e}")))?;
                let public =
                    p521::ecdsa::VerifyingKey::from_encoded_point(&public.to_encoded_point(false))
                        .map_err(|e| {
                            Error::Key(format!("P-521 verifying key import failed: {e}"))
                        })?;
                RustCryptoKey::EcP521 {
                    private: None,
                    public,
                }
            }
            KeyAlgorithm::Ed25519 => {
                use ed25519_dalek::pkcs8::DecodePublicKey;
                let public = ed25519_dalek::VerifyingKey::from_public_key_der(der)
                    .map_err(|e| Error::Key(format!("Ed25519 SPKI import failed: {e}")))?;
                RustCryptoKey::Ed25519 {
                    private: None,
                    public,
                }
            }
            #[cfg(feature = "legacy")]
            KeyAlgorithm::Dsa => {
                use dsa::pkcs8::DecodePublicKey;
                let public = dsa::VerifyingKey::from_public_key_der(der)
                    .map_err(|e| Error::Key(format!("DSA SPKI import failed: {e}")))?;
                RustCryptoKey::Dsa {
                    private: None,
                    public,
                }
            }
            _ => {
                return Err(Error::unsupported(
                    Operation::KeyImport(algorithm),
                    "SPKI for requested key family",
                ))
            }
        };
        Ok(Self::from_rustcrypto(key))
    }

    /// Import raw symmetric key bytes.
    pub fn from_symmetric_bytes(algorithm: KeyAlgorithm, bytes: &[u8]) -> Result<Self> {
        require_supported(Operation::KeyImport(algorithm))?;
        if bytes.is_empty() {
            return Err(Error::Key("symmetric key must not be empty".into()));
        }
        let key = match algorithm {
            KeyAlgorithm::Hmac => RustCryptoKey::Hmac(bytes.to_vec()),
            KeyAlgorithm::Aes if matches!(bytes.len(), 16 | 24 | 32) => {
                RustCryptoKey::Aes(bytes.to_vec())
            }
            KeyAlgorithm::Aes => {
                return Err(Error::Key("AES keys must be 16, 24, or 32 bytes".into()))
            }
            #[cfg(feature = "legacy")]
            KeyAlgorithm::TripleDes if bytes.len() == 24 => RustCryptoKey::Des3(bytes.to_vec()),
            #[cfg(feature = "legacy")]
            KeyAlgorithm::TripleDes => return Err(Error::Key("3DES keys must be 24 bytes".into())),
            _ => {
                return Err(Error::unsupported(
                    Operation::KeyImport(algorithm),
                    "raw symmetric bytes for requested key family",
                ))
            }
        };
        Ok(Self::from_rustcrypto(key))
    }

    /// Import raw X25519 key components.
    pub fn from_x25519(private: Option<&[u8]>, public: &[u8]) -> Result<Self> {
        require_supported(Operation::KeyImport(KeyAlgorithm::X25519))?;
        let public: [u8; 32] = public
            .try_into()
            .map_err(|_| Error::Key("X25519 public key must be 32 bytes".into()))?;
        let private = private
            .map(|value| {
                value
                    .try_into()
                    .map_err(|_| Error::Key("X25519 private key must be 32 bytes".into()))
            })
            .transpose()?;
        Ok(Self::from_rustcrypto(RustCryptoKey::X25519 {
            private,
            public,
        }))
    }

    /// Import provider-neutral finite-field Diffie-Hellman components.
    ///
    /// All integers use unsigned big-endian encoding. This constructor only
    /// imports and protects the key material; agreement still returns
    /// `UnsupportedAlgorithm` when the selected provider has no safe
    /// finite-field DH implementation.
    pub fn from_dh_parameters(
        modulus: &[u8],
        generator: &[u8],
        subgroup_order: Option<&[u8]>,
        private: Option<&[u8]>,
        public: &[u8],
    ) -> Result<Self> {
        require_supported(Operation::KeyImport(KeyAlgorithm::Dh))?;
        if modulus.is_empty() || generator.is_empty() || public.is_empty() {
            return Err(Error::Key(
                "DH modulus, generator, and public key must not be empty".into(),
            ));
        }
        if subgroup_order.is_some_and(<[u8]>::is_empty) {
            return Err(Error::Key("DH subgroup order must not be empty".into()));
        }
        if private.is_some_and(<[u8]>::is_empty) {
            return Err(Error::Key("DH private exponent must not be empty".into()));
        }
        Ok(Self::from_rustcrypto(RustCryptoKey::Dh {
            private: private.map(<[u8]>::to_vec),
            parameters: DhParameters::new(modulus, generator, subgroup_order, public),
        }))
    }

    /// Import provider-neutral post-quantum key encodings.
    ///
    /// `private_der` is a PKCS#8 encoding when present and `public_der` is an
    /// SPKI encoding. The selected provider validates support before any key
    /// material is retained.
    #[cfg(feature = "post-quantum")]
    pub fn from_post_quantum_der(
        algorithm: crate::algorithm::PqAlgorithm,
        private_der: Option<&[u8]>,
        public_der: &[u8],
    ) -> Result<Self> {
        let key_algorithm = KeyAlgorithm::PostQuantum(algorithm);
        require_supported(Operation::KeyImport(key_algorithm))?;
        if public_der.is_empty() {
            return Err(Error::Key("post-quantum SPKI must not be empty".into()));
        }
        Ok(Self::from_rustcrypto(RustCryptoKey::PostQuantum {
            algorithm,
            private_der: private_der.map(|value| value.to_vec()),
            public_der: public_der.to_vec(),
        }))
    }

    /// Import an aggregate raw composite ML-DSA key.
    ///
    /// The public key is `ML-DSA public || traditional public`. When present,
    /// the private key is `32-byte ML-DSA seed || traditional private`.
    /// Component encodings and lengths are fixed by `variant`; DER encodings
    /// are not accepted. The imported public key is checked against the
    /// private key.
    ///
    /// Importers are responsible for the draft's key-origin rule: neither
    /// component may have been used independently or in another composite
    /// combination.
    #[cfg(feature = "post-quantum")]
    pub fn from_composite_ml_dsa(
        variant: crate::algorithm::CompositeMlDsaVariant,
        private: Option<&[u8]>,
        public: &[u8],
    ) -> Result<Self> {
        let key_algorithm = KeyAlgorithm::CompositeMlDsa(variant);
        require_supported(Operation::KeyImport(key_algorithm))?;
        crate::software::composite::validate_import(variant, private, public)?;
        Ok(Self::from_rustcrypto(RustCryptoKey::CompositeMlDsa {
            variant,
            private: private.map(<[u8]>::to_vec),
            public: public.to_vec(),
        }))
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        match self.inner() {
            RustCryptoKey::Rsa { .. } => KeyAlgorithm::Rsa,
            RustCryptoKey::EcP256 { .. } => KeyAlgorithm::Ec(crate::algorithm::EcCurve::P256),
            RustCryptoKey::EcP384 { .. } => KeyAlgorithm::Ec(crate::algorithm::EcCurve::P384),
            RustCryptoKey::EcP521 { .. } => KeyAlgorithm::Ec(crate::algorithm::EcCurve::P521),
            RustCryptoKey::Ed25519 { .. } => KeyAlgorithm::Ed25519,
            RustCryptoKey::X25519 { .. } => KeyAlgorithm::X25519,
            RustCryptoKey::Dh { .. } => KeyAlgorithm::Dh,
            RustCryptoKey::Hmac(_) => KeyAlgorithm::Hmac,
            RustCryptoKey::Aes(_) => KeyAlgorithm::Aes,
            #[cfg(feature = "legacy")]
            RustCryptoKey::Dsa { .. } => KeyAlgorithm::Dsa,
            #[cfg(feature = "legacy")]
            RustCryptoKey::Des3(_) => KeyAlgorithm::TripleDes,
            #[cfg(feature = "post-quantum")]
            RustCryptoKey::PostQuantum { algorithm, .. } => KeyAlgorithm::PostQuantum(*algorithm),
            #[cfg(feature = "post-quantum")]
            RustCryptoKey::CompositeMlDsa { variant, .. } => KeyAlgorithm::CompositeMlDsa(*variant),
        }
    }

    pub fn has_private_key(&self) -> bool {
        match self.inner() {
            RustCryptoKey::Rsa { private, .. } => private.is_some(),
            RustCryptoKey::EcP256 { private, .. } => private.is_some(),
            RustCryptoKey::EcP384 { private, .. } => private.is_some(),
            RustCryptoKey::EcP521 { private, .. } => private.is_some(),
            RustCryptoKey::Ed25519 { private, .. } => private.is_some(),
            RustCryptoKey::X25519 { private, .. } => private.is_some(),
            RustCryptoKey::Dh { private, .. } => private.is_some(),
            RustCryptoKey::Hmac(_) | RustCryptoKey::Aes(_) => true,
            #[cfg(feature = "legacy")]
            RustCryptoKey::Dsa { private, .. } => private.is_some(),
            #[cfg(feature = "legacy")]
            RustCryptoKey::Des3(_) => true,
            #[cfg(feature = "post-quantum")]
            RustCryptoKey::PostQuantum { private_der, .. } => private_der.is_some(),
            #[cfg(feature = "post-quantum")]
            RustCryptoKey::CompositeMlDsa { private, .. } => private.is_some(),
        }
    }

    /// Return a neutral public component: SPKI DER for ordinary public-key
    /// algorithms, raw X25519/DH values, or an aggregate raw composite key.
    pub fn public_component(&self) -> Result<Vec<u8>> {
        use rsa::pkcs8::EncodePublicKey;
        match self.inner() {
            RustCryptoKey::Rsa { public, .. } => public
                .to_public_key_der()
                .map(|der| der.as_bytes().to_vec())
                .map_err(|e| Error::Key(format!("RSA SPKI export failed: {e}"))),
            RustCryptoKey::EcP256 { public, .. } => public
                .to_public_key_der()
                .map(|der| der.as_bytes().to_vec())
                .map_err(|e| Error::Key(format!("P-256 SPKI export failed: {e}"))),
            RustCryptoKey::EcP384 { public, .. } => public
                .to_public_key_der()
                .map(|der| der.as_bytes().to_vec())
                .map_err(|e| Error::Key(format!("P-384 SPKI export failed: {e}"))),
            RustCryptoKey::EcP521 { public, .. } => {
                p521::PublicKey::from_sec1_bytes(public.to_encoded_point(false).as_bytes())
                    .map_err(|e| Error::Key(format!("P-521 public conversion failed: {e}")))?
                    .to_public_key_der()
                    .map(|der| der.as_bytes().to_vec())
                    .map_err(|e| Error::Key(format!("P-521 SPKI export failed: {e}")))
            }
            RustCryptoKey::Ed25519 { public, .. } => public
                .to_public_key_der()
                .map(|der| der.as_bytes().to_vec())
                .map_err(|e| Error::Key(format!("Ed25519 SPKI export failed: {e}"))),
            RustCryptoKey::X25519 { public, .. } => Ok(public.to_vec()),
            RustCryptoKey::Dh { parameters, .. } => Ok(parameters.public_key().to_vec()),
            #[cfg(feature = "legacy")]
            RustCryptoKey::Dsa { public, .. } => public
                .to_public_key_der()
                .map(|der| der.as_bytes().to_vec())
                .map_err(|e| Error::Key(format!("DSA SPKI export failed: {e}"))),
            #[cfg(feature = "post-quantum")]
            RustCryptoKey::PostQuantum { public_der, .. } => Ok(public_der.clone()),
            #[cfg(feature = "post-quantum")]
            RustCryptoKey::CompositeMlDsa { public, .. } => Ok(public.clone()),
            _ => Err(Error::Key("symmetric keys have no public component".into())),
        }
    }

    /// Explicitly export the public component as SPKI DER.
    ///
    /// X25519 retains its historical raw-byte behavior. Composite ML-DSA keys
    /// are rejected because their draft encoding is an aggregate raw value;
    /// use [`export_composite_public`](Self::export_composite_public).
    pub fn export_spki_der(&self) -> Result<Vec<u8>> {
        require_supported(Operation::KeyExport(self.algorithm()))?;
        #[cfg(feature = "post-quantum")]
        if matches!(self.inner(), RustCryptoKey::CompositeMlDsa { .. }) {
            return Err(Error::Key(
                "composite ML-DSA keys have no SPKI encoding; use export_composite_public".into(),
            ));
        }
        self.public_component()
    }

    /// Explicitly export private or symmetric key material into a zeroizing buffer.
    pub fn export_private(&self) -> Result<Zeroizing<Vec<u8>>> {
        require_supported(Operation::KeyExport(self.algorithm()))?;
        use rsa::pkcs8::EncodePrivateKey;
        let bytes = match self.inner() {
            RustCryptoKey::Rsa {
                private: Some(private),
                ..
            } => private
                .to_pkcs8_der()
                .map(|der| der.as_bytes().to_vec())
                .map_err(|e| Error::Key(format!("RSA PKCS#8 export failed: {e}")))?,
            RustCryptoKey::EcP256 {
                private: Some(private),
                ..
            } => private
                .to_pkcs8_der()
                .map(|der| der.as_bytes().to_vec())
                .map_err(|e| Error::Key(format!("P-256 PKCS#8 export failed: {e}")))?,
            RustCryptoKey::EcP384 {
                private: Some(private),
                ..
            } => private
                .to_pkcs8_der()
                .map(|der| der.as_bytes().to_vec())
                .map_err(|e| Error::Key(format!("P-384 PKCS#8 export failed: {e}")))?,
            RustCryptoKey::EcP521 {
                private: Some(private),
                ..
            } => p521::SecretKey::from_slice(private.to_bytes().as_slice())
                .map_err(|e| Error::Key(format!("P-521 private conversion failed: {e}")))?
                .to_pkcs8_der()
                .map(|der| der.as_bytes().to_vec())
                .map_err(|e| Error::Key(format!("P-521 PKCS#8 export failed: {e}")))?,
            RustCryptoKey::Ed25519 {
                private: Some(private),
                ..
            } => private
                .to_pkcs8_der()
                .map(|der| der.as_bytes().to_vec())
                .map_err(|e| Error::Key(format!("Ed25519 PKCS#8 export failed: {e}")))?,
            RustCryptoKey::X25519 {
                private: Some(private),
                ..
            } => private.to_vec(),
            RustCryptoKey::Dh {
                private: Some(private),
                ..
            } => private.clone(),
            RustCryptoKey::Hmac(bytes) | RustCryptoKey::Aes(bytes) => bytes.clone(),
            #[cfg(feature = "legacy")]
            RustCryptoKey::Dsa {
                private: Some(private),
                ..
            } => private
                .to_pkcs8_der()
                .map(|der| der.as_bytes().to_vec())
                .map_err(|e| Error::Key(format!("DSA PKCS#8 export failed: {e}")))?,
            #[cfg(feature = "legacy")]
            RustCryptoKey::Des3(bytes) => bytes.clone(),
            #[cfg(feature = "post-quantum")]
            RustCryptoKey::PostQuantum {
                private_der: Some(private),
                ..
            } => private.clone(),
            #[cfg(feature = "post-quantum")]
            RustCryptoKey::CompositeMlDsa {
                private: Some(private),
                ..
            } => private.clone(),
            _ => return Err(Error::Key("key has no private material".into())),
        };
        Ok(Zeroizing::new(bytes))
    }

    /// Export the aggregate raw public key for a composite ML-DSA key.
    #[cfg(feature = "post-quantum")]
    pub fn export_composite_public(&self) -> Result<Vec<u8>> {
        require_supported(Operation::KeyExport(self.algorithm()))?;
        match self.inner() {
            RustCryptoKey::CompositeMlDsa { public, .. } => Ok(public.clone()),
            _ => Err(Error::Key("composite ML-DSA key required".into())),
        }
    }

    /// Export the aggregate raw private key into a zeroizing buffer.
    #[cfg(feature = "post-quantum")]
    pub fn export_composite_private(&self) -> Result<Zeroizing<Vec<u8>>> {
        require_supported(Operation::KeyExport(self.algorithm()))?;
        match self.inner() {
            RustCryptoKey::CompositeMlDsa {
                private: Some(private),
                ..
            } => Ok(Zeroizing::new(private.clone())),
            RustCryptoKey::CompositeMlDsa { private: None, .. } => {
                Err(Error::Key("key has no private material".into()))
            }
            _ => Err(Error::Key("composite ML-DSA key required".into())),
        }
    }

    /// Return neutral finite-field DH public parameters when this is a DH key.
    #[must_use]
    pub fn dh_parameters(&self) -> Option<&DhParameters> {
        match self.inner() {
            RustCryptoKey::Dh { parameters, .. } => Some(parameters),
            _ => None,
        }
    }
}

pub(crate) enum RustCryptoKey {
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
    Dh {
        private: Option<Vec<u8>>,
        parameters: DhParameters,
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
    #[cfg(feature = "post-quantum")]
    CompositeMlDsa {
        variant: crate::algorithm::CompositeMlDsaVariant,
        private: Option<Vec<u8>>,
        public: Vec<u8>,
    },
}

impl Drop for RustCryptoKey {
    fn drop(&mut self) {
        match self {
            RustCryptoKey::Hmac(bytes) | RustCryptoKey::Aes(bytes) => bytes.zeroize(),
            RustCryptoKey::X25519 { private, .. } => {
                if let Some(bytes) = private {
                    bytes.zeroize();
                }
            }
            RustCryptoKey::Dh { private, .. } => {
                if let Some(bytes) = private {
                    bytes.zeroize();
                }
            }
            #[cfg(feature = "legacy")]
            RustCryptoKey::Des3(bytes) => bytes.zeroize(),
            #[cfg(feature = "post-quantum")]
            RustCryptoKey::PostQuantum { private_der, .. } => {
                if let Some(der) = private_der {
                    der.zeroize();
                }
            }
            #[cfg(feature = "post-quantum")]
            RustCryptoKey::CompositeMlDsa { private, .. } => {
                if let Some(bytes) = private {
                    bytes.zeroize();
                }
            }
            RustCryptoKey::Rsa { .. }
            | RustCryptoKey::EcP256 { .. }
            | RustCryptoKey::EcP384 { .. }
            | RustCryptoKey::EcP521 { .. }
            | RustCryptoKey::Ed25519 { .. } => {}
            #[cfg(feature = "legacy")]
            RustCryptoKey::Dsa { .. } => {}
        }
    }
}

impl ZeroizeOnDrop for RustCryptoKey {}

impl From<RustCryptoKey> for SoftwareKey {
    fn from(key: RustCryptoKey) -> Self {
        Self::from_rustcrypto(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn underlying_key_material_is_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<RustCryptoKey>();
    }

    #[test]
    fn debug_redacts_secret() {
        let key = SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Hmac, b"do-not-print").unwrap();
        let debug = format!("{key:?}");
        assert!(!debug.contains("do-not-print"));
    }

    #[test]
    fn cloning_shares_opaque_handle() {
        let key = SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Aes, &[7; 32]).unwrap();
        let clone = key.clone();
        assert!(Arc::ptr_eq(&key.0, &clone.0));
    }

    #[test]
    fn imports_neutral_dh_parameters_without_exposing_private_exponent() {
        let key = SoftwareKey::from_dh_parameters(&[23], &[4], Some(&[11]), Some(&[5]), &[12])
            .expect("DH import");
        assert_eq!(key.algorithm(), KeyAlgorithm::Dh);
        assert!(key.has_private_key());
        assert_eq!(key.public_component().unwrap(), vec![12]);
        let parameters = key.dh_parameters().expect("DH parameters");
        assert_eq!(parameters.modulus(), &[23]);
        assert_eq!(parameters.generator(), &[4]);
        assert_eq!(parameters.subgroup_order(), Some(&[11][..]));
        assert_eq!(key.export_private().unwrap().as_slice(), &[5]);
        assert!(!format!("{key:?}").contains('5'));
    }
}
