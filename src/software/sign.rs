//! Software signing and verification using RustCrypto primitives.
//!
//! `SoftwareSigner` and `SoftwareVerifier` implement the `Signer` and `Verifier`
//! traits from `crate::traits`, holding both the algorithm and key material.

use crate::algorithm::{EcCurve, HashAlgorithm, SignatureAlgorithm};
use crate::backend::{require_supported, Operation};
use crate::digest;
use crate::error::{Error, Result};
use crate::key::{RustCryptoKey as SoftwareKey, SoftwareKey as OpaqueSoftwareKey};
use crate::traits;
use signature::SignatureEncoding;

// ── Hash dispatch macro ─────────────────────────────────────────────

/// Dispatch a macro invocation across all `HashAlgorithm` variants.
/// The callback macro must accept a single type parameter `($hasher:ty)`.
macro_rules! dispatch_hash {
    ($hash:expr, $callback:ident) => {
        match $hash {
            HashAlgorithm::Sha1 => $callback!(sha1::Sha1),
            HashAlgorithm::Sha224 => $callback!(sha2::Sha224),
            HashAlgorithm::Sha256 => $callback!(sha2::Sha256),
            HashAlgorithm::Sha384 => $callback!(sha2::Sha384),
            HashAlgorithm::Sha512 => $callback!(sha2::Sha512),
            HashAlgorithm::Sha3_224 => $callback!(sha3::Sha3_224),
            HashAlgorithm::Sha3_256 => $callback!(sha3::Sha3_256),
            HashAlgorithm::Sha3_384 => $callback!(sha3::Sha3_384),
            HashAlgorithm::Sha3_512 => $callback!(sha3::Sha3_512),
            #[cfg(feature = "legacy")]
            HashAlgorithm::Md5 => $callback!(md5::Md5),
            #[cfg(feature = "legacy")]
            HashAlgorithm::Ripemd160 => $callback!(ripemd::Ripemd160),
        }
    };
}

// ── SoftwareSigner ──────────────────────────────────────────────────

/// Software-backed signer that holds algorithm and key material.
pub struct SoftwareSigner {
    algorithm: SignatureAlgorithm,
    key: OpaqueSoftwareKey,
    /// Optional FIPS 204 / FIPS 205 context string for ML-DSA / SLH-DSA.
    /// Ignored by every other algorithm. An earlier version hardcoded this
    /// to empty for both sign and verify, which prevented callers from using
    /// a single PQ key across multiple protocols with domain separation.
    #[cfg_attr(not(feature = "post-quantum"), allow(dead_code))]
    pq_context: Vec<u8>,
}

impl SoftwareSigner {
    /// Create a new signer with an empty FIPS 204/205 context (equivalent to
    /// [`new_with_pq_context`](Self::new_with_pq_context) with `&[]`).
    pub fn new<K: Into<OpaqueSoftwareKey>>(algorithm: SignatureAlgorithm, key: K) -> Result<Self> {
        Self::new_with_pq_context(algorithm, key, &[])
    }

    /// Create a new signer with an explicit FIPS 204 (ML-DSA) or FIPS 205
    /// (SLH-DSA) context string. Composite ML-DSA supplies its fixed label
    /// internally and therefore rejects a caller-provided context.
    pub fn new_with_pq_context<K: Into<OpaqueSoftwareKey>>(
        algorithm: SignatureAlgorithm,
        key: K,
        pq_context: &[u8],
    ) -> Result<Self> {
        require_supported(Operation::Sign(algorithm))?;
        let key = key.into();
        validate_signing_key(&algorithm, key.inner())?;
        if !pq_context.is_empty() && !is_pq_algorithm(&algorithm) {
            return Err(Error::Key(
                "signature algorithm does not accept a context string supplied by the caller"
                    .into(),
            ));
        }
        Ok(Self {
            algorithm,
            key,
            pq_context: pq_context.to_vec(),
        })
    }
}

impl traits::Signer for SoftwareSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let key = self.key.inner();
        match &self.algorithm {
            SignatureAlgorithm::RsaPkcs1v15(hash) => rsa_pkcs1v15_sign(key, *hash, data),
            SignatureAlgorithm::RsaPss(hash) => rsa_pss_sign(key, *hash, data),
            SignatureAlgorithm::Ecdsa(curve, hash) => ecdsa_sign(key, *curve, *hash, data),
            SignatureAlgorithm::Ed25519 => ed25519_sign(key, data),
            SignatureAlgorithm::Ed448 => ed448_sign(key, data),
            SignatureAlgorithm::Hmac(hash) => hmac_sign(key, *hash, data),
            #[cfg(feature = "legacy")]
            SignatureAlgorithm::Dsa(hash) => dsa_sign(key, *hash, data),
            #[cfg(feature = "post-quantum")]
            SignatureAlgorithm::MlDsa(variant) => {
                pq_ml_dsa_sign_dispatch(key, *variant, data, &self.pq_context)
            }
            #[cfg(feature = "post-quantum")]
            SignatureAlgorithm::CompositeMlDsa(variant) => {
                crate::software::composite::sign(key, *variant, data)
            }
            #[cfg(feature = "post-quantum")]
            SignatureAlgorithm::SlhDsa(variant) => {
                pq_slh_dsa_sign_dispatch(key, *variant, data, &self.pq_context)
            }
        }
    }
}

/// Returns true iff `algo` is a post-quantum algorithm that supports a
/// FIPS 204 / 205 context string.
#[allow(dead_code)] // used only when `post-quantum` feature is enabled
fn is_pq_algorithm(algo: &SignatureAlgorithm) -> bool {
    #[cfg(feature = "post-quantum")]
    {
        matches!(
            algo,
            SignatureAlgorithm::MlDsa(_) | SignatureAlgorithm::SlhDsa(_)
        )
    }
    #[cfg(not(feature = "post-quantum"))]
    {
        let _ = algo;
        false
    }
}

// ── SoftwareVerifier ────────────────────────────────────────────────

/// Software-backed verifier that holds algorithm and key material.
pub struct SoftwareVerifier {
    algorithm: SignatureAlgorithm,
    key: OpaqueSoftwareKey,
    rsa_pss_salt_len: Option<usize>,
    /// See [`SoftwareSigner::new_with_pq_context`]. Must match the signer's
    /// context byte-for-byte or verification fails.
    #[cfg_attr(not(feature = "post-quantum"), allow(dead_code))]
    pq_context: Vec<u8>,
}

impl SoftwareVerifier {
    /// Create a new verifier with an empty FIPS 204/205 context.
    pub fn new<K: Into<OpaqueSoftwareKey>>(algorithm: SignatureAlgorithm, key: K) -> Result<Self> {
        Self::new_with_pq_context(algorithm, key, &[])
    }

    /// Create a new verifier with an explicit FIPS 204 (ML-DSA) or FIPS 205
    /// (SLH-DSA) context string. Must match the signer's context exactly;
    /// see [`SoftwareSigner::new_with_pq_context`] for rationale.
    pub fn new_with_pq_context<K: Into<OpaqueSoftwareKey>>(
        algorithm: SignatureAlgorithm,
        key: K,
        pq_context: &[u8],
    ) -> Result<Self> {
        require_supported(Operation::Verify(algorithm))?;
        let key = key.into();
        validate_verifying_key(&algorithm, key.inner())?;
        if !pq_context.is_empty() && !is_pq_algorithm(&algorithm) {
            return Err(Error::Key(
                "signature algorithm does not accept a context string supplied by the caller"
                    .into(),
            ));
        }
        Ok(Self {
            algorithm,
            key,
            rsa_pss_salt_len: None,
            pq_context: pq_context.to_vec(),
        })
    }

    /// Create an RSA-PSS verifier with an explicit salt length.
    ///
    /// This is intended for parameterized certificate/CMS algorithms where
    /// the salt length is carried in the signed `AlgorithmIdentifier`.
    /// A salt length that cannot fit in the key's encoded message
    /// (`emLen - hLen - 2`, RFC 8017 §9.1.2) is rejected here, before the
    /// attacker-controlled value reaches `rsa`'s unchecked length arithmetic.
    pub fn new_rsa_pss_with_salt<K: Into<OpaqueSoftwareKey>>(
        hash: HashAlgorithm,
        salt_len: usize,
        key: K,
    ) -> Result<Self> {
        let mut verifier = Self::new(SignatureAlgorithm::RsaPss(hash), key)?;
        let max_salt_len = rsa_pss_max_salt_len(extract_rsa_public(verifier.key.inner())?, hash)
            .ok_or_else(|| Error::Key("RSA-PSS key is too small for the selected hash".into()))?;
        if salt_len > max_salt_len {
            return Err(Error::Key(format!(
                "RSA-PSS salt length {salt_len} exceeds the {max_salt_len}-byte maximum for this key and hash"
            )));
        }
        verifier.rsa_pss_salt_len = Some(salt_len);
        Ok(verifier)
    }

    /// Verify a signature encoded in the ASN.1 form used by X.509/CMS.
    ///
    /// ECDSA and DSA protocol signatures are DER sequences, while the lower
    /// provider interface uses fixed-width neutral components.
    pub fn verify_der_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        match self.algorithm {
            SignatureAlgorithm::Ecdsa(curve, _) => {
                let raw = digest::ecdsa_der_to_raw(curve, signature)?;
                traits::Verifier::verify(self, data, &raw)
            }
            #[cfg(feature = "legacy")]
            SignatureAlgorithm::Dsa(hash) => {
                use dsa::pkcs8::der::Decode;
                use signature::DigestVerifier;

                let key = self.key.inner();
                let vk = match key {
                    SoftwareKey::Dsa {
                        private: Some(sk), ..
                    } => sk.verifying_key().clone(),
                    SoftwareKey::Dsa { public, .. } => public.clone(),
                    _ => return Err(Error::Key("DSA key required".into())),
                };
                let parsed = dsa::Signature::from_der(signature)
                    .map_err(|e| Error::Crypto(format!("invalid DSA DER signature: {e}")))?;
                let result = match hash {
                    HashAlgorithm::Sha1 => vk.verify_digest(
                        |d: &mut sha1::Sha1| {
                            ::digest::Update::update(d, data);
                            Ok(())
                        },
                        &parsed,
                    ),
                    HashAlgorithm::Sha256 => vk.verify_digest(
                        |d: &mut sha2::Sha256| {
                            ::digest::Update::update(d, data);
                            Ok(())
                        },
                        &parsed,
                    ),
                    _ => {
                        return Err(Error::unsupported(
                            Operation::Verify(self.algorithm),
                            format!("DSA with {hash:?}"),
                        ))
                    }
                };
                Ok(result.is_ok())
            }
            _ => traits::Verifier::verify(self, data, signature),
        }
    }
}

impl traits::Verifier for SoftwareVerifier {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        let key = self.key.inner();
        match &self.algorithm {
            SignatureAlgorithm::RsaPkcs1v15(hash) => {
                rsa_pkcs1v15_verify(key, *hash, data, signature)
            }
            SignatureAlgorithm::RsaPss(hash) => {
                rsa_pss_verify(key, *hash, self.rsa_pss_salt_len, data, signature)
            }
            SignatureAlgorithm::Ecdsa(curve, hash) => {
                ecdsa_verify(key, *curve, *hash, data, signature)
            }
            SignatureAlgorithm::Ed25519 => ed25519_verify(key, data, signature),
            SignatureAlgorithm::Ed448 => ed448_verify(key, data, signature),
            SignatureAlgorithm::Hmac(hash) => hmac_verify(key, *hash, data, signature),
            #[cfg(feature = "legacy")]
            SignatureAlgorithm::Dsa(hash) => dsa_verify(key, *hash, data, signature),
            #[cfg(feature = "post-quantum")]
            SignatureAlgorithm::MlDsa(variant) => {
                pq_ml_dsa_verify_dispatch(key, *variant, data, signature, &self.pq_context)
            }
            #[cfg(feature = "post-quantum")]
            SignatureAlgorithm::CompositeMlDsa(variant) => {
                crate::software::composite::verify(key, *variant, data, signature)
            }
            #[cfg(feature = "post-quantum")]
            SignatureAlgorithm::SlhDsa(variant) => {
                pq_slh_dsa_verify_dispatch(key, *variant, data, signature, &self.pq_context)
            }
        }
    }
}

// ── Key validation ──────────────────────────────────────────────────

/// Validate that a key is suitable for signing with the given algorithm.
fn validate_signing_key(algorithm: &SignatureAlgorithm, key: &SoftwareKey) -> Result<()> {
    match (algorithm, key) {
        (
            SignatureAlgorithm::RsaPkcs1v15(_) | SignatureAlgorithm::RsaPss(_),
            SoftwareKey::Rsa { private, public },
        ) => {
            if private.is_none() {
                return Err(Error::Key("RSA private key required for signing".into()));
            }
            crate::key::enforce_rsa_min_bits(Operation::Sign(*algorithm), public)
        }
        (SignatureAlgorithm::Ecdsa(EcCurve::P256, _), SoftwareKey::EcP256 { private, .. }) => {
            if private.is_none() {
                return Err(Error::Key("P-256 private key required for signing".into()));
            }
            Ok(())
        }
        (SignatureAlgorithm::Ecdsa(EcCurve::P384, _), SoftwareKey::EcP384 { private, .. }) => {
            if private.is_none() {
                return Err(Error::Key("P-384 private key required for signing".into()));
            }
            Ok(())
        }
        (SignatureAlgorithm::Ecdsa(EcCurve::P521, _), SoftwareKey::EcP521 { private, .. }) => {
            if private.is_none() {
                return Err(Error::Key("P-521 private key required for signing".into()));
            }
            Ok(())
        }
        (
            SignatureAlgorithm::Ecdsa(EcCurve::Secp256k1, _),
            SoftwareKey::EcSecp256k1 { private, .. },
        ) => {
            if private.is_none() {
                return Err(Error::Key(
                    "secp256k1 private key required for signing".into(),
                ));
            }
            Ok(())
        }
        (
            SignatureAlgorithm::Ecdsa(EcCurve::BrainpoolP256r1, _),
            SoftwareKey::EcBrainpoolP256r1 { private, .. },
        ) => {
            if private.is_none() {
                return Err(Error::Key(
                    "brainpoolP256r1 private key required for signing".into(),
                ));
            }
            Ok(())
        }
        (
            SignatureAlgorithm::Ecdsa(EcCurve::BrainpoolP384r1, _),
            SoftwareKey::EcBrainpoolP384r1 { private, .. },
        ) => {
            if private.is_none() {
                return Err(Error::Key(
                    "brainpoolP384r1 private key required for signing".into(),
                ));
            }
            Ok(())
        }
        (SignatureAlgorithm::Ed25519, SoftwareKey::Ed25519 { private, .. }) => {
            if private.is_none() {
                return Err(Error::Key(
                    "Ed25519 private key required for signing".into(),
                ));
            }
            Ok(())
        }
        (SignatureAlgorithm::Ed448, SoftwareKey::Ed448 { private, .. }) => {
            if private.is_none() {
                return Err(Error::Key("Ed448 private key required for signing".into()));
            }
            Ok(())
        }
        (SignatureAlgorithm::Hmac(_), SoftwareKey::Hmac(key_bytes)) => {
            if key_bytes.is_empty() {
                return Err(Error::Key("HMAC key must not be empty".into()));
            }
            Ok(())
        }
        #[cfg(feature = "legacy")]
        (SignatureAlgorithm::Dsa(_), SoftwareKey::Dsa { private, .. }) => {
            if private.is_none() {
                return Err(Error::Key("DSA private key required for signing".into()));
            }
            Ok(())
        }
        #[cfg(feature = "post-quantum")]
        (
            SignatureAlgorithm::MlDsa(variant),
            SoftwareKey::PostQuantum {
                algorithm,
                private_der,
                ..
            },
        ) => {
            use crate::algorithm::PqAlgorithm;
            let expected = PqAlgorithm::MlDsa(*variant);
            if *algorithm != expected {
                return Err(Error::Key(format!(
                    "key algorithm mismatch: key is {}, but signature requires {}",
                    algorithm.name(),
                    expected.name(),
                )));
            }
            if private_der.is_none() {
                return Err(Error::Key(format!(
                    "{} private key required for signing",
                    variant.name()
                )));
            }
            Ok(())
        }
        #[cfg(feature = "post-quantum")]
        (
            SignatureAlgorithm::CompositeMlDsa(variant),
            SoftwareKey::CompositeMlDsa {
                variant: key_variant,
                private,
                ..
            },
        ) => {
            if key_variant != variant {
                return Err(Error::Key(format!(
                    "composite key is {}, but signature requires {}",
                    key_variant.name(),
                    variant.name()
                )));
            }
            if private.is_none() {
                return Err(Error::Key(format!(
                    "{} aggregate private key required for signing",
                    variant.name()
                )));
            }
            Ok(())
        }
        #[cfg(feature = "post-quantum")]
        (
            SignatureAlgorithm::SlhDsa(variant),
            SoftwareKey::PostQuantum {
                algorithm,
                private_der,
                ..
            },
        ) => {
            use crate::algorithm::PqAlgorithm;
            let expected = PqAlgorithm::SlhDsa(*variant);
            if *algorithm != expected {
                return Err(Error::Key(format!(
                    "key algorithm mismatch: key is {}, but signature requires {}",
                    algorithm.name(),
                    expected.name(),
                )));
            }
            if private_der.is_none() {
                return Err(Error::Key(format!(
                    "{} private key required for signing",
                    variant.name()
                )));
            }
            Ok(())
        }
        _ => Err(Error::Key(format!(
            "key type does not match algorithm {algorithm:?}"
        ))),
    }
}

/// Validate that a key is suitable for verifying with the given algorithm.
fn validate_verifying_key(algorithm: &SignatureAlgorithm, key: &SoftwareKey) -> Result<()> {
    match (algorithm, key) {
        (
            SignatureAlgorithm::RsaPkcs1v15(_) | SignatureAlgorithm::RsaPss(_),
            SoftwareKey::Rsa { public, .. },
        ) => crate::key::enforce_rsa_min_bits(Operation::Verify(*algorithm), public),
        (SignatureAlgorithm::Ecdsa(EcCurve::P256, _), SoftwareKey::EcP256 { .. }) => Ok(()),
        (SignatureAlgorithm::Ecdsa(EcCurve::P384, _), SoftwareKey::EcP384 { .. }) => Ok(()),
        (SignatureAlgorithm::Ecdsa(EcCurve::P521, _), SoftwareKey::EcP521 { .. }) => Ok(()),
        (SignatureAlgorithm::Ecdsa(EcCurve::Secp256k1, _), SoftwareKey::EcSecp256k1 { .. }) => {
            Ok(())
        }
        (
            SignatureAlgorithm::Ecdsa(EcCurve::BrainpoolP256r1, _),
            SoftwareKey::EcBrainpoolP256r1 { .. },
        )
        | (
            SignatureAlgorithm::Ecdsa(EcCurve::BrainpoolP384r1, _),
            SoftwareKey::EcBrainpoolP384r1 { .. },
        ) => Ok(()),
        (SignatureAlgorithm::Ed25519, SoftwareKey::Ed25519 { .. }) => Ok(()),
        (SignatureAlgorithm::Ed448, SoftwareKey::Ed448 { .. }) => Ok(()),
        (SignatureAlgorithm::Hmac(_), SoftwareKey::Hmac(key_bytes)) => {
            if key_bytes.is_empty() {
                return Err(Error::Key("HMAC key must not be empty".into()));
            }
            Ok(())
        }
        #[cfg(feature = "legacy")]
        (SignatureAlgorithm::Dsa(_), SoftwareKey::Dsa { .. }) => Ok(()),
        #[cfg(feature = "post-quantum")]
        (SignatureAlgorithm::MlDsa(variant), SoftwareKey::PostQuantum { algorithm, .. }) => {
            use crate::algorithm::PqAlgorithm;
            let expected = PqAlgorithm::MlDsa(*variant);
            if *algorithm != expected {
                return Err(Error::Key(format!(
                    "key algorithm mismatch: key is {}, but verification requires {}",
                    algorithm.name(),
                    expected.name(),
                )));
            }
            Ok(())
        }
        #[cfg(feature = "post-quantum")]
        (
            SignatureAlgorithm::CompositeMlDsa(variant),
            SoftwareKey::CompositeMlDsa {
                variant: key_variant,
                ..
            },
        ) => {
            if key_variant != variant {
                return Err(Error::Key(format!(
                    "composite key is {}, but verification requires {}",
                    key_variant.name(),
                    variant.name()
                )));
            }
            Ok(())
        }
        #[cfg(feature = "post-quantum")]
        (SignatureAlgorithm::SlhDsa(variant), SoftwareKey::PostQuantum { algorithm, .. }) => {
            use crate::algorithm::PqAlgorithm;
            let expected = PqAlgorithm::SlhDsa(*variant);
            if *algorithm != expected {
                return Err(Error::Key(format!(
                    "key algorithm mismatch: key is {}, but verification requires {}",
                    algorithm.name(),
                    expected.name(),
                )));
            }
            Ok(())
        }
        _ => Err(Error::Key(format!(
            "key type does not match algorithm {algorithm:?}"
        ))),
    }
}

// ── RSA PKCS#1 v1.5 ────────────────────────────────────────────────

fn rsa_pkcs1v15_sign(key: &SoftwareKey, hash: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    use signature::RandomizedSigner;
    let SoftwareKey::Rsa {
        private: Some(private_key),
        ..
    } = key
    else {
        return Err(Error::Key("RSA private key required".into()));
    };
    // PKCS#1 v1.5 padding is deterministic; the RNG only feeds RSA
    // blinding of the private operation (see .cargo/audit.toml, Marvin).
    // `getrandom::SysRng` is fallible, so an entropy failure is an error
    // rather than a panic (ADR 0001).
    macro_rules! do_sign {
        ($hasher:ty) => {{
            let sk = rsa::pkcs1v15::SigningKey::<$hasher>::new(private_key.clone());
            sk.try_sign_with_rng(&mut getrandom::SysRng, data)
                .map(|sig| sig.to_vec())
                .map_err(|e| Error::Crypto(format!("RSA PKCS#1 v1.5 sign: {e}")))
        }};
    }
    dispatch_hash!(hash, do_sign)
}

fn rsa_pkcs1v15_verify(
    key: &SoftwareKey,
    hash: HashAlgorithm,
    data: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    use signature::Verifier;
    let public_key = extract_rsa_public(key)?;
    let sig = rsa::pkcs1v15::Signature::try_from(sig_bytes)
        .map_err(|e| Error::Crypto(format!("invalid RSA signature: {e}")))?;
    macro_rules! do_verify {
        ($hasher:ty) => {{
            let vk = rsa::pkcs1v15::VerifyingKey::<$hasher>::new(public_key.clone());
            Ok(vk.verify(data, &sig).is_ok())
        }};
    }
    dispatch_hash!(hash, do_verify)
}

// ── RSA-PSS ─────────────────────────────────────────────────────────

fn rsa_pss_sign(key: &SoftwareKey, hash: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    use signature::RandomizedSigner;
    let SoftwareKey::Rsa {
        private: Some(private_key),
        ..
    } = key
    else {
        return Err(Error::Key("RSA private key required for PSS".into()));
    };
    // The salt and the blinding factor both come from `getrandom::SysRng`
    // (fallible, stateless, fork-safe; see docs/adr/0001-rng-choice.md).
    macro_rules! do_sign {
        ($hasher:ty) => {{
            let sk = rsa::pss::SigningKey::<$hasher>::new(private_key.clone());
            sk.try_sign_with_rng(&mut getrandom::SysRng, data)
                .map(|sig| sig.to_vec())
                .map_err(|e| Error::Crypto(format!("RSA-PSS sign: {e}")))
        }};
    }
    dispatch_hash!(hash, do_sign)
}

fn rsa_pss_verify(
    key: &SoftwareKey,
    hash: HashAlgorithm,
    salt_len: Option<usize>,
    data: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    use signature::Verifier;
    let public_key = extract_rsa_public(key)?;
    let sig = rsa::pss::Signature::try_from(sig_bytes)
        .map_err(|e| Error::Crypto(format!("invalid RSA-PSS signature: {e}")))?;
    macro_rules! do_verify {
        ($hasher:ty) => {{
            let vk = match salt_len {
                Some(salt_len) => rsa::pss::VerifyingKey::<$hasher>::new_with_salt_len(
                    public_key.clone(),
                    salt_len,
                ),
                None => rsa::pss::VerifyingKey::<$hasher>::new(public_key.clone()),
            };
            Ok(vk.verify(data, &sig).is_ok())
        }};
    }
    dispatch_hash!(hash, do_verify)
}

/// Largest RSA-PSS salt that fits the key's encoded message:
/// `emLen - hLen - 2` with `emLen = ceil((modBits - 1) / 8)` (RFC 8017 §9.1.1).
/// Returns `None` when even a zero-length salt cannot fit.
fn rsa_pss_max_salt_len(public_key: &rsa::RsaPublicKey, hash: HashAlgorithm) -> Option<usize> {
    use rsa::traits::PublicKeyParts;
    macro_rules! output_len {
        ($hasher:ty) => {
            <$hasher as ::digest::Digest>::output_size()
        };
    }
    let h_len = dispatch_hash!(hash, output_len);
    let em_len = (public_key.n().bits() as usize)
        .saturating_sub(1)
        .div_ceil(8);
    em_len.checked_sub(h_len + 2)
}

/// Extract the RSA public key from a `SoftwareKey::Rsa`.
fn extract_rsa_public(key: &SoftwareKey) -> Result<&rsa::RsaPublicKey> {
    match key {
        SoftwareKey::Rsa { public, .. } => Ok(public),
        _ => Err(Error::Key("RSA key required".into())),
    }
}

// ── ECDSA ───────────────────────────────────────────────────────────

fn ecdsa_sign(
    key: &SoftwareKey,
    curve: EcCurve,
    hash: HashAlgorithm,
    data: &[u8],
) -> Result<Vec<u8>> {
    use signature::hazmat::PrehashSigner;
    let raw_hash = digest::digest(hash, data)?;
    match (curve, key) {
        (
            EcCurve::P256,
            SoftwareKey::EcP256 {
                private: Some(sk), ..
            },
        ) => {
            let prehash = digest::pad_prehash(&raw_hash, 32);
            let sig: p256::ecdsa::Signature = sk
                .sign_prehash(&prehash)
                .map_err(|e| Error::Crypto(format!("ECDSA P-256 sign: {e}")))?;
            Ok(digest::p256_sig_to_raw(&sig))
        }
        (
            EcCurve::P384,
            SoftwareKey::EcP384 {
                private: Some(sk), ..
            },
        ) => {
            let prehash = digest::pad_prehash(&raw_hash, 48);
            let sig: p384::ecdsa::Signature = sk
                .sign_prehash(&prehash)
                .map_err(|e| Error::Crypto(format!("ECDSA P-384 sign: {e}")))?;
            Ok(digest::p384_sig_to_raw(&sig))
        }
        (
            EcCurve::P521,
            SoftwareKey::EcP521 {
                private: Some(sk), ..
            },
        ) => {
            let prehash = digest::pad_prehash(&raw_hash, 66);
            let sig: p521::ecdsa::Signature = sk
                .sign_prehash(&prehash)
                .map_err(|e| Error::Crypto(format!("ECDSA P-521 sign: {e}")))?;
            Ok(digest::p521_sig_to_raw(&sig))
        }
        (
            EcCurve::Secp256k1,
            SoftwareKey::EcSecp256k1 {
                private: Some(sk), ..
            },
        ) => {
            // k256 declares NORMALIZE_S, so the emitted `s` is always low-S.
            let prehash = digest::pad_prehash(&raw_hash, 32);
            let sig: k256::ecdsa::Signature = sk
                .sign_prehash(&prehash)
                .map_err(|e| Error::Crypto(format!("ECDSA secp256k1 sign: {e}")))?;
            Ok(digest::k256_sig_to_raw(&sig))
        }
        (
            EcCurve::BrainpoolP256r1,
            SoftwareKey::EcBrainpoolP256r1 {
                private: Some(sk), ..
            },
        ) => {
            let prehash = digest::pad_prehash(&raw_hash, 32);
            let sig: ecdsa::Signature<bp256::BrainpoolP256r1> = sk
                .sign_prehash(&prehash)
                .map_err(|e| Error::Crypto(format!("ECDSA brainpoolP256r1 sign: {e}")))?;
            Ok(digest::bp256_sig_to_raw(&sig))
        }
        (
            EcCurve::BrainpoolP384r1,
            SoftwareKey::EcBrainpoolP384r1 {
                private: Some(sk), ..
            },
        ) => {
            let prehash = digest::pad_prehash(&raw_hash, 48);
            let sig: ecdsa::Signature<bp384::BrainpoolP384r1> = sk
                .sign_prehash(&prehash)
                .map_err(|e| Error::Crypto(format!("ECDSA brainpoolP384r1 sign: {e}")))?;
            Ok(digest::bp384_sig_to_raw(&sig))
        }
        _ => Err(Error::Key(format!(
            "ECDSA {curve:?} private key required for signing"
        ))),
    }
}

fn ecdsa_verify(
    key: &SoftwareKey,
    curve: EcCurve,
    hash: HashAlgorithm,
    data: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    use signature::hazmat::PrehashVerifier;
    let raw_hash = digest::digest(hash, data)?;
    match (curve, key) {
        (
            EcCurve::P256,
            SoftwareKey::EcP256 {
                private: Some(sk), ..
            },
        ) => {
            let prehash = digest::pad_prehash(&raw_hash, 32);
            let sig = digest::raw_to_p256_sig(sig_bytes)?;
            Ok(sk.verifying_key().verify_prehash(&prehash, &sig).is_ok())
        }
        (EcCurve::P256, SoftwareKey::EcP256 { public, .. }) => {
            let prehash = digest::pad_prehash(&raw_hash, 32);
            let sig = digest::raw_to_p256_sig(sig_bytes)?;
            Ok(public.verify_prehash(&prehash, &sig).is_ok())
        }
        (
            EcCurve::P384,
            SoftwareKey::EcP384 {
                private: Some(sk), ..
            },
        ) => {
            let prehash = digest::pad_prehash(&raw_hash, 48);
            let sig = digest::raw_to_p384_sig(sig_bytes)?;
            Ok(sk.verifying_key().verify_prehash(&prehash, &sig).is_ok())
        }
        (EcCurve::P384, SoftwareKey::EcP384 { public, .. }) => {
            let prehash = digest::pad_prehash(&raw_hash, 48);
            let sig = digest::raw_to_p384_sig(sig_bytes)?;
            Ok(public.verify_prehash(&prehash, &sig).is_ok())
        }
        (EcCurve::Secp256k1, SoftwareKey::EcSecp256k1 { private, public }) => {
            let prehash = digest::pad_prehash(&raw_hash, 32);
            // ecdsa 0.17 rejects high-S signatures for NORMALIZE_S curves
            // (BIP-62), but AWS-LC, OpenSSL and most tokens emit either
            // form. Normalizing first keeps both providers' verifiers in
            // agreement; the scalar-range checks already ran in `normalize`.
            let sig = digest::raw_to_k256_sig(sig_bytes)?.normalize_s();
            let public = private.as_ref().map_or(*public, |sk| *sk.verifying_key());
            Ok(public.verify_prehash(&prehash, &sig).is_ok())
        }
        (EcCurve::BrainpoolP256r1, SoftwareKey::EcBrainpoolP256r1 { private, public }) => {
            let prehash = digest::pad_prehash(&raw_hash, 32);
            let sig = digest::raw_to_bp256_sig(sig_bytes)?;
            let public = private.as_ref().map_or(*public, |sk| *sk.verifying_key());
            Ok(public.verify_prehash(&prehash, &sig).is_ok())
        }
        (EcCurve::BrainpoolP384r1, SoftwareKey::EcBrainpoolP384r1 { private, public }) => {
            let prehash = digest::pad_prehash(&raw_hash, 48);
            let sig = digest::raw_to_bp384_sig(sig_bytes)?;
            let public = private.as_ref().map_or(*public, |sk| *sk.verifying_key());
            Ok(public.verify_prehash(&prehash, &sig).is_ok())
        }
        (
            EcCurve::P521,
            SoftwareKey::EcP521 {
                private: Some(sk), ..
            },
        ) => {
            let prehash = digest::pad_prehash(&raw_hash, 66);
            let sig = digest::raw_to_p521_sig(sig_bytes)?;
            let vk = p521::ecdsa::VerifyingKey::from(sk);
            Ok(vk.verify_prehash(&prehash, &sig).is_ok())
        }
        (EcCurve::P521, SoftwareKey::EcP521 { public, .. }) => {
            let prehash = digest::pad_prehash(&raw_hash, 66);
            let sig = digest::raw_to_p521_sig(sig_bytes)?;
            Ok(public.verify_prehash(&prehash, &sig).is_ok())
        }
        _ => Err(Error::Key(format!(
            "ECDSA {curve:?} key required for verification"
        ))),
    }
}

// ── Ed25519 ─────────────────────────────────────────────────────────

fn ed25519_sign(key: &SoftwareKey, data: &[u8]) -> Result<Vec<u8>> {
    use ed25519_dalek::Signer;
    let SoftwareKey::Ed25519 {
        private: Some(sk), ..
    } = key
    else {
        return Err(Error::Key("Ed25519 private key required".into()));
    };
    let sig = sk.sign(data);
    Ok(sig.to_bytes().to_vec())
}

fn ed25519_verify(key: &SoftwareKey, data: &[u8], sig_bytes: &[u8]) -> Result<bool> {
    let vk = match key {
        SoftwareKey::Ed25519 {
            private: Some(sk), ..
        } => sk.verifying_key(),
        SoftwareKey::Ed25519 { public, .. } => *public,
        _ => return Err(Error::Key("Ed25519 key required".into())),
    };
    let sig = ed25519_dalek::Signature::from_slice(sig_bytes)
        .map_err(|e| Error::Crypto(format!("invalid Ed25519 signature: {e}")))?;
    // `verify_strict` rejects non-canonical `R` encodings, low-order `R`
    // (identity / small-subgroup points), and non-canonical scalar `s`.
    // Standard implementations (ed25519-dalek, OpenSSL, BoringSSL, NaCl)
    // always produce canonical signatures, so this is a no-op for
    // legitimate signers; the strict check closes a malleability surface
    // for consensus / certificate-transparency / signed-receipt callers
    // that treat the signature bytes themselves as unique.
    Ok(vk.verify_strict(data, &sig).is_ok())
}

// ── Ed448 ───────────────────────────────────────────────────────────

/// Pure Ed448 (RFC 8032 §5.2.6) with the empty context string; 114 bytes.
fn ed448_sign(key: &SoftwareKey, data: &[u8]) -> Result<Vec<u8>> {
    let SoftwareKey::Ed448 {
        private: Some(sk), ..
    } = key
    else {
        return Err(Error::Key("Ed448 private key required".into()));
    };
    Ok(sk.sign_raw(data).to_bytes().to_vec())
}

fn ed448_verify(key: &SoftwareKey, data: &[u8], sig_bytes: &[u8]) -> Result<bool> {
    let vk = match key {
        SoftwareKey::Ed448 {
            private: Some(sk), ..
        } => sk.verifying_key(),
        SoftwareKey::Ed448 { public, .. } => *public,
        _ => return Err(Error::Key("Ed448 key required".into())),
    };
    let sig = ed448_goldilocks::Signature::from_slice(sig_bytes)
        .map_err(|e| Error::Crypto(format!("invalid Ed448 signature: {e}")))?;
    // `verify_raw` is pure Ed448 (phflag 0, ctx ""). ed448-goldilocks
    // rejects a non-canonical or zero `s`, an `R` or `A` that is the
    // identity or fails to decompress, and then checks the *non-cofactored*
    // equation `[S]B == R + [k]A`. That is stricter than RFC 8032 §5.2.7's
    // cofactored check and matches the Ed25519 `verify_strict` posture
    // above: honest signers never produce signatures the strict check
    // rejects, and signature bytes stay unique for callers that key on
    // them. Inputs are public, so none of this needs to be constant-time.
    Ok(vk.verify_raw(&sig, data).is_ok())
}

// ── HMAC ────────────────────────────────────────────────────────────

fn hmac_sign(key: &SoftwareKey, hash: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    let SoftwareKey::Hmac(key_bytes) = key else {
        return Err(Error::Key("HMAC key required".into()));
    };
    digest::compute_hmac(hash, key_bytes, data)
}

fn hmac_verify(
    key: &SoftwareKey,
    hash: HashAlgorithm,
    data: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    let SoftwareKey::Hmac(key_bytes) = key else {
        return Err(Error::Key("HMAC key required".into()));
    };
    let expected = digest::compute_hmac(hash, key_bytes, data)?;
    Ok(digest::constant_time_eq(&expected, sig_bytes))
}

// ── DSA (legacy) ────────────────────────────────────────────────────

#[cfg(feature = "legacy")]
fn dsa_sign(key: &SoftwareKey, hash: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    use ::digest::Update;
    use signature::DigestSigner;

    let SoftwareKey::Dsa {
        private: Some(sk), ..
    } = key
    else {
        return Err(Error::Key("DSA private key required".into()));
    };
    // `signature 3` hands the signer a fresh digest to update; DSA signing
    // stays deterministic (RFC 6979), so no RNG is involved.
    let sig: dsa::Signature = match hash {
        HashAlgorithm::Sha1 => sk
            .try_sign_digest(|d: &mut sha1::Sha1| {
                d.update(data);
                Ok(())
            })
            .map_err(|e| Error::Crypto(format!("DSA sign: {e}")))?,
        HashAlgorithm::Sha256 => sk
            .try_sign_digest(|d: &mut sha2::Sha256| {
                d.update(data);
                Ok(())
            })
            .map_err(|e| Error::Crypto(format!("DSA sign: {e}")))?,
        _ => {
            return Err(Error::unsupported(
                crate::backend::Operation::Sign(SignatureAlgorithm::Dsa(hash)),
                format!("DSA with {hash:?}"),
            ));
        }
    };
    Ok(dsa_sig_to_raw(sk.verifying_key(), &sig))
}

#[cfg(feature = "legacy")]
fn dsa_verify(
    key: &SoftwareKey,
    hash: HashAlgorithm,
    data: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    use ::digest::Update;
    use signature::DigestVerifier;

    let vk = match key {
        SoftwareKey::Dsa {
            private: Some(sk), ..
        } => sk.verifying_key().clone(),
        SoftwareKey::Dsa { public, .. } => public.clone(),
        _ => return Err(Error::Key("DSA key required".into())),
    };
    let sig = raw_to_dsa_sig(&vk, sig_bytes)?;
    let result = match hash {
        HashAlgorithm::Sha1 => vk.verify_digest(
            |d: &mut sha1::Sha1| {
                d.update(data);
                Ok(())
            },
            &sig,
        ),
        HashAlgorithm::Sha256 => vk.verify_digest(
            |d: &mut sha2::Sha256| {
                d.update(data);
                Ok(())
            },
            &sig,
        ),
        _ => {
            return Err(Error::unsupported(
                crate::backend::Operation::Verify(SignatureAlgorithm::Dsa(hash)),
                format!("DSA with {hash:?}"),
            ));
        }
    };
    Ok(result.is_ok())
}

#[cfg(feature = "legacy")]
fn dsa_q_len(vk: &dsa::VerifyingKey) -> usize {
    (vk.components().q().bits() as usize).div_ceil(8)
}

#[cfg(feature = "legacy")]
fn dsa_sig_to_raw(vk: &dsa::VerifyingKey, sig: &dsa::Signature) -> Vec<u8> {
    let q_len = dsa_q_len(vk);
    // r and s are public signature components: variable-time trimming is fine.
    let r_bytes = sig.r().to_be_bytes_trimmed_vartime();
    let s_bytes = sig.s().to_be_bytes_trimmed_vartime();
    // Invariant: FIPS 186-4 §4.6 defines a valid DSA signature as
    // (r, s) with 0 < r < q and 0 < s < q. Therefore r_bytes.len() and
    // s_bytes.len() are both `<= q_len`. The `saturating_sub` calls below
    // defend against a buggy signer that violates this, but silent
    // truncation would produce a signature whose serialization does not
    // round-trip. Assert in debug builds so such a signer is caught in
    // tests rather than producing confusingly-malformed output in prod.
    debug_assert!(
        r_bytes.len() <= q_len,
        "DSA signer produced r ({} bytes) > q ({} bytes); violates FIPS 186-4",
        r_bytes.len(),
        q_len,
    );
    debug_assert!(
        s_bytes.len() <= q_len,
        "DSA signer produced s ({} bytes) > q ({} bytes); violates FIPS 186-4",
        s_bytes.len(),
        q_len,
    );
    let mut out = vec![0u8; q_len * 2];
    let r_start = q_len.saturating_sub(r_bytes.len());
    out[r_start..q_len].copy_from_slice(&r_bytes[r_bytes.len().saturating_sub(q_len)..]);
    let s_start = q_len + q_len.saturating_sub(s_bytes.len());
    out[s_start..q_len * 2].copy_from_slice(&s_bytes[s_bytes.len().saturating_sub(q_len)..]);
    out
}

#[cfg(feature = "legacy")]
fn raw_to_dsa_sig(vk: &dsa::VerifyingKey, rs: &[u8]) -> Result<dsa::Signature> {
    let q_len = dsa_q_len(vk);
    if rs.len() != q_len * 2 {
        return Err(Error::Crypto(format!(
            "DSA signature must be {} bytes (2 * q_len={}), got {}",
            q_len * 2,
            q_len,
            rs.len()
        )));
    }
    let precision = u32::try_from(q_len * 8)
        .map_err(|_| Error::Crypto("DSA subgroup size overflows u32".into()))?;
    let r = dsa::BoxedUint::from_be_slice(&rs[..q_len], precision)
        .map_err(|e| Error::Crypto(format!("invalid DSA signature r: {e}")))?;
    let s = dsa::BoxedUint::from_be_slice(&rs[q_len..], precision)
        .map_err(|e| Error::Crypto(format!("invalid DSA signature s: {e}")))?;
    dsa::Signature::from_components(r, s)
        .ok_or_else(|| Error::Crypto("invalid DSA signature: r or s is zero".into()))
}

// ── Post-quantum: ML-DSA (FIPS 204) ────────────────────────────────

#[cfg(feature = "post-quantum")]
fn pq_ml_dsa_sign_dispatch(
    key: &SoftwareKey,
    variant: crate::algorithm::MlDsaVariant,
    data: &[u8],
    context: &[u8],
) -> Result<Vec<u8>> {
    use crate::algorithm::MlDsaVariant;
    let SoftwareKey::PostQuantum {
        private_der: Some(private),
        ..
    } = key
    else {
        return Err(Error::Key(format!(
            "{} private key required for signing",
            variant.name()
        )));
    };
    match variant {
        MlDsaVariant::MlDsa44 => pq_ml_dsa_sign::<ml_dsa::MlDsa44>(private, data, context),
        MlDsaVariant::MlDsa65 => pq_ml_dsa_sign::<ml_dsa::MlDsa65>(private, data, context),
        MlDsaVariant::MlDsa87 => pq_ml_dsa_sign::<ml_dsa::MlDsa87>(private, data, context),
    }
}

/// Sign with ML-DSA (FIPS 204).
///
/// `private_der` may be either a full PKCS#8 DER document (RustCrypto format)
/// or just the 32-byte seed (OpenSSL format, extracted by the loader).
#[cfg(feature = "post-quantum")]
fn pq_ml_dsa_sign<P>(private_der: &[u8], data: &[u8], context: &[u8]) -> Result<Vec<u8>>
where
    P: ml_dsa::MlDsaParams,
    P: pkcs8::spki::AssociatedAlgorithmIdentifier<Params = pkcs8::der::AnyRef<'static>>,
{
    // `getrandom::SysRng` is a zero-sized, stateless, fork-safe wrapper over
    // the OS entropy syscall. `sign_randomized` takes `TryCryptoRng`, so an
    // RNG failure is reported by `ml_dsa` and then wrapped by the
    // `.map_err(|e| Error::Crypto(...))` call below as `Error::Crypto`
    // (with the underlying `ml_dsa::Error` in the message) rather than
    // panicking. See docs/adr/0001-rng-choice.md.
    let sk = load_ml_dsa_signing_key::<P>(private_der)?;
    let sig = sk
        .sign_randomized(data, context, &mut getrandom::SysRng)
        .map_err(|e| Error::Crypto(format!("ML-DSA sign failed: {e}")))?;
    Ok(sig.encode().to_vec())
}

#[cfg(feature = "post-quantum")]
fn pq_ml_dsa_verify_dispatch(
    key: &SoftwareKey,
    variant: crate::algorithm::MlDsaVariant,
    data: &[u8],
    sig_bytes: &[u8],
    context: &[u8],
) -> Result<bool> {
    use crate::algorithm::MlDsaVariant;
    let SoftwareKey::PostQuantum { public_der, .. } = key else {
        return Err(Error::Key(format!(
            "{} key required for verification",
            variant.name()
        )));
    };
    match variant {
        MlDsaVariant::MlDsa44 => {
            pq_ml_dsa_verify::<ml_dsa::MlDsa44>(public_der, data, sig_bytes, context)
        }
        MlDsaVariant::MlDsa65 => {
            pq_ml_dsa_verify::<ml_dsa::MlDsa65>(public_der, data, sig_bytes, context)
        }
        MlDsaVariant::MlDsa87 => {
            pq_ml_dsa_verify::<ml_dsa::MlDsa87>(public_der, data, sig_bytes, context)
        }
    }
}

/// Verify with ML-DSA (FIPS 204).
#[cfg(feature = "post-quantum")]
fn pq_ml_dsa_verify<P>(
    public_der: &[u8],
    data: &[u8],
    sig_bytes: &[u8],
    context: &[u8],
) -> Result<bool>
where
    P: ml_dsa::MlDsaParams,
    P: pkcs8::spki::AssociatedAlgorithmIdentifier<Params = pkcs8::der::AnyRef<'static>>,
{
    use pkcs8::spki::DecodePublicKey;
    let vk = ml_dsa::VerifyingKey::<P>::from_public_key_der(public_der)
        .map_err(|e| Error::Key(format!("failed to parse ML-DSA public key: {e}")))?;
    let encoded_sig = ml_dsa::EncodedSignature::<P>::try_from(sig_bytes)
        .map_err(|_| Error::Crypto("invalid ML-DSA signature length".into()))?;
    let sig = ml_dsa::Signature::<P>::decode(&encoded_sig)
        .ok_or_else(|| Error::Crypto("failed to decode ML-DSA signature".into()))?;
    Ok(vk.verify_with_context(data, context, &sig))
}

/// Generate a fresh ML-DSA (FIPS 204) key pair.
///
/// Returns an opaque [`crate::SoftwareKey`] carrying:
/// - `algorithm`: `PqAlgorithm::MlDsa(variant)`.
/// - `private_der`: the 32-byte FIPS 204 seed (the durable secret).
///   `ExpandedSigningKey` is derived on demand by the sign path.
/// - `public_der`: the SPKI DER encoding of the verifying key.
///
/// Entropy is drawn directly from the OS via [`getrandom::fill`],
/// matching the signing path's [`getrandom::SysRng`] usage so the crate
/// has a single RNG policy for post-quantum operations. See
/// `docs/adr/0001-rng-choice.md`.
///
/// Zeroization: the stack-resident 32-byte seed buffer is wiped
/// immediately after it is copied into `private_der`. The heap-resident
/// private material is either moved into the returned [`crate::SoftwareKey`]
/// (whose custom [`Drop`] plus `ZeroizeOnDrop` marker wipe the seed on
/// drop) or, on any error return below, wiped explicitly before the
/// error propagates — so the seed does not linger in any allocation on
/// either exit path.
#[cfg(feature = "post-quantum")]
pub fn generate_ml_dsa(variant: crate::algorithm::MlDsaVariant) -> Result<OpaqueSoftwareKey> {
    use crate::algorithm::{MlDsaVariant, PqAlgorithm};
    use pkcs8::spki::EncodePublicKey;
    use zeroize::Zeroize;

    let mut seed_bytes = [0u8; 32];
    if let Err(e) = getrandom::fill(&mut seed_bytes) {
        seed_bytes.zeroize();
        return Err(Error::Crypto(format!("OS entropy draw failed: {e}")));
    }

    // Copy the seed into a heap-owned Vec now so every subsequent error
    // path wipes a single, well-defined allocation. The stack copy is
    // wiped immediately; from this point on, the only live copy of the
    // seed lives in `private_der` until it is either moved into the
    // `SoftwareKey` or explicitly zeroized on an error path.
    let mut private_der = seed_bytes.to_vec();
    seed_bytes.zeroize();

    fn encode_public<P>(seed: &ml_dsa::Seed) -> Result<Vec<u8>>
    where
        P: ml_dsa::MlDsaParams,
        P: pkcs8::spki::AssociatedAlgorithmIdentifier<Params = pkcs8::der::AnyRef<'static>>,
    {
        let sk = ml_dsa::ExpandedSigningKey::<P>::from_seed(seed);
        let vk = sk.verifying_key();
        let der = vk
            .to_public_key_der()
            .map_err(|e| Error::Crypto(format!("ML-DSA SPKI encode: {e}")))?;
        Ok(der.as_bytes().to_vec())
    }

    let build = || -> Result<Vec<u8>> {
        let seed = ml_dsa::Seed::try_from(private_der.as_slice())
            .map_err(|e| Error::Crypto(format!("ML-DSA seed construction failed: {e}")))?;
        match variant {
            MlDsaVariant::MlDsa44 => encode_public::<ml_dsa::MlDsa44>(&seed),
            MlDsaVariant::MlDsa65 => encode_public::<ml_dsa::MlDsa65>(&seed),
            MlDsaVariant::MlDsa87 => encode_public::<ml_dsa::MlDsa87>(&seed),
        }
    };
    let public_der = match build() {
        Ok(der) => der,
        Err(e) => {
            private_der.zeroize();
            return Err(e);
        }
    };

    Ok(SoftwareKey::PostQuantum {
        algorithm: PqAlgorithm::MlDsa(variant),
        private_der: Some(private_der),
        public_der,
    }
    .into())
}

// ── Post-quantum: SLH-DSA (FIPS 205) ───────────────────────────────

#[cfg(feature = "post-quantum")]
fn pq_slh_dsa_sign_dispatch(
    key: &SoftwareKey,
    variant: crate::algorithm::SlhDsaVariant,
    data: &[u8],
    context: &[u8],
) -> Result<Vec<u8>> {
    use crate::algorithm::SlhDsaVariant;
    let SoftwareKey::PostQuantum {
        private_der: Some(private),
        ..
    } = key
    else {
        return Err(Error::Key(format!(
            "{} private key required for signing",
            variant.name()
        )));
    };
    match variant {
        SlhDsaVariant::Sha2_128f => pq_slh_dsa_sign::<slh_dsa::Sha2_128f>(private, data, context),
        SlhDsaVariant::Sha2_128s => pq_slh_dsa_sign::<slh_dsa::Sha2_128s>(private, data, context),
        SlhDsaVariant::Sha2_192f => pq_slh_dsa_sign::<slh_dsa::Sha2_192f>(private, data, context),
        SlhDsaVariant::Sha2_192s => pq_slh_dsa_sign::<slh_dsa::Sha2_192s>(private, data, context),
        SlhDsaVariant::Sha2_256f => pq_slh_dsa_sign::<slh_dsa::Sha2_256f>(private, data, context),
        SlhDsaVariant::Sha2_256s => pq_slh_dsa_sign::<slh_dsa::Sha2_256s>(private, data, context),
    }
}

/// Sign with SLH-DSA (FIPS 205).
///
/// `private_der` may be either a full PKCS#8 DER document (RustCrypto format)
/// or just the raw key bytes (OpenSSL format, extracted by the loader).
#[cfg(feature = "post-quantum")]
fn pq_slh_dsa_sign<P>(private_der: &[u8], data: &[u8], context: &[u8]) -> Result<Vec<u8>>
where
    P: slh_dsa::ParameterSet,
{
    let sk = load_slh_dsa_signing_key::<P>(private_der)?;
    let sig = sk
        .try_sign_with_context(data, context, None)
        .map_err(|e| Error::Crypto(format!("SLH-DSA sign failed: {e}")))?;
    Ok(sig.to_bytes().to_vec())
}

#[cfg(feature = "post-quantum")]
fn pq_slh_dsa_verify_dispatch(
    key: &SoftwareKey,
    variant: crate::algorithm::SlhDsaVariant,
    data: &[u8],
    sig_bytes: &[u8],
    context: &[u8],
) -> Result<bool> {
    use crate::algorithm::SlhDsaVariant;
    let SoftwareKey::PostQuantum { public_der, .. } = key else {
        return Err(Error::Key(format!(
            "{} key required for verification",
            variant.name()
        )));
    };
    match variant {
        SlhDsaVariant::Sha2_128f => {
            pq_slh_dsa_verify::<slh_dsa::Sha2_128f>(public_der, data, sig_bytes, context)
        }
        SlhDsaVariant::Sha2_128s => {
            pq_slh_dsa_verify::<slh_dsa::Sha2_128s>(public_der, data, sig_bytes, context)
        }
        SlhDsaVariant::Sha2_192f => {
            pq_slh_dsa_verify::<slh_dsa::Sha2_192f>(public_der, data, sig_bytes, context)
        }
        SlhDsaVariant::Sha2_192s => {
            pq_slh_dsa_verify::<slh_dsa::Sha2_192s>(public_der, data, sig_bytes, context)
        }
        SlhDsaVariant::Sha2_256f => {
            pq_slh_dsa_verify::<slh_dsa::Sha2_256f>(public_der, data, sig_bytes, context)
        }
        SlhDsaVariant::Sha2_256s => {
            pq_slh_dsa_verify::<slh_dsa::Sha2_256s>(public_der, data, sig_bytes, context)
        }
    }
}

/// Verify with SLH-DSA (FIPS 205).
#[cfg(feature = "post-quantum")]
fn pq_slh_dsa_verify<P>(
    public_der: &[u8],
    data: &[u8],
    sig_bytes: &[u8],
    context: &[u8],
) -> Result<bool>
where
    P: slh_dsa::ParameterSet,
{
    use pkcs8::spki::DecodePublicKey;
    let vk = slh_dsa::VerifyingKey::<P>::from_public_key_der(public_der)
        .map_err(|e| Error::Key(format!("failed to parse SLH-DSA public key: {e}")))?;
    let sig = slh_dsa::Signature::<P>::try_from(sig_bytes)
        .map_err(|e| Error::Crypto(format!("invalid SLH-DSA signature: {e}")))?;
    Ok(vk.try_verify_with_context(data, context, &sig).is_ok())
}

// ── PQ key loaders ──────────────────────────────────────────────────

/// Validate ML-DSA / SLH-DSA key encodings during import: the SPKI must
/// parse, and when a private key is present the public key derived from it
/// must equal the imported one.
#[cfg(feature = "post-quantum")]
pub(crate) fn validate_pq_import(
    algorithm: crate::algorithm::PqAlgorithm,
    private_der: Option<&[u8]>,
    public_der: &[u8],
) -> Result<()> {
    use crate::algorithm::{MlDsaVariant, PqAlgorithm, SlhDsaVariant};
    use pkcs8::spki::DecodePublicKey;

    fn ml_dsa<P>(private_der: Option<&[u8]>, public_der: &[u8]) -> Result<bool>
    where
        P: ml_dsa::MlDsaParams,
        P: pkcs8::spki::AssociatedAlgorithmIdentifier<Params = pkcs8::der::AnyRef<'static>>,
    {
        let vk = ml_dsa::VerifyingKey::<P>::from_public_key_der(public_der)
            .map_err(|e| Error::Key(format!("failed to parse ML-DSA public key: {e}")))?;
        let Some(private_der) = private_der else {
            return Ok(true);
        };
        let sk = load_ml_dsa_signing_key::<P>(private_der)?;
        Ok(sk.verifying_key().encode() == vk.encode())
    }

    fn slh_dsa<P: slh_dsa::ParameterSet>(
        private_der: Option<&[u8]>,
        public_der: &[u8],
    ) -> Result<bool> {
        let vk = slh_dsa::VerifyingKey::<P>::from_public_key_der(public_der)
            .map_err(|e| Error::Key(format!("failed to parse SLH-DSA public key: {e}")))?;
        let Some(private_der) = private_der else {
            return Ok(true);
        };
        // An SLH-DSA private key embeds its public key, so recompute the
        // root from the secret seeds (FIPS 205 slh_keygen_internal) rather
        // than trusting the embedded copy.
        let sk = load_slh_dsa_signing_key::<P>(private_der)?;
        let bytes = zeroize::Zeroizing::new(sk.to_bytes());
        let n = bytes.len() / 4; // SK.seed || SK.prf || PK.seed || PK.root
        let derived = slh_dsa::SigningKey::<P>::slh_keygen_internal(
            &bytes[..n],
            &bytes[n..2 * n],
            &bytes[2 * n..3 * n],
        );
        Ok(derived.as_ref() == &vk && sk.as_ref() == &vk)
    }

    let matches = match algorithm {
        PqAlgorithm::MlDsa(MlDsaVariant::MlDsa44) => {
            ml_dsa::<ml_dsa::MlDsa44>(private_der, public_der)
        }
        PqAlgorithm::MlDsa(MlDsaVariant::MlDsa65) => {
            ml_dsa::<ml_dsa::MlDsa65>(private_der, public_der)
        }
        PqAlgorithm::MlDsa(MlDsaVariant::MlDsa87) => {
            ml_dsa::<ml_dsa::MlDsa87>(private_der, public_der)
        }
        PqAlgorithm::SlhDsa(SlhDsaVariant::Sha2_128f) => {
            slh_dsa::<slh_dsa::Sha2_128f>(private_der, public_der)
        }
        PqAlgorithm::SlhDsa(SlhDsaVariant::Sha2_128s) => {
            slh_dsa::<slh_dsa::Sha2_128s>(private_der, public_der)
        }
        PqAlgorithm::SlhDsa(SlhDsaVariant::Sha2_192f) => {
            slh_dsa::<slh_dsa::Sha2_192f>(private_der, public_der)
        }
        PqAlgorithm::SlhDsa(SlhDsaVariant::Sha2_192s) => {
            slh_dsa::<slh_dsa::Sha2_192s>(private_der, public_der)
        }
        PqAlgorithm::SlhDsa(SlhDsaVariant::Sha2_256f) => {
            slh_dsa::<slh_dsa::Sha2_256f>(private_der, public_der)
        }
        PqAlgorithm::SlhDsa(SlhDsaVariant::Sha2_256s) => {
            slh_dsa::<slh_dsa::Sha2_256s>(private_der, public_der)
        }
        PqAlgorithm::MlKem(_) => {
            return Err(Error::Key(format!(
                "{} is not a signature algorithm",
                algorithm.name()
            )))
        }
    }?;
    if !matches {
        return Err(Error::Key(format!(
            "{} public key does not match the private key",
            algorithm.name()
        )));
    }
    Ok(())
}

/// Load an ML-DSA signing key from either PKCS#8 DER or a 32-byte seed.
#[cfg(feature = "post-quantum")]
fn load_ml_dsa_signing_key<P>(private_der: &[u8]) -> Result<ml_dsa::ExpandedSigningKey<P>>
where
    P: ml_dsa::MlDsaParams,
    P: pkcs8::spki::AssociatedAlgorithmIdentifier<Params = pkcs8::der::AnyRef<'static>>,
{
    // Try full PKCS#8 DER first (RustCrypto format)
    use pkcs8::DecodePrivateKey;
    if let Ok(sk) = ml_dsa::ExpandedSigningKey::<P>::from_pkcs8_der(private_der) {
        return Ok(sk);
    }
    // Fall back to 32-byte seed (from OpenSSL format, extracted by loader)
    if private_der.len() == 32 {
        let seed = ml_dsa::Seed::try_from(private_der)
            .map_err(|_| Error::Key("invalid ML-DSA seed length".into()))?;
        return Ok(ml_dsa::ExpandedSigningKey::<P>::from_seed(&seed));
    }
    Err(Error::Key(format!(
        "failed to parse ML-DSA private key: expected PKCS#8 DER or 32-byte seed, got {} bytes",
        private_der.len()
    )))
}

/// Load an SLH-DSA signing key from either PKCS#8 DER or raw key bytes.
#[cfg(feature = "post-quantum")]
fn load_slh_dsa_signing_key<P>(private_der: &[u8]) -> Result<slh_dsa::SigningKey<P>>
where
    P: slh_dsa::ParameterSet,
{
    use pkcs8::DecodePrivateKey;
    if let Ok(sk) = slh_dsa::SigningKey::<P>::from_pkcs8_der(private_der) {
        return Ok(sk);
    }
    slh_dsa::SigningKey::<P>::try_from(private_der)
        .map_err(|e| Error::Key(format!("failed to parse SLH-DSA private key: {e}")))
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {

    /// Infallible `CryptoRng` view of the OS RNG for test fixtures that demand one.
    fn test_rng() -> rand_core::UnwrapErr<getrandom::SysRng> {
        rand_core::UnwrapErr(getrandom::SysRng)
    }
    use super::*;
    use crate::traits::{Signer, Verifier};

    /// Every exposed SLH-DSA key type must retain the dependency's wiping destructor.
    #[cfg(feature = "post-quantum")]
    #[test]
    fn slh_dsa_signing_keys_zeroize_on_drop() {
        fn requires_wiping_drop<T: zeroize::ZeroizeOnDrop>() {
            assert!(std::mem::needs_drop::<T>());
        }
        requires_wiping_drop::<slh_dsa::SigningKey<slh_dsa::Sha2_128f>>();
        requires_wiping_drop::<slh_dsa::SigningKey<slh_dsa::Sha2_128s>>();
        requires_wiping_drop::<slh_dsa::SigningKey<slh_dsa::Sha2_192f>>();
        requires_wiping_drop::<slh_dsa::SigningKey<slh_dsa::Sha2_192s>>();
        requires_wiping_drop::<slh_dsa::SigningKey<slh_dsa::Sha2_256f>>();
        requires_wiping_drop::<slh_dsa::SigningKey<slh_dsa::Sha2_256s>>();
    }

    /// Wiping typed keys preserves signing through both raw and PKCS#8 import paths.
    #[cfg(feature = "post-quantum")]
    #[test]
    fn slh_dsa_raw_and_pkcs8_signatures_roundtrip() {
        use crate::algorithm::{PqAlgorithm, SlhDsaVariant};
        use pkcs8::{spki::EncodePublicKey, EncodePrivateKey};
        let sk = slh_dsa::SigningKey::<slh_dsa::Sha2_128f>::slh_keygen_internal(
            &[1; 16], &[2; 16], &[3; 16],
        );
        let vk: &slh_dsa::VerifyingKey<_> = sk.as_ref();
        let public = vk.to_public_key_der().unwrap();
        let raw = zeroize::Zeroizing::new(sk.to_bytes());
        let pkcs8 = sk.to_pkcs8_der().unwrap();
        let algorithm = SignatureAlgorithm::SlhDsa(SlhDsaVariant::Sha2_128f);
        for private in [raw.as_slice(), pkcs8.as_bytes()] {
            let key = OpaqueSoftwareKey::from_post_quantum_der(
                PqAlgorithm::SlhDsa(SlhDsaVariant::Sha2_128f),
                Some(private),
                public.as_bytes(),
            )
            .unwrap();
            let signer = SoftwareSigner::new(algorithm, key.clone()).unwrap();
            let verifier = SoftwareVerifier::new(algorithm, key).unwrap();
            let signature = signer.sign(b"SLH-DSA zeroizing key control").unwrap();
            assert!(verifier
                .verify(b"SLH-DSA zeroizing key control", &signature)
                .unwrap());
            assert!(!verifier.verify(b"different message", &signature).unwrap());
        }
    }

    #[test]
    fn ed25519_roundtrip() {
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::generate(&mut test_rng());
        let vk = sk.verifying_key();

        let sign_key = SoftwareKey::Ed25519 {
            private: Some(sk.clone()),
            public: vk,
        };
        let signer =
            SoftwareSigner::new(SignatureAlgorithm::Ed25519, sign_key).expect("signer creation");
        let data = b"The quick brown fox jumps over the lazy dog";
        let signature = signer.sign(data).expect("signing should succeed");

        // Verify with public-only key
        let verify_key = SoftwareKey::Ed25519 {
            private: None,
            public: vk,
        };
        let verifier = SoftwareVerifier::new(SignatureAlgorithm::Ed25519, verify_key)
            .expect("verifier creation");
        assert!(
            verifier.verify(data, &signature).unwrap(),
            "Ed25519 roundtrip should verify"
        );

        // Tampered data should fail
        assert!(
            !verifier.verify(b"tampered data", &signature).unwrap(),
            "Ed25519 verification of tampered data should return false"
        );
    }

    /// Malleability regression: strict verification must reject a signature
    /// whose low-order part has been mangled. The well-known low-order `R`
    /// encoding `\x00...\x00` (identity element) is invalid under
    /// [RFC 8032 §5.1.7] rules that `verify_strict` enforces.
    ///
    /// Pre-fix (plain `verify`), some constructions of low-order-R
    /// signatures could verify against any message, enabling signature
    /// malleability / "bug attacks" on consensus-critical callers.
    #[test]
    fn ed25519_rejects_low_order_r() {
        use ed25519_dalek::Verifier as _;

        // Small-order public key A and small-order R, both the identity
        // point (compressed y = 1), with s = 0. Cofactorless `verify`
        // recomputes R' = [s]B - [k]A = identity for every message and so
        // accepts this signature; `verify_strict` rejects the weak A / R.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&identity).expect("identity decodes");
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&identity);
        let message = b"any message at all";

        // Pin the premise: the permissive check really does accept it.
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        assert!(
            vk.verify(message, &sig).is_ok(),
            "plain verify should accept"
        );

        let verify_key = SoftwareKey::Ed25519 {
            private: None,
            public: vk,
        };
        let verifier = SoftwareVerifier::new(SignatureAlgorithm::Ed25519, verify_key)
            .expect("verifier creation");
        let result = verifier.verify(message, &sig_bytes).unwrap();
        assert!(!result, "low-order R signature must not verify");
    }

    fn rsa_key(bits: usize) -> SoftwareKey {
        let private = rsa::RsaPrivateKey::new(&mut test_rng(), bits).unwrap();
        let public = private.to_public_key();
        SoftwareKey::Rsa {
            private: Some(private),
            public,
        }
    }

    /// Public-only RSA key whose modulus has exactly `bits` significant bits.
    ///
    /// `rsa` refuses to *generate* keys below 1024 bits, but the PSS encoding
    /// bounds are a pure function of the modulus width, so a synthetic odd
    /// modulus `2^(bits-1) + 1` exercises them without a real key pair.
    fn rsa_public_with_bits(bits: usize) -> SoftwareKey {
        let mut modulus = vec![0u8; bits.div_ceil(8)];
        modulus[0] = 1 << ((bits - 1) % 8);
        *modulus.last_mut().unwrap() |= 1;
        let public = rsa::RsaPublicKey::new(
            rsa::BoxedUint::from_be_slice_vartime(&modulus),
            rsa::BoxedUint::from(65_537u32),
        )
        .unwrap();
        SoftwareKey::Rsa {
            private: None,
            public,
        }
    }

    #[cfg(not(feature = "legacy"))]
    #[test]
    fn rsa_keys_below_2048_bits_are_rejected() {
        let algorithm = SignatureAlgorithm::RsaPss(HashAlgorithm::Sha256);
        let err = match SoftwareSigner::new(algorithm, rsa_key(1024)) {
            Ok(_) => panic!("1024-bit RSA signer should be rejected"),
            Err(e) => e,
        };
        assert!(
            matches!(err, Error::UnsupportedAlgorithm { operation: Operation::Sign(_), ref algorithm, .. }
                if algorithm.contains("1024-bit RSA key")),
            "got {err:?}"
        );
        let err = match SoftwareVerifier::new(algorithm, rsa_key(1024)) {
            Ok(_) => panic!("1024-bit RSA verifier should be rejected"),
            Err(e) => e,
        };
        assert!(
            matches!(
                err,
                Error::UnsupportedAlgorithm {
                    operation: Operation::Verify(_),
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    /// Distinguish impossible PSS encodings from exact zero-salt capacity.
    #[test]
    fn rsa_pss_capacity_includes_hash_and_trailer() {
        for (bits, expected) in [(512, None), (520, None), (528, Some(0)), (536, Some(1))] {
            let key = rsa_public_with_bits(bits);
            assert_eq!(
                rsa_pss_max_salt_len(extract_rsa_public(&key).unwrap(), HashAlgorithm::Sha512),
                expected,
            );
        }
    }

    /// Legacy mode still rejects impossible encodings before creating a verifier.
    #[cfg(feature = "legacy")]
    #[test]
    fn rsa_pss_legacy_rejects_hash_larger_than_encoding() {
        let key = OpaqueSoftwareKey::from(rsa_public_with_bits(512));
        for salt in [0, 1, usize::MAX] {
            let result =
                SoftwareVerifier::new_rsa_pss_with_salt(HashAlgorithm::Sha512, salt, key.clone());
            assert!(
                matches!(result, Err(Error::Key(ref message)) if message.contains("too small"))
            );
        }
        // SHA-256 does fit this key, including an explicitly empty salt.
        assert!(SoftwareVerifier::new_rsa_pss_with_salt(HashAlgorithm::Sha256, 0, key).is_ok());
        let exact = OpaqueSoftwareKey::from(rsa_public_with_bits(528));
        assert!(
            SoftwareVerifier::new_rsa_pss_with_salt(HashAlgorithm::Sha512, 0, exact.clone())
                .is_ok()
        );
        assert!(SoftwareVerifier::new_rsa_pss_with_salt(HashAlgorithm::Sha512, 1, exact).is_err());
    }

    #[test]
    fn rsa_pss_salt_len_is_bounded() {
        // 2048-bit modulus: emLen = 256, so SHA-256 allows 256 - 32 - 2 = 222.
        let key = OpaqueSoftwareKey::from(rsa_key(2048));
        let signer = SoftwareSigner::new(
            SignatureAlgorithm::RsaPss(HashAlgorithm::Sha256),
            key.clone(),
        )
        .unwrap();
        let signature = signer.sign(b"data").unwrap();

        let verifier =
            SoftwareVerifier::new_rsa_pss_with_salt(HashAlgorithm::Sha256, 222, key.clone())
                .expect("maximum salt length accepted");
        assert!(!verifier.verify(b"data", &signature).unwrap());
        // The default signer uses a hash-length salt.
        let verifier =
            SoftwareVerifier::new_rsa_pss_with_salt(HashAlgorithm::Sha256, 32, key.clone())
                .unwrap();
        assert!(verifier.verify(b"data", &signature).unwrap());

        for salt_len in [223, usize::MAX] {
            let err = match SoftwareVerifier::new_rsa_pss_with_salt(
                HashAlgorithm::Sha256,
                salt_len,
                key.clone(),
            ) {
                Ok(_) => panic!("salt length {salt_len} should be rejected"),
                Err(e) => e,
            };
            assert!(err.to_string().contains("salt length"), "{err}");
        }
    }

    #[test]
    fn hmac_sha256_roundtrip() {
        let secret = b"super-secret-key-for-hmac-testing";
        let algo = SignatureAlgorithm::Hmac(HashAlgorithm::Sha256);

        let sign_key = SoftwareKey::Hmac(secret.to_vec());
        let signer = SoftwareSigner::new(algo, sign_key).expect("signer creation");
        let data = b"message to authenticate";
        let mac = signer.sign(data).expect("HMAC should succeed");
        assert_eq!(mac.len(), 32, "SHA-256 HMAC output should be 32 bytes");

        let verify_key = SoftwareKey::Hmac(secret.to_vec());
        let verifier = SoftwareVerifier::new(algo, verify_key).expect("verifier creation");
        assert!(
            verifier.verify(data, &mac).unwrap(),
            "HMAC roundtrip should verify"
        );

        // Wrong key should fail
        let wrong_key = SoftwareKey::Hmac(b"wrong-key".to_vec());
        let wrong_verifier = SoftwareVerifier::new(algo, wrong_key).expect("verifier creation");
        assert!(
            !wrong_verifier.verify(data, &mac).unwrap(),
            "HMAC with wrong key should fail"
        );
    }

    #[test]
    fn hmac_rejects_empty_key() {
        let err = match SoftwareSigner::new(
            SignatureAlgorithm::Hmac(HashAlgorithm::Sha256),
            SoftwareKey::Hmac(Vec::new()),
        ) {
            Ok(_) => panic!("empty HMAC key should be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("must not be empty"), "{err}");

        let err = match SoftwareVerifier::new(
            SignatureAlgorithm::Hmac(HashAlgorithm::Sha256),
            SoftwareKey::Hmac(Vec::new()),
        ) {
            Ok(_) => panic!("empty HMAC key should be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("must not be empty"), "{err}");
    }

    #[test]
    fn new_with_pq_context_rejects_non_pq_algorithm() {
        let key = SoftwareKey::Hmac(b"shhh".to_vec());
        let err = match SoftwareSigner::new_with_pq_context(
            SignatureAlgorithm::Hmac(HashAlgorithm::Sha256),
            key,
            b"protocol-v1",
        ) {
            Ok(_) => panic!("non-PQ algorithm with context should be rejected"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("does not accept a context"),
            "{err}"
        );
    }

    #[test]
    fn key_algorithm_mismatch_rejected() {
        let key = SoftwareKey::Hmac(b"key".to_vec());
        let result = SoftwareSigner::new(SignatureAlgorithm::Ed25519, key);
        assert!(
            result.is_err(),
            "HMAC key with Ed25519 algorithm should fail"
        );

        let key = SoftwareKey::Ed25519 {
            private: None,
            public: ed25519_dalek::SigningKey::generate(&mut test_rng()).verifying_key(),
        };
        let result = SoftwareSigner::new(SignatureAlgorithm::Ed25519, key);
        assert!(
            result.is_err(),
            "Ed25519 public-only key should fail for signing"
        );
    }

    /// Randomization regression: ML-DSA signing moved from
    /// `sign_deterministic` to `sign_randomized` (see
    /// `docs/adr/0001-rng-choice.md`). Two signatures over the same
    /// message with the same key must therefore differ, and both must
    /// still verify — this test locks in both properties so that a
    /// future refactor cannot silently revert to the deterministic
    /// path.
    ///
    /// ML-DSA-44 is used because it's the smallest parameter set;
    /// this test runs in well under a second.
    #[cfg(feature = "post-quantum")]
    #[test]
    fn ml_dsa_44_sign_is_randomized_and_verifies() {
        use crate::algorithm::{MlDsaVariant, PqAlgorithm};
        use pkcs8::spki::EncodePublicKey;

        // Fixed seed — this is a test; determinism in key material is
        // fine because the property we're asserting is randomness in
        // the *signature*, not in the key.
        let seed_bytes = [0x42u8; 32];
        let seed = ml_dsa::Seed::try_from(&seed_bytes[..]).expect("32 bytes");
        let expanded_sk = ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa44>::from_seed(&seed);
        let public_der = expanded_sk
            .verifying_key()
            .to_public_key_der()
            .expect("public key DER encoding")
            .to_vec();

        let sign_key = SoftwareKey::PostQuantum {
            algorithm: PqAlgorithm::MlDsa(MlDsaVariant::MlDsa44),
            private_der: Some(seed_bytes.to_vec()),
            public_der: public_der.clone(),
        };
        let signer =
            SoftwareSigner::new(SignatureAlgorithm::MlDsa(MlDsaVariant::MlDsa44), sign_key)
                .expect("signer creation");

        let data = b"FIPS 204 randomized signing property test";
        let sig1 = signer.sign(data).expect("first sign");
        let sig2 = signer.sign(data).expect("second sign");

        assert_ne!(
            sig1, sig2,
            "ML-DSA sign_randomized must produce different signatures \
             for the same message — if this fires, someone reverted \
             pq_ml_dsa_sign to sign_deterministic"
        );

        let verify_key = SoftwareKey::PostQuantum {
            algorithm: PqAlgorithm::MlDsa(MlDsaVariant::MlDsa44),
            private_der: None,
            public_der,
        };
        let verifier =
            SoftwareVerifier::new(SignatureAlgorithm::MlDsa(MlDsaVariant::MlDsa44), verify_key)
                .expect("verifier creation");

        assert!(
            verifier.verify(data, &sig1).expect("verify call"),
            "first signature must verify"
        );
        assert!(
            verifier.verify(data, &sig2).expect("verify call"),
            "second signature must verify"
        );
    }

    /// `generate_ml_dsa` round-trip: the returned key must sign and
    /// verify against itself, at every security level. This also
    /// covers the `public_der` SPKI encoding path (which feeds the
    /// verifier) and the seed-based signer loader (which feeds the
    /// signer).
    #[cfg(feature = "post-quantum")]
    #[test]
    fn generate_ml_dsa_round_trips_all_variants() {
        use crate::algorithm::MlDsaVariant;
        for variant in [
            MlDsaVariant::MlDsa44,
            MlDsaVariant::MlDsa65,
            MlDsaVariant::MlDsa87,
        ] {
            let key = generate_ml_dsa(variant).expect("generate_ml_dsa");
            let SoftwareKey::PostQuantum {
                private_der,
                public_der,
                ..
            } = key.inner()
            else {
                panic!("generate_ml_dsa returned non-PQ SoftwareKey");
            };
            assert_eq!(
                private_der.as_ref().map(Vec::len),
                Some(32),
                "{} private must be a 32-byte seed",
                variant.name()
            );
            assert!(
                !public_der.is_empty(),
                "{} public_der must be populated",
                variant.name()
            );

            // ML-DSA-87 blows the default 2 MiB debug-build thread
            // stack during ExpandedSigningKey derivation + sign; the
            // other two variants fit. Spawn ML-DSA-87 on an 8 MiB
            // thread to match the jose-rs test harness convention.
            let data = b"generate_ml_dsa round-trip";
            let signer = SoftwareSigner::new(
                SignatureAlgorithm::MlDsa(variant),
                clone_pq_key(key.inner()),
            )
            .expect("signer");
            let verifier = SoftwareVerifier::new(
                SignatureAlgorithm::MlDsa(variant),
                clone_pq_key(key.inner()),
            )
            .expect("verifier");

            let run = move || {
                let sig = signer.sign(data).expect("sign");
                assert!(verifier.verify(data, &sig).expect("verify call"));
            };
            if matches!(variant, MlDsaVariant::MlDsa87) {
                std::thread::Builder::new()
                    .stack_size(8 * 1024 * 1024)
                    .spawn(run)
                    .expect("spawn")
                    .join()
                    .expect("join");
            } else {
                run();
            }
        }
    }

    #[cfg(feature = "post-quantum")]
    fn clone_pq_key(key: &SoftwareKey) -> SoftwareKey {
        let SoftwareKey::PostQuantum {
            algorithm,
            private_der,
            public_der,
        } = key
        else {
            panic!("expected PostQuantum");
        };
        SoftwareKey::PostQuantum {
            algorithm: *algorithm,
            private_der: private_der.clone(),
            public_der: public_der.clone(),
        }
    }

    /// Two successive `generate_ml_dsa` calls must produce different
    /// seeds. Smoke-tests that the RNG isn't returning constant bytes.
    #[cfg(feature = "post-quantum")]
    #[test]
    fn generate_ml_dsa_seeds_are_unique() {
        use crate::algorithm::MlDsaVariant;
        let a = generate_ml_dsa(MlDsaVariant::MlDsa44).unwrap();
        let b = generate_ml_dsa(MlDsaVariant::MlDsa44).unwrap();
        let (
            SoftwareKey::PostQuantum {
                private_der: pa, ..
            },
            SoftwareKey::PostQuantum {
                private_der: pb, ..
            },
        ) = (a.inner(), b.inner())
        else {
            panic!("unexpected variant");
        };
        assert_ne!(pa, pb, "two generate_ml_dsa calls must differ");
    }

    // RFC 8032 §7.4 Ed448 test vectors.
    const ED448_BLANK_SEED: &str = "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b";
    const ED448_BLANK_PUBLIC: &str = "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180";
    const ED448_BLANK_SIG: &str = "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600";
    const ED448_ONE_SEED: &str = "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e";
    const ED448_ONE_PUBLIC: &str = "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480";
    const ED448_ONE_SIG: &str = "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00";
    /// Same key and message as `ED448_ONE_SIG`, but signed with context "foo".
    const ED448_ONE_CTX_FOO_SIG: &str = "d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85741de5c8da1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d5428407e85dcbc98a49155c13764e66c3c00";

    fn ed448_keys(seed_hex: &str, public_hex: &str) -> (SoftwareKey, SoftwareKey) {
        let seed = hex::decode(seed_hex).unwrap();
        let sk = ed448_goldilocks::SigningKey::try_from(seed.as_slice()).unwrap();
        let vk = sk.verifying_key();
        assert_eq!(vk.to_bytes().as_slice(), hex::decode(public_hex).unwrap());
        (
            SoftwareKey::Ed448 {
                private: Some(Box::new(sk)),
                public: vk,
            },
            SoftwareKey::Ed448 {
                private: None,
                public: vk,
            },
        )
    }

    /// Invariant: pure Ed448 signing is deterministic and byte-identical to
    /// the RFC 8032 §7.4 vectors; both key shapes verify them.
    #[test]
    fn ed448_matches_rfc8032_vectors() {
        for (seed, public, message, expected) in [
            (
                ED448_BLANK_SEED,
                ED448_BLANK_PUBLIC,
                &b""[..],
                ED448_BLANK_SIG,
            ),
            (ED448_ONE_SEED, ED448_ONE_PUBLIC, &[0x03][..], ED448_ONE_SIG),
        ] {
            let (private, _) = ed448_keys(seed, public);
            let signer = SoftwareSigner::new(SignatureAlgorithm::Ed448, private).unwrap();
            let signature = signer.sign(message).unwrap();
            assert_eq!(signature.len(), 114);
            assert_eq!(hex::encode(&signature), expected);
            let (private, public) = ed448_keys(seed, public);
            for key in [private, public] {
                let verifier = SoftwareVerifier::new(SignatureAlgorithm::Ed448, key).unwrap();
                assert!(verifier.verify(message, &signature).unwrap());
                assert!(!verifier.verify(b"tampered", &signature).unwrap());
            }
        }
    }

    /// Invariant: the context string is fixed to "" (RFC 8410 / JOSE), so a
    /// signature made with a non-empty context does not verify, and callers
    /// cannot supply one through the post-quantum context path.
    #[test]
    fn ed448_is_pure_with_empty_context_only() {
        let (private, public) = ed448_keys(ED448_ONE_SEED, ED448_ONE_PUBLIC);
        let verifier = SoftwareVerifier::new(SignatureAlgorithm::Ed448, public).unwrap();
        let ctx_signature = hex::decode(ED448_ONE_CTX_FOO_SIG).unwrap();
        assert!(!verifier.verify(&[0x03], &ctx_signature).unwrap());
        assert!(
            SoftwareSigner::new_with_pq_context(SignatureAlgorithm::Ed448, private, b"foo")
                .is_err()
        );
    }

    /// Invariant: malformed signature lengths are errors (not `false`), and
    /// keys of another family are rejected at construction.
    #[test]
    fn ed448_rejects_malformed_signatures_and_foreign_keys() {
        let (_, public) = ed448_keys(ED448_BLANK_SEED, ED448_BLANK_PUBLIC);
        let verifier = SoftwareVerifier::new(SignatureAlgorithm::Ed448, public).unwrap();
        let good = hex::decode(ED448_BLANK_SIG).unwrap();
        assert!(matches!(
            verifier.verify(b"", &good[..113]),
            Err(Error::Crypto(_))
        ));
        let mut long = good.clone();
        long.push(0);
        assert!(matches!(verifier.verify(b"", &long), Err(Error::Crypto(_))));
        assert!(
            SoftwareSigner::new(SignatureAlgorithm::Ed448, SoftwareKey::Hmac(vec![1; 32])).is_err()
        );
        let (ed25519, _) = {
            let sk = ed25519_dalek::SigningKey::generate(&mut test_rng());
            let vk = sk.verifying_key();
            (
                SoftwareKey::Ed25519 {
                    private: Some(sk),
                    public: vk,
                },
                (),
            )
        };
        assert!(SoftwareSigner::new(SignatureAlgorithm::Ed448, ed25519).is_err());
    }

    fn secp256k1_keys() -> (SoftwareKey, SoftwareKey) {
        use p256::elliptic_curve::Generate;
        let sk = k256::ecdsa::SigningKey::generate_from_rng(&mut test_rng());
        let vk = *sk.verifying_key();
        (
            SoftwareKey::EcSecp256k1 {
                private: Some(sk),
                public: vk,
            },
            SoftwareKey::EcSecp256k1 {
                private: None,
                public: vk,
            },
        )
    }

    /// Invariant: ES256K signatures are emitted low-S (BIP-62) and both the
    /// low-S and the equivalent high-S encoding verify, so signatures from
    /// providers that do not normalize (AWS-LC, OpenSSL, tokens) are accepted.
    #[test]
    fn secp256k1_emits_low_s_and_accepts_high_s() {
        let (private, public) = secp256k1_keys();
        let algorithm = SignatureAlgorithm::Ecdsa(EcCurve::Secp256k1, HashAlgorithm::Sha256);
        let signature = SoftwareSigner::new(algorithm, private)
            .unwrap()
            .sign(b"ES256K")
            .unwrap();
        assert_eq!(signature.len(), 64);
        let parsed = digest::raw_to_k256_sig(&signature).unwrap();
        assert_eq!(parsed.normalize_s(), parsed, "signer must emit low-S");

        // Build the high-S twin: s' = n - s.
        let order = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
            .unwrap();
        let s = &signature[32..];
        let mut high = vec![0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let diff = i16::from(order[i]) - i16::from(s[i]) - borrow;
            borrow = i16::from(diff < 0);
            high[i] = (diff + 256 * borrow) as u8;
        }
        let mut high_s = signature[..32].to_vec();
        high_s.extend(high);
        assert_ne!(high_s, signature);
        let verifier = SoftwareVerifier::new(algorithm, public).unwrap();
        assert!(verifier.verify(b"ES256K", &signature).unwrap());
        assert!(verifier.verify(b"ES256K", &high_s).unwrap());
        assert!(!verifier.verify(b"tampered", &signature).unwrap());
        let der = digest::ecdsa_raw_to_der(EcCurve::Secp256k1, &signature).unwrap();
        assert!(verifier.verify_der_signature(b"ES256K", &der).unwrap());
    }

    /// Invariant: the no-policy rule applies to secp256k1 too (any hash is
    /// accepted by the primitive layer), and foreign keys are rejected.
    #[test]
    fn secp256k1_accepts_any_hash_and_rejects_foreign_keys() {
        let (private, public) = secp256k1_keys();
        let algorithm = SignatureAlgorithm::Ecdsa(EcCurve::Secp256k1, HashAlgorithm::Sha512);
        let signature = SoftwareSigner::new(algorithm, private)
            .unwrap()
            .sign(b"x")
            .unwrap();
        assert!(SoftwareVerifier::new(algorithm, public)
            .unwrap()
            .verify(b"x", &signature)
            .unwrap());
        let (p256_private, _) = {
            use p256::elliptic_curve::Generate;
            let sk = p256::ecdsa::SigningKey::generate_from_rng(&mut test_rng());
            let vk = *sk.verifying_key();
            (
                SoftwareKey::EcP256 {
                    private: Some(sk),
                    public: vk,
                },
                (),
            )
        };
        assert!(SoftwareSigner::new(
            SignatureAlgorithm::Ecdsa(EcCurve::Secp256k1, HashAlgorithm::Sha256),
            p256_private
        )
        .is_err());
    }

    /// Invariant: Brainpool ECDSA round-trips with raw and DER encodings,
    /// signatures are 2x field width, and foreign keys are rejected.
    #[test]
    fn brainpool_ecdsa_roundtrip() {
        use p256::elliptic_curve::Generate;
        let sk = ecdsa::SigningKey::<bp256::BrainpoolP256r1>::generate_from_rng(&mut test_rng());
        let vk = *sk.verifying_key();
        let private = SoftwareKey::EcBrainpoolP256r1 {
            private: Some(sk),
            public: vk,
        };
        let public = SoftwareKey::EcBrainpoolP256r1 {
            private: None,
            public: vk,
        };
        let algorithm = SignatureAlgorithm::Ecdsa(EcCurve::BrainpoolP256r1, HashAlgorithm::Sha256);
        let signature = SoftwareSigner::new(algorithm, private)
            .unwrap()
            .sign(b"brainpool")
            .unwrap();
        assert_eq!(signature.len(), 64);
        let verifier = SoftwareVerifier::new(algorithm, public).unwrap();
        assert!(verifier.verify(b"brainpool", &signature).unwrap());
        assert!(!verifier.verify(b"tampered", &signature).unwrap());
        let der = digest::ecdsa_raw_to_der(EcCurve::BrainpoolP256r1, &signature).unwrap();
        assert!(verifier.verify_der_signature(b"brainpool", &der).unwrap());

        let sk = ecdsa::SigningKey::<bp384::BrainpoolP384r1>::generate_from_rng(&mut test_rng());
        let vk = *sk.verifying_key();
        let key384 = SoftwareKey::EcBrainpoolP384r1 {
            private: Some(sk),
            public: vk,
        };
        let algorithm384 =
            SignatureAlgorithm::Ecdsa(EcCurve::BrainpoolP384r1, HashAlgorithm::Sha384);
        // A P384r1 key is not a P256r1 key.
        assert!(SoftwareSigner::new(algorithm, key384).is_err());
        let sk = ecdsa::SigningKey::<bp384::BrainpoolP384r1>::generate_from_rng(&mut test_rng());
        let vk = *sk.verifying_key();
        let signature = SoftwareSigner::new(
            algorithm384,
            SoftwareKey::EcBrainpoolP384r1 {
                private: Some(sk),
                public: vk,
            },
        )
        .unwrap()
        .sign(b"brainpool")
        .unwrap();
        assert_eq!(signature.len(), 96);
        assert!(SoftwareVerifier::new(
            algorithm384,
            SoftwareKey::EcBrainpoolP384r1 {
                private: None,
                public: vk,
            },
        )
        .unwrap()
        .verify(b"brainpool", &signature)
        .unwrap());
    }
}
