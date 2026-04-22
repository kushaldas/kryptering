//! PKCS#11 hardware security module backend.
//!
//! This module is gated behind the `pkcs11` feature (enabled by default).
//! It provides [`Pkcs11Provider`] for managing a PKCS#11 library and slot,
//! [`Pkcs11Session`] for authenticated sessions, and concrete implementations
//! of the core crypto traits ([`Signer`], [`Verifier`], [`Decryptor`],
//! [`Encryptor`], [`KeyWrapper`], [`KeyAgreement`]) backed by token objects.

use crate::algorithm::{
    CipherAlgorithm, HashAlgorithm, KeyTransportAlgorithm, KeyWrapAlgorithm, SignatureAlgorithm,
};
use crate::error::{Error, Result};
use crate::traits::{Decryptor, Encryptor, KeyAgreement, KeyWrapper, Signer, Verifier};

use cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};

use std::path::Path;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Provider & session
// ---------------------------------------------------------------------------

/// Manages a PKCS#11 library and slot.
pub struct Pkcs11Provider {
    pkcs11: cryptoki::context::Pkcs11,
    slot: cryptoki::slot::Slot,
}

impl Pkcs11Provider {
    /// Load a PKCS#11 library from `library_path`, initialize it, and select
    /// the first slot with an initialized token.
    ///
    /// If the library has already been initialized — either by another
    /// `Pkcs11Provider` in the same process or by a non-kryptering PKCS#11
    /// user — `C_Initialize` returning `CKR_CRYPTOKI_ALREADY_INITIALIZED` is
    /// treated as success. Creating multiple providers over the same library
    /// path is therefore safe; the first call wins, the others no-op on the
    /// init step.
    pub fn new(library_path: &Path) -> Result<Self> {
        use cryptoki::error::{Error as CrError, RvError};
        let pkcs11 = cryptoki::context::Pkcs11::new(library_path)
            .map_err(|e| Error::Pkcs11(format!("failed to load PKCS#11 library: {e}")))?;
        match pkcs11.initialize(cryptoki::context::CInitializeArgs::OsThreads) {
            Ok(()) => {}
            Err(CrError::AlreadyInitialized) => {}
            Err(CrError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
            Err(e) => return Err(Error::Pkcs11(format!("C_Initialize failed: {e}"))),
        }
        let slots = pkcs11
            .get_slots_with_initialized_token()
            .map_err(|e| Error::Pkcs11(format!("C_GetSlotList failed: {e}")))?;
        let slot = slots
            .into_iter()
            .next()
            .ok_or_else(|| Error::Pkcs11("no slots with initialized token found".into()))?;
        Ok(Self { pkcs11, slot })
    }

    /// Open a read-write session and log in with the given UTF-8 PIN.
    ///
    /// Internally the PIN is handed to `cryptoki::types::AuthPin` which
    /// wraps it in `secrecy::SecretString` (zeroizes on drop). The caller
    /// is responsible for wiping its own `pin` buffer after the call.
    ///
    /// For tokens that accept non-UTF-8 byte PINs, use
    /// [`open_session_bytes`](Self::open_session_bytes).
    pub fn open_session(&self, pin: &str) -> Result<Pkcs11Session> {
        self.open_session_bytes(pin.as_bytes())
    }

    /// Open a read-write session and log in with a raw-byte PIN.
    ///
    /// PKCS#11 `C_Login` defines the PIN as an arbitrary UTF-8 octet
    /// string (PKCS#11 v2.40 §11.6) but some tokens accept binary PINs
    /// in practice. This entrypoint lets the caller pass bytes directly;
    /// non-UTF-8 bytes are rejected because cryptoki 0.7's `AuthPin`
    /// stores a `SecretString` internally.
    ///
    /// Zeroization contract: the caller's `pin` slice is not wiped by
    /// this function — wipe it in the caller. The intermediate `String`
    /// built here moves into `AuthPin`/`SecretString` which zeroizes on
    /// drop.
    pub fn open_session_bytes(&self, pin: &[u8]) -> Result<Pkcs11Session> {
        let pin_str = std::str::from_utf8(pin)
            .map_err(|e| Error::Pkcs11(format!("PKCS#11 PIN must be valid UTF-8: {e}")))?;
        let session = self
            .pkcs11
            .open_rw_session(self.slot)
            .map_err(|e| Error::Pkcs11(format!("C_OpenSession failed: {e}")))?;
        session
            .login(
                cryptoki::session::UserType::User,
                Some(&cryptoki::types::AuthPin::new(pin_str.to_owned())),
            )
            .map_err(|e| Error::Pkcs11(format!("C_Login failed: {e}")))?;
        Ok(Pkcs11Session {
            session: Arc::new(Mutex::new(session)),
        })
    }
}

/// An authenticated PKCS#11 session.
///
/// The inner session is wrapped in `Arc<Mutex<..>>` so that concrete
/// trait objects (`Pkcs11Signer`, etc.) can share it while satisfying
/// the `Send + Sync` requirements of the crypto traits.
pub struct Pkcs11Session {
    session: Arc<Mutex<cryptoki::session::Session>>,
}

impl Pkcs11Session {
    /// Find a private key by label.
    pub fn find_private_key(&self, label: &str) -> Result<ObjectHandle> {
        self.find_object(label, ObjectClass::PRIVATE_KEY)
    }

    /// Find a public key by label.
    pub fn find_public_key(&self, label: &str) -> Result<ObjectHandle> {
        self.find_object(label, ObjectClass::PUBLIC_KEY)
    }

    /// Find a secret (symmetric) key by label.
    pub fn find_secret_key(&self, label: &str) -> Result<ObjectHandle> {
        self.find_object(label, ObjectClass::SECRET_KEY)
    }

    /// Get a reference to the underlying (locked) cryptoki session.
    pub fn session(&self) -> &Arc<Mutex<cryptoki::session::Session>> {
        &self.session
    }

    // Internal helper shared by the three public `find_*` methods.
    fn find_object(&self, label: &str, class: ObjectClass) -> Result<ObjectHandle> {
        let template = vec![
            Attribute::Class(class),
            Attribute::Label(label.as_bytes().to_vec()),
        ];
        let session = self
            .session
            .lock()
            .map_err(|e| Error::Pkcs11(format!("session lock poisoned: {e}")))?;
        let objects = session
            .find_objects(&template)
            .map_err(|e| Error::Pkcs11(format!("C_FindObjects failed: {e}")))?;
        objects
            .into_iter()
            .next()
            .ok_or_else(|| Error::Pkcs11(format!("no {class} object found with label \"{label}\"")))
    }
}

// ---------------------------------------------------------------------------
// Algorithm -> Mechanism mapping
// ---------------------------------------------------------------------------

/// Map a [`SignatureAlgorithm`] to the corresponding cryptoki [`Mechanism`].
///
/// For RSA PKCS#1 v1.5 and RSA-PSS the mechanism includes hashing, so the
/// caller passes raw (unhashed) data.  For `Ecdsa` we return `CKM_ECDSA`
/// (raw), which expects **pre-hashed** data.
#[allow(unreachable_patterns)] // feature-gated variants (Dsa, MlDsa, SlhDsa) may not exist
fn signature_mechanism(algo: &SignatureAlgorithm) -> Result<Mechanism<'static>> {
    match algo {
        SignatureAlgorithm::RsaPkcs1v15(hash) => match hash {
            HashAlgorithm::Sha1 => Ok(Mechanism::Sha1RsaPkcs),
            HashAlgorithm::Sha256 => Ok(Mechanism::Sha256RsaPkcs),
            HashAlgorithm::Sha384 => Ok(Mechanism::Sha384RsaPkcs),
            HashAlgorithm::Sha512 => Ok(Mechanism::Sha512RsaPkcs),
            other => Err(Error::UnsupportedAlgorithm(format!(
                "RSA PKCS#1 v1.5 with {other:?} not supported via PKCS#11"
            ))),
        },
        SignatureAlgorithm::RsaPss(hash) => {
            let (hash_mech, mgf, s_len) = pss_params_for(*hash)?;
            let pss = PkcsPssParams {
                hash_alg: hash_mech,
                mgf,
                s_len: s_len.into(),
            };
            match hash {
                HashAlgorithm::Sha1 => Ok(Mechanism::Sha1RsaPkcsPss(pss)),
                HashAlgorithm::Sha256 => Ok(Mechanism::Sha256RsaPkcsPss(pss)),
                HashAlgorithm::Sha384 => Ok(Mechanism::Sha384RsaPkcsPss(pss)),
                HashAlgorithm::Sha512 => Ok(Mechanism::Sha512RsaPkcsPss(pss)),
                other => Err(Error::UnsupportedAlgorithm(format!(
                    "RSA-PSS with {other:?} not supported via PKCS#11"
                ))),
            }
        }
        // CKM_ECDSA (raw) -- caller must pre-hash.
        SignatureAlgorithm::Ecdsa(_, _) => Ok(Mechanism::Ecdsa),
        SignatureAlgorithm::Ed25519 => Ok(Mechanism::Eddsa),
        SignatureAlgorithm::Hmac(hash) => match hash {
            // cryptoki 0.7 only exposes Sha256Hmac as a named Mechanism variant.
            // SHA-1/384/512 HMAC MechanismType constants exist but have no
            // corresponding Mechanism enum variant, so they are unsupported until
            // cryptoki is upgraded.
            HashAlgorithm::Sha256 => Ok(Mechanism::Sha256Hmac),
            other => Err(Error::UnsupportedAlgorithm(format!(
                "HMAC with {other:?} not supported via PKCS#11 (cryptoki 0.7 \
                 only exposes SHA-256 HMAC)"
            ))),
        },
        other => Err(Error::UnsupportedAlgorithm(format!(
            "{other:?} not supported via PKCS#11"
        ))),
    }
}

/// Return `(hash_mechanism_type, mgf, salt_len)` for RSA-PSS.
fn pss_params_for(hash: HashAlgorithm) -> Result<(MechanismType, PkcsMgfType, u64)> {
    match hash {
        HashAlgorithm::Sha1 => Ok((MechanismType::SHA1, PkcsMgfType::MGF1_SHA1, 20)),
        HashAlgorithm::Sha256 => Ok((MechanismType::SHA256, PkcsMgfType::MGF1_SHA256, 32)),
        HashAlgorithm::Sha384 => Ok((MechanismType::SHA384, PkcsMgfType::MGF1_SHA384, 48)),
        HashAlgorithm::Sha512 => Ok((MechanismType::SHA512, PkcsMgfType::MGF1_SHA512, 64)),
        other => Err(Error::UnsupportedAlgorithm(format!(
            "RSA-PSS with {other:?}"
        ))),
    }
}

/// Build an RSA-OAEP [`Mechanism`] from an [`OaepConfig`](crate::algorithm::OaepConfig)
/// and an optional OAEP label.
///
/// An earlier version ignored any label the caller configured and unconditionally
/// used `PkcsOaepSource::empty()`. That left the PKCS#11 and software backends
/// producing mutually-incompatible OAEP ciphertexts whenever a label was in use.
fn oaep_mechanism<'a>(
    cfg: &crate::algorithm::OaepConfig,
    label: Option<&'a [u8]>,
) -> Result<Mechanism<'a>> {
    let hash_mech = hash_to_mechanism_type(cfg.digest)?;
    let mgf = hash_to_mgf(cfg.mgf_digest)?;
    let source = match label {
        Some(bytes) => PkcsOaepSource::data_specified(bytes),
        None => PkcsOaepSource::empty(),
    };
    let params = PkcsOaepParams::new(hash_mech, mgf, source);
    Ok(Mechanism::RsaPkcsOaep(params))
}

fn hash_to_mechanism_type(h: HashAlgorithm) -> Result<MechanismType> {
    match h {
        HashAlgorithm::Sha1 => Ok(MechanismType::SHA1),
        HashAlgorithm::Sha256 => Ok(MechanismType::SHA256),
        HashAlgorithm::Sha384 => Ok(MechanismType::SHA384),
        HashAlgorithm::Sha512 => Ok(MechanismType::SHA512),
        other => Err(Error::UnsupportedAlgorithm(format!(
            "hash {other:?} not supported for PKCS#11 OAEP"
        ))),
    }
}

fn hash_to_mgf(h: HashAlgorithm) -> Result<PkcsMgfType> {
    match h {
        HashAlgorithm::Sha1 => Ok(PkcsMgfType::MGF1_SHA1),
        HashAlgorithm::Sha256 => Ok(PkcsMgfType::MGF1_SHA256),
        HashAlgorithm::Sha384 => Ok(PkcsMgfType::MGF1_SHA384),
        HashAlgorithm::Sha512 => Ok(PkcsMgfType::MGF1_SHA512),
        other => Err(Error::UnsupportedAlgorithm(format!(
            "MGF with {other:?} not supported"
        ))),
    }
}

/// Prepare the data that will be passed to `C_Sign` / `C_Verify`.
///
/// For ECDSA (CKM_ECDSA) the token expects a pre-computed hash; for all
/// other mechanisms the token performs hashing internally.
fn prepare_sign_data(algo: &SignatureAlgorithm, data: &[u8]) -> Vec<u8> {
    match algo {
        SignatureAlgorithm::Ecdsa(_, hash) => crate::digest::digest(*hash, data),
        _ => data.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Signer
// ---------------------------------------------------------------------------

/// Signs data using a private key held on a PKCS#11 token.
pub struct Pkcs11Signer {
    session: Arc<Mutex<cryptoki::session::Session>>,
    key_handle: ObjectHandle,
    algorithm: SignatureAlgorithm,
}

impl Pkcs11Signer {
    /// Create a new signer that will use the private key identified by
    /// `key_label` on the given session.
    pub fn new(
        session: &Pkcs11Session,
        key_label: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<Self> {
        let key_handle = session.find_private_key(key_label)?;
        Ok(Self {
            session: Arc::clone(&session.session),
            key_handle,
            algorithm,
        })
    }
}

impl Signer for Pkcs11Signer {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mechanism = signature_mechanism(&self.algorithm)?;
        let sign_data = prepare_sign_data(&self.algorithm, data);
        let session = self
            .session
            .lock()
            .map_err(|e| Error::Pkcs11(format!("session lock poisoned: {e}")))?;
        session
            .sign(&mechanism, self.key_handle, &sign_data)
            .map_err(|e| Error::Pkcs11(format!("C_Sign failed: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// Verifies signatures using a public key held on a PKCS#11 token.
pub struct Pkcs11Verifier {
    session: Arc<Mutex<cryptoki::session::Session>>,
    key_handle: ObjectHandle,
    algorithm: SignatureAlgorithm,
}

impl Pkcs11Verifier {
    /// Create a new verifier that will use the public key identified by
    /// `key_label` on the given session.
    pub fn new(
        session: &Pkcs11Session,
        key_label: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<Self> {
        let key_handle = session.find_public_key(key_label)?;
        Ok(Self {
            session: Arc::clone(&session.session),
            key_handle,
            algorithm,
        })
    }
}

impl Verifier for Pkcs11Verifier {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        let mechanism = signature_mechanism(&self.algorithm)?;
        let verify_data = prepare_sign_data(&self.algorithm, data);
        let session = self
            .session
            .lock()
            .map_err(|e| Error::Pkcs11(format!("session lock poisoned: {e}")))?;
        match session.verify(&mechanism, self.key_handle, &verify_data, signature) {
            Ok(()) => Ok(true),
            Err(cryptoki::error::Error::Pkcs11(cryptoki::error::RvError::SignatureInvalid, _)) => {
                Ok(false)
            }
            Err(cryptoki::error::Error::Pkcs11(cryptoki::error::RvError::SignatureLenRange, _)) => {
                Ok(false)
            }
            Err(e) => Err(Error::Pkcs11(format!("C_Verify failed: {e}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// HMAC Signer + Verifier (symmetric key)
// ---------------------------------------------------------------------------

/// Signs and verifies HMAC using a secret key held on a PKCS#11 token.
///
/// HMAC uses a symmetric (secret) key rather than an asymmetric key pair,
/// so a single object serves as both [`Signer`] and [`Verifier`].
pub struct Pkcs11HmacSigner {
    session: Arc<Mutex<cryptoki::session::Session>>,
    key_handle: ObjectHandle,
    algorithm: SignatureAlgorithm,
}

impl Pkcs11HmacSigner {
    /// Create a new HMAC signer/verifier.  `key_label` identifies the
    /// generic-secret (HMAC) key on the token.
    pub fn new(
        session: &Pkcs11Session,
        key_label: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<Self> {
        let key_handle = session.find_secret_key(key_label)?;
        Ok(Self {
            session: Arc::clone(&session.session),
            key_handle,
            algorithm,
        })
    }
}

impl Signer for Pkcs11HmacSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mechanism = signature_mechanism(&self.algorithm)?;
        let session = self
            .session
            .lock()
            .map_err(|e| Error::Pkcs11(format!("session lock poisoned: {e}")))?;
        session
            .sign(&mechanism, self.key_handle, data)
            .map_err(|e| Error::Pkcs11(format!("C_Sign (HMAC) failed: {e}")))
    }
}

impl Verifier for Pkcs11HmacSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        let mechanism = signature_mechanism(&self.algorithm)?;
        let session = self
            .session
            .lock()
            .map_err(|e| Error::Pkcs11(format!("session lock poisoned: {e}")))?;
        match session.verify(&mechanism, self.key_handle, data, signature) {
            Ok(()) => Ok(true),
            Err(cryptoki::error::Error::Pkcs11(cryptoki::error::RvError::SignatureInvalid, _)) => {
                Ok(false)
            }
            Err(cryptoki::error::Error::Pkcs11(cryptoki::error::RvError::SignatureLenRange, _)) => {
                Ok(false)
            }
            Err(e) => Err(Error::Pkcs11(format!("C_Verify (HMAC) failed: {e}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// Decryptor (RSA-OAEP key transport)
// ---------------------------------------------------------------------------

/// Decrypts data using a private key held on a PKCS#11 token (RSA-OAEP).
pub struct Pkcs11Decryptor {
    session: Arc<Mutex<cryptoki::session::Session>>,
    key_handle: ObjectHandle,
    algorithm: KeyTransportAlgorithm,
    /// Optional RSA-OAEP label bound at construction time. The PKCS#11
    /// `C_Decrypt` call reads the label via [`PkcsOaepSource`] inside the
    /// mechanism parameters, so callers who need label-bound OAEP
    /// interop with the software backend must supply it here.
    oaep_label: Option<Vec<u8>>,
}

impl Pkcs11Decryptor {
    /// Create a new decryptor without an OAEP label (equivalent to
    /// [`new_with_oaep_label`](Self::new_with_oaep_label) with `None`).
    pub fn new(
        session: &Pkcs11Session,
        key_label: &str,
        algorithm: KeyTransportAlgorithm,
    ) -> Result<Self> {
        Self::new_with_oaep_label(session, key_label, algorithm, None)
    }

    /// Create a new decryptor with an optional RSA-OAEP label. The label is
    /// threaded into the PKCS#11 mechanism parameters on every
    /// `decrypt` call via `PkcsOaepSource::data_specified`.
    pub fn new_with_oaep_label(
        session: &Pkcs11Session,
        key_label: &str,
        algorithm: KeyTransportAlgorithm,
        oaep_label: Option<Vec<u8>>,
    ) -> Result<Self> {
        let key_handle = session.find_private_key(key_label)?;
        Ok(Self {
            session: Arc::clone(&session.session),
            key_handle,
            algorithm,
            oaep_label,
        })
    }
}

impl Decryptor for Pkcs11Decryptor {
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mechanism = key_transport_mechanism(&self.algorithm, self.oaep_label.as_deref())?;
        let session = self
            .session
            .lock()
            .map_err(|e| Error::Pkcs11(format!("session lock poisoned: {e}")))?;
        session
            .decrypt(&mechanism, self.key_handle, ciphertext)
            .map_err(|e| Error::Pkcs11(format!("C_Decrypt failed: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Encryptor (RSA-OAEP key transport)
// ---------------------------------------------------------------------------

/// Encrypts data using a public key held on a PKCS#11 token (RSA-OAEP).
pub struct Pkcs11Encryptor {
    session: Arc<Mutex<cryptoki::session::Session>>,
    key_handle: ObjectHandle,
    algorithm: KeyTransportAlgorithm,
    /// Optional RSA-OAEP label bound at construction time. See
    /// [`Pkcs11Decryptor::new_with_oaep_label`] for rationale.
    oaep_label: Option<Vec<u8>>,
}

impl Pkcs11Encryptor {
    /// Create a new encryptor without an OAEP label (equivalent to
    /// [`new_with_oaep_label`](Self::new_with_oaep_label) with `None`).
    pub fn new(
        session: &Pkcs11Session,
        key_label: &str,
        algorithm: KeyTransportAlgorithm,
    ) -> Result<Self> {
        Self::new_with_oaep_label(session, key_label, algorithm, None)
    }

    /// Create a new encryptor with an optional RSA-OAEP label.
    pub fn new_with_oaep_label(
        session: &Pkcs11Session,
        key_label: &str,
        algorithm: KeyTransportAlgorithm,
        oaep_label: Option<Vec<u8>>,
    ) -> Result<Self> {
        let key_handle = session.find_public_key(key_label)?;
        Ok(Self {
            session: Arc::clone(&session.session),
            key_handle,
            algorithm,
            oaep_label,
        })
    }
}

impl Encryptor for Pkcs11Encryptor {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mechanism = key_transport_mechanism(&self.algorithm, self.oaep_label.as_deref())?;
        let session = self
            .session
            .lock()
            .map_err(|e| Error::Pkcs11(format!("session lock poisoned: {e}")))?;
        session
            .encrypt(&mechanism, self.key_handle, plaintext)
            .map_err(|e| Error::Pkcs11(format!("C_Encrypt failed: {e}")))
    }
}

/// Map a [`KeyTransportAlgorithm`] to the corresponding PKCS#11 mechanism.
///
/// `label` is only consulted for RSA-OAEP; the RSA PKCS#1 v1.5 mechanism has
/// no label concept and ignores the parameter.
fn key_transport_mechanism<'a>(
    algo: &KeyTransportAlgorithm,
    label: Option<&'a [u8]>,
) -> Result<Mechanism<'a>> {
    match algo {
        #[cfg(feature = "legacy")]
        KeyTransportAlgorithm::RsaPkcs1v15 => Ok(Mechanism::RsaPkcs),
        KeyTransportAlgorithm::RsaOaep(cfg) => oaep_mechanism(cfg, label),
    }
}

// ---------------------------------------------------------------------------
// KeyWrapper (AES key-wrap via C_Encrypt / C_Decrypt)
// ---------------------------------------------------------------------------

/// Wraps and unwraps keys using a KEK held on a PKCS#11 token.
///
/// Uses `C_Encrypt`/`C_Decrypt` with `CKM_AES_KEY_WRAP` (RFC 3394).
pub struct Pkcs11KeyWrapper {
    session: Arc<Mutex<cryptoki::session::Session>>,
    key_handle: ObjectHandle,
    algorithm: KeyWrapAlgorithm,
}

impl Pkcs11KeyWrapper {
    /// Create a new key wrapper.  `key_label` identifies the AES KEK on the
    /// token.
    pub fn new(
        session: &Pkcs11Session,
        key_label: &str,
        algorithm: KeyWrapAlgorithm,
    ) -> Result<Self> {
        let key_handle = session.find_secret_key(key_label)?;
        Ok(Self {
            session: Arc::clone(&session.session),
            key_handle,
            algorithm,
        })
    }
}

impl KeyWrapper for Pkcs11KeyWrapper {
    fn wrap(&self, key_data: &[u8]) -> Result<Vec<u8>> {
        let mechanism = keywrap_mechanism(&self.algorithm)?;
        let session = self
            .session
            .lock()
            .map_err(|e| Error::Pkcs11(format!("session lock poisoned: {e}")))?;
        session
            .encrypt(&mechanism, self.key_handle, key_data)
            .map_err(|e| Error::Pkcs11(format!("C_Encrypt (key wrap) failed: {e}")))
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>> {
        let mechanism = keywrap_mechanism(&self.algorithm)?;
        let session = self
            .session
            .lock()
            .map_err(|e| Error::Pkcs11(format!("session lock poisoned: {e}")))?;
        session
            .decrypt(&mechanism, self.key_handle, wrapped)
            .map_err(|e| Error::Pkcs11(format!("C_Decrypt (key unwrap) failed: {e}")))
    }
}

/// Map a [`KeyWrapAlgorithm`] to the corresponding PKCS#11 mechanism.
fn keywrap_mechanism(algo: &KeyWrapAlgorithm) -> Result<Mechanism<'static>> {
    match algo {
        KeyWrapAlgorithm::AesKw(_) => Ok(Mechanism::AesKeyWrap),
        #[cfg(feature = "legacy")]
        KeyWrapAlgorithm::TripleDesKw => Err(Error::UnsupportedAlgorithm(
            "3DES key wrap not supported via PKCS#11".into(),
        )),
    }
}

// ---------------------------------------------------------------------------
// KeyAgreement (ECDH)
// ---------------------------------------------------------------------------

/// Performs ECDH key agreement using a private key held on a PKCS#11 token.
///
/// Uses `CKM_ECDH1_DERIVE` with the null KDF.  The resulting derived key's
/// raw value is extracted via `C_GetAttributeValue(CKA_VALUE)`.
pub struct Pkcs11KeyAgreement {
    session: Arc<Mutex<cryptoki::session::Session>>,
    key_handle: ObjectHandle,
    /// Expected byte-length of the derived shared secret.
    key_len: usize,
}

impl Pkcs11KeyAgreement {
    /// Create a new key agreement object.  `key_label` identifies the EC
    /// private key on the token, and `key_len` is the expected shared secret
    /// size in bytes (e.g. 32 for P-256).
    pub fn new(session: &Pkcs11Session, key_label: &str, key_len: usize) -> Result<Self> {
        let key_handle = session.find_private_key(key_label)?;
        Ok(Self {
            session: Arc::clone(&session.session),
            key_handle,
            key_len,
        })
    }
}

impl KeyAgreement for Pkcs11KeyAgreement {
    fn agree(&self, peer_public_key: &[u8]) -> Result<Vec<u8>> {
        let ec_params = Ecdh1DeriveParams::new(EcKdf::null(), peer_public_key);
        let mechanism = Mechanism::Ecdh1Derive(ec_params);

        // Template for the derived generic-secret key so we can read its value.
        let template = vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(cryptoki::object::KeyType::GENERIC_SECRET),
            Attribute::Encrypt(false),
            Attribute::Decrypt(false),
            Attribute::ValueLen((self.key_len as u64).into()),
            Attribute::Extractable(true),
            Attribute::Sensitive(false),
        ];

        let session = self
            .session
            .lock()
            .map_err(|e| Error::Pkcs11(format!("session lock poisoned: {e}")))?;
        let derived_key = session
            .derive_key(&mechanism, self.key_handle, &template)
            .map_err(|e| Error::Pkcs11(format!("C_DeriveKey (ECDH) failed: {e}")))?;

        // Read CKA_VALUE from the derived key.
        let attrs = session
            .get_attributes(derived_key, &[AttributeType::Value])
            .map_err(|e| Error::Pkcs11(format!("C_GetAttributeValue failed: {e}")))?;

        for attr in attrs {
            if let Attribute::Value(v) = attr {
                // Best-effort cleanup of the temporary derived-key object.
                // Session-scoped secret keys are destroyed automatically when
                // the session closes (PKCS#11 v2.40 §5.3, CKA_TOKEN=false by
                // default from C_DeriveKey), so a failure here leaks only
                // until session close and is not a correctness concern. We
                // assert in debug builds to catch unexpected failures during
                // development; in release we accept the (temporary) leak.
                let destroy_result = session.destroy_object(derived_key);
                debug_assert!(
                    destroy_result.is_ok(),
                    "ECDH derived-key destroy failed: {destroy_result:?}"
                );
                return Ok(v);
            }
        }

        // Same best-effort cleanup on the failure path.
        let destroy_result = session.destroy_object(derived_key);
        debug_assert!(
            destroy_result.is_ok(),
            "ECDH derived-key destroy failed: {destroy_result:?}"
        );
        Err(Error::Pkcs11(
            "CKA_VALUE not present on derived ECDH key".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// AES Cipher (AES-CBC / AES-GCM via PKCS#11)
// ---------------------------------------------------------------------------

/// Encrypts and decrypts using an AES key held on a PKCS#11 token.
///
/// Supports [`CipherAlgorithm::AesCbc`] (`CKM_AES_CBC_PAD` with PKCS#7
/// padding) and [`CipherAlgorithm::AesGcm`] (`CKM_AES_GCM` with 128-bit
/// authentication tag).
///
/// The wire format matches the software backend: the IV/nonce is prepended
/// to the ciphertext on encrypt and stripped on decrypt.
///
/// * AES-CBC: 16-byte IV prefix
/// * AES-GCM: 12-byte nonce prefix, 16-byte auth tag appended by the token
pub struct Pkcs11Cipher {
    session: Arc<Mutex<cryptoki::session::Session>>,
    key_handle: ObjectHandle,
    algorithm: CipherAlgorithm,
}

impl Pkcs11Cipher {
    /// Create a new cipher.  `key_label` identifies the AES secret key on
    /// the token.
    pub fn new(
        session: &Pkcs11Session,
        key_label: &str,
        algorithm: CipherAlgorithm,
    ) -> Result<Self> {
        let key_handle = session.find_secret_key(key_label)?;
        Ok(Self {
            session: Arc::clone(&session.session),
            key_handle,
            algorithm,
        })
    }

    /// Encrypt `plaintext`, returning `IV/nonce || ciphertext` (with
    /// appended tag for GCM).
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let session = self
            .session
            .lock()
            .map_err(|e| Error::Pkcs11(format!("session lock poisoned: {e}")))?;
        match self.algorithm {
            CipherAlgorithm::AesCbc(_) => {
                let mut iv = [0u8; 16];
                session
                    .generate_random_slice(&mut iv)
                    .map_err(|e| Error::Pkcs11(format!("C_GenerateRandom failed: {e}")))?;
                let mechanism = Mechanism::AesCbcPad(iv);
                let ct = session
                    .encrypt(&mechanism, self.key_handle, plaintext)
                    .map_err(|e| Error::Pkcs11(format!("C_Encrypt (AES-CBC) failed: {e}")))?;
                let mut result = Vec::with_capacity(16 + ct.len());
                result.extend_from_slice(&iv);
                result.extend_from_slice(&ct);
                Ok(result)
            }
            CipherAlgorithm::AesGcm(_) => {
                let mut nonce = [0u8; 12];
                session
                    .generate_random_slice(&mut nonce)
                    .map_err(|e| Error::Pkcs11(format!("C_GenerateRandom failed: {e}")))?;
                let gcm_params = cryptoki::mechanism::aead::GcmParams::new(&nonce, &[], 128.into());
                let mechanism = Mechanism::AesGcm(gcm_params);
                let ct = session
                    .encrypt(&mechanism, self.key_handle, plaintext)
                    .map_err(|e| Error::Pkcs11(format!("C_Encrypt (AES-GCM) failed: {e}")))?;
                let mut result = Vec::with_capacity(12 + ct.len());
                result.extend_from_slice(&nonce);
                result.extend_from_slice(&ct);
                Ok(result)
            }
            #[cfg(feature = "legacy")]
            CipherAlgorithm::TripleDesCbc => Err(Error::UnsupportedAlgorithm(
                "3DES-CBC not supported via PKCS#11 cipher".into(),
            )),
        }
    }

    /// Decrypt `data` (expected format: `IV/nonce || ciphertext`), returning
    /// plaintext.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let session = self
            .session
            .lock()
            .map_err(|e| Error::Pkcs11(format!("session lock poisoned: {e}")))?;
        match self.algorithm {
            CipherAlgorithm::AesCbc(_) => {
                if data.len() < 32 {
                    return Err(Error::Crypto(
                        "AES-CBC ciphertext too short (need IV + at least one block)".into(),
                    ));
                }
                let mut iv = [0u8; 16];
                iv.copy_from_slice(&data[..16]);
                let ciphertext = &data[16..];
                let mechanism = Mechanism::AesCbcPad(iv);
                session
                    .decrypt(&mechanism, self.key_handle, ciphertext)
                    .map_err(|e| Error::Pkcs11(format!("C_Decrypt (AES-CBC) failed: {e}")))
            }
            CipherAlgorithm::AesGcm(_) => {
                // 12-byte nonce + at least 16-byte tag
                if data.len() < 12 + 16 {
                    return Err(Error::Crypto(
                        "AES-GCM ciphertext too short (need nonce + tag)".into(),
                    ));
                }
                let nonce = &data[..12];
                let ct_and_tag = &data[12..];
                let gcm_params = cryptoki::mechanism::aead::GcmParams::new(nonce, &[], 128.into());
                let mechanism = Mechanism::AesGcm(gcm_params);
                session
                    .decrypt(&mechanism, self.key_handle, ct_and_tag)
                    .map_err(|e| Error::Pkcs11(format!("C_Decrypt (AES-GCM) failed: {e}")))
            }
            #[cfg(feature = "legacy")]
            CipherAlgorithm::TripleDesCbc => Err(Error::UnsupportedAlgorithm(
                "3DES-CBC not supported via PKCS#11 cipher".into(),
            )),
        }
    }
}
