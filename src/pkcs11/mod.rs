//! PKCS#11 hardware security module backend.
//!
//! This module is gated behind the `pkcs11` feature (enabled by default).
//! It provides [`Pkcs11Provider`] for managing a PKCS#11 library and slot,
//! [`Pkcs11Session`] for authenticated sessions, and concrete implementations
//! of the core crypto traits ([`Signer`], [`Verifier`], [`Decryptor`],
//! [`Encryptor`], [`KeyWrapper`], [`KeyAgreement`]) backed by token objects.
//!
//! RSA operations require a readable `CKA_MODULUS` of at least 2048 bits.
//! Non-FIPS `legacy` builds permit 1024-bit RSA for historical documents.
//! The actual key is checked on every use, including private-key operations.

use crate::algorithm::{
    CipherAlgorithm, HashAlgorithm, KeyTransportAlgorithm, KeyWrapAlgorithm, SignatureAlgorithm,
};
use crate::backend::Operation;
use crate::error::{Error, Result};
use crate::traits::{Decryptor, Encryptor, KeyAgreement, KeyWrapper, Signer, Verifier};

use cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::slot::Slot;
use cryptoki::types::Ulong;
use zeroize::{Zeroize, Zeroizing};

mod context_cache;

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
    /// Load and initialize a configured module once, without selecting a token
    /// or opening an authenticated session. Useful during application startup.
    ///
    /// Successful contexts are retained until process exit; no explicit unload
    /// or finalization is performed. Other users of the same vendor module must
    /// not call C_Finalize while kryptering is using it. Initialization failures
    /// may be retried. Paths must resolve to existing files; symlink aliases
    /// share a context, but distinct hard-link paths are not deduplicated.
    ///
    /// Initialize after starting workers. After a fork of an initialized process,
    /// exec before using PKCS#11 in the child. Inherited providers, sessions and
    /// operation objects must not be used or dropped in that child.
    pub fn preload(library_path: &Path) -> Result<()> {
        load_initialized_context(library_path).map(|_| ())
    }

    /// Load a PKCS#11 library from `library_path`, initialize it, and select
    /// the only slot with an initialized token.
    ///
    /// If more than one initialized token is visible, this returns an error
    /// instead of silently selecting the first slot. Multi-token deployments
    /// should use [`new_with_slot_id`](Self::new_with_slot_id) or
    /// [`new_with_token`](Self::new_with_token) so the intended token identity
    /// is pinned by configuration.
    ///
    /// Module contexts are shared by canonical file path and retained until
    /// process exit. Repeated construction does not reload or reinitialize the
    /// module, but token selection is performed each time. See
    /// [`preload`](Self::preload) for lifecycle requirements.
    pub fn new(library_path: &Path) -> Result<Self> {
        let pkcs11 = load_initialized_context(library_path)?;
        let slots = pkcs11
            .get_slots_with_initialized_token()
            .map_err(|e| Error::Pkcs11(format!("C_GetSlotList failed: {e}")))?;
        let slot = select_single_initialized_slot(&slots)?;
        Ok(Self { pkcs11, slot })
    }

    /// Load a PKCS#11 library and bind to a specific initialized slot id.
    pub fn new_with_slot_id(library_path: &Path, slot_id: u64) -> Result<Self> {
        let pkcs11 = load_initialized_context(library_path)?;
        let slot = Slot::try_from(slot_id)
            .map_err(|e| Error::Pkcs11(format!("invalid PKCS#11 slot id {slot_id}: {e}")))?;
        let token_info = pkcs11
            .get_token_info(slot)
            .map_err(|e| Error::Pkcs11(format!("C_GetTokenInfo failed for slot {slot}: {e}")))?;
        if !token_info.token_initialized() {
            return Err(Error::Pkcs11(format!(
                "slot {slot} does not contain an initialized token"
            )));
        }
        Ok(Self { pkcs11, slot })
    }

    /// Load a PKCS#11 library and bind to a token identified by label and,
    /// optionally, serial number.
    ///
    /// Token label and serial are expected to come from trusted deployment
    /// configuration. If the selector matches zero or multiple tokens, the
    /// provider fails closed.
    pub fn new_with_token(
        library_path: &Path,
        token_label: &str,
        token_serial: Option<&str>,
    ) -> Result<Self> {
        let pkcs11 = load_initialized_context(library_path)?;
        let slots = pkcs11
            .get_slots_with_token()
            .map_err(|e| Error::Pkcs11(format!("C_GetSlotList failed: {e}")))?;
        let mut matches = Vec::new();
        for slot in slots {
            let token_info = pkcs11.get_token_info(slot).map_err(|e| {
                Error::Pkcs11(format!("C_GetTokenInfo failed for slot {slot}: {e}"))
            })?;
            if token_info.token_initialized()
                && token_info.label() == token_label
                && token_serial.is_none_or(|serial| token_info.serial_number() == serial)
            {
                matches.push(slot);
            }
        }
        let slot = select_unique_matching_token(&matches, token_label, token_serial)?;
        Ok(Self { pkcs11, slot })
    }

    /// Return the selected slot id.
    pub fn slot_id(&self) -> u64 {
        self.slot.id()
    }

    fn open_session_on_slot(&self, pin: &[u8], slot: Slot) -> Result<Pkcs11Session> {
        use cryptoki::error::{Error as CrError, RvError};
        MODULE_CONTEXTS.check_process()?;
        crate::backend::ensure_backend()?;
        let raw_pin = cryptoki::types::RawAuthPin::new(Box::new(pin.to_vec()));
        let session = self
            .pkcs11
            .open_rw_session(slot)
            .map_err(|e| Error::Pkcs11(format!("C_OpenSession failed: {e}")))?;
        match session.login_with_raw(cryptoki::session::UserType::User, &raw_pin) {
            Ok(()) => {}
            // PKCS#11 does not authenticate the supplied PIN in this case.
            // Raw sessions and external contexts can change login state without
            // notification, so no cached verifier can prove login continuity.
            Err(CrError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {
                return Err(Error::Pkcs11("cannot verify PIN: token already logged in; reuse the authenticated session or close all sessions before logging in again".into()));
            }
            Err(e) => return Err(Error::Pkcs11(format!("C_Login failed: {e}"))),
        }
        Ok(Pkcs11Session {
            session: Arc::new(Mutex::new(session)),
            pkcs11: self.pkcs11.clone(),
            slot,
        })
    }
}

static MODULE_CONTEXTS: context_cache::ModuleCache<cryptoki::context::Pkcs11> =
    context_cache::ModuleCache::new();

fn load_initialized_context(library_path: &Path) -> Result<cryptoki::context::Pkcs11> {
    MODULE_CONTEXTS.get_or_load(library_path, initialize_context)
}

fn initialize_context(library_path: &Path) -> Result<cryptoki::context::Pkcs11> {
    use cryptoki::context::{CInitializeArgs, CInitializeFlags};
    use cryptoki::error::{Error as CrError, RvError};
    let pkcs11 = cryptoki::context::Pkcs11::new(library_path)
        .map_err(|e| Error::Pkcs11(format!("failed to load PKCS#11 library: {e}")))?;
    // cryptoki 0.12 replaced the `OsThreads` shorthand with an explicit
    // `CInitializeFlags` bitset; `OS_LOCKING_OK` is the standard flag
    // telling the token that the application lets the library provide
    // its own OS-threaded locking, which matches the previous behaviour.
    match pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) => {}
        Err(CrError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
        Err(e) => return Err(Error::Pkcs11(format!("C_Initialize failed: {e}"))),
    }
    Ok(pkcs11)
}

fn select_single_initialized_slot(slots: &[Slot]) -> Result<Slot> {
    match slots {
        [] => Err(Error::Pkcs11(
            "no slots with initialized token found".into(),
        )),
        [slot] => Ok(*slot),
        _ => Err(Error::Pkcs11(format!(
            "multiple initialized token slots found ({}); use Pkcs11Provider::new_with_slot_id \
             or Pkcs11Provider::new_with_token to pin the intended token",
            format_slot_list(slots)
        ))),
    }
}

fn select_unique_matching_token(
    slots: &[Slot],
    token_label: &str,
    token_serial: Option<&str>,
) -> Result<Slot> {
    match slots {
        [] => Err(Error::Pkcs11(format!(
            "no initialized token matches label {token_label:?}{}",
            token_serial
                .map(|serial| format!(" and serial {serial:?}"))
                .unwrap_or_default()
        ))),
        [slot] => Ok(*slot),
        _ => Err(Error::Pkcs11(format!(
            "multiple initialized tokens match label {token_label:?}{} ({}); add a serial \
             number or select by slot id",
            token_serial
                .map(|serial| format!(" and serial {serial:?}"))
                .unwrap_or_default(),
            format_slot_list(slots)
        ))),
    }
}

fn format_slot_list(slots: &[Slot]) -> String {
    slots
        .iter()
        .map(|slot| slot.id().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

impl Pkcs11Provider {
    /// Open a read-write session and log in with the given UTF-8 PIN.
    ///
    /// Internally the PIN bytes are copied into a
    /// `cryptoki::types::RawAuthPin` (`secrecy::SecretBox<Vec<u8>>`, which
    /// zeroizes on drop). The caller is responsible for wiping its own
    /// `pin` buffer after the call.
    ///
    /// If the token is already logged in, this fails closed because `C_Login`
    /// does not authenticate the supplied PIN. Share the existing session among
    /// operations, or close all sessions before logging in again. See
    /// [`open_session_bytes`](Self::open_session_bytes).
    ///
    /// For tokens that accept non-UTF-8 byte PINs, use
    /// [`open_session_bytes`](Self::open_session_bytes).
    pub fn open_session(&self, pin: &str) -> Result<Pkcs11Session> {
        self.open_session_bytes(pin.as_bytes())
    }

    /// Open a read-write session and log in with a raw-byte PIN.
    ///
    /// PKCS#11 `C_Login` defines the PIN as a UTF-8 octet string
    /// (PKCS#11 v2.40 §11.6) but some tokens accept binary PINs in
    /// practice. This entrypoint passes the bytes to `C_Login` verbatim
    /// via cryptoki's `Session::login_with_raw`; no UTF-8 validation is
    /// performed.
    ///
    /// Zeroization contract: the caller's `pin` slice is not wiped by
    /// this function — wipe it in the caller. The intermediate copy
    /// built here lives in a `RawAuthPin` (`secrecy::SecretBox<Vec<u8>>`)
    /// which zeroizes on drop.
    ///
    /// Login state is shared by all sessions of this application on a token.
    /// `CKR_USER_ALREADY_LOGGED_IN` never checks the supplied PIN, so it always
    /// returns [`Error::Pkcs11`]. This includes logins originally established
    /// by kryptering: raw sessions and other contexts can log out, change the
    /// PIN, and log in again without notifying this library.
    ///
    /// Reuse an existing [`Pkcs11Session`] to construct multiple operation
    /// objects; they share its synchronized session. This function never logs
    /// out other sessions to force a PIN check. For a fresh login, close all
    /// sessions (including operation objects and external raw handles) first.
    /// FIPS builds require [`initialize_backend`](crate::initialize_backend)
    /// before opening a session.
    pub fn open_session_bytes(&self, pin: &[u8]) -> Result<Pkcs11Session> {
        self.open_session_on_slot(pin, self.slot)
    }
}

/// An authenticated PKCS#11 session.
///
/// The inner session is wrapped in `Arc<Mutex<..>>` so that concrete
/// trait objects (`Pkcs11Signer`, etc.) can share it while satisfying
/// the `Send + Sync` requirements of the crypto traits.
pub struct Pkcs11Session {
    session: Arc<Mutex<cryptoki::session::Session>>,
    /// Context and slot of the session, for mechanism queries.
    pkcs11: cryptoki::context::Pkcs11,
    slot: Slot,
}

impl Pkcs11Session {
    /// Find a private key by label.
    pub fn find_private_key(&self, label: &str) -> Result<ObjectHandle> {
        self.find_object(label, ObjectClass::PRIVATE_KEY, None)
    }

    /// Find a private key by label and `CKA_ID`.
    pub fn find_private_key_by_id(&self, label: &str, id: &[u8]) -> Result<ObjectHandle> {
        self.find_object(label, ObjectClass::PRIVATE_KEY, Some(id))
    }

    /// Find a public key by label.
    pub fn find_public_key(&self, label: &str) -> Result<ObjectHandle> {
        self.find_object(label, ObjectClass::PUBLIC_KEY, None)
    }

    /// Find a public key by label and `CKA_ID`.
    pub fn find_public_key_by_id(&self, label: &str, id: &[u8]) -> Result<ObjectHandle> {
        self.find_object(label, ObjectClass::PUBLIC_KEY, Some(id))
    }

    /// Find a secret (symmetric) key by label.
    pub fn find_secret_key(&self, label: &str) -> Result<ObjectHandle> {
        self.find_object(label, ObjectClass::SECRET_KEY, None)
    }

    /// Find a secret key by label and `CKA_ID`.
    pub fn find_secret_key_by_id(&self, label: &str, id: &[u8]) -> Result<ObjectHandle> {
        self.find_object(label, ObjectClass::SECRET_KEY, Some(id))
    }

    /// Get a reference to the underlying (locked) cryptoki session.
    pub fn session(&self) -> &Arc<Mutex<cryptoki::session::Session>> {
        &self.session
    }

    // Internal helper shared by the three public `find_*` methods.
    fn find_object(
        &self,
        label: &str,
        class: ObjectClass,
        id: Option<&[u8]>,
    ) -> Result<ObjectHandle> {
        let mut template = vec![
            Attribute::Class(class),
            Attribute::Label(label.as_bytes().to_vec()),
        ];
        if let Some(id) = id {
            template.push(Attribute::Id(id.to_vec()));
        }
        let session = self
            .session
            .lock()
            .map_err(|e| Error::Pkcs11(format!("session lock poisoned: {e}")))?;
        let mut objects = session
            .find_objects(&template)
            .map_err(|e| Error::Pkcs11(format!("C_FindObjects failed: {e}")))?;
        match objects.len() {
            0 => Err(Error::Pkcs11(format!(
                "no {class} object found with label {label:?}{}",
                id.map(|_| " and matching CKA_ID").unwrap_or_default()
            ))),
            1 => Ok(objects.remove(0)),
            n => Err(Error::Pkcs11(format!(
                "ambiguous {class} object lookup: {n} objects found with label {label:?}{}; \
                 use a unique label or the *_by_id lookup methods",
                id.map(|_| " and matching CKA_ID").unwrap_or_default()
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Algorithm -> Mechanism mapping
// ---------------------------------------------------------------------------

/// Enforce token RSA strength under the same session lock as the operation.
fn validate_rsa_key(
    session: &cryptoki::session::Session,
    key: ObjectHandle,
    operation: Operation,
) -> Result<()> {
    let rsa = matches!(
        operation,
        Operation::Sign(SignatureAlgorithm::RsaPkcs1v15(_) | SignatureAlgorithm::RsaPss(_))
            | Operation::Verify(SignatureAlgorithm::RsaPkcs1v15(_) | SignatureAlgorithm::RsaPss(_))
            | Operation::TransportEncrypt(_)
            | Operation::TransportDecrypt(_)
    );
    if !rsa {
        return Ok(());
    }
    let attrs = session
        .get_attributes(key, &[AttributeType::Modulus])
        .map_err(|e| Error::Pkcs11(format!("cannot read RSA CKA_MODULUS: {e}")))?;
    check_rsa_modulus(&attrs, operation)
}

/// Measure the significant modulus bits, failing closed on unavailable data.
fn check_rsa_modulus(attrs: &[Attribute], operation: Operation) -> Result<()> {
    let modulus = attrs.iter().find_map(|attr| match attr {
        Attribute::Modulus(value) => Some(value.as_slice()),
        _ => None,
    });
    let modulus = modulus
        .and_then(|value| {
            value
                .iter()
                .position(|byte| *byte != 0)
                .map(|i| &value[i..])
        })
        .ok_or_else(|| Error::Pkcs11("missing or zero RSA CKA_MODULUS".into()))?;
    let bits = (modulus.len() - 1)
        .checked_mul(8)
        .and_then(|bits| bits.checked_add(8 - modulus[0].leading_zeros() as usize))
        .ok_or_else(|| Error::Pkcs11("RSA CKA_MODULUS is too large".into()))?;
    let minimum = if cfg!(all(feature = "legacy", not(feature = "fips"))) {
        1024
    } else {
        2048
    };
    if bits < minimum {
        return Err(Error::unsupported(
            operation,
            format!("{bits}-bit RSA key (PKCS#11 requires at least {minimum} bits)"),
        ));
    }
    Ok(())
}

/// Curve family a PKCS#11 signature key lives on, read from `CKA_EC_PARAMS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignatureKeyCurve {
    /// Short-Weierstrass named curve (`CKK_EC`).
    Weierstrass(crate::algorithm::EcCurve),
    /// `CKK_EC_EDWARDS` edwards25519.
    Ed25519,
    /// `CKK_EC_EDWARDS` edwards448.
    Ed448,
    /// `CKK_EC_MONTGOMERY` curve25519 / curve448; agreement-only, never signs.
    Montgomery,
}

/// Curve a signature algorithm needs its key to be on, or `None` for
/// algorithms whose keys carry no `CKA_EC_PARAMS` (RSA, HMAC, post-quantum).
fn expected_signature_curve(algorithm: SignatureAlgorithm) -> Option<SignatureKeyCurve> {
    match algorithm {
        SignatureAlgorithm::Ecdsa(curve, _) => Some(SignatureKeyCurve::Weierstrass(curve)),
        SignatureAlgorithm::Ed25519 => Some(SignatureKeyCurve::Ed25519),
        SignatureAlgorithm::Ed448 => Some(SignatureKeyCurve::Ed448),
        _ => None,
    }
}

/// RFC 8410 id-Ed25519 / id-Ed448 as DER OIDs, plus the PrintableString
/// curve names PKCS#11 v3 permits (and SoftHSM2 emits) for Edwards keys.
const OID_DER_ED25519: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70]; // 1.3.101.112
const OID_DER_ED448: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x71]; // 1.3.101.113
const PRINTABLE_EDWARDS25519: &[u8] = b"\x13\x0cedwards25519";
const PRINTABLE_EDWARDS448: &[u8] = b"\x13\x0aedwards448";

/// Map `CKA_EC_PARAMS` of a signature key to its curve family. Explicit
/// parameters, unlisted named curves and malformed encodings return `None`.
fn signature_curve_for_ec_params(params: &[u8]) -> Option<SignatureKeyCurve> {
    if let Some(curve) = ec_curve_for_ec_params(params) {
        return Some(SignatureKeyCurve::Weierstrass(curve));
    }
    match params {
        OID_DER_ED25519 | PRINTABLE_EDWARDS25519 => Some(SignatureKeyCurve::Ed25519),
        OID_DER_ED448 | PRINTABLE_EDWARDS448 => Some(SignatureKeyCurve::Ed448),
        OID_DER_X25519 | PRINTABLE_CURVE25519 | OID_DER_X448 | PRINTABLE_CURVE448 => {
            Some(SignatureKeyCurve::Montgomery)
        }
        _ => None,
    }
}

/// Decide whether a key whose `CKA_EC_PARAMS` is `params` may serve
/// `algorithm`.
///
/// `CKM_ECDSA` is the same mechanism for every Weierstrass curve and the
/// caller's `SignatureAlgorithm` is the only place the curve is named, so
/// without this check a secp256k1 or Brainpool token key could be driven
/// as "P-256" (same field width, same hash) and the curve-specific FIPS
/// rule would be decided by a label rather than by the key. A key on a
/// different recognized curve is always refused. Unrecognized parameters
/// cannot be checked: they are allowed in non-FIPS builds (the token still
/// enforces key/mechanism consistency) and refused under `fips`, matching
/// [`Pkcs11KeyAgreement`].
fn check_key_curve(algorithm: SignatureAlgorithm, params: Option<&[u8]>) -> Result<()> {
    let Some(expected) = expected_signature_curve(algorithm) else {
        return Ok(());
    };
    match params.and_then(signature_curve_for_ec_params) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(Error::Key(format!(
            "PKCS#11 key is on {actual:?}, but {algorithm:?} requires {expected:?}"
        ))),
        None if cfg!(feature = "fips") => Err(Error::Crypto(format!(
            "FIPS policy cannot approve PKCS#11 {algorithm:?}: the key's CKA_EC_PARAMS is not \
             a recognized named curve"
        ))),
        None => Ok(()),
    }
}

/// Read the key's `CKA_EC_PARAMS` and apply [`check_key_curve`]. Algorithms
/// without a curve (RSA, HMAC, post-quantum) skip the attribute read.
fn validate_key_curve(
    session: &Pkcs11Session,
    key: ObjectHandle,
    algorithm: SignatureAlgorithm,
) -> Result<()> {
    if expected_signature_curve(algorithm).is_none() {
        return Ok(());
    }
    let guard = session
        .session
        .lock()
        .map_err(|e| Error::Pkcs11(format!("session lock poisoned: {e}")))?;
    let attrs = guard
        .get_attributes(key, &[AttributeType::EcParams])
        .map_err(|e| Error::Pkcs11(format!("cannot read CKA_EC_PARAMS: {e}")))?;
    drop(guard);
    let params = attrs.iter().find_map(|attr| match attr {
        Attribute::EcParams(params) => Some(params.as_slice()),
        _ => None,
    });
    check_key_curve(algorithm, params)
}

/// `CKM_ECDSA` returns raw `r || s` at the curve's field width; anything else
/// means the token signed over a different curve than the one named.
fn validate_ecdsa_signature_len(algorithm: SignatureAlgorithm, signature: &[u8]) -> Result<()> {
    let SignatureAlgorithm::Ecdsa(curve, _) = algorithm else {
        return Ok(());
    };
    let expected = 2 * crate::ecdsa_encoding::curve_field_len(curve);
    if signature.len() != expected {
        return Err(Error::Pkcs11(format!(
            "C_Sign returned {} bytes for ECDSA {curve:?}; expected {expected}",
            signature.len()
        )));
    }
    Ok(())
}

/// Map a [`SignatureAlgorithm`] to the corresponding cryptoki [`Mechanism`].
///
/// For RSA PKCS#1 v1.5 and RSA-PSS the mechanism includes hashing, so the
/// caller passes raw (unhashed) data.  For `Ecdsa` we return `CKM_ECDSA`
/// (raw), which expects **pre-hashed** data.
#[allow(unreachable_patterns)] // feature-gated variants (Dsa, MlDsa, SlhDsa) may not exist
fn signature_mechanism(
    algo: &SignatureAlgorithm,
    operation: Operation,
) -> Result<Mechanism<'static>> {
    match algo {
        SignatureAlgorithm::RsaPkcs1v15(hash) => match hash {
            HashAlgorithm::Sha1 => Ok(Mechanism::Sha1RsaPkcs),
            HashAlgorithm::Sha256 => Ok(Mechanism::Sha256RsaPkcs),
            HashAlgorithm::Sha384 => Ok(Mechanism::Sha384RsaPkcs),
            HashAlgorithm::Sha512 => Ok(Mechanism::Sha512RsaPkcs),
            other => Err(Error::unsupported(
                operation,
                format!("RSA PKCS#1 v1.5 with {other:?} not supported via PKCS#11"),
            )),
        },
        SignatureAlgorithm::RsaPss(hash) => {
            let (hash_mech, mgf, s_len) = pss_params_for(*hash, operation)?;
            let pss = PkcsPssParams {
                hash_alg: hash_mech,
                mgf,
                s_len,
            };
            match hash {
                HashAlgorithm::Sha1 => Ok(Mechanism::Sha1RsaPkcsPss(pss)),
                HashAlgorithm::Sha256 => Ok(Mechanism::Sha256RsaPkcsPss(pss)),
                HashAlgorithm::Sha384 => Ok(Mechanism::Sha384RsaPkcsPss(pss)),
                HashAlgorithm::Sha512 => Ok(Mechanism::Sha512RsaPkcsPss(pss)),
                other => Err(Error::unsupported(
                    operation,
                    format!("RSA-PSS with {other:?} not supported via PKCS#11"),
                )),
            }
        }
        // CKM_ECDSA (raw) -- caller must pre-hash.
        SignatureAlgorithm::Ecdsa(_, _) => Ok(Mechanism::Ecdsa),
        SignatureAlgorithm::Ed25519 => {
            // cryptoki 0.12: Mechanism::Eddsa now takes EddsaParams. Per
            // CKM_EDDSA (PKCS#11 v3.1 §2.3.11): for Ed25519 the parameter
            // structure is optional and absence implies pure Ed25519 —
            // which is what we want. `EddsaSignatureScheme::Ed25519`
            // produces a null-pointer `inner`, preserving the previous
            // wire behaviour for tokens that expect no mechanism param.
            use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
            Ok(Mechanism::Eddsa(EddsaParams::new(
                EddsaSignatureScheme::Ed25519,
            )))
        }
        SignatureAlgorithm::Ed448 => {
            // PKCS#11 v3.1 §2.3.11: for Ed448 the CK_EDDSA_PARAMS structure
            // is required; `phFlag = false` with an empty context selects
            // pure Ed448 with ctx = "" (RFC 8032 §5.2), matching the
            // software providers and RFC 8410 / JOSE usage.
            use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
            Ok(Mechanism::Eddsa(EddsaParams::new(
                EddsaSignatureScheme::Ed448(&[]),
            )))
        }
        SignatureAlgorithm::Hmac(hash) => match hash {
            // cryptoki 0.12 exposes Sha1/224/256/384/512 HMAC as named
            // Mechanism variants. Widening to match is a separate change;
            // preserving the pre-bump surface keeps this upgrade minimal.
            HashAlgorithm::Sha256 => Ok(Mechanism::Sha256Hmac),
            other => Err(Error::unsupported(
                operation,
                format!(
                    "HMAC with {other:?} not supported via PKCS#11 (only SHA-256 \
                 HMAC is currently wired up; cryptoki 0.12 exposes more)"
                ),
            )),
        },
        other => Err(Error::unsupported(
            operation,
            format!("{other:?} not supported via PKCS#11"),
        )),
    }
}

/// Return `(hash_mechanism_type, mgf, salt_len)` for RSA-PSS.
fn pss_params_for(
    hash: HashAlgorithm,
    operation: Operation,
) -> Result<(MechanismType, PkcsMgfType, Ulong)> {
    match hash {
        HashAlgorithm::Sha1 => Ok((MechanismType::SHA1, PkcsMgfType::MGF1_SHA1, 20.into())),
        HashAlgorithm::Sha256 => Ok((MechanismType::SHA256, PkcsMgfType::MGF1_SHA256, 32.into())),
        HashAlgorithm::Sha384 => Ok((MechanismType::SHA384, PkcsMgfType::MGF1_SHA384, 48.into())),
        HashAlgorithm::Sha512 => Ok((MechanismType::SHA512, PkcsMgfType::MGF1_SHA512, 64.into())),
        other => Err(Error::unsupported(
            operation,
            format!("RSA-PSS with {other:?}"),
        )),
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
    operation: Operation,
) -> Result<Mechanism<'a>> {
    let hash_mech = hash_to_mechanism_type(cfg.digest, operation)?;
    let mgf = hash_to_mgf(cfg.mgf_digest, operation)?;
    let source = match label {
        Some(bytes) => PkcsOaepSource::data_specified(bytes),
        None => PkcsOaepSource::empty(),
    };
    let params = PkcsOaepParams::new(hash_mech, mgf, source);
    Ok(Mechanism::RsaPkcsOaep(params))
}

fn hash_to_mechanism_type(h: HashAlgorithm, operation: Operation) -> Result<MechanismType> {
    match h {
        HashAlgorithm::Sha1 => Ok(MechanismType::SHA1),
        HashAlgorithm::Sha256 => Ok(MechanismType::SHA256),
        HashAlgorithm::Sha384 => Ok(MechanismType::SHA384),
        HashAlgorithm::Sha512 => Ok(MechanismType::SHA512),
        other => Err(Error::unsupported(
            operation,
            format!("hash {other:?} not supported for PKCS#11 OAEP"),
        )),
    }
}

fn hash_to_mgf(h: HashAlgorithm, operation: Operation) -> Result<PkcsMgfType> {
    match h {
        HashAlgorithm::Sha1 => Ok(PkcsMgfType::MGF1_SHA1),
        HashAlgorithm::Sha256 => Ok(PkcsMgfType::MGF1_SHA256),
        HashAlgorithm::Sha384 => Ok(PkcsMgfType::MGF1_SHA384),
        HashAlgorithm::Sha512 => Ok(PkcsMgfType::MGF1_SHA512),
        other => Err(Error::unsupported(
            operation,
            format!("MGF with {other:?} not supported"),
        )),
    }
}

/// Prepare the data that will be passed to `C_Sign` / `C_Verify`.
///
/// For ECDSA (CKM_ECDSA) the token expects a pre-computed hash; for all
/// other mechanisms the token performs hashing internally.
fn prepare_sign_data(algo: &SignatureAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    match algo {
        SignatureAlgorithm::Ecdsa(_, hash) => crate::digest::digest(*hash, data),
        _ => Ok(data.to_vec()),
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
        validate_key_curve(session, key_handle, algorithm)?;
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
        // PKCS#11 is orthogonal to the selected software provider, but it is
        // not an escape hatch around the process-wide initialization policy.
        // Enforce FIPS approval before token-only operations so FIPS
        // builds cannot use the HSM as an escape hatch. Capability
        // is not checked here — the HSM may support algorithms the
        // software provider does not.
        crate::backend::require_fips_approved(Operation::Sign(self.algorithm))?;
        let mechanism = signature_mechanism(&self.algorithm, Operation::Sign(self.algorithm))?;
        let sign_data = prepare_sign_data(&self.algorithm, data)?;
        let session = self
            .session
            .lock()
            .map_err(|e| Error::Pkcs11(format!("session lock poisoned: {e}")))?;
        validate_rsa_key(&session, self.key_handle, Operation::Sign(self.algorithm))?;
        let signature = session
            .sign(&mechanism, self.key_handle, &sign_data)
            .map_err(|e| Error::Pkcs11(format!("C_Sign failed: {e}")))?;
        validate_ecdsa_signature_len(self.algorithm, &signature)?;
        Ok(signature)
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
        validate_key_curve(session, key_handle, algorithm)?;
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
        crate::backend::require_fips_approved(Operation::Verify(self.algorithm))?;
        let mechanism = signature_mechanism(&self.algorithm, Operation::Verify(self.algorithm))?;
        let verify_data = prepare_sign_data(&self.algorithm, data)?;
        let session = self
            .session
            .lock()
            .map_err(|e| Error::Pkcs11(format!("session lock poisoned: {e}")))?;
        validate_rsa_key(&session, self.key_handle, Operation::Verify(self.algorithm))?;
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
        crate::backend::require_fips_approved(Operation::Sign(self.algorithm))?;
        let mechanism = signature_mechanism(&self.algorithm, Operation::Sign(self.algorithm))?;
        let session = self
            .session
            .lock()
            .map_err(|e| Error::Pkcs11(format!("session lock poisoned: {e}")))?;
        validate_rsa_key(&session, self.key_handle, Operation::Sign(self.algorithm))?;
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
        crate::backend::require_fips_approved(Operation::Verify(self.algorithm))?;
        let mechanism = signature_mechanism(&self.algorithm, Operation::Verify(self.algorithm))?;
        let session = self
            .session
            .lock()
            .map_err(|e| Error::Pkcs11(format!("session lock poisoned: {e}")))?;
        validate_rsa_key(&session, self.key_handle, Operation::Verify(self.algorithm))?;
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
        crate::backend::require_fips_approved(Operation::TransportDecrypt(self.algorithm))?;
        let mechanism = key_transport_mechanism(
            &self.algorithm,
            self.oaep_label.as_deref(),
            Operation::TransportDecrypt(self.algorithm),
        )?;
        let session = self
            .session
            .lock()
            .map_err(|e| Error::Pkcs11(format!("session lock poisoned: {e}")))?;
        validate_rsa_key(
            &session,
            self.key_handle,
            Operation::TransportDecrypt(self.algorithm),
        )?;
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
        crate::backend::require_fips_approved(Operation::TransportEncrypt(self.algorithm))?;
        let mechanism = key_transport_mechanism(
            &self.algorithm,
            self.oaep_label.as_deref(),
            Operation::TransportEncrypt(self.algorithm),
        )?;
        let session = self
            .session
            .lock()
            .map_err(|e| Error::Pkcs11(format!("session lock poisoned: {e}")))?;
        validate_rsa_key(
            &session,
            self.key_handle,
            Operation::TransportEncrypt(self.algorithm),
        )?;
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
    operation: Operation,
) -> Result<Mechanism<'a>> {
    match algo {
        #[cfg(feature = "legacy")]
        KeyTransportAlgorithm::RsaPkcs1v15 => Ok(Mechanism::RsaPkcs),
        KeyTransportAlgorithm::RsaOaep(cfg) => oaep_mechanism(cfg, label, operation),
    }
}

// ---------------------------------------------------------------------------
// KeyWrapper (AES key-wrap via C_WrapKey / C_UnwrapKey or C_Encrypt / C_Decrypt)
// ---------------------------------------------------------------------------

/// Wraps and unwraps keys using a KEK held on a PKCS#11 token.
///
/// Uses `CKM_AES_KEY_WRAP` (RFC 3394). Tokens offer the mechanism to
/// different functions, so the path is chosen from the slot's
/// `C_GetMechanismInfo` flags when the wrapper is created:
///
/// * `CKF_WRAP` / `CKF_UNWRAP` (SoftHSM2 and most HSMs): the key bytes are
///   imported as a temporary session object and wrapped with `C_WrapKey`,
///   or unwrapped with `C_UnwrapKey` into a temporary session object whose
///   `CKA_VALUE` is read back. The temporary object is destroyed before
///   `wrap`/`unwrap` return, also on error.
/// * otherwise `CKF_ENCRYPT` / `CKF_DECRYPT`: `C_Encrypt` / `C_Decrypt`
///   over the key bytes.
///
/// Input lengths are checked as in the software providers: `wrap` takes at
/// least 16 bytes, `unwrap` at least 24, both in multiples of 8.
pub struct Pkcs11KeyWrapper {
    session: Arc<Mutex<cryptoki::session::Session>>,
    key_handle: ObjectHandle,
    algorithm: KeyWrapAlgorithm,
    /// Token function driving `wrap`.
    wrap_call: KeyWrapCall,
    /// Token function driving `unwrap`.
    unwrap_call: KeyWrapCall,
}

/// Which token function a [`Pkcs11KeyWrapper`] direction goes through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyWrapCall {
    /// `C_WrapKey` / `C_UnwrapKey` on a temporary session object.
    KeyManagement,
    /// `C_Encrypt` / `C_Decrypt` over the raw key bytes.
    Cipher,
    /// The token offers the mechanism to neither.
    Unsupported,
}

/// Prefer the key-management function when the mechanism flags allow it.
fn select_keywrap_call(key_management: bool, cipher: bool) -> KeyWrapCall {
    if key_management {
        KeyWrapCall::KeyManagement
    } else if cipher {
        KeyWrapCall::Cipher
    } else {
        KeyWrapCall::Unsupported
    }
}

impl Pkcs11KeyWrapper {
    /// Create a new key wrapper.  `key_label` identifies the AES KEK on the
    /// token.
    ///
    /// For [`KeyWrapAlgorithm::AesKw`] the KEK's `CKA_VALUE_LEN` must match
    /// the declared AES key size. Tokens that do not expose
    /// `CKA_VALUE_LEN` skip this check.
    pub fn new(
        session: &Pkcs11Session,
        key_label: &str,
        algorithm: KeyWrapAlgorithm,
    ) -> Result<Self> {
        let key_handle = session.find_secret_key(key_label)?;
        #[allow(irrefutable_let_patterns)] // TripleDesKw only exists with `legacy`
        if let KeyWrapAlgorithm::AesKw(size) = algorithm {
            let guard = session
                .session
                .lock()
                .map_err(|e| Error::Pkcs11(format!("session lock poisoned: {e}")))?;
            let attrs = guard
                .get_attributes(key_handle, &[AttributeType::ValueLen])
                .map_err(|e| Error::Pkcs11(format!("C_GetAttributeValue failed: {e}")))?;
            drop(guard);
            check_kek_value_len(&attrs, size.key_len())?;
        }
        let (wrap_call, unwrap_call) = keywrap_calls(session, algorithm)?;
        Ok(Self {
            session: Arc::clone(&session.session),
            key_handle,
            algorithm,
            wrap_call,
            unwrap_call,
        })
    }
}

/// Choose the `wrap` and `unwrap` token functions from the mechanism info.
fn keywrap_calls(
    session: &Pkcs11Session,
    algorithm: KeyWrapAlgorithm,
) -> Result<(KeyWrapCall, KeyWrapCall)> {
    use cryptoki::error::{Error as CrError, RvError};
    // Without a PKCS#11 mechanism (3DES-KW) `wrap`/`unwrap` report the
    // algorithm as unsupported before looking at the call.
    let Ok(mechanism) = keywrap_mechanism(&algorithm, Operation::Wrap(algorithm)) else {
        return Ok((KeyWrapCall::Unsupported, KeyWrapCall::Unsupported));
    };
    match session
        .pkcs11
        .get_mechanism_info(session.slot, mechanism.mechanism_type())
    {
        Ok(info) => Ok(keywrap_calls_for(&info)),
        Err(CrError::Pkcs11(RvError::MechanismInvalid, _)) => {
            Ok((KeyWrapCall::Unsupported, KeyWrapCall::Unsupported))
        }
        Err(e) => Err(Error::Pkcs11(format!("C_GetMechanismInfo failed: {e}"))),
    }
}

/// Each direction on its own flags: `wrap` on `CKF_WRAP` / `CKF_ENCRYPT`,
/// `unwrap` on `CKF_UNWRAP` / `CKF_DECRYPT`.
fn keywrap_calls_for(info: &cryptoki::mechanism::MechanismInfo) -> (KeyWrapCall, KeyWrapCall) {
    (
        select_keywrap_call(info.wrap(), info.encrypt()),
        select_keywrap_call(info.unwrap(), info.decrypt()),
    )
}

impl KeyWrapper for Pkcs11KeyWrapper {
    fn wrap(&self, key_data: &[u8]) -> Result<Vec<u8>> {
        let operation = Operation::Wrap(self.algorithm);
        crate::backend::require_fips_approved(operation)?;
        let mechanism = keywrap_mechanism(&self.algorithm, operation)?;
        // RFC 3394 §2.2.1: n >= 2 64-bit blocks, as in the software
        // providers. Checked here because tokens differ (SoftHSM2 zero-pads
        // a partial block instead of refusing it).
        if key_data.len() < 16 || !key_data.len().is_multiple_of(8) {
            return Err(Error::Crypto("invalid AES-KW input length".into()));
        }
        let session = self
            .session
            .lock()
            .map_err(|e| Error::Pkcs11(format!("session lock poisoned: {e}")))?;
        let expected_len = key_data
            .len()
            .checked_add(8)
            .ok_or_else(|| Error::Crypto("AES-KW input is too long".into()))?;
        let wrapped = match self.wrap_call {
            KeyWrapCall::KeyManagement => {
                wrap_with_wrap_key(&session, &mechanism, self.key_handle, key_data)
            }
            KeyWrapCall::Cipher => session
                .encrypt(&mechanism, self.key_handle, key_data)
                .map_err(|e| Error::Pkcs11(format!("C_Encrypt (key wrap) failed: {e}"))),
            KeyWrapCall::Unsupported => Err(Error::unsupported(
                operation,
                format!(
                    "the token offers {} to neither C_WrapKey nor C_Encrypt",
                    mechanism.mechanism_type()
                ),
            )),
        }?;
        check_keywrap_output(wrapped, expected_len)
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>> {
        let operation = Operation::Unwrap(self.algorithm);
        crate::backend::require_fips_approved(operation)?;
        let mechanism = keywrap_mechanism(&self.algorithm, operation)?;
        // Integrity block plus n >= 2 key-data blocks.
        if wrapped.len() < 24 || !wrapped.len().is_multiple_of(8) {
            return Err(Error::Crypto("invalid AES-KW input length".into()));
        }
        let session = self
            .session
            .lock()
            .map_err(|e| Error::Pkcs11(format!("session lock poisoned: {e}")))?;
        let value = match self.unwrap_call {
            KeyWrapCall::KeyManagement => {
                unwrap_with_unwrap_key(&session, &mechanism, self.key_handle, wrapped)
            }
            KeyWrapCall::Cipher => session
                .decrypt(&mechanism, self.key_handle, wrapped)
                .map_err(|e| Error::Pkcs11(format!("C_Decrypt (key unwrap) failed: {e}"))),
            KeyWrapCall::Unsupported => Err(Error::unsupported(
                operation,
                format!(
                    "the token offers {} to neither C_UnwrapKey nor C_Decrypt",
                    mechanism.mechanism_type()
                ),
            )),
        }?;
        check_keywrap_output(value, wrapped.len() - 8)
    }
}

/// Enforce the AES-KW result invariant and wipe rejected plaintext buffers.
fn check_keywrap_output(output: Vec<u8>, expected: usize) -> Result<Vec<u8>> {
    let mut output = Zeroizing::new(output);
    if output.len() != expected {
        return Err(Error::Pkcs11(format!(
            "AES-KW output length mismatch: expected {expected} bytes, got {}",
            output.len()
        )));
    }
    Ok(std::mem::take(&mut *output))
}

/// `C_WrapKey` of raw key bytes: import them as a temporary session
/// generic-secret object, wrap it with the KEK, and destroy it again.
fn wrap_with_wrap_key(
    session: &cryptoki::session::Session,
    mechanism: &Mechanism,
    kek: ObjectHandle,
    key_data: &[u8],
) -> Result<Vec<u8>> {
    let mut template = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
        // Session object: never persisted to the token, and destroyed by
        // the token at session close even if `C_DestroyObject` fails.
        Attribute::Token(false),
        Attribute::Extractable(true),
        Attribute::Value(key_data.to_vec()),
    ];
    let created = session.create_object(&template);
    // The template holds a copy of the key bytes.
    for attr in &mut template {
        if let Attribute::Value(value) = attr {
            value.zeroize();
        }
    }
    let key =
        created.map_err(|e| Error::Pkcs11(format!("C_CreateObject (key to wrap) failed: {e}")))?;
    let wrapped = session
        .wrap_key(mechanism, kek, key)
        .map_err(|e| Error::Pkcs11(format!("C_WrapKey failed: {e}")));
    // Destroy on every path. A failed destroy leaves an extractable copy of
    // the key on the token until the session closes: report that first so
    // the caller can close the session to purge it.
    session.destroy_object(key).map_err(|e| {
        Error::Pkcs11(format!(
            "C_DestroyObject failed for the temporary key-to-wrap object; close the session \
             to purge it: {e}"
        ))
    })?;
    wrapped
}

/// `C_UnwrapKey` into a temporary session generic-secret object, read its
/// `CKA_VALUE`, and destroy it again.
fn unwrap_with_unwrap_key(
    session: &cryptoki::session::Session,
    mechanism: &Mechanism,
    kek: ObjectHandle,
    wrapped: &[u8],
) -> Result<Vec<u8>> {
    let template = [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
        // Session object, as for the ECDH secret: never persisted, and
        // destroyed at session close even if `C_DestroyObject` fails.
        Attribute::Token(false),
        Attribute::Sensitive(false),
        Attribute::Extractable(true),
    ];
    let key = session
        .unwrap_key(mechanism, kek, wrapped, &template)
        .map_err(|e| Error::Pkcs11(format!("C_UnwrapKey failed: {e}")))?;
    let value = session
        .get_attributes(key, &[AttributeType::Value])
        .map_err(|e| Error::Pkcs11(format!("C_GetAttributeValue failed: {e}")))
        .and_then(|attrs| {
            attrs
                .into_iter()
                .find_map(|attr| match attr {
                    Attribute::Value(v) => Some(Zeroizing::new(v)),
                    _ => None,
                })
                .ok_or_else(|| Error::Pkcs11("CKA_VALUE not present on unwrapped key".into()))
        });
    // As in `wrap_with_wrap_key`, a failed destroy takes precedence; the
    // read value is zeroized on drop.
    session.destroy_object(key).map_err(|e| {
        Error::Pkcs11(format!(
            "C_DestroyObject failed for the unwrapped key object; close the session to \
             purge it: {e}"
        ))
    })?;
    let mut value = value?;
    Ok(std::mem::take(&mut *value))
}

/// Check a KEK's `CKA_VALUE_LEN` (if the token returned it) against the
/// declared key size in bytes. An absent attribute is accepted.
fn check_kek_value_len(attrs: &[Attribute], expected: usize) -> Result<()> {
    for attr in attrs {
        if let Attribute::ValueLen(len) = attr {
            let actual = **len;
            if usize::try_from(actual).ok() != Some(expected) {
                return Err(Error::Pkcs11(format!(
                    "PKCS#11 KEK length mismatch: token key has CKA_VALUE_LEN {actual} bytes, \
                     algorithm declares {expected} bytes"
                )));
            }
        }
    }
    Ok(())
}

/// Map a [`KeyWrapAlgorithm`] to the corresponding PKCS#11 mechanism.
fn keywrap_mechanism(algo: &KeyWrapAlgorithm, _operation: Operation) -> Result<Mechanism<'static>> {
    match algo {
        KeyWrapAlgorithm::AesKw(_) => Ok(Mechanism::AesKeyWrap),
        #[cfg(feature = "legacy")]
        KeyWrapAlgorithm::TripleDesKw => Err(Error::unsupported(
            _operation,
            "3DES key wrap not supported via PKCS#11",
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
/// If destroying the temporary secret fails, that error takes precedence over
/// any attribute-read error. Close the session to purge the remaining object.
pub struct Pkcs11KeyAgreement {
    session: Arc<Mutex<cryptoki::session::Session>>,
    key_handle: ObjectHandle,
    /// Expected byte-length of the derived shared secret.
    key_len: usize,
    /// Curve read from the private key's `CKA_EC_PARAMS`, or `None` if the
    /// token did not expose it or it is not a curve kryptering recognizes.
    curve: Option<AgreementCurve>,
}

/// Curve families `CKM_ECDH1_DERIVE` can run over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgreementCurve {
    /// Short-Weierstrass named curve; the peer key is a SEC1 point.
    Weierstrass(crate::algorithm::EcCurve),
    /// `CKK_EC_MONTGOMERY` curve25519 (RFC 7748); raw 32-byte u-coordinates.
    X25519,
    /// `CKK_EC_MONTGOMERY` curve448 (RFC 7748); raw 56-byte u-coordinates.
    X448,
}

impl AgreementCurve {
    /// Expected shared-secret and peer-key width.
    fn field_len(self) -> usize {
        match self {
            Self::Weierstrass(curve) => crate::ecdsa_encoding::curve_field_len(curve),
            Self::X25519 => 32,
            Self::X448 => 56,
        }
    }

    /// Provider operation used for capability and FIPS policy checks.
    fn operation(self) -> Operation {
        match self {
            Self::Weierstrass(curve) => Operation::Agreement(curve),
            Self::X25519 => Operation::X25519Agreement,
            Self::X448 => Operation::X448Agreement,
        }
    }
}

impl Pkcs11KeyAgreement {
    /// Create a new key agreement object.  `key_label` identifies the EC
    /// private key on the token, and `key_len` is the expected shared secret
    /// size in bytes. Named curves require exactly their field width
    /// (32/48/66 bytes for P-256/P-384/P-521, 32 for secp256k1 and
    /// brainpoolP256r1, 48 for brainpoolP384r1, 64 for brainpoolP512r1,
    /// 32 for X25519 and 56 for X448); mismatches return an error.
    ///
    /// The curve used for FIPS policy checks is taken from the key's
    /// `CKA_EC_PARAMS` (named-curve OID, or the `curve25519` / `curve448`
    /// PrintableString form SoftHSM2 writes for `CKK_EC_MONTGOMERY` keys),
    /// not inferred from `key_len`. For Montgomery keys the peer public key
    /// passed to [`KeyAgreement::agree`] is the raw little-endian
    /// u-coordinate (RFC 7748), not a SEC1 point.
    pub fn new(session: &Pkcs11Session, key_label: &str, key_len: usize) -> Result<Self> {
        let key_handle = session.find_private_key(key_label)?;
        let guard = session
            .session
            .lock()
            .map_err(|e| Error::Pkcs11(format!("session lock poisoned: {e}")))?;
        let attrs = guard
            .get_attributes(key_handle, &[AttributeType::EcParams])
            .map_err(|e| Error::Pkcs11(format!("C_GetAttributeValue failed: {e}")))?;
        drop(guard);
        let curve = attrs.iter().find_map(|attr| match attr {
            Attribute::EcParams(params) => agreement_curve_for_ec_params(params),
            _ => None,
        });
        validate_ecdh_key_len(curve, key_len)?;
        Ok(Self {
            session: Arc::clone(&session.session),
            key_handle,
            key_len,
            curve,
        })
    }
}

/// Prevent CKD_NULL output truncation for recognized named curves.
fn validate_ecdh_key_len(curve: Option<AgreementCurve>, key_len: usize) -> Result<()> {
    let Some(curve) = curve else {
        return Ok(());
    };
    let expected = curve.field_len();
    if key_len != expected {
        return Err(Error::Pkcs11(format!(
            "ECDH shared secret length must be {expected} bytes for {curve:?}, got {key_len}"
        )));
    }
    Ok(())
}

/// DER-encoded `namedCurve` OIDs as they appear in `CKA_EC_PARAMS`.
const OID_DER_P256: &[u8] = &[
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // 1.2.840.10045.3.1.7
];
const OID_DER_P384: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]; // 1.3.132.0.34
const OID_DER_P521: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]; // 1.3.132.0.35
const OID_DER_SECP256K1: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a]; // 1.3.132.0.10
const OID_DER_BRAINPOOL_P256R1: &[u8] = &[
    0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07, // 1.3.36.3.3.2.8.1.1.7
];
const OID_DER_BRAINPOOL_P384R1: &[u8] = &[
    0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b, // 1.3.36.3.3.2.8.1.1.11
];
const OID_DER_BRAINPOOL_P512R1: &[u8] = &[
    0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d, // 1.3.36.3.3.2.8.1.1.13
];

/// RFC 8410 id-X25519 / id-X448 as DER OIDs, plus the PrintableString curve
/// names PKCS#11 v3 permits (and SoftHSM2 emits) for Montgomery keys.
const OID_DER_X25519: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x6e]; // 1.3.101.110
const OID_DER_X448: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x6f]; // 1.3.101.111
const PRINTABLE_CURVE25519: &[u8] = b"\x13\x0acurve25519";
const PRINTABLE_CURVE448: &[u8] = b"\x13\x08curve448";

/// Map `CKA_EC_PARAMS` to the agreement curve family, covering the named
/// Weierstrass curves and the two Montgomery curves.
fn agreement_curve_for_ec_params(params: &[u8]) -> Option<AgreementCurve> {
    if let Some(curve) = ec_curve_for_ec_params(params) {
        return Some(AgreementCurve::Weierstrass(curve));
    }
    match params {
        OID_DER_X25519 | PRINTABLE_CURVE25519 => Some(AgreementCurve::X25519),
        OID_DER_X448 | PRINTABLE_CURVE448 => Some(AgreementCurve::X448),
        _ => None,
    }
}

/// Map a `CKA_EC_PARAMS` value (DER `ECParameters`) to a supported named
/// Weierstrass curve. Explicit parameters, other named curves, and malformed
/// encodings return `None`.
fn ec_curve_for_ec_params(params: &[u8]) -> Option<crate::algorithm::EcCurve> {
    match params {
        OID_DER_P256 => Some(crate::algorithm::EcCurve::P256),
        OID_DER_P384 => Some(crate::algorithm::EcCurve::P384),
        OID_DER_P521 => Some(crate::algorithm::EcCurve::P521),
        OID_DER_SECP256K1 => Some(crate::algorithm::EcCurve::Secp256k1),
        OID_DER_BRAINPOOL_P256R1 => Some(crate::algorithm::EcCurve::BrainpoolP256r1),
        OID_DER_BRAINPOOL_P384R1 => Some(crate::algorithm::EcCurve::BrainpoolP384r1),
        OID_DER_BRAINPOOL_P512R1 => Some(crate::algorithm::EcCurve::BrainpoolP512r1),
        _ => None,
    }
}

impl KeyAgreement for Pkcs11KeyAgreement {
    fn agree(&self, peer_public_key: &[u8]) -> Result<Vec<u8>> {
        if let Some(curve) = self.curve {
            crate::backend::require_fips_approved(curve.operation())?;
            if matches!(curve, AgreementCurve::X25519 | AgreementCurve::X448)
                && peer_public_key.len() != curve.field_len()
            {
                return Err(Error::Key(format!(
                    "{curve:?} peer public key must be the raw {}-byte u-coordinate, got {}",
                    curve.field_len(),
                    peer_public_key.len()
                )));
            }
        } else {
            crate::backend::ensure_backend()?;
            #[cfg(feature = "fips")]
            return Err(Error::Crypto(
                "FIPS policy cannot approve PKCS#11 ECDH: private key CKA_EC_PARAMS is not \
                 the named curve P-256, P-384 or P-521"
                    .into(),
            ));
        }
        let ec_params = Ecdh1DeriveParams::new(EcKdf::null(), peer_public_key);
        let mechanism = Mechanism::Ecdh1Derive(ec_params);

        // Template for the derived generic-secret key so we can read its value.
        let template = vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(cryptoki::object::KeyType::GENERIC_SECRET),
            Attribute::Encrypt(false),
            Attribute::Decrypt(false),
            Attribute::ValueLen(self.key_len.try_into().map_err(|_| {
                Error::Pkcs11(format!("key_len {} too large for Ulong", self.key_len))
            })?),
            Attribute::Extractable(true),
            Attribute::Sensitive(false),
            // Session object: never persisted to the token, and destroyed by
            // the token at session close even if `C_DestroyObject` fails.
            Attribute::Token(false),
        ];

        let session = self
            .session
            .lock()
            .map_err(|e| Error::Pkcs11(format!("session lock poisoned: {e}")))?;
        let derived_key = session
            .derive_key(&mechanism, self.key_handle, &template)
            .map_err(|e| Error::Pkcs11(format!("C_DeriveKey (ECDH) failed: {e}")))?;

        // Read CKA_VALUE, then destroy the extractable derived object on
        // every path before propagating any error.
        let value = session
            .get_attributes(derived_key, &[AttributeType::Value])
            .map_err(|e| Error::Pkcs11(format!("C_GetAttributeValue failed: {e}")))
            .and_then(|attrs| {
                attrs
                    .into_iter()
                    .find_map(|attr| match attr {
                        Attribute::Value(v) => Some(zeroize::Zeroizing::new(v)),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        Error::Pkcs11("CKA_VALUE not present on derived ECDH key".into())
                    })
            });
        let destroyed = session.destroy_object(derived_key);
        let mut secret = Zeroizing::new(finish_ecdh_cleanup(value, destroyed)?);
        reject_non_contributory_secret(self.curve, &secret)?;
        Ok(std::mem::take(&mut *secret))
    }
}

/// RFC 7748 §6.1 / §6.2: a low-order peer u-coordinate makes the X25519 /
/// X448 ladder output all zeros regardless of the private key, letting the
/// peer pin every key derived from the secret. The software providers refuse
/// that unconditionally; PKCS#11 does not require tokens to, so the same rule
/// is applied to the derived `CKA_VALUE` here. Weierstrass curves are left
/// alone: the token's point validation rejects the identity, and a zero
/// x-coordinate is not a low-order signal there.
fn reject_non_contributory_secret(curve: Option<AgreementCurve>, secret: &[u8]) -> Result<()> {
    let Some(curve @ (AgreementCurve::X25519 | AgreementCurve::X448)) = curve else {
        return Ok(());
    };
    if secret.iter().fold(0u8, |acc, byte| acc | byte) == 0 {
        return Err(Error::Key(format!(
            "{curve:?} peer public key is a low-order point (shared secret is all zero)"
        )));
    }
    Ok(())
}

/// Resolve both completed operations, prioritizing failure to purge the secret.
fn finish_ecdh_cleanup(
    value: Result<Zeroizing<Vec<u8>>>,
    destroyed: cryptoki::error::Result<()>,
) -> Result<Vec<u8>> {
    // A failed destroy leaves an extractable copy of the shared secret on
    // the token until the session closes. Report it even if reading failed;
    // any successfully read secret is zeroized on this error path.
    destroyed.map_err(|e| {
        Error::Pkcs11(format!(
            "C_DestroyObject failed for derived ECDH key; close the session to purge it: {e}"
        ))
    })?;
    let mut value = value?;
    Ok(std::mem::take(&mut *value))
}

// ---------------------------------------------------------------------------
// AES Cipher (AES-CBC / AES-GCM via PKCS#11)
// ---------------------------------------------------------------------------

/// Encrypts and decrypts using an AES key held on a PKCS#11 token.
///
/// Supports [`CipherAlgorithm::AesGcm`] (`CKM_AES_GCM` with 128-bit
/// authentication tag). AES-CBC is intentionally not exposed through this
/// high-level PKCS#11 cipher because unauthenticated CBC belongs behind the
/// same hazmat boundary as the software backend.
///
/// The wire format matches the software backend: the IV/nonce is prepended
/// to the ciphertext on encrypt and stripped on decrypt.
///
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
        validate_pkcs11_cipher_algorithm(algorithm)?;
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
        crate::backend::require_fips_approved(Operation::Encrypt(self.algorithm))?;
        let session = self
            .session
            .lock()
            .map_err(|e| Error::Pkcs11(format!("session lock poisoned: {e}")))?;
        match self.algorithm {
            CipherAlgorithm::AesCbc(_) => Err(unsupported_pkcs11_aes_cbc()),
            CipherAlgorithm::AesGcm(_) => {
                let mut nonce = [0u8; 12];
                session
                    .generate_random_slice(&mut nonce)
                    .map_err(|e| Error::Pkcs11(format!("C_GenerateRandom failed: {e}")))?;
                // cryptoki 0.12: `GcmParams::new` takes `&mut [u8]` for the
                // IV (the PKCS#11 spec allows the library to overwrite it
                // with a library-generated value) and now returns `Result`.
                // The GcmParams borrow scope must end before we can read
                // `nonce` for the wire output, so the encrypt call is kept
                // inside a block. What we serialize is the post-call value
                // — identical to the generated nonce on tokens that accept
                // caller-provided IVs, and the actually-used value on
                // tokens that overwrite.
                let ct = {
                    let gcm_params =
                        cryptoki::mechanism::aead::GcmParams::new(&mut nonce, &[], 128.into())
                            .map_err(|e| Error::Pkcs11(format!("GcmParams::new failed: {e}")))?;
                    let mechanism = Mechanism::AesGcm(gcm_params);
                    session
                        .encrypt(&mechanism, self.key_handle, plaintext)
                        .map_err(|e| Error::Pkcs11(format!("C_Encrypt (AES-GCM) failed: {e}")))?
                };
                let mut result = Vec::with_capacity(12 + ct.len());
                result.extend_from_slice(&nonce);
                result.extend_from_slice(&ct);
                Ok(result)
            }
            #[cfg(feature = "legacy")]
            CipherAlgorithm::TripleDesCbc => Err(Error::unsupported(
                Operation::Encrypt(self.algorithm),
                "3DES-CBC not supported via PKCS#11 cipher",
            )),
        }
    }

    /// Decrypt `data` (expected format: `IV/nonce || ciphertext`), returning
    /// plaintext.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        crate::backend::require_fips_approved(Operation::Decrypt(self.algorithm))?;
        let session = self
            .session
            .lock()
            .map_err(|e| Error::Pkcs11(format!("session lock poisoned: {e}")))?;
        match self.algorithm {
            CipherAlgorithm::AesCbc(_) => Err(unsupported_pkcs11_aes_cbc()),
            CipherAlgorithm::AesGcm(_) => {
                // 12-byte nonce + at least 16-byte tag
                if data.len() < 12 + 16 {
                    return Err(Error::Crypto(
                        "AES-GCM ciphertext too short (need nonce + tag)".into(),
                    ));
                }
                // cryptoki 0.12: `GcmParams::new` requires `&mut [u8]`; copy
                // the nonce prefix into a local mutable buffer so the input
                // slice stays immutable.
                let mut iv_buf = [0u8; 12];
                iv_buf.copy_from_slice(&data[..12]);
                let ct_and_tag = &data[12..];
                let gcm_params =
                    cryptoki::mechanism::aead::GcmParams::new(&mut iv_buf, &[], 128.into())
                        .map_err(|e| Error::Pkcs11(format!("GcmParams::new failed: {e}")))?;
                let mechanism = Mechanism::AesGcm(gcm_params);
                session
                    .decrypt(&mechanism, self.key_handle, ct_and_tag)
                    .map_err(|e| Error::Pkcs11(format!("C_Decrypt (AES-GCM) failed: {e}")))
            }
            #[cfg(feature = "legacy")]
            CipherAlgorithm::TripleDesCbc => Err(Error::unsupported(
                Operation::Decrypt(self.algorithm),
                "3DES-CBC not supported via PKCS#11 cipher",
            )),
        }
    }
}

fn validate_pkcs11_cipher_algorithm(algorithm: CipherAlgorithm) -> Result<()> {
    match algorithm {
        CipherAlgorithm::AesCbc(_) => Err(unsupported_pkcs11_aes_cbc()),
        CipherAlgorithm::AesGcm(_) => Ok(()),
        #[cfg(feature = "legacy")]
        CipherAlgorithm::TripleDesCbc => Err(Error::unsupported(
            Operation::Encrypt(algorithm),
            "3DES-CBC not supported via PKCS#11 cipher",
        )),
    }
}

fn unsupported_pkcs11_aes_cbc() -> Error {
    Error::unsupported(
        Operation::Encrypt(CipherAlgorithm::AesCbc(
            crate::algorithm::AesKeySize::Aes128,
        )),
        "AES-CBC is unauthenticated and is not supported by the high-level PKCS#11 cipher; \
         use an authenticated mode such as AES-GCM or a dedicated hazmat API"
            .to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::{AesKeySize, OaepConfig};

    /// Recognized EC curves require full-width ECDH output in every provider mode.
    #[test]
    fn ecdh_key_lengths_match_named_curves() {
        use crate::algorithm::EcCurve;
        for (curve, expected) in [
            (AgreementCurve::Weierstrass(EcCurve::P256), 32),
            (AgreementCurve::Weierstrass(EcCurve::P384), 48),
            (AgreementCurve::Weierstrass(EcCurve::P521), 66),
            (AgreementCurve::Weierstrass(EcCurve::Secp256k1), 32),
            (AgreementCurve::Weierstrass(EcCurve::BrainpoolP256r1), 32),
            (AgreementCurve::Weierstrass(EcCurve::BrainpoolP384r1), 48),
            (AgreementCurve::Weierstrass(EcCurve::BrainpoolP512r1), 64),
            (AgreementCurve::X25519, 32),
            (AgreementCurve::X448, 56),
        ] {
            assert!(validate_ecdh_key_len(Some(curve), expected).is_ok());
            for length in [0, 1, expected - 1, expected + 1, usize::MAX] {
                assert!(matches!(
                    validate_ecdh_key_len(Some(curve), length),
                    Err(Error::Pkcs11(_))
                ));
            }
        }
        assert!(validate_ecdh_key_len(None, 7).is_ok());
    }

    /// Unknown curves retain the existing provider-policy handling at agreement time.
    #[test]
    fn ecdh_unknown_curve_length_defers_to_existing_policy() {
        assert!(validate_ecdh_key_len(None, 32).is_ok());
    }

    /// A failed destroy must report session-close recovery whether reading the
    /// secret succeeds, fails, or returns no CKA_VALUE attribute.
    #[test]
    fn ecdh_cleanup_failure_takes_precedence() {
        for value in [
            Err(Error::Pkcs11("C_GetAttributeValue failed".into())),
            Err(Error::Pkcs11(
                "CKA_VALUE not present on derived ECDH key".into(),
            )),
            Ok(Zeroizing::new(vec![0x42; 32])),
        ] {
            let error = finish_ecdh_cleanup(
                value,
                Err(cryptoki::error::Error::Pkcs11(
                    cryptoki::error::RvError::GeneralError,
                    cryptoki::context::Function::DestroyObject,
                )),
            )
            .unwrap_err();
            assert!(matches!(error, Error::Pkcs11(_)));
            let message = error.to_string();
            assert!(message.contains("C_DestroyObject failed"), "{message}");
            assert!(
                message.contains("close the session to purge it"),
                "{message}"
            );
        }
    }

    /// Successful destruction must preserve the original attribute-read error.
    #[test]
    fn ecdh_successful_cleanup_preserves_read_error() {
        let error = finish_ecdh_cleanup(
            Err(Error::Pkcs11("C_GetAttributeValue failed".into())),
            Ok(()),
        )
        .unwrap_err();
        assert!(
            matches!(error, Error::Pkcs11(ref message) if message == "C_GetAttributeValue failed")
        );
    }

    /// Successful reading and destruction must return the shared secret unchanged.
    #[test]
    fn ecdh_successful_cleanup_returns_secret() {
        let secret = vec![0x42; 32];
        let result = finish_ecdh_cleanup(Ok(Zeroizing::new(secret.clone())), Ok(())).unwrap();
        assert_eq!(result, secret);
    }

    fn assert_unsupported_operation<T>(result: Result<T>, expected: Operation) {
        match result {
            Err(Error::UnsupportedAlgorithm { operation, .. }) => {
                assert_eq!(operation, expected);
            }
            Err(error) => panic!("expected UnsupportedAlgorithm, got: {error}"),
            Ok(_) => panic!("expected UnsupportedAlgorithm, got success"),
        }
    }

    #[test]
    fn default_provider_selection_rejects_ambiguous_slots() {
        let slot_one = Slot::try_from(1_u64).unwrap();
        let slot_two = Slot::try_from(2_u64).unwrap();
        let err = select_single_initialized_slot(&[slot_one, slot_two]).unwrap_err();
        assert!(
            err.to_string().contains("multiple initialized token slots"),
            "got: {err}"
        );
    }

    #[test]
    fn default_provider_selection_accepts_one_slot() {
        let slot = Slot::try_from(7_u64).unwrap();
        assert_eq!(select_single_initialized_slot(&[slot]).unwrap().id(), 7);
    }

    #[test]
    fn token_selector_rejects_ambiguous_matches() {
        let slot_one = Slot::try_from(3_u64).unwrap();
        let slot_two = Slot::try_from(4_u64).unwrap();
        let err =
            select_unique_matching_token(&[slot_one, slot_two], "prod-token", None).unwrap_err();
        assert!(
            err.to_string().contains("multiple initialized tokens"),
            "got: {err}"
        );
    }

    #[test]
    fn pkcs11_cipher_rejects_aes_cbc_before_key_lookup() {
        let err = validate_pkcs11_cipher_algorithm(CipherAlgorithm::AesCbc(AesKeySize::Aes128))
            .unwrap_err();
        assert!(err.to_string().contains("AES-CBC"), "got: {err}");
    }

    #[test]
    fn pkcs11_cipher_accepts_aes_gcm_algorithm() {
        assert!(
            validate_pkcs11_cipher_algorithm(CipherAlgorithm::AesGcm(AesKeySize::Aes256)).is_ok()
        );
    }

    #[test]
    fn signature_mechanism_reports_callers_operation() {
        for algorithm in [
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha3_256),
            SignatureAlgorithm::RsaPss(HashAlgorithm::Sha3_256),
        ] {
            for operation in [Operation::Sign(algorithm), Operation::Verify(algorithm)] {
                assert_unsupported_operation(signature_mechanism(&algorithm, operation), operation);
            }
        }
    }

    #[test]
    fn oaep_mechanism_reports_encrypt_and_decrypt_operations() {
        for config in [
            OaepConfig {
                digest: HashAlgorithm::Sha3_256,
                mgf_digest: HashAlgorithm::Sha256,
            },
            OaepConfig {
                digest: HashAlgorithm::Sha256,
                mgf_digest: HashAlgorithm::Sha3_256,
            },
        ] {
            let algorithm = KeyTransportAlgorithm::RsaOaep(config);
            for operation in [
                Operation::TransportEncrypt(algorithm),
                Operation::TransportDecrypt(algorithm),
            ] {
                assert_unsupported_operation(
                    key_transport_mechanism(&algorithm, None, operation),
                    operation,
                );
            }
        }
    }

    #[cfg(feature = "legacy")]
    #[test]
    fn keywrap_mechanism_reports_wrap_and_unwrap_operations() {
        let algorithm = KeyWrapAlgorithm::TripleDesKw;
        for operation in [Operation::Wrap(algorithm), Operation::Unwrap(algorithm)] {
            assert_unsupported_operation(keywrap_mechanism(&algorithm, operation), operation);
        }
    }

    #[test]
    fn ec_params_named_curve_oids_map_to_fips_policy_curves() {
        use crate::algorithm::EcCurve;
        assert_eq!(ec_curve_for_ec_params(OID_DER_P256), Some(EcCurve::P256));
        assert_eq!(ec_curve_for_ec_params(OID_DER_P384), Some(EcCurve::P384));
        assert_eq!(ec_curve_for_ec_params(OID_DER_P521), Some(EcCurve::P521));
        // Non-NIST named curves are recognized (so the secret length is
        // enforced) but are refused by the FIPS policy, not by this mapping.
        for (params, curve) in [
            (OID_DER_SECP256K1, EcCurve::Secp256k1),
            (OID_DER_BRAINPOOL_P256R1, EcCurve::BrainpoolP256r1),
            (OID_DER_BRAINPOOL_P384R1, EcCurve::BrainpoolP384r1),
            (OID_DER_BRAINPOOL_P512R1, EcCurve::BrainpoolP512r1),
        ] {
            assert_eq!(ec_curve_for_ec_params(params), Some(curve));
            assert!(!crate::backend::fips_approved_curve(curve));
        }
        // PrintableString curve names and unknown OIDs stay unmapped.
        assert_eq!(ec_curve_for_ec_params(b"\x13\x0aprime256v1"), None);
        assert_eq!(ec_curve_for_ec_params(&[]), None);
        // Montgomery curves resolve to their own agreement operations (never
        // FIPS approved) from either the OID or the PrintableString form.
        for (params, curve, operation) in [
            (
                OID_DER_X25519,
                AgreementCurve::X25519,
                Operation::X25519Agreement,
            ),
            (
                PRINTABLE_CURVE25519,
                AgreementCurve::X25519,
                Operation::X25519Agreement,
            ),
            (OID_DER_X448, AgreementCurve::X448, Operation::X448Agreement),
            (
                PRINTABLE_CURVE448,
                AgreementCurve::X448,
                Operation::X448Agreement,
            ),
        ] {
            assert_eq!(agreement_curve_for_ec_params(params), Some(curve));
            assert_eq!(curve.operation(), operation);
            assert_eq!(ec_curve_for_ec_params(params), None);
        }
        assert_eq!(
            agreement_curve_for_ec_params(OID_DER_P256),
            Some(AgreementCurve::Weierstrass(EcCurve::P256))
        );
        assert_eq!(agreement_curve_for_ec_params(b"\x13\x0aprime256v1"), None);
    }

    #[test]
    fn keywrap_prefers_wrap_key_over_encrypt() {
        assert_eq!(select_keywrap_call(true, true), KeyWrapCall::KeyManagement);
        assert_eq!(select_keywrap_call(true, false), KeyWrapCall::KeyManagement);
        assert_eq!(select_keywrap_call(false, true), KeyWrapCall::Cipher);
        assert_eq!(select_keywrap_call(false, false), KeyWrapCall::Unsupported);
    }

    #[test]
    fn keywrap_calls_follow_each_directions_flags() {
        use cryptoki_sys::{CKF_DECRYPT, CKF_ENCRYPT, CKF_UNWRAP, CKF_WRAP, CK_MECHANISM_INFO};
        use KeyWrapCall::{Cipher, KeyManagement, Unsupported};
        let calls = |flags| {
            keywrap_calls_for(&cryptoki::mechanism::MechanismInfo::from(
                CK_MECHANISM_INFO {
                    ulMinKeySize: 16,
                    ulMaxKeySize: 32,
                    flags,
                },
            ))
        };
        // SoftHSM2: wrap-only.
        assert_eq!(calls(CKF_WRAP | CKF_UNWRAP), (KeyManagement, KeyManagement));
        // Encrypt-only tokens keep the C_Encrypt / C_Decrypt path.
        assert_eq!(calls(CKF_ENCRYPT | CKF_DECRYPT), (Cipher, Cipher));
        assert_eq!(
            calls(CKF_WRAP | CKF_UNWRAP | CKF_ENCRYPT | CKF_DECRYPT),
            (KeyManagement, KeyManagement)
        );
        assert_eq!(calls(CKF_WRAP | CKF_DECRYPT), (KeyManagement, Cipher));
        assert_eq!(calls(CKF_ENCRYPT | CKF_UNWRAP), (Cipher, KeyManagement));
        assert_eq!(calls(CKF_WRAP), (KeyManagement, Unsupported));
        assert_eq!(calls(CKF_DECRYPT), (Unsupported, Cipher));
        assert_eq!(calls(0), (Unsupported, Unsupported));
    }

    #[test]
    fn kek_value_len_check() {
        let len = |n: usize| Attribute::ValueLen(n.try_into().unwrap());
        assert!(check_kek_value_len(&[len(32)], 32).is_ok());
        assert!(check_kek_value_len(&[len(16)], 32).is_err());
        // Attribute not exposed by the token: fall through.
        assert!(check_kek_value_len(&[], 32).is_ok());
    }

    /// Invariant: an all-zero Montgomery secret is refused (RFC 7748 §6.1);
    /// Weierstrass secrets and unrecognized curves pass through untouched.
    #[test]
    fn montgomery_all_zero_secret_is_rejected() {
        for curve in [AgreementCurve::X25519, AgreementCurve::X448] {
            let width = curve.field_len();
            let err = reject_non_contributory_secret(Some(curve), &vec![0; width]).unwrap_err();
            assert!(err.to_string().contains("low-order"), "{err}");
            let mut nonzero = vec![0; width];
            nonzero[width - 1] = 1;
            assert!(reject_non_contributory_secret(Some(curve), &nonzero).is_ok());
            nonzero[width - 1] = 0;
            nonzero[0] = 0x80;
            assert!(reject_non_contributory_secret(Some(curve), &nonzero).is_ok());
        }
        let p256 = AgreementCurve::Weierstrass(crate::algorithm::EcCurve::P256);
        assert!(reject_non_contributory_secret(Some(p256), &[0; 32]).is_ok());
        assert!(reject_non_contributory_secret(None, &[0; 32]).is_ok());
    }

    /// Invariant: a signature key must be on the curve the algorithm names,
    /// so the curve-specific FIPS rule is decided by `CKA_EC_PARAMS` and not
    /// by the caller's label. Algorithms without a curve are not checked.
    #[test]
    fn signature_key_curve_must_match_algorithm() {
        use crate::algorithm::EcCurve;
        let es256 = SignatureAlgorithm::Ecdsa(EcCurve::P256, HashAlgorithm::Sha256);
        let es256k = SignatureAlgorithm::Ecdsa(EcCurve::Secp256k1, HashAlgorithm::Sha256);
        let bp256 = SignatureAlgorithm::Ecdsa(EcCurve::BrainpoolP256r1, HashAlgorithm::Sha256);
        assert!(check_key_curve(es256, Some(OID_DER_P256)).is_ok());
        assert!(check_key_curve(es256k, Some(OID_DER_SECP256K1)).is_ok());
        assert!(check_key_curve(bp256, Some(OID_DER_BRAINPOOL_P256R1)).is_ok());
        // Same 32-byte field width, different curve: refused in every direction.
        for (algorithm, params) in [
            (es256, OID_DER_SECP256K1),
            (es256, OID_DER_BRAINPOOL_P256R1),
            (es256k, OID_DER_P256),
            (es256k, OID_DER_BRAINPOOL_P256R1),
            (bp256, OID_DER_P256),
            (es256, OID_DER_P384),
        ] {
            assert!(
                matches!(check_key_curve(algorithm, Some(params)), Err(Error::Key(_))),
                "{algorithm:?} accepted {params:02x?}"
            );
        }
        // Edwards keys match from either encoding, never across Ed25519/Ed448,
        // and never serve ECDSA.
        for params in [OID_DER_ED25519, PRINTABLE_EDWARDS25519] {
            assert!(check_key_curve(SignatureAlgorithm::Ed25519, Some(params)).is_ok());
            assert!(check_key_curve(SignatureAlgorithm::Ed448, Some(params)).is_err());
            assert!(check_key_curve(es256, Some(params)).is_err());
        }
        for params in [OID_DER_ED448, PRINTABLE_EDWARDS448] {
            assert!(check_key_curve(SignatureAlgorithm::Ed448, Some(params)).is_ok());
            assert!(check_key_curve(SignatureAlgorithm::Ed25519, Some(params)).is_err());
            assert!(check_key_curve(es256, Some(params)).is_err());
        }
        // Montgomery keys are agreement-only.
        for params in [
            OID_DER_X25519,
            PRINTABLE_CURVE25519,
            OID_DER_X448,
            PRINTABLE_CURVE448,
        ] {
            assert!(check_key_curve(SignatureAlgorithm::Ed25519, Some(params)).is_err());
            assert!(check_key_curve(SignatureAlgorithm::Ed448, Some(params)).is_err());
            assert!(check_key_curve(es256, Some(params)).is_err());
        }
        // Unrecognized or absent parameters cannot be checked: allowed unless
        // `fips`, where the policy fails closed like PKCS#11 agreement does.
        for params in [Some(&b"\x13\x0aprime256v1"[..]), Some(&[][..]), None] {
            assert_eq!(
                check_key_curve(es256, params).is_ok(),
                !cfg!(feature = "fips"),
                "{params:?}"
            );
        }
        // Algorithms whose keys carry no curve are never checked.
        assert!(check_key_curve(SignatureAlgorithm::RsaPss(HashAlgorithm::Sha256), None).is_ok());
        assert!(check_key_curve(
            SignatureAlgorithm::Hmac(HashAlgorithm::Sha256),
            Some(OID_DER_SECP256K1)
        )
        .is_ok());
    }

    /// Invariant: `CKM_ECDSA` raw output must be exactly `2 * field` bytes.
    #[test]
    fn ecdsa_signature_length_matches_curve() {
        use crate::algorithm::EcCurve;
        for (curve, field) in [
            (EcCurve::P256, 32),
            (EcCurve::P384, 48),
            (EcCurve::P521, 66),
            (EcCurve::Secp256k1, 32),
            (EcCurve::BrainpoolP256r1, 32),
            (EcCurve::BrainpoolP384r1, 48),
            (EcCurve::BrainpoolP512r1, 64),
        ] {
            let algorithm = SignatureAlgorithm::Ecdsa(curve, HashAlgorithm::Sha256);
            assert!(validate_ecdsa_signature_len(algorithm, &vec![1; 2 * field]).is_ok());
            for length in [0, 2 * field - 1, 2 * field + 1, 4 * field] {
                assert!(
                    validate_ecdsa_signature_len(algorithm, &vec![1; length]).is_err(),
                    "{curve:?} accepted {length} bytes"
                );
            }
        }
        assert!(validate_ecdsa_signature_len(SignatureAlgorithm::Ed448, &[1; 7]).is_ok());
        assert!(validate_ecdsa_signature_len(
            SignatureAlgorithm::RsaPss(HashAlgorithm::Sha256),
            &[1; 7]
        )
        .is_ok());
    }

    /// Missing attributes and claimed sizes cannot substitute for the actual modulus.
    #[test]
    fn rsa_modulus_must_be_present_and_nonzero() {
        let operation = Operation::Sign(SignatureAlgorithm::RsaPss(HashAlgorithm::Sha256));
        for attrs in [
            vec![],
            vec![Attribute::ModulusBits(4096.into())],
            vec![Attribute::Modulus(vec![])],
            vec![Attribute::Modulus(vec![0; 512])],
        ] {
            assert!(check_rsa_modulus(&attrs, operation)
                .unwrap_err()
                .to_string()
                .contains("CKA_MODULUS"));
        }
    }

    /// Significant-bit floors cover all RSA operations and cannot be bypassed by padding.
    #[test]
    fn rsa_modulus_sizes_follow_feature_policy() {
        let minimum = if cfg!(all(feature = "legacy", not(feature = "fips"))) {
            1024
        } else {
            2048
        };
        let rsa = SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha256);
        let pss = SignatureAlgorithm::RsaPss(HashAlgorithm::Sha256);
        let oaep = KeyTransportAlgorithm::RsaOaep(OaepConfig::default());
        for bits in [512usize, 1023, 1024, 2047, 2048, 2049] {
            let mut modulus = vec![0xff; bits.div_ceil(8)];
            modulus[0] >>= (8 - bits % 8) % 8;
            for padding in [0, 257] {
                let mut encoded = vec![0; padding];
                encoded.extend_from_slice(&modulus);
                for operation in [
                    Operation::Sign(rsa),
                    Operation::Sign(pss),
                    Operation::Verify(rsa),
                    Operation::Verify(pss),
                    Operation::TransportEncrypt(oaep),
                    Operation::TransportDecrypt(oaep),
                ] {
                    let result =
                        check_rsa_modulus(&[Attribute::Modulus(encoded.clone())], operation);
                    if bits >= minimum {
                        result.unwrap();
                    } else {
                        assert_unsupported_operation(result, operation);
                    }
                }
            }
        }
    }

    /// Both wrapping directions require the exact expected length, not just block alignment.
    #[test]
    fn keywrap_output_rejects_truncated_and_extended_results() {
        for input_len in [16, 24, 32, 40] {
            for expected in [input_len + 8, input_len] {
                for actual in [0, expected - 8, expected - 1, expected + 1, expected + 8] {
                    let error = check_keywrap_output(vec![0x42; actual], expected).unwrap_err();
                    assert!(
                        error.to_string().contains("output length mismatch"),
                        "{error}"
                    );
                }
                let valid = vec![0x42; expected];
                assert_eq!(
                    check_keywrap_output(valid.clone(), expected).unwrap(),
                    valid
                );
            }
        }
    }
}
