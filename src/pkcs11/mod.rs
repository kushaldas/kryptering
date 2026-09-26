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

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

// ---------------------------------------------------------------------------
// Provider & session
// ---------------------------------------------------------------------------

/// Manages a PKCS#11 library and slot.
pub struct Pkcs11Provider {
    pkcs11: cryptoki::context::Pkcs11,
    slot: cryptoki::slot::Slot,
    /// The library file; part of the token identity the login registry is
    /// keyed by.
    module: ModuleIdentity,
}

impl Pkcs11Provider {
    /// Load a PKCS#11 library from `library_path`, initialize it, and select
    /// the only slot with an initialized token.
    ///
    /// If more than one initialized token is visible, this returns an error
    /// instead of silently selecting the first slot. Multi-token deployments
    /// should use [`new_with_slot_id`](Self::new_with_slot_id) or
    /// [`new_with_token`](Self::new_with_token) so the intended token identity
    /// is pinned by configuration.
    ///
    /// If the library has already been initialized — either by another
    /// `Pkcs11Provider` in the same process or by a non-kryptering PKCS#11
    /// user — `C_Initialize` returning `CKR_CRYPTOKI_ALREADY_INITIALIZED` is
    /// treated as success. Creating multiple providers over the same library
    /// path is therefore safe; the first call wins, the others no-op on the
    /// init step.
    pub fn new(library_path: &Path) -> Result<Self> {
        let pkcs11 = load_initialized_context(library_path)?;
        let slots = pkcs11
            .get_slots_with_initialized_token()
            .map_err(|e| Error::Pkcs11(format!("C_GetSlotList failed: {e}")))?;
        let slot = select_single_initialized_slot(&slots)?;
        Ok(Self {
            pkcs11,
            slot,
            module: module_identity(library_path),
        })
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
        Ok(Self {
            pkcs11,
            slot,
            module: module_identity(library_path),
        })
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
            .get_slots_with_initialized_token()
            .map_err(|e| Error::Pkcs11(format!("C_GetSlotList failed: {e}")))?;
        let mut matches = Vec::new();
        for slot in slots {
            let token_info = pkcs11.get_token_info(slot).map_err(|e| {
                Error::Pkcs11(format!("C_GetTokenInfo failed for slot {slot}: {e}"))
            })?;
            if token_info.label() == token_label
                && token_serial.is_none_or(|serial| token_info.serial_number() == serial)
            {
                matches.push(slot);
            }
        }
        let slot = select_unique_matching_token(&matches, token_label, token_serial)?;
        Ok(Self {
            pkcs11,
            slot,
            module: module_identity(library_path),
        })
    }

    /// Return the selected slot id.
    pub fn slot_id(&self) -> u64 {
        self.slot.id()
    }

    fn open_session_on_slot(&self, pin: &[u8], slot: Slot) -> Result<Pkcs11Session> {
        use cryptoki::error::{Error as CrError, RvError};
        let token = self.token_identity(slot)?;
        // `RawAuthPin` is `secrecy::SecretBox<Vec<u8>>`: the PIN bytes are
        // passed to `C_Login` verbatim (no UTF-8 requirement) and the copy
        // is zeroized on drop.
        let raw_pin = cryptoki::types::RawAuthPin::new(Box::new(pin.to_vec()));
        // Held across `C_OpenSession` and `C_Login`, so that no other
        // kryptering login in this process interleaves and every session
        // kryptering opens is tracked before the next one looks; see
        // [`LoginRecord`].
        let mut logins = login_registry()
            .lock()
            .map_err(|e| Error::Pkcs11(format!("PKCS#11 login registry lock poisoned: {e}")))?;
        // Computed before `C_Login`: if the digest or RNG is unavailable
        // (e.g. an uninitialized FIPS backend) the PIN could not be checked
        // on `CKR_USER_ALREADY_LOGGED_IN`, so refuse up front.
        let verifier = logins.verifier(pin)?;
        let record = logins.track(token);
        let session = self
            .pkcs11
            .open_rw_session(slot)
            .map_err(|e| Error::Pkcs11(format!("C_OpenSession failed: {e}")))?;
        // Login state is per application per token (PKCS#11 v2.40 §5.6):
        // once any session of this application is logged in, `C_Login` on a
        // further session of the same token returns
        // `CKR_USER_ALREADY_LOGGED_IN` without checking the PIN, and the new
        // session is already authenticated. Accept that only for the PIN of
        // the login kryptering recorded; see [`LoginRegistry`]. A refused
        // session is closed on return, while the lock is still held.
        match session.login_with_raw(cryptoki::session::UserType::User, &raw_pin) {
            Ok(()) => record.logged_in(verifier),
            Err(CrError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => record.check(&verifier)?,
            Err(e) => return Err(Error::Pkcs11(format!("C_Login failed: {e}"))),
        }
        let session = Arc::new(Mutex::new(session));
        record.sessions.push(Arc::downgrade(&session));
        drop(logins);
        Ok(Pkcs11Session {
            session,
            pkcs11: self.pkcs11.clone(),
            slot,
        })
    }

    fn token_identity(&self, slot: Slot) -> Result<TokenIdentity> {
        let token_info = self
            .pkcs11
            .get_token_info(slot)
            .map_err(|e| Error::Pkcs11(format!("C_GetTokenInfo failed for slot {slot}: {e}")))?;
        Ok(TokenIdentity {
            module: self.module.clone(),
            slot: slot.id(),
            serial: token_info.serial_number().to_owned(),
            label: token_info.label().to_owned(),
        })
    }
}

/// The library file a provider loaded, so that every path to the same
/// module shares a login-registry entry.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum ModuleIdentity {
    /// Device and inode: the dynamic loader maps every path to the same
    /// file, symbolic and hard links alike, to one loaded module.
    #[cfg(unix)]
    File { dev: u64, ino: u64 },
    /// The path, canonicalized when possible. Used where the file cannot be
    /// inspected, for example a bare file name resolved by the loader.
    Path(PathBuf),
}

fn module_identity(library_path: &Path) -> ModuleIdentity {
    #[cfg(unix)]
    if let Ok(metadata) = std::fs::metadata(library_path) {
        use std::os::unix::fs::MetadataExt;
        return ModuleIdentity::File {
            dev: metadata.dev(),
            ino: metadata.ino(),
        };
    }
    ModuleIdentity::Path(
        std::fs::canonicalize(library_path).unwrap_or_else(|_| library_path.to_path_buf()),
    )
}

/// A token as seen by this process: the module it was loaded through, its
/// slot, and the serial number and label the token reports.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct TokenIdentity {
    module: ModuleIdentity,
    slot: u64,
    serial: String,
    label: String,
}

/// Byte length of the per-process PIN verifier key.
const PIN_VERIFIER_KEY_LEN: usize = 32;

/// Wrong PINs in a row that a [`LoginRecord`] checks before it refuses every
/// further session. Those PINs never reach the token, so its own retry
/// counter does not limit guessing against the record.
const MAX_PIN_MISMATCHES: u32 = 3;

/// PIN verifiers for the tokens this process logged in to through kryptering.
///
/// PKCS#11 cannot check a PIN without `C_Login`, and `C_Login` returns
/// `CKR_USER_ALREADY_LOGGED_IN` without looking at the PIN once any session
/// of the application is logged in to the token. Re-checking it with
/// `C_Logout` + `C_Login` is not an option either: `C_Logout` logs out every
/// session of the application. So every `C_Login` that returns `CKR_OK`
/// records HMAC-SHA-256 of the PIN under a random per-process key, and
/// `CKR_USER_ALREADY_LOGGED_IN` is accepted only when the supplied PIN
/// matches the recorded verifier (compared in constant time). The raw PIN is
/// never stored.
///
/// A PIN change while the token stays logged in (`C_SetPIN` from this or
/// another application) cannot be seen: the old PIN keeps matching until
/// kryptering's sessions on the token are closed and the login ends.
#[derive(Default)]
struct LoginRegistry {
    /// HMAC key, drawn from the provider RNG on first use.
    key: Option<Zeroizing<Vec<u8>>>,
    tokens: HashMap<TokenIdentity, LoginRecord>,
}

/// Kryptering's login to one token.
///
/// The login state lasts while any session of the application on the token
/// is open. Kryptering opens sessions only under the registry lock and adds
/// each one here before releasing it, so when none of them is alive the
/// login the verifier belongs to has ended, or is kept alive by sessions
/// opened outside kryptering: [`LoginRegistry::track`] then drops the
/// verifier. (A session still being closed on another thread can make a
/// join fail closed in the meantime.)
#[derive(Default)]
struct LoginRecord {
    /// Verifier of the PIN of the last `C_Login` that returned `CKR_OK`.
    verifier: Option<Zeroizing<Vec<u8>>>,
    /// Sessions kryptering opened on the token; closed ones are pruned.
    sessions: Vec<Weak<Mutex<cryptoki::session::Session>>>,
    /// Wrong PINs checked against `verifier` since the last match.
    mismatches: u32,
}

fn login_registry() -> &'static Mutex<LoginRegistry> {
    static LOGINS: OnceLock<Mutex<LoginRegistry>> = OnceLock::new();
    LOGINS.get_or_init(Mutex::default)
}

impl LoginRegistry {
    /// HMAC-SHA-256 of `pin` under the per-process key. RNG and digest errors
    /// are returned, never papered over.
    fn verifier(&mut self, pin: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let key = match &mut self.key {
            Some(key) => key.as_slice(),
            empty => empty
                .insert(Zeroizing::new(crate::backend::random_bytes(
                    PIN_VERIFIER_KEY_LEN,
                )?))
                .as_slice(),
        };
        crate::digest::compute_hmac(HashAlgorithm::Sha256, key, pin).map(Zeroizing::new)
    }

    /// The record for `token`, with closed sessions pruned. Without a live
    /// session the login may have ended: the verifier and the mismatch count
    /// are reset.
    fn track(&mut self, token: TokenIdentity) -> &mut LoginRecord {
        let record = self.tokens.entry(token).or_default();
        record.sessions.retain(|session| session.strong_count() > 0);
        if record.sessions.is_empty() {
            record.verifier = None;
            record.mismatches = 0;
        }
        record
    }
}

impl LoginRecord {
    /// Record the verifier of a PIN that `C_Login` accepted.
    fn logged_in(&mut self, verifier: Zeroizing<Vec<u8>>) {
        self.verifier = Some(verifier);
        self.mismatches = 0;
    }

    /// Accept `CKR_USER_ALREADY_LOGGED_IN` only for the recorded PIN, and
    /// only while fewer than [`MAX_PIN_MISMATCHES`] wrong PINs came in a row.
    fn check(&mut self, verifier: &[u8]) -> Result<()> {
        if self.mismatches >= MAX_PIN_MISMATCHES {
            return Err(Error::Pkcs11(format!(
                "{MAX_PIN_MISMATCHES} wrong PINs while the token is logged in: further sessions \
                 are refused until kryptering's sessions on the token are closed"
            )));
        }
        match &self.verifier {
            Some(recorded) if crate::digest::constant_time_eq(recorded, verifier) => {
                self.mismatches = 0;
                Ok(())
            }
            Some(_) => {
                self.mismatches += 1;
                if self.mismatches >= MAX_PIN_MISMATCHES {
                    // Refused from now on; keep nothing to guess against.
                    self.verifier = None;
                }
                Err(Error::Pkcs11(
                    "token is already logged in by this process with a different PIN".into(),
                ))
            }
            None => Err(Error::Pkcs11(
                "cannot verify PIN: token already logged in outside kryptering".into(),
            )),
        }
    }
}

fn load_initialized_context(library_path: &Path) -> Result<cryptoki::context::Pkcs11> {
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
    /// If this process is already logged in to the token through another
    /// session, `C_Login` returns `CKR_USER_ALREADY_LOGGED_IN` without
    /// checking the PIN. The session is then opened only if `pin` equals the
    /// PIN of the kryptering login still in effect on that token, from any
    /// [`Pkcs11Provider`]; otherwise this fails with [`Error::Pkcs11`]. After
    /// three wrong PINs in a row every further session is refused until
    /// kryptering's sessions on the token are closed. See
    /// [`open_session_bytes`](Self::open_session_bytes) for details.
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
    /// PIN checks while already logged in: login state is per process and
    /// token, so once any session is logged in `C_Login` returns
    /// `CKR_USER_ALREADY_LOGGED_IN` for every PIN, and PKCS#11 offers no
    /// other way to check one (`C_Logout` would log out every session). Each
    /// `C_Login` that succeeds therefore records HMAC-SHA-256 of the PIN
    /// under a random per-process key (never the PIN itself) for the token,
    /// identified by module file, slot id, serial number and label. On
    /// `CKR_USER_ALREADY_LOGGED_IN` the session is opened only if the
    /// supplied PIN matches that record in constant time; otherwise this
    /// returns [`Error::Pkcs11`] ("token is already logged in by this
    /// process with a different PIN"). The record is kept only while a
    /// session kryptering opened on the token (or an object made from one)
    /// is alive. Once they are all closed the login has ended; a login that
    /// is still in place was made outside kryptering and is not joined, even
    /// with the right PIN ("cannot verify PIN").
    ///
    /// Those wrong PINs never reach the token, so its retry counter does not
    /// limit them. After three in a row this refuses every further session,
    /// with the right PIN too, until kryptering's sessions on the token are
    /// closed and the next `C_Login` is checked by the token again.
    ///
    /// A PIN change made while the token is logged in (`C_SetPIN` from this
    /// or another application) is not seen: until kryptering's sessions on
    /// the token are closed, the old PIN still opens a session and the new
    /// one is refused.
    ///
    /// Computing the verifier needs the selected provider's RNG and HMAC,
    /// so in a `fips` build this fails with
    /// [`Error::BackendNotInitialized`] until
    /// [`initialize_backend`](crate::backend::initialize_backend) has run.
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
        crate::backend::require_fips_approved(Operation::Verify(self.algorithm))?;
        let mechanism = signature_mechanism(&self.algorithm, Operation::Verify(self.algorithm))?;
        let verify_data = prepare_sign_data(&self.algorithm, data)?;
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
        crate::backend::require_fips_approved(Operation::Sign(self.algorithm))?;
        let mechanism = signature_mechanism(&self.algorithm, Operation::Sign(self.algorithm))?;
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
        crate::backend::require_fips_approved(Operation::Verify(self.algorithm))?;
        let mechanism = signature_mechanism(&self.algorithm, Operation::Verify(self.algorithm))?;
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
        match self.wrap_call {
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
        }
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
        match self.unwrap_call {
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
        }
    }
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
pub struct Pkcs11KeyAgreement {
    session: Arc<Mutex<cryptoki::session::Session>>,
    key_handle: ObjectHandle,
    /// Expected byte-length of the derived shared secret.
    key_len: usize,
    /// Named curve read from the private key's `CKA_EC_PARAMS`, or `None`
    /// if the token did not expose it or it is not P-256/P-384/P-521.
    curve: Option<crate::algorithm::EcCurve>,
}

impl Pkcs11KeyAgreement {
    /// Create a new key agreement object.  `key_label` identifies the EC
    /// private key on the token, and `key_len` is the expected shared secret
    /// size in bytes (e.g. 32 for P-256).
    ///
    /// The curve used for FIPS policy checks is taken from the key's
    /// `CKA_EC_PARAMS` (named-curve OID), not inferred from `key_len`.
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
            Attribute::EcParams(params) => ec_curve_for_ec_params(params),
            _ => None,
        });
        Ok(Self {
            session: Arc::clone(&session.session),
            key_handle,
            key_len,
            curve,
        })
    }
}

/// DER-encoded `namedCurve` OIDs as they appear in `CKA_EC_PARAMS`.
const OID_DER_P256: &[u8] = &[
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // 1.2.840.10045.3.1.7
];
const OID_DER_P384: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]; // 1.3.132.0.34
const OID_DER_P521: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]; // 1.3.132.0.35

/// Map a `CKA_EC_PARAMS` value (DER `ECParameters`) to a supported named
/// curve. Explicit parameters, other named curves, and malformed encodings
/// return `None`.
fn ec_curve_for_ec_params(params: &[u8]) -> Option<crate::algorithm::EcCurve> {
    match params {
        OID_DER_P256 => Some(crate::algorithm::EcCurve::P256),
        OID_DER_P384 => Some(crate::algorithm::EcCurve::P384),
        OID_DER_P521 => Some(crate::algorithm::EcCurve::P521),
        _ => None,
    }
}

impl KeyAgreement for Pkcs11KeyAgreement {
    fn agree(&self, peer_public_key: &[u8]) -> Result<Vec<u8>> {
        if let Some(curve) = self.curve {
            crate::backend::require_fips_approved(Operation::Agreement(curve))?;
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

        // A failed destroy leaves an extractable copy of the shared secret
        // on the token until the session closes. Fail closed so the caller
        // learns about it (and can close the session to purge it) rather
        // than silently continuing; the read secret is zeroized on drop.
        let mut value = value?;
        destroyed.map_err(|e| {
            Error::Pkcs11(format!(
                "C_DestroyObject failed for derived ECDH key; close the session to purge it: {e}"
            ))
        })?;
        Ok(std::mem::take(&mut *value))
    }
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
        // secp256k1 (1.3.132.0.10) has a 32-byte secret but is not approved.
        assert_eq!(
            ec_curve_for_ec_params(&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a]),
            None
        );
        assert_eq!(ec_curve_for_ec_params(&[]), None);
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

    fn token(serial: &str) -> TokenIdentity {
        TokenIdentity {
            module: ModuleIdentity::Path(PathBuf::from("/opt/hsm/libpkcs11.so")),
            slot: 1,
            serial: serial.to_owned(),
            label: "token".to_owned(),
        }
    }

    #[test]
    fn login_record_accepts_only_the_recorded_pin() {
        crate::backend::initialize_backend().expect("backend initialization");
        let mut logins = LoginRegistry::default();
        let verifier = logins.verifier(b"1234").unwrap();
        assert_eq!(verifier.len(), 32);
        assert_ne!(verifier.as_slice(), b"1234");
        assert_eq!(logins.verifier(b"1234").unwrap(), verifier);

        let mut record = LoginRecord::default();
        let err = record.check(&verifier).unwrap_err();
        assert!(
            err.to_string().contains("logged in outside kryptering"),
            "got: {err}"
        );

        record.logged_in(verifier.clone());
        assert!(record.check(&verifier).is_ok());
        // Each run of wrong PINs stays below the limit; the right PIN then
        // resets the count.
        for wrong in [&b"12345"[..], b"123", b"4321", b""] {
            let wrong = logins.verifier(wrong).unwrap();
            for _ in 1..MAX_PIN_MISMATCHES {
                let err = record.check(&wrong).unwrap_err();
                assert!(err.to_string().contains("different PIN"), "got: {err}");
            }
            assert!(record.check(&verifier).is_ok());
        }

        // A later successful login replaces the record.
        let replacement = logins.verifier(b"5678").unwrap();
        record.logged_in(replacement.clone());
        assert!(record.check(&replacement).is_ok());
        assert!(record.check(&verifier).is_err());
    }

    #[test]
    fn login_record_refuses_everything_after_repeated_wrong_pins() {
        crate::backend::initialize_backend().expect("backend initialization");
        let mut logins = LoginRegistry::default();
        let right = logins.verifier(b"1234").unwrap();
        let wrong = logins.verifier(b"0000").unwrap();
        let mut record = LoginRecord::default();
        record.logged_in(right.clone());
        for _ in 0..MAX_PIN_MISMATCHES {
            let err = record.check(&wrong).unwrap_err();
            assert!(err.to_string().contains("different PIN"), "got: {err}");
        }
        assert!(record.verifier.is_none());
        for pin in [&right, &wrong] {
            let err = record.check(pin).unwrap_err();
            assert!(err.to_string().contains("3 wrong PINs"), "got: {err}");
        }
        // Only a `C_Login` the token accepted lifts it.
        record.logged_in(right.clone());
        assert!(record.check(&right).is_ok());
    }

    #[test]
    fn login_registry_forgets_the_pin_without_a_live_session() {
        crate::backend::initialize_backend().expect("backend initialization");
        let mut logins = LoginRegistry::default();
        let right = logins.verifier(b"1234").unwrap();
        let wrong = logins.verifier(b"0000").unwrap();
        let record = logins.track(token("a"));
        record.logged_in(right.clone());
        assert!(record.check(&wrong).is_err());
        assert_eq!(record.mismatches, 1);

        // No session kryptering opened is alive: the login may have ended.
        let record = logins.track(token("a"));
        assert!(record.verifier.is_none());
        assert_eq!(record.mismatches, 0);
        let err = record.check(&right).unwrap_err();
        assert!(
            err.to_string().contains("logged in outside kryptering"),
            "got: {err}"
        );
        // Records are per token.
        logins.track(token("a")).logged_in(right.clone());
        assert!(logins.tokens[&token("a")].verifier.is_some());
        assert!(logins.track(token("b")).verifier.is_none());
    }

    #[test]
    fn login_registry_keys_are_per_registry() {
        crate::backend::initialize_backend().expect("backend initialization");
        let first = LoginRegistry::default().verifier(b"1234").unwrap();
        let second = LoginRegistry::default().verifier(b"1234").unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn module_identity_names_the_file() {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let other_spelling = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("..")
            .join("Cargo.toml");
        assert_eq!(module_identity(&manifest), module_identity(&other_spelling));
        assert_ne!(
            module_identity(&manifest),
            module_identity(&Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md"))
        );
        // A bare name the loader resolves stays as given.
        assert_eq!(
            module_identity(Path::new("libkryptering-missing-module.so")),
            ModuleIdentity::Path(PathBuf::from("libkryptering-missing-module.so"))
        );
    }

    #[test]
    fn kek_value_len_check() {
        let len = |n: usize| Attribute::ValueLen(n.try_into().unwrap());
        assert!(check_kek_value_len(&[len(32)], 32).is_ok());
        assert!(check_kek_value_len(&[len(16)], 32).is_err());
        // Attribute not exposed by the token: fall through.
        assert!(check_kek_value_len(&[], 32).is_ok());
    }
}
