#![forbid(unsafe_code)]

//! Key agreement: ECDH (P-256, P-384, P-521, secp256k1, brainpoolP256r1,
//! brainpoolP384r1), X25519, X448, and finite-field Diffie-Hellman (X9.42).
//!
//! Finite-field DH ([`agree_dh`]) delegates to [`crate::hazmat::dh`], which
//! exponentiates with `crypto_bigint`'s constant-time Montgomery `pow` over
//! an exponent padded to the modulus width, and validates the group
//! parameters, private exponent range, and peer subgroup membership. It
//! exists for legacy XML-Enc / CMS interop; prefer ECDH or X25519.
//!
//! Upstream shared-secret types (`p256::ecdh::SharedSecret`,
//! `x25519_dalek::SharedSecret`, `x448::SharedSecret`) wipe themselves on
//! drop; the returned `Vec<u8>` is the caller's copy to protect.

use crate::backend::{require_supported, Operation};
use crate::error::{Error, Result};
use crate::key::{RustCryptoKey, SoftwareKey};
use zeroize::Zeroizing;

/// Compute ECDH using an opaque provider key.
pub fn agree(
    curve: crate::algorithm::EcCurve,
    peer_public: &[u8],
    private: &SoftwareKey,
) -> Result<Vec<u8>> {
    // Refuse unsupported curves (e.g. brainpoolP512r1, which has no
    // RustCrypto implementation) before looking at the key at all.
    require_supported(Operation::Agreement(curve))?;
    match (curve, private.inner()) {
        (
            crate::algorithm::EcCurve::P256,
            RustCryptoKey::EcP256 {
                private: Some(key), ..
            },
        ) => {
            let scalar = Zeroizing::new(key.to_bytes());
            let key = p256::SecretKey::from_slice(scalar.as_slice())
                .map_err(|e| Error::Key(format!("P-256 private conversion failed: {e}")))?;
            ecdh_p256(peer_public, &key)
        }
        (
            crate::algorithm::EcCurve::P384,
            RustCryptoKey::EcP384 {
                private: Some(key), ..
            },
        ) => {
            let scalar = Zeroizing::new(key.to_bytes());
            let key = p384::SecretKey::from_slice(scalar.as_slice())
                .map_err(|e| Error::Key(format!("P-384 private conversion failed: {e}")))?;
            ecdh_p384(peer_public, &key)
        }
        (
            crate::algorithm::EcCurve::P521,
            RustCryptoKey::EcP521 {
                private: Some(key), ..
            },
        ) => {
            let scalar = Zeroizing::new(key.to_bytes());
            let key = p521::SecretKey::from_slice(scalar.as_slice())
                .map_err(|e| Error::Key(format!("P-521 private conversion failed: {e}")))?;
            ecdh_p521(peer_public, &key)
        }
        (
            crate::algorithm::EcCurve::Secp256k1,
            RustCryptoKey::EcSecp256k1 {
                private: Some(key), ..
            },
        ) => {
            let scalar = Zeroizing::new(key.to_bytes());
            let key = k256::SecretKey::from_slice(scalar.as_slice())
                .map_err(|e| Error::Key(format!("secp256k1 private conversion failed: {e}")))?;
            ecdh_secp256k1(peer_public, &key)
        }
        (
            crate::algorithm::EcCurve::BrainpoolP256r1,
            RustCryptoKey::EcBrainpoolP256r1 {
                private: Some(key), ..
            },
        ) => {
            let scalar = Zeroizing::new(key.to_bytes());
            let key = bp256::r1::SecretKey::from_slice(scalar.as_slice()).map_err(|e| {
                Error::Key(format!("brainpoolP256r1 private conversion failed: {e}"))
            })?;
            ecdh_brainpool_p256r1(peer_public, &key)
        }
        (
            crate::algorithm::EcCurve::BrainpoolP384r1,
            RustCryptoKey::EcBrainpoolP384r1 {
                private: Some(key), ..
            },
        ) => {
            let scalar = Zeroizing::new(key.to_bytes());
            let key = bp384::r1::SecretKey::from_slice(scalar.as_slice()).map_err(|e| {
                Error::Key(format!("brainpoolP384r1 private conversion failed: {e}"))
            })?;
            ecdh_brainpool_p384r1(peer_public, &key)
        }
        _ => Err(Error::Key(format!(
            "private {curve:?} key required for ECDH"
        ))),
    }
}

/// Compute an ECDH shared secret (x-coordinate) over brainpoolP256r1.
pub fn ecdh_brainpool_p256r1(
    originator_public: &[u8],
    recipient_private: &bp256::r1::SecretKey,
) -> Result<Vec<u8>> {
    require_supported(Operation::Agreement(
        crate::algorithm::EcCurve::BrainpoolP256r1,
    ))?;
    let public_key =
        elliptic_curve::PublicKey::<bp256::BrainpoolP256r1>::from_sec1_bytes(originator_public)
            .map_err(|e| Error::Key(format!("invalid brainpoolP256r1 public key: {e}")))?;
    let shared_secret = elliptic_curve::ecdh::diffie_hellman(
        recipient_private.to_nonzero_scalar(),
        public_key.as_affine(),
    );
    Ok(shared_secret.raw_secret_bytes().to_vec())
}

/// Compute an ECDH shared secret (x-coordinate) over brainpoolP384r1.
pub fn ecdh_brainpool_p384r1(
    originator_public: &[u8],
    recipient_private: &bp384::r1::SecretKey,
) -> Result<Vec<u8>> {
    require_supported(Operation::Agreement(
        crate::algorithm::EcCurve::BrainpoolP384r1,
    ))?;
    let public_key =
        elliptic_curve::PublicKey::<bp384::BrainpoolP384r1>::from_sec1_bytes(originator_public)
            .map_err(|e| Error::Key(format!("invalid brainpoolP384r1 public key: {e}")))?;
    let shared_secret = elliptic_curve::ecdh::diffie_hellman(
        recipient_private.to_nonzero_scalar(),
        public_key.as_affine(),
    );
    Ok(shared_secret.raw_secret_bytes().to_vec())
}

/// Compute an ECDH shared secret (x-coordinate) over secp256k1.
pub fn ecdh_secp256k1(
    originator_public: &[u8],
    recipient_private: &k256::SecretKey,
) -> Result<Vec<u8>> {
    require_supported(Operation::Agreement(crate::algorithm::EcCurve::Secp256k1))?;
    let public_key = k256::PublicKey::from_sec1_bytes(originator_public)
        .map_err(|e| Error::Key(format!("invalid secp256k1 public key: {e}")))?;
    let shared_secret = k256::ecdh::diffie_hellman(
        recipient_private.to_nonzero_scalar(),
        public_key.as_affine(),
    );
    Ok(shared_secret.raw_secret_bytes().to_vec())
}

/// Compute X25519 agreement using an opaque provider key.
pub fn agree_x25519(peer_public: &[u8], private: &SoftwareKey) -> Result<Vec<u8>> {
    match private.inner() {
        RustCryptoKey::X25519 {
            private: Some(key), ..
        } => ecdh_x25519(peer_public, key),
        _ => Err(Error::Key("X25519 private key required".into())),
    }
}

/// Compute finite-field Diffie-Hellman agreement without exporting the
/// private exponent from the opaque key handle. Group validation is retained
/// from import; peer and private-exponent validation still run on every call.
pub fn agree_dh(peer_public: &[u8], private: &SoftwareKey) -> Result<Vec<u8>> {
    require_supported(Operation::DhAgreement)?;
    match private.inner() {
        RustCryptoKey::Dh {
            private: Some(exponent),
            group,
            ..
        } => group.agree(peer_public, exponent),
        _ => Err(Error::Key("finite-field DH private key required".into())),
    }
}

/// Compute an ECDH shared secret for P-256.
///
/// Takes the originator's (ephemeral) public key as uncompressed SEC1 bytes
/// and the recipient's (static) private key.
pub fn ecdh_p256(originator_public: &[u8], recipient_private: &p256::SecretKey) -> Result<Vec<u8>> {
    require_supported(Operation::Agreement(crate::algorithm::EcCurve::P256))?;
    // `from_sec1_bytes` parses the SEC1 encoding and rejects the identity
    // point and off-curve coordinates in one step.
    let public_key = p256::PublicKey::from_sec1_bytes(originator_public)
        .map_err(|e| Error::Key(format!("invalid P-256 public key: {e}")))?;

    let shared_secret = p256::ecdh::diffie_hellman(
        recipient_private.to_nonzero_scalar(),
        public_key.as_affine(),
    );

    Ok(shared_secret.raw_secret_bytes().to_vec())
}

/// Compute an ECDH shared secret for P-384.
pub fn ecdh_p384(originator_public: &[u8], recipient_private: &p384::SecretKey) -> Result<Vec<u8>> {
    require_supported(Operation::Agreement(crate::algorithm::EcCurve::P384))?;
    // `from_sec1_bytes` parses the SEC1 encoding and rejects the identity
    // point and off-curve coordinates in one step.
    let public_key = p384::PublicKey::from_sec1_bytes(originator_public)
        .map_err(|e| Error::Key(format!("invalid P-384 public key: {e}")))?;

    let shared_secret = p384::ecdh::diffie_hellman(
        recipient_private.to_nonzero_scalar(),
        public_key.as_affine(),
    );

    Ok(shared_secret.raw_secret_bytes().to_vec())
}

/// Compute an ECDH shared secret for P-521.
pub fn ecdh_p521(originator_public: &[u8], recipient_private: &p521::SecretKey) -> Result<Vec<u8>> {
    require_supported(Operation::Agreement(crate::algorithm::EcCurve::P521))?;
    // `from_sec1_bytes` parses the SEC1 encoding and rejects the identity
    // point and off-curve coordinates in one step.
    let public_key = p521::PublicKey::from_sec1_bytes(originator_public)
        .map_err(|e| Error::Key(format!("invalid P-521 public key: {e}")))?;

    let shared_secret = p521::ecdh::diffie_hellman(
        recipient_private.to_nonzero_scalar(),
        public_key.as_affine(),
    );

    Ok(shared_secret.raw_secret_bytes().to_vec())
}

/// Compute X448 agreement using an opaque provider key.
///
/// `peer_public` is the peer's raw 56-byte little-endian u-coordinate and
/// `private` must hold an X448 private scalar (see
/// [`SoftwareKey::from_x448`]). Returns the 56-byte shared secret; see
/// [`ecdh_x448`] for the low-order and all-zero rejection rules.
pub fn agree_x448(peer_public: &[u8], private: &SoftwareKey) -> Result<Vec<u8>> {
    match private.inner() {
        RustCryptoKey::X448 {
            private: Some(key), ..
        } => ecdh_x448(peer_public, key),
        _ => Err(Error::Key("X448 private key required".into())),
    }
}

/// Compute an X448 shared secret (RFC 7748 §5 / §6.2).
///
/// Both inputs are the raw 56-byte little-endian encodings. The peer's
/// u-coordinate is rejected when it is one of the canonical low-order
/// encodings (u = 0, 1, p-1), and the output is additionally checked for
/// the all-zero value because non-canonical encodings (u >= p) reduce to
/// those points inside the ladder (RFC 7748 §6.2, §7).
pub fn ecdh_x448(originator_public: &[u8], recipient_private: &[u8]) -> Result<Vec<u8>> {
    require_supported(Operation::X448Agreement)?;
    if originator_public.len() != 56 {
        return Err(Error::Key(format!(
            "invalid X448 public key length: {} (expected 56)",
            originator_public.len()
        )));
    }
    if recipient_private.len() != 56 {
        return Err(Error::Key(format!(
            "invalid X448 private key length: {} (expected 56)",
            recipient_private.len()
        )));
    }
    let their_public = x448::PublicKey::from_bytes(originator_public).ok_or_else(|| {
        Error::Key("X448 peer public key is malformed or a low-order point".into())
    })?;

    // Same stack-copy discipline as `ecdh_x25519`: `StaticSecret::from`
    // takes the array by value and wipes its own copy on drop, so wipe
    // ours explicitly instead of leaving it in this frame.
    let mut priv_bytes = [0u8; 56];
    priv_bytes.copy_from_slice(recipient_private);
    let my_secret = x448::StaticSecret::from(priv_bytes);
    {
        use zeroize::Zeroize;
        priv_bytes.zeroize();
    }

    let shared_secret = my_secret.diffie_hellman(&their_public);
    if shared_secret
        .as_bytes()
        .iter()
        .fold(0u8, |acc, byte| acc | byte)
        == 0
    {
        return Err(Error::Key(
            "X448 peer public key is a low-order point (shared secret is all zero)".into(),
        ));
    }
    Ok(shared_secret.as_bytes().to_vec())
}

/// Compute an X25519 Diffie-Hellman shared secret (RFC 7748).
///
/// Takes the originator's (ephemeral) public key as raw 32 bytes
/// and the recipient's (static) private key as raw 32 bytes.
/// Returns the 32-byte shared secret.
///
/// Rejects attacker-chosen low-order peer public keys that would force the
/// shared secret to the identity (all-zero) output. RFC 7748 §6.1 notes
/// that implementers MAY check for this "non-contributory" behaviour; in
/// practice any protocol that feeds the shared secret into a KDF and then
/// authenticates with it is subverted if the peer can pin the secret to a
/// known value, so we perform the check unconditionally.
pub fn ecdh_x25519(originator_public: &[u8], recipient_private: &[u8]) -> Result<Vec<u8>> {
    require_supported(Operation::X25519Agreement)?;
    if originator_public.len() != 32 {
        return Err(Error::Key(format!(
            "invalid X25519 public key length: {} (expected 32)",
            originator_public.len()
        )));
    }
    if recipient_private.len() != 32 {
        return Err(Error::Key(format!(
            "invalid X25519 private key length: {} (expected 32)",
            recipient_private.len()
        )));
    }

    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(originator_public);
    let their_public = x25519_dalek::PublicKey::from(pub_bytes);

    // priv_bytes is a stack copy of the caller's private scalar. StaticSecret
    // takes the array by value (so `my_secret` holds its own copy, wiped by
    // x25519-dalek's ZeroizeOnDrop), but our stack copy must be wiped
    // explicitly or it lingers in this frame until the function returns.
    let mut priv_bytes = [0u8; 32];
    priv_bytes.copy_from_slice(recipient_private);
    let my_secret = x25519_dalek::StaticSecret::from(priv_bytes);
    {
        use zeroize::Zeroize;
        priv_bytes.zeroize();
    }

    let shared_secret = my_secret.diffie_hellman(&their_public);
    if !shared_secret.was_contributory() {
        return Err(Error::Key(
            "X25519 peer public key is a low-order point (shared secret is identity)".into(),
        ));
    }
    Ok(shared_secret.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use p256::elliptic_curve::Generate;

    /// Infallible `CryptoRng` view of the OS RNG for test fixtures that demand one.
    fn test_rng() -> rand_core::UnwrapErr<getrandom::SysRng> {
        rand_core::UnwrapErr(getrandom::SysRng)
    }
    use super::*;

    #[test]
    fn x25519_roundtrip() {
        // Both parties generate key pairs; shared secret must match
        let alice_secret = x25519_dalek::StaticSecret::random_from_rng(&mut test_rng());
        let alice_public = x25519_dalek::PublicKey::from(&alice_secret);

        let bob_secret = x25519_dalek::StaticSecret::random_from_rng(&mut test_rng());
        let bob_public = x25519_dalek::PublicKey::from(&bob_secret);

        // Alice computes shared secret with Bob's public key
        let shared_alice = ecdh_x25519(bob_public.as_bytes(), alice_secret.as_bytes()).unwrap();

        // Bob computes shared secret with Alice's public key
        let shared_bob = ecdh_x25519(alice_public.as_bytes(), bob_secret.as_bytes()).unwrap();

        assert_eq!(shared_alice, shared_bob);
        assert_eq!(shared_alice.len(), 32);
    }

    #[test]
    fn x25519_rejects_low_order_public_key() {
        // The all-zero public key is the canonical low-order point: it maps
        // to the identity on Curve25519, so the DH output is forced to the
        // all-zero shared secret regardless of the recipient's private key.
        // An earlier version of ecdh_x25519 returned that all-zero secret
        // without complaint, letting a malicious peer pin the KDF input.
        let secret = x25519_dalek::StaticSecret::random_from_rng(&mut test_rng());
        let low_order_pub = [0u8; 32];
        let err = ecdh_x25519(&low_order_pub, secret.as_bytes()).unwrap_err();
        assert!(
            err.to_string().contains("low-order"),
            "unexpected error: {err}"
        );
    }

    /// Agreement uses validated production-size parameters behind an opaque private key.
    #[test]
    fn finite_field_dh_uses_opaque_private_key() {
        let (p, g, q) = crate::hazmat::dh::tests::parameters();
        let private = SoftwareKey::from_dh_parameters(&p, &g, Some(&q), Some(&[1]), &g).unwrap();
        assert_eq!(agree_dh(&g, &private).unwrap(), g);
    }

    #[test]
    fn x25519_invalid_public_key_length() {
        let secret = [0u8; 32];
        let short_pub = [0u8; 16];
        let err = ecdh_x25519(&short_pub, &secret).unwrap_err();
        assert!(
            err.to_string().contains("invalid X25519 public key length"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn x25519_invalid_private_key_length() {
        let pub_key = [0u8; 32];
        let short_priv = [0u8; 16];
        let err = ecdh_x25519(&pub_key, &short_priv).unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid X25519 private key length"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn x25519_deterministic() {
        // Same inputs produce same output
        let alice_secret = x25519_dalek::StaticSecret::random_from_rng(&mut test_rng());
        let bob_secret = x25519_dalek::StaticSecret::random_from_rng(&mut test_rng());
        let bob_public = x25519_dalek::PublicKey::from(&bob_secret);

        let shared1 = ecdh_x25519(bob_public.as_bytes(), alice_secret.as_bytes()).unwrap();
        let shared2 = ecdh_x25519(bob_public.as_bytes(), alice_secret.as_bytes()).unwrap();

        assert_eq!(shared1, shared2);
    }

    #[test]
    fn p256_roundtrip() {
        use p256::elliptic_curve::sec1::ToSec1Point;

        let alice_secret = p256::SecretKey::generate_from_rng(&mut test_rng());
        let alice_public = alice_secret.public_key();

        let bob_secret = p256::SecretKey::generate_from_rng(&mut test_rng());
        let bob_public = bob_secret.public_key();

        let shared_alice =
            ecdh_p256(bob_public.to_sec1_point(false).as_bytes(), &alice_secret).unwrap();
        let shared_bob =
            ecdh_p256(alice_public.to_sec1_point(false).as_bytes(), &bob_secret).unwrap();

        assert_eq!(shared_alice, shared_bob);
        assert_eq!(shared_alice.len(), 32);
    }

    #[test]
    fn p384_roundtrip() {
        use p384::elliptic_curve::sec1::ToSec1Point;

        let alice_secret = p384::SecretKey::generate_from_rng(&mut test_rng());
        let alice_public = alice_secret.public_key();

        let bob_secret = p384::SecretKey::generate_from_rng(&mut test_rng());
        let bob_public = bob_secret.public_key();

        let shared_alice =
            ecdh_p384(bob_public.to_sec1_point(false).as_bytes(), &alice_secret).unwrap();
        let shared_bob =
            ecdh_p384(alice_public.to_sec1_point(false).as_bytes(), &bob_secret).unwrap();

        assert_eq!(shared_alice, shared_bob);
        assert_eq!(shared_alice.len(), 48);
    }

    #[test]
    fn p521_roundtrip() {
        use p521::elliptic_curve::sec1::ToSec1Point;

        let alice_secret = p521::SecretKey::generate_from_rng(&mut test_rng());
        let alice_public = alice_secret.public_key();

        let bob_secret = p521::SecretKey::generate_from_rng(&mut test_rng());
        let bob_public = bob_secret.public_key();

        let shared_alice =
            ecdh_p521(bob_public.to_sec1_point(false).as_bytes(), &alice_secret).unwrap();
        let shared_bob =
            ecdh_p521(alice_public.to_sec1_point(false).as_bytes(), &bob_secret).unwrap();

        assert_eq!(shared_alice, shared_bob);
        assert_eq!(shared_alice.len(), 66);
    }

    // RFC 7748 §6.2 X448 Diffie-Hellman vector.
    const X448_ALICE_PRIVATE: &str = "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b";
    const X448_ALICE_PUBLIC: &str = "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0";
    const X448_BOB_PRIVATE: &str = "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d";
    const X448_BOB_PUBLIC: &str = "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609";
    const X448_SHARED: &str = "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d";

    /// Invariant: X448 reproduces RFC 7748 §6.2 from both sides and the
    /// §5.2 single-call vectors, through both the raw and opaque-key APIs.
    #[test]
    fn x448_matches_rfc7748_vectors() {
        let alice_private = hex::decode(X448_ALICE_PRIVATE).unwrap();
        let alice_public = hex::decode(X448_ALICE_PUBLIC).unwrap();
        let bob_private = hex::decode(X448_BOB_PRIVATE).unwrap();
        let bob_public = hex::decode(X448_BOB_PUBLIC).unwrap();
        let shared = hex::decode(X448_SHARED).unwrap();
        assert_eq!(ecdh_x448(&bob_public, &alice_private).unwrap(), shared);
        assert_eq!(ecdh_x448(&alice_public, &bob_private).unwrap(), shared);
        let alice =
            crate::key::SoftwareKey::from_x448(Some(&alice_private), &alice_public).unwrap();
        assert_eq!(agree_x448(&bob_public, &alice).unwrap(), shared);
        assert_eq!(
            agree_x448(&bob_public, &alice).unwrap(),
            shared,
            "deterministic"
        );

        // RFC 7748 §5.2 (scalar, u-coordinate, output), one call each.
        for (scalar, u, output) in [
            (
                "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
                "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
                "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f",
            ),
            (
                "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f",
                "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db",
                "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d",
            ),
        ] {
            assert_eq!(
                hex::encode(ecdh_x448(&hex::decode(u).unwrap(), &hex::decode(scalar).unwrap()).unwrap()),
                output
            );
        }
    }

    /// Invariant: low-order peer points (RFC 7748 §6.2 / §7) are rejected
    /// before any secret is derived, and wrong lengths or key families error.
    #[test]
    fn x448_rejects_low_order_points_lengths_and_foreign_keys() {
        let private = hex::decode(X448_ALICE_PRIVATE).unwrap();
        for low_order in [
            ed448_goldilocks::MontgomeryPoint::LOW_A.0,
            ed448_goldilocks::MontgomeryPoint::LOW_B.0,
            ed448_goldilocks::MontgomeryPoint::LOW_C.0,
        ] {
            let err = ecdh_x448(&low_order, &private).unwrap_err();
            assert!(
                err.to_string().contains("low-order"),
                "unexpected error: {err}"
            );
        }
        let public = hex::decode(X448_BOB_PUBLIC).unwrap();
        assert!(ecdh_x448(&public[..55], &private).is_err());
        let mut long = public.clone();
        long.push(0);
        assert!(ecdh_x448(&long, &private).is_err());
        assert!(ecdh_x448(&public, &private[..55]).is_err());
        assert!(crate::key::SoftwareKey::from_x448(Some(&private[..55]), &public).is_err());
        assert!(crate::key::SoftwareKey::from_x448(None, &public[..55]).is_err());

        let x25519 = crate::key::SoftwareKey::from_x25519(Some(&[9; 32]), &[9; 32]).unwrap();
        assert!(agree_x448(&public, &x25519).is_err());
        let public_only = crate::key::SoftwareKey::from_x448(None, &public).unwrap();
        assert!(agree_x448(&public, &public_only).is_err());
    }

    /// Invariant: secp256k1 ECDH is symmetric, 32 bytes, and rejects the
    /// identity / off-curve peer encodings.
    #[test]
    fn secp256k1_roundtrip_and_rejects_invalid_points() {
        use p256::elliptic_curve::sec1::ToSec1Point;
        use p256::elliptic_curve::Generate;
        let alice = k256::SecretKey::generate_from_rng(&mut test_rng());
        let bob = k256::SecretKey::generate_from_rng(&mut test_rng());
        let alice_point = alice.public_key().to_sec1_point(false);
        let bob_point = bob.public_key().to_sec1_point(false);
        let shared_alice = ecdh_secp256k1(bob_point.as_bytes(), &alice).unwrap();
        let shared_bob = ecdh_secp256k1(alice_point.as_bytes(), &bob).unwrap();
        assert_eq!(shared_alice, shared_bob);
        assert_eq!(shared_alice.len(), 32);
        // Compressed peer encodings are accepted too.
        let compressed = bob.public_key().to_sec1_point(true);
        assert_eq!(
            ecdh_secp256k1(compressed.as_bytes(), &alice).unwrap(),
            shared_alice
        );

        assert!(ecdh_secp256k1(&[0x00], &alice).is_err(), "identity");
        let mut off_curve = alice_point.as_bytes().to_vec();
        off_curve[64] ^= 1;
        assert!(ecdh_secp256k1(&off_curve, &bob).is_err(), "off-curve");

        let opaque = crate::key::SoftwareKey::from_pkcs8_der(
            crate::backend::KeyAlgorithm::Ec(crate::algorithm::EcCurve::Secp256k1),
            {
                use k256::pkcs8::EncodePrivateKey;
                alice.to_pkcs8_der().unwrap().as_bytes()
            },
        )
        .unwrap();
        assert_eq!(
            agree(
                crate::algorithm::EcCurve::Secp256k1,
                bob_point.as_bytes(),
                &opaque
            )
            .unwrap(),
            shared_alice
        );
        assert!(agree(
            crate::algorithm::EcCurve::P256,
            bob_point.as_bytes(),
            &opaque
        )
        .is_err());
    }

    /// Invariant: Brainpool ECDH reproduces RFC 7027 Appendix A from both
    /// sides, through the raw and opaque-key entry points.
    #[test]
    fn brainpool_ecdh_matches_rfc7027() {
        fn peer_point(x: &str, y: &str) -> Vec<u8> {
            let mut point = vec![0x04];
            point.extend(hex::decode(x).unwrap());
            point.extend(hex::decode(y).unwrap());
            point
        }
        // A.1 brainpoolP256r1
        let d_a = hex::decode("81DB1EE100150FF2EA338D708271BE38300CB54241D79950F77B063039804F1D")
            .unwrap();
        let q_a = peer_point(
            "44106E913F92BC02A1705D9953A8414DB95E1AAA49E81D9E85F929A8E3100BE5",
            "8AB4846F11CACCB73CE49CBDD120F5A900A69FD32C272223F789EF10EB089BDC",
        );
        let d_b = hex::decode("55E40BC41E37E3E2AD25C3C6654511FFA8474A91A0032087593852D3E7D76BD3")
            .unwrap();
        let q_b = peer_point(
            "8D2D688C6CF93E1160AD04CC4429117DC2C41825E1E9FCA0ADDD34E6F1B39F7B",
            "990C57520812BE512641E47034832106BC7D3E8DD0E4C7F1136D7006547CEC6A",
        );
        let x_z = hex::decode("89AFC39D41D3B327814B80940B042590F96556EC91E6AE7939BCE31F3A18BF2B")
            .unwrap();
        let a = bp256::r1::SecretKey::from_slice(&d_a).unwrap();
        let b = bp256::r1::SecretKey::from_slice(&d_b).unwrap();
        assert_eq!(ecdh_brainpool_p256r1(&q_b, &a).unwrap(), x_z);
        assert_eq!(ecdh_brainpool_p256r1(&q_a, &b).unwrap(), x_z);
        let opaque = {
            use pkcs8::EncodePrivateKey;
            crate::key::SoftwareKey::from_pkcs8_der(
                crate::backend::KeyAlgorithm::Ec(crate::algorithm::EcCurve::BrainpoolP256r1),
                a.to_pkcs8_der().unwrap().as_bytes(),
            )
            .unwrap()
        };
        assert_eq!(
            agree(crate::algorithm::EcCurve::BrainpoolP256r1, &q_b, &opaque).unwrap(),
            x_z
        );
        assert!(agree(crate::algorithm::EcCurve::P256, &q_b, &opaque).is_err());
        assert!(ecdh_brainpool_p256r1(&[0x00], &a).is_err(), "identity");

        // A.2 brainpoolP384r1
        let d_a = hex::decode("1E20F5E048A5886F1F157C74E91BDE2B98C8B52D58E5003D57053FC4B0BD65D6F15EB5D1EE1610DF870795143627D042").unwrap();
        let q_a = peer_point(
            "68B665DD91C195800650CDD363C625F4E742E8134667B767B1B476793588F885AB698C852D4A6E77A252D6380FCAF068",
            "55BC91A39C9EC01DEE36017B7D673A931236D2F1F5C83942D049E3FA20607493E0D038FF2FD30C2AB67D15C85F7FAA59",
        );
        let d_b = hex::decode("032640BC6003C59260F7250C3DB58CE647F98E1260ACCE4ACDA3DD869F74E01F8BA5E0324309DB6A9831497ABAC96670").unwrap();
        let q_b = peer_point(
            "4D44326F269A597A5B58BBA565DA5556ED7FD9A8A9EB76C25F46DB69D19DC8CE6AD18E404B15738B2086DF37E71D1EB4",
            "62D692136DE56CBE93BF5FA3188EF58BC8A3A0EC6C1E151A21038A42E9185329B5B275903D192F8D4E1F32FE9CC78C48",
        );
        let x_z = hex::decode("0BD9D3A7EA0B3D519D09D8E48D0785FB744A6B355E6304BC51C229FBBCE239BBADF6403715C35D4FB2A5444F575D4F42").unwrap();
        let a = bp384::r1::SecretKey::from_slice(&d_a).unwrap();
        let b = bp384::r1::SecretKey::from_slice(&d_b).unwrap();
        assert_eq!(ecdh_brainpool_p384r1(&q_b, &a).unwrap(), x_z);
        assert_eq!(ecdh_brainpool_p384r1(&q_a, &b).unwrap(), x_z);
    }
}
