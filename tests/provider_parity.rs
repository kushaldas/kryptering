//! Cases that must behave identically under every document provider.
//!
//! Each test runs against whichever provider the build selects, so CI runs
//! this file once per provider feature set. FIPS builds run every case too:
//! approved operations must give the same answers, and operations FIPS does
//! not approve must be refused as unsupported rather than skipped.

use kryptering::kdf::{HkdfParams, Pbkdf2Params};
use kryptering::{
    AesKeySize, EcCurve, HashAlgorithm, KeyAlgorithm, KeyWrapAlgorithm, Operation,
    SignatureAlgorithm, SoftwareKey, SoftwareSigner, SoftwareVerifier,
};
use kryptering::{Signer, Verifier};

use p256::elliptic_curve::Generate;

/// Infallible `CryptoRng` view of the OS RNG for test fixtures that demand one.
fn test_rng() -> rand_core::UnwrapErr<getrandom::SysRng> {
    rand_core::UnwrapErr(getrandom::SysRng)
}

fn decode(hex_value: &str) -> Vec<u8> {
    hex::decode(hex_value).expect("valid test vector")
}

/// Assert that `operation` was refused as unsupported, as FIPS builds do for
/// every operation the module does not approve.
fn assert_refused<T>(result: kryptering::Result<T>, operation: Operation) {
    match result {
        Err(kryptering::Error::UnsupportedAlgorithm {
            operation: actual, ..
        }) if actual == operation => {}
        Err(error) => panic!("{operation:?} failed without being refused: {error}"),
        Ok(_) => panic!("{operation:?} was accepted"),
    }
}

#[test]
fn raw_symmetric_import_rejects_asymmetric_families() {
    kryptering::initialize_backend().expect("provider initialization");
    for algorithm in [
        KeyAlgorithm::Rsa,
        KeyAlgorithm::Ec(EcCurve::P256),
        KeyAlgorithm::Ed25519,
        KeyAlgorithm::X25519,
        KeyAlgorithm::Dh,
    ] {
        assert!(
            SoftwareKey::from_symmetric_bytes(algorithm, b"not a raw symmetric key").is_err(),
            "{algorithm:?} accepted raw bytes"
        );
    }
    assert!(SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Hmac, b"secret").is_ok());
    assert!(SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Aes, &[0; 32]).is_ok());
    assert!(SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Aes, &[0; 20]).is_err());
}

#[test]
fn x25519_agreement_matches_rfc7748_and_checks_key_type() {
    kryptering::initialize_backend().expect("provider initialization");
    // RFC 7748 §6.1.
    let alice_private = decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let alice_public = decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let bob_public = decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let shared = decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    let aes = SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Aes, &[7; 32]).unwrap();

    if cfg!(feature = "fips") {
        // X25519 is not FIPS approved: every entry point refuses the RFC
        // inputs before inspecting them or the key type.
        assert_refused(
            kryptering::keyagreement::ecdh_x25519(&bob_public, &alice_private),
            Operation::X25519Agreement,
        );
        assert_refused(
            SoftwareKey::from_x25519(Some(&alice_private), &alice_public),
            Operation::KeyImport(KeyAlgorithm::X25519),
        );
        assert_refused(
            kryptering::keyagreement::agree_x25519(&bob_public, &aes),
            Operation::X25519Agreement,
        );
    } else {
        assert_eq!(
            kryptering::keyagreement::ecdh_x25519(&bob_public, &alice_private).unwrap(),
            shared
        );
        let alice = SoftwareKey::from_x25519(Some(&alice_private), &alice_public).unwrap();
        assert_eq!(
            kryptering::keyagreement::agree_x25519(&bob_public, &alice).unwrap(),
            shared
        );

        assert!(kryptering::keyagreement::agree_x25519(&bob_public, &aes).is_err());
        assert!(kryptering::keyagreement::ecdh_x25519(&bob_public, &alice_private[..31]).is_err());
    }
}

/// RFC 8032 §7.4 "-----Blank" Ed448 vector wrapped as RFC 8410 PKCS#8 v1 / SPKI.
fn ed448_rfc8032_blank_keys() -> (Vec<u8>, Vec<u8>) {
    let seed = decode("6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b");
    let public = decode("5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180");
    let mut pkcs8 = decode("3047020100300506032b6571043b0439");
    pkcs8.extend(seed);
    let mut spki = decode("3043300506032b6571033a00");
    spki.extend(public);
    (pkcs8, spki)
}

/// Ed448 is implemented by RustCrypto only; AWS-LC and FIPS refuse it before
/// looking at key material. Where implemented, it reproduces RFC 8032 §7.4.
#[test]
fn ed448_matches_rfc8032_and_is_refused_where_unsupported() {
    kryptering::initialize_backend().expect("provider initialization");
    let (pkcs8, spki) = ed448_rfc8032_blank_keys();
    let expected = decode("533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600");
    let hmac = SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Hmac, b"secret").unwrap();

    if cfg!(feature = "rustcrypto") {
        let private = SoftwareKey::from_pkcs8_der(KeyAlgorithm::Ed448, &pkcs8).unwrap();
        let public = SoftwareKey::from_spki_der(KeyAlgorithm::Ed448, &spki).unwrap();
        assert_eq!(private.export_spki_der().unwrap(), spki);
        let signer = SoftwareSigner::new(SignatureAlgorithm::Ed448, private).unwrap();
        let signature = signer.sign(b"").unwrap();
        assert_eq!(signature, expected);
        let verifier = SoftwareVerifier::new(SignatureAlgorithm::Ed448, public).unwrap();
        assert!(verifier.verify(b"", &signature).unwrap());
        assert!(!verifier.verify(b"x", &signature).unwrap());
        assert!(SoftwareSigner::new(SignatureAlgorithm::Ed448, hmac).is_err());
    } else {
        assert_refused(
            SoftwareKey::from_pkcs8_der(KeyAlgorithm::Ed448, &pkcs8),
            Operation::KeyImport(KeyAlgorithm::Ed448),
        );
        assert_refused(
            SoftwareKey::from_spki_der(KeyAlgorithm::Ed448, &spki),
            Operation::KeyImport(KeyAlgorithm::Ed448),
        );
        // Refusal precedes the key-family check.
        assert_refused(
            SoftwareSigner::new(SignatureAlgorithm::Ed448, hmac.clone()),
            Operation::Sign(SignatureAlgorithm::Ed448),
        );
        assert_refused(
            SoftwareVerifier::new(SignatureAlgorithm::Ed448, hmac),
            Operation::Verify(SignatureAlgorithm::Ed448),
        );
    }
}

/// X448 mirrors the X25519 contract: RFC 7748 §6.2 where implemented
/// (RustCrypto), typed refusal elsewhere.
#[test]
fn x448_agreement_matches_rfc7748_and_checks_key_type() {
    kryptering::initialize_backend().expect("provider initialization");
    let alice_private = decode("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
    let alice_public = decode("9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0");
    let bob_public = decode("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609");
    let shared = decode("07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");
    let aes = SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Aes, &[7; 32]).unwrap();

    if cfg!(feature = "rustcrypto") {
        assert_eq!(
            kryptering::keyagreement::ecdh_x448(&bob_public, &alice_private).unwrap(),
            shared
        );
        let alice = SoftwareKey::from_x448(Some(&alice_private), &alice_public).unwrap();
        assert_eq!(
            kryptering::keyagreement::agree_x448(&bob_public, &alice).unwrap(),
            shared
        );
        assert!(kryptering::keyagreement::agree_x448(&bob_public, &aes).is_err());
        assert!(kryptering::keyagreement::ecdh_x448(&bob_public, &alice_private[..55]).is_err());
        assert!(kryptering::keyagreement::ecdh_x448(&[0; 56], &alice_private).is_err());
    } else {
        assert_refused(
            kryptering::keyagreement::ecdh_x448(&bob_public, &alice_private),
            Operation::X448Agreement,
        );
        assert_refused(
            SoftwareKey::from_x448(Some(&alice_private), &alice_public),
            Operation::KeyImport(KeyAlgorithm::X448),
        );
        assert_refused(
            kryptering::keyagreement::agree_x448(&bob_public, &aes),
            Operation::X448Agreement,
        );
    }
}

#[test]
fn signers_reject_keys_of_another_family() {
    kryptering::initialize_backend().expect("provider initialization");
    let hmac = SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Hmac, b"secret").unwrap();
    for algorithm in [
        SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha256),
        SignatureAlgorithm::Ecdsa(EcCurve::P256, HashAlgorithm::Sha256),
        SignatureAlgorithm::Ed25519,
        SignatureAlgorithm::Ed448,
    ] {
        assert!(SoftwareSigner::new(algorithm, hmac.clone()).is_err());
        assert!(SoftwareVerifier::new(algorithm, hmac.clone()).is_err());
    }
    if cfg!(feature = "fips") {
        // FIPS refuses Ed25519 itself, before the key family is checked.
        assert_refused(
            SoftwareSigner::new(SignatureAlgorithm::Ed25519, hmac.clone()),
            Operation::Sign(SignatureAlgorithm::Ed25519),
        );
        assert_refused(
            SoftwareVerifier::new(SignatureAlgorithm::Ed25519, hmac),
            Operation::Verify(SignatureAlgorithm::Ed25519),
        );
    }
}

/// Encode a P-256 signature's fixed-width r||s as minimal DER.
fn p256_der(raw: &[u8]) -> Vec<u8> {
    p256::ecdsa::Signature::from_slice(raw)
        .unwrap()
        .to_der()
        .as_bytes()
        .to_vec()
}

#[test]
fn ecdsa_verify_accepts_the_same_encodings() {
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};

    kryptering::initialize_backend().expect("provider initialization");
    let private = p256::SecretKey::generate_from_rng(&mut test_rng());
    let key = SoftwareKey::from_pkcs8_der(
        KeyAlgorithm::Ec(EcCurve::P256),
        private.to_pkcs8_der().unwrap().as_bytes(),
    )
    .unwrap();
    let public = SoftwareKey::from_spki_der(
        KeyAlgorithm::Ec(EcCurve::P256),
        private.public_key().to_public_key_der().unwrap().as_bytes(),
    )
    .unwrap();
    let algorithm = SignatureAlgorithm::Ecdsa(EcCurve::P256, HashAlgorithm::Sha256);
    let raw = SoftwareSigner::new(algorithm, key)
        .unwrap()
        .sign(b"parity")
        .unwrap();
    assert_eq!(raw.len(), 64);
    let verifier = SoftwareVerifier::new(algorithm, public).unwrap();

    let mut padded = vec![0];
    padded.extend_from_slice(&raw[..32]);
    padded.push(0);
    padded.extend_from_slice(&raw[32..]);

    for (name, encoding) in [
        ("raw", raw.clone()),
        ("DER", p256_der(&raw)),
        ("padded", padded),
    ] {
        assert!(verifier.verify(b"parity", &encoding).unwrap(), "{name}");
        assert!(!verifier.verify(b"tampered", &encoding).unwrap(), "{name}");
    }
    assert!(verifier.verify(b"parity", &[0; 64]).is_err());
    assert!(verifier.verify(b"parity", &raw[..63]).is_err());
}

/// Encode public test scalars without applying validity checks to the fixture.
fn ecdsa_test_der(raw: &[u8]) -> Vec<u8> {
    let mut content = Vec::new();
    for scalar in raw.chunks_exact(raw.len() / 2) {
        let start = scalar
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(scalar.len() - 1);
        let scalar = &scalar[start..];
        let sign = usize::from(scalar[0] & 0x80 != 0);
        content.extend([2, (scalar.len() + sign) as u8]);
        if sign != 0 {
            content.push(0);
        }
        content.extend(scalar);
    }
    let mut der = vec![0x30];
    if content.len() >= 128 {
        der.push(0x81);
    }
    der.push(content.len() as u8);
    der.extend(content);
    der
}

/// Every provider applies identical encoding precedence and scalar-order bounds.
#[test]
fn ecdsa_encoding_and_scalar_boundaries_match() {
    use p256::elliptic_curve::Curve;
    use p256::pkcs8::EncodePublicKey;
    kryptering::initialize_backend().unwrap();
    // (curve, subgroup order at raw width, SPKI, canonical hash)
    let cases = [
        (
            EcCurve::P256,
            p256::NistP256::ORDER.to_be_bytes().to_vec(),
            p256::SecretKey::generate_from_rng(&mut test_rng())
                .public_key()
                .to_public_key_der()
                .unwrap(),
            HashAlgorithm::Sha256,
        ),
        (
            EcCurve::P384,
            p384::NistP384::ORDER.to_be_bytes().to_vec(),
            p384::SecretKey::generate_from_rng(&mut test_rng())
                .public_key()
                .to_public_key_der()
                .unwrap(),
            HashAlgorithm::Sha384,
        ),
        (
            EcCurve::P521,
            p521::NistP521::ORDER.to_be_bytes()[6..].to_vec(),
            p521::SecretKey::generate_from_rng(&mut test_rng())
                .public_key()
                .to_public_key_der()
                .unwrap(),
            HashAlgorithm::Sha512,
        ),
        (
            EcCurve::Secp256k1,
            k256::Secp256k1::ORDER.to_be_bytes().to_vec(),
            k256::SecretKey::generate_from_rng(&mut test_rng())
                .public_key()
                .to_public_key_der()
                .unwrap(),
            HashAlgorithm::Sha256,
        ),
        (
            EcCurve::BrainpoolP256r1,
            bp256::BrainpoolP256r1::ORDER.to_be_bytes().to_vec(),
            bp256::r1::SecretKey::generate_from_rng(&mut test_rng())
                .public_key()
                .to_public_key_der()
                .unwrap(),
            HashAlgorithm::Sha256,
        ),
        (
            EcCurve::BrainpoolP384r1,
            bp384::BrainpoolP384r1::ORDER.to_be_bytes().to_vec(),
            bp384::r1::SecretKey::generate_from_rng(&mut test_rng())
                .public_key()
                .to_public_key_der()
                .unwrap(),
            HashAlgorithm::Sha384,
        ),
    ];
    for (curve, order, spki, hash) in cases {
        let field = order.len();
        if !kryptering::supports(Operation::KeyImport(KeyAlgorithm::Ec(curve))).unwrap() {
            // secp256k1 under FIPS, Brainpool on AWS-LC / FIPS: a typed
            // refusal at import, before any parsing.
            assert_refused(
                SoftwareKey::from_spki_der(KeyAlgorithm::Ec(curve), spki.as_bytes()),
                Operation::KeyImport(KeyAlgorithm::Ec(curve)),
            );
            continue;
        }
        let key = SoftwareKey::from_spki_der(KeyAlgorithm::Ec(curve), spki.as_bytes()).unwrap();
        let verifier = SoftwareVerifier::new(SignatureAlgorithm::Ecdsa(curve, hash), key).unwrap();
        let mut one = vec![0; field];
        one[field - 1] = 1;
        let mut below = order.clone();
        below[field - 1] -= 1;
        let mut above = order.clone();
        above[field - 1] += 1;
        for scalar in [one.clone(), below] {
            let raw = [scalar.as_slice(), one.as_slice()].concat();
            let der = ecdsa_test_der(&raw);
            assert_eq!(
                kryptering::digest::ecdsa_raw_to_der(curve, &der).unwrap(),
                der
            );
            assert_eq!(
                kryptering::digest::ecdsa_der_to_raw(curve, &der).unwrap(),
                raw
            );
            assert!(!verifier.verify(b"boundary", &der).unwrap());
        }
        // Well-formed DER with an over-width scalar must not fall back to raw.
        let mut oversized = vec![0; 2 * (field + 1)];
        oversized[0] = 1;
        *oversized.last_mut().unwrap() = 1;
        let oversized_der = ecdsa_test_der(&oversized);
        assert!(kryptering::digest::ecdsa_raw_to_der(curve, &oversized_der).is_err());
        assert!(verifier.verify(b"boundary", &oversized_der).is_err());
        // r=s=1 produces an eight-byte DER value, well below every raw width.
        let short = [0x30, 6, 2, 1, 1, 2, 1, 1];
        assert_eq!(
            kryptering::digest::ecdsa_raw_to_der(curve, &short).unwrap(),
            short
        );
        for invalid in [vec![0; field], order, above, vec![0xff; field]] {
            for swap in [false, true] {
                let raw = if swap {
                    [one.as_slice(), invalid.as_slice()].concat()
                } else {
                    [invalid.as_slice(), one.as_slice()].concat()
                };
                let der = ecdsa_test_der(&raw);
                let padded = [&[0][..], &raw[..field], &[0], &raw[field..]].concat();
                assert!(kryptering::digest::ecdsa_der_to_raw(curve, &der).is_err());
                for encoding in [&raw, &der, &padded] {
                    assert!(
                        kryptering::digest::ecdsa_raw_to_der(curve, encoding).is_err(),
                        "{curve:?}"
                    );
                    assert!(verifier.verify(b"boundary", encoding).is_err(), "{curve:?}");
                }
            }
        }
        // A DER value can have exactly the raw width: only explicit DER APIs
        // may interpret that ambiguous input as DER.
        let (r_len, s_len) = if curve == EcCurve::P521 {
            (62, 63)
        } else {
            (field - 3, field - 3)
        };
        let mut components = vec![0; field * 2];
        components[field - r_len..field].fill(1);
        components[2 * field - s_len..].fill(1);
        let ambiguous = ecdsa_test_der(&components);
        assert_eq!(ambiguous.len(), field * 2);
        assert_eq!(
            kryptering::digest::ecdsa_der_to_raw(curve, &ambiguous).unwrap(),
            components
        );
        if curve == EcCurve::P521 {
            assert!(kryptering::digest::ecdsa_raw_to_der(curve, &ambiguous).is_err());
        } else {
            let encoded = kryptering::digest::ecdsa_raw_to_der(curve, &ambiguous).unwrap();
            assert_eq!(
                kryptering::digest::ecdsa_der_to_raw(curve, &encoded).unwrap(),
                ambiguous
            );
        }
        let mut raw = [one.as_slice(), one.as_slice()].concat();
        raw[0] = 0x30;
        if curve == EcCurve::P521 {
            // A P-521 scalar cannot have 0x30 in its most significant octet.
            assert!(kryptering::digest::ecdsa_raw_to_der(curve, &raw).is_err());
        } else {
            let der = kryptering::digest::ecdsa_raw_to_der(curve, &raw).unwrap();
            assert_eq!(
                kryptering::digest::ecdsa_der_to_raw(curve, &der).unwrap(),
                raw
            );
        }
    }
}

/// Strict DER conversion rejects malformed lengths and noncanonical integers.
#[test]
fn ecdsa_malformed_der_is_rejected_without_panics() {
    for curve in [
        EcCurve::P256,
        EcCurve::P384,
        EcCurve::P521,
        EcCurve::Secp256k1,
        EcCurve::BrainpoolP256r1,
        EcCurve::BrainpoolP384r1,
        EcCurve::BrainpoolP512r1,
    ] {
        let excessive = [
            vec![0x30, 0x80 | std::mem::size_of::<usize>() as u8],
            vec![0xff; std::mem::size_of::<usize>()],
        ]
        .concat();
        for der in [
            excessive,
            vec![0x30, 6, 2, 1, 0, 2, 1, 1],
            vec![0x30, 7, 2, 2, 0, 1, 2, 1, 1],
            vec![0x30, 6, 2, 1, 0x80, 2, 1, 1],
        ] {
            assert!(kryptering::digest::ecdsa_der_to_raw(curve, &der).is_err());
        }
    }
}

#[test]
fn ecdsa_verifies_cross_curve_digest_pairs() {
    use p384::ecdsa::signature::hazmat::PrehashSigner;
    use p384::pkcs8::EncodePublicKey;

    kryptering::initialize_backend().expect("provider initialization");
    // XML-DSig pairs a P-384 key with whatever digest the URI names.
    let signing = p384::ecdsa::SigningKey::generate_from_rng(&mut test_rng());
    let public = SoftwareKey::from_spki_der(
        KeyAlgorithm::Ec(EcCurve::P384),
        signing
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let digest = kryptering::digest::digest(HashAlgorithm::Sha256, b"cross").unwrap();
    let signature: p384::ecdsa::Signature = signing.sign_prehash(&digest).unwrap();
    let verifier = SoftwareVerifier::new(
        SignatureAlgorithm::Ecdsa(EcCurve::P384, HashAlgorithm::Sha256),
        public,
    )
    .unwrap();
    assert!(verifier.verify(b"cross", &signature.to_bytes()).unwrap());
    assert!(!verifier.verify(b"tampered", &signature.to_bytes()).unwrap());
}

#[test]
fn rsa_keys_below_2048_bits_are_refused_when_used() {
    use kryptering::{KeyTransportAlgorithm, OaepConfig};
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};

    kryptering::initialize_backend().expect("provider initialization");
    let private = rsa::RsaPrivateKey::new(&mut test_rng(), 1024).unwrap();
    let spki = private.to_public_key().to_public_key_der().unwrap();
    let pkcs8 = private.to_pkcs8_der().unwrap();
    let public = SoftwareKey::from_spki_der(KeyAlgorithm::Rsa, spki.as_bytes());
    let private = SoftwareKey::from_pkcs8_der(KeyAlgorithm::Rsa, pkcs8.as_bytes());
    if cfg!(feature = "fips") {
        // FIPS builds refuse short RSA keys already at import.
        assert!(public.is_err() && private.is_err());
        return;
    }
    let public = public.unwrap();
    let algorithm = SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha256);
    // The one intended difference: RustCrypto with `legacy` uses short RSA
    // keys for historical interoperability; AWS-LC never does.
    let usable = cfg!(all(feature = "rustcrypto", feature = "legacy"));
    match private {
        Ok(private) => assert_eq!(SoftwareSigner::new(algorithm, private).is_ok(), usable),
        // AWS-LC's RSA key-pair parser itself refuses short private keys.
        Err(_) => assert!(!usable && cfg!(feature = "aws-lc")),
    }
    let verified = SoftwareVerifier::new(algorithm, public.clone())
        .and_then(|verifier| verifier.verify(b"message", &[0; 128]));
    assert_eq!(verified.is_ok(), usable, "{verified:?}");
    if !usable {
        assert!(verified
            .unwrap_err()
            .to_string()
            .contains("1024-bit RSA key"));
    }
    let oaep = KeyTransportAlgorithm::RsaOaep(OaepConfig::default());
    let transported = kryptering::keytransport::kt_encrypt(oaep, &public, &[0x42; 16], None);
    assert_eq!(transported.is_ok(), usable, "{transported:?}");
}

#[test]
fn aes_cbc_rejects_iv_only_input() {
    kryptering::initialize_backend().expect("provider initialization");
    for size in [AesKeySize::Aes128, AesKeySize::Aes256] {
        let key = vec![3; size.key_len()];
        assert!(kryptering::hazmat::aes_cbc::decrypt(size, &key, &[9; 16]).is_err());
        let sealed = kryptering::hazmat::aes_cbc::encrypt(size, &key, b"").unwrap();
        assert_eq!(sealed.len(), 32);
        assert!(kryptering::hazmat::aes_cbc::decrypt(size, &key, &sealed)
            .unwrap()
            .is_empty());
    }
}

#[test]
fn aes_key_wrap_matches_rfc3394_and_rejects_short_input() {
    kryptering::initialize_backend().expect("provider initialization");
    // RFC 3394 §4.1 and §4.6.
    let kek128 = decode("000102030405060708090A0B0C0D0E0F");
    let kek256 = decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    let data = decode("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");
    for (size, kek, input, expected) in [
        (
            AesKeySize::Aes128,
            &kek128,
            &data[..16],
            "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
        ),
        (
            AesKeySize::Aes256,
            &kek256,
            &data[..],
            "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
        ),
    ] {
        let algorithm = KeyWrapAlgorithm::AesKw(size);
        let wrapped = kryptering::keywrap::wrap(algorithm, kek, input).unwrap();
        assert_eq!(wrapped, decode(expected));
        assert_eq!(
            kryptering::keywrap::unwrap(algorithm, kek, &wrapped).unwrap(),
            input
        );
        let mut tampered = wrapped.clone();
        tampered[0] ^= 1;
        assert!(kryptering::keywrap::unwrap(algorithm, kek, &tampered).is_err());

        assert!(kryptering::keywrap::wrap(algorithm, kek, &[]).is_err());
        assert!(kryptering::keywrap::wrap(algorithm, kek, &[1; 8]).is_err());
        assert!(kryptering::keywrap::wrap(algorithm, kek, &[1; 20]).is_err());
        assert!(kryptering::keywrap::unwrap(algorithm, kek, &wrapped[..16]).is_err());
    }
}

#[test]
fn kdfs_match_rfc_vectors() {
    kryptering::initialize_backend().expect("provider initialization");
    // RFC 5869 A.2 (long inputs) and A.3 (no salt, no info).
    let a2 = kryptering::kdf::hkdf_derive(
        &(0u8..=0x4f).collect::<Vec<_>>(),
        82,
        &HkdfParams {
            hash: HashAlgorithm::Sha256,
            salt: Some((0x60u8..=0xaf).collect()),
            info: Some((0xb0u8..=0xff).collect()),
            key_length_bits: 0,
        },
    )
    .unwrap();
    assert_eq!(
        a2,
        decode(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87"
        )
    );
    let a3 = kryptering::kdf::hkdf_derive(&[0x0b; 22], 42, &HkdfParams::default()).unwrap();
    assert_eq!(
        a3,
        decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8"
        )
    );
    assert!(kryptering::kdf::hkdf_derive(&[1], 255 * 32 + 1, &HkdfParams::default()).is_err());

    // Cross-checked against Python's hashlib.pbkdf2_hmac. The 8-byte salt and
    // password are below the SP 800-132 minimums FIPS builds enforce.
    for (hash, len, expected) in [
        (HashAlgorithm::Sha256, 64, "2ecc2dfd549e0925a0e4a0b860368e7492b6e65339188d3e1e9e43799b90ff64cf800fb11ff3602b51ed7c8c766643c32be8af72829b3146642d9ddbdf8d7d6d"),
        (HashAlgorithm::Sha512, 40, "fee75217fa12304834340c9e672f9aaa9cc4bb229a9fd37edcdcd6ae57b42ad8ca5ea636c777c33c"),
    ] {
        let output = kryptering::kdf::pbkdf2_derive(
            b"Password",
            &Pbkdf2Params {
                hash,
                salt: b"NaCl1234".to_vec(),
                iteration_count: 1000,
                key_length: len,
            },
        );
        if cfg!(feature = "fips") {
            assert!(
                matches!(
                    output,
                    Err(kryptering::Error::Crypto(ref message))
                        if message.contains("SP 800-132")
                ),
                "{hash:?}: {output:?}"
            );
        } else {
            assert_eq!(output.unwrap(), decode(expected), "{hash:?}");
        }
    }

    // The same shapes with SP 800-132 compliant parameters (128-bit salt and
    // password, 1000 iterations), which every provider including FIPS must
    // derive identically. Cross-checked against Python's hashlib.pbkdf2_hmac.
    for (hash, len, expected) in [
        (HashAlgorithm::Sha256, 64, "1e30cde84a0370317564c82ece78efb738195387129590d2fd3d7b48714a40c874de73f494b275b7147b58171cc17101b3cba6a0bd0a3766c839dd7e98f71aed"),
        (HashAlgorithm::Sha512, 40, "20ae6a68e7f944784e186fa29c12c6ae0926c736f4cdb5f025becc9c70a0e12cf39145acd1ad6113"),
    ] {
        let output = kryptering::kdf::pbkdf2_derive(
            b"PasswordPassword",
            &Pbkdf2Params {
                hash,
                salt: b"NaCl1234NaCl1234".to_vec(),
                iteration_count: 1000,
                key_length: len,
            },
        )
        .unwrap();
        assert_eq!(output, decode(expected), "{hash:?}");
    }

    let recommended = Pbkdf2Params::recommended(HashAlgorithm::Sha512, b"salt".to_vec(), 32);
    assert_eq!(recommended.hash, HashAlgorithm::Sha512);
    assert_eq!(recommended.iteration_count, 210_000);
}

/// ES256K: both providers verify low-S and high-S encodings of the same
/// signature (RustCrypto normalizes, AWS-LC accepts natively). Only the
/// RustCrypto signer guarantees low-S output; AWS-LC emits whichever form
/// the nonce produced. FIPS refuses the curve outright.
#[test]
fn secp256k1_high_s_signature_verifies_on_every_provider() {
    use k256::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use p256::elliptic_curve::Curve;
    kryptering::initialize_backend().expect("provider initialization");
    let private = k256::SecretKey::generate_from_rng(&mut test_rng());
    let pkcs8 = private.to_pkcs8_der().unwrap();
    let spki = private.public_key().to_public_key_der().unwrap();
    let algorithm = SignatureAlgorithm::Ecdsa(EcCurve::Secp256k1, HashAlgorithm::Sha256);
    if cfg!(feature = "fips") {
        assert_refused(
            SoftwareKey::from_pkcs8_der(KeyAlgorithm::Ec(EcCurve::Secp256k1), pkcs8.as_bytes()),
            Operation::KeyImport(KeyAlgorithm::Ec(EcCurve::Secp256k1)),
        );
        let hmac = SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Hmac, b"secret").unwrap();
        assert_refused(
            SoftwareSigner::new(algorithm, hmac),
            Operation::Sign(algorithm),
        );
        return;
    }
    let key = SoftwareKey::from_pkcs8_der(KeyAlgorithm::Ec(EcCurve::Secp256k1), pkcs8.as_bytes())
        .unwrap();
    let public =
        SoftwareKey::from_spki_der(KeyAlgorithm::Ec(EcCurve::Secp256k1), spki.as_bytes()).unwrap();
    let raw = SoftwareSigner::new(algorithm, key)
        .unwrap()
        .sign(b"ES256K")
        .unwrap();
    assert_eq!(raw.len(), 64);

    // n - s: the high-S twin of a low-S signature (and vice versa).
    let order = k256::Secp256k1::ORDER.to_be_bytes();
    let mut twin_s = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let diff = i16::from(order[i]) - i16::from(raw[32 + i]) - borrow;
        borrow = i16::from(diff < 0);
        twin_s[i] = (diff + 256 * borrow) as u8;
    }
    let mut twin = raw[..32].to_vec();
    twin.extend(twin_s);
    // Low-S means s <= n/2, i.e. s < its twin. Order the pair by that rule
    // rather than assuming which one the provider emitted.
    let (low_s, high_s) = if raw[32..] < twin[32..] {
        (raw.clone(), twin)
    } else {
        (twin, raw.clone())
    };
    if cfg!(feature = "rustcrypto") {
        assert_eq!(raw, low_s, "RustCrypto signer must emit low-S");
    }

    let verifier = SoftwareVerifier::new(algorithm, public).unwrap();
    for (name, signature) in [("low-S", low_s), ("high-S", high_s)] {
        assert!(verifier.verify(b"ES256K", &signature).unwrap(), "{name}");
        assert!(!verifier.verify(b"tampered", &signature).unwrap(), "{name}");
        let der = kryptering::digest::ecdsa_raw_to_der(EcCurve::Secp256k1, &signature).unwrap();
        assert!(
            verifier.verify_der_signature(b"ES256K", &der).unwrap(),
            "{name} DER"
        );
    }
}

/// Wycheproof `ecdsa_secp256k1_sha256_test.json` (v1) cases through the
/// shared DER path. The "signature malleability" case is *valid* here: both
/// providers accept high-S (only Bitcoin consensus rejects it). Encoding and
/// range faults must be rejected, as `Ok(false)` or a typed error.
#[test]
fn secp256k1_wycheproof_vectors() {
    kryptering::initialize_backend().expect("provider initialization");
    let spki = decode("3056301006072a8648ce3d020106052b8104000a03420004b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9");
    let curve = KeyAlgorithm::Ec(EcCurve::Secp256k1);
    if cfg!(feature = "fips") {
        assert_refused(
            SoftwareKey::from_spki_der(curve, &spki),
            Operation::KeyImport(curve),
        );
        return;
    }
    let public = SoftwareKey::from_spki_der(curve, &spki).unwrap();
    let verifier = SoftwareVerifier::new(
        SignatureAlgorithm::Ecdsa(EcCurve::Secp256k1, HashAlgorithm::Sha256),
        public,
    )
    .unwrap();
    // (tcId, valid, msg, DER signature)
    let cases = [
        (5, true, "313233343030", "3046022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365022100900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87"),
        (295, true, "3235353835", "3045022100dd1b7d09a7bd8218961034a39a87fecf5314f00c4d25eb58a07ac85e85eab516022035138c401ef8d3493d65c9002fe62b43aee568731b744548358996d9cc427e06"),
        (296, true, "343236343739373234", "304502210095c29267d972a043d955224546222bba343fc1d4db0fec262a33ac61305696ae02206edfe96713aed56f8a28a6653f57e0b829712e5eddc67f34682b24f0676b2640"),
        // MissingZero: r encoded as a negative INTEGER.
        (6, false, "313233343030", "30440220813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba"),
        // BerEncodedSignature: long-form length for a short sequence.
        (8, false, "313233343030", "308145022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba"),
        // InvalidEncoding: sequence length off by one.
        (10, false, "313233343030", "3046022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba"),
        // ModifiedSignature: trailing bytes after the sequence.
        (23, false, "313233343030", "3047022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba0000"),
        // RangeCheck: r + n.
        (152, false, "313233343030", "3045022101813ef79ccefa9a56f7ba805f0e478583b90deabca4b05c4574e49b5899b964a602206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba"),
        // ModifiedInteger: -r.
        (155, false, "313233343030", "30450221ff7ec10863310565a908457fa0f1b87a7b01a0f22a0a9843f64aedc334367cdc9b02206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba"),
        // IntegerOverflow: r + 2^256.
        (158, false, "313233343030", "3045022101813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba"),
        // InvalidSignature: r = s = 0.
        (168, false, "313233343030", "3006020100020100"),
        // InvalidTypesInSignature: s is a REAL.
        (232, false, "313233343030", "3008020100090380fe01"),
    ];
    for (tc_id, valid, msg, sig) in cases {
        let result = verifier.verify_der_signature(&decode(msg), &decode(sig));
        if valid {
            assert!(result.unwrap(), "Wycheproof tcId {tc_id} must verify");
        } else {
            assert!(
                !matches!(result, Ok(true)),
                "Wycheproof tcId {tc_id} must be rejected"
            );
        }
    }
}

/// brainpoolP512r1 has no software implementation anywhere (RustCrypto has no
/// bp512 crate, aws-lc-rs has no Brainpool): both providers refuse it with a
/// typed error before parsing. Only PKCS#11 tokens serve it.
#[test]
fn brainpool_p512r1_is_pkcs11_only() {
    kryptering::initialize_backend().expect("provider initialization");
    // RFC 7027 A.3 Q_A as SPKI (id-ecPublicKey, brainpoolP512r1).
    let mut spki = decode("30819b301406072a8648ce3d020106092b240303020801010d0381820004");
    spki.extend(decode("0A420517E406AAC0ACDCE90FCD71487718D3B953EFD7FBEC5F7F27E28C6149999397E91E029E06457DB2D3E640668B392C2A7E737A7F0BF04436D11640FD09FD"));
    spki.extend(decode("72E6882E8DB28AAD36237CD25D580DB23783961C8DC52DFA2EC138AD472A0FCEF3887CF62B623B2A87DE5C588301EA3E5FC269B373B60724F5E82A6AD147FDE7"));
    let curve = KeyAlgorithm::Ec(EcCurve::BrainpoolP512r1);
    assert!(!kryptering::supports(Operation::KeyImport(curve)).unwrap());
    assert!(!kryptering::supports(Operation::Agreement(EcCurve::BrainpoolP512r1)).unwrap());
    assert_refused(
        SoftwareKey::from_spki_der(curve, &spki),
        Operation::KeyImport(curve),
    );
    let aes = SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Aes, &[7; 32]).unwrap();
    let algorithm = SignatureAlgorithm::Ecdsa(EcCurve::BrainpoolP512r1, HashAlgorithm::Sha512);
    assert_refused(
        SoftwareSigner::new(algorithm, aes.clone()),
        Operation::Sign(algorithm),
    );
    assert_refused(
        kryptering::keyagreement::agree(EcCurve::BrainpoolP512r1, &spki[spki.len() - 129..], &aes),
        Operation::Agreement(EcCurve::BrainpoolP512r1),
    );
}
