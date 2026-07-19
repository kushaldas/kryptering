#![cfg(not(feature = "fips"))]

use kryptering::kdf::{ConcatKdfParams, HkdfParams, Pbkdf2Params};
use kryptering::{
    AesKeySize, CipherAlgorithm, EcCurve, HashAlgorithm, KeyAlgorithm, KeyTransportAlgorithm,
    KeyWrapAlgorithm, OaepConfig, SignatureAlgorithm, SoftwareKey, SoftwareSigner,
    SoftwareVerifier,
};
use kryptering::{Signer, Verifier};

fn decode(hex_value: &str) -> Vec<u8> {
    hex::decode(hex_value).expect("valid test vector")
}

#[test]
fn digest_hmac_streaming_and_rng_known_answers() {
    let expected = decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(
        kryptering::digest::digest(HashAlgorithm::Sha256, b"abc").unwrap(),
        expected
    );

    let mut stream = kryptering::digest::new_digest(HashAlgorithm::Sha256).unwrap();
    stream.update(b"a");
    stream.update(b"bc");
    assert_eq!(stream.finalize().unwrap(), expected);

    let mac = kryptering::digest::compute_hmac(
        HashAlgorithm::Sha256,
        b"key",
        b"The quick brown fox jumps over the lazy dog",
    )
    .unwrap();
    assert_eq!(
        mac,
        decode("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
    );

    let first = kryptering::random_bytes(32).unwrap();
    let second = kryptering::random_bytes(32).unwrap();
    assert_eq!(first.len(), 32);
    assert_ne!(
        first, second,
        "two provider RNG outputs unexpectedly matched"
    );
}

#[test]
fn aes_gcm_cbc_and_key_wrap_interoperate_with_known_vectors() {
    let plaintext = b"provider baseline plaintext";
    let key = [0x42; 16];

    let gcm =
        kryptering::cipher::encrypt(CipherAlgorithm::AesGcm(AesKeySize::Aes128), &key, plaintext)
            .unwrap();
    assert_eq!(
        kryptering::cipher::decrypt(CipherAlgorithm::AesGcm(AesKeySize::Aes128), &key, &gcm,)
            .unwrap(),
        plaintext
    );
    let mut tampered = gcm;
    *tampered.last_mut().unwrap() ^= 1;
    assert!(kryptering::cipher::decrypt(
        CipherAlgorithm::AesGcm(AesKeySize::Aes128),
        &key,
        &tampered,
    )
    .is_err());

    let cbc = kryptering::hazmat::aes_cbc::encrypt(AesKeySize::Aes128, &key, plaintext).unwrap();
    assert_eq!(
        kryptering::hazmat::aes_cbc::decrypt(AesKeySize::Aes128, &key, &cbc).unwrap(),
        plaintext
    );

    let kek = decode("000102030405060708090a0b0c0d0e0f");
    let key_data = decode("00112233445566778899aabbccddeeff");
    let wrapped =
        kryptering::keywrap::wrap(KeyWrapAlgorithm::AesKw(AesKeySize::Aes128), &kek, &key_data)
            .unwrap();
    assert_eq!(
        wrapped,
        decode("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5")
    );
    assert_eq!(
        kryptering::keywrap::unwrap(KeyWrapAlgorithm::AesKw(AesKeySize::Aes128), &kek, &wrapped,)
            .unwrap(),
        key_data
    );
}

#[test]
fn kdfs_match_known_answers() {
    let concat = kryptering::kdf::concat_kdf(
        b"shared secret",
        32,
        &ConcatKdfParams {
            hash: HashAlgorithm::Sha256,
            algorithm_id: Some(b"A128KW".to_vec()),
            party_u_info: Some(b"alice".to_vec()),
            party_v_info: Some(b"bob".to_vec()),
        },
    )
    .unwrap();
    assert_eq!(
        concat,
        decode("a8b55fdab717db26556f37ba799362af1843c31144642d93b86c19d336a10405")
    );

    let pbkdf2 = kryptering::kdf::pbkdf2_derive(
        b"password",
        &Pbkdf2Params {
            hash: HashAlgorithm::Sha256,
            salt: b"salt1234".to_vec(),
            iteration_count: 2,
            key_length: 32,
        },
    )
    .unwrap();
    assert_eq!(
        pbkdf2,
        decode("1565c519e97a92936c1b7299600a5f3da7a42771e4f469a45c19aafe2e22d5ba")
    );

    let hkdf = kryptering::kdf::hkdf_derive(
        &[0x0b; 22],
        42,
        &HkdfParams {
            hash: HashAlgorithm::Sha256,
            salt: Some(decode("000102030405060708090a0b0c")),
            info: Some(decode("f0f1f2f3f4f5f6f7f8f9")),
            key_length_bits: 0,
        },
    )
    .unwrap();
    assert_eq!(
        hkdf,
        decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865"
        )
    );
}

#[test]
fn rsa_signatures_and_transport_use_opaque_imported_keys() {
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};

    let private = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
    let private_der = private.to_pkcs8_der().unwrap();
    let public_der = private.to_public_key().to_public_key_der().unwrap();
    let private_key =
        SoftwareKey::from_pkcs8_der(KeyAlgorithm::Rsa, private_der.as_bytes()).unwrap();
    let public_key = SoftwareKey::from_spki_der(KeyAlgorithm::Rsa, public_der.as_bytes()).unwrap();

    for algorithm in [
        SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha256),
        SignatureAlgorithm::RsaPss(HashAlgorithm::Sha256),
    ] {
        let signature = SoftwareSigner::new(algorithm, private_key.clone())
            .unwrap()
            .sign(b"provider signature baseline")
            .unwrap();
        let verifier = SoftwareVerifier::new(algorithm, public_key.clone()).unwrap();
        assert!(verifier
            .verify(b"provider signature baseline", &signature)
            .unwrap());
        assert!(!verifier.verify(b"tampered", &signature).unwrap());
    }

    let algorithm = KeyTransportAlgorithm::RsaOaep(OaepConfig::default());
    let encrypted = kryptering::keytransport::kt_encrypt(
        algorithm,
        &public_key,
        b"sixteen byte key",
        Some(b"provider-baseline"),
    )
    .unwrap();
    assert_eq!(
        kryptering::keytransport::kt_decrypt(
            algorithm,
            &private_key,
            &encrypted,
            Some(b"provider-baseline"),
        )
        .unwrap(),
        b"sixteen byte key"
    );
    assert!(kryptering::keytransport::kt_decrypt(
        algorithm,
        &private_key,
        &encrypted,
        Some(b"wrong-label"),
    )
    .is_err());
}

#[test]
fn ecdsa_ed25519_and_agreement_use_neutral_key_formats() {
    use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let ec_private = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let ec_private_der = ec_private.to_pkcs8_der().unwrap();
    let ec_public_der = ec_private.public_key().to_public_key_der().unwrap();
    let ec_private_key =
        SoftwareKey::from_pkcs8_der(KeyAlgorithm::Ec(EcCurve::P256), ec_private_der.as_bytes())
            .unwrap();
    let ec_public_key =
        SoftwareKey::from_spki_der(KeyAlgorithm::Ec(EcCurve::P256), ec_public_der.as_bytes())
            .unwrap();
    let algorithm = SignatureAlgorithm::Ecdsa(EcCurve::P256, HashAlgorithm::Sha256);
    let signature = SoftwareSigner::new(algorithm, ec_private_key.clone())
        .unwrap()
        .sign(b"ecdsa provider baseline")
        .unwrap();
    assert!(SoftwareVerifier::new(algorithm, ec_public_key)
        .unwrap()
        .verify(b"ecdsa provider baseline", &signature)
        .unwrap());

    let peer = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let peer_der = peer.to_pkcs8_der().unwrap();
    let peer_key =
        SoftwareKey::from_pkcs8_der(KeyAlgorithm::Ec(EcCurve::P256), peer_der.as_bytes()).unwrap();
    let ec_shared = kryptering::keyagreement::agree(
        EcCurve::P256,
        peer.public_key().to_encoded_point(false).as_bytes(),
        &ec_private_key,
    )
    .unwrap();
    let peer_shared = kryptering::keyagreement::agree(
        EcCurve::P256,
        ec_private.public_key().to_encoded_point(false).as_bytes(),
        &peer_key,
    )
    .unwrap();
    assert_eq!(ec_shared, peer_shared);

    let ed_private = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let ed_private_der = ed_private.to_pkcs8_der().unwrap();
    let ed_public_der = ed_private.verifying_key().to_public_key_der().unwrap();
    let ed_private_key =
        SoftwareKey::from_pkcs8_der(KeyAlgorithm::Ed25519, ed_private_der.as_bytes()).unwrap();
    let ed_public_key =
        SoftwareKey::from_spki_der(KeyAlgorithm::Ed25519, ed_public_der.as_bytes()).unwrap();
    let signature = SoftwareSigner::new(SignatureAlgorithm::Ed25519, ed_private_key)
        .unwrap()
        .sign(b"ed25519 provider baseline")
        .unwrap();
    assert!(
        SoftwareVerifier::new(SignatureAlgorithm::Ed25519, ed_public_key)
            .unwrap()
            .verify(b"ed25519 provider baseline", &signature)
            .unwrap()
    );

    let alice = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let bob = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let alice_public = x25519_dalek::PublicKey::from(&alice);
    let bob_public = x25519_dalek::PublicKey::from(&bob);
    let alice_key =
        SoftwareKey::from_x25519(Some(alice.as_bytes()), alice_public.as_bytes()).unwrap();
    let bob_key = SoftwareKey::from_x25519(Some(bob.as_bytes()), bob_public.as_bytes()).unwrap();
    assert_eq!(
        kryptering::keyagreement::agree_x25519(bob_public.as_bytes(), &alice_key).unwrap(),
        kryptering::keyagreement::agree_x25519(alice_public.as_bytes(), &bob_key).unwrap()
    );
}

#[test]
fn p384_and_p521_signatures_and_agreement_complete_the_curve_baseline() {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};

    let p384_a = p384::SecretKey::random(&mut rand::rngs::OsRng);
    let p384_b = p384::SecretKey::random(&mut rand::rngs::OsRng);
    let p384_a_der = p384_a.to_pkcs8_der().unwrap();
    let p384_b_der = p384_b.to_pkcs8_der().unwrap();
    let p384_public_der = p384_a.public_key().to_public_key_der().unwrap();
    let p384_a_key =
        SoftwareKey::from_pkcs8_der(KeyAlgorithm::Ec(EcCurve::P384), p384_a_der.as_bytes())
            .unwrap();
    let p384_b_key =
        SoftwareKey::from_pkcs8_der(KeyAlgorithm::Ec(EcCurve::P384), p384_b_der.as_bytes())
            .unwrap();
    let p384_public =
        SoftwareKey::from_spki_der(KeyAlgorithm::Ec(EcCurve::P384), p384_public_der.as_bytes())
            .unwrap();
    let p384_algorithm = SignatureAlgorithm::Ecdsa(EcCurve::P384, HashAlgorithm::Sha384);
    let signature = SoftwareSigner::new(p384_algorithm, p384_a_key.clone())
        .unwrap()
        .sign(b"P-384 baseline")
        .unwrap();
    assert!(SoftwareVerifier::new(p384_algorithm, p384_public)
        .unwrap()
        .verify(b"P-384 baseline", &signature)
        .unwrap());
    let p384_ab = kryptering::keyagreement::agree(
        EcCurve::P384,
        p384_b.public_key().to_encoded_point(false).as_bytes(),
        &p384_a_key,
    )
    .unwrap();
    let p384_ba = kryptering::keyagreement::agree(
        EcCurve::P384,
        p384_a.public_key().to_encoded_point(false).as_bytes(),
        &p384_b_key,
    )
    .unwrap();
    assert_eq!(p384_ab, p384_ba);

    let p521_a = p521::SecretKey::random(&mut rand::rngs::OsRng);
    let p521_b = p521::SecretKey::random(&mut rand::rngs::OsRng);
    let p521_a_der = p521_a.to_pkcs8_der().unwrap();
    let p521_b_der = p521_b.to_pkcs8_der().unwrap();
    let p521_public_der = p521_a.public_key().to_public_key_der().unwrap();
    let p521_a_key =
        SoftwareKey::from_pkcs8_der(KeyAlgorithm::Ec(EcCurve::P521), p521_a_der.as_bytes())
            .unwrap();
    let p521_b_key =
        SoftwareKey::from_pkcs8_der(KeyAlgorithm::Ec(EcCurve::P521), p521_b_der.as_bytes())
            .unwrap();
    let p521_public =
        SoftwareKey::from_spki_der(KeyAlgorithm::Ec(EcCurve::P521), p521_public_der.as_bytes())
            .unwrap();
    let p521_algorithm = SignatureAlgorithm::Ecdsa(EcCurve::P521, HashAlgorithm::Sha512);
    let signature = SoftwareSigner::new(p521_algorithm, p521_a_key.clone())
        .unwrap()
        .sign(b"P-521 baseline")
        .unwrap();
    assert!(SoftwareVerifier::new(p521_algorithm, p521_public)
        .unwrap()
        .verify(b"P-521 baseline", &signature)
        .unwrap());
    let p521_ab = kryptering::keyagreement::agree(
        EcCurve::P521,
        p521_b.public_key().to_encoded_point(false).as_bytes(),
        &p521_a_key,
    )
    .unwrap();
    let p521_ba = kryptering::keyagreement::agree(
        EcCurve::P521,
        p521_a.public_key().to_encoded_point(false).as_bytes(),
        &p521_b_key,
    )
    .unwrap();
    assert_eq!(p521_ab, p521_ba);
}

#[test]
fn unsupported_operations_are_reported_before_key_parsing() {
    #[cfg(feature = "aws-lc")]
    {
        let operation = kryptering::Operation::Wrap(KeyWrapAlgorithm::AesKw(AesKeySize::Aes192));
        assert!(!kryptering::supports(operation).unwrap());
        let error = kryptering::keywrap::wrap(
            KeyWrapAlgorithm::AesKw(AesKeySize::Aes192),
            b"not even a valid key",
            b"not valid key data",
        )
        .unwrap_err();
        assert!(matches!(
            error,
            kryptering::Error::UnsupportedAlgorithm {
                operation: actual,
                ..
            } if actual == operation
        ));
    }

    #[cfg(feature = "rustcrypto")]
    {
        let operation = kryptering::Operation::Pbkdf2(HashAlgorithm::Sha3_256);
        assert!(!kryptering::supports(operation).unwrap());
        let error = kryptering::kdf::pbkdf2_derive(
            b"password",
            &Pbkdf2Params {
                hash: HashAlgorithm::Sha3_256,
                salt: b"salt1234".to_vec(),
                iteration_count: 1,
                key_length: 16,
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            kryptering::Error::UnsupportedAlgorithm {
                operation: actual,
                ..
            } if actual == operation
        ));
    }
}
