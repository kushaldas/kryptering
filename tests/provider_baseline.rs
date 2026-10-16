use kryptering::kdf::{ConcatKdfParams, HkdfParams, Pbkdf2Params};
use kryptering::{
    AesKeySize, CipherAlgorithm, EcCurve, HashAlgorithm, KeyAlgorithm, KeyTransportAlgorithm,
    KeyWrapAlgorithm, OaepConfig, Operation, SignatureAlgorithm, SoftwareKey, SoftwareSigner,
    SoftwareVerifier,
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
fn digest_hmac_streaming_and_rng_known_answers() {
    kryptering::initialize_backend().expect("provider initialization");
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
    kryptering::initialize_backend().expect("provider initialization");
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
    let length_error =
        kryptering::hazmat::aes_cbc::decrypt(AesKeySize::Aes128, &key, &[0; 17]).unwrap_err();
    let mut bad_padding = cbc;
    // Flip the last byte of the preceding ciphertext block by the known
    // padding length. CBC XORs this value into the final plaintext byte,
    // changing it from the valid padding length to zero. Both PKCS#7 and the
    // accepted ISO 10126 padding reject a zero length. Mutating the final
    // ciphertext block instead would randomize the decrypted block and can
    // occasionally produce valid padding by chance.
    let preceding_block_last = bad_padding.len() - 17;
    let padding_len = 16 - plaintext.len() % 16;
    bad_padding[preceding_block_last] ^= padding_len as u8;
    let padding_error =
        kryptering::hazmat::aes_cbc::decrypt(AesKeySize::Aes128, &key, &bad_padding).unwrap_err();
    assert_eq!(length_error.to_string(), padding_error.to_string());
    assert_eq!(
        length_error.to_string(),
        "cryptographic operation failed: AES-CBC decrypt failed"
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
fn generic_cipher_dispatcher_rejects_unauthenticated_aes_cbc() {
    kryptering::initialize_backend().expect("provider initialization");
    let algorithm = CipherAlgorithm::AesCbc(AesKeySize::Aes128);
    let key = [0x42; 16];
    for error in [
        kryptering::cipher::encrypt(algorithm, &key, b"plaintext").unwrap_err(),
        kryptering::cipher::decrypt(algorithm, &key, &[0; 32]).unwrap_err(),
    ] {
        assert!(
            matches!(
                error,
                kryptering::Error::UnsupportedAlgorithm { ref algorithm, .. }
                    if algorithm.contains("hazmat::aes_cbc")
            ),
            "unexpected error: {error:?}"
        );
    }
}

#[test]
fn kdfs_match_known_answers() {
    kryptering::initialize_backend().expect("provider initialization");
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

    // Two iterations and an 8-byte salt and password are below the SP 800-132
    // minimums FIPS builds enforce.
    let pbkdf2 = kryptering::kdf::pbkdf2_derive(
        b"password",
        &Pbkdf2Params {
            hash: HashAlgorithm::Sha256,
            salt: b"salt1234".to_vec(),
            iteration_count: 2,
            key_length: 32,
        },
    );
    if cfg!(feature = "fips") {
        assert!(
            matches!(
                pbkdf2,
                Err(kryptering::Error::Crypto(ref message))
                    if message.contains("SP 800-132")
            ),
            "{pbkdf2:?}"
        );
    } else {
        assert_eq!(
            pbkdf2.unwrap(),
            decode("1565c519e97a92936c1b7299600a5f3da7a42771e4f469a45c19aafe2e22d5ba")
        );
    }

    // SP 800-132 compliant parameters, which every provider including FIPS
    // must derive identically. Cross-checked against Python's
    // hashlib.pbkdf2_hmac.
    let compliant = kryptering::kdf::pbkdf2_derive(
        b"password1234567",
        &Pbkdf2Params {
            hash: HashAlgorithm::Sha256,
            salt: b"saltsaltsaltsalt".to_vec(),
            iteration_count: 1000,
            key_length: 32,
        },
    )
    .unwrap();
    assert_eq!(
        compliant,
        decode("724279c0f9e0aa29e8ddf3c22073ec166b6677aa6ccf007e2f7e3bacbb6a03a7")
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

    kryptering::initialize_backend().expect("provider initialization");
    let private = rsa::RsaPrivateKey::new(&mut test_rng(), 2048).unwrap();
    let private_der = private.to_pkcs8_der().unwrap();
    let public_der = private.to_public_key().to_public_key_der().unwrap();
    let private_key =
        SoftwareKey::from_pkcs8_der(KeyAlgorithm::Rsa, private_der.as_bytes()).unwrap();
    let public_key = SoftwareKey::from_spki_der(KeyAlgorithm::Rsa, public_der.as_bytes()).unwrap();

    #[cfg(feature = "aws-lc")]
    assert!(matches!(
        SoftwareVerifier::new_rsa_pss_with_salt(HashAlgorithm::Sha256, 48, public_key.clone(),),
        Err(kryptering::Error::UnsupportedAlgorithm { .. })
    ));
    if cfg!(feature = "fips") {
        // AWS-LC implements SHA-1 PKCS#1 v1.5 verification and SHA-1 OAEP,
        // but FIPS does not approve them, so both are refused before key use.
        let sha1 = SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha1);
        assert_refused(
            SoftwareVerifier::new(sha1, public_key.clone()),
            Operation::Verify(sha1),
        );
        let sha1_oaep = KeyTransportAlgorithm::RsaOaep(OaepConfig {
            digest: HashAlgorithm::Sha1,
            mgf_digest: HashAlgorithm::Sha1,
        });
        assert_refused(
            kryptering::keytransport::kt_encrypt(sha1_oaep, &public_key, b"sixteen byte key", None),
            Operation::TransportEncrypt(sha1_oaep),
        );
        assert_refused(
            kryptering::keytransport::kt_decrypt(sha1_oaep, &private_key, &[0; 256], None),
            Operation::TransportDecrypt(sha1_oaep),
        );
    }

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
    use p256::elliptic_curve::sec1::ToSec1Point;

    kryptering::initialize_backend().expect("provider initialization");
    let ec_private = p256::SecretKey::generate_from_rng(&mut test_rng());
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
    let verifier = SoftwareVerifier::new(algorithm, ec_public_key).unwrap();
    assert!(verifier
        .verify(b"ecdsa provider baseline", &signature)
        .unwrap());
    assert!(!verifier.verify(b"tampered", &signature).unwrap());

    let peer = p256::SecretKey::generate_from_rng(&mut test_rng());
    let peer_der = peer.to_pkcs8_der().unwrap();
    let peer_key =
        SoftwareKey::from_pkcs8_der(KeyAlgorithm::Ec(EcCurve::P256), peer_der.as_bytes()).unwrap();
    let ec_shared = kryptering::keyagreement::agree(
        EcCurve::P256,
        peer.public_key().to_sec1_point(false).as_bytes(),
        &ec_private_key,
    )
    .unwrap();
    let peer_shared = kryptering::keyagreement::agree(
        EcCurve::P256,
        ec_private.public_key().to_sec1_point(false).as_bytes(),
        &peer_key,
    )
    .unwrap();
    assert_eq!(ec_shared, peer_shared);

    let ed_private = ed25519_dalek::SigningKey::generate(&mut test_rng());
    let ed_private_der = ed_private.to_pkcs8_der().unwrap();
    let ed_public_der = ed_private.verifying_key().to_public_key_der().unwrap();
    if cfg!(feature = "fips") {
        // Ed25519 is not FIPS approved: valid keys are refused at import, and
        // signing is refused before the key is inspected.
        let import = Operation::KeyImport(KeyAlgorithm::Ed25519);
        assert_refused(
            SoftwareKey::from_pkcs8_der(KeyAlgorithm::Ed25519, ed_private_der.as_bytes()),
            import,
        );
        assert_refused(
            SoftwareKey::from_spki_der(KeyAlgorithm::Ed25519, ed_public_der.as_bytes()),
            import,
        );
        assert_refused(
            SoftwareSigner::new(SignatureAlgorithm::Ed25519, ec_private_key.clone()),
            Operation::Sign(SignatureAlgorithm::Ed25519),
        );
    } else {
        let ed_private_key =
            SoftwareKey::from_pkcs8_der(KeyAlgorithm::Ed25519, ed_private_der.as_bytes()).unwrap();
        let ed_public_key =
            SoftwareKey::from_spki_der(KeyAlgorithm::Ed25519, ed_public_der.as_bytes()).unwrap();
        let signature = SoftwareSigner::new(SignatureAlgorithm::Ed25519, ed_private_key)
            .unwrap()
            .sign(b"ed25519 provider baseline")
            .unwrap();
        let verifier = SoftwareVerifier::new(SignatureAlgorithm::Ed25519, ed_public_key).unwrap();
        assert!(verifier
            .verify(b"ed25519 provider baseline", &signature)
            .unwrap());
        assert!(!verifier.verify(b"tampered", &signature).unwrap());
    }

    let alice = x25519_dalek::StaticSecret::random_from_rng(&mut test_rng());
    let bob = x25519_dalek::StaticSecret::random_from_rng(&mut test_rng());
    let alice_public = x25519_dalek::PublicKey::from(&alice);
    let bob_public = x25519_dalek::PublicKey::from(&bob);
    if cfg!(feature = "fips") {
        // Likewise X25519: import and both agreement entry points refuse it.
        assert_refused(
            SoftwareKey::from_x25519(Some(alice.as_bytes()), alice_public.as_bytes()),
            Operation::KeyImport(KeyAlgorithm::X25519),
        );
        assert_refused(
            kryptering::keyagreement::ecdh_x25519(bob_public.as_bytes(), alice.as_bytes()),
            Operation::X25519Agreement,
        );
        assert_refused(
            kryptering::keyagreement::agree_x25519(bob_public.as_bytes(), &ec_private_key),
            Operation::X25519Agreement,
        );
    } else {
        let alice_key =
            SoftwareKey::from_x25519(Some(alice.as_bytes()), alice_public.as_bytes()).unwrap();
        let bob_key =
            SoftwareKey::from_x25519(Some(bob.as_bytes()), bob_public.as_bytes()).unwrap();
        assert_eq!(
            kryptering::keyagreement::agree_x25519(bob_public.as_bytes(), &alice_key).unwrap(),
            kryptering::keyagreement::agree_x25519(alice_public.as_bytes(), &bob_key).unwrap()
        );
        assert!(kryptering::keyagreement::agree_x25519(&[0; 32], &alice_key).is_err());
    }
}

#[test]
fn p384_and_p521_signatures_and_agreement_complete_the_curve_baseline() {
    use p256::elliptic_curve::sec1::ToSec1Point;
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};

    kryptering::initialize_backend().expect("provider initialization");
    let p384_a = p384::SecretKey::generate_from_rng(&mut test_rng());
    let p384_b = p384::SecretKey::generate_from_rng(&mut test_rng());
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
    let verifier = SoftwareVerifier::new(p384_algorithm, p384_public).unwrap();
    assert!(verifier.verify(b"P-384 baseline", &signature).unwrap());
    assert!(!verifier.verify(b"tampered", &signature).unwrap());
    let p384_ab = kryptering::keyagreement::agree(
        EcCurve::P384,
        p384_b.public_key().to_sec1_point(false).as_bytes(),
        &p384_a_key,
    )
    .unwrap();
    let p384_ba = kryptering::keyagreement::agree(
        EcCurve::P384,
        p384_a.public_key().to_sec1_point(false).as_bytes(),
        &p384_b_key,
    )
    .unwrap();
    assert_eq!(p384_ab, p384_ba);

    let p521_a = p521::SecretKey::generate_from_rng(&mut test_rng());
    let p521_b = p521::SecretKey::generate_from_rng(&mut test_rng());
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
    let verifier = SoftwareVerifier::new(p521_algorithm, p521_public).unwrap();
    assert!(verifier.verify(b"P-521 baseline", &signature).unwrap());
    assert!(!verifier.verify(b"tampered", &signature).unwrap());
    let p521_ab = kryptering::keyagreement::agree(
        EcCurve::P521,
        p521_b.public_key().to_sec1_point(false).as_bytes(),
        &p521_a_key,
    )
    .unwrap();
    let p521_ba = kryptering::keyagreement::agree(
        EcCurve::P521,
        p521_a.public_key().to_sec1_point(false).as_bytes(),
        &p521_b_key,
    )
    .unwrap();
    assert_eq!(p521_ab, p521_ba);
}

#[test]
fn unsupported_operations_are_reported_before_key_parsing() {
    kryptering::initialize_backend().expect("provider initialization");
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

    #[cfg(feature = "fips")]
    {
        // AWS-LC implements SHA-1 PBKDF2, but FIPS does not approve it. The
        // refusal comes before the SP 800-132 parameter checks would fail.
        let operation = kryptering::Operation::Pbkdf2(HashAlgorithm::Sha1);
        assert!(!kryptering::supports(operation).unwrap());
        let error = kryptering::kdf::pbkdf2_derive(
            b"password",
            &Pbkdf2Params {
                hash: HashAlgorithm::Sha1,
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

#[test]
fn ecdsa_signing_capabilities_are_also_verifiable() {
    kryptering::initialize_backend().expect("provider initialization");
    // Every provider, FIPS included, signs each curve with its matched
    // digest, so the loop below cannot pass without checking anything.
    for (curve, hash) in [
        (EcCurve::P256, HashAlgorithm::Sha256),
        (EcCurve::P384, HashAlgorithm::Sha384),
        (EcCurve::P521, HashAlgorithm::Sha512),
    ] {
        let algorithm = SignatureAlgorithm::Ecdsa(curve, hash);
        assert!(
            kryptering::supports(kryptering::Operation::Sign(algorithm)).unwrap(),
            "matched-pair ECDSA signing unsupported for {algorithm:?}"
        );
    }
    // ES256K is served by both software providers outside FIPS mode only.
    let es256k = SignatureAlgorithm::Ecdsa(EcCurve::Secp256k1, HashAlgorithm::Sha256);
    assert_eq!(
        kryptering::supports(kryptering::Operation::Sign(es256k)).unwrap(),
        !cfg!(feature = "fips")
    );
    for curve in [
        EcCurve::P256,
        EcCurve::P384,
        EcCurve::P521,
        EcCurve::Secp256k1,
        EcCurve::BrainpoolP256r1,
        EcCurve::BrainpoolP384r1,
        EcCurve::BrainpoolP512r1,
    ] {
        for hash in [
            HashAlgorithm::Sha1,
            HashAlgorithm::Sha224,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha512,
            HashAlgorithm::Sha3_384,
            HashAlgorithm::Sha3_512,
        ] {
            // Verification may be broader than signing: AWS-LC verifies the
            // cross curve/digest pairs XML-DSig produces (e.g. P-384 with
            // SHA-256) but only signs with its fixed matched pairs.
            let algorithm = SignatureAlgorithm::Ecdsa(curve, hash);
            if kryptering::supports(kryptering::Operation::Sign(algorithm)).unwrap() {
                assert!(
                    kryptering::supports(kryptering::Operation::Verify(algorithm)).unwrap(),
                    "signable but unverifiable ECDSA capability for {algorithm:?}"
                );
            }
        }
    }
}

/// Ed448 / X448 round-trip through the neutral RFC 8410 and raw formats on
/// RustCrypto; AWS-LC reports them unsupported before parsing anything.
#[test]
fn ed448_and_x448_use_neutral_key_formats_or_are_refused() {
    kryptering::initialize_backend().expect("provider initialization");
    // RFC 8032 §7.4 "-----1 octet" key as PKCS#8 v1 / SPKI.
    let mut ed_pkcs8 = decode("3047020100300506032b6571043b0439");
    ed_pkcs8.extend(decode("c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e"));
    let mut ed_spki = decode("3043300506032b6571033a00");
    ed_spki.extend(decode("43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480"));
    let x_private = decode("1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d");
    let x_public = decode("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609");

    #[cfg(feature = "rustcrypto")]
    {
        let private = SoftwareKey::from_pkcs8_der(KeyAlgorithm::Ed448, &ed_pkcs8).unwrap();
        let public = SoftwareKey::from_spki_der(KeyAlgorithm::Ed448, &ed_spki).unwrap();
        assert_eq!(private.export_spki_der().unwrap(), ed_spki);
        // The exported PKCS#8 re-imports to the same key.
        let exported = private.export_private().unwrap();
        let reimported = SoftwareKey::from_pkcs8_der(KeyAlgorithm::Ed448, &exported).unwrap();
        assert_eq!(reimported.export_spki_der().unwrap(), ed_spki);
        let signature = SoftwareSigner::new(SignatureAlgorithm::Ed448, private)
            .unwrap()
            .sign(&[0x03])
            .unwrap();
        assert_eq!(hex::encode(&signature), "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00");
        assert!(SoftwareVerifier::new(SignatureAlgorithm::Ed448, public)
            .unwrap()
            .verify(&[0x03], &signature)
            .unwrap());

        let bob = SoftwareKey::from_x448(Some(&x_private), &x_public).unwrap();
        assert_eq!(bob.export_spki_der().unwrap(), x_public);
        assert_eq!(bob.export_private().unwrap().to_vec(), x_private);
        let alice_public = decode("9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0");
        assert_eq!(
            hex::encode(kryptering::keyagreement::agree_x448(&alice_public, &bob).unwrap()),
            "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d"
        );
    }
    #[cfg(feature = "aws-lc")]
    {
        for operation in [
            Operation::KeyImport(KeyAlgorithm::Ed448),
            Operation::KeyImport(KeyAlgorithm::X448),
            Operation::Sign(SignatureAlgorithm::Ed448),
            Operation::X448Agreement,
        ] {
            assert!(!kryptering::supports(operation).unwrap(), "{operation:?}");
        }
        assert_refused(
            SoftwareKey::from_pkcs8_der(KeyAlgorithm::Ed448, &ed_pkcs8),
            Operation::KeyImport(KeyAlgorithm::Ed448),
        );
        assert_refused(
            SoftwareKey::from_spki_der(KeyAlgorithm::Ed448, &ed_spki),
            Operation::KeyImport(KeyAlgorithm::Ed448),
        );
        assert_refused(
            SoftwareKey::from_x448(Some(&x_private), &x_public),
            Operation::KeyImport(KeyAlgorithm::X448),
        );
        assert_refused(
            kryptering::keyagreement::ecdh_x448(&x_public, &x_private),
            Operation::X448Agreement,
        );
    }
}

/// ES256K keys travel as ordinary PKCS#8 / SPKI; signatures interoperate
/// between the providers through the shared raw / DER encodings. ECDH over
/// secp256k1 is RustCrypto-only; AWS-LC refuses it before parsing anything.
#[test]
fn secp256k1_signatures_and_agreement_use_neutral_key_formats() {
    use k256::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use p256::elliptic_curve::sec1::ToSec1Point;
    kryptering::initialize_backend().expect("provider initialization");
    let private = k256::SecretKey::generate_from_rng(&mut test_rng());
    let peer = k256::SecretKey::generate_from_rng(&mut test_rng());
    let pkcs8 = private.to_pkcs8_der().unwrap();
    let spki = private.public_key().to_public_key_der().unwrap();
    let curve = KeyAlgorithm::Ec(EcCurve::Secp256k1);
    let algorithm = SignatureAlgorithm::Ecdsa(EcCurve::Secp256k1, HashAlgorithm::Sha256);
    let peer_point = peer.public_key().to_sec1_point(false);

    if cfg!(feature = "fips") {
        assert_refused(
            SoftwareKey::from_pkcs8_der(curve, pkcs8.as_bytes()),
            Operation::KeyImport(curve),
        );
        assert_refused(
            kryptering::keyagreement::agree(
                EcCurve::Secp256k1,
                peer_point.as_bytes(),
                &SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Aes, &[1; 32]).unwrap(),
            ),
            Operation::Agreement(EcCurve::Secp256k1),
        );
        return;
    }

    let key = SoftwareKey::from_pkcs8_der(curve, pkcs8.as_bytes()).unwrap();
    let public = SoftwareKey::from_spki_der(curve, spki.as_bytes()).unwrap();
    assert_eq!(key.export_spki_der().unwrap(), spki.as_bytes());
    let signature = SoftwareSigner::new(algorithm, key.clone())
        .unwrap()
        .sign(b"ES256K")
        .unwrap();
    assert_eq!(signature.len(), 64);
    let verifier = SoftwareVerifier::new(algorithm, public).unwrap();
    assert!(verifier.verify(b"ES256K", &signature).unwrap());
    assert!(!verifier.verify(b"tampered", &signature).unwrap());
    // Verify the same signature through the independent k256 implementation.
    {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        // Provider-neutral digest: `sha2` is not a dev-dependency under AWS-LC.
        let prehash = kryptering::digest::digest(HashAlgorithm::Sha256, b"ES256K").unwrap();
        // AWS-LC emits either `s` form; k256 only verifies low-S (BIP-62), so
        // normalize first. The RustCrypto signer already emits low-S.
        let sig = k256::ecdsa::Signature::from_slice(&signature)
            .unwrap()
            .normalize_s();
        let vk = k256::ecdsa::VerifyingKey::from(private.public_key());
        assert!(vk.verify_prehash(&prehash, &sig).is_ok());
    }

    #[cfg(feature = "rustcrypto")]
    {
        let shared =
            kryptering::keyagreement::agree(EcCurve::Secp256k1, peer_point.as_bytes(), &key)
                .unwrap();
        let expected =
            k256::ecdh::diffie_hellman(peer.to_nonzero_scalar(), private.public_key().as_affine());
        assert_eq!(shared, expected.raw_secret_bytes().to_vec());
    }
    #[cfg(feature = "aws-lc")]
    {
        assert!(!kryptering::supports(Operation::Agreement(EcCurve::Secp256k1)).unwrap());
        assert_refused(
            kryptering::keyagreement::agree(EcCurve::Secp256k1, peer_point.as_bytes(), &key),
            Operation::Agreement(EcCurve::Secp256k1),
        );
    }
}

/// Brainpool keys travel as ordinary PKCS#8 / SPKI. RustCrypto reproduces
/// RFC 7027 A.1 and signs/verifies; AWS-LC refuses every Brainpool curve
/// before parsing.
#[test]
fn brainpool_uses_neutral_key_formats_or_is_refused() {
    use bp256::pkcs8::EncodePrivateKey;
    kryptering::initialize_backend().expect("provider initialization");
    let d_a = decode("81DB1EE100150FF2EA338D708271BE38300CB54241D79950F77B063039804F1D");
    let mut q_b = vec![0x04];
    q_b.extend(decode(
        "8D2D688C6CF93E1160AD04CC4429117DC2C41825E1E9FCA0ADDD34E6F1B39F7B",
    ));
    q_b.extend(decode(
        "990C57520812BE512641E47034832106BC7D3E8DD0E4C7F1136D7006547CEC6A",
    ));
    let pkcs8 = bp256::r1::SecretKey::from_slice(&d_a)
        .unwrap()
        .to_pkcs8_der()
        .unwrap();
    let curve = KeyAlgorithm::Ec(EcCurve::BrainpoolP256r1);
    let algorithm = SignatureAlgorithm::Ecdsa(EcCurve::BrainpoolP256r1, HashAlgorithm::Sha256);

    #[cfg(feature = "rustcrypto")]
    {
        let key = SoftwareKey::from_pkcs8_der(curve, pkcs8.as_bytes()).unwrap();
        let spki = key.export_spki_der().unwrap();
        let public = SoftwareKey::from_spki_der(curve, &spki).unwrap();
        let x_z = decode("89AFC39D41D3B327814B80940B042590F96556EC91E6AE7939BCE31F3A18BF2B");
        assert_eq!(
            kryptering::keyagreement::agree(EcCurve::BrainpoolP256r1, &q_b, &key).unwrap(),
            x_z
        );
        let signature = SoftwareSigner::new(algorithm, key)
            .unwrap()
            .sign(b"brainpool")
            .unwrap();
        assert_eq!(signature.len(), 64);
        let verifier = SoftwareVerifier::new(algorithm, public).unwrap();
        assert!(verifier.verify(b"brainpool", &signature).unwrap());
        assert!(!verifier.verify(b"tampered", &signature).unwrap());
    }
    #[cfg(feature = "aws-lc")]
    {
        for curve in [
            EcCurve::BrainpoolP256r1,
            EcCurve::BrainpoolP384r1,
            EcCurve::BrainpoolP512r1,
        ] {
            assert!(!kryptering::supports(Operation::KeyImport(KeyAlgorithm::Ec(curve))).unwrap());
            assert!(!kryptering::supports(Operation::Agreement(curve)).unwrap());
        }
        assert_refused(
            SoftwareKey::from_pkcs8_der(curve, pkcs8.as_bytes()),
            Operation::KeyImport(curve),
        );
        let aes = SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Aes, &[7; 32]).unwrap();
        assert_refused(
            SoftwareSigner::new(algorithm, aes.clone()),
            Operation::Sign(algorithm),
        );
        assert_refused(
            kryptering::keyagreement::agree(EcCurve::BrainpoolP256r1, &q_b, &aes),
            Operation::Agreement(EcCurve::BrainpoolP256r1),
        );
    }
}
