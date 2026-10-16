#![cfg(feature = "fips")]

use kryptering::kdf::{ConcatKdfParams, Pbkdf2Params};
use kryptering::{AesKeySize, CipherAlgorithm, HashAlgorithm};

fn decode(value: &str) -> Vec<u8> {
    hex::decode(value).expect("valid literal test vector")
}

#[test]
fn fips_provider_matches_literal_known_answers() {
    kryptering::initialize_backend().expect("FIPS provider initialization");

    assert_eq!(
        kryptering::digest::digest(HashAlgorithm::Sha256, b"abc").unwrap(),
        decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );

    // NIST SP 800-38D, AES-128-GCM test case with a zero key, nonce, and
    // one-block plaintext. Kryptering's wire format is nonce || ciphertext || tag.
    let framed = decode(
        "000000000000000000000000\
         0388dace60b6a392f328c2b971b2fe78\
         ab6e47d42cec13bdf53a67b21257bddf",
    );
    assert_eq!(
        kryptering::cipher::decrypt(
            CipherAlgorithm::AesGcm(AesKeySize::Aes128),
            &[0; 16],
            &framed,
        )
        .unwrap(),
        [0; 16]
    );

    assert_eq!(
        kryptering::kdf::pbkdf2_derive(
            b"password1234567",
            &Pbkdf2Params {
                hash: HashAlgorithm::Sha256,
                salt: b"saltsaltsaltsalt".to_vec(),
                iteration_count: 1000,
                key_length: 32,
            },
        )
        .unwrap(),
        decode("724279c0f9e0aa29e8ddf3c22073ec166b6677aa6ccf007e2f7e3bacbb6a03a7")
    );

    // SP 800-132 minimums: 128-bit salt, 1000 iterations, 112-bit password.
    for (password, salt, iteration_count) in [
        (&b"password1234567"[..], &b"salt1234"[..], 1000),
        (&b"password1234567"[..], &b"saltsaltsaltsalt"[..], 999),
        (&b"password"[..], &b"saltsaltsaltsalt"[..], 1000),
    ] {
        assert!(kryptering::kdf::pbkdf2_derive(
            password,
            &Pbkdf2Params {
                hash: HashAlgorithm::Sha256,
                salt: salt.to_vec(),
                iteration_count,
                key_length: 32,
            },
        )
        .is_err());
    }

    assert_eq!(
        kryptering::kdf::concat_kdf(
            b"shared secret",
            32,
            &ConcatKdfParams {
                hash: HashAlgorithm::Sha256,
                algorithm_id: Some(b"A128KW".to_vec()),
                party_u_info: Some(b"alice".to_vec()),
                party_v_info: Some(b"bob".to_vec()),
            },
        )
        .unwrap(),
        decode("a8b55fdab717db26556f37ba799362af1843c31144642d93b86c19d336a10405")
    );
}

#[test]
fn fips_provider_rejects_pkcs12_kdf() {
    kryptering::initialize_backend().expect("FIPS provider initialization");
    let error = kryptering::pkcs12::derive(
        HashAlgorithm::Sha256,
        kryptering::pkcs12::ID_KEY,
        "password",
        b"saltsalt",
        2,
        32,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        kryptering::Error::UnsupportedAlgorithm {
            operation: kryptering::Operation::Pkcs12Kdf(HashAlgorithm::Sha256),
            ..
        }
    ));
}

#[test]
fn fips_provider_rejects_rsa_keys_below_2048_bits_at_import() {
    kryptering::initialize_backend().expect("FIPS provider initialization");
    // Literal 1024-bit RSA SubjectPublicKeyInfo. Parsing must reach the
    // explicit FIPS size gate rather than relying on a signature operation.
    let der = decode(
        "30819f300d06092a864886f70d010101050003818d0030818902818100\
         bd3c69e1f18c3330b0326c8878620ec7b441634118f95443de49b538\
         9f65270c1f56a42dc188ef3e837cda20019694f15f7cbc69a9f287f469\
         9c2bd96def73f50055ff608f554926e3fd7efd32ec587259184d9b149e\
         2696832392a6ca3ec8a4c84de5852a056882ade7dd3b7036aceb61877c\
         32ca56b79a0595486b8c17e60d0203010001",
    );
    let error =
        kryptering::SoftwareKey::from_spki_der(kryptering::KeyAlgorithm::Rsa, &der).unwrap_err();
    assert!(matches!(
        error,
        kryptering::Error::UnsupportedAlgorithm {
            operation: kryptering::Operation::KeyImport(kryptering::KeyAlgorithm::Rsa),
            ..
        }
    ));
}

/// Ed448 and X448 are not FIPS-approved: every entry point refuses with a
/// typed `UnsupportedAlgorithm` before inspecting key material.
#[test]
fn fips_provider_refuses_ed448_and_x448() {
    use kryptering::{KeyAlgorithm, Operation, SignatureAlgorithm, SoftwareKey, SoftwareSigner};
    kryptering::initialize_backend().expect("provider initialization");
    fn refused<T>(result: kryptering::Result<T>, operation: Operation) {
        match result {
            Err(kryptering::Error::UnsupportedAlgorithm {
                operation: actual, ..
            }) => assert_eq!(actual, operation),
            Err(other) => panic!("expected refusal of {operation:?}, got {other:?}"),
            Ok(_) => panic!("{operation:?} was accepted under FIPS"),
        }
    }
    let aes = SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Aes, &[7; 32]).unwrap();
    refused(
        SoftwareKey::from_pkcs8_der(KeyAlgorithm::Ed448, b"not even DER"),
        Operation::KeyImport(KeyAlgorithm::Ed448),
    );
    refused(
        SoftwareKey::from_spki_der(KeyAlgorithm::Ed448, b"not even DER"),
        Operation::KeyImport(KeyAlgorithm::Ed448),
    );
    refused(
        SoftwareSigner::new(SignatureAlgorithm::Ed448, aes.clone()),
        Operation::Sign(SignatureAlgorithm::Ed448),
    );
    refused(
        SoftwareKey::from_x448(Some(&[1; 56]), &[2; 56]),
        Operation::KeyImport(KeyAlgorithm::X448),
    );
    refused(
        kryptering::keyagreement::ecdh_x448(&[2; 56], &[1; 56]),
        Operation::X448Agreement,
    );
    refused(
        kryptering::keyagreement::agree_x448(&[2; 56], &aes),
        Operation::X448Agreement,
    );
    assert!(!kryptering::supports(Operation::Sign(SignatureAlgorithm::Ed448)).unwrap());
    assert!(!kryptering::supports(Operation::X448Agreement).unwrap());
}

/// secp256k1 and the Brainpool curves are not FIPS-approved: import, signing
/// and agreement are refused before any key material is parsed.
#[test]
fn fips_provider_refuses_non_nist_curves() {
    use kryptering::{
        EcCurve, KeyAlgorithm, Operation, SignatureAlgorithm, SoftwareKey, SoftwareSigner,
    };
    kryptering::initialize_backend().expect("provider initialization");
    let aes = SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Aes, &[7; 32]).unwrap();
    for curve in [
        EcCurve::Secp256k1,
        EcCurve::BrainpoolP256r1,
        EcCurve::BrainpoolP384r1,
        EcCurve::BrainpoolP512r1,
    ] {
        let algorithm = SignatureAlgorithm::Ecdsa(curve, HashAlgorithm::Sha256);
        for operation in [
            Operation::KeyImport(KeyAlgorithm::Ec(curve)),
            Operation::Sign(algorithm),
            Operation::Verify(algorithm),
            Operation::Agreement(curve),
        ] {
            assert!(!kryptering::supports(operation).unwrap(), "{operation:?}");
        }
        let refused = |result: kryptering::Result<SoftwareKey>, operation: Operation| match result {
            Err(kryptering::Error::UnsupportedAlgorithm {
                operation: actual, ..
            }) => assert_eq!(actual, operation),
            other => panic!("expected refusal of {operation:?}, got {other:?}"),
        };
        refused(
            SoftwareKey::from_pkcs8_der(KeyAlgorithm::Ec(curve), b"not even DER"),
            Operation::KeyImport(KeyAlgorithm::Ec(curve)),
        );
        refused(
            SoftwareKey::from_spki_der(KeyAlgorithm::Ec(curve), b"not even DER"),
            Operation::KeyImport(KeyAlgorithm::Ec(curve)),
        );
        match SoftwareSigner::new(algorithm, aes.clone()) {
            Err(kryptering::Error::UnsupportedAlgorithm {
                operation: actual, ..
            }) => assert_eq!(actual, Operation::Sign(algorithm)),
            other => panic!("expected refusal, got {:?}", other.err()),
        }
        match kryptering::keyagreement::agree(curve, &[4; 65], &aes) {
            Err(kryptering::Error::UnsupportedAlgorithm {
                operation: actual, ..
            }) => assert_eq!(actual, Operation::Agreement(curve)),
            other => panic!("expected refusal, got {other:?}"),
        }
    }
}
