#![forbid(unsafe_code)]

//! Block cipher operations (AES-CBC, AES-GCM, optionally 3DES-CBC).

use crate::algorithm::{AesKeySize, CipherAlgorithm};
use crate::error::{Error, Result};

/// Encrypt `plaintext` using the given block cipher algorithm and `key`.
///
/// For AES-CBC a random 16-byte IV is prepended to the ciphertext and PKCS#7
/// padding is applied.  For AES-GCM a random 12-byte nonce is prepended.
/// For 3DES-CBC (legacy) a random 8-byte IV is prepended with PKCS#7 padding.
pub fn encrypt(algorithm: CipherAlgorithm, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    match algorithm {
        CipherAlgorithm::AesCbc(size) => aes_cbc_encrypt(size, key, plaintext),
        CipherAlgorithm::AesGcm(size) => aes_gcm_encrypt(size, key, plaintext),
        #[cfg(feature = "legacy")]
        CipherAlgorithm::TripleDesCbc => triple_des_cbc_encrypt(key, plaintext),
    }
}

/// Decrypt `ciphertext` using the given block cipher algorithm and `key`.
///
/// Expects the IV/nonce prepended to the ciphertext (as produced by [`encrypt`]).
/// AES-CBC uses xmlenc-compatible unpadding that accepts both PKCS#7 and
/// ISO 10126 padding.
pub fn decrypt(algorithm: CipherAlgorithm, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    match algorithm {
        CipherAlgorithm::AesCbc(size) => aes_cbc_decrypt(size, key, ciphertext),
        CipherAlgorithm::AesGcm(size) => aes_gcm_decrypt(size, key, ciphertext),
        #[cfg(feature = "legacy")]
        CipherAlgorithm::TripleDesCbc => triple_des_cbc_decrypt(key, ciphertext),
    }
}

// ── AES-CBC with PKCS#7 padding ─────────────────────────────────────

fn aes_cbc_encrypt(size: AesKeySize, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    use rand::RngCore;

    let expected = size.key_len();
    if key.len() != expected {
        return Err(Error::Crypto(format!(
            "expected {expected} byte key, got {}",
            key.len()
        )));
    }

    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    let mut buf = pkcs7_pad(plaintext, 16);
    let buf_len = buf.len();

    macro_rules! do_encrypt {
        ($aes:ty) => {{
            let enc = cbc::Encryptor::<$aes>::new_from_slices(key, &iv)
                .map_err(|e| Error::Crypto(format!("AES-CBC init: {e}")))?;
            enc.encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf, buf_len)
                .map_err(|e| Error::Crypto(format!("AES-CBC encrypt: {e}")))?;
        }};
    }

    match size {
        AesKeySize::Aes128 => do_encrypt!(aes::Aes128),
        AesKeySize::Aes192 => do_encrypt!(aes::Aes192),
        AesKeySize::Aes256 => do_encrypt!(aes::Aes256),
    }

    let mut result = Vec::with_capacity(16 + buf.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&buf);
    Ok(result)
}

fn aes_cbc_decrypt(size: AesKeySize, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};

    let expected = size.key_len();
    if key.len() != expected {
        return Err(Error::Crypto(format!(
            "expected {expected} byte key, got {}",
            key.len()
        )));
    }
    if data.len() < 16 || data.len() % 16 != 0 {
        return Err(Error::Crypto("AES-CBC data invalid length".into()));
    }

    let iv = &data[..16];
    let ciphertext = &data[16..];
    let mut buf = ciphertext.to_vec();

    macro_rules! do_decrypt {
        ($aes:ty) => {{
            let dec = cbc::Decryptor::<$aes>::new_from_slices(key, iv)
                .map_err(|e| Error::Crypto(format!("AES-CBC init: {e}")))?;
            dec.decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
                .map_err(|e| Error::Crypto(format!("AES-CBC decrypt: {e}")))?;
        }};
    }

    match size {
        AesKeySize::Aes128 => do_decrypt!(aes::Aes128),
        AesKeySize::Aes192 => do_decrypt!(aes::Aes192),
        AesKeySize::Aes256 => do_decrypt!(aes::Aes256),
    }

    xmlenc_unpad(&buf, 16)
}

// ── AES-GCM ──────────────────────────────────────────────────────────

fn aes_gcm_encrypt(size: AesKeySize, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{aead::Aead, KeyInit, Nonce};
    use rand::RngCore;

    let expected = size.key_len();
    if key.len() != expected {
        return Err(Error::Crypto(format!(
            "expected {expected} byte key, got {}",
            key.len()
        )));
    }

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct = match size {
        AesKeySize::Aes128 => {
            let cipher = aes_gcm::Aes128Gcm::new_from_slice(key)
                .map_err(|e| Error::Crypto(format!("AES-GCM init: {e}")))?;
            cipher
                .encrypt(nonce, plaintext)
                .map_err(|e| Error::Crypto(format!("AES-GCM encrypt: {e}")))?
        }
        AesKeySize::Aes192 => {
            use aes_gcm::aead::consts::U12;
            let cipher = aes_gcm::AesGcm::<aes::Aes192, U12>::new_from_slice(key)
                .map_err(|e| Error::Crypto(format!("AES-GCM init: {e}")))?;
            cipher
                .encrypt(nonce, plaintext)
                .map_err(|e| Error::Crypto(format!("AES-GCM encrypt: {e}")))?
        }
        AesKeySize::Aes256 => {
            let cipher = aes_gcm::Aes256Gcm::new_from_slice(key)
                .map_err(|e| Error::Crypto(format!("AES-GCM init: {e}")))?;
            cipher
                .encrypt(nonce, plaintext)
                .map_err(|e| Error::Crypto(format!("AES-GCM encrypt: {e}")))?
        }
    };

    let mut result = Vec::with_capacity(12 + ct.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ct);
    Ok(result)
}

fn aes_gcm_decrypt(size: AesKeySize, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{aead::Aead, KeyInit, Nonce};

    let expected = size.key_len();
    if key.len() != expected {
        return Err(Error::Crypto(format!(
            "expected {expected} byte key, got {}",
            key.len()
        )));
    }
    if data.len() < 12 + 16 {
        return Err(Error::Crypto("AES-GCM data too short".into()));
    }

    let nonce = Nonce::from_slice(&data[..12]);
    let ct_and_tag = &data[12..];

    match size {
        AesKeySize::Aes128 => {
            let cipher = aes_gcm::Aes128Gcm::new_from_slice(key)
                .map_err(|e| Error::Crypto(format!("AES-GCM init: {e}")))?;
            cipher
                .decrypt(nonce, ct_and_tag)
                .map_err(|e| Error::Crypto(format!("AES-GCM decrypt: {e}")))
        }
        AesKeySize::Aes192 => {
            use aes_gcm::aead::consts::U12;
            let cipher = aes_gcm::AesGcm::<aes::Aes192, U12>::new_from_slice(key)
                .map_err(|e| Error::Crypto(format!("AES-GCM init: {e}")))?;
            cipher
                .decrypt(nonce, ct_and_tag)
                .map_err(|e| Error::Crypto(format!("AES-GCM decrypt: {e}")))
        }
        AesKeySize::Aes256 => {
            let cipher = aes_gcm::Aes256Gcm::new_from_slice(key)
                .map_err(|e| Error::Crypto(format!("AES-GCM init: {e}")))?;
            cipher
                .decrypt(nonce, ct_and_tag)
                .map_err(|e| Error::Crypto(format!("AES-GCM decrypt: {e}")))
        }
    }
}

// ── 3DES-CBC ─────────────────────────────────────────────────────────

#[cfg(feature = "legacy")]
fn triple_des_cbc_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    use rand::RngCore;

    if key.len() != 24 {
        return Err(Error::Crypto(format!(
            "3DES key must be 24 bytes, got {}",
            key.len()
        )));
    }

    let mut iv = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut iv);

    let mut buf = pkcs7_pad(plaintext, 8);
    let buf_len = buf.len();

    let enc = cbc::Encryptor::<des::TdesEde3>::new_from_slices(key, &iv)
        .map_err(|e| Error::Crypto(format!("3DES init: {e}")))?;
    enc.encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf, buf_len)
        .map_err(|e| Error::Crypto(format!("3DES encrypt: {e}")))?;

    let mut result = Vec::with_capacity(8 + buf.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&buf);
    Ok(result)
}

#[cfg(feature = "legacy")]
fn triple_des_cbc_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};

    if key.len() != 24 {
        return Err(Error::Crypto(format!(
            "3DES key must be 24 bytes, got {}",
            key.len()
        )));
    }
    if data.len() < 8 || data.len() % 8 != 0 {
        return Err(Error::Crypto("3DES data invalid length".into()));
    }

    let iv = &data[..8];
    let mut buf = data[8..].to_vec();

    let dec = cbc::Decryptor::<des::TdesEde3>::new_from_slices(key, iv)
        .map_err(|e| Error::Crypto(format!("3DES init: {e}")))?;
    dec.decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
        .map_err(|e| Error::Crypto(format!("3DES decrypt: {e}")))?;

    xmlenc_unpad(&buf, 8)
}

// ── PKCS#7 padding ───────────────────────────────────────────────────

/// Apply PKCS#7 padding to `data` for the given `block_size`.
pub(crate) fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad_len = block_size - (data.len() % block_size);
    let mut padded = Vec::with_capacity(data.len() + pad_len);
    padded.extend_from_slice(data);
    padded.extend(std::iter::repeat_n(pad_len as u8, pad_len));
    padded
}

/// Remove W3C XML Encryption padding.
///
/// The XML Encryption spec (both 1.0 PKCS#7 style and 1.1 ISO 10126 style)
/// stores the padding length in the last byte.  PKCS#7 fills all padding bytes
/// with the length value; ISO 10126 uses random filler bytes with only the
/// last byte indicating the length.  We accept both by only checking the last
/// byte, which is compatible with either scheme.
pub(crate) fn xmlenc_unpad(data: &[u8], block_size: usize) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let pad_byte = *data.last().unwrap();
    let pad_len = pad_byte as usize;
    if pad_len == 0 || pad_len > block_size || pad_len > data.len() {
        return Err(Error::Crypto("invalid padding".into()));
    }
    Ok(data[..data.len() - pad_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::AesKeySize;

    #[test]
    fn test_pkcs7_roundtrip() {
        let padded = pkcs7_pad(b"hello", 16);
        assert_eq!(padded.len(), 16);
        let unpadded = xmlenc_unpad(&padded, 16).unwrap();
        assert_eq!(unpadded, b"hello");
    }

    #[test]
    fn test_iso10126_unpad() {
        // ISO 10126 padding: random bytes + last byte = pad length
        let mut data = b"hello world!".to_vec(); // 12 bytes
        data.extend_from_slice(&[0xAB, 0xCD, 0xEF, 0x04]); // 4 bytes padding, last = 4
        let unpadded = xmlenc_unpad(&data, 16).unwrap();
        assert_eq!(unpadded, b"hello world!");
    }

    #[test]
    fn test_aes128_cbc_roundtrip() {
        let key = [0x42u8; 16];
        let algo = CipherAlgorithm::AesCbc(AesKeySize::Aes128);
        let pt = b"hello world test";
        let ct = encrypt(algo, &key, pt).unwrap();
        let decrypted = decrypt(algo, &key, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_aes256_gcm_roundtrip() {
        let key = [0x42u8; 32];
        let algo = CipherAlgorithm::AesGcm(AesKeySize::Aes256);
        let pt = b"hello world";
        let ct = encrypt(algo, &key, pt).unwrap();
        let decrypted = decrypt(algo, &key, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_aes_gcm_authentication_failure() {
        let key = [0x42u8; 16];
        let algo = CipherAlgorithm::AesGcm(AesKeySize::Aes128);
        let pt = b"test message for GCM auth failure";
        let mut ct = encrypt(algo, &key, pt).unwrap();

        // Corrupt the last byte (part of the GCM authentication tag)
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;

        let result = decrypt(algo, &key, &ct);
        assert!(
            result.is_err(),
            "decryption should fail for corrupted GCM ciphertext"
        );
    }

    #[test]
    fn test_aes_gcm_wrong_key() {
        let key1 = [0x42u8; 16];
        let key2 = [0x99u8; 16];
        let algo = CipherAlgorithm::AesGcm(AesKeySize::Aes128);
        let pt = b"sensitive data";
        let ct = encrypt(algo, &key1, pt).unwrap();

        let result = decrypt(algo, &key2, &ct);
        assert!(result.is_err(), "decryption with wrong key should fail");
    }

    #[test]
    fn test_aes_gcm_roundtrip_all_sizes() {
        let cases: &[(AesKeySize, usize)] = &[
            (AesKeySize::Aes128, 16),
            (AesKeySize::Aes192, 24),
            (AesKeySize::Aes256, 32),
        ];
        let pt = b"Hello, World! This is a test message for AES-GCM encryption.";

        for &(size, key_len) in cases {
            let key: Vec<u8> = (0..key_len).map(|i| i as u8).collect();
            let algo = CipherAlgorithm::AesGcm(size);
            let ct = encrypt(algo, &key, pt).unwrap();
            let decrypted = decrypt(algo, &key, &ct).unwrap();
            assert_eq!(decrypted, pt, "roundtrip failed for {size:?}");
        }
    }

    #[test]
    fn test_aes_cbc_roundtrip_all_sizes() {
        let cases: &[(AesKeySize, usize)] = &[
            (AesKeySize::Aes128, 16),
            (AesKeySize::Aes192, 24),
            (AesKeySize::Aes256, 32),
        ];
        let plaintexts: &[&[u8]] = &[
            b"A",
            b"Hello",
            b"Hello, World!",
            b"Exactly16bytes!!", // Exactly one AES block
            b"This is a much longer test message that spans multiple AES blocks.",
        ];

        for &(size, key_len) in cases {
            let key: Vec<u8> = (0..key_len).map(|i| i as u8).collect();
            let algo = CipherAlgorithm::AesCbc(size);
            for &pt in plaintexts {
                let ct = encrypt(algo, &key, pt).unwrap();
                let decrypted = decrypt(algo, &key, &ct).unwrap();
                assert_eq!(
                    decrypted, pt,
                    "roundtrip failed for {size:?}, pt_len={}",
                    pt.len()
                );
            }
        }
    }

    #[cfg(feature = "legacy")]
    #[test]
    fn test_3des_roundtrip() {
        let key = [0x42u8; 24];
        let algo = CipherAlgorithm::TripleDesCbc;
        let pt = b"test data";
        let ct = encrypt(algo, &key, pt).unwrap();
        let decrypted = decrypt(algo, &key, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_wrong_key_size() {
        let result = encrypt(
            CipherAlgorithm::AesCbc(AesKeySize::Aes128),
            &[0u8; 15],
            b"data",
        );
        assert!(result.is_err());
    }
}
