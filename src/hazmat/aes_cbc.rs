#![forbid(unsafe_code)]

//! # ⚠ HAZMAT — AES-CBC (unauthenticated) ⚠
//!
//! AES-CBC with PKCS#7 / ISO 10126 padding, provided solely for legacy
//! interop (XML Encryption 1.0/1.1, older CMS profiles). See
//! [`crate::hazmat`] for the top-level warning.
//!
//! Use AES-GCM via [`crate::cipher`] for any new protocol. If you
//! genuinely need CBC for interop, you **must** wrap these outputs
//! with an HMAC over `IV || ciphertext` using a separate key and
//! verify that HMAC in constant time before calling [`decrypt`].
//!
//! ## Wire format
//!
//! `encrypt` prepends a 16-byte random IV to the ciphertext:
//! `IV || PKCS#7-padded-ciphertext`. `decrypt` expects the same layout
//! and accepts either PKCS#7 or ISO 10126 padding on the way back (for
//! XML-Enc compatibility).
//!
//! ## Error handling
//!
//! [`decrypt`] deliberately collapses every post-key-check failure
//! (wrong IV-less input length, wrong key for the ciphertext, bad
//! padding, internal RustCrypto error) into a single opaque
//! `Error::Crypto("AES-CBC decrypt failed")`. This narrows the
//! padding oracle but **does not close it** — timing differences
//! between the failure paths are still observable, and an attacker
//! who can repeatedly submit chosen ciphertexts to a real decryption
//! oracle will still recover plaintext. Authenticate your ciphertexts.

use crate::algorithm::AesKeySize;
use crate::error::{Error, Result};
use crate::software::cipher::{pkcs7_pad, xmlenc_unpad};

/// Encrypt `plaintext` under `key` using AES-CBC with PKCS#7 padding.
///
/// Prepends a freshly-generated 16-byte random IV to the ciphertext.
/// The output is **unauthenticated**; see the module-level warning.
pub fn encrypt(size: AesKeySize, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
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

/// Decrypt `data` (`IV || ciphertext`) under `key` using AES-CBC.
///
/// Every post-key-check failure collapses to
/// `Error::Crypto("AES-CBC decrypt failed")` to narrow (not close) the
/// padding oracle. See the module-level warning — authenticate the
/// ciphertext before calling this.
pub fn decrypt(size: AesKeySize, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};

    let expected = size.key_len();
    if key.len() != expected {
        return Err(Error::Crypto(format!(
            "expected {expected} byte key, got {}",
            key.len()
        )));
    }

    // From here down, every error path returns the same opaque message.
    let opaque = || Error::Crypto("AES-CBC decrypt failed".into());

    if data.len() < 16 || data.len() % 16 != 0 {
        return Err(opaque());
    }

    let iv = &data[..16];
    let ciphertext = &data[16..];
    let mut buf = ciphertext.to_vec();

    macro_rules! do_decrypt {
        ($aes:ty) => {{
            let dec =
                cbc::Decryptor::<$aes>::new_from_slices(key, iv).map_err(|_| opaque())?;
            dec.decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
                .map_err(|_| opaque())?;
        }};
    }

    match size {
        AesKeySize::Aes128 => do_decrypt!(aes::Aes128),
        AesKeySize::Aes192 => do_decrypt!(aes::Aes192),
        AesKeySize::Aes256 => do_decrypt!(aes::Aes256),
    }

    xmlenc_unpad(&buf, 16).map_err(|_| opaque())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_sizes() {
        let cases: &[(AesKeySize, usize)] = &[
            (AesKeySize::Aes128, 16),
            (AesKeySize::Aes192, 24),
            (AesKeySize::Aes256, 32),
        ];
        let plaintexts: &[&[u8]] = &[
            b"A",
            b"Hello",
            b"Hello, World!",
            b"Exactly16bytes!!",
            b"This is a much longer test message that spans multiple AES blocks.",
        ];

        for &(size, key_len) in cases {
            let key: Vec<u8> = (0..key_len).map(|i| i as u8).collect();
            for &pt in plaintexts {
                let ct = encrypt(size, &key, pt).unwrap();
                let decrypted = decrypt(size, &key, &ct).unwrap();
                assert_eq!(decrypted, pt, "roundtrip {size:?} pt_len={}", pt.len());
            }
        }
    }

    #[test]
    fn decrypt_errors_are_opaque() {
        // Every post-key-check failure must return the same message so that
        // callers cannot distinguish padding errors from ciphertext errors.
        // This narrows the padding oracle; see module docs for why it does
        // not eliminate it.
        let key = [0x42u8; 16];

        // Case: truncated input (structural). Message must match the
        // opaque form, not mention "length" or "block" etc.
        let err = decrypt(AesKeySize::Aes128, &key, &[0u8; 8]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("AES-CBC decrypt failed"), "got {msg}");

        // Case: bit-flip in ciphertext body (likely fails unpad or block
        // decrypt). Must produce the same opaque message.
        let ct = encrypt(AesKeySize::Aes128, &key, b"secret payload").unwrap();
        let mut bad = ct.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        let err = decrypt(AesKeySize::Aes128, &key, &bad).unwrap_err();
        assert!(
            err.to_string().contains("AES-CBC decrypt failed"),
            "got {err}"
        );

        // Case: wrong key (random plaintext, padding almost always invalid).
        let err = decrypt(AesKeySize::Aes128, &[0x00u8; 16], &ct).unwrap_err();
        assert!(
            err.to_string().contains("AES-CBC decrypt failed"),
            "got {err}"
        );
    }

    #[test]
    fn key_size_error_is_distinct() {
        // Key-size errors are structural (attacker can't influence them by
        // submitting ciphertexts), so they're allowed to be distinct and
        // helpful. Pin this so it doesn't regress into the opaque path.
        let err = decrypt(AesKeySize::Aes128, &[0u8; 15], &[0u8; 32]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("16 byte key"), "got {msg}");
    }
}
