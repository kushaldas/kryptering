#![forbid(unsafe_code)]

//! RSA key transport (RSA-OAEP, optionally RSA PKCS#1 v1.5).

use crate::algorithm::{HashAlgorithm, KeyTransportAlgorithm, OaepConfig};
use crate::error::{Error, Result};

/// Encrypt `key_data` using the specified RSA key transport algorithm.
///
/// An optional `label` may be provided for OAEP (the OAEPparams / label value).
pub fn kt_encrypt(
    algorithm: KeyTransportAlgorithm,
    public_key: &rsa::RsaPublicKey,
    key_data: &[u8],
    label: Option<&[u8]>,
) -> Result<Vec<u8>> {
    match algorithm {
        #[cfg(feature = "legacy")]
        KeyTransportAlgorithm::RsaPkcs1v15 => rsa_pkcs1_encrypt(public_key, key_data),
        KeyTransportAlgorithm::RsaOaep(config) => {
            rsa_oaep_encrypt(public_key, key_data, &config, label)
        }
    }
}

/// Decrypt `encrypted` using the specified RSA key transport algorithm.
///
/// An optional `label` may be provided for OAEP (must match the value used
/// during encryption).
pub fn kt_decrypt(
    algorithm: KeyTransportAlgorithm,
    private_key: &rsa::RsaPrivateKey,
    encrypted: &[u8],
    label: Option<&[u8]>,
) -> Result<Vec<u8>> {
    match algorithm {
        #[cfg(feature = "legacy")]
        KeyTransportAlgorithm::RsaPkcs1v15 => rsa_pkcs1_decrypt(private_key, encrypted),
        KeyTransportAlgorithm::RsaOaep(config) => {
            rsa_oaep_decrypt(private_key, encrypted, &config, label)
        }
    }
}

// ── RSA PKCS#1 v1.5 ─────────────────────────────────────────────────

#[cfg(feature = "legacy")]
fn rsa_pkcs1_encrypt(public_key: &rsa::RsaPublicKey, key_data: &[u8]) -> Result<Vec<u8>> {
    use rsa::Pkcs1v15Encrypt;
    let mut rng = rand::thread_rng();
    public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, key_data)
        .map_err(|e| Error::Crypto(format!("RSA PKCS#1 encrypt: {e}")))
}

#[cfg(feature = "legacy")]
fn rsa_pkcs1_decrypt(
    private_key: &rsa::RsaPrivateKey,
    encrypted: &[u8],
) -> Result<Vec<u8>> {
    use rsa::Pkcs1v15Encrypt;
    private_key
        .decrypt(Pkcs1v15Encrypt, encrypted)
        .map_err(|e| Error::Crypto(format!("RSA PKCS#1 decrypt: {e}")))
}

// ── RSA-OAEP ────────────────────────────────────────────────────────

/// Inner encrypt macro: creates an OAEP padding scheme from concrete types.
macro_rules! oaep_encrypt {
    ($public_key:expr, $key_data:expr, $digest:ty, $mgf:ty, $label:expr) => {{
        use rsa::Oaep;
        let mut rng = rand::thread_rng();
        let mut padding = Oaep::new_with_mgf_hash::<$digest, $mgf>();
        if let Some(label_bytes) = $label {
            padding.label = Some(String::from_utf8_lossy(label_bytes).into_owned());
        }
        $public_key
            .encrypt(&mut rng, padding, $key_data)
            .map_err(|e| Error::Crypto(format!("RSA-OAEP encrypt: {e}")))
    }};
}

/// Inner decrypt macro: creates an OAEP padding scheme from concrete types.
macro_rules! oaep_decrypt {
    ($private_key:expr, $encrypted:expr, $digest:ty, $mgf:ty, $label:expr) => {{
        use rsa::Oaep;
        let mut padding = Oaep::new_with_mgf_hash::<$digest, $mgf>();
        if let Some(label_bytes) = $label {
            padding.label = Some(String::from_utf8_lossy(label_bytes).into_owned());
        }
        $private_key
            .decrypt(padding, $encrypted)
            .map_err(|e| Error::Crypto(format!("RSA-OAEP decrypt: {e}")))
    }};
}

/// Dispatch OAEP encrypt for a given (digest, mgf_digest) pair.
macro_rules! oaep_dispatch_encrypt {
    ($pk:expr, $data:expr, $digest:expr, $mgf:expr, $label:expr) => {{
        macro_rules! with_mgf {
            ($d:ty) => {
                match $mgf {
                    HashAlgorithm::Sha1 => oaep_encrypt!($pk, $data, $d, sha1::Sha1, $label),
                    HashAlgorithm::Sha224 => oaep_encrypt!($pk, $data, $d, sha2::Sha224, $label),
                    HashAlgorithm::Sha256 => oaep_encrypt!($pk, $data, $d, sha2::Sha256, $label),
                    HashAlgorithm::Sha384 => oaep_encrypt!($pk, $data, $d, sha2::Sha384, $label),
                    HashAlgorithm::Sha512 => oaep_encrypt!($pk, $data, $d, sha2::Sha512, $label),
                    _ => oaep_encrypt!($pk, $data, $d, sha1::Sha1, $label),
                }
            };
        }
        match $digest {
            HashAlgorithm::Sha1 => with_mgf!(sha1::Sha1),
            HashAlgorithm::Sha224 => with_mgf!(sha2::Sha224),
            HashAlgorithm::Sha256 => with_mgf!(sha2::Sha256),
            HashAlgorithm::Sha384 => with_mgf!(sha2::Sha384),
            HashAlgorithm::Sha512 => with_mgf!(sha2::Sha512),
            #[cfg(feature = "legacy")]
            HashAlgorithm::Md5 => with_mgf!(md5::Md5),
            #[cfg(feature = "legacy")]
            HashAlgorithm::Ripemd160 => with_mgf!(ripemd::Ripemd160),
            _ => oaep_encrypt!($pk, $data, sha1::Sha1, sha1::Sha1, $label),
        }
    }};
}

/// Dispatch OAEP decrypt for a given (digest, mgf_digest) pair.
macro_rules! oaep_dispatch_decrypt {
    ($pk:expr, $data:expr, $digest:expr, $mgf:expr, $label:expr) => {{
        macro_rules! with_mgf {
            ($d:ty) => {
                match $mgf {
                    HashAlgorithm::Sha1 => oaep_decrypt!($pk, $data, $d, sha1::Sha1, $label),
                    HashAlgorithm::Sha224 => oaep_decrypt!($pk, $data, $d, sha2::Sha224, $label),
                    HashAlgorithm::Sha256 => oaep_decrypt!($pk, $data, $d, sha2::Sha256, $label),
                    HashAlgorithm::Sha384 => oaep_decrypt!($pk, $data, $d, sha2::Sha384, $label),
                    HashAlgorithm::Sha512 => oaep_decrypt!($pk, $data, $d, sha2::Sha512, $label),
                    _ => oaep_decrypt!($pk, $data, $d, sha1::Sha1, $label),
                }
            };
        }
        match $digest {
            HashAlgorithm::Sha1 => with_mgf!(sha1::Sha1),
            HashAlgorithm::Sha224 => with_mgf!(sha2::Sha224),
            HashAlgorithm::Sha256 => with_mgf!(sha2::Sha256),
            HashAlgorithm::Sha384 => with_mgf!(sha2::Sha384),
            HashAlgorithm::Sha512 => with_mgf!(sha2::Sha512),
            #[cfg(feature = "legacy")]
            HashAlgorithm::Md5 => with_mgf!(md5::Md5),
            #[cfg(feature = "legacy")]
            HashAlgorithm::Ripemd160 => with_mgf!(ripemd::Ripemd160),
            _ => oaep_decrypt!($pk, $data, sha1::Sha1, sha1::Sha1, $label),
        }
    }};
}

fn rsa_oaep_encrypt(
    public_key: &rsa::RsaPublicKey,
    key_data: &[u8],
    config: &OaepConfig,
    label: Option<&[u8]>,
) -> Result<Vec<u8>> {
    oaep_dispatch_encrypt!(public_key, key_data, config.digest, config.mgf_digest, label)
}

fn rsa_oaep_decrypt(
    private_key: &rsa::RsaPrivateKey,
    encrypted: &[u8],
    config: &OaepConfig,
    label: Option<&[u8]>,
) -> Result<Vec<u8>> {
    oaep_dispatch_decrypt!(private_key, encrypted, config.digest, config.mgf_digest, label)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::RsaPrivateKey;

    fn test_keypair() -> (rsa::RsaPublicKey, rsa::RsaPrivateKey) {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = rsa::RsaPublicKey::from(&private_key);
        (public_key, private_key)
    }

    #[test]
    fn test_rsa_oaep_sha1_roundtrip() {
        let (pub_key, priv_key) = test_keypair();
        let algo = KeyTransportAlgorithm::RsaOaep(OaepConfig::default());
        let key_data = b"16-byte-key!!!!"; // 15 bytes

        let encrypted = kt_encrypt(algo, &pub_key, key_data, None).unwrap();
        let decrypted = kt_decrypt(algo, &priv_key, &encrypted, None).unwrap();
        assert_eq!(decrypted, key_data);
    }

    #[test]
    fn test_rsa_oaep_sha256_roundtrip() {
        let (pub_key, priv_key) = test_keypair();
        let algo = KeyTransportAlgorithm::RsaOaep(OaepConfig {
            digest: HashAlgorithm::Sha256,
            mgf_digest: HashAlgorithm::Sha256,
        });
        let key_data = [0x42u8; 32];

        let encrypted = kt_encrypt(algo, &pub_key, &key_data, None).unwrap();
        let decrypted = kt_decrypt(algo, &priv_key, &encrypted, None).unwrap();
        assert_eq!(decrypted, key_data);
    }

    #[test]
    fn test_rsa_oaep_with_label() {
        let (pub_key, priv_key) = test_keypair();
        let algo = KeyTransportAlgorithm::RsaOaep(OaepConfig::default());
        let key_data = b"secret key data!";
        let label = b"my-label";

        let encrypted = kt_encrypt(algo, &pub_key, key_data, Some(label)).unwrap();
        let decrypted = kt_decrypt(algo, &priv_key, &encrypted, Some(label)).unwrap();
        assert_eq!(decrypted, key_data);
    }

    #[test]
    fn test_rsa_oaep_wrong_key_fails() {
        let (pub_key, _priv_key) = test_keypair();
        let (_pub_key2, priv_key2) = test_keypair();
        let algo = KeyTransportAlgorithm::RsaOaep(OaepConfig::default());
        let key_data = b"secret key data!";

        let encrypted = kt_encrypt(algo, &pub_key, key_data, None).unwrap();
        let result = kt_decrypt(algo, &priv_key2, &encrypted, None);
        assert!(result.is_err(), "decrypt with wrong key should fail");
    }

    #[test]
    fn test_rsa_oaep_mixed_digests() {
        let (pub_key, priv_key) = test_keypair();
        // SHA-256 digest with SHA-1 MGF (common in XML Encryption 1.0 style)
        let algo = KeyTransportAlgorithm::RsaOaep(OaepConfig {
            digest: HashAlgorithm::Sha256,
            mgf_digest: HashAlgorithm::Sha1,
        });
        let key_data = [0xAB; 24];

        let encrypted = kt_encrypt(algo, &pub_key, &key_data, None).unwrap();
        let decrypted = kt_decrypt(algo, &priv_key, &encrypted, None).unwrap();
        assert_eq!(decrypted, key_data);
    }

    #[cfg(feature = "legacy")]
    #[test]
    fn test_rsa_pkcs1v15_roundtrip() {
        let (pub_key, priv_key) = test_keypair();
        let algo = KeyTransportAlgorithm::RsaPkcs1v15;
        let key_data = b"a 24 byte key here!!!!!";

        let encrypted = kt_encrypt(algo, &pub_key, key_data, None).unwrap();
        let decrypted = kt_decrypt(algo, &priv_key, &encrypted, None).unwrap();
        assert_eq!(decrypted, key_data);
    }
}
