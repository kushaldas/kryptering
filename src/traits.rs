use crate::algorithm::SignatureAlgorithm;
use crate::error::Result;

/// Signs data. Implemented by both software keys and HSM-backed keys.
pub trait Signer: Send + Sync {
    /// The signature algorithm this signer uses.
    fn algorithm(&self) -> SignatureAlgorithm;
    /// Sign the provided data.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
}

/// Verifies signatures. Implemented by both software keys and HSM-backed keys.
pub trait Verifier: Send + Sync {
    /// The signature algorithm this verifier uses.
    fn algorithm(&self) -> SignatureAlgorithm;
    /// Verify a signature over data. Returns `true` if valid.
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool>;
}

/// Decrypts key material (RSA key transport / key decryption).
pub trait Decryptor: Send + Sync {
    /// Decrypt ciphertext, returning the plaintext key material.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

/// Encrypts key material (RSA key transport / key encryption).
pub trait Encryptor: Send + Sync {
    /// Encrypt key material.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
}

/// Wraps and unwraps keys (AES-KW, AES-GCMKW, etc.).
pub trait KeyWrapper: Send + Sync {
    /// Wrap (encrypt) key data using the KEK.
    fn wrap(&self, key_data: &[u8]) -> Result<Vec<u8>>;
    /// Unwrap (decrypt) wrapped key data using the KEK.
    fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>>;
}

/// ECDH key agreement — produces a shared secret from a peer's public key.
pub trait KeyAgreement: Send + Sync {
    /// Perform key agreement with the peer's public key, returning the shared secret.
    fn agree(&self, peer_public_key: &[u8]) -> Result<Vec<u8>>;
}
