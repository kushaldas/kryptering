/// Errors produced by kryptering cryptographic operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("key error: {0}")]
    Key(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[cfg(feature = "pkcs11")]
    #[error("PKCS#11 error: {0}")]
    Pkcs11(String),
}

pub type Result<T> = std::result::Result<T, Error>;
