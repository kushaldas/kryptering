pub mod algorithm;
pub mod digest;
pub mod error;
pub mod hazmat;
pub mod kdf;
pub mod key;
pub mod software;
pub mod traits;

#[cfg(feature = "pkcs11")]
pub mod pkcs11;

// Re-export core types at crate root for convenience.
pub use algorithm::*;
pub use error::{Error, Result};
pub use key::SoftwareKey;
pub use traits::*;

// Re-export software backend types.
pub use software::cipher;
pub use software::keyagreement;
pub use software::keytransport;
pub use software::keywrap;
pub use software::sign::{SoftwareSigner, SoftwareVerifier};
