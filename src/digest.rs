use crate::algorithm::HashAlgorithm;
use crate::error::{Error, Result};
use digest::Digest;

/// Streaming digest interface.
pub trait DigestStream: Send {
    fn update(&mut self, data: &[u8]);
    fn finalize(self: Box<Self>) -> Vec<u8>;
    fn algorithm(&self) -> HashAlgorithm;
}

/// Create a streaming digest for the given algorithm.
pub fn new_digest(algorithm: HashAlgorithm) -> Result<Box<dyn DigestStream>> {
    match algorithm {
        HashAlgorithm::Sha1 => Ok(Box::new(DigestImpl::<sha1::Sha1>::new(algorithm))),
        HashAlgorithm::Sha224 => Ok(Box::new(DigestImpl::<sha2::Sha224>::new(algorithm))),
        HashAlgorithm::Sha256 => Ok(Box::new(DigestImpl::<sha2::Sha256>::new(algorithm))),
        HashAlgorithm::Sha384 => Ok(Box::new(DigestImpl::<sha2::Sha384>::new(algorithm))),
        HashAlgorithm::Sha512 => Ok(Box::new(DigestImpl::<sha2::Sha512>::new(algorithm))),
        HashAlgorithm::Sha3_224 => Ok(Box::new(DigestImpl::<sha3::Sha3_224>::new(algorithm))),
        HashAlgorithm::Sha3_256 => Ok(Box::new(DigestImpl::<sha3::Sha3_256>::new(algorithm))),
        HashAlgorithm::Sha3_384 => Ok(Box::new(DigestImpl::<sha3::Sha3_384>::new(algorithm))),
        HashAlgorithm::Sha3_512 => Ok(Box::new(DigestImpl::<sha3::Sha3_512>::new(algorithm))),
        #[cfg(feature = "legacy")]
        HashAlgorithm::Md5 => Ok(Box::new(DigestImpl::<md5::Md5>::new(algorithm))),
        #[cfg(feature = "legacy")]
        HashAlgorithm::Ripemd160 => Ok(Box::new(DigestImpl::<ripemd::Ripemd160>::new(algorithm))),
    }
}

/// Compute a digest in one shot.
pub fn digest(algorithm: HashAlgorithm, data: &[u8]) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::Sha1 => sha1::Sha1::digest(data).to_vec(),
        HashAlgorithm::Sha224 => sha2::Sha224::digest(data).to_vec(),
        HashAlgorithm::Sha256 => sha2::Sha256::digest(data).to_vec(),
        HashAlgorithm::Sha384 => sha2::Sha384::digest(data).to_vec(),
        HashAlgorithm::Sha512 => sha2::Sha512::digest(data).to_vec(),
        HashAlgorithm::Sha3_224 => sha3::Sha3_224::digest(data).to_vec(),
        HashAlgorithm::Sha3_256 => sha3::Sha3_256::digest(data).to_vec(),
        HashAlgorithm::Sha3_384 => sha3::Sha3_384::digest(data).to_vec(),
        HashAlgorithm::Sha3_512 => sha3::Sha3_512::digest(data).to_vec(),
        #[cfg(feature = "legacy")]
        HashAlgorithm::Md5 => md5::Md5::digest(data).to_vec(),
        #[cfg(feature = "legacy")]
        HashAlgorithm::Ripemd160 => ripemd::Ripemd160::digest(data).to_vec(),
    }
}

/// Compute HMAC for the given hash algorithm.
pub fn compute_hmac(hash: HashAlgorithm, key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    macro_rules! hmac_compute {
        ($hasher:ty) => {{
            let mut mac = <Hmac<$hasher>>::new_from_slice(key).expect("HMAC key");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }};
    }
    match hash {
        HashAlgorithm::Sha1 => hmac_compute!(sha1::Sha1),
        HashAlgorithm::Sha224 => hmac_compute!(sha2::Sha224),
        HashAlgorithm::Sha256 => hmac_compute!(sha2::Sha256),
        HashAlgorithm::Sha384 => hmac_compute!(sha2::Sha384),
        HashAlgorithm::Sha512 => hmac_compute!(sha2::Sha512),
        HashAlgorithm::Sha3_224 => hmac_compute!(sha3::Sha3_224),
        HashAlgorithm::Sha3_256 => hmac_compute!(sha3::Sha3_256),
        HashAlgorithm::Sha3_384 => hmac_compute!(sha3::Sha3_384),
        HashAlgorithm::Sha3_512 => hmac_compute!(sha3::Sha3_512),
        #[cfg(feature = "legacy")]
        HashAlgorithm::Md5 => hmac_compute!(md5::Md5),
        #[cfg(feature = "legacy")]
        HashAlgorithm::Ripemd160 => hmac_compute!(ripemd::Ripemd160),
    }
}

/// Constant-time comparison supporting truncated HMAC.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if b.is_empty() || a.is_empty() {
        return false;
    }
    if b.len() < a.len() {
        return a[..b.len()]
            .iter()
            .zip(b.iter())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0;
    }
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

// ── Internal digest wrapper ─────────────────────────────────────────

struct DigestImpl<H: Digest + Send> {
    inner: H,
    algo: HashAlgorithm,
}

impl<H: Digest + Send> DigestImpl<H> {
    fn new(algo: HashAlgorithm) -> Self {
        Self {
            inner: H::new(),
            algo,
        }
    }
}

impl<H: Digest + Send + 'static> DigestStream for DigestImpl<H> {
    fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.inner, data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        Digest::finalize(self.inner).to_vec()
    }

    fn algorithm(&self) -> HashAlgorithm {
        self.algo
    }
}

/// ECDSA signature format conversion: raw r||s to DER.
pub fn ecdsa_raw_to_der(curve: crate::algorithm::EcCurve, raw: &[u8]) -> Result<Vec<u8>> {
    match curve {
        crate::algorithm::EcCurve::P256 => {
            let sig = raw_to_p256_sig(raw)?;
            Ok(sig.to_der().as_bytes().to_vec())
        }
        crate::algorithm::EcCurve::P384 => {
            let sig = raw_to_p384_sig(raw)?;
            Ok(sig.to_der().as_bytes().to_vec())
        }
        crate::algorithm::EcCurve::P521 => {
            let sig = raw_to_p521_sig(raw)?;
            Ok(sig.to_der().as_bytes().to_vec())
        }
    }
}

/// ECDSA signature format conversion: DER to raw r||s.
pub fn ecdsa_der_to_raw(curve: crate::algorithm::EcCurve, der: &[u8]) -> Result<Vec<u8>> {
    match curve {
        crate::algorithm::EcCurve::P256 => {
            let sig = p256::ecdsa::Signature::from_der(der)
                .map_err(|e| Error::Crypto(format!("invalid P-256 DER signature: {e}")))?;
            Ok(p256_sig_to_raw(&sig))
        }
        crate::algorithm::EcCurve::P384 => {
            let sig = p384::ecdsa::Signature::from_der(der)
                .map_err(|e| Error::Crypto(format!("invalid P-384 DER signature: {e}")))?;
            Ok(p384_sig_to_raw(&sig))
        }
        crate::algorithm::EcCurve::P521 => {
            let sig = p521::ecdsa::Signature::from_der(der)
                .map_err(|e| Error::Crypto(format!("invalid P-521 DER signature: {e}")))?;
            Ok(p521_sig_to_raw(&sig))
        }
    }
}

// ── ECDSA raw/typed conversion helpers ──────────────────────────────

/// Normalize a raw r||s ECDSA signature where each component may be
/// padded or truncated. Splits evenly, strips leading zeros, left-pads to field_size.
pub(crate) fn normalize_raw_ecdsa(sig_bytes: &[u8], field_size: usize) -> Result<Vec<u8>> {
    if sig_bytes.len() % 2 != 0 {
        return Err(Error::Crypto(format!(
            "ECDSA signature has odd length {}, cannot split into r||s",
            sig_bytes.len()
        )));
    }
    let half = sig_bytes.len() / 2;
    let mut out = vec![0u8; field_size * 2];
    for (i, component) in [&sig_bytes[..half], &sig_bytes[half..]].iter().enumerate() {
        let trimmed = match component.iter().position(|&b| b != 0) {
            Some(pos) => &component[pos..],
            None => &component[component.len().saturating_sub(1)..],
        };
        if trimmed.len() > field_size {
            return Err(Error::Crypto(format!(
                "ECDSA component {} too large: {} bytes (field size {})",
                if i == 0 { "r" } else { "s" },
                trimmed.len(),
                field_size
            )));
        }
        let offset = i * field_size + field_size - trimmed.len();
        out[offset..offset + trimmed.len()].copy_from_slice(trimmed);
    }
    Ok(out)
}

pub(crate) fn raw_to_p256_sig(sig_bytes: &[u8]) -> Result<p256::ecdsa::Signature> {
    const FIELD: usize = 32;
    if sig_bytes.len() == FIELD * 2 {
        let r = p256::FieldBytes::from_slice(&sig_bytes[..FIELD]);
        let s = p256::FieldBytes::from_slice(&sig_bytes[FIELD..]);
        return p256::ecdsa::Signature::from_scalars(*r, *s)
            .map_err(|e| Error::Crypto(format!("invalid P-256 signature: {e}")));
    }
    if sig_bytes.first() == Some(&0x30) {
        return p256::ecdsa::Signature::from_der(sig_bytes)
            .map_err(|e| Error::Crypto(format!("invalid P-256 DER signature: {e}")));
    }
    let normalized = normalize_raw_ecdsa(sig_bytes, FIELD)?;
    let r = p256::FieldBytes::from_slice(&normalized[..FIELD]);
    let s = p256::FieldBytes::from_slice(&normalized[FIELD..]);
    p256::ecdsa::Signature::from_scalars(*r, *s)
        .map_err(|e| Error::Crypto(format!("invalid P-256 signature: {e}")))
}

pub(crate) fn p256_sig_to_raw(sig: &p256::ecdsa::Signature) -> Vec<u8> {
    let (r, s) = sig.split_bytes();
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&r);
    out.extend_from_slice(&s);
    out
}

pub(crate) fn raw_to_p384_sig(sig_bytes: &[u8]) -> Result<p384::ecdsa::Signature> {
    const FIELD: usize = 48;
    if sig_bytes.len() == FIELD * 2 {
        let r = p384::FieldBytes::from_slice(&sig_bytes[..FIELD]);
        let s = p384::FieldBytes::from_slice(&sig_bytes[FIELD..]);
        return p384::ecdsa::Signature::from_scalars(*r, *s)
            .map_err(|e| Error::Crypto(format!("invalid P-384 signature: {e}")));
    }
    if sig_bytes.first() == Some(&0x30) {
        return p384::ecdsa::Signature::from_der(sig_bytes)
            .map_err(|e| Error::Crypto(format!("invalid P-384 DER signature: {e}")));
    }
    let normalized = normalize_raw_ecdsa(sig_bytes, FIELD)?;
    let r = p384::FieldBytes::from_slice(&normalized[..FIELD]);
    let s = p384::FieldBytes::from_slice(&normalized[FIELD..]);
    p384::ecdsa::Signature::from_scalars(*r, *s)
        .map_err(|e| Error::Crypto(format!("invalid P-384 signature: {e}")))
}

pub(crate) fn p384_sig_to_raw(sig: &p384::ecdsa::Signature) -> Vec<u8> {
    let (r, s) = sig.split_bytes();
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(&r);
    out.extend_from_slice(&s);
    out
}

pub(crate) fn raw_to_p521_sig(sig_bytes: &[u8]) -> Result<p521::ecdsa::Signature> {
    const FIELD: usize = 66;
    if sig_bytes.len() == FIELD * 2 {
        let r = p521::FieldBytes::from_slice(&sig_bytes[..FIELD]);
        let s = p521::FieldBytes::from_slice(&sig_bytes[FIELD..]);
        return p521::ecdsa::Signature::from_scalars(*r, *s)
            .map_err(|e| Error::Crypto(format!("invalid P-521 signature: {e}")));
    }
    if sig_bytes.first() == Some(&0x30) {
        return p521::ecdsa::Signature::from_der(sig_bytes)
            .map_err(|e| Error::Crypto(format!("invalid P-521 DER signature: {e}")));
    }
    let normalized = normalize_raw_ecdsa(sig_bytes, FIELD)?;
    let r = p521::FieldBytes::from_slice(&normalized[..FIELD]);
    let s = p521::FieldBytes::from_slice(&normalized[FIELD..]);
    p521::ecdsa::Signature::from_scalars(*r, *s)
        .map_err(|e| Error::Crypto(format!("invalid P-521 signature: {e}")))
}

pub(crate) fn p521_sig_to_raw(sig: &p521::ecdsa::Signature) -> Vec<u8> {
    let (r, s) = sig.split_bytes();
    let mut out = Vec::with_capacity(132);
    out.extend_from_slice(&r);
    out.extend_from_slice(&s);
    out
}

/// Left-pad a prehash with zeros to match the EC field size.
pub(crate) fn pad_prehash(prehash: &[u8], field_size: usize) -> Vec<u8> {
    if prehash.len() >= field_size {
        return prehash.to_vec();
    }
    let mut padded = vec![0u8; field_size];
    padded[field_size - prehash.len()..].copy_from_slice(prehash);
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let result = digest(HashAlgorithm::Sha256, b"hello");
        assert_eq!(result.len(), 32);
        let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        let hex: String = result.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, expected);
    }

    #[test]
    fn test_sha1() {
        let result = digest(HashAlgorithm::Sha1, b"hello");
        assert_eq!(result.len(), 20);
    }

    #[test]
    fn test_sha512() {
        let result = digest(HashAlgorithm::Sha512, b"hello");
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_streaming_digest() {
        let mut hasher = new_digest(HashAlgorithm::Sha256).unwrap();
        hasher.update(b"hel");
        hasher.update(b"lo");
        let result = hasher.finalize();
        let expected = digest(HashAlgorithm::Sha256, b"hello");
        assert_eq!(result, expected);
    }
}
