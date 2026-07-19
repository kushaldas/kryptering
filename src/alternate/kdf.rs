//! Provider-backed KDFs implemented only in terms of the selected digest/HMAC boundary.

use crate::algorithm::HashAlgorithm;
use crate::backend::{require_supported, Operation};
use crate::digest;
use crate::error::{Error, Result};

pub const PBKDF2_MIN_SALT_LEN: usize = 8;
pub const PBKDF2_MIN_ITERATIONS: u32 = 1;
pub const PBKDF2_MAX_ITERATIONS: u32 = 100_000_000;
pub const PBKDF2_MAX_KEY_LEN: usize = 1 << 20;
pub const CONCAT_KDF_MAX_KEY_LEN: usize = 1 << 20;

#[derive(Debug, Clone)]
pub struct ConcatKdfParams {
    pub hash: HashAlgorithm,
    pub algorithm_id: Option<Vec<u8>>,
    pub party_u_info: Option<Vec<u8>>,
    pub party_v_info: Option<Vec<u8>>,
}

impl Default for ConcatKdfParams {
    fn default() -> Self {
        Self {
            hash: HashAlgorithm::Sha256,
            algorithm_id: None,
            party_u_info: None,
            party_v_info: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Pbkdf2Params {
    pub hash: HashAlgorithm,
    pub salt: Vec<u8>,
    pub iteration_count: u32,
    pub key_length: usize,
}

impl Pbkdf2Params {
    pub fn recommended(salt: Vec<u8>, key_length: usize) -> Self {
        Self {
            hash: HashAlgorithm::Sha256,
            salt,
            iteration_count: 600_000,
            key_length,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HkdfParams {
    pub hash: HashAlgorithm,
    pub salt: Option<Vec<u8>>,
    pub info: Option<Vec<u8>>,
    pub key_length_bits: u32,
}

impl Default for HkdfParams {
    fn default() -> Self {
        Self {
            hash: HashAlgorithm::Sha256,
            salt: None,
            info: None,
            key_length_bits: 0,
        }
    }
}

pub fn concat_kdf(
    shared_secret: &[u8],
    key_len: usize,
    params: &ConcatKdfParams,
) -> Result<Vec<u8>> {
    require_supported(Operation::ConcatKdf(params.hash))?;
    if key_len == 0 || key_len > CONCAT_KDF_MAX_KEY_LEN {
        return Err(Error::Crypto("invalid ConcatKDF output length".into()));
    }
    let mut other_info = Vec::new();
    for value in [
        &params.algorithm_id,
        &params.party_u_info,
        &params.party_v_info,
    ]
    .into_iter()
    .flatten()
    {
        other_info.extend_from_slice(value);
    }
    let hash_len = hash_len(params.hash)?;
    let mut output = Vec::with_capacity(key_len);
    for counter in 1..=key_len.div_ceil(hash_len) {
        let counter = u32::try_from(counter)
            .map_err(|_| Error::Crypto("ConcatKDF counter overflow".into()))?;
        let mut input = Vec::with_capacity(4 + shared_secret.len() + other_info.len());
        input.extend_from_slice(&counter.to_be_bytes());
        input.extend_from_slice(shared_secret);
        input.extend_from_slice(&other_info);
        output.extend_from_slice(&digest::digest(params.hash, &input)?);
    }
    output.truncate(key_len);
    Ok(output)
}

pub fn pbkdf2_derive(password: &[u8], params: &Pbkdf2Params) -> Result<Vec<u8>> {
    require_supported(Operation::Pbkdf2(params.hash))?;
    if params.salt.len() < PBKDF2_MIN_SALT_LEN
        || params.iteration_count < PBKDF2_MIN_ITERATIONS
        || params.iteration_count > PBKDF2_MAX_ITERATIONS
        || params.key_length == 0
        || params.key_length > PBKDF2_MAX_KEY_LEN
    {
        return Err(Error::Crypto("invalid PBKDF2 parameters".into()));
    }
    let h_len = hash_len(params.hash)?;
    let blocks = params.key_length.div_ceil(h_len);
    let mut output = Vec::with_capacity(blocks * h_len);
    for block in 1..=blocks {
        let block = u32::try_from(block)
            .map_err(|_| Error::Crypto("PBKDF2 block counter overflow".into()))?;
        let mut first_input = params.salt.clone();
        first_input.extend_from_slice(&block.to_be_bytes());
        let mut u = digest::compute_hmac(params.hash, password, &first_input)?;
        let mut accumulator = u.clone();
        for _ in 1..params.iteration_count {
            u = digest::compute_hmac(params.hash, password, &u)?;
            for (left, right) in accumulator.iter_mut().zip(&u) {
                *left ^= right;
            }
        }
        output.extend_from_slice(&accumulator);
    }
    output.truncate(params.key_length);
    Ok(output)
}

pub fn hkdf_derive(shared_secret: &[u8], key_len: usize, params: &HkdfParams) -> Result<Vec<u8>> {
    require_supported(Operation::Hkdf(params.hash))?;
    let output_len = if params.key_length_bits > 0 {
        if !params.key_length_bits.is_multiple_of(8) {
            return Err(Error::Crypto(
                "HKDF output length is not byte aligned".into(),
            ));
        }
        params.key_length_bits as usize / 8
    } else {
        key_len
    };
    let h_len = hash_len(params.hash)?;
    if output_len == 0 || output_len > 255 * h_len {
        return Err(Error::Crypto("invalid HKDF output length".into()));
    }
    let zero_salt = vec![0u8; h_len];
    let salt = params.salt.as_deref().unwrap_or(&zero_salt);
    let prk = digest::compute_hmac(params.hash, salt, shared_secret)?;
    let info = params.info.as_deref().unwrap_or_default();
    let mut output = Vec::with_capacity(output_len);
    let mut previous = Vec::new();
    for counter in 1..=output_len.div_ceil(h_len) {
        let mut input = previous;
        input.extend_from_slice(info);
        input.push(counter as u8);
        previous = digest::compute_hmac(params.hash, &prk, &input)?;
        output.extend_from_slice(&previous);
    }
    output.truncate(output_len);
    Ok(output)
}

fn hash_len(hash: HashAlgorithm) -> Result<usize> {
    Ok(digest::digest(hash, &[])?.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_rfc5869_case_1() {
        let output = hkdf_derive(
            &[0x0b; 22],
            42,
            &HkdfParams {
                hash: HashAlgorithm::Sha256,
                salt: Some((0u8..13).collect()),
                info: Some((0xf0u8..0xfa).collect()),
                key_length_bits: 0,
            },
        )
        .unwrap();
        assert_eq!(
            hex::encode(output),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }
}
