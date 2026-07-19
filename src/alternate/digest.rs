//! Digest and HMAC dispatch for the AWS-LC provider.

use crate::algorithm::{EcCurve, HashAlgorithm};
use crate::backend::{require_supported, Operation};
use crate::error::{Error, Result};

/// Opaque streaming digest interface.
pub trait DigestStream: Send {
    fn update(&mut self, data: &[u8]);
    fn finalize(self: Box<Self>) -> Result<Vec<u8>>;
    fn algorithm(&self) -> HashAlgorithm;
}

/// AWS-LC-backed streaming digest.
///
/// Wraps `aws_lc_rs::digest::Context` so input is fed to the hash incrementally
/// in constant memory, matching the RustCrypto provider's `DigestImpl`
/// behaviour. An earlier version buffered the entire input in a `Vec<u8>` and
/// hashed it in one shot at finalize time, which made RSS grow linearly with
/// input size on AWS-LC builds while RustCrypto stayed flat.
struct AwsLcDigest {
    algorithm: HashAlgorithm,
    context: aws_lc_rs::digest::Context,
}

impl DigestStream for AwsLcDigest {
    fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    fn finalize(self: Box<Self>) -> Result<Vec<u8>> {
        Ok(self.context.finish().as_ref().to_vec())
    }

    fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }
}

pub fn new_digest(algorithm: HashAlgorithm) -> Result<Box<dyn DigestStream>> {
    require_supported(Operation::Digest(algorithm))?;
    let aws_algorithm = aws_digest(algorithm).ok_or_else(|| {
        Error::unsupported(Operation::Digest(algorithm), format!("{algorithm:?}"))
    })?;
    Ok(Box::new(AwsLcDigest {
        algorithm,
        context: aws_lc_rs::digest::Context::new(aws_algorithm),
    }))
}

pub fn digest(algorithm: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    require_supported(Operation::Digest(algorithm))?;
    let algorithm = aws_digest(algorithm).ok_or_else(|| {
        Error::unsupported(Operation::Digest(algorithm), format!("{algorithm:?}"))
    })?;
    Ok(aws_lc_rs::digest::digest(algorithm, data).as_ref().to_vec())
}

pub fn compute_hmac(hash: HashAlgorithm, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    require_supported(Operation::Hmac(hash))?;
    let algorithm = aws_hmac(hash)
        .ok_or_else(|| Error::unsupported(Operation::Hmac(hash), format!("{hash:?}")))?;
    let key = aws_lc_rs::hmac::Key::new(algorithm, key);
    Ok(aws_lc_rs::hmac::sign(&key, data).as_ref().to_vec())
}

fn aws_digest(hash: HashAlgorithm) -> Option<&'static aws_lc_rs::digest::Algorithm> {
    Some(match hash {
        HashAlgorithm::Sha1 => &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
        HashAlgorithm::Sha224 => &aws_lc_rs::digest::SHA224,
        HashAlgorithm::Sha256 => &aws_lc_rs::digest::SHA256,
        HashAlgorithm::Sha384 => &aws_lc_rs::digest::SHA384,
        HashAlgorithm::Sha512 => &aws_lc_rs::digest::SHA512,
        HashAlgorithm::Sha3_256 => &aws_lc_rs::digest::SHA3_256,
        HashAlgorithm::Sha3_384 => &aws_lc_rs::digest::SHA3_384,
        HashAlgorithm::Sha3_512 => &aws_lc_rs::digest::SHA3_512,
        _ => return None,
    })
}

fn aws_hmac(hash: HashAlgorithm) -> Option<aws_lc_rs::hmac::Algorithm> {
    Some(match hash {
        HashAlgorithm::Sha1 => aws_lc_rs::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        HashAlgorithm::Sha224 => aws_lc_rs::hmac::HMAC_SHA224,
        HashAlgorithm::Sha256 => aws_lc_rs::hmac::HMAC_SHA256,
        HashAlgorithm::Sha384 => aws_lc_rs::hmac::HMAC_SHA384,
        HashAlgorithm::Sha512 => aws_lc_rs::hmac::HMAC_SHA512,
        _ => return None,
    })
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() || a.is_empty() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn hmac_verify_truncated(
    hash: HashAlgorithm,
    key: &[u8],
    data: &[u8],
    signature: &[u8],
    expected_len_bytes: usize,
) -> Result<bool> {
    if expected_len_bytes == 0 || signature.len() != expected_len_bytes {
        return Ok(false);
    }
    let full = compute_hmac(hash, key, data)?;
    if expected_len_bytes > full.len() {
        return Ok(false);
    }
    Ok(constant_time_eq(&full[..expected_len_bytes], signature))
}

pub fn ecdsa_raw_to_der(curve: EcCurve, raw: &[u8]) -> Result<Vec<u8>> {
    let field = curve_field_len(curve);
    raw_signature_to_der(field, raw, "ECDSA")
}

fn raw_signature_to_der(field: usize, raw: &[u8], name: &str) -> Result<Vec<u8>> {
    if raw.first() == Some(&0x30) {
        // A valid DER signature can be shorter than the fixed-width raw form
        // when r or s has leading zero octets. Treat it as DER only when the
        // entire sequence parses; a raw r||s value may legitimately start in
        // 0x30 and must retain the raw fallback.
        if let Ok(normalized) = der_signature_to_raw(field, raw, name) {
            return raw_signature_to_der(field, &normalized, name);
        }
    }
    if raw.len() < 2 || !raw.len().is_multiple_of(2) {
        return Err(Error::Crypto(format!(
            "invalid {name} raw signature length {}",
            raw.len()
        )));
    }
    let half = raw.len() / 2;
    let mut normalized = vec![0u8; field * 2];
    copy_raw_component(&raw[..half], &mut normalized[..field], name)?;
    copy_raw_component(&raw[half..], &mut normalized[field..], name)?;
    let r = der_integer(&normalized[..field]);
    let s = der_integer(&normalized[field..]);
    let mut content = Vec::with_capacity(r.len() + s.len());
    content.extend_from_slice(&r);
    content.extend_from_slice(&s);
    let mut output = vec![0x30];
    output.extend_from_slice(&der_length(content.len()));
    output.extend_from_slice(&content);
    Ok(output)
}

pub fn ecdsa_der_to_raw(curve: EcCurve, der: &[u8]) -> Result<Vec<u8>> {
    der_signature_to_raw(curve_field_len(curve), der, "ECDSA")
}

fn der_signature_to_raw(field: usize, der: &[u8], name: &str) -> Result<Vec<u8>> {
    let mut cursor = 0;
    expect_tag(der, &mut cursor, 0x30)?;
    let sequence_len = read_length(der, &mut cursor)?;
    if cursor + sequence_len != der.len() {
        return Err(Error::Crypto(format!("invalid {name} DER sequence length")));
    }
    let r = read_integer(der, &mut cursor)?;
    let s = read_integer(der, &mut cursor)?;
    if cursor != der.len() {
        return Err(Error::Crypto("trailing ECDSA DER data".into()));
    }
    let mut raw = vec![0u8; field * 2];
    copy_integer(r, &mut raw[..field])?;
    copy_integer(s, &mut raw[field..])?;
    Ok(raw)
}

fn curve_field_len(curve: EcCurve) -> usize {
    match curve {
        EcCurve::P256 => 32,
        EcCurve::P384 => 48,
        EcCurve::P521 => 66,
    }
}

fn der_integer(value: &[u8]) -> Vec<u8> {
    let value = value
        .iter()
        .position(|byte| *byte != 0)
        .map_or(&value[value.len() - 1..], |index| &value[index..]);
    let leading_zero = value[0] & 0x80 != 0;
    let mut output = vec![0x02];
    output.extend_from_slice(&der_length(value.len() + usize::from(leading_zero)));
    if leading_zero {
        output.push(0);
    }
    output.extend_from_slice(value);
    output
}

fn der_length(length: usize) -> Vec<u8> {
    if length < 128 {
        return vec![length as u8];
    }
    let bytes = length.to_be_bytes();
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let mut output = vec![0x80 | (bytes.len() - start) as u8];
    output.extend_from_slice(&bytes[start..]);
    output
}

fn expect_tag(input: &[u8], cursor: &mut usize, expected: u8) -> Result<()> {
    if input.get(*cursor) != Some(&expected) {
        return Err(Error::Crypto("invalid ECDSA DER tag".into()));
    }
    *cursor += 1;
    Ok(())
}

fn read_length(input: &[u8], cursor: &mut usize) -> Result<usize> {
    let first = *input
        .get(*cursor)
        .ok_or_else(|| Error::Crypto("truncated ECDSA DER length".into()))?;
    *cursor += 1;
    if first & 0x80 == 0 {
        return Ok(first as usize);
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > std::mem::size_of::<usize>() || *cursor + count > input.len() {
        return Err(Error::Crypto("invalid ECDSA DER length".into()));
    }
    let mut length = 0usize;
    for byte in &input[*cursor..*cursor + count] {
        length = (length << 8) | *byte as usize;
    }
    // DER (X.690 §8.1.3.3) requires the minimum number of length octets:
    //   * a one-octet long form may only encode values >= 128 (otherwise
    //     the short form must be used);
    //   * a multi-octet long form must not have a leading zero octet
    //     (otherwise fewer octets suffice).
    // Rejecting non-minimal encodings closes a signature-malleability
    // surface where two distinct DER byte strings decode to the same r||s.
    if count == 1 && length < 128 {
        return Err(Error::Crypto("non-minimal ECDSA DER length".into()));
    }
    if count > 1 && input[*cursor] == 0 {
        return Err(Error::Crypto("non-minimal ECDSA DER length".into()));
    }
    *cursor += count;
    Ok(length)
}

fn read_integer<'a>(input: &'a [u8], cursor: &mut usize) -> Result<&'a [u8]> {
    expect_tag(input, cursor, 0x02)?;
    let length = read_length(input, cursor)?;
    let value = input
        .get(*cursor..*cursor + length)
        .ok_or_else(|| Error::Crypto("truncated ECDSA DER integer".into()))?;
    *cursor += length;
    if value.is_empty() || value[0] & 0x80 != 0 {
        return Err(Error::Crypto(
            "invalid negative or empty ECDSA integer".into(),
        ));
    }
    // DER (X.690 §8.3.2) requires the minimum number of content octets. A
    // leading 0x00 is only permitted when the next octet has its high bit
    // set (to keep the integer positive); any other leading zero is
    // non-minimal and yields a second, distinct DER encoding of the same
    // value — a signature-malleability surface for consensus callers.
    if value.len() > 1 && value[0] == 0 && value[1] & 0x80 == 0 {
        return Err(Error::Crypto("non-minimal ECDSA DER integer".into()));
    }
    Ok(value)
}

fn copy_integer(value: &[u8], output: &mut [u8]) -> Result<()> {
    let value = if value.len() > 1 && value[0] == 0 {
        &value[1..]
    } else {
        value
    };
    if value.len() > output.len() {
        return Err(Error::Crypto(
            "ECDSA DER integer exceeds curve width".into(),
        ));
    }
    let offset = output.len() - value.len();
    output[offset..].copy_from_slice(value);
    Ok(())
}

fn copy_raw_component(value: &[u8], output: &mut [u8], name: &str) -> Result<()> {
    let value = value
        .iter()
        .position(|byte| *byte != 0)
        .map_or(&value[value.len().saturating_sub(1)..], |index| {
            &value[index..]
        });
    if value.len() > output.len() {
        return Err(Error::Crypto(format!(
            "{name} signature component exceeds field width"
        )));
    }
    let offset = output.len() - value.len();
    output[offset..].copy_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_answer() {
        let output = digest(HashAlgorithm::Sha256, b"abc").unwrap();
        assert_eq!(
            hex::encode(output),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn ecdsa_der_round_trip() {
        let mut raw = vec![0u8; 64];
        raw[0] = 0x80;
        raw[63] = 7;
        let der = ecdsa_raw_to_der(EcCurve::P256, &raw).unwrap();
        assert_eq!(ecdsa_der_to_raw(EcCurve::P256, &der).unwrap(), raw);
    }

    #[test]
    fn ecdsa_accepts_short_and_zero_padded_raw_components() {
        let short = vec![1u8; 62];
        assert!(ecdsa_raw_to_der(EcCurve::P256, &short).is_ok());

        let mut padded = vec![0u8; 66];
        padded[1] = 1;
        padded[34] = 2;
        assert!(ecdsa_raw_to_der(EcCurve::P256, &padded).is_ok());
    }

    // DER canonicality (X.690 §8.1.3.3 / §8.3.2): two distinct byte strings
    // must not decode to the same r||s. Each test below is a valid
    // signature semantically but a non-minimal DER encoding; the parser
    // must reject it so consensus callers see one canonical form.

    #[test]
    fn ecdsa_rejects_non_minimal_long_form_length() {
        // SEQUENCE of two 1-byte integers (r=1, s=1). Canonical:
        //   30 06 02 01 01 02 01 01
        // Non-minimal length for the SEQUENCE (0x81 0x06 instead of 0x06):
        //   30 81 06 02 01 01 02 01 01
        let non_minimal = [0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        assert!(ecdsa_der_to_raw(EcCurve::P256, &non_minimal).is_err());
    }

    #[test]
    fn ecdsa_rejects_non_minimal_multi_octet_length() {
        // SEQUENCE length 0x80 encoded as 0x82 0x00 0x80 instead of 0x81 0x80.
        // The length octets alone must be rejected before the body is inspected.
        let mut non_minimal = vec![0x30, 0x82, 0x00, 0x80];
        // r: 32 bytes with high bit set (needs leading zero) -> 33 content bytes
        non_minimal.push(0x02);
        non_minimal.push(0x21);
        non_minimal.push(0x00);
        non_minimal.extend([0x80; 32]);
        // s: 32 bytes with high bit set -> 33 content bytes
        non_minimal.push(0x02);
        non_minimal.push(0x21);
        non_minimal.push(0x00);
        non_minimal.extend([0x80; 32]);
        assert!(ecdsa_der_to_raw(EcCurve::P256, &non_minimal).is_err());
    }

    #[test]
    fn ecdsa_rejects_unnecessary_leading_zero_in_integer() {
        // r = 0x01 encoded as 0x02 0x02 0x00 0x01 (leading zero, next byte
        // high bit clear) instead of the minimal 0x02 0x01 0x01.
        let non_minimal = [0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01];
        assert!(ecdsa_der_to_raw(EcCurve::P256, &non_minimal).is_err());
    }

    #[test]
    fn ecdsa_accepts_required_leading_zero_in_integer() {
        // r = 0x80 (high bit set) must be encoded as 0x02 0x02 0x00 0x80 to
        // stay positive — the leading zero is required, not non-minimal.
        let mut der = vec![0x30, 0x08, 0x02, 0x02, 0x00, 0x80, 0x02, 0x02, 0x00, 0x80];
        // Pad the raw form to 64 bytes so der_to_raw lands in field width.
        let _ = &mut der;
        let raw = ecdsa_der_to_raw(EcCurve::P256, &der).expect("required leading zero is canonical");
        assert_eq!(raw.len(), 64);
    }
}
