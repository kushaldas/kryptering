//! Provider-independent ECDSA encoding and scalar validation.
use crate::algorithm::EcCurve;
use crate::error::{Error, Result};

/// Exact-width inputs are raw; other lengths may contain canonical DER.
/// Structural DER success commits to DER even if its scalars are invalid.
pub(crate) fn normalize(curve: EcCurve, input: &[u8]) -> Result<Vec<u8>> {
    let field = curve_field_len(curve);
    if input.len() != field * 2 && input.first() == Some(&0x30) {
        if let Ok((r, s)) = parse_der(input) {
            let raw = der_components_to_raw(field, r, s)?;
            validate_scalars(curve, &raw)?;
            return Ok(raw);
        }
    }
    if input.len() < 2 || !input.len().is_multiple_of(2) {
        return Err(Error::Crypto("invalid ECDSA raw signature length".into()));
    }
    let half = input.len() / 2;
    let mut raw = vec![0; field * 2];
    copy_raw_component(&input[..half], &mut raw[..field], "ECDSA")?;
    copy_raw_component(&input[half..], &mut raw[field..], "ECDSA")?;
    validate_scalars(curve, &raw)?;
    Ok(raw)
}

pub(crate) fn to_der(curve: EcCurve, input: &[u8]) -> Result<Vec<u8>> {
    let raw = normalize(curve, input)?;
    let field = curve_field_len(curve);
    let mut content = der_integer(&raw[..field]);
    content.extend(der_integer(&raw[field..]));
    let mut output = vec![0x30];
    output.extend(der_length(content.len()));
    output.extend(content);
    Ok(output)
}

pub(crate) fn from_der(curve: EcCurve, input: &[u8]) -> Result<Vec<u8>> {
    let (r, s) = parse_der(input)?;
    let raw = der_components_to_raw(curve_field_len(curve), r, s)?;
    validate_scalars(curve, &raw)?;
    Ok(raw)
}

/// Signature scalars are public: bytewise range comparisons need not be constant-time.
fn validate_scalars(curve: EcCurve, raw: &[u8]) -> Result<()> {
    let order = curve_order(curve);
    for scalar in raw.chunks_exact(order.len()) {
        if scalar.iter().all(|byte| *byte == 0) || scalar >= order {
            return Err(Error::Crypto(
                "invalid ECDSA signature scalar (must satisfy 1 <= scalar < curve order)".into(),
            ));
        }
    }
    Ok(())
}

/// Subgroup orders encoded at the curve's raw width.
///
/// Sources: SEC 2 v2 §2.4.1 (secp256k1) and §2.4.2–2.4.4 (NIST curves),
/// RFC 5639 §3.4 / §3.6 / §3.7 (Brainpool). Cross-checked against OpenSSL
/// `ecparam -text` and the RustCrypto curve crates' `ORDER` constants.
fn curve_order(curve: EcCurve) -> &'static [u8] {
    match curve {
        EcCurve::Secp256k1 => &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ],
        EcCurve::BrainpoolP256r1 => &[
            0xa9, 0xfb, 0x57, 0xdb, 0xa1, 0xee, 0xa9, 0xbc, 0x3e, 0x66, 0x0a, 0x90, 0x9d, 0x83,
            0x8d, 0x71, 0x8c, 0x39, 0x7a, 0xa3, 0xb5, 0x61, 0xa6, 0xf7, 0x90, 0x1e, 0x0e, 0x82,
            0x97, 0x48, 0x56, 0xa7,
        ],
        EcCurve::BrainpoolP384r1 => &[
            0x8c, 0xb9, 0x1e, 0x82, 0xa3, 0x38, 0x6d, 0x28, 0x0f, 0x5d, 0x6f, 0x7e, 0x50, 0xe6,
            0x41, 0xdf, 0x15, 0x2f, 0x71, 0x09, 0xed, 0x54, 0x56, 0xb3, 0x1f, 0x16, 0x6e, 0x6c,
            0xac, 0x04, 0x25, 0xa7, 0xcf, 0x3a, 0xb6, 0xaf, 0x6b, 0x7f, 0xc3, 0x10, 0x3b, 0x88,
            0x32, 0x02, 0xe9, 0x04, 0x65, 0x65,
        ],
        EcCurve::BrainpoolP512r1 => &[
            0xaa, 0xdd, 0x9d, 0xb8, 0xdb, 0xe9, 0xc4, 0x8b, 0x3f, 0xd4, 0xe6, 0xae, 0x33, 0xc9,
            0xfc, 0x07, 0xcb, 0x30, 0x8d, 0xb3, 0xb3, 0xc9, 0xd2, 0x0e, 0xd6, 0x63, 0x9c, 0xca,
            0x70, 0x33, 0x08, 0x70, 0x55, 0x3e, 0x5c, 0x41, 0x4c, 0xa9, 0x26, 0x19, 0x41, 0x86,
            0x61, 0x19, 0x7f, 0xac, 0x10, 0x47, 0x1d, 0xb1, 0xd3, 0x81, 0x08, 0x5d, 0xda, 0xdd,
            0xb5, 0x87, 0x96, 0x82, 0x9c, 0xa9, 0x00, 0x69,
        ],
        EcCurve::P256 => &[
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ],
        EcCurve::P384 => &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81,
            0xf4, 0x37, 0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec,
            0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73,
        ],
        EcCurve::P521 => &[
            0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xfa, 0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f, 0x96, 0x6b,
            0x7f, 0xcc, 0x01, 0x48, 0xf7, 0x09, 0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c,
            0x47, 0xae, 0xbb, 0x6f, 0xb7, 0x1e, 0x91, 0x38, 0x64, 0x09,
        ],
    }
}

fn parse_der(der: &[u8]) -> Result<(&[u8], &[u8])> {
    let mut cursor = 0;
    expect_tag(der, &mut cursor, 0x30)?;
    let sequence_len = read_length(der, &mut cursor)?;
    if cursor.checked_add(sequence_len) != Some(der.len()) {
        return Err(Error::Crypto("invalid ECDSA DER sequence length".into()));
    }
    let r = read_integer(der, &mut cursor)?;
    let s = read_integer(der, &mut cursor)?;
    if cursor != der.len() {
        return Err(Error::Crypto("trailing ECDSA DER data".into()));
    }
    Ok((r, s))
}

fn der_components_to_raw(field: usize, r: &[u8], s: &[u8]) -> Result<Vec<u8>> {
    let mut raw = vec![0u8; field * 2];
    copy_integer(r, &mut raw[..field])?;
    copy_integer(s, &mut raw[field..])?;
    Ok(raw)
}

/// Width in bytes of one field element / scalar for `curve`.
pub(crate) fn curve_field_len(curve: EcCurve) -> usize {
    match curve {
        EcCurve::P256 | EcCurve::Secp256k1 | EcCurve::BrainpoolP256r1 => 32,
        EcCurve::P384 | EcCurve::BrainpoolP384r1 => 48,
        EcCurve::P521 => 66,
        EcCurve::BrainpoolP512r1 => 64,
    }
}

/// Every curve kryptering names, for exhaustive table tests.
#[cfg(test)]
pub(crate) const ALL_CURVES: [EcCurve; 7] = [
    EcCurve::P256,
    EcCurve::P384,
    EcCurve::P521,
    EcCurve::Secp256k1,
    EcCurve::BrainpoolP256r1,
    EcCurve::BrainpoolP384r1,
    EcCurve::BrainpoolP512r1,
];

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
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| Error::Crypto("invalid ECDSA DER integer length".into()))?;
    let value = input
        .get(*cursor..end)
        .ok_or_else(|| Error::Crypto("truncated ECDSA DER integer".into()))?;
    *cursor = end;
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

    /// Invariant: every order table entry is encoded at the curve's raw width
    /// and the scalar check accepts `n - 1`, rejects `n` and rejects zero.
    #[test]
    fn curve_orders_have_raw_width_and_bound_scalars() {
        for curve in ALL_CURVES {
            let field = curve_field_len(curve);
            let order = curve_order(curve);
            assert_eq!(order.len(), field, "{curve:?}");
            assert_eq!(order[field - 1] & 1, 1, "{curve:?} order must be odd");
            let mut below = order.to_vec();
            below[field - 1] -= 1;
            let mut raw = below.clone();
            raw.extend_from_slice(&below);
            assert!(validate_scalars(curve, &raw).is_ok(), "{curve:?}");
            let mut at_order = order.to_vec();
            at_order.extend_from_slice(&below);
            assert!(validate_scalars(curve, &at_order).is_err(), "{curve:?}");
            let mut zero = vec![0; field];
            zero.extend_from_slice(&below);
            assert!(validate_scalars(curve, &zero).is_err(), "{curve:?}");
        }
    }
}
