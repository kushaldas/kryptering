#![forbid(unsafe_code)]

//! # ⚠ HAZMAT — Finite-field Diffie-Hellman (X9.42) ⚠
//!
//! Modular-exponentiation Diffie-Hellman, provided solely for legacy
//! interop (XML Encryption 1.0/1.1 DH-ES per W3C, RFC 2631 CMS). See
//! [`crate::hazmat`] for the top-level warning.
//!
//! For any new protocol, use ECDH ([`crate::keyagreement::ecdh_p256`] etc.
//! or [`crate::keyagreement::ecdh_x25519`]). Finite-field DH is slower,
//! larger, and has a rougher side-channel profile.
//!
//! ## Wire format
//!
//! All byte slices are **big-endian**. [`compute`] returns the shared
//! secret zero-padded on the left to `p.len()` bytes — this is required
//! by the DH-ES / ConcatKDF pipeline so that the derived KEK is
//! reproducible against test vectors.
//!
//! ## Constant-time caveats
//!
//! The modular exponentiation is performed via
//! [`crypto_bigint::modular::BoxedMontyForm::pow`], which uses a
//! Montgomery ladder with windowed lookups. This is **constant-time in
//! the bit pattern** of the exponent, but the **bit-length** of the
//! exponent is observable: the number of ladder iterations is
//! proportional to `exponent.bits_precision()`.
//!
//! We mitigate the bit-length leak by padding the private exponent to
//! `p.bits_precision()` before calling `pow`. Every DH operation against
//! the same modulus therefore runs for the same number of iterations
//! regardless of the caller's private-key magnitude.
//!
//! Heap allocation and windowed-table cache timing are **not** mitigated.
//! A remote network attacker without sub-microsecond timing precision
//! will not recover key material; a co-located attacker (shared SMT
//! core, shared L1 cache, hypervisor-level observation) may still extract
//! bits. If that threat model applies, do DH on a hardware HSM.
//!
//! ## Subgroup validation
//!
//! [`compute`] performs two checks on the peer's public key `y`:
//!
//! 1. `1 < y < p` — rejects the identity / trivial points.
//! 2. `y^q mod p == 1` — confirms `y` is in the subgroup of order `q`.
//!    Prevents small-subgroup attacks where an attacker supplies a `y`
//!    in a short-order subgroup to leak bits of the private key.
//!
//! `q` is therefore required (the API takes `Option<&[u8]>` for
//! signature stability with the previous keyagreement::dh_compute, but
//! `None` is rejected).

use crate::error::{Error, Result};
use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{BoxedUint, Choice, CtEq, CtGt, CtLt, Odd};
use zeroize::Zeroize;

/// Compute `shared = other_public ^ my_private mod p`.
///
/// All values are big-endian byte slices. The output is zero-padded
/// on the left to `p.len()` bytes. `q` (the subgroup order) is
/// required for subgroup validation; passing `None` returns an error.
pub fn compute(
    other_public: &[u8],
    my_private: &[u8],
    p: &[u8],
    q: Option<&[u8]>,
) -> Result<Vec<u8>> {
    // ---- Parse public parameters (all non-secret) ----

    // ---- Structural checks (fail fast, no crypto yet) ----

    if p.is_empty() {
        return Err(Error::Key("DH modulus p is empty".into()));
    }
    let q_bytes = q.ok_or_else(|| {
        Error::Key("DH subgroup order q is required for subgroup validation".into())
    })?;
    if my_private.len() > p.len() {
        return Err(Error::Key(
            "DH private exponent longer than modulus byte length".into(),
        ));
    }

    // Pick a common bit precision for every BoxedUint in this call. We
    // round up to the modulus byte length in bits; crypto-bigint will
    // further round up internally to a whole-limb boundary, so all our
    // operands land in the same limb count.
    let bits = (p.len() as u32) * 8;

    let p_uint = BoxedUint::from_be_slice(p, bits)
        .map_err(|e| Error::Key(format!("DH modulus parse: {e:?}")))?;
    let one = BoxedUint::one_with_precision(bits);

    // Reject even modulus up-front — Montgomery form requires it odd,
    // and all real DH primes are odd. This path also catches `p == 0`
    // and `p == 2` as edge cases.
    let p_odd = Option::<Odd<BoxedUint>>::from(Odd::new(p_uint.clone()))
        .ok_or_else(|| Error::Key("DH modulus p must be odd".into()))?;
    let params = BoxedMontyParams::new(p_odd);

    // ---- Peer public key range check: 1 < y < p ----

    let y_uint = BoxedUint::from_be_slice(other_public, bits).map_err(|e| {
        Error::Key(format!("DH peer public key parse: {e:?}"))
    })?;
    let y_gt_one: Choice = y_uint.ct_gt(&one);
    let y_lt_p: Choice = y_uint.ct_lt(&p_uint);
    if !bool::from(y_gt_one & y_lt_p) {
        return Err(Error::Key(
            "DH peer public key out of range (must be in 2..p-1)".into(),
        ));
    }

    // ---- Subgroup check: y^q mod p == 1 ----
    // q is public (it's a group parameter), so using ct_eq here is
    // strictly for API uniformity — the check itself leaks nothing
    // secret.
    let q_uint = BoxedUint::from_be_slice(q_bytes, bits)
        .map_err(|e| Error::Key(format!("DH subgroup order q parse: {e:?}")))?;
    let y_mont = BoxedMontyForm::new(y_uint, &params);
    let subgroup_check = y_mont.pow(&q_uint).retrieve();
    if !bool::from(subgroup_check.ct_eq(&one)) {
        return Err(Error::Key(
            "DH peer public key fails subgroup check (y^q mod p != 1)".into(),
        ));
    }

    // ---- Shared secret: y^x mod p ----
    // Pad x to `bits` precision so pow() iterates for a fixed count
    // regardless of the caller's leading-zero trimming. `my_private`
    // bytes shorter than p.len() are zero-extended by from_be_slice.
    let mut priv_uint = BoxedUint::from_be_slice(my_private, bits)
        .map_err(|e| Error::Key(format!("DH private exponent parse: {e:?}")))?;

    let shared_mont = y_mont.pow(&priv_uint);

    // Wipe the heap copy of the private exponent before returning.
    priv_uint.zeroize();

    let shared_uint = shared_mont.retrieve();

    // ---- Output: big-endian, left-padded to p.len() ----
    let raw = shared_uint.to_be_bytes();
    let out = left_pad_to(&raw, p.len());
    Ok(out)
}

/// Left-pad `input` with leading zero bytes until its length equals
/// `target_len`. Returns `input` unchanged if it is already long
/// enough; truncates leading zeros if longer (only possible when the
/// Montgomery form's limb rounding produced extra high bytes, all of
/// which must be zero because `shared < p`).
fn left_pad_to(input: &[u8], target_len: usize) -> Vec<u8> {
    if input.len() == target_len {
        return input.to_vec();
    }
    if input.len() < target_len {
        let mut out = vec![0u8; target_len - input.len()];
        out.extend_from_slice(input);
        return out;
    }
    // input longer than p.len(): trim leading bytes. These are
    // expected to be zero because shared < p.
    input[input.len() - target_len..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 5114 section 2.2 (id-dhpublicnumber group "2048-bit MODP
    // Group with 224-bit Prime Order Subgroup") — the group used by
    // bergshamra's test fixtures. Inlined in hex for test isolation.
    const RFC5114_GROUP2_P: &str = "\
AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75E6FA141D\
F95A56DBAF9A3C407BA1DF15EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC212\
9037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207C9F98D11ED34DBF6C6BA0B2C\
8BBC27BE6A00E0A0B9C49708B3BF8A317091883681286130BC8985DB1602E714415D9330\
278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486DCDF93ACC44328387315D75E1\
98C641A480CD86A1B9E587E8BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763\
C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71CF9DE5384E71B81C0AC4DFFE\
0C10E64F";
    const RFC5114_GROUP2_G: &str = "\
AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3A6824A4E\
10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7\
C17669101999024AF4D027275AC1348BB8A762D0521BC98AE247150422EA1ED409939D54\
DA7460CDB5F6C6B250717CBEF180EB34118E98D119529A45D6F834566E3025E316A330EF\
BB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB10E183EDD19963DDD9E263E4\
770589EF6AA21E7F5F2FF381B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269\
EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3\
191F2BFA";
    const RFC5114_GROUP2_Q: &str =
        "801C0D34C58D93FE997177101F80535A4738CEBCBF389A99B36371EB";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Small-prime sanity check: p = 23, q = 11 (safe prime with subgroup
    /// of order 11). Exercises the happy path end-to-end with trivial
    /// inputs so failures are easy to diagnose.
    #[test]
    fn small_prime_roundtrip() {
        // p = 23, q = 11. Generator g = 4 has order 11 in Z/23Z*.
        let p = &[23u8];
        let q = &[11u8];
        let g = 4u8;
        let p_uint = 23u32;

        let x_a = 5u8;
        let x_b = 7u8;
        // y_a = g^x_a mod p, y_b = g^x_b mod p (computed by hand)
        let y_a = modpow_u32(g as u32, x_a as u32, p_uint) as u8;
        let y_b = modpow_u32(g as u32, x_b as u32, p_uint) as u8;

        let shared_a = compute(&[y_b], &[x_a], p, Some(q)).unwrap();
        let shared_b = compute(&[y_a], &[x_b], p, Some(q)).unwrap();
        assert_eq!(shared_a, shared_b);
        assert_eq!(shared_a.len(), 1);
    }

    fn modpow_u32(base: u32, exp: u32, modulus: u32) -> u32 {
        let mut result = 1u64;
        let mut b = base as u64 % modulus as u64;
        let m = modulus as u64;
        let mut e = exp;
        while e > 0 {
            if e & 1 == 1 {
                result = (result * b) % m;
            }
            b = (b * b) % m;
            e >>= 1;
        }
        result as u32
    }

    /// RFC 5114 Group 2 (2048-bit / 224-bit q) round-trip. This is the
    /// production-size exercise: same moduli shape as bergshamra's
    /// RFC 5114 Group 3 fixtures, slightly different subgroup size.
    #[test]
    fn rfc5114_group2_roundtrip() {
        let p = hex(RFC5114_GROUP2_P);
        let g = hex(RFC5114_GROUP2_G);
        let q = hex(RFC5114_GROUP2_Q);

        // Pick two small private exponents. These are in [1, q-1]
        // trivially.
        let x_a = {
            let mut v = vec![0u8; q.len() - 1];
            v.push(0x11);
            v
        };
        let x_b = {
            let mut v = vec![0u8; q.len() - 1];
            v.push(0x23);
            v
        };

        // y = g^x mod p, computed via compute() by agreeing against g
        // (i.e. treating g as the "peer public" and x as "my private").
        // `compute` range-checks y against p, subgroup-checks y^q==1,
        // and (since g has order q in this group) both pass for y=g.
        let y_a = compute(&g, &x_a, &p, Some(&q)).unwrap();
        let y_b = compute(&g, &x_b, &p, Some(&q)).unwrap();
        assert_eq!(y_a.len(), p.len(), "y_a must be padded to len(p)");
        assert_eq!(y_b.len(), p.len(), "y_b must be padded to len(p)");

        // Alice: y_b ^ x_a mod p ; Bob: y_a ^ x_b mod p
        let shared_a = compute(&y_b, &x_a, &p, Some(&q)).unwrap();
        let shared_b = compute(&y_a, &x_b, &p, Some(&q)).unwrap();
        assert_eq!(shared_a, shared_b);
        assert_eq!(shared_a.len(), p.len());
    }

    #[test]
    fn rejects_y_zero() {
        let p = &[23u8];
        let q = &[11u8];
        let err = compute(&[0u8], &[5u8], p, Some(q)).unwrap_err();
        assert!(err.to_string().contains("out of range"), "{err}");
    }

    #[test]
    fn rejects_y_one() {
        let p = &[23u8];
        let q = &[11u8];
        let err = compute(&[1u8], &[5u8], p, Some(q)).unwrap_err();
        assert!(err.to_string().contains("out of range"), "{err}");
    }

    #[test]
    fn rejects_y_equal_p() {
        let p = &[23u8];
        let q = &[11u8];
        let err = compute(&[23u8], &[5u8], p, Some(q)).unwrap_err();
        assert!(err.to_string().contains("out of range"), "{err}");
    }

    #[test]
    fn rejects_missing_q() {
        let p = &[23u8];
        let err = compute(&[5u8], &[3u8], p, None).unwrap_err();
        assert!(
            err.to_string().contains("subgroup order q is required"),
            "{err}"
        );
    }

    #[test]
    fn rejects_bad_subgroup_point() {
        // In Z/23Z* with q=11, order-2 elements are {22}. 22^11 mod 23 = 22,
        // not 1, so the subgroup check fires.
        let p = &[23u8];
        let q = &[11u8];
        let err = compute(&[22u8], &[5u8], p, Some(q)).unwrap_err();
        assert!(err.to_string().contains("subgroup check"), "{err}");
    }

    #[test]
    fn rejects_even_modulus() {
        let p = &[22u8]; // even
        let q = &[11u8];
        let err = compute(&[5u8], &[3u8], p, Some(q)).unwrap_err();
        assert!(err.to_string().contains("must be odd"), "{err}");
    }

    #[test]
    fn rejects_private_longer_than_modulus() {
        let p = &[23u8];
        let q = &[11u8];
        let too_long = &[0u8, 3u8];
        let err = compute(&[5u8], too_long, p, Some(q)).unwrap_err();
        assert!(
            err.to_string()
                .contains("private exponent longer than modulus"),
            "{err}"
        );
    }

    #[test]
    fn output_is_left_padded_to_p_length() {
        // Construct a case where the shared secret happens to be small
        // (fits in fewer bytes than p). With p=23 and a chosen (y,x),
        // the output is still returned as a 1-byte vector. For a
        // multi-byte regression, exercise via the RFC 5114 test above
        // which asserts .len() == p.len().
        let p = &[23u8];
        let q = &[11u8];
        // y=4 (g=4 has order 11), x=1 -> shared = 4^1 mod 23 = 4
        let shared = compute(&[4u8], &[1u8], p, Some(q)).unwrap();
        assert_eq!(shared, vec![4u8]);
        assert_eq!(shared.len(), p.len());
    }
}
