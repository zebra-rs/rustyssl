//! SM2's signature arithmetic (GB/T 32918.2; `sm2_sign.c`).
//!
//! - [`z_preimage`]: what the Z value hashes, `ENTL || ID || a || b || xG || yG || xA || yA`,
//!   each field element padded to the field's octets.
//! - [`sign_s`]: `s = (1 + d)^-1 (k - r d) mod n` on constant-time field elements of the
//!   order's length ([`super::fe`]), so neither the private key nor the nonce shows in the time
//!   taken.

use super::fe::Fp;
use crate::bn::{BigNum, Endian};

/// Why the Z value's input couldn't be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZError {
    /// The ID's length in bits doesn't fit ENTL's 16 bits (`SM2_R_ID_TOO_LARGE`).
    IdTooLarge,
    /// A value is longer than the field (`ERR_R_INTERNAL_ERROR`).
    TooLong,
}

/// `ENTL || ID || a || b || xG || yG || xA || yA`: the ID's length in bits (two octets), the
/// ID, then the curve's coefficients, the generator, and the public key, each in `p_bytes`.
pub fn z_preimage(id: &[u8], p_bytes: usize, values: [&BigNum; 6]) -> Result<Vec<u8>, ZError> {
    // OpenSSL refuses an ID of UINT16_MAX / 8 octets or more.
    if id.len() >= usize::from(u16::MAX / 8) {
        return Err(ZError::IdTooLarge);
    }
    let entl = u16::try_from(id.len().saturating_mul(8)).map_err(|_| ZError::IdTooLarge)?;
    let mut out = Vec::with_capacity(id.len().saturating_add(p_bytes.saturating_mul(6)));
    out.extend_from_slice(&entl.to_be_bytes());
    out.extend_from_slice(id);
    for v in values {
        let b = v
            .to_bin(Some(p_bytes), Endian::Big, false)
            .ok_or(ZError::TooLong)?;
        out.extend_from_slice(&b);
    }
    Ok(out)
}

/// Why `s` couldn't be computed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignError {
    /// The Montgomery arithmetic refused its operands (`ERR_R_BN_LIB`).
    Bn,
    /// `1 + d` is a multiple of the order, so it has no inverse and every `s` would be zero.
    PrivateKey,
    /// `s` came out zero.
    ZeroS,
}

/// `s = (1 + d)^-1 (k - r d) mod n`, with OpenSSL's limits on its Montgomery operands (each of
/// at most the order's limbs).
pub fn sign_s(order: &BigNum, d: &BigNum, k: &BigNum, r: &BigNum) -> Result<BigNum, SignError> {
    crate::dit::with(|| sign_s_dit(order, d, k, r))
}

/// [`sign_s`]'s work.
fn sign_s_dit(order: &BigNum, d: &BigNum, k: &BigNum, r: &BigNum) -> Result<BigNum, SignError> {
    let f = Fp::new(order).ok_or(SignError::Bn)?;
    let de = f.from_bn_unreduced(d).ok_or(SignError::Bn)?;
    let ke = f.from_bn_unreduced(k).ok_or(SignError::Bn)?;
    let re = f.from_bn_unreduced(r).ok_or(SignError::Bn)?;
    let one_d = f.add(&f.one(), &de);
    // A property of the key, not of a secret it hides: d = n - 1 can't sign.
    if f.is_zero(&one_d) {
        return Err(SignError::PrivateKey);
    }
    let t = f.sub(&ke, &f.mul(&re, &de));
    let s = f.mul(&f.inv(&one_d), &t);
    if f.is_zero(&s) {
        return Err(SignError::ZeroS);
    }
    Ok(f.to_bn(&s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn;

    fn num(h: &str) -> BigNum {
        BigNum::from_hex_digits(h.as_bytes()).unwrap_or_default()
    }

    const N: &str = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123";

    #[test]
    fn s_agrees_with_bignum() {
        let n = num(N);
        let (d, k, r) = (
            num("3945208F7B2144B1"),
            num("ABCDEF0123"),
            num("FEDCBA987654"),
        );
        let s = sign_s(&n, &d, &k, &r).unwrap_or_default();
        // s (1 + d) = k - r d (mod n)
        let one_d = bn::add(&d, &BigNum::one()).unwrap_or_default();
        let lhs = bn::nnmod(&bn::mul(&s, &one_d).unwrap_or_default(), &n).unwrap_or_default();
        let rd = bn::mul(&r, &d).unwrap_or_default();
        let rhs = bn::nnmod(&bn::sub(&k, &rd).unwrap_or_default(), &n).unwrap_or_default();
        assert!(bn::cmp(&lhs, &rhs).is_eq());
        // d = n - 1 has no (1 + d)^-1.
        let mut nm1 = n.clone();
        assert!(nm1.sub_word(1).is_ok());
        assert_eq!(sign_s(&n, &nm1, &k, &r), Err(SignError::PrivateKey));
        // k = r d gives s = 0.
        let k0 = bn::nnmod(&rd, &n).unwrap_or_default();
        assert_eq!(sign_s(&n, &d, &k0, &r), Err(SignError::ZeroS));
    }

    #[test]
    fn z_preimage_is_entl_id_and_padded_values() {
        let v = num("01");
        let z = z_preimage(b"AB", 4, [&v, &v, &v, &v, &v, &v]).unwrap_or_default();
        assert_eq!(&z[..4], &[0x00, 0x10, b'A', b'B']);
        assert_eq!(z.len(), 4 + 6 * 4);
        assert_eq!(&z[4..8], &[0, 0, 0, 1]);
        assert_eq!(z_preimage(&[0; 8191], 4, [&v; 6]), Err(ZError::IdTooLarge));
        assert!(z_preimage(&[0; 8190], 4, [&v; 6]).is_ok());
        let big = num("0102030405");
        assert_eq!(
            z_preimage(b"", 4, [&big, &v, &v, &v, &v, &v]),
            Err(ZError::TooLong)
        );
    }
}
