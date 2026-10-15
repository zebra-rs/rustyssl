//! ECDSA's arithmetic and its signature encoding (`ecdsa_ossl.c`, `asn1_dsa.c`).
//!
//! - [`digest_to_int`]: a digest as the number signed, cut to the order's length as OpenSSL
//!   cuts it (whole octets, then bits).
//! - [`sign_s`] and [`inverse_mod_order`]: `s = k^-1 (m + r d) mod n` and `k^-1 mod n`, on
//!   constant-time field elements of the order's length ([`super::fe`]), so neither the
//!   private key nor the nonce shows in the time taken. They fail where OpenSSL's Montgomery
//!   arithmetic fails: an operand longer (in limbs) than the order, or an even order.
//! - [`encode_sig`] and [`decode_sig`]: `SEQUENCE { r INTEGER, s INTEGER }` exactly as
//!   OpenSSL's own DER code writes and reads it: non-negative minimal INTEGERs, lengths in
//!   one, two, or three octets (not necessarily minimal), nothing after the second INTEGER.
//! - [`Rfc6979`]: RFC 6979's deterministic nonces (`deterministic_nonce.c`): the HMAC-DRBG's
//!   seed (the private key and the digest, each the order's length) and each candidate's
//!   number, accepted as OpenSSL accepts it (above 1 and below the order). The DRBG itself is
//!   the caller's (OpenSSL's HMAC-DRBG-KDF).

use zeroize::Zeroizing;

use super::fe::Fp;
use crate::bn::{self, BigNum, Endian};

/// Why a signature couldn't be computed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignError {
    /// The Montgomery arithmetic refused its operands (`ERR_R_BN_LIB`).
    Bn,
    /// `s` came out zero.
    ZeroS,
}

/// The digest as a number of at most the order's bits: whole octets cut first, then the
/// excess bits shifted out.
pub fn digest_to_int(dgst: &[u8], order_bits: usize) -> BigNum {
    let max_octets = order_bits.div_ceil(8);
    let cut = dgst.get(..max_octets).unwrap_or(dgst);
    let m = BigNum::from_bin(cut, Endian::Big, false).unwrap_or_default();
    if cut.len().saturating_mul(8) > order_bits {
        bn::rshift(&m, 8usize.saturating_sub(order_bits % 8))
    } else {
        m
    }
}

/// The HMAC-DRBG's entropy and nonce input, each the order's length in octets.
pub type Seed = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

/// RFC 6979's nonce derivation for one order (section 3.2).
pub struct Rfc6979 {
    order: BigNum,
    /// `qlen`: the order's bits.
    qlen: usize,
    /// `rlen`: the order's octets.
    rlen: usize,
}

impl Rfc6979 {
    /// The derivation for `order`, or `None` for a zero order.
    pub fn new(order: &BigNum) -> Option<Self> {
        let qlen = order.num_bits();
        (qlen != 0).then(|| Self {
            order: order.abs(),
            qlen,
            rlen: qlen.div_ceil(8),
        })
    }

    /// The octets each candidate takes (`rlen`).
    pub fn candidate_len(&self) -> usize {
        self.rlen
    }

    /// The HMAC-DRBG's entropy and nonce: `int2octets(x)` and `bits2octets(h1)` (2.3.3, 2.3.4),
    /// or `None` if the private key is longer than the order.
    pub fn seed(&self, x: &BigNum, h1: &[u8]) -> Option<Seed> {
        let entropy = x.to_bin(Some(self.rlen), Endian::Big, false)?;
        // bits2int, then reduced once (it's below 2^qlen, so below twice the order).
        let mut z = self.bits2int(h1);
        if bn::cmp(&z, &self.order).is_ge() {
            z = bn::usub(&z, &self.order).ok()?;
        }
        let nonce = z.to_bin(Some(self.rlen), Endian::Big, false)?;
        Some((entropy, nonce))
    }

    /// `bits2int` (2.3.2): the octets as a number, shifted right to at most `qlen` bits.
    fn bits2int(&self, b: &[u8]) -> BigNum {
        let v = BigNum::from_bin(b, Endian::Big, false).unwrap_or_default();
        let blen = b.len().saturating_mul(8);
        if blen > self.qlen {
            bn::rshift(&v, blen.saturating_sub(self.qlen))
        } else {
            v
        }
    }

    /// A candidate's nonce: its `rlen` octets as a number, if it's above 1 and below the order
    /// (otherwise the DRBG goes on to the next).
    pub fn candidate(&self, t: &[u8]) -> Option<BigNum> {
        let k = self.bits2int(t);
        (!k.is_zero() && !k.is_one() && bn::ucmp(&k, &self.order).is_lt()).then_some(k)
    }
}

/// The order's field, if its arithmetic works (an odd order above 2).
fn order_field(order: &BigNum) -> Option<Fp> {
    Fp::new(order)
}

/// `k^-1 mod n` by Fermat's little theorem in constant time (`ec_field_inverse_mod_ord`), for
/// `k` of at most the order's limbs.
pub fn inverse_mod_order(order: &BigNum, k: &BigNum) -> Option<BigNum> {
    let f = order_field(order)?;
    let x = f.from_bn_unreduced(k)?;
    Some(f.to_bn(&f.inv(&x)))
}

/// `s = kinv (m + r d) mod n`, with OpenSSL's limits on its Montgomery operands: `r`, `d`, and
/// `kinv` each of at most the order's limbs.
pub fn sign_s(
    order: &BigNum,
    d: &BigNum,
    m: &BigNum,
    kinv: &BigNum,
    r: &BigNum,
) -> Result<BigNum, SignError> {
    let f = order_field(order).ok_or(SignError::Bn)?;
    let get = |v: &BigNum| f.from_bn_unreduced(&v.abs()).ok_or(SignError::Bn);
    let (fd, fr, fk) = (get(d)?, get(r)?, get(kinv)?);
    // The digest has at most the order's bits, so it's below 2n.
    let fm = get(m)?;
    let s = f.mul(&fk, &f.add(&f.mul(&fr, &fd), &fm));
    if f.is_zero(&s) {
        return Err(SignError::ZeroS);
    }
    Ok(f.to_bn(&s))
}

/// `ossl_encode_der_length`.
fn push_length(out: &mut Vec<u8>, len: usize) -> Option<()> {
    let [_, _, _, _, _, _, hi, lo] = u64::try_from(len).ok()?.to_be_bytes();
    if len > 0xffff {
        return None;
    }
    if len > 0xff {
        out.extend_from_slice(&[0x82, hi, lo]);
    } else {
        if len > 0x7f {
            out.push(0x81);
        }
        out.push(lo);
    }
    Some(())
}

/// `ossl_encode_der_integer`'s content: the number in `bits / 8 + 1` octets.
fn integer_content(n: &BigNum) -> Option<Vec<u8>> {
    if n.is_negative() {
        return None;
    }
    let len = (n.num_bits() / 8).saturating_add(1);
    n.to_bin(Some(len), Endian::Big, false).map(|z| z.to_vec())
}

/// `ossl_encode_der_dsa_sig`: the DER of `SEQUENCE { r, s }`, or `None` for a negative number
/// or a length over 65535.
pub fn encode_sig(r: &BigNum, s: &BigNum) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    for n in [r, s] {
        let c = integer_content(n)?;
        body.push(0x02);
        push_length(&mut body, c.len())?;
        body.extend_from_slice(&c);
    }
    let mut out = vec![0x30];
    push_length(&mut out, body.len())?;
    out.extend_from_slice(&body);
    Some(out)
}

/// What [`decode_sig`] read: both numbers and the octets consumed on success; on failure, `r`
/// if it was read before the failure (OpenSSL has stored it by then).
#[derive(Debug, PartialEq, Eq)]
pub enum Decoded {
    Sig {
        r: BigNum,
        s: BigNum,
        consumed: usize,
    },
    Failed {
        r: Option<BigNum>,
    },
}

/// `ossl_decode_der_length`: the contents and what follows them.
fn read_length(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&first, rest) = input.split_first()?;
    let (len, rest) = match first {
        0..=0x7f => (usize::from(first), rest),
        0x81 => {
            let (&l, rest) = rest.split_first()?;
            (usize::from(l), rest)
        }
        0x82 => {
            let (l, rest) = rest.split_at_checked(2)?;
            let [a, b] = <[u8; 2]>::try_from(l).ok()?;
            (usize::from(u16::from_be_bytes([a, b])), rest)
        }
        _ => return None,
    };
    rest.split_at_checked(len)
}

/// `ossl_decode_der_integer`: a non-negative minimal INTEGER, and what follows it.
fn read_integer(input: &[u8]) -> Option<(BigNum, &[u8])> {
    let (&tag, rest) = input.split_first()?;
    if tag != 0x02 {
        return None;
    }
    let (content, rest) = read_length(rest)?;
    let (&first, after) = content.split_first()?;
    if first & 0x80 != 0 {
        return None;
    }
    if first == 0 && after.first().is_some_and(|&b| b & 0x80 == 0) {
        return None;
    }
    Some((BigNum::from_bin(content, Endian::Big, false).ok()?, rest))
}

/// `ossl_decode_der_dsa_sig`.
pub fn decode_sig(input: &[u8]) -> Decoded {
    let fail = |r| Decoded::Failed { r };
    let Some((&tag, rest)) = input.split_first() else {
        return fail(None);
    };
    if tag != 0x30 {
        return fail(None);
    }
    let Some((content, after)) = read_length(rest) else {
        return fail(None);
    };
    let Some((r, rest)) = read_integer(content) else {
        return fail(None);
    };
    let Some((s, rest)) = read_integer(rest) else {
        return fail(Some(r));
    };
    if !rest.is_empty() {
        return fail(Some(r));
    }
    Decoded::Sig {
        r,
        s,
        consumed: input.len().saturating_sub(after.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn num(h: &str) -> BigNum {
        BigNum::from_hex_digits(h.as_bytes()).unwrap_or_default()
    }

    #[test]
    fn signatures_encode_and_decode() {
        let (r, s) = (num("80"), num("02"));
        let der = encode_sig(&r, &s).unwrap_or_default();
        assert_eq!(der, [0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x02]);
        let mut with_more = der.clone();
        with_more.push(0);
        match decode_sig(&with_more) {
            Decoded::Sig {
                r: dr,
                s: ds,
                consumed,
            } => {
                assert!(bn::cmp(&dr, &r).is_eq() && bn::cmp(&ds, &s).is_eq());
                assert_eq!(consumed, der.len());
            }
            Decoded::Failed { .. } => panic!("decodes"),
        }
        // A negative s fails after r was read.
        let bad = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0xff];
        assert_eq!(decode_sig(&bad), Decoded::Failed { r: Some(num("01")) });
        let mut neg = num("1");
        neg.set_negative(true);
        assert!(encode_sig(&neg, &s).is_none());
    }

    #[test]
    fn s_agrees_with_bignum() {
        let n = num("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
        let (d, m, k, r) = (
            num("C0FFEE"),
            num("123456789"),
            num("ABCDEF"),
            num("FEDCBA"),
        );
        let kinv = inverse_mod_order(&n, &k).unwrap_or_default();
        let one = bn::nnmod(&bn::mul(&kinv, &k).unwrap_or_default(), &n).unwrap_or_default();
        assert!(one.is_one());
        let s = sign_s(&n, &d, &m, &kinv, &r).unwrap_or_default();
        let rd = bn::add(&bn::mul(&r, &d).unwrap_or_default(), &m).unwrap_or_default();
        let want = bn::nnmod(&bn::mul(&rd, &kinv).unwrap_or_default(), &n).unwrap_or_default();
        assert!(bn::cmp(&s, &want).is_eq());
        // An operand longer than the order is refused, as OpenSSL refuses it.
        let long = num("1000000000000000000000000000000000000000000000000000000000000000000");
        assert_eq!(sign_s(&n, &long, &m, &kinv, &r), Err(SignError::Bn));
    }

    /// RFC 6979's A.2.5: P-256, SHA-256, "sample".
    #[test]
    fn rfc6979_gives_the_rfc_nonce() {
        use crate::rand::{Drbg, HmacDrbg};
        let q = num("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
        let x = num("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
        // SHA-256("sample").
        let h1 = num("AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF")
            .to_bin(None, Endian::Big, false)
            .unwrap_or_default();
        let r = Rfc6979::new(&q).unwrap_or_else(|| panic!("an order"));
        let (entropy, nonce) = r.seed(&x, &h1).unwrap_or_else(|| panic!("a seed"));
        let mut drbg = HmacDrbg::new(crate::md::Algorithm::Sha256).unwrap_or_else(|_| panic!());
        drbg.instantiate(&entropy, &nonce, &[]);
        let mut t = vec![0u8; r.candidate_len()];
        let k = loop {
            drbg.generate(&mut t, &[])
                .unwrap_or_else(|_| panic!("generates"));
            if let Some(k) = r.candidate(&t) {
                break k;
            }
        };
        let want = num("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60");
        assert!(bn::cmp(&k, &want).is_eq());
        // 0, 1, and the order itself are refused; a longer digest is cut to qlen bits.
        assert!(r.candidate(&[0; 32]).is_none() && r.candidate(&[0xff; 32]).is_none());
        let mut one = [0u8; 32];
        one[31] = 1;
        assert!(r.candidate(&one).is_none());
        assert!(r.seed(&x, &[0xff; 64]).is_some());
        assert!(
            r.seed(&q, &[]).is_some()
                && r.seed(&bn::lshift(&q, 8).unwrap_or_default(), &[])
                    .is_none()
        );
        assert!(Rfc6979::new(&BigNum::zero()).is_none());
    }

    #[test]
    fn digests_are_cut_to_the_order() {
        assert!(bn::cmp(&digest_to_int(&[0xff, 0xee, 0xdd], 12), &num("FFE")).is_eq());
        assert!(bn::cmp(&digest_to_int(&[0x12, 0x34], 16), &num("1234")).is_eq());
        assert!(digest_to_int(&[], 256).is_zero());
    }
}
