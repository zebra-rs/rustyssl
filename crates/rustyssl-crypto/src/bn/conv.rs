//! Conversions (`bn_lib.c`'s `bin2bn` and `bn2binpad`, `bn_conv.c`, `bn_print.c`, `bn_mpi.c`):
//! octet strings in either order, signed (two's complement) or not; hex and decimal text; and
//! MPIs.

use zeroize::Zeroizing;

use super::{BigNum, Error, LIMB_BITS, LIMB_BYTES, Limb, MAX_LIMBS, shl, shr, trimmed};

/// The order of an octet string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endian {
    /// Most significant octet first.
    Big,
    /// Least significant octet first.
    Little,
}

/// `BN_DEC_CONV`: ten to the `BN_DEC_NUM`, the most decimal digits a limb holds whole.
const DEC_CONV: Limb = 10_000_000_000_000_000_000;
/// `BN_DEC_NUM`.
const DEC_NUM: usize = 19;

impl BigNum {
    /// `bin2bn`: the number in `s`, unsigned or two's complement. Zero for no octets.
    pub fn from_bin(s: &[u8], endian: Endian, signed: bool) -> Result<Self, Error> {
        // Least significant first, from here on.
        let le: Zeroizing<Vec<u8>> = Zeroizing::new(match endian {
            Endian::Little => s.to_vec(),
            Endian::Big => s.iter().rev().copied().collect(),
        });
        let neg = signed && le.last().is_some_and(|b| b & 0x80 != 0);
        let xor: u8 = if neg { 0xff } else { 0 };
        // Leading sign extension goes, except a last 0xff that a negative number needs.
        let mut len = le.len();
        while len > 0 && le.get(len.wrapping_sub(1)) == Some(&xor) {
            len = len.wrapping_sub(1);
        }
        if neg && (len == 0 || le.get(len.wrapping_sub(1)).is_some_and(|b| b & 0x80 == 0)) {
            len = len.wrapping_add(1);
        }
        if len == 0 {
            return Ok(Self::zero());
        }
        if len.div_ceil(LIMB_BYTES) > MAX_LIMBS {
            return Err(Error::TooLong);
        }
        let mut limbs = Vec::with_capacity(len.div_ceil(LIMB_BYTES));
        let mut carry = u8::from(neg);
        for chunk in le.get(..len).unwrap_or(&[]).chunks(LIMB_BYTES) {
            let mut l: Limb = 0;
            for (k, &b) in chunk.iter().enumerate() {
                let x = b ^ xor;
                let byte = x.wrapping_add(carry);
                carry = u8::from(x > byte);
                l |= shl(Limb::from(byte), k.wrapping_mul(8));
            }
            limbs.push(l);
        }
        Self::from_limbs(neg, limbs)
    }

    /// `bn2binpad`: the number in `tolen` octets (or as few as it takes, for `None`), unsigned
    /// or two's complement; `None` if it doesn't fit.
    ///
    /// A signed number takes an extra octet when its top bit disagrees with its sign, as
    /// OpenSSL reckons it: a negative number whose magnitude fills its top octet gets none.
    pub fn to_bin(
        &self,
        tolen: Option<usize>,
        endian: Endian,
        signed: bool,
    ) -> Option<Zeroizing<Vec<u8>>> {
        let n8 = self.num_bits();
        let n = n8.div_ceil(8);
        let (xor, mut carry, ext) = if signed {
            let top_set = n.saturating_mul(8) == n8;
            let ext = if top_set { !self.neg } else { self.neg };
            (
                if self.neg { 0xffu8 } else { 0 },
                u8::from(self.neg),
                usize::from(ext),
            )
        } else {
            (0, 0, 0)
        };
        let need = n.saturating_add(ext);
        let tolen = match tolen {
            None => need,
            Some(t) if t < need => return None,
            Some(t) => t,
        };
        let mut out = Zeroizing::new(vec![0u8; tolen]);
        let limbs = self.limbs();
        for j in 0..tolen {
            let byte = limbs.get(j / LIMB_BYTES).map_or(0, |l| {
                l.to_le_bytes().get(j % LIMB_BYTES).copied().unwrap_or(0)
            });
            let x = byte ^ xor;
            let o = x.wrapping_add(carry);
            carry = u8::from(x > o);
            let at = match endian {
                Endian::Little => j,
                Endian::Big => tolen.wrapping_sub(1).wrapping_sub(j),
            };
            if let Some(slot) = out.get_mut(at) {
                *slot = o;
            }
        }
        Some(out)
    }

    /// `BN_bn2hex`'s text: `0`, or an optional `-` and the magnitude's octets in uppercase hex,
    /// without leading zero octets.
    pub fn to_hex(&self) -> String {
        if self.is_zero() {
            return "0".to_owned();
        }
        let mut s = String::with_capacity(self.num_bytes().saturating_mul(2).saturating_add(1));
        if self.neg {
            s.push('-');
        }
        let bytes = self.to_bin(None, Endian::Big, false).unwrap_or_default();
        for b in bytes.iter() {
            s.push_str(&format!("{b:02X}"));
        }
        s
    }

    /// `BN_print`'s text: an optional `-` and the magnitude in uppercase hex without leading
    /// zero digits, or `0`.
    pub fn to_hex_digits(&self) -> String {
        let mut s = String::new();
        if self.neg {
            s.push('-');
        }
        if self.is_zero() {
            s.push('0');
            return s;
        }
        let mut digits = false;
        for l in self.limbs().iter().rev() {
            for k in (0..16usize).rev() {
                let v = shr(*l, k.wrapping_mul(4)) & 0xf;
                if digits || v != 0 {
                    s.push(char::from(
                        b"0123456789ABCDEF"
                            .get(usize::try_from(v).unwrap_or(0))
                            .copied()
                            .unwrap_or(b'0'),
                    ));
                    digits = true;
                }
            }
        }
        s
    }

    /// `BN_bn2dec`'s text: an optional `-` and the decimal digits.
    pub fn to_dec(&self) -> String {
        if self.is_zero() {
            return "0".to_owned();
        }
        let mut t = self.abs();
        let mut chunks = Vec::new();
        while !t.is_zero() {
            chunks.push(t.div_word(DEC_CONV));
        }
        let mut s = String::new();
        if self.neg {
            s.push('-');
        }
        let mut rest = chunks.iter().rev();
        if let Some(first) = rest.next() {
            s.push_str(&first.to_string());
        }
        for c in rest {
            s.push_str(&format!("{c:019}"));
        }
        s
    }

    /// The value of `digits`, every one a hex digit (`BN_hex2bn` after its sign).
    pub fn from_hex_digits(digits: &[u8]) -> Result<Self, Error> {
        // `bn_expand(ret, i * 4)`.
        if digits.len().saturating_mul(4).div_ceil(LIMB_BITS) > MAX_LIMBS {
            return Err(Error::TooLong);
        }
        let mut limbs = Vec::with_capacity(digits.len().div_ceil(16));
        for chunk in digits.rchunks(16) {
            let l = chunk
                .iter()
                .fold(0, |l: Limb, &c| shl(l, 4) | Limb::from(hex_value(c)));
            limbs.push(l);
        }
        Self::from_limbs(false, trimmed(limbs))
    }

    /// The value of `digits`, every one a decimal digit (`BN_dec2bn` after its sign).
    pub fn from_dec_digits(digits: &[u8]) -> Result<Self, Error> {
        if digits.len().saturating_mul(4).div_ceil(LIMB_BITS) > MAX_LIMBS {
            return Err(Error::TooLong);
        }
        let mut n = Self::zero();
        let first = digits.len() % DEC_NUM;
        let (head, tail) = digits.split_at(first);
        for chunk in core::iter::once(head)
            .filter(|h| !h.is_empty())
            .chain(tail.chunks(DEC_NUM))
        {
            let l = chunk.iter().fold(0, |l: Limb, &c| {
                l.wrapping_mul(10)
                    .wrapping_add(Limb::from(c.wrapping_sub(b'0')))
            });
            n.mul_word(DEC_CONV)?;
            n.add_word(l)?;
        }
        Ok(n)
    }

    /// `BN_bn2mpi`: a four-octet big-endian length, then the magnitude with a sign bit (and a
    /// zero octet first if its top bit is taken).
    pub fn to_mpi(&self) -> Zeroizing<Vec<u8>> {
        let bits = self.num_bits();
        let num = bits.div_ceil(8);
        let ext = bits > 0 && bits.is_multiple_of(8);
        let l = num.saturating_add(usize::from(ext));
        let mut out = Zeroizing::new(Vec::with_capacity(l.saturating_add(4)));
        out.extend_from_slice(&u32::try_from(l).unwrap_or(u32::MAX).to_be_bytes());
        if ext {
            out.push(0);
        }
        out.extend_from_slice(&self.to_bin(None, Endian::Big, false).unwrap_or_default());
        if self.neg
            && let Some(b) = out.get_mut(4)
        {
            *b |= 0x80;
        }
        out
    }

    /// `BN_mpi2bn`: the number in an MPI of exactly `d`'s length.
    pub fn from_mpi(d: &[u8]) -> Result<Self, Error> {
        let Some((&[b0, b1, b2, b3], body)) = d.split_first_chunk::<4>() else {
            return Err(Error::InvalidLength);
        };
        if b0 & 0x80 != 0 {
            return Err(Error::InvalidLength);
        }
        let len = u32::from_be_bytes([b0, b1, b2, b3]);
        if usize::try_from(len).ok() != Some(body.len()) {
            return Err(Error::EncodingError);
        }
        if body.is_empty() {
            return Ok(Self::zero());
        }
        let neg = body.first().is_some_and(|b| b & 0x80 != 0);
        let mut n = Self::from_bin(body, Endian::Big, false)?;
        n.set_negative(neg);
        if neg {
            n.clear_bit(n.num_bits().saturating_sub(1));
        }
        Ok(n)
    }
}

/// A hex digit's value (`OPENSSL_hexchar2int`), 0 for anything else.
fn hex_value(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c.wrapping_sub(b'0'),
        b'a'..=b'f' => c.wrapping_sub(b'a').wrapping_add(10),
        b'A'..=b'F' => c.wrapping_sub(b'A').wrapping_add(10),
        _ => 0,
    }
}
