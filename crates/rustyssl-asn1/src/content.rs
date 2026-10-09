//! Content octets of the primitive types, decoded as OpenSSL's `c2i` functions decode them
//! (`c2i_ibuf`, `ossl_c2i_uint64_int`, `ossl_c2i_ASN1_BIT_STRING`), and the end-of-contents
//! octets.

/// Why INTEGER content octets were refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegerError {
    /// No content (`ASN1_R_ILLEGAL_ZERO_CONTENT`).
    ZeroContent,
    /// A pad octet that wasn't needed (`ASN1_R_ILLEGAL_PADDING`).
    IllegalPadding,
    /// More than 8 octets of magnitude for a native integer (`ASN1_R_TOO_LARGE`).
    TooLarge,
}

/// `c2i_ibuf`: an INTEGER's magnitude (big-endian, without the pad octet) and sign from its
/// content octets. A pad octet is allowed only where the sign needs it.
pub fn integer(content: &[u8]) -> Result<(Vec<u8>, bool), IntegerError> {
    let (&first, rest) = content.split_first().ok_or(IntegerError::ZeroContent)?;
    let negative = first & 0x80 != 0;
    let Some(&second) = rest.first() else {
        let magnitude = if negative {
            (first ^ 0xff).wrapping_add(1)
        } else {
            first
        };
        return Ok((vec![magnitude], negative));
    };
    // 0xff followed by zeros is the minimal negative of its length, not a pad.
    let pad = first == 0 || (first == 0xff && rest.iter().any(|&b| b != 0));
    if pad && negative == (second & 0x80 != 0) {
        return Err(IntegerError::IllegalPadding);
    }
    let body = if pad { rest } else { content };
    let magnitude = if negative {
        twos_complement(body)
    } else {
        body.to_vec()
    };
    Ok((magnitude, negative))
}

/// The two's complement of a big-endian number.
fn twos_complement(octets: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; octets.len()];
    let mut carry: u16 = 1;
    for (o, &b) in out.iter_mut().rev().zip(octets.iter().rev()) {
        carry = carry.wrapping_add(u16::from(b ^ 0xff));
        *o = carry.to_le_bytes()[0];
        carry >>= 8;
    }
    out
}

/// `ossl_c2i_uint64_int`: an INTEGER of at most 8 octets of magnitude, as its magnitude and
/// sign.
pub fn integer_u64(content: &[u8]) -> Result<(u64, bool), IntegerError> {
    let (magnitude, negative) = integer(content)?;
    if magnitude.len() > 8 {
        return Err(IntegerError::TooLarge);
    }
    let value = magnitude.iter().fold(0u64, |r, &b| (r << 8) | u64::from(b));
    Ok((value, negative))
}

/// Why BIT STRING content octets were refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitStringError {
    /// No unused-bits octet (`ASN1_R_STRING_TOO_SHORT`).
    TooShort,
    /// An unused-bits count above 7 (`ASN1_R_INVALID_BIT_STRING_BITS_LEFT`).
    BitsLeft,
}

/// `ossl_c2i_ASN1_BIT_STRING`: the unused-bits count and the octets, the unused bits of the
/// last cleared.
pub fn bit_string(content: &[u8]) -> Result<(u8, Vec<u8>), BitStringError> {
    let (&bits, rest) = content.split_first().ok_or(BitStringError::TooShort)?;
    if bits > 7 {
        return Err(BitStringError::BitsLeft);
    }
    let mut octets = rest.to_vec();
    if let Some(last) = octets.last_mut() {
        *last &= 0xff << bits;
    }
    Ok((bits, octets))
}

/// Whether `input` starts with end-of-contents octets (`asn1_check_eoc`).
pub fn is_eoc(input: &[u8]) -> bool {
    input.starts_with(&[0, 0])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers() {
        assert_eq!(integer(&[]), Err(IntegerError::ZeroContent));
        assert_eq!(integer(&[0x05]), Ok((vec![5], false)));
        assert_eq!(integer(&[0x80]), Ok((vec![0x80], true)));
        assert_eq!(integer(&[0xff]), Ok((vec![1], true)));
        assert_eq!(integer(&[0x00, 0x80]), Ok((vec![0x80], false)));
        assert_eq!(integer(&[0x00, 0x7f]), Err(IntegerError::IllegalPadding));
        assert_eq!(integer(&[0xff, 0x7f]), Ok((vec![0x81], true)));
        assert_eq!(integer(&[0xff, 0x80]), Err(IntegerError::IllegalPadding));
        assert_eq!(integer(&[0xff, 0x00]), Ok((vec![0x01, 0x00], true)));
        assert_eq!(integer(&[0xff, 0x7f, 0xff]), Ok((vec![0x80, 0x01], true)));
        assert_eq!(integer_u64(&[0x01, 0x00]), Ok((256, false)));
        assert_eq!(integer_u64(&[0x01; 9]), Err(IntegerError::TooLarge));
        assert_eq!(
            integer_u64(&[0x00, 0xff, 0, 0, 0, 0, 0, 0, 0]),
            Ok((0xff00_0000_0000_0000, false))
        );
    }

    #[test]
    fn bit_strings() {
        assert_eq!(bit_string(&[]), Err(BitStringError::TooShort));
        assert_eq!(bit_string(&[8]), Err(BitStringError::BitsLeft));
        assert_eq!(bit_string(&[0]), Ok((0, vec![])));
        assert_eq!(bit_string(&[3, 0xff, 0xff]), Ok((3, vec![0xff, 0xf8])));
        assert!(is_eoc(&[0, 0, 1]) && !is_eoc(&[0]) && !is_eoc(&[0, 1]));
    }
}
