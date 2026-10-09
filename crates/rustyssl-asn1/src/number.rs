//! INTEGER magnitudes as text and back, as OpenSSL converts them through BIGNUM in
//! `i2s_ASN1_INTEGER` (`bignum_to_string`: decimal below 128 bits, `0x` and uppercase hex from
//! there) and `s2i_ASN1_INTEGER` (an optional `-` and `0x`, then `BN_dec2bn` or `BN_hex2bn`, which
//! take a `-` of their own, and nothing after the digits). Magnitudes are big-endian octets;
//! leading zero octets don't count.

/// `magnitude` without its leading zero octets.
pub fn significant(magnitude: &[u8]) -> &[u8] {
    let start = magnitude
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(magnitude.len());
    magnitude.get(start..).unwrap_or(&[])
}

/// `BN_num_bits` of a magnitude.
pub fn num_bits(magnitude: &[u8]) -> usize {
    let m = significant(magnitude);
    match m.first() {
        None => 0,
        Some(&first) => {
            let top = usize::try_from(u8::BITS.wrapping_sub(first.leading_zeros())).unwrap_or(8);
            m.len()
                .saturating_sub(1)
                .saturating_mul(8)
                .saturating_add(top)
        }
    }
}

/// `bignum_to_string` of a magnitude and sign: decimal below 128 bits, `0x` and uppercase hex
/// (two digits an octet) from there, with `-` first for a negative non-zero value.
pub fn to_text(magnitude: &[u8], negative: bool) -> String {
    let m = significant(magnitude);
    let sign = if negative && !m.is_empty() { "-" } else { "" };
    if num_bits(m) < 128 {
        let value = m.iter().fold(0u128, |v, &b| (v << 8) | u128::from(b));
        format!("{sign}{value}")
    } else {
        let hex: String = m.iter().map(|b| format!("{b:02X}")).collect();
        format!("{sign}0x{hex}")
    }
}

/// `s2i_ASN1_INTEGER`'s parse: the magnitude (minimal, empty for zero), and whether the value
/// is negative. `None` for text `BN_dec2bn`/`BN_hex2bn` refuse or that has more after the
/// digits.
pub fn from_text(text: &[u8]) -> Option<(Vec<u8>, bool)> {
    let (outer_negative, rest) = match text.split_first() {
        Some((b'-', rest)) => (true, rest),
        _ => (false, text),
    };
    let (hex, rest) = match rest {
        [b'0', b'x' | b'X', rest @ ..] => (true, rest),
        _ => (false, rest),
    };
    // BN_dec2bn and BN_hex2bn take a sign of their own.
    let (inner_negative, digits) = match rest.split_first() {
        Some((b'-', digits)) => (true, digits),
        _ => (false, rest),
    };
    let count = digits
        .iter()
        .take_while(|b| {
            if hex {
                b.is_ascii_hexdigit()
            } else {
                b.is_ascii_digit()
            }
        })
        .count();
    if count == 0 || count != digits.len() {
        return None;
    }
    let magnitude = if hex {
        from_hex(digits)
    } else {
        from_decimal(digits)
    };
    let zero = magnitude.is_empty();
    Some((magnitude, !zero && (inner_negative || outer_negative)))
}

/// The magnitude of hex digits, minimal.
fn from_hex(digits: &[u8]) -> Vec<u8> {
    let nibble = |c: u8| match c {
        b'0'..=b'9' => c.wrapping_sub(b'0'),
        b'a'..=b'f' => c.wrapping_sub(b'a').wrapping_add(10),
        _ => c.wrapping_sub(b'A').wrapping_add(10),
    };
    let mut out = Vec::with_capacity(digits.len().div_ceil(2));
    let odd = digits.len() % 2 == 1;
    let (first, rest) = if odd {
        digits.split_at(1)
    } else {
        (&[][..], digits)
    };
    if let Some(&c) = first.first() {
        out.push(nibble(c));
    }
    for [hi, lo] in rest.as_chunks::<2>().0 {
        out.push((nibble(*hi) << 4) | nibble(*lo));
    }
    significant(&out).to_vec()
}

/// The magnitude of decimal digits, minimal.
fn from_decimal(digits: &[u8]) -> Vec<u8> {
    // Little-endian base-256 limbs, multiplied by 10 and added to per digit.
    let mut limbs: Vec<u8> = Vec::new();
    for &c in digits {
        let mut carry = u16::from(c.wrapping_sub(b'0'));
        for limb in &mut limbs {
            let v = u16::from(*limb).wrapping_mul(10).wrapping_add(carry);
            *limb = v.to_le_bytes()[0];
            carry = v >> 8;
        }
        if carry != 0 {
            limbs.push(carry.to_le_bytes()[0]);
        }
    }
    limbs.reverse();
    significant(&limbs).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text() {
        assert_eq!(to_text(&[], true), "0");
        assert_eq!(to_text(&[0, 0, 5], true), "-5");
        assert_eq!(
            to_text(&[0xff; 15], false),
            "1329227995784915872903807060280344575"
        );
        assert_eq!(
            to_text(&[0x7f; 16], false),
            "169473963133173273960190490760135540607"
        );
        assert_eq!(
            to_text(
                &[0x80].iter().chain(&[0; 15]).copied().collect::<Vec<_>>(),
                true
            ),
            "-0x80000000000000000000000000000000"
        );
        assert_eq!(num_bits(&[0, 1, 0]), 9);
    }

    #[test]
    fn parsing() {
        assert_eq!(from_text(b"0"), Some((vec![], false)));
        assert_eq!(from_text(b"-0"), Some((vec![], false)));
        assert_eq!(from_text(b"256"), Some((vec![1, 0], false)));
        assert_eq!(from_text(b"-0x1F"), Some((vec![0x1f], true)));
        assert_eq!(from_text(b"--5"), Some((vec![5], true)));
        assert_eq!(from_text(b"0x-5"), Some((vec![5], true)));
        assert_eq!(from_text(b"0xabc"), Some((vec![0x0a, 0xbc], false)));
        assert_eq!(from_text(b"12a"), None);
        assert_eq!(from_text(b""), None);
        assert_eq!(from_text(b"-"), None);
        assert_eq!(from_text(b"0x"), None);
        assert_eq!(
            from_text(b"340282366920938463463374607431768211456"),
            Some((vec![1].into_iter().chain([0; 16]).collect(), false))
        );
    }
}
