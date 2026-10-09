//! OBJECT IDENTIFIER content octets and their dotted text, as OpenSSL converts them
//! (`a2d_ASN1_OBJECT`, `OBJ_obj2txt`), arcs of any size included.
//!
//! The parsing follows OpenSSL's step for step, since its leniencies are observable: arcs may
//! be separated by spaces as well as dots, an empty arc is 0 (`1.2..3` is 1.2.0.3), a trailing
//! separator is ignored, and text that ends before any arc after the first number is no OID
//! (empty, without an error). Each arc's value is exact however long; the work is quadratic in
//! an arc's length, as OpenSSL's is.

use core::fmt::Write as _;

/// Why text isn't an OID, as `a2d_ASN1_OBJECT` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextError {
    /// The first number isn't 0, 1, or 2.
    FirstNumTooLarge,
    /// The text ends after the first number.
    MissingSecondNumber,
    /// Something other than `.` or a space follows a number.
    InvalidSeparator,
    /// A character in an arc isn't a digit.
    InvalidDigit,
    /// The second number is 40 or more under a first of 0 or 1.
    SecondNumberTooLarge,
    /// The content octets don't fit the output.
    BufferTooSmall,
}

/// Content octets from dotted text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encoded {
    /// The octets of every arc encoded before the end or the error.
    pub octets: Vec<u8>,
    /// Why the text isn't an OID, if it isn't.
    pub error: Option<TextError>,
}

/// Encodes dotted `text` (all of it: `a2d_ASN1_OBJECT`'s `num` bytes, which aren't 0; empty
/// text is a NUL-terminated string that was empty) into content octets.
/// With a `capacity`, an arc that wouldn't fit fails with [`TextError::BufferTooSmall`],
/// leaving the arcs before it in `octets`.
pub fn encode_text(text: &[u8], capacity: Option<usize>) -> Encoded {
    let mut octets = Vec::new();
    let error = encode_into(text, capacity, &mut octets).err();
    Encoded { octets, error }
}

fn encode_into(text: &[u8], capacity: Option<usize>, out: &mut Vec<u8>) -> Result<(), TextError> {
    let mut bytes = text.iter().copied();
    // Empty text is a NUL-terminated string's: OpenSSL reads the NUL as the first number.
    let c = bytes.next().unwrap_or(0);
    if !(b'0'..=b'2').contains(&c) {
        return Err(TextError::FirstNumTooLarge);
    }
    let first = u64::from(c.wrapping_sub(b'0'));
    let Some(mut c) = bytes.next() else {
        return Err(TextError::MissingSecondNumber);
    };
    let mut bytes = bytes.peekable();
    loop {
        if bytes.peek().is_none() {
            return Ok(());
        }
        if c != b'.' && c != b' ' {
            return Err(TextError::InvalidSeparator);
        }
        let mut value = Natural::default();
        let mut chunk = 0u64;
        let mut scale = 1u64;
        for next in bytes.by_ref() {
            c = next;
            if c == b' ' || c == b'.' {
                break;
            }
            if !c.is_ascii_digit() {
                return Err(TextError::InvalidDigit);
            }
            chunk = chunk
                .wrapping_mul(10)
                .wrapping_add(u64::from(c.wrapping_sub(b'0')));
            scale = scale.wrapping_mul(10);
            if scale == CHUNK {
                value.mul_add(scale, chunk);
                (chunk, scale) = (0, 1);
            }
        }
        value.mul_add(scale, chunk);
        if out.is_empty() {
            if first < 2 && !value.is_less_than(40) {
                return Err(TextError::SecondNumberTooLarge);
            }
            value.mul_add(1, first.wrapping_mul(40));
        }
        let arc = value.to_base128();
        if let Some(capacity) = capacity
            && out
                .len()
                .checked_add(arc.len())
                .is_none_or(|end| end > capacity)
        {
            return Err(TextError::BufferTooSmall);
        }
        out.extend(arc);
    }
}

/// The longest content `OBJ_obj2txt` converts: RFC 2578's 128 arcs of at most 32 bits.
pub const MAX_TEXT_CONTENT: usize = 586;

/// Dotted text from content octets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    /// The text of every arc decoded before the end or the error.
    pub text: Vec<u8>,
    /// Whether the content was decoded to its end.
    pub complete: bool,
}

/// Decodes content octets into dotted text, as `OBJ_obj2txt` does for an unnamed OID: the
/// first number is 0, 1, or 2 (2 for a first subidentifier of 80 or more), and content longer
/// than [`MAX_TEXT_CONTENT`] or ending inside a subidentifier fails.
pub fn decode_text(content: &[u8]) -> Decoded {
    let mut text = Vec::new();
    if content.len() > MAX_TEXT_CONTENT {
        return Decoded {
            text,
            complete: false,
        };
    }
    let mut bytes = content.iter().copied().peekable();
    let mut first = true;
    while bytes.peek().is_some() {
        let mut value = Natural::default();
        loop {
            let Some(c) = bytes.next() else {
                return Decoded {
                    text,
                    complete: false,
                };
            };
            value.mul_add(128, u64::from(c & 0x7f));
            if c & 0x80 == 0 {
                break;
            }
        }
        if first {
            first = false;
            let leading: u8 = if value.is_less_than(40) {
                0
            } else if value.is_less_than(80) {
                1
            } else {
                2
            };
            value.sub_small(leading.wrapping_mul(40));
            text.push(b'0'.wrapping_add(leading));
        }
        text.push(b'.');
        text.extend(value.to_decimal().bytes());
    }
    Decoded {
        text,
        complete: true,
    }
}

/// Whether `content` is a valid OID encoding, as `c2i_ASN1_OBJECT` checks it: at least one
/// octet, the last ending a subidentifier, and no subidentifier starting with 0x80.
pub fn is_valid_content(content: &[u8]) -> bool {
    let mut previous = 0u8;
    for &c in content {
        if c == 0x80 && previous & 0x80 == 0 {
            return false;
        }
        previous = c;
    }
    !content.is_empty() && previous & 0x80 == 0
}

/// Ten to the number of decimal digits folded into one multiplication.
const CHUNK: u64 = 10_000_000_000_000_000_000;

/// A natural number of any size: little-endian 64-bit limbs, without high zero limbs.
#[derive(Debug, Default, Clone)]
struct Natural(Vec<u64>);

impl Natural {
    /// `self = self * multiplier + addend`.
    fn mul_add(&mut self, multiplier: u64, addend: u64) {
        let mut carry = u128::from(addend);
        for limb in &mut self.0 {
            let product = u128::from(*limb)
                .wrapping_mul(u128::from(multiplier))
                .wrapping_add(carry);
            *limb = low(product);
            carry = product >> 64;
        }
        if carry != 0 {
            self.0.push(low(carry));
        }
        self.normalize();
    }

    /// `self -= small`, for `small` at most `self`.
    fn sub_small(&mut self, small: u8) {
        let mut borrow = u64::from(small);
        for limb in &mut self.0 {
            let (difference, under) = limb.overflowing_sub(borrow);
            *limb = difference;
            borrow = u64::from(under);
            if borrow == 0 {
                break;
            }
        }
        self.normalize();
    }

    fn is_less_than(&self, small: u64) -> bool {
        match self.0.as_slice() {
            [] => small > 0,
            [only] => *only < small,
            _ => false,
        }
    }

    /// Divides by `divisor` (not 0), returning the remainder.
    fn div_small(&mut self, divisor: u64) -> u64 {
        let mut remainder = 0u128;
        for limb in self.0.iter_mut().rev() {
            let dividend = (remainder << 64) | u128::from(*limb);
            *limb = low(dividend.checked_div(u128::from(divisor)).unwrap_or(0));
            remainder = dividend.checked_rem(u128::from(divisor)).unwrap_or(0);
        }
        self.normalize();
        low(remainder)
    }

    /// The base-128 encoding of a subidentifier: high groups first, all but the last with the
    /// continuation bit.
    fn to_base128(&self) -> Vec<u8> {
        let mut rest = self.clone();
        let mut groups = vec![low_byte(rest.div_small(128))];
        while !rest.0.is_empty() {
            groups.push(low_byte(rest.div_small(128)) | 0x80);
        }
        groups.reverse();
        groups
    }

    fn to_decimal(&self) -> String {
        let mut rest = self.clone();
        let mut chunks = vec![rest.div_small(CHUNK)];
        while !rest.0.is_empty() {
            chunks.push(rest.div_small(CHUNK));
        }
        let mut text = String::new();
        let mut chunks = chunks.iter().rev();
        if let Some(top) = chunks.next() {
            let _ = write!(text, "{top}");
        }
        for chunk in chunks {
            let _ = write!(text, "{chunk:019}");
        }
        text
    }

    fn normalize(&mut self) {
        while self.0.last() == Some(&0) {
            self.0.pop();
        }
    }
}

/// The low 64 bits.
fn low(value: u128) -> u64 {
    u64::try_from(value & u128::from(u64::MAX)).unwrap_or(0)
}

/// The low 7 bits, as a byte.
fn low_byte(value: u64) -> u8 {
    u8::try_from(value & 0x7f).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(text: &str) -> Encoded {
        encode_text(text.as_bytes(), None)
    }

    fn ok(octets: &[u8]) -> Encoded {
        Encoded {
            octets: octets.to_vec(),
            error: None,
        }
    }

    #[test]
    fn encodes_dotted_text() {
        assert_eq!(
            encode("1.2.840.113549"),
            ok(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d])
        );
        assert_eq!(encode("2.5.4.3"), ok(&[0x55, 0x04, 0x03]));
        assert_eq!(encode("2.999"), ok(&[0x88, 0x37]));
        assert_eq!(encode("0.0"), ok(&[0x00]));
        // Spaces separate too; empty arcs are 0; a trailing separator is dropped.
        assert_eq!(encode("1 2 3"), ok(&[0x2a, 0x03]));
        assert_eq!(encode("1.2..3"), ok(&[0x2a, 0x00, 0x03]));
        assert_eq!(encode("1.2."), ok(&[0x2a]));
        assert_eq!(encode("1. "), ok(&[0x28]));
        // Text ending right after the first number's separator, or with no separator, is no
        // OID but no error either.
        assert_eq!(encode("1."), ok(&[]));
        assert_eq!(encode("12"), ok(&[]));
    }

    #[test]
    fn rejects_what_openssl_rejects() {
        let error = |text: &str| encode(text).error;
        assert_eq!(error("3.1"), Some(TextError::FirstNumTooLarge));
        assert_eq!(error("x"), Some(TextError::FirstNumTooLarge));
        assert_eq!(error(""), Some(TextError::FirstNumTooLarge));
        assert_eq!(error("1"), Some(TextError::MissingSecondNumber));
        assert_eq!(error("1-2"), Some(TextError::InvalidSeparator));
        assert_eq!(error("1.2a"), Some(TextError::InvalidDigit));
        assert_eq!(error("1.40"), Some(TextError::SecondNumberTooLarge));
        assert_eq!(
            error("0.99999999999999999999999"),
            Some(TextError::SecondNumberTooLarge)
        );
        assert_eq!(
            encode_text(b"1.2.840", Some(2)),
            Encoded {
                octets: vec![0x2a],
                error: Some(TextError::BufferTooSmall)
            }
        );
    }

    #[test]
    fn large_arcs_round_trip() {
        for text in [
            "2.25.329800735698586629295641978511506172918",
            "1.2.18446744073709551615.18446744073709551616",
            "2.18446744073709551535",
            "2.99999999999999999999999999999999999999999999999999999999999",
        ] {
            let encoded = encode(text);
            assert_eq!(encoded.error, None, "{text}");
            let decoded = decode_text(&encoded.octets);
            assert_eq!(
                (decoded.text.as_slice(), decoded.complete),
                (text.as_bytes(), true)
            );
        }
    }

    #[test]
    fn decodes_as_openssl_does() {
        let decode = |content: &[u8]| {
            let d = decode_text(content);
            (String::from_utf8(d.text).unwrap(), d.complete)
        };
        assert_eq!(decode(&[0x55, 0x04, 0x03]), ("2.5.4.3".to_owned(), true));
        assert_eq!(decode(&[0x00]), ("0.0".to_owned(), true));
        assert_eq!(decode(&[0x80, 0x01]), ("0.1".to_owned(), true));
        assert_eq!(decode(&[0x2a, 0x86]), ("1.2".to_owned(), false));
        assert_eq!(decode(&[0x86]), (String::new(), false));
        assert_eq!(decode(&[]), (String::new(), true));
        assert_eq!(decode(&[0x01; 587]), (String::new(), false));
    }

    #[test]
    fn validity() {
        assert!(is_valid_content(&[0x2a, 0x03]));
        assert!(!is_valid_content(&[]));
        assert!(!is_valid_content(&[0x2a, 0x83]));
        assert!(!is_valid_content(&[0x80, 0x01]));
        assert!(!is_valid_content(&[0x2a, 0x80, 0x01]));
        assert!(is_valid_content(&[0x2a, 0x81, 0x80, 0x01]));
    }
}
