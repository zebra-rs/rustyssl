//! BER and DER identifier and length octets, as OpenSSL reads and writes them
//! (`ASN1_get_object`, `ASN1_put_object`, `ASN1_object_size`), and a bounded, zero-copy reader
//! of whole elements, definite or indefinite length.
//!
//! # Leniency
//!
//! OpenSSL's header reader accepts BER, and more; applications see the difference, so this one
//! accepts exactly the same:
//! - a length in long form however small, with any number of leading zero octets (up to the 127
//!   the first octet allows), as long as what's left fits in 8 octets and in a C `long`;
//! - a tag number in high-tag form however small, with any number of leading `0x80` octets;
//! - the indefinite length on a constructed element (not on a primitive one).
//!
//! [`is_der`] tells whether a header is in DER's single form, for callers that want it.
//!
//! # Bounds
//!
//! A header is read one octet at a time through an accessor, never past what it needs, so a
//! caller that only knows how much input is claimed (C's `long` length) needn't trust more. A
//! high tag number stops at 24 bits before its last octet, a length at `i64::MAX`. The element
//! reader skips nested indefinite-length content with a counter, as OpenSSL's `asn1_find_end`
//! does, so depth costs no stack.

/// The constructed bit of the identifier octet.
pub const CONSTRUCTED: u8 = 0x20;
/// The class bits of the identifier octet.
pub const CLASS_MASK: u8 = 0xc0;
/// The tag bits of a low-tag-form identifier octet; all set means the high-tag form.
const LOW_TAG_MASK: u8 = 0x1f;
/// OpenSSL's limit on a high tag number before its last octet: `INT_MAX >> 7`.
const TAG_LIMIT: i64 = (i32::MAX >> 7) as i64;

/// An element's identifier and length octets, as `ASN1_get_object` reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The identifier's constructed bit.
    pub constructed: bool,
    /// The identifier's class bits (`0x00`, `0x40`, `0x80`, or `0xc0`).
    pub class: u8,
    /// The tag number.
    pub tag: i32,
    /// The content length; 0 for the indefinite length.
    pub length: i64,
    /// Whether the length is indefinite.
    pub indefinite: bool,
    /// The number of identifier and length octets.
    pub header_len: usize,
    /// Whether the length exceeds the input after the header (`ASN1_R_TOO_LONG`, which
    /// OpenSSL reports with the header nonetheless).
    pub overrun: bool,
}

/// Why `ASN1_get_object` can't read a header, and what it has stored by then.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    /// No input (`ASN1_R_TOO_SMALL`).
    TooSmall,
    /// The identifier or length octets are cut short, too large, or an indefinite length is
    /// on a primitive element (`ASN1_R_HEADER_TOO_LONG`). OpenSSL has already stored the tag
    /// and class when the identifier was complete, and the length when that was too.
    Malformed {
        /// The tag number and class, if the identifier was read.
        tag_class: Option<(i32, u8)>,
        /// The length, if it was read.
        length: Option<i64>,
    },
}

/// Reads a header from `available` octets of input (OpenSSL's `omax`, which may be 0 or
/// negative), fetching octet `i` with `octet(i)` only for `i < available`.
pub fn read_header(
    available: i64,
    mut octet: impl FnMut(usize) -> u8,
) -> Result<Header, HeaderError> {
    if available <= 0 {
        return Err(HeaderError::TooSmall);
    }
    let malformed = |tag_class, length| HeaderError::Malformed { tag_class, length };
    let mut max = available;
    let mut pos = 0usize;
    let first = octet(pos);
    let constructed = first & CONSTRUCTED != 0;
    let class = first & CLASS_MASK;
    let tag;
    pos = pos.wrapping_add(1);
    max = max.wrapping_sub(1);
    if max == 0 {
        return Err(malformed(None, None));
    }
    if first & LOW_TAG_MASK == LOW_TAG_MASK {
        let mut number: i64 = 0;
        let mut next = octet(pos);
        while next & 0x80 != 0 {
            number = (number << 7) | i64::from(next & 0x7f);
            pos = pos.wrapping_add(1);
            max = max.wrapping_sub(1);
            if max == 0 || number > TAG_LIMIT {
                return Err(malformed(None, None));
            }
            next = octet(pos);
        }
        number = (number << 7) | i64::from(next & 0x7f);
        tag = i32::try_from(number).unwrap_or(i32::MAX);
        pos = pos.wrapping_add(1);
        max = max.wrapping_sub(1);
        if max == 0 {
            return Err(malformed(None, None));
        }
    } else {
        tag = i32::from(first & LOW_TAG_MASK);
    }
    let tag_class = Some((tag, class));

    // asn1_get_length: `max` octets remain, the length's first among them.
    max = max.wrapping_sub(1);
    let first_length = octet(pos);
    pos = pos.wrapping_add(1);
    let (length, indefinite) = if first_length == 0x80 {
        (0, true)
    } else if first_length & 0x80 == 0 {
        (i64::from(first_length), false)
    } else {
        let mut count = i64::from(first_length & 0x7f);
        if max < count {
            return Err(malformed(tag_class, None));
        }
        while count > 0 && octet(pos) == 0 {
            pos = pos.wrapping_add(1);
            count = count.wrapping_sub(1);
        }
        if count > 8 {
            return Err(malformed(tag_class, None));
        }
        let mut value: u64 = 0;
        while count > 0 {
            value = (value << 8) | u64::from(octet(pos));
            pos = pos.wrapping_add(1);
            count = count.wrapping_sub(1);
        }
        let Ok(value) = i64::try_from(value) else {
            return Err(malformed(tag_class, None));
        };
        (value, false)
    };
    if indefinite && !constructed {
        return Err(malformed(tag_class, Some(length)));
    }
    let remaining = i64::try_from(pos).map_or(0, |used| available.wrapping_sub(used));
    Ok(Header {
        constructed,
        class,
        tag,
        length,
        indefinite,
        header_len: pos,
        overrun: length > remaining,
    })
}

/// [`read_header`] on a slice.
pub fn header(input: &[u8]) -> Result<Header, HeaderError> {
    let available = i64::try_from(input.len()).unwrap_or(i64::MAX);
    read_header(available, |i| input.get(i).copied().unwrap_or(0))
}

/// Appends a header as `ASN1_put_object` writes it, C's `int` arithmetic included: any
/// nonzero `constructed` sets the bit, 2 writes the indefinite length, a tag below 31 (even a
/// negative one) is written in low form, and a length up to 127 (even a negative one) is
/// written as its low octet.
pub fn put_header(out: &mut Vec<u8>, constructed: i32, length: i32, tag: i32, class: i32) {
    let mut identifier = if constructed != 0 { CONSTRUCTED } else { 0 };
    identifier |= u8::try_from(class & i32::from(CLASS_MASK)).unwrap_or(0);
    if tag < 31 {
        out.push(identifier | u8::try_from(tag & i32::from(LOW_TAG_MASK)).unwrap_or(0));
    } else {
        out.push(identifier | LOW_TAG_MASK);
        out.extend(base128(tag));
    }
    if constructed == 2 {
        out.push(0x80);
    } else if length <= 127 {
        out.push(length.to_le_bytes()[0]);
    } else {
        let octets: Vec<u8> = length
            .to_be_bytes()
            .into_iter()
            .skip_while(|&b| b == 0)
            .collect();
        out.push(0x80 | u8::try_from(octets.len()).unwrap_or(0));
        out.extend(octets);
    }
}

/// The base-128 octets of a positive tag number, high groups first, all but the last with the
/// continuation bit.
fn base128(tag: i32) -> Vec<u8> {
    let mut groups = Vec::new();
    let mut rest = tag;
    while rest > 0 {
        groups.push(u8::try_from(rest & 0x7f).unwrap_or(0));
        rest >>= 7;
    }
    groups.reverse();
    let last = groups.len().saturating_sub(1);
    for group in groups.iter_mut().take(last) {
        *group |= 0x80;
    }
    groups
}

/// The size of a whole element as `ASN1_object_size` computes it: header and content, or -1
/// for a negative length or a total past `INT_MAX`.
pub fn object_size(constructed: i32, length: i32, tag: i32) -> i32 {
    if length < 0 {
        return -1;
    }
    let mut size: i32 = 1;
    if tag >= 31 {
        let mut rest = tag;
        while rest > 0 {
            rest >>= 7;
            size = size.wrapping_add(1);
        }
    }
    if constructed == 2 {
        size = size.wrapping_add(3);
    } else {
        size = size.wrapping_add(1);
        if length > 127 {
            let mut rest = length;
            while rest > 0 {
                rest >>= 8;
                size = size.wrapping_add(1);
            }
        }
    }
    if size >= i32::MAX.wrapping_sub(length) {
        return -1;
    }
    size.wrapping_add(length)
}

/// Whether `input` starts with a header in DER's single form: definite length, both the tag
/// number and the length in their shortest encoding.
pub fn is_der(input: &[u8]) -> bool {
    let Ok(h) = header(input) else {
        return false;
    };
    if h.indefinite {
        return false;
    }
    let (Ok(length), Some(written)) = (i32::try_from(h.length), input.get(..h.header_len)) else {
        return false;
    };
    let mut canonical = Vec::new();
    put_header(
        &mut canonical,
        i32::from(h.constructed),
        length,
        h.tag,
        i32::from(h.class),
    );
    canonical == written
}

/// Why an element can't be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElementError {
    /// The header is malformed or its length runs past the input.
    BadHeader,
    /// Indefinite-length content ends before its end-of-contents octets.
    MissingEoc,
}

/// A whole element: its header, its content, and all its octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Element<'a> {
    pub header: Header,
    /// The content octets: for the indefinite length, up to the closing end-of-contents.
    pub content: &'a [u8],
    /// The element's octets, header to end (end-of-contents included).
    pub raw: &'a [u8],
}

/// Reads the element at the start of `input`.
pub fn element(input: &[u8]) -> Result<Element<'_>, ElementError> {
    let h = header(input).map_err(|_| ElementError::BadHeader)?;
    if h.overrun {
        return Err(ElementError::BadHeader);
    }
    let rest = input.get(h.header_len..).unwrap_or(&[]);
    let (content, raw_len) = if h.indefinite {
        let used = find_end(rest)?;
        let content = rest.get(..used.saturating_sub(2)).unwrap_or(&[]);
        (content, h.header_len.saturating_add(used))
    } else {
        let length = usize::try_from(h.length).map_err(|_| ElementError::BadHeader)?;
        let content = rest.get(..length).ok_or(ElementError::BadHeader)?;
        (content, h.header_len.saturating_add(length))
    };
    Ok(Element {
        header: h,
        content,
        raw: input.get(..raw_len).unwrap_or(input),
    })
}

/// The number of octets of indefinite-length content in `input`, its end-of-contents
/// included, found as OpenSSL's `asn1_find_end` finds it: counting the end-of-contents octets
/// still expected instead of recursing.
pub fn find_end(input: &[u8]) -> Result<usize, ElementError> {
    let mut expected: u32 = 1;
    let mut pos = 0usize;
    while let Some(rest) = input.get(pos..).filter(|r| !r.is_empty()) {
        if rest.starts_with(&[0, 0]) {
            pos = pos.saturating_add(2);
            expected = expected.saturating_sub(1);
            if expected == 0 {
                return Ok(pos);
            }
            continue;
        }
        let h = header(rest).map_err(|_| ElementError::BadHeader)?;
        if h.overrun {
            return Err(ElementError::BadHeader);
        }
        pos = pos.saturating_add(h.header_len);
        if h.indefinite {
            expected = expected.checked_add(1).ok_or(ElementError::BadHeader)?;
        } else {
            pos =
                pos.saturating_add(usize::try_from(h.length).map_err(|_| ElementError::BadHeader)?);
        }
    }
    Err(ElementError::MissingEoc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(bytes: &[u8]) -> Header {
        header(bytes).unwrap()
    }

    #[test]
    fn reads_headers_as_openssl_does() {
        let seq = h(&[0x30, 0x03, 1, 2, 3]);
        assert_eq!(
            (
                seq.constructed,
                seq.class,
                seq.tag,
                seq.length,
                seq.header_len
            ),
            (true, 0, 16, 3, 2)
        );
        assert!(!seq.overrun);
        // Long-form lengths however small, with leading zeros.
        assert_eq!(h(&[0x04, 0x81, 0x01, 9]).length, 1);
        assert_eq!(h(&[0x04, 0x84, 0, 0, 0, 1, 9]).header_len, 6);
        // High-tag form, even for small numbers, even with leading 0x80 octets.
        assert_eq!(h(&[0x9f, 0x05, 0x00]).tag, 5);
        assert_eq!(h(&[0x1f, 0x80, 0x80, 0x81, 0x00, 0x00]).tag, 128);
        assert_eq!(h(&[0xbf, 0x8f, 0xff, 0xff, 0x7f, 0x00]).tag, 0x1ff_ffff);
        // Indefinite length on a constructed element.
        let inf = h(&[0x30, 0x80, 0, 0]);
        assert!(inf.indefinite && inf.length == 0);
        // A length past the input is reported with the header.
        assert!(h(&[0x04, 0x05, 1]).overrun);
    }

    #[test]
    fn rejects_what_openssl_rejects() {
        assert_eq!(header(&[]), Err(HeaderError::TooSmall));
        let bad = |bytes: &[u8]| matches!(header(bytes), Err(HeaderError::Malformed { .. }));
        assert!(bad(&[0x04]));
        assert!(bad(&[0x1f]));
        assert!(bad(&[0x1f, 0x81]));
        assert!(bad(&[0x1f, 0x05]));
        assert!(bad(&[0x04, 0x80]));
        assert!(bad(&[0x04, 0x82, 0x01]));
        assert!(bad(&[0x04, 0x89, 1, 1, 1, 1, 1, 1, 1, 1, 1]));
        assert!(bad(&[0x04, 0x88, 0x80, 0, 0, 0, 0, 0, 0, 0]));
        assert!(bad(&[0x1f, 0xff, 0xff, 0xff, 0xff, 0x7f, 0]));
        assert_eq!(
            header(&[0x04, 0x80, 0]),
            Err(HeaderError::Malformed {
                tag_class: Some((4, 0)),
                length: Some(0)
            })
        );
    }

    #[test]
    fn writes_headers_as_openssl_does() {
        let put = |constructed, length, tag, class| {
            let mut out = Vec::new();
            put_header(&mut out, constructed, length, tag, class);
            out
        };
        assert_eq!(put(1, 3, 16, 0), [0x30, 0x03]);
        assert_eq!(put(0, 200, 4, 0x80), [0x84, 0x81, 200]);
        assert_eq!(put(0, 0x1_0000, 4, 0), [0x04, 0x83, 1, 0, 0]);
        assert_eq!(put(2, 99, 16, 0), [0x30, 0x80]);
        assert_eq!(put(0, 1, 31, 0x40), [0x5f, 0x1f, 0x01]);
        assert_eq!(put(0, 1, 200, 0), [0x1f, 0x81, 0x48, 0x01]);
        assert_eq!(put(0, -1, -3, 0), [0x1d, 0xff]);
        assert_eq!(object_size(0, 200, 4), 203);
        assert_eq!(object_size(2, 5, 16), 9);
        assert_eq!(object_size(0, 1, 200), 5);
        assert_eq!(object_size(0, -1, 4), -1);
        assert_eq!(object_size(0, i32::MAX - 2, 4), -1);
        for (c, l, t, cl) in [
            (0, 0, 0, 0),
            (1, 127, 30, 0xc0),
            (0, 128, 31, 0),
            (0, 70000, 1 << 20, 0x80),
        ] {
            assert_eq!(
                put(c, l, t, cl).len() + usize::try_from(l).unwrap(),
                usize::try_from(object_size(c, l, t)).unwrap()
            );
            let mut bytes = put(c, l, t, cl);
            bytes.resize(bytes.len() + usize::try_from(l).unwrap(), 0);
            assert!(is_der(&bytes));
        }
    }

    #[test]
    fn der_is_the_shortest_form() {
        assert!(is_der(&[0x04, 0x01, 0]));
        assert!(!is_der(&[0x04, 0x81, 0x01, 0]));
        assert!(!is_der(&[0x1f, 0x05, 0x00]));
        assert!(!is_der(&[0x30, 0x80, 0, 0]));
    }

    #[test]
    fn reads_elements_definite_and_indefinite() {
        let e = element(&[0x30, 0x03, 0x02, 0x01, 0x05, 0xff]).unwrap();
        assert_eq!((e.content, e.raw.len()), (&[0x02, 0x01, 0x05][..], 5));
        let input = [
            0x30, 0x80, 0x24, 0x80, 0x04, 0x01, 0xaa, 0x00, 0x00, 0x02, 0x01, 0x07, 0x00, 0x00,
            0xee,
        ];
        let e = element(&input).unwrap();
        assert_eq!(e.raw.len(), 14);
        assert_eq!(e.content, &input[2..12]);
        assert_eq!(
            element(&[0x30, 0x80, 0x02, 0x01, 0x05]),
            Err(ElementError::MissingEoc)
        );
        assert_eq!(element(&[0x30, 0x05, 0x02]), Err(ElementError::BadHeader));
        // Deep nesting costs a counter, not stack.
        let mut deep = Vec::new();
        for _ in 0..100_000 {
            deep.extend([0x30, 0x80]);
        }
        deep.resize(deep.len() + 200_000, 0);
        assert_eq!(element(&deep).unwrap().raw.len(), deep.len());
    }
}
