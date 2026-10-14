//! Character strings as OpenSSL converts and prints them: UTF-8 (`UTF8_getc`/`UTF8_putc`),
//! conversion between the multibyte forms with the choice of string type (`ASN1_mbstring_ncopy`),
//! and the escaping printer behind `ASN1_STRING_print_ex` (RFC 2253 and 2254 escapes, quotes,
//! hex dumps).
//!
//! These are ports, step for step: the error each input gets, the order checks run in, and the
//! output in the chunks OpenSSL writes it in (a printer stops at the first chunk its sink
//! refuses) are all observable.

use core::ffi::CStr;

use rustyssl_abi::{
    ASN1_STRFLGS_DUMP_ALL, ASN1_STRFLGS_DUMP_DER, ASN1_STRFLGS_DUMP_UNKNOWN, ASN1_STRFLGS_ESC_2253,
    ASN1_STRFLGS_ESC_2254, ASN1_STRFLGS_ESC_CTRL, ASN1_STRFLGS_ESC_MSB, ASN1_STRFLGS_ESC_QUOTE,
    ASN1_STRFLGS_IGNORE_TYPE, ASN1_STRFLGS_SHOW_TYPE, ASN1_STRFLGS_UTF8_CONVERT,
    ASN1_STRING_FLAG_BITS_LEFT, B_ASN1_BMPSTRING, B_ASN1_IA5STRING, B_ASN1_NUMERICSTRING,
    B_ASN1_PRINTABLESTRING, B_ASN1_T61STRING, B_ASN1_UNIVERSALSTRING, B_ASN1_UTF8STRING,
    CHARTYPE_FIRST_ESC_2253, CHARTYPE_LAST_ESC_2253, CHARTYPE_PRINTABLESTRING, MBSTRING_ASC,
    MBSTRING_BMP, MBSTRING_UNIV, MBSTRING_UTF8, V_ASN1_BIT_STRING, V_ASN1_BMPSTRING,
    V_ASN1_BOOLEAN, V_ASN1_ENUMERATED, V_ASN1_IA5STRING, V_ASN1_INTEGER, V_ASN1_NULL,
    V_ASN1_NUMERICSTRING, V_ASN1_OBJECT, V_ASN1_OTHER, V_ASN1_PRINTABLESTRING, V_ASN1_SEQUENCE,
    V_ASN1_SET, V_ASN1_T61STRING, V_ASN1_UNDEF, V_ASN1_UNIVERSALSTRING, V_ASN1_UTF8STRING,
};

use zeroize::Zeroizing;

use crate::der;

/// The first code point past Unicode.
const UNICODE_LIMIT: u32 = 0x11_0000;

fn is_surrogate(value: u32) -> bool {
    (0xd800..=0xdfff).contains(&value)
}

/// Whether `value` is a Unicode scalar value (`is_unicode_valid`).
pub fn is_unicode_valid(value: u32) -> bool {
    value < UNICODE_LIMIT && !is_surrogate(value)
}

/// `UTF8_getc`: the character at the start of `input` and its length in octets, or OpenSSL's
/// negative error: -1 cut short, -2 a bad first octet (or a surrogate), -3 a bad continuation
/// octet, -4 an overlong or out-of-range value. `Ok(None)` for no input.
pub fn utf8_get(input: &[u8]) -> Result<Option<(u32, usize)>, i32> {
    let Some(&first) = input.first() else {
        return Ok(None);
    };
    let continuation = |i: usize| input.get(i).copied().unwrap_or(0);
    let tail_ok = |n: usize| (1..n).all(|i| continuation(i) & 0xc0 == 0x80);
    let low = |i: usize| u32::from(continuation(i) & 0x3f);
    let (value, length) = if first & 0x80 == 0 {
        (u32::from(first), 1)
    } else if first & 0xe0 == 0xc0 {
        if input.len() < 2 {
            return Err(-1);
        }
        if !tail_ok(2) {
            return Err(-3);
        }
        let value = (u32::from(first & 0x1f) << 6) | low(1);
        if value < 0x80 {
            return Err(-4);
        }
        (value, 2)
    } else if first & 0xf0 == 0xe0 {
        if input.len() < 3 {
            return Err(-1);
        }
        if !tail_ok(3) {
            return Err(-3);
        }
        let value = (u32::from(first & 0xf) << 12) | (low(1) << 6) | low(2);
        if value < 0x800 {
            return Err(-4);
        }
        if is_surrogate(value) {
            return Err(-2);
        }
        (value, 3)
    } else if first & 0xf8 == 0xf0 {
        if input.len() < 4 {
            return Err(-1);
        }
        if !tail_ok(4) {
            return Err(-3);
        }
        let value = (u32::from(first & 0x7) << 18) | (low(1) << 12) | (low(2) << 6) | low(3);
        if !(0x1_0000..UNICODE_LIMIT).contains(&value) {
            return Err(-4);
        }
        (value, 4)
    } else {
        return Err(-2);
    };
    Ok(Some((value, length)))
}

/// `UTF8_putc`'s encoding of `value`, or its error: -2 for a surrogate or a value past Unicode.
pub fn utf8_put(value: u64) -> Result<Vec<u8>, i32> {
    let byte = |v: u64| u8::try_from(v & 0xff).unwrap_or(0);
    if value < 0x80 {
        Ok(vec![byte(value)])
    } else if value < 0x800 {
        Ok(vec![
            byte(((value >> 6) & 0x1f) | 0xc0),
            byte((value & 0x3f) | 0x80),
        ])
    } else if value < 0x1_0000 {
        if is_surrogate(u32::try_from(value).unwrap_or(0)) {
            return Err(-2);
        }
        Ok(vec![
            byte(((value >> 12) & 0xf) | 0xe0),
            byte(((value >> 6) & 0x3f) | 0x80),
            byte((value & 0x3f) | 0x80),
        ])
    } else if value < u64::from(UNICODE_LIMIT) {
        Ok(vec![
            byte(((value >> 18) & 0x7) | 0xf0),
            byte(((value >> 12) & 0x3f) | 0x80),
            byte(((value >> 6) & 0x3f) | 0x80),
            byte((value & 0x3f) | 0x80),
        ])
    } else {
        Err(-2)
    }
}

/// A big-endian UTF-16 unit.
fn bmp_unit(value: u32) -> [u8; 2] {
    u16::try_from(value & 0xffff).unwrap_or(0).to_be_bytes()
}

/// Room for the UTF-16 of `n` octets and a zero unit, so the buffer never moves (and leaves
/// no copy of a password behind).
fn bmp_buffer(n: usize) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(Vec::with_capacity(n.saturating_mul(2).saturating_add(2)))
}

/// `OPENSSL_asc2uni`: each octet of `asc` as a big-endian UTF-16 unit, undecoded, then a zero
/// unit (PKCS #12 passwords). Wiped when dropped.
pub fn asc_to_bmp(asc: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = bmp_buffer(asc.len());
    for &c in asc {
        out.extend_from_slice(&[0, c]);
    }
    out.extend_from_slice(&[0, 0]);
    out
}

/// `OPENSSL_utf82uni`: `utf8` as big-endian UTF-16 (surrogate pairs past the BMP), then a zero
/// unit; input that isn't UTF-8 is taken as `asc_to_bmp` takes it, as OpenSSL does for
/// passwords set by its older versions. Wiped when dropped.
pub fn utf8_to_bmp(utf8: &[u8]) -> Zeroizing<Vec<u8>> {
    // Each character's UTF-16 takes at most twice its UTF-8 octets.
    let mut out = bmp_buffer(utf8.len());
    let mut rest = utf8;
    while !rest.is_empty() {
        let Ok(Some((value, length))) = utf8_get(rest) else {
            return asc_to_bmp(utf8);
        };
        match value.checked_sub(0x1_0000) {
            Some(v) => {
                out.extend_from_slice(&bmp_unit(0xd800 | (v >> 10)));
                out.extend_from_slice(&bmp_unit(0xdc00 | (v & 0x3ff)));
            }
            None => out.extend_from_slice(&bmp_unit(value)),
        }
        rest = rest.get(length..).unwrap_or_default();
    }
    out.extend_from_slice(&[0, 0]);
    out
}

/// `OPENSSL_uni2asc`: the low octet of each big-endian UTF-16 unit of `bmp`, ending in a zero
/// octet (the last unit's when it's zero), or `None` for an odd length.
pub fn bmp_to_asc(bmp: &[u8]) -> Option<Vec<u8>> {
    if !bmp.len().is_multiple_of(2) {
        return None;
    }
    let mut out: Vec<u8> = bmp.as_chunks::<2>().0.iter().map(|&[_, low]| low).collect();
    if bmp.last().is_some_and(|&b| b == 0) {
        if let Some(last) = out.last_mut() {
            *last = 0;
        }
    } else {
        out.push(0);
    }
    Some(out)
}

/// `OPENSSL_uni2utf8`: big-endian UTF-16 `bmp` as UTF-8, ending in a zero octet unless its
/// last unit is zero (which converts to one), or `None` for an odd length. Input that isn't
/// UTF-16 (a lone surrogate) is taken as `bmp_to_asc` takes it.
pub fn bmp_to_utf8(bmp: &[u8]) -> Option<Vec<u8>> {
    if !bmp.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::new();
    let mut rest = bmp;
    while let [a, b, tail @ ..] = rest {
        let unit = (u32::from(*a) << 8) | u32::from(*b);
        // As in OpenSSL, a low surrogate first is taken as a pair's start, which then makes a
        // value past Unicode.
        let (value, tail) = if (0xd800..0xe000).contains(&unit) {
            let [c, d, tail @ ..] = tail else {
                return bmp_to_asc(bmp);
            };
            let low = (u32::from(*c) << 8) | u32::from(*d);
            if !(0xdc00..0xe000).contains(&low) {
                return bmp_to_asc(bmp);
            }
            // At most 0x1f_ffff + 0x1_0000: no wrap.
            let value = (((unit & 0x7ff) << 10) | (low & 0x3ff)).wrapping_add(0x1_0000);
            (value, tail)
        } else {
            (unit, tail)
        };
        match utf8_put(u64::from(value)) {
            Ok(encoded) => out.extend_from_slice(&encoded),
            Err(_) => return bmp_to_asc(bmp),
        }
        rest = tail;
    }
    if !matches!(bmp, [.., 0, 0]) {
        out.push(0);
    }
    Some(out)
}

/// A multibyte form (`MBSTRING_ASC`, `_BMP`, `_UNIV`, `_UTF8`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    Ascii,
    Bmp,
    Universal,
    Utf8,
}

impl Form {
    /// The form an `MBSTRING_*` value names.
    pub fn from_mbstring(value: i32) -> Option<Form> {
        match value {
            MBSTRING_ASC => Some(Form::Ascii),
            MBSTRING_BMP => Some(Form::Bmp),
            MBSTRING_UNIV => Some(Form::Universal),
            MBSTRING_UTF8 => Some(Form::Utf8),
            _ => None,
        }
    }
}

/// `traverse_string`: the characters of `input` in `form` (whose length fits it), stopping at
/// malformed UTF-8 (`Err`).
fn characters(input: &[u8], form: Form) -> impl Iterator<Item = Result<u32, ()>> + '_ {
    let mut rest = input;
    core::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let width = match form {
            Form::Ascii => 1,
            Form::Bmp => 2,
            Form::Universal => 4,
            Form::Utf8 => match utf8_get(rest) {
                Ok(Some((value, length))) => {
                    rest = rest.get(length..).unwrap_or(&[]);
                    return Some(Ok(value));
                }
                _ => {
                    rest = &[];
                    return Some(Err(()));
                }
            },
        };
        let (char_octets, tail) = rest.split_at(width.min(rest.len()));
        rest = tail;
        Some(Ok(char_octets
            .iter()
            .fold(0u32, |v, &b| (v << 8) | u32::from(b))))
    })
}

/// Why `ASN1_mbstring_ncopy` refuses an input (its `ASN1_R_*` reason, named).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MbError {
    StringTooLong,
    PassedInvalidArgument,
    InvalidBmpLength,
    InvalidUniversalLength,
    InvalidUtf8,
    UnknownFormat,
    /// Fewer characters than `minsize`.
    TooShort(i64),
    /// More characters than `maxsize`.
    TooLong(i64),
    IllegalCharacters,
}

/// The string type `ASN1_mbstring_ncopy` chooses, and the output form it converts to.
pub fn choose_type(mask: u64) -> (i32, Form) {
    let has = |bit: i32| mask & u64::try_from(bit).unwrap_or(0) != 0;
    if has(B_ASN1_NUMERICSTRING) {
        (V_ASN1_NUMERICSTRING, Form::Ascii)
    } else if has(B_ASN1_PRINTABLESTRING) {
        (V_ASN1_PRINTABLESTRING, Form::Ascii)
    } else if has(B_ASN1_IA5STRING) {
        (V_ASN1_IA5STRING, Form::Ascii)
    } else if has(B_ASN1_T61STRING) {
        (V_ASN1_T61STRING, Form::Ascii)
    } else if has(B_ASN1_BMPSTRING) {
        (V_ASN1_BMPSTRING, Form::Bmp)
    } else if has(B_ASN1_UNIVERSALSTRING) {
        (V_ASN1_UNIVERSALSTRING, Form::Universal)
    } else {
        (V_ASN1_UTF8STRING, Form::Utf8)
    }
}

/// The masks of the types `type_str` checks.
fn checked_types() -> u64 {
    [
        B_ASN1_NUMERICSTRING,
        B_ASN1_PRINTABLESTRING,
        B_ASN1_IA5STRING,
        B_ASN1_T61STRING,
        B_ASN1_BMPSTRING,
        B_ASN1_UNIVERSALSTRING,
        B_ASN1_UTF8STRING,
    ]
    .iter()
    .fold(0, |m, &b| m | u64::try_from(b).unwrap_or(0))
}

/// Whether `c` is a PrintableString character (`ossl_isasn1print`).
pub fn is_asn1_print(c: u32) -> bool {
    u8::try_from(c)
        .ok()
        .filter(u8::is_ascii)
        .is_some_and(|b| char_type(b) & CHARTYPE_PRINTABLESTRING_U16 != 0)
}

/// `type_str`: narrows the types `mask` allows to those that can hold `value`, or `None` if
/// none can.
fn narrow(mask: u64, value: u32) -> Option<u64> {
    let bit = |b: i32| u64::try_from(b).unwrap_or(0);
    let mut types = mask & checked_types();
    if types != mask {
        types |= bit(B_ASN1_UTF8STRING);
    }
    let ascii = u8::try_from(value).ok().filter(u8::is_ascii);
    if types & bit(B_ASN1_NUMERICSTRING) != 0
        && !ascii.is_some_and(|c| c.is_ascii_digit() || c == b' ')
    {
        types &= !bit(B_ASN1_NUMERICSTRING);
    }
    if types & bit(B_ASN1_PRINTABLESTRING) != 0 && !is_asn1_print(value) {
        types &= !bit(B_ASN1_PRINTABLESTRING);
    }
    if types & bit(B_ASN1_IA5STRING) != 0 && ascii.is_none() {
        types &= !bit(B_ASN1_IA5STRING);
    }
    if types & bit(B_ASN1_T61STRING) != 0 && value > 0xff {
        types &= !bit(B_ASN1_T61STRING);
    }
    if types & bit(B_ASN1_BMPSTRING) != 0 && value > 0xffff {
        types &= !bit(B_ASN1_BMPSTRING);
    }
    if types & bit(B_ASN1_UTF8STRING) != 0 && !is_unicode_valid(value) {
        types &= !bit(B_ASN1_UTF8STRING);
    }
    (types != 0).then_some(types)
}

/// What `ASN1_mbstring_ncopy` makes of `input`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Converted {
    /// The string type chosen.
    pub string_type: i32,
    /// The form it is stored in.
    pub form: Form,
    /// The input form, for when the two are the same (then `octets` is the input).
    pub same_form: bool,
}

/// `ASN1_mbstring_ncopy` up to the conversion: checks `input` (in `form`) and chooses its type.
/// `mask` 0 means `DIRSTRING_TYPE`, which the caller passes.
pub fn check_and_choose(
    input: &[u8],
    form: Option<Form>,
    mask: u64,
    minsize: i64,
    maxsize: i64,
) -> Result<Converted, MbError> {
    let len = input.len();
    // OpenSSL refuses INT_MAX octets and more.
    if i32::try_from(len).map_or(true, |l| l == i32::MAX) {
        return Err(MbError::StringTooLong);
    }
    let count: usize = match form {
        Some(Form::Bmp) => {
            if !len.is_multiple_of(2) {
                return Err(MbError::InvalidBmpLength);
            }
            len / 2
        }
        Some(Form::Universal) => {
            if !len.is_multiple_of(4) {
                return Err(MbError::InvalidUniversalLength);
            }
            len / 4
        }
        Some(Form::Utf8) => {
            let mut n = 0usize;
            for c in characters(input, Form::Utf8) {
                match c {
                    Ok(value) if is_unicode_valid(value) => n = n.saturating_add(1),
                    _ => return Err(MbError::InvalidUtf8),
                }
            }
            n
        }
        Some(Form::Ascii) => len,
        None => return Err(MbError::UnknownFormat),
    };
    let form = form.unwrap_or(Form::Ascii);
    let count = i64::try_from(count).unwrap_or(i64::MAX);
    if minsize > 0 && count < minsize {
        return Err(MbError::TooShort(minsize));
    }
    if maxsize > 0 && count > maxsize {
        return Err(MbError::TooLong(maxsize));
    }
    let mut types = mask;
    for c in characters(input, form) {
        let Ok(value) = c else {
            return Err(MbError::IllegalCharacters);
        };
        types = narrow(types, value).ok_or(MbError::IllegalCharacters)?;
    }
    let (string_type, out_form) = choose_type(types);
    Ok(Converted {
        string_type,
        form: out_form,
        same_form: out_form == form,
    })
}

/// The conversion of `input` (in `from`, already checked) to `to`, or `MbError` for a character
/// UTF-8 can't hold (`InvalidUtf8`) or an output past `INT_MAX` octets.
pub fn convert(input: &[u8], from: Form, to: Form) -> Result<Vec<u8>, MbError> {
    // As OpenSSL, refuse a BMPString or UniversalString past INT_MAX octets before making it.
    let count = characters(input, from).count();
    let limit = usize::try_from(i32::MAX).unwrap_or(usize::MAX);
    let too_long = match to {
        Form::Bmp => count > limit / 2,
        Form::Universal => count > limit / 4,
        Form::Ascii | Form::Utf8 => false,
    };
    if too_long {
        return Err(MbError::StringTooLong);
    }
    let mut out = Vec::new();
    for c in characters(input, from) {
        let value = c.map_err(|()| MbError::InvalidUtf8)?;
        match to {
            Form::Ascii => out.push(u8::try_from(value & 0xff).unwrap_or(0)),
            Form::Bmp => {
                out.extend_from_slice(&u16::try_from(value & 0xffff).unwrap_or(0).to_be_bytes())
            }
            Form::Universal => out.extend_from_slice(&value.to_be_bytes()),
            Form::Utf8 => {
                let encoded = utf8_put(u64::from(value)).map_err(|_| MbError::InvalidUtf8)?;
                if out.len()
                    >= usize::try_from(i32::MAX)
                        .unwrap_or(usize::MAX)
                        .saturating_sub(encoded.len())
                {
                    return Err(MbError::StringTooLong);
                }
                out.extend(encoded);
            }
        }
    }
    Ok(out)
}

const CHARTYPE_PRINTABLESTRING_U16: u16 = flag16(CHARTYPE_PRINTABLESTRING);

const fn flag16(flag: i32) -> u16 {
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "flags below 0x10000"
    )]
    {
        flag as u16
    }
}

/// OpenSSL's `char_type` table (`charmap.pl`), for the 128 ASCII characters.
#[expect(
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "evaluated at compile time, where an index out of range fails the build"
)]
const CHAR_TYPE: [u16; 128] = {
    let esc_2253 = flag16(ASN1_STRFLGS_ESC_2253);
    let esc_ctrl = flag16(ASN1_STRFLGS_ESC_CTRL);
    let noesc_quote = flag16(ASN1_STRFLGS_ESC_QUOTE);
    let pstring = CHARTYPE_PRINTABLESTRING_U16;
    let first_esc = flag16(CHARTYPE_FIRST_ESC_2253);
    let last_esc = flag16(CHARTYPE_LAST_ESC_2253);
    let esc_2254 = flag16(ASN1_STRFLGS_ESC_2254);
    let host_any = 0x1000;
    let host_dot = 0x2000;
    let host_hyphen = 0x4000;
    let host_wild = 0x8000;
    let mut table = [0u16; 128];
    let mut i = 0;
    while i < 128 {
        if i < 32 || i > 126 {
            table[i] |= esc_ctrl;
        }
        let c = i as u8;
        if c.is_ascii_alphanumeric() {
            table[i] |= pstring | host_any;
        }
        i += 1;
    }
    table[b' ' as usize] |= noesc_quote | first_esc | last_esc;
    table[b'#' as usize] |= noesc_quote | first_esc;
    table[b',' as usize] |= noesc_quote | esc_2253;
    table[b'+' as usize] |= noesc_quote | esc_2253;
    table[b'"' as usize] |= esc_2253;
    table[b'\\' as usize] |= esc_2253;
    table[b'<' as usize] |= noesc_quote | esc_2253;
    table[b'>' as usize] |= noesc_quote | esc_2253;
    table[b';' as usize] |= noesc_quote | esc_2253;
    table[0] |= esc_2254;
    table[b'(' as usize] |= esc_2254;
    table[b')' as usize] |= esc_2254;
    table[b'*' as usize] |= esc_2254 | host_wild;
    table[b'\\' as usize] |= esc_2254;
    table[b' ' as usize] |= pstring;
    table[b'\'' as usize] |= pstring;
    table[b'(' as usize] |= pstring;
    table[b')' as usize] |= pstring;
    table[b'+' as usize] |= pstring;
    table[b',' as usize] |= pstring;
    table[b'-' as usize] |= pstring | host_hyphen;
    table[b'.' as usize] |= pstring | host_dot;
    table[b'/' as usize] |= pstring;
    table[b':' as usize] |= pstring;
    table[b'=' as usize] |= pstring;
    table[b'?' as usize] |= pstring;
    table
};

/// The properties of an ASCII character (0 past ASCII).
pub fn char_type(c: u8) -> u16 {
    CHAR_TYPE.get(usize::from(c)).copied().unwrap_or(0)
}

/// The width in octets of each universal type's characters, as `ASN1_STRING_print_ex` reads
/// them (0 for UTF-8, -1 for a type it doesn't treat as text).
pub fn tag_width(tag: i32) -> i32 {
    match tag {
        V_ASN1_UTF8STRING => 0,
        18..=20 | 22..=24 | 26 => 1,
        V_ASN1_UNIVERSALSTRING => 4,
        V_ASN1_BMPSTRING => 2,
        _ => -1,
    }
}

/// `ASN1_tag2str`'s names of the universal tags.
pub fn tag_name(tag: i32) -> &'static CStr {
    const NAMES: [&CStr; 31] = [
        c"EOC",
        c"BOOLEAN",
        c"INTEGER",
        c"BIT STRING",
        c"OCTET STRING",
        c"NULL",
        c"OBJECT",
        c"OBJECT DESCRIPTOR",
        c"EXTERNAL",
        c"REAL",
        c"ENUMERATED",
        c"<ASN1 11>",
        c"UTF8STRING",
        c"<ASN1 13>",
        c"<ASN1 14>",
        c"<ASN1 15>",
        c"SEQUENCE",
        c"SET",
        c"NUMERICSTRING",
        c"PRINTABLESTRING",
        c"T61STRING",
        c"VIDEOTEXSTRING",
        c"IA5STRING",
        c"UTCTIME",
        c"GENERALIZEDTIME",
        c"GRAPHICSTRING",
        c"VISIBLESTRING",
        c"GENERALSTRING",
        c"UNIVERSALSTRING",
        c"<ASN1 29>",
        c"BMPSTRING",
    ];
    // V_ASN1_NEG_INTEGER and V_ASN1_NEG_ENUMERATED name their positive types.
    let tag = if tag == (V_ASN1_INTEGER | 0x100) || tag == (V_ASN1_ENUMERATED | 0x100) {
        tag & !0x100
    } else {
        tag
    };
    let name: Option<&&'static CStr> = usize::try_from(tag).ok().and_then(|t| NAMES.get(t));
    name.map_or(c"(unknown)", |n| *n)
}

/// The content octets OpenSSL encodes for an INTEGER's magnitude (`i2c_ibuf`): two's
/// complement, with a pad octet where the sign needs one; one zero octet for no magnitude.
pub fn integer_content(magnitude: &[u8], negative: bool) -> Vec<u8> {
    let Some(&first) = magnitude.first() else {
        return vec![0];
    };
    let (pad, pad_byte) = if !negative {
        (first > 127, 0u8)
    } else if first > 128 {
        (true, 0xff)
    } else if first == 128 {
        let rest_nonzero = magnitude.iter().skip(1).any(|&b| b != 0);
        (rest_nonzero, if rest_nonzero { 0xff } else { 0 })
    } else {
        (false, 0xff)
    };
    let mut out = Vec::with_capacity(magnitude.len().saturating_add(1));
    if pad {
        out.push(pad_byte);
    }
    // Two's complement of the magnitude when negative: invert and add one, from the end.
    let mut carry = u16::from(pad_byte & 1);
    let mut body: Vec<u8> = magnitude
        .iter()
        .rev()
        .map(|&b| {
            let sum = carry.wrapping_add(u16::from(b ^ pad_byte));
            carry = sum >> 8;
            u8::try_from(sum & 0xff).unwrap_or(0)
        })
        .collect();
    body.reverse();
    out.extend(body);
    out
}

/// The content octets OpenSSL encodes for a BIT STRING (`ossl_i2c_ASN1_BIT_STRING`): the
/// unused-bits octet (stored in `flags`, else from the lowest set bit), then the octets up to
/// the last nonzero one (all of them with a stored count), the unused bits cleared.
pub fn bit_string_content(octets: &[u8], flags: i64) -> Vec<u8> {
    let stored = flags & i64::from(ASN1_STRING_FLAG_BITS_LEFT) != 0;
    let (len, bits) = if octets.is_empty() {
        (0, 0)
    } else if stored {
        (octets.len(), u8::try_from(flags & 0x07).unwrap_or(0))
    } else {
        let len = octets
            .iter()
            .rposition(|&b| b != 0)
            .map_or(0, |i| i.saturating_add(1));
        let last = octets.get(len.wrapping_sub(1)).copied().unwrap_or(0);
        let bits = if len == 0 {
            0
        } else {
            u8::try_from(last.trailing_zeros().min(7)).unwrap_or(0)
        };
        (len, bits)
    };
    let mut out = vec![bits];
    out.extend(octets.iter().take(len));
    if len > 0
        && let Some(last) = out.last_mut()
    {
        *last &= 0xffu8.checked_shl(u32::from(bits)).unwrap_or(0);
    }
    out
}

/// What `i2d_ASN1_TYPE` encodes for an `ASN1_STRING` of type `string_type` placed in an
/// `ASN1_TYPE` (how `ASN1_STRFLGS_DUMP_DER` dumps a string), or `None` where OpenSSL would read
/// the string as another structure (BOOLEAN, OBJECT) or fail.
pub fn any_der(string_type: i32, data: &[u8], flags: i64) -> Option<Vec<u8>> {
    let (content, use_header, indefinite): (Vec<u8>, bool, bool) = match string_type {
        V_ASN1_OBJECT | V_ASN1_BOOLEAN => return None,
        V_ASN1_UNDEF => (Vec::new(), true, true),
        V_ASN1_NULL => (Vec::new(), true, false),
        V_ASN1_BIT_STRING => (bit_string_content(data, flags), true, false),
        V_ASN1_INTEGER | V_ASN1_ENUMERATED => (integer_content(data, false), true, false),
        V_ASN1_SEQUENCE | V_ASN1_SET | V_ASN1_OTHER => (data.to_vec(), false, false),
        _ => (data.to_vec(), true, false),
    };
    if !use_header {
        return Some(content);
    }
    let length = i32::try_from(content.len()).ok()?;
    let mut out = Vec::new();
    if indefinite {
        der::put_header(&mut out, 2, 0, string_type, 0);
        out.extend([0, 0]);
    } else {
        der::put_header(&mut out, 0, length, string_type, 0);
        out.extend(content);
    }
    Some(out)
}

/// The escape flags `ASN1_STRING_print_ex` keeps from its flags (`ESC_FLAGS`).
pub fn escape_flags(flags: u64) -> u16 {
    let mask = [
        ASN1_STRFLGS_ESC_2253,
        ASN1_STRFLGS_ESC_2254,
        ASN1_STRFLGS_ESC_QUOTE,
        ASN1_STRFLGS_ESC_CTRL,
        ASN1_STRFLGS_ESC_MSB,
    ]
    .iter()
    .fold(0u64, |m, &f| m | u64::try_from(f).unwrap_or(0));
    u16::try_from(flags & mask).unwrap_or(0)
}

/// Where the printer writes: each call is one of OpenSSL's writes; `false` stops the printer.
/// `None` only counts.
pub type Sink<'a> = Option<&'a mut dyn FnMut(&[u8]) -> bool>;

fn emit(sink: &mut Sink<'_>, octets: &[u8]) -> bool {
    match sink {
        Some(write) => write(octets),
        None => true,
    }
}

/// `do_esc_char`: writes `c` escaped as `flags` say; returns the characters written, or `None`
/// if a write failed. Sets `quotes` when the value must be quoted instead.
fn escape_char(
    c: u32,
    flags: u16,
    quotes: &mut Option<&mut bool>,
    sink: &mut Sink<'_>,
) -> Option<i32> {
    if c > 0xffff {
        return emit(sink, format!("\\W{c:08X}").as_bytes()).then_some(10);
    }
    if c > 0xff {
        return emit(sink, format!("\\U{c:04X}").as_bytes()).then_some(6);
    }
    let byte = u8::try_from(c).unwrap_or(0);
    let chflags = if byte > 0x7f {
        flags & flag16(ASN1_STRFLGS_ESC_MSB)
    } else {
        char_type(byte) & flags
    };
    let backslash_escape = flag16(ASN1_STRFLGS_ESC_2253)
        | flag16(CHARTYPE_FIRST_ESC_2253)
        | flag16(CHARTYPE_LAST_ESC_2253);
    if chflags & backslash_escape != 0 {
        if chflags & flag16(ASN1_STRFLGS_ESC_QUOTE) != 0 {
            if let Some(q) = quotes {
                **q = true;
            }
            return emit(sink, &[byte]).then_some(1);
        }
        return (emit(sink, b"\\") && emit(sink, &[byte])).then_some(2);
    }
    let hex_escape = flag16(ASN1_STRFLGS_ESC_CTRL)
        | flag16(ASN1_STRFLGS_ESC_MSB)
        | flag16(ASN1_STRFLGS_ESC_2254);
    if chflags & hex_escape != 0 {
        return emit(sink, format!("\\{byte:02X}").as_bytes()).then_some(3);
    }
    if byte == b'\\' && flags & escape_flags(u64::MAX) != 0 {
        return emit(sink, b"\\\\").then_some(2);
    }
    emit(sink, &[byte]).then_some(1)
}

/// Why the printer stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrintError {
    /// A write failed, or the text is malformed (no error raised).
    Failed,
    /// A UniversalString's length isn't a multiple of 4.
    InvalidUniversalLength,
    /// A BMPString's length isn't even.
    InvalidBmpLength,
}

/// `do_buf`: writes `data` as characters of `width` octets (0 for UTF-8; with `convert`, each
/// as UTF-8 octets), escaped. Returns the characters written.
fn print_buf(
    data: &[u8],
    width: i32,
    convert: bool,
    flags: u16,
    mut quotes: Option<&mut bool>,
    sink: &mut Sink<'_>,
) -> Result<i32, PrintError> {
    match width {
        4 if !data.len().is_multiple_of(4) => return Err(PrintError::InvalidUniversalLength),
        2 if !data.len().is_multiple_of(2) => return Err(PrintError::InvalidBmpLength),
        0..=2 | 4 => {}
        _ => return Err(PrintError::Failed),
    }
    let rfc2253 = flags & flag16(ASN1_STRFLGS_ESC_2253) != 0;
    let mut outlen: i32 = 0;
    let mut at = 0usize;
    while at < data.len() {
        let mut orflags = if at == 0 && rfc2253 {
            flag16(CHARTYPE_FIRST_ESC_2253)
        } else {
            0
        };
        let rest = data.get(at..).unwrap_or(&[]);
        let (c, used) = match width {
            0 => match utf8_get(rest) {
                Ok(Some(found)) => found,
                _ => return Err(PrintError::Failed),
            },
            w => {
                let w = usize::try_from(w).unwrap_or(1);
                let octets = rest.get(..w).unwrap_or(rest);
                (octets.iter().fold(0u32, |v, &b| (v << 8) | u32::from(b)), w)
            }
        };
        at = at.saturating_add(used);
        if at >= data.len() && rfc2253 {
            orflags = flag16(CHARTYPE_LAST_ESC_2253);
        }
        let mut add = |n: i32| outlen = outlen.saturating_add(n);
        if convert {
            let encoded = utf8_put(u64::from(c)).map_err(|_| PrintError::Failed)?;
            for byte in encoded {
                add(
                    escape_char(u32::from(byte), flags | orflags, &mut quotes, sink)
                        .ok_or(PrintError::Failed)?,
                );
            }
        } else {
            add(escape_char(c, flags | orflags, &mut quotes, sink).ok_or(PrintError::Failed)?);
        }
    }
    Ok(outlen)
}

/// Uppercase hex of each octet, as `do_hex_dump` writes it (one write per octet).
fn hex_dump(data: &[u8], sink: &mut Sink<'_>) -> Option<i32> {
    if sink.is_some() {
        for &b in data {
            if !emit(sink, format!("{b:02X}").as_bytes()) {
                return None;
            }
        }
    }
    i32::try_from(data.len()).ok().map(|n| n.wrapping_shl(1))
}

/// `do_print_ex`: prints a string of `string_type` holding `data` (with `string_flags`) as
/// `ASN1_STRING_print_ex` does with `lflags`. Returns the characters printed.
pub fn print_ex(
    data: &[u8],
    string_type: i32,
    string_flags: i64,
    lflags: u64,
    mut sink: Sink<'_>,
) -> Result<i32, PrintError> {
    let has = |flag: i32| lflags & u64::try_from(flag).unwrap_or(0) != 0;
    let has_l = |flag: u64| lflags & flag != 0;
    let flags = escape_flags(lflags);
    let mut outlen: i32 = 0;
    if has(ASN1_STRFLGS_SHOW_TYPE) {
        let name = tag_name(string_type).to_bytes();
        outlen = i32::try_from(name.len()).unwrap_or(0);
        if !emit(&mut sink, name) || !emit(&mut sink, b":") {
            return Err(PrintError::Failed);
        }
        outlen = outlen.saturating_add(1);
    }
    let width = if has_l(u64::try_from(ASN1_STRFLGS_DUMP_ALL).unwrap_or(0)) {
        -1
    } else if has(ASN1_STRFLGS_IGNORE_TYPE) {
        1
    } else {
        let width = if (1..31).contains(&string_type) {
            tag_width(string_type)
        } else {
            -1
        };
        if width == -1 && !has(ASN1_STRFLGS_DUMP_UNKNOWN) {
            1
        } else {
            width
        }
    };
    if width == -1 {
        if !emit(&mut sink, b"#") {
            return Err(PrintError::Failed);
        }
        let dumped = if has(ASN1_STRFLGS_DUMP_DER) {
            let der = any_der(string_type, data, string_flags).ok_or(PrintError::Failed)?;
            if der.is_empty() {
                return Err(PrintError::Failed);
            }
            hex_dump(&der, &mut sink)
        } else {
            hex_dump(data, &mut sink)
        };
        let len = dumped.ok_or(PrintError::Failed)?.saturating_add(1);
        if len < 0 || len > i32::MAX.saturating_sub(outlen) {
            return Err(PrintError::Failed);
        }
        return Ok(outlen.saturating_add(len));
    }
    let (width, convert) = if has(ASN1_STRFLGS_UTF8_CONVERT) {
        if width == 0 {
            (1, false)
        } else {
            (width, true)
        }
    } else {
        (width, false)
    };
    let mut quoted = false;
    let len = print_buf(data, width, convert, flags, Some(&mut quoted), &mut None)?;
    if len > i32::MAX.saturating_sub(2).saturating_sub(outlen) {
        return Err(PrintError::Failed);
    }
    outlen = outlen.saturating_add(len);
    if quoted {
        outlen = outlen.saturating_add(2);
    }
    if sink.is_none() {
        return Ok(outlen);
    }
    if quoted && !emit(&mut sink, b"\"") {
        return Err(PrintError::Failed);
    }
    print_buf(data, width, convert, flags, None, &mut sink)?;
    if quoted && !emit(&mut sink, b"\"") {
        return Err(PrintError::Failed);
    }
    Ok(outlen)
}

#[cfg(test)]
mod tests {
    use rustyssl_abi::V_ASN1_OCTET_STRING;

    use super::*;

    #[test]
    fn utf8_round_trips_and_errors() {
        for v in [0u32, 0x7f, 0x80, 0x7ff, 0x800, 0xffff, 0x1_0000, 0x10_ffff] {
            let encoded = utf8_put(u64::from(v)).unwrap();
            assert_eq!(utf8_get(&encoded), Ok(Some((v, encoded.len()))));
        }
        assert_eq!(utf8_put(0xd800), Err(-2));
        assert_eq!(utf8_put(0x11_0000), Err(-2));
        assert_eq!(utf8_get(&[0xc3]), Err(-1));
        assert_eq!(utf8_get(&[0xc3, 0x41]), Err(-3));
        assert_eq!(utf8_get(&[0xc1, 0x81]), Err(-4));
        assert_eq!(utf8_get(&[0xed, 0xa0, 0x80]), Err(-2));
        assert_eq!(utf8_get(&[0xff]), Err(-2));
        assert_eq!(utf8_get(&[]), Ok(None));
    }

    #[test]
    fn bmp_passwords() {
        assert_eq!(*asc_to_bmp(b"a\xe9"), [0, b'a', 0, 0xe9, 0, 0]);
        assert_eq!(*asc_to_bmp(b""), [0, 0]);
        // U+00E9 and U+1F600 (a surrogate pair).
        let utf8 = "\u{e9}\u{1f600}".as_bytes();
        let bmp = [0x00, 0xe9, 0xd8, 0x3d, 0xde, 0x00, 0, 0];
        assert_eq!(*utf8_to_bmp(utf8), bmp);
        assert_eq!(bmp_to_utf8(&bmp).unwrap(), [utf8, &[0]].concat());
        // Not UTF-8: each octet as it is.
        assert_eq!(utf8_to_bmp(b"\xe9a"), asc_to_bmp(b"\xe9a"));
        // No terminating unit: a zero octet is added.
        assert_eq!(bmp_to_utf8(&[0, b'a']).unwrap(), b"a\0");
        assert_eq!(bmp_to_utf8(&[]).unwrap(), b"\0");
        assert_eq!(bmp_to_asc(&[0, b'a', 0, 0]).unwrap(), b"a\0");
        assert_eq!(bmp_to_asc(&[0, b'a']).unwrap(), b"a\0");
        assert_eq!(bmp_to_asc(&[]).unwrap(), b"\0");
        assert_eq!(bmp_to_asc(&[0]), None);
        assert_eq!(bmp_to_utf8(&[0]), None);
        // A lone surrogate, high or low: the low octets.
        assert_eq!(
            bmp_to_utf8(&[0xd8, 0x3d, 0, b'a']).unwrap(),
            [0x3d, b'a', 0]
        );
        assert_eq!(bmp_to_utf8(&[0xdc, 0x00, 0xdc, 0x00]).unwrap(), [0, 0]);
    }

    #[test]
    fn the_char_table_is_charmap_pl() {
        // Spot checks against OpenSSL 3.5's generated charmap.h.
        assert_eq!(char_type(0), 1026);
        assert_eq!(char_type(b' '), 120);
        assert_eq!(char_type(b'"'), 1);
        assert_eq!(char_type(b'#'), 40);
        assert_eq!(char_type(b'*'), 33792);
        assert_eq!(char_type(b'+'), 25);
        assert_eq!(char_type(b'-'), 16400);
        assert_eq!(char_type(b'.'), 8208);
        assert_eq!(char_type(b'0'), 4112);
        assert_eq!(char_type(b';'), 9);
        assert_eq!(char_type(b'\\'), 1025);
        assert_eq!(char_type(127), 2);
    }

    #[test]
    fn integer_and_bit_string_content() {
        assert_eq!(integer_content(&[], false), [0]);
        assert_eq!(integer_content(&[0x80], false), [0, 0x80]);
        assert_eq!(integer_content(&[0x80], true), [0x80]);
        assert_eq!(integer_content(&[0x80, 0x01], true), [0xff, 0x7f, 0xff]);
        assert_eq!(integer_content(&[0x01], true), [0xff]);
        assert_eq!(integer_content(&[0x01, 0x00], true), [0xff, 0x00]);
        assert_eq!(bit_string_content(&[0x80, 0x00], 0), [7, 0x80]);
        assert_eq!(
            bit_string_content(&[0xff], i64::from(ASN1_STRING_FLAG_BITS_LEFT) | 3),
            [3, 0xf8]
        );
        assert_eq!(bit_string_content(&[], 0), [0]);
    }

    #[test]
    fn strings_typed_boolean_or_object_have_no_der() {
        // OpenSSL reads such a string as an ASN1_BOOLEAN or ASN1_OBJECT here (a heap address's
        // low octet, or memory past the struct); rustyssl declines to dump it.
        assert_eq!(any_der(V_ASN1_BOOLEAN, &[1], 0), None);
        assert_eq!(any_der(V_ASN1_OBJECT, &[0x2a], 0), None);
        assert_eq!(any_der(V_ASN1_NULL, &[], 0), Some(vec![5, 0]));
    }

    #[test]
    fn printing_escapes_as_openssl_does() {
        let print = |data: &[u8], t: i32, flags: u64| {
            let mut out = Vec::new();
            let mut sink = |b: &[u8]| {
                out.extend_from_slice(b);
                true
            };
            let n = print_ex(data, t, 0, flags, Some(&mut sink)).unwrap();
            (n, String::from_utf8(out).unwrap())
        };
        let rfc2253 = 0x1 | 0x2 | 0x4 | 0x10 | 0x100 | 0x200;
        assert_eq!(
            print(b" a,b ", V_ASN1_UTF8STRING, rfc2253),
            (8, "\\ a\\,b\\ ".to_owned())
        );
        assert_eq!(
            print(b"#x", V_ASN1_IA5STRING, rfc2253),
            (3, "\\#x".to_owned())
        );
        assert_eq!(
            print(b"a,b", V_ASN1_IA5STRING, 0x1 | 0x8),
            (5, "\"a,b\"".to_owned())
        );
        assert_eq!(
            print(&[0x01, 0x00], V_ASN1_BMPSTRING, 0),
            (6, "\\U0100".to_owned())
        );
        assert_eq!(
            print(b"\x01", V_ASN1_OCTET_STRING, 0x80),
            (3, "#01".to_owned())
        );
    }
}
