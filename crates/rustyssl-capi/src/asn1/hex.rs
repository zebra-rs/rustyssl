//! Strings as hex text (`i2a_ASN1_STRING`, `a2i_ASN1_STRING(3)`) and octets printed for key
//! components (`ASN1_buf_print`), as OpenSSL's `f_string.c` and `t_pkey.c` do.
//!
//! `a2i_ASN1_STRING` reads lines into the caller's buffer as OpenSSL does, quirks included: a
//! line is cut at its last character that isn't a hex digit (looking no further left than the
//! second character), and a trailing backslash, which continues the string on the next line,
//! takes the character before it along.

use core::ffi::{c_char, c_int};
use core::ptr;

use rustyssl_abi::{
    ASN1_R_NON_HEX_CHARACTERS, ASN1_R_ODD_NUMBER_OF_CHARS, ASN1_R_SHORT_LINE, ASN1_STRING, BIO,
    ERR_LIB_ASN1,
};

use crate::bio;
use crate::bio::print::BIO_printf;
use crate::err;
use crate::ffi::ffi_export;
use crate::mem;

/// Octets on a line of `ASN1_buf_print` (`ASN1_BUF_PRINT_WIDTH`, private to `t_pkey.c`).
const BUF_PRINT_WIDTH: usize = 15;

/// The most indentation `ASN1_buf_print` writes (`ASN1_PRINT_MAX_INDENT`, private to
/// `t_pkey.c`).
const PRINT_MAX_INDENT: c_int = 128;

/// Uppercase hex digits, as `ossl_to_hex` writes them.
const HEX: &[u8; 16] = b"0123456789ABCDEF";

ffi_export! {
    /// Writes `a`'s octets to `bp` as uppercase hex, a backslash and newline after every 35
    /// octets, or `0` for none. Returns the characters written, 0 for NULL `a`, or -1 if a
    /// write fails. `type` is unused.
    ///
    /// # Safety
    /// `bp` is NULL or a live BIO; `a` is NULL or a live string.
    pub unsafe extern "C" fn i2a_ASN1_STRING(bp: *mut BIO, a: *const ASN1_STRING, type_: c_int) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        let _ = type_;
        if a.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let a = unsafe { &*a };
        let write = |data: &[u8]| {
            let n = c_int::try_from(data.len()).unwrap_or(0);
            // SAFETY: the caller's BIO; `data` holds `n` octets.
            let written = unsafe { bio::BIO_write(bp, data.as_ptr().cast(), n) };
            written == n
        };
        if a.length == 0 {
            return if write(b"0") { 1 } else { -1 };
        }
        let octets = match usize::try_from(a.length) {
            // SAFETY: a string's data holds its length.
            Ok(n) if !a.data.is_null() => unsafe { core::slice::from_raw_parts(a.data, n) },
            _ => &[],
        };
        let mut n: c_int = 0;
        for (i, &octet) in octets.iter().enumerate() {
            if i != 0 && i % 35 == 0 {
                if !write(b"\\\n") {
                    return -1;
                }
                n = n.wrapping_add(2);
            }
            let digit = |v: u8| HEX.get(usize::from(v)).copied().unwrap_or(b'0');
            if !write(&[digit(octet >> 4), digit(octet & 0xf)]) {
                return -1;
            }
            n = n.wrapping_add(2);
        }
        n
    }
}

/// The hex digit's value, or `None`.
fn hex_value(c: u8) -> Option<u8> {
    char::from(c)
        .to_digit(16)
        .and_then(|d| u8::try_from(d).ok())
}

/// The lines of `a2i_ASN1_STRING`: the octets, or the error reason.
///
/// # Safety
/// `bp` is NULL or a live BIO; `buf` is valid for `size` octets.
unsafe fn read_lines(
    bp: *mut BIO,
    buf: *mut c_char,
    size: c_int,
) -> Result<Option<Vec<u8>>, c_int> {
    let line_at = |i: usize| -> *mut u8 { buf.cast::<u8>().wrapping_add(i) };
    // SAFETY: the caller's guarantee.
    let read_line = || unsafe { bio::BIO_gets(bp, buf, size) };
    let mut octets: Vec<u8> = Vec::new();
    let mut first = true;
    let mut got = read_line();
    loop {
        if got < 1 {
            return if first {
                Ok(None)
            } else {
                Err(ASN1_R_SHORT_LINE)
            };
        }
        first = false;
        let mut i = usize::try_from(got).unwrap_or(0);
        // SAFETY: `BIO_gets` wrote `i` characters into `buf`; reads stay below `i`.
        let at = |k: usize| unsafe { line_at(k).read() };
        // SAFETY: as above; writes stay within them.
        let clear = |k: usize| unsafe { line_at(k).write(0) };
        if at(i.wrapping_sub(1)) == b'\n' {
            i = i.wrapping_sub(1);
            clear(i);
        }
        if i == 0 {
            return Err(ASN1_R_SHORT_LINE);
        }
        if at(i.wrapping_sub(1)) == b'\r' {
            i = i.wrapping_sub(1);
            clear(i);
        }
        if i == 0 {
            return Err(ASN1_R_SHORT_LINE);
        }
        let again = at(i.wrapping_sub(1)) == b'\\';
        if let Some(end) = (1..i).rev().find(|&j| !at(j).is_ascii_hexdigit()) {
            i = end;
        }
        clear(i);
        if i < 2 {
            return Err(ASN1_R_SHORT_LINE);
        }
        // The character before a trailing backslash goes too, as in OpenSSL.
        let count = i.wrapping_sub(usize::from(again));
        if count % 2 != 0 {
            return Err(ASN1_R_ODD_NUMBER_OF_CHARS);
        }
        for pair in 0..count / 2 {
            let k = pair.wrapping_mul(2);
            let (Some(hi), Some(lo)) = (hex_value(at(k)), hex_value(at(k.wrapping_add(1)))) else {
                return Err(ASN1_R_NON_HEX_CHARACTERS);
            };
            octets.push((hi << 4) | lo);
        }
        if !again {
            return Ok(Some(octets));
        }
        got = read_line();
    }
}

ffi_export! {
    /// Reads hex (as `i2a_ASN1_STRING` writes it) from `bp`, a line of at most `size`
    /// characters at a time into `buf`, into `bs`'s data and length (its earlier data isn't
    /// freed, as in OpenSSL). Returns 1, or 0 with an error (`ASN1_R_SHORT_LINE`,
    /// `ASN1_R_ODD_NUMBER_OF_CHARS`, `ASN1_R_NON_HEX_CHARACTERS`).
    ///
    /// Unlike OpenSSL, NULL `bs` or `buf` returns 0 rather than crashing (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `bp` is NULL or a live BIO; `bs` is NULL or a live string; `buf` is NULL or valid for
    /// `size` octets.
    pub unsafe extern "C" fn a2i_ASN1_STRING(bp: *mut BIO, bs: *mut ASN1_STRING, buf: *mut c_char, size: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        if bs.is_null() || buf.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let octets = match unsafe { read_lines(bp, buf, size) } {
            Ok(octets) => octets,
            Err(reason) => {
                err::raise(ERR_LIB_ASN1, reason, "a2i_ASN1_STRING");
                return 0;
            }
        };
        let (data, length): (*mut u8, usize) = match octets {
            None => (ptr::null_mut(), 0),
            Some(octets) => {
                // OpenSSL's block has room for twice the first line; the octets fill the start.
                let data: *mut u8 = mem::alloc(octets.len().max(1)).cast();
                if data.is_null() {
                    return 0;
                }
                // SAFETY: room for the octets.
                unsafe { ptr::copy_nonoverlapping(octets.as_ptr(), data, octets.len()) };
                (data, octets.len())
            }
        };
        // SAFETY: the caller's string.
        let string = unsafe { &mut *bs };
        string.length = c_int::try_from(length).unwrap_or(c_int::MAX);
        string.data = data;
        1
    }
}

ffi_export! {
    /// Prints `buflen` octets of `buf` to `bp` as lowercase hex separated by colons, 15 a line,
    /// each line indented by `indent` (at most 128), and a newline. Returns 1, or 0.
    ///
    /// # Safety
    /// `bp` is NULL or a live BIO; `buf` holds `buflen` octets.
    pub unsafe extern "C" fn ASN1_buf_print(bp: *mut BIO, buf: *const u8, buflen: usize, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        let octets = if buflen == 0 || buf.is_null() {
            &[][..]
        } else {
            // SAFETY: the caller's guarantee.
            unsafe { core::slice::from_raw_parts(buf, buflen) }
        };
        for (i, &octet) in octets.iter().enumerate() {
            if i % BUF_PRINT_WIDTH == 0 {
                // SAFETY: the caller's BIO; a string.
                if i > 0 && unsafe { bio::BIO_puts(bp, c"\n".as_ptr()) } <= 0 {
                    return 0;
                }
                // SAFETY: as above.
                if unsafe { bio::BIO_indent(bp, indent, PRINT_MAX_INDENT) } == 0 {
                    return 0;
                }
            }
            let sep = if i == buflen.wrapping_sub(1) { c"" } else { c":" };
            // SAFETY: as above; the format takes an int and a string.
            if unsafe { BIO_printf(bp, c"%02x%s".as_ptr(), c_int::from(octet), sep.as_ptr()) } <= 0 {
                return 0;
            }
        }
        // SAFETY: as above.
        if unsafe { bio::BIO_write(bp, c"\n".as_ptr().cast(), 1) } <= 0 {
            return 0;
        }
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_arguments_are_safe() {
        let mut buf = [0 as c_char; 8];
        // SAFETY: NULL is refused before any read.
        let r = unsafe { a2i_ASN1_STRING(ptr::null_mut(), ptr::null_mut(), buf.as_mut_ptr(), 8) };
        assert_eq!(r, 0);
        let s = crate::asn1::string::type_new(rustyssl_abi::V_ASN1_OCTET_STRING);
        // SAFETY: as above.
        let r = unsafe { a2i_ASN1_STRING(ptr::null_mut(), s, ptr::null_mut(), 8) };
        assert_eq!(r, 0);
        // SAFETY: the string made here.
        unsafe { crate::asn1::string::ASN1_STRING_free(s) };
        // SAFETY: NULL writes nothing.
        let r = unsafe { i2a_ASN1_STRING(ptr::null_mut(), ptr::null(), 0) };
        assert_eq!(r, 0);
    }
}
