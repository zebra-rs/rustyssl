//! Fuzzes the hex codec through its C ABI: `OPENSSL_hexstr2buf_ex` on arbitrary text with an
//! arbitrary separator must agree with a model decoder, and what it decodes must come back the
//! same through `OPENSSL_buf2hexstr_ex`.

#![no_main]

use core::ffi::{c_char, c_int, c_uchar};
use core::ptr;
use std::ffi::CString;

use libfuzzer_sys::fuzz_target;
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn OPENSSL_hexstr2buf_ex(
        buf: *mut c_uchar,
        buf_n: usize,
        buflen: *mut usize,
        str: *const c_char,
        sep: c_char,
    ) -> c_int;
    fn OPENSSL_buf2hexstr_ex(
        str: *mut c_char,
        str_n: usize,
        strlength: *mut usize,
        buf: *const c_uchar,
        buflen: usize,
        sep: c_char,
    ) -> c_int;
    fn ERR_clear_error();
}

/// The model: skip the separator between pairs (a C `char`, so where `char` is signed one above
/// 0x7f never matches), decode pairs of hex digits.
fn model(text: &[u8], separator: c_char) -> Option<Vec<u8>> {
    let digit = |c: u8| char::from(c).to_digit(16).map(|d| d as u8);
    let mut out = Vec::new();
    let mut bytes = text.iter();
    while let Some(&high) = bytes.next() {
        if separator != 0 && c_int::from(high) == c_int::from(separator) {
            continue;
        }
        let low = *bytes.next()?;
        out.push(digit(high)? << 4 | digit(low)?);
    }
    Some(out)
}

fuzz_target!(|data: &[u8]| {
    let Some((&separator, text)) = data.split_first() else { return };
    let separator = c_char::from_ne_bytes([separator]);
    let text: Vec<u8> = text.iter().copied().take_while(|b| *b != 0).collect();
    let c_text = CString::new(text.clone()).unwrap();
    let mut buf = vec![0u8; text.len() / 2 + 1];
    let mut len = 0usize;
    // SAFETY: the buffer and length are valid; the text is NUL-terminated.
    let ok = unsafe { OPENSSL_hexstr2buf_ex(buf.as_mut_ptr(), buf.len(), &mut len, c_text.as_ptr(), separator) };
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
    let expected = model(&text, separator);
    assert_eq!(ok == 1, expected.is_some());
    let Some(expected) = expected else { return };
    assert_eq!(&buf[..len], &expected[..]);

    let mut needed = 0usize;
    // SAFETY: a null output only computes the length.
    let sized = unsafe { OPENSSL_buf2hexstr_ex(ptr::null_mut(), 0, &mut needed, buf.as_ptr(), len, 0) };
    assert_eq!(sized, 1);
    let mut hex = vec![0 as c_char; needed];
    // SAFETY: the output holds `needed` bytes.
    let written = unsafe { OPENSSL_buf2hexstr_ex(hex.as_mut_ptr(), needed, &mut needed, buf.as_ptr(), len, 0) };
    assert_eq!(written, 1);
    let mut again = vec![0u8; len + 1];
    let mut again_len = 0usize;
    // SAFETY: as above; the hex is NUL-terminated.
    let decoded = unsafe { OPENSSL_hexstr2buf_ex(again.as_mut_ptr(), again.len(), &mut again_len, hex.as_ptr(), 0) };
    assert_eq!(decoded, 1);
    assert_eq!(&again[..again_len], &expected[..]);
});
