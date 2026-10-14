//! Fuzzes the PKCS #12 password strings through the C ABI: arbitrary octets as big-endian UTF-16
//! (`OPENSSL_uni2utf8`, `OPENSSL_uni2asc`, which read friendly names from PKCS #12 files) and as
//! a password (`OPENSSL_utf82uni`, `OPENSSL_asc2uni`). UTF-8 must come back the same, and as
//! the standard library encodes it in UTF-16; any octets must come back from `asc2uni`.

#![no_main]

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn OPENSSL_asc2uni(asc: *const c_char, asclen: c_int, uni: *mut *mut c_uchar, unilen: *mut c_int) -> *mut c_uchar;
    fn OPENSSL_utf82uni(asc: *const c_char, asclen: c_int, uni: *mut *mut c_uchar, unilen: *mut c_int) -> *mut c_uchar;
    fn OPENSSL_uni2asc(uni: *const c_uchar, unilen: c_int) -> *mut c_char;
    fn OPENSSL_uni2utf8(uni: *const c_uchar, unilen: c_int) -> *mut c_char;
    fn CRYPTO_free(p: *mut c_void, file: *const c_char, line: c_int);
}

/// Takes `len` octets of a C result and frees it.
fn take(p: *mut c_uchar, len: usize) -> Vec<u8> {
    assert!(!p.is_null());
    // SAFETY: a live block of at least `len` octets, freed once.
    unsafe {
        let v = std::slice::from_raw_parts(p, len).to_vec();
        CRYPTO_free(p.cast(), c"fuzz".as_ptr(), 0);
        v
    }
}

/// A C string result up to and including its NUL, freed.
fn take_string(p: *mut c_char) -> Vec<u8> {
    assert!(!p.is_null());
    // SAFETY: a live C string.
    let len = unsafe { core::ffi::CStr::from_ptr(p) }.count_bytes() + 1;
    take(p.cast(), len)
}

fuzz_target!(|data: &[u8]| {
    let Ok(len) = c_int::try_from(data.len()) else {
        return;
    };
    // UTF-16 in: NULL exactly for an odd length.
    // SAFETY: `data` holds `len` octets, here and below.
    let utf8 = unsafe { OPENSSL_uni2utf8(data.as_ptr(), len) };
    // SAFETY: as above.
    let asc = unsafe { OPENSSL_uni2asc(data.as_ptr(), len) };
    assert_eq!(utf8.is_null(), data.len() % 2 == 1);
    assert_eq!(asc.is_null(), data.len() % 2 == 1);
    if !utf8.is_null() {
        take_string(utf8);
        take_string(asc);
    }

    // A password in, octet by octet, and back.
    let mut n: c_int = 0;
    // SAFETY: as above; `n` is local.
    let uni = unsafe { OPENSSL_asc2uni(data.as_ptr().cast(), len, ptr::null_mut(), &mut n) };
    let uni = take(uni, usize::try_from(n).unwrap());
    assert_eq!(uni.len(), data.len() * 2 + 2);
    if !data.contains(&0) {
        // SAFETY: `uni` holds `n` octets.
        let back = take_string(unsafe { OPENSSL_uni2asc(uni.as_ptr(), n) });
        assert_eq!(back, [data, &[0]].concat());
    }

    // UTF-8 in: as the standard library encodes it, and back.
    // SAFETY: as above.
    let uni = unsafe { OPENSSL_utf82uni(data.as_ptr().cast(), len, ptr::null_mut(), &mut n) };
    let uni = take(uni, usize::try_from(n).unwrap());
    if let Ok(s) = core::str::from_utf8(data) {
        let expected: Vec<u8> = s.encode_utf16().chain([0]).flat_map(u16::to_be_bytes).collect();
        assert_eq!(uni, expected);
        if !data.contains(&0) {
            // SAFETY: `uni` holds `n` octets.
            let back = take_string(unsafe { OPENSSL_uni2utf8(uni.as_ptr(), n) });
            assert_eq!(back, [data, &[0]].concat());
        }
    }
});
