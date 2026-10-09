//! Fuzzes the time parser through the C ABI: arbitrary octets as a UTCTIME or GENERALIZEDTIME,
//! strict (`ASN1_STRING_FLAG_X509_TIME`) or not. A time that parses must normalize to one that
//! parses to the same date and time; `ASN1_TIME_compare` must agree with `ASN1_TIME_diff`; and
//! printing must not fail on it.

#![no_main]

use core::ffi::{c_int, c_long, c_void};

use libfuzzer_sys::fuzz_target;
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

#[repr(C)]
struct AsnString {
    length: c_int,
    type_: c_int,
    data: *mut u8,
    flags: c_long,
}

#[repr(C)]
struct Bio {
    _opaque: [u8; 0],
}

unsafe extern "C" {
    fn BIO_s_mem() -> *const c_void;
    fn BIO_new(method: *const c_void) -> *mut Bio;
    fn BIO_free(b: *mut Bio) -> c_int;
    fn ASN1_STRING_type_new(type_: c_int) -> *mut AsnString;
    fn ASN1_STRING_set(s: *mut AsnString, data: *const c_void, len: c_int) -> c_int;
    fn ASN1_STRING_dup(s: *const AsnString) -> *mut AsnString;
    fn ASN1_STRING_free(s: *mut AsnString);
    fn ASN1_TIME_to_tm(s: *const AsnString, tm: *mut libc::tm) -> c_int;
    fn ASN1_TIME_normalize(s: *mut AsnString) -> c_int;
    fn ASN1_TIME_diff(pday: *mut c_int, psec: *mut c_int, from: *const AsnString, to: *const AsnString) -> c_int;
    fn ASN1_TIME_compare(a: *const AsnString, b: *const AsnString) -> c_int;
    fn ASN1_TIME_print_ex(bp: *mut Bio, s: *const AsnString, flags: core::ffi::c_ulong) -> c_int;
    fn ASN1_TIME_set_string(s: *mut AsnString, text: *const core::ffi::c_char) -> c_int;
    fn ERR_clear_error();
}

fn fields(t: &libc::tm) -> [c_int; 6] {
    [t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec]
}

fuzz_target!(|input: &[u8]| {
    let Some((&selector, data)) = input.split_first() else {
        return;
    };
    let kind = if selector & 1 == 0 { 23 } else { 24 };
    // SAFETY: new strings, freed below; the input holds its length.
    unsafe {
        let s = ASN1_STRING_type_new(kind);
        ASN1_STRING_set(s, data.as_ptr().cast(), c_int::try_from(data.len()).unwrap());
        if selector & 2 != 0 {
            (*s).flags = 0x100;
        }
        let mut tm: libc::tm = core::mem::zeroed();
        if ASN1_TIME_to_tm(s, &mut tm) == 1 {
            let n = ASN1_STRING_dup(s);
            assert_eq!(ASN1_TIME_normalize(n), 1, "a valid time normalizes");
            let mut again: libc::tm = core::mem::zeroed();
            assert_eq!(ASN1_TIME_to_tm(n, &mut again), 1);
            assert_eq!(fields(&tm), fields(&again));
            let fixed = ASN1_STRING_type_new(24);
            ASN1_TIME_set_string(fixed, c"20240229123456Z".as_ptr());
            let (mut days, mut secs) = (0, 0);
            assert_eq!(ASN1_TIME_diff(&mut days, &mut secs, fixed, s), 1);
            let sign = if days > 0 || secs > 0 { 1 } else if days < 0 || secs < 0 { -1 } else { 0 };
            assert_eq!(ASN1_TIME_compare(s, fixed), sign);
            let bio = BIO_new(BIO_s_mem());
            assert_eq!(ASN1_TIME_print_ex(bio, s, 0), 1);
            assert_eq!(ASN1_TIME_print_ex(bio, s, 1), 1);
            BIO_free(bio);
            ASN1_STRING_free(fixed);
            ASN1_STRING_free(n);
        }
        ASN1_STRING_free(s);
        ERR_clear_error();
    }
});
