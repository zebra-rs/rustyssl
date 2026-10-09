//! Fuzzes character strings through the C ABI: arbitrary octets as a string of an arbitrary
//! type, printed with arbitrary `ASN1_STRFLGS_*` flags by `ASN1_STRING_print_ex` (the count it
//! returns for no BIO must be what it writes to one), and converted by `ASN1_mbstring_ncopy`
//! from each input form; a conversion's result must come back the same through
//! `ASN1_STRING_to_UTF8` and `ASN1_mbstring_copy` from UTF-8 to its type.

#![no_main]

use core::ffi::{c_int, c_long, c_ulong, c_void};
use core::ptr;

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
    fn BIO_ctrl(b: *mut Bio, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    fn ASN1_STRING_type_new(type_: c_int) -> *mut AsnString;
    fn ASN1_STRING_set(s: *mut AsnString, data: *const c_void, len: c_int) -> c_int;
    fn ASN1_STRING_free(s: *mut AsnString);
    fn ASN1_STRING_print_ex(out: *mut Bio, s: *const AsnString, flags: c_ulong) -> c_int;
    fn ASN1_mbstring_ncopy(out: *mut *mut AsnString, input: *const u8, len: c_int, inform: c_int, mask: c_ulong, min: c_long, max: c_long) -> c_int;
    fn ASN1_mbstring_copy(out: *mut *mut AsnString, input: *const u8, len: c_int, inform: c_int, mask: c_ulong) -> c_int;
    fn ASN1_STRING_to_UTF8(out: *mut *mut u8, s: *const AsnString) -> c_int;
    fn ASN1_tag2bit(tag: c_int) -> c_ulong;
    fn CRYPTO_free(p: *mut c_void, file: *const i8, line: c_int);
    fn ERR_clear_error();
}

const BIO_CTRL_INFO: c_int = 3;
const MBSTRING_FLAG: c_int = 0x1000;
const FORMS: [c_int; 4] = [MBSTRING_FLAG, MBSTRING_FLAG | 1, MBSTRING_FLAG | 2, MBSTRING_FLAG | 4];

fn octets_of(s: *const AsnString) -> Vec<u8> {
    // SAFETY: a live string.
    unsafe {
        let s = &*s;
        if s.data.is_null() || s.length <= 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(s.data, usize::try_from(s.length).unwrap()).to_vec()
        }
    }
}

fuzz_target!(|input: &[u8]| {
    let Some((head, data)) = input.split_at_checked(5) else {
        return;
    };
    let kind = c_int::from(head[0] % 34) - 2;
    let flags = c_ulong::from(u16::from_le_bytes([head[1], head[2]]) & 0x07ff);
    let mask = c_ulong::from(u32::from_le_bytes([head[3], head[4], 0, 0])) & 0x2_3f3f;
    let len = c_int::try_from(data.len()).unwrap();

    // Printing: the count for no BIO is what a BIO gets.
    // SAFETY: a new string, given the input; a memory BIO; both freed below.
    unsafe {
        let s = ASN1_STRING_type_new(kind);
        ASN1_STRING_set(s, data.as_ptr().cast(), len);
        let counted = ASN1_STRING_print_ex(ptr::null_mut(), s, flags);
        let bio = BIO_new(BIO_s_mem());
        let written = ASN1_STRING_print_ex(bio, s, flags);
        let mut out: *mut i8 = ptr::null_mut();
        let n = BIO_ctrl(bio, BIO_CTRL_INFO, 0, (&raw mut out).cast());
        assert_eq!(counted, written);
        if written >= 0 {
            assert_eq!(c_long::from(written), n, "the count is the characters written");
        }
        BIO_free(bio);
        ASN1_STRING_free(s);
    }

    // Converting from each form, then back through UTF-8.
    for form in FORMS {
        let mut out: *mut AsnString = ptr::null_mut();
        // SAFETY: the input holds `len` octets; `out` is local.
        let t = unsafe { ASN1_mbstring_ncopy(&mut out, data.as_ptr(), len, form, mask, 0, 0) };
        if t < 0 {
            assert!(out.is_null());
            continue;
        }
        let converted = octets_of(out);
        let mut utf8: *mut u8 = ptr::null_mut();
        // SAFETY: a live string; `utf8` is local.
        let n = unsafe { ASN1_STRING_to_UTF8(&mut utf8, out) };
        if n >= 0 {
            let mut back: *mut AsnString = ptr::null_mut();
            // SAFETY: `utf8` holds `n` octets; `back` is local.
            let t2 = unsafe { ASN1_mbstring_copy(&mut back, utf8, n, MBSTRING_FLAG, ASN1_tag2bit(t)) };
            if t2 == t {
                assert_eq!(octets_of(back), converted, "type {t}");
            }
            // SAFETY: made above.
            unsafe {
                ASN1_STRING_free(back);
                CRYPTO_free(utf8.cast(), c"fuzz".as_ptr(), 0);
            }
        }
        // SAFETY: made above.
        unsafe { ASN1_STRING_free(out) };
    }
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
