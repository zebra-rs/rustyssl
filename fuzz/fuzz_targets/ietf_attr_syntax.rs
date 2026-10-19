//! Fuzzes RFC 5755 IetfAttrSyntax decoding on untrusted input: d2i_OSSL_IETF_ATTR_SYNTAX
//! (which refuses values of mixed types), then everything that reads one: the re-encoding, the
//! policy authority, each value, an added value, and the print into a memory BIO. Nothing may
//! crash or read out of bounds (ASan).

#![no_main]

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{BIO, BIO_METHOD, GENERAL_NAMES, OSSL_IETF_ATTR_SYNTAX};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn d2i_OSSL_IETF_ATTR_SYNTAX(a: *mut *mut OSSL_IETF_ATTR_SYNTAX, pp: *mut *const c_uchar, len: c_long) -> *mut OSSL_IETF_ATTR_SYNTAX;
    fn i2d_OSSL_IETF_ATTR_SYNTAX(a: *const OSSL_IETF_ATTR_SYNTAX, out: *mut *mut c_uchar) -> c_int;
    fn OSSL_IETF_ATTR_SYNTAX_free(a: *mut OSSL_IETF_ATTR_SYNTAX);
    fn OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority(a: *const OSSL_IETF_ATTR_SYNTAX) -> *const GENERAL_NAMES;
    fn OSSL_IETF_ATTR_SYNTAX_get_value_num(a: *const OSSL_IETF_ATTR_SYNTAX) -> c_int;
    fn OSSL_IETF_ATTR_SYNTAX_get0_value(a: *const OSSL_IETF_ATTR_SYNTAX, ind: c_int, t: *mut c_int) -> *mut c_void;
    fn OSSL_IETF_ATTR_SYNTAX_add1_value(a: *mut OSSL_IETF_ATTR_SYNTAX, t: c_int, data: *mut c_void) -> c_int;
    fn OSSL_IETF_ATTR_SYNTAX_print(bp: *mut BIO, a: *mut OSSL_IETF_ATTR_SYNTAX, indent: c_int) -> c_int;
    fn ASN1_OCTET_STRING_new() -> *mut c_void;
    fn ASN1_OCTET_STRING_free(a: *mut c_void);
    fn BIO_new(m: *const BIO_METHOD) -> *mut BIO;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn CRYPTO_free(p: *mut c_void, file: *const core::ffi::c_char, line: c_int);
    fn ERR_clear_error();
}

fuzz_target!(|data: &[u8]| {
    let Ok(len) = c_long::try_from(data.len()) else { return };
    // SAFETY: the input, read within its length; the structures, BIO and encodings made here,
    // freed.
    unsafe {
        let mut p = data.as_ptr();
        let a = d2i_OSSL_IETF_ATTR_SYNTAX(ptr::null_mut(), &mut p, len);
        if a.is_null() {
            ERR_clear_error();
            return;
        }
        let mut der = ptr::null_mut();
        if i2d_OSSL_IETF_ATTR_SYNTAX(a, &mut der) > 0 {
            CRYPTO_free(der.cast(), c"".as_ptr(), 0);
        }
        OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority(a);
        let n = OSSL_IETF_ATTR_SYNTAX_get_value_num(a);
        for i in -1..=n {
            let mut t = 0;
            OSSL_IETF_ATTR_SYNTAX_get0_value(a, i, &mut t);
        }
        // An octet string: kept when the decoded type is octets, the caller's otherwise.
        let o = ASN1_OCTET_STRING_new();
        if OSSL_IETF_ATTR_SYNTAX_add1_value(a, rustyssl_abi::OSSL_IETFAS_OCTETS, o) != 1 {
            ASN1_OCTET_STRING_free(o);
        }
        let b = BIO_new(BIO_s_mem());
        for indent in [0, 3, -2] {
            OSSL_IETF_ATTR_SYNTAX_print(b, a, indent);
        }
        BIO_free(b);
        OSSL_IETF_ATTR_SYNTAX_free(a);
        ERR_clear_error();
    }
});
