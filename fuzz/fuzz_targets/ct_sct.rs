//! Fuzzes certificate transparency's parsers on untrusted input: the input decoded as a TLS
//! SCT list (`o2i_SCT_LIST`), as a DER one (`d2i_SCT_LIST`), and as one SCT (`o2i_SCT`); what
//! decodes is encoded again (a list's encoding decoding to the same encoding) and printed.
//! Nothing may crash or read out of bounds (ASan).

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{BIO, BIO_METHOD, CTLOG_STORE, SCT, stack_st_SCT};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn o2i_SCT_LIST(a: *mut *mut stack_st_SCT, pp: *mut *const c_uchar, len: usize) -> *mut stack_st_SCT;
    fn d2i_SCT_LIST(a: *mut *mut stack_st_SCT, pp: *mut *const c_uchar, len: c_long) -> *mut stack_st_SCT;
    fn i2o_SCT_LIST(a: *const stack_st_SCT, pp: *mut *mut c_uchar) -> c_int;
    fn SCT_LIST_free(a: *mut stack_st_SCT);
    fn SCT_LIST_print(a: *const stack_st_SCT, out: *mut BIO, indent: c_int, sep: *const c_char, store: *const CTLOG_STORE);
    fn o2i_SCT(psct: *mut *mut SCT, pp: *mut *const c_uchar, len: usize) -> *mut SCT;
    fn i2o_SCT(sct: *const SCT, out: *mut *mut c_uchar) -> c_int;
    fn SCT_print(sct: *const SCT, out: *mut BIO, indent: c_int, store: *const CTLOG_STORE);
    fn SCT_free(sct: *mut SCT);
    fn CRYPTO_free(p: *mut c_void, file: *const c_char, line: c_int);
    fn BIO_new(m: *const BIO_METHOD) -> *mut BIO;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn ERR_clear_error();
}

fuzz_target!(|data: &[u8]| {
    // SAFETY: the input's octets; lists, SCTs, encodings, and a BIO made and freed here.
    unsafe {
        let b = BIO_new(BIO_s_mem());
        let mut p = data.as_ptr();
        let l = o2i_SCT_LIST(ptr::null_mut(), &mut p, data.len());
        if !l.is_null() {
            let mut out = ptr::null_mut();
            let n = i2o_SCT_LIST(l, &mut out);
            if let Ok(n) = usize::try_from(n) {
                let mut q = out.cast_const();
                let again = o2i_SCT_LIST(ptr::null_mut(), &mut q, n);
                assert!(!again.is_null());
                let mut out2 = ptr::null_mut();
                let n2 = i2o_SCT_LIST(again, &mut out2);
                assert_eq!(usize::try_from(n2).ok(), Some(n));
                assert_eq!(core::slice::from_raw_parts(out2, n), core::slice::from_raw_parts(out, n));
                CRYPTO_free(out2.cast(), ptr::null(), 0);
                SCT_LIST_free(again);
            }
            CRYPTO_free(out.cast(), ptr::null(), 0);
            SCT_LIST_print(l, b, 2, c"\n".as_ptr(), ptr::null());
            SCT_LIST_free(l);
        }
        let mut p = data.as_ptr();
        let len = c_long::try_from(data.len()).unwrap_or(0);
        let l = d2i_SCT_LIST(ptr::null_mut(), &mut p, len);
        SCT_LIST_free(l);
        let mut p = data.as_ptr();
        let s = o2i_SCT(ptr::null_mut(), &mut p, data.len());
        if !s.is_null() {
            let mut out = ptr::null_mut();
            i2o_SCT(s, &mut out);
            CRYPTO_free(out.cast(), ptr::null(), 0);
            SCT_print(s, b, 0, ptr::null());
            SCT_free(s);
        }
        BIO_free(b);
        ERR_clear_error();
    }
});
