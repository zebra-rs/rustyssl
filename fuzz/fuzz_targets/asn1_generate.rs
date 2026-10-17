//! Fuzzes `ASN1_generate_v3`'s string language: the input (as a C string) generates a value
//! without a configuration, which is then encoded. Nothing may crash or read out of bounds
//! (ASan).

#![no_main]

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{ASN1_TYPE, X509V3_CTX};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn ASN1_generate_v3(str: *const c_char, cnf: *mut X509V3_CTX) -> *mut ASN1_TYPE;
    fn i2d_ASN1_TYPE(a: *const ASN1_TYPE, out: *mut *mut c_uchar) -> c_int;
    fn ASN1_TYPE_free(a: *mut ASN1_TYPE);
    fn CRYPTO_free(p: *mut c_void, file: *const c_char, line: c_int);
    fn ERR_clear_error();
}

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::ffi::CString::new(data) else { return };
    // SAFETY: a C string; a value and its encoding made and freed here.
    unsafe {
        let t = ASN1_generate_v3(s.as_ptr(), ptr::null_mut());
        if !t.is_null() {
            let mut der = ptr::null_mut();
            i2d_ASN1_TYPE(t, &mut der);
            CRYPTO_free(der.cast(), ptr::null(), 0);
            ASN1_TYPE_free(t);
        }
        ERR_clear_error();
    }
});
