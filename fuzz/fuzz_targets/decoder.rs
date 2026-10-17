//! Fuzzes the decoder framework's walk with the default provider's structural decoders (PEM to
//! DER with traditional DEK-Info encryption, SubjectPublicKeyInfo to its key type's,
//! EncryptedPrivateKeyInfo), which key files bring from untrusted sources, under each selection
//! and input structure, without a passphrase. Nothing may crash or read out of bounds (ASan),
//! and what a decoder passes on must lie within its parameters.

#![no_main]

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{
    OSSL_DECODER, OSSL_DECODER_CTX, OSSL_DECODER_INSTANCE, OSSL_LIB_CTX, OSSL_PARAM,
    OSSL_PARAM_OCTET_STRING,
};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

type Construct =
    unsafe extern "C" fn(*mut OSSL_DECODER_INSTANCE, *const OSSL_PARAM, *mut c_void) -> c_int;

unsafe extern "C" {
    fn OSSL_DECODER_CTX_new() -> *mut OSSL_DECODER_CTX;
    fn OSSL_DECODER_CTX_free(c: *mut OSSL_DECODER_CTX);
    fn OSSL_DECODER_fetch(l: *mut OSSL_LIB_CTX, n: *const c_char, p: *const c_char) -> *mut OSSL_DECODER;
    fn OSSL_DECODER_free(d: *mut OSSL_DECODER);
    fn OSSL_DECODER_CTX_add_decoder(c: *mut OSSL_DECODER_CTX, d: *mut OSSL_DECODER) -> c_int;
    fn OSSL_DECODER_CTX_add_extra(c: *mut OSSL_DECODER_CTX, l: *mut OSSL_LIB_CTX, p: *const c_char) -> c_int;
    fn OSSL_DECODER_CTX_set_selection(c: *mut OSSL_DECODER_CTX, s: c_int) -> c_int;
    fn OSSL_DECODER_CTX_set_input_structure(c: *mut OSSL_DECODER_CTX, s: *const c_char) -> c_int;
    fn OSSL_DECODER_CTX_set_construct(c: *mut OSSL_DECODER_CTX, f: Option<Construct>) -> c_int;
    fn OSSL_DECODER_from_data(c: *mut OSSL_DECODER_CTX, p: *mut *const u8, l: *mut usize) -> c_int;
    fn ERR_clear_error();
}

/// Reads every octet passed on (ASan checks they're there) and refuses, so the walk goes on.
unsafe extern "C" fn construct(_i: *mut OSSL_DECODER_INSTANCE, params: *const OSSL_PARAM, _d: *mut c_void) -> c_int {
    let mut p = params;
    // SAFETY: the decoder's array, ended by a NULL key.
    while let Some(param) = unsafe { p.as_ref() } {
        if param.key.is_null() {
            break;
        }
        if param.data_type == OSSL_PARAM_OCTET_STRING.cast_unsigned() && !param.data.is_null() {
            // SAFETY: the parameter's octets.
            let d = unsafe { core::slice::from_raw_parts(param.data.cast::<u8>(), param.data_size) };
            core::hint::black_box(d.iter().fold(0u8, |a, &b| a ^ b));
        }
        p = p.wrapping_add(1);
    }
    0
}

const STRUCTURES: [Option<&CStr>; 5] = [
    None,
    Some(c"SubjectPublicKeyInfo"),
    Some(c"PrivateKeyInfo"),
    Some(c"EncryptedPrivateKeyInfo"),
    Some(c"type-specific"),
];

fuzz_target!(|input: &[u8]| {
    let Some((&flags, input)) = input.split_first() else {
        return;
    };
    // SAFETY: no preconditions; the context and decoders made here.
    unsafe {
        let c = OSSL_DECODER_CTX_new();
        for props in [c"structure=SubjectPublicKeyInfo", c"input=pem", c"structure=EncryptedPrivateKeyInfo"] {
            let d = OSSL_DECODER_fetch(ptr::null_mut(), c"DER".as_ptr(), props.as_ptr());
            OSSL_DECODER_CTX_add_decoder(c, d);
            OSSL_DECODER_free(d);
        }
        if flags & 0x80 != 0 {
            OSSL_DECODER_CTX_add_extra(c, ptr::null_mut(), ptr::null());
        }
        OSSL_DECODER_CTX_set_selection(c, c_int::from(flags & 0x07));
        if let Some(s) = STRUCTURES[usize::from((flags >> 3) & 0x07) % STRUCTURES.len()] {
            OSSL_DECODER_CTX_set_input_structure(c, s.as_ptr());
        }
        OSSL_DECODER_CTX_set_construct(c, Some(construct));
        let mut p = input.as_ptr();
        let mut left = input.len();
        if !input.is_empty() && OSSL_DECODER_from_data(c, &mut p, &mut left) != 0 {
            assert!(left <= input.len(), "more left than given");
        }
        OSSL_DECODER_CTX_free(c);
        ERR_clear_error();
    }
});
