//! Fuzzes OSSL_STORE's file loader on untrusted input: the input attached as a BIO and read
//! object by object (any type, or one expected type chosen by the first octet), every object's
//! contents asked for, with a passphrase callback that gives one. Nothing may crash or read out
//! of bounds (ASan).

#![no_main]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{BIO, OSSL_STORE_CTX, OSSL_STORE_INFO};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn BIO_new_mem_buf(buf: *const c_void, len: c_int) -> *mut BIO;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn OSSL_STORE_attach(bp: *mut BIO, scheme: *const c_char, libctx: *mut c_void, propq: *const c_char, ui_method: *const c_void, ui_data: *mut c_void, params: *const c_void, post_process: *const c_void, post_process_data: *mut c_void) -> *mut OSSL_STORE_CTX;
    fn OSSL_STORE_expect(ctx: *mut OSSL_STORE_CTX, expected_type: c_int) -> c_int;
    fn OSSL_STORE_load(ctx: *mut OSSL_STORE_CTX) -> *mut OSSL_STORE_INFO;
    fn OSSL_STORE_eof(ctx: *mut OSSL_STORE_CTX) -> c_int;
    fn OSSL_STORE_error(ctx: *mut OSSL_STORE_CTX) -> c_int;
    fn OSSL_STORE_close(ctx: *mut OSSL_STORE_CTX) -> c_int;
    fn OSSL_STORE_INFO_get_type(info: *const OSSL_STORE_INFO) -> c_int;
    fn OSSL_STORE_INFO_get0_data(type_: c_int, info: *const OSSL_STORE_INFO) -> *mut c_void;
    fn OSSL_STORE_INFO_free(info: *mut OSSL_STORE_INFO);
    fn UI_UTIL_wrap_read_pem_callback(cb: Option<unsafe extern "C" fn(*mut c_char, c_int, c_int, *mut c_void) -> c_int>, rwflag: c_int) -> *mut c_void;
    fn UI_destroy_method(ui: *mut c_void);
    fn ERR_clear_error();
}

/// A passphrase callback that answers "pass".
unsafe extern "C" fn pass(buf: *mut c_char, size: c_int, _rwflag: c_int, _u: *mut c_void) -> c_int {
    if size < 4 {
        return 0;
    }
    // SAFETY: the caller's buffer of `size` octets.
    unsafe { ptr::copy_nonoverlapping(b"pass".as_ptr().cast(), buf, 4) };
    4
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let Ok(len) = c_int::try_from(rest.len()) else {
        return;
    };
    // SAFETY: the input's octets, which outlive the BIO.
    let bio = unsafe { BIO_new_mem_buf(rest.as_ptr().cast(), len) };
    // SAFETY: a callback of the right type.
    let ui = unsafe { UI_UTIL_wrap_read_pem_callback(Some(pass), 0) };
    // SAFETY: the BIO; the default scheme and library context; the UI method.
    let ctx = unsafe { OSSL_STORE_attach(bio, ptr::null(), ptr::null_mut(), ptr::null(), ui, ptr::null_mut(), ptr::null(), ptr::null(), ptr::null_mut()) };
    if !ctx.is_null() {
        let expected = c_int::from(mode % 7);
        if expected != 0 {
            // SAFETY: the store opened here.
            unsafe { OSSL_STORE_expect(ctx, expected) };
        }
        for _ in 0..64 {
            // SAFETY: as above.
            let info = unsafe { OSSL_STORE_load(ctx) };
            if info.is_null() {
                // SAFETY: as above.
                if unsafe { OSSL_STORE_eof(ctx) } != 0 {
                    break;
                }
                // SAFETY: as above.
                unsafe { OSSL_STORE_error(ctx) };
                continue;
            }
            // SAFETY: the information loaded.
            let t = unsafe { OSSL_STORE_INFO_get_type(info) };
            // SAFETY: as above.
            unsafe { OSSL_STORE_INFO_get0_data(t, info) };
            // SAFETY: as above, freed once.
            unsafe { OSSL_STORE_INFO_free(info) };
        }
        // SAFETY: the store opened here.
        unsafe { OSSL_STORE_close(ctx) };
    }
    // SAFETY: made here.
    unsafe { UI_destroy_method(ui) };
    // SAFETY: as above.
    unsafe { BIO_free(bio) };
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
