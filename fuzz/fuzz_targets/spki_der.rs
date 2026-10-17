//! Fuzzes the typed SubjectPublicKeyInfo decoders (`d2i_RSA_PUBKEY`, `d2i_DSA_PUBKEY`,
//! `d2i_EC_PUBKEY`), which certificates and key files carry from untrusted sources, through
//! the key types' ASN.1 methods. Nothing may crash or read out of bounds (ASan), a decoder may
//! consume only the input, and a key it makes must encode again and decode back.

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

type D2i = unsafe extern "C" fn(*mut *mut c_void, *mut *const c_uchar, c_long) -> *mut c_void;
type I2d = unsafe extern "C" fn(*const c_void, *mut *mut c_uchar) -> c_int;
type Free = unsafe extern "C" fn(*mut c_void);

unsafe extern "C" {
    fn d2i_RSA_PUBKEY(a: *mut *mut c_void, pp: *mut *const c_uchar, len: c_long) -> *mut c_void;
    fn i2d_RSA_PUBKEY(a: *const c_void, pp: *mut *mut c_uchar) -> c_int;
    fn RSA_free(r: *mut c_void);
    fn d2i_DSA_PUBKEY(a: *mut *mut c_void, pp: *mut *const c_uchar, len: c_long) -> *mut c_void;
    fn i2d_DSA_PUBKEY(a: *const c_void, pp: *mut *mut c_uchar) -> c_int;
    fn DSA_free(d: *mut c_void);
    fn d2i_EC_PUBKEY(a: *mut *mut c_void, pp: *mut *const c_uchar, len: c_long) -> *mut c_void;
    fn i2d_EC_PUBKEY(a: *const c_void, pp: *mut *mut c_uchar) -> c_int;
    fn EC_KEY_free(k: *mut c_void);
    fn CRYPTO_free(p: *mut c_void, file: *const c_char, line: c_int);
    fn ERR_clear_error();
}

fuzz_target!(|input: &[u8]| {
    let Some((&flags, input)) = input.split_first() else {
        return;
    };
    let (d2i, i2d, free): (D2i, I2d, Free) = match flags % 3 {
        0 => (d2i_RSA_PUBKEY, i2d_RSA_PUBKEY, RSA_free),
        1 => (d2i_DSA_PUBKEY, i2d_DSA_PUBKEY, DSA_free),
        _ => (d2i_EC_PUBKEY, i2d_EC_PUBKEY, EC_KEY_free),
    };
    let mut p = input.as_ptr();
    let len = c_long::try_from(input.len()).unwrap();
    // SAFETY: `input` holds `len` octets.
    let k = unsafe { d2i(ptr::null_mut(), &mut p, len) };
    let used = p as usize - input.as_ptr() as usize;
    if k.is_null() {
        assert_eq!(used, 0, "a failed decode moved the input");
    } else {
        assert!(used <= input.len(), "consumed past the input");
        let mut der: *mut c_uchar = ptr::null_mut();
        // SAFETY: a live key.
        let n = unsafe { i2d(k, &mut der) };
        assert!(n > 0, "a decoded key encodes");
        let mut q = der.cast_const();
        // SAFETY: the encoding of `n` octets.
        let back = unsafe { d2i(ptr::null_mut(), &mut q, c_long::from(n)) };
        assert!(!back.is_null(), "its encoding decodes");
        // SAFETY: values made here, freed once.
        unsafe {
            CRYPTO_free(der.cast(), ptr::null(), 0);
            free(back);
            free(k);
        }
    }
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
