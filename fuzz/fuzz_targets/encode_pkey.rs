//! Fuzzes encoding keys decoded from untrusted DER: each key the decoders make of the input
//! (d2i_AutoPrivateKey, else d2i_PUBKEY) through OSSL_ENCODER_CTX_new_for_pkey with a selection,
//! output type, and structure the input picks, and through i2d_PrivateKey, i2d_PublicKey,
//! i2d_KeyParams, and i2d_PUBKEY. Nothing may crash or write out of bounds (ASan), and each
//! i2d's length must be the length it writes, into a new buffer or the caller's.

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_uchar};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{EVP_PKEY, OSSL_ENCODER_CTX};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn d2i_AutoPrivateKey(a: *mut *mut EVP_PKEY, pp: *mut *const u8, len: c_long) -> *mut EVP_PKEY;
    fn d2i_PUBKEY(a: *mut *mut EVP_PKEY, pp: *mut *const u8, len: c_long) -> *mut EVP_PKEY;
    fn OSSL_ENCODER_CTX_new_for_pkey(pkey: *const EVP_PKEY, selection: c_int, output_type: *const c_char, output_struct: *const c_char, propquery: *const c_char) -> *mut OSSL_ENCODER_CTX;
    fn OSSL_ENCODER_to_data(ctx: *mut OSSL_ENCODER_CTX, pdata: *mut *mut c_uchar, len: *mut usize) -> c_int;
    fn OSSL_ENCODER_CTX_free(ctx: *mut OSSL_ENCODER_CTX);
    fn i2d_PrivateKey(a: *const EVP_PKEY, pp: *mut *mut c_uchar) -> c_int;
    fn i2d_PublicKey(a: *const EVP_PKEY, pp: *mut *mut c_uchar) -> c_int;
    fn i2d_KeyParams(a: *const EVP_PKEY, pp: *mut *mut c_uchar) -> c_int;
    fn i2d_PUBKEY(a: *const EVP_PKEY, pp: *mut *mut c_uchar) -> c_int;
    fn CRYPTO_free(p: *mut core::ffi::c_void, file: *const c_char, line: c_int);
    fn EVP_PKEY_free(k: *mut EVP_PKEY);
    fn ERR_clear_error();
}

const SELECTIONS: [c_int; 6] = [0x87, 0x86, 0x84, 0x01, 0x02, 0];
const TYPES: [&core::ffi::CStr; 3] = [c"DER", c"PEM", c"blob"];
const STRUCTURES: [Option<&core::ffi::CStr>; 8] = [
    None,
    Some(c"PrivateKeyInfo"),
    Some(c"SubjectPublicKeyInfo"),
    Some(c"type-specific"),
    Some(c"EncryptedPrivateKeyInfo"),
    Some(c"pkcs1"),
    Some(c"X9.62"),
    Some(c"X9.42"),
];

type I2d = unsafe extern "C" fn(*const EVP_PKEY, *mut *mut c_uchar) -> c_int;

fuzz_target!(|input: &[u8]| {
    let Some((&how, der)) = input.split_first() else {
        return;
    };
    let Ok(len) = c_long::try_from(der.len()) else {
        return;
    };
    // SAFETY: the input's octets; the keys, contexts, and buffers made here, freed once.
    unsafe {
        let mut p = der.as_ptr();
        let mut k = d2i_AutoPrivateKey(ptr::null_mut(), &mut p, len);
        if k.is_null() {
            p = der.as_ptr();
            k = d2i_PUBKEY(ptr::null_mut(), &mut p, len);
        }
        if k.is_null() {
            ERR_clear_error();
            return;
        }
        let sel = SELECTIONS[usize::from(how) % SELECTIONS.len()];
        let t = TYPES[usize::from(how / 6) % TYPES.len()];
        let s = STRUCTURES[usize::from(how / 18) % STRUCTURES.len()];
        let ctx = OSSL_ENCODER_CTX_new_for_pkey(k, sel, t.as_ptr(), s.map_or(ptr::null(), |s| s.as_ptr()), ptr::null());
        let mut data: *mut c_uchar = ptr::null_mut();
        let mut dlen = 0usize;
        if !ctx.is_null() && OSSL_ENCODER_to_data(ctx, &mut data, &mut dlen) != 0 {
            assert!(!data.is_null() || dlen == 0, "an encoding without its octets");
        }
        CRYPTO_free(data.cast(), ptr::null(), 0);
        OSSL_ENCODER_CTX_free(ctx);
        for f in [i2d_PrivateKey as I2d, i2d_PublicKey, i2d_KeyParams, i2d_PUBKEY] {
            let n = f(k, ptr::null_mut());
            let mut fresh: *mut c_uchar = ptr::null_mut();
            let m = f(k, &mut fresh);
            assert_eq!(n, m, "an i2d's length not the length it writes");
            if let Ok(size) = usize::try_from(m)
                && size > 0
                && size <= 65536
            {
                let mut buf = vec![0u8; size];
                let mut at = buf.as_mut_ptr();
                assert_eq!(f(k, &mut at), m, "an i2d into the caller's buffer");
                assert_eq!(at as usize - buf.as_ptr() as usize, size, "an i2d moving past its output");
                assert_eq!(core::slice::from_raw_parts(fresh, size), &buf[..], "two i2d encodings differ");
            }
            CRYPTO_free(fresh.cast(), ptr::null(), 0);
        }
        EVP_PKEY_free(k);
        ERR_clear_error();
    }
});
