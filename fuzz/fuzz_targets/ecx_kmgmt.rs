//! Fuzzes ECX keys made from parameters (`EVP_PKEY_fromdata` through the X25519 and ED25519 key
//! managers), as a decoder hands them a key from an untrusted file: private and public keys of
//! any length, either alone or both. Nothing may crash or read out of bounds (ASan); a key it
//! makes exports, imports again to an equal key, and checks cleanly.

#![no_main]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{EVP_PKEY, EVP_PKEY_CTX, OSSL_LIB_CTX, OSSL_PARAM};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn EVP_PKEY_CTX_new_from_name(
        libctx: *mut OSSL_LIB_CTX,
        name: *const c_char,
        propq: *const c_char,
    ) -> *mut EVP_PKEY_CTX;
    fn EVP_PKEY_CTX_new_from_pkey(
        libctx: *mut OSSL_LIB_CTX,
        k: *mut EVP_PKEY,
        propq: *const c_char,
    ) -> *mut EVP_PKEY_CTX;
    fn EVP_PKEY_CTX_free(c: *mut EVP_PKEY_CTX);
    fn EVP_PKEY_fromdata_init(c: *mut EVP_PKEY_CTX) -> c_int;
    fn EVP_PKEY_fromdata(
        c: *mut EVP_PKEY_CTX,
        k: *mut *mut EVP_PKEY,
        selection: c_int,
        params: *mut OSSL_PARAM,
    ) -> c_int;
    fn EVP_PKEY_todata(k: *const EVP_PKEY, selection: c_int, out: *mut *mut OSSL_PARAM) -> c_int;
    fn EVP_PKEY_eq(a: *const EVP_PKEY, b: *const EVP_PKEY) -> c_int;
    fn EVP_PKEY_check(c: *mut EVP_PKEY_CTX) -> c_int;
    fn EVP_PKEY_free(k: *mut EVP_PKEY);
    fn OSSL_PARAM_construct_octet_string(
        key: *const c_char,
        buf: *mut c_void,
        bsize: usize,
    ) -> OSSL_PARAM;
    fn OSSL_PARAM_construct_end() -> OSSL_PARAM;
    fn OSSL_PARAM_free(p: *mut OSSL_PARAM);
    fn ERR_clear_error();
}

const SELECTIONS: [c_int; 6] = [0x87, 0x86, 0x85, 0x84, 0x83, 0x07];

/// Makes a key of `keytype` from `params`, or NULL.
fn fromdata(keytype: &core::ffi::CStr, selection: c_int, params: *mut OSSL_PARAM) -> *mut EVP_PKEY {
    // SAFETY: a static name.
    let c = unsafe { EVP_PKEY_CTX_new_from_name(ptr::null_mut(), keytype.as_ptr(), ptr::null()) };
    let mut k = ptr::null_mut();
    // SAFETY: the context; an array.
    unsafe {
        EVP_PKEY_fromdata_init(c);
        EVP_PKEY_fromdata(c, &mut k, selection, params);
        EVP_PKEY_CTX_free(c);
    }
    k
}

fuzz_target!(|input: &[u8]| {
    let Some((&flags, rest)) = input.split_first() else {
        return;
    };
    let keytype = if flags & 1 == 0 {
        c"X25519"
    } else {
        c"ED25519"
    };
    let selection = SELECTIONS[usize::from(flags >> 1) % SELECTIONS.len()];
    let cut = usize::from(flags >> 4).saturating_mul(4).min(rest.len());
    let (mut d, mut q) = (rest[..cut].to_vec(), rest[cut..].to_vec());
    let mut params = Vec::new();
    // SAFETY: static names; octets that outlive the array.
    unsafe {
        if flags & 2 != 0 {
            params.push(OSSL_PARAM_construct_octet_string(
                c"priv".as_ptr(),
                d.as_mut_ptr().cast(),
                d.len(),
            ));
        }
        if flags & 4 != 0 {
            params.push(OSSL_PARAM_construct_octet_string(
                c"pub".as_ptr(),
                q.as_mut_ptr().cast(),
                q.len(),
            ));
        }
        params.push(OSSL_PARAM_construct_end());
    }
    let k = fromdata(keytype, selection, params.as_mut_ptr());
    if !k.is_null() {
        let mut out = ptr::null_mut();
        // SAFETY: a live key; a place for an array.
        if unsafe { EVP_PKEY_todata(k, 0x87, &mut out) } == 1 {
            let back = fromdata(keytype, 0x87, out);
            assert!(!back.is_null(), "its export imports");
            // SAFETY: live keys.
            assert_eq!(unsafe { EVP_PKEY_eq(k, back) }, 1, "to an equal key");
            // SAFETY: made above, each freed once.
            unsafe { EVP_PKEY_free(back) };
            // SAFETY: as above.
            unsafe { OSSL_PARAM_free(out) };
        }
        // SAFETY: a live key.
        let c = unsafe { EVP_PKEY_CTX_new_from_pkey(ptr::null_mut(), k, ptr::null()) };
        // SAFETY: the context.
        let v = unsafe { EVP_PKEY_check(c) };
        assert!(v == 0 || v == 1, "checks cleanly");
        // SAFETY: made above.
        unsafe { EVP_PKEY_CTX_free(c) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(k) };
    }
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
