//! Fuzzes ML-KEM keys made from parameters (`EVP_PKEY_fromdata` through the ML-KEM-512, -768,
//! and -1024 key managers), as a decoder hands them a key from an untrusted file: seeds of any
//! length, and private and public keys either of any length from the input or a generated key's
//! with octets changed, alone or together. Nothing may crash or read out of bounds (ASan); a key
//! it makes exports, imports again to an equal key, and checks cleanly.

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
    fn EVP_PKEY_CTX_set_params(c: *mut EVP_PKEY_CTX, params: *const OSSL_PARAM) -> c_int;
    fn EVP_PKEY_keygen_init(c: *mut EVP_PKEY_CTX) -> c_int;
    fn EVP_PKEY_generate(c: *mut EVP_PKEY_CTX, k: *mut *mut EVP_PKEY) -> c_int;
    fn EVP_PKEY_fromdata_init(c: *mut EVP_PKEY_CTX) -> c_int;
    fn EVP_PKEY_fromdata(
        c: *mut EVP_PKEY_CTX,
        k: *mut *mut EVP_PKEY,
        selection: c_int,
        params: *mut OSSL_PARAM,
    ) -> c_int;
    fn EVP_PKEY_todata(k: *const EVP_PKEY, selection: c_int, out: *mut *mut OSSL_PARAM) -> c_int;
    fn EVP_PKEY_get_raw_private_key(k: *const EVP_PKEY, out: *mut u8, len: *mut usize) -> c_int;
    fn EVP_PKEY_get_raw_public_key(k: *const EVP_PKEY, out: *mut u8, len: *mut usize) -> c_int;
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
const ALGS: [&core::ffi::CStr; 3] = [c"ML-KEM-512", c"ML-KEM-768", c"ML-KEM-1024"];

/// Makes a key of `alg` from `params`, or NULL.
fn fromdata(alg: &core::ffi::CStr, selection: c_int, params: *mut OSSL_PARAM) -> *mut EVP_PKEY {
    // SAFETY: a static name.
    let c = unsafe { EVP_PKEY_CTX_new_from_name(ptr::null_mut(), alg.as_ptr(), ptr::null()) };
    let mut k = ptr::null_mut();
    // SAFETY: the context; an array.
    unsafe {
        EVP_PKEY_fromdata_init(c);
        EVP_PKEY_fromdata(c, &mut k, selection, params);
        EVP_PKEY_CTX_free(c);
    }
    k
}

/// The private and public keys of the key of `alg` generated from `seed`.
fn generated(alg: &core::ffi::CStr, seed: &mut [u8; 64]) -> (Vec<u8>, Vec<u8>) {
    let (mut d, mut q) = (vec![0u8; 4000], vec![0u8; 2000]);
    let (mut dl, mut ql) = (d.len(), q.len());
    // SAFETY: a static name; the seed outlives the array; the key made and freed here.
    unsafe {
        let c = EVP_PKEY_CTX_new_from_name(ptr::null_mut(), alg.as_ptr(), ptr::null());
        let params = [
            OSSL_PARAM_construct_octet_string(c"seed".as_ptr(), seed.as_mut_ptr().cast(), 64),
            OSSL_PARAM_construct_end(),
        ];
        let mut k = ptr::null_mut();
        EVP_PKEY_keygen_init(c);
        EVP_PKEY_CTX_set_params(c, params.as_ptr());
        assert_eq!(EVP_PKEY_generate(c, &mut k), 1, "a key from a seed");
        EVP_PKEY_get_raw_private_key(k, d.as_mut_ptr(), &mut dl);
        EVP_PKEY_get_raw_public_key(k, q.as_mut_ptr(), &mut ql);
        EVP_PKEY_free(k);
        EVP_PKEY_CTX_free(c);
    }
    d.truncate(dl);
    q.truncate(ql);
    (d, q)
}

/// Changes octets of `v` by the input's (offset, xor) triples.
fn edit(v: &mut [u8], edits: &[u8]) {
    for e in edits.chunks_exact(3) {
        if !v.is_empty() {
            let i = usize::from(u16::from_le_bytes([e[0], e[1]])) % v.len();
            v[i] ^= e[2];
        }
    }
}

fuzz_target!(|input: &[u8]| {
    let Some((&flags, rest)) = input.split_first() else {
        return;
    };
    let alg = ALGS[usize::from(flags & 3) % 3];
    let selection = SELECTIONS[usize::from(flags >> 2 & 7) % SELECTIONS.len()];
    let mut seed = [0u8; 64];
    let n = rest.len().min(64);
    seed[..n].copy_from_slice(&rest[..n]);
    let rest = &rest[n..];
    let (mut d, mut q, mut s) = if flags & 0x20 != 0 {
        // Raw octets: a seed, a private key, and a public key from the input.
        let third = rest.len() / 3;
        let (a, b) = rest.split_at(third);
        let (b, c) = b.split_at(third);
        (b.to_vec(), c.to_vec(), a.to_vec())
    } else {
        let (mut d, mut q) = generated(alg, &mut seed);
        let (dedits, qedits) = rest.split_at(rest.len() / 2);
        edit(&mut d, dedits);
        edit(&mut q, qedits);
        (d, q, seed.to_vec())
    };
    let mut params = Vec::new();
    // SAFETY: static names; octets that outlive the array.
    unsafe {
        if flags & 0x40 != 0 {
            params.push(OSSL_PARAM_construct_octet_string(
                c"seed".as_ptr(),
                s.as_mut_ptr().cast(),
                s.len(),
            ));
        }
        if flags & 0x80 != 0 {
            params.push(OSSL_PARAM_construct_octet_string(
                c"priv".as_ptr(),
                d.as_mut_ptr().cast(),
                d.len(),
            ));
        }
        if flags & 0x10 != 0 || flags & 0xc0 == 0 {
            params.push(OSSL_PARAM_construct_octet_string(
                c"pub".as_ptr(),
                q.as_mut_ptr().cast(),
                q.len(),
            ));
        }
        params.push(OSSL_PARAM_construct_end());
    }
    let k = fromdata(alg, selection, params.as_mut_ptr());
    if !k.is_null() {
        let mut out = ptr::null_mut();
        // SAFETY: a live key; a place for an array.
        if unsafe { EVP_PKEY_todata(k, 0x87, &mut out) } == 1 {
            let back = fromdata(alg, 0x87, out);
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
