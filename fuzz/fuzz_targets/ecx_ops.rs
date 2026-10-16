//! Fuzzes the X25519 exchange and Ed25519 signatures with untrusted parts: a peer's public key
//! of any value, and signatures, public keys, messages, and context strings of any value and
//! length through every algorithm. Nothing may crash or read out of bounds (ASan); a secret is
//! 32 octets, a verification gives 1 or 0, and what a private key signs, its key verifies.

#![no_main]

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{
    ENGINE, EVP_PKEY, EVP_PKEY_CTX, EVP_PKEY_ED25519, EVP_PKEY_X25519, EVP_SIGNATURE, OSSL_LIB_CTX,
    OSSL_PARAM,
};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn EVP_PKEY_new_raw_private_key(
        t: c_int,
        e: *mut ENGINE,
        k: *const u8,
        n: usize,
    ) -> *mut EVP_PKEY;
    fn EVP_PKEY_new_raw_public_key(
        t: c_int,
        e: *mut ENGINE,
        k: *const u8,
        n: usize,
    ) -> *mut EVP_PKEY;
    fn EVP_PKEY_CTX_new_from_pkey(
        libctx: *mut OSSL_LIB_CTX,
        k: *mut EVP_PKEY,
        propq: *const c_char,
    ) -> *mut EVP_PKEY_CTX;
    fn EVP_PKEY_CTX_free(c: *mut EVP_PKEY_CTX);
    fn EVP_PKEY_derive_init(c: *mut EVP_PKEY_CTX) -> c_int;
    fn EVP_PKEY_derive_set_peer(c: *mut EVP_PKEY_CTX, peer: *mut EVP_PKEY) -> c_int;
    fn EVP_PKEY_derive(c: *mut EVP_PKEY_CTX, key: *mut u8, keylen: *mut usize) -> c_int;
    fn EVP_SIGNATURE_fetch(
        libctx: *mut OSSL_LIB_CTX,
        name: *const c_char,
        propq: *const c_char,
    ) -> *mut EVP_SIGNATURE;
    fn EVP_SIGNATURE_free(s: *mut EVP_SIGNATURE);
    fn EVP_PKEY_sign_message_init(
        c: *mut EVP_PKEY_CTX,
        s: *mut EVP_SIGNATURE,
        params: *const OSSL_PARAM,
    ) -> c_int;
    fn EVP_PKEY_verify_message_init(
        c: *mut EVP_PKEY_CTX,
        s: *mut EVP_SIGNATURE,
        params: *const OSSL_PARAM,
    ) -> c_int;
    fn EVP_PKEY_sign(
        c: *mut EVP_PKEY_CTX,
        sig: *mut u8,
        siglen: *mut usize,
        tbs: *const u8,
        tbslen: usize,
    ) -> c_int;
    fn EVP_PKEY_verify(
        c: *mut EVP_PKEY_CTX,
        sig: *const u8,
        siglen: usize,
        tbs: *const u8,
        tbslen: usize,
    ) -> c_int;
    fn EVP_PKEY_free(k: *mut EVP_PKEY);
    fn OSSL_PARAM_construct_octet_string(
        key: *const c_char,
        buf: *mut c_void,
        bsize: usize,
    ) -> OSSL_PARAM;
    fn OSSL_PARAM_construct_end() -> OSSL_PARAM;
    fn ERR_clear_error();
}

const ALGS: [&CStr; 3] = [c"ED25519", c"ED25519ph", c"ED25519ctx"];

/// Takes `n` octets from the front of `input` (fewer at its end).
fn take<'a>(input: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (a, b) = input.split_at(n.min(input.len()));
    *input = b;
    a
}

/// The X25519 exchange of a private key with an untrusted peer.
fn exchange(mut input: &[u8]) {
    let private = take(&mut input, 32);
    let public = take(&mut input, 32);
    // SAFETY: octets of the lengths given.
    let k = unsafe {
        EVP_PKEY_new_raw_private_key(
            EVP_PKEY_X25519,
            ptr::null_mut(),
            private.as_ptr(),
            private.len(),
        )
    };
    // SAFETY: as above.
    let peer = unsafe {
        EVP_PKEY_new_raw_public_key(
            EVP_PKEY_X25519,
            ptr::null_mut(),
            public.as_ptr(),
            public.len(),
        )
    };
    if !k.is_null() && !peer.is_null() {
        let mut out = [0u8; 40];
        let mut len = out.len();
        // SAFETY: live keys; room for `len` octets.
        unsafe {
            let c = EVP_PKEY_CTX_new_from_pkey(ptr::null_mut(), k, ptr::null());
            EVP_PKEY_derive_init(c);
            EVP_PKEY_derive_set_peer(c, peer);
            if EVP_PKEY_derive(c, out.as_mut_ptr(), &mut len) == 1 {
                assert_eq!(len, 32);
            }
            EVP_PKEY_CTX_free(c);
        }
    }
    // SAFETY: the keys, or NULL.
    unsafe {
        EVP_PKEY_free(k);
        EVP_PKEY_free(peer);
    }
}

/// Verifies an untrusted signature with an untrusted public key, then signs and verifies with
/// a private key.
fn signatures(flags: u8, mut input: &[u8]) {
    let alg = ALGS[usize::from(flags >> 1) % ALGS.len()];
    let clen = usize::from(input.first().copied().unwrap_or(0));
    let _ = take(&mut input, 1);
    let mut context = take(&mut input, clen).to_vec();
    let key = take(&mut input, 32);
    let sig = take(&mut input, 64 + usize::from(flags >> 6));
    let msg = input;
    let mut params = Vec::new();
    // SAFETY: a static name; octets that outlive the array.
    unsafe {
        if flags & 8 != 0 {
            params.push(OSSL_PARAM_construct_octet_string(
                c"context-string".as_ptr(),
                context.as_mut_ptr().cast(),
                context.len(),
            ));
        }
        params.push(OSSL_PARAM_construct_end());
    }
    // SAFETY: a static name.
    let s = unsafe { EVP_SIGNATURE_fetch(ptr::null_mut(), alg.as_ptr(), ptr::null()) };
    assert!(!s.is_null());
    for private in [false, true] {
        // SAFETY: octets of the length given.
        let k = unsafe {
            if private {
                EVP_PKEY_new_raw_private_key(
                    EVP_PKEY_ED25519,
                    ptr::null_mut(),
                    key.as_ptr(),
                    key.len(),
                )
            } else {
                EVP_PKEY_new_raw_public_key(
                    EVP_PKEY_ED25519,
                    ptr::null_mut(),
                    key.as_ptr(),
                    key.len(),
                )
            }
        };
        if k.is_null() {
            continue;
        }
        // SAFETY: a live key; the algorithm; the array; octets of the lengths given.
        unsafe {
            let c = EVP_PKEY_CTX_new_from_pkey(ptr::null_mut(), k, ptr::null());
            if !private {
                if EVP_PKEY_verify_message_init(c, s, params.as_ptr()) == 1 {
                    let r = EVP_PKEY_verify(c, sig.as_ptr(), sig.len(), msg.as_ptr(), msg.len());
                    assert!(r == 0 || r == 1);
                }
            } else if EVP_PKEY_sign_message_init(c, s, params.as_ptr()) == 1 {
                let mut out = [0u8; 64];
                let mut len = out.len();
                if EVP_PKEY_sign(c, out.as_mut_ptr(), &mut len, msg.as_ptr(), msg.len()) == 1 {
                    assert_eq!(len, 64);
                    assert_eq!(EVP_PKEY_verify_message_init(c, s, params.as_ptr()), 1);
                    let r = EVP_PKEY_verify(c, out.as_ptr(), len, msg.as_ptr(), msg.len());
                    assert_eq!(r, 1);
                }
            }
            EVP_PKEY_CTX_free(c);
            EVP_PKEY_free(k);
        }
    }
    // SAFETY: the fetched algorithm.
    unsafe { EVP_SIGNATURE_free(s) };
}

fuzz_target!(|input: &[u8]| {
    let Some((&flags, rest)) = input.split_first() else {
        return;
    };
    if flags & 1 == 0 {
        exchange(rest);
    } else {
        signatures(flags, rest);
    }
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
