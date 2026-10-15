//! Fuzzes EC keys made from parameters (`EVP_PKEY_fromdata` through the EC key manager), as a
//! decoder hands it a key from an untrusted file: a named group or explicit parameters (field,
//! curve, generator, order, cofactor, seed), a private number, an encoded public point, and
//! the other parameters (point format, encoding, check type, cofactor mode). Nothing may crash
//! or read out of bounds (ASan); a key it makes that exports (one whose private number fits
//! the order's length) must import again with the same parameters; checks pass or fail
//! cleanly.

#![no_main]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{BIGNUM, EVP_PKEY, EVP_PKEY_CTX, OSSL_LIB_CTX, OSSL_PARAM, OSSL_PARAM_BLD};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn OSSL_PARAM_BLD_new() -> *mut OSSL_PARAM_BLD;
    fn OSSL_PARAM_BLD_free(bld: *mut OSSL_PARAM_BLD);
    fn OSSL_PARAM_BLD_to_param(bld: *mut OSSL_PARAM_BLD) -> *mut OSSL_PARAM;
    fn OSSL_PARAM_BLD_push_utf8_string(
        bld: *mut OSSL_PARAM_BLD,
        key: *const c_char,
        buf: *const c_char,
        bsize: usize,
    ) -> c_int;
    fn OSSL_PARAM_BLD_push_octet_string(
        bld: *mut OSSL_PARAM_BLD,
        key: *const c_char,
        buf: *const c_void,
        bsize: usize,
    ) -> c_int;
    fn OSSL_PARAM_BLD_push_BN(
        bld: *mut OSSL_PARAM_BLD,
        key: *const c_char,
        bn: *const BIGNUM,
    ) -> c_int;
    fn OSSL_PARAM_BLD_push_int(bld: *mut OSSL_PARAM_BLD, key: *const c_char, v: c_int) -> c_int;
    fn OSSL_PARAM_free(p: *mut OSSL_PARAM);
    fn BN_bin2bn(s: *const u8, len: c_int, ret: *mut BIGNUM) -> *mut BIGNUM;
    fn BN_free(b: *mut BIGNUM);
    fn EVP_PKEY_CTX_new_from_name(
        libctx: *mut OSSL_LIB_CTX,
        name: *const c_char,
        propq: *const c_char,
    ) -> *mut EVP_PKEY_CTX;
    fn EVP_PKEY_CTX_new_from_pkey(
        libctx: *mut OSSL_LIB_CTX,
        pkey: *mut EVP_PKEY,
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
    fn EVP_PKEY_todata(k: *const EVP_PKEY, selection: c_int, params: *mut *mut OSSL_PARAM)
    -> c_int;
    fn EVP_PKEY_parameters_eq(a: *const EVP_PKEY, b: *const EVP_PKEY) -> c_int;
    fn EVP_PKEY_check(c: *mut EVP_PKEY_CTX) -> c_int;
    fn EVP_PKEY_public_check_quick(c: *mut EVP_PKEY_CTX) -> c_int;
    fn EVP_PKEY_param_check(c: *mut EVP_PKEY_CTX) -> c_int;
    fn EVP_PKEY_free(k: *mut EVP_PKEY);
    fn ERR_clear_error();
}

/// The selections a key is made with: key pair, public key, parameters, and odd ones.
const SELECTIONS: [c_int; 6] = [0x87, 0x86, 0x84, 0x85, 0x80, 0x07];
const GROUPS: [&[u8]; 6] = [
    b"prime256v1\0",
    b"secp384r1\0",
    b"secp112r1\0",
    b"sect163k1\0",
    b"sect113r1\0",
    b"brainpoolP256r1\0",
];
const FORMATS: [&[u8]; 3] = [b"compressed\0", b"uncompressed\0", b"hybrid\0"];
const CHECKS: [&[u8]; 3] = [b"default\0", b"named\0", b"named-nist\0"];
const FIELDS: [&[u8]; 2] = [b"prime-field\0", b"characteristic-two-field\0"];

/// The input as chunks, each led by its length octet.
struct Chunks<'a>(&'a [u8]);

impl<'a> Chunks<'a> {
    fn byte(&mut self) -> u8 {
        let (&b, rest) = self.0.split_first().unwrap_or((&0, &[]));
        self.0 = rest;
        b
    }

    fn take(&mut self) -> &'a [u8] {
        let n = usize::from(self.byte()).min(self.0.len());
        let (chunk, rest) = self.0.split_at(n);
        self.0 = rest;
        chunk
    }
}

fn key(s: &[u8]) -> *const c_char {
    s.as_ptr().cast()
}

/// Makes a key from `params`, or NULL.
fn fromdata(selection: c_int, params: *mut OSSL_PARAM) -> *mut EVP_PKEY {
    // SAFETY: static names.
    let c = unsafe { EVP_PKEY_CTX_new_from_name(ptr::null_mut(), key(b"EC\0"), ptr::null()) };
    let mut k = ptr::null_mut();
    // SAFETY: the context; an array or NULL.
    unsafe {
        EVP_PKEY_fromdata_init(c);
        EVP_PKEY_fromdata(c, &mut k, selection, params);
        EVP_PKEY_CTX_free(c);
    }
    k
}

fuzz_target!(|input: &[u8]| {
    let mut ch = Chunks(input);
    let flags = ch.byte();
    let selection = SELECTIONS[usize::from(ch.byte()) % SELECTIONS.len()];
    let mut numbers: Vec<*mut BIGNUM> = Vec::new();
    // SAFETY: no preconditions.
    let bld = unsafe { OSSL_PARAM_BLD_new() };
    let mut bn = |bytes: &[u8]| {
        // SAFETY: the octets; a new number.
        let b = unsafe { BN_bin2bn(bytes.as_ptr(), bytes.len() as c_int, ptr::null_mut()) };
        numbers.push(b);
        b
    };
    // SAFETY: the builder; static keys and values; numbers and chunks that outlive the array.
    unsafe {
        if flags & 1 == 0 {
            let g = GROUPS[usize::from(ch.byte()) % GROUPS.len()];
            OSSL_PARAM_BLD_push_utf8_string(bld, key(b"group\0"), key(g), 0);
        } else {
            let f = FIELDS[usize::from(flags >> 7)];
            OSSL_PARAM_BLD_push_utf8_string(bld, key(b"field-type\0"), key(f), 0);
            for name in [&b"p\0"[..], b"a\0", b"b\0", b"order\0", b"cofactor\0"] {
                let n = bn(ch.take());
                OSSL_PARAM_BLD_push_BN(bld, key(name), n);
            }
            let gen_ = ch.take();
            OSSL_PARAM_BLD_push_octet_string(
                bld,
                key(b"generator\0"),
                gen_.as_ptr().cast(),
                gen_.len(),
            );
            if flags & 2 != 0 {
                let seed = ch.take();
                OSSL_PARAM_BLD_push_octet_string(
                    bld,
                    key(b"seed\0"),
                    seed.as_ptr().cast(),
                    seed.len(),
                );
            }
        }
        if flags & 4 != 0 {
            let n = bn(ch.take());
            OSSL_PARAM_BLD_push_BN(bld, key(b"priv\0"), n);
        }
        if flags & 8 != 0 {
            let q = ch.take();
            OSSL_PARAM_BLD_push_octet_string(bld, key(b"pub\0"), q.as_ptr().cast(), q.len());
        }
        if flags & 16 != 0 {
            let f = FORMATS[usize::from(ch.byte()) % FORMATS.len()];
            OSSL_PARAM_BLD_push_utf8_string(bld, key(b"point-format\0"), key(f), 0);
        }
        if flags & 32 != 0 {
            let c = CHECKS[usize::from(ch.byte()) % CHECKS.len()];
            OSSL_PARAM_BLD_push_utf8_string(bld, key(b"group-check\0"), key(c), 0);
        }
        if flags & 64 != 0 {
            OSSL_PARAM_BLD_push_int(bld, key(b"use-cofactor-flag\0"), c_int::from(ch.byte() & 1));
        }
    }
    // SAFETY: the builder; what it reads is alive.
    let params = unsafe { OSSL_PARAM_BLD_to_param(bld) };
    let k = fromdata(selection, params);
    if !k.is_null() {
        let mut out = ptr::null_mut();
        // SAFETY: a live key; a place for an array. A private number longer than the order
        // doesn't fit its padded export, which fails as OpenSSL's does.
        if unsafe { EVP_PKEY_todata(k, 0x87, &mut out) } == 1 {
            let back = fromdata(0x87, out);
            assert!(!back.is_null(), "its export imports");
            // SAFETY: live keys.
            assert_eq!(
                unsafe { EVP_PKEY_parameters_eq(k, back) },
                1,
                "with the same parameters"
            );
            // SAFETY: made above, each freed once.
            unsafe {
                EVP_PKEY_free(back);
                OSSL_PARAM_free(out);
            }
        }
        // SAFETY: a live key.
        let c = unsafe { EVP_PKEY_CTX_new_from_pkey(ptr::null_mut(), k, ptr::null()) };
        // SAFETY: the context; results either way.
        unsafe {
            EVP_PKEY_public_check_quick(c);
            EVP_PKEY_param_check(c);
            EVP_PKEY_check(c);
            EVP_PKEY_CTX_free(c);
            EVP_PKEY_free(k);
        }
    }
    // SAFETY: made above, each freed once.
    unsafe {
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(bld);
        for b in numbers {
            BN_free(b);
        }
        ERR_clear_error();
    }
});
