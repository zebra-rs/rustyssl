//! Fuzzes the default provider's KDFs through the C ABI (`EVP_KDF`), against the KDF backend
//! of `rustyssl_crypto::kdf` as the oracle: the first octets pick the KDF, the digest, and the
//! output length, and the rest splits into the key (or password, or secret), salt, and info (or
//! seed). HKDF (each mode), TLS1-PRF, PBKDF2, SSKDF, and X963KDF must derive what the backend
//! does; a copy of the context must derive the same again. Nothing may panic or go out of
//! bounds (ASan).

#![no_main]

use core::ffi::{CStr, c_char, c_int, c_uchar, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;
use rustyssl_crypto::{kdf, md};

/// `OSSL_PARAM`.
#[repr(C)]
#[derive(Clone, Copy)]
struct Param {
    key: *const c_char,
    data_type: u32,
    data: *mut c_void,
    data_size: usize,
    return_size: usize,
}

unsafe extern "C" {
    fn EVP_KDF_fetch(ctx: *mut c_void, name: *const c_char, props: *const c_char) -> *mut c_void;
    fn EVP_KDF_free(kdf: *mut c_void);
    fn EVP_KDF_CTX_new(kdf: *mut c_void) -> *mut c_void;
    fn EVP_KDF_CTX_free(ctx: *mut c_void);
    fn EVP_KDF_CTX_dup(ctx: *const c_void) -> *mut c_void;
    fn EVP_KDF_derive(ctx: *mut c_void, key: *mut c_uchar, keylen: usize, params: *const Param) -> c_int;
    fn OSSL_PARAM_construct_utf8_string(key: *const c_char, buf: *mut c_char, bsize: usize) -> Param;
    fn OSSL_PARAM_construct_octet_string(key: *const c_char, buf: *mut c_void, bsize: usize) -> Param;
    fn OSSL_PARAM_construct_int(key: *const c_char, buf: *mut c_int) -> Param;
    fn OSSL_PARAM_construct_uint64(key: *const c_char, buf: *mut u64) -> Param;
    fn OSSL_PARAM_construct_end() -> Param;
    fn ERR_clear_error();
}

const DIGESTS: [(&CStr, md::Algorithm, usize); 6] = [
    (c"SHA1", md::Algorithm::Sha1, 20),
    (c"SHA256", md::Algorithm::Sha256, 32),
    (c"SHA384", md::Algorithm::Sha384, 48),
    (c"SHA512-256", md::Algorithm::Sha512_256, 32),
    (c"SHA3-256", md::Algorithm::Sha3_256, 32),
    (c"MD5", md::Algorithm::Md5, 16),
];

/// The rest split in three at the given octets' positions.
fn three(rest: &[u8]) -> (&[u8], &[u8], &[u8]) {
    let at = |r: &[u8]| r.first().map_or(0, |&b| usize::from(b)).min(r.len());
    let (a, r) = rest.split_at(at(rest));
    let (b, c) = r.split_at(at(r));
    (a.get(1..).unwrap_or_default(), b.get(1..).unwrap_or_default(), c)
}

fn octets(key: &CStr, data: &[u8]) -> Param {
    // SAFETY: a static key; the data outlives the parameter's use.
    unsafe { OSSL_PARAM_construct_octet_string(key.as_ptr(), data.as_ptr().cast_mut().cast(), data.len()) }
}

/// Derives `len` octets with `name` and `params`, and again from a copy; `None` if refused.
fn derive(name: &CStr, params: &[Param], len: usize) -> Option<Vec<u8>> {
    let mut out = vec![0u8; len];
    // SAFETY: a static name; the parameters' data outlives these calls; room for `len` octets.
    unsafe {
        let k = EVP_KDF_fetch(ptr::null_mut(), name.as_ptr(), ptr::null());
        assert!(!k.is_null());
        let ctx = EVP_KDF_CTX_new(k);
        EVP_KDF_free(k);
        let ok = EVP_KDF_derive(ctx, out.as_mut_ptr(), len, params.as_ptr()) == 1;
        if ok {
            let dup = EVP_KDF_CTX_dup(ctx);
            if !dup.is_null() {
                let mut again = vec![0u8; len];
                assert_eq!(EVP_KDF_derive(dup, again.as_mut_ptr(), len, ptr::null()), 1);
                assert_eq!(again, out);
                EVP_KDF_CTX_free(dup);
            }
        }
        EVP_KDF_CTX_free(ctx);
        ERR_clear_error();
        ok.then_some(out)
    }
}

fuzz_target!(|input: &[u8]| {
    let [which, d, l, rest @ ..] = input else { return };
    let (dname, alg, size) = DIGESTS[usize::from(*d) % DIGESTS.len()];
    let len = 1 + usize::from(*l);
    let (a, b, c) = three(rest);
    let digest = || {
        // SAFETY: a static key and name.
        unsafe { OSSL_PARAM_construct_utf8_string(c"digest".as_ptr(), dname.as_ptr().cast_mut(), 0) }
    };
    let end = || {
        // SAFETY: no preconditions.
        unsafe { OSSL_PARAM_construct_end() }
    };
    match which % 7 {
        // HKDF in each mode.
        m @ 0..=2 => {
            let mut mode = c_int::from(m);
            // SAFETY: a static key; the mode outlives the parameter's use.
            let mode_p = unsafe { OSSL_PARAM_construct_int(c"mode".as_ptr(), &raw mut mode) };
            let params = [digest(), mode_p, octets(c"key", a), octets(c"salt", b), octets(c"info", c), end()];
            let len = if m == 1 { size } else { len };
            let got = derive(c"HKDF", &params, len);
            let mut want = vec![0u8; len];
            let r = match m {
                0 => kdf::hkdf(alg, b, a, c, &mut want),
                1 => kdf::hkdf_extract(alg, b, a, &mut want),
                _ => kdf::hkdf_expand(alg, a, c, &mut want),
            };
            if let Some(got) = got {
                assert!(r.is_ok());
                assert_eq!(got, want);
            }
        }
        // TLS1-PRF.
        3 => {
            let params = [digest(), octets(c"secret", a), octets(c"seed", b), octets(c"seed", c), end()];
            let got = derive(c"TLS1-PRF", &params, len);
            let seed = [b, c].concat();
            let mut want = vec![0u8; len];
            if let Some(got) = got {
                assert!(kdf::tls1_prf(alg, a, &seed, &mut want).is_ok());
                assert_eq!(got, want);
            }
        }
        // PBKDF2, a few iterations.
        4 => {
            let mut iter = 1 + u64::from(*l % 4);
            let mut pkcs5: c_int = 1;
            // SAFETY: static keys; the locals outlive the parameters' use.
            let (iter_p, pkcs5_p) = unsafe {
                (
                    OSSL_PARAM_construct_uint64(c"iter".as_ptr(), &raw mut iter),
                    OSSL_PARAM_construct_int(c"pkcs5".as_ptr(), &raw mut pkcs5),
                )
            };
            let params = [digest(), pkcs5_p, octets(c"pass", a), octets(c"salt", b), iter_p, end()];
            let got = derive(c"PBKDF2", &params, len);
            let mut want = vec![0u8; len];
            if let Some(got) = got {
                assert!(kdf::pbkdf2(alg, a, b, iter, &mut want).is_ok());
                assert_eq!(got, want);
            }
        }
        // SSKDF over the digest, and X9.63.
        k => {
            let name = if k == 5 { c"SSKDF" } else { c"X963KDF" };
            let params = [digest(), octets(c"secret", a), octets(c"info", c), end()];
            let got = derive(name, &params, len);
            let mut want = vec![0u8; len];
            if let Some(got) = got {
                let r = if k == 5 { kdf::sskdf_hash(alg, a, c, &mut want) } else { kdf::x963(alg, a, c, &mut want) };
                assert!(r.is_ok());
                assert_eq!(got, want);
            }
        }
    }
});
