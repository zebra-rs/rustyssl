//! Fuzzes the default provider's KDFs through the C ABI (`EVP_KDF`), against the KDF backend
//! of `rustyssl_crypto::kdf` as the oracle: the first octets pick the KDF, the digest, and the
//! output length, and the rest splits into the key (or password, or secret), salt, and info (or
//! seed). HKDF (each mode), TLS1-PRF, PBKDF2, SSKDF, X963KDF, scrypt (small costs), SSHKDF,
//! KBKDF over HMAC (both modes), X942KDF-ASN1, PKCS12KDF, KRB5KDF over AES-CBC, and Argon2
//! (small costs) must derive what the backend does; a copy of the context must derive the same
//! again (for HMAC-DRBG-KDF, which has no backend, a copy must go on as the original does).
//! Nothing may panic or go out of bounds (ASan).

#![no_main]

use core::ffi::{CStr, c_char, c_int, c_uchar, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;
use rustyssl_crypto::{kdf, md, sym};

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
    fn EVP_KDF_derive(
        ctx: *mut c_void,
        key: *mut c_uchar,
        keylen: usize,
        params: *const Param,
    ) -> c_int;
    fn OSSL_PARAM_construct_utf8_string(
        key: *const c_char,
        buf: *mut c_char,
        bsize: usize,
    ) -> Param;
    fn OSSL_PARAM_construct_octet_string(
        key: *const c_char,
        buf: *mut c_void,
        bsize: usize,
    ) -> Param;
    fn OSSL_PARAM_construct_int(key: *const c_char, buf: *mut c_int) -> Param;
    fn OSSL_PARAM_construct_uint64(key: *const c_char, buf: *mut u64) -> Param;
    fn OSSL_PARAM_construct_uint32(key: *const c_char, buf: *mut u32) -> Param;
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
    (
        a.get(1..).unwrap_or_default(),
        b.get(1..).unwrap_or_default(),
        c,
    )
}

fn octets(key: &CStr, data: &[u8]) -> Param {
    // SAFETY: a static key; the data outlives the parameter's use.
    unsafe {
        OSSL_PARAM_construct_octet_string(key.as_ptr(), data.as_ptr().cast_mut().cast(), data.len())
    }
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
    let [which, d, l, rest @ ..] = input else {
        return;
    };
    let (dname, alg, size) = DIGESTS[usize::from(*d) % DIGESTS.len()];
    let len = 1 + usize::from(*l);
    let (a, b, c) = three(rest);
    let digest = || {
        // SAFETY: a static key and name.
        unsafe {
            OSSL_PARAM_construct_utf8_string(c"digest".as_ptr(), dname.as_ptr().cast_mut(), 0)
        }
    };
    let end = || {
        // SAFETY: no preconditions.
        unsafe { OSSL_PARAM_construct_end() }
    };
    let utf8 = |key: &CStr, value: &CStr| {
        // SAFETY: static keys and strings.
        unsafe { OSSL_PARAM_construct_utf8_string(key.as_ptr(), value.as_ptr().cast_mut(), 0) }
    };
    match which % 16 {
        // HKDF in each mode.
        m @ 0..=2 => {
            let mut mode = c_int::from(m);
            // SAFETY: a static key; the mode outlives the parameter's use.
            let mode_p = unsafe { OSSL_PARAM_construct_int(c"mode".as_ptr(), &raw mut mode) };
            let params = [
                digest(),
                mode_p,
                octets(c"key", a),
                octets(c"salt", b),
                octets(c"info", c),
                end(),
            ];
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
            let params = [
                digest(),
                octets(c"secret", a),
                octets(c"seed", b),
                octets(c"seed", c),
                end(),
            ];
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
            let params = [
                digest(),
                pkcs5_p,
                octets(c"pass", a),
                octets(c"salt", b),
                iter_p,
                end(),
            ];
            let got = derive(c"PBKDF2", &params, len);
            let mut want = vec![0u8; len];
            if let Some(got) = got {
                assert!(kdf::pbkdf2(alg, a, b, iter, &mut want).is_ok());
                assert_eq!(got, want);
            }
        }
        // scrypt with small costs.
        7 => {
            let (mut n, mut r, mut p) = (
                2u64 << (*l % 6),
                1 + u64::from(*d % 4),
                1 + u64::from(*l % 3),
            );
            // SAFETY: static keys; the locals outlive the parameters' use.
            let costs = unsafe {
                [
                    OSSL_PARAM_construct_uint64(c"n".as_ptr(), &raw mut n),
                    OSSL_PARAM_construct_uint64(c"r".as_ptr(), &raw mut r),
                    OSSL_PARAM_construct_uint64(c"p".as_ptr(), &raw mut p),
                ]
            };
            let params = [
                octets(c"pass", a),
                octets(c"salt", b),
                costs[0],
                costs[1],
                costs[2],
                end(),
            ];
            let got = derive(c"SCRYPT", &params, len);
            let mut want = vec![0u8; len];
            if let Some(got) = got {
                assert!(kdf::scrypt(a, b, n, r, p, 1 << 30, &mut want).is_ok());
                assert_eq!(got, want);
            }
        }
        // SSHKDF.
        8 => {
            let kind = [c"A", c"B", c"C", c"D", c"E", c"F"][usize::from(*l) % 6];
            let params = [
                digest(),
                octets(c"key", a),
                octets(c"xcghash", b),
                octets(c"session_id", c),
                utf8(c"type", kind),
                end(),
            ];
            let got = derive(c"SSHKDF", &params, len);
            let mut want = vec![0u8; len];
            if let Some(got) = got {
                let t = kind.to_bytes().first().copied().unwrap_or(b'A');
                assert!(kdf::sshkdf(alg, a, b, t, c, &mut want).is_ok());
                assert_eq!(got, want);
            }
        }
        // KBKDF over HMAC, counter or feedback mode.
        9 | 10 => {
            let feedback = which % 16 == 10;
            let mode = if feedback { c"FEEDBACK" } else { c"COUNTER" };
            let iv: Vec<u8> = if feedback && *l % 2 == 0 {
                vec![0x5a; size]
            } else {
                Vec::new()
            };
            let params = [
                utf8(c"mac", c"HMAC"),
                digest(),
                utf8(c"mode", mode),
                octets(c"key", a),
                octets(c"salt", b),
                octets(c"info", c),
                octets(c"seed", &iv),
                end(),
            ];
            let got = derive(c"KBKDF", &params, len);
            let mut want = vec![0u8; len];
            if let Some(got) = got {
                let m = rustyssl_crypto::mac::hmac(alg, a).unwrap();
                let mode = if feedback {
                    kdf::KbkdfMode::Feedback(&iv)
                } else {
                    kdf::KbkdfMode::Counter
                };
                assert!(kdf::kbkdf(&*m, mode, 32, b, c, true, true, &mut want).is_ok());
                assert_eq!(got, want);
            }
        }
        // X942KDF-ASN1 with AES-128-WRAP's key bits.
        11 => {
            let params = [
                digest(),
                octets(c"secret", a),
                utf8(c"cekalg", c"AES-128-WRAP"),
                octets(c"ukm", b),
                end(),
            ];
            let got = derive(c"X942KDF-ASN1", &params, len);
            let mut want = vec![0u8; len];
            if let Some(got) = got {
                // id-aes128-wrap (2.16.840.1.101.3.4.1.5).
                let oid = [
                    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x05,
                ];
                let info = kdf::X942Info {
                    cek_oid: &oid,
                    kek_length: 16,
                    party_u: (!b.is_empty()).then_some(b),
                    ..kdf::X942Info::default()
                };
                assert!(kdf::x942(alg, a, &info, &mut want).is_ok());
                assert_eq!(got, want);
            }
        }
        // PKCS12KDF, a few iterations, for each purpose.
        12 => {
            let mut id = c_int::from(*l % 3) + 1;
            let mut iter = u64::from(*l % 4);
            // SAFETY: static keys; the locals outlive the parameters' use.
            let (id_p, iter_p) = unsafe {
                (
                    OSSL_PARAM_construct_int(c"id".as_ptr(), &raw mut id),
                    OSSL_PARAM_construct_uint64(c"iter".as_ptr(), &raw mut iter),
                )
            };
            let params = [
                digest(),
                octets(c"pass", a),
                octets(c"salt", b),
                id_p,
                iter_p,
                end(),
            ];
            let got = derive(c"PKCS12KDF", &params, len);
            let mut want = vec![0u8; len];
            if let Some(got) = got {
                let id = u8::try_from(id).unwrap();
                assert!(kdf::pkcs12(alg, a, b, id, iter, &mut want).is_ok());
                assert_eq!(got, want);
            }
        }
        // KRB5KDF over AES-CBC, the key's length out.
        13 => {
            let (name, n) = [
                (c"AES-128-CBC", 16),
                (c"AES-192-CBC", 24),
                (c"AES-256-CBC", 32),
            ][usize::from(*l) % 3];
            let key = rest.get(..n).unwrap_or_default();
            let constant = c.get(..c.len().min(16)).unwrap_or_default();
            let params = [
                utf8(c"cipher", name),
                octets(c"key", key),
                octets(c"constant", constant),
                end(),
            ];
            let got = derive(c"KRB5KDF", &params, n);
            if let Some(got) = got {
                let cipher = sym::block_cipher(sym::BlockAlgorithm::Aes, key, None).unwrap();
                let mut want = vec![0u8; n];
                assert!(kdf::krb5kdf(&*cipher, constant, false, &mut want).is_ok());
                assert_eq!(got, want);
            }
        }
        // HMAC-DRBG-KDF: a copy goes on as the original does.
        14 => {
            let params = [digest(), octets(c"entropy", a), octets(c"nonce", b), end()];
            let mut first = vec![0u8; len];
            let mut out = vec![0u8; len];
            let mut again = vec![0u8; len];
            // SAFETY: a static name; the parameters' data outlives these calls; room for `len`
            // octets in each buffer.
            unsafe {
                let k = EVP_KDF_fetch(ptr::null_mut(), c"HMAC-DRBG-KDF".as_ptr(), ptr::null());
                let ctx = EVP_KDF_CTX_new(k);
                EVP_KDF_free(k);
                if EVP_KDF_derive(ctx, first.as_mut_ptr(), len, params.as_ptr()) == 1 {
                    let dup = EVP_KDF_CTX_dup(ctx);
                    assert!(!dup.is_null());
                    assert_eq!(EVP_KDF_derive(ctx, out.as_mut_ptr(), len, ptr::null()), 1);
                    assert_eq!(EVP_KDF_derive(dup, again.as_mut_ptr(), len, ptr::null()), 1);
                    assert_eq!(out, again);
                    EVP_KDF_CTX_free(dup);
                } else {
                    assert!(a.is_empty() || b.is_empty());
                }
                EVP_KDF_CTX_free(ctx);
                ERR_clear_error();
            }
        }
        // Argon2, small costs, each variant.
        15 => {
            let (name, variant) = [
                (c"ARGON2I", kdf::Argon2Variant::I),
                (c"ARGON2D", kdf::Argon2Variant::D),
                (c"ARGON2ID", kdf::Argon2Variant::Id),
            ][usize::from(*d) % 3];
            let (mut lanes, mut iter, mut memcost) = (
                1 + u32::from(*l % 3),
                1 + u32::from(*d % 2),
                8 * 3 + u32::from(*l % 9),
            );
            // SAFETY: static keys; the locals outlive the parameters' use.
            let costs = unsafe {
                [
                    OSSL_PARAM_construct_uint32(c"lanes".as_ptr(), &raw mut lanes),
                    OSSL_PARAM_construct_uint32(c"iter".as_ptr(), &raw mut iter),
                    OSSL_PARAM_construct_uint32(c"memcost".as_ptr(), &raw mut memcost),
                ]
            };
            let params = [
                octets(c"pass", a),
                octets(c"salt", b),
                octets(c"secret", c),
                costs[0],
                costs[1],
                costs[2],
                end(),
            ];
            let got = derive(name, &params, len);
            if let Some(got) = got {
                let p = kdf::Argon2 {
                    variant,
                    version: 0x13,
                    passes: iter,
                    memory: memcost,
                    lanes,
                    password: a,
                    salt: b,
                    secret: c,
                    ad: &[],
                };
                let mut want = vec![0u8; len];
                assert!(kdf::argon2(&p, &mut want).is_ok());
                assert_eq!(got, want);
            } else {
                assert!(b.len() < 8 || len < 4);
            }
        }
        // SSKDF over the digest, and X9.63.
        k => {
            let name = if k == 5 { c"SSKDF" } else { c"X963KDF" };
            let params = [digest(), octets(c"secret", a), octets(c"info", c), end()];
            let got = derive(name, &params, len);
            let mut want = vec![0u8; len];
            if let Some(got) = got {
                let r = if k == 5 {
                    kdf::sskdf_hash(alg, a, c, &mut want)
                } else {
                    kdf::x963(alg, a, c, &mut want)
                };
                assert!(r.is_ok());
                assert_eq!(got, want);
            }
        }
    }
});
