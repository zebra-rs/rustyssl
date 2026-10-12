//! Fuzzes the default provider's DRBGs through the C ABI (`EVP_RAND`), against the DRBG
//! mechanisms of `rustyssl_crypto::rand` as the oracle: the first octets pick the DRBG (CTR-DRBG
//! with a key length, with or without the derivation function; HASH- or HMAC-DRBG with a
//! digest), whether a personalization string is given, and the output length; the rest splits
//! into the entropy and nonce a TEST-RAND parent gives, and additional input. The DRBG,
//! instantiated under the parent, must generate (twice, then after a reseed with entropy given)
//! what the backend mechanism does from the same entropy, nonce, and personalization string (the
//! reference's default one if none). Nothing may panic or go out of bounds (ASan).

#![no_main]

use core::ffi::{CStr, c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;
use rustyssl_crypto::md::Algorithm;
use rustyssl_crypto::rand::{CtrDrbg, Drbg, HashDrbg, HmacDrbg};

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
    fn EVP_RAND_fetch(ctx: *mut c_void, name: *const c_char, props: *const c_char) -> *mut c_void;
    fn EVP_RAND_free(rand: *mut c_void);
    fn EVP_RAND_CTX_new(rand: *mut c_void, parent: *mut c_void) -> *mut c_void;
    fn EVP_RAND_CTX_free(ctx: *mut c_void);
    fn EVP_RAND_CTX_set_params(ctx: *mut c_void, params: *const Param) -> c_int;
    fn EVP_RAND_instantiate(
        ctx: *mut c_void,
        strength: c_uint,
        pr: c_int,
        pstr: *const c_uchar,
        pstr_len: usize,
        params: *const Param,
    ) -> c_int;
    fn EVP_RAND_generate(
        ctx: *mut c_void,
        out: *mut c_uchar,
        outlen: usize,
        strength: c_uint,
        pr: c_int,
        addin: *const c_uchar,
        addin_len: usize,
    ) -> c_int;
    fn EVP_RAND_reseed(
        ctx: *mut c_void,
        pr: c_int,
        ent: *const c_uchar,
        ent_len: usize,
        addin: *const c_uchar,
        addin_len: usize,
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
    fn OSSL_PARAM_construct_uint(key: *const c_char, buf: *mut c_uint) -> Param;
    fn OSSL_PARAM_construct_end() -> Param;
    fn ERR_clear_error();
}

/// `DRBG_DEFAULT_PERS_STRING` with its NUL, as the reference passes it.
const DEFAULT_PERS: &[u8] = b"OpenSSL NIST SP 800-90A DRBG\0";

const DIGESTS: [(&CStr, Algorithm); 5] = [
    (c"SHA1", Algorithm::Sha1),
    (c"SHA256", Algorithm::Sha256),
    (c"SHA512", Algorithm::Sha512),
    (c"SHA3-256", Algorithm::Sha3_256),
    (c"SHA512-224", Algorithm::Sha512_224),
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

fn end() -> Param {
    // SAFETY: no preconditions.
    unsafe { OSSL_PARAM_construct_end() }
}

/// A context of the random algorithm `name` under `parent`.
fn rand_ctx(name: &CStr, parent: *mut c_void) -> *mut c_void {
    // SAFETY: a static name; the caller's parent.
    unsafe {
        let rand = EVP_RAND_fetch(ptr::null_mut(), name.as_ptr(), ptr::null());
        assert!(!rand.is_null());
        let ctx = EVP_RAND_CTX_new(rand, parent);
        EVP_RAND_free(rand);
        ctx
    }
}

/// Some input as the C call takes it: NULL for none.
fn opt(b: &[u8]) -> (*const c_uchar, usize) {
    if b.is_empty() {
        (ptr::null(), 0)
    } else {
        (b.as_ptr(), b.len())
    }
}

fuzz_target!(|input: &[u8]| {
    let [which, d, l, rest @ ..] = input else {
        return;
    };
    let len = usize::from(*l) + 1;
    let (entropy, nonce, adin) = three(rest);
    let pers = (which & 0x80 != 0).then_some(&adin[..adin.len().min(40)]);

    // The parent: TEST-RAND of strength 256 with the entropy and nonce.
    let parent = rand_ctx(c"TEST-RAND", ptr::null_mut());
    let mut strength: c_uint = 256;
    // SAFETY: static keys; the locals outlive the call.
    let params = unsafe {
        [
            OSSL_PARAM_construct_uint(c"strength".as_ptr(), &raw mut strength),
            OSSL_PARAM_construct_octet_string(
                c"test_entropy".as_ptr(),
                entropy.as_ptr().cast_mut().cast(),
                entropy.len(),
            ),
            OSSL_PARAM_construct_octet_string(
                c"test_nonce".as_ptr(),
                nonce.as_ptr().cast_mut().cast(),
                nonce.len(),
            ),
            end(),
        ]
    };
    // SAFETY: the parent; the parameters above.
    assert_eq!(
        unsafe { EVP_RAND_CTX_set_params(parent, params.as_ptr()) },
        1
    );
    // SAFETY: as above.
    assert_eq!(
        unsafe { EVP_RAND_instantiate(parent, 0, 0, ptr::null(), 0, ptr::null()) },
        1
    );

    // The DRBG and its oracle.
    let (ctx, oracle): (*mut c_void, Box<dyn Drbg>) = match which % 3 {
        0 => {
            let (name, keylen) = [
                (c"AES-128-CTR", 16),
                (c"AES-192-CTR", 24),
                (c"AES-256-CTR", 32),
            ][usize::from(*d % 3)];
            let mut use_df: c_int = c_int::from(*d & 4 == 0);
            let ctx = rand_ctx(c"CTR-DRBG", parent);
            // SAFETY: static keys and strings; a local.
            let params = unsafe {
                [
                    OSSL_PARAM_construct_int(c"use_derivation_function".as_ptr(), &raw mut use_df),
                    OSSL_PARAM_construct_utf8_string(
                        c"cipher".as_ptr(),
                        name.as_ptr().cast_mut(),
                        0,
                    ),
                    end(),
                ]
            };
            // SAFETY: the context; the parameters above.
            assert_eq!(unsafe { EVP_RAND_CTX_set_params(ctx, params.as_ptr()) }, 1);
            (ctx, Box::new(CtrDrbg::new(keylen, use_df != 0).unwrap()))
        }
        k => {
            let (dname, alg) = DIGESTS[usize::from(*d) % DIGESTS.len()];
            let (name, oracle): (&CStr, Box<dyn Drbg>) = if k == 1 {
                (c"HASH-DRBG", Box::new(HashDrbg::new(alg).unwrap()))
            } else {
                (c"HMAC-DRBG", Box::new(HmacDrbg::new(alg).unwrap()))
            };
            let ctx = rand_ctx(name, parent);
            // SAFETY: static keys and strings.
            let params = unsafe {
                [
                    OSSL_PARAM_construct_utf8_string(
                        c"digest".as_ptr(),
                        dname.as_ptr().cast_mut(),
                        0,
                    ),
                    OSSL_PARAM_construct_utf8_string(
                        c"mac".as_ptr(),
                        c"HMAC".as_ptr().cast_mut(),
                        0,
                    ),
                    end(),
                ]
            };
            // SAFETY: the context; the parameters above.
            assert_eq!(unsafe { EVP_RAND_CTX_set_params(ctx, params.as_ptr()) }, 1);
            (ctx, oracle)
        }
    };
    let mut oracle = oracle;
    let limits = oracle.limits();
    let (pp, pl) = pers.map_or((ptr::null(), 0), |p| (p.as_ptr(), p.len()));
    // SAFETY: the context; the personalization string.
    let ok = unsafe { EVP_RAND_instantiate(ctx, 0, 0, pp, pl, ptr::null()) } == 1;
    // What the DRBG takes from its parent: the entropy (up to its limit) and, if it takes one,
    // the nonce (likewise).
    let used_entropy = &entropy[..entropy.len().min(limits.max_entropy)];
    let used_nonce = if limits.min_nonce > 0 {
        &nonce[..nonce.len().min(limits.max_nonce)]
    } else {
        &[][..]
    };
    let pers_used = pers.unwrap_or(DEFAULT_PERS);
    let valid = used_entropy.len() >= limits.min_entropy
        && (limits.min_nonce == 0 || !nonce.is_empty())
        && pers_used.len() <= limits.max_personalization;
    assert_eq!(
        ok,
        valid,
        "instantiation: entropy {} nonce {} pers {}",
        entropy.len(),
        nonce.len(),
        pers_used.len()
    );
    if ok {
        oracle.instantiate(used_entropy, used_nonce, pers_used);
        let adin = &adin[..adin.len().min(limits.max_additional_input)];
        let (ap, al) = opt(adin);
        for round in 0..3 {
            if round == 2 {
                // A reseed with entropy given (and the parent's after it).
                let ent: Vec<u8> = used_entropy.iter().rev().copied().collect();
                if ent.len() >= limits.min_entropy {
                    let (ep, el) = opt(&ent);
                    // SAFETY: the context; the inputs.
                    assert_eq!(unsafe { EVP_RAND_reseed(ctx, 0, ep, el, ap, al) }, 1);
                    oracle.reseed(&ent, adin).unwrap();
                    oracle.reseed(used_entropy, &[]).unwrap();
                }
            }
            let mut got = vec![0u8; len];
            // SAFETY: the context; room for `len` octets; the additional input.
            assert_eq!(
                unsafe { EVP_RAND_generate(ctx, got.as_mut_ptr(), len, 0, 0, ap, al) },
                1
            );
            let mut want = vec![0u8; len];
            oracle.generate(&mut want, adin).unwrap();
            assert_eq!(got, want, "round {round}");
        }
    }
    // SAFETY: the contexts made here.
    unsafe {
        EVP_RAND_CTX_free(ctx);
        EVP_RAND_CTX_free(parent);
        ERR_clear_error();
    }
});
