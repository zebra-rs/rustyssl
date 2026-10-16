//! Fuzzes the SLH-DSA signatures (on their fast parameter sets), whose verification takes an
//! untrusted signature: a key generated from the input's seeds verifies the rest of the input
//! (any length) as a signature of a fixed message, or signs a message from the input (with a
//! context string and test entropy from it, and maybe as a raw message) and verifies the
//! signature with octets changed. Nothing may crash or read out of bounds (ASan); a signature always
//! verifies unchanged, and a verification is 0 or 1.

#![no_main]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{EVP_PKEY, EVP_PKEY_CTX, EVP_SIGNATURE, OSSL_LIB_CTX, OSSL_PARAM};
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
    fn EVP_PKEY_sign(
        c: *mut EVP_PKEY_CTX,
        sig: *mut u8,
        siglen: *mut usize,
        tbs: *const u8,
        tbslen: usize,
    ) -> c_int;
    fn EVP_PKEY_verify_message_init(
        c: *mut EVP_PKEY_CTX,
        s: *mut EVP_SIGNATURE,
        params: *const OSSL_PARAM,
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
    fn OSSL_PARAM_construct_int(key: *const c_char, buf: *mut c_int) -> OSSL_PARAM;
    fn OSSL_PARAM_construct_end() -> OSSL_PARAM;
    fn ERR_clear_error();
}

const ALGS: [(&core::ffi::CStr, usize, usize); 4] = [
    (c"SLH-DSA-SHA2-128f", 16, 17088),
    (c"SLH-DSA-SHAKE-128f", 16, 17088),
    (c"SLH-DSA-SHA2-192f", 24, 35664),
    (c"SLH-DSA-SHAKE-256f", 32, 49856),
];

/// Takes up to `n` octets from the front of `rest`.
fn take<'a>(rest: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (a, b) = rest.split_at(n.min(rest.len()));
    *rest = b;
    a
}

/// Verifies `sig` of `msg` with `params`: the init's result and the verification's.
fn verify(
    c: *mut EVP_PKEY_CTX,
    s: *mut EVP_SIGNATURE,
    params: &[OSSL_PARAM],
    sig: &[u8],
    msg: &[u8],
) -> (c_int, c_int) {
    // SAFETY: a live context and signature; the caller's parameters, which outlive the call.
    let init = unsafe { EVP_PKEY_verify_message_init(c, s, params.as_ptr()) };
    // SAFETY: a live context; the octets given.
    let r = unsafe { EVP_PKEY_verify(c, sig.as_ptr(), sig.len(), msg.as_ptr(), msg.len()) };
    (init, r)
}

fuzz_target!(|input: &[u8]| {
    let Some((&flags, mut rest)) = input.split_first() else {
        return;
    };
    let (alg, n, slen) = ALGS[usize::from(flags & 3)];
    let mut seed = vec![0u8; 3 * n];
    let s = take(&mut rest, 3 * n);
    seed[..s.len()].copy_from_slice(s);
    let mut k = ptr::null_mut();
    // SAFETY: a static name; the seed outlives the array; the context made and freed here.
    unsafe {
        let c = EVP_PKEY_CTX_new_from_name(ptr::null_mut(), alg.as_ptr(), ptr::null());
        let params = [
            OSSL_PARAM_construct_octet_string(
                c"seed".as_ptr(),
                seed.as_mut_ptr().cast(),
                seed.len(),
            ),
            OSSL_PARAM_construct_end(),
        ];
        EVP_PKEY_keygen_init(c);
        EVP_PKEY_CTX_set_params(c, params.as_ptr());
        assert_eq!(EVP_PKEY_generate(c, &mut k), 1, "a key from seeds");
        EVP_PKEY_CTX_free(c);
    }
    // SAFETY: a live key; a static name.
    let (c, sa) = unsafe {
        (
            EVP_PKEY_CTX_new_from_pkey(ptr::null_mut(), k, ptr::null()),
            EVP_SIGNATURE_fetch(ptr::null_mut(), alg.as_ptr(), ptr::null()),
        )
    };
    if flags & 4 != 0 {
        // The rest as a signature of a fixed message.
        // SAFETY: a static name and value.
        let none = [unsafe { OSSL_PARAM_construct_end() }];
        let (init, r) = verify(c, sa, &none, rest, b"message");
        assert_eq!(init, 1);
        assert!(r == 0 || r == 1, "a verification is 0 or 1");
        if rest.len() != slen {
            assert_eq!(r, 0, "a signature of another length doesn't verify");
        }
    } else {
        // A context string and a message, each led by its length, and 32 octets of entropy;
        // the remaining (offset, xor) triples change the signature.
        let cl = usize::from(take(&mut rest, 1).first().copied().unwrap_or(0));
        let mut ctx = take(&mut rest, cl).to_vec();
        let ml = usize::from(take(&mut rest, 1).first().copied().unwrap_or(0));
        let msg = take(&mut rest, ml).to_vec();
        let mut ent = vec![0u8; n];
        let e = take(&mut rest, n);
        ent[..e.len()].copy_from_slice(e);
        let mut encoding: c_int = c_int::from(flags & 8 == 0);
        // SAFETY: the buffers outlive the array.
        let params = unsafe {
            [
                OSSL_PARAM_construct_octet_string(
                    c"context-string".as_ptr(),
                    ctx.as_mut_ptr().cast(),
                    ctx.len(),
                ),
                OSSL_PARAM_construct_octet_string(
                    c"test-entropy".as_ptr(),
                    ent.as_mut_ptr().cast(),
                    n,
                ),
                OSSL_PARAM_construct_int(c"message-encoding".as_ptr(), &mut encoding),
                OSSL_PARAM_construct_end(),
            ]
        };
        let mut sig = vec![0u8; slen];
        let mut sl = slen;
        // SAFETY: a live context and signature; the parameters; room for the signature.
        let r = unsafe {
            assert_eq!(EVP_PKEY_sign_message_init(c, sa, params.as_ptr()), 1);
            EVP_PKEY_sign(c, sig.as_mut_ptr(), &mut sl, msg.as_ptr(), msg.len())
        };
        {
            assert_eq!((r, sl), (1, slen), "a signature");
            assert_eq!(
                verify(c, sa, &params, &sig, &msg),
                (1, 1),
                "a signature verifies unchanged"
            );
            for t in rest.chunks_exact(3) {
                let i = usize::from(u16::from_le_bytes([t[0], t[1]])) % slen;
                sig[i] ^= t[2];
            }
            let (_, r) = verify(c, sa, &params, &sig, &msg);
            assert!(r == 0 || r == 1, "a verification is 0 or 1");
        }
    }
    // SAFETY: made above, each freed once.
    unsafe {
        EVP_SIGNATURE_free(sa);
        EVP_PKEY_CTX_free(c);
        EVP_PKEY_free(k);
        ERR_clear_error();
    }
});
