//! Fuzzes the ML-KEM KEM, whose decapsulation takes a peer's untrusted ciphertext: a key
//! generated from the input's seed decapsulates the rest of the input (any length, or an
//! encapsulation's ciphertext with octets changed). Nothing may crash or read out of bounds
//! (ASan); a ciphertext of the right length always decapsulates, to the same secret twice, and
//! an unchanged encapsulation to its own secret.

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
    fn EVP_PKEY_encapsulate_init(c: *mut EVP_PKEY_CTX, params: *const OSSL_PARAM) -> c_int;
    fn EVP_PKEY_encapsulate(
        c: *mut EVP_PKEY_CTX,
        out: *mut u8,
        outlen: *mut usize,
        secret: *mut u8,
        secretlen: *mut usize,
    ) -> c_int;
    fn EVP_PKEY_decapsulate_init(c: *mut EVP_PKEY_CTX, params: *const OSSL_PARAM) -> c_int;
    fn EVP_PKEY_decapsulate(
        c: *mut EVP_PKEY_CTX,
        secret: *mut u8,
        secretlen: *mut usize,
        input: *const u8,
        inlen: usize,
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

const ALGS: [(&core::ffi::CStr, usize); 3] = [
    (c"ML-KEM-512", 768),
    (c"ML-KEM-768", 1088),
    (c"ML-KEM-1024", 1568),
];

/// Decapsulates `ct`: the result and the secret.
fn decapsulate(c: *mut EVP_PKEY_CTX, ct: &[u8]) -> (c_int, [u8; 32]) {
    let mut ss = [0u8; 32];
    let mut sl = ss.len();
    // SAFETY: a live context; room for the secret; the ciphertext's octets.
    let r = unsafe { EVP_PKEY_decapsulate(c, ss.as_mut_ptr(), &mut sl, ct.as_ptr(), ct.len()) };
    (r, ss)
}

fuzz_target!(|input: &[u8]| {
    let Some((&flags, rest)) = input.split_first() else {
        return;
    };
    let (alg, clen) = ALGS[usize::from(flags & 3) % 3];
    let mut seed = [0u8; 64];
    let n = rest.len().min(64);
    seed[..n].copy_from_slice(&rest[..n]);
    let rest = &rest[n..];
    let mut k = ptr::null_mut();
    // SAFETY: a static name; the seed outlives the array; the context made and freed here.
    unsafe {
        let c = EVP_PKEY_CTX_new_from_name(ptr::null_mut(), alg.as_ptr(), ptr::null());
        let params = [
            OSSL_PARAM_construct_octet_string(c"seed".as_ptr(), seed.as_mut_ptr().cast(), 64),
            OSSL_PARAM_construct_end(),
        ];
        EVP_PKEY_keygen_init(c);
        EVP_PKEY_CTX_set_params(c, params.as_ptr());
        assert_eq!(EVP_PKEY_generate(c, &mut k), 1, "a key from a seed");
        EVP_PKEY_CTX_free(c);
    }
    // SAFETY: a live key.
    let c = unsafe { EVP_PKEY_CTX_new_from_pkey(ptr::null_mut(), k, ptr::null()) };
    let ct = if flags & 4 != 0 {
        rest.to_vec()
    } else {
        // An encapsulation with the first 32 octets as ikmE, its ciphertext changed by the
        // remaining (offset, xor) triples.
        let mut e = [0u8; 32];
        let m = rest.len().min(32);
        e[..m].copy_from_slice(&rest[..m]);
        let mut ct = vec![0u8; clen];
        let (mut cl, mut ss, mut sl) = (clen, [0u8; 32], 32);
        // SAFETY: the entropy outlives the array; a live context; rooms of the lengths given.
        unsafe {
            let params = [
                OSSL_PARAM_construct_octet_string(c"ikme".as_ptr(), e.as_mut_ptr().cast(), 32),
                OSSL_PARAM_construct_end(),
            ];
            assert_eq!(EVP_PKEY_encapsulate_init(c, params.as_ptr()), 1);
            assert_eq!(
                EVP_PKEY_encapsulate(c, ct.as_mut_ptr(), &mut cl, ss.as_mut_ptr(), &mut sl),
                1
            );
            assert_eq!(EVP_PKEY_decapsulate_init(c, ptr::null()), 1);
        }
        let (r, back) = decapsulate(c, &ct);
        assert_eq!(
            (r, back),
            (1, ss),
            "an encapsulation decapsulates to its secret"
        );
        for t in rest[m..].chunks_exact(3) {
            let i = usize::from(u16::from_le_bytes([t[0], t[1]])) % clen;
            ct[i] ^= t[2];
        }
        ct
    };
    // SAFETY: a live context.
    assert_eq!(unsafe { EVP_PKEY_decapsulate_init(c, ptr::null()) }, 1);
    let (r1, s1) = decapsulate(c, &ct);
    if ct.len() == clen {
        let (r2, s2) = decapsulate(c, &ct);
        assert_eq!(
            (r1, r2),
            (1, 1),
            "a ciphertext of the right length decapsulates"
        );
        assert_eq!(s1, s2, "to the same secret");
    } else {
        assert_eq!(r1, 0, "a ciphertext of another length doesn't");
    }
    // SAFETY: made above, each freed once.
    unsafe {
        EVP_PKEY_CTX_free(c);
        EVP_PKEY_free(k);
        ERR_clear_error();
    }
});
