//! Fuzzes the hybrid ML-KEM groups (X25519MLKEM768, X448MLKEM1024, SecP256r1MLKEM768,
//! SecP384r1MLKEM1024), whose TLS key shares are untrusted: a generated key decapsulates the
//! input as a ciphertext (any length), and the input is imported as a public key and set as an
//! encoded public key, which then takes an encapsulation. Nothing may crash or read out of
//! bounds (ASan); a decapsulation of the wrong length fails, and a public key taken
//! encapsulates.

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
    fn EVP_PKEY_keygen_init(c: *mut EVP_PKEY_CTX) -> c_int;
    fn EVP_PKEY_paramgen_init(c: *mut EVP_PKEY_CTX) -> c_int;
    fn EVP_PKEY_generate(c: *mut EVP_PKEY_CTX, k: *mut *mut EVP_PKEY) -> c_int;
    fn EVP_PKEY_fromdata_init(c: *mut EVP_PKEY_CTX) -> c_int;
    fn EVP_PKEY_fromdata(
        c: *mut EVP_PKEY_CTX,
        k: *mut *mut EVP_PKEY,
        selection: c_int,
        params: *mut OSSL_PARAM,
    ) -> c_int;
    fn EVP_PKEY_set1_encoded_public_key(k: *mut EVP_PKEY, p: *const u8, len: usize) -> c_int;
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

/// The hybrids: name, ciphertext length, public key length.
const ALGS: [(&core::ffi::CStr, usize, usize); 4] = [
    (c"X25519MLKEM768", 1120, 1216),
    (c"X448MLKEM1024", 1624, 1624),
    (c"SecP256r1MLKEM768", 1153, 1249),
    (c"SecP384r1MLKEM1024", 1665, 1665),
];

/// A key made by generation (`keygen`) or parameter generation (an empty key).
fn generated(alg: &core::ffi::CStr, keygen: bool) -> *mut EVP_PKEY {
    let mut k = ptr::null_mut();
    // SAFETY: a static name; the context made and freed here.
    unsafe {
        let c = EVP_PKEY_CTX_new_from_name(ptr::null_mut(), alg.as_ptr(), ptr::null());
        if keygen {
            EVP_PKEY_keygen_init(c);
        } else {
            EVP_PKEY_paramgen_init(c);
        }
        assert_eq!(EVP_PKEY_generate(c, &mut k), 1, "a key");
        EVP_PKEY_CTX_free(c);
    }
    k
}

/// Encapsulates to `k`: the result.
fn encapsulate(k: *mut EVP_PKEY) -> c_int {
    let (mut ct, mut ss) = ([0u8; 2000], [0u8; 200]);
    let (mut cl, mut sl) = (ct.len(), ss.len());
    // SAFETY: a live key; rooms of the lengths given; the context made and freed here.
    unsafe {
        let c = EVP_PKEY_CTX_new_from_pkey(ptr::null_mut(), k, ptr::null());
        EVP_PKEY_encapsulate_init(c, ptr::null());
        let r = EVP_PKEY_encapsulate(c, ct.as_mut_ptr(), &mut cl, ss.as_mut_ptr(), &mut sl);
        EVP_PKEY_CTX_free(c);
        r
    }
}

fuzz_target!(|input: &[u8]| {
    let Some((&flags, rest)) = input.split_first() else {
        return;
    };
    let (alg, ctlen, publen) = ALGS[usize::from(flags & 3)];
    match flags >> 2 & 3 {
        0 => {
            let k = generated(alg, true);
            let mut ss = [0u8; 200];
            let mut sl = ss.len();
            // SAFETY: a live key; room for the secret; the input's octets.
            let r = unsafe {
                let c = EVP_PKEY_CTX_new_from_pkey(ptr::null_mut(), k, ptr::null());
                assert_eq!(EVP_PKEY_decapsulate_init(c, ptr::null()), 1);
                let r =
                    EVP_PKEY_decapsulate(c, ss.as_mut_ptr(), &mut sl, rest.as_ptr(), rest.len());
                EVP_PKEY_CTX_free(c);
                r
            };
            assert!(r == 0 || r == 1, "a decapsulation is 0 or 1");
            if rest.len() != ctlen {
                assert_eq!(r, 0, "a ciphertext of another length doesn't decapsulate");
            }
            // SAFETY: made above.
            unsafe { EVP_PKEY_free(k) };
        }
        1 => {
            let mut data = rest.to_vec();
            let mut k = ptr::null_mut();
            // SAFETY: a static name and key; the copy outlives the array.
            let r = unsafe {
                let c = EVP_PKEY_CTX_new_from_name(ptr::null_mut(), alg.as_ptr(), ptr::null());
                let mut params = [
                    OSSL_PARAM_construct_octet_string(
                        c"pub".as_ptr(),
                        data.as_mut_ptr().cast(),
                        data.len(),
                    ),
                    OSSL_PARAM_construct_end(),
                ];
                EVP_PKEY_fromdata_init(c);
                let r = EVP_PKEY_fromdata(c, &mut k, 0x86, params.as_mut_ptr());
                EVP_PKEY_CTX_free(c);
                r
            };
            if r == 1 {
                assert_eq!(data.len(), publen, "only a public key of the right length");
                assert_eq!(encapsulate(k), 1, "a public key taken encapsulates");
            }
            // SAFETY: made above, or NULL.
            unsafe { EVP_PKEY_free(k) };
        }
        _ => {
            let k = generated(alg, false);
            // SAFETY: a live key; the input's octets.
            if unsafe { EVP_PKEY_set1_encoded_public_key(k, rest.as_ptr(), rest.len()) } == 1 {
                assert_eq!(rest.len(), publen, "only a public key of the right length");
                assert_eq!(encapsulate(k), 1, "a public key taken encapsulates");
            }
            // SAFETY: made above.
            unsafe { EVP_PKEY_free(k) };
        }
    }
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
