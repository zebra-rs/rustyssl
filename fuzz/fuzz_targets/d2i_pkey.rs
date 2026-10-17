//! Fuzzes decoding keys from DER, which certificates, key files, and protocols bring from
//! untrusted sources: d2i_AutoPrivateKey, d2i_PrivateKey of each classic key type, d2i_PUBKEY,
//! EVP_PKCS82PKEY, and d2i_X509_PUBKEY, through the key decoders and the legacy fallbacks.
//! Nothing may crash or read out of bounds (ASan), the octets consumed must lie within the
//! input, and a key decoded must answer for its sizes and parameters.
//!
//! The post-quantum key decoders come with step 4.7b2b (their placeholders abort for a key of
//! theirs), so inputs naming the NIST algorithm arcs they use are skipped.

#![no_main]

use core::ffi::{c_char, c_int, c_long};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{EVP_PKEY, PKCS8_PRIV_KEY_INFO, X509_PUBKEY};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn d2i_AutoPrivateKey(a: *mut *mut EVP_PKEY, pp: *mut *const u8, len: c_long) -> *mut EVP_PKEY;
    fn d2i_PrivateKey(t: c_int, a: *mut *mut EVP_PKEY, pp: *mut *const u8, len: c_long) -> *mut EVP_PKEY;
    fn d2i_PUBKEY(a: *mut *mut EVP_PKEY, pp: *mut *const u8, len: c_long) -> *mut EVP_PKEY;
    fn d2i_PKCS8_PRIV_KEY_INFO(a: *mut *mut PKCS8_PRIV_KEY_INFO, pp: *mut *const u8, len: c_long) -> *mut PKCS8_PRIV_KEY_INFO;
    fn PKCS8_PRIV_KEY_INFO_free(p: *mut PKCS8_PRIV_KEY_INFO);
    fn EVP_PKCS82PKEY(p: *const PKCS8_PRIV_KEY_INFO) -> *mut EVP_PKEY;
    fn d2i_X509_PUBKEY(a: *mut *mut X509_PUBKEY, pp: *mut *const u8, len: c_long) -> *mut X509_PUBKEY;
    fn X509_PUBKEY_get(x: *const X509_PUBKEY) -> *mut EVP_PKEY;
    fn X509_PUBKEY_free(x: *mut X509_PUBKEY);
    fn EVP_PKEY_get_bits(k: *const EVP_PKEY) -> c_int;
    fn EVP_PKEY_get_size(k: *const EVP_PKEY) -> c_int;
    fn EVP_PKEY_get_security_bits(k: *const EVP_PKEY) -> c_int;
    fn EVP_PKEY_get_octet_string_param(k: *const EVP_PKEY, n: *const c_char, b: *mut u8, l: usize, o: *mut usize) -> c_int;
    fn EVP_PKEY_eq(a: *const EVP_PKEY, b: *const EVP_PKEY) -> c_int;
    fn EVP_PKEY_free(k: *mut EVP_PKEY);
    fn ERR_clear_error();
}

/// The key types d2i_PrivateKey is given (rsaEncryption, RSA-PSS, DSA, DH, X9.42 DH, EC, SM2,
/// X25519, X448, ED25519, ED448).
const TYPES: [c_int; 11] = [6, 912, 116, 28, 920, 408, 1172, 1034, 1035, 1087, 1088];

/// The NIST arcs of ML-DSA and SLH-DSA (2.16.840.1.101.3.4.3) and ML-KEM (...4.4).
fn names_post_quantum(input: &[u8]) -> bool {
    input.windows(8).any(|w| {
        w[..7] == [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04] && (w[7] == 3 || w[7] == 4)
    })
}

fuzz_target!(|input: &[u8]| {
    let Some((&how, der)) = input.split_first() else {
        return;
    };
    if names_post_quantum(der) {
        return;
    }
    let Ok(len) = c_long::try_from(der.len()) else {
        return;
    };
    let mut p = der.as_ptr();
    // SAFETY: the input's octets; the keys and structures made here, freed once.
    unsafe {
        let k = match how % 6 {
            0 => d2i_AutoPrivateKey(ptr::null_mut(), &mut p, len),
            1 => d2i_PrivateKey(TYPES[usize::from(how / 6) % TYPES.len()], ptr::null_mut(), &mut p, len),
            2 => d2i_PUBKEY(ptr::null_mut(), &mut p, len),
            3 => {
                let p8 = d2i_PKCS8_PRIV_KEY_INFO(ptr::null_mut(), &mut p, len);
                let k = if p8.is_null() { ptr::null_mut() } else { EVP_PKCS82PKEY(p8) };
                PKCS8_PRIV_KEY_INFO_free(p8);
                k
            }
            _ => {
                let x = d2i_X509_PUBKEY(ptr::null_mut(), &mut p, len);
                let k = if x.is_null() { ptr::null_mut() } else { X509_PUBKEY_get(x) };
                X509_PUBKEY_free(x);
                k
            }
        };
        let consumed = (p as usize).wrapping_sub(der.as_ptr() as usize);
        assert!(consumed <= der.len(), "consumed past the input");
        if !k.is_null() {
            core::hint::black_box((EVP_PKEY_get_bits(k), EVP_PKEY_get_size(k), EVP_PKEY_get_security_bits(k)));
            let mut buf = [0u8; 2600];
            let mut out = 0usize;
            if EVP_PKEY_get_octet_string_param(k, c"encoded-pub-key".as_ptr(), buf.as_mut_ptr(), buf.len(), &mut out) != 0 {
                assert!(out <= buf.len(), "an encoding past its buffer");
            }
            assert_eq!(EVP_PKEY_eq(k, k), 1, "a key not equal to itself");
            EVP_PKEY_free(k);
        }
        ERR_clear_error();
    }
});
