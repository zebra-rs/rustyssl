//! Fuzzes CMS decryption on untrusted input: the input decoded as a ContentInfo and, if it is
//! (Auth)EnvelopedData, decrypted with a password (RFC 3211's key unwrap), a KEK (AES key
//! wrap), and RSA and EC keys (OAEP parameters, ECDH's originator key and KDF parameters),
//! each from a fresh decoding. Nothing may crash or read out of bounds (ASan).

#![no_main]

use core::ffi::{c_int, c_long, c_uchar, c_uint};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{BIO, BIO_METHOD, CMS_ContentInfo, EVP_PKEY, X509};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn d2i_CMS_ContentInfo(a: *mut *mut CMS_ContentInfo, pp: *mut *const c_uchar, len: c_long) -> *mut CMS_ContentInfo;
    fn CMS_ContentInfo_free(a: *mut CMS_ContentInfo);
    fn CMS_decrypt(cms: *mut CMS_ContentInfo, pk: *mut EVP_PKEY, cert: *mut X509, dcont: *mut BIO, out: *mut BIO, flags: c_uint) -> c_int;
    fn CMS_decrypt_set1_password(cms: *mut CMS_ContentInfo, pass: *mut c_uchar, passlen: isize) -> c_int;
    fn CMS_decrypt_set1_key(cms: *mut CMS_ContentInfo, key: *mut c_uchar, keylen: usize, id: *const c_uchar, idlen: usize) -> c_int;
    fn PEM_read_bio_PrivateKey(bp: *mut BIO, x: *mut *mut EVP_PKEY, cb: *mut core::ffi::c_void, u: *mut core::ffi::c_void) -> *mut EVP_PKEY;
    fn EVP_PKEY_free(pkey: *mut EVP_PKEY);
    fn BIO_new(m: *const BIO_METHOD) -> *mut BIO;
    fn BIO_new_mem_buf(buf: *const core::ffi::c_void, len: c_int) -> *mut BIO;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn ERR_clear_error();
}

const RSA_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALmArfR+4VzWVKki
E/W9DkexrDbauDcSSy3TyJesI5aYBJ3R5aeGzS3Gwm5m4u/BYhPk8UTy+PN+cnPw
xT4gcaJthCk+WKbO+wktlpusHZXKNpdTHzmFrlsZc6KLKq8tuzzXnawxMv/gPLEO
KIJJDn2l3zG/R7A6zwg9q/tauDNhAgMBAAECgYEAhwVImMu5kW9YE/t/97/yIvEJ
3qt4pm0kV2jteqiLBtQDmDPtKvENayJe5yjwSX7CuqRLkNohpmoFOKqphrzquAY0
tHJKfs/dYs3zKhfpPvlAnoAML5NUFetZrDWpqNFnDLE5BC1q/KnZVdlqThRrELEn
2LUm+XXtENcJR59s+yECQQDzosFpHrU4QTuzu/0OhtENRJchduA0Dr20uAiAVJ3v
Y6a+XHA0kWVqZ0cY+hWiJUwgl6JCIQk0Frx81PcSeP/FAkEAwuqs+LShUr1wCRGQ
Kaw9uJ86EzmazinwXWz2D//nN4m12KcTOuvNX+UQjlhBO14otRfwBNJWzPuOskNw
5kJi7QJBAIGNXS1pr9GPFpEXeJPd6pIUlAyuasAjyoqrhZG/7Q+bvNHi06OQYQ44
htzoNtK25Ik8OILTkFJLeMUkdZE0GEUCQBu1yzNsUob1wYi4g3s5Lmkh0drL1LM8
iRxvEihCJDfkDwMm9Xfp7/+TDCCAcX2kLDtalNfKo2Zu2OGE7vb9Nx0CQEQmVDFy
EkBz0E+P6mIeiDpg/4cFG8f+Uz8QHrqNC+YFWA3JK2+QGJn5XgqPL8r97BFjMIxQ
5UnOFyI3lig5SFI=
-----END PRIVATE KEY-----
";

const EC_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgLkdevDxeg4v1m2Y7
/1HCYEAjUQZgcaW8rJrHXQlWf32hRANCAARPnndmGK0zys00giH7M+beePFYbSIk
3MZKw4u594qttHl3huTTpAtGL7Eta2f0zUTTauqzwpgv20gtghban85u
-----END PRIVATE KEY-----
";

const CMS_DEBUG_DECRYPT: c_uint = 0x20000;

fn key(pem: &str) -> *mut EVP_PKEY {
    let len = c_int::try_from(pem.len()).unwrap_or(0);
    // SAFETY: the PEM's octets, which outlive the BIO.
    let b = unsafe { BIO_new_mem_buf(pem.as_ptr().cast(), len) };
    // SAFETY: a live BIO; no password callback.
    let k = unsafe { PEM_read_bio_PrivateKey(b, ptr::null_mut(), ptr::null_mut(), ptr::null_mut()) };
    // SAFETY: the BIO made here.
    unsafe { BIO_free(b) };
    k
}

/// Decodes the input afresh and runs `f` on it with an output BIO.
fn with_cms(data: &[u8], f: impl FnOnce(*mut CMS_ContentInfo, *mut BIO)) {
    let Ok(len) = c_long::try_from(data.len()) else { return };
    let mut p = data.as_ptr();
    // SAFETY: the input's octets.
    let cms = unsafe { d2i_CMS_ContentInfo(ptr::null_mut(), &mut p, len) };
    if cms.is_null() {
        return;
    }
    // SAFETY: the built-in method.
    let out = unsafe { BIO_new(BIO_s_mem()) };
    f(cms, out);
    // SAFETY: the BIO made here.
    unsafe { BIO_free(out) };
    // SAFETY: the object decoded, freed once.
    unsafe { CMS_ContentInfo_free(cms) };
}

fuzz_target!(|data: &[u8]| {
    let mut pass = *b"pw";
    let mut kek: [u8; 16] = core::array::from_fn(|i| u8::try_from(i).unwrap_or(0));
    with_cms(data, |cms, out| {
        // SAFETY: a live object; the password.
        if unsafe { CMS_decrypt_set1_password(cms, pass.as_mut_ptr(), 2) } == 1 {
            // SAFETY: as above; the BIO.
            unsafe { CMS_decrypt(cms, ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), out, 0) };
        }
    });
    with_cms(data, |cms, out| {
        // SAFETY: a live object; the key.
        if unsafe { CMS_decrypt_set1_key(cms, kek.as_mut_ptr(), kek.len(), ptr::null(), 0) } == 1 {
            // SAFETY: as above; the BIO.
            unsafe { CMS_decrypt(cms, ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), out, 0) };
        }
    });
    for (pem, flags) in [(RSA_KEY, 0), (RSA_KEY, CMS_DEBUG_DECRYPT), (EC_KEY, 0)] {
        let k = key(pem);
        with_cms(data, |cms, out| {
            // SAFETY: a live object; the key; the BIO.
            unsafe { CMS_decrypt(cms, k, ptr::null_mut(), ptr::null_mut(), out, flags) };
        });
        // SAFETY: the key loaded here.
        unsafe { EVP_PKEY_free(k) };
    }
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
