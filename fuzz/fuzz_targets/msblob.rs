//! Fuzzes the Microsoft key blob and PVK readers on untrusted input: b2i_PrivateKey and
//! b2i_PublicKey (with the input's own length and with a longer one claimed by none), their
//! BIO forms, b2i_PVK_bio (with a passphrase, so an encrypted PVK gets as far as PVKKDF), and
//! the MSBLOB and PVK decoders; each key read is written again. Nothing may crash or read out
//! of bounds (ASan).

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{BIO, BIO_METHOD, EVP_PKEY, OSSL_DECODER_CTX};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn b2i_PrivateKey(in_: *mut *const c_uchar, length: c_long) -> *mut EVP_PKEY;
    fn b2i_PublicKey(in_: *mut *const c_uchar, length: c_long) -> *mut EVP_PKEY;
    fn b2i_PrivateKey_bio(in_: *mut BIO) -> *mut EVP_PKEY;
    fn b2i_PublicKey_bio(in_: *mut BIO) -> *mut EVP_PKEY;
    fn b2i_PVK_bio(in_: *mut BIO, cb: Option<unsafe extern "C" fn(*mut c_char, c_int, c_int, *mut c_void) -> c_int>, u: *mut c_void) -> *mut EVP_PKEY;
    fn i2b_PrivateKey_bio(out: *mut BIO, pk: *const EVP_PKEY) -> c_int;
    fn i2b_PublicKey_bio(out: *mut BIO, pk: *const EVP_PKEY) -> c_int;
    fn i2b_PVK_bio(out: *mut BIO, pk: *const EVP_PKEY, enclevel: c_int, cb: *const c_void, u: *mut c_void) -> c_int;
    fn BIO_new_mem_buf(buf: *const c_void, len: c_int) -> *mut BIO;
    fn BIO_new(m: *const BIO_METHOD) -> *mut BIO;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn EVP_PKEY_free(k: *mut EVP_PKEY);
    fn OSSL_DECODER_CTX_new_for_pkey(pkey: *mut *mut EVP_PKEY, input_type: *const c_char, input_struct: *const c_char, keytype: *const c_char, selection: c_int, libctx: *mut c_void, propquery: *const c_char) -> *mut OSSL_DECODER_CTX;
    fn OSSL_DECODER_CTX_set_passphrase(ctx: *mut OSSL_DECODER_CTX, kstr: *const c_uchar, klen: usize) -> c_int;
    fn OSSL_DECODER_from_data(ctx: *mut OSSL_DECODER_CTX, pdata: *mut *const c_uchar, len: *mut usize) -> c_int;
    fn OSSL_DECODER_CTX_free(ctx: *mut OSSL_DECODER_CTX);
    fn ERR_clear_error();
}

/// The passphrase "pw".
unsafe extern "C" fn pw(buf: *mut c_char, size: c_int, _rwflag: c_int, _u: *mut c_void) -> c_int {
    if size < 2 {
        return -1;
    }
    // SAFETY: room for `size` octets.
    unsafe { ptr::copy_nonoverlapping(c"pw".as_ptr(), buf, 2) };
    2
}

/// Writes the key again (as a blob of each kind and a PVK) and frees it.
///
/// # Safety
/// `k` is NULL or a live key.
unsafe fn rewrite(k: *mut EVP_PKEY) {
    if k.is_null() {
        return;
    }
    // SAFETY: the key; new BIOs, freed here.
    unsafe {
        let w = BIO_new(BIO_s_mem());
        i2b_PrivateKey_bio(w, k);
        i2b_PublicKey_bio(w, k);
        i2b_PVK_bio(w, k, 0, ptr::null(), ptr::null_mut());
        BIO_free(w);
        EVP_PKEY_free(k);
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(len) = c_int::try_from(data.len()) else { return };
    // SAFETY: the input, read within its length; the keys and BIOs made here, freed.
    unsafe {
        for public in [false, true] {
            let mut p = data.as_ptr();
            let k = if public { b2i_PublicKey(&mut p, len.into()) } else { b2i_PrivateKey(&mut p, len.into()) };
            rewrite(k);
            let b = BIO_new_mem_buf(data.as_ptr().cast(), len);
            let k = if public { b2i_PublicKey_bio(b) } else { b2i_PrivateKey_bio(b) };
            BIO_free(b);
            rewrite(k);
        }
        let b = BIO_new_mem_buf(data.as_ptr().cast(), len);
        rewrite(b2i_PVK_bio(b, Some(pw), ptr::null_mut()));
        BIO_free(b);
        for input in [c"MSBLOB", c"PVK"] {
            let mut k = ptr::null_mut();
            let ctx = OSSL_DECODER_CTX_new_for_pkey(&mut k, input.as_ptr(), ptr::null(), ptr::null(), 0, ptr::null_mut(), ptr::null());
            OSSL_DECODER_CTX_set_passphrase(ctx, c"pw".as_ptr().cast(), 2);
            let mut p = data.as_ptr();
            let mut left = data.len();
            OSSL_DECODER_from_data(ctx, &mut p, &mut left);
            OSSL_DECODER_CTX_free(ctx);
            rewrite(k);
        }
        ERR_clear_error();
    }
});
