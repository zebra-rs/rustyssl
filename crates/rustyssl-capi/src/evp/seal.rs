//! Envelope encryption (`p_seal.c`, `p_open.c`): `EVP_SealInit` encrypts a random key for each
//! public key and starts the cipher with it; `EVP_OpenInit` decrypts that key with the private
//! key and starts the decryption. Their updates are the header's macros over
//! `EVP_EncryptUpdate` and `EVP_DecryptUpdate`.

use core::ffi::{c_int, c_uchar};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_EVP, ERR_R_EVP_LIB, EVP_CIPHER, EVP_CIPHER_CTX, EVP_MAX_KEY_LENGTH, EVP_PKEY,
    EVP_PKEY_CTX, OSSL_LIB_CTX,
};
use rustyssl_crypto::bn::Zeroizing;

use super::asymcipher::{
    EVP_PKEY_decrypt, EVP_PKEY_decrypt_init, EVP_PKEY_encrypt, EVP_PKEY_encrypt_init,
};
use super::cipher::EVP_CIPHER_get0_provider;
use super::cipher_ctx::{
    EVP_CIPHER_CTX_get_iv_length, EVP_CIPHER_CTX_get_key_length, EVP_CIPHER_CTX_get0_cipher,
    EVP_CIPHER_CTX_rand_key, EVP_CIPHER_CTX_reset, EVP_CIPHER_CTX_set_key_length,
    EVP_DecryptFinal_ex, EVP_DecryptInit_ex, EVP_EncryptFinal_ex, EVP_EncryptInit_ex,
};
use super::pkey::EVP_PKEY_get_size;
use super::pkey_ctx::{EVP_PKEY_CTX_free, EVP_PKEY_CTX_new, EVP_PKEY_CTX_new_from_pkey};
use crate::err;
use crate::ffi::ffi_export;
use crate::rand_lib::RAND_priv_bytes_ex;

/// A public-key context, freed when it drops.
struct Pctx(*mut EVP_PKEY_CTX);

impl Drop for Pctx {
    fn drop(&mut self) {
        // SAFETY: a context made here, or NULL.
        unsafe { EVP_PKEY_CTX_free(self.0) };
    }
}

/// The library context of the cipher the context holds (its provider's), NULL if none.
///
/// # Safety
/// `ctx` is a live cipher context.
unsafe fn cipher_libctx(ctx: *const EVP_CIPHER_CTX) -> *mut OSSL_LIB_CTX {
    // SAFETY: the caller's context.
    let cipher = unsafe { EVP_CIPHER_CTX_get0_cipher(ctx) };
    if cipher.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the context's cipher.
    let prov = unsafe { EVP_CIPHER_get0_provider(cipher) };
    // SAFETY: the cipher's provider, or NULL.
    unsafe { crate::provider::libctx_of(prov) }
}

ffi_export! {
    /// Starts `type` (unless NULL, keeping the context's) with a random key and IV, and that
    /// key encrypted for each of the `npubk` keys into `ek[i]` (room for its size), its length
    /// in `ekl[i]`. `npubk`, 1 without public keys (only the cipher set), or 0.
    ///
    /// # Safety
    /// `ctx` is a live cipher context; `type` is NULL or live; `iv` has room for the cipher's
    /// IV; `ek`, `ekl` and `pubk` hold `npubk` entries, each `ek[i]` room for `pubk[i]`'s size.
    pub unsafe extern "C" fn EVP_SealInit(ctx: *mut EVP_CIPHER_CTX, type_: *const EVP_CIPHER, ek: *mut *mut c_uchar, ekl: *mut c_int, iv: *mut c_uchar, pubk: *mut *mut EVP_PKEY, npubk: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if !type_.is_null() {
            // SAFETY: the caller's context.
            unsafe { EVP_CIPHER_CTX_reset(ctx) };
            // SAFETY: the context; the caller's cipher.
            if unsafe { EVP_EncryptInit_ex(ctx, type_, ptr::null_mut(), ptr::null(), ptr::null()) } == 0 {
                return 0;
            }
        }
        // SAFETY: the caller's context.
        let libctx = unsafe { cipher_libctx(ctx) };
        let Ok(n) = usize::try_from(npubk) else { return 1 };
        if n == 0 || pubk.is_null() {
            return 1;
        }
        let mut key = Zeroizing::new([0u8; EVP_MAX_KEY_LENGTH as usize]);
        // SAFETY: the context; room for its key (at most EVP_MAX_KEY_LENGTH).
        if unsafe { EVP_CIPHER_CTX_rand_key(ctx, key.as_mut_ptr()) } <= 0 {
            return 0;
        }
        // SAFETY: the context.
        let Ok(ivlen) = usize::try_from(unsafe { EVP_CIPHER_CTX_get_iv_length(ctx) }) else { return 0 };
        // SAFETY: the caller's room for the cipher's IV.
        if unsafe { RAND_priv_bytes_ex(libctx, iv, ivlen, 0) } <= 0 {
            return 0;
        }
        // SAFETY: the context.
        let Ok(keylen) = usize::try_from(unsafe { EVP_CIPHER_CTX_get_key_length(ctx) }) else { return 0 };
        if keylen > key.len() {
            return 0;
        }
        // SAFETY: the context; the key and the IV.
        if unsafe { EVP_EncryptInit_ex(ctx, ptr::null(), ptr::null_mut(), key.as_ptr(), iv) } == 0 {
            return 0;
        }
        if ek.is_null() || ekl.is_null() {
            return 0;
        }
        // SAFETY: the caller's `npubk` keys.
        let keys = unsafe { core::slice::from_raw_parts(pubk, n) };
        // SAFETY: the caller's `npubk` buffers.
        let outs = unsafe { core::slice::from_raw_parts(ek, n) };
        // SAFETY: the caller's `npubk` length slots.
        let lens = unsafe { core::slice::from_raw_parts_mut(ekl, n) };
        for ((&pk, &out), outl) in keys.iter().zip(outs).zip(lens.iter_mut()) {
            // SAFETY: the caller's key.
            let Ok(mut outlen) = usize::try_from(unsafe { EVP_PKEY_get_size(pk) }) else { return 0 };
            // SAFETY: the cipher's library context; the caller's key.
            let p = Pctx(unsafe { EVP_PKEY_CTX_new_from_pkey(libctx, pk, ptr::null()) });
            if p.0.is_null() {
                err::raise(ERR_LIB_EVP, ERR_R_EVP_LIB, "EVP_SealInit");
                return 0;
            }
            // SAFETY: the context made above.
            if unsafe { EVP_PKEY_encrypt_init(p.0) } <= 0 {
                return 0;
            }
            // SAFETY: the context; the caller's room for the key's size; the cipher key.
            if unsafe { EVP_PKEY_encrypt(p.0, out, &raw mut outlen, key.as_ptr(), keylen) } <= 0 {
                return 0;
            }
            let Ok(l) = c_int::try_from(outlen) else { return 0 };
            *outl = l;
        }
        npubk
    }
}

ffi_export! {
    /// Finishes the encryption into `out` and readies the context for another message with
    /// the same key. 1, or 0.
    ///
    /// # Safety
    /// As for `EVP_EncryptFinal_ex`.
    pub unsafe extern "C" fn EVP_SealFinal(ctx: *mut EVP_CIPHER_CTX, out: *mut c_uchar, outl: *mut c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let mut i = unsafe { EVP_EncryptFinal_ex(ctx, out, outl) };
        if i != 0 {
            // SAFETY: as above.
            i = unsafe { EVP_EncryptInit_ex(ctx, ptr::null(), ptr::null_mut(), ptr::null(), ptr::null()) };
        }
        i
    }
}

ffi_export! {
    /// Starts decrypting with `type` (unless NULL), the key `ek` (`ekl` octets) decrypted with
    /// `priv_`, and `iv`. 1 (also without a key: only the cipher set), or 0.
    ///
    /// # Safety
    /// `ctx` is a live cipher context; `type` and `priv_` are NULL or live; `ek` holds `ekl`
    /// octets; `iv` holds the cipher's IV.
    pub unsafe extern "C" fn EVP_OpenInit(ctx: *mut EVP_CIPHER_CTX, type_: *const EVP_CIPHER, ek: *const c_uchar, ekl: c_int, iv: *const c_uchar, priv_: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if !type_.is_null() {
            // SAFETY: the caller's context.
            unsafe { EVP_CIPHER_CTX_reset(ctx) };
            // SAFETY: the context; the caller's cipher.
            if unsafe { EVP_DecryptInit_ex(ctx, type_, ptr::null_mut(), ptr::null(), ptr::null()) } == 0 {
                return 0;
            }
        }
        if priv_.is_null() {
            return 1;
        }
        // SAFETY: the caller's key.
        let p = Pctx(unsafe { EVP_PKEY_CTX_new(priv_, ptr::null_mut()) });
        if p.0.is_null() {
            err::raise(ERR_LIB_EVP, ERR_R_EVP_LIB, "EVP_OpenInit");
            return 0;
        }
        // A negative length is a huge `size_t` in OpenSSL, which the decryption refuses.
        let ekl = usize::try_from(ekl).unwrap_or(usize::MAX);
        let mut keylen = 0usize;
        // SAFETY: the context made above.
        if unsafe { EVP_PKEY_decrypt_init(p.0) } <= 0 {
            return 0;
        }
        // SAFETY: the context; the caller's encrypted key.
        if unsafe { EVP_PKEY_decrypt(p.0, ptr::null_mut(), &raw mut keylen, ek, ekl) } <= 0 {
            return 0;
        }
        let mut key = Zeroizing::new(vec![0u8; keylen]);
        // SAFETY: the context; room for `keylen` octets; the encrypted key.
        if unsafe { EVP_PKEY_decrypt(p.0, key.as_mut_ptr(), &raw mut keylen, ek, ekl) } <= 0 {
            return 0;
        }
        let Ok(kl) = c_int::try_from(keylen) else { return 0 };
        // SAFETY: the caller's context.
        if unsafe { EVP_CIPHER_CTX_set_key_length(ctx, kl) } <= 0 {
            return 0;
        }
        // SAFETY: the context; the decrypted key and the caller's IV.
        if unsafe { EVP_DecryptInit_ex(ctx, ptr::null(), ptr::null_mut(), key.as_ptr(), iv) } == 0 {
            return 0;
        }
        1
    }
}

ffi_export! {
    /// Finishes the decryption into `out` and readies the context for another message. 1, or 0.
    ///
    /// # Safety
    /// As for `EVP_DecryptFinal_ex`.
    pub unsafe extern "C" fn EVP_OpenFinal(ctx: *mut EVP_CIPHER_CTX, out: *mut c_uchar, outl: *mut c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let mut i = unsafe { EVP_DecryptFinal_ex(ctx, out, outl) };
        if i != 0 {
            // SAFETY: as above.
            i = unsafe { EVP_DecryptInit_ex(ctx, ptr::null(), ptr::null_mut(), ptr::null(), ptr::null()) };
        }
        i
    }
}
