//! `pem_sign.c`: a signature made with `EVP_SignFinal` and written in base64
//! (`EVP_EncodeBlock`, no line breaks). The init and update are the digest's.

use core::ffi::{c_int, c_uchar, c_uint};
use core::ptr;

use rustyssl_abi::{ERR_LIB_PEM, EVP_MD, EVP_MD_CTX, EVP_PKEY};

use crate::evp::encode::EVP_EncodeBlock;
use crate::evp::md_ctx::{EVP_DigestInit_ex, EVP_DigestUpdate};
use crate::evp::pkey::EVP_PKEY_get_size;
use crate::evp::sigver::EVP_SignFinal;
use crate::ffi::ffi_export;

ffi_export! {
    /// Starts the digest `type` in `ctx` (`EVP_DigestInit_ex`). 1, or 0.
    ///
    /// # Safety
    /// As for `EVP_DigestInit_ex`.
    pub unsafe extern "C" fn PEM_SignInit(ctx: *mut EVP_MD_CTX, type_: *mut EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_DigestInit_ex(ctx, type_, ptr::null_mut()) }
    }
}

ffi_export! {
    /// Hashes `count` octets of `data` (`EVP_DigestUpdate`). 1, or 0.
    ///
    /// # Safety
    /// As for `EVP_DigestUpdate`.
    pub unsafe extern "C" fn PEM_SignUpdate(ctx: *mut EVP_MD_CTX, data: *const c_uchar, count: c_uint) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        let Ok(count) = usize::try_from(count) else { return 0 };
        // SAFETY: the caller's guarantee.
        unsafe { EVP_DigestUpdate(ctx, data.cast(), count) }
    }
}

ffi_export! {
    /// The signature of what `ctx` hashed, by `pkey`, base64-encoded into `sigret` (room for
    /// the encoding of the key's size, and a NUL) and its length in `siglen`. 1, or 0.
    ///
    /// # Safety
    /// `ctx` is a live digest context; `pkey` is a live key; `sigret` has room for the base64
    /// of `EVP_PKEY_get_size(pkey)` octets and a NUL; `siglen` is writable.
    pub unsafe extern "C" fn PEM_SignFinal(ctx: *mut EVP_MD_CTX, sigret: *mut c_uchar, siglen: *mut c_uint, pkey: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        // SAFETY: the caller's key (NULL gives a size of 0 or less).
        let size = unsafe { EVP_PKEY_get_size(pkey) };
        // OpenSSL allocates the key's size and signs into it; an allocation of nothing is NULL,
        // so a key without a size fails here, before signing.
        let Ok(size) = usize::try_from(size) else { return 0 };
        if size == 0 {
            return 0;
        }
        let mut m = vec![0u8; size];
        let mut m_len: c_uint = 0;
        // SAFETY: the caller's context and key; room for the key's size.
        if unsafe { EVP_SignFinal(ctx, m.as_mut_ptr(), &raw mut m_len, pkey) } <= 0 {
            return 0;
        }
        let Ok(dlen) = c_int::try_from(m_len) else { return 0 };
        if sigret.is_null() || siglen.is_null() {
            return 0;
        }
        // SAFETY: the caller's room for the encoding; the signature of `m_len` octets.
        let i = unsafe { EVP_EncodeBlock(sigret, m.as_ptr(), dlen) };
        let Ok(i) = c_uint::try_from(i) else { return 0 };
        // SAFETY: the caller's length slot.
        unsafe { *siglen = i };
        1
    }
}
