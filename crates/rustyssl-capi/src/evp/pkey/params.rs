//! A key's parameters (`EVP_PKEY_get_params(3)`, `EVP_PKEY_set_params(3)`; `p_lib.c`): asked
//! of and given to its key manager, with the typed helpers that build a one-parameter array,
//! and the group name and encoded public key built on them. Setting parameters marks the key
//! changed, so its exports to other key managers are made again.

use core::ffi::{c_char, c_int, c_long};
use core::ptr;

use rustyssl_abi::{
    ASN1_PKEY_CTRL_GET1_TLS_ENCPT, ASN1_PKEY_CTRL_SET1_TLS_ENCPT, BIGNUM, ERR_LIB_EVP, EVP_PKEY,
    EVP_R_INVALID_KEY, OSSL_PARAM, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, OSSL_PKEY_PARAM_GROUP_NAME,
};

use super::pkey;
use crate::bn::BN_num_bits;
use crate::bn::conv::BN_bn2nativepad;
use crate::err;
use crate::ffi::ffi_export;
use crate::mem::{CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc, CRYPTO_zalloc, OPENSSL_cleanse};
use crate::params::bn::OSSL_PARAM_get_BN;
use crate::params::{
    OSSL_PARAM_construct_BN, OSSL_PARAM_construct_int, OSSL_PARAM_construct_octet_string,
    OSSL_PARAM_construct_size_t, OSSL_PARAM_construct_utf8_string, OSSL_PARAM_modified, end,
    unmodified,
};

ffi_export! {
    /// Asks the key manager for `params`; 0 with `EVP_R_INVALID_KEY` for a blank key.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `params` is an array the key manager may fill.
    pub unsafe extern "C" fn EVP_PKEY_get_params(pkey: *const EVP_PKEY, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if let Some(k) = unsafe { self::pkey(pkey) } {
            let (km, kd) = k.provided();
            if let Some(km) = km {
                let ptr = kd.as_ref().map_or(ptr::null_mut(), |d| d.ptr());
                // SAFETY: the key manager's data; the caller's array.
                return c_int::from(unsafe { km.get().get_params(ptr, params) } > 0);
            }
            if k.lock().is_legacy() {
                // A typed key's parameters come through its ctrl translation (4.2c).
                crate::stub::unimplemented("EVP_PKEY_get_params of a key typed by an ASN.1 method");
            }
        }
        err::raise(ERR_LIB_EVP, EVP_R_INVALID_KEY, "EVP_PKEY_get_params");
        0
    }
}

ffi_export! {
    /// Gives the key manager `params`, marking the key changed; 0 with `EVP_R_INVALID_KEY` for a
    /// key without a key manager.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `params` is NULL or an array.
    pub unsafe extern "C" fn EVP_PKEY_set_params(pkey: *mut EVP_PKEY, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if let Some(k) = unsafe { self::pkey(pkey) } {
            let (km, kd) = {
                let mut s = k.lock();
                if s.keymgmt.is_some() {
                    s.dirty_cnt = s.dirty_cnt.wrapping_add(1);
                }
                (s.keymgmt.clone(), s.keydata.clone())
            };
            if let Some(km) = km {
                let ptr = kd.as_ref().map_or(ptr::null_mut(), |d| d.ptr());
                // SAFETY: the key manager's data; the caller's array.
                return unsafe { km.get().set_params(ptr, params) };
            }
        }
        err::raise(ERR_LIB_EVP, EVP_R_INVALID_KEY, "EVP_PKEY_set_params");
        0
    }
}

ffi_export! {
    /// The parameters a provided key's key manager reports, or NULL.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_gettable_params(pkey: *const EVP_PKEY) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let km = unsafe { self::pkey(pkey) }.and_then(|k| k.provided().0);
        km.map_or(ptr::null(), |m| m.get().gettable_params())
    }
}

ffi_export! {
    /// The parameters a provided key's key manager can be given, or NULL.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_settable_params(pkey: *const EVP_PKEY) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let km = unsafe { self::pkey(pkey) }.and_then(|k| k.provided().0);
        km.map_or(ptr::null(), |m| m.get().settable_params())
    }
}

/// Gets the one parameter of `params` (and its end): whether the key manager succeeded and set
/// it.
///
/// # Safety
/// `pkey` is NULL or a live key; `params` holds one parameter and the end.
unsafe fn get_one(pkey: *const EVP_PKEY, params: &mut [OSSL_PARAM; 2]) -> c_int {
    // SAFETY: the caller's guarantee.
    let ok = unsafe { EVP_PKEY_get_params(pkey, params.as_mut_ptr()) } != 0;
    // SAFETY: a parameter of the array.
    c_int::from(ok && unsafe { OSSL_PARAM_modified(params.as_ptr()) } != 0)
}

ffi_export! {
    /// The integer parameter `key_name` into `out`.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `key_name` is NULL or a string; `out` is room for an int.
    pub unsafe extern "C" fn EVP_PKEY_get_int_param(pkey: *const EVP_PKEY, key_name: *const c_char, out: *mut c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if key_name.is_null() {
            return 0;
        }
        // SAFETY: the caller's key and room.
        let mut params = [unsafe { OSSL_PARAM_construct_int(key_name, out) }, end()];
        // SAFETY: the caller's guarantee.
        unsafe { get_one(pkey, &mut params) }
    }
}

ffi_export! {
    /// The `size_t` parameter `key_name` into `out`.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `key_name` is NULL or a string; `out` is room for a size.
    pub unsafe extern "C" fn EVP_PKEY_get_size_t_param(pkey: *const EVP_PKEY, key_name: *const c_char, out: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if key_name.is_null() {
            return 0;
        }
        // SAFETY: the caller's key and room.
        let mut params = [unsafe { OSSL_PARAM_construct_size_t(key_name, out) }, end()];
        // SAFETY: the caller's guarantee.
        unsafe { get_one(pkey, &mut params) }
    }
}

ffi_export! {
    /// The octet string parameter `key_name` into `buf` (its size into `out_len`); with a NULL
    /// `buf`, only its size.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `key_name` is NULL or a string; `buf` is NULL or has room
    /// for `max_buf_sz` octets; `out_len` is NULL or room for a size.
    pub unsafe extern "C" fn EVP_PKEY_get_octet_string_param(pkey: *const EVP_PKEY, key_name: *const c_char, buf: *mut u8, max_buf_sz: usize, out_len: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if key_name.is_null() {
            return 0;
        }
        // SAFETY: the caller's key and buffer.
        let mut params = [unsafe { OSSL_PARAM_construct_octet_string(key_name, buf.cast(), max_buf_sz) }, end()];
        // SAFETY: the caller's guarantee.
        let ret1 = unsafe { EVP_PKEY_get_params(pkey, params.as_mut_ptr()) } != 0;
        // SAFETY: a parameter of the array.
        let ret2 = ret1 && unsafe { OSSL_PARAM_modified(params.as_ptr()) } != 0;
        if ret2 && !out_len.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { out_len.write(params[0].return_size) };
        }
        c_int::from(ret2)
    }
}

ffi_export! {
    /// The UTF-8 string parameter `key_name` into `str_`, NUL-terminated (its length into
    /// `out_len`); 0 if there's no room for the NUL.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `key_name` is NULL or a string; `str_` is NULL or has room
    /// for `max_buf_sz` characters; `out_len` is NULL or room for a size.
    pub unsafe extern "C" fn EVP_PKEY_get_utf8_string_param(pkey: *const EVP_PKEY, key_name: *const c_char, str_: *mut c_char, max_buf_sz: usize, out_len: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if key_name.is_null() {
            return 0;
        }
        // SAFETY: the caller's key and buffer.
        let mut params = [unsafe { OSSL_PARAM_construct_utf8_string(key_name, str_, max_buf_sz) }, end()];
        // SAFETY: the caller's guarantee.
        let ret1 = unsafe { EVP_PKEY_get_params(pkey, params.as_mut_ptr()) } != 0;
        // SAFETY: a parameter of the array.
        let ret2 = ret1 && unsafe { OSSL_PARAM_modified(params.as_ptr()) } != 0;
        let size = params[0].return_size;
        if ret2 && !out_len.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { out_len.write(size) };
        }
        if ret2 && size == max_buf_sz {
            // No room for the NUL.
            return 0;
        }
        if ret2 && !str_.is_null() && size < max_buf_sz {
            // SAFETY: within the caller's buffer.
            unsafe { str_.wrapping_add(size).write(0) };
        }
        c_int::from(ret2)
    }
}

ffi_export! {
    /// The integer parameter `key_name` as a new `BIGNUM` into `bn`.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `key_name` is NULL or a string; `bn` is NULL or room for a
    /// pointer.
    pub unsafe extern "C" fn EVP_PKEY_get_bn_param(pkey: *const EVP_PKEY, key_name: *const c_char, bn: *mut *mut BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if key_name.is_null() || bn.is_null() {
            return 0;
        }
        let mut buffer = [0u8; 2048];
        // SAFETY: the caller's key; the buffer above.
        let mut params = [unsafe { OSSL_PARAM_construct_BN(key_name, buffer.as_mut_ptr(), buffer.len()) }, end()];
        let mut buf: *mut u8 = ptr::null_mut();
        let mut buf_sz = 0;
        // SAFETY: the caller's guarantee.
        if unsafe { EVP_PKEY_get_params(pkey, params.as_mut_ptr()) } == 0 {
            // SAFETY: a parameter of the array.
            if unsafe { OSSL_PARAM_modified(params.as_ptr()) } == 0 || params[0].return_size == 0 {
                return 0;
            }
            // The buffer was too small: again with one of the size asked for.
            buf_sz = params[0].return_size;
            // SAFETY: a size.
            buf = unsafe { CRYPTO_zalloc(buf_sz, c"".as_ptr(), 0) }.cast();
            if buf.is_null() {
                return 0;
            }
            params[0].data = buf.cast();
            params[0].data_size = buf_sz;
        }
        let mut ret = 0;
        // SAFETY: as above.
        let fetched = buf.is_null() || unsafe { EVP_PKEY_get_params(pkey, params.as_mut_ptr()) } != 0;
        // SAFETY: a parameter of the array.
        let modified = unsafe { OSSL_PARAM_modified(params.as_ptr()) } != 0;
        if fetched && modified {
            // SAFETY: a parameter of the array; the caller's room.
            ret = unsafe { OSSL_PARAM_get_BN(params.as_ptr(), bn) };
        }
        if !buf.is_null() {
            if modified {
                // SAFETY: allocated above, of `buf_sz` octets.
                unsafe { CRYPTO_clear_free(buf.cast(), buf_sz, c"".as_ptr(), 0) };
            } else {
                // SAFETY: as above.
                unsafe { CRYPTO_free(buf.cast(), c"".as_ptr(), 0) };
            }
        } else if modified {
            // SAFETY: the local buffer.
            unsafe { OPENSSL_cleanse(buffer.as_mut_ptr().cast(), params[0].data_size) };
        }
        ret
    }
}

/// Sets the one parameter of `params` (and its end).
///
/// # Safety
/// `pkey` is NULL or a live key; `params` holds one parameter and the end.
unsafe fn set_one(pkey: *mut EVP_PKEY, params: &mut [OSSL_PARAM; 2]) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { super::params::EVP_PKEY_set_params(pkey, params.as_mut_ptr()) }
}

ffi_export! {
    /// Sets the integer parameter `key_name`.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `key_name` is NULL or a string.
    pub unsafe extern "C" fn EVP_PKEY_set_int_param(pkey: *mut EVP_PKEY, key_name: *const c_char, in_: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if key_name.is_null() {
            return 0;
        }
        let mut v = in_;
        // SAFETY: the caller's key; the local value.
        let mut params = [unsafe { OSSL_PARAM_construct_int(key_name, &raw mut v) }, end()];
        // SAFETY: the caller's guarantee.
        unsafe { set_one(pkey, &mut params) }
    }
}

ffi_export! {
    /// Sets the `size_t` parameter `key_name`.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `key_name` is NULL or a string.
    pub unsafe extern "C" fn EVP_PKEY_set_size_t_param(pkey: *mut EVP_PKEY, key_name: *const c_char, in_: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if key_name.is_null() {
            return 0;
        }
        let mut v = in_;
        // SAFETY: the caller's key; the local value.
        let mut params = [unsafe { OSSL_PARAM_construct_size_t(key_name, &raw mut v) }, end()];
        // SAFETY: the caller's guarantee.
        unsafe { set_one(pkey, &mut params) }
    }
}

ffi_export! {
    /// Sets the integer parameter `key_name` from a `BIGNUM` (of at most 2048 octets) of a key
    /// with data.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `key_name` is NULL or a string; `bn` is NULL or a live
    /// number.
    pub unsafe extern "C" fn EVP_PKEY_set_bn_param(pkey: *mut EVP_PKEY, key_name: *const c_char, bn: *const BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if key_name.is_null() || bn.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::pkey(pkey) }) else { return 0 };
        if !k.lock().is_assigned() {
            return 0;
        }
        let mut buffer = [0u8; 2048];
        // SAFETY: the caller's number.
        let bits = unsafe { BN_num_bits(bn) };
        let bsize = (bits + 7) / 8;
        let Ok(n) = usize::try_from(bsize) else { return 0 };
        if n > buffer.len() {
            return 0;
        }
        // SAFETY: the caller's number; room for `bsize` octets.
        if unsafe { BN_bn2nativepad(bn, buffer.as_mut_ptr(), bsize) } < 0 {
            return 0;
        }
        // SAFETY: the caller's key; the local buffer.
        let mut params = [unsafe { OSSL_PARAM_construct_BN(key_name, buffer.as_mut_ptr(), n) }, end()];
        // SAFETY: the caller's guarantee.
        unsafe { set_one(pkey, &mut params) }
    }
}

ffi_export! {
    /// Sets the UTF-8 string parameter `key_name`.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `key_name` and `str_` are NULL or strings.
    pub unsafe extern "C" fn EVP_PKEY_set_utf8_string_param(pkey: *mut EVP_PKEY, key_name: *const c_char, str_: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if key_name.is_null() {
            return 0;
        }
        // SAFETY: the caller's key and string.
        let mut params = [unsafe { OSSL_PARAM_construct_utf8_string(key_name, str_.cast_mut(), 0) }, end()];
        // SAFETY: the caller's guarantee.
        unsafe { set_one(pkey, &mut params) }
    }
}

ffi_export! {
    /// Sets the octet string parameter `key_name`.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `key_name` is NULL or a string; `buf` holds `bsize` octets.
    pub unsafe extern "C" fn EVP_PKEY_set_octet_string_param(pkey: *mut EVP_PKEY, key_name: *const c_char, buf: *const u8, bsize: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if key_name.is_null() {
            return 0;
        }
        // SAFETY: the caller's key and buffer.
        let mut params = [unsafe { OSSL_PARAM_construct_octet_string(key_name, buf.cast_mut().cast(), bsize) }, end()];
        // SAFETY: the caller's guarantee.
        unsafe { set_one(pkey, &mut params) }
    }
}

ffi_export! {
    /// The key's group name (`OSSL_PKEY_PARAM_GROUP_NAME`) into `gname`.
    ///
    /// # Safety
    /// As for `EVP_PKEY_get_utf8_string_param`.
    pub unsafe extern "C" fn EVP_PKEY_get_group_name(pkey: *const EVP_PKEY, gname: *mut c_char, gname_sz: usize, gname_len: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME.as_ptr(), gname, gname_sz, gname_len) }
    }
}

ffi_export! {
    /// Sets a provided key's encoded public key (`OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY`).
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `pub_` holds `publen` octets.
    pub unsafe extern "C" fn EVP_PKEY_set1_encoded_public_key(pkey: *mut EVP_PKEY, pub_: *const u8, publen: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::pkey(pkey) }) else { return 0 };
        if k.is_provided() {
            // SAFETY: the caller's guarantee.
            return unsafe { EVP_PKEY_set_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY.as_ptr(), pub_, publen) };
        }
        let Ok(len) = c_int::try_from(publen) else { return 0 };
        // Historically `EVP_PKEY_set1_tls_encodedpoint`.
        // SAFETY: the caller's octets.
        match unsafe { super::asn1_ctrl(k, ASN1_PKEY_CTRL_SET1_TLS_ENCPT, c_long::from(len), pub_.cast_mut().cast()) } {
            Some(rv) => c_int::from(rv > 0),
            // A blank key: `legacy_asn1_ctrl_to_param` finds no key manager.
            None => 0,
        }
    }
}

ffi_export! {
    /// A provided key's encoded public key, in a new buffer at `*ppub`; its size, or 0.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `ppub` is room for a pointer.
    pub unsafe extern "C" fn EVP_PKEY_get1_encoded_public_key(pkey: *mut EVP_PKEY, ppub: *mut *mut u8) -> usize
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::pkey(pkey) }) else { return 0 };
        if k.is_provided() {
            let mut return_size = unmodified();
            let key = OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY.as_ptr();
            // Its size first.
            // SAFETY: the caller's key; no buffer.
            unsafe { EVP_PKEY_get_octet_string_param(pkey, key, ptr::null_mut(), 0, &raw mut return_size) };
            if return_size == unmodified() {
                return 0;
            }
            // SAFETY: a size.
            let buf: *mut u8 = unsafe { CRYPTO_malloc(return_size, c"".as_ptr(), 0) }.cast();
            if buf.is_null() {
                return 0;
            }
            // SAFETY: the caller's key; the buffer of that size.
            if unsafe { EVP_PKEY_get_octet_string_param(pkey, key, buf, return_size, ptr::null_mut()) } == 0 {
                // SAFETY: allocated above.
                unsafe { CRYPTO_free(buf.cast(), c"".as_ptr(), 0) };
                return 0;
            }
            if !ppub.is_null() {
                // SAFETY: the caller's guarantee.
                unsafe { ppub.write(buf) };
            }
            return return_size;
        }
        // SAFETY: the caller's room for the pointer.
        match unsafe { super::asn1_ctrl(k, ASN1_PKEY_CTRL_GET1_TLS_ENCPT, 0, ppub.cast()) } {
            Some(rv) => usize::try_from(rv).unwrap_or(0),
            None => 0,
        }
    }
}
