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
                // SAFETY: the caller's guarantee.
                return c_int::from(unsafe { legacy_get_params(pkey, params) } > 0);
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

/// What the legacy payload table names (`evp_pkey_translations`).
#[derive(Clone, Copy)]
enum Payload {
    GroupName,
    PrivKey,
    PubKey,
    EcPubXy,
    FfcP,
    FfcQ,
    FfcG,
    EcDecoded,
    RsaN,
    RsaE,
    RsaD,
    /// rsa-factor1.. (0-based).
    Factor(usize),
    Exponent(usize),
    Coefficient(usize),
}

/// The payload a parameter's key names (in any case), if any.
fn payload(key: &[u8]) -> Option<Payload> {
    use rustyssl_abi::{
        OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS as DECODED, OSSL_PKEY_PARAM_EC_PUB_X,
        OSSL_PKEY_PARAM_EC_PUB_Y, OSSL_PKEY_PARAM_FFC_G, OSSL_PKEY_PARAM_FFC_P,
        OSSL_PKEY_PARAM_FFC_Q, OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PKEY_PARAM_PUB_KEY,
        OSSL_PKEY_PARAM_RSA_D, OSSL_PKEY_PARAM_RSA_E, OSSL_PKEY_PARAM_RSA_N,
    };
    let is = |name: &core::ffi::CStr| key.eq_ignore_ascii_case(name.to_bytes());
    let fixed = [
        (OSSL_PKEY_PARAM_GROUP_NAME, Payload::GroupName),
        (OSSL_PKEY_PARAM_PRIV_KEY, Payload::PrivKey),
        (OSSL_PKEY_PARAM_PUB_KEY, Payload::PubKey),
        (OSSL_PKEY_PARAM_EC_PUB_X, Payload::EcPubXy),
        (OSSL_PKEY_PARAM_EC_PUB_Y, Payload::EcPubXy),
        (OSSL_PKEY_PARAM_FFC_P, Payload::FfcP),
        (OSSL_PKEY_PARAM_FFC_Q, Payload::FfcQ),
        (OSSL_PKEY_PARAM_FFC_G, Payload::FfcG),
        (OSSL_PKEY_PARAM_RSA_N, Payload::RsaN),
        (OSSL_PKEY_PARAM_RSA_E, Payload::RsaE),
        (OSSL_PKEY_PARAM_RSA_D, Payload::RsaD),
        (DECODED, Payload::EcDecoded),
    ];
    if let Some(&(_, p)) = fixed.iter().find(|(n, _)| is(n)) {
        return Some(p);
    }
    // rsa-factor1..10, rsa-exponent1..10, rsa-coefficient1..9.
    let lower = key.to_ascii_lowercase();
    let numbered = |prefix: &[u8], max: usize| -> Option<usize> {
        let digits = lower.strip_prefix(prefix)?;
        let n: usize = core::str::from_utf8(digits).ok()?.parse().ok()?;
        (digits.first() != Some(&b'0') && (1..=max).contains(&n)).then(|| n - 1)
    };
    numbered(b"rsa-factor", 10)
        .map(Payload::Factor)
        .or_else(|| numbered(b"rsa-exponent", 10).map(Payload::Exponent))
        .or_else(|| numbered(b"rsa-coefficient", 9).map(Payload::Coefficient))
}

/// `get_payload_bn`: the number into the parameter (an unsigned integer one). 1, or 0.
///
/// # Safety
/// `p` is a parameter; `bn` is NULL or a live number.
unsafe fn put_bn(p: *mut OSSL_PARAM, bn: *const BIGNUM) -> c_int {
    // SAFETY: the caller's parameter.
    let ty = unsafe { (*p).data_type };
    if bn.is_null() || ty != rustyssl_abi::OSSL_PARAM_UNSIGNED_INTEGER as u32 {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    unsafe { crate::params::bn::OSSL_PARAM_set_BN(p, bn) }
}

/// A private or public key's number into the parameter (an unsigned integer one), as
/// `default_fixup_args` gives it: a missing one reads as 0. 1, or 0.
///
/// # Safety
/// `p` is a parameter; `bn` is NULL or a live number.
unsafe fn put_key_bn(p: *mut OSSL_PARAM, bn: *const BIGNUM) -> c_int {
    if bn.is_null() {
        // SAFETY: the caller's parameter.
        return unsafe { crate::params::OSSL_PARAM_set_uint(p, 0) };
    }
    // SAFETY: the caller's guarantee.
    unsafe { put_bn(p, bn) }
}

/// `get_payload_public_key`'s octets for a DH key: `ossl_dh_key2buf`'s padded public key
/// (nothing, failing, without one). 1, or 0.
///
/// # Safety
/// `p` is a parameter; `d` is NULL or a live `DH`.
unsafe fn dh_public_octets(p: *mut OSSL_PARAM, d: *const rustyssl_abi::DH) -> c_int {
    // SAFETY: the caller's guarantee.
    let st = unsafe { crate::dh::dh(d.cast_mut()) }.map(crate::dh::Dh::snapshot);
    let buf = st.and_then(|st| {
        let n = crate::dh_backend::key2buf(&st, None);
        let mut v = vec![0u8; n];
        (n > 0 && crate::dh_backend::key2buf(&st, Some(&mut v)) == n).then_some(v)
    });
    let (ptr_, len) = buf
        .as_ref()
        .map_or((ptr::null(), 0), |v| (v.as_ptr(), v.len()));
    // SAFETY: the caller's parameter; the octets, or NULL.
    unsafe { crate::params::OSSL_PARAM_set_octet_string(p, ptr_.cast(), len) }
}

/// `evp_pkey_get_params_to_ctrl`: each parameter from the key's legacy data through the payload
/// table: the last one's result, or -2 for a parameter it doesn't name (the rest unread).
///
/// # Safety
/// `pkey` is a live key with legacy data; `params` is NULL or an array.
unsafe fn legacy_get_params(pkey: *const EVP_PKEY, params: *mut OSSL_PARAM) -> c_int {
    use crate::rsa_lib as r;
    use rustyssl_abi::{
        EVP_PKEY_DH, EVP_PKEY_DHX, EVP_PKEY_DSA, EVP_PKEY_EC, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS,
        EVP_R_UNSUPPORTED_KEY_TYPE,
    };
    const F: &str = "evp_pkey_setget_params_to_ctrl";
    let unsupported = || {
        err::raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_KEY_TYPE, F);
        0
    };
    // SAFETY: the caller's guarantee.
    let base = unsafe { super::EVP_PKEY_get_base_id(pkey) };
    let is_rsa = base == EVP_PKEY_RSA || base == EVP_PKEY_RSA_PSS;
    let mut ret = 1;
    let mut p = params;
    // SAFETY: the caller's array, up to its end.
    while let Some(param) = unsafe { p.as_mut() } {
        if param.key.is_null() {
            break;
        }
        // SAFETY: a parameter's key is a string.
        let key = unsafe { core::ffi::CStr::from_ptr(param.key) }.to_bytes();
        let Some(which) = payload(key) else { return -2 };
        // `EVP_PKEY_get0_RSA` raises for another type, as the numbered getters see it.
        // SAFETY: the caller's key.
        let rsa = || unsafe { super::rsa::get0_rsa(pkey) };
        // SAFETY: the caller's key.
        let ec = || unsafe { super::ec::EVP_PKEY_get0_EC_KEY(pkey) };
        let bn_type = param.data_type == rustyssl_abi::OSSL_PARAM_UNSIGNED_INTEGER as u32;
        ret = match which {
            Payload::GroupName => {
                if base == EVP_PKEY_EC {
                    // SAFETY: the parameter; the key's EC_KEY.
                    unsafe { ec_group_name(param, ec()) }
                } else {
                    unsupported()
                }
            }
            Payload::PubKey => {
                let octets = param.data_type == rustyssl_abi::OSSL_PARAM_OCTET_STRING as u32;
                if base == EVP_PKEY_DH || base == EVP_PKEY_DHX {
                    // SAFETY: the caller's key.
                    let d = unsafe { super::dh::EVP_PKEY_get0_DH(pkey) };
                    if octets {
                        // SAFETY: the parameter; the key's `DH`.
                        unsafe { dh_public_octets(param, d) }
                    } else if bn_type {
                        // SAFETY: the key's `DH`.
                        let bn = unsafe { crate::dh::DH_get0_pub_key(d) };
                        // SAFETY: the parameter; the number or NULL.
                        unsafe { put_key_bn(param, bn) }
                    } else {
                        0
                    }
                } else if base == EVP_PKEY_DSA {
                    if bn_type {
                        // SAFETY: the caller's key.
                        let d = unsafe { super::dsa::EVP_PKEY_get0_DSA(pkey) };
                        // SAFETY: the key's `DSA`.
                        let bn = unsafe { crate::dsa::DSA_get0_pub_key(d) };
                        // SAFETY: the parameter; the number or NULL.
                        unsafe { put_key_bn(param, bn) }
                    } else {
                        0
                    }
                } else if base == EVP_PKEY_EC {
                    if octets {
                        // SAFETY: the parameter; the key's EC_KEY.
                        unsafe { ec_public_key(param, ec()) }
                    } else {
                        0
                    }
                } else {
                    unsupported()
                }
            }
            Payload::EcDecoded => {
                if base == EVP_PKEY_EC {
                    // SAFETY: the key's EC_KEY.
                    let v = unsafe { crate::ec::key::EC_KEY_decoded_from_explicit_params(ec()) };
                    if v < 0 {
                        err::raise(
                            ERR_LIB_EVP,
                            rustyssl_abi::EVP_R_INVALID_KEY,
                            "get_ec_decoded_from_explicit_params",
                        );
                        0
                    } else {
                        // SAFETY: the parameter.
                        unsafe { crate::params::OSSL_PARAM_set_int(param, v) }
                    }
                } else {
                    unsupported()
                }
            }
            Payload::PrivKey => {
                if !bn_type {
                    0
                } else if base == EVP_PKEY_DH {
                    // SAFETY: the caller's key.
                    let d = unsafe { super::dh::EVP_PKEY_get0_DH(pkey) };
                    // SAFETY: the key's `DH`.
                    let bn = unsafe { crate::dh::DH_get0_priv_key(d) };
                    // SAFETY: the parameter; the number or NULL.
                    unsafe { put_key_bn(param, bn) }
                } else if base == EVP_PKEY_EC {
                    // SAFETY: the key's EC_KEY.
                    let bn = unsafe { crate::ec::key::EC_KEY_get0_private_key(ec()) };
                    // SAFETY: the parameter; the number or NULL.
                    unsafe { put_key_bn(param, bn) }
                } else {
                    unsupported()
                }
            }
            Payload::EcPubXy => {
                let e = ec();
                if e.is_null() {
                    unsupported()
                } else if !bn_type {
                    0
                } else {
                    // SAFETY: the parameter and its key; the key's EC_KEY.
                    unsafe { ec_public_xy(param, key, e) }
                }
            }
            Payload::FfcP | Payload::FfcQ | Payload::FfcG => {
                let bn = if base == EVP_PKEY_DH {
                    // SAFETY: the caller's key.
                    let d = unsafe { super::dh::EVP_PKEY_get0_DH(pkey) };
                    match which {
                        // SAFETY: the key's `DH`.
                        Payload::FfcP => unsafe { crate::dh::DH_get0_p(d) },
                        // SAFETY: as above.
                        Payload::FfcQ => unsafe { crate::dh::DH_get0_q(d) },
                        // SAFETY: as above.
                        _ => unsafe { crate::dh::DH_get0_g(d) },
                    }
                } else if base == EVP_PKEY_DSA {
                    // SAFETY: the caller's key.
                    let d = unsafe { super::dsa::EVP_PKEY_get0_DSA(pkey) };
                    match which {
                        // SAFETY: the key's `DSA`.
                        Payload::FfcP => unsafe { crate::dsa::DSA_get0_p(d) },
                        // SAFETY: as above.
                        Payload::FfcQ => unsafe { crate::dsa::DSA_get0_q(d) },
                        // SAFETY: as above.
                        _ => unsafe { crate::dsa::DSA_get0_g(d) },
                    }
                } else {
                    // Only p's getter raises for another type.
                    if matches!(which, Payload::FfcP) {
                        unsupported();
                    }
                    ptr::null()
                };
                // SAFETY: the parameter; the number or NULL.
                unsafe { put_bn(param, bn) }
            }
            Payload::RsaN | Payload::RsaE | Payload::RsaD => {
                if is_rsa {
                    let k = rsa();
                    let get: unsafe extern "C" fn(*const rustyssl_abi::RSA) -> *const BIGNUM =
                        match which {
                            Payload::RsaN => r::RSA_get0_n,
                            Payload::RsaE => r::RSA_get0_e,
                            _ => r::RSA_get0_d,
                        };
                    // SAFETY: the key's `RSA`.
                    let bn = unsafe { get(k) };
                    // SAFETY: the parameter; the key's number or NULL.
                    unsafe { put_bn(param, bn) }
                } else {
                    0
                }
            }
            Payload::Factor(i) | Payload::Exponent(i) | Payload::Coefficient(i) => {
                let k = rsa();
                // SAFETY: the key's `RSA`, or NULL.
                let bn = unsafe { numbered(k, which, i) };
                // SAFETY: the parameter; the number or NULL.
                unsafe { put_bn(param, bn) }
            }
        };
        // SAFETY: still within the array.
        p = unsafe { p.add(1) };
    }
    ret
}

/// `get_payload_group_name` for an EC key: its curve's name (nothing for a curve without
/// one). 1, or 0.
///
/// # Safety
/// `p` is a parameter; `ec` is NULL or a live `EC_KEY`.
unsafe fn ec_group_name(p: *mut OSSL_PARAM, ec: *const rustyssl_abi::EC_KEY) -> c_int {
    let g = if ec.is_null() {
        ptr::null()
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { crate::ec::key::EC_KEY_get0_group(ec) }
    };
    let nid = if g.is_null() {
        rustyssl_abi::NID_undef
    } else {
        // SAFETY: its group.
        unsafe { crate::ec::group::EC_GROUP_get_curve_name(g) }
    };
    // SAFETY: no preconditions.
    let name = unsafe { crate::ec::curves::OSSL_EC_curve_nid2name(nid) };
    if name.is_null() {
        return 1;
    }
    // SAFETY: the caller's parameter; a static name.
    unsafe { crate::params::OSSL_PARAM_set_utf8_string(p, name) }
}

/// `get_payload_public_key` for an EC key: its point, compressed. 1, or 0.
///
/// # Safety
/// `p` is an octet-string parameter; `ec` is NULL or a live `EC_KEY`.
unsafe fn ec_public_key(p: *mut OSSL_PARAM, ec: *const rustyssl_abi::EC_KEY) -> c_int {
    if ec.is_null() {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let g = unsafe { crate::ec::key::EC_KEY_get0_group(ec) };
    // SAFETY: as above.
    let pt = unsafe { crate::ec::key::EC_KEY_get0_public_key(ec) };
    let mut buf: *mut u8 = ptr::null_mut();
    // SAFETY: the key's group and point, or NULL; a local.
    let n = unsafe {
        crate::ec::point::EC_POINT_point2buf(
            g,
            pt,
            rustyssl_abi::POINT_CONVERSION_COMPRESSED,
            &raw mut buf,
            ptr::null_mut(),
        )
    };
    // SAFETY: the caller's parameter; the encoding (or NULL and 0).
    let ret = unsafe { crate::params::OSSL_PARAM_set_octet_string(p, buf.cast(), n) };
    // SAFETY: NULL or the encoding, freed once.
    unsafe { crate::mem::release(buf.cast()) };
    ret
}

/// `get_payload_public_key_ec`: the point's x (for `qx`) or y (for `qy`, by the key's first two
/// octets, as OpenSSL compares them). 1, or 0.
///
/// # Safety
/// `p` is an unsigned-integer parameter; `ec` is a live `EC_KEY`.
unsafe fn ec_public_xy(p: *mut OSSL_PARAM, key: &[u8], ec: *const rustyssl_abi::EC_KEY) -> c_int {
    // SAFETY: the caller's guarantee.
    let g = unsafe { crate::ec::key::EC_KEY_get0_group(ec) };
    // SAFETY: as above.
    let pt = unsafe { crate::ec::key::EC_KEY_get0_public_key(ec) };
    // SAFETY: no preconditions.
    let (x, y) = (unsafe { crate::bn::BN_new() }, unsafe {
        crate::bn::BN_new()
    });
    let ret = (|| {
        if x.is_null() || y.is_null() {
            return 0;
        }
        // SAFETY: the key's group and point; live numbers.
        if unsafe {
            crate::ec::point::EC_POINT_get_affine_coordinates(g, pt, x, y, ptr::null_mut())
        } == 0
        {
            return 0;
        }
        let which = match key.get(..2) {
            Some(b"qx") => x,
            Some(b"qy") => y,
            _ => return 0,
        };
        // SAFETY: the parameter; the number.
        unsafe { put_bn(p, which) }
    })();
    // SAFETY: made above, or NULL.
    unsafe { crate::bn::BN_free(x) };
    // SAFETY: as above.
    unsafe { crate::bn::BN_free(y) };
    ret
}

/// `get_rsa_payload_factor`/`_exponent`/`_coefficient`: the key's `i`th (0-based) prime, CRT
/// exponent, or coefficient, the extra primes' after the first ones.
///
/// # Safety
/// `k` is NULL or a live `RSA`.
unsafe fn numbered(k: *mut rustyssl_abi::RSA, which: Payload, i: usize) -> *const BIGNUM {
    use crate::rsa_lib as r;
    if k.is_null() {
        return ptr::null();
    }
    // SAFETY: the caller's key.
    let extra = usize::try_from(unsafe { r::RSA_get_multi_prime_extra_count(k) }).unwrap_or(0);
    let get: unsafe extern "C" fn(*const rustyssl_abi::RSA) -> *const BIGNUM = match (which, i) {
        (Payload::Factor(_), 0) => r::RSA_get0_p,
        (Payload::Factor(_), 1) => r::RSA_get0_q,
        (Payload::Exponent(_), 0) => r::RSA_get0_dmp1,
        (Payload::Exponent(_), 1) => r::RSA_get0_dmq1,
        (Payload::Coefficient(_), 0) => r::RSA_get0_iqmp,
        _ => {
            // The extra primes': factors and exponents from the third, coefficients from the second.
            let first = if matches!(which, Payload::Coefficient(_)) {
                1
            } else {
                2
            };
            let Some(j) = i.checked_sub(first).filter(|&j| j < extra) else {
                return ptr::null();
            };
            let mut arr: [*const BIGNUM; 10] = [ptr::null(); 10];
            let mut arr2: [*const BIGNUM; 10] = [ptr::null(); 10];
            let ok = if matches!(which, Payload::Factor(_)) {
                // SAFETY: as above; room for every extra prime.
                unsafe { r::RSA_get0_multi_prime_factors(k, arr.as_mut_ptr()) }
            } else {
                // SAFETY: as above.
                unsafe {
                    r::RSA_get0_multi_prime_crt_params(k, arr.as_mut_ptr(), arr2.as_mut_ptr())
                }
            };
            let src = if matches!(which, Payload::Coefficient(_)) {
                &arr2
            } else {
                &arr
            };
            return if ok != 0 {
                src.get(j).copied().unwrap_or(ptr::null())
            } else {
                ptr::null()
            };
        }
    };
    // SAFETY: as above.
    unsafe { get(k) }
}
