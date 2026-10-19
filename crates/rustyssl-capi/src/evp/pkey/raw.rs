//! Raw keys (`EVP_PKEY_new_raw_private_key(3)`, `EVP_PKEY_get_raw_private_key(3)`,
//! `EVP_PKEY_new_CMAC_key(3)`; `p_lib.c`): keys made from their raw octets through the key
//! manager's import (`EVP_PKEY_fromdata` with `priv` or `pub`), or else by the key type's ASN.1
//! method (an application's or an engine's), and their raw octets exported back.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    ENGINE, ERR_LIB_EVP, ERR_R_EVP_LIB, EVP_CIPHER, EVP_PKEY, EVP_PKEY_NONE,
    EVP_R_GET_RAW_KEY_FAILED, EVP_R_KEY_SETUP_FAILED,
    EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
    OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_LIB_CTX, OSSL_PARAM, OSSL_PKEY_PARAM_CIPHER,
    OSSL_PKEY_PARAM_ENGINE, OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PKEY_PARAM_PUB_KEY,
};

use super::super::pkey_ctx::{
    EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_name, EVP_PKEY_fromdata, EVP_PKEY_fromdata_init,
    KEYPAIR,
};
use super::{PkeyRef, pkey};
use crate::err::{self, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::evp::cipher::EVP_CIPHER_get0_name;
use crate::ffi::ffi_export;
use crate::objects::OBJ_nid2sn;
use crate::params::{
    OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_utf8_string,
    OSSL_PARAM_get_octet_string, OSSL_PARAM_locate_const, end,
};

/// `new_raw_key_int`: a key of type `strtype` (or `nidtype`) from its raw private or public key,
/// or NULL with an error.
///
/// # Safety
/// `libctx` is NULL or a live library context; `strtype` and `propq` are NULL or strings; `key`
/// holds `len` octets.
#[expect(
    clippy::too_many_arguments,
    reason = "OpenSSL's internal function's arguments"
)]
unsafe fn new_raw_key(
    libctx: *mut OSSL_LIB_CTX,
    strtype: *const c_char,
    propq: *const c_char,
    nidtype: c_int,
    e: *mut ENGINE,
    key: *const u8,
    len: usize,
    is_priv: bool,
) -> *mut EVP_PKEY {
    const F: &str = "new_raw_key_int";
    // SAFETY: the caller's guarantee.
    let type_name = unsafe { super::text(strtype) }.map(CStr::to_bytes);
    // Without an engine given, one registered for the type takes it to the legacy path.
    let mut claimed = !e.is_null();
    if e.is_null() {
        let (m, tmpe) = match type_name {
            Some(n) => super::ameth::find_str_engine(n),
            None if nidtype != EVP_PKEY_NONE => super::ameth::find_engine(nidtype),
            None => (None, ptr::null_mut()),
        };
        claimed = !tmpe.is_null() && m.is_some();
        // SAFETY: the search's functional reference, or NULL.
        unsafe { crate::engine::ENGINE_finish(tmpe) };
    }
    if claimed {
        // SAFETY: the caller's guarantee.
        return unsafe { legacy_raw_key(e, strtype, nidtype, key, len, is_priv) };
    }
    // A key manager makes the key if it can, else the type's ASN.1 method.
    let name = if strtype.is_null() {
        // SAFETY: a type number.
        unsafe { OBJ_nid2sn(nidtype) }
    } else {
        strtype
    };
    // SAFETY: the caller's guarantee.
    let ctx = unsafe { EVP_PKEY_CTX_new_from_name(libctx, name, propq) };
    if ctx.is_null() {
        return ptr::null_mut();
    }
    let mut pkey: *mut EVP_PKEY = ptr::null_mut();
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    // SAFETY: the context made above.
    if unsafe { EVP_PKEY_fromdata_init(ctx) } == 1 {
        // SAFETY: the mark set above.
        unsafe { ERR_clear_last_mark() };
        let k = if is_priv {
            OSSL_PKEY_PARAM_PRIV_KEY
        } else {
            OSSL_PKEY_PARAM_PUB_KEY
        };
        // SAFETY: a static key; the caller's octets.
        let p =
            unsafe { OSSL_PARAM_construct_octet_string(k.as_ptr(), key.cast_mut().cast(), len) };
        let mut params = [p, end()];
        // SAFETY: the context; the array above.
        if unsafe { EVP_PKEY_fromdata(ctx, &raw mut pkey, KEYPAIR, params.as_mut_ptr()) } != 1 {
            err::raise(ERR_LIB_EVP, EVP_R_KEY_SETUP_FAILED, F);
        }
        // SAFETY: made above.
        unsafe { EVP_PKEY_CTX_free(ctx) };
        return pkey;
    }
    // SAFETY: as above.
    unsafe { ERR_pop_to_mark() };
    // The type's ASN.1 method sets the key (the context is freed after).
    // SAFETY: the caller's guarantee.
    let k = unsafe { legacy_raw_key(e, strtype, nidtype, key, len, is_priv) };
    // SAFETY: made above.
    unsafe { EVP_PKEY_CTX_free(ctx) };
    k
}

/// `new_raw_key_int`'s legacy path: a key typed by the ASN.1 method of `strtype` (or `nidtype`)
/// given its raw key by the method, or NULL with an error. The key keeps the engine `e`, if
/// given, or the one whose method it took.
///
/// # Safety
/// `e` is NULL or a live engine; `strtype` is NULL or a string; `key` holds `len` octets.
unsafe fn legacy_raw_key(
    e: *mut ENGINE,
    strtype: *const c_char,
    nidtype: c_int,
    key: *const u8,
    len: usize,
    is_priv: bool,
) -> *mut EVP_PKEY {
    const F: &str = "new_raw_key_int";
    // SAFETY: just made, with its reference.
    let Some(k) = (unsafe { PkeyRef::adopt(super::new()) }) else {
        err::raise(ERR_LIB_EVP, ERR_R_EVP_LIB, F);
        return ptr::null_mut();
    };
    // SAFETY: the caller's guarantee.
    let name = unsafe { super::text(strtype) }.map(CStr::to_bytes);
    if !super::set_type_engine(Some(k.get()), e, nidtype, name, None) {
        return ptr::null_mut();
    }
    let Some(f) = k.get().ameth_funcs() else {
        return ptr::null_mut();
    };
    let Some(set) = (if is_priv {
        f.set_priv_key
    } else {
        f.set_pub_key
    }) else {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
            F,
        );
        return ptr::null_mut();
    };
    // SAFETY: the method's function with the key's handle and the caller's octets.
    if unsafe { set(k.as_ptr(), key, len) } == 0 {
        err::raise(ERR_LIB_EVP, EVP_R_KEY_SETUP_FAILED, F);
        return ptr::null_mut();
    }
    k.into_raw()
}

ffi_export! {
    /// A key of type `keytype` from its raw private key, with its key manager fetched from
    /// `libctx` with `propq`; NULL with an error.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `keytype` and `propq` are NULL or strings;
    /// `priv_` holds `len` octets.
    pub unsafe extern "C" fn EVP_PKEY_new_raw_private_key_ex(libctx: *mut OSSL_LIB_CTX, keytype: *const c_char, propq: *const c_char, priv_: *const u8, len: usize) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { new_raw_key(libctx, keytype, propq, EVP_PKEY_NONE, ptr::null_mut(), priv_, len, true) }
    }
}

ffi_export! {
    /// A key of type `type_` from its raw private key; NULL with an error.
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `priv_` holds `len` octets.
    pub unsafe extern "C" fn EVP_PKEY_new_raw_private_key(type_: c_int, e: *mut ENGINE, priv_: *const u8, len: usize) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { new_raw_key(ptr::null_mut(), ptr::null(), ptr::null(), type_, e, priv_, len, true) }
    }
}

ffi_export! {
    /// A key of type `keytype` from its raw public key, as
    /// `EVP_PKEY_new_raw_private_key_ex`.
    ///
    /// # Safety
    /// As for `EVP_PKEY_new_raw_private_key_ex`.
    pub unsafe extern "C" fn EVP_PKEY_new_raw_public_key_ex(libctx: *mut OSSL_LIB_CTX, keytype: *const c_char, propq: *const c_char, pub_: *const u8, len: usize) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { new_raw_key(libctx, keytype, propq, EVP_PKEY_NONE, ptr::null_mut(), pub_, len, false) }
    }
}

ffi_export! {
    /// A key of type `type_` from its raw public key; NULL with an error.
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `pub_` holds `len` octets.
    pub unsafe extern "C" fn EVP_PKEY_new_raw_public_key(type_: c_int, e: *mut ENGINE, pub_: *const u8, len: usize) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { new_raw_key(ptr::null_mut(), ptr::null(), ptr::null(), type_, e, pub_, len, false) }
    }
}

/// `raw_key_details_st`: where `get_raw_key_details` puts the key.
struct RawKey {
    key: *mut *mut c_void,
    len: *mut usize,
    selection: c_int,
}

/// `get_raw_key_details`: the exported `priv` (or `pub`) into the caller's buffer, or only its
/// size without one.
///
/// # Safety
/// `params` is a parameter array; `arg` is a `RawKey`.
unsafe extern "C" fn get_raw_key_details(params: *const OSSL_PARAM, arg: *mut c_void) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(raw) = (unsafe { arg.cast::<RawKey>().as_ref() }) else {
        return 0;
    };
    let key = if raw.selection == OSSL_KEYMGMT_SELECT_PRIVATE_KEY {
        OSSL_PKEY_PARAM_PRIV_KEY
    } else if raw.selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY {
        OSSL_PKEY_PARAM_PUB_KEY
    } else {
        return 0;
    };
    // SAFETY: the caller's array; a static key.
    let p = unsafe { OSSL_PARAM_locate_const(params, key.as_ptr()) };
    if p.is_null() {
        return 0;
    }
    let max = if raw.key.is_null() {
        0
    } else {
        // SAFETY: the caller's size.
        unsafe { raw.len.read() }
    };
    // SAFETY: a parameter of the array; the caller's buffer of `max` octets and size.
    unsafe { OSSL_PARAM_get_octet_string(p, raw.key, max, raw.len) }
}

/// `EVP_PKEY_get_raw_private_key` and `_public_key`.
///
/// # Safety
/// `pkey` is NULL or a live key; `buf` is NULL or has room for `*len` octets; `len` is room for
/// a size.
unsafe fn get_raw(pkey: *const EVP_PKEY, buf: *mut u8, len: *mut usize, selection: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { self::pkey(pkey) }) else {
        return 0;
    };
    let provided = k.is_provided();
    if provided {
        let mut b = buf.cast::<c_void>();
        let mut raw = RawKey {
            key: if buf.is_null() {
                ptr::null_mut()
            } else {
                &raw mut b
            },
            len,
            selection,
        };
        // SAFETY: the callback takes the `RawKey`, which outlives the call.
        return unsafe {
            super::export(
                k,
                selection,
                Some(get_raw_key_details),
                (&raw mut raw).cast(),
            )
        };
    }
    let is_priv = selection == OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    let f = if is_priv {
        "EVP_PKEY_get_raw_private_key"
    } else {
        "EVP_PKEY_get_raw_public_key"
    };
    let get = k.ameth_funcs().and_then(|m| {
        if is_priv {
            m.get_priv_key
        } else {
            m.get_pub_key
        }
    });
    let Some(get) = get else {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
            f,
        );
        return 0;
    };
    // SAFETY: the method's function with the key's handle; the caller's buffer and size.
    if unsafe { get(k.handle(), buf, len) } == 0 {
        err::raise(ERR_LIB_EVP, EVP_R_GET_RAW_KEY_FAILED, f);
        return 0;
    }
    1
}

ffi_export! {
    /// The key's raw private key into `priv_` (its size into `len`, which holds the room); with
    /// a NULL `priv_`, only its size.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `priv_` is NULL or has room for `*len` octets; `len` is
    /// room for a size.
    pub unsafe extern "C" fn EVP_PKEY_get_raw_private_key(pkey: *const EVP_PKEY, priv_: *mut u8, len: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { get_raw(pkey, priv_, len, OSSL_KEYMGMT_SELECT_PRIVATE_KEY) }
    }
}

ffi_export! {
    /// The key's raw public key, as `EVP_PKEY_get_raw_private_key`.
    ///
    /// # Safety
    /// As for `EVP_PKEY_get_raw_private_key`.
    pub unsafe extern "C" fn EVP_PKEY_get_raw_public_key(pkey: *const EVP_PKEY, pub_: *mut u8, len: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { get_raw(pkey, pub_, len, OSSL_KEYMGMT_SELECT_PUBLIC_KEY) }
    }
}

ffi_export! {
    /// A CMAC key of `cipher` from the `len` octets at `priv_`; NULL with
    /// `EVP_R_KEY_SETUP_FAILED`.
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `priv_` holds `len` octets; `cipher` is NULL or a
    /// live cipher.
    pub unsafe extern "C" fn EVP_PKEY_new_CMAC_key(e: *mut ENGINE, priv_: *const u8, len: usize, cipher: *const EVP_CIPHER) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        const F: &str = "new_cmac_key_int";
        // The key manager looks the engine up by its id (`OSSL_PKEY_PARAM_ENGINE`).
        let engine_id = if e.is_null() {
            ptr::null()
        } else {
            // SAFETY: the caller's live engine.
            unsafe { crate::engine::ENGINE_get_id(e) }
        };
        // SAFETY: the caller's guarantee.
        let name = if cipher.is_null() { ptr::null() } else { unsafe { EVP_CIPHER_get0_name(cipher) } };
        if name.is_null() {
            err::raise(ERR_LIB_EVP, EVP_R_KEY_SETUP_FAILED, F);
            return ptr::null_mut();
        }
        // SAFETY: the default context; a static name.
        let ctx = unsafe { EVP_PKEY_CTX_new_from_name(ptr::null_mut(), c"CMAC".as_ptr(), ptr::null()) };
        if ctx.is_null() {
            return ptr::null_mut();
        }
        let mut pkey: *mut EVP_PKEY = ptr::null_mut();
        // SAFETY: the context made above.
        if unsafe { EVP_PKEY_fromdata_init(ctx) } <= 0 {
            err::raise(ERR_LIB_EVP, EVP_R_KEY_SETUP_FAILED, F);
        } else {
            // SAFETY: a static key; the caller's octets.
            let p0 = unsafe {
                OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY.as_ptr(), priv_.cast_mut().cast(), len)
            };
            // SAFETY: a static key; the cipher's name.
            let p1 = unsafe {
                OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_CIPHER.as_ptr(), name.cast_mut(), 0)
            };
            let mut params = vec![p0, p1];
            if !engine_id.is_null() {
                // SAFETY: a static key; the engine's id.
                params.push(unsafe {
                    OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_ENGINE.as_ptr(), engine_id.cast_mut(), 0)
                });
            }
            params.push(end());
            // SAFETY: the context; the array above.
            if unsafe { EVP_PKEY_fromdata(ctx, &raw mut pkey, KEYPAIR, params.as_mut_ptr()) } <= 0 {
                err::raise(ERR_LIB_EVP, EVP_R_KEY_SETUP_FAILED, F);
            }
        }
        // SAFETY: made above.
        unsafe { EVP_PKEY_CTX_free(ctx) };
        pkey
    }
}
