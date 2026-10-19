//! Loading keys and SSL client certificates through an engine (`eng_pkey.c`): the engine must
//! be initialized (have a functional reference), and its loader runs with no lock held.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use std::sync::atomic::Ordering;

use rustyssl_abi::{
    ENGINE, ENGINE_R_FAILED_LOADING_PRIVATE_KEY, ENGINE_R_FAILED_LOADING_PUBLIC_KEY,
    ENGINE_R_NO_LOAD_FUNCTION, ENGINE_R_NOT_INITIALISED, ERR_LIB_ENGINE, EVP_PKEY, SSL, UI_METHOD,
    X509, stack_st_X509, stack_st_X509_NAME,
};

use super::{Fields, engine, global, null_parameter};
use crate::err;
use crate::ffi::ffi_export;

/// The engine's settings if it's initialized; the error OpenSSL raises otherwise.
///
/// # Safety
/// `e` is NULL or a live engine.
unsafe fn initialized(e: *mut ENGINE, function: &str) -> Option<Fields> {
    // SAFETY: the caller's guarantee.
    let Some(en) = (unsafe { engine(e) }) else {
        null_parameter(function);
        return None;
    };
    let g = global();
    let ready = en.funct_ref.load(Ordering::Acquire) != 0;
    drop(g);
    if !ready {
        err::raise(ERR_LIB_ENGINE, ENGINE_R_NOT_INITIALISED, function);
        return None;
    }
    Some(en.fields())
}

/// `ENGINE_load_private_key`/`_public_key`.
///
/// # Safety
/// As for those functions.
unsafe fn load_key(
    e: *mut ENGINE,
    key_id: *const c_char,
    ui_method: *mut UI_METHOD,
    callback_data: *mut c_void,
    public: bool,
) -> *mut EVP_PKEY {
    let (function, failed) = if public {
        ("ENGINE_load_public_key", ENGINE_R_FAILED_LOADING_PUBLIC_KEY)
    } else {
        (
            "ENGINE_load_private_key",
            ENGINE_R_FAILED_LOADING_PRIVATE_KEY,
        )
    };
    // SAFETY: the caller's guarantee.
    let Some(f) = (unsafe { initialized(e, function) }) else {
        return ptr::null_mut();
    };
    let loader = if public {
        f.load_pubkey
    } else {
        f.load_privkey
    };
    let Some(loader) = loader else {
        err::raise(ERR_LIB_ENGINE, ENGINE_R_NO_LOAD_FUNCTION, function);
        return ptr::null_mut();
    };
    // SAFETY: the engine's own function, with the caller's arguments; no lock is held.
    let pkey = unsafe { loader(e, key_id, ui_method, callback_data) };
    if pkey.is_null() {
        err::raise(ERR_LIB_ENGINE, failed, function);
    }
    pkey
}

ffi_export! {
    /// The private key `key_id` from the (initialized) engine's loader, or NULL.
    ///
    /// # Safety
    /// `e` is NULL or a live engine; the rest is what the engine's loader takes.
    pub unsafe extern "C" fn ENGINE_load_private_key(e: *mut ENGINE, key_id: *const c_char, ui_method: *mut UI_METHOD, callback_data: *mut c_void) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { load_key(e, key_id, ui_method, callback_data, false) }
    }
}

ffi_export! {
    /// The public key `key_id` from the (initialized) engine's loader, or NULL.
    ///
    /// # Safety
    /// `e` is NULL or a live engine; the rest is what the engine's loader takes.
    pub unsafe extern "C" fn ENGINE_load_public_key(e: *mut ENGINE, key_id: *const c_char, ui_method: *mut UI_METHOD, callback_data: *mut c_void) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { load_key(e, key_id, ui_method, callback_data, true) }
    }
}

ffi_export! {
    /// The SSL client certificate, key and chain from the (initialized) engine's loader: what
    /// the loader returns, or 0.
    ///
    /// # Safety
    /// `e` is NULL or a live engine; the rest is what the engine's loader takes.
    pub unsafe extern "C" fn ENGINE_load_ssl_client_cert(e: *mut ENGINE, s: *mut SSL, ca_dn: *mut stack_st_X509_NAME, pcert: *mut *mut X509, ppkey: *mut *mut EVP_PKEY, pother: *mut *mut stack_st_X509, ui_method: *mut UI_METHOD, callback_data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        const F: &str = "ENGINE_load_ssl_client_cert";
        // SAFETY: the caller's guarantee.
        let Some(f) = (unsafe { initialized(e, F) }) else { return 0 };
        let Some(loader) = f.load_ssl_client_cert else {
            err::raise(ERR_LIB_ENGINE, ENGINE_R_NO_LOAD_FUNCTION, F);
            return 0;
        };
        // SAFETY: the engine's own function, with the caller's arguments; no lock is held.
        unsafe { loader(e, s, ca_dn, pcert, ppkey, pother, ui_method, callback_data) }
    }
}
