//! The provider side of the configuration's `providers` module (`crypto/provider_conf.c`):
//! activating a provider a section names, and recording one it doesn't activate (its module
//! path and parameters, for a later load).
//!
//! OpenSSL holds its configuration lock while it activates (running the provider's init); here
//! the store's lock is taken only to check and record, so the provider's functions run with no
//! lock held. Where a provider made here loses a race to the store, OpenSSL frees it twice;
//! here once. And the reference `ossl_provider_find` gave for a provider already in the store
//! is given back, where OpenSSL keeps it (so the provider is never torn down).

use core::ffi::{CStr, c_int};
use std::ffi::CString;

use rustyssl_abi::{
    ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER, OSSL_LIB_CTX, OSSL_PROVIDER,
};

use super::{
    Info, Ptr, Stored, activate, add_to_store, context, deactivate, new, set_module_path,
    with_store,
};
use crate::err;
use crate::handle::Handle;

/// Whether the configuration already activated a provider of the name.
fn already_activated(activated: &[Stored], name: &CStr) -> bool {
    activated
        .iter()
        .any(|p| p.get().is_some_and(|p| p.name() == name))
}

/// `provider_conf_activate`: activates the provider `name` (with the module `path`, if any)
/// with the section's parameters (`Err` with `provider_conf_params`'s result if they couldn't
/// be read), and keeps it. Returns 1 if activated; 0 for a failure that isn't fatal (or one
/// already activated); below 0 for a fatal one (an unknown provider, unless `soft`).
///
/// # Safety
/// `libctx` is NULL or a live library context.
pub(crate) unsafe fn activate_from_conf(
    libctx: *mut OSSL_LIB_CTX,
    name: &CStr,
    path: Option<CString>,
    soft: bool,
    params: Result<Vec<(CString, CString)>, c_int>,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let checked = with_store(unsafe { context(libctx) }, |s| {
        let mut store = s.lock();
        if already_activated(&store.conf_activated, name) {
            return false;
        }
        // An activation is attempted: no fallback, so a misconfiguration can't silently bring
        // in the default provider.
        store.use_fallbacks = false;
        true
    });
    match checked {
        None => {
            err::raise(
                ERR_LIB_CRYPTO,
                ERR_R_INTERNAL_ERROR,
                "provider_conf_activate",
            );
            return -1;
        }
        Some(false) => return 0,
        Some(true) => {}
    }
    // `ossl_provider_find` without loading the configuration, else `ossl_provider_new`.
    // SAFETY: the caller's guarantee.
    let found = with_store(unsafe { context(libctx) }, |s| s.lock().find(name)).flatten();
    let (prov, found) = match found {
        // SAFETY: in the store, so live; this reference is ours.
        Some(p) if unsafe { OSSL_PROVIDER::up_ref(p) } => (p, true),
        // SAFETY: the caller's guarantee; no explicit parameters.
        _ => (unsafe { new(libctx, name, core::ptr::null()) }, false),
    };
    if prov.is_null() {
        if soft {
            // SAFETY: no preconditions.
            unsafe { crate::err::ERR_clear_error() };
        }
        return if soft { 0 } else { -1 };
    }
    if let Some(path) = path {
        // SAFETY: a live provider.
        unsafe { set_module_path(prov, path) };
    }
    let mut ok = match params {
        Err(rc) => rc,
        Ok(params) => {
            // SAFETY: a live provider.
            if let Some(p) = unsafe { OSSL_PROVIDER::get(prov) } {
                p.parameters
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .extend(params);
            }
            1
        }
    };
    let mut prov_gone = false;
    if ok == 1 {
        // SAFETY: a live provider, for each call below.
        if !unsafe { activate(prov) } {
            ok = 0;
        } else {
            // SAFETY: as above; a new provider's reference goes to the store.
            match unsafe { add_to_store(prov, false) } {
                None => {
                    // SAFETY: as above.
                    unsafe { deactivate(prov) };
                    ok = 0;
                }
                Some(actual) => {
                    // A new provider that lost a race to the store is freed by it.
                    prov_gone = actual != prov && !found;
                    // SAFETY: the store's provider, with our reference.
                    if actual != prov && !unsafe { activate(actual) } {
                        // SAFETY: our reference to it.
                        unsafe { OSSL_PROVIDER::free(actual) };
                        ok = 0;
                    } else {
                        // SAFETY: the caller's guarantee.
                        let kept = with_store(unsafe { context(libctx) }, |s| {
                            s.lock().conf_activated.push(Stored(Ptr(actual)));
                        });
                        if kept.is_none() {
                            // SAFETY: as above.
                            unsafe { deactivate(actual) };
                            // SAFETY: as above.
                            unsafe { OSSL_PROVIDER::free(actual) };
                            ok = 0;
                        } else {
                            ok = 1;
                            if found {
                                // The find's reference: the list holds add_to_store's.
                                // SAFETY: the reference taken above.
                                unsafe { OSSL_PROVIDER::free(prov) };
                            }
                            return ok;
                        }
                    }
                }
            }
        }
    }
    if ok <= 0 && !prov_gone {
        // SAFETY: our reference.
        unsafe { OSSL_PROVIDER::free(prov) };
    }
    ok
}

/// `ossl_provider_info_add_to_store`: records a provider the configuration names without
/// activating it, with its module path and parameters, for a later load.
///
/// # Safety
/// `libctx` is NULL or a live library context.
pub(crate) unsafe fn add_info_from_conf(
    libctx: *mut OSSL_LIB_CTX,
    name: Option<&CStr>,
    path: Option<CString>,
    parameters: Option<Vec<(CString, CString)>>,
) -> bool {
    let Some(name) = name else {
        err::raise(
            ERR_LIB_CRYPTO,
            ERR_R_PASSED_NULL_PARAMETER,
            "ossl_provider_info_add_to_store",
        );
        return false;
    };
    // SAFETY: the caller's guarantee.
    let added = with_store(unsafe { context(libctx) }, |s| {
        s.lock().infos.push(Info {
            name: name.to_owned(),
            init: None,
            path,
            parameters,
        });
    });
    if added.is_none() {
        err::raise(
            ERR_LIB_CRYPTO,
            ERR_R_INTERNAL_ERROR,
            "ossl_provider_info_add_to_store",
        );
    }
    added.is_some()
}
