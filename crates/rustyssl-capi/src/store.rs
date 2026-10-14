//! Store loaders an application registers (`OSSL_STORE_LOADER_new(3)`, deprecated in 3.0;
//! `store_register.c`): the loader object, its functions, and the registry of loaders by URI
//! scheme.
//!
//! These come ahead of the rest of `OSSL_STORE` (step 6.9) because OpenSSL's command-line tools
//! register their `org.openssl.engine` loader at start-up. Opening a store is still a stub, so
//! nothing calls a registered loader's functions yet.

use core::ffi::{CStr, c_char, c_int};
use core::ptr;
use std::sync::{Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    ENGINE, ERR_LIB_OSSL_STORE, OSSL_STORE_LOADER, OSSL_STORE_R_INVALID_SCHEME,
    OSSL_STORE_R_LOADER_INCOMPLETE, OSSL_STORE_R_UNREGISTERED_SCHEME, OSSL_STORE_attach_fn,
    OSSL_STORE_close_fn, OSSL_STORE_ctrl_fn, OSSL_STORE_eof_fn, OSSL_STORE_error_fn,
    OSSL_STORE_expect_fn, OSSL_STORE_find_fn, OSSL_STORE_load_fn, OSSL_STORE_open_ex_fn,
    OSSL_STORE_open_fn,
};

use crate::err;
use crate::ffi::ffi_export;

/// A loader's functions.
#[derive(Clone, Copy, Default)]
struct Funcs {
    open: OSSL_STORE_open_fn,
    open_ex: OSSL_STORE_open_ex_fn,
    attach: OSSL_STORE_attach_fn,
    ctrl: OSSL_STORE_ctrl_fn,
    expect: OSSL_STORE_expect_fn,
    find: OSSL_STORE_find_fn,
    load: OSSL_STORE_load_fn,
    eof: OSSL_STORE_eof_fn,
    error: OSSL_STORE_error_fn,
    close: OSSL_STORE_close_fn,
}

/// An application's loader (`struct ossl_store_loader_st` without a provider).
struct Loader {
    engine: *mut ENGINE,
    /// The caller's scheme string, not copied (as in OpenSSL).
    scheme: *const c_char,
    funcs: Mutex<Funcs>,
}

impl Loader {
    fn funcs(&self) -> MutexGuard<'_, Funcs> {
        self.funcs.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The scheme, as the caller's C string.
    fn scheme(&self) -> &CStr {
        // SAFETY: OSSL_STORE_LOADER_new refuses NULL, and the caller keeps the string.
        unsafe { CStr::from_ptr(self.scheme) }
    }
}

/// A registered loader.
struct Registered(*mut OSSL_STORE_LOADER);

// SAFETY: the registry only keeps and returns the pointers; the application owns the loaders.
unsafe impl Send for Registered {}

/// The registered loaders, by scheme.
static REGISTRY: Mutex<Vec<Registered>> = Mutex::new(Vec::new());

fn registry() -> MutexGuard<'static, Vec<Registered>> {
    REGISTRY.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The loader behind `l`.
///
/// # Safety
/// `l` is NULL or a live loader from `OSSL_STORE_LOADER_new`.
unsafe fn loader<'a>(l: *const OSSL_STORE_LOADER) -> Option<&'a Loader> {
    // SAFETY: the caller's guarantee.
    unsafe { l.cast::<Loader>().as_ref() }
}

ffi_export! {
    /// A new loader for the URI scheme `scheme` (kept, not copied) and the engine `e`, with no
    /// functions. NULL with `OSSL_STORE_R_INVALID_SCHEME` for a NULL scheme.
    ///
    /// # Safety
    /// `scheme` is NULL or a C string that outlives the loader.
    pub unsafe extern "C" fn OSSL_STORE_LOADER_new(e: *mut ENGINE, scheme: *const c_char) -> *mut OSSL_STORE_LOADER
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        if scheme.is_null() {
            err::raise(ERR_LIB_OSSL_STORE, OSSL_STORE_R_INVALID_SCHEME, "OSSL_STORE_LOADER_new");
            return ptr::null_mut();
        }
        Box::into_raw(Box::new(Loader { engine: e, scheme, funcs: Mutex::new(Funcs::default()) })).cast()
    }
}

ffi_export! {
    /// Frees a loader from `OSSL_STORE_LOADER_new` (unregister it first); NULL does nothing.
    ///
    /// # Safety
    /// `loader` is NULL or a live loader, not used afterwards.
    pub unsafe extern "C" fn OSSL_STORE_LOADER_free(loader: *mut OSSL_STORE_LOADER)
    where failure = (), library = ERR_LIB_OSSL_STORE
    {
        if !loader.is_null() {
            // SAFETY: a loader from OSSL_STORE_LOADER_new, freed once.
            drop(unsafe { Box::from_raw(loader.cast::<Loader>()) });
        }
    }
}

ffi_export! {
    /// The loader's engine.
    ///
    /// # Safety
    /// `loader` is a live loader.
    pub unsafe extern "C" fn OSSL_STORE_LOADER_get0_engine(loader: *const OSSL_STORE_LOADER) -> *const ENGINE
    where failure = ptr::null(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { self::loader(loader) }.map_or(ptr::null(), |l| l.engine.cast_const())
    }
}

ffi_export! {
    /// The loader's scheme.
    ///
    /// # Safety
    /// `loader` is a live loader.
    pub unsafe extern "C" fn OSSL_STORE_LOADER_get0_scheme(loader: *const OSSL_STORE_LOADER) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { self::loader(loader) }.map_or(ptr::null(), |l| l.scheme)
    }
}

/// Sets one of a loader's functions. Returns 1 (0 for NULL, where OpenSSL crashes).
///
/// # Safety
/// `l` is NULL or a live loader.
unsafe fn set(l: *mut OSSL_STORE_LOADER, f: impl FnOnce(&mut Funcs)) -> c_int {
    // SAFETY: the caller's guarantee.
    match unsafe { loader(l) } {
        Some(l) => {
            f(&mut l.funcs());
            1
        }
        None => 0,
    }
}

ffi_export! {
    /// Sets the loader's `open`. Returns 1.
    ///
    /// # Safety
    /// `loader` is a live loader; the function is NULL or of the documented type.
    pub unsafe extern "C" fn OSSL_STORE_LOADER_set_open(loader: *mut OSSL_STORE_LOADER, function: OSSL_STORE_open_fn) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { set(loader, |f| f.open = function) }
    }
}

ffi_export! {
    /// Sets the loader's `open_ex`. Returns 1.
    ///
    /// # Safety
    /// `loader` is a live loader; the function is NULL or of the documented type.
    pub unsafe extern "C" fn OSSL_STORE_LOADER_set_open_ex(loader: *mut OSSL_STORE_LOADER, function: OSSL_STORE_open_ex_fn) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { set(loader, |f| f.open_ex = function) }
    }
}

ffi_export! {
    /// Sets the loader's `attach`. Returns 1.
    ///
    /// # Safety
    /// `loader` is a live loader; the function is NULL or of the documented type.
    pub unsafe extern "C" fn OSSL_STORE_LOADER_set_attach(loader: *mut OSSL_STORE_LOADER, function: OSSL_STORE_attach_fn) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { set(loader, |f| f.attach = function) }
    }
}

ffi_export! {
    /// Sets the loader's `ctrl`. Returns 1.
    ///
    /// # Safety
    /// `loader` is a live loader; the function is NULL or of the documented type.
    pub unsafe extern "C" fn OSSL_STORE_LOADER_set_ctrl(loader: *mut OSSL_STORE_LOADER, function: OSSL_STORE_ctrl_fn) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { set(loader, |f| f.ctrl = function) }
    }
}

ffi_export! {
    /// Sets the loader's `expect`. Returns 1.
    ///
    /// # Safety
    /// `loader` is a live loader; the function is NULL or of the documented type.
    pub unsafe extern "C" fn OSSL_STORE_LOADER_set_expect(loader: *mut OSSL_STORE_LOADER, function: OSSL_STORE_expect_fn) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { set(loader, |f| f.expect = function) }
    }
}

ffi_export! {
    /// Sets the loader's `find`. Returns 1.
    ///
    /// # Safety
    /// `loader` is a live loader; the function is NULL or of the documented type.
    pub unsafe extern "C" fn OSSL_STORE_LOADER_set_find(loader: *mut OSSL_STORE_LOADER, function: OSSL_STORE_find_fn) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { set(loader, |f| f.find = function) }
    }
}

ffi_export! {
    /// Sets the loader's `load`. Returns 1.
    ///
    /// # Safety
    /// `loader` is a live loader; the function is NULL or of the documented type.
    pub unsafe extern "C" fn OSSL_STORE_LOADER_set_load(loader: *mut OSSL_STORE_LOADER, function: OSSL_STORE_load_fn) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { set(loader, |f| f.load = function) }
    }
}

ffi_export! {
    /// Sets the loader's `eof`. Returns 1.
    ///
    /// # Safety
    /// `loader` is a live loader; the function is NULL or of the documented type.
    pub unsafe extern "C" fn OSSL_STORE_LOADER_set_eof(loader: *mut OSSL_STORE_LOADER, function: OSSL_STORE_eof_fn) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { set(loader, |f| f.eof = function) }
    }
}

ffi_export! {
    /// Sets the loader's `error`. Returns 1.
    ///
    /// # Safety
    /// `loader` is a live loader; the function is NULL or of the documented type.
    pub unsafe extern "C" fn OSSL_STORE_LOADER_set_error(loader: *mut OSSL_STORE_LOADER, function: OSSL_STORE_error_fn) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { set(loader, |f| f.error = function) }
    }
}

ffi_export! {
    /// Sets the loader's `close`. Returns 1.
    ///
    /// # Safety
    /// `loader` is a live loader; the function is NULL or of the documented type.
    pub unsafe extern "C" fn OSSL_STORE_LOADER_set_close(loader: *mut OSSL_STORE_LOADER, function: OSSL_STORE_close_fn) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { set(loader, |f| f.close = function) }
    }
}

/// Whether `scheme` has RFC 3986's syntax: a letter, then letters, digits, `+`, `-`, or `.`.
/// As in OpenSSL, the empty scheme passes too (its check only fails a character it stops on).
fn valid_scheme(scheme: &[u8]) -> bool {
    match scheme.split_first() {
        Some((first, rest)) => {
            first.is_ascii_alphabetic()
                && rest
                    .iter()
                    .all(|c| c.is_ascii_alphanumeric() || b"+-.".contains(c))
        }
        None => true,
    }
}

ffi_export! {
    /// Registers the loader under its scheme (replacing one registered under it). Returns 1;
    /// 0 with `OSSL_STORE_R_INVALID_SCHEME` (data `scheme=...`) for a scheme that isn't RFC
    /// 3986's, or `OSSL_STORE_R_LOADER_INCOMPLETE` without `open`, `load`, `eof`, `error`, and
    /// `close`.
    ///
    /// # Safety
    /// `loader` is a live loader that stays live while registered.
    pub unsafe extern "C" fn OSSL_STORE_register_loader(loader: *mut OSSL_STORE_LOADER) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        let Some(l) = (unsafe { self::loader(loader) }) else { return 0 };
        let scheme = l.scheme().to_bytes();
        if !valid_scheme(scheme) {
            let mut data = b"scheme=".to_vec();
            data.extend_from_slice(scheme);
            err::raise_with_bytes(ERR_LIB_OSSL_STORE, OSSL_STORE_R_INVALID_SCHEME, "ossl_store_register_loader_int", &data);
            return 0;
        }
        let f = *l.funcs();
        if f.open.is_none() || f.load.is_none() || f.eof.is_none() || f.error.is_none() || f.close.is_none() {
            err::raise(ERR_LIB_OSSL_STORE, OSSL_STORE_R_LOADER_INCOMPLETE, "ossl_store_register_loader_int");
            return 0;
        }
        let mut reg = registry();
        // SAFETY: registered loaders are live while registered.
        reg.retain(|r| unsafe { self::loader(r.0) }.is_some_and(|o| o.scheme().to_bytes() != scheme));
        reg.push(Registered(loader));
        1
    }
}

ffi_export! {
    /// Unregisters and returns the loader registered under `scheme`; NULL with
    /// `OSSL_STORE_R_UNREGISTERED_SCHEME` (data `scheme=...`) if there's none.
    ///
    /// # Safety
    /// `scheme` is a C string.
    pub unsafe extern "C" fn OSSL_STORE_unregister_loader(scheme: *const c_char) -> *mut OSSL_STORE_LOADER
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        if scheme.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let wanted = unsafe { CStr::from_ptr(scheme) };
        let mut reg = registry();
        // SAFETY: registered loaders are live while registered.
        let at = reg.iter().position(|r| unsafe { self::loader(r.0) }.is_some_and(|l| l.scheme() == wanted));
        match at {
            Some(i) => reg.remove(i).0,
            None => {
                drop(reg);
                let mut data = b"scheme=".to_vec();
                data.extend_from_slice(wanted.to_bytes());
                err::raise_with_bytes(ERR_LIB_OSSL_STORE, OSSL_STORE_R_UNREGISTERED_SCHEME, "ossl_store_unregister_loader_int", &data);
                ptr::null_mut()
            }
        }
    }
}
