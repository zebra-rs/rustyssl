//! Loaders from providers (`OSSL_STORE_LOADER_fetch(3)`; `store_meth.c`): an
//! `OSSL_STORE_LOADER` made from a provider's store algorithm, fetched by URI scheme and
//! properties, listed, and asked for its names, properties, description, and provider.
//!
//! As in OpenSSL, a loader needs `open` or `attach`, and `load`, `eof`, and `close`; fetch
//! errors are `OSSL_STORE`'s, naming the "Scheme" (with a hint when none of the active
//! providers has one).

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use rustyssl_abi::{
    ERR_LIB_OSSL_STORE, ERR_R_PASSED_NULL_PARAMETER, OSSL_ALGORITHM, OSSL_FUNC_STORE_ATTACH,
    OSSL_FUNC_STORE_CLOSE, OSSL_FUNC_STORE_DELETE, OSSL_FUNC_STORE_EOF,
    OSSL_FUNC_STORE_EXPORT_OBJECT, OSSL_FUNC_STORE_LOAD, OSSL_FUNC_STORE_OPEN,
    OSSL_FUNC_STORE_OPEN_EX, OSSL_FUNC_STORE_SET_CTX_PARAMS, OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS,
    OSSL_FUNC_store_attach_fn, OSSL_FUNC_store_close_fn, OSSL_FUNC_store_delete_fn,
    OSSL_FUNC_store_eof_fn, OSSL_FUNC_store_export_object_fn, OSSL_FUNC_store_load_fn,
    OSSL_FUNC_store_open_ex_fn, OSSL_FUNC_store_open_fn, OSSL_FUNC_store_set_ctx_params_fn,
    OSSL_FUNC_store_settable_ctx_params_fn, OSSL_LIB_CTX, OSSL_OP_STORE, OSSL_PROVIDER,
    OSSL_STORE_LOADER, OSSL_STORE_R_LOADER_INCOMPLETE,
};

use super::{Loader, loader};
use crate::err;
use crate::evp::fetch::{self, Kind, Style};
use crate::ffi::ffi_export;
use crate::handle::Handle;
use crate::provider::Ptr;

/// A provider's loader: the provider part of `ossl_store_loader_st`.
pub(crate) struct Provided {
    /// The provider, with a reference.
    pub(crate) prov: Ptr<OSSL_PROVIDER>,
    pub(crate) scheme_id: u32,
    /// The provider's strings, valid while it lives.
    pub(crate) propdef: *const c_char,
    pub(crate) description: *const c_char,
    pub(crate) refs: AtomicUsize,
    pub(crate) open: OSSL_FUNC_store_open_fn,
    pub(crate) attach: OSSL_FUNC_store_attach_fn,
    pub(crate) settable_ctx_params: OSSL_FUNC_store_settable_ctx_params_fn,
    pub(crate) set_ctx_params: OSSL_FUNC_store_set_ctx_params_fn,
    pub(crate) load: OSSL_FUNC_store_load_fn,
    pub(crate) eof: OSSL_FUNC_store_eof_fn,
    pub(crate) close: OSSL_FUNC_store_close_fn,
    pub(crate) export_object: OSSL_FUNC_store_export_object_fn,
    pub(crate) delete: OSSL_FUNC_store_delete_fn,
    pub(crate) open_ex: OSSL_FUNC_store_open_ex_fn,
}

/// A dispatch table's function as the type its id stands for.
///
/// # Safety
/// `F` is the function pointer type `f` really has.
unsafe fn cast<F: Copy>(f: unsafe extern "C" fn()) -> F {
    // SAFETY: the caller's guarantee; function pointers all have one size.
    unsafe { core::mem::transmute_copy(&f) }
}

/// `loader_from_algorithm`: a loader from the provider's algorithm, with one reference, or NULL
/// with an error.
///
/// # Safety
/// `algo`'s strings and table are the provider's, valid while it lives; `prov` is a live
/// provider.
unsafe fn from_algorithm(
    scheme_id: u32,
    algo: &OSSL_ALGORITHM,
    prov: *mut OSSL_PROVIDER,
) -> *mut c_void {
    let mut p = Provided {
        prov: Ptr(prov),
        scheme_id,
        propdef: algo.property_definition,
        description: algo.algorithm_description,
        refs: AtomicUsize::new(1),
        open: None,
        attach: None,
        settable_ctx_params: None,
        set_ctx_params: None,
        load: None,
        eof: None,
        close: None,
        export_object: None,
        delete: None,
        open_ex: None,
    };
    let mut at = algo.implementation;
    // SAFETY: the caller's guarantee: the table is ended by a zero id.
    while let Some(d) = unsafe { at.as_ref() } {
        if d.function_id == 0 {
            break;
        }
        at = at.wrapping_add(1);
        let Some(func) = d.function else { continue };
        /// Stores `func` as the function its id stands for, the first of each id only.
        macro_rules! set {
            ($field:ident) => {
                if p.$field.is_none() {
                    // SAFETY: the provider's guarantee of the function type for this id.
                    p.$field = unsafe { cast(func) };
                }
            };
        }
        match d.function_id {
            OSSL_FUNC_STORE_OPEN => set!(open),
            OSSL_FUNC_STORE_ATTACH => set!(attach),
            OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS => set!(settable_ctx_params),
            OSSL_FUNC_STORE_SET_CTX_PARAMS => set!(set_ctx_params),
            OSSL_FUNC_STORE_LOAD => set!(load),
            OSSL_FUNC_STORE_EOF => set!(eof),
            OSSL_FUNC_STORE_CLOSE => set!(close),
            OSSL_FUNC_STORE_EXPORT_OBJECT => set!(export_object),
            OSSL_FUNC_STORE_DELETE => set!(delete),
            OSSL_FUNC_STORE_OPEN_EX => set!(open_ex),
            _ => {}
        }
    }
    if (p.open.is_none() && p.attach.is_none())
        || p.load.is_none()
        || p.eof.is_none()
        || p.close.is_none()
    {
        err::raise(
            ERR_LIB_OSSL_STORE,
            OSSL_STORE_R_LOADER_INCOMPLETE,
            "loader_from_algorithm",
        );
        return ptr::null_mut();
    }
    // SAFETY: the caller's live provider; the loader holds the reference.
    if !unsafe { OSSL_PROVIDER::up_ref(prov) } {
        return ptr::null_mut();
    }
    Box::into_raw(Box::new(Loader::provided(p))).cast()
}

/// Adds a reference to a loader in a store.
unsafe fn up_ref(m: *mut c_void) {
    // SAFETY: a live loader.
    unsafe { OSSL_STORE_LOADER_up_ref(m.cast()) };
}

/// Drops a reference to a loader in a store.
unsafe fn free(m: *mut c_void) {
    // SAFETY: a reference the store held.
    unsafe { super::OSSL_STORE_LOADER_free(m.cast()) };
}

/// Loaders to fetching.
static LOADERS: Kind = Kind {
    operation: OSSL_OP_STORE,
    style: Style::Store,
    from_algorithm,
    up_ref,
    free,
};

/// A provider's loader behind a pointer.
///
/// # Safety
/// `l` is NULL or a live loader.
pub(crate) unsafe fn provided<'a>(l: *const OSSL_STORE_LOADER) -> Option<&'a Provided> {
    // SAFETY: the caller's guarantee.
    unsafe { loader(l) }.and_then(|l| l.provided.as_ref())
}

/// Drops a reference to a provider's loader: whether it was the last (the loader must then be
/// freed).
pub(crate) fn release(p: &Provided) -> bool {
    if p.refs.fetch_sub(1, Ordering::AcqRel) > 1 {
        return false;
    }
    // SAFETY: the reference the loader held.
    unsafe { OSSL_PROVIDER::free(p.prov.0) };
    true
}

/// A C string argument, or `None` for NULL.
///
/// # Safety
/// `p` is NULL or a C string.
unsafe fn text<'a>(p: *const c_char) -> Option<&'a CStr> {
    // SAFETY: the caller's guarantee.
    (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) })
}

ffi_export! {
    /// The loader for the URI scheme from the library context's providers (`propq` choosing
    /// among them), with a reference, or NULL.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `scheme` and `properties` NULL or C strings.
    pub unsafe extern "C" fn OSSL_STORE_LOADER_fetch(libctx: *mut OSSL_LIB_CTX, scheme: *const c_char, properties: *const c_char) -> *mut OSSL_STORE_LOADER
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        let (s, p) = (unsafe { text(scheme) }, unsafe { text(properties) });
        // SAFETY: as above.
        unsafe { fetch::fetch(libctx, &LOADERS, s, p) }.cast()
    }
}

ffi_export! {
    /// Adds a reference to a provider's loader (a registered one has none): 1.
    ///
    /// # Safety
    /// `loader` is a live loader.
    pub unsafe extern "C" fn OSSL_STORE_LOADER_up_ref(loader: *mut OSSL_STORE_LOADER) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        if let Some(p) = unsafe { provided(loader) } {
            p.refs.fetch_add(1, Ordering::Relaxed);
        }
        1
    }
}

ffi_export! {
    /// The loader's provider (NULL for a registered one).
    ///
    /// # Safety
    /// `loader` is a live loader.
    pub unsafe extern "C" fn OSSL_STORE_LOADER_get0_provider(loader: *const OSSL_STORE_LOADER) -> *const OSSL_PROVIDER
    where failure = ptr::null(), library = ERR_LIB_OSSL_STORE
    {
        if loader.is_null() {
            err::raise(ERR_LIB_OSSL_STORE, ERR_R_PASSED_NULL_PARAMETER, "OSSL_STORE_LOADER_get0_provider");
            return ptr::null();
        }
        // SAFETY: the caller's guarantee.
        unsafe { provided(loader) }.map_or(ptr::null(), |p| p.prov.0.cast_const())
    }
}

ffi_export! {
    /// The loader's property definition (NULL for a registered one).
    ///
    /// # Safety
    /// `loader` is a live loader.
    pub unsafe extern "C" fn OSSL_STORE_LOADER_get0_properties(loader: *const OSSL_STORE_LOADER) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_OSSL_STORE
    {
        if loader.is_null() {
            err::raise(ERR_LIB_OSSL_STORE, ERR_R_PASSED_NULL_PARAMETER, "OSSL_STORE_LOADER_get0_properties");
            return ptr::null();
        }
        // SAFETY: the caller's guarantee.
        unsafe { provided(loader) }.map_or(ptr::null(), |p| p.propdef)
    }
}

ffi_export! {
    /// The loader's description (NULL for none, or a registered one).
    ///
    /// # Safety
    /// `loader` is a live loader.
    pub unsafe extern "C" fn OSSL_STORE_LOADER_get0_description(loader: *const OSSL_STORE_LOADER) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { provided(loader) }.map_or(ptr::null(), |p| p.description)
    }
}

ffi_export! {
    /// Whether `name` is one of the loader's schemes (0 for a registered one).
    ///
    /// # Safety
    /// `loader` is a live loader; `name` NULL or a C string.
    pub unsafe extern "C" fn OSSL_STORE_LOADER_is_a(loader: *const OSSL_STORE_LOADER, name: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { provided(loader) }) else { return 0 };
        // SAFETY: as above.
        let n = unsafe { text(name) }.map_or(&b""[..], CStr::to_bytes);
        c_int::from(fetch::number_in(p.prov.0, n) == p.scheme_id)
    }
}

type NameFn = unsafe extern "C" fn(*const c_char, *mut c_void);
type DoAllFn = unsafe extern "C" fn(*mut OSSL_STORE_LOADER, *mut c_void);

ffi_export! {
    /// Calls `fn_` with each of the loader's schemes (none for a registered one): 1, or 0 for a
    /// NULL loader.
    ///
    /// # Safety
    /// `loader` is NULL or a live loader; `fn_` NULL or a callback for `data`.
    pub unsafe extern "C" fn OSSL_STORE_LOADER_names_do_all(loader: *const OSSL_STORE_LOADER, fn_: Option<NameFn>, data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_STORE
    {
        if loader.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { provided(loader) }) else { return 1 };
        for &n in &fetch::c_names_of(p.prov.0, p.scheme_id) {
            if let Some(f) = fn_ {
                // SAFETY: the caller's callback with a string the context keeps, and its data.
                unsafe { f(n, data) };
            }
        }
        1
    }
}

ffi_export! {
    /// Calls `user_fn` with each loader the library context's active providers offer.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `user_fn` NULL or a callback for
    /// `user_arg`.
    pub unsafe extern "C" fn OSSL_STORE_LOADER_do_all_provided(libctx: *mut OSSL_LIB_CTX, user_fn: Option<DoAllFn>, user_arg: *mut c_void)
    where failure = (), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        for m in &unsafe { fetch::all(libctx, &LOADERS) } {
            if let Some(f) = user_fn {
                // SAFETY: the caller's callback with a loader held for the call.
                unsafe { f(m.as_ptr().cast(), user_arg) };
            }
        }
    }
}
