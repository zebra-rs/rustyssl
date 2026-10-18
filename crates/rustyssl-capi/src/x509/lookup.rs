//! A store's lookups (`x509_lu.c`, `x509_meth.c`, `by_file.c`, `by_dir.c`, `by_store.c`):
//! `X509_LOOKUP` and its methods (`X509_LOOKUP_METHOD`, the application's and the built-in
//! ones), and the built-in lookups: a file loaded into the store (`X509_LOOKUP_file`), a
//! directory of files named by their subject's hash (`X509_LOOKUP_hash_dir`, as `c_rehash`
//! makes it), and OSSL_STORE URIs (`X509_LOOKUP_store`).
//!
//! As OpenSSL's:
//! - A hashed directory's files are `<hash>.<n>` for certificates and `<hash>.r<n>` for CRLs,
//!   tried from 0 up while they exist; a directory's CRLs found are remembered, so the next
//!   search starts past them.
//! - The default file and directory are `SSL_CERT_FILE` and `SSL_CERT_DIR` from the
//!   environment (not when setuid), or OPENSSLDIR's `cert.pem` and `certs`.
//!
//! - The store lookup checks a URI opens when it's added, and loads it (and the names it
//!   gives, one level down) into the store when searched.
//!
//! The types are opaque in OpenSSL's headers, so their layouts are ours (OpenSSL's, in fact).

use core::cell::UnsafeCell;
use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use core::ptr;
use std::sync::Mutex;

use rustyssl_abi::{
    ASN1_INTEGER, BIO, ERR_LIB_X509, ERR_R_ASN1_LIB, ERR_R_BIO_LIB, ERR_R_PASSED_NULL_PARAMETER,
    ERR_R_PEM_LIB, OSSL_LIB_CTX, OSSL_STORE_INFO_CERT, OSSL_STORE_INFO_CRL, OSSL_STORE_INFO_NAME,
    OSSL_STORE_SEARCH, PEM_R_NO_START_LINE, X509_CRL, X509_FILETYPE_ASN1, X509_FILETYPE_DEFAULT,
    X509_FILETYPE_PEM, X509_L_ADD_DIR, X509_L_ADD_STORE, X509_L_FILE_LOAD, X509_L_LOAD_STORE,
    X509_LOOKUP, X509_LOOKUP_METHOD, X509_LOOKUP_TYPE, X509_LOOKUP_ctrl_fn,
    X509_LOOKUP_get_by_alias_fn, X509_LOOKUP_get_by_fingerprint_fn,
    X509_LOOKUP_get_by_issuer_serial_fn, X509_LOOKUP_get_by_subject_fn, X509_LU_CRL, X509_LU_X509,
    X509_NAME, X509_OBJECT, X509_R_BAD_X509_FILETYPE, X509_R_INVALID_DIRECTORY,
    X509_R_LOADING_CERT_DIR, X509_R_LOADING_DEFAULTS, X509_R_NO_CERTIFICATE_FOUND,
    X509_R_NO_CERTIFICATE_OR_CRL_FOUND, X509_R_NO_CRL_FOUND, X509_R_WRONG_LOOKUP_TYPE, X509_STORE,
};

use super::cert::{X509_free, X509_get_default_cert_dir, X509_get_default_cert_dir_env};
use super::cert::{X509_get_default_cert_file, X509_get_default_cert_file_env, X509_new_ex};
use super::crl::X509_CRL_free;
use super::info::X509_INFO_free;
use super::name::X509_NAME_hash_ex;
use super::store::{Object, X509_STORE_add_cert, X509_STORE_add_crl, key, store};
use crate::bio::file::{BIO_new_file, BIO_s_file};
use crate::bio::{BIO_free, BIO_new};
use crate::err::{
    self, ERR_clear_error, ERR_clear_last_mark, ERR_peek_last_error, ERR_pop_to_mark, ERR_set_mark,
};
use crate::ffi::ffi_export;
use crate::mem;
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value};
use crate::threads::{CRYPTO_THREAD_unlock, CRYPTO_THREAD_write_lock};

// Methods.

/// `struct x509_lookup_method_st`.
#[repr(C)]
pub(crate) struct Method {
    name: *mut c_char,
    new_item: Option<unsafe extern "C" fn(*mut X509_LOOKUP) -> c_int>,
    free: Option<unsafe extern "C" fn(*mut X509_LOOKUP)>,
    init: Option<unsafe extern "C" fn(*mut X509_LOOKUP) -> c_int>,
    shutdown: Option<unsafe extern "C" fn(*mut X509_LOOKUP) -> c_int>,
    ctrl: X509_LOOKUP_ctrl_fn,
    get_by_subject: X509_LOOKUP_get_by_subject_fn,
    get_by_issuer_serial: X509_LOOKUP_get_by_issuer_serial_fn,
    get_by_fingerprint: X509_LOOKUP_get_by_fingerprint_fn,
    get_by_alias: X509_LOOKUP_get_by_alias_fn,
    get_by_subject_ex: Option<GetBySubjectEx>,
    ctrl_ex: Option<CtrlEx>,
}

type GetBySubjectEx = unsafe extern "C" fn(
    *mut X509_LOOKUP,
    X509_LOOKUP_TYPE,
    *const X509_NAME,
    *mut X509_OBJECT,
    *mut OSSL_LIB_CTX,
    *const c_char,
) -> c_int;

type CtrlEx = unsafe extern "C" fn(
    *mut X509_LOOKUP,
    c_int,
    *const c_char,
    c_long,
    *mut *mut c_char,
    *mut OSSL_LIB_CTX,
    *const c_char,
) -> c_int;

/// A built-in method, which applications may change (OpenSSL's are writable statics).
struct Builtin(UnsafeCell<Method>);
// SAFETY: changing a built-in method is the application's to serialize, as in OpenSSL.
unsafe impl Sync for Builtin {}

impl Builtin {
    fn get(&self) -> *mut X509_LOOKUP_METHOD {
        self.0.get().cast()
    }
}

/// A method with only a name, as OpenSSL's initializers leave the rest NULL.
const fn named(name: &'static CStr) -> Method {
    Method {
        name: name.as_ptr().cast_mut(),
        new_item: None,
        free: None,
        init: None,
        shutdown: None,
        ctrl: None,
        get_by_subject: None,
        get_by_issuer_serial: None,
        get_by_fingerprint: None,
        get_by_alias: None,
        get_by_subject_ex: None,
        ctrl_ex: None,
    }
}

/// The method behind `m`, or `None` for NULL.
///
/// # Safety
/// `m` is NULL or a live method.
unsafe fn meth<'a>(m: *const X509_LOOKUP_METHOD) -> Option<&'a mut Method> {
    // SAFETY: the caller's guarantee.
    unsafe { m.cast::<Method>().cast_mut().as_mut() }
}

ffi_export! {
    /// A new method named `name` (a copy) with no functions, or NULL.
    ///
    /// # Safety
    /// `name` is NULL or a C string.
    pub unsafe extern "C" fn X509_LOOKUP_meth_new(name: *const c_char) -> *mut X509_LOOKUP_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        if name.is_null() {
            return ptr::null_mut();
        }
        let m = mem::alloc_zeroed(size_of::<Method>()).cast::<Method>();
        // SAFETY: new and zeroed (a valid `Method`), or NULL.
        let Some(method) = (unsafe { m.as_mut() }) else { return ptr::null_mut() };
        // SAFETY: the caller's C string.
        method.name = c_copy(unsafe { CStr::from_ptr(name) }.to_bytes());
        if method.name.is_null() {
            // SAFETY: made above.
            unsafe { mem::release(m.cast()) };
            return ptr::null_mut();
        }
        m.cast()
    }
}

/// A copy of `octets` and a NUL, in C memory, or NULL.
fn c_copy(octets: &[u8]) -> *mut c_char {
    let Some(n) = octets.len().checked_add(1) else {
        return ptr::null_mut();
    };
    let p = mem::alloc(n).cast::<u8>();
    if !p.is_null() {
        // SAFETY: the new block holds `n` octets.
        let block = unsafe { core::slice::from_raw_parts_mut(p, n) };
        if let Some((last, body)) = block.split_last_mut() {
            body.copy_from_slice(octets);
            *last = 0;
        }
    }
    p.cast()
}

ffi_export! {
    /// Frees a method made by `X509_LOOKUP_meth_new` (nothing for NULL).
    ///
    /// # Safety
    /// `method` is NULL or a method made by `X509_LOOKUP_meth_new`, no longer used.
    pub unsafe extern "C" fn X509_LOOKUP_meth_free(method: *mut X509_LOOKUP_METHOD)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(m) = unsafe { meth(method) } {
            // SAFETY: its own name.
            unsafe { mem::release(m.name.cast()) };
        }
        // SAFETY: as above.
        unsafe { mem::release(method.cast()) };
    }
}

ffi_export! {
    /// Sets the function making a lookup's data: 1 (0 for no method).
    ///
    /// # Safety
    /// `method` is NULL or a live method; `new_item` is NULL or a function of the type.
    pub unsafe extern "C" fn X509_LOOKUP_meth_set_new_item(method: *mut X509_LOOKUP_METHOD, new_item: Option<unsafe extern "C" fn(*mut X509_LOOKUP) -> c_int>) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { meth(method) }) else { return 0 };
        m.new_item = new_item;
        1
    }
}

ffi_export! {
    /// The function making a lookup's data, or NULL.
    ///
    /// # Safety
    /// `method` is NULL or a live method.
    pub unsafe extern "C" fn X509_LOOKUP_meth_get_new_item(method: *const X509_LOOKUP_METHOD) -> Option<unsafe extern "C" fn(*mut X509_LOOKUP) -> c_int>
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { meth(method) }.and_then(|m| m.new_item)
    }
}

ffi_export! {
    /// Sets the function freeing a lookup's data: 1 (0 for no method).
    ///
    /// # Safety
    /// `method` is NULL or a live method; `free_fn` is NULL or a function of the type.
    pub unsafe extern "C" fn X509_LOOKUP_meth_set_free(method: *mut X509_LOOKUP_METHOD, free_fn: Option<unsafe extern "C" fn(*mut X509_LOOKUP)>) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { meth(method) }) else { return 0 };
        m.free = free_fn;
        1
    }
}

ffi_export! {
    /// The function freeing a lookup's data, or NULL.
    ///
    /// # Safety
    /// `method` is NULL or a live method.
    pub unsafe extern "C" fn X509_LOOKUP_meth_get_free(method: *const X509_LOOKUP_METHOD) -> Option<unsafe extern "C" fn(*mut X509_LOOKUP)>
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { meth(method) }.and_then(|m| m.free)
    }
}

ffi_export! {
    /// Sets the function starting a lookup: 1 (0 for no method).
    ///
    /// # Safety
    /// `method` is NULL or a live method; `init` is NULL or a function of the type.
    pub unsafe extern "C" fn X509_LOOKUP_meth_set_init(method: *mut X509_LOOKUP_METHOD, init: Option<unsafe extern "C" fn(*mut X509_LOOKUP) -> c_int>) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { meth(method) }) else { return 0 };
        m.init = init;
        1
    }
}

ffi_export! {
    /// The function starting a lookup, or NULL.
    ///
    /// # Safety
    /// `method` is NULL or a live method.
    pub unsafe extern "C" fn X509_LOOKUP_meth_get_init(method: *const X509_LOOKUP_METHOD) -> Option<unsafe extern "C" fn(*mut X509_LOOKUP) -> c_int>
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { meth(method) }.and_then(|m| m.init)
    }
}

ffi_export! {
    /// Sets the function stopping a lookup: 1 (0 for no method).
    ///
    /// # Safety
    /// `method` is NULL or a live method; `shutdown` is NULL or a function of the type.
    pub unsafe extern "C" fn X509_LOOKUP_meth_set_shutdown(method: *mut X509_LOOKUP_METHOD, shutdown: Option<unsafe extern "C" fn(*mut X509_LOOKUP) -> c_int>) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { meth(method) }) else { return 0 };
        m.shutdown = shutdown;
        1
    }
}

ffi_export! {
    /// The function stopping a lookup, or NULL.
    ///
    /// # Safety
    /// `method` is NULL or a live method.
    pub unsafe extern "C" fn X509_LOOKUP_meth_get_shutdown(method: *const X509_LOOKUP_METHOD) -> Option<unsafe extern "C" fn(*mut X509_LOOKUP) -> c_int>
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { meth(method) }.and_then(|m| m.shutdown)
    }
}

ffi_export! {
    /// Sets the control function: 1 (0 for no method).
    ///
    /// # Safety
    /// `method` is NULL or a live method; `ctrl_fn` is NULL or a function of the type.
    pub unsafe extern "C" fn X509_LOOKUP_meth_set_ctrl(method: *mut X509_LOOKUP_METHOD, ctrl_fn: X509_LOOKUP_ctrl_fn) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { meth(method) }) else { return 0 };
        m.ctrl = ctrl_fn;
        1
    }
}

ffi_export! {
    /// The control function, or NULL.
    ///
    /// # Safety
    /// `method` is NULL or a live method.
    pub unsafe extern "C" fn X509_LOOKUP_meth_get_ctrl(method: *const X509_LOOKUP_METHOD) -> X509_LOOKUP_ctrl_fn
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { meth(method) }.and_then(|m| m.ctrl)
    }
}

ffi_export! {
    /// Sets the lookup by subject: 1 (0 for no method).
    ///
    /// # Safety
    /// `method` is NULL or a live method; `fn_` is NULL or a function of the type.
    pub unsafe extern "C" fn X509_LOOKUP_meth_set_get_by_subject(method: *mut X509_LOOKUP_METHOD, fn_: X509_LOOKUP_get_by_subject_fn) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { meth(method) }) else { return 0 };
        m.get_by_subject = fn_;
        1
    }
}

ffi_export! {
    /// The lookup by subject, or NULL.
    ///
    /// # Safety
    /// `method` is NULL or a live method.
    pub unsafe extern "C" fn X509_LOOKUP_meth_get_get_by_subject(method: *const X509_LOOKUP_METHOD) -> X509_LOOKUP_get_by_subject_fn
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { meth(method) }.and_then(|m| m.get_by_subject)
    }
}

ffi_export! {
    /// Sets the lookup by issuer and serial number: 1 (0 for no method).
    ///
    /// # Safety
    /// `method` is NULL or a live method; `fn_` is NULL or a function of the type.
    pub unsafe extern "C" fn X509_LOOKUP_meth_set_get_by_issuer_serial(method: *mut X509_LOOKUP_METHOD, fn_: X509_LOOKUP_get_by_issuer_serial_fn) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { meth(method) }) else { return 0 };
        m.get_by_issuer_serial = fn_;
        1
    }
}

ffi_export! {
    /// The lookup by issuer and serial number, or NULL.
    ///
    /// # Safety
    /// `method` is NULL or a live method.
    pub unsafe extern "C" fn X509_LOOKUP_meth_get_get_by_issuer_serial(method: *const X509_LOOKUP_METHOD) -> X509_LOOKUP_get_by_issuer_serial_fn
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { meth(method) }.and_then(|m| m.get_by_issuer_serial)
    }
}

ffi_export! {
    /// Sets the lookup by fingerprint: 1 (0 for no method).
    ///
    /// # Safety
    /// `method` is NULL or a live method; `fn_` is NULL or a function of the type.
    pub unsafe extern "C" fn X509_LOOKUP_meth_set_get_by_fingerprint(method: *mut X509_LOOKUP_METHOD, fn_: X509_LOOKUP_get_by_fingerprint_fn) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { meth(method) }) else { return 0 };
        m.get_by_fingerprint = fn_;
        1
    }
}

ffi_export! {
    /// The lookup by fingerprint, or NULL.
    ///
    /// # Safety
    /// `method` is NULL or a live method.
    pub unsafe extern "C" fn X509_LOOKUP_meth_get_get_by_fingerprint(method: *const X509_LOOKUP_METHOD) -> X509_LOOKUP_get_by_fingerprint_fn
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { meth(method) }.and_then(|m| m.get_by_fingerprint)
    }
}

ffi_export! {
    /// Sets the lookup by alias: 1 (0 for no method).
    ///
    /// # Safety
    /// `method` is NULL or a live method; `fn_` is NULL or a function of the type.
    pub unsafe extern "C" fn X509_LOOKUP_meth_set_get_by_alias(method: *mut X509_LOOKUP_METHOD, fn_: X509_LOOKUP_get_by_alias_fn) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { meth(method) }) else { return 0 };
        m.get_by_alias = fn_;
        1
    }
}

ffi_export! {
    /// The lookup by alias, or NULL.
    ///
    /// # Safety
    /// `method` is NULL or a live method.
    pub unsafe extern "C" fn X509_LOOKUP_meth_get_get_by_alias(method: *const X509_LOOKUP_METHOD) -> X509_LOOKUP_get_by_alias_fn
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { meth(method) }.and_then(|m| m.get_by_alias)
    }
}

// Lookups.

/// `struct x509_lookup_st`.
#[repr(C)]
struct Lookup {
    init: c_int,
    skip: c_int,
    method: *mut X509_LOOKUP_METHOD,
    method_data: *mut c_void,
    store_ctx: *mut X509_STORE,
}

/// The lookup behind `ctx`, or `None` for NULL.
///
/// # Safety
/// `ctx` is NULL or a live lookup.
unsafe fn lookup<'a>(ctx: *const X509_LOOKUP) -> Option<&'a mut Lookup> {
    // SAFETY: the caller's guarantee.
    unsafe { ctx.cast::<Lookup>().cast_mut().as_mut() }
}

/// The lookup's method (NULL for none).
///
/// # Safety
/// `ctx` is NULL or a live lookup.
pub(crate) unsafe fn method_of(ctx: *const X509_LOOKUP) -> *mut X509_LOOKUP_METHOD {
    // SAFETY: the caller's guarantee.
    unsafe { lookup(ctx) }.map_or(ptr::null_mut(), |l| l.method)
}

/// Whether the lookup is to be skipped, and its method's functions, if it has a method.
///
/// # Safety
/// `ctx` is NULL or a live lookup, whose method is NULL or live.
unsafe fn functions<'a>(ctx: *const X509_LOOKUP) -> Option<(bool, &'a Method)> {
    // SAFETY: the caller's guarantee.
    let l = unsafe { lookup(ctx) }?;
    // SAFETY: as above.
    let m = unsafe { meth(l.method) }?;
    Some((l.skip != 0, m))
}

/// Makes `xs` the lookup's store.
///
/// # Safety
/// `ctx` is a live lookup.
pub(crate) unsafe fn set_store(ctx: *mut X509_LOOKUP, xs: *mut X509_STORE) {
    // SAFETY: the caller's guarantee.
    if let Some(l) = unsafe { lookup(ctx) } {
        l.store_ctx = xs;
    }
}

ffi_export! {
    /// A new lookup of `method`, made ready by its `new_item`, or NULL.
    ///
    /// # Safety
    /// `method` is a live method that outlives the lookup.
    pub unsafe extern "C" fn X509_LOOKUP_new(method: *mut X509_LOOKUP_METHOD) -> *mut X509_LOOKUP
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        let ret = mem::alloc_zeroed(size_of::<Lookup>()).cast::<X509_LOOKUP>();
        // SAFETY: new and zeroed (a valid `Lookup`), or NULL.
        let Some(l) = (unsafe { lookup(ret) }) else { return ptr::null_mut() };
        l.method = method;
        // SAFETY: the caller's method.
        let new_item = unsafe { meth(method) }.and_then(|m| m.new_item);
        // SAFETY: the method's function, with the new lookup.
        if let Some(f) = new_item && unsafe { f(ret) } == 0 {
            // SAFETY: made above.
            unsafe { mem::release(ret.cast()) };
            return ptr::null_mut();
        }
        ret
    }
}

ffi_export! {
    /// Frees the lookup, with its method's `free` (nothing for NULL).
    ///
    /// # Safety
    /// `ctx` is NULL or a lookup made by `X509_LOOKUP_new`, not otherwise used after.
    pub unsafe extern "C" fn X509_LOOKUP_free(ctx: *mut X509_LOOKUP)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some((_, m)) = unsafe { functions(ctx) }
            && let Some(f) = m.free
        {
            // SAFETY: the method's function, with its lookup.
            unsafe { f(ctx) };
        }
        // SAFETY: as above.
        unsafe { mem::release(ctx.cast()) };
    }
}

ffi_export! {
    /// Starts the lookup (its method's `init`): 1 (without one), the method's answer, or 0
    /// without a method.
    ///
    /// # Safety
    /// `ctx` is NULL or a live lookup.
    pub unsafe extern "C" fn X509_LOOKUP_init(ctx: *mut X509_LOOKUP) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some((_, m)) = (unsafe { functions(ctx) }) else { return 0 };
        // SAFETY: the method's function, with its lookup.
        m.init.map_or(1, |f| unsafe { f(ctx) })
    }
}

ffi_export! {
    /// Stops the lookup (its method's `shutdown`): 1 (without one), the method's answer, or 0
    /// without a method.
    ///
    /// # Safety
    /// `ctx` is NULL or a live lookup.
    pub unsafe extern "C" fn X509_LOOKUP_shutdown(ctx: *mut X509_LOOKUP) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some((_, m)) = (unsafe { functions(ctx) }) else { return 0 };
        // SAFETY: the method's function, with its lookup.
        m.shutdown.map_or(1, |f| unsafe { f(ctx) })
    }
}

ffi_export! {
    /// Runs a control command with the library context (its method's `ctrl_ex`, or `ctrl`):
    /// the method's answer, 1 without either, or -1 without a method.
    ///
    /// # Safety
    /// `ctx` is NULL or a live lookup; the arguments are as the command needs.
    pub unsafe extern "C" fn X509_LOOKUP_ctrl_ex(ctx: *mut X509_LOOKUP, cmd: c_int, argc: *const c_char, argl: c_long, ret: *mut *mut c_char, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some((_, m)) = (unsafe { functions(ctx) }) else { return -1 };
        if let Some(f) = m.ctrl_ex {
            // SAFETY: the method's function, with the caller's arguments.
            return unsafe { f(ctx, cmd, argc, argl, ret, libctx, propq) };
        }
        // SAFETY: as above.
        m.ctrl.map_or(1, |f| unsafe { f(ctx, cmd, argc, argl, ret) })
    }
}

ffi_export! {
    /// Runs a control command (`X509_LOOKUP_ctrl_ex` in the default library context).
    ///
    /// # Safety
    /// As for [`X509_LOOKUP_ctrl_ex`].
    pub unsafe extern "C" fn X509_LOOKUP_ctrl(ctx: *mut X509_LOOKUP, cmd: c_int, argc: *const c_char, argl: c_long, ret: *mut *mut c_char) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { X509_LOOKUP_ctrl_ex(ctx, cmd, argc, argl, ret, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Looks up an object of `type_` named `name` into `ret` (its method's
    /// `get_by_subject_ex`, or `get_by_subject`): its answer, or 0 for a lookup skipped or
    /// without one.
    ///
    /// # Safety
    /// `ctx` is NULL or a live lookup; `name` is NULL or a live name; `ret` is a live object.
    pub unsafe extern "C" fn X509_LOOKUP_by_subject_ex(ctx: *mut X509_LOOKUP, type_: X509_LOOKUP_TYPE, name: *const X509_NAME, ret: *mut X509_OBJECT, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some((skip, m)) = (unsafe { functions(ctx) }) else { return 0 };
        if skip {
            return 0;
        }
        if let Some(f) = m.get_by_subject_ex {
            // SAFETY: the method's function, with the caller's arguments.
            return unsafe { f(ctx, type_, name, ret, libctx, propq) };
        }
        // SAFETY: as above.
        m.get_by_subject.map_or(0, |f| unsafe { f(ctx, type_, name, ret) })
    }
}

ffi_export! {
    /// Looks up an object by subject (`X509_LOOKUP_by_subject_ex` in the default library
    /// context).
    ///
    /// # Safety
    /// As for [`X509_LOOKUP_by_subject_ex`].
    pub unsafe extern "C" fn X509_LOOKUP_by_subject(ctx: *mut X509_LOOKUP, type_: X509_LOOKUP_TYPE, name: *const X509_NAME, ret: *mut X509_OBJECT) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { X509_LOOKUP_by_subject_ex(ctx, type_, name, ret, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Looks up an object by issuer and serial number (its method's `get_by_issuer_serial`):
    /// its answer, or 0 without one.
    ///
    /// # Safety
    /// `ctx` is NULL or a live lookup; the others are as its method needs.
    pub unsafe extern "C" fn X509_LOOKUP_by_issuer_serial(ctx: *mut X509_LOOKUP, type_: X509_LOOKUP_TYPE, name: *const X509_NAME, serial: *const ASN1_INTEGER, ret: *mut X509_OBJECT) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some((_, m)) = (unsafe { functions(ctx) }) else { return 0 };
        // SAFETY: the method's function, with the caller's arguments.
        m.get_by_issuer_serial.map_or(0, |f| unsafe { f(ctx, type_, name, serial, ret) })
    }
}

ffi_export! {
    /// Looks up an object by fingerprint (its method's `get_by_fingerprint`): its answer, or 0
    /// without one.
    ///
    /// # Safety
    /// `ctx` is NULL or a live lookup; the others are as its method needs.
    pub unsafe extern "C" fn X509_LOOKUP_by_fingerprint(ctx: *mut X509_LOOKUP, type_: X509_LOOKUP_TYPE, bytes: *const c_uchar, len: c_int, ret: *mut X509_OBJECT) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some((_, m)) = (unsafe { functions(ctx) }) else { return 0 };
        // SAFETY: the method's function, with the caller's arguments.
        m.get_by_fingerprint.map_or(0, |f| unsafe { f(ctx, type_, bytes, len, ret) })
    }
}

ffi_export! {
    /// Looks up an object by alias (its method's `get_by_alias`): its answer, or 0 without
    /// one.
    ///
    /// # Safety
    /// `ctx` is NULL or a live lookup; the others are as its method needs.
    pub unsafe extern "C" fn X509_LOOKUP_by_alias(ctx: *mut X509_LOOKUP, type_: X509_LOOKUP_TYPE, str: *const c_char, len: c_int, ret: *mut X509_OBJECT) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some((_, m)) = (unsafe { functions(ctx) }) else { return 0 };
        // SAFETY: the method's function, with the caller's arguments.
        m.get_by_alias.map_or(0, |f| unsafe { f(ctx, type_, str, len, ret) })
    }
}

ffi_export! {
    /// Sets the lookup's method data: 1 (0 for no lookup).
    ///
    /// # Safety
    /// `ctx` is NULL or a live lookup.
    pub unsafe extern "C" fn X509_LOOKUP_set_method_data(ctx: *mut X509_LOOKUP, data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(l) = (unsafe { lookup(ctx) }) else { return 0 };
        l.method_data = data;
        1
    }
}

ffi_export! {
    /// The lookup's method data, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live lookup.
    pub unsafe extern "C" fn X509_LOOKUP_get_method_data(ctx: *const X509_LOOKUP) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { lookup(ctx) }.map_or(ptr::null_mut(), |l| l.method_data)
    }
}

ffi_export! {
    /// The lookup's store, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live lookup.
    pub unsafe extern "C" fn X509_LOOKUP_get_store(ctx: *const X509_LOOKUP) -> *mut X509_STORE
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { lookup(ctx) }.map_or(ptr::null_mut(), |l| l.store_ctx)
    }
}

// Loading files (`by_file.c`).

/// The lookup's store (NULL for none).
///
/// # Safety
/// `ctx` is NULL or a live lookup.
unsafe fn store_of(ctx: *const X509_LOOKUP) -> *mut X509_STORE {
    // SAFETY: the caller's guarantee.
    unsafe { lookup(ctx) }.map_or(ptr::null_mut(), |l| l.store_ctx)
}

/// A file opened for reading (`BIO_read_filename`), or NULL with `ERR_R_BIO_LIB`.
///
/// # Safety
/// `file` is a C string.
unsafe fn open(file: *const c_char) -> *mut BIO {
    // SAFETY: no preconditions.
    let method = unsafe { BIO_s_file() };
    // SAFETY: a static method.
    let in_ = unsafe { BIO_new(method) };
    let flags = c_long::from(rustyssl_abi::BIO_CLOSE | rustyssl_abi::BIO_FP_READ);
    let cmd = rustyssl_abi::BIO_C_SET_FILENAME;
    let opened = !in_.is_null()
        // SAFETY: the new BIO; the caller's file name.
        && unsafe { crate::bio::BIO_ctrl(in_, cmd, flags, file.cast_mut().cast()) } > 0;
    if !opened {
        err::raise(ERR_LIB_X509, ERR_R_BIO_LIB, "X509_load_cert_file_ex");
        // SAFETY: as above.
        unsafe { BIO_free(in_) };
        return ptr::null_mut();
    }
    in_
}

/// Whether the last error is PEM's "no start line" (the end of a file's PEM blocks).
fn no_start_line() -> bool {
    // SAFETY: no preconditions.
    let e = unsafe { ERR_peek_last_error() };
    err::reason_of(e) == PEM_R_NO_START_LINE
}

ffi_export! {
    /// Adds the certificates of the file (`X509_FILETYPE_PEM`, all of them, or
    /// `X509_FILETYPE_ASN1`, one) to the lookup's store: their number, or 0
    /// (`X509_R_NO_CERTIFICATE_FOUND`, `X509_R_BAD_X509_FILETYPE`, and others).
    ///
    /// # Safety
    /// `ctx` is NULL or a live lookup; `file` is NULL or a C string; `propq` is NULL or a C
    /// string.
    pub unsafe extern "C" fn X509_load_cert_file_ex(ctx: *mut X509_LOOKUP, file: *const c_char, type_: c_int, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        const F: &str = "X509_load_cert_file_ex";
        if file.is_null() {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let in_ = unsafe { open(file) };
        if in_.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let xs = unsafe { store_of(ctx) };
        // SAFETY: as above.
        let mut x = unsafe { X509_new_ex(libctx, propq) };
        let mut count = 0;
        if x.is_null() {
            err::raise(ERR_LIB_X509, ERR_R_ASN1_LIB, F);
        } else if type_ == X509_FILETYPE_PEM {
            loop {
                // SAFETY: no preconditions.
                unsafe { ERR_set_mark() };
                // SAFETY: the file; a slot for the certificate; no callback and an empty
                // password.
                let got = unsafe { crate::pem_pkey::PEM_read_bio_X509_AUX(in_, &raw mut x, None, c"".as_ptr().cast_mut().cast()) };
                if got.is_null() {
                    if no_start_line() && count > 0 {
                        // SAFETY: no preconditions.
                        unsafe { ERR_pop_to_mark() };
                        break;
                    }
                    // SAFETY: as above.
                    unsafe { ERR_clear_last_mark() };
                    if count == 0 {
                        err::raise(ERR_LIB_X509, X509_R_NO_CERTIFICATE_FOUND, F);
                    } else {
                        err::raise(ERR_LIB_X509, ERR_R_PEM_LIB, F);
                        count = 0;
                    }
                    break;
                }
                // SAFETY: as above.
                unsafe { ERR_clear_last_mark() };
                // SAFETY: the lookup's store, or NULL; the certificate read.
                if unsafe { X509_STORE_add_cert(xs, x) } == 0 {
                    count = 0;
                    break;
                }
                // SAFETY: read above, added with its own reference.
                unsafe { X509_free(x) };
                // SAFETY: as above.
                x = unsafe { X509_new_ex(libctx, propq) };
                if x.is_null() {
                    err::raise(ERR_LIB_X509, ERR_R_ASN1_LIB, F);
                    count = 0;
                    break;
                }
                count += 1;
            }
        } else if type_ == X509_FILETYPE_ASN1 {
            // SAFETY: the file; the slot.
            if unsafe { crate::x509::cert::d2i_X509_bio(in_, &raw mut x) }.is_null() {
                err::raise(ERR_LIB_X509, X509_R_NO_CERTIFICATE_FOUND, F);
            } else {
                // SAFETY: as above.
                count = unsafe { X509_STORE_add_cert(xs, x) };
            }
        } else {
            err::raise(ERR_LIB_X509, X509_R_BAD_X509_FILETYPE, F);
        }
        // SAFETY: made here, or NULL.
        unsafe { X509_free(x) };
        // SAFETY: as above.
        unsafe { BIO_free(in_) };
        count
    }
}

ffi_export! {
    /// Adds the certificates of the file (`X509_load_cert_file_ex` in the default library
    /// context).
    ///
    /// # Safety
    /// As for [`X509_load_cert_file_ex`].
    pub unsafe extern "C" fn X509_load_cert_file(ctx: *mut X509_LOOKUP, file: *const c_char, type_: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { X509_load_cert_file_ex(ctx, file, type_, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Adds the CRLs of the file (PEM, all of them, or DER, one) to the lookup's store: their
    /// number, or 0 (`X509_R_NO_CRL_FOUND`, `X509_R_BAD_X509_FILETYPE`, and others).
    ///
    /// # Safety
    /// `ctx` is NULL or a live lookup; `file` is NULL or a C string.
    pub unsafe extern "C" fn X509_load_crl_file(ctx: *mut X509_LOOKUP, file: *const c_char, type_: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        const F: &str = "X509_load_crl_file";
        if file.is_null() {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let in_ = unsafe { open(file) };
        if in_.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let xs = unsafe { store_of(ctx) };
        let mut count = 0;
        let mut x: *mut X509_CRL = ptr::null_mut();
        if type_ == X509_FILETYPE_PEM {
            loop {
                // SAFETY: the file; no slot or callback, and an empty password.
                x = unsafe { crate::pem_pkey::PEM_read_bio_X509_CRL(in_, ptr::null_mut(), None, c"".as_ptr().cast_mut().cast()) };
                if x.is_null() {
                    if no_start_line() && count > 0 {
                        // SAFETY: no preconditions.
                        unsafe { ERR_clear_error() };
                        break;
                    }
                    if count == 0 {
                        err::raise(ERR_LIB_X509, X509_R_NO_CRL_FOUND, F);
                    } else {
                        err::raise(ERR_LIB_X509, ERR_R_PEM_LIB, F);
                        count = 0;
                    }
                    break;
                }
                // SAFETY: the lookup's store, or NULL; the CRL read.
                if unsafe { X509_STORE_add_crl(xs, x) } == 0 {
                    count = 0;
                    break;
                }
                count += 1;
                // SAFETY: read above, added with its own reference.
                unsafe { X509_CRL_free(x) };
            }
        } else if type_ == X509_FILETYPE_ASN1 {
            // SAFETY: the file; no slot.
            x = unsafe { crate::x509::crl::d2i_X509_CRL_bio(in_, ptr::null_mut()) };
            if x.is_null() {
                err::raise(ERR_LIB_X509, X509_R_NO_CRL_FOUND, F);
            } else {
                // SAFETY: as above.
                count = unsafe { X509_STORE_add_crl(xs, x) };
            }
        } else {
            err::raise(ERR_LIB_X509, X509_R_BAD_X509_FILETYPE, F);
        }
        // SAFETY: read here, or NULL.
        unsafe { X509_CRL_free(x) };
        // SAFETY: as above.
        unsafe { BIO_free(in_) };
        count
    }
}

ffi_export! {
    /// Adds the certificates and CRLs of a PEM file (`PEM_X509_INFO_read_bio_ex`) to the
    /// lookup's store, or those of another type's (`X509_load_cert_file_ex`): their number, or
    /// 0 (`X509_R_NO_CERTIFICATE_OR_CRL_FOUND` for none).
    ///
    /// # Safety
    /// As for [`X509_load_cert_file_ex`].
    pub unsafe extern "C" fn X509_load_cert_crl_file_ex(ctx: *mut X509_LOOKUP, file: *const c_char, type_: c_int, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        const F: &str = "X509_load_cert_crl_file_ex";
        if type_ != X509_FILETYPE_PEM {
            // SAFETY: the caller's guarantee.
            return unsafe { X509_load_cert_file_ex(ctx, file, type_, libctx, propq) };
        }
        // SAFETY: the caller's file name, or NULL; a static mode.
        let in_ = unsafe { BIO_new_file(file, c"r".as_ptr()) };
        if in_.is_null() {
            err::raise(ERR_LIB_X509, ERR_R_BIO_LIB, F);
            return 0;
        }
        // SAFETY: the file; a new list; no callback and an empty password; the caller's
        // context.
        let inf = unsafe { crate::x509::info::PEM_X509_INFO_read_bio_ex(in_, ptr::null_mut(), None, c"".as_ptr().cast_mut().cast(), libctx, propq) };
        // SAFETY: as above.
        unsafe { BIO_free(in_) };
        if inf.is_null() {
            err::raise(ERR_LIB_X509, ERR_R_PEM_LIB, F);
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let xs = unsafe { store_of(ctx) };
        let mut count = 0;
        let mut failed = false;
        // SAFETY: the list read.
        let n = unsafe { OPENSSL_sk_num(inf.cast()) };
        'add: for i in 0..n {
            // SAFETY: an index within the list.
            let itmp = unsafe { OPENSSL_sk_value(inf.cast(), i) }.cast::<rustyssl_abi::X509_INFO>();
            // SAFETY: an entry of the list.
            let Some(item) = (unsafe { itmp.as_ref() }) else { continue };
            if !item.x509.is_null() {
                // SAFETY: the lookup's store, or NULL; the entry's certificate.
                if unsafe { X509_STORE_add_cert(xs, item.x509) } == 0 {
                    (count, failed) = (0, true);
                    break 'add;
                }
                count += 1;
            }
            if !item.crl.is_null() {
                // SAFETY: as above; its CRL.
                if unsafe { X509_STORE_add_crl(xs, item.crl) } == 0 {
                    (count, failed) = (0, true);
                    break 'add;
                }
                count += 1;
            }
        }
        if count == 0 && !failed {
            err::raise(ERR_LIB_X509, X509_R_NO_CERTIFICATE_OR_CRL_FOUND, F);
        }
        // SAFETY: the list and its entries.
        unsafe { OPENSSL_sk_pop_free(inf.cast(), Some(info_free)) };
        count
    }
}

/// `X509_INFO_free` as a stack's free function.
unsafe extern "C" fn info_free(i: *mut c_void) {
    // SAFETY: an entry of the list, which the list owned.
    unsafe { X509_INFO_free(i.cast()) };
}

ffi_export! {
    /// Adds the certificates and CRLs of a file (`X509_load_cert_crl_file_ex` in the default
    /// library context).
    ///
    /// # Safety
    /// As for [`X509_load_cert_file_ex`].
    pub unsafe extern "C" fn X509_load_cert_crl_file(ctx: *mut X509_LOOKUP, file: *const c_char, type_: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { X509_load_cert_crl_file_ex(ctx, file, type_, ptr::null_mut(), ptr::null()) }
    }
}

/// An environment variable's value, unless the process is setuid (`ossl_safe_getenv`), or the
/// default; as a C string.
///
/// # Safety
/// `env` and `default` are static C strings.
unsafe fn env_or(env: *const c_char, default: *const c_char) -> std::ffi::CString {
    // SAFETY: the caller's guarantee.
    let name = unsafe { CStr::from_ptr(env) };
    crate::init::safe_getenv(name).unwrap_or_else(|| {
        // SAFETY: as above.
        unsafe { CStr::from_ptr(default) }.to_owned()
    })
}

/// A file type from a control's `long`, or -1 for one beyond `int` (OpenSSL's cast).
fn filetype(argl: c_long) -> c_int {
    c_int::try_from(argl).unwrap_or(-1)
}

/// `by_file_ctrl_ex`: `X509_L_FILE_LOAD` of a file (PEM: certificates and CRLs; DER: a
/// certificate) or of the default (`SSL_CERT_FILE`, or OPENSSLDIR's `cert.pem`): 1, or 0.
unsafe extern "C" fn file_ctrl_ex(
    ctx: *mut X509_LOOKUP,
    cmd: c_int,
    argp: *const c_char,
    argl: c_long,
    _ret: *mut *mut c_char,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> c_int {
    crate::ffi::guard(
        ERR_LIB_X509,
        "by_file_ctrl_ex",
        || 0,
        move || {
            if cmd != X509_L_FILE_LOAD {
                return 0;
            }
            let pem = X509_FILETYPE_PEM;
            if argl == c_long::from(X509_FILETYPE_DEFAULT) {
                // SAFETY: no preconditions.
                let env = unsafe { X509_get_default_cert_file_env() };
                // SAFETY: as above.
                let default = unsafe { X509_get_default_cert_file() };
                // SAFETY: static names.
                let file = unsafe { env_or(env, default) };
                // SAFETY: the caller's lookup; the file's name; the caller's context.
                let ok =
                    unsafe { X509_load_cert_crl_file_ex(ctx, file.as_ptr(), pem, libctx, propq) }
                        != 0;
                if !ok {
                    err::raise(ERR_LIB_X509, X509_R_LOADING_DEFAULTS, "by_file_ctrl_ex");
                }
                return c_int::from(ok);
            }
            let ok = if argl == c_long::from(pem) {
                // SAFETY: as above, with the caller's file.
                unsafe { X509_load_cert_crl_file_ex(ctx, argp, pem, libctx, propq) }
            } else {
                // SAFETY: as above.
                unsafe { X509_load_cert_file_ex(ctx, argp, filetype(argl), libctx, propq) }
            };
            c_int::from(ok != 0)
        },
    )
}

/// `by_file_ctrl`: [`file_ctrl_ex`] in the default library context.
unsafe extern "C" fn file_ctrl(
    ctx: *mut X509_LOOKUP,
    cmd: c_int,
    argp: *const c_char,
    argl: c_long,
    ret: *mut *mut c_char,
) -> c_int {
    // SAFETY: the caller's arguments.
    unsafe { file_ctrl_ex(ctx, cmd, argp, argl, ret, ptr::null_mut(), ptr::null()) }
}

static FILE_LOOKUP: Builtin = Builtin(UnsafeCell::new(Method {
    ctrl: Some(file_ctrl),
    ctrl_ex: Some(file_ctrl_ex),
    ..named(c"Load file into cache")
}));

/// The file lookup's method.
pub(crate) fn file_method() -> *mut X509_LOOKUP_METHOD {
    FILE_LOOKUP.get()
}

ffi_export! {
    /// The method that loads files into the store (`X509_L_FILE_LOAD`).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn X509_LOOKUP_file() -> *mut X509_LOOKUP_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        FILE_LOOKUP.get()
    }
}

// Hashed directories (`by_dir.c`).

/// A directory of a hashed-directory lookup (`BY_DIR_ENTRY`).
struct DirEntry {
    dir: Vec<u8>,
    dir_type: c_int,
    /// The CRL hashes found, with the suffix to look from (`BY_DIR_HASH`), sorted by hash.
    hashes: Vec<(c_ulong, c_int)>,
}

/// A hashed-directory lookup's data (`BY_DIR`).
#[derive(Default)]
struct ByDir {
    dirs: Mutex<Vec<DirEntry>>,
}

fn by_dir_entries(d: &ByDir) -> std::sync::MutexGuard<'_, Vec<DirEntry>> {
    d.dirs
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The lookup's directory data, or `None`.
///
/// # Safety
/// `ctx` is NULL or a live hashed-directory lookup.
unsafe fn by_dir<'a>(ctx: *const X509_LOOKUP) -> Option<&'a ByDir> {
    // SAFETY: the caller's guarantee.
    let data = unsafe { lookup(ctx) }?.method_data;
    // SAFETY: a hashed-directory lookup's data is a `ByDir` (`new_dir`).
    unsafe { data.cast::<ByDir>().as_ref() }
}

/// `new_dir`: the lookup's (empty) list of directories.
unsafe extern "C" fn new_dir(lu: *mut X509_LOOKUP) -> c_int {
    // SAFETY: the new lookup.
    let Some(l) = (unsafe { lookup(lu) }) else {
        return 0;
    };
    l.method_data = Box::into_raw(Box::new(ByDir::default())).cast();
    1
}

/// `free_dir`: frees the list.
unsafe extern "C" fn free_dir(lu: *mut X509_LOOKUP) {
    // SAFETY: the lookup being freed.
    let Some(l) = (unsafe { lookup(lu) }) else {
        return;
    };
    if !l.method_data.is_null() {
        // SAFETY: made by `new_dir`, freed once.
        drop(unsafe { Box::from_raw(l.method_data.cast::<ByDir>()) });
        l.method_data = ptr::null_mut();
    }
}

/// `add_cert_dir`: adds each directory of the `:`-separated list not already there: 1, or 0
/// (`X509_R_INVALID_DIRECTORY` for none).
///
/// # Safety
/// `dir` is NULL or a C string.
unsafe fn add_cert_dir(ld: &ByDir, dir: *const c_char, type_: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let text = (!dir.is_null()).then(|| unsafe { CStr::from_ptr(dir) }.to_bytes());
    let Some(text) = text.filter(|t| !t.is_empty()) else {
        err::raise(ERR_LIB_X509, X509_R_INVALID_DIRECTORY, "add_cert_dir");
        return 0;
    };
    let mut dirs = by_dir_entries(ld);
    for part in text.split(|&c| c == b':').filter(|p| !p.is_empty()) {
        if dirs.iter().any(|e| e.dir == part) {
            continue;
        }
        dirs.push(DirEntry {
            dir: part.to_vec(),
            dir_type: type_,
            hashes: Vec::new(),
        });
    }
    1
}

/// `dir_ctrl`: `X509_L_ADD_DIR` of directories, or of the default (`SSL_CERT_DIR`, or
/// OPENSSLDIR's `certs`): 1, or 0.
unsafe extern "C" fn dir_ctrl(
    ctx: *mut X509_LOOKUP,
    cmd: c_int,
    argp: *const c_char,
    argl: c_long,
    _retp: *mut *mut c_char,
) -> c_int {
    crate::ffi::guard(
        ERR_LIB_X509,
        "dir_ctrl",
        || 0,
        move || {
            if cmd != X509_L_ADD_DIR {
                return 0;
            }
            // SAFETY: a hashed-directory lookup.
            let Some(ld) = (unsafe { by_dir(ctx) }) else {
                return 0;
            };
            if argl == c_long::from(X509_FILETYPE_DEFAULT) {
                // SAFETY: no preconditions.
                let env = unsafe { X509_get_default_cert_dir_env() };
                // SAFETY: as above.
                let default = unsafe { X509_get_default_cert_dir() };
                // SAFETY: static names.
                let dir = unsafe { env_or(env, default) };
                // SAFETY: the directories' C string.
                let ret = unsafe { add_cert_dir(ld, dir.as_ptr(), X509_FILETYPE_PEM) };
                if ret == 0 {
                    err::raise(ERR_LIB_X509, X509_R_LOADING_CERT_DIR, "dir_ctrl");
                }
                return ret;
            }
            // SAFETY: the caller's directories.
            unsafe { add_cert_dir(ld, argp, filetype(argl)) }
        },
    )
}

/// Whether `path` exists as a link or file (`lstat`), and whether it leads somewhere (`stat`).
fn exists(path: &[u8]) -> (bool, bool) {
    use std::os::unix::ffi::OsStrExt as _;
    let p = std::path::Path::new(std::ffi::OsStr::from_bytes(path));
    (
        std::fs::symlink_metadata(p).is_ok(),
        std::fs::metadata(p).is_ok(),
    )
}

/// `get_cert_by_subject_ex`: loads the directories' files for `name`'s hash (`<hash>.<n>`,
/// or `<hash>.r<n>` for CRLs) into the store, and finds the store's object of `type_` named
/// `name`, into `ret` (its reference the store's): 1, or 0.
unsafe extern "C" fn dir_get_by_subject_ex(
    xl: *mut X509_LOOKUP,
    type_: X509_LOOKUP_TYPE,
    name: *const X509_NAME,
    ret: *mut X509_OBJECT,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> c_int {
    crate::ffi::guard(
        ERR_LIB_X509,
        "get_cert_by_subject_ex",
        || 0,
        move || {
            if name.is_null() {
                return 0;
            }
            // SAFETY: the caller's lookup.
            let ok = unsafe { dir_search(xl, type_, name, ret, libctx, propq) };
            // SAFETY: as above.
            let xs = unsafe { store_of(xl) };
            // SAFETY: the lookup's store, or NULL.
            if let Some(s) = unsafe { store(xs) }
            // SAFETY: the store's lock.
            && unsafe { CRYPTO_THREAD_write_lock(s.lock) } != 0
            {
                // SAFETY: the store's objects, under its lock.
                if unsafe { crate::stack::OPENSSL_sk_is_sorted(s.objs.cast()) } == 0 {
                    // SAFETY: as above.
                    unsafe { crate::stack::OPENSSL_sk_sort(s.objs.cast()) };
                }
                // SAFETY: as above.
                unsafe { CRYPTO_THREAD_unlock(s.lock) };
            }
            ok
        },
    )
}

/// The search of [`dir_get_by_subject_ex`], before its sorting of the store's objects.
///
/// # Safety
/// `xl` is a live hashed-directory lookup; `name` is a live name; `ret` is a live object.
unsafe fn dir_search(
    xl: *mut X509_LOOKUP,
    type_: X509_LOOKUP_TYPE,
    name: *const X509_NAME,
    ret: *mut X509_OBJECT,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> c_int {
    let postfix: &[u8] = match type_ {
        X509_LU_X509 => b"",
        X509_LU_CRL => b"r",
        _ => {
            err::raise(
                ERR_LIB_X509,
                X509_R_WRONG_LOOKUP_TYPE,
                "get_cert_by_subject_ex",
            );
            return 0;
        }
    };
    // SAFETY: the caller's guarantee.
    let Some(ld) = (unsafe { by_dir(xl) }) else {
        return 0;
    };
    let mut hash_ok = 0;
    // SAFETY: the caller's name; the caller's context; a local.
    let h = unsafe { X509_NAME_hash_ex(name, libctx, propq, &raw mut hash_ok) };
    if hash_ok == 0 {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let xs = unsafe { store_of(xl) };
    // SAFETY: the lookup's store, or NULL.
    let s = unsafe { store(xs) };
    let count = by_dir_entries(ld).len();
    for i in 0..count {
        let (dir, dir_type, start) = {
            let dirs = by_dir_entries(ld);
            let Some(ent) = dirs.get(i) else { break };
            let k = if type_ == X509_LU_CRL {
                ent.hashes
                    .binary_search_by_key(&h, |&(hash, _)| hash)
                    .ok()
                    .and_then(|j| ent.hashes.get(j))
                    .map_or(0, |&(_, k)| k)
            } else {
                0
            };
            (ent.dir.clone(), ent.dir_type, k)
        };
        let mut k = start;
        loop {
            let mut path = dir.clone();
            path.extend_from_slice(format!("/{h:08x}.").as_bytes());
            path.extend_from_slice(postfix);
            path.extend_from_slice(k.to_string().as_bytes());
            let (linked, real) = exists(&path);
            if !linked {
                break;
            }
            if real {
                path.push(0);
                // SAFETY: no preconditions.
                unsafe { ERR_set_mark() };
                if type_ == X509_LU_X509 {
                    // SAFETY: the lookup; the file's C string; the caller's context.
                    unsafe {
                        X509_load_cert_file_ex(xl, path.as_ptr().cast(), dir_type, libctx, propq)
                    };
                } else {
                    // SAFETY: as above.
                    unsafe { X509_load_crl_file(xl, path.as_ptr().cast(), dir_type) };
                }
                // SAFETY: no preconditions.
                unsafe { ERR_pop_to_mark() };
            }
            k = k.saturating_add(1);
        }
        let mut tmp: *mut Object = ptr::null_mut();
        if k > 0
            && let Some(s) = s
        {
            // SAFETY: the store's lock.
            if unsafe { CRYPTO_THREAD_write_lock(s.lock) } == 0 {
                return 0;
            }
            let probe = key(type_, name);
            let pp: *const Object = &raw const probe;
            // SAFETY: the store's objects, under its lock; a pointer to the key.
            let j = unsafe { crate::stack::OPENSSL_sk_find(s.objs.cast(), pp.cast()) };
            // SAFETY: as above; an index within the stack, or -1.
            tmp = unsafe { OPENSSL_sk_value(s.objs.cast(), j) }.cast();
            // SAFETY: as above.
            unsafe { CRYPTO_THREAD_unlock(s.lock) };
        }
        if type_ == X509_LU_CRL && k > 0 {
            let mut dirs = by_dir_entries(ld);
            if let Some(ent) = dirs.get_mut(i) {
                match ent.hashes.binary_search_by_key(&h, |&(hash, _)| hash) {
                    Ok(j) => {
                        if let Some(e) = ent.hashes.get_mut(j)
                            && e.1 < k
                        {
                            e.1 = k;
                        }
                    }
                    Err(j) => ent.hashes.insert(j, (h, k)),
                }
            }
        }
        // SAFETY: an object of the store, or NULL.
        if let Some(t) = unsafe { tmp.as_ref() } {
            // SAFETY: the caller's object.
            if let Some(r) = unsafe { ret.cast::<Object>().as_mut() } {
                r.type_ = t.type_;
                r.data = t.data;
            }
            // SAFETY: no preconditions.
            unsafe { ERR_clear_error() };
            return 1;
        }
    }
    0
}

/// `get_cert_by_subject`: [`dir_get_by_subject_ex`] in the default library context.
unsafe extern "C" fn dir_get_by_subject(
    xl: *mut X509_LOOKUP,
    type_: X509_LOOKUP_TYPE,
    name: *const X509_NAME,
    ret: *mut X509_OBJECT,
) -> c_int {
    // SAFETY: the caller's arguments.
    unsafe { dir_get_by_subject_ex(xl, type_, name, ret, ptr::null_mut(), ptr::null()) }
}

static DIR_LOOKUP: Builtin = Builtin(UnsafeCell::new(Method {
    new_item: Some(new_dir),
    free: Some(free_dir),
    ctrl: Some(dir_ctrl),
    get_by_subject: Some(dir_get_by_subject),
    get_by_subject_ex: Some(dir_get_by_subject_ex),
    ..named(c"Load certs from files in a directory")
}));

/// The hashed-directory lookup's method.
pub(crate) fn dir_method() -> *mut X509_LOOKUP_METHOD {
    DIR_LOOKUP.get()
}

ffi_export! {
    /// The method that finds certificates and CRLs in hashed directories (`X509_L_ADD_DIR`).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn X509_LOOKUP_hash_dir() -> *mut X509_LOOKUP_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        DIR_LOOKUP.get()
    }
}

// OSSL_STORE URIs (`by_store.c`).

/// `cached_store_st`: a URI to load from, its library context and properties.
struct CachedStore {
    uri: std::ffi::CString,
    libctx: *mut OSSL_LIB_CTX,
    propq: Option<std::ffi::CString>,
}

/// `cache_objects`: adds what the store at the URI holds (matching the search, if any) to the
/// lookup's store, following names `depth` levels down: whether the last object was added.
///
/// # Safety
/// `lctx` is a live lookup; `search` NULL or a live search.
unsafe fn cache_objects(
    lctx: *mut X509_LOOKUP,
    uri: *const c_char,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
    search: *const OSSL_STORE_SEARCH,
    depth: c_int,
) -> c_int {
    use crate::store::ctx::{
        OSSL_STORE_close, OSSL_STORE_find, OSSL_STORE_load, OSSL_STORE_open_ex,
    };
    use crate::store::info::{
        OSSL_STORE_INFO_free, OSSL_STORE_INFO_get_type, OSSL_STORE_INFO_get0_CERT,
        OSSL_STORE_INFO_get0_CRL, OSSL_STORE_INFO_get0_NAME,
    };
    // SAFETY: the caller's lookup.
    let xstore = unsafe { store_of(lctx) };
    // SAFETY: the URI; the context and properties; no UI, parameters, or post-processing.
    let ctx = unsafe {
        OSSL_STORE_open_ex(
            uri,
            libctx,
            propq,
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            None,
            ptr::null_mut(),
        )
    };
    if ctx.is_null() {
        return 0;
    }
    if !search.is_null() {
        // SAFETY: the store opened here; the caller's search.
        unsafe { OSSL_STORE_find(ctx, search) };
    }
    let mut ok = 0;
    loop {
        // SAFETY: as above.
        let info = unsafe { OSSL_STORE_load(ctx) };
        if info.is_null() {
            break;
        }
        // SAFETY: the information loaded.
        // SAFETY: the information loaded.
        let t = unsafe { OSSL_STORE_INFO_get_type(info) };
        ok = match t {
            OSSL_STORE_INFO_NAME if depth > 0 => {
                // SAFETY: as above.
                let name = unsafe { OSSL_STORE_INFO_get0_NAME(info) };
                // SAFETY: the lookup; its name, a C string.
                unsafe { cache_objects(lctx, name, libctx, propq, search, depth - 1) }
            }
            OSSL_STORE_INFO_CERT => {
                // SAFETY: as above.
                let x = unsafe { OSSL_STORE_INFO_get0_CERT(info) };
                // SAFETY: the lookup's store; the certificate.
                unsafe { X509_STORE_add_cert(xstore, x) }
            }
            OSSL_STORE_INFO_CRL => {
                // SAFETY: as above.
                let x = unsafe { OSSL_STORE_INFO_get0_CRL(info) };
                // SAFETY: the lookup's store; the CRL.
                unsafe { X509_STORE_add_crl(xstore, x) }
            }
            _ => 0,
        };
        // SAFETY: loaded here.
        unsafe { OSSL_STORE_INFO_free(info) };
        if ok == 0 {
            break;
        }
    }
    // SAFETY: opened here.
    unsafe { OSSL_STORE_close(ctx) };
    ok
}

/// The lookup's URIs.
///
/// # Safety
/// `ctx` is NULL or a live store lookup.
unsafe fn stores_of<'a>(ctx: *const X509_LOOKUP) -> Option<&'a mut Vec<CachedStore>> {
    // SAFETY: the caller's guarantee: the method data is the lookup's list, or NULL.
    unsafe { lookup(ctx) }
        .and_then(|l| unsafe { l.method_data.cast::<Vec<CachedStore>>().as_mut() })
}

/// `by_store_ctrl_ex`: `X509_L_ADD_STORE` (a URI that opens, kept; nothing for NULL) and
/// `X509_L_LOAD_STORE` (the URI's objects added now).
unsafe extern "C" fn store_ctrl_ex(
    ctx: *mut X509_LOOKUP,
    cmd: c_int,
    argp: *const c_char,
    _argl: c_long,
    _retp: *mut *mut c_char,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> c_int {
    crate::ffi::guard(
        ERR_LIB_X509,
        "by_store_ctrl_ex",
        || 0,
        move || match cmd {
            X509_L_ADD_STORE if argp.is_null() => 1,
            X509_L_ADD_STORE => {
                use crate::store::ctx::{OSSL_STORE_close, OSSL_STORE_open_ex};
                // SAFETY: the caller's URI; the context and properties.
                let sctx = unsafe {
                    OSSL_STORE_open_ex(
                        argp,
                        libctx,
                        propq,
                        ptr::null(),
                        ptr::null_mut(),
                        ptr::null(),
                        None,
                        ptr::null_mut(),
                    )
                };
                if sctx.is_null() {
                    return 0;
                }
                // SAFETY: opened here.
                unsafe { OSSL_STORE_close(sctx) };
                // SAFETY: the caller's C string.
                let uri = unsafe { CStr::from_ptr(argp) }.to_owned();
                // SAFETY: as above, or NULL.
                let propq = (!propq.is_null()).then(|| unsafe { CStr::from_ptr(propq) }.to_owned());
                let store = CachedStore { uri, libctx, propq };
                // SAFETY: the caller's lookup.
                match unsafe { stores_of(ctx) } {
                    Some(v) => v.push(store),
                    None => {
                        // SAFETY: as above.
                        let Some(l) = (unsafe { lookup(ctx) }) else {
                            return 0;
                        };
                        l.method_data = Box::into_raw(Box::new(vec![store])).cast();
                    }
                }
                1
            }
            X509_L_LOAD_STORE => {
                if argp.is_null() {
                    err::raise(
                        rustyssl_abi::ERR_LIB_OSSL_STORE,
                        ERR_R_PASSED_NULL_PARAMETER,
                        "OSSL_STORE_open_ex",
                    );
                    return 0;
                }
                // SAFETY: the caller's lookup and URI.
                unsafe { cache_objects(ctx, argp, libctx, propq, ptr::null(), 0) }
            }
            _ => 0,
        },
    )
}

/// `by_store_ctrl`: [`store_ctrl_ex`] in the default library context.
unsafe extern "C" fn store_ctrl(
    ctx: *mut X509_LOOKUP,
    cmd: c_int,
    argp: *const c_char,
    argl: c_long,
    retp: *mut *mut c_char,
) -> c_int {
    // SAFETY: the caller's arguments.
    unsafe { store_ctrl_ex(ctx, cmd, argp, argl, retp, ptr::null_mut(), ptr::null()) }
}

/// `by_store_subject`: the URIs' objects with the subject added to the store, then the store's
/// object of the type and subject into `ret` (not up-referenced, as by_dir's): 1, or 0.
unsafe extern "C" fn store_subject(
    ctx: *mut X509_LOOKUP,
    type_: X509_LOOKUP_TYPE,
    name: *const X509_NAME,
    ret: *mut X509_OBJECT,
) -> c_int {
    crate::ffi::guard(
        ERR_LIB_X509,
        "by_store_subject",
        || 0,
        move || {
            use crate::store::info::{OSSL_STORE_SEARCH_by_name, OSSL_STORE_SEARCH_free};
            // SAFETY: the caller's name, not changed by the search.
            let search = unsafe { OSSL_STORE_SEARCH_by_name(name.cast_mut()) };
            // A copy, so loading (which may use the lookup) holds no reference to the list.
            // SAFETY: the caller's lookup.
            let uris: Vec<(
                std::ffi::CString,
                *mut OSSL_LIB_CTX,
                Option<std::ffi::CString>,
            )> = unsafe { stores_of(ctx) }
                .map(|v| {
                    v.iter()
                        .map(|s| (s.uri.clone(), s.libctx, s.propq.clone()))
                        .collect()
                })
                .unwrap_or_default();
            let mut ok = 0;
            for (uri, libctx, propq) in &uris {
                let p = propq.as_deref().map_or(ptr::null(), CStr::as_ptr);
                // SAFETY: the lookup; a C string; the search.
                ok = unsafe { cache_objects(ctx, uri.as_ptr(), *libctx, p, search, 1) };
                if ok != 0 {
                    break;
                }
            }
            // SAFETY: made here.
            unsafe { OSSL_STORE_SEARCH_free(search) };
            if ok == 0 {
                return 0;
            }
            // SAFETY: the caller's lookup.
            let xs = unsafe { store_of(ctx) };
            // SAFETY: its store.
            let Some(s) = (unsafe { store(xs) }) else {
                return 0;
            };
            // SAFETY: the store's lock.
            if unsafe { CRYPTO_THREAD_write_lock(s.lock) } == 0 {
                return 0;
            }
            let probe = key(type_, name);
            let pp: *const Object = &raw const probe;
            // SAFETY: the store's objects, under its lock; a pointer to the key.
            let j = unsafe { crate::stack::OPENSSL_sk_find(s.objs.cast(), pp.cast()) };
            // SAFETY: as above; an index within the stack, or -1.
            let tmp: *mut Object = unsafe { OPENSSL_sk_value(s.objs.cast(), j) }.cast();
            // SAFETY: as above.
            unsafe { CRYPTO_THREAD_unlock(s.lock) };
            // SAFETY: an object of the store, or NULL.
            let Some(t) = (unsafe { tmp.as_ref() }) else {
                return 0;
            };
            if t.type_ != X509_LU_X509 && t.type_ != X509_LU_CRL {
                return 0;
            }
            // SAFETY: the caller's object.
            if let Some(r) = unsafe { ret.cast::<Object>().as_mut() } {
                r.type_ = t.type_;
                r.data = t.data;
            }
            1
        },
    )
}

/// `by_store_free`: frees the URIs.
unsafe extern "C" fn store_free(ctx: *mut X509_LOOKUP) {
    // SAFETY: the caller's lookup.
    if let Some(l) = unsafe { lookup(ctx) }
        && !l.method_data.is_null()
    {
        // SAFETY: the list `store_ctrl_ex` made, freed once.
        drop(unsafe { Box::from_raw(l.method_data.cast::<Vec<CachedStore>>()) });
        l.method_data = ptr::null_mut();
    }
}

static STORE_LOOKUP: Builtin = Builtin(UnsafeCell::new(Method {
    free: Some(store_free),
    ctrl: Some(store_ctrl),
    get_by_subject: Some(store_subject),
    ctrl_ex: Some(store_ctrl_ex),
    ..named(c"Load certs from STORE URIs")
}));

/// The store lookup's method.
pub(crate) fn store_method() -> *mut X509_LOOKUP_METHOD {
    STORE_LOOKUP.get()
}

ffi_export! {
    /// The method that loads OSSL_STORE URIs (`X509_L_ADD_STORE`, `X509_L_LOAD_STORE`).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn X509_LOOKUP_store() -> *mut X509_LOOKUP_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        STORE_LOOKUP.get()
    }
}

/// Whether the lookup is to be skipped (`skip`).
///
/// # Safety
/// `ctx` is NULL or a live lookup.
pub(crate) unsafe fn skip_of(ctx: *const X509_LOOKUP) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { lookup(ctx) }.is_some_and(|l| l.skip != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_lookups_and_methods_are_safe() {
        let l: *mut X509_LOOKUP = ptr::null_mut();
        // SAFETY: NULL where OpenSSL dereferences it.
        assert_eq!(unsafe { X509_LOOKUP_init(l) }, 0);
        // SAFETY: as above.
        let r = unsafe { X509_LOOKUP_ctrl(l, 1, ptr::null(), 0, ptr::null_mut()) };
        assert_eq!(r, -1);
        // SAFETY: as above.
        assert!(unsafe { X509_LOOKUP_get_store(l) }.is_null());
        // SAFETY: as above.
        let r = unsafe { X509_LOOKUP_set_method_data(l, ptr::null_mut()) };
        assert_eq!(r, 0);
        let m: *mut X509_LOOKUP_METHOD = ptr::null_mut();
        // SAFETY: as above.
        assert_eq!(unsafe { X509_LOOKUP_meth_set_init(m, None) }, 0);
        // SAFETY: as above.
        assert!(unsafe { X509_LOOKUP_meth_get_init(m) }.is_none());
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }
}
