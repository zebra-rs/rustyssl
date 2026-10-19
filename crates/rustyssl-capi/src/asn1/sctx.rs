//! `tasn_scn.c`: the context of OpenSSL's ASN.1 structure scanner. OpenSSL 3.5 has the context
//! and its accessors but nothing that scans with it, so its item, template, and flags stay
//! unset (NULL and 0); the application's callback is kept and never called, and its data is
//! the application's.

use core::ffi::{c_int, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use rustyssl_abi::{ASN1_ITEM, ASN1_SCTX, ASN1_TEMPLATE, ERR_LIB_ASN1};

use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};

/// The scanner's callback.
type ScanCb = unsafe extern "C" fn(ctx: *mut ASN1_SCTX) -> c_int;

/// A scanner context.
pub(crate) struct Sctx {
    /// The callback a scan would call, kept as OpenSSL keeps it.
    _scan_cb: Option<ScanCb>,
    app_data: AtomicPtr<c_void>,
}

handle_type!(ASN1_SCTX => Sctx);

ffi_export! {
    /// A new scanner context with `scan_cb`, or NULL.
    ///
    /// # Safety
    /// None.
    pub unsafe extern "C" fn ASN1_SCTX_new(scan_cb: Option<ScanCb>) -> *mut ASN1_SCTX
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        ASN1_SCTX::new_handle(Sctx { _scan_cb: scan_cb, app_data: AtomicPtr::new(ptr::null_mut()) })
    }
}

ffi_export! {
    /// Frees the context; NULL is a no-op.
    ///
    /// # Safety
    /// `p` is NULL or a live context, not used after.
    pub unsafe extern "C" fn ASN1_SCTX_free(p: *mut ASN1_SCTX)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_SCTX::free(p) };
    }
}

ffi_export! {
    /// The item being scanned: NULL, as nothing scans.
    ///
    /// # Safety
    /// `p` is NULL or a live context.
    pub unsafe extern "C" fn ASN1_SCTX_get_item(p: *mut ASN1_SCTX) -> *const ASN1_ITEM
    where failure = ptr::null(), library = ERR_LIB_ASN1
    {
        let _ = p;
        ptr::null()
    }
}

ffi_export! {
    /// The template being scanned: NULL, as nothing scans.
    ///
    /// # Safety
    /// `p` is NULL or a live context.
    pub unsafe extern "C" fn ASN1_SCTX_get_template(p: *mut ASN1_SCTX) -> *const ASN1_TEMPLATE
    where failure = ptr::null(), library = ERR_LIB_ASN1
    {
        let _ = p;
        ptr::null()
    }
}

ffi_export! {
    /// The scan's flags: 0, as nothing scans.
    ///
    /// # Safety
    /// `p` is NULL or a live context.
    pub unsafe extern "C" fn ASN1_SCTX_get_flags(p: *mut ASN1_SCTX) -> c_ulong
    where failure = 0, library = ERR_LIB_ASN1
    {
        let _ = p;
        0
    }
}

ffi_export! {
    /// Sets the application's data; NULL `p` is ignored (OpenSSL writes through it).
    ///
    /// # Safety
    /// `p` is NULL or a live context.
    pub unsafe extern "C" fn ASN1_SCTX_set_app_data(p: *mut ASN1_SCTX, data: *mut c_void)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        if let Some(s) = unsafe { ASN1_SCTX::get(p) } {
            s.app_data.store(data, Ordering::Relaxed);
        }
    }
}

ffi_export! {
    /// The application's data, or NULL.
    ///
    /// # Safety
    /// `p` is NULL or a live context.
    pub unsafe extern "C" fn ASN1_SCTX_get_app_data(p: *mut ASN1_SCTX) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_SCTX::get(p) }.map_or(ptr::null_mut(), |s| s.app_data.load(Ordering::Relaxed))
    }
}
