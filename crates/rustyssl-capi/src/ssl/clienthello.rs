//! The client hello callback's getters (`SSL_client_hello_*`, ssl_lib.c): the ClientHello the
//! server is processing, as the core keeps it. Pointers point into the core's copy, which
//! stays put while the callback runs (the connection isn't stepping then).

use core::ffi::{c_int, c_uchar, c_uint};
use core::ptr;

use rustyssl_abi::{ERR_LIB_SSL, SSL};

use super::conn::{Ssl, ssl};
use crate::ffi::ffi_export;
use crate::mem;

/// Runs `f` on the ClientHello being processed and its collected extensions, if any.
fn with_hello<T>(
    x: &Ssl,
    f: impl FnOnce(&rustyssl_tls::msgs::hello::ClientHello, &[(u16, &[u8])]) -> T,
) -> Option<T> {
    let st = x.state();
    let conn = st.drv.tls.as_ref()?;
    let (hello, exts) = conn.client_hello_exts()?;
    Some(f(hello, &exts))
}

/// The connection behind `s`.
///
/// # Safety
/// `s` is NULL or a live connection.
unsafe fn of<'a>(s: *const SSL) -> Option<&'a Ssl> {
    // SAFETY: the caller's guarantee.
    unsafe { ssl(s) }
}

/// Writes `p` to `out` if `out` isn't NULL.
///
/// # Safety
/// `out` is NULL or writable.
unsafe fn put(out: *mut *const c_uchar, p: *const u8) {
    if !out.is_null() {
        // SAFETY: the caller's slot.
        unsafe { out.write(p) };
    }
}

ffi_export! {
    /// Whether the ClientHello came in SSLv2 format (0 without one).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_client_hello_isv2(s: *mut SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { of(s) }) else { return 0 };
        with_hello(x, |h, _| c_int::from(h.sslv2)).unwrap_or(0)
    }
}

ffi_export! {
    /// The ClientHello's legacy_version (0 without one).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_client_hello_get0_legacy_version(s: *mut SSL) -> c_uint
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { of(s) }) else { return 0 };
        with_hello(x, |h, _| c_uint::from(h.legacy_version)).unwrap_or(0)
    }
}

ffi_export! {
    /// The client's random in `*out` and its length (32; 0 without a ClientHello).
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `out` NULL or writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_client_hello_get0_random(s: *mut SSL, out: *mut *const c_uchar) -> usize
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { of(s) }) else { return 0 };
        let Some(p) = with_hello(x, |h, _| h.random.as_ptr()) else { return 0 };
        // SAFETY: the caller's slot; the core's copy, live while the callback runs.
        unsafe { put(out, p) };
        rustyssl_tls::consts::RANDOM_LEN
    }
}

ffi_export! {
    /// The legacy session ID in `*out` and its length (0 without a ClientHello).
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `out` NULL or writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_client_hello_get0_session_id(s: *mut SSL, out: *mut *const c_uchar) -> usize
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { of(s) }) else { return 0 };
        let Some((p, n)) = with_hello(x, |h, _| (h.session_id.as_ptr(), h.session_id.len())) else { return 0 };
        // SAFETY: as above.
        unsafe { put(out, p) };
        n
    }
}

ffi_export! {
    /// The cipher suites' octets in `*out` and their length (0 without a ClientHello).
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `out` NULL or writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_client_hello_get0_ciphers(s: *mut SSL, out: *mut *const c_uchar) -> usize
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { of(s) }) else { return 0 };
        let Some((p, n)) = with_hello(x, |h, _| (h.cipher_suites.as_ptr(), h.cipher_suites.len())) else { return 0 };
        // SAFETY: as above.
        unsafe { put(out, p) };
        n
    }
}

ffi_export! {
    /// The compression methods in `*out` and their count (0 without a ClientHello).
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `out` NULL or writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_client_hello_get0_compression_methods(s: *mut SSL, out: *mut *const c_uchar) -> usize
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { of(s) }) else { return 0 };
        let Some((p, n)) = with_hello(x, |h, _| (h.compression_methods.as_ptr(), h.compression_methods.len())) else { return 0 };
        // SAFETY: as above.
        unsafe { put(out, p) };
        n
    }
}

ffi_export! {
    /// The types of the extensions received, in received order, in a new array (`*out`,
    /// `OPENSSL_free`d by the caller; NULL with none) and their count: 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `out` and `outlen` NULL or writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_client_hello_get1_extensions_present(s: *mut SSL, out: *mut *mut c_int, outlen: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { of(s) }) else { return 0 };
        if out.is_null() || outlen.is_null() {
            return 0;
        }
        let Some(types) = with_hello(x, |_, e| e.iter().map(|(t, _)| c_int::from(*t)).collect::<Vec<_>>()) else {
            return 0;
        };
        if types.is_empty() {
            // SAFETY: the caller's slots.
            unsafe { out.write(ptr::null_mut()) };
            // SAFETY: as above.
            unsafe { outlen.write(0) };
            return 1;
        }
        let Some(size) = types.len().checked_mul(core::mem::size_of::<c_int>()) else { return 0 };
        let a: *mut c_int = mem::alloc(size).cast();
        if a.is_null() {
            return 0;
        }
        for (i, t) in types.iter().enumerate() {
            // SAFETY: element `i` of the `types.len()` allocated.
            let slot = unsafe { a.add(i) };
            // SAFETY: as above.
            unsafe { slot.write(*t) };
        }
        // SAFETY: the caller's slots.
        unsafe { out.write(a) };
        // SAFETY: as above.
        unsafe { outlen.write(types.len()) };
        1
    }
}

ffi_export! {
    /// The extensions' types in received order into `exts` (room for `*num_exts`), or only
    /// their count when `exts` is NULL: 1, or 0 (too little room).
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `exts` NULL or room for `*num_exts`; `num_exts` NULL or
    /// writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_client_hello_get_extension_order(s: *mut SSL, exts: *mut u16, num_exts: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { of(s) }) else { return 0 };
        if num_exts.is_null() {
            return 0;
        }
        let Some(types) = with_hello(x, |_, e| e.iter().map(|(t, _)| *t).collect::<Vec<_>>()) else {
            return 0;
        };
        if types.is_empty() || exts.is_null() {
            // SAFETY: the caller's slot.
            unsafe { num_exts.write(types.len()) };
            return 1;
        }
        // SAFETY: as above.
        if unsafe { num_exts.read() } < types.len() {
            return 0;
        }
        for (i, t) in types.iter().enumerate() {
            // SAFETY: element `i` of the caller's room for at least `types.len()`.
            let slot = unsafe { exts.add(i) };
            // SAFETY: as above.
            unsafe { slot.write(*t) };
        }
        // SAFETY: the caller's slot.
        unsafe { num_exts.write(types.len()) };
        1
    }
}

ffi_export! {
    /// The body of the received extension `type_` in `*out` and `*outlen`: 1, or 0 (none).
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `out` and `outlen` NULL or writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_client_hello_get0_ext(s: *mut SSL, type_: c_uint, out: *mut *const c_uchar, outlen: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { of(s) }) else { return 0 };
        let found = with_hello(x, |_, e| {
            e.iter().find(|(t, _)| c_uint::from(*t) == type_).map(|(_, b)| (b.as_ptr(), b.len()))
        });
        let Some(Some((p, n))) = found else { return 0 };
        // SAFETY: the caller's slot.
        unsafe { put(out, p) };
        if !outlen.is_null() {
            // SAFETY: as above.
            unsafe { outlen.write(n) };
        }
        1
    }
}
