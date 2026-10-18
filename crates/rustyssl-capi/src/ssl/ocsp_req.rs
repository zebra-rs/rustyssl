//! The OCSP status request's responder IDs and extensions (`SSL_set_tlsext_status_ids`,
//! `_exts`): encoded for a client's ClientHello, decoded for a server's status callback.

use core::ffi::{c_long, c_void};
use core::ptr;

use super::conn::SslState;
use crate::ocsp::asn::{OCSP_RESPID_free, d2i_OCSP_RESPID, i2d_OCSP_RESPID};
use crate::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value,
};
use crate::x509::ext::{X509_EXTENSION_free, d2i_X509_EXTENSIONS, i2d_X509_EXTENSIONS};

/// `OCSP_RESPID_free` for `OPENSSL_sk_pop_free`.
unsafe extern "C" fn respid_free(p: *mut c_void) {
    // SAFETY: an element of a responder ID stack.
    unsafe { OCSP_RESPID_free(p.cast()) };
}

/// `X509_EXTENSION_free` for `OPENSSL_sk_pop_free`.
pub(crate) unsafe extern "C" fn extension_free(p: *mut c_void) {
    // SAFETY: an element of an extension stack.
    unsafe { X509_EXTENSION_free(p.cast()) };
}

/// Frees the connection's responder IDs and extensions (`SSL_free`, or a new ClientHello's).
///
/// # Safety
/// `st.ocsp_ids` and `st.ocsp_exts` are NULL or stacks the connection owns.
pub(crate) unsafe fn free(st: &mut SslState) {
    // SAFETY: the caller's guarantee.
    unsafe { OPENSSL_sk_pop_free(st.ocsp_ids.cast(), Some(respid_free)) };
    // SAFETY: as above.
    unsafe { OPENSSL_sk_pop_free(st.ocsp_exts.cast(), Some(extension_free)) };
    st.ocsp_ids = ptr::null_mut();
    st.ocsp_exts = ptr::null_mut();
}

/// The DER of each responder ID in the connection's stack, and of its extensions (empty if
/// none), for a client's status request.
///
/// # Safety
/// As for [`free`].
pub(crate) unsafe fn encode(st: &SslState) -> (Vec<Vec<u8>>, Vec<u8>) {
    let mut ids = Vec::new();
    // SAFETY: NULL or the connection's stack (-1 for NULL).
    let n = unsafe { OPENSSL_sk_num(st.ocsp_ids.cast()) };
    for i in 0..n {
        // SAFETY: an index in range.
        let id = unsafe { OPENSSL_sk_value(st.ocsp_ids.cast(), i) };
        let mut p: *mut u8 = ptr::null_mut();
        // SAFETY: a live responder ID; a slot for the encoding.
        let len = unsafe { i2d_OCSP_RESPID(id.cast(), &raw mut p) };
        if let Ok(len) = usize::try_from(len)
            && !p.is_null()
        {
            // SAFETY: the `len` octets i2d wrote.
            ids.push(unsafe { core::slice::from_raw_parts(p, len) }.to_vec());
        }
        // SAFETY: the encoding, ours, or NULL.
        unsafe { crate::mem::release(p.cast()) };
    }
    let mut exts = Vec::new();
    if !st.ocsp_exts.is_null() {
        let mut p: *mut u8 = ptr::null_mut();
        // SAFETY: the connection's extensions; a slot for the encoding.
        let len = unsafe { i2d_X509_EXTENSIONS(st.ocsp_exts.cast(), &raw mut p) };
        if let Ok(len) = usize::try_from(len)
            && !p.is_null()
        {
            // SAFETY: as above.
            exts = unsafe { core::slice::from_raw_parts(p, len) }.to_vec();
        }
        // SAFETY: as above.
        unsafe { crate::mem::release(p.cast()) };
    }
    (ids, exts)
}

/// Replaces the connection's responder IDs and extensions with what a client sent (the core
/// checked that each decodes), for `SSL_get_tlsext_status_ids` and `_exts` in the server's
/// status callback.
///
/// # Safety
/// As for [`free`].
pub(crate) unsafe fn install(st: &mut SslState, ids: &[Vec<u8>], exts: &[u8]) {
    // SAFETY: the caller's guarantee.
    unsafe { free(st) };
    // SAFETY: no preconditions.
    let sk = unsafe { OPENSSL_sk_new_null() };
    if !sk.is_null() {
        for der in ids {
            let Ok(len) = c_long::try_from(der.len()) else {
                continue;
            };
            let mut p = der.as_ptr();
            // SAFETY: the ID's octets.
            let id = unsafe { d2i_OCSP_RESPID(ptr::null_mut(), &raw mut p, len) };
            // SAFETY: our stack, which takes the ID.
            if !id.is_null() && unsafe { OPENSSL_sk_push(sk, id.cast()) } == 0 {
                // SAFETY: not taken.
                unsafe { OCSP_RESPID_free(id) };
            }
        }
    }
    st.ocsp_ids = sk.cast();
    if let Ok(len) = c_long::try_from(exts.len())
        && len > 0
    {
        let mut p = exts.as_ptr();
        // SAFETY: the extensions' octets.
        st.ocsp_exts = unsafe { d2i_X509_EXTENSIONS(ptr::null_mut(), &raw mut p, len) }.cast();
    }
}
