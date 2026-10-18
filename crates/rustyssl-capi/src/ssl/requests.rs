//! What an application asks of an established connection (`ssl_lib.c`): key updates,
//! renegotiation, post-handshake authentication, and exported keying material. The core makes
//! the checks; the request is carried out by the next `SSL_do_handshake`, `SSL_read`, or
//! `SSL_write`, as in OpenSSL.

use core::ffi::{c_char, c_int, c_uchar};
use core::ptr;

use rustyssl_abi::{ERR_LIB_SSL, SSL, SSL_KEY_UPDATE_NONE, SSL_R_BAD_WRITE_RETRY, SSL_R_WRONG_SSL_VERSION};
use rustyssl_tls::error::Error as TlsError;

use super::conn::{Ssl, ssl};
use crate::err;
use crate::ffi::ffi_export;

/// Raises a core refusal (nothing for OpenSSL's silent failures, reason 0).
fn raise(e: &TlsError, function: &str) {
    if e.reason != 0 {
        err::raise(ERR_LIB_SSL, e.reason, function);
    }
}

/// `ssl3_renegotiate_check`: starts a renegotiation `SSL_renegotiate` asked for, when no I/O is
/// pending and (unless `initok`) no handshake is under way. Called on entry to
/// `SSL_do_handshake`, `SSL_read`, and `SSL_write`.
pub(crate) fn renegotiate_check(x: &Ssl, initok: bool) {
    let mut st = x.state();
    let pending = !st.drv.out.is_empty() || st.drv.wpend.is_some();
    let started = st
        .drv
        .tls
        .as_mut()
        .is_some_and(|c| c.renegotiate_check(initok, pending || c.pending_app() > 0));
    if started {
        st.in_init = true;
        st.num_renegotiations = st.num_renegotiations.saturating_add(1);
        st.total_renegotiations = st.total_renegotiations.saturating_add(1);
    }
}

ffi_export! {
    /// Asks for a TLS 1.3 KeyUpdate (`SSL_KEY_UPDATE_NOT_REQUESTED` or
    /// `SSL_KEY_UPDATE_REQUESTED`), sent by the next handshake or write: 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_key_update(s: *mut SSL, updatetype: c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        const F: &str = "SSL_key_update";
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let mut st = x.state();
        let pending = st.drv.wpend.is_some();
        let r = match st.drv.tls.as_mut() {
            None => Err(TlsError::quiet(SSL_R_WRONG_SSL_VERSION)),
            Some(c) => {
                if c.is_tls13() && pending {
                    // Checked after the version, type, and handshake (as OpenSSL orders them).
                    match c.request_key_update(updatetype) {
                        Ok(()) => Err(TlsError::quiet(SSL_R_BAD_WRITE_RETRY)),
                        Err(e) => Err(e),
                    }
                } else {
                    c.request_key_update(updatetype)
                }
            }
        };
        match r {
            Ok(()) => {
                st.in_init = true;
                1
            }
            Err(e) => {
                drop(st);
                raise(&e, F);
                0
            }
        }
    }
}

ffi_export! {
    /// The KeyUpdate waiting to be sent (`SSL_KEY_UPDATE_NONE` without one).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_key_update_type(s: *const SSL) -> c_int
    where failure = SSL_KEY_UPDATE_NONE, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return SSL_KEY_UPDATE_NONE };
        x.state().drv.tls.as_ref().map_or(SSL_KEY_UPDATE_NONE, |c| c.key_update_type())
    }
}

/// `SSL_renegotiate` and `SSL_renegotiate_abbreviated`.
///
/// # Safety
/// `s` is NULL or a live connection.
unsafe fn renegotiate(s: *mut SSL, new_session: bool, function: &str) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(x) = (unsafe { ssl(s) }) else { return 0 };
    let mut st = x.state();
    let options = st.options;
    let r = match st.drv.tls.as_mut() {
        Some(c) => c.request_renegotiate(new_session),
        // Before any handshake: only the option can refuse (OpenSSL's flag waits for one).
        None if options & rustyssl_abi::SSL_OP_NO_RENEGOTIATION != 0 => {
            Err(TlsError::quiet(rustyssl_abi::SSL_R_NO_RENEGOTIATION))
        }
        None => Ok(()),
    };
    drop(st);
    match r {
        Ok(()) => 1,
        Err(e) => {
            raise(&e, function);
            0
        }
    }
}

ffi_export! {
    /// Asks for a renegotiation with a new session (before TLS 1.3): 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_renegotiate(s: *mut SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { renegotiate(s, true, "SSL_renegotiate") }
    }
}

ffi_export! {
    /// Asks for a renegotiation resuming the session: 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_renegotiate_abbreviated(s: *mut SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { renegotiate(s, false, "SSL_renegotiate_abbreviated") }
    }
}

ffi_export! {
    /// Whether a renegotiation was asked for and hasn't finished.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_renegotiate_pending(s: *const SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        c_int::from(x.state().drv.tls.as_ref().is_some_and(|c| c.renegotiate_pending()))
    }
}

ffi_export! {
    /// Asks a TLS 1.3 client for its certificate after the handshake: 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_verify_client_post_handshake(s: *mut SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        const F: &str = "SSL_verify_client_post_handshake";
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let mut st = x.state();
        let r = match st.drv.tls.as_mut() {
            Some(c) => c.request_post_handshake_auth(),
            None => Err(TlsError::quiet(SSL_R_WRONG_SSL_VERSION)),
        };
        match r {
            Ok(()) => {
                st.in_init = true;
                1
            }
            Err(e) => {
                drop(st);
                if e.library_reason {
                    err::raise(ERR_LIB_SSL, e.reason, F);
                } else {
                    raise(&e, F);
                }
                0
            }
        }
    }
}

/// The slice behind a pointer and length, empty for a NULL pointer.
///
/// # Safety
/// `p` is NULL or points to `n` readable octets.
unsafe fn octets<'a>(p: *const c_uchar, n: usize) -> &'a [u8] {
    if p.is_null() || n == 0 {
        return &[];
    }
    // SAFETY: the caller's guarantee.
    unsafe { core::slice::from_raw_parts(p, n) }
}

/// Copies `v` into the caller's `out` (`olen` octets).
///
/// # Safety
/// `out` has room for `olen` octets.
unsafe fn put(out: *mut c_uchar, olen: usize, v: &[u8]) -> bool {
    if out.is_null() || v.len() != olen {
        return false;
    }
    // SAFETY: the caller's room; our octets.
    unsafe { ptr::copy_nonoverlapping(v.as_ptr(), out, olen) };
    true
}

ffi_export! {
    /// Keying material for `label` and (if `use_context`) `context` (RFC 5705, RFC 8446): 1, 0
    /// on failure, -1 without a session.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `out` has room for `olen` octets; `label` has `llen`
    /// octets; `context` NULL or `contextlen` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_export_keying_material(s: *mut SSL, out: *mut c_uchar, olen: usize, label: *const c_char, llen: usize, context: *const c_uchar, contextlen: usize, use_context: c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        const F: &str = "SSL_export_keying_material";
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return -1 };
        // SAFETY: the caller's label.
        let label = unsafe { octets(label.cast(), llen) };
        // SAFETY: the caller's context.
        let ctx = unsafe { octets(context, contextlen) };
        let st = x.state();
        let prov = st.drv.provider.clone();
        let (Some(c), Some(p)) = (st.drv.tls.as_ref(), prov) else {
            return -1;
        };
        if c.negotiated().version < 0x0301 {
            return -1;
        }
        let r = c.export_keying_material(&*p, label, (use_context != 0).then_some(ctx), olen);
        drop(st);
        match r {
            // SAFETY: the caller's room.
            Ok(v) => c_int::from(unsafe { put(out, olen, &v) }),
            Err(e) => {
                if e.library_reason {
                    err::raise(ERR_LIB_SSL, e.reason, F);
                } else {
                    raise(&e, F);
                }
                0
            }
        }
    }
}

ffi_export! {
    /// TLS 1.3's early keying material for `label` and `context`: 1, or 0.
    ///
    /// # Safety
    /// As for `SSL_export_keying_material`.
    pub unsafe extern "C" fn rustyssl_private_SSL_export_keying_material_early(s: *mut SSL, out: *mut c_uchar, olen: usize, label: *const c_char, llen: usize, context: *const c_uchar, contextlen: usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        const F: &str = "SSL_export_keying_material_early";
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        // SAFETY: the caller's label.
        let label = unsafe { octets(label.cast(), llen) };
        // SAFETY: the caller's context.
        let ctx = unsafe { octets(context, contextlen) };
        let st = x.state();
        let prov = st.drv.provider.clone();
        let (Some(c), Some(p)) = (st.drv.tls.as_ref(), prov) else {
            return 0;
        };
        if !c.is_tls13() {
            return 0;
        }
        let r = c.export_keying_material_early(&*p, label, ctx, olen);
        drop(st);
        match r {
            // SAFETY: the caller's room.
            Ok(v) => c_int::from(unsafe { put(out, olen, &v) }),
            Err(e) => {
                raise(&e, F);
                0
            }
        }
    }
}
