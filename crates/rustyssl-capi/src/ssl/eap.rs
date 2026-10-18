//! The EAP-FAST hooks (RFC 4851): `SSL_set_session_ticket_ext` (the client's session_ticket
//! extension contents, a PAC-Opaque), `SSL_set_session_ticket_ext_cb` (the extension seen by
//! the application), and `SSL_set_session_secret_cb` (the master secret to resume with).

use core::ffi::{c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_SSL, ERR_R_INTERNAL_ERROR, SSL, SSL_AD_INTERNAL_ERROR, SSL_CIPHER,
    tls_session_secret_cb_fn, tls_session_ticket_ext_cb_fn,
};
use rustyssl_tls::conn::Answer;

use super::conn::{Ssl, ssl};
use crate::ffi::ffi_export;
use crate::stack::{OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_push};

/// `sizeof(s->session->master_key)` (`TLS13_MAX_RESUMPTION_PSK_LENGTH`, `ssl_local.h`): the
/// room the session secret callback gets.
const MASTER_KEY_ROOM: usize = 512;

/// A connection's EAP-FAST settings.
#[derive(Debug)]
pub(crate) struct Eap {
    /// The session_ticket extension's contents (`Some(None)`: set with no data).
    pub(crate) ticket_ext: Option<Option<Vec<u8>>>,
    pub(crate) ticket_ext_cb: tls_session_ticket_ext_cb_fn,
    pub(crate) ticket_ext_arg: *mut c_void,
    pub(crate) secret_cb: tls_session_secret_cb_fn,
    pub(crate) secret_arg: *mut c_void,
}

impl Default for Eap {
    fn default() -> Self {
        Self {
            ticket_ext: None,
            ticket_ext_cb: None,
            ticket_ext_arg: ptr::null_mut(),
            secret_cb: None,
            secret_arg: ptr::null_mut(),
        }
    }
}

ffi_export! {
    /// Sets the client's session_ticket extension contents (NULL: send none): 1.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `ext_data` NULL or `ext_len` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_session_ticket_ext(s: *mut SSL, ext_data: *mut c_void, ext_len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let data = if ext_data.is_null() {
            None
        } else {
            let Ok(len) = usize::try_from(ext_len) else { return 0 };
            // SAFETY: the caller's `ext_len` octets.
            Some(unsafe { core::slice::from_raw_parts(ext_data.cast::<u8>(), len) }.to_vec())
        };
        x.state().eap.ticket_ext = Some(data);
        1
    }
}

ffi_export! {
    /// Sets the callback that sees the peer's session_ticket extension: 1.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_session_ticket_ext_cb(s: *mut SSL, cb: tls_session_ticket_ext_cb_fn, arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let mut st = x.state();
        st.eap.ticket_ext_cb = cb;
        st.eap.ticket_ext_arg = arg;
        1
    }
}

ffi_export! {
    /// Sets the callback giving the master secret to resume with (EAP-FAST): 1.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_session_secret_cb(s: *mut SSL, cb: tls_session_secret_cb_fn, arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let mut st = x.state();
        st.eap.secret_cb = cb;
        st.eap.secret_arg = arg;
        1
    }
}

/// The session_ticket extension for the application's callback: whether it accepts it.
///
/// # Safety
/// `s` is the live connection behind `x`; no lock is held.
pub(crate) unsafe fn ticket_ext(s: *mut SSL, x: &Ssl, data: &[u8]) -> Answer {
    let (cb, arg) = {
        let st = x.state();
        (st.eap.ticket_ext_cb, st.eap.ticket_ext_arg)
    };
    let (Some(cb), Ok(len)) = (cb, c_int::try_from(data.len())) else {
        return Answer::Allowed(false);
    };
    // SAFETY: the application's callback with its connection and the extension's octets.
    Answer::Allowed(unsafe { cb(s, data.as_ptr(), len, arg) } != 0)
}

/// The session secret callback: the master secret it writes and its preferred suite, given
/// (on a server) the client's suites.
///
/// # Safety
/// `s` is the live connection behind `x`; no lock is held.
pub(crate) unsafe fn secret(s: *mut SSL, x: &Ssl, peer: Option<&[u32]>) -> Answer {
    let fail = Answer::Fail {
        alert: u8::try_from(SSL_AD_INTERNAL_ERROR).ok(),
        reason: ERR_R_INTERNAL_ERROR,
    };
    let (cb, arg) = {
        let st = x.state();
        (st.eap.secret_cb, st.eap.secret_arg)
    };
    let Some(cb) = cb else {
        return Answer::SessionSecret(None);
    };
    let stack = match peer {
        None => ptr::null_mut(),
        Some(ids) => {
            // SAFETY: no preconditions.
            let sk = unsafe { OPENSSL_sk_new_null() };
            if sk.is_null() {
                return fail;
            }
            for &id in ids {
                let Some(cp) = rustyssl_tls::suites::by_id(id) else {
                    continue;
                };
                let p = super::ciphers::cipher_ptr(cp);
                // SAFETY: our stack; a static suite.
                unsafe { OPENSSL_sk_push(sk, p.cast_mut().cast()) };
            }
            sk
        }
    };
    let mut buf = vec![0u8; MASTER_KEY_ROOM];
    let mut len = c_int::try_from(MASTER_KEY_ROOM).unwrap_or(c_int::MAX);
    let mut pref: *const SSL_CIPHER = ptr::null();
    // SAFETY: the application's callback with its connection, our buffer of `len` octets and
    // slots, and the suites (or NULL); no lock is held.
    let ok = unsafe {
        cb(
            s,
            buf.as_mut_ptr().cast(),
            &raw mut len,
            stack.cast(),
            &raw mut pref,
            arg,
        )
    } != 0;
    // SAFETY: our stack (its suites are static), or NULL.
    unsafe { OPENSSL_sk_free(stack) };
    let Some(n) = usize::try_from(len)
        .ok()
        .filter(|&n| ok && n > 0 && n <= buf.len())
    else {
        return Answer::SessionSecret(None);
    };
    buf.truncate(n);
    let pref = super::ciphers::cipher_of(pref).map(|c| c.id);
    Answer::SessionSecret(Some((buf, pref)))
}
