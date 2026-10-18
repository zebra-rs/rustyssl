//! The PSK callbacks, answering the core's requests: TLS 1.3's session callbacks
//! (`SSL_CTX_set_psk_use_session_callback`, `_find_session_callback`) and the TLS 1.2-style
//! key callbacks (`SSL_CTX_set_psk_client_callback`, `_server_callback`), which TLS 1.3 also
//! uses when no session callback gives a session.

use core::ffi::{c_char, c_uchar, c_uint};
use core::ptr;
use std::ffi::{CStr, CString};

use rustyssl_abi::{
    EVP_MD, PSK_MAX_IDENTITY_LEN, PSK_MAX_PSK_LEN, SSL, SSL_AD_INTERNAL_ERROR, SSL_R_BAD_EXTENSION,
    SSL_SESSION,
};
use rustyssl_crypto::bn::Zeroizing;
use rustyssl_tls::conn::{Answer, ExternalPsk};
use rustyssl_tls::crypto::HashAlg;

use super::conn::Ssl;
use super::session;
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free};

/// A callback's failure: the core's alert and reason for it.
fn failed() -> Answer {
    Answer::Fail {
        alert: u8::try_from(SSL_AD_INTERNAL_ERROR).ok(),
        reason: SSL_R_BAD_EXTENSION,
    }
}

/// The core's view of the callback's session (whose reference it takes), with `identity` as
/// its ticket; `None` for NULL.
///
/// # Safety
/// `sess` is NULL or a session the caller holds a reference to.
unsafe fn take(
    sess: *mut SSL_SESSION,
    identity: Option<Vec<u8>>,
) -> Option<rustyssl_tls::conn::Session> {
    // SAFETY: the caller's guarantee.
    let core = unsafe { session::with(sess, None, |d| Some(super::sess_cache::to_core(d))) };
    // SAFETY: the callback's reference, or NULL.
    unsafe { session::free(sess) };
    core.map(|mut c| {
        if let Some(id) = identity {
            c.ticket = Some(id);
        }
        c
    })
}

/// `Request::PskSession`: a client's session to offer (`psk_use_session_cb`, given the
/// handshake digest after a HelloRetryRequest), or the session for a server's identity
/// (`psk_find_session_cb`).
///
/// # Safety
/// `s` is the live connection behind `x`; no lock is held.
pub(crate) unsafe fn session(s: *mut SSL, x: &Ssl, identity: &[u8], md: Option<HashAlg>) -> Answer {
    let (server, use_cb, find_cb, ctx) = {
        let st = x.state();
        (
            st.server,
            st.psk_use_session_cb,
            st.psk_find_session_cb,
            st.ctx,
        )
    };
    let mut sess: *mut SSL_SESSION = ptr::null_mut();
    if server {
        let Some(cb) = find_cb else {
            return Answer::Continue;
        };
        // SAFETY: the application's callback with its connection, the identity's octets, and
        // our slot for its session; no lock is held.
        if unsafe { cb(s, identity.as_ptr(), identity.len(), &raw mut sess) } == 0 {
            return failed();
        }
        // SAFETY: the callback's session, or NULL.
        return Answer::Session(unsafe { take(sess, None) });
    }
    let Some(cb) = use_cb else {
        return Answer::Continue;
    };
    // `ssl_handshake_md`: fetched in the context's library context.
    // SAFETY: the connection's context, which it keeps alive.
    let (libctx, propq) = unsafe { super::ctx::ctx(ctx.cast_const()) }
        .map_or((ptr::null_mut(), ptr::null()), |c| {
            (c.libctx, c.propq_ptr())
        });
    let evp: *mut EVP_MD = match md {
        // SAFETY: the library context (or NULL), a NUL-terminated name, the properties.
        Some(h) => unsafe {
            EVP_MD_fetch(libctx, super::tls_provider::hash_name(h).as_ptr(), propq)
        },
        None => ptr::null_mut(),
    };
    let mut id: *const c_uchar = ptr::null();
    let mut idlen = 0usize;
    // SAFETY: the application's callback with its connection, the digest (or NULL), and our
    // slots for the identity and session; no lock is held.
    let ok = unsafe { cb(s, evp, &raw mut id, &raw mut idlen, &raw mut sess) } != 0;
    // SAFETY: fetched above, or NULL.
    unsafe { EVP_MD_free(evp) };
    if !ok {
        // SAFETY: the callback's session, or NULL.
        unsafe { session::free(sess) };
        return failed();
    }
    let identity = if id.is_null() || idlen == 0 {
        Vec::new()
    } else {
        // SAFETY: the callback's identity, `idlen` octets.
        unsafe { core::slice::from_raw_parts(id, idlen) }.to_vec()
    };
    // SAFETY: the callback's session, or NULL.
    Answer::Session(unsafe { take(sess, Some(identity)) })
}

/// The key a PSK callback wrote: its first `n` octets, or (when it claims more than the buffer)
/// a key of the claimed length capped one past the limit, which the core refuses as OpenSSL
/// does.
fn key_of(buf: &[u8], n: c_uint) -> Vec<u8> {
    let n = usize::try_from(n).unwrap_or(usize::MAX);
    match buf.get(..n) {
        Some(k) => k.to_vec(),
        None => {
            let mut k = buf.to_vec();
            k.resize(buf.len().saturating_add(1), 0);
            k
        }
    }
}

/// `Request::Psk`: the TLS 1.2-style callbacks. A client's (`psk_client_callback`, given the
/// server's hint or NULL) gives an identity and a key; a server's (`psk_server_callback`) the
/// key for the client's identity. An empty key is none.
///
/// # Safety
/// `s` is the live connection behind `x`; no lock is held.
pub(crate) unsafe fn key(s: *mut SSL, x: &Ssl, hint_or_identity: &[u8]) -> Answer {
    let (server, client_cb, server_cb) = {
        let st = x.state();
        (st.server, st.psk_client_callback, st.psk_server_callback)
    };
    let max_psk = usize::try_from(PSK_MAX_PSK_LEN).unwrap_or(512);
    let mut psk = Zeroizing::new(vec![0u8; max_psk]);
    let Ok(psk_len) = c_uint::try_from(psk.len()) else {
        return Answer::Psk(None);
    };
    // As `PACKET_strndup`: up to the first NUL.
    let text = hint_or_identity
        .split(|&b| b == 0)
        .next()
        .unwrap_or_default();
    let Ok(text) = CString::new(text) else {
        return Answer::Psk(None);
    };
    if server {
        let Some(cb) = server_cb else {
            return Answer::Psk(None);
        };
        // SAFETY: the application's callback with its connection, the NUL-terminated
        // identity, and our buffer of `psk_len` octets; no lock is held.
        let n = unsafe { cb(s, text.as_ptr(), psk.as_mut_ptr(), psk_len) };
        return Answer::Psk(Some(ExternalPsk {
            identity: hint_or_identity.to_vec(),
            key: key_of(&psk, n),
            cipher_id: 0,
        }));
    }
    let Some(cb) = client_cb else {
        return Answer::Psk(None);
    };
    let max_id = usize::try_from(PSK_MAX_IDENTITY_LEN).unwrap_or(128);
    let mut identity = vec![0u8; max_id.saturating_add(1)];
    let Ok(id_len) = c_uint::try_from(max_id) else {
        return Answer::Psk(None);
    };
    // A hint that is absent or empty is NULL.
    let hint: *const c_char = if hint_or_identity.is_empty() {
        ptr::null()
    } else {
        text.as_ptr()
    };
    // SAFETY: the application's callback with its connection, the hint (or NULL), our
    // identity buffer (one octet more than it may use, so it stays terminated), and our key
    // buffer; no lock is held.
    let n = unsafe {
        cb(
            s,
            hint,
            identity.as_mut_ptr().cast(),
            id_len,
            psk.as_mut_ptr(),
            psk_len,
        )
    };
    let id = CStr::from_bytes_until_nul(&identity)
        .map_or_else(|_| Vec::new(), |c| c.to_bytes().to_vec());
    Answer::Psk(Some(ExternalPsk {
        identity: id,
        key: key_of(&psk, n),
        cipher_id: 0,
    }))
}

/// Whether the connection has a PSK callback of the TLS 1.2 kind, and of the TLS 1.3 session
/// kind, for its role.
pub(crate) fn flags(st: &super::conn::SslState) -> (bool, bool) {
    if st.server {
        (
            st.psk_server_callback.is_some(),
            st.psk_find_session_cb.is_some(),
        )
    } else {
        (
            st.psk_client_callback.is_some(),
            st.psk_use_session_cb.is_some(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_of_caps_an_overlong_claim() {
        assert_eq!(key_of(&[1, 2, 3], 2), vec![1, 2]);
        assert_eq!(key_of(&[1, 2, 3], 9).len(), 4);
        assert!(key_of(&[1, 2, 3], 0).is_empty());
    }

    #[test]
    fn a_failure_is_bad_extension() {
        assert_eq!(
            failed(),
            Answer::Fail {
                alert: u8::try_from(SSL_AD_INTERNAL_ERROR).ok(),
                reason: SSL_R_BAD_EXTENSION
            }
        );
    }
}
