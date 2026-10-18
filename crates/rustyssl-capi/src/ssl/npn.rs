//! Next Protocol Negotiation: the callbacks the core asks through
//! [`Request::Npn`](rustyssl_tls::conn::Request::Npn) (the client's selection,
//! `tls_parse_stoc_npn`; the server's advertisement, `tls_construct_stoc_next_proto_neg`) and
//! `SSL_get0_next_proto_negotiated`.

use core::ffi::{c_uchar, c_uint};
use core::ptr;

use rustyssl_abi::{ERR_LIB_SSL, SSL, SSL_TLSEXT_ERR_OK};
use rustyssl_tls::conn::Answer;

use super::conn::{Ssl, ssl};
use super::io::config::CtxSnapshot;
use crate::ffi::ffi_export;

/// The client's select callback on the server's `protos`, or the server's advertisement
/// callback, as the connection's role asks.
///
/// # Safety
/// `s` is the live connection behind `x`; no lock is held.
pub(crate) unsafe fn answer(
    s: *mut SSL,
    x: &Ssl,
    snap: Option<&CtxSnapshot>,
    protos: &[u8],
) -> Answer {
    let server = x.state().server;
    let Some(snap) = snap else {
        return Answer::Npn(None);
    };
    if server {
        let Some(cb) = snap.npn_advertised_cb else {
            return Answer::Npn(None);
        };
        let mut out: *const c_uchar = ptr::null();
        let mut len: c_uint = 0;
        // SAFETY: the application's callback; no lock is held.
        let ret = unsafe { cb(s, &raw mut out, &raw mut len, snap.npn_advertised_cb_arg) };
        if ret != SSL_TLSEXT_ERR_OK {
            return Answer::Npn(None);
        }
        let Ok(n) = usize::try_from(len) else {
            return Answer::Npn(None);
        };
        if out.is_null() || n == 0 {
            return Answer::Npn(Some(Vec::new()));
        }
        // SAFETY: the list the callback gave, `len` octets.
        return Answer::Npn(Some(
            unsafe { core::slice::from_raw_parts(out, n) }.to_vec(),
        ));
    }
    let Some(cb) = snap.npn_select_cb else {
        return Answer::Npn(None);
    };
    let Ok(inlen) = c_uint::try_from(protos.len()) else {
        return Answer::Npn(None);
    };
    let mut out: *mut c_uchar = ptr::null_mut();
    let mut outlen: c_uchar = 0;
    // SAFETY: the application's callback with the server's list; no lock is held.
    let ret = unsafe {
        cb(
            s,
            &raw mut out,
            &raw mut outlen,
            protos.as_ptr(),
            inlen,
            snap.npn_select_cb_arg,
        )
    };
    if ret != SSL_TLSEXT_ERR_OK || outlen == 0 || out.is_null() {
        return Answer::Npn(None);
    }
    // SAFETY: the protocol the callback chose, `outlen` octets.
    Answer::Npn(Some(
        unsafe { core::slice::from_raw_parts(out, usize::from(outlen)) }.to_vec(),
    ))
}

ffi_export! {
    /// The protocol NPN negotiated (`get0`), or NULL and 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `data` and `len` are valid for writes.
    pub unsafe extern "C" fn rustyssl_private_SSL_get0_next_proto_negotiated(s: *const SSL, data: *mut *const c_uchar, len: *mut c_uint)
    where failure = (), library = ERR_LIB_SSL
    {
        // The core's copy stays put until the next handshake changes it.
        // SAFETY: the caller's guarantee.
        let (p, n) = unsafe { ssl(s) }
            .and_then(|x| {
                let st = x.state();
                let npn = st.drv.tls.as_ref()?.negotiated().npn.as_ref()?;
                Some((npn.as_ptr(), c_uint::try_from(npn.len()).ok()?))
            })
            .unwrap_or((ptr::null(), 0));
        if !data.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { data.write(p) };
        }
        if !len.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { len.write(n) };
        }
    }
}
