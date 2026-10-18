//! The core's requests (ADR 0002), each answered by calling the application's callback with
//! no lock held: verification (`ssl_verify_cert_chain`), the servername, ALPN, client hello,
//! certificate, and client certificate callbacks, the record padding and early data
//! callbacks, and OCSP status.
//!
//! A callback that asks to suspend sets the connection's `rwstate` (`SSL_X509_LOOKUP`,
//! `SSL_CLIENT_HELLO_CB`, `SSL_RETRY_VERIFY`) and the request stays pending: the caller returns
//! -1, `SSL_get_error` reports the matching `WANT_*`, and the next call asks again.

use core::ffi::{c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_SSL, ERR_R_INTERNAL_ERROR, ERR_R_X509_LIB, EVP_PKEY, SSL, SSL_AD_INTERNAL_ERROR,
    SSL_AD_NO_APPLICATION_PROTOCOL, SSL_AD_UNRECOGNIZED_NAME, SSL_CLIENT_HELLO_CB,
    SSL_CLIENT_HELLO_RETRY, SSL_CLIENT_HELLO_SUCCESS, SSL_R_CALLBACK_FAILED, SSL_R_CERT_CB_ERROR,
    SSL_R_NO_APPLICATION_PROTOCOL, SSL_RETRY_VERIFY, SSL_TLSEXT_ERR_ALERT_FATAL, SSL_TLSEXT_ERR_OK,
    SSL_VERIFY_NONE, SSL_X509_LOOKUP, X509, stack_st_X509,
};
use rustyssl_tls::conn::{Answer, Request};

use super::super::conn::Ssl;
use super::config::{self, CtxSnapshot};
use super::x509_free;
use crate::err;
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value};
use crate::x509::cert::X509_free;

/// An alert's `c_int` constant as its octet.
fn alert(v: c_int) -> Option<u8> {
    u8::try_from(v).ok()
}

/// Answers `req`, or `None` when the callback asked to suspend (with `rwstate` set) or the
/// request can't be answered (with an ERR entry).
///
/// # Safety
/// `x` is a live connection.
pub(crate) unsafe fn handle(
    s: *mut SSL,
    x: &Ssl,
    snap: Option<&CtxSnapshot>,
    req: Request,
) -> Option<Answer> {
    match req {
        // SAFETY: the caller's guarantee.
        Request::Verify { chain } => unsafe { verify(s, x, snap, &chain) },
        Request::Servername => {
            let (cb, arg) = snap.map_or((None, ptr::null_mut()), |c| {
                (c.servername_cb, c.servername_arg)
            });
            let Some(cb) = cb else {
                return Some(Answer::Tlsext {
                    ret: rustyssl_abi::SSL_TLSEXT_ERR_NOACK,
                    alert: SSL_AD_UNRECOGNIZED_NAME,
                });
            };
            // SAFETY: the servername callback's real type, as SSL_CTX_callback_ctrl stored it.
            let cb: unsafe extern "C" fn(*mut SSL, *mut c_int, *mut c_void) -> c_int =
                unsafe { core::mem::transmute(cb) };
            let mut al = SSL_AD_UNRECOGNIZED_NAME;
            // SAFETY: the application's callback; no lock is held.
            let ret = unsafe { cb(s, &raw mut al, arg) };
            // SAFETY: as above.
            unsafe { refresh_certs(x, snap) };
            Some(Answer::Tlsext { ret, alert: al })
        }
        Request::AlpnSelect { protos } => {
            let (cb, arg) = snap.map_or((None, ptr::null_mut()), |c| {
                (c.alpn_select_cb, c.alpn_select_cb_arg)
            });
            let Some(cb) = cb else {
                return Some(Answer::Alpn(None));
            };
            let Ok(inlen) = u32::try_from(protos.len()) else {
                return Some(Answer::Alpn(None));
            };
            let mut out: *const c_uchar = ptr::null();
            let mut outlen: c_uchar = 0;
            // SAFETY: the application's callback with the client's list; no lock is held.
            let ret = unsafe {
                cb(
                    s,
                    &raw mut out,
                    &raw mut outlen,
                    protos.as_ptr(),
                    inlen,
                    arg,
                )
            };
            if ret == SSL_TLSEXT_ERR_OK && !out.is_null() {
                // SAFETY: the protocol the callback chose, `outlen` octets.
                let p = unsafe { core::slice::from_raw_parts(out, usize::from(outlen)) }.to_vec();
                return Some(Answer::Alpn(Some(p)));
            }
            if ret == SSL_TLSEXT_ERR_ALERT_FATAL {
                return Some(Answer::Fail {
                    alert: alert(SSL_AD_NO_APPLICATION_PROTOCOL),
                    reason: SSL_R_NO_APPLICATION_PROTOCOL,
                });
            }
            Some(Answer::Alpn(None))
        }
        // SAFETY: as above.
        Request::Npn { protos } => Some(unsafe { super::super::npn::answer(s, x, snap, &protos) }),
        Request::ClientHello => {
            let (cb, arg) = snap.map_or((None, ptr::null_mut()), |c| {
                (c.client_hello_cb, c.client_hello_cb_arg)
            });
            let Some(cb) = cb else {
                return Some(Answer::Continue);
            };
            let mut al = SSL_AD_INTERNAL_ERROR;
            // SAFETY: the application's callback; no lock is held.
            let ret = unsafe { cb(s, &raw mut al, arg) };
            // SAFETY: the caller's guarantee.
            unsafe { refresh_certs(x, snap) };
            match ret {
                SSL_CLIENT_HELLO_RETRY => {
                    x.state().rwstate = SSL_CLIENT_HELLO_CB;
                    None
                }
                SSL_CLIENT_HELLO_SUCCESS => Some(Answer::Continue),
                _ => Some(Answer::Fail {
                    alert: alert(al),
                    reason: SSL_R_CALLBACK_FAILED,
                }),
            }
        }
        Request::Cert => {
            let (cb, arg) = {
                let st = x.state();
                (st.cert.cert_cb, st.cert.cert_cb_arg)
            };
            let Some(cb) = cb else {
                return Some(Answer::Continue);
            };
            // SAFETY: the application's callback; no lock is held.
            let rv = unsafe { cb(s, arg) };
            if rv < 0 {
                x.state().rwstate = SSL_X509_LOOKUP;
                return None;
            }
            if rv == 0 {
                return Some(Answer::Fail {
                    alert: alert(SSL_AD_INTERNAL_ERROR),
                    reason: SSL_R_CERT_CB_ERROR,
                });
            }
            // SAFETY: as above.
            unsafe { refresh_certs(x, snap) };
            Some(Answer::Continue)
        }
        Request::ClientCert => {
            let Some(cb) = snap.and_then(|c| c.client_cert_cb) else {
                return Some(Answer::Continue);
            };
            let mut cert: *mut X509 = ptr::null_mut();
            let mut key: *mut EVP_PKEY = ptr::null_mut();
            // SAFETY: the application's callback with the slots; no lock is held.
            let rv = unsafe { cb(s, &raw mut cert, &raw mut key) };
            if rv < 0 {
                x.state().rwstate = SSL_X509_LOOKUP;
                return None;
            }
            if rv == 1 && !cert.is_null() && !key.is_null() {
                // `tls_prepare_client_certificate`: use them if they fit together.
                // SAFETY: the callback's certificate and key, whose references we own.
                let ok = unsafe { super::super::keys::rustyssl_private_SSL_use_certificate(s, cert) } == 1
                    // SAFETY: as above.
                    && unsafe { super::super::keys::rustyssl_private_SSL_use_PrivateKey(s, key) } == 1;
                if !ok {
                    // SAFETY: no preconditions.
                    unsafe { crate::err::ERR_clear_error() };
                }
            }
            // SAFETY: the callback's references (SSL_use_* took their own).
            unsafe { X509_free(cert) };
            // SAFETY: as above.
            unsafe { crate::evp::pkey::EVP_PKEY_free(key) };
            // SAFETY: as above.
            unsafe { refresh_certs(x, snap) };
            Some(Answer::Continue)
        }
        Request::RecordPadding { content_type, len } => {
            let (cb, arg) = {
                let st = x.state();
                (st.record_padding_cb, st.record_padding_arg)
            };
            let Some(cb) = cb else {
                return Some(Answer::Padding(0));
            };
            // SAFETY: the application's callback; no lock is held.
            Some(Answer::Padding(unsafe {
                cb(s, c_int::from(content_type), len, arg)
            }))
        }
        Request::AllowEarlyData => {
            let (cb, arg) = {
                let st = x.state();
                (st.allow_early_data_cb, st.allow_early_data_cb_data)
            };
            let Some(cb) = cb else {
                return Some(Answer::Allowed(true));
            };
            // SAFETY: the application's callback; no lock is held.
            Some(Answer::Allowed(unsafe { cb(s, arg) } != 0))
        }
        Request::Status => {
            let (cb, arg) = snap.map_or((None, ptr::null_mut()), |c| (c.status_cb, c.status_arg));
            let Some(cb) = cb else {
                return Some(Answer::Status {
                    ret: 1,
                    response: None,
                });
            };
            // SAFETY: the status callback's real type, as SSL_CTX_callback_ctrl stored it.
            let cb: unsafe extern "C" fn(*mut SSL, *mut c_void) -> c_int =
                unsafe { core::mem::transmute(cb) };
            // SAFETY: the application's callback; no lock is held.
            let ret = unsafe { cb(s, arg) };
            let response = {
                let st = x.state();
                (!st.ocsp_resp.is_null() && st.ocsp_resp_len > 0).then(|| {
                    // SAFETY: the response the connection owns, `ocsp_resp_len` octets.
                    unsafe { core::slice::from_raw_parts(st.ocsp_resp, st.ocsp_resp_len) }.to_vec()
                })
            };
            Some(Answer::Status { ret, response })
        }
        // The session cache (`sess_cache`).
        Request::GetSession { id } => {
            // SAFETY: the caller's guarantee; no lock is held.
            Some(unsafe { super::super::sess_cache::on_get_session(s, x, &id) })
        }
        Request::RemoveSession { id } => {
            // SAFETY: as above.
            Some(unsafe { super::super::sess_cache::on_remove_request(x, &id) })
        }
        // SAFETY: as above.
        Request::CtValidate => Some(unsafe { super::super::ct::validate(s, x) }),
        Request::SessionTicketExt { data } => {
            // SAFETY: as above.
            Some(unsafe { super::super::eap::ticket_ext(s, x, &data) })
        }
        Request::SessionSecret { peer_ciphers } => {
            // SAFETY: as above.
            Some(unsafe { super::super::eap::secret(s, x, peer_ciphers.as_deref()) })
        }
        // SAFETY: as above.
        Request::TicketGenerate => Some(unsafe { ticket_generate(s, x) }),
        Request::TicketDecrypt {
            keyname,
            status,
            session,
        } => {
            // SAFETY: as above.
            Some(unsafe { ticket_decrypt(s, x, &keyname, status, session.as_deref()) })
        }
        // SAFETY: as above.
        Request::StatelessCookieGen => Some(unsafe { stateless_cookie_gen(s, snap) }),
        Request::StatelessCookieVerify { cookie } => {
            // SAFETY: as above.
            Some(unsafe { stateless_cookie_verify(s, snap, &cookie) })
        }
        Request::CustomExt {
            index,
            typ,
            context,
            body,
            chainidx,
            cert,
        } => {
            // SAFETY: as above.
            Some(unsafe {
                super::super::custom::answer(
                    s,
                    x,
                    index,
                    typ,
                    context,
                    body.as_deref(),
                    chainidx,
                    cert.as_deref(),
                )
            })
        }
        // The configuration never asks for these yet (their callbacks aren't wired): answering
        // wrongly could accept what the application would refuse.
        _ => {
            err::raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR, "ssl_handshake_request");
            None
        }
    }
}

/// The session context's ticket callbacks and their argument.
fn ticket_cbs(
    x: &Ssl,
) -> (
    rustyssl_abi::SSL_CTX_generate_session_ticket_fn,
    rustyssl_abi::SSL_CTX_decrypt_session_ticket_fn,
    *mut c_void,
) {
    let sctx = x.state().session_ctx;
    // SAFETY: the connection's session context, which it keeps alive.
    unsafe { super::super::ctx::ctx(sctx) }.map_or((None, None, ptr::null_mut()), |c| {
        let cs = c.state();
        (
            cs.generate_ticket_cb,
            cs.decrypt_ticket_cb,
            cs.ticket_cb_data,
        )
    })
}

/// `generate_ticket_cb`: the application may set the ticket's application data on the
/// connection's session (`SSL_get_session`), made here from the core's for the call. 0 fails
/// the handshake.
///
/// # Safety
/// `s` is the live connection behind `x`; no lock is held.
unsafe fn ticket_generate(s: *mut SSL, x: &Ssl) -> Answer {
    let fail = Answer::Fail {
        alert: alert(SSL_AD_INTERNAL_ERROR),
        reason: ERR_R_INTERNAL_ERROR,
    };
    let (gen_cb, _, arg) = ticket_cbs(x);
    let Some(cb) = gen_cb else {
        return Answer::TicketAppData(None);
    };
    let Some(core) = x
        .state()
        .drv
        .tls
        .as_ref()
        .map(|c| c.negotiated().session.clone())
    else {
        return fail;
    };
    // The connection's session, or one made from the core's for the call.
    let current = x.state().sess.session;
    let tmp = if current.is_null() {
        // SAFETY: the caller's guarantee.
        let t = unsafe { super::super::sess_cache::session_from_core(x, &core) };
        if t.is_null() {
            return fail;
        }
        x.state().sess.session = t;
        t
    } else {
        ptr::null_mut()
    };
    // SAFETY: the application's callback with its connection and argument; no lock is held.
    let ok = unsafe { cb(s, arg) } != 0;
    let cur = x.state().sess.session;
    // SAFETY: the session the callback saw (or one it set), or NULL.
    let appdata = unsafe {
        super::super::session::with(cur, None, |d| d.ticket_appdata.as_ref().map(|a| a.to_vec()))
    };
    if !tmp.is_null() {
        let t = core::mem::replace(&mut x.state().sess.session, ptr::null_mut());
        // SAFETY: our temporary reference (or what replaced it).
        unsafe { super::super::session::free(t) };
    }
    if !ok {
        return fail;
    }
    Answer::TicketAppData(appdata)
}

/// `decrypt_ticket_cb`: the application's verdict on a ticket (`SSL_TICKET_RETURN_*`), given
/// the decryption's status and the session in it (as an object for the call).
///
/// # Safety
/// `s` is the live connection behind `x`; no lock is held.
unsafe fn ticket_decrypt(
    s: *mut SSL,
    x: &Ssl,
    keyname: &[u8],
    status: c_int,
    session: Option<&rustyssl_tls::conn::Session>,
) -> Answer {
    let (_, dec_cb, arg) = ticket_cbs(x);
    let Some(cb) = dec_cb else {
        return Answer::TicketDecrypt(rustyssl_abi::SSL_TICKET_RETURN_ABORT);
    };
    let sess = match session {
        // SAFETY: the caller's guarantee.
        Some(c) => unsafe { super::super::sess_cache::session_from_core(x, c) },
        None => ptr::null_mut(),
    };
    // SAFETY: the application's callback with its connection, the session (or NULL), and the
    // key name's octets; no lock is held.
    let r = unsafe { cb(s, sess, keyname.as_ptr(), keyname.len(), status, arg) };
    // SAFETY: our reference, or NULL.
    unsafe { super::super::session::free(sess) };
    Answer::TicketDecrypt(r)
}

/// `gen_stateless_cookie_cb`: the application's cookie (at most `SSL_COOKIE_LENGTH` octets), or
/// `None` when it failed.
///
/// # Safety
/// `s` is a live connection; no lock is held.
unsafe fn stateless_cookie_gen(s: *mut SSL, snap: Option<&CtxSnapshot>) -> Answer {
    let Some(cb) = snap.and_then(|c| c.gen_stateless_cookie_cb) else {
        return Answer::Cookie(None);
    };
    let mut buf = vec![0u8; usize::try_from(rustyssl_abi::SSL_COOKIE_LENGTH).unwrap_or(4096)];
    let mut len = 0usize;
    // SAFETY: the application's callback with its connection and a buffer of
    // `SSL_COOKIE_LENGTH` octets.
    if unsafe { cb(s, buf.as_mut_ptr(), &raw mut len) } == 0 {
        return Answer::Cookie(None);
    }
    if len > buf.len() {
        return Answer::Cookie(None);
    }
    buf.truncate(len);
    Answer::Cookie(Some(buf))
}

/// `verify_stateless_cookie_cb`: whether the application's cookie is good.
///
/// # Safety
/// `s` is a live connection; no lock is held.
unsafe fn stateless_cookie_verify(
    s: *mut SSL,
    snap: Option<&CtxSnapshot>,
    cookie: &[u8],
) -> Answer {
    let Some(cb) = snap.and_then(|c| c.verify_stateless_cookie_cb) else {
        return Answer::Allowed(false);
    };
    // SAFETY: the application's callback with its connection and the cookie's octets.
    Answer::Allowed(unsafe { cb(s, cookie.as_ptr(), cookie.len()) } != 0)
}

/// After a callback that may have changed the connection's certificates (or moved it to
/// another context), gives the core the certificates now configured.
///
/// # Safety
/// `x` is a live connection.
unsafe fn refresh_certs(x: &Ssl, snap: Option<&CtxSnapshot>) {
    // The context may have changed (`SSL_set_SSL_CTX` from the servername callback).
    let fresh = config::snapshot(x);
    let Some(snap) = fresh.as_ref().or(snap) else {
        return;
    };
    let Some(prov) = x.state().drv.provider.clone() else {
        return;
    };
    // SAFETY: the connection; the context's snapshot.
    let (certs, current) = unsafe { config::certs(x, snap, &prov) };
    let mut st = x.state();
    let (verify_mode, sid_ctx) = (st.verify_mode, st.sid_ctx.clone());
    if let Some(c) = st.drv.tls.as_mut() {
        let cfg = c.config_mut();
        cfg.certs = certs;
        cfg.current_cert = current;
        cfg.verify_mode = verify_mode;
        cfg.sid_ctx = sid_ctx;
    }
}

/// `ssl_verify_cert_chain` (`ssl_verify_internal`): the peer's chain verified with the
/// connection's verify store (else its context's), its parameters, its callback (or the
/// context's whole-verification callback), and the purpose of the peer's role.
///
/// # Safety
/// `x` is a live connection.
unsafe fn verify(
    s: *mut SSL,
    x: &Ssl,
    snap: Option<&CtxSnapshot>,
    peer: &[Vec<u8>],
) -> Option<Answer> {
    use crate::x509::ctx::{
        X509_STORE_CTX_free, X509_STORE_CTX_get_error, X509_STORE_CTX_get0_param,
        X509_STORE_CTX_get1_chain, X509_STORE_CTX_init, X509_STORE_CTX_new_ex,
        X509_STORE_CTX_set_default, X509_STORE_CTX_set_ex_data, X509_STORE_CTX_set_verify_cb,
    };
    use crate::x509::vpm::{
        X509_VERIFY_PARAM_move_peername, X509_VERIFY_PARAM_set_auth_level, X509_VERIFY_PARAM_set1,
    };
    // OpenSSL raises these from `ssl_verify_cert_chain`'s worker.
    const F: &str = "ssl_verify_internal";
    let Some(snap) = snap else {
        err::raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR, F);
        return None;
    };
    // The chain as the core received it (a server records it only after verification).
    // SAFETY: the snapshot's library context and properties, alive with it.
    let owned = unsafe { Chain::of(peer, snap.libctx, snap.propq()) };
    let chain = owned.0;
    let (store, verify_cb, server, verify_mode, level) = {
        let mut st = x.state();
        st.rwstate = rustyssl_abi::SSL_NOTHING;
        let store = if st.cert.verify_store.is_null() {
            snap.cert_store
        } else {
            st.cert.verify_store
        };
        (
            store,
            st.verify_callback,
            st.server,
            st.verify_mode,
            st.cert.sec_level,
        )
    };
    // SAFETY: our stack of the peer's certificates, or NULL (-1).
    let n = unsafe { OPENSSL_sk_num(chain.cast()) };
    let proceed_anyway = verify_mode == SSL_VERIFY_NONE;
    if n <= 0 {
        return Some(Answer::Verified {
            result: i64::from(rustyssl_abi::X509_V_ERR_UNSPECIFIED),
            proceed: proceed_anyway,
            verified_chain: Vec::new(),
        });
    }
    // SAFETY: the context's library context and property query.
    let ctx = unsafe { X509_STORE_CTX_new_ex(snap.libctx, snap.propq()) };
    if ctx.is_null() {
        err::raise(ERR_LIB_SSL, ERR_R_X509_LIB, F);
        return Some(Answer::Verified {
            result: 0,
            proceed: false,
            verified_chain: Vec::new(),
        });
    }
    // SAFETY: the chain's first certificate (index in range).
    let leaf: *mut X509 = unsafe { OPENSSL_sk_value(chain.cast(), 0) }.cast();
    // SAFETY: the new context; the store; the leaf; the chain.
    if unsafe { X509_STORE_CTX_init(ctx, store, leaf, chain) } == 0 {
        err::raise(ERR_LIB_SSL, ERR_R_X509_LIB, F);
        // SAFETY: made above.
        unsafe { X509_STORE_CTX_free(ctx) };
        return Some(Answer::Verified {
            result: 0,
            proceed: false,
            verified_chain: Vec::new(),
        });
    }
    // SAFETY: the context's parameters.
    let param = unsafe { X509_STORE_CTX_get0_param(ctx) };
    // SAFETY: as above.
    unsafe { X509_VERIFY_PARAM_set_auth_level(param, level) };
    // SAFETY: no preconditions.
    let idx = unsafe { super::super::ctx::rustyssl_private_SSL_get_ex_data_X509_STORE_CTX_idx() };
    // SAFETY: the context; the connection as its application data.
    unsafe { X509_STORE_CTX_set_ex_data(ctx, idx, s.cast()) };
    // Verify via DANE if enabled, with the context's matching types as they are now.
    let dane: *mut rustyssl_abi::SSL_DANE = {
        let mut st = x.state();
        if st.lists.dane.enabled() {
            // SAFETY: the connection holds a reference to its context.
            if let Some(cx) = unsafe { super::super::conn::ctx_of(&st) } {
                st.lists.dane.refresh(&cx.state().lists.dane_ctx);
            }
            // Boxed: the address is stable while the connection lives.
            ptr::from_mut::<super::super::dane::Dane>(&mut st.lists.dane).cast()
        } else {
            ptr::null_mut()
        }
    };
    if !dane.is_null() {
        // SAFETY: the context; the connection's DANE state, which outlives it.
        unsafe { crate::x509::ctx::X509_STORE_CTX_set0_dane(ctx, dane) };
    }
    let purpose = if server { c"ssl_client" } else { c"ssl_server" };
    // SAFETY: as above; a NUL-terminated name.
    unsafe { X509_STORE_CTX_set_default(ctx, purpose.as_ptr()) };
    // Anything non-default in the connection's parameters overrides the context's.
    // SAFETY: as above; the connection's parameters.
    unsafe { X509_VERIFY_PARAM_set1(param, x.param) };
    if verify_cb.is_some() {
        // SAFETY: as above; the application's callback.
        unsafe { X509_STORE_CTX_set_verify_cb(ctx, verify_cb) };
    }
    let i = match snap.app_verify_callback {
        // SAFETY: the application's whole-verification callback; no lock is held.
        Some(cb) => unsafe { cb(ctx, snap.app_verify_arg) },
        None => {
            // SAFETY: the initialized context; no lock is held.
            let r = unsafe { crate::x509::verify::X509_verify_cert(ctx) };
            r.max(0)
        }
    };
    // SAFETY: as above.
    let result = unsafe { X509_STORE_CTX_get_error(ctx) };
    // SAFETY: as above.
    let verified: *mut stack_st_X509 = unsafe { X509_STORE_CTX_get1_chain(ctx) };
    // SAFETY: the connection's parameters; the context's (its peer name moves over).
    unsafe { X509_VERIFY_PARAM_move_peername(x.param, param) };
    // SAFETY: made above.
    unsafe { X509_STORE_CTX_free(ctx) };
    let retry = x.state().rwstate == SSL_RETRY_VERIFY;
    if i <= 0 && retry {
        // SAFETY: our copy of the chain, or NULL.
        unsafe { OPENSSL_sk_pop_free(verified.cast(), Some(x509_free)) };
        return None;
    }
    let mut der = Vec::new();
    // SAFETY: the verified chain, or NULL (-1).
    let vn = unsafe { OPENSSL_sk_num(verified.cast()) };
    for k in 0..vn.max(0) {
        // SAFETY: an index in range.
        let c: *mut X509 = unsafe { OPENSSL_sk_value(verified.cast(), k) }.cast();
        if !c.is_null() {
            // SAFETY: a certificate of the chain.
            der.extend(unsafe { config::der_of(c) });
        }
    }
    let old = {
        let mut st = x.state();
        st.verify_result = core::ffi::c_long::from(result);
        // The peer's certificate is its own only once the chain is accepted.
        st.drv.peer.accepted = i > 0 || proceed_anyway;
        core::mem::replace(&mut st.drv.peer.verified, verified)
    };
    // SAFETY: the previous verified chain, ours, freed with no lock held.
    unsafe { OPENSSL_sk_pop_free(old.cast(), Some(x509_free)) };
    Some(Answer::Verified {
        result: i64::from(result),
        proceed: i > 0 || proceed_anyway,
        verified_chain: der,
    })
}

/// A certificate stack made from DER encodings, freed when dropped.
struct Chain(*mut stack_st_X509);

impl Chain {
    /// The certificates that decode in `libctx`, in order (`d2i_X509` runs with no lock held).
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `propq` is NULL or a string.
    unsafe fn of(
        ders: &[Vec<u8>],
        libctx: *mut rustyssl_abi::OSSL_LIB_CTX,
        propq: *const core::ffi::c_char,
    ) -> Self {
        // SAFETY: no preconditions.
        let sk: *mut stack_st_X509 = unsafe { crate::stack::OPENSSL_sk_new_null() }.cast();
        for der in ders {
            // SAFETY: the caller's guarantee.
            let c = unsafe { crate::x509::cert::decode_in(der, libctx, propq) };
            if c.is_null() {
                continue;
            }
            // SAFETY: the new stack, which takes the reference.
            if unsafe { crate::stack::OPENSSL_sk_push(sk.cast(), c.cast()) } == 0 {
                // SAFETY: not taken.
                unsafe { X509_free(c) };
            }
        }
        Self(sk)
    }
}

impl Drop for Chain {
    fn drop(&mut self) {
        // SAFETY: our stack and its references, freed with no lock held.
        unsafe { OPENSSL_sk_pop_free(self.0.cast(), Some(x509_free)) };
    }
}
