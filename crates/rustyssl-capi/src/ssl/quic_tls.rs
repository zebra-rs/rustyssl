//! The third-party QUIC stack API (`SSL_set_quic_tls_cbs(3)`, step 10.3): a QUIC stack drives
//! a TLS `SSL` through six callbacks, as `ssl/quic/quic_tls_api.c` and `quic_tls.c` do.
//!
//! The core runs in QUIC mode (`rustyssl_tls::conn::quic`). The driver (`super::io`) carries
//! what it makes to the callbacks, in the order libssl calls them: each write of handshake
//! octets to `crypto_send` (a partial write is retried, as `SSL_ERROR_WANT_WRITE`), each secret
//! to `yield_secret` once the octets made before it are sent, each alert to `alert`. Reads take
//! a record from `crypto_recv_rcd` (none: `SSL_ERROR_WANT_READ`), copy it into the core, and
//! release it with `crypto_release_rcd`. The peer's transport parameters go to
//! `got_transport_params`. Every callback runs with no lock held.

use core::ffi::{c_int, c_uchar, c_void};
use core::ptr;
use std::collections::VecDeque;
use std::sync::Arc;

use rustyssl_abi::{
    BIO, BIO_FLAGS_READ, BIO_FLAGS_RWS, BIO_FLAGS_SHOULD_RETRY, BIO_FLAGS_WRITE, ERR_LIB_SSL,
    ERR_R_INTERNAL_ERROR, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, OSSL_DISPATCH,
    OSSL_FUNC_SSL_QUIC_TLS_ALERT, OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD,
    OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD, OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND,
    OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS, OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET,
    OSSL_FUNC_SSL_QUIC_TLS_alert_fn, OSSL_FUNC_SSL_QUIC_TLS_crypto_recv_rcd_fn,
    OSSL_FUNC_SSL_QUIC_TLS_crypto_release_rcd_fn, OSSL_FUNC_SSL_QUIC_TLS_crypto_send_fn,
    OSSL_FUNC_SSL_QUIC_TLS_got_transport_params_fn, OSSL_FUNC_SSL_QUIC_TLS_yield_secret_fn, SSL,
    SSL_AD_INTERNAL_ERROR, SSL_CTRL_SET_MIN_PROTO_VERSION, SSL_OP_ENABLE_MIDDLEBOX_COMPAT,
    SSL_R_BAD_EXTENSION, SSL_R_MISSING_QUIC_TLS_FUNCTIONS, SSL_R_RECORD_LAYER_FAILURE, SSL_READING,
    SSL_WRITING, TLS1_3_VERSION, TLSEXT_TYPE_quic_transport_parameters,
};
use rustyssl_tls::conn::common::EarlyDataState;
use rustyssl_tls::conn::{Answer, Direction, QuicLevel, QuicSecret, QuicTlsConfig};
use rustyssl_tls::error::Error as TlsError;

use super::accessors::rustyssl_private_SSL_clear_options;
use super::conn::{
    Ssl, rustyssl_private_SSL_ctrl, rustyssl_private_SSL_in_before, rustyssl_private_SSL_is_tls,
    rustyssl_private_SSL_set_bio, ssl,
};
use super::custom::{Callbacks as ExtCallbacks, Method};
use super::io::set_early_data_state;
use super::sess_cache::rustyssl_private_SSL_get_session;
use super::session::rustyssl_private_SSL_SESSION_get_max_early_data;
use crate::bio::null::BIO_s_null;
use crate::bio::{BIO_clear_flags, BIO_new, BIO_set_flags};
use crate::err;
use crate::ffi::ffi_export;

/// The application's callbacks (`OSSL_QUIC_TLS_CALLBACKS`), each kept from the first table
/// that had it, for the connection's lifetime (`tls_callbacks_from_dispatch`).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Callbacks {
    send: OSSL_FUNC_SSL_QUIC_TLS_crypto_send_fn,
    recv: OSSL_FUNC_SSL_QUIC_TLS_crypto_recv_rcd_fn,
    release: OSSL_FUNC_SSL_QUIC_TLS_crypto_release_rcd_fn,
    yield_secret: OSSL_FUNC_SSL_QUIC_TLS_yield_secret_fn,
    got_params: OSSL_FUNC_SSL_QUIC_TLS_got_transport_params_fn,
    alert: OSSL_FUNC_SSL_QUIC_TLS_alert_fn,
}

/// A connection's third-party QUIC state (`sc->qtcb`, `sc->qtarg`, and what `sc->qtls`
/// keeps); `SSL_clear` leaves it.
#[derive(Debug)]
pub(crate) struct QuicTls {
    cbs: Callbacks,
    arg: *mut c_void,
    /// Whether `SSL_set_quic_tls_cbs` set the connection up (`sc->qtls`).
    pub(crate) on: bool,
    /// The local transport parameters (a copy: OpenSSL keeps the caller's pointer).
    pub(crate) params: Option<Vec<u8>>,
    /// Whether early data is on (`ossl_quic_tls_set_early_data_enabled`).
    early_data: bool,
    /// OpenSSL's own QUIC (`super::quic`): the transport in place of the callbacks.
    pub(crate) sink: Option<Arc<dyn Sink>>,
}

/// The transport of OpenSSL's own QUIC, in place of the six callbacks (`quic_tls.c`'s
/// internal ones). Called with no lock held.
pub(crate) trait Sink: Send + Sync + core::fmt::Debug {
    /// Handshake octets to send, all taken.
    fn send(&self, data: &[u8]);
    /// A secret; false fails the connection.
    fn secret(&self, s: QuicSecret) -> bool;
    /// An alert to send.
    fn alert(&self, a: u8);
    /// The next received CRYPTO octets and their level, if any.
    fn recv(&self) -> Option<(QuicLevel, Vec<u8>)>;
    /// The peer's transport parameters.
    fn got_params(&self, params: &[u8]);
}

impl Default for QuicTls {
    fn default() -> Self {
        Self {
            cbs: Callbacks::default(),
            arg: ptr::null_mut(),
            on: false,
            params: None,
            early_data: false,
            sink: None,
        }
    }
}

impl QuicTls {
    /// The core's QUIC mode settings, when the connection has the callbacks.
    pub(crate) fn config(&self) -> Option<QuicTlsConfig> {
        self.on.then(|| QuicTlsConfig {
            transport_params: self.params.clone(),
            early_data: self.early_data,
        })
    }
}

/// What waits to go to the callbacks, in order.
#[derive(Debug)]
pub(crate) enum Out {
    /// Handshake octets for `crypto_send`.
    Crypto(Vec<u8>),
    /// A secret for `yield_secret`.
    Secret(QuicSecret),
    /// An alert for `alert`.
    Alert(u8),
}

/// The driver's queue for the callbacks (per handshake: `SSL_clear` empties it).
#[derive(Debug, Default)]
pub(crate) struct Queue {
    out: VecDeque<Out>,
    /// How much of the front octets `crypto_send` took.
    sent: usize,
}

/// What [`pump`] found.
pub(crate) enum Pumped {
    /// All delivered.
    Done,
    /// `crypto_send` took only part: `SSL_ERROR_WANT_WRITE`.
    Retry,
    /// A callback failed; the connection failed with it (the core reports it next).
    Failed,
}

/// What [`read`] found.
pub(crate) enum Read {
    /// A record was fed to the core.
    Got,
    /// No record: `SSL_ERROR_WANT_READ`.
    Retry,
    /// A callback failed; the connection failed with it.
    Failed,
}

/// Whether `x` is driven through the QUIC callbacks.
pub(crate) fn is_on(x: &Ssl) -> bool {
    x.state().quic.on
}

/// Moves the core's handshake octets made before the write secret it just raised (all of them,
/// without `secret`) and its alerts into the queue, then `secret` after them.
pub(crate) fn queue(x: &Ssl, secret: Option<QuicSecret>) {
    let mut st = x.state();
    let d = &mut st.drv;
    let Some(c) = d.tls.as_mut() else { return };
    let (crypto, alerts) = match secret.as_ref() {
        Some(q) if q.direction == Direction::Write => {
            (c.take_quic_crypto_before_secret(), Vec::new())
        }
        Some(_) => (Vec::new(), Vec::new()),
        None => (c.take_quic_crypto(), c.take_quic_alerts()),
    };
    let q = &mut d.quic;
    q.out
        .extend(crypto.into_iter().map(|(_, data)| Out::Crypto(data)));
    q.out.extend(alerts.into_iter().map(Out::Alert));
    if let Some(s) = secret {
        q.out.push_back(Out::Secret(s));
    }
}

/// `BIO_clear_retry_flags` on `b`, if any.
///
/// # Safety
/// `b` is NULL or a live BIO.
unsafe fn clear_retry(b: *mut BIO) {
    if !b.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { BIO_clear_flags(b, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY) };
    }
}

/// `BIO_set_retry_read` / `_write` on `b` (the record layer's BIO), if any.
///
/// # Safety
/// `b` is NULL or a live BIO.
unsafe fn set_retry(b: *mut BIO, flag: c_int) {
    if !b.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { clear_retry(b) };
        // SAFETY: as above.
        unsafe { BIO_set_flags(b, flag | BIO_FLAGS_SHOULD_RETRY) };
    }
}

/// A callback failed (`QUIC_TLS_FATAL` with internal_error in `function`): the entry, then the
/// connection fails as `ossl_tls_handle_rlayer_return` makes it (or, for a secret, as
/// `ssl_set_new_record_layer` does), its alert going to the stack; the core reports the rest.
fn callback_failed(x: &Ssl, function: &str, secret: bool) {
    err::raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR, function);
    let mut st = x.state();
    let prov = st.drv.provider.clone();
    if let (Some(c), Some(p)) = (st.drv.tls.as_mut(), prov) {
        if secret {
            c.fail_quic_secret(
                &*p,
                TlsError::internal().in_func("ssl_set_new_record_layer"),
            );
        } else {
            c.fail(
                &*p,
                TlsError::alert(SSL_AD_INTERNAL_ERROR, SSL_R_RECORD_LAYER_FAILURE).in_func(""),
            );
        }
        st.in_init = c.in_init();
    }
    st.drv.quic = Queue::default();
}

/// Delivers the queue to the callbacks, in order, with no lock held.
///
/// # Safety
/// `s` is the live connection behind `x`.
pub(crate) unsafe fn pump(s: *mut SSL, x: &Ssl) -> Pumped {
    let sink = x.state().quic.sink.clone();
    if let Some(sink) = sink {
        return pump_sink(x, &*sink);
    }
    loop {
        let (item, cbs, arg, wbio) = {
            let mut st = x.state();
            let (cbs, arg, wbio) = (st.quic.cbs, st.quic.arg, st.wbio);
            let q = &mut st.drv.quic;
            let item = match q.out.front() {
                None => return Pumped::Done,
                Some(Out::Crypto(d)) => Out::Crypto(d.get(q.sent..).unwrap_or_default().to_vec()),
                Some(Out::Alert(a)) => Out::Alert(*a),
                Some(Out::Secret(_)) => match q.out.pop_front() {
                    Some(o) => o,
                    None => return Pumped::Done,
                },
            };
            (item, cbs, arg, wbio)
        };
        match item {
            Out::Crypto(data) => {
                let Some(send) = cbs.send else {
                    callback_failed(x, "quic_write_records", false);
                    return Pumped::Failed;
                };
                // SAFETY: the connection's BIO, NULL or live.
                unsafe { clear_retry(wbio) };
                let mut consumed = 0usize;
                // SAFETY: the application's callback with its connection, the octets, and its
                // argument; no lock is held.
                let r = unsafe { send(s, data.as_ptr(), data.len(), &raw mut consumed, arg) };
                if r == 0 || consumed > data.len() {
                    callback_failed(x, "quic_write_records", false);
                    return Pumped::Failed;
                }
                let mut st = x.state();
                let q = &mut st.drv.quic;
                if consumed == data.len() {
                    q.out.pop_front();
                    q.sent = 0;
                } else {
                    q.sent = q.sent.saturating_add(consumed);
                    st.rwstate = SSL_WRITING;
                    drop(st);
                    // SAFETY: as above.
                    unsafe { set_retry(wbio, BIO_FLAGS_WRITE) };
                    return Pumped::Retry;
                }
            }
            Out::Alert(a) => {
                x.state().drv.quic.out.pop_front();
                let Some(alert) = cbs.alert else {
                    return Pumped::Failed;
                };
                // SAFETY: the application's callback; no lock is held.
                if unsafe { alert(s, a, arg) } == 0 {
                    err::raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR, "quic_write_records");
                    return Pumped::Failed;
                }
            }
            Out::Secret(q) => {
                let level = u32::try_from(q.level.protection_level()).unwrap_or(0);
                let dir = c_int::from(q.direction == Direction::Write);
                let secret = q.secret.bytes();
                let ok = cbs.yield_secret.is_some_and(|f| {
                    // SAFETY: the application's callback with the secret's octets; no lock is
                    // held.
                    unsafe { f(s, level, dir, secret.as_ptr(), secret.len(), arg) != 0 }
                });
                if !ok {
                    callback_failed(x, "quic_new_record_layer", true);
                    return Pumped::Failed;
                }
            }
        }
    }
}

/// [`pump`] into OpenSSL's own transport.
fn pump_sink(x: &Ssl, sink: &dyn Sink) -> Pumped {
    loop {
        let item = {
            let mut st = x.state();
            st.drv.quic.sent = 0;
            st.drv.quic.out.pop_front()
        };
        match item {
            None => return Pumped::Done,
            Some(Out::Crypto(d)) => sink.send(&d),
            Some(Out::Alert(a)) => sink.alert(a),
            Some(Out::Secret(q)) => {
                if !sink.secret(q) {
                    callback_failed(x, "quic_new_record_layer", true);
                    return Pumped::Failed;
                }
            }
        }
    }
}

/// Reads a record from the stack into the core (`quic_read_record`), releasing it once copied.
///
/// # Safety
/// `s` is the live connection behind `x`.
pub(crate) unsafe fn read(s: *mut SSL, x: &Ssl) -> Read {
    let sink = x.state().quic.sink.clone();
    if let Some(sink) = sink {
        let Some((level, data)) = sink.recv() else {
            x.state().rwstate = SSL_READING;
            return Read::Retry;
        };
        let fed = {
            let mut st = x.state();
            st.drv
                .tls
                .as_mut()
                .map(|c| c.feed_quic_crypto(level, &data))
        };
        return match fed {
            Some(Ok(())) => Read::Got,
            Some(Err(e)) => {
                let mut st = x.state();
                let prov = st.drv.provider.clone();
                if let (Some(c), Some(p)) = (st.drv.tls.as_mut(), prov) {
                    c.fail(&*p, e);
                    st.in_init = c.in_init();
                }
                Read::Failed
            }
            None => Read::Failed,
        };
    }
    let (cbs, arg, rbio) = {
        let st = x.state();
        (st.quic.cbs, st.quic.arg, st.rbio)
    };
    let (Some(recv), Some(release)) = (cbs.recv, cbs.release) else {
        callback_failed(x, "quic_read_record", false);
        return Read::Failed;
    };
    // SAFETY: the connection's BIO, NULL or live.
    unsafe { clear_retry(rbio) };
    let mut buf: *const c_uchar = ptr::null();
    let mut n = 0usize;
    // SAFETY: the application's callback with places for the record; no lock is held.
    if unsafe { recv(s, &raw mut buf, &raw mut n, arg) } == 0 {
        callback_failed(x, "quic_read_record", false);
        return Read::Failed;
    }
    if n == 0 {
        x.state().rwstate = SSL_READING;
        // SAFETY: as above.
        unsafe { set_retry(rbio, BIO_FLAGS_READ) };
        return Read::Retry;
    }
    if buf.is_null() || isize::try_from(n).is_err() {
        callback_failed(x, "quic_read_record", false);
        return Read::Failed;
    }
    // SAFETY: the stack's record: `n` octets at `buf`, valid until it is released.
    let data = unsafe { core::slice::from_raw_parts(buf, n) }.to_vec();
    let fed = {
        let mut st = x.state();
        st.drv.tls.as_mut().map(|c| {
            let level = c.read_level();
            c.feed_quic_crypto(level, &data)
        })
    };
    if !matches!(fed, Some(Ok(()))) {
        callback_failed(x, "quic_read_record", false);
        return Read::Failed;
    }
    // SAFETY: the application's callback with the length it gave; no lock is held.
    if unsafe { release(s, n, arg) } == 0 {
        callback_failed(x, "quic_release_record", false);
        return Read::Failed;
    }
    Read::Got
}

/// `parse_transport_params_cb`: the peer's parameters to `got_transport_params`, with no lock
/// held. A 0 fails with bad_extension and alert 0 (`custom_ext_parse`'s `al`).
///
/// # Safety
/// `s` is the live connection behind `x`.
pub(crate) unsafe fn got_params(s: *mut SSL, x: &Ssl, params: &[u8]) -> Answer {
    let sink = x.state().quic.sink.clone();
    if let Some(sink) = sink {
        sink.got_params(params);
        return Answer::Continue;
    }
    let (f, arg) = {
        let st = x.state();
        (st.quic.cbs.got_params, st.quic.arg)
    };
    // SAFETY: the application's callback with the parameters; no lock is held.
    let ok = f.is_some_and(|f| unsafe { f(s, params.as_ptr(), params.len(), arg) } != 0);
    if ok {
        Answer::Continue
    } else {
        Answer::Fail {
            alert: Some(0),
            reason: SSL_R_BAD_EXTENSION,
        }
    }
}

/// Reads one table entry's function as the type its id names.
///
/// # Safety
/// `f` is the application's function for an id whose prototype is `T`'s.
unsafe fn as_fn<T: Copy>(f: Option<unsafe extern "C" fn()>) -> Option<T> {
    // SAFETY: the caller's guarantee: `T` is a function pointer type of the same size.
    f.map(|f| unsafe { core::mem::transmute_copy::<unsafe extern "C" fn(), T>(&f) })
}

/// `tls_callbacks_from_dispatch`: fills the callbacks not set yet from `t`; whether all six are
/// set then.
///
/// # Safety
/// `t` is a dispatch table ended by a zero id.
unsafe fn from_dispatch(cbs: &mut Callbacks, mut t: *const OSSL_DISPATCH) -> bool {
    // SAFETY: the caller's guarantee: the table goes on to its end.
    while let Some(d) = unsafe { t.as_ref() } {
        if d.function_id == 0 {
            break;
        }
        match d.function_id {
            OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND if cbs.send.is_none() => {
                // SAFETY: the application's function for this id, of the prototype it names.
                cbs.send = unsafe { as_fn(d.function) };
            }
            OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD if cbs.recv.is_none() => {
                // SAFETY: the application's function for this id, of the prototype it names.
                cbs.recv = unsafe { as_fn(d.function) };
            }
            OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD if cbs.release.is_none() => {
                // SAFETY: the application's function for this id, of the prototype it names.
                cbs.release = unsafe { as_fn(d.function) };
            }
            OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET if cbs.yield_secret.is_none() => {
                // SAFETY: the application's function for this id, of the prototype it names.
                cbs.yield_secret = unsafe { as_fn(d.function) };
            }
            OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS if cbs.got_params.is_none() => {
                // SAFETY: the application's function for this id, of the prototype it names.
                cbs.got_params = unsafe { as_fn(d.function) };
            }
            OSSL_FUNC_SSL_QUIC_TLS_ALERT if cbs.alert.is_none() => {
                // SAFETY: the application's function for this id, of the prototype it names.
                cbs.alert = unsafe { as_fn(d.function) };
            }
            _ => {}
        }
        t = t.wrapping_add(1);
    }
    cbs.send.is_some()
        && cbs.recv.is_some()
        && cbs.release.is_some()
        && cbs.yield_secret.is_some()
        && cbs.got_params.is_some()
        && cbs.alert.is_some()
}

ffi_export! {
    /// Drives the TLS connection `s` through a QUIC stack's callbacks (`qtdis`, with `arg`):
    /// TLS 1.3 only, no middlebox compatibility, null BIOs, and the transport parameters
    /// extension. 1, or 0 (`SSL_R_MISSING_QUIC_TLS_FUNCTIONS` when a callback is missing; 0
    /// with no entry when the extension is registered already, as on a second call).
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `qtdis` a dispatch table ended by a zero id, whose
    /// functions and `arg` stay valid while the connection uses them.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_quic_tls_cbs(s: *mut SSL, qtdis: *const OSSL_DISPATCH, arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        const F: &str = "SSL_set_quic_tls_cbs";
        // SAFETY: the caller's guarantee.
        if unsafe { rustyssl_private_SSL_is_tls(s) } == 0 {
            err::raise(ERR_LIB_SSL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, F);
            return 0;
        }
        // SAFETY: as above.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let server = {
            let mut st = x.state();
            let mut cbs = st.quic.cbs;
            // SAFETY: the caller's guarantee.
            let all = unsafe { from_dispatch(&mut cbs, qtdis) };
            st.quic.cbs = cbs;
            if !all {
                drop(st);
                err::raise(ERR_LIB_SSL, SSL_R_MISSING_QUIC_TLS_FUNCTIONS, "tls_callbacks_from_dispatch");
                return 0;
            }
            st.quic.arg = arg;
            // A new `QUIC_TLS`: its parameters and early data setting start again.
            st.quic.on = true;
            st.quic.params = None;
            st.quic.early_data = false;
            st.server
        };
        // `ossl_quic_tls_configure`.
        let v13 = core::ffi::c_long::from(TLS1_3_VERSION);
        // SAFETY: the live connection.
        if unsafe { rustyssl_private_SSL_ctrl(s, SSL_CTRL_SET_MIN_PROTO_VERSION, v13, ptr::null_mut()) } == 0 {
            err::raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR, "ossl_quic_tls_configure");
            return 0;
        }
        // SAFETY: no preconditions.
        let method = unsafe { BIO_s_null() };
        // SAFETY: the null BIO's method.
        let nullbio = unsafe { BIO_new(method) };
        if nullbio.is_null() {
            err::raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR, "ossl_quic_tls_configure");
            return 0;
        }
        // The record layer doesn't use the BIOs, but libssl expects some.
        // SAFETY: the live connection takes the BIO's reference (once, for both).
        unsafe { rustyssl_private_SSL_set_bio(s, nullbio, nullbio) };
        // SAFETY: the live connection.
        unsafe { rustyssl_private_SSL_clear_options(s, SSL_OP_ENABLE_MIDDLEBOX_COMPAT) };
        let Ok(typ) = u16::try_from(TLSEXT_TYPE_quic_transport_parameters) else { return 0 };
        let mut st = x.state();
        // `ossl_tls_add_custom_ext_intern` on the connection's list, after the context's.
        if super::custom::find(&st.cert.custext, Some(server), typ) {
            return 0;
        }
        st.cert.custext.push(Method {
            typ,
            context: rustyssl_tls::conn::quic::PARAMS_CONTEXT,
            role: Some(server),
            cbs: ExtCallbacks::New {
                add: None,
                free: None,
                add_arg: ptr::null_mut(),
                parse: None,
                parse_arg: ptr::null_mut(),
            },
        });
        1
    }
}

ffi_export! {
    /// Sets the transport parameters to send (copied): 1, or 0 once they were sent, or before
    /// `SSL_set_quic_tls_cbs`.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `params` NULL or `params_len` readable octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_quic_tls_transport_params(s: *mut SSL, params: *const c_uchar, params_len: usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let mut st = x.state();
        if !st.quic.on {
            drop(st);
            err::raise(ERR_LIB_SSL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, "SSL_set_quic_tls_transport_params");
            return 0;
        }
        if st.drv.tls.as_ref().is_some_and(|c| c.quic_transport_params_consumed()) {
            return 0;
        }
        let p = if params_len == 0 {
            Vec::new()
        } else if params.is_null() || isize::try_from(params_len).is_err() {
            return 0;
        } else {
            // SAFETY: the caller's guarantee: `params_len` readable octets.
            unsafe { core::slice::from_raw_parts(params, params_len) }.to_vec()
        };
        if let Some(q) = st.drv.tls.as_mut().and_then(|c| c.config_mut().quic.as_mut()) {
            q.transport_params = Some(p.clone());
        }
        st.quic.params = Some(p);
        1
    }
}

ffi_export! {
    /// Turns 0-RTT on or off before the handshake: a server accepts it (and its tickets allow
    /// it), a client offers it, which needs a session that allows 0xffffffff octets or a PSK
    /// session callback. 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_quic_tls_early_data_enabled(s: *mut SSL, enabled: c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        const F: &str = "SSL_set_quic_tls_early_data_enabled";
        // SAFETY: the caller's guarantee.
        if unsafe { rustyssl_private_SSL_is_tls(s) } == 0 {
            err::raise(ERR_LIB_SSL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, F);
            return 0;
        }
        // SAFETY: as above.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        if !is_on(x) {
            err::raise(ERR_LIB_SSL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, F);
            return 0;
        }
        // SAFETY: the live connection.
        if unsafe { rustyssl_private_SSL_in_before(s) } == 0 {
            return 0;
        }
        let server = x.state().server;
        if enabled != 0 && !server {
            // SAFETY: as above; the session is the connection's.
            let sess = unsafe { rustyssl_private_SSL_get_session(s) };
            // SAFETY: NULL or the connection's session.
            let allowed = !sess.is_null() && unsafe { rustyssl_private_SSL_SESSION_get_max_early_data(sess) } == u32::MAX;
            if !allowed && x.state().psk_use_session_cb.is_none() {
                return 0;
            }
        }
        let mut st = x.state();
        let e = match (enabled != 0, server) {
            (false, _) => {
                st.max_early_data = 0;
                EarlyDataState::None
            }
            (true, true) => {
                st.max_early_data = u32::MAX;
                EarlyDataState::Accepting
            }
            (true, false) => EarlyDataState::Connecting,
        };
        st.quic.early_data = enabled != 0;
        set_early_data_state(&mut st, e);
        1
    }
}
