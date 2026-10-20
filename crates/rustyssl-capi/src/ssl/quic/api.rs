//! The QUIC paths of libssl's functions (`quic_impl.c`): each export checks for a QUIC object
//! first and, for one, calls the function here.

use core::ffi::{c_int, c_void};
use core::ptr;
use std::sync::Arc;

use rustyssl_abi::{
    BIO, BIO_ADDR, BIO_CTRL_DGRAM_DETECT_PEER_ADDR, BIO_DGRAM_CAP_HANDLES_DST_ADDR, ERR_LIB_SSL,
    ERR_R_INTERNAL_ERROR, ERR_R_PASSED_INVALID_ARGUMENT, ERR_R_PASSED_NULL_PARAMETER,
    ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, ERR_R_UNSUPPORTED, SSL, SSL_ACCEPT_CONNECTION_NO_BLOCK,
    SSL_ACCEPT_STREAM_BIDI, SSL_ACCEPT_STREAM_NO_BLOCK, SSL_ACCEPT_STREAM_UNI, SSL_CTX,
    SSL_DEFAULT_STREAM_MODE_AUTO_UNI, SSL_DEFAULT_STREAM_MODE_NONE, SSL_ERROR_NONE, SSL_ERROR_SSL,
    SSL_ERROR_SYSCALL, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE, SSL_ERROR_ZERO_RETURN,
    SSL_INCOMING_STREAM_POLICY_ACCEPT, SSL_INCOMING_STREAM_POLICY_AUTO,
    SSL_INCOMING_STREAM_POLICY_REJECT, SSL_LISTENER_FLAG_NO_VALIDATE,
    SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER, SSL_MODE_ENABLE_PARTIAL_WRITE, SSL_R_BAD_WRITE_RETRY,
    SSL_R_BIO_NOT_SET, SSL_R_CONN_USE_ONLY, SSL_R_LISTENER_USE_ONLY, SSL_R_NO_STREAM,
    SSL_R_PROTOCOL_IS_SHUTDOWN, SSL_R_REMOTE_PEER_ADDRESS_NOT_SET, SSL_R_STREAM_COUNT_LIMITED,
    SSL_R_STREAM_FINISHED, SSL_R_STREAM_RECV_ONLY, SSL_R_STREAM_RESET, SSL_R_STREAM_SEND_ONLY,
    SSL_R_UNSUPPORTED_WRITE_FLAG, SSL_STREAM_FLAG_ADVANCE, SSL_STREAM_FLAG_NO_BLOCK,
    SSL_STREAM_FLAG_UNI, SSL_STREAM_TYPE_BIDI, SSL_STREAM_TYPE_NONE, SSL_STREAM_TYPE_READ,
    SSL_STREAM_TYPE_WRITE, SSL_WRITE_FLAG_CONCLUDE,
};
use rustyssl_quic::channel::State;
use rustyssl_quic::stream::{RecvState, SendState, is_server_init, is_uni};

use super::hs::{Hs, Shared};
use super::{ConnRec, Engine, EngineState, Kind, ListenerRec, Quic, Rec, StreamApi, StreamRec};
use crate::err;
use crate::ssl::conn::{Ssl, ssl};

/// `QCTX_*`: what an object may be for a call.
const C: u32 = 1;
const S: u32 = 2;
const L: u32 = 4;
const D: u32 = 0x80;
const NO_ERROR: u32 = 0x100;

/// An object resolved for a call (`QCTX`).
pub(crate) struct Qctx<'a> {
    pub(crate) q: &'a Quic,
    pub(crate) x: &'a Ssl,
    /// The connection's key (a connection, or a stream's connection).
    pub(crate) conn: usize,
    pub(crate) is_stream: bool,
    /// An I/O call (it sets what `SSL_get_error` reports).
    pub(crate) in_io: bool,
}

/// `wrong_type`: the reason for an object of the wrong kind.
fn wrong_type(flags: u32) {
    if flags & NO_ERROR != 0 {
        return;
    }
    let reason = match flags & (C | S | L | D) {
        D => rustyssl_abi::SSL_R_DOMAIN_USE_ONLY,
        L => SSL_R_LISTENER_USE_ONLY,
        C => SSL_R_CONN_USE_ONLY,
        x if x == S || x == C | S => SSL_R_NO_STREAM,
        _ => ERR_R_UNSUPPORTED,
    };
    err::raise(ERR_LIB_SSL, reason, "wrong_type");
}

/// `expect_quic_as` without default stream creation: `None` (with an error raised unless
/// `NO_ERROR`) for an object of a kind `flags` doesn't allow, or `Some(None)` for an object
/// that isn't QUIC at all.
///
/// # Safety
/// `s` is NULL or a live `SSL`.
unsafe fn expect<'a>(s: *const SSL, flags: u32) -> Option<Qctx<'a>> {
    // SAFETY: the caller's guarantee.
    let Some(x) = (unsafe { ssl(s) }) else {
        if flags & NO_ERROR == 0 {
            err::raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER, "expect_quic_as");
        }
        return None;
    };
    let q = x.quic.get()?;
    let (conn, is_stream) = match q.kind {
        Kind::Domain => {
            if flags & D == 0 {
                wrong_type(flags);
                return None;
            }
            (0, false)
        }
        Kind::Listener => {
            if flags & L == 0 {
                wrong_type(flags);
                return None;
            }
            (0, false)
        }
        Kind::Conn => {
            if flags & C == 0 {
                // A connection with a default stream is a stream for `S`.
                let has = q
                    .engine
                    .lock()
                    .conn(q.key())
                    .is_some_and(|c| c.default_stream.is_some());
                if flags & S == 0 || !has {
                    wrong_type(flags);
                    return None;
                }
            }
            (q.key(), false)
        }
        Kind::Stream => {
            if flags & S == 0 {
                wrong_type(flags);
                return None;
            }
            let conn = q.engine.lock().stream(q.key()).map_or(0, |r| r.conn);
            (conn, true)
        }
    };
    Some(Qctx {
        q,
        x,
        conn,
        is_stream,
        in_io: false,
    })
}

impl Qctx<'_> {
    fn engine(&self) -> &Arc<Engine> {
        &self.q.engine
    }

    /// `quic_set_last_error`.
    fn set_last_error(&self, es: &mut EngineState, e: c_int) {
        if !self.in_io {
            return;
        }
        if self.is_stream {
            if let Some(r) = es.stream(self.q.key()) {
                r.last_error = e;
            }
        } else if let Some(c) = es.conn(self.conn) {
            c.last_error = e;
        }
    }

    /// `QUIC_RAISE_NORMAL_ERROR`: 0.
    fn normal(&self, es: &mut EngineState, e: c_int) -> c_int {
        self.set_last_error(es, e);
        0
    }

    /// `QUIC_RAISE_NON_NORMAL_ERROR`: 0.
    fn non_normal(&self, es: &mut EngineState, reason: c_int, function: &str) -> c_int {
        self.set_last_error(es, SSL_ERROR_SSL);
        err::raise(ERR_LIB_SSL, reason, function);
        0
    }

    /// `qctx_lock_for_io`: an I/O call starts with no error.
    fn begin_io(&mut self) {
        self.in_io = true;
        let mut es = self.engine().lock();
        self.set_last_error(&mut es, SSL_ERROR_NONE);
    }

    /// The stream the call is for: the stream object's, or the connection's default stream.
    fn stream_id(&self, es: &mut EngineState) -> Option<u64> {
        if self.is_stream {
            es.stream(self.q.key()).map(|r| r.api.id)
        } else {
            es.conn(self.conn)?.default_stream.as_ref().map(|d| d.id)
        }
    }

    fn stream_api<'e>(&self, es: &'e mut EngineState) -> Option<&'e mut StreamApi> {
        if self.is_stream {
            es.stream(self.q.key()).map(|r| &mut r.api)
        } else {
            es.conn(self.conn)?.default_stream.as_mut()
        }
    }
}

/// `quic_mutation_allowed`.
fn mutation_allowed(es: &mut EngineState, conn: usize, req_active: bool) -> bool {
    let Some(c) = es.conn(conn) else { return false };
    if c.shutting_down {
        return false;
    }
    match es.channel_of(conn) {
        Some(ch) => ch.state() == State::Active && (!req_active || ch.is_active()),
        None => !req_active,
    }
}

fn term_any(es: &mut EngineState, conn: usize) -> bool {
    es.channel_of(conn)
        .is_some_and(|ch| ch.state() != State::Active)
}

fn handshake_complete(es: &mut EngineState, conn: usize) -> bool {
    es.channel_of(conn)
        .is_some_and(|ch| ch.is_handshake_complete())
}

// ---- Objects ----

/// `SSL_new` on a QUIC context (`ossl_quic_new`): `None` for another context.
///
/// # Safety
/// `ctx` is a live context.
pub(crate) unsafe fn ssl_new(ctx: *mut SSL_CTX) -> Option<*mut SSL> {
    // SAFETY: the caller's guarantee.
    let c = unsafe { crate::ssl::ctx::ctx(ctx) }?;
    let method = c.state().method;
    if !method.quic {
        return None;
    }
    if method.server {
        err::raise(
            ERR_LIB_SSL,
            ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED,
            "ossl_quic_new",
        );
        return Some(ptr::null_mut());
    }
    // SAFETY: the caller's guarantee.
    let s = unsafe { crate::ssl::conn::new_ssl(ctx) };
    // SAFETY: the new connection, or NULL.
    let Some(x) = (unsafe { ssl(s) }) else {
        return Some(ptr::null_mut());
    };
    // SAFETY: the new connection.
    unsafe { crate::ssl::conn::rustyssl_private_SSL_set_connect_state(s) };
    let engine = Engine::new(ctx, false, false);
    let mode = x.state().mode;
    let mut rec = ConnRec::new(s, Shared::new(false), false, mode);
    init_options(x, &mut rec, c.state().options);
    {
        let mut es = engine.lock();
        es.owner = s;
        es.objs.insert(s.addr(), Rec::Conn(rec));
    }
    let _ = x.quic.set(Quic {
        kind: Kind::Conn,
        engine,
        s,
    });
    Some(s)
}

/// `SSL_new_listener` (`ossl_quic_new_listener`).
///
/// # Safety
/// `ctx` is NULL or a live context.
pub(crate) unsafe fn new_listener(ctx: *mut SSL_CTX, flags: u64) -> *mut SSL {
    // SAFETY: the caller's guarantee.
    if unsafe { crate::ssl::ctx::ctx(ctx) }.is_none() {
        err::raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER, "SSL_new_listener");
        return ptr::null_mut();
    }
    // SAFETY: as above.
    let s = unsafe { crate::ssl::conn::new_ssl(ctx) };
    // SAFETY: the new object, or NULL.
    let Some(x) = (unsafe { ssl(s) }) else {
        return ptr::null_mut();
    };
    // SAFETY: the new object.
    unsafe { crate::ssl::conn::rustyssl_private_SSL_set_accept_state(s) };
    let validate = flags & u64::from(SSL_LISTENER_FLAG_NO_VALIDATE) == 0;
    let engine = Engine::new(ctx, true, validate);
    {
        let mut es = engine.lock();
        es.owner = s;
        es.objs
            .insert(s.addr(), Rec::Listener(ListenerRec { listening: false }));
    }
    let _ = x.quic.set(Quic {
        kind: Kind::Listener,
        engine,
        s,
    });
    s
}

/// The provider of `s`'s engine, made once (from the owner's library context).
///
/// # Safety
/// `owner` is the engine's live owner; no lock is held.
pub(super) unsafe fn ensure_provider(engine: &Engine, owner: &Ssl) -> bool {
    if engine.lock().prov.is_some() {
        return true;
    }
    let Some(snap) = crate::ssl::io::config::snapshot(owner) else {
        return false;
    };
    // SAFETY: the owner's context's snapshot.
    let p = unsafe { crate::ssl::io::provider(owner, &snap) };
    engine.lock().prov.get_or_insert(p);
    true
}

// ---- Handshake ----

/// The engine's owner, as an object.
pub(super) fn owner<'a>(es: &EngineState) -> Option<&'a Ssl> {
    // SAFETY: the owner holds the engine, so it lives while the engine is used.
    unsafe { ssl(es.owner) }
}

/// `quic_do_handshake`: 1 once complete, 0 or -1 with the error set.
///
/// # Safety
/// No lock is held.
unsafe fn do_handshake(c: &Qctx<'_>) -> c_int {
    const F: &str = "quic_do_handshake";
    let engine = Arc::clone(c.engine());
    {
        let mut es = engine.lock();
        if handshake_complete(&mut es, c.conn) {
            return 1;
        }
        if !mutation_allowed(&mut es, c.conn, false) {
            return c.non_normal(&mut es, SSL_R_PROTOCOL_IS_SHUTDOWN, F);
        }
        let (rbio, wbio) = es.bios();
        if rbio.is_null() || wbio.is_null() {
            c.non_normal(&mut es, SSL_R_BIO_NOT_SET, F);
            return -1;
        }
        let started = es.conn(c.conn).is_some_and(|r| r.ch.is_some());
        // SAFETY: the owner's live BIO.
        let addressed =
            unsafe { super::caps(wbio) } & u64::from(BIO_DGRAM_CAP_HANDLES_DST_ADDR) != 0;
        if !started && addressed && es.conn(c.conn).is_some_and(|r| r.initial_peer.is_none()) {
            // SAFETY: no preconditions.
            let a = unsafe { crate::bio::addr::BIO_ADDR_new() };
            // SAFETY: the live BIO; a whole address.
            let found = !a.is_null()
                && unsafe { crate::bio::BIO_ctrl(wbio, BIO_CTRL_DGRAM_DETECT_PEER_ADDR, 0, a.cast()) } > 0
                // SAFETY: as above.
                && unsafe { crate::bio::addr::BIO_ADDR_family(a) } != libc::AF_UNSPEC;
            if found && let Some(r) = es.conn(c.conn) {
                // SAFETY: the address the BIO filled.
                r.initial_peer = Some(unsafe { super::peer_of(a) });
            }
            // SAFETY: ours, or NULL.
            unsafe { crate::bio::addr::BIO_ADDR_free(a) };
            if !found {
                c.non_normal(&mut es, SSL_R_REMOTE_PEER_ADDRESS_NOT_SET, F);
                return -1;
            }
        }
    }
    // SAFETY: no lock is held.
    if !unsafe { ensure_started(c) } {
        return -1;
    }
    {
        let mut es = engine.lock();
        if handshake_complete(&mut es, c.conn) {
            return 1;
        }
    }
    // SAFETY: as above.
    unsafe { super::tick(&engine) };
    let mut es = engine.lock();
    if handshake_complete(&mut es, c.conn) {
        return 1;
    }
    if term_any(&mut es, c.conn) {
        return c.non_normal(&mut es, SSL_R_PROTOCOL_IS_SHUTDOWN, F);
    }
    c.normal(&mut es, SSL_ERROR_WANT_READ);
    -1
}

/// `ensure_channel_started`: a client's channel, made on its first handshake call.
///
/// # Safety
/// No lock is held.
unsafe fn ensure_started(c: &Qctx<'_>) -> bool {
    let engine = Arc::clone(c.engine());
    if engine.lock().conn(c.conn).is_some_and(|r| r.ch.is_some()) {
        return true;
    }
    let Some(owner) = owner(&engine.lock()) else {
        return false;
    };
    // SAFETY: the owner is live; no lock is held.
    if !unsafe { ensure_provider(&engine, owner) } {
        let mut es = engine.lock();
        c.non_normal(&mut es, ERR_R_INTERNAL_ERROR, "ensure_channel_started");
        return false;
    }
    let alpn = !c.x.state().alpn.is_empty();
    let sh = Shared::new(alpn);
    super::attach_tls(c.x, &sh);
    let mut es = engine.lock();
    let Some(p) = es.prov.clone() else {
        return false;
    };
    let peer = es
        .conn(c.conn)
        .and_then(|r| r.initial_peer.clone())
        .unwrap_or_default();
    let now = es.now();
    let idle = es
        .conn(c.conn)
        .map_or(rustyssl_quic::channel::DEFAULT_IDLE_TIMEOUT_MS, |r| {
            r.idle_timeout_req
        });
    es.port.channel_config_mut().idle_timeout_ms = idle;
    match es
        .port
        .connect(&*p, Box::new(Hs(Arc::clone(&sh))), peer, now)
    {
        Ok(id) => {
            if let Some(r) = es.conn(c.conn) {
                r.ch = Some(id);
                r.shared = sh;
                r.started = true;
            }
            es.by_channel.insert(id, c.conn);
            true
        }
        Err(_) => {
            c.non_normal(&mut es, ERR_R_INTERNAL_ERROR, "ensure_channel_started");
            false
        }
    }
}

/// `SSL_do_handshake`, `SSL_connect`, `SSL_accept` on a QUIC object.
///
/// # Safety
/// `s` is a live QUIC object; no lock is held.
pub(crate) unsafe fn handshake(s: *mut SSL) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(mut c) = (unsafe { expect(s, C | S) }) else {
        return 0;
    };
    c.begin_io();
    // SAFETY: as above.
    unsafe { do_handshake(&c) }
}

// ---- Events ----

/// `SSL_handle_events`.
///
/// # Safety
/// `q` is a live object's; no lock is held.
pub(crate) unsafe fn handle_events(q: &Quic) -> c_int {
    if q.kind == Kind::Domain {
        for e in domain_members(q) {
            // SAFETY: the caller's guarantee.
            unsafe { super::tick(&e) };
        }
        return 1;
    }
    // SAFETY: the caller's guarantee.
    unsafe { super::tick(&q.engine) };
    1
}

/// `SSL_get_event_timeout`.
///
/// # Safety
/// `tv` and `is_infinite` are writable.
pub(crate) unsafe fn event_timeout(
    q: &Quic,
    tv: *mut libc::timeval,
    is_infinite: *mut c_int,
) -> c_int {
    let es = q.engine.lock();
    let now = es.now();
    let deadline = es.port.next_timeout(now);
    drop(es);
    let (sec, usec, inf) = match deadline {
        None => (1_000_000, 0, 1),
        Some(t) => {
            let d = t.0.saturating_sub(now.0);
            let sec = d / 1_000_000_000;
            let usec = (d % 1_000_000_000) / 1000;
            (sec, usec, 0)
        }
    };
    if !tv.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe {
            (*tv).tv_sec = sec.try_into().unwrap_or(1_000_000);
            (*tv).tv_usec = usec.try_into().unwrap_or(0);
        }
    }
    if !is_infinite.is_null() {
        // SAFETY: as above.
        unsafe { is_infinite.write(inf) };
    }
    1
}

// ---- Errors ----

/// `SSL_get_error` on a QUIC object: `Some` with the answer, or `None` to go on as for TLS.
///
/// # Safety
/// `s` is a live QUIC object.
pub(crate) unsafe fn get_error(s: *const SSL, ret: c_int) -> Option<c_int> {
    if ret > 0 {
        return Some(SSL_ERROR_NONE);
    }
    // SAFETY: the caller's guarantee.
    let c = unsafe { expect(s, C | S | NO_ERROR) }?;
    let mut es = c.engine().lock();
    let last = if c.is_stream {
        es.stream(c.q.key())
            .map_or(SSL_ERROR_NONE, |r| r.last_error)
    } else {
        es.conn(c.conn).map_or(SSL_ERROR_NONE, |r| r.last_error)
    };
    drop(es);
    if last != SSL_ERROR_NONE {
        return Some(last);
    }
    if c.is_stream {
        return Some(SSL_ERROR_SSL);
    }
    // SAFETY: no preconditions.
    let l = unsafe { crate::err::ERR_peek_error() };
    if l != 0 {
        let lib = (l >> rustyssl_abi::ERR_LIB_OFFSET)
            & core::ffi::c_ulong::try_from(rustyssl_abi::ERR_LIB_MASK).unwrap_or(0xff);
        let sys = core::ffi::c_ulong::try_from(rustyssl_abi::ERR_LIB_SYS).unwrap_or(2);
        return Some(if lib == sys {
            SSL_ERROR_SYSCALL
        } else {
            SSL_ERROR_SSL
        });
    }
    Some(SSL_ERROR_SYSCALL)
}

// ---- Streams ----

/// Makes a stream object for stream `id` of connection `conn` (`create_xso_from_stream`),
/// with no lock held.
///
/// # Safety
/// `conn_s` is the live connection; no lock is held.
unsafe fn make_stream(engine: &Arc<Engine>, conn_s: *mut SSL, id: u64) -> *mut SSL {
    // SAFETY: the caller's guarantee.
    let Some(cx) = (unsafe { ssl(conn_s) }) else {
        return ptr::null_mut();
    };
    let ctx = cx.state().ctx;
    // SAFETY: the connection's live context.
    let s = unsafe { crate::ssl::conn::new_ssl(ctx) };
    // SAFETY: the new object, or NULL.
    let Some(x) = (unsafe { ssl(s) }) else {
        return ptr::null_mut();
    };
    // The stream holds a reference to its connection.
    // SAFETY: the live connection.
    unsafe { crate::ssl::conn::rustyssl_private_SSL_up_ref(conn_s) };
    {
        let mut es = engine.lock();
        let (mode, opts) = es.conn(conn_s.addr()).map_or((0, 0), |r| {
            r.streams = r.streams.saturating_add(1);
            (r.default_ssl_mode, r.default_ssl_options)
        });
        es.objs.insert(
            s.addr(),
            Rec::Stream(StreamRec {
                conn: conn_s.addr(),
                conn_s,
                api: StreamApi::new(id, mode, opts),
                last_error: SSL_ERROR_NONE,
            }),
        );
    }
    let _ = x.quic.set(Quic {
        kind: Kind::Stream,
        engine: Arc::clone(engine),
        s,
    });
    s
}

/// `SSL_new_stream` (`quic_conn_stream_new`).
///
/// # Safety
/// `s` is a live QUIC object; no lock is held.
pub(crate) unsafe fn new_stream(s: *mut SSL, flags: u64) -> *mut SSL {
    const F: &str = "quic_conn_stream_new";
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { expect(s, C) }) else {
        return ptr::null_mut();
    };
    let uni = flags & u64::from(SSL_STREAM_FLAG_UNI) != 0;
    let _ = flags & u64::from(SSL_STREAM_FLAG_NO_BLOCK | SSL_STREAM_FLAG_ADVANCE);
    let engine = Arc::clone(c.engine());
    let id = {
        let mut es = engine.lock();
        if !mutation_allowed(&mut es, c.conn, false) {
            c.non_normal(&mut es, SSL_R_PROTOCOL_IS_SHUTDOWN, F);
            return ptr::null_mut();
        }
        let id = es.channel_of(c.conn).and_then(|ch| ch.stream_open(!uni));
        let Some(id) = id else {
            c.non_normal(&mut es, SSL_R_STREAM_COUNT_LIMITED, F);
            return ptr::null_mut();
        };
        if let Some(r) = es.conn(c.conn) {
            r.default_created = true;
        }
        id
    };
    // SAFETY: the live connection; no lock is held.
    unsafe { make_stream(&engine, c.q.s, id) }
}

/// `SSL_accept_stream` (`ossl_quic_accept_stream`).
///
/// # Safety
/// `s` is a live QUIC object; no lock is held.
pub(crate) unsafe fn accept_stream(s: *mut SSL, flags: u64) -> *mut SSL {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { expect(s, C) }) else {
        return ptr::null_mut();
    };
    let engine = Arc::clone(c.engine());
    let _ = flags & u64::from(SSL_ACCEPT_STREAM_NO_BLOCK);
    let uni = flags & u64::from(SSL_ACCEPT_STREAM_UNI) != 0;
    let bidi = flags & u64::from(SSL_ACCEPT_STREAM_BIDI) != 0;
    let id = {
        let mut es = engine.lock();
        if effective_policy(&mut es, c.conn) == SSL_INCOMING_STREAM_POLICY_REJECT {
            c.non_normal(
                &mut es,
                ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED,
                "ossl_quic_accept_stream",
            );
            return ptr::null_mut();
        }
        let now = es.now();
        // One direction only when one is asked for alone.
        let id = es.channel_of(c.conn).and_then(|ch| match (uni, bidi) {
            (true, false) => ch.accept_stream_of(true, now),
            (false, true) => ch.accept_stream_of(false, now),
            _ => ch.accept_stream(now),
        });
        let Some(id) = id else {
            return ptr::null_mut();
        };
        if let Some(r) = es.conn(c.conn) {
            r.default_created = true;
        }
        id
    };
    // SAFETY: the live connection; no lock is held.
    unsafe { make_stream(&engine, c.q.s, id) }
}

/// `qc_get_effective_incoming_stream_policy`.
fn effective_policy(es: &mut EngineState, conn: usize) -> c_int {
    let Some(r) = es.conn(conn) else {
        return SSL_INCOMING_STREAM_POLICY_ACCEPT;
    };
    match r.incoming_policy {
        SSL_INCOMING_STREAM_POLICY_AUTO => {
            if (r.default_stream.is_none() && !r.default_created)
                || r.default_stream_mode == u32::try_from(SSL_DEFAULT_STREAM_MODE_NONE).unwrap_or(0)
            {
                SSL_INCOMING_STREAM_POLICY_ACCEPT
            } else {
                SSL_INCOMING_STREAM_POLICY_REJECT
            }
        }
        p => p,
    }
}

/// `qc_try_create_default_xso_for_write`.
fn default_for_write(c: &Qctx<'_>, es: &mut EngineState) -> bool {
    const F: &str = "qc_try_create_default_xso_for_write";
    let Some(r) = es.conn(c.conn) else {
        return false;
    };
    let none = u32::try_from(SSL_DEFAULT_STREAM_MODE_NONE).unwrap_or(0);
    if r.default_created || r.default_stream_mode == none {
        c.non_normal(es, SSL_R_NO_STREAM, F);
        return false;
    }
    let uni = r.default_stream_mode == u32::try_from(SSL_DEFAULT_STREAM_MODE_AUTO_UNI).unwrap_or(2);
    let (mode, opts) = (r.default_ssl_mode, r.default_ssl_options);
    let Some(id) = es.channel_of(c.conn).and_then(|ch| ch.stream_open(!uni)) else {
        c.non_normal(es, SSL_R_STREAM_COUNT_LIMITED, "quic_conn_stream_new");
        return false;
    };
    if let Some(r) = es.conn(c.conn) {
        r.default_stream = Some(StreamApi::new(id, mode, opts));
        r.default_created = true;
    }
    true
}

/// `qc_wait_for_default_xso_for_read` (non-blocking): 1, or 0 with the error set.
///
/// # Safety
/// No lock is held.
unsafe fn default_for_read(c: &Qctx<'_>, peek: bool) -> bool {
    const F: &str = "qc_wait_for_default_xso_for_read";
    let engine = Arc::clone(c.engine());
    let mut ticked = false;
    loop {
        let mut es = engine.lock();
        let Some(r) = es.conn(c.conn) else {
            return false;
        };
        let none = u32::try_from(SSL_DEFAULT_STREAM_MODE_NONE).unwrap_or(0);
        if r.default_created || r.default_stream_mode == none {
            c.non_normal(&mut es, SSL_R_NO_STREAM, F);
            return false;
        }
        let server = r.server;
        let (mode, opts) = (r.default_ssl_mode, r.default_ssl_options);
        // The peer's first stream: ordinal 0, bidi or uni.
        let first = [u64::from(!server), u64::from(!server) | 2];
        let now = es.now();
        let found = es.channel_of(c.conn).and_then(|ch| {
            first
                .iter()
                .copied()
                .find(|id| ch.streams().get(*id).is_some())
                .inspect(|id| ch.remove_from_accept_queue(*id, now))
        });
        if let Some(id) = found {
            if let Some(r) = es.conn(c.conn) {
                r.default_stream = Some(StreamApi::new(id, mode, opts));
                r.default_created = true;
            }
            return true;
        }
        if peek {
            return false;
        }
        if ticked {
            if term_any(&mut es, c.conn) {
                c.non_normal(&mut es, SSL_R_PROTOCOL_IS_SHUTDOWN, F);
            } else {
                c.normal(&mut es, SSL_ERROR_WANT_READ);
            }
            return false;
        }
        drop(es);
        // SAFETY: no lock is held.
        unsafe { super::tick(&engine) };
        ticked = true;
    }
}

/// `SSL_get_stream_id`: `u64::MAX` without a stream.
pub(crate) fn stream_id(s: *mut SSL) -> u64 {
    // SAFETY: the export's caller passes a live object.
    let Some(c) = (unsafe { expect(s, S) }) else {
        return u64::MAX;
    };
    let mut es = c.engine().lock();
    c.stream_id(&mut es).unwrap_or(u64::MAX)
}

/// `SSL_is_stream_local`: -1 without a stream.
pub(crate) fn is_stream_local(s: *mut SSL) -> c_int {
    // SAFETY: the export's caller passes a live object.
    let Some(c) = (unsafe { expect(s, S) }) else {
        return -1;
    };
    let mut es = c.engine().lock();
    let Some(id) = c.stream_id(&mut es) else {
        return -1;
    };
    let server = es.conn(c.conn).is_some_and(|r| r.server);
    c_int::from(is_server_init(id) == server)
}

/// `SSL_get_stream_type`.
pub(crate) fn stream_type(s: *mut SSL) -> c_int {
    let bidi = c_int::try_from(SSL_STREAM_TYPE_BIDI).unwrap_or(3);
    // SAFETY: the export's caller passes a live object.
    let Some(c) = (unsafe { expect(s, C | S) }) else {
        return bidi;
    };
    let mut es = c.engine().lock();
    let Some(id) = c.stream_id(&mut es) else {
        let none = u32::try_from(SSL_DEFAULT_STREAM_MODE_NONE).unwrap_or(0);
        return match es.conn(c.conn) {
            Some(r) if r.default_created || r.default_stream_mode == none => {
                c_int::try_from(SSL_STREAM_TYPE_NONE).unwrap_or(0)
            }
            _ => bidi,
        };
    };
    if !is_uni(id) {
        return bidi;
    }
    let server = es.conn(c.conn).is_some_and(|r| r.server);
    if is_server_init(id) != server {
        c_int::try_from(SSL_STREAM_TYPE_READ).unwrap_or(1)
    } else {
        c_int::try_from(SSL_STREAM_TYPE_WRITE).unwrap_or(2)
    }
}

// ---- Data ----

/// `SSL_write_ex2` and friends on a QUIC object (`ossl_quic_write_flags`).
///
/// # Safety
/// `s` is a live QUIC object; `buf` holds `len` octets; no lock is held.
pub(crate) unsafe fn write(
    s: *mut SSL,
    buf: *const c_void,
    len: usize,
    flags: u64,
    written: &mut usize,
) -> c_int {
    const F: &str = "ossl_quic_write_flags";
    *written = 0;
    // SAFETY: the caller's guarantee.
    let Some(mut c) = (unsafe { expect(s, C | S) }) else {
        return 0;
    };
    c.begin_io();
    let engine = Arc::clone(c.engine());
    if flags & !u64::from(SSL_WRITE_FLAG_CONCLUDE) != 0 {
        let mut es = engine.lock();
        return c.non_normal(&mut es, SSL_R_UNSUPPORTED_WRITE_FLAG, F);
    }
    {
        let mut es = engine.lock();
        if !mutation_allowed(&mut es, c.conn, false) {
            return c.non_normal(&mut es, SSL_R_PROTOCOL_IS_SHUTDOWN, F);
        }
    }
    // SAFETY: no lock is held.
    if unsafe { do_handshake(&c) } < 1 {
        return 0;
    }
    let mut es = engine.lock();
    if len > 0 && c.stream_id(&mut es).is_none() && !c.is_stream && !default_for_write(&c, &mut es)
    {
        return 0;
    }
    let Some(id) = c.stream_id(&mut es) else {
        if len == 0 {
            return 1;
        }
        return c.non_normal(&mut es, SSL_R_NO_STREAM, F);
    };
    let conclude = flags & u64::from(SSL_WRITE_FLAG_CONCLUDE) != 0;
    if let Err(r) = validate_for_write(&mut es, c.conn, id) {
        if len > 0 {
            return c.non_normal(&mut es, r, F);
        }
    }
    if len == 0 {
        if conclude && let Some(ch) = es.channel_of(c.conn) {
            let _ = ch.stream_send(id, &[], true);
        }
        drop(es);
        // SAFETY: no lock is held.
        unsafe { super::tick(&engine) };
        return 1;
    }
    // SAFETY: the caller's guarantee: `len` readable octets.
    let data = unsafe { core::slice::from_raw_parts(buf.cast::<u8>(), len) };
    let Some(api) = c.stream_api(&mut es) else {
        return c.non_normal(&mut es, ERR_R_INTERNAL_ERROR, F);
    };
    let partial = api.ssl_mode & SSL_MODE_ENABLE_PARTIAL_WRITE != 0;
    let moving = api.ssl_mode & SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER != 0;
    let aon = api.aon;
    // An all-or-nothing write in progress goes on from where it was.
    let skip = match aon {
        Some((base, l, pos)) => {
            if (!moving && base != buf.addr()) || l != len {
                return c.non_normal(&mut es, SSL_R_BAD_WRITE_RETRY, "quic_write_nonblocking_aon");
            }
            pos
        }
        None => 0,
    };
    let rest = data.get(skip..).unwrap_or_default();
    let n = match es
        .channel_of(c.conn)
        .map(|ch| ch.stream_send(id, rest, false))
    {
        Some(Ok(n)) => n,
        _ => return c.non_normal(&mut es, ERR_R_INTERNAL_ERROR, F),
    };
    let all = n == rest.len();
    if all
        && conclude
        && let Some(ch) = es.channel_of(c.conn)
    {
        let _ = ch.stream_send(id, &[], true);
    }
    drop(es);
    // SAFETY: no lock is held.
    unsafe { super::tick(&engine) };
    let mut es = engine.lock();
    let Some(api) = c.stream_api(&mut es) else {
        return 0;
    };
    if partial {
        api.aon = None;
        *written = n;
        if n == 0 {
            return c.normal(&mut es, SSL_ERROR_WANT_WRITE);
        }
        return 1;
    }
    if all {
        *written = len;
        api.aon = None;
        return 1;
    }
    let pos = skip.saturating_add(n);
    if aon.is_some() || n > 0 {
        api.aon = Some((buf.addr(), len, pos));
    }
    c.normal(&mut es, SSL_ERROR_WANT_WRITE)
}

/// `quic_validate_for_write`: the reason a stream can't be written.
fn validate_for_write(es: &mut EngineState, conn: usize, id: u64) -> Result<(), c_int> {
    let Some(ch) = es.channel_of(conn) else {
        return Err(ERR_R_INTERNAL_ERROR);
    };
    let Some(st) = ch.streams().get(id) else {
        return Err(ERR_R_INTERNAL_ERROR);
    };
    let Some(sp) = st.send.as_ref() else {
        return Err(SSL_R_STREAM_RECV_ONLY);
    };
    match sp.state {
        SendState::Ready | SendState::Send | SendState::DataSent => {
            if sp.buf.is_finished() {
                Err(SSL_R_STREAM_FINISHED)
            } else {
                Ok(())
            }
        }
        SendState::DataRecvd => Err(SSL_R_STREAM_FINISHED),
        SendState::ResetSent | SendState::ResetRecvd => Err(SSL_R_STREAM_RESET),
    }
}

/// What reading a stream found (`quic_validate_for_read`).
enum ReadCheck {
    Ok,
    Eos,
    Err(c_int),
}

fn validate_for_read(es: &mut EngineState, conn: usize, id: u64) -> ReadCheck {
    let Some(ch) = es.channel_of(conn) else {
        return ReadCheck::Err(ERR_R_INTERNAL_ERROR);
    };
    let Some(st) = ch.streams().get(id) else {
        // A stream that's gone was read to its end.
        return ReadCheck::Eos;
    };
    let Some(rp) = st.recv.as_ref() else {
        return ReadCheck::Err(SSL_R_STREAM_SEND_ONLY);
    };
    match rp.state {
        RecvState::Recv | RecvState::SizeKnown | RecvState::DataRecvd => ReadCheck::Ok,
        RecvState::DataRead => ReadCheck::Eos,
        RecvState::ResetRecvd | RecvState::ResetRead => ReadCheck::Err(SSL_R_STREAM_RESET),
    }
}

/// `quic_read_actual`: 1 (perhaps with nothing read), or 0 with the error set.
fn read_actual(
    c: &Qctx<'_>,
    es: &mut EngineState,
    id: u64,
    buf: &mut [u8],
    peek: bool,
    n: &mut usize,
) -> c_int {
    const F: &str = "quic_read_actual";
    match validate_for_read(es, c.conn, id) {
        ReadCheck::Ok => {}
        ReadCheck::Eos => return c.normal(es, SSL_ERROR_ZERO_RETURN),
        ReadCheck::Err(r) => return c.non_normal(es, r, F),
    }
    let now = es.now();
    let Some(ch) = es.channel_of(c.conn) else {
        return c.non_normal(es, ERR_R_INTERNAL_ERROR, F);
    };
    let r = if peek {
        ch.stream_peek(id, buf)
    } else {
        ch.stream_recv(id, buf, now)
    };
    let Ok((got, fin)) = r else {
        return c.non_normal(es, ERR_R_INTERNAL_ERROR, F);
    };
    *n = got;
    if got == 0 && fin {
        return c.normal(es, SSL_ERROR_ZERO_RETURN);
    }
    1
}

/// `SSL_read_ex` and `SSL_peek_ex` on a QUIC object (`quic_read`).
///
/// # Safety
/// `s` is a live QUIC object; `buf` has room for `len` octets; no lock is held.
pub(crate) unsafe fn read(
    s: *mut SSL,
    buf: *mut c_void,
    len: usize,
    peek: bool,
    n: &mut usize,
) -> c_int {
    *n = 0;
    // SAFETY: the caller's guarantee.
    let Some(mut c) = (unsafe { expect(s, C | S) }) else {
        return 0;
    };
    c.begin_io();
    // SAFETY: no lock is held.
    if unsafe { do_handshake(&c) } < 1 {
        return 0;
    }
    let engine = Arc::clone(c.engine());
    let has = {
        let mut es = engine.lock();
        c.stream_id(&mut es).is_some()
    };
    // SAFETY: no lock is held.
    if !has && !unsafe { default_for_read(&c, false) } {
        return 0;
    }
    let out: &mut [u8] = if len == 0 || buf.is_null() {
        &mut []
    } else {
        // SAFETY: the caller's guarantee: room for `len` octets.
        unsafe { core::slice::from_raw_parts_mut(buf.cast::<u8>(), len) }
    };
    for attempt in 0..2 {
        let mut es = engine.lock();
        let Some(id) = c.stream_id(&mut es) else {
            return 0;
        };
        if read_actual(&c, &mut es, id, out, peek, n) == 0 {
            return 0;
        }
        if *n > 0 {
            drop(es);
            // SAFETY: no lock is held.
            unsafe { super::tick(&engine) };
            return 1;
        }
        if !mutation_allowed(&mut es, c.conn, false) {
            return c.non_normal(&mut es, SSL_R_PROTOCOL_IS_SHUTDOWN, "quic_read");
        }
        if attempt == 1 {
            return c.normal(&mut es, SSL_ERROR_WANT_READ);
        }
        drop(es);
        // SAFETY: no lock is held.
        unsafe { super::tick(&engine) };
    }
    0
}

// ---- Listeners ----

/// `SSL_listen`.
pub(crate) fn listen(s: *mut SSL) -> c_int {
    // SAFETY: the export's caller passes a live object.
    let Some(mut c) = (unsafe { expect(s, L) }) else {
        return 0;
    };
    c.begin_io();
    let mut es = c.engine().lock();
    if let Some(l) = es.listener_rec(c.q.key()) {
        l.listening = true;
    }
    1
}

/// `SSL_accept_connection` (non-blocking).
///
/// # Safety
/// `s` is a live QUIC object; no lock is held.
pub(crate) unsafe fn accept_connection(s: *mut SSL, flags: u64) -> *mut SSL {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { expect(s, L) }) else {
        return ptr::null_mut();
    };
    let _ = flags & u64::from(SSL_ACCEPT_CONNECTION_NO_BLOCK);
    let engine = Arc::clone(c.engine());
    listen(s);
    for attempt in 0..2 {
        {
            let mut es = engine.lock();
            if let Some(conn) = es.accept_queue.pop_front() {
                // The connection now holds a reference to its listener.
                // SAFETY: the live listener.
                unsafe { crate::ssl::conn::rustyssl_private_SSL_up_ref(s) };
                if let Some(r) = es.conn(conn.addr()) {
                    r.listener = s;
                }
                return conn;
            }
        }
        if attempt == 0 {
            // SAFETY: no lock is held.
            unsafe { super::tick(&engine) };
        }
    }
    ptr::null_mut()
}

/// `SSL_get_accept_connection_queue_len`.
pub(crate) fn accept_queue_len(s: *mut SSL) -> usize {
    // SAFETY: the export's caller passes a live object.
    let Some(c) = (unsafe { expect(s, L) }) else {
        return 0;
    };
    c.engine().lock().accept_queue.len()
}

// ---- Settings ----

/// `SSL_set1_initial_peer_addr`.
///
/// # Safety
/// `peer` is NULL or a live address.
pub(crate) unsafe fn set_initial_peer(s: *mut SSL, peer: *const BIO_ADDR) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { expect(s, C | S) }) else {
        return 0;
    };
    let mut es = c.engine().lock();
    let started = es.conn(c.conn).is_some_and(|r| r.ch.is_some());
    if started {
        return c.non_normal(
            &mut es,
            ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED,
            "ossl_quic_conn_set_initial_peer_addr",
        );
    }
    let p = if peer.is_null() {
        None
    } else {
        // SAFETY: the caller's guarantee.
        Some(unsafe { super::peer_of(peer) })
    };
    if let Some(r) = es.conn(c.conn) {
        r.initial_peer = p;
    }
    1
}

/// Whether the network BIOs can block (they have poll descriptors).
fn can_block(es: &EngineState) -> bool {
    let (r, w) = es.bios();
    let pollable = |b| {
        if b == ptr::null_mut() {
            return false;
        }
        let mut d: rustyssl_abi::BIO_POLL_DESCRIPTOR =
            // SAFETY: an all-zero descriptor is the empty one.
            unsafe { core::mem::zeroed() };
        // SAFETY: a live BIO; a whole descriptor.
        (unsafe { crate::bio::BIO_get_rpoll_descriptor(b, &raw mut d) }) == 1
            && c_int::try_from(d.type_)
                .is_ok_and(|t| t != rustyssl_abi::BIO_POLL_DESCRIPTOR_TYPE_NONE)
    };
    pollable(r) && pollable(w)
}

/// `SSL_get_blocking_mode`.
pub(crate) fn get_blocking(q: &Quic) -> c_int {
    let es = q.engine.lock();
    c_int::from(es.desires_blocking && can_block(&es))
}

/// `SSL_set_blocking_mode`.
pub(crate) fn set_blocking(q: &Quic, blocking: c_int) -> c_int {
    let mut es = q.engine.lock();
    if blocking != 0 && !can_block(&es) {
        err::raise(
            ERR_LIB_SSL,
            ERR_R_UNSUPPORTED,
            "ossl_quic_conn_set_blocking_mode",
        );
        return 0;
    }
    es.desires_blocking = blocking != 0;
    1
}

/// `SSL_get0_connection`.
pub(crate) fn get0_connection(s: *mut SSL) -> *mut SSL {
    // SAFETY: the export's caller passes a live object.
    let Some(c) = (unsafe { expect(s, C | S) }) else {
        return ptr::null_mut();
    };
    if c.is_stream {
        c.engine()
            .lock()
            .stream(c.q.key())
            .map_or(ptr::null_mut(), |r| r.conn_s)
    } else {
        s
    }
}

/// `SSL_get0_listener`.
pub(crate) fn get0_listener(s: *mut SSL) -> *mut SSL {
    // SAFETY: the export's caller passes a live object.
    let Some(c) = (unsafe { expect(s, C | S | L) }) else {
        return ptr::null_mut();
    };
    if c.q.kind == Kind::Listener {
        return s;
    }
    let mut es = c.engine().lock();
    if es.listener {
        es.owner
    } else {
        let _ = es.conn(c.conn);
        ptr::null_mut()
    }
}

/// `SSL_set_default_stream_mode`.
pub(crate) fn set_default_stream_mode(s: *mut SSL, mode: u32) -> c_int {
    // SAFETY: the export's caller passes a live object.
    let Some(c) = (unsafe { expect(s, C) }) else {
        return 0;
    };
    let mut es = c.engine().lock();
    let Some(r) = es.conn(c.conn) else { return 0 };
    if r.default_created {
        return c.non_normal(
            &mut es,
            ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED,
            "ossl_quic_set_default_stream_mode",
        );
    }
    let ok = [
        SSL_DEFAULT_STREAM_MODE_NONE,
        rustyssl_abi::SSL_DEFAULT_STREAM_MODE_AUTO_BIDI,
        SSL_DEFAULT_STREAM_MODE_AUTO_UNI,
    ]
    .iter()
    .any(|&m| u32::try_from(m).is_ok_and(|m| m == mode));
    if !ok {
        return c.non_normal(
            &mut es,
            ERR_R_PASSED_INVALID_ARGUMENT,
            "ossl_quic_set_default_stream_mode",
        );
    }
    r.default_stream_mode = mode;
    1
}

/// `SSL_set_incoming_stream_policy`.
pub(crate) fn set_incoming_stream_policy(s: *mut SSL, policy: c_int, aec: u64) -> c_int {
    // SAFETY: the export's caller passes a live object.
    let Some(c) = (unsafe { expect(s, C) }) else {
        return 0;
    };
    let mut es = c.engine().lock();
    match policy {
        SSL_INCOMING_STREAM_POLICY_AUTO
        | SSL_INCOMING_STREAM_POLICY_ACCEPT
        | SSL_INCOMING_STREAM_POLICY_REJECT => {
            if let Some(r) = es.conn(c.conn) {
                r.incoming_policy = policy;
                r.incoming_aec = aec;
            }
            1
        }
        _ => c.non_normal(
            &mut es,
            ERR_R_PASSED_INVALID_ARGUMENT,
            "ossl_quic_set_incoming_stream_policy",
        ),
    }
}

/// `SSL_get_accept_stream_queue_len`.
pub(crate) fn accept_stream_queue_len(s: *mut SSL) -> usize {
    // SAFETY: the export's caller passes a live object.
    let Some(c) = (unsafe { expect(s, C) }) else {
        return 0;
    };
    let mut es = c.engine().lock();
    es.channel_of(c.conn)
        .map_or(0, |ch| ch.streams().accept_queue_len())
}

/// Whether `ctx` has a QUIC method (`IS_QUIC_CTX`).
///
/// # Safety
/// `ctx` is NULL or a live context.
pub(crate) unsafe fn is_quic_ctx(ctx: *mut SSL_CTX) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { crate::ssl::ctx::ctx(ctx) }.is_some_and(|c| c.state().method.quic)
}

/// `SSL_connect` and `SSL_accept` (`ossl_quic_connect`, `ossl_quic_accept`): the role must be
/// the connection's, then the handshake.
///
/// # Safety
/// `s` is a live QUIC object; no lock is held.
unsafe fn handshake_as(s: *mut SSL, server: bool) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { expect(s, C) }) else {
        return -1;
    };
    {
        let mut es = c.engine().lock();
        let Some(r) = es.conn(c.conn) else { return -1 };
        if r.as_server_state != server {
            if r.ch.is_some() {
                drop(es);
                err::raise(
                    ERR_LIB_SSL,
                    rustyssl_abi::SSL_R_INVALID_COMMAND,
                    "ossl_quic_set_connect_state",
                );
                return -1;
            }
            r.as_server_state = server;
        }
    }
    // SAFETY: as above.
    unsafe { handshake(s) }
}

/// `SSL_connect`.
///
/// # Safety
/// `s` is a live QUIC object; no lock is held.
pub(crate) unsafe fn connect(s: *mut SSL) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { handshake_as(s, false) }
}

/// `SSL_accept`.
///
/// # Safety
/// `s` is a live QUIC object; no lock is held.
pub(crate) unsafe fn accept(s: *mut SSL) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { handshake_as(s, true) }
}

/// `SSL_net_read_desired`: whether the port reads (it does while it has a live channel or
/// listens).
pub(crate) fn net_read_desired(q: &Quic) -> c_int {
    let mut es = q.engine.lock();
    let listening = es
        .objs
        .values()
        .any(|r| matches!(r, Rec::Listener(l) if l.listening));
    let ids: Vec<u64> = es.port.channel_ids();
    let live = ids.into_iter().any(|id| {
        es.port
            .channel(id)
            .is_some_and(|ch| ch.state() != State::Terminated)
    });
    c_int::from(listening || live)
}

/// `SSL_net_write_desired`: whether datagrams wait for the network (never: a tick sends all it
/// can, and a full BIO drops them as a lossy network does).
pub(crate) fn net_write_desired(_q: &Quic) -> c_int {
    0
}

/// `SSL_get0_domain`: no QUIC object here belongs to a domain.
pub(crate) fn get0_domain(s: *mut SSL) -> *mut SSL {
    // SAFETY: the export's caller passes a live object.
    let Some(c) = (unsafe { expect(s, C | S | L | D) }) else {
        return ptr::null_mut();
    };
    if c.q.kind == Kind::Domain {
        return s;
    }
    c.engine().lock().domain
}

/// `expect_quic_with_stream_lock(s, remote_init=0)`: a stream object, or a connection whose
/// default stream is made for writing if it has none yet (after the handshake).
///
/// # Safety
/// `s` is a live QUIC object; no lock is held.
unsafe fn expect_auto_write<'a>(s: *mut SSL) -> Option<Qctx<'a>> {
    // SAFETY: the caller's guarantee.
    let c = unsafe { expect(s, C | S) }?;
    if c.is_stream {
        return Some(c);
    }
    let has = {
        let mut es = c.engine().lock();
        c.stream_id(&mut es).is_some()
    };
    if !has {
        {
            let mut es = c.engine().lock();
            if !mutation_allowed(&mut es, c.conn, false) {
                c.non_normal(&mut es, SSL_R_PROTOCOL_IS_SHUTDOWN, "expect_quic_as");
                return None;
            }
        }
        // SAFETY: no lock is held.
        if unsafe { do_handshake(&c) } < 1 {
            return None;
        }
        let mut es = c.engine().lock();
        if !default_for_write(&c, &mut es) {
            return None;
        }
    }
    Some(c)
}

/// `SSL_stream_conclude` (`ossl_quic_conn_stream_conclude`).
///
/// # Safety
/// `s` is a live QUIC object; no lock is held.
pub(crate) unsafe fn stream_conclude(s: *mut SSL, _flags: u64) -> c_int {
    const F: &str = "ossl_quic_conn_stream_conclude";
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { expect_auto_write(s) }) else {
        return 0;
    };
    let engine = Arc::clone(c.engine());
    {
        let mut es = engine.lock();
        let Some(id) = c.stream_id(&mut es) else {
            return 0;
        };
        if !mutation_allowed(&mut es, c.conn, true) {
            return c.non_normal(&mut es, SSL_R_PROTOCOL_IS_SHUTDOWN, F);
        }
        if let Err(r) = validate_for_write(&mut es, c.conn, id) {
            return c.non_normal(&mut es, r, F);
        }
        if let Some(ch) = es.channel_of(c.conn) {
            let _ = ch.stream_send(id, &[], true);
        }
    }
    // SAFETY: no lock is held.
    unsafe { super::tick(&engine) };
    1
}

/// `SSL_stream_reset` (`ossl_quic_stream_reset`).
///
/// # Safety
/// `s` is a live QUIC object; `args` NULL or readable; no lock is held.
pub(crate) unsafe fn stream_reset(
    s: *mut SSL,
    args: *const rustyssl_abi::SSL_STREAM_RESET_ARGS,
    _args_len: usize,
) -> c_int {
    const F: &str = "ossl_quic_stream_reset";
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { expect_auto_write(s) }) else {
        return 0;
    };
    let code = if args.is_null() {
        0
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { (*args).quic_error_code }
    };
    let engine = Arc::clone(c.engine());
    let mut es = engine.lock();
    let Some(id) = c.stream_id(&mut es) else {
        return 0;
    };
    if let Err(r) = validate_for_write(&mut es, c.conn, id) {
        return c.non_normal(&mut es, r, F);
    }
    let ok = es
        .channel_of(c.conn)
        .is_some_and(|ch| ch.stream_reset(id, code).is_ok());
    drop(es);
    // SAFETY: no lock is held.
    unsafe { super::tick(&engine) };
    c_int::from(ok)
}

/// `quic_classify_stream`: a stream direction's state and its error code.
fn classify(es: &mut EngineState, conn: usize, id: u64, write: bool) -> (c_int, u64) {
    use rustyssl_abi::{
        SSL_STREAM_STATE_CONN_CLOSED, SSL_STREAM_STATE_FINISHED, SSL_STREAM_STATE_OK,
        SSL_STREAM_STATE_RESET_LOCAL, SSL_STREAM_STATE_RESET_REMOTE, SSL_STREAM_STATE_WRONG_DIR,
    };
    let server = es.conn(conn).is_some_and(|r| r.server);
    let local = is_server_init(id) == server;
    if is_uni(id) && local != write {
        return (SSL_STREAM_STATE_WRONG_DIR, u64::MAX);
    }
    if term_any(es, conn) {
        return (SSL_STREAM_STATE_CONN_CLOSED, u64::MAX);
    }
    let Some(ch) = es.channel_of(conn) else {
        return (SSL_STREAM_STATE_OK, u64::MAX);
    };
    let Some(st) = ch.streams().get(id) else {
        // Gone: both parts finished.
        return (SSL_STREAM_STATE_FINISHED, u64::MAX);
    };
    if write {
        let Some(p) = st.send.as_ref() else {
            return (SSL_STREAM_STATE_WRONG_DIR, u64::MAX);
        };
        if let Some(code) = p.reset_code {
            return (SSL_STREAM_STATE_RESET_LOCAL, code);
        }
        if let Some(code) = p.peer_stop_sending {
            return (SSL_STREAM_STATE_RESET_REMOTE, code);
        }
        if p.buf.is_finished() {
            return (SSL_STREAM_STATE_FINISHED, u64::MAX);
        }
        (SSL_STREAM_STATE_OK, u64::MAX)
    } else {
        let Some(p) = st.recv.as_ref() else {
            return (SSL_STREAM_STATE_WRONG_DIR, u64::MAX);
        };
        if p.state == RecvState::DataRead {
            return (SSL_STREAM_STATE_FINISHED, u64::MAX);
        }
        if let Some(code) = p.stop_sending {
            return (SSL_STREAM_STATE_RESET_LOCAL, code);
        }
        if let Some(code) = p.reset_code {
            return (SSL_STREAM_STATE_RESET_REMOTE, code);
        }
        (SSL_STREAM_STATE_OK, u64::MAX)
    }
}

/// `SSL_get_stream_read_state` and `_write_state`.
pub(crate) fn stream_state(s: *mut SSL, write: bool) -> c_int {
    // SAFETY: the export's caller passes a live object.
    let Some(c) = (unsafe { expect(s, S) }) else {
        return rustyssl_abi::SSL_STREAM_STATE_NONE;
    };
    let mut es = c.engine().lock();
    let Some(id) = c.stream_id(&mut es) else {
        return rustyssl_abi::SSL_STREAM_STATE_NONE;
    };
    classify(&mut es, c.conn, id, write).0
}

/// `SSL_get_stream_read_error_code` and `_write_error_code`.
///
/// # Safety
/// `code` is NULL or writable.
pub(crate) unsafe fn stream_error_code(s: *mut SSL, write: bool, code: *mut u64) -> c_int {
    use rustyssl_abi::{
        SSL_STREAM_STATE_FINISHED, SSL_STREAM_STATE_RESET_LOCAL, SSL_STREAM_STATE_RESET_REMOTE,
    };
    // SAFETY: the export's caller passes a live object.
    let Some(c) = (unsafe { expect(s, S) }) else {
        return -1;
    };
    let mut es = c.engine().lock();
    let Some(id) = c.stream_id(&mut es) else {
        return -1;
    };
    let (state, aec) = classify(&mut es, c.conn, id, write);
    if !code.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { code.write(aec) };
    }
    match state {
        SSL_STREAM_STATE_FINISHED => 0,
        SSL_STREAM_STATE_RESET_LOCAL | SSL_STREAM_STATE_RESET_REMOTE => 1,
        _ => -1,
    }
}

/// `SSL_get_conn_close_info`.
///
/// # Safety
/// `info` is NULL or writable.
pub(crate) unsafe fn conn_close_info(
    s: *mut SSL,
    info: *mut rustyssl_abi::SSL_CONN_CLOSE_INFO,
    _info_len: usize,
) -> c_int {
    use rustyssl_abi::{SSL_CONN_CLOSE_FLAG_LOCAL, SSL_CONN_CLOSE_FLAG_TRANSPORT};
    // SAFETY: the export's caller passes a live object.
    let Some(c) = (unsafe { expect(s, C) }) else {
        return -1;
    };
    let mut es = c.engine().lock();
    let Some(tc) = es
        .channel_of(c.conn)
        .and_then(|ch| ch.terminate_cause().cloned())
    else {
        return 0;
    };
    let Some(r) = es.conn(c.conn) else { return 0 };
    // The reason stays at a fixed address, NUL-terminated, while the connection lives.
    let same = r
        .close_reason
        .as_ref()
        .is_some_and(|v| v.split_last().map(|(_, b)| b) == Some(tc.reason.as_slice()));
    if !same {
        let mut v = tc.reason.clone();
        v.push(0);
        r.close_reason = Some(v);
    }
    let reason = r
        .close_reason
        .as_ref()
        .map_or(ptr::null(), |v| v.as_ptr().cast());
    if info.is_null() {
        return 1;
    }
    let mut flags = 0u32;
    if !tc.remote {
        flags |= SSL_CONN_CLOSE_FLAG_LOCAL;
    }
    if !tc.app {
        flags |= SSL_CONN_CLOSE_FLAG_TRANSPORT;
    }
    // SAFETY: the caller's guarantee.
    unsafe {
        (*info).error_code = tc.code;
        (*info).frame_type = tc.frame_type;
        (*info).reason = reason;
        (*info).reason_len = tc.reason.len();
        (*info).flags = flags;
    }
    1
}

/// `SSL_new_listener_from`: listeners on a domain (none here: no object is a domain).
pub(crate) fn new_listener_from(s: *mut SSL, flags: u64) -> *mut SSL {
    // SAFETY: the export's caller passes a live object.
    let Some(c) = (unsafe { expect(s, D) }) else {
        return ptr::null_mut();
    };
    let ctx = c.x.state().ctx;
    // SAFETY: the domain's live context.
    let l = unsafe { new_listener(ctx, flags) };
    // SAFETY: the new listener, or NULL.
    let Some(lq) = (unsafe { super::of(l) }) else {
        return ptr::null_mut();
    };
    // The listener holds a reference to its domain.
    // SAFETY: the live domain.
    unsafe { crate::ssl::conn::rustyssl_private_SSL_up_ref(s) };
    let flags = c.engine().lock().domain_flags;
    {
        let mut es = lq.engine.lock();
        es.domain = s;
        es.domain_flags = flags;
    }
    if let Some(Rec::Domain(d)) = c.engine().lock().objs.get_mut(&c.q.key()) {
        d.members.push(Arc::downgrade(&lq.engine));
    }
    l
}

/// `SSL_new_from_listener`: a client connection on a listener's port.
///
/// # Safety
/// `s` is a live QUIC object; no lock is held.
pub(crate) unsafe fn new_from_listener(s: *mut SSL, flags: u64) -> *mut SSL {
    if flags != 0 {
        return ptr::null_mut();
    }
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { expect(s, L) }) else {
        return ptr::null_mut();
    };
    let engine = Arc::clone(c.engine());
    let ctx = c.x.state().ctx;
    // SAFETY: the listener's live context.
    let n = unsafe { crate::ssl::conn::new_ssl(ctx) };
    // SAFETY: the new object, or NULL.
    let Some(x) = (unsafe { ssl(n) }) else {
        return ptr::null_mut();
    };
    // SAFETY: the new connection.
    unsafe { crate::ssl::conn::rustyssl_private_SSL_set_connect_state(n) };
    // The connection holds a reference to its listener.
    // SAFETY: the live listener.
    unsafe { crate::ssl::conn::rustyssl_private_SSL_up_ref(s) };
    let mode = x.state().mode;
    // SAFETY: the listener's live context.
    let ctx_options = unsafe { crate::ssl::ctx::ctx(ctx) }.map_or(0, |c| c.state().options);
    {
        let mut es = engine.lock();
        let mut r = ConnRec::new(n, Shared::new(false), false, mode);
        init_options(x, &mut r, ctx_options);
        r.listener = s;
        es.objs.insert(n.addr(), Rec::Conn(r));
    }
    let _ = x.quic.set(Quic {
        kind: Kind::Conn,
        engine,
        s: n,
    });
    n
}

/// `SSL_new_domain` (`ossl_quic_new_domain`): an object whose listeners share its domain
/// flags, and which ticks them all.
///
/// # Safety
/// `ctx` is a live QUIC context.
pub(crate) unsafe fn new_domain(ctx: *mut SSL_CTX, flags: u64) -> *mut SSL {
    use rustyssl_abi::{
        SSL_DOMAIN_FLAG_MULTI_THREAD, SSL_DOMAIN_FLAG_SINGLE_THREAD,
        SSL_DOMAIN_FLAG_THREAD_ASSISTED,
    };
    // SAFETY: the caller's guarantee.
    let Some(cx) = (unsafe { crate::ssl::ctx::ctx(ctx) }) else {
        return ptr::null_mut();
    };
    let ctx_flags = cx.state().domain_flags;
    let threading = u64::from(
        SSL_DOMAIN_FLAG_SINGLE_THREAD
            | SSL_DOMAIN_FLAG_MULTI_THREAD
            | SSL_DOMAIN_FLAG_THREAD_ASSISTED,
    );
    let wanted = if flags & threading != 0 {
        flags
    } else {
        ctx_flags | flags
    };
    let Some(domain_flags) = adjust_domain_flags(wanted) else {
        return ptr::null_mut();
    };
    // SAFETY: the caller's guarantee.
    let s = unsafe { crate::ssl::conn::new_ssl(ctx) };
    // SAFETY: the new object, or NULL.
    let Some(x) = (unsafe { ssl(s) }) else {
        return ptr::null_mut();
    };
    let engine = Engine::new(ctx, false, false);
    {
        let mut es = engine.lock();
        es.domain_flags = domain_flags;
        es.objs.insert(
            s.addr(),
            Rec::Domain(super::DomainRec {
                members: Vec::new(),
            }),
        );
    }
    let _ = x.quic.set(Quic {
        kind: Kind::Domain,
        engine,
        s,
    });
    s
}

/// The engines of a domain's listeners, still alive.
pub(crate) fn domain_members(q: &Quic) -> Vec<Arc<Engine>> {
    match q.engine.lock().objs.get(&q.key()) {
        Some(Rec::Domain(d)) => d
            .members
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .collect(),
        _ => Vec::new(),
    }
}

/// `SSL_get_value_uint` (`ossl_quic_get_value_uint`).
///
/// # Safety
/// `value` is NULL or writable.
pub(crate) unsafe fn get_value(s: *mut SSL, class: u32, id: u32, value: *mut u64) -> c_int {
    let (class, id) = (
        c_int::try_from(class).unwrap_or(-1),
        c_int::try_from(id).unwrap_or(-1),
    );
    // SAFETY: the export's caller passes a live object.
    let Some(c) = (unsafe { expect_for_value(s, id) }) else {
        return 0;
    };
    if value.is_null() {
        let mut es = c.engine().lock();
        return c.non_normal(
            &mut es,
            ERR_R_PASSED_INVALID_ARGUMENT,
            "ossl_quic_get_value_uint",
        );
    }
    match getset(&c, class, id, None) {
        Some(v) => {
            // SAFETY: the caller's guarantee.
            unsafe { value.write(v) };
            1
        }
        None => 0,
    }
}

/// `SSL_set_value_uint` (`ossl_quic_set_value_uint`).
pub(crate) fn set_value(s: *mut SSL, class: u32, id: u32, value: u64) -> c_int {
    let (class, id) = (
        c_int::try_from(class).unwrap_or(-1),
        c_int::try_from(id).unwrap_or(-1),
    );
    use rustyssl_abi::{
        SSL_VALUE_EVENT_HANDLING_MODE, SSL_VALUE_QUIC_IDLE_TIMEOUT,
        SSL_VALUE_QUIC_MAX_PENDING_CONNS,
    };
    // SAFETY: the export's caller passes a live object.
    let Some(c) = (unsafe { expect_for_value(s, id) }) else {
        return 0;
    };
    match id {
        SSL_VALUE_QUIC_IDLE_TIMEOUT
        | SSL_VALUE_EVENT_HANDLING_MODE
        | SSL_VALUE_QUIC_MAX_PENDING_CONNS => {
            c_int::from(getset(&c, class, id, Some(value)).is_some())
        }
        _ => {
            let mut es = c.engine().lock();
            c.non_normal(
                &mut es,
                rustyssl_abi::SSL_R_UNSUPPORTED_CONFIG_VALUE,
                "ossl_quic_set_value_uint",
            )
        }
    }
}

/// `expect_quic_for_value`.
///
/// # Safety
/// `s` is NULL or a live `SSL`.
unsafe fn expect_for_value<'a>(s: *mut SSL, id: c_int) -> Option<Qctx<'a>> {
    use rustyssl_abi::{
        SSL_VALUE_EVENT_HANDLING_MODE, SSL_VALUE_QUIC_MAX_PENDING_CONNS,
        SSL_VALUE_STREAM_WRITE_BUF_AVAIL, SSL_VALUE_STREAM_WRITE_BUF_SIZE,
        SSL_VALUE_STREAM_WRITE_BUF_USED,
    };
    let flags = match id {
        SSL_VALUE_EVENT_HANDLING_MODE
        | SSL_VALUE_STREAM_WRITE_BUF_SIZE
        | SSL_VALUE_STREAM_WRITE_BUF_USED
        | SSL_VALUE_STREAM_WRITE_BUF_AVAIL => C | S,
        SSL_VALUE_QUIC_MAX_PENDING_CONNS => C | L,
        _ => C,
    };
    // SAFETY: the caller's guarantee.
    unsafe { expect(s, flags) }
}

/// The value `id` of class `class`, after setting it to `set` if given; `None` with an error.
#[allow(
    clippy::too_many_lines,
    reason = "one arm per value, as qc_getset_* are"
)]
fn getset(c: &Qctx<'_>, class: c_int, id: c_int, set: Option<u64>) -> Option<u64> {
    use rustyssl_abi::{
        SSL_R_FEATURE_NEGOTIATION_NOT_COMPLETE, SSL_R_FEATURE_NOT_RENEGOTIABLE,
        SSL_R_UNSUPPORTED_CONFIG_VALUE, SSL_R_UNSUPPORTED_CONFIG_VALUE_CLASS,
        SSL_R_UNSUPPORTED_CONFIG_VALUE_OP, SSL_VALUE_CLASS_FEATURE_NEGOTIATED,
        SSL_VALUE_CLASS_FEATURE_PEER_REQUEST, SSL_VALUE_CLASS_FEATURE_REQUEST,
        SSL_VALUE_CLASS_GENERIC, SSL_VALUE_EVENT_HANDLING_MODE,
        SSL_VALUE_EVENT_HANDLING_MODE_EXPLICIT, SSL_VALUE_QUIC_IDLE_TIMEOUT,
        SSL_VALUE_QUIC_MAX_PENDING_CONNS, SSL_VALUE_QUIC_STREAM_BIDI_LOCAL_AVAIL,
        SSL_VALUE_QUIC_STREAM_BIDI_REMOTE_AVAIL, SSL_VALUE_QUIC_STREAM_UNI_LOCAL_AVAIL,
        SSL_VALUE_QUIC_STREAM_UNI_REMOTE_AVAIL, SSL_VALUE_STREAM_WRITE_BUF_AVAIL,
        SSL_VALUE_STREAM_WRITE_BUF_SIZE, SSL_VALUE_STREAM_WRITE_BUF_USED,
    };
    const F: &str = "ossl_quic_get_value_uint";
    let mut es = c.engine().lock();
    let fail = |es: &mut EngineState, r: c_int| -> Option<u64> {
        c.non_normal(es, r, F);
        None
    };
    match id {
        SSL_VALUE_QUIC_IDLE_TIMEOUT => match class {
            SSL_VALUE_CLASS_FEATURE_REQUEST => {
                let started = es.conn(c.conn)?.ch.is_some();
                let cur = match es.channel_of(c.conn) {
                    Some(ch) => ch.idle_timeout_request(),
                    None => es.conn(c.conn)?.idle_timeout_req,
                };
                if let Some(v) = set {
                    if v > rustyssl_quic::wire::VARINT_MAX {
                        return fail(&mut es, ERR_R_PASSED_INVALID_ARGUMENT);
                    }
                    if started {
                        return fail(&mut es, SSL_R_FEATURE_NOT_RENEGOTIABLE);
                    }
                    es.conn(c.conn)?.idle_timeout_req = v;
                }
                Some(cur)
            }
            SSL_VALUE_CLASS_FEATURE_PEER_REQUEST | SSL_VALUE_CLASS_FEATURE_NEGOTIATED => {
                if set.is_some() {
                    return fail(&mut es, SSL_R_UNSUPPORTED_CONFIG_VALUE_OP);
                }
                if !handshake_complete(&mut es, c.conn) {
                    return fail(&mut es, SSL_R_FEATURE_NEGOTIATION_NOT_COMPLETE);
                }
                let ch = es.channel_of(c.conn)?;
                Some(if class == SSL_VALUE_CLASS_FEATURE_NEGOTIATED {
                    ch.idle_timeout_actual()
                } else {
                    ch.idle_timeout_peer_request().unwrap_or(0)
                })
            }
            _ => fail(&mut es, SSL_R_UNSUPPORTED_CONFIG_VALUE_CLASS),
        },
        SSL_VALUE_QUIC_MAX_PENDING_CONNS => {
            if class != SSL_VALUE_CLASS_GENERIC || c.q.kind != Kind::Listener {
                return fail(&mut es, SSL_R_UNSUPPORTED_CONFIG_VALUE_CLASS);
            }
            let cur = u64::try_from(es.port.max_pending()).unwrap_or(u64::MAX);
            if let Some(v) = set {
                es.port
                    .set_max_pending(usize::try_from(v).unwrap_or(usize::MAX));
            }
            Some(cur)
        }
        SSL_VALUE_QUIC_STREAM_BIDI_LOCAL_AVAIL
        | SSL_VALUE_QUIC_STREAM_BIDI_REMOTE_AVAIL
        | SSL_VALUE_QUIC_STREAM_UNI_LOCAL_AVAIL
        | SSL_VALUE_QUIC_STREAM_UNI_REMOTE_AVAIL => {
            if class != SSL_VALUE_CLASS_GENERIC {
                return fail(&mut es, SSL_R_UNSUPPORTED_CONFIG_VALUE_CLASS);
            }
            let uni = matches!(
                id,
                SSL_VALUE_QUIC_STREAM_UNI_LOCAL_AVAIL | SSL_VALUE_QUIC_STREAM_UNI_REMOTE_AVAIL
            );
            let remote = matches!(
                id,
                SSL_VALUE_QUIC_STREAM_BIDI_REMOTE_AVAIL | SSL_VALUE_QUIC_STREAM_UNI_REMOTE_AVAIL
            );
            Some(es.channel_of(c.conn).map_or(0, |ch| {
                if remote {
                    ch.streams().remote_avail(uni)
                } else {
                    ch.streams().local_avail(uni)
                }
            }))
        }
        SSL_VALUE_EVENT_HANDLING_MODE => {
            if class != SSL_VALUE_CLASS_GENERIC {
                return fail(&mut es, SSL_R_UNSUPPORTED_CONFIG_VALUE_CLASS);
            }
            let key = c.q.key();
            if let Some(v) = set {
                if v > u64::try_from(SSL_VALUE_EVENT_HANDLING_MODE_EXPLICIT).unwrap_or(2) {
                    return fail(&mut es, ERR_R_PASSED_INVALID_ARGUMENT);
                }
                es.event_mode.insert(key, v);
                return Some(v);
            }
            Some(es.event_mode.get(&key).copied().unwrap_or(0))
        }
        SSL_VALUE_STREAM_WRITE_BUF_SIZE
        | SSL_VALUE_STREAM_WRITE_BUF_USED
        | SSL_VALUE_STREAM_WRITE_BUF_AVAIL => {
            if class != SSL_VALUE_CLASS_GENERIC {
                return fail(&mut es, SSL_R_UNSUPPORTED_CONFIG_VALUE_CLASS);
            }
            let Some(sid) = c.stream_id(&mut es) else {
                return fail(&mut es, SSL_R_NO_STREAM);
            };
            let has_send = es
                .channel_of(c.conn)
                .and_then(|ch| ch.streams().get(sid))
                .map(|st| {
                    st.send
                        .as_ref()
                        .map(|p| (p.buf.capacity(), p.buf.used(), p.buf.space()))
                });
            let v = match has_send {
                None => 0,
                Some(None) => return fail(&mut es, SSL_R_STREAM_RECV_ONLY),
                Some(Some((size, used, avail))) => match id {
                    SSL_VALUE_STREAM_WRITE_BUF_SIZE => size,
                    SSL_VALUE_STREAM_WRITE_BUF_USED => used,
                    _ => avail,
                },
            };
            Some(u64::try_from(v).unwrap_or(u64::MAX))
        }
        _ => fail(&mut es, SSL_R_UNSUPPORTED_CONFIG_VALUE),
    }
}

/// `SSL_shutdown_ex` and `SSL_shutdown` on a QUIC object (`ossl_quic_conn_shutdown`),
/// without blocking.
///
/// # Safety
/// `s` is a live QUIC object; `args` NULL or readable; no lock is held.
pub(crate) unsafe fn shutdown(
    s: *mut SSL,
    flags: u64,
    args: *const rustyssl_abi::SSL_SHUTDOWN_EX_ARGS,
    _args_len: usize,
) -> c_int {
    use rustyssl_abi::{SSL_SHUTDOWN_FLAG_NO_STREAM_FLUSH, SSL_SHUTDOWN_FLAG_WAIT_PEER};
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { expect(s, C | S) }) else {
        return -1;
    };
    if c.is_stream {
        err::raise(ERR_LIB_SSL, SSL_R_CONN_USE_ONLY, "ossl_quic_conn_shutdown");
        return -1;
    }
    let stream_flush = flags & u64::from(SSL_SHUTDOWN_FLAG_NO_STREAM_FLUSH) == 0;
    let wait_peer = flags & u64::from(SSL_SHUTDOWN_FLAG_WAIT_PEER) != 0;
    let given = if args.is_null() {
        None
    } else {
        // SAFETY: the caller's guarantee.
        let a = unsafe { &*args };
        let reason = if a.quic_reason.is_null() {
            Vec::new()
        } else {
            // SAFETY: a NUL-terminated string (`SSL_SHUTDOWN_EX_ARGS`).
            unsafe { core::ffi::CStr::from_ptr(a.quic_reason) }
                .to_bytes()
                .to_vec()
        };
        Some((a.quic_error_code, reason))
    };
    let engine = Arc::clone(c.engine());
    let terminated = |es: &mut EngineState| {
        es.channel_of(c.conn)
            .is_none_or(|ch| ch.state() == State::Terminated)
    };
    {
        let mut es = engine.lock();
        if terminated(&mut es) {
            return 1;
        }
        if !wait_peer
            && let Some(g) = given.clone()
            && let Some(r) = es.conn(c.conn)
        {
            r.close = Some(g);
        }
    }
    if !wait_peer && stream_flush {
        let flushed = |es: &mut EngineState| {
            es.channel_of(c.conn)
                .is_none_or(|ch| ch.streams().is_flushed())
        };
        let mut es = engine.lock();
        if let Some(r) = es.conn(c.conn) {
            r.shutting_down = true;
        }
        if !flushed(&mut es) {
            drop(es);
            // SAFETY: no lock is held.
            unsafe { super::tick(&engine) };
            es = engine.lock();
        }
        if !flushed(&mut es) {
            return 0;
        }
    }
    if wait_peer {
        let mut es = engine.lock();
        if !term_any(&mut es, c.conn) {
            drop(es);
            // SAFETY: no lock is held.
            unsafe { super::tick(&engine) };
            es = engine.lock();
            if !term_any(&mut es, c.conn) {
                return 0;
            }
        }
    }
    {
        let mut es = engine.lock();
        let close = es.conn(c.conn).and_then(|r| {
            r.shutting_down = true;
            r.close.clone()
        });
        let (code, reason) = close.or(given).unwrap_or_default();
        let now = es.now();
        if let Some(ch) = es.channel_of(c.conn)
            && ch.state() == State::Active
        {
            ch.shutdown(code, &reason, now);
        }
        c.x.state().shutdown |= rustyssl_abi::SSL_SENT_SHUTDOWN;
        if terminated(&mut es) {
            return 1;
        }
    }
    // SAFETY: no lock is held.
    unsafe { super::tick(&engine) };
    let mut es = engine.lock();
    c_int::from(terminated(&mut es))
}

/// `SSL_set0_rbio` and `SSL_set0_wbio` on a QUIC object (`quic_set0_net_rbio`): the port's
/// network BIO, taking the caller's reference.
///
/// # Safety
/// `b` is NULL or a live BIO whose reference is given.
pub(crate) unsafe fn set0_net_bio(s: *mut SSL, b: *mut BIO, write: bool) {
    // SAFETY: the export's caller passes a live object.
    let Some(c) = (unsafe { expect(s, C | S | L) }) else {
        return;
    };
    let old = {
        let mut es = c.engine().lock();
        let slot = if write {
            &mut es.net_wbio
        } else {
            &mut es.net_rbio
        };
        if *slot == b {
            return;
        }
        core::mem::replace(slot, b)
    };
    // SAFETY: the reference the port held, freed with no lock held.
    unsafe { crate::bio::BIO_free_all(old) };
    if !b.is_null() {
        // Best effort (`BIO_set_nbio`).
        // SAFETY: the caller's live BIO.
        unsafe { crate::bio::BIO_ctrl(b, rustyssl_abi::BIO_C_SET_NBIO, 1, ptr::null_mut()) };
    }
}

/// `SSL_get_rbio` and `SSL_get_wbio` on a QUIC object: the port's network BIO.
pub(crate) fn net_bio(s: *const SSL, write: bool) -> *mut BIO {
    // SAFETY: the export's caller passes a live object.
    let Some(c) = (unsafe { expect(s, C | S | L) }) else {
        return ptr::null_mut();
    };
    let es = c.engine().lock();
    if write { es.net_wbio } else { es.net_rbio }
}

/// `SSL_version` and `SSL_client_version`: QUICv1 for a connection or stream, 0 for a listener.
pub(crate) fn quic_version(q: &Quic) -> c_int {
    match q.kind {
        Kind::Conn | Kind::Stream => rustyssl_abi::OSSL_QUIC1_VERSION,
        Kind::Listener | Kind::Domain => 0,
    }
}

/// `SSL_get_shutdown` (`ossl_quic_get_shutdown`).
pub(crate) fn get_shutdown(s: *const SSL) -> c_int {
    // SAFETY: the export's caller passes a live object.
    let Some(c) = (unsafe { expect(s, C) }) else {
        return 0;
    };
    let mut es = c.engine().lock();
    match es.channel_of(c.conn).map(|ch| ch.state()) {
        Some(State::Active) | None => 0,
        Some(State::Closing) => rustyssl_abi::SSL_SENT_SHUTDOWN,
        Some(_) => rustyssl_abi::SSL_SENT_SHUTDOWN | rustyssl_abi::SSL_RECEIVED_SHUTDOWN,
    }
}

/// `SSL_want` (`ossl_quic_want`): from what `SSL_get_error` reports.
pub(crate) fn want(s: *const SSL) -> c_int {
    use rustyssl_abi::{
        SSL_CLIENT_HELLO_CB, SSL_ERROR_WANT_CLIENT_HELLO_CB, SSL_ERROR_WANT_RETRY_VERIFY,
        SSL_ERROR_WANT_X509_LOOKUP, SSL_NOTHING, SSL_READING, SSL_RETRY_VERIFY, SSL_WRITING,
        SSL_X509_LOOKUP,
    };
    // SAFETY: the export's caller passes a live object.
    let Some(c) = (unsafe { expect(s, C | S) }) else {
        return SSL_NOTHING;
    };
    let mut es = c.engine().lock();
    let last = if c.is_stream {
        es.stream(c.q.key())
            .map_or(SSL_ERROR_NONE, |r| r.last_error)
    } else {
        es.conn(c.conn).map_or(SSL_ERROR_NONE, |r| r.last_error)
    };
    match last {
        SSL_ERROR_WANT_READ => SSL_READING,
        SSL_ERROR_WANT_WRITE => SSL_WRITING,
        SSL_ERROR_WANT_RETRY_VERIFY => SSL_RETRY_VERIFY,
        SSL_ERROR_WANT_CLIENT_HELLO_CB => SSL_CLIENT_HELLO_CB,
        SSL_ERROR_WANT_X509_LOOKUP => SSL_X509_LOOKUP,
        _ => SSL_NOTHING,
    }
}

/// `ossl_quic_pending_int`: the octets the stream has to read (or, `check_channel`, whether
/// anything is pending at all).
///
/// # Safety
/// `s` is a live QUIC object; no lock is held.
unsafe fn pending_int(s: *const SSL, check_channel: bool) -> usize {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { expect(s, C | S) }) else {
        return 0;
    };
    let started = c
        .engine()
        .lock()
        .conn(c.conn)
        .is_some_and(|r| r.ch.is_some());
    if !started {
        return 0;
    }
    let mut es = c.engine().lock();
    let id = match c.stream_id(&mut es) {
        Some(id) => id,
        None => {
            // A default stream the peer may have opened, made only to look (`peek`).
            drop(es);
            // SAFETY: no lock is held.
            if !unsafe { default_for_read(&c, true) } {
                err::raise(ERR_LIB_SSL, SSL_R_NO_STREAM, "ossl_quic_pending_int");
                return 0;
            }
            es = c.engine().lock();
            match c.stream_id(&mut es) {
                Some(id) => id,
                None => return 0,
            }
        }
    };
    let term = term_any(&mut es, c.conn);
    let (avail, end) = es
        .channel_of(c.conn)
        .map_or((0, false), |ch| ch.streams().readable(id));
    let avail = usize::try_from(avail).unwrap_or(usize::MAX);
    if check_channel {
        usize::from(avail > 0 || end || term)
    } else {
        avail
    }
}

/// `SSL_pending`.
///
/// # Safety
/// `s` is a live QUIC object; no lock is held.
pub(crate) unsafe fn pending(s: *const SSL) -> usize {
    // SAFETY: the caller's guarantee.
    unsafe { pending_int(s, false) }
}

/// `SSL_has_pending`.
///
/// # Safety
/// `s` is a live QUIC object; no lock is held.
pub(crate) unsafe fn has_pending(s: *const SSL) -> c_int {
    // SAFETY: the caller's guarantee.
    c_int::from(unsafe { pending_int(s, true) } > 0)
}

/// `SSL_key_update` (`ossl_quic_key_update`): a transport key update.
pub(crate) fn key_update(s: *mut SSL, update_type: c_int) -> c_int {
    use rustyssl_abi::{SSL_KEY_UPDATE_NOT_REQUESTED, SSL_KEY_UPDATE_REQUESTED};
    // SAFETY: the export's caller passes a live object.
    let Some(c) = (unsafe { expect(s, C) }) else {
        return 0;
    };
    if update_type != SSL_KEY_UPDATE_NOT_REQUESTED && update_type != SSL_KEY_UPDATE_REQUESTED {
        err::raise(
            ERR_LIB_SSL,
            ERR_R_PASSED_INVALID_ARGUMENT,
            "ossl_quic_key_update",
        );
        return 0;
    }
    let mut es = c.engine().lock();
    let Some(p) = es.prov.clone() else {
        drop(es);
        err::raise(
            ERR_LIB_SSL,
            rustyssl_abi::SSL_R_TOO_MANY_KEY_UPDATES,
            "ossl_quic_key_update",
        );
        return 0;
    };
    let now = es.now();
    let ok = es
        .channel_of(c.conn)
        .is_some_and(|ch| ch.key_update(&*p, now).is_ok());
    drop(es);
    if !ok {
        err::raise(
            ERR_LIB_SSL,
            rustyssl_abi::SSL_R_TOO_MANY_KEY_UPDATES,
            "ossl_quic_key_update",
        );
        return 0;
    }
    1
}

/// `SSL_set_connect_state` and `SSL_set_accept_state` (errors suppressed).
pub(crate) fn set_role(s: *mut SSL, server: bool) {
    // SAFETY: the export's caller passes a live object.
    let Some(c) = (unsafe { expect(s, C | NO_ERROR) }) else {
        return;
    };
    let mut es = c.engine().lock();
    if let Some(r) = es.conn(c.conn)
        && r.ch.is_none()
    {
        r.as_server_state = server;
    }
}

/// `SSL_get_rpoll_descriptor` and `_wpoll_descriptor`: the network BIO's.
///
/// # Safety
/// `desc` is NULL or writable.
pub(crate) unsafe fn poll_descriptor(
    s: *mut SSL,
    desc: *mut rustyssl_abi::BIO_POLL_DESCRIPTOR,
    write: bool,
) -> c_int {
    // SAFETY: the export's caller passes a live object.
    let Some(c) = (unsafe { expect(s, C | S | L) }) else {
        return 0;
    };
    let b = {
        let es = c.engine().lock();
        if write { es.net_wbio } else { es.net_rbio }
    };
    if desc.is_null() || b.is_null() {
        let mut es = c.engine().lock();
        return c.non_normal(
            &mut es,
            ERR_R_PASSED_INVALID_ARGUMENT,
            "ossl_quic_get_rpoll_descriptor",
        );
    }
    // SAFETY: the port's live BIO; the caller's descriptor.
    unsafe {
        if write {
            crate::bio::BIO_get_wpoll_descriptor(b, desc)
        } else {
            crate::bio::BIO_get_rpoll_descriptor(b, desc)
        }
    }
}

/// `OSSL_QUIC_PERMITTED_OPTIONS_CONN` (ssl_local.h), from the public option bits.
fn permitted_conn() -> u64 {
    use rustyssl_abi as a;
    legacy_and_tls12()
        | ops!(
            a::SSL_OP_CIPHER_SERVER_PREFERENCE,
            a::SSL_OP_DISABLE_TLSEXT_CA_NAMES,
            a::SSL_OP_NO_TX_CERTIFICATE_COMPRESSION,
            a::SSL_OP_NO_RX_CERTIFICATE_COMPRESSION,
            a::SSL_OP_PRIORITIZE_CHACHA,
            a::SSL_OP_NO_QUERY_MTU,
            a::SSL_OP_NO_TICKET,
            a::SSL_OP_NO_ANTI_REPLAY,
        )
}

/// `OSSL_QUIC_PERMITTED_OPTIONS_STREAM`.
pub(super) fn permitted_stream() -> u64 {
    legacy_and_tls12() | rustyssl_abi::SSL_OP_CLEANSE_PLAINTEXT
}

/// The union of option bits of mixed integer types (the legacy ones are 0 `int`s).
macro_rules! ops {
    ($($o:expr),* $(,)?) => {
        0u64 $(| u64::try_from($o).unwrap_or(0))*
    };
}
use ops;

/// `OSSL_LEGACY_SSL_OPTIONS | OSSL_TLS1_2_OPTIONS`.
fn legacy_and_tls12() -> u64 {
    use rustyssl_abi as a;
    ops!(
        a::SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG,
        a::SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER,
        a::SSL_OP_SSLEAY_080_CLIENT_DH_BUG,
        a::SSL_OP_TLS_D5_BUG,
        a::SSL_OP_TLS_BLOCK_PADDING_BUG,
        a::SSL_OP_MSIE_SSLV2_RSA_PADDING,
        a::SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG,
        a::SSL_OP_MICROSOFT_SESS_ID_BUG,
        a::SSL_OP_NETSCAPE_CHALLENGE_BUG,
        a::SSL_OP_PKCS1_CHECK_1,
        a::SSL_OP_PKCS1_CHECK_2,
        a::SSL_OP_SINGLE_DH_USE,
        a::SSL_OP_SINGLE_ECDH_USE,
        a::SSL_OP_EPHEMERAL_RSA,
        a::SSL_OP_CRYPTOPRO_TLSEXT_BUG,
        a::SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS,
        a::SSL_OP_ALLOW_CLIENT_RENEGOTIATION,
        a::SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION,
        a::SSL_OP_NO_COMPRESSION,
        a::SSL_OP_NO_SSLv3,
        a::SSL_OP_NO_TLSv1,
        a::SSL_OP_NO_TLSv1_1,
        a::SSL_OP_NO_TLSv1_2,
        a::SSL_OP_NO_DTLSv1,
        a::SSL_OP_NO_DTLSv1_2,
        a::SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION,
        a::SSL_OP_CISCO_ANYCONNECT,
        a::SSL_OP_NO_RENEGOTIATION,
        a::SSL_OP_NO_EXTENDED_MASTER_SECRET,
        a::SSL_OP_NO_ENCRYPT_THEN_MAC,
        a::SSL_OP_COOKIE_EXCHANGE,
        a::SSL_OP_LEGACY_SERVER_CONNECT,
        a::SSL_OP_IGNORE_UNEXPECTED_EOF,
    )
}

/// A new QUIC connection's options (`ossl_quic_new`): its handshake layer's keep the
/// connection-level ones, its streams' default the permitted ones.
pub(crate) fn init_options(x: &Ssl, rec: &mut ConnRec, ctx_options: u64) {
    x.state().options &= permitted_conn();
    rec.default_ssl_options = ctx_options & (permitted_conn() | permitted_stream());
}

/// `SSL_set_options`, `SSL_clear_options` and `SSL_get_options` (`quic_mask_or_options`).
pub(crate) fn options(s: *const SSL, mask: u64, or: u64) -> u64 {
    // SAFETY: the export's caller passes a live object.
    let Some(c) = (unsafe { expect(s, C | S) }) else {
        return 0;
    };
    if !c.is_stream {
        let mut st = c.x.state();
        st.options = (st.options & !(mask & permitted_conn())) | (or & permitted_conn());
    }
    let mut es = c.engine().lock();
    let all = permitted_conn() | permitted_stream();
    let mut ret = 0;
    if let Some(r) = es.conn(c.conn) {
        if !c.is_stream {
            r.default_ssl_options = ((r.default_ssl_options & !mask) | or) & all;
        }
        ret = r.default_ssl_options;
    }
    if let Some(api) = c.stream_api(&mut es) {
        api.ssl_options = ((api.ssl_options & !mask) | or) & permitted_stream();
        if c.is_stream {
            ret = api.ssl_options;
        }
    }
    ret
}

/// `SSL_ctrl` on a QUIC object (`ossl_quic_ctrl`): `Some` with the answer, or `None` for a
/// TLS control the connection's handshake layer answers.
///
/// # Safety
/// `s` is a live QUIC object; `parg` is what `cmd` documents; no lock is held.
pub(crate) unsafe fn ctrl(
    s: *mut SSL,
    cmd: c_int,
    larg: core::ffi::c_long,
    parg: *mut c_void,
) -> Option<core::ffi::c_long> {
    use core::ffi::c_long;
    use rustyssl_abi::{
        DTLS_CTRL_GET_TIMEOUT, DTLS_CTRL_HANDLE_TIMEOUT, SSL_CTRL_CLEAR_MODE,
        SSL_CTRL_GET_READ_AHEAD, SSL_CTRL_MODE, SSL_CTRL_SET_MAX_PIPELINES,
        SSL_CTRL_SET_MAX_SEND_FRAGMENT, SSL_CTRL_SET_READ_AHEAD, SSL_CTRL_SET_SPLIT_SEND_FRAGMENT,
    };
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { expect(s, C | S | L) }) else {
        return Some(0);
    };
    let listener = c.q.kind == Kind::Listener;
    let unsupported = || {
        err::raise(ERR_LIB_SSL, ERR_R_UNSUPPORTED, "ossl_quic_ctrl");
        Some(0)
    };
    match cmd {
        SSL_CTRL_MODE | SSL_CTRL_CLEAR_MODE => {
            if listener {
                return unsupported();
            }
            let bits = u32::try_from(larg).unwrap_or(0);
            let set = cmd == SSL_CTRL_MODE;
            let mut es = c.engine().lock();
            let mut ret = 0u32;
            if let Some(r) = es.conn(c.conn) {
                if !c.is_stream {
                    if set {
                        r.default_ssl_mode |= bits;
                    } else {
                        r.default_ssl_mode &= !bits;
                    }
                }
                ret = r.default_ssl_mode;
            }
            if let Some(api) = c.stream_api(&mut es) {
                let mut bits = bits;
                // Partial writes can't start during an all-or-nothing write.
                if set && api.aon.is_some() {
                    bits &= !SSL_MODE_ENABLE_PARTIAL_WRITE;
                }
                if set {
                    api.ssl_mode |= bits;
                } else {
                    api.ssl_mode &= !bits;
                }
                ret = api.ssl_mode;
            }
            Some(c_long::from(ret))
        }
        DTLS_CTRL_GET_TIMEOUT => {
            let mut inf = 0;
            // SAFETY: `parg` is the caller's `struct timeval`.
            unsafe { event_timeout(c.q, parg.cast(), &raw mut inf) };
            Some(c_long::from(inf == 0))
        }
        DTLS_CTRL_HANDLE_TIMEOUT => {
            // SAFETY: no lock is held.
            unsafe { super::tick(c.engine()) };
            Some(1)
        }
        SSL_CTRL_GET_READ_AHEAD
        | SSL_CTRL_SET_READ_AHEAD
        | SSL_CTRL_SET_MAX_SEND_FRAGMENT
        | SSL_CTRL_SET_SPLIT_SEND_FRAGMENT
        | SSL_CTRL_SET_MAX_PIPELINES => Some(0),
        _ if listener => unsupported(),
        _ => None,
    }
}

/// `SSL_clear` on a QUIC object (`ossl_quic_reset`): unsupported.
pub(crate) fn clear(s: *mut SSL) -> c_int {
    // SAFETY: the export's caller passes a live object.
    if unsafe { expect(s, C | S | L) }.is_some() {
        err::raise(ERR_LIB_SSL, ERR_R_UNSUPPORTED, "ossl_quic_reset");
    }
    0
}

/// `SSL_get_domain_flags` (`ossl_quic_get_domain_flags`).
///
/// # Safety
/// `out` is NULL or writable.
pub(crate) unsafe fn get_domain_flags(s: *const SSL, out: *mut u64) -> c_int {
    // SAFETY: the export's caller passes a live object.
    let Some(c) = (unsafe { expect(s, C | S | L | D) }) else {
        return 0;
    };
    let flags = c.engine().lock().domain_flags;
    if !out.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { out.write(flags) };
    }
    1
}

/// `ossl_adjust_domain_flags`: the flags as a domain takes them, or `None` with an error.
pub(crate) fn adjust_domain_flags(flags: u64) -> Option<u64> {
    use rustyssl_abi::{
        SSL_DOMAIN_FLAG_BLOCKING, SSL_DOMAIN_FLAG_LEGACY_BLOCKING, SSL_DOMAIN_FLAG_MULTI_THREAD,
        SSL_DOMAIN_FLAG_SINGLE_THREAD, SSL_DOMAIN_FLAG_THREAD_ASSISTED,
    };
    let single = u64::from(SSL_DOMAIN_FLAG_SINGLE_THREAD);
    let multi = u64::from(SSL_DOMAIN_FLAG_MULTI_THREAD);
    let assisted = u64::from(SSL_DOMAIN_FLAG_THREAD_ASSISTED);
    let supported = single
        | multi
        | assisted
        | u64::from(SSL_DOMAIN_FLAG_BLOCKING)
        | u64::from(SSL_DOMAIN_FLAG_LEGACY_BLOCKING);
    if flags & !supported != 0 {
        err::raise_with_text(
            ERR_LIB_SSL,
            ERR_R_UNSUPPORTED,
            "ossl_adjust_domain_flags",
            "unsupported domain flag requested",
        );
        return None;
    }
    let mut f = flags;
    if f & assisted != 0 {
        f |= multi;
    }
    if f & (multi | single) == 0 {
        f |= multi;
    }
    if f & single != 0 && f & multi != 0 {
        err::raise_with_text(
            ERR_LIB_SSL,
            ERR_R_PASSED_INVALID_ARGUMENT,
            "ossl_adjust_domain_flags",
            "mutually exclusive domain flags specified",
        );
        return None;
    }
    Some(f)
}

/// A new context's domain flags (`SSL_CTX_new_ex`): QUIC's defaults, 0 for TLS.
pub(crate) fn default_domain_flags(m: &crate::ssl::method::Method) -> u64 {
    use rustyssl_abi::{
        SSL_DOMAIN_FLAG_BLOCKING, SSL_DOMAIN_FLAG_LEGACY_BLOCKING, SSL_DOMAIN_FLAG_MULTI_THREAD,
        SSL_DOMAIN_FLAG_THREAD_ASSISTED,
    };
    if !m.quic {
        0
    } else if m.thread {
        u64::from(
            SSL_DOMAIN_FLAG_MULTI_THREAD
                | SSL_DOMAIN_FLAG_THREAD_ASSISTED
                | SSL_DOMAIN_FLAG_BLOCKING,
        )
    } else {
        u64::from(SSL_DOMAIN_FLAG_MULTI_THREAD | SSL_DOMAIN_FLAG_LEGACY_BLOCKING)
    }
}
