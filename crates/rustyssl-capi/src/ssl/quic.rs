//! OpenSSL's QUIC objects (ADR 0006, section 3; `quic_impl.c`, `quic_port.c`,
//! `quic_engine.c`): connections, stream objects, and listeners over `rustyssl-quic`'s sans-IO
//! transport.
//!
//! - **Objects.** A QUIC object is an ordinary `SSL` handle whose `quic` slot says what it is.
//!   A connection is its own handshake layer (OpenSSL's `qc->tls`): its state holds the TLS
//!   settings and core, in QUIC mode, so the TLS getters work on it unchanged ([`hs`]).
//! - **Engines.** One [`Engine`] per port (a client connection's, or a listener's) holds the
//!   transport and the API state of every object on it behind one mutex, OpenSSL's contentive
//!   model. A call locks it, works, and unlocks; the handshake layer and everything else that
//!   calls the application runs between ticks with no lock held ([`tick`]). The lock order is
//!   the engine's, then a connection's state.
//! - **Network.** A tick reads datagrams from the port's read BIO with `BIO_recvmmsg`, feeds
//!   the port, handles its timers, and sends what it has with `BIO_sendmmsg`.

pub(crate) mod api;
pub(crate) mod hs;
pub(crate) mod poll;

use core::ffi::{c_int, c_void};
use core::ptr;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use rustyssl_abi::{
    BIO, BIO_ADDR, BIO_CTRL_DGRAM_GET_EFFECTIVE_CAPS, BIO_DGRAM_CAP_HANDLES_DST_ADDR, BIO_MSG, SSL,
    SSL_CTX, SSL_DEFAULT_STREAM_MODE_AUTO_BIDI, SSL_ERROR_NONE, SSL_INCOMING_STREAM_POLICY_AUTO,
};
use rustyssl_quic::channel::{Channel, PeerAddr};
use rustyssl_quic::port::{ChannelId, Port, PortConfig, PortEvent};
use rustyssl_quic::time::Time;
use rustyssl_quic::tls::{Answer, Handshake};

use self::hs::{Hs, Shared};
use super::conn::{Ssl, ssl};
use super::io::Stop;
use super::tls_provider::EvpProvider;
use crate::bio::addr;

/// What a QUIC `SSL` handle is (`SSL_TYPE_QUIC_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Conn,
    Listener,
    Stream,
    Domain,
}

/// The QUIC part of an `SSL` handle.
pub(crate) struct Quic {
    pub(crate) kind: Kind,
    pub(crate) engine: Arc<Engine>,
    /// The handle (its address is the object's key in the engine).
    pub(crate) s: *mut SSL,
}

// SAFETY: the handle is a thread-safe `SSL`; everything else is behind the engine's mutex.
unsafe impl Send for Quic {}
// SAFETY: as above.
unsafe impl Sync for Quic {}

impl Quic {
    pub(crate) fn key(&self) -> usize {
        self.s.addr()
    }
}

impl Drop for Quic {
    fn drop(&mut self) {
        let mut free = Vec::new();
        {
            let mut es = self.engine.lock();
            es.forget(self.key(), self.kind, &mut free);
        }
        for s in free {
            // SAFETY: a reference the object held (its listener or connection, or a connection
            // waiting to be accepted).
            unsafe { super::conn::rustyssl_private_SSL_free(s) };
        }
    }
}

/// A stream as the API layer tracks it (`QUIC_XSO`'s data-plane state).
#[derive(Debug)]
pub(crate) struct StreamApi {
    pub(crate) id: u64,
    pub(crate) ssl_mode: u32,
    /// An all-or-nothing write in progress: the buffer's address, length, and what's taken.
    pub(crate) aon: Option<(usize, usize, usize)>,
    pub(crate) ssl_options: u64,
    /// The application read the end of the stream (`retired_fin`).
    pub(crate) retired_fin: bool,
    /// The application reset the send part (`requested_reset`).
    pub(crate) requested_reset: bool,
}

impl StreamApi {
    /// A stream's state with its connection's defaults (`create_xso_from_stream`).
    pub(crate) fn new(id: u64, ssl_mode: u32, conn_options: u64) -> Self {
        Self {
            id,
            ssl_mode,
            aon: None,
            ssl_options: conn_options & api::permitted_stream(),
            retired_fin: false,
            requested_reset: false,
        }
    }
}

/// A connection's API state (`QUIC_CONNECTION`).
pub(crate) struct ConnRec {
    /// The connection's handle.
    pub(crate) s: *mut SSL,
    pub(crate) shared: Arc<Shared>,
    pub(crate) ch: Option<ChannelId>,
    pub(crate) server: bool,
    pub(crate) default_stream: Option<StreamApi>,
    pub(crate) default_stream_mode: u32,
    /// A default stream existed once (none is made again).
    pub(crate) default_created: bool,
    pub(crate) incoming_policy: c_int,
    pub(crate) incoming_aec: u64,
    pub(crate) default_ssl_mode: u32,
    /// The options new streams take.
    pub(crate) default_ssl_options: u64,
    pub(crate) last_error: c_int,
    pub(crate) started: bool,
    pub(crate) shutting_down: bool,
    pub(crate) initial_peer: Option<PeerAddr>,
    /// The listener it came from (a reference held once it is accepted).
    pub(crate) listener: *mut SSL,
    /// Stream objects made from it.
    pub(crate) streams: usize,
    /// The role `SSL_set_connect_state`/`SSL_set_accept_state` asked for.
    pub(crate) as_server_state: bool,
    /// The idle timeout to request, until the channel is made (milliseconds).
    pub(crate) idle_timeout_req: u64,
    /// The close `SSL_shutdown_ex` asked for (code and reason).
    pub(crate) close: Option<(u64, Vec<u8>)>,
    /// The peer's or our close reason, NUL-terminated, for `SSL_get_conn_close_info`.
    pub(crate) close_reason: Option<Vec<u8>>,
}

/// A stream object's API state.
pub(crate) struct StreamRec {
    pub(crate) conn: usize,
    /// The connection's handle (a reference held).
    pub(crate) conn_s: *mut SSL,
    pub(crate) api: StreamApi,
    pub(crate) last_error: c_int,
}

/// A listener's API state.
pub(crate) struct ListenerRec {
    pub(crate) listening: bool,
}

/// A domain's API state: its listeners' engines.
pub(crate) struct DomainRec {
    pub(crate) members: Vec<std::sync::Weak<Engine>>,
}

pub(crate) enum Rec {
    Conn(ConnRec),
    Stream(StreamRec),
    Listener(ListenerRec),
    Domain(DomainRec),
}

/// A port, and the objects on it.
pub(crate) struct Engine {
    st: Mutex<EngineState>,
}

pub(crate) struct EngineState {
    pub(crate) port: Port,
    pub(crate) prov: Option<Arc<EvpProvider>>,
    /// The handle whose BIOs are the network (the client connection or the listener).
    pub(crate) owner: *mut SSL,
    start: Instant,
    pub(crate) objs: BTreeMap<usize, Rec>,
    /// Each channel's connection.
    pub(crate) by_channel: BTreeMap<ChannelId, usize>,
    /// Handshakes the port made for new channels since the last look.
    made: Arc<Mutex<VecDeque<Arc<Shared>>>>,
    fresh: VecDeque<Arc<Shared>>,
    /// New channels without objects yet.
    pending: VecDeque<(ChannelId, Arc<Shared>)>,
    /// Connection objects waiting for `SSL_accept_connection` (a reference held each).
    pub(crate) accept_queue: VecDeque<*mut SSL>,
    pub(crate) listener: bool,
    /// The application wants blocking calls (`SSL_set_blocking_mode`).
    pub(crate) desires_blocking: bool,
    /// Each object's `SSL_VALUE_EVENT_HANDLING_MODE`.
    pub(crate) event_mode: BTreeMap<usize, u64>,
    /// The domain flags of the objects on it (`SSL_get_domain_flags`).
    pub(crate) domain_flags: u64,
    /// Datagrams `SSL_inject_net_dgram` queued, for the next tick.
    pub(crate) injected: VecDeque<(PeerAddr, Vec<u8>)>,
    /// The domain a listener was made from (a reference held), or NULL.
    pub(crate) domain: *mut SSL,
    /// The network BIOs (a reference held each).
    pub(crate) net_rbio: *mut BIO,
    pub(crate) net_wbio: *mut BIO,
}

impl Drop for EngineState {
    fn drop(&mut self) {
        // SAFETY: our references, each NULL or live.
        unsafe { crate::bio::BIO_free_all(self.net_rbio) };
        // SAFETY: as above.
        unsafe { crate::bio::BIO_free_all(self.net_wbio) };
    }
}

// SAFETY: the raw pointers are thread-safe `SSL` handles, used under the mutex.
unsafe impl Send for EngineState {}

/// A context moved into the port's handshake factory.
struct SendPtr(*mut SSL_CTX);
// SAFETY: a context is a thread-safe handle; the factory only reads its settings.
unsafe impl Send for SendPtr {}

impl Engine {
    /// An engine for a client connection, or (`listen`) a listener on `ctx`.
    pub(crate) fn new(ctx: *mut SSL_CTX, listen: bool, validate: bool) -> Arc<Self> {
        let made: Arc<Mutex<VecDeque<Arc<Shared>>>> = Arc::default();
        let new_handshake = listen.then(|| {
            let made = Arc::clone(&made);
            let ctx = SendPtr(ctx);
            let f: Box<dyn FnMut() -> Box<dyn Handshake> + Send> = Box::new(move || {
                let ctx = &ctx;
                // A server without an ALPN selection callback can't do QUIC (quic_tls.c).
                // SAFETY: the listener's context, which it holds.
                let alpn = unsafe { super::ctx::ctx(ctx.0) }
                    .is_some_and(|c| c.state().alpn_select_cb.is_some());
                let sh = Shared::new(alpn);
                made.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push_back(Arc::clone(&sh));
                Box::new(Hs(sh))
            });
            f
        });
        let cfg = PortConfig {
            listen,
            validate_addr: validate,
            new_handshake,
            ..PortConfig::default()
        };
        Arc::new(Self {
            st: Mutex::new(EngineState {
                port: Port::new(cfg),
                prov: None,
                owner: ptr::null_mut(),
                start: Instant::now(),
                objs: BTreeMap::new(),
                by_channel: BTreeMap::new(),
                made,
                fresh: VecDeque::new(),
                pending: VecDeque::new(),
                accept_queue: VecDeque::new(),
                listener: listen,
                desires_blocking: true,
                event_mode: BTreeMap::new(),
                net_rbio: ptr::null_mut(),
                net_wbio: ptr::null_mut(),
                // SAFETY: the caller's live context.
                domain_flags: unsafe { super::ctx::ctx(ctx) }.map_or(0, |c| c.state().domain_flags),
                domain: ptr::null_mut(),
                injected: VecDeque::new(),
            }),
        })
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, EngineState> {
        self.st.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl EngineState {
    pub(crate) fn now(&self) -> Time {
        Time(u64::try_from(self.start.elapsed().as_nanos()).unwrap_or(u64::MAX))
    }

    pub(crate) fn conn(&mut self, key: usize) -> Option<&mut ConnRec> {
        match self.objs.get_mut(&key) {
            Some(Rec::Conn(c)) => Some(c),
            _ => None,
        }
    }

    pub(crate) fn stream(&mut self, key: usize) -> Option<&mut StreamRec> {
        match self.objs.get_mut(&key) {
            Some(Rec::Stream(r)) => Some(r),
            _ => None,
        }
    }

    pub(crate) fn listener_rec(&mut self, key: usize) -> Option<&mut ListenerRec> {
        match self.objs.get_mut(&key) {
            Some(Rec::Listener(l)) => Some(l),
            _ => None,
        }
    }

    /// A connection's channel.
    pub(crate) fn channel_of(&mut self, key: usize) -> Option<&mut Channel> {
        let id = self.conn(key)?.ch?;
        self.port.channel(id)
    }

    /// Removes an object being freed; what it held goes into `free`.
    fn forget(&mut self, key: usize, kind: Kind, free: &mut Vec<*mut SSL>) {
        match (kind, self.objs.remove(&key)) {
            (Kind::Conn, Some(Rec::Conn(c))) => {
                if let Some(id) = c.ch {
                    self.by_channel.remove(&id);
                    self.port.remove(id);
                }
                if !c.listener.is_null() {
                    free.push(c.listener);
                }
            }
            (Kind::Stream, Some(Rec::Stream(r))) => {
                // An unfinished send part is reset, and the receive part stopped
                // (`ossl_quic_free`).
                if let Some(ch) = self.channel_of(r.conn) {
                    let id = r.api.id;
                    let _ = ch.stream_reset(id, 0);
                    let _ = ch.stream_stop_sending(id, 0);
                    ch.stream_release(id);
                }
                if let Some(c) = self.conn(r.conn) {
                    c.streams = c.streams.saturating_sub(1);
                }
                free.push(r.conn_s);
            }
            (Kind::Listener, _) => {
                free.extend(self.accept_queue.drain(..));
                if !self.domain.is_null() {
                    free.push(core::mem::replace(&mut self.domain, ptr::null_mut()));
                }
                for (id, _) in self.pending.drain(..) {
                    self.port.remove(id);
                }
            }
            _ => {}
        }
    }

    /// The network BIOs.
    pub(crate) fn bios(&self) -> (*mut BIO, *mut BIO) {
        (self.net_rbio, self.net_wbio)
    }

    /// Reads what the network has into the port.
    fn net_read(&mut self) {
        let Some(p) = self.prov.clone() else { return };
        while let Some((from, d)) = self.injected.pop_front() {
            let now = self.now();
            self.port.handle_datagram(&*p, now, &from, &d);
            self.after_datagram();
        }
        let (rbio, _) = self.bios();
        if rbio.is_null() {
            return;
        }
        let mut buf = vec![0u8; 65536];
        let fallback = self.default_peer();
        for _ in 0..64 {
            // The source address, which a BIO that knows it fills (as the demuxer asks).
            // SAFETY: no preconditions.
            let peer = unsafe { addr::BIO_ADDR_new() };
            let mut msg = BIO_MSG {
                data: buf.as_mut_ptr().cast::<c_void>(),
                data_len: buf.len(),
                peer,
                local: ptr::null_mut(),
                flags: 0,
            };
            let mut n = 0usize;
            // SAFETY: no preconditions.
            unsafe { crate::err::ERR_set_mark() };
            // SAFETY: the live BIO; one message over our buffer; a local count.
            let ok = unsafe {
                crate::bio::BIO_recvmmsg(
                    rbio,
                    &raw mut msg,
                    core::mem::size_of::<BIO_MSG>(),
                    1,
                    0,
                    &raw mut n,
                )
            };
            // SAFETY: the mark set above.
            unsafe { crate::err::ERR_pop_to_mark() };
            let got = ok == 1 && n == 1;
            // SAFETY: our address, or NULL.
            let known =
                !peer.is_null() && unsafe { addr::BIO_ADDR_family(peer) } != libc::AF_UNSPEC;
            let from = if got && known {
                // SAFETY: the address the BIO filled.
                unsafe { peer_of(peer) }
            } else {
                fallback.clone()
            };
            // SAFETY: ours, or NULL.
            unsafe { addr::BIO_ADDR_free(peer) };
            if !got {
                break;
            }
            let len = msg.data_len.min(buf.len());
            let now = self.now();
            if let Some(d) = buf.get(..len) {
                self.port.handle_datagram(&*p, now, &from, d);
            }
            self.after_datagram();
        }
    }

    /// The peer a datagram without a source address came from: a client's server.
    fn default_peer(&self) -> PeerAddr {
        self.objs
            .values()
            .find_map(|r| match r {
                Rec::Conn(c) if !c.server => c.initial_peer.clone(),
                _ => None,
            })
            .unwrap_or_default()
    }

    /// Matches the handshakes the port made with the channels it reported.
    fn after_datagram(&mut self) {
        let made: Vec<Arc<Shared>> = self
            .made
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain(..)
            .collect();
        self.fresh.extend(made);
        self.collect();
        self.fresh.clear();
    }

    /// Sends what the port has.
    pub(crate) fn net_write(&mut self) {
        let Some(p) = self.prov.clone() else { return };
        let (_, wbio) = self.bios();
        if wbio.is_null() {
            return;
        }
        let now = self.now();
        // SAFETY: the owner's live BIO.
        let dst = unsafe { caps(wbio) } & u64::from(BIO_DGRAM_CAP_HANDLES_DST_ADDR) != 0;
        while let Some((peer, mut data)) = self.port.poll_transmit(&*p, now) {
            let a = if dst { addr_of(&peer) } else { ptr::null_mut() };
            let mut msg = BIO_MSG {
                data: data.as_mut_ptr().cast::<c_void>(),
                data_len: data.len(),
                peer: a,
                local: ptr::null_mut(),
                flags: 0,
            };
            let mut n = 0usize;
            // SAFETY: no preconditions.
            unsafe { crate::err::ERR_set_mark() };
            // SAFETY: the live BIO; one message over the datagram; a local count.
            unsafe {
                crate::bio::BIO_sendmmsg(
                    wbio,
                    &raw mut msg,
                    core::mem::size_of::<BIO_MSG>(),
                    1,
                    0,
                    &raw mut n,
                )
            };
            // SAFETY: the mark set above.
            unsafe { crate::err::ERR_pop_to_mark() };
            // SAFETY: ours, or NULL.
            unsafe { addr::BIO_ADDR_free(a) };
        }
    }

    /// Takes the port's and the channels' events.
    pub(crate) fn collect(&mut self) {
        while let Some(ev) = self.port.poll_event() {
            match ev {
                PortEvent::Incoming(id) => {
                    if let Some(sh) = self.fresh.pop_front() {
                        self.pending.push_back((id, sh));
                    }
                }
                PortEvent::Channel(id) => {
                    // The handshake layer runs in the connection's own driver and the API
                    // asks the channel for its state: nothing else is waited for.
                    while self
                        .port
                        .channel(id)
                        .and_then(Channel::poll_event)
                        .is_some()
                    {}
                }
            }
        }
    }

    /// Network in, timers, events, network out.
    fn run(&mut self) {
        self.net_read();
        if let Some(p) = self.prov.clone() {
            let now = self.now();
            self.port.handle_timeout(&*p, now);
        }
        self.collect();
        self.net_write();
    }

    /// The connections whose handshake layer has work (a reference taken each).
    fn to_drive(&self) -> Vec<(*mut SSL, Arc<Shared>)> {
        let mut v = Vec::new();
        for r in self.objs.values() {
            if let Rec::Conn(c) = r
                && c.ch.is_some()
                && c.shared.lock().need_drive
            {
                // SAFETY: a live connection (it removes itself from the engine when freed).
                unsafe { super::conn::rustyssl_private_SSL_up_ref(c.s) };
                v.push((c.s, Arc::clone(&c.shared)));
            }
        }
        v
    }
}

/// The QUIC part of `s`, if it is a QUIC object.
///
/// # Safety
/// `s` is NULL or a live `SSL`.
pub(crate) unsafe fn of<'a>(s: *const SSL) -> Option<&'a Quic> {
    // SAFETY: the caller's guarantee.
    unsafe { ssl(s) }?.quic.get()
}

// ---- Addresses ----

/// A `BIO_ADDR` as the transport's opaque peer address: family, port, raw address.
///
/// # Safety
/// `a` is a live address.
pub(crate) unsafe fn peer_of(a: *const BIO_ADDR) -> PeerAddr {
    // SAFETY: the caller's guarantee.
    let family = unsafe { addr::BIO_ADDR_family(a) };
    // SAFETY: as above.
    let port = unsafe { addr::BIO_ADDR_rawport(a) };
    let mut raw = [0u8; 128];
    let mut len = raw.len();
    // SAFETY: as above; a local buffer and its length.
    if unsafe { addr::BIO_ADDR_rawaddress(a, raw.as_mut_ptr().cast(), &raw mut len) } == 0 {
        len = 0;
    }
    let mut v = Vec::with_capacity(len.saturating_add(4));
    v.extend_from_slice(&u16::try_from(family).unwrap_or(0).to_ne_bytes());
    v.extend_from_slice(&port.to_ne_bytes());
    v.extend_from_slice(raw.get(..len).unwrap_or_default());
    PeerAddr(v)
}

/// The `BIO_ADDR` of a peer address (a new one), or NULL.
pub(crate) fn addr_of(p: &PeerAddr) -> *mut BIO_ADDR {
    let [f0, f1, p0, p1, rest @ ..] = p.0.as_slice() else {
        return ptr::null_mut();
    };
    // SAFETY: no preconditions.
    let a = unsafe { addr::BIO_ADDR_new() };
    if a.is_null() {
        return a;
    }
    // SAFETY: the new address; the raw address octets and their length.
    let ok = unsafe {
        addr::BIO_ADDR_rawmake(
            a,
            c_int::from(u16::from_ne_bytes([*f0, *f1])),
            rest.as_ptr().cast(),
            rest.len(),
            u16::from_ne_bytes([*p0, *p1]),
        )
    };
    if ok == 0 {
        // SAFETY: ours.
        unsafe { addr::BIO_ADDR_free(a) };
        return ptr::null_mut();
    }
    a
}

/// The effective datagram capabilities of `b` (0 for a BIO without them).
///
/// # Safety
/// `b` is NULL or a live BIO.
pub(crate) unsafe fn caps(b: *mut BIO) -> u64 {
    if b.is_null() {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let c =
        unsafe { crate::bio::BIO_ctrl(b, BIO_CTRL_DGRAM_GET_EFFECTIVE_CAPS, 0, ptr::null_mut()) };
    u64::try_from(c).unwrap_or(0)
}

// ---- The handshake layer ----

/// Puts `x`'s own TLS state in QUIC mode, with the transport behind `sh` in place of the
/// callbacks (`ossl_quic_tls_configure`).
pub(crate) fn attach_tls(x: &Ssl, sh: &Arc<Shared>) {
    // The handshake layer's BIOs are null ones: its octets go through the transport.
    // SAFETY: no preconditions.
    let nb = unsafe { crate::bio::BIO_new(crate::bio::null::BIO_s_null()) };
    if !nb.is_null() {
        // One reference for each side.
        // SAFETY: the new BIO.
        unsafe { crate::bio::BIO_up_ref(nb) };
    }
    let mut st = x.state();
    let old = (
        core::mem::replace(&mut st.rbio, nb),
        core::mem::replace(&mut st.wbio, nb),
    );
    st.quic.on = true;
    let sink: Arc<dyn super::quic_tls::Sink> = Arc::clone(sh) as Arc<dyn super::quic_tls::Sink>;
    st.quic.sink = Some(sink);
    st.min_proto_version = rustyssl_abi::TLS1_3_VERSION;
    st.options &= !rustyssl_abi::SSL_OP_ENABLE_MIDDLEBOX_COMPAT;
    drop(st);
    // SAFETY: references the state held, each NULL or live.
    unsafe { crate::bio::BIO_free_all(old.0) };
    // SAFETY: as above.
    unsafe { crate::bio::BIO_free_all(old.1) };
}

/// Runs the handshake layer of connection `s` as far as it goes, with no lock held (OpenSSL's
/// `ossl_quic_tls_tick`): the handshake, then post-handshake messages.
///
/// # Safety
/// `s` is a live connection; no lock is held.
unsafe fn drive_tls(s: *mut SSL, sh: &Shared) {
    // SAFETY: the caller's guarantee.
    let Some(x) = (unsafe { ssl(s) }) else { return };
    let (params, completed, failed) = {
        let mut q = sh.lock();
        q.need_drive = false;
        (q.local_params.take(), q.completed, q.failed)
    };
    if let Some(p) = params {
        let mut st = x.state();
        if let Some(qc) = st
            .drv
            .tls
            .as_mut()
            .and_then(|c| c.config_mut().quic.as_mut())
        {
            qc.transport_params = Some(p.clone());
        }
        st.quic.params = Some(p);
    }
    if failed {
        return;
    }
    // SAFETY: the caller's guarantee.
    if !unsafe { super::io::ensure_core(s, x) } {
        sh.fail(alert_internal());
        return;
    }
    // SAFETY: as above.
    let stop = unsafe { super::io::drive(s, x, completed, "SSL_do_handshake") };
    match stop {
        Stop::Failed | Stop::Syscall | Stop::Closed => sh.fail(alert_internal()),
        Stop::Done | Stop::Idle | Stop::AppData | Stop::Retry => {
            let st = x.state();
            if !completed && !st.in_init {
                let alpn = (!st.drv.alpn.is_empty()).then(|| st.drv.alpn.clone());
                drop(st);
                sh.complete(alpn);
            }
        }
    }
}

fn alert_internal() -> u8 {
    u8::try_from(rustyssl_abi::SSL_AD_INTERNAL_ERROR).unwrap_or(80)
}

// ---- Ticks ----

/// One tick of `engine` (`ossl_quic_reactor_tick`): network in, timers, the handshake layers
/// (unlocked), network out; repeated while the handshake layers make progress.
///
/// # Safety
/// Called with no lock held.
pub(crate) unsafe fn tick(engine: &Arc<Engine>) {
    let owner = api::owner(&engine.lock());
    if let Some(o) = owner {
        // SAFETY: the engine's live owner; no lock is held.
        if !unsafe { api::ensure_provider(engine, o) } {
            return;
        }
    }
    for _ in 0..32 {
        let (todo, pending, owner) = {
            let mut es = engine.lock();
            es.run();
            let todo = es.to_drive();
            let pending: Vec<(ChannelId, Arc<Shared>)> = es.pending.drain(..).collect();
            (todo, pending, es.owner)
        };
        let mut made = Vec::new();
        for (id, sh) in pending {
            // SAFETY: the listener, which holds the engine; no lock is held.
            match unsafe { make_incoming(engine, owner, &sh) } {
                Some(s) => made.push((id, s)),
                None => engine.lock().port.remove(id),
            }
        }
        for (s, sh) in &todo {
            // SAFETY: a live connection (a reference is held); no lock is held.
            unsafe { drive_tls(*s, sh) };
        }
        let progressed = !todo.is_empty() || !made.is_empty();
        {
            let mut es = engine.lock();
            let mut kick: Vec<ChannelId> = Vec::new();
            for (id, s) in made {
                let key = s.addr();
                if let Some(c) = es.conn(key) {
                    c.ch = Some(id);
                }
                es.by_channel.insert(id, key);
                es.accept_queue.push_back(s);
            }
            for (s, sh) in &todo {
                if sh.has_output()
                    && let Some(c) = es.conn(s.addr())
                    && let Some(id) = c.ch
                {
                    kick.push(id);
                }
            }
            if let Some(p) = es.prov.clone() {
                let now = es.now();
                for id in kick {
                    if let Some(ch) = es.port.channel(id) {
                        ch.tls_answer(&*p, Answer::Continue, now);
                    }
                }
            }
            es.collect();
            es.net_write();
        }
        for (s, _) in todo {
            // SAFETY: the reference taken in `to_drive`.
            unsafe { super::conn::rustyssl_private_SSL_free(s) };
        }
        if !progressed {
            break;
        }
    }
}

/// Makes the object of a connection a listener accepted (`create_qc_from_incoming_conn`), with
/// no lock held (`SSL_new` runs the application's ex_data callbacks).
///
/// # Safety
/// `listener` is the engine's live listener; no lock is held.
unsafe fn make_incoming(
    engine: &Arc<Engine>,
    listener: *mut SSL,
    sh: &Arc<Shared>,
) -> Option<*mut SSL> {
    // SAFETY: the caller's guarantee.
    let lx = unsafe { ssl(listener) }?;
    let ctx = lx.state().ctx;
    // SAFETY: the listener's live context.
    let s = unsafe { super::conn::new_ssl(ctx) };
    // SAFETY: the new connection, or NULL.
    let x = unsafe { ssl(s) }?;
    // SAFETY: the new connection.
    unsafe { super::conn::rustyssl_private_SSL_set_accept_state(s) };
    attach_tls(x, sh);
    let mode = x.state().mode;
    // SAFETY: the listener's live context.
    let ctx_options = unsafe { super::ctx::ctx(ctx) }.map_or(0, |c| c.state().options);
    let mut rec = ConnRec::new(s, Arc::clone(sh), true, mode);
    api::init_options(x, &mut rec, ctx_options);
    engine.lock().objs.insert(s.addr(), Rec::Conn(rec));
    let _ = x.quic.set(Quic {
        kind: Kind::Conn,
        engine: Arc::clone(engine),
        s,
    });
    Some(s)
}

impl ConnRec {
    pub(crate) fn new(s: *mut SSL, shared: Arc<Shared>, server: bool, mode: u32) -> Self {
        Self {
            s,
            shared,
            ch: None,
            server,
            default_stream: None,
            default_stream_mode: u32::try_from(SSL_DEFAULT_STREAM_MODE_AUTO_BIDI).unwrap_or(1),
            default_created: false,
            incoming_policy: SSL_INCOMING_STREAM_POLICY_AUTO,
            incoming_aec: 0,
            default_ssl_mode: mode,
            default_ssl_options: 0,
            last_error: SSL_ERROR_NONE,
            started: false,
            shutting_down: false,
            initial_peer: None,
            listener: ptr::null_mut(),
            streams: 0,
            as_server_state: server,
            idle_timeout_req: rustyssl_quic::channel::DEFAULT_IDLE_TIMEOUT_MS,
            close: None,
            close_reason: None,
        }
    }
}

/// Whether QUIC can use suite `c` (`SSL_QUIC` in OpenSSL's table: the GCM suites and
/// ChaCha20-Poly1305).
pub(crate) fn quic_suite(c: &rustyssl_tls::suites::Cipher) -> bool {
    [
        rustyssl_abi::TLS1_3_CK_AES_128_GCM_SHA256,
        rustyssl_abi::TLS1_3_CK_AES_256_GCM_SHA384,
        rustyssl_abi::TLS1_3_CK_CHACHA20_POLY1305_SHA256,
    ]
    .iter()
    .any(|&id| u32::try_from(id).is_ok_and(|id| id == c.id))
}
