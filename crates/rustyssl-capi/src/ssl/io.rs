//! The driver between libssl's API and the sans-IO core (ADR 0002, decision 4). The core's
//! connection lives in the `SSL`'s state, and every entry point that runs the protocol
//! (`SSL_do_handshake`, `SSL_read`, `SSL_write`, `SSL_shutdown`, ...) goes through one step
//! loop ([`drive`]):
//!
//! 1. take the core connection out of the state (lock, take, unlock);
//! 2. `step` it with no lock held;
//! 3. put it back, with the mirrors the getters read (lock, store, unlock);
//! 4. act on the event with **no lock held**: call the application's callbacks, answer the
//!    core's requests, move octets between the core and the BIOs.
//!
//! The connection is back in the state before any callback runs, so a callback may call any
//! getter on the same `SSL` (security rule 7). A callback that drives the same `SSL` again
//! (`SSL_read` from inside the info callback) is refused with
//! `ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED`: OpenSSL's state machine isn't re-entrant either, and
//! the outer call owns the pending request.

pub(crate) mod alpn;
pub(crate) mod api;
pub(crate) mod config;
pub(crate) mod requests;
pub(crate) mod strings;

use core::ffi::{c_int, c_long, c_void};
use core::ptr;
use std::ffi::CString;
use std::sync::Arc;

use rustyssl_abi::{
    BIO, BIO_CTRL_EOF, BIO_FLAGS_SHOULD_RETRY, ERR_LIB_SSL, ERR_R_INTERNAL_ERROR,
    ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, SSL, SSL_AD_CLOSE_NOTIFY, SSL_AD_REASON_OFFSET,
    SSL_CB_ACCEPT_EXIT, SSL_CB_CONNECT_EXIT, SSL_NOTHING, SSL_OP_IGNORE_UNEXPECTED_EOF,
    SSL_R_UNEXPECTED_EOF_WHILE_READING, SSL_READING, SSL_RECEIVED_SHUTDOWN, SSL_WRITING,
    stack_st_X509,
};
use rustyssl_tls::conn::common::SecurityHook;
use rustyssl_tls::conn::common::security::SecOther;
use rustyssl_tls::conn::{Connection, Event};
use rustyssl_tls::error::Error as TlsError;

use self::config::CtxSnapshot;
use super::conn::{Ssl, SslState};
use super::tls_provider::EvpProvider;
use crate::bio::{BIO_ctrl, BIO_read, BIO_test_flags, BIO_write};
use crate::err;
use crate::stack::{OPENSSL_sk_new_null, OPENSSL_sk_pop_free, OPENSSL_sk_push};
use crate::x509::cert::{X509_free, X509_up_ref, d2i_X509};

/// A TLS record header's length, and an SSLv2 ClientHello's.
const HEADER_LEN: usize = 5;
const SSL2_HEADER_LEN: usize = 2;

/// How much a read-ahead read asks for at once (a full record and then some).
const READ_AHEAD_CHUNK: usize = 16 * 1024 + 2048;

/// The peer's certificates as `X509` objects the connection owns, at stable addresses for the
/// `get0` getters.
#[derive(Debug)]
pub(crate) struct PeerCerts {
    /// How many certificates of the core's chain these were made from.
    pub(crate) from: usize,
    /// The chain, leaf first (owned stack and references), or NULL.
    pub(crate) chain: *mut stack_st_X509,
    /// What `SSL_get_peer_cert_chain` reports (owned): the chain on a client, the chain
    /// without the leaf on a server; or NULL.
    pub(crate) chain_no_leaf: *mut stack_st_X509,
    /// Whether verification accepted the chain, which makes its leaf the peer's certificate
    /// (`SSL_get0_peer_certificate`).
    pub(crate) accepted: bool,
    /// The chain verification built (owned), or NULL.
    pub(crate) verified: *mut stack_st_X509,
}

impl Default for PeerCerts {
    fn default() -> Self {
        Self {
            from: 0,
            chain: ptr::null_mut(),
            chain_no_leaf: ptr::null_mut(),
            accepted: false,
            verified: ptr::null_mut(),
        }
    }
}

impl Drop for PeerCerts {
    fn drop(&mut self) {
        // SAFETY: our own stacks and references, each NULL or live.
        unsafe { OPENSSL_sk_pop_free(self.chain.cast(), Some(x509_free)) };
        // SAFETY: as above.
        unsafe { OPENSSL_sk_pop_free(self.chain_no_leaf.cast(), Some(x509_free)) };
        // SAFETY: as above.
        unsafe { OPENSSL_sk_pop_free(self.verified.cast(), Some(x509_free)) };
    }
}

/// `X509_free` as a stack's free function.
pub(crate) unsafe extern "C" fn x509_free(p: *mut c_void) {
    // SAFETY: a certificate of the stack, which the stack owned.
    unsafe { X509_free(p.cast()) };
}

impl Driver {
    /// What `SSL_clear` leaves: the session's part (the peer's certificates and the cipher),
    /// with everything else back to its start. `self` keeps the rest, to be freed with no lock
    /// held.
    pub(crate) fn clear(&mut self) -> Self {
        let cipher = self
            .tls
            .as_ref()
            .and_then(|c| c.negotiated().cipher)
            .or(self.kept_cipher);
        Self {
            peer: core::mem::take(&mut self.peer),
            kept_cipher: cipher,
            group_names: core::mem::take(&mut self.group_names),
            provider: self.provider.take(),
            ..Self::default()
        }
    }
}

/// The core connection and what the driver keeps beside it.
#[derive(Default)]
pub(crate) struct Driver {
    /// The core's connection, once a handshake started (`None` while a step runs).
    pub(crate) tls: Option<Box<Connection>>,
    /// The cryptography of the connection's library context.
    pub(crate) provider: Option<Arc<EvpProvider>>,
    /// Output the core produced that the write BIO hasn't taken yet.
    pub(crate) out: Vec<u8>,
    /// A write waiting to be retried (`wpend_tot`, `wpend_buf`): what it accepted, and its
    /// buffer's address.
    pub(crate) wpend: Option<(usize, usize)>,
    /// Whether a call is driving the core (a callback re-entering is refused).
    pub(crate) driving: bool,
    /// The peer's certificates as objects.
    pub(crate) peer: PeerCerts,
    /// The last warning alert received (`s->s3.warn_alert`), for `SSL_ERROR_ZERO_RETURN`.
    pub(crate) warn_alert: u8,
    /// Whether the connection failed outside the core (an unexpected EOF).
    pub(crate) failed: bool,
    /// The selected ALPN protocol, at a stable address for `SSL_get0_alpn_selected`.
    pub(crate) alpn: Vec<u8>,
    /// The server name the client sent (server side), at a stable address.
    pub(crate) servername: Option<CString>,
    /// The record being read without read-ahead: its header so far, and the body left.
    pub(crate) rec_header: Vec<u8>,
    /// See `rec_header`.
    pub(crate) rec_left: usize,
    /// Whether any record has been read (only the first may be an SSLv2 ClientHello).
    pub(crate) first_record_done: bool,
    /// The cipher of a connection `SSL_clear` reset: OpenSSL keeps the session, and
    /// `SSL_get_current_cipher` reports its cipher until a new handshake replaces it.
    pub(crate) kept_cipher: Option<&'static rustyssl_tls::suites::Cipher>,
    /// The group names `SSL_group_to_name` handed out, kept for the connection's lifetime.
    pub(crate) group_names: Vec<CString>,
}

// SAFETY: the raw pointers are owned references (stacks of certificates) used under the
// connection's lock, as the rest of `SslState`'s.
unsafe impl Send for Driver {}

impl core::fmt::Debug for Driver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Driver")
            .field("tls", &self.tls.is_some())
            .field("out", &self.out.len())
            .field("driving", &self.driving)
            .finish_non_exhaustive()
    }
}

/// Raises the core's error as OpenSSL's ERR entry, in `function`. A received alert's reason
/// gets OpenSSL's data, `SSL alert number <n>`.
#[track_caller]
pub(crate) fn raise_core(e: &TlsError, function: &str) {
    let alert_reasons = SSL_AD_REASON_OFFSET..SSL_AD_REASON_OFFSET.saturating_add(256);
    if !e.library_reason && alert_reasons.contains(&e.reason) {
        let desc = e.reason.saturating_sub(SSL_AD_REASON_OFFSET);
        err::raise_with_text(
            ERR_LIB_SSL,
            e.reason,
            function,
            &format!("SSL alert number {desc}"),
        );
    } else if let Some(d) = e.data {
        err::raise_with_text(ERR_LIB_SSL, e.reason, function, d);
    } else {
        err::raise(ERR_LIB_SSL, e.reason, function);
    }
}

/// Copies the core's state into the mirrors the getters read.
fn mirror(st: &mut SslState, c: &Connection) {
    st.hand_state = c.state();
    st.in_init = c.in_init();
    st.flow_uninited = c.before();
    let n = c.negotiated();
    if n.cipher.is_some() {
        st.version = c_int::from(n.version);
    }
    st.shutdown =
        c_int::try_from(c.shutdown_state()).unwrap_or(0) | (st.shutdown & SSL_RECEIVED_SHUTDOWN);
    st.verify_result = c_long::try_from(n.verify_result).unwrap_or(c_long::MAX);
    st.hit = c_int::from(n.reused);
    let h = c.handshake();
    if h.client_random != [0; 32] {
        st.client_random = h.client_random;
    }
    if h.server_random != [0; 32] {
        st.server_random = h.server_random;
    }
    let (own, peer) = if st.server {
        (&n.server_finished, &n.client_finished)
    } else {
        (&n.client_finished, &n.server_finished)
    };
    own.clone_into(&mut st.finish_md);
    peer.clone_into(&mut st.peer_finish_md);
    st.drv.warn_alert = c.alerts().2;
    if let Some(a) = &n.alpn
        && *a != st.drv.alpn
    {
        a.clone_into(&mut st.drv.alpn);
    }
    if st.server
        && let Some(name) = &n.servername
        && st
            .drv
            .servername
            .as_ref()
            .is_none_or(|old| old.as_bytes() != name.as_slice())
    {
        st.drv.servername = CString::new(name.clone()).ok();
    }
}

/// The peer's chain as objects, made with no lock held (`d2i_X509` runs the application's
/// ex_data callbacks): `None` if the objects already made are of the core's chain.
fn peer_objects(c: &Connection, have: usize, server: bool) -> Option<PeerCerts> {
    let n = c.negotiated();
    if n.peer_chain.len() == have {
        return None;
    }
    let mut p = PeerCerts {
        from: n.peer_chain.len(),
        ..PeerCerts::default()
    };
    // SAFETY: no preconditions.
    p.chain = unsafe { OPENSSL_sk_new_null() }.cast();
    // SAFETY: as above.
    p.chain_no_leaf = unsafe { OPENSSL_sk_new_null() }.cast();
    for (i, der) in n.peer_chain.iter().enumerate() {
        let Ok(len) = c_long::try_from(der.len()) else {
            continue;
        };
        let mut q = der.as_ptr();
        // SAFETY: the certificate's octets.
        let x = unsafe { d2i_X509(ptr::null_mut(), &raw mut q, len) };
        if x.is_null() {
            continue;
        }
        // SAFETY: our new stack; the certificate, whose reference it takes.
        unsafe { OPENSSL_sk_push(p.chain.cast(), x.cast()) };
        // A server's peer chain leaves the client's certificate out (OpenSSL keeps it in the
        // session's peer, apart from the chain).
        if (i > 0 || !server)
            // SAFETY: the same certificate, a second reference for the second stack.
            && unsafe { X509_up_ref(x) } != 0
        {
            // SAFETY: as above.
            unsafe { OPENSSL_sk_push(p.chain_no_leaf.cast(), x.cast()) };
        }
    }
    Some(p)
}

/// Where a drive stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stop {
    /// The handshake finished.
    Done,
    /// Application data is ready.
    AppData,
    /// The peer sent close_notify (or the EOF counts as one).
    Closed,
    /// Nothing more to do (the handshake is done and the caller isn't reading).
    Idle,
    /// Waiting: `rwstate` says for what.
    Retry,
    /// Failed: the ERR entry is raised.
    Failed,
    /// An I/O failure with no ERR entry (`SSL_ERROR_SYSCALL`).
    Syscall,
}

/// What reading input found.
enum Input {
    /// Octets were fed to the core.
    Got,
    /// The BIO would block.
    Retry,
    /// End of file.
    Eof,
    /// The BIO failed without asking to retry.
    Error,
}

/// The read BIO, read without holding the lock (the BIO's own callbacks may run).
///
/// # Safety
/// `x` is a live connection.
unsafe fn read_input(x: &Ssl) -> Input {
    let (rbio, want) = {
        let mut st = x.state();
        let read_ahead = st.read_ahead != 0;
        let d = &mut st.drv;
        let want = if read_ahead {
            READ_AHEAD_CHUNK
        } else if d.rec_left > 0 {
            d.rec_left
        } else {
            let hdr = if !d.first_record_done
                && d.rec_header.first().is_some_and(|b| b & 0x80 != 0)
                && st.server
            {
                SSL2_HEADER_LEN
            } else {
                HEADER_LEN
            };
            hdr.saturating_sub(st.drv.rec_header.len()).max(1)
        };
        (st.rbio, want)
    };
    if rbio.is_null() {
        return Input::Error;
    }
    let mut buf = vec![0u8; want];
    let Ok(n) = c_int::try_from(buf.len()) else {
        return Input::Error;
    };
    // SAFETY: the connection's BIO; the room. No lock is held.
    let r = unsafe { BIO_read(rbio, buf.as_mut_ptr().cast(), n) };
    if r <= 0 {
        // SAFETY: as above.
        if unsafe { BIO_test_flags(rbio, BIO_FLAGS_SHOULD_RETRY) } != 0 {
            return Input::Retry;
        }
        // SAFETY: as above.
        if unsafe { BIO_ctrl(rbio, BIO_CTRL_EOF, 0, ptr::null_mut()) } != 0 {
            return Input::Eof;
        }
        return Input::Error;
    }
    let got = usize::try_from(r).unwrap_or(0).min(buf.len());
    buf.truncate(got);
    let mut st = x.state();
    let read_ahead = st.read_ahead != 0;
    if !read_ahead {
        let server = st.server;
        track_records(&mut st.drv, server, &buf);
    }
    if let Some(c) = st.drv.tls.as_mut() {
        c.feed(&buf);
    }
    Input::Got
}

/// Follows record boundaries in the input without read-ahead, so each read asks for exactly
/// the rest of the current record (`ssl3_read_n` without read-ahead).
fn track_records(d: &mut Driver, server: bool, mut data: &[u8]) {
    while !data.is_empty() {
        if d.rec_left > 0 {
            let n = d.rec_left.min(data.len());
            d.rec_left = d.rec_left.saturating_sub(n);
            data = data.get(n..).unwrap_or_default();
            if d.rec_left == 0 {
                d.rec_header.clear();
                d.first_record_done = true;
            }
            continue;
        }
        let sslv2 = !d.first_record_done
            && server
            && d.rec_header
                .first()
                .or(data.first())
                .is_some_and(|b| b & 0x80 != 0);
        let hdr_len = if sslv2 { SSL2_HEADER_LEN } else { HEADER_LEN };
        let need = hdr_len.saturating_sub(d.rec_header.len());
        let n = need.min(data.len());
        d.rec_header
            .extend_from_slice(data.get(..n).unwrap_or_default());
        data = data.get(n..).unwrap_or_default();
        if d.rec_header.len() == hdr_len {
            let b = |i: usize| usize::from(d.rec_header.get(i).copied().unwrap_or(0));
            d.rec_left = if sslv2 {
                ((b(0) & 0x7f) << 8) | b(1)
            } else {
                (b(3) << 8) | b(4)
            };
            if d.rec_left == 0 {
                d.rec_header.clear();
                d.first_record_done = true;
            }
        }
    }
}

/// What flushing the output found.
pub(crate) enum Flush {
    /// All written.
    Done,
    /// The BIO would block; the rest is kept.
    Retry,
    /// The BIO failed.
    Error,
}

/// Writes the pending output to the write BIO, without holding the lock.
///
/// # Safety
/// `x` is a live connection.
pub(crate) unsafe fn flush(x: &Ssl) -> Flush {
    loop {
        let (wbio, chunk) = {
            let st = x.state();
            if st.drv.out.is_empty() {
                return Flush::Done;
            }
            (st.wbio, st.drv.out.clone())
        };
        if wbio.is_null() {
            return Flush::Error;
        }
        let Ok(n) = c_int::try_from(
            chunk
                .len()
                .min(usize::try_from(c_int::MAX).unwrap_or(usize::MAX)),
        ) else {
            return Flush::Error;
        };
        // SAFETY: the connection's BIO; the octets. No lock is held.
        let r = unsafe { BIO_write(wbio, chunk.as_ptr().cast(), n) };
        if r <= 0 {
            // SAFETY: as above.
            if unsafe { BIO_test_flags(wbio, BIO_FLAGS_SHOULD_RETRY) } != 0 {
                x.state().rwstate = SSL_WRITING;
                return Flush::Retry;
            }
            return Flush::Error;
        }
        let done = usize::try_from(r).unwrap_or(0).min(chunk.len());
        let mut st = x.state();
        let out = &mut st.drv.out;
        out.drain(..done.min(out.len()));
    }
}

/// The connection's provider of TLS crypto, made from its context's library context on first
/// use.
///
/// # Safety
/// `snap` is `x`'s context's snapshot.
pub(crate) unsafe fn provider(x: &Ssl, snap: &config::CtxSnapshot) -> Arc<EvpProvider> {
    let mut st = x.state();
    match &st.drv.provider {
        Some(p) => Arc::clone(p),
        None => {
            // SAFETY: the context's library context (it outlives the connection) and property
            // query.
            let p = Arc::new(unsafe { EvpProvider::new(snap.libctx, snap.propq()) });
            st.drv.provider = Some(Arc::clone(&p));
            p
        }
    }
}

/// The core's hook for the connection's security callback (`ssl_security` calling
/// `sec_cb(s, NULL, op, bits, nid, other, sec_ex)`), or `None` while it is the default one,
/// which the core applies itself. The core calls it during a step, with no lock held; `other`
/// is the `SSL_CIPHER *`, the two code point octets, or NULL. A NULL callback (which OpenSSL
/// would call) aborts (security rule 10).
///
/// # Safety
/// `s` is the live connection behind `x`; the hook is used while it lives.
pub(crate) unsafe fn security_hook(s: *mut SSL, x: &Ssl) -> Option<SecurityHook> {
    let (cb, ex) = {
        let st = x.state();
        (st.cert.sec_cb, st.cert.sec_ex)
    };
    let Some(f) = cb else {
        crate::stub::unimplemented("a handshake with a NULL security callback");
    };
    let default: super::types::SecCb = Some(super::cert::default_security_callback);
    if default.is_some_and(|d| core::ptr::fn_addr_eq(f, d)) {
        return None;
    }
    // The pointers travel as addresses: the hook must be `Send + Sync`, and the connection
    // outlives its core connection.
    let (s_addr, ex_addr) = (s.expose_provenance(), ex.expose_provenance());
    Some(Arc::new(move |op, bits, nid, other| {
        let s = ptr::with_exposed_provenance_mut::<SSL>(s_addr);
        let ex = ptr::with_exposed_provenance_mut::<c_void>(ex_addr);
        let code: [u8; 2];
        let other: *mut c_void = match other {
            SecOther::None => ptr::null_mut(),
            // The suite table's entry, as `cipher_ptr` gives it.
            SecOther::Cipher(c) => ptr::from_ref(c).cast_mut().cast(),
            SecOther::CodePoint(b) => {
                code = b;
                code.as_ptr().cast_mut().cast()
            }
        };
        // SAFETY: the application's callback with its arguments; no lock is held.
        unsafe { f(s, ptr::null(), op, bits, nid, other, ex) != 0 }
    }))
}

/// Starts the core connection if there isn't one (`SSL_do_handshake`'s first call, or the
/// first `SSL_read`/`SSL_write`), with a configuration from the connection and its context.
///
/// # Safety
/// `s` is the live connection behind `x`.
pub(crate) unsafe fn ensure_core(s: *mut SSL, x: &Ssl) -> bool {
    if x.state().drv.tls.is_some() {
        return true;
    }
    let Some(snap) = config::snapshot(x) else {
        return false;
    };
    // SAFETY: the context's library context (it outlives the connection).
    let prov = unsafe { provider(x, &snap) };
    // SAFETY: the caller's connection; its context's snapshot.
    let cfg = unsafe { config::build(s, x, &snap, &prov) };
    // SAFETY: the caller's connection.
    let hook = unsafe { security_hook(s, x) };
    let mut cfg = cfg;
    cfg.custom_security_callback = hook.is_some();
    let mut c = Box::new(Connection::new(cfg));
    c.set_security_hook(hook);
    c.start();
    let mut st = x.state();
    if st.drv.tls.is_none() {
        mirror(&mut st, &c);
        st.drv.tls = Some(c);
    }
    true
}

/// Calls the info callback (the connection's, else its context's) with no lock held.
///
/// # Safety
/// `s` is the live connection behind `x`.
pub(crate) unsafe fn info(
    s: *mut SSL,
    x: &Ssl,
    snap: Option<&CtxSnapshot>,
    where_: c_int,
    ret: c_int,
) {
    let cb = x
        .state()
        .info_callback
        .or_else(|| snap.and_then(|c| c.info_callback));
    if let Some(cb) = cb {
        // SAFETY: the application's callback with its connection; no lock is held.
        unsafe { cb(s, where_, ret) };
    }
}

/// Runs the core until it reaches a stop for the caller's purpose: the handshake's end, or
/// (when `reading`) application data or closure. Reports `SSL_CB_*_EXIT` when the handshake
/// part returns, as `state_machine` does.
///
/// # Safety
/// `s` is the live connection behind `x`.
pub(crate) unsafe fn drive(s: *mut SSL, x: &Ssl, reading: bool, function: &str) -> Stop {
    {
        let mut st = x.state();
        if st.drv.driving {
            drop(st);
            err::raise(ERR_LIB_SSL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, function);
            return Stop::Failed;
        }
        if st.drv.failed {
            return Stop::Failed;
        }
        st.drv.driving = true;
        st.rwstate = SSL_NOTHING;
    }
    // SAFETY: the caller's guarantee.
    let stop = unsafe { drive_inner(s, x, reading, function) };
    x.state().drv.driving = false;
    stop
}

/// The step loop of [`drive`].
///
/// # Safety
/// As for [`drive`].
unsafe fn drive_inner(s: *mut SSL, x: &Ssl, reading: bool, function: &str) -> Stop {
    let snap = config::snapshot(x);
    let server = x.state().server;
    let exit = if server {
        SSL_CB_ACCEPT_EXIT
    } else {
        SSL_CB_CONNECT_EXIT
    };
    let mut in_handshake = false;
    let stop = loop {
        // SAFETY: the caller's guarantee.
        match unsafe { flush(x) } {
            Flush::Done => {}
            Flush::Retry => break Stop::Retry,
            Flush::Error => break Stop::Syscall,
        }
        let taken = {
            let mut st = x.state();
            let prov = st.drv.provider.clone();
            st.drv.tls.take().zip(prov)
        };
        let Some((mut conn, prov)) = taken else {
            err::raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR, function);
            break Stop::Failed;
        };
        if conn.in_init() {
            in_handshake = true;
        }
        let r = conn.step(&*prov, reading);
        let out = conn.take_output();
        let have = x.state().drv.peer.from;
        let peers = peer_objects(&conn, have, server);
        let old_peers = {
            let mut st = x.state();
            st.drv.out.extend_from_slice(&out);
            mirror(&mut st, &conn);
            st.drv.tls = Some(conn);
            peers.map(|mut p| {
                // The verified chain stays until verification replaces it.
                core::mem::swap(&mut p.verified, &mut st.drv.peer.verified);
                core::mem::replace(&mut st.drv.peer, p)
            })
        };
        // Freed with no lock held (ex_data callbacks).
        drop(old_peers);
        let ev = match r {
            Ok(ev) => ev,
            Err(e) => {
                raise_core(&e, function);
                // The alert goes out if the BIO takes it.
                // SAFETY: the caller's guarantee.
                let _ = unsafe { flush(x) };
                break Stop::Failed;
            }
        };
        match ev {
            Event::Info { where_, ret } => {
                // SAFETY: the caller's guarantee.
                unsafe { info(s, x, snap.as_ref(), where_, ret) };
            }
            Event::Message {
                write,
                version,
                content_type,
                bytes,
            } => {
                // SAFETY: as above.
                unsafe { message(s, x, write, version, content_type, &bytes) };
            }
            Event::Keylog(line) => {
                if let Some(cb) = snap.as_ref().and_then(|c| c.keylog_callback)
                    && let Ok(l) = CString::new(line)
                {
                    // SAFETY: the application's callback with its connection and a
                    // NUL-terminated line; no lock is held.
                    unsafe { cb(s, l.as_ptr()) };
                }
            }
            // Sessions and their cache arrive with `SSL_SESSION`: nothing to update yet.
            Event::UpdateCache { .. } | Event::RemoveSession => {}
            Event::Request(req) => {
                // SAFETY: as above.
                match unsafe { requests::handle(s, x, snap.as_ref(), req) } {
                    Some(a) => {
                        if let Some(c) = x.state().drv.tls.as_mut() {
                            c.answer(a);
                        }
                    }
                    None => break Stop::Retry,
                }
            }
            Event::Output => {}
            Event::NeedInput => {
                // SAFETY: as above.
                match unsafe { read_input(x) } {
                    Input::Got => {}
                    Input::Retry => {
                        x.state().rwstate = SSL_READING;
                        break Stop::Retry;
                    }
                    Input::Eof => {
                        let ignore = x.state().options & SSL_OP_IGNORE_UNEXPECTED_EOF != 0;
                        if ignore {
                            let mut st = x.state();
                            st.shutdown |= SSL_RECEIVED_SHUTDOWN;
                            st.drv.warn_alert = u8::try_from(SSL_AD_CLOSE_NOTIFY).unwrap_or(0);
                            if let Some(c) = st.drv.tls.as_mut() {
                                let f = c.shutdown_state() | rustyssl_tls::conn::RECEIVED_SHUTDOWN;
                                c.set_shutdown_state(f);
                            }
                            break Stop::Closed;
                        }
                        err::raise(ERR_LIB_SSL, SSL_R_UNEXPECTED_EOF_WHILE_READING, function);
                        x.state().drv.failed = true;
                        break Stop::Failed;
                    }
                    Input::Error => break Stop::Syscall,
                }
            }
            Event::HandshakeDone => {
                // SAFETY: as above.
                match unsafe { flush(x) } {
                    Flush::Done => {}
                    Flush::Retry => break Stop::Retry,
                    Flush::Error => break Stop::Syscall,
                }
                if in_handshake {
                    in_handshake = false;
                    // SAFETY: as above.
                    unsafe { info(s, x, snap.as_ref(), exit, 1) };
                }
                if !reading {
                    break Stop::Done;
                }
            }
            Event::AppData => break Stop::AppData,
            Event::Idle => {
                // SAFETY: as above.
                match unsafe { flush(x) } {
                    Flush::Done => break Stop::Idle,
                    Flush::Retry => break Stop::Retry,
                    Flush::Error => break Stop::Syscall,
                }
            }
            Event::Closed => break Stop::Closed,
        }
    };
    if in_handshake && stop != Stop::Done {
        // SAFETY: the caller's guarantee.
        unsafe { info(s, x, snap.as_ref(), exit, -1) };
    }
    stop
}

/// Calls the message callback with no lock held.
///
/// # Safety
/// `s` is the live connection behind `x`.
unsafe fn message(
    s: *mut SSL,
    x: &Ssl,
    write: bool,
    version: c_int,
    content_type: c_int,
    bytes: &[u8],
) {
    let (cb, arg) = {
        let st = x.state();
        (st.msg_callback, st.msg_callback_arg)
    };
    if let Some(cb) = cb {
        // SAFETY: the application's callback with the octets, its connection, and its
        // argument; no lock is held.
        unsafe {
            cb(
                c_int::from(write),
                version,
                content_type,
                bytes.as_ptr().cast(),
                bytes.len(),
                s,
                arg,
            )
        };
    }
}

/// The read and write BIOs, as `SSL_get_error` inspects them.
pub(crate) fn bios(x: &Ssl) -> (*mut BIO, *mut BIO) {
    let st = x.state();
    (st.rbio, st.wbio)
}

#[cfg(test)]
mod tests;
