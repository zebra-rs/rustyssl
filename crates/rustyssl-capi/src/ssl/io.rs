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
pub(crate) mod ticket_key;

use core::ffi::{c_int, c_long, c_void};
use core::ptr;
use std::ffi::CString;
use std::sync::{Arc, Mutex, PoisonError};

use rustyssl_abi::{
    BIO, BIO_CTRL_EOF, BIO_FLAGS_READ, BIO_FLAGS_RWS, BIO_FLAGS_SHOULD_RETRY, ERR_LIB_SSL,
    ERR_R_INTERNAL_ERROR, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, SSL, SSL_AD_CLOSE_NOTIFY,
    SSL_AD_REASON_OFFSET, SSL_CB_ACCEPT_EXIT, SSL_CB_CONNECT_EXIT, SSL_MODE_AUTO_RETRY,
    SSL_NOTHING, SSL_OP_IGNORE_UNEXPECTED_EOF, SSL_R_UNEXPECTED_EOF_WHILE_READING, SSL_READING,
    SSL_RECEIVED_SHUTDOWN, SSL_WRITING, stack_st_X509,
};
use rustyssl_tls::conn::common::security::SecOther;
use rustyssl_tls::conn::common::{EarlyDataState, SecurityHook};
use rustyssl_tls::conn::{Connection, Event, Request};
use rustyssl_tls::error::Error as TlsError;
use rustyssl_tls::record::PaddingHook;

use self::config::CtxSnapshot;
use super::conn::{Ssl, SslState};
use super::tls_provider::EvpProvider;
use crate::bio::{BIO_ctrl, BIO_read, BIO_test_flags, BIO_write};
use crate::err;
use crate::stack::{OPENSSL_sk_new_null, OPENSSL_sk_pop_free, OPENSSL_sk_push};
use crate::x509::cert::{X509_free, X509_up_ref};

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
    /// What's left to write of the record at the front of `out` (0: a record starts there).
    pub(crate) out_record_left: usize,
    /// DTLS: the lengths of the datagrams in `out`, in order.
    pub(crate) out_dgrams: std::collections::VecDeque<usize>,
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
    /// The peer's raw public key (RFC 7250) as an object, decoded on first use.
    pub(crate) peer_rpk: PeerRpk,
    /// The core's round-trip marks last seen, and when each last moved (`ts_msg_write`,
    /// `ts_msg_read`), for `SSL_get_handshake_rtt`.
    pub(crate) rtt_marks: (u32, u32),
    /// See `rtt_marks`.
    pub(crate) rtt_times: (Option<std::time::Instant>, Option<std::time::Instant>),
    /// TLS 1.3's early data state (`early_data_state`), kept here before the core exists and
    /// mirrored from it after.
    pub(crate) early_data_state: EarlyDataState,
    /// The core's peer CA names that `SslState::peer_ca_names` was last made from.
    pub(crate) peer_ca_names: Option<Vec<Vec<u8>>>,
    /// The last ClientHello's cipher suites seen, and whether `CipherLists::peer` is yet to be
    /// made from them (once the hello is processed and a TLS 1.2 resumption is known).
    pub(crate) peer_ciphers_raw: (Vec<u8>, bool),
}

/// An owned `EVP_PKEY` (the peer's raw public key), freed with the connection.
#[derive(Debug)]
pub(crate) struct PeerRpk(pub(crate) *mut rustyssl_abi::EVP_PKEY);

impl Default for PeerRpk {
    fn default() -> Self {
        Self(ptr::null_mut())
    }
}

impl Drop for PeerRpk {
    fn drop(&mut self) {
        // SAFETY: our key, or NULL.
        unsafe { crate::evp::pkey::EVP_PKEY_free(self.0) };
    }
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
    // OpenSSL's raising function when the core named it, else the API function's.
    let function = e.func.unwrap_or(function);
    if let Some(c) = e.cause {
        err::raise(c.lib, c.reason, c.func);
    }
    // An alert sent with `SSLfatal_alert` has no entry of its own.
    if e.reason == 0 && !e.library_reason {
        return;
    }
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
    // `ossl_tls_handle_rlayer_return`'s entry after a record-layer failure that sent an alert.
    if let Some(r) = e.follow_up {
        err::raise(ERR_LIB_SSL, r, "");
    }
}

/// A client's copy of the OCSP response the server stapled (`s->ext.ocsp.resp`), which
/// `SSL_get_tlsext_status_ocsp_resp` returns (to the status callback too), unless it already
/// holds it.
///
/// # Safety
/// `st.ocsp_resp` is NULL or the connection's own `st.ocsp_resp_len` octets (C memory).
unsafe fn set_peer_ocsp(st: &mut SslState, resp: &[u8]) {
    if !st.ocsp_resp.is_null()
        // SAFETY: the caller's guarantee.
        && unsafe { core::slice::from_raw_parts(st.ocsp_resp, st.ocsp_resp_len) } == resp
    {
        return;
    }
    let copy: *mut u8 = crate::mem::alloc(resp.len().max(1)).cast();
    if copy.is_null() {
        return;
    }
    // SAFETY: a fresh block of at least `resp.len()` octets.
    unsafe { core::ptr::copy_nonoverlapping(resp.as_ptr(), copy, resp.len()) };
    let old = core::mem::replace(&mut st.ocsp_resp, copy);
    st.ocsp_resp_len = resp.len();
    // SAFETY: the response the connection owned (C memory), or NULL.
    unsafe { crate::mem::release(old.cast()) };
}

/// `parse_ca_names`'s list, as `X509_NAME`s: the names the peer sent (NULL when it sent no
/// list, empty when it sent an empty one), replacing the connection's.
///
/// # Safety
/// `st.peer_ca_names` is NULL or the connection's own list.
unsafe fn set_peer_ca_names(st: &mut SslState, names: Option<&[Vec<u8>]>) {
    // SAFETY: the caller's guarantee.
    unsafe { OPENSSL_sk_pop_free(st.peer_ca_names.cast(), Some(super::ctx::name_free)) };
    st.peer_ca_names = ptr::null_mut();
    let Some(names) = names else {
        return;
    };
    // SAFETY: no preconditions.
    let sk: *mut rustyssl_abi::stack_st_X509_NAME = unsafe { OPENSSL_sk_new_null() }.cast();
    if sk.is_null() {
        return;
    }
    for der in names {
        let Ok(len) = c_long::try_from(der.len()) else {
            continue;
        };
        let mut p = der.as_ptr();
        // SAFETY: the name's octets (the core checked that they decode).
        let nm = unsafe { crate::x509::name::d2i_X509_NAME(ptr::null_mut(), &raw mut p, len) };
        // SAFETY: our stack, which takes the name.
        if !nm.is_null() && unsafe { OPENSSL_sk_push(sk.cast(), nm.cast()) } == 0 {
            // SAFETY: not taken.
            unsafe { crate::x509::name::X509_NAME_free(nm) };
        }
    }
    st.peer_ca_names = sk;
}

/// Copies the core's state into the mirrors the getters read.
fn mirror(st: &mut SslState, c: &Connection) {
    st.hand_state = c.state();
    // A server's `peer_ciphers` (`bytes_to_cipher_list` of each ClientHello), which outlast
    // the handshake (`SSL_get_client_ciphers`, `SSL_get_shared_ciphers`). OpenSSL keeps the
    // old list when it resumes a TLS 1.2 session.
    if let Some(raw) = c.raw_cipherlist()
        && raw != st.drv.peer_ciphers_raw.0.as_slice()
    {
        st.drv.peer_ciphers_raw = (raw.to_vec(), true);
    }
    if st.drv.peer_ciphers_raw.1 && c.state() != rustyssl_abi::TLS_ST_SR_CLNT_HELLO {
        st.drv.peer_ciphers_raw.1 = false;
        let resumed12 = c.negotiated().reused && !c.is_tls13();
        if !resumed12 && let Some(list) = super::ciphers::peer_list(&st.drv.peer_ciphers_raw.0) {
            st.ciphers.peer = list;
        }
    }
    st.drv.early_data_state = c.early_data_state();
    let marks = c.rtt_marks();
    if marks != st.drv.rtt_marks {
        let now = std::time::Instant::now();
        if marks.0 != st.drv.rtt_marks.0 {
            st.drv.rtt_times.0 = Some(now);
        }
        if marks.1 != st.drv.rtt_marks.1 {
            st.drv.rtt_times.1 = Some(now);
        }
        st.drv.rtt_marks = marks;
    }
    st.in_init = c.event_in_init();
    st.flow_uninited = c.before();
    let n = c.negotiated();
    // Once the hellos chose it (`ssl_choose_server_version` sets `s->version` before the
    // certificate callback runs), or with a suite.
    if n.cipher.is_some() || (!c.before() && c.version_decided()) {
        st.version = c_int::from(n.version);
    }
    st.shutdown =
        c_int::try_from(c.shutdown_state()).unwrap_or(0) | (st.shutdown & SSL_RECEIVED_SHUTDOWN);
    st.verify_result = c_long::try_from(n.verify_result).unwrap_or(c_long::MAX);
    st.hit = c_int::from(n.reused);
    // `s->s3.send_connection_binding`: the peer's renegotiation_info (or SCSV) was seen.
    st.send_connection_binding = c_int::from(n.secure_renegotiation);
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
    if !st.server
        && let Some(r) = &n.ocsp_response
    {
        // SAFETY: the connection's own response, or NULL.
        unsafe { set_peer_ocsp(st, r) };
    }
    if n.peer_ca_names != st.drv.peer_ca_names {
        n.peer_ca_names.clone_into(&mut st.drv.peer_ca_names);
        // SAFETY: the connection's own list, or NULL, replaced (no callbacks run).
        unsafe { set_peer_ca_names(st, n.peer_ca_names.as_deref()) };
    }
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
///
/// # Safety
/// `libctx` is NULL or a live library context; `propq` is NULL or a string.
unsafe fn peer_objects(
    c: &Connection,
    have: usize,
    server: bool,
    libctx: *mut rustyssl_abi::OSSL_LIB_CTX,
    propq: *const core::ffi::c_char,
) -> Option<PeerCerts> {
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
        // Decoded in the connection's library context (`tls_process_server_certificate`).
        // SAFETY: the caller's guarantee.
        let x = unsafe { crate::x509::cert::decode_in(der, libctx, propq) };
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
    if x.state().method.dtls {
        // SAFETY: the caller's guarantee.
        return unsafe { read_datagram(x) };
    }
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

/// DTLS: one datagram from the read BIO (`dtls_get_more_records`' read with room for the
/// largest record).
///
/// # Safety
/// `x` is a live connection.
unsafe fn read_datagram(x: &Ssl) -> Input {
    let rbio = x.state().rbio;
    if rbio.is_null() {
        return Input::Error;
    }
    let size = |v: c_int| usize::try_from(v).unwrap_or(0);
    let want = size(rustyssl_abi::SSL3_RT_MAX_PLAIN_LENGTH)
        .saturating_add(size(rustyssl_abi::SSL3_RT_MAX_ENCRYPTED_OVERHEAD))
        .saturating_add(rustyssl_tls::record::dtls::HEADER_LEN)
        .saturating_add(size(rustyssl_abi::SSL3_ALIGN_PAYLOAD));
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
    buf.truncate(usize::try_from(r).unwrap_or(0));
    if let Some(c) = x.state().drv.tls.as_mut() {
        c.feed_datagram(&buf);
    }
    Input::Got
}

/// Moves the core's output (DTLS: its datagrams) to the driver's buffer.
pub(crate) fn push_output(d: &mut Driver, c: &mut Connection) {
    if c.config().dtls {
        for dg in c.take_datagrams() {
            d.out_dgrams.push_back(dg.len());
            d.out.extend_from_slice(&dg);
        }
    } else {
        let out = c.take_output();
        d.out.extend_from_slice(&out);
    }
}

/// [`push_output`] for the connection's core, if it's in place.
pub(crate) fn move_output(st: &mut SslState) {
    let d = &mut st.drv;
    if let Some(mut c) = d.tls.take() {
        push_output(d, &mut c);
        d.tls = Some(c);
    }
}

/// Calls the message callback with no lock held (for what the core doesn't report itself).
///
/// # Safety
/// `s` is the live connection behind `x`.
pub(crate) unsafe fn report(
    s: *mut SSL,
    x: &Ssl,
    write: bool,
    version: c_int,
    content_type: c_int,
    bytes: &[u8],
) {
    // SAFETY: the caller's guarantee.
    unsafe { message(s, x, write, version, content_type, bytes) };
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
        // One record per write, as the record layer writes them (a BIO that takes only some
        // writes sees each record retried on its own).
        let (wbio, chunk) = {
            let mut st = x.state();
            if st.drv.out.is_empty() {
                st.drv.out_record_left = 0;
                return Flush::Done;
            }
            if st.drv.out_record_left == 0 {
                st.drv.out_record_left = if st.method.dtls {
                    // One datagram per write.
                    st.drv.out_dgrams.pop_front().unwrap_or(st.drv.out.len())
                } else {
                    record_len(&st.drv.out)
                };
            }
            let n = st.drv.out_record_left.min(st.drv.out.len());
            (st.wbio, st.drv.out.get(..n).unwrap_or_default().to_vec())
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
            // `tls_retry_write_records`: a failed write that won't be retried is a system
            // error (a zero return isn't, as it may come from a custom BIO).
            if r < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                err::raise_with_text(
                    rustyssl_abi::ERR_LIB_SYS,
                    errno,
                    "tls_retry_write_records",
                    "tls_retry_write_records failure",
                );
            }
            return Flush::Error;
        }
        let done = usize::try_from(r).unwrap_or(0).min(chunk.len());
        let mut st = x.state();
        st.drv.out_record_left = st.drv.out_record_left.saturating_sub(done);
        let out = &mut st.drv.out;
        out.drain(..done.min(out.len()));
    }
}

/// The length of the TLS record at the front of `out` (header included), or all of `out` when
/// it doesn't start with a whole header.
fn record_len(out: &[u8]) -> usize {
    match out.get(..5) {
        Some(&[_, _, _, hi, lo]) => {
            5usize.saturating_add(usize::from(u16::from_be_bytes([hi, lo])))
        }
        _ => out.len(),
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

/// The core's hook for the record padding callback (`rlayer_padding_wrapper`): the
/// connection's callback and argument when a record is written, read from its padding cell.
/// The core asks whether there is a callback when it makes a write epoch's record layer, as
/// OpenSSL decides there whether to pad with it.
///
/// # Safety
/// `s` is a live connection; the hook is used while it lives.
unsafe fn padding_hook(s: *mut SSL, st: &SslState) -> PaddingHook {
    let current = |cell: &Mutex<super::conn::PaddingCell>| {
        let c = cell.lock().unwrap_or_else(PoisonError::into_inner);
        (c.0, c.1)
    };
    let cell = Arc::clone(&st.padding_cell);
    let present = Arc::clone(&cell);
    // The connection's pointer travels as an address: the hook must be `Send + Sync`, and the
    // connection outlives its core connection.
    let s_addr = s.expose_provenance();
    PaddingHook {
        pad: Arc::new(move |ty, len| {
            let s = ptr::with_exposed_provenance_mut::<SSL>(s_addr);
            let (cb, arg) = current(&cell);
            // SAFETY: the application's callback with its arguments.
            cb.map(|f| unsafe { f(s, c_int::from(ty), len, arg) })
        }),
        present: Arc::new(move || current(&present).0.is_some()),
    }
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
    // SAFETY: as above.
    c.set_padding_hook(Some(unsafe { padding_hook(s, &x.state()) }));
    c.start();
    let mut st = x.state();
    if st.drv.tls.is_none() {
        c.set_early_data_state(st.drv.early_data_state);
        mirror(&mut st, &c);
        st.drv.tls = Some(c);
    }
    true
}

/// Sets the early data state, in the core too once it exists.
pub(crate) fn set_early_data_state(st: &mut SslState, e: EarlyDataState) {
    st.drv.early_data_state = e;
    if let Some(c) = st.drv.tls.as_mut() {
        c.set_early_data_state(e);
    }
}

/// `ossl_statem_check_finish_init` (`sending`: 0 for a read, 1 for a write, -1 for a
/// handshake call): a handshake stopped for early data goes on. Nothing before the core exists.
pub(crate) fn check_finish_init(x: &Ssl, sending: c_int) {
    let mut st = x.state();
    let Some(c) = st.drv.tls.as_mut() else { return };
    c.check_finish_init(sending);
    let (in_init, e) = (c.in_init(), c.early_data_state());
    st.in_init = in_init;
    st.drv.early_data_state = e;
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

/// Whether the info, message, and key log callbacks are installed now: the application may
/// set them at any time, and the core reports to them as OpenSSL calls them when set.
pub(crate) fn notify_flags(
    st: &SslState,
    snap: Option<&config::CtxSnapshot>,
) -> (bool, bool, bool) {
    (
        st.info_callback.is_some() || snap.is_some_and(|c| c.info_callback.is_some()),
        st.msg_callback.is_some(),
        snap.is_some_and(|c| c.keylog_callback.is_some()),
    )
}

/// Whether the connection has `SSL_MODE_AUTO_RETRY` (the default).
fn auto_retry(x: &Ssl) -> bool {
    x.state().mode & SSL_MODE_AUTO_RETRY != 0
}

/// The step loop of [`drive`].
///
/// # Safety
/// As for [`drive`].
unsafe fn drive_inner(s: *mut SSL, x: &Ssl, reading: bool, function: &str) -> Stop {
    let mut snap = config::snapshot(x);
    let server = x.state().server;
    let exit = if server {
        SSL_CB_ACCEPT_EXIT
    } else {
        SSL_CB_CONNECT_EXIT
    };
    let mut in_handshake = false;
    // Whether a handshake message arrived after the handshake (see `Event::HandshakeDone`).
    let mut post_handshake = false;
    let mut cleared = false;
    // Whether the connection had failed when this call began (the core reports the alert
    // and the exit before the failure, so a later step sees its own error).
    let mut failed_at_entry = None;
    let dtls = x.state().method.dtls;
    if dtls {
        // `dtls1_query_mtu`, before the handshake writes (a write in a DTLS handshake fails
        // without an MTU).
        // SAFETY: the caller's guarantee.
        let _ = unsafe { super::dtls::query_mtu(x) };
    }
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
            let notify = notify_flags(&st, snap.as_ref());
            st.drv.tls.take().zip(prov).map(|(mut c, p)| {
                c.config_mut().callbacks.info = notify.0;
                c.config_mut().callbacks.msg = notify.1;
                c.config_mut().callbacks.keylog = notify.2;
                (c, p)
            })
        };
        let Some((mut conn, prov)) = taken else {
            err::raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR, function);
            break Stop::Failed;
        };
        let was_init = conn.in_init();
        // A connection that already failed fails again with no new entry, and the queue is
        // kept (`state_machine` returns at once in `MSG_FLOW_ERROR`).
        let failed_before = *failed_at_entry.get_or_insert_with(|| conn.error().is_some());
        if was_init {
            in_handshake = true;
            if !cleared && !failed_before {
                // `state_machine` starts with `ERR_clear_error` and `clear_sys_error` (fork M).
                cleared = true;
                // SAFETY: no preconditions.
                unsafe { crate::err::ERR_clear_error() };
                crate::errno::set(0);
            }
        }
        let (was_before, was_in_init) = (conn.before(), conn.in_init());
        let skipped = conn.skipped_records();
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_set_mark() };
        let r = conn.step(&*prov, reading);
        // A skipped early data record's failed decryption leaves nothing on the queue.
        if conn.skipped_records() == skipped {
            // SAFETY: the mark set above.
            unsafe { crate::err::ERR_clear_last_mark() };
        } else {
            // SAFETY: as above.
            unsafe { crate::err::ERR_pop_to_mark() };
        }
        // A handshake's start (`tls_setup_handshake`) and a TLS 1.3 server's end, which the
        // session cache counts.
        let started = if was_before && !conn.before() {
            Some(true)
        } else {
            (!was_in_init && conn.in_init() && !conn.is_tls13()).then_some(false)
        };
        // (A stop for early data isn't the end.)
        let tls13_server_done = server
            && was_in_init
            && !conn.in_init()
            && conn.is_tls13()
            && conn.state() != rustyssl_abi::TLS_ST_EARLY_DATA;
        // A handshake message after the handshake took the connection back into init: the
        // next step runs it, with no more input needed (fork M).
        let entered = !was_init && conn.in_init();
        if entered {
            in_handshake = true;
            post_handshake = true;
        }
        let timer = conn.take_dtls_timer();
        let have = x.state().drv.peer.from;
        let (libctx, propq) = snap
            .as_ref()
            .map_or((ptr::null_mut(), ptr::null()), |c| (c.libctx, c.propq()));
        // SAFETY: the snapshot's library context and properties, alive with it.
        let peers = unsafe { peer_objects(&conn, have, server, libctx, propq) };
        let old_peers = {
            let mut st = x.state();
            push_output(&mut st.drv, &mut conn);
            mirror(&mut st, &conn);
            st.drv.tls = Some(conn);
            if let Some(first) = started {
                super::sess_cache::on_start(&mut st, first);
            }
            peers.map(|mut p| {
                // The verified chain and the verdict stay until verification replaces them (a
                // server records the chain only after verifying it).
                core::mem::swap(&mut p.verified, &mut st.drv.peer.verified);
                p.accepted = st.drv.peer.accepted;
                core::mem::replace(&mut st.drv.peer, p)
            })
        };
        // Freed with no lock held (ex_data callbacks).
        drop(old_peers);
        if let Some(t) = timer {
            // SAFETY: the caller's guarantee; no lock is held.
            unsafe { super::dtls::apply_timer(s, x, t) };
        }
        if tls13_server_done {
            // SAFETY: the caller's guarantee; no lock is held.
            unsafe { super::sess_cache::on_finish_tls13_server(x) };
        }
        let ev = match r {
            Ok(ev) => ev,
            Err(e) => {
                if !failed_before {
                    raise_core(&e, function);
                }
                // A fatal alert (sent or received) takes the session out of the cache.
                // SAFETY: as above.
                unsafe { super::sess_cache::on_fatal(x) };
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
            Event::UpdateCache { server } => {
                // SAFETY: as above.
                unsafe { super::sess_cache::on_update_cache(s, x, server) };
            }
            Event::RemoveSession => {
                // SAFETY: as above.
                unsafe { super::sess_cache::on_remove_session(x) };
            }
            Event::Request(req) => {
                let servername = matches!(req, Request::Servername);
                // SAFETY: as above.
                let answer = unsafe { requests::handle(s, x, snap.as_ref(), req) };
                if servername {
                    // The servername callback may have switched the context
                    // (`SSL_set_SSL_CTX`): the later callbacks are the new context's.
                    snap = config::snapshot(x);
                }
                match answer {
                    Some(a) => {
                        if let Some(c) = x.state().drv.tls.as_mut() {
                            c.answer(a);
                        }
                    }
                    None => break Stop::Retry,
                }
            }
            Event::Output => {}
            Event::NeedInput if entered => {}
            Event::NeedInput => {
                // What was written goes out before waiting for the peer (`statem_flush`).
                // SAFETY: as above.
                match unsafe { flush(x) } {
                    Flush::Done => {}
                    Flush::Retry => break Stop::Retry,
                    Flush::Error => break Stop::Syscall,
                }
                // `dtls1_read_bytes`: a timer that fired retransmits before reading.
                if dtls && super::dtls::expired(x) {
                    // SAFETY: as above.
                    let r = unsafe { super::dtls::handle_timeout(s, x) };
                    if r > 0 {
                        continue;
                    }
                }
                // SAFETY: as above.
                match unsafe { read_input(x) } {
                    Input::Got => {}
                    Input::Retry => {
                        // Application data that arrived during a renegotiation is returned
                        // first (`ssl3_read_bytes` with `in_read_app_data`) (fork M).
                        if reading
                            && x.state()
                                .drv
                                .tls
                                .as_ref()
                                .is_some_and(|c| c.pending_app() > 0)
                        {
                            break Stop::AppData;
                        }
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
                        // `ossl_tls_handle_rlayer_return`: an unexpected EOF is fatal, with a
                        // decode_error alert (which the closed transport usually refuses), and a
                        // read reports it by returning 0.
                        // Raised there with no function (`ERR_set_debug(file, line, 0)`).
                        err::raise(ERR_LIB_SSL, SSL_R_UNEXPECTED_EOF_WHILE_READING, "");
                        {
                            let mut st = x.state();
                            st.drv.failed = true;
                            let prov = st.drv.provider.clone();
                            if let (Some(c), Some(p)) = (st.drv.tls.as_mut(), prov) {
                                c.fail(
                                    &*p,
                                    TlsError::alert(
                                        rustyssl_abi::SSL_AD_DECODE_ERROR,
                                        SSL_R_UNEXPECTED_EOF_WHILE_READING,
                                    ),
                                );
                                let mut c2 = st.drv.tls.take();
                                if let Some(cc) = c2.as_mut() {
                                    push_output(&mut st.drv, cc);
                                }
                                st.drv.tls = c2;
                            }
                        }
                        // SAFETY: the caller's guarantee.
                        let _ = unsafe { flush(x) };
                        if reading && !in_handshake {
                            x.state().rwstate = SSL_NOTHING;
                            break Stop::Closed;
                        }
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
                // `ssl3_read_bytes`: a handshake message after the handshake (a ticket, a
                // KeyUpdate) ends a read without SSL_MODE_AUTO_RETRY when no more input is
                // buffered, so a blocking caller can go back to select (s_client does).
                if post_handshake && !auto_retry(x) {
                    let rbio = {
                        let mut st = x.state();
                        let idle = st
                            .drv
                            .tls
                            .as_ref()
                            .is_some_and(|c| c.buffered_input() == 0 && c.pending_app() == 0);
                        if !idle || st.drv.rec_left > 0 || !st.drv.rec_header.is_empty() {
                            None
                        } else {
                            st.rwstate = SSL_READING;
                            Some(st.rbio)
                        }
                    };
                    if let Some(b) = rbio {
                        if !b.is_null() {
                            // SAFETY: the connection's BIO; no lock is held.
                            unsafe {
                                crate::bio::BIO_clear_flags(
                                    b,
                                    BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY,
                                )
                            };
                            // SAFETY: as above.
                            unsafe {
                                crate::bio::BIO_set_flags(
                                    b,
                                    BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY,
                                )
                            };
                        }
                        break Stop::Retry;
                    }
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
            Event::Interrupted => break Stop::Failed,
            Event::SessionRenewed => {
                // SAFETY: as above.
                unsafe { super::sess_cache::on_session_renewed(x) };
            }
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
