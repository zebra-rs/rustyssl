//! `SSL_poll` (`ssl/rio/poll_immediate.c`) and `SSL_inject_net_dgram`.

use core::ffi::{c_int, c_uchar};
use std::time::{Duration, Instant};

use libc::timeval;
use rustyssl_abi::{
    BIO_ADDR, BIO_POLL_DESCRIPTOR, BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD, BIO_POLL_DESCRIPTOR_TYPE_SSL,
    ERR_LIB_SSL, ERR_R_UNSUPPORTED, SSL, SSL_POLL_EVENT_EC, SSL_POLL_EVENT_ECD, SSL_POLL_EVENT_EL,
    SSL_POLL_EVENT_ER, SSL_POLL_EVENT_EW, SSL_POLL_EVENT_F, SSL_POLL_EVENT_IC, SSL_POLL_EVENT_ISB,
    SSL_POLL_EVENT_ISU, SSL_POLL_EVENT_OSB, SSL_POLL_EVENT_OSU, SSL_POLL_EVENT_R, SSL_POLL_EVENT_W,
    SSL_POLL_FLAG_NO_HANDLE_EVENTS, SSL_POLL_ITEM, SSL_R_POLL_REQUEST_NOT_SUPPORTED,
};
use rustyssl_quic::channel::{PeerAddr, State};
use rustyssl_quic::stream::{RecvState, SendState, is_uni};

use super::api::{self, Qctx};
use super::{EngineState, Kind};
use crate::err;
use crate::ffi::ffi_export;

/// Datagrams `SSL_inject_net_dgram` may queue before a tick takes them (ours: OpenSSL's
/// demuxer takes as many as memory allows).
pub(crate) const MAX_INJECTED: usize = 1024;

ffi_export! {
    /// Queues a datagram as if the network had delivered it from `peer` (the next tick
    /// processes it): 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live object; `buf` holds `buf_len` octets; `peer` and `local` NULL or
    /// live addresses.
    pub unsafe extern "C" fn rustyssl_private_SSL_inject_net_dgram(s: *mut SSL, buf: *const c_uchar, buf_len: usize, peer: *const BIO_ADDR, local: *const BIO_ADDR) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        let _ = local;
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { api::expect_csl(s) }) else { return 0 };
        if buf.is_null() && buf_len > 0 || isize::try_from(buf_len).is_err() {
            return 0;
        }
        let data = if buf_len == 0 {
            Vec::new()
        } else {
            // SAFETY: the caller's guarantee: `buf_len` readable octets.
            unsafe { core::slice::from_raw_parts(buf, buf_len) }.to_vec()
        };
        let from = if peer.is_null() {
            PeerAddr::default()
        } else {
            // SAFETY: the caller's guarantee.
            unsafe { super::peer_of(peer) }
        };
        let mut es = c.q.engine.lock();
        if es.injected.len() >= MAX_INJECTED {
            return 0;
        }
        es.injected.push_back((from, data));
        1
    }
}

/// `test_poll_event_*` and `ossl_quic_conn_poll_events`: the events of `events` that hold.
fn poll_events(c: &Qctx<'_>, es: &mut EngineState, events: u64) -> u64 {
    let mut rev = 0u64;
    let want = |e: u32| events & u64::from(e) != 0;
    if c.q.kind == Kind::Listener {
        if want(SSL_POLL_EVENT_IC) && !es.accept_queue.is_empty() {
            rev |= u64::from(SSL_POLL_EVENT_IC);
        }
        // A listener's port runs until it is freed: never EL.
        let _ = SSL_POLL_EVENT_EL;
        return rev;
    }
    let started = es.conn(c.conn).is_some_and(|r| r.ch.is_some());
    if !started {
        // Only writing can be tried before the connection starts.
        if want(SSL_POLL_EVENT_W) {
            rev |= u64::from(SSL_POLL_EVENT_W);
        }
        return rev;
    }
    let shutting_down = es.conn(c.conn).is_some_and(|r| r.shutting_down);
    let state = es.channel_of(c.conn).map(|ch| ch.state());
    let active = state == Some(State::Active);
    if let Some(id) = c.stream_id(es) {
        let (retired_fin, requested_reset) = c
            .stream_api(es)
            .map_or((false, false), |a| (a.retired_fin, a.requested_reset));
        let ch = es.channel_of(c.conn);
        let st = ch.as_ref().and_then(|ch| ch.streams().get(id));
        let recv = st.and_then(|s| s.recv.as_ref());
        let send = st.and_then(|s| s.send.as_ref());
        // A stream read to its end may be gone already.
        let gone = st.is_none();
        if want(SSL_POLL_EVENT_R) {
            let r = gone
                || recv.is_some_and(|p| {
                    p.state == RecvState::DataRead
                        || (!matches!(p.state, RecvState::ResetRecvd | RecvState::ResetRead)
                            && (p.buf.available() > 0 || (p.buf.all_received() && !retired_fin)))
                });
            if r {
                rev |= u64::from(SSL_POLL_EVENT_R);
            }
        }
        if want(SSL_POLL_EVENT_ER) && recv.is_some_and(|p| p.reset_code.is_some()) && !retired_fin {
            rev |= u64::from(SSL_POLL_EVENT_ER);
        }
        if want(SSL_POLL_EVENT_W)
            && !shutting_down
            && active
            && send.is_some_and(|p| {
                matches!(p.state, SendState::Ready | SendState::Send)
                    && p.buf.space() > 0
                    && !p.buf.is_finished()
                    && p.fc.cwm() > p.buf.write_end()
            })
        {
            rev |= u64::from(SSL_POLL_EVENT_W);
        }
        if want(SSL_POLL_EVENT_EW)
            && send.is_some_and(|p| p.peer_stop_sending.is_some())
            && !requested_reset
            && !shutting_down
        {
            rev |= u64::from(SSL_POLL_EVENT_EW);
        }
    }
    if !c.is_stream {
        if want(SSL_POLL_EVENT_EC) && !active {
            rev |= u64::from(SSL_POLL_EVENT_EC);
        }
        if want(SSL_POLL_EVENT_ECD) && state == Some(State::Terminated) {
            rev |= u64::from(SSL_POLL_EVENT_ECD);
        }
        let ch = es.channel_of(c.conn);
        let queued = |uni: bool| {
            ch.as_ref()
                .map_or(0, |ch| ch.streams().accept_queue_len_of(uni))
        };
        if want(SSL_POLL_EVENT_ISB) && queued(false) > 0 {
            rev |= u64::from(SSL_POLL_EVENT_ISB);
        }
        if want(SSL_POLL_EVENT_ISU) && queued(true) > 0 {
            rev |= u64::from(SSL_POLL_EVENT_ISU);
        }
        let avail = |uni: bool| {
            !shutting_down
                && active
                && ch
                    .as_ref()
                    .is_some_and(|ch| ch.streams().local_avail(uni) > 0)
        };
        if want(SSL_POLL_EVENT_OSB) && avail(false) {
            rev |= u64::from(SSL_POLL_EVENT_OSB);
        }
        if want(SSL_POLL_EVENT_OSU) && avail(true) {
            rev |= u64::from(SSL_POLL_EVENT_OSU);
        }
    }
    let _ = is_uni;
    rev
}

/// The item at `i` of a strided array.
///
/// # Safety
/// `items` holds `i + 1` items `stride` octets apart.
unsafe fn item<'a>(items: *mut SSL_POLL_ITEM, stride: usize, i: usize) -> &'a mut SSL_POLL_ITEM {
    // SAFETY: the caller's guarantee.
    unsafe { &mut *items.cast::<u8>().add(i * stride).cast::<SSL_POLL_ITEM>() }
}

/// What a readout found.
enum Readout {
    /// Items reporting events.
    Count(usize),
    /// An item failed (marked `F`; the rest cleared); the count includes it.
    Failed(usize),
}

/// `poll_readout`.
///
/// # Safety
/// As for `SSL_poll`; no lock is held.
unsafe fn readout(items: *mut SSL_POLL_ITEM, num: usize, stride: usize, tick: bool) -> Readout {
    let mut count = 0usize;
    for i in 0..num {
        // SAFETY: the caller's guarantee.
        let it = unsafe { item(items, stride, i) };
        let ty = c_int::try_from(it.desc.type_).unwrap_or(-1);
        let mut rev = 0u64;
        let fail = match ty {
            BIO_POLL_DESCRIPTOR_TYPE_SSL => {
                // SAFETY: the union's `ssl` member for this type.
                let s = unsafe { it.desc.value.ssl };
                if s.is_null() {
                    false
                } else {
                    // SAFETY: the caller's live object.
                    match unsafe { api::expect_csl(s) } {
                        Some(c) => {
                            if tick {
                                // SAFETY: no lock is held.
                                unsafe { super::tick(&c.q.engine) };
                            }
                            let mut es = c.q.engine.lock();
                            rev = poll_events(&c, &mut es, it.events);
                            false
                        }
                        None => {
                            // SAFETY: as above.
                            if unsafe { super::of(s) }.is_none() {
                                err::raise_with_text(
                                    ERR_LIB_SSL,
                                    SSL_R_POLL_REQUEST_NOT_SUPPORTED,
                                    "poll_readout",
                                    "SSL_poll currently only supports QUIC SSL objects",
                                );
                            }
                            true
                        }
                    }
                }
            }
            BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD => {
                err::raise_with_text(
                    ERR_LIB_SSL,
                    SSL_R_POLL_REQUEST_NOT_SUPPORTED,
                    "poll_readout",
                    "SSL_poll currently does not support polling sockets",
                );
                true
            }
            _ => {
                err::raise_with_text(
                    ERR_LIB_SSL,
                    SSL_R_POLL_REQUEST_NOT_SUPPORTED,
                    "poll_readout",
                    &format!("SSL_poll does not support unknown poll descriptor type {ty}"),
                );
                true
            }
        };
        if fail {
            it.revents = u64::from(SSL_POLL_EVENT_F);
            for j in i.saturating_add(1)..num {
                // SAFETY: as above.
                unsafe { item(items, stride, j) }.revents = 0;
            }
            return Readout::Failed(count.saturating_add(1));
        }
        it.revents = rev;
        if rev != 0 {
            count = count.saturating_add(1);
        }
    }
    Readout::Count(count)
}

/// `poll_block`: waits on the items' sockets until one is ready, a timer is due, or
/// `deadline`. Err (marked) if an item can't be waited on.
///
/// # Safety
/// As for `SSL_poll`; no lock is held.
unsafe fn block(
    items: *mut SSL_POLL_ITEM,
    num: usize,
    stride: usize,
    deadline: Option<Instant>,
) -> Result<(), usize> {
    let mut fds: Vec<libc::pollfd> = Vec::new();
    let mut wake = deadline;
    for i in 0..num {
        // SAFETY: the caller's guarantee.
        let it = unsafe { item(items, stride, i) };
        // SAFETY: as in `readout`.
        let s = unsafe { it.desc.value.ssl };
        // SAFETY: as above.
        let Some(q) = (unsafe { super::of(s) }) else {
            continue;
        };
        let not_sock = |count: usize| {
            err::raise_with_text(
                ERR_LIB_SSL,
                SSL_R_POLL_REQUEST_NOT_SUPPORTED,
                "poll_translate_ssl_quic",
                "SSL_poll requires the network BIOs underlying a QUIC SSL object provide poll descriptors",
            );
            count
        };
        if api::net_read_desired(q) != 0 {
            // SAFETY: an all-zero descriptor is the empty one.
            let mut d: BIO_POLL_DESCRIPTOR = unsafe { core::mem::zeroed() };
            // SAFETY: the live object; a whole descriptor.
            let ok = unsafe { api::poll_descriptor(s, &raw mut d, false) } == 1;
            if !ok || c_int::try_from(d.type_).ok() != Some(BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD) {
                it.revents = u64::from(SSL_POLL_EVENT_F);
                for j in i.saturating_add(1)..num {
                    // SAFETY: as above.
                    unsafe { item(items, stride, j) }.revents = 0;
                }
                return Err(not_sock(1));
            }
            // SAFETY: the union's `fd` member for a socket descriptor.
            let fd = unsafe { d.value.fd };
            fds.push(libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            });
        }
        let mut tv = timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let mut inf = 1;
        // SAFETY: local places.
        unsafe { api::event_timeout(q, &raw mut tv, &raw mut inf) };
        if inf == 0 {
            let d = Duration::new(
                u64::try_from(tv.tv_sec).unwrap_or(0),
                u32::try_from(tv.tv_usec).unwrap_or(0).saturating_mul(1000),
            );
            let t = Instant::now().checked_add(d);
            wake = match (wake, t) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        }
    }
    let timeout = wake.map_or(-1, |w| {
        let ms = w.saturating_duration_since(Instant::now()).as_millis();
        c_int::try_from(ms.saturating_add(1)).unwrap_or(c_int::MAX)
    });
    if fds.is_empty() {
        if timeout >= 0 {
            std::thread::sleep(Duration::from_millis(u64::try_from(timeout).unwrap_or(0)));
        }
        return Ok(());
    }
    let n = libc::nfds_t::try_from(fds.len()).unwrap_or(0);
    // SAFETY: a local array of `n` descriptors.
    unsafe { libc::poll(fds.as_mut_ptr(), n, timeout) };
    Ok(())
}

ffi_export! {
    /// Waits until one of `items` (QUIC objects) has one of its events, or `timeout` passes
    /// (NULL: forever; zero: don't wait): 1 with each item's `revents` set and how many report
    /// events in `*result_count`, or 0 (an item that can't be polled is marked
    /// `SSL_POLL_EVENT_F`).
    ///
    /// # Safety
    /// `items` holds `num_items` items `stride` octets apart; `timeout` NULL or readable;
    /// `result_count` NULL or writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_poll(items: *mut SSL_POLL_ITEM, num_items: usize, stride: usize, timeout: *const timeval, flags: u64, result_count: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        let mut tick = flags & u64::from(SSL_POLL_FLAG_NO_HANDLE_EVENTS) == 0;
        let wait = if timeout.is_null() {
            None
        } else {
            // SAFETY: the caller's guarantee.
            let t = unsafe { *timeout };
            Some(Duration::new(u64::try_from(t.tv_sec).unwrap_or(0), u32::try_from(t.tv_usec).unwrap_or(0).saturating_mul(1000)))
        };
        let set = |n: usize| {
            if !result_count.is_null() {
                // SAFETY: the caller's guarantee.
                unsafe { result_count.write(n) };
            }
        };
        if num_items == 0 {
            if let Some(d) = wait {
                std::thread::sleep(d);
            }
            set(0);
            return 1;
        }
        if items.is_null() || stride < core::mem::size_of::<SSL_POLL_ITEM>() {
            err::raise(ERR_LIB_SSL, ERR_R_UNSUPPORTED, "SSL_poll");
            set(0);
            return 0;
        }
        let zero = wait.is_some_and(|d| d.is_zero());
        let deadline = wait.and_then(|d| Instant::now().checked_add(d));
        loop {
            // SAFETY: the caller's guarantee; no lock is held.
            let n = match unsafe { readout(items, num_items, stride, tick) } {
                Readout::Count(n) => n,
                Readout::Failed(n) => {
                    set(n);
                    return 0;
                }
            };
            if n > 0 || zero || deadline.is_some_and(|d| Instant::now() >= d) {
                set(n);
                return 1;
            }
            tick = true;
            // SAFETY: as above.
            if let Err(n) = unsafe { block(items, num_items, stride, deadline) } {
                set(n);
                return 0;
            }
        }
    }
}
