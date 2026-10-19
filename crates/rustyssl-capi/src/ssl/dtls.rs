//! DTLS's connection state outside the core (`d1_lib.c`): the path MTU and its queries to the
//! datagram BIO, the retransmission timer (the clock, `DTLS_set_timer_cb`, the BIO's
//! `BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT`), the DTLS controls, `DTLS_get_data_mtu`, and
//! `DTLSv1_listen`'s stateless cookie exchange.

use core::ffi::{c_int, c_long, c_uint, c_void};
use core::ptr;

use rustyssl_abi::{
    BIO_ADDR, BIO_CTRL_DGRAM_GET_FALLBACK_MTU, BIO_CTRL_DGRAM_GET_MTU_OVERHEAD,
    BIO_CTRL_DGRAM_GET_PEER, BIO_CTRL_DGRAM_QUERY_MTU, BIO_CTRL_DGRAM_SET_MTU,
    BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT, BIO_CTRL_DGRAM_SET_PEER, BIO_FLAGS_SHOULD_RETRY,
    DTLS_CTRL_GET_LINK_MIN_MTU, DTLS_CTRL_GET_TIMEOUT, DTLS_CTRL_HANDLE_TIMEOUT,
    DTLS_CTRL_SET_LINK_MTU, DTLS_timer_cb, ERR_LIB_SSL, SSL, SSL_CTRL_SET_MTU, SSL_OP_NO_QUERY_MTU,
};
use rustyssl_tls::conn::dtls::Timer;

use super::conn::{Ssl, ssl};
use crate::bio::BIO_ctrl;
use crate::err;
use crate::ffi::ffi_export;

/// The smallest link MTU (`g_probable_mtu`'s last).
const MIN_LINK_MTU: usize = 256;

/// The most an MTU may sit below the link minimum (`DTLS1_MAX_MTU_OVERHEAD`, private to
/// libssl).
const MAX_MTU_OVERHEAD: usize = 48;

/// The first timeout (`dtls1_start_timer` without a callback).
const FIRST_TIMEOUT_US: u32 = 1_000_000;

/// The longest timeout (`dtls1_double_timeout`).
const MAX_TIMEOUT_US: u32 = 60_000_000;

/// Times within this are due (`dtls1_get_timeout`: 15 ms).
const DUE_US: u64 = 15_000;

/// The connection's DTLS state (`DTLS1_STATE`'s parts outside the core).
#[derive(Debug)]
pub(crate) struct D1 {
    /// The MTU in use (`mtu`; 0 until set or queried).
    pub(crate) mtu: usize,
    /// The link MTU set (`link_mtu`; 0 for none).
    pub(crate) link_mtu: usize,
    /// When the timer fires, in microseconds since the epoch (`next_timeout`; `None` when
    /// stopped).
    deadline: Option<u64>,
    /// The timer's duration (`timeout_duration_us`).
    duration_us: u32,
    /// `DTLS_set_timer_cb`.
    pub(crate) timer_cb: DTLS_timer_cb,
}

impl Default for D1 {
    fn default() -> Self {
        Self {
            mtu: 0,
            link_mtu: 0,
            deadline: None,
            duration_us: FIRST_TIMEOUT_US,
            timer_cb: None,
        }
    }
}

impl D1 {
    /// `dtls1_clear`: back to the start, keeping the timer callback, and the MTUs under
    /// `SSL_OP_NO_QUERY_MTU`.
    pub(crate) fn clear(&mut self, keep_mtu: bool) {
        let fresh = Self {
            timer_cb: self.timer_cb,
            mtu: if keep_mtu { self.mtu } else { 0 },
            link_mtu: if keep_mtu { self.link_mtu } else { 0 },
            ..Self::default()
        };
        *self = fresh;
    }
}

/// The time now in microseconds since the epoch (`ossl_time_now`).
fn now_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

/// A time in microseconds as a `timeval`.
fn timeval(us: u64) -> libc::timeval {
    libc::timeval {
        tv_sec: libc::time_t::try_from(us / 1_000_000).unwrap_or(libc::time_t::MAX),
        tv_usec: libc::suseconds_t::try_from(us % 1_000_000).unwrap_or(0),
    }
}

/// `BIO_ctrl` as a `usize` (negative: 0).
///
/// # Safety
/// `b` is NULL or a live BIO; no lock is held.
unsafe fn ctrl_usize(b: *mut rustyssl_abi::BIO, cmd: c_int, larg: c_long) -> usize {
    if b.is_null() {
        return 0;
    }
    // SAFETY: the caller's BIO; the command takes no pointer.
    usize::try_from(unsafe { BIO_ctrl(b, cmd, larg, ptr::null_mut()) }).unwrap_or(0)
}

/// `dtls1_min_mtu`: the link minimum less the BIO's overhead.
///
/// # Safety
/// `wbio` is NULL or a live BIO; no lock is held.
unsafe fn min_mtu(wbio: *mut rustyssl_abi::BIO) -> usize {
    // SAFETY: the caller's guarantee.
    MIN_LINK_MTU.saturating_sub(unsafe { ctrl_usize(wbio, BIO_CTRL_DGRAM_GET_MTU_OVERHEAD, 0) })
}

/// `dtls1_query_mtu`: the MTU to write with, from the link MTU set, else the BIO's (unless
/// `SSL_OP_NO_QUERY_MTU`), at least the minimum. `false` when none is known.
///
/// # Safety
/// `x` is a live connection; no lock is held.
pub(crate) unsafe fn query_mtu(x: &Ssl) -> bool {
    let (wbio, link, mut mtu, noquery) = {
        let st = x.state();
        (
            st.wbio,
            st.d1.link_mtu,
            st.d1.mtu,
            st.options & SSL_OP_NO_QUERY_MTU != 0,
        )
    };
    if link > 0 {
        // SAFETY: the connection's BIO; no lock is held.
        mtu = link.saturating_sub(unsafe { ctrl_usize(wbio, BIO_CTRL_DGRAM_GET_MTU_OVERHEAD, 0) });
        x.state().d1.link_mtu = 0;
    }
    // SAFETY: as above.
    let min = unsafe { min_mtu(wbio) };
    let mut ok = true;
    if mtu < min {
        if noquery {
            ok = false;
        } else {
            // SAFETY: as above.
            mtu = unsafe { ctrl_usize(wbio, BIO_CTRL_DGRAM_QUERY_MTU, 0) };
            if mtu < min {
                mtu = min;
                if !wbio.is_null() {
                    // SAFETY: as above.
                    unsafe {
                        BIO_ctrl(
                            wbio,
                            BIO_CTRL_DGRAM_SET_MTU,
                            c_long::try_from(mtu).unwrap_or(c_long::MAX),
                            ptr::null_mut(),
                        )
                    };
                }
            }
        }
    }
    let mut st = x.state();
    st.d1.mtu = mtu;
    if let Some(c) = st.drv.tls.as_mut() {
        c.config_mut().dtls_mtu = mtu;
    }
    ok
}

/// Tells the read BIO when the timer fires (`dtls1_bio_set_next_timeout`).
///
/// # Safety
/// `x` is a live connection; no lock is held.
unsafe fn notify_bio(x: &Ssl) {
    let (rbio, deadline) = {
        let st = x.state();
        (st.rbio, st.d1.deadline)
    };
    if rbio.is_null() {
        return;
    }
    let mut tv = timeval(deadline.unwrap_or(0));
    // SAFETY: the connection's BIO and a local timeval; no lock is held.
    unsafe {
        BIO_ctrl(
            rbio,
            BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT,
            0,
            (&raw mut tv).cast::<c_void>(),
        )
    };
}

/// `dtls1_start_timer`: from now, for the current duration (the callback's first one when the
/// timer was stopped).
///
/// # Safety
/// `s` is the live connection behind `x`; no lock is held.
unsafe fn start_timer(s: *mut SSL, x: &Ssl) {
    let (stopped, cb) = {
        let st = x.state();
        (st.d1.deadline.is_none(), st.d1.timer_cb)
    };
    if stopped {
        let d = match cb {
            // SAFETY: the application's callback with its connection; no lock is held.
            Some(f) => unsafe { f(s, 0) },
            None => FIRST_TIMEOUT_US,
        };
        x.state().d1.duration_us = d;
    }
    {
        let mut st = x.state();
        let d = u64::from(st.d1.duration_us);
        st.d1.deadline = Some(now_us().saturating_add(d));
    }
    // SAFETY: the caller's guarantee.
    unsafe { notify_bio(x) };
}

/// `dtls1_stop_timer`'s clock part.
///
/// # Safety
/// `x` is a live connection; no lock is held.
unsafe fn stop_timer(x: &Ssl) {
    {
        let mut st = x.state();
        st.d1.deadline = None;
        st.d1.duration_us = FIRST_TIMEOUT_US;
    }
    // SAFETY: the caller's guarantee.
    unsafe { notify_bio(x) };
}

/// Makes the timer change the core asked for.
///
/// # Safety
/// `s` is the live connection behind `x`; no lock is held.
pub(crate) unsafe fn apply_timer(s: *mut SSL, x: &Ssl, t: Timer) {
    match t {
        // SAFETY: the caller's guarantee.
        Timer::Start => unsafe { start_timer(s, x) },
        // SAFETY: as above.
        Timer::Stop => unsafe { stop_timer(x) },
    }
}

/// `dtls1_get_timeout`: the time left (0 when within 15 ms), or `None` when stopped.
fn time_left(x: &Ssl) -> Option<u64> {
    let deadline = x.state().d1.deadline?;
    let left = deadline.saturating_sub(now_us());
    Some(if left <= DUE_US { 0 } else { left })
}

/// `dtls1_is_timer_expired`.
pub(crate) fn expired(x: &Ssl) -> bool {
    time_left(x) == Some(0)
}

/// `dtls1_handle_timeout`: when the timer fired, the next duration (the callback's, or
/// doubled), the timeout counted (too many is fatal; after the third the MTU falls back), the
/// timer started again, and the flight retransmitted. 1 when retransmitted, 0 when the timer
/// hadn't fired (or a flight is being written), -1 on failure.
///
/// # Safety
/// `s` is the live connection behind `x`; no lock is held.
pub(crate) unsafe fn handle_timeout(s: *mut SSL, x: &Ssl) -> c_int {
    if !expired(x) {
        return 0;
    }
    let (cb, duration) = {
        let st = x.state();
        (st.d1.timer_cb, st.d1.duration_us)
    };
    let next = match cb {
        // SAFETY: the application's callback with its connection; no lock is held.
        Some(f) => unsafe { f(s, duration) },
        None => duration.saturating_mul(2).min(MAX_TIMEOUT_US),
    };
    x.state().d1.duration_us = next;
    let fallback = {
        let mut st = x.state();
        let prov = st.drv.provider.clone();
        match (st.drv.tls.as_mut(), prov) {
            (Some(c), Some(p)) => c.dtls_count_timeout(&*p),
            _ => return 0,
        }
    };
    let fallback = match fallback {
        Ok(f) => f,
        Err(e) => {
            super::io::raise_core(&e, "dtls1_check_timeout_num");
            return -1;
        }
    };
    if fallback {
        let wbio = x.state().wbio;
        // SAFETY: the connection's BIO; no lock is held.
        let m = unsafe { ctrl_usize(wbio, BIO_CTRL_DGRAM_GET_FALLBACK_MTU, 0) };
        let mut st = x.state();
        if m < st.d1.mtu {
            st.d1.mtu = m;
            if let Some(c) = st.drv.tls.as_mut() {
                c.config_mut().dtls_mtu = m;
            }
        }
    }
    // SAFETY: the caller's guarantee.
    unsafe { start_timer(s, x) };
    let r = {
        let mut st = x.state();
        let prov = st.drv.provider.clone();
        match (st.drv.tls.as_mut(), prov) {
            (Some(c), Some(p)) => {
                let writing = c.dtls_writing_flight();
                let r = c.dtls_retransmit_on_timeout(&*p);
                super::io::move_output(&mut st);
                r.map(|()| c_int::from(!writing))
            }
            _ => Ok(0),
        }
    };
    match r {
        Ok(v) => {
            if v > 0 {
                // SAFETY: the caller's guarantee.
                let _ = unsafe { super::io::flush(x) };
            }
            v
        }
        Err(e) => {
            super::io::raise_core(&e, "dtls1_retransmit_message");
            -1
        }
    }
}

/// The DTLS controls (`dtls1_ctrl`); `None` for the rest (and for a TLS connection).
///
/// # Safety
/// `s` is the live connection behind `x`; `parg` as `cmd` documents; no lock is held.
pub(crate) unsafe fn ssl_ctrl(
    s: *mut SSL,
    x: &Ssl,
    cmd: c_int,
    larg: c_long,
    parg: *mut c_void,
) -> Option<c_long> {
    if !x.state().method.dtls {
        return None;
    }
    let min = c_long::try_from(MIN_LINK_MTU).unwrap_or(256);
    Some(match cmd {
        DTLS_CTRL_GET_TIMEOUT => match time_left(x) {
            Some(us) if !parg.is_null() => {
                // SAFETY: the caller's `struct timeval`.
                unsafe { parg.cast::<libc::timeval>().write(timeval(us)) };
                1
            }
            _ => 0,
        },
        // SAFETY: the caller's guarantee.
        DTLS_CTRL_HANDLE_TIMEOUT => c_long::from(unsafe { handle_timeout(s, x) }),
        DTLS_CTRL_SET_LINK_MTU => {
            if larg < min {
                return Some(0);
            }
            x.state().d1.link_mtu = usize::try_from(larg).unwrap_or(0);
            1
        }
        DTLS_CTRL_GET_LINK_MIN_MTU => min,
        SSL_CTRL_SET_MTU => {
            let floor = min.saturating_sub(c_long::try_from(MAX_MTU_OVERHEAD).unwrap_or(48));
            if larg < floor {
                return Some(0);
            }
            let mut st = x.state();
            st.d1.mtu = usize::try_from(larg).unwrap_or(0);
            let m = st.d1.mtu;
            if let Some(c) = st.drv.tls.as_mut() {
                c.config_mut().dtls_mtu = m;
            }
            larg
        }
        _ => return None,
    })
}

ffi_export! {
    /// Sets the retransmission timer's callback (`DTLS_set_timer_cb`): it gets the last
    /// duration (0 at the start) and returns the next, in microseconds.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_DTLS_set_timer_cb(s: *mut SSL, cb: DTLS_timer_cb)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if let Some(x) = unsafe { ssl(s) } {
            x.state().d1.timer_cb = cb;
        }
    }
}

ffi_export! {
    /// The application data that fits one datagram with the current suite
    /// (`DTLS_get_data_mtu`): the MTU less the header, explicit IV, MAC or tag, and CBC's
    /// padding; 0 with no suite or no room.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_DTLS_get_data_mtu(s: *const SSL) -> usize
    where failure = 0, library = ERR_LIB_SSL
    {
        use rustyssl_tls::suites::Protection;
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let st = x.state();
        let mut mtu = st.d1.mtu;
        let Some(c) = st.drv.tls.as_ref() else { return 0 };
        let Some(cp) = c.negotiated().cipher else { return 0 };
        let (mac, mut int, blk, mut ext) = match cp.protection() {
            Protection::Aead(a) => {
                let explicit = if cp.tls12_aead_iv_lengths().1 > 0 { 8 } else { 0 };
                (0usize, 0usize, 0usize, a.tag_len().saturating_add(explicit))
            }
            Protection::Null { mac } => (mac.len(), 0, 0, 0),
            Protection::Cbc { cipher, mac } => {
                let b = cipher.block_len();
                (mac.len(), 1, b, b)
            }
            Protection::Unsupported => return 0,
        };
        if c.negotiated().etm {
            ext = ext.saturating_add(mac);
        } else {
            int = int.saturating_add(mac);
        }
        let header = rustyssl_tls::record::dtls::HEADER_LEN;
        if ext.saturating_add(header) >= mtu {
            return 0;
        }
        mtu = mtu.saturating_sub(ext.saturating_add(header));
        if blk > 0 {
            mtu = mtu.saturating_sub(mtu.checked_rem(blk).unwrap_or(0));
        }
        if int >= mtu {
            return 0;
        }
        mtu.saturating_sub(int)
    }
}

/// `BIO_should_retry`.
///
/// # Safety
/// `b` is a live BIO.
unsafe fn should_retry(b: *mut rustyssl_abi::BIO) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { crate::bio::BIO_test_flags(b, BIO_FLAGS_SHOULD_RETRY) != 0 }
}

/// Copies the peer's address from the read BIO to `to` (`BIO_dgram_get_peer`), `false` when
/// it has none.
///
/// # Safety
/// `rbio` is a live BIO; `to` a live address.
unsafe fn get_peer(rbio: *mut rustyssl_abi::BIO, to: *mut BIO_ADDR) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { BIO_ctrl(rbio, BIO_CTRL_DGRAM_GET_PEER, 0, to.cast()) > 0 }
}

/// What a datagram's ClientHello says.
struct Hello {
    /// The record's sequence number (the HelloVerifyRequest goes in it).
    seq: [u8; 8],
    /// The cookie.
    cookie: Vec<u8>,
}

/// `DTLSv1_listen`'s parse of a datagram: one record with one unfragmented ClientHello.
/// `Err(reason)` for a datagram to ignore (OpenSSL raises it and returns 0).
fn parse_hello(d: &[u8], x: &Ssl) -> Result<(u16, Hello, Vec<u8>), c_int> {
    use rustyssl_abi::{
        DTLS1_VERSION_MAJOR, SSL_R_BAD_PROTOCOL_VERSION_NUMBER, SSL_R_FRAGMENTED_CLIENT_HELLO,
        SSL_R_INVALID_SEQUENCE_NUMBER, SSL_R_LENGTH_MISMATCH, SSL_R_RECORD_TOO_SMALL,
        SSL_R_UNEXPECTED_MESSAGE, SSL_R_WRONG_VERSION_NUMBER, SSL3_MT_CLIENT_HELLO,
        SSL3_RT_HANDSHAKE,
    };
    use rustyssl_tls::codec::Reader;
    let header = rustyssl_tls::record::dtls::HEADER_LEN;
    if d.len() < header {
        return Err(SSL_R_RECORD_TOO_SMALL);
    }
    let mm = SSL_R_LENGTH_MISMATCH;
    let mut r = Reader::new(d);
    let rectype = r.u8().map_err(|_| mm)?;
    let vmaj = r.u8().map_err(|_| mm)?;
    let vmin = r.u8().map_err(|_| mm)?;
    let version = u16::from_be_bytes([vmaj, vmin]);
    if c_int::from(rectype) != SSL3_RT_HANDSHAKE {
        return Err(SSL_R_UNEXPECTED_MESSAGE);
    }
    if c_int::from(vmaj) != DTLS1_VERSION_MAJOR {
        return Err(SSL_R_BAD_PROTOCOL_VERSION_NUMBER);
    }
    let seqb = r.take(8).map_err(|_| mm)?;
    let mut seq = [0u8; 8];
    seq.copy_from_slice(seqb);
    let mut msg = r.vec16().map_err(|_| mm)?;
    if seq.first() != Some(&0) || seq.get(1) != Some(&0) {
        return Err(SSL_R_UNEXPECTED_MESSAGE);
    }
    let raw_msg = msg.rest().to_vec();
    let msgtype = msg.u8().map_err(|_| mm)?;
    let msglen = msg.u24().map_err(|_| mm)?;
    let msgseq = msg.u16().map_err(|_| mm)?;
    let fragoff = msg.u24().map_err(|_| mm)?;
    let fraglen = msg.u24().map_err(|_| mm)?;
    let flen = usize::try_from(fraglen).map_err(|_| mm)?;
    let mut payload = Reader::new(msg.take(flen).map_err(|_| mm)?);
    if !msg.is_empty() {
        return Err(mm);
    }
    if c_int::from(msgtype) != SSL3_MT_CLIENT_HELLO {
        return Err(SSL_R_UNEXPECTED_MESSAGE);
    }
    if msgseq > 1 {
        return Err(SSL_R_INVALID_SEQUENCE_NUMBER);
    }
    if fragoff != 0 || fraglen > msglen {
        return Err(SSL_R_FRAGMENTED_CLIENT_HELLO);
    }
    let clientvers = payload.u16().map_err(|_| mm)?;
    let method = x.state().method.version;
    if method != rustyssl_abi::DTLS_ANY_VERSION
        && rustyssl_tls::conn::common::version::cmp(
            true,
            clientvers,
            u16::try_from(method).unwrap_or(0),
        )
        .is_lt()
    {
        return Err(SSL_R_WRONG_VERSION_NUMBER);
    }
    payload.take(32).map_err(|_| mm)?;
    payload.vec8().map_err(|_| mm)?;
    let cookie = payload.vec8().map_err(|_| mm)?.rest().to_vec();
    Ok((version, Hello { seq, cookie }, raw_msg))
}

ffi_export! {
    /// Answers ClientHellos with HelloVerifyRequests, statelessly, until one comes with a
    /// cookie the verify callback accepts (`DTLSv1_listen`): 1 with the client's address in
    /// `client` and the connection ready to `SSL_accept` that ClientHello; 0 when the read BIO
    /// would block or a datagram was ignored; -1 on a fatal error.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `client` NULL or a live address.
    pub unsafe extern "C" fn rustyssl_private_DTLSv1_listen(s: *mut SSL, client: *mut BIO_ADDR) -> c_int
    where failure = -1, library = ERR_LIB_SSL
    {
        use rustyssl_abi::{
            SSL_R_BIO_NOT_SET, SSL_R_COOKIE_GEN_CALLBACK_FAILURE,
            SSL_R_NO_VERIFY_COOKIE_CALLBACK, SSL_R_UNSUPPORTED_SSL_VERSION,
        };
        const F: &str = "DTLSv1_listen";
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return -1 };
        if x.state().handshake_func.is_none() {
            // SAFETY: the live connection.
            unsafe { super::conn::rustyssl_private_SSL_set_accept_state(s) };
        }
        // SAFETY: as above.
        if unsafe { super::conn::rustyssl_private_SSL_clear(s) } == 0 {
            return -1;
        }
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
        let (rbio, wbio) = super::io::bios(x);
        if rbio.is_null() || wbio.is_null() {
            err::raise(ERR_LIB_SSL, SSL_R_BIO_NOT_SET, F);
            return -1;
        }
        if !x.state().method.dtls {
            err::raise(ERR_LIB_SSL, SSL_R_UNSUPPORTED_SSL_VERSION, F);
            return -1;
        }
        let max = usize::try_from(rustyssl_abi::SSL3_RT_MAX_PLAIN_LENGTH).unwrap_or(16384)
            .saturating_add(rustyssl_tls::record::dtls::HEADER_LEN);
        let datagram = loop {
            crate::errno::set(0);
            let mut buf = vec![0u8; max];
            let n = c_int::try_from(max).unwrap_or(c_int::MAX);
            // SAFETY: the connection's BIO and our buffer; no lock is held.
            let r = unsafe { crate::bio::BIO_read(rbio, buf.as_mut_ptr().cast(), n) };
            if r <= 0 {
                // SAFETY: as above.
                return if unsafe { should_retry(rbio) } { 0 } else { -1 };
            }
            buf.truncate(usize::try_from(r).unwrap_or(0));
            let (version, hello, raw_msg) = match parse_hello(&buf, x) {
                Ok(h) => h,
                Err(reason) => {
                    // The message callback saw the header if it was there.
                    // SAFETY: as above.
                    unsafe { report_header(s, x, false, &buf) };
                    err::raise(ERR_LIB_SSL, reason, F);
                    return 0;
                }
            };
            // SAFETY: as above.
            unsafe { report_header(s, x, false, &buf) };
            let v = x.state().version;
            // SAFETY: as above.
            unsafe { super::io::report(s, x, false, v, rustyssl_abi::SSL3_RT_HANDSHAKE, &raw_msg) };
            let _ = version;
            let snap = super::io::config::snapshot(x);
            let verified = if hello.cookie.is_empty() {
                false
            } else {
                let Some(cb) = snap.as_ref().and_then(|c| c.app_verify_cookie_cb) else {
                    err::raise(ERR_LIB_SSL, SSL_R_NO_VERIFY_COOKIE_CALLBACK, F);
                    return -1;
                };
                let len = c_uint::try_from(hello.cookie.len()).unwrap_or(0);
                // SAFETY: the application's callback with its connection and the cookie; no
                // lock is held.
                unsafe { cb(s, hello.cookie.as_ptr(), len) != 0 }
            };
            if verified {
                break buf;
            }
            let mut cookie = vec![0u8; rustyssl_tls::conn::dtls::COOKIE_LEN];
            let mut clen: c_uint = 0;
            let gen_cb = snap.as_ref().and_then(|c| c.app_gen_cookie_cb);
            // SAFETY: the application's callback with its connection and a buffer of
            // DTLS1_COOKIE_LENGTH octets; no lock is held.
            let ok = gen_cb.is_some_and(|g| unsafe { g(s, cookie.as_mut_ptr(), &raw mut clen) } != 0);
            let clen = usize::try_from(clen).unwrap_or(usize::MAX);
            if !ok || clen > cookie.len() {
                err::raise(ERR_LIB_SSL, SSL_R_COOKIE_GEN_CALLBACK_FAILURE, F);
                return -1;
            }
            cookie.truncate(clen);
            let rec_version = if x.state().method.version == rustyssl_abi::DTLS_ANY_VERSION {
                rustyssl_tls::consts::version::DTLS1
            } else {
                u16::try_from(x.state().version).unwrap_or(rustyssl_tls::consts::version::DTLS1)
            };
            let Ok(rec) = hvr_record(rec_version, &hello.seq, &cookie) else {
                err::raise(ERR_LIB_SSL, rustyssl_abi::ERR_R_INTERNAL_ERROR, F);
                return -1;
            };
            // SAFETY: as above.
            unsafe { report_header(s, x, true, &rec) };
            // SAFETY: no preconditions.
            let addr = unsafe { crate::bio::addr::BIO_ADDR_new() };
            if !addr.is_null() {
                // SAFETY: the BIOs and our address; no lock is held.
                if unsafe { get_peer(rbio, addr) } {
                    // SAFETY: as above.
                    unsafe { BIO_ctrl(wbio, BIO_CTRL_DGRAM_SET_PEER, 0, addr.cast()) };
                }
                // SAFETY: ours.
                unsafe { crate::bio::addr::BIO_ADDR_free(addr) };
            }
            let n = c_int::try_from(rec.len()).unwrap_or(c_int::MAX);
            // SAFETY: the BIO and our record; no lock is held.
            let w = unsafe { crate::bio::BIO_write(wbio, rec.as_ptr().cast(), n) };
            if w < n {
                // SAFETY: as above.
                return if unsafe { should_retry(wbio) } { 0 } else { -1 };
            }
            // SAFETY: as above.
            if unsafe { BIO_ctrl(wbio, rustyssl_abi::BIO_CTRL_FLUSH, 0, ptr::null_mut()) } <= 0 {
                // SAFETY: as above.
                return if unsafe { should_retry(wbio) } { 0 } else { -1 };
            }
        };
        // The connection takes it from here, as if it had sent the HelloVerifyRequest.
        // SAFETY: the live connection.
        if !unsafe { super::io::ensure_core(s, x) } {
            return -1;
        }
        {
            let mut st = x.state();
            st.options |= rustyssl_abi::SSL_OP_COOKIE_EXCHANGE;
            if let Some(c) = st.drv.tls.as_mut() {
                c.config_mut().options |= rustyssl_abi::SSL_OP_COOKIE_EXCHANGE;
                c.dtls_listen_done();
                c.feed_datagram(&datagram);
            }
        }
        if !client.is_null() {
            // SAFETY: the BIO and the caller's address; no lock is held.
            if !unsafe { get_peer(rbio, client) } {
                // SAFETY: the caller's address.
                unsafe { crate::bio::addr::BIO_ADDR_clear(client) };
            }
        }
        1
    }
}

/// A HelloVerifyRequest record in sequence number `seq` (`DTLSv1_listen`'s).
fn hvr_record(version: u16, seq: &[u8; 8], cookie: &[u8]) -> Result<Vec<u8>, ()> {
    let body = rustyssl_tls::msgs::HelloVerifyRequest {
        server_version: rustyssl_tls::consts::version::DTLS1,
        cookie: cookie.to_vec(),
    }
    .encode()
    .map_err(|_| ())?;
    let typ = u8::try_from(rustyssl_abi::DTLS1_MT_HELLO_VERIFY_REQUEST).map_err(|_| ())?;
    let len = u32::try_from(body.len()).map_err(|_| ())?.to_be_bytes();
    let l3 = len.get(1..).ok_or(())?;
    let mut msg = vec![typ];
    msg.extend_from_slice(l3);
    msg.extend_from_slice(&[0, 0, 0, 0, 0]);
    msg.extend_from_slice(l3);
    msg.extend_from_slice(&body);
    let mut rec = vec![u8::try_from(rustyssl_abi::SSL3_RT_HANDSHAKE).map_err(|_| ())?];
    rec.extend_from_slice(&version.to_be_bytes());
    rec.extend_from_slice(seq);
    rec.extend_from_slice(&u16::try_from(msg.len()).map_err(|_| ())?.to_be_bytes());
    rec.extend_from_slice(&msg);
    Ok(rec)
}

/// Reports a record's header to the message callback (with its own version).
///
/// # Safety
/// `s` is the live connection behind `x`; no lock is held.
unsafe fn report_header(s: *mut SSL, x: &Ssl, write: bool, rec: &[u8]) {
    let header = rustyssl_tls::record::dtls::HEADER_LEN;
    let Some(h) = rec.get(..header) else { return };
    let v = c_int::from(u16::from_be_bytes([
        h.get(1).copied().unwrap_or(0),
        h.get(2).copied().unwrap_or(0),
    ]));
    // SAFETY: the caller's guarantee.
    unsafe { super::io::report(s, x, write, v, rustyssl_abi::SSL3_RT_HEADER, h) };
}
