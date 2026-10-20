//! libssl's entry points that run the protocol (`SSL_do_handshake`, `SSL_read`, `SSL_write`,
//! `SSL_shutdown`, `SSL_get_error`, ...) and the getters that report what it negotiated, over
//! the step loop ([`super::drive`]).

use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_uint, c_void};
use core::ptr;

use rustyssl_abi::{
    BIO_FLAGS_IO_SPECIAL, BIO_FLAGS_READ, BIO_FLAGS_WRITE, BIO_RR_ACCEPT, BIO_RR_CONNECT,
    ERR_LIB_SSL, ERR_LIB_SYS, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, ERR_SYSTEM_FLAG, EVP_PKEY,
    NID_undef, SSL, SSL_AD_CLOSE_NOTIFY, SSL_AD_REASON_OFFSET, SSL_CIPHER, SSL_CLIENT_HELLO_CB,
    SSL_ERROR_NONE, SSL_ERROR_SSL, SSL_ERROR_SYSCALL, SSL_ERROR_WANT_ACCEPT, SSL_ERROR_WANT_ASYNC,
    SSL_ERROR_WANT_CLIENT_HELLO_CB, SSL_ERROR_WANT_CONNECT, SSL_ERROR_WANT_READ,
    SSL_ERROR_WANT_RETRY_VERIFY, SSL_ERROR_WANT_WRITE, SSL_ERROR_WANT_X509_LOOKUP,
    SSL_ERROR_ZERO_RETURN, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER, SSL_MODE_ENABLE_PARTIAL_WRITE,
    SSL_NOTHING, SSL_R_APPLICATION_DATA_AFTER_CLOSE_NOTIFY, SSL_R_BAD_LENGTH,
    SSL_R_BAD_WRITE_RETRY, SSL_R_CONNECTION_TYPE_NOT_SET, SSL_R_PROTOCOL_IS_SHUTDOWN,
    SSL_R_SHUTDOWN_WHILE_IN_INIT, SSL_R_UNINITIALIZED, SSL_READING, SSL_RECEIVED_SHUTDOWN,
    SSL_RETRY_VERIFY, SSL_SENT_SHUTDOWN, SSL_WRITING, SSL_X509_LOOKUP, X509, stack_st_X509,
};

use super::super::conn::{Ssl, ssl};
use super::{Flush, Stop, drive, ensure_core, flush, raise_core};
use crate::bio::{BIO_get_retry_reason, BIO_test_flags};
use crate::err;
use crate::ffi::ffi_export;
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_value};
use crate::x509::cert::X509_up_ref;
use rustyssl_tls::conn::Connection;
use rustyssl_tls::conn::common::EarlyDataState;

/// Runs (or finishes) the handshake: 1, or -1 (`SSL_get_error` says why).
///
/// # Safety
/// `s` is the live connection behind `x`.
unsafe fn handshake(s: *mut SSL, x: &Ssl, function: &str) -> c_int {
    // SAFETY: the caller's guarantee.
    if !unsafe { ensure_core(s, x) } {
        return -1;
    }
    // SAFETY: as above.
    match unsafe { drive(s, x, false, function) } {
        Stop::Done | Stop::Idle | Stop::AppData => 1,
        Stop::Retry | Stop::Failed | Stop::Syscall | Stop::Closed => -1,
    }
}

/// Whether a handshake is under way or hasn't started (`SSL_in_init || SSL_in_before`).
fn in_init(x: &Ssl) -> bool {
    let st = x.state();
    st.in_init || st.flow_uninited
}

ffi_export! {
    /// Runs the handshake as far as it can go: 1 when it has finished, -1 otherwise (with
    /// `SSL_get_error` saying what it waits for, or why it failed).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_do_handshake(s: *mut SSL) -> c_int
    where failure = -1, library = ERR_LIB_SSL
    {
        const F: &str = "SSL_do_handshake";
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return -1 };
        if x.state().handshake_func.is_none() {
            err::raise(ERR_LIB_SSL, SSL_R_CONNECTION_TYPE_NOT_SET, F);
            return -1;
        }
        super::check_finish_init(x, -1);
        super::super::requests::renegotiate_check(x, false);
        if !in_init(x) {
            // The handshake is done; its last flight may still be waiting for the BIO.
            // SAFETY: the live connection.
            return match unsafe { flush(x) } {
                Flush::Done => 1,
                Flush::Retry | Flush::Error => -1,
            };
        }
        // SAFETY: as above.
        unsafe { handshake(s, x, F) }
    }
}

ffi_export! {
    /// The client's handshake (`SSL_set_connect_state` first if no role is set): as
    /// `SSL_do_handshake`.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_connect(s: *mut SSL) -> c_int
    where failure = -1, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        if x.state().handshake_func.is_none() {
            // SAFETY: as above.
            unsafe { super::super::conn::rustyssl_private_SSL_set_connect_state(s) };
        }
        // SAFETY: as above.
        unsafe { rustyssl_private_SSL_do_handshake(s) }
    }
}

ffi_export! {
    /// The server's handshake (`SSL_set_accept_state` first if no role is set): as
    /// `SSL_do_handshake`.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_accept(s: *mut SSL) -> c_int
    where failure = -1, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        if x.state().handshake_func.is_none() {
            // SAFETY: as above.
            unsafe { super::super::conn::rustyssl_private_SSL_set_accept_state(s) };
        }
        // SAFETY: as above.
        unsafe { rustyssl_private_SSL_do_handshake(s) }
    }
}

/// `ssl_read_internal` and `ssl_peek_internal`: up to `num` octets into `buf`; 1 with the count
/// in `*readbytes`, 0 at close_notify, -1 otherwise.
///
/// # Safety
/// `s` is NULL or a live connection; `buf` has room for `num` octets.
pub(crate) unsafe fn read_internal(
    s: *mut SSL,
    buf: *mut c_void,
    num: usize,
    peek: bool,
    readbytes: &mut usize,
    function: &str,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(x) = (unsafe { ssl(s) }) else {
        return -1;
    };
    {
        let mut st = x.state();
        if st.handshake_func.is_none() {
            drop(st);
            err::raise(ERR_LIB_SSL, SSL_R_UNINITIALIZED, function);
            return -1;
        }
        if st.shutdown & SSL_RECEIVED_SHUTDOWN != 0 {
            st.rwstate = SSL_NOTHING;
            return 0;
        }
        if matches!(
            st.drv.early_data_state,
            EarlyDataState::ConnectRetry | EarlyDataState::AcceptRetry
        ) {
            drop(st);
            err::raise(ERR_LIB_SSL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, function);
            return 0;
        }
    }
    super::check_finish_init(x, 0);
    // SAFETY: as above.
    if !unsafe { ensure_core(s, x) } {
        return -1;
    }
    super::super::requests::renegotiate_check(x, false);
    // Reading early data: a handshake message (the EndOfEarlyData) ends it (`ssl3_read_bytes`).
    let reading_early = x.state().drv.early_data_state == EarlyDataState::Reading;
    loop {
        {
            let mut st = x.state();
            if let Some(c) = st.drv.tls.as_mut()
                && c.pending_app() > 0
                && !buf.is_null()
                && num > 0
            {
                // SAFETY: the caller's room for `num` octets.
                let out = unsafe { core::slice::from_raw_parts_mut(buf.cast::<u8>(), num) };
                *readbytes = c.read_app(out, peek);
                return 1;
            }
            // `ssl3_read_bytes` with no room: records are read (and handshake messages, a
            // ticket, handled) until application data is there, which stays for later.
            if num == 0 && st.drv.tls.as_ref().is_some_and(|c| c.pending_app() > 0) {
                return 0;
            }
        }
        // A failure marks the connection in init (`ossl_statem_fatal`): whether it was before.
        let was_init = x.state().drv.tls.as_ref().is_none_or(|c| c.in_init());
        // SAFETY: as above.
        let stop = unsafe { drive(s, x, true, function) };
        if reading_early && x.state().drv.early_data_state == EarlyDataState::FinishedReading {
            return -1;
        }
        match stop {
            Stop::AppData | Stop::Done | Stop::Idle => {}
            Stop::Closed => {
                x.state().rwstate = SSL_NOTHING;
                return 0;
            }
            Stop::Failed if !was_init && read_fatal_alert(x) => return 0,
            Stop::Retry | Stop::Failed | Stop::Syscall => return -1,
        }
    }
}

/// Whether the read failed on a fatal alert from the peer: after the handshake,
/// `ssl3_read_bytes` returns 0 then (setting `SSL_RECEIVED_SHUTDOWN`), so `SSL_read` does; in
/// a handshake the handshake function's failure is -1.
fn read_fatal_alert(x: &Ssl) -> bool {
    let st = x.state();
    st.drv.tls.as_ref().is_some_and(|c| {
        let (_, fatal, _) = c.alerts();
        fatal != 0
            && c.error().is_some_and(|e| {
                !e.library_reason
                    && e.reason == SSL_AD_REASON_OFFSET.saturating_add(c_int::from(fatal))
            })
    })
}

ffi_export! {
    /// Reads up to `num` octets of application data (running the handshake first if needed):
    /// how many, 0 at close_notify, or -1 (`SSL_get_error` says why).
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `buf` has room for `num` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_read(s: *mut SSL, buf: *mut c_void, num: c_int) -> c_int
    where failure = -1, library = ERR_LIB_SSL
    {
        let Ok(n) = usize::try_from(num) else {
            err::raise(ERR_LIB_SSL, SSL_R_BAD_LENGTH, "SSL_read");
            return -1;
        };
        let mut got = 0usize;
        // SAFETY: the caller's guarantee.
        let r = unsafe { read_internal(s, buf, n, false, &mut got, "SSL_read") };
        if r > 0 { c_int::try_from(got).unwrap_or(c_int::MAX) } else { r }
    }
}

ffi_export! {
    /// Reads up to `num` octets: 1 with the count in `*readbytes`, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `buf` has room for `num` octets; `readbytes` NULL or
    /// writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_read_ex(s: *mut SSL, buf: *mut c_void, num: usize, readbytes: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        let mut got = 0usize;
        // SAFETY: the caller's guarantee.
        let r = unsafe { read_internal(s, buf, num, false, &mut got, "SSL_read_ex") };
        if r > 0 && !readbytes.is_null() {
            // SAFETY: the caller's slot.
            unsafe { readbytes.write(got) };
        }
        r.max(0)
    }
}

ffi_export! {
    /// As `SSL_read`, leaving the data to be read again.
    ///
    /// # Safety
    /// As for `SSL_read`.
    pub unsafe extern "C" fn rustyssl_private_SSL_peek(s: *mut SSL, buf: *mut c_void, num: c_int) -> c_int
    where failure = -1, library = ERR_LIB_SSL
    {
        let Ok(n) = usize::try_from(num) else {
            err::raise(ERR_LIB_SSL, SSL_R_BAD_LENGTH, "SSL_peek");
            return -1;
        };
        let mut got = 0usize;
        // SAFETY: the caller's guarantee.
        let r = unsafe { read_internal(s, buf, n, true, &mut got, "SSL_peek") };
        if r > 0 { c_int::try_from(got).unwrap_or(c_int::MAX) } else { r }
    }
}

ffi_export! {
    /// As `SSL_read_ex`, leaving the data to be read again.
    ///
    /// # Safety
    /// As for `SSL_read_ex`.
    pub unsafe extern "C" fn rustyssl_private_SSL_peek_ex(s: *mut SSL, buf: *mut c_void, num: usize, readbytes: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        let mut got = 0usize;
        // SAFETY: the caller's guarantee.
        let r = unsafe { read_internal(s, buf, num, true, &mut got, "SSL_peek_ex") };
        if r > 0 && !readbytes.is_null() {
            // SAFETY: the caller's slot.
            unsafe { readbytes.write(got) };
        }
        r.max(0)
    }
}

/// `ssl_write_internal` and `ssl3_write_bytes`: writes `num` octets (one record's worth with
/// `SSL_MODE_ENABLE_PARTIAL_WRITE`); 1 with the count in `*written`, or -1. A write that
/// couldn't be sent must be retried with the same arguments (`SSL_R_BAD_WRITE_RETRY`
/// otherwise, unless `SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER`).
///
/// # Safety
/// `s` is NULL or a live connection; `buf` holds `num` octets.
pub(crate) unsafe fn write_internal(
    s: *mut SSL,
    buf: *const c_void,
    num: usize,
    written: &mut usize,
    function: &str,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(x) = (unsafe { ssl(s) }) else {
        return 0;
    };
    {
        let mut st = x.state();
        if st.handshake_func.is_none() {
            drop(st);
            err::raise(ERR_LIB_SSL, SSL_R_UNINITIALIZED, function);
            return -1;
        }
        if st.shutdown & SSL_SENT_SHUTDOWN != 0 {
            st.rwstate = SSL_NOTHING;
            drop(st);
            err::raise(ERR_LIB_SSL, SSL_R_PROTOCOL_IS_SHUTDOWN, function);
            return -1;
        }
        if matches!(
            st.drv.early_data_state,
            EarlyDataState::ConnectRetry | EarlyDataState::AcceptRetry | EarlyDataState::ReadRetry
        ) {
            drop(st);
            err::raise(ERR_LIB_SSL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, function);
            return 0;
        }
    }
    super::check_finish_init(x, 1);
    // SAFETY: as above.
    if !unsafe { ensure_core(s, x) } {
        return -1;
    }
    super::super::requests::renegotiate_check(x, false);
    super::super::requests::post_handshake_write(x);
    // A server writing early to an unauthenticated client doesn't run the handshake.
    let unauth = x.state().drv.early_data_state == EarlyDataState::UnauthWriting;
    if in_init(x) && !unauth {
        // SAFETY: as above.
        match unsafe { drive(s, x, false, function) } {
            Stop::Done | Stop::Idle | Stop::AppData => {}
            _ => return -1,
        }
    }
    let (pending, mode, max_frag) = {
        let st = x.state();
        (st.drv.wpend, st.mode, st.max_send_fragment)
    };
    if let Some((tot, addr)) = pending {
        let moving = mode & SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER != 0;
        if tot > num {
            // `ssl3_write_bytes`: a retry with less than was pending is fatal
            // (`SSLfatal(SSL_AD_INTERNAL_ERROR, SSL_R_BAD_LENGTH)`; its alert waits behind the
            // pending write, so none goes out here).
            err::raise(ERR_LIB_SSL, SSL_R_BAD_LENGTH, function);
            let mut st = x.state();
            st.drv.failed = true;
            let prov = st.drv.provider.clone();
            if let (Some(c), Some(p)) = (st.drv.tls.as_mut(), prov) {
                c.fail(&*p, rustyssl_tls::error::Error::quiet(SSL_R_BAD_LENGTH));
            }
            return -1;
        }
        if !moving && addr != buf.addr() {
            err::raise(ERR_LIB_SSL, SSL_R_BAD_WRITE_RETRY, function);
            return -1;
        }
        // SAFETY: as above.
        return match unsafe { drive(s, x, false, function) } {
            Stop::Idle | Stop::Done | Stop::AppData => {
                let mut st = x.state();
                st.drv.wpend = None;
                st.drv.out_after_wpend = false;
                drop(st);
                *written = tot;
                1
            }
            _ => -1,
        };
    }
    if num == 0 {
        // `ssl3_write_bytes`: nothing to write is done (`SSL_write` then returns 0, and
        // `SSL_write_ex` 1).
        *written = 0;
        return 1;
    }
    let chunk = if mode & SSL_MODE_ENABLE_PARTIAL_WRITE != 0 {
        num.min(max_frag.max(1))
    } else {
        num
    };
    // The core is written to out of the lock: the record padding callback may run.
    let taken = {
        let mut st = x.state();
        match st.drv.provider.clone() {
            Some(p) => st.drv.tls.take().map(|c| (c, p)),
            None => None,
        }
    };
    let r = taken.map(|(mut c, p)| {
        // SAFETY: the caller's `num` octets, of which `chunk` are taken.
        let data = unsafe { core::slice::from_raw_parts(buf.cast::<u8>(), chunk) };
        let r = c.write_app(&*p, data);
        let mut st = x.state();
        if st.drv.tls.is_none() {
            st.drv.tls = Some(c);
        }
        r
    });
    match r {
        Some(Ok(_)) => {}
        Some(Err(e)) => {
            raise_core(&e, function);
            return -1;
        }
        None => return -1,
    }
    // Deliver what the write reported (record headers to the message callback) and flush.
    // SAFETY: as above.
    match unsafe { drive(s, x, false, function) } {
        Stop::Idle | Stop::Done | Stop::AppData => {
            *written = chunk;
            1
        }
        Stop::Retry => {
            let mut st = x.state();
            st.drv.wpend = Some((chunk, buf.addr()));
            st.drv.out_after_wpend = false;
            -1
        }
        _ => -1,
    }
}

ffi_export! {
    /// Writes `num` octets of application data (running the handshake first if needed): how
    /// many, or a value of 0 or less (`SSL_get_error` says why).
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `buf` holds `num` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_write(s: *mut SSL, buf: *const c_void, num: c_int) -> c_int
    where failure = -1, library = ERR_LIB_SSL
    {
        let Ok(n) = usize::try_from(num) else {
            err::raise(ERR_LIB_SSL, SSL_R_BAD_LENGTH, "SSL_write");
            return -1;
        };
        let mut done = 0usize;
        // SAFETY: the caller's guarantee.
        let r = unsafe { write_internal(s, buf, n, &mut done, "SSL_write") };
        if r > 0 { c_int::try_from(done).unwrap_or(c_int::MAX) } else { r }
    }
}

ffi_export! {
    /// Writes `num` octets: 1 with the count in `*written`, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `buf` holds `num` octets; `written` NULL or writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_write_ex(s: *mut SSL, buf: *const c_void, num: usize, written: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        let mut done = 0usize;
        // SAFETY: the caller's guarantee.
        let r = unsafe { write_internal(s, buf, num, &mut done, "SSL_write_ex") };
        if r > 0 && !written.is_null() {
            // SAFETY: the caller's slot.
            unsafe { written.write(done) };
        }
        r.max(0)
    }
}

ffi_export! {
    /// Why the last call returned `ret` (`SSL_ERROR_*`): an error on the queue first
    /// (`SSL_ERROR_SSL`, or `SSL_ERROR_SYSCALL` for a system error), then what the connection
    /// waits for and on which BIO, then close_notify (`SSL_ERROR_ZERO_RETURN`), else
    /// `SSL_ERROR_SYSCALL`.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_error(s: *const SSL, ret: c_int) -> c_int
    where failure = SSL_ERROR_SSL, library = ERR_LIB_SSL
    {
        if ret > 0 {
            return SSL_ERROR_NONE;
        }
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return SSL_ERROR_SSL };
        // SAFETY: no preconditions.
        let l = unsafe { crate::err::ERR_peek_error() };
        if l != 0 {
            let system = l & core::ffi::c_ulong::from(ERR_SYSTEM_FLAG) != 0;
            let lib = (l >> rustyssl_abi::ERR_LIB_OFFSET) & core::ffi::c_ulong::try_from(rustyssl_abi::ERR_LIB_MASK).unwrap_or(0xff);
            return if system || lib == core::ffi::c_ulong::try_from(ERR_LIB_SYS).unwrap_or(2) {
                SSL_ERROR_SYSCALL
            } else {
                SSL_ERROR_SSL
            };
        }
        let (rwstate, shutdown, warn) = {
            let st = x.state();
            (st.rwstate, st.shutdown, st.drv.warn_alert)
        };
        let (rbio, wbio) = super::bios(x);
        let flags = |b: *mut rustyssl_abi::BIO, f: c_int| -> bool {
            // SAFETY: the connection's BIO, or NULL (no flags).
            !b.is_null() && unsafe { BIO_test_flags(b, f) } != 0
        };
        let special = |b: *mut rustyssl_abi::BIO| -> c_int {
            // SAFETY: as above.
            match unsafe { BIO_get_retry_reason(b) } {
                BIO_RR_CONNECT => SSL_ERROR_WANT_CONNECT,
                BIO_RR_ACCEPT => SSL_ERROR_WANT_ACCEPT,
                _ => SSL_ERROR_SYSCALL,
            }
        };
        if rwstate == SSL_READING {
            if flags(rbio, BIO_FLAGS_READ) {
                return SSL_ERROR_WANT_READ;
            }
            if flags(rbio, BIO_FLAGS_WRITE) {
                return SSL_ERROR_WANT_WRITE;
            }
            if flags(rbio, BIO_FLAGS_IO_SPECIAL) {
                return special(rbio);
            }
        }
        if rwstate == SSL_WRITING {
            if flags(wbio, BIO_FLAGS_WRITE) {
                return SSL_ERROR_WANT_WRITE;
            }
            if flags(wbio, BIO_FLAGS_READ) {
                return SSL_ERROR_WANT_READ;
            }
            if flags(wbio, BIO_FLAGS_IO_SPECIAL) {
                return special(wbio);
            }
        }
        match rwstate {
            SSL_X509_LOOKUP => return SSL_ERROR_WANT_X509_LOOKUP,
            SSL_RETRY_VERIFY => return SSL_ERROR_WANT_RETRY_VERIFY,
            rustyssl_abi::SSL_ASYNC_PAUSED => return SSL_ERROR_WANT_ASYNC,
            rustyssl_abi::SSL_ASYNC_NO_JOBS => return rustyssl_abi::SSL_ERROR_WANT_ASYNC_JOB,
            SSL_CLIENT_HELLO_CB => return SSL_ERROR_WANT_CLIENT_HELLO_CB,
            _ => {}
        }
        if shutdown & SSL_RECEIVED_SHUTDOWN != 0 && c_int::from(warn) == SSL_AD_CLOSE_NOTIFY {
            return SSL_ERROR_ZERO_RETURN;
        }
        SSL_ERROR_SYSCALL
    }
}

ffi_export! {
    /// Shuts the connection down (`ssl3_shutdown`): sends close_notify once, then (on a later
    /// call) waits for the peer's. 1 when both are done, 0 when ours is sent and the peer's not
    /// yet received, -1 when the BIO would block or on error (`SSL_R_SHUTDOWN_WHILE_IN_INIT`
    /// during a handshake). Quiet shutdown only sets the flags.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_shutdown(s: *mut SSL) -> c_int
    where failure = -1, library = ERR_LIB_SSL
    {
        const F: &str = "SSL_shutdown";
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return -1 };
        {
            let mut st = x.state();
            if st.handshake_func.is_none() {
                drop(st);
                err::raise(ERR_LIB_SSL, SSL_R_UNINITIALIZED, F);
                return -1;
            }
            if st.in_init {
                drop(st);
                err::raise(ERR_LIB_SSL, SSL_R_SHUTDOWN_WHILE_IN_INIT, F);
                return -1;
            }
            // Quiet shutdown (and a connection that never started) only sets the flags.
            if st.quiet_shutdown != 0 || st.flow_uninited {
                st.shutdown = SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN;
                if let Some(c) = st.drv.tls.as_mut() {
                    c.set_shutdown_state(rustyssl_tls::conn::SENT_SHUTDOWN | rustyssl_tls::conn::RECEIVED_SHUTDOWN);
                }
                return 1;
            }
        }
        let sent = x.state().shutdown & SSL_SENT_SHUTDOWN != 0;
        if !sent {
            let snap = super::config::snapshot(x);
            let r = {
                let mut st = x.state();
                let prov = st.drv.provider.clone();
                let notify = super::notify_flags(&st, snap.as_ref());
                st.shutdown |= SSL_SENT_SHUTDOWN;
                match (st.drv.tls.as_mut(), prov) {
                    (Some(c), Some(p)) => {
                        c.config_mut().callbacks.info = notify.0;
                        c.config_mut().callbacks.msg = notify.1;
                        c.send_close_notify(&*p)
                    }
                    _ => Ok(()),
                }
            };
            if let Err(e) = r {
                raise_core(&e, F);
                return -1;
            }
            // SAFETY: the live connection.
            match unsafe { drive(s, x, false, F) } {
                Stop::Idle | Stop::Done | Stop::AppData | Stop::Closed => {}
                _ => return -1,
            }
        } else if !x.state().drv.out.is_empty() {
            // SAFETY: as above.
            match unsafe { flush(x) } {
                Flush::Done => {}
                Flush::Retry | Flush::Error => return -1,
            }
        } else if x.state().shutdown & SSL_RECEIVED_SHUTDOWN == 0 {
            // Wait for the peer's close_notify (`ssl3_read_bytes` with no buffer): application
            // data after our close_notify is fatal (no alert: ours is already sent).
            loop {
                let pending = x.state().drv.tls.as_ref().is_some_and(|c| c.pending_app() > 0);
                if pending {
                    err::raise(ERR_LIB_SSL, SSL_R_APPLICATION_DATA_AFTER_CLOSE_NOTIFY, "ssl3_read_bytes");
                    x.state().drv.failed = true;
                    return -1;
                }
                // SAFETY: as above.
                match unsafe { drive(s, x, true, F) } {
                    // A fatal alert from the peer fails the read but marks the connection
                    // received-shutdown (`ssl3_read_bytes`), so with both directions closed
                    // the call returns 1, the alert's entry still queued (BoGo's
                    // `Unclean-Shutdown-Alert`, which fails on the reference too).
                    Stop::Closed | Stop::Failed => break,
                    Stop::AppData | Stop::Done | Stop::Idle => {}
                    Stop::Retry | Stop::Syscall => return -1,
                }
            }
            // `ssl3_shutdown`: the read ended (an unexpected EOF is fatal) without the peer's
            // close_notify.
            if x.state().shutdown & SSL_RECEIVED_SHUTDOWN == 0 {
                return -1;
            }
        }
        let st = x.state();
        c_int::from(st.shutdown == SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN && st.drv.out.is_empty())
    }
}

ffi_export! {
    /// How many octets of application data can be read without reading the BIO.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_pending(s: *const SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        x.state().drv.tls.as_ref().map_or(0, |c| c_int::try_from(c.pending_app()).unwrap_or(c_int::MAX))
    }
}

ffi_export! {
    /// Whether data is buffered: application data, or record octets read but not processed.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_has_pending(s: *const SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        x.state().drv.tls.as_ref().map_or(0, |c| c_int::from(c.pending_app() > 0 || c.buffered_input() > 0))
    }
}

ffi_export! {
    /// The negotiated cipher, or NULL before one is.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_current_cipher(s: *const SSL) -> *const SSL_CIPHER
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return ptr::null() };
        let st = x.state();
        st.drv
            .tls
            .as_ref()
            .and_then(|c| c.negotiated().cipher)
            .or(st.drv.kept_cipher)
            .map_or(ptr::null(), super::super::ciphers::cipher_ptr)
    }
}

ffi_export! {
    /// The cipher being negotiated (`s->s3.tmp.new_cipher`), or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_pending_cipher(s: *const SSL) -> *const SSL_CIPHER
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return ptr::null() };
        x.state()
            .drv
            .tls
            .as_ref()
            .and_then(|c| c.handshake().new_cipher)
            .map_or(ptr::null(), super::super::ciphers::cipher_ptr)
    }
}

ffi_export! {
    /// The ALPN protocol selected (`*data` and `*len`; NULL and 0 for none).
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `data` and `len` writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_get0_alpn_selected(s: *const SSL, data: *mut *const c_uchar, len: *mut c_uint)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let st = unsafe { ssl(s) }.map(Ssl::state);
        let (p, n) = match &st {
            Some(st) if !st.drv.alpn.is_empty() => (st.drv.alpn.as_ptr(), c_uint::try_from(st.drv.alpn.len()).unwrap_or(0)),
            _ => (ptr::null(), 0),
        };
        if !data.is_null() {
            // SAFETY: the caller's slot.
            unsafe { data.write(p) };
        }
        if !len.is_null() {
            // SAFETY: as above.
            unsafe { len.write(n) };
        }
    }
}

/// The peer's certificate (the connection keeps it), or NULL.
fn peer_leaf(x: &Ssl) -> *mut X509 {
    let st = x.state();
    // A resumed handshake sends no certificate: the peer is the session's (`s->session->peer`),
    // even though the core restores the session's chain (which is then not a received one, and
    // not verified again).
    if st.hit != 0 && !st.sess.session.is_null() {
        // SAFETY: the connection's session, which it holds a reference to.
        return unsafe {
            crate::ssl::session::rustyssl_private_SSL_SESSION_get0_peer(st.sess.session)
        };
    }
    if !st.drv.peer.accepted {
        return ptr::null_mut();
    }
    // SAFETY: our stack, or NULL (-1).
    if unsafe { OPENSSL_sk_num(st.drv.peer.chain.cast()) } <= 0 {
        return ptr::null_mut();
    }
    // SAFETY: an index in range.
    unsafe { OPENSSL_sk_value(st.drv.peer.chain.cast(), 0) }.cast()
}

ffi_export! {
    /// The peer's certificate (no reference taken), or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get0_peer_certificate(s: *const SSL) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ssl(s) }.map_or(ptr::null_mut(), peer_leaf)
    }
}

ffi_export! {
    /// The peer's certificate with a reference for the caller, or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get1_peer_certificate(s: *const SSL) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let x = unsafe { ssl(s) }.map_or(ptr::null_mut(), peer_leaf);
        // SAFETY: the connection's certificate, or NULL.
        if !x.is_null() && unsafe { X509_up_ref(x) } == 0 {
            return ptr::null_mut();
        }
        x
    }
}

ffi_export! {
    /// The certificates the peer sent (a client sees the server's leaf among them; a server
    /// doesn't see the client's), owned by the connection; NULL before any.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_peer_cert_chain(s: *const SSL) -> *mut stack_st_X509
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return ptr::null_mut() };
        let st = x.state();
        // A resumed handshake's chain is the session's (`s->session->peer_chain`): a cached
        // session's, or none from a ticket.
        if st.hit != 0 && !st.sess.session.is_null() {
            // SAFETY: the connection's session, which it holds a reference to.
            return unsafe { crate::ssl::session::with(st.sess.session, ptr::null_mut(), |d| d.peer_chain) };
        }
        if st.drv.peer.from == 0 {
            return ptr::null_mut();
        }
        st.drv.peer.chain_no_leaf
    }
}

ffi_export! {
    /// The chain verification built (owned by the connection), or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get0_verified_chain(s: *const SSL) -> *mut stack_st_X509
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ssl(s) }.map_or(ptr::null_mut(), |x| x.state().drv.peer.verified)
    }
}

ffi_export! {
    /// TLS 1.3's early data status (`SSL_EARLY_DATA_NOT_SENT`, `_REJECTED`, `_ACCEPTED`).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_early_data_status(s: *const SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        x.state().drv.tls.as_ref().map_or(rustyssl_abi::SSL_EARLY_DATA_NOT_SENT, |c| c.negotiated().early_data_status)
    }
}

/// A signature scheme's name, hash NID, key type NID, and combined signature NID, as
/// OpenSSL's `sigalg_lookup_tbl` gives them (code points from the core's table).
fn sigalg_info(code: u16) -> Option<(&'static CStr, c_int, c_int, c_int)> {
    use rustyssl_abi::*;
    use rustyssl_tls::consts::sigscheme as s;
    let ec = NID_X9_62_id_ecPublicKey;
    Some(match code {
        s::ECDSA_SECP256R1_SHA256 => (
            c"ecdsa_secp256r1_sha256",
            NID_sha256,
            ec,
            NID_ecdsa_with_SHA256,
        ),
        s::ECDSA_SECP384R1_SHA384 => (
            c"ecdsa_secp384r1_sha384",
            NID_sha384,
            ec,
            NID_ecdsa_with_SHA384,
        ),
        s::ECDSA_SECP521R1_SHA512 => (
            c"ecdsa_secp521r1_sha512",
            NID_sha512,
            ec,
            NID_ecdsa_with_SHA512,
        ),
        s::ED25519 => (c"ed25519", NID_undef, NID_ED25519, NID_undef),
        s::ED448 => (c"ed448", NID_undef, NID_ED448, NID_undef),
        s::ECDSA_SHA224 => (c"ecdsa_sha224", NID_sha224, ec, NID_ecdsa_with_SHA224),
        s::ECDSA_SHA1 => (c"ecdsa_sha1", NID_sha1, ec, NID_ecdsa_with_SHA1),
        s::ECDSA_BRAINPOOLP256R1_SHA256 => (
            c"ecdsa_brainpoolP256r1tls13_sha256",
            NID_sha256,
            ec,
            NID_ecdsa_with_SHA256,
        ),
        s::ECDSA_BRAINPOOLP384R1_SHA384 => (
            c"ecdsa_brainpoolP384r1tls13_sha384",
            NID_sha384,
            ec,
            NID_ecdsa_with_SHA384,
        ),
        s::ECDSA_BRAINPOOLP512R1_SHA512 => (
            c"ecdsa_brainpoolP512r1tls13_sha512",
            NID_sha512,
            ec,
            NID_ecdsa_with_SHA512,
        ),
        s::RSA_PSS_RSAE_SHA256 => (c"rsa_pss_rsae_sha256", NID_sha256, NID_rsassaPss, NID_undef),
        s::RSA_PSS_RSAE_SHA384 => (c"rsa_pss_rsae_sha384", NID_sha384, NID_rsassaPss, NID_undef),
        s::RSA_PSS_RSAE_SHA512 => (c"rsa_pss_rsae_sha512", NID_sha512, NID_rsassaPss, NID_undef),
        s::RSA_PSS_PSS_SHA256 => (c"rsa_pss_pss_sha256", NID_sha256, NID_rsassaPss, NID_undef),
        s::RSA_PSS_PSS_SHA384 => (c"rsa_pss_pss_sha384", NID_sha384, NID_rsassaPss, NID_undef),
        s::RSA_PSS_PSS_SHA512 => (c"rsa_pss_pss_sha512", NID_sha512, NID_rsassaPss, NID_undef),
        s::RSA_PKCS1_SHA256 => (
            c"rsa_pkcs1_sha256",
            NID_sha256,
            NID_rsaEncryption,
            NID_sha256WithRSAEncryption,
        ),
        s::RSA_PKCS1_SHA384 => (
            c"rsa_pkcs1_sha384",
            NID_sha384,
            NID_rsaEncryption,
            NID_sha384WithRSAEncryption,
        ),
        s::RSA_PKCS1_SHA512 => (
            c"rsa_pkcs1_sha512",
            NID_sha512,
            NID_rsaEncryption,
            NID_sha512WithRSAEncryption,
        ),
        s::RSA_PKCS1_SHA224 => (
            c"rsa_pkcs1_sha224",
            NID_sha224,
            NID_rsaEncryption,
            NID_sha224WithRSAEncryption,
        ),
        s::RSA_PKCS1_SHA1 => (
            c"rsa_pkcs1_sha1",
            NID_sha1,
            NID_rsaEncryption,
            NID_sha1WithRSAEncryption,
        ),
        s::DSA_SHA256 => (c"dsa_sha256", NID_sha256, NID_dsa, NID_dsa_with_SHA256),
        s::DSA_SHA384 => (c"dsa_sha384", NID_sha384, NID_dsa, NID_undef),
        s::DSA_SHA512 => (c"dsa_sha512", NID_sha512, NID_dsa, NID_undef),
        s::DSA_SHA224 => (c"dsa_sha224", NID_sha224, NID_dsa, NID_undef),
        s::DSA_SHA1 => (c"dsa_sha1", NID_sha1, NID_dsa, NID_dsaWithSHA1),
        s::RSA_PKCS1_MD5_SHA1 => (
            c"rsa_pkcs1_md5_sha1",
            NID_md5_sha1,
            NID_rsaEncryption,
            NID_undef,
        ),
        // The providers' schemes: `sig` and `sigandhash` are both the sigalg name's NID.
        s::MLDSA44 => (c"mldsa44", NID_undef, NID_ML_DSA_44, NID_ML_DSA_44),
        s::MLDSA65 => (c"mldsa65", NID_undef, NID_ML_DSA_65, NID_ML_DSA_65),
        s::MLDSA87 => (c"mldsa87", NID_undef, NID_ML_DSA_87, NID_ML_DSA_87),
        _ => return None,
    })
}

ffi_export! {
    /// The key type NID of the scheme the peer signed with, in `*pnid`: 1, or 0 if none.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `pnid` writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_peer_signature_type_nid(s: *const SSL, pnid: *mut c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let code = x.state().drv.tls.as_ref().and_then(|c| c.negotiated().peer_scheme);
        let Some((_, _, sig, _)) = code.and_then(sigalg_info) else { return 0 };
        if !pnid.is_null() {
            // SAFETY: the caller's slot.
            unsafe { pnid.write(sig) };
        }
        1
    }
}

ffi_export! {
    /// The key type NID of the scheme this end signed with, in `*pnid`: 1, or 0 if none.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `pnid` writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_signature_type_nid(s: *const SSL, pnid: *mut c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let code = x.state().drv.tls.as_ref().and_then(|c| c.negotiated().own_scheme);
        let Some((_, _, sig, _)) = code.and_then(sigalg_info) else { return 0 };
        if !pnid.is_null() {
            // SAFETY: the caller's slot.
            unsafe { pnid.write(sig) };
        }
        1
    }
}

/// Fills `SSL_get_sigalgs`' and `SSL_get_shared_sigalgs`' outputs for entry `idx` of `list`;
/// returns the list's length (0 if `idx` is out of range and outputs are asked for).
///
/// # Safety
/// The output pointers are NULL or writable.
unsafe fn sigalg_out(
    list: &[u16],
    idx: c_int,
    psign: *mut c_int,
    phash: *mut c_int,
    psignhash: *mut c_int,
    rsig: *mut c_uchar,
    rhash: *mut c_uchar,
) -> c_int {
    let n = c_int::try_from(list.len()).unwrap_or(c_int::MAX);
    if idx < 0 {
        return n;
    }
    let Some(&code) = usize::try_from(idx).ok().and_then(|i| list.get(i)) else {
        return 0;
    };
    let (_, hash, sig, sighash) =
        sigalg_info(code).unwrap_or((c"", NID_undef, NID_undef, NID_undef));
    let [hi, lo] = code.to_be_bytes();
    /// Stores `v` in `p` unless it is NULL.
    ///
    /// # Safety
    /// `p` is NULL or writable.
    unsafe fn put<T>(p: *mut T, v: T) {
        if !p.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { p.write(v) };
        }
    }
    // SAFETY: the caller's slots, each NULL or writable.
    unsafe { put(psign, sig) };
    // SAFETY: as above.
    unsafe { put(phash, hash) };
    // SAFETY: as above.
    unsafe { put(psignhash, sighash) };
    // SAFETY: as above.
    unsafe { put(rsig, lo) };
    // SAFETY: as above.
    unsafe { put(rhash, hi) };
    n
}

ffi_export! {
    /// The peer's signature algorithms: their number, and entry `idx`'s details.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; the outputs NULL or writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_sigalgs(s: *mut SSL, idx: c_int, psign: *mut c_int, phash: *mut c_int, psignhash: *mut c_int, rsig: *mut c_uchar, rhash: *mut c_uchar) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let list = x.state().drv.tls.as_ref().map(|c| c.negotiated().peer_sigalgs.clone()).unwrap_or_default();
        // SAFETY: the caller's slots.
        unsafe { sigalg_out(&list, idx, psign, phash, psignhash, rsig, rhash) }
    }
}

ffi_export! {
    /// The signature algorithms both ends share: their number, and entry `idx`'s details.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; the outputs NULL or writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_shared_sigalgs(s: *mut SSL, idx: c_int, psign: *mut c_int, phash: *mut c_int, psignhash: *mut c_int, rsig: *mut c_uchar, rhash: *mut c_uchar) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        // Unlike `SSL_get_sigalgs`, a negative index gives 0, not the count.
        if idx < 0 {
            return 0;
        }
        let list = x.state().drv.tls.as_ref().map(|c| c.negotiated().shared_sigalgs.clone()).unwrap_or_default();
        // SAFETY: the caller's slots.
        unsafe { sigalg_out(&list, idx, psign, phash, psignhash, rsig, rhash) }
    }
}

/// The ctrl commands that report what a handshake negotiated (`ssl3_ctrl`): `Some` result for
/// those handled, `None` for those that still abort.
///
/// # Safety
/// `x` is a live connection; `parg` is what `cmd` documents.
pub(crate) unsafe fn handshake_ctrl(x: &Ssl, cmd: c_int, parg: *mut c_void) -> Option<c_long> {
    use rustyssl_abi::{
        SSL_CTRL_GET_EXTMS_SUPPORT, SSL_CTRL_GET_NEGOTIATED_GROUP,
        SSL_CTRL_GET_PEER_SIGNATURE_NAME, SSL_CTRL_GET_PEER_SIGNATURE_NID,
        SSL_CTRL_GET_PEER_TMP_KEY, SSL_CTRL_GET_SIGNATURE_NAME, SSL_CTRL_GET_SIGNATURE_NID,
    };
    let st = x.state();
    let tls = st.drv.tls.as_deref();
    // A scheme's name and hash: a built-in's, else a provider's (the context's cache).
    let lookup = |code: u16| -> Option<(*const c_char, c_int)> {
        sigalg_info(code)
            .map(|(name, hash, ..)| (name.as_ptr(), hash))
            .or_else(|| st.drv.provider.as_ref()?.provider_sigalg(code))
    };
    let scheme_name = |code: Option<u16>| -> c_long {
        let Some((name, _)) = code.and_then(lookup) else {
            return 0;
        };
        if parg.is_null() {
            return 0;
        }
        // SAFETY: the caller's slot for a string pointer; the name is static, or lives with the
        // connection's provider.
        unsafe { parg.cast::<*const c_char>().write(name) };
        1
    };
    let scheme_hash = |code: Option<u16>| -> c_long {
        let Some((_, hash)) = code.and_then(lookup) else {
            return 0;
        };
        if !parg.is_null() {
            // SAFETY: the caller's slot for an int.
            unsafe { parg.cast::<c_int>().write(hash) };
        }
        1
    };
    Some(match cmd {
        SSL_CTRL_GET_PEER_SIGNATURE_NAME => {
            scheme_name(tls.and_then(|c| c.negotiated().peer_scheme))
        }
        SSL_CTRL_GET_SIGNATURE_NAME => scheme_name(tls.and_then(|c| c.negotiated().own_scheme)),
        SSL_CTRL_GET_PEER_SIGNATURE_NID => {
            scheme_hash(tls.and_then(|c| c.negotiated().peer_scheme))
        }
        SSL_CTRL_GET_SIGNATURE_NID => scheme_hash(tls.and_then(|c| c.negotiated().own_scheme)),
        SSL_CTRL_GET_NEGOTIATED_GROUP => {
            // TLS 1.3's group when the handshake made a key exchange, else the session's
            // (`kex_group`: a resumed TLS 1.2 handshake reports the original's).
            let id = tls
                .filter(|c| c.is_tls13())
                .and_then(|c| c.negotiated().group)
                .or_else(|| {
                    // SAFETY: the connection's session, or NULL, alive under its lock.
                    let k = unsafe { crate::ssl::session::sess(st.sess.session) }
                        .map_or(0, |d| d.data().kex_group);
                    u16::try_from(k).ok().filter(|&k| k != 0)
                });
            let prov = st.drv.provider.clone();
            match (id, prov) {
                (Some(id), Some(p)) => c_long::from(super::config::group_nid(&p, id)),
                _ => c_long::from(NID_undef),
            }
        }
        // The client's raw cipher list (a server's), or the length of one suite's code.
        rustyssl_abi::SSL_CTRL_GET_RAW_CIPHERLIST => {
            if parg.is_null() {
                return Some(2);
            }
            let Some(raw) = tls.and_then(Connection::raw_cipherlist) else {
                return Some(0);
            };
            // SAFETY: the caller's slot for a pointer; the list stays with the connection.
            unsafe { parg.cast::<*const u8>().write(raw.as_ptr()) };
            c_long::try_from(raw.len()).unwrap_or(0)
        }
        // The peer's ec_point_formats extension, as received.
        rustyssl_abi::SSL_CTRL_GET_EC_POINT_FORMATS => {
            let Some(f) = tls.and_then(|c| c.handshake().sh.peer_ecpointformats.as_ref()) else {
                return Some(0);
            };
            if !parg.is_null() {
                // SAFETY: as above.
                unsafe { parg.cast::<*const u8>().write(f.as_ptr()) };
            }
            c_long::try_from(f.len()).unwrap_or(0)
        }
        SSL_CTRL_GET_EXTMS_SUPPORT => match tls {
            Some(c) if !st.in_init => c_long::from(c.negotiated().ems),
            _ => -1,
        },
        SSL_CTRL_GET_PEER_TMP_KEY => {
            let share = tls.and_then(|c| c.handshake().sh.peer_tmp.clone());
            let dh = tls.and_then(|c| c.handshake().sh.peer_dh.clone());
            let prov = st.drv.provider.clone();
            drop(st);
            let key = match (share, dh, prov) {
                (Some((id, octets)), _, Some(p)) => p.peer_share_key(id, &octets),
                (None, Some((dp, dg, ys)), Some(p)) => p.peer_dh_key(&dp, &dg, &ys),
                _ => None,
            };
            match key {
                Some(k) if !parg.is_null() => {
                    // SAFETY: the caller's slot for a key it now owns.
                    unsafe { parg.cast::<*mut EVP_PKEY>().write(k) };
                    1
                }
                Some(k) => {
                    // SAFETY: the key made above, not handed out.
                    unsafe { crate::evp::pkey::EVP_PKEY_free(k) };
                    0
                }
                None => 0,
            }
        }
        _ => return None,
    })
}

ffi_export! {
    /// The TLS name of a group (`x25519`, `X25519MLKEM768`, ...), by NID or by
    /// `TLSEXT_nid_unknown | code point`; NULL if the providers have no such group.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_group_to_name(s: *mut SSL, id: c_int) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return ptr::null() };
        let Some(snap) = super::config::snapshot(x) else { return ptr::null() };
        // SAFETY: the connection's context's snapshot.
        let prov = unsafe { super::provider(x, &snap) };
        let code = if id & rustyssl_abi::TLSEXT_nid_unknown != 0 {
            u16::try_from(id & 0xffff).ok()
        } else {
            super::config::group_of_nid(&prov, id)
        };
        let Some(code) = code else { return ptr::null() };
        let Some(g) = rustyssl_tls::crypto::Provider::groups(&*prov).into_iter().find(|g| g.id == code) else {
            return ptr::null();
        };
        let Ok(name) = std::ffi::CString::new(g.name) else { return ptr::null() };
        let mut st = x.state();
        let names = &mut st.drv.group_names;
        if let Some(n) = names.iter().find(|n| **n == name) {
            return n.as_ptr();
        }
        // The CString's buffer doesn't move when the vector grows.
        let p = name.as_ptr();
        names.push(name);
        p
    }
}

ffi_export! {
    /// The peer's raw public key (RFC 7250), owned by the connection; NULL when the peer sent a
    /// certificate or nothing.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get0_peer_rpk(s: *const SSL) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return ptr::null_mut() };
        let mut st = x.state();
        if !st.drv.peer_rpk.0.is_null() {
            return st.drv.peer_rpk.0;
        }
        let Some(der) = st.drv.tls.as_ref().and_then(|c| c.negotiated().peer_rpk.clone()) else {
            // A resumed session's (`sc->session->peer_rpk`).
            // SAFETY: the connection's session, or NULL.
            return unsafe { crate::ssl::session::with(st.sess.session, ptr::null_mut(), |d| d.peer_rpk) };
        };
        let Ok(len) = c_long::try_from(der.len()) else { return ptr::null_mut() };
        let mut p = der.as_ptr();
        // Decoded in the context's library context (`tls_process_rpk`).
        // SAFETY: the connection's live context, or NULL.
        let (libctx, propq) = unsafe { crate::ssl::ctx::ctx(st.ctx.cast_const()) }
            .map_or((ptr::null_mut(), ptr::null()), |c| (c.libctx, c.propq_ptr()));
        // SAFETY: the key's SubjectPublicKeyInfo octets (decoding runs no callbacks); the
        // library context and properties.
        let k = unsafe {
            crate::x509::pubkey::d2i_PUBKEY_ex(ptr::null_mut(), &raw mut p, len, libctx, propq)
        };
        st.drv.peer_rpk.0 = k;
        k
    }
}

/// A negotiated certificate type (RFC 7250) of the connection.
fn cert_type(s: *const SSL, client: bool) -> c_int {
    // SAFETY: the caller's connection, NULL or live.
    let Some(x) = (unsafe { ssl(s) }) else {
        return rustyssl_abi::TLSEXT_cert_type_x509;
    };
    let st = x.state();
    st.drv
        .tls
        .as_ref()
        .map_or(rustyssl_abi::TLSEXT_cert_type_x509, |c| {
            let n = c.negotiated();
            c_int::from(if client {
                n.client_cert_type
            } else {
                n.server_cert_type
            })
        })
}

ffi_export! {
    /// The certificate type the client authenticates with (`TLSEXT_cert_type_*`).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_negotiated_client_cert_type(s: *const SSL) -> c_int
    where failure = rustyssl_abi::TLSEXT_cert_type_x509, library = ERR_LIB_SSL
    {
        cert_type(s, true)
    }
}

ffi_export! {
    /// The certificate type the server authenticates with (`TLSEXT_cert_type_*`).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_negotiated_server_cert_type(s: *const SSL) -> c_int
    where failure = rustyssl_abi::TLSEXT_cert_type_x509, library = ERR_LIB_SSL
    {
        cert_type(s, false)
    }
}
