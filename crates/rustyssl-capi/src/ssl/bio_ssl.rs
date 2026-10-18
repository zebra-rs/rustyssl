//! The SSL filter BIO (`BIO_f_ssl`, `bio_ssl.c`): reads and writes go through a connection,
//! with the connection's want-states turned into the BIO's retry flags, and optional
//! renegotiation after a byte count or a time. The constructors `BIO_new_ssl`,
//! `BIO_new_ssl_connect`, and `BIO_new_buffer_ssl_connect`, and `BIO_ssl_copy_session_id` and
//! `BIO_ssl_shutdown`.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use rustyssl_abi::{
    BIO, BIO_C_DO_STATE_MACHINE, BIO_C_GET_FD, BIO_C_GET_SSL, BIO_C_GET_SSL_NUM_RENEGOTIATES,
    BIO_C_SET_SSL, BIO_C_SET_SSL_RENEGOTIATE_BYTES, BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT,
    BIO_C_SSL_MODE, BIO_CLOSE, BIO_CTRL_DUP, BIO_CTRL_FLUSH, BIO_CTRL_GET_CLOSE,
    BIO_CTRL_GET_RPOLL_DESCRIPTOR, BIO_CTRL_GET_WPOLL_DESCRIPTOR, BIO_CTRL_INFO, BIO_CTRL_PENDING,
    BIO_CTRL_POP, BIO_CTRL_PUSH, BIO_CTRL_RESET, BIO_CTRL_SET_CALLBACK, BIO_CTRL_SET_CLOSE,
    BIO_CTRL_WPENDING, BIO_FLAGS_IO_SPECIAL, BIO_FLAGS_READ, BIO_FLAGS_SHOULD_RETRY,
    BIO_FLAGS_WRITE, BIO_METHOD, BIO_POLL_DESCRIPTOR, BIO_RR_ACCEPT, BIO_RR_CONNECT,
    BIO_RR_SSL_X509_LOOKUP, BIO_TYPE_SSL, BIO_info_cb, ERR_LIB_SSL, SSL, SSL_CTX, SSL_ERROR_NONE,
    SSL_ERROR_WANT_ACCEPT, SSL_ERROR_WANT_CONNECT, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE,
    SSL_ERROR_WANT_X509_LOOKUP,
};

use super::conn::{
    Role, rustyssl_private_SSL_clear, rustyssl_private_SSL_free, rustyssl_private_SSL_get_rbio,
    rustyssl_private_SSL_get_wbio, rustyssl_private_SSL_in_init, rustyssl_private_SSL_new,
    rustyssl_private_SSL_set_accept_state, rustyssl_private_SSL_set_bio,
    rustyssl_private_SSL_set_connect_state, ssl,
};
use super::dup::rustyssl_private_SSL_dup;
use super::io::api::{
    read_internal, rustyssl_private_SSL_do_handshake, rustyssl_private_SSL_get_error,
    rustyssl_private_SSL_pending, rustyssl_private_SSL_shutdown, write_internal,
};
use super::requests::rustyssl_private_SSL_renegotiate;
use crate::bio::method::{Builtin, Funcs};
use crate::bio::state::{self, lock};
use crate::bio::{self as bio, object};
use crate::ffi::{ffi_callback, ffi_export};

// Functions another part of libssl provides (they may still be generated stubs, which abort).
unsafe extern "C" {
    fn rustyssl_private_SSL_copy_session_id(to: *mut SSL, from: *const SSL) -> c_int;
}

/// A connection pointer kept in the BIO's state.
#[derive(Clone, Copy)]
struct SslPtr(*mut SSL);

// SAFETY: only an address; the connection itself is thread-safe (an `Ssl` handle).
unsafe impl Send for SslPtr {}

/// `BIO_SSL`.
struct BioSsl {
    ssl: SslPtr,
    num_renegotiates: c_long,
    renegotiate_count: u64,
    byte_count: u64,
    renegotiate_timeout: u64,
    last_time: u64,
}

impl Default for BioSsl {
    fn default() -> Self {
        Self {
            ssl: SslPtr(ptr::null_mut()),
            num_renegotiates: 0,
            renegotiate_count: 0,
            byte_count: 0,
            renegotiate_timeout: 0,
            last_time: 0,
        }
    }
}

/// `time(NULL)`.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The connection of the SSL BIO `b`, or null.
fn ssl_of(b: &bio::Bio) -> *mut SSL {
    state::get::<BioSsl>(b).map_or(ptr::null_mut(), |st| lock(&st).ssl.0)
}

/// After a successful read or write of `n` octets: the renegotiation the byte count or the
/// timeout asks for.
///
/// # Safety
/// `s` is a live connection.
unsafe fn after_io(b: &bio::Bio, s: *mut SSL, n: usize) {
    let Some(st) = state::get::<BioSsl>(b) else {
        return;
    };
    let mut renegotiate = false;
    {
        let mut bs = lock(&st);
        let mut done = false;
        if bs.renegotiate_count > 0 {
            bs.byte_count = bs
                .byte_count
                .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
            if bs.byte_count > bs.renegotiate_count {
                bs.byte_count = 0;
                bs.num_renegotiates = bs.num_renegotiates.saturating_add(1);
                renegotiate = true;
                done = true;
            }
        }
        if bs.renegotiate_timeout > 0 && !done {
            let tm = now();
            if tm > bs.last_time.saturating_add(bs.renegotiate_timeout) {
                bs.last_time = tm;
                bs.num_renegotiates = bs.num_renegotiates.saturating_add(1);
                renegotiate = true;
            }
        }
    }
    if renegotiate {
        // SAFETY: the caller's guarantee; no lock is held.
        unsafe { rustyssl_private_SSL_renegotiate(s) };
    }
}

/// `BIO_set_retry_reason`.
///
/// # Safety
/// `b` is a live BIO.
unsafe fn set_reason(b: *mut BIO, reason: c_int) {
    // SAFETY: the caller's guarantee.
    unsafe { bio::BIO_set_retry_reason(b, reason) };
}

/// The retry flags and reason for the connection's `SSL_get_error` after `ret` (`ssl_read`
/// and `ssl_write`; `accept` counts `SSL_ERROR_WANT_ACCEPT` only for reads).
///
/// # Safety
/// `b` is the live BIO behind `o`; `s` is a live connection.
unsafe fn retry(b: *mut BIO, o: &bio::Bio, s: *mut SSL, ret: c_int, accept: bool) -> c_int {
    // SAFETY: the caller's guarantee.
    let e = unsafe { rustyssl_private_SSL_get_error(s, ret) };
    let special = BIO_FLAGS_IO_SPECIAL | BIO_FLAGS_SHOULD_RETRY;
    let mut reason = 0;
    match e {
        SSL_ERROR_WANT_READ => o.set_retry_read(),
        SSL_ERROR_WANT_WRITE => o.set_retry_write(),
        SSL_ERROR_WANT_X509_LOOKUP => {
            o.set_flags(special);
            reason = BIO_RR_SSL_X509_LOOKUP;
        }
        SSL_ERROR_WANT_ACCEPT if accept => {
            o.set_flags(special);
            reason = BIO_RR_ACCEPT;
        }
        SSL_ERROR_WANT_CONNECT => {
            o.set_flags(special);
            reason = BIO_RR_CONNECT;
        }
        _ => {}
    }
    // SAFETY: the caller's guarantee.
    unsafe { set_reason(b, reason) };
    e
}

ffi_callback! {
    /// `ssl_new`: an empty state, not initialised, with no flags.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn ssl_bio_new(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(o) = (unsafe { object(b) }) else { return 0 };
        o.init.store(0, Ordering::Relaxed);
        state::install(o, BioSsl::default());
        o.clear_flags(!0);
        1
    }
}

/// `ssl_free`'s work, without freeing the state: with the close flag, the connection is shut
/// down (unless in a handshake) and freed.
///
/// # Safety
/// `o` is a live BIO.
unsafe fn release(o: &bio::Bio) {
    if o.shutdown.load(Ordering::Relaxed) == 0 {
        return;
    }
    let s = ssl_of(o);
    // SAFETY: the BIO's connection, which it owns.
    if !s.is_null() && unsafe { rustyssl_private_SSL_in_init(s) } == 0 {
        // SAFETY: as above.
        unsafe { rustyssl_private_SSL_shutdown(s) };
    }
    if o.init.load(Ordering::Relaxed) != 0 {
        // SAFETY: as above; the BIO's reference.
        unsafe { rustyssl_private_SSL_free(s) };
    }
    o.clear_flags(!0);
    o.init.store(0, Ordering::Relaxed);
}

ffi_callback! {
    /// `ssl_free`.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn ssl_bio_free(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(o) = (unsafe { object(b) }) else { return 0 };
        // SAFETY: as above.
        unsafe { release(o) };
        state::remove::<BioSsl>(o);
        1
    }
}

ffi_callback! {
    /// `ssl_read`: `SSL_read_ex` through the connection, with its retry state.
    ///
    /// # Safety
    /// `b` is a live BIO; `out` is null or valid for `size` octets; `readbytes` is valid.
    pub(crate) unsafe extern "C" fn ssl_bio_read(b: *mut BIO, out: *mut c_char, size: usize, readbytes: *mut usize) -> c_int
    where failure = -1, library = ERR_LIB_SSL
    {
        if out.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(o) = (unsafe { object(b) }) else { return 0 };
        let s = ssl_of(o);
        o.clear_retry_flags();
        let mut n = 0;
        // SAFETY: the BIO's connection (null is refused there); the caller's buffer.
        let ret = unsafe { read_internal(s, out.cast(), size, false, &mut n, "ssl_read_internal") };
        if !readbytes.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { readbytes.write(n) };
        }
        // SAFETY: as above.
        if unsafe { retry(b, o, s, ret, true) } == SSL_ERROR_NONE {
            // SAFETY: as above.
            unsafe { after_io(o, s, n) };
        }
        ret
    }
}

ffi_callback! {
    /// `ssl_write`: `SSL_write_ex` through the connection, with its retry state.
    ///
    /// # Safety
    /// `b` is a live BIO; `data` is null or valid for `size` octets; `written` is valid.
    pub(crate) unsafe extern "C" fn ssl_bio_write(b: *mut BIO, data: *const c_char, size: usize, written: *mut usize) -> c_int
    where failure = -1, library = ERR_LIB_SSL
    {
        if data.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(o) = (unsafe { object(b) }) else { return 0 };
        let s = ssl_of(o);
        o.clear_retry_flags();
        let mut n = 0;
        // SAFETY: the BIO's connection (null is refused there); the caller's data.
        let ret = unsafe { write_internal(s, data.cast(), size, &mut n, "ssl_write_internal") };
        if !written.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { written.write(n) };
        }
        // SAFETY: as above.
        if unsafe { retry(b, o, s, ret, false) } == SSL_ERROR_NONE {
            // SAFETY: as above.
            unsafe { after_io(o, s, n) };
        }
        ret
    }
}

ffi_callback! {
    /// `ssl_puts`: the string written through the BIO.
    ///
    /// # Safety
    /// `b` is a live BIO; `text` is a NUL-terminated string.
    pub(crate) unsafe extern "C" fn ssl_bio_puts(b: *mut BIO, text: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_SSL
    {
        if text.is_null() {
            return -1;
        }
        // SAFETY: the caller's string.
        let n = unsafe { core::ffi::CStr::from_ptr(text) }.to_bytes().len();
        let Ok(n) = c_int::try_from(n) else { return -1 };
        // SAFETY: the caller's BIO and string.
        unsafe { bio::BIO_write(b, text.cast(), n) }
    }
}

/// `BIO_C_SET_SSL`: takes `s` (owning it if `close`), with its read BIO (and anything after
/// this BIO) as the next BIO.
///
/// # Safety
/// `b` is the live BIO behind `o`; `s` is null or a live connection.
unsafe fn set_ssl(b: *mut BIO, o: &bio::Bio, close: c_long, s: *mut SSL) -> c_long {
    // SAFETY: the BIO's own pointer.
    let next = unsafe { bio::BIO_next(b) };
    if !ssl_of(o).is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { release(o) };
        state::install(o, BioSsl::default());
    }
    o.shutdown.store(
        c_int::try_from(close).unwrap_or(BIO_CLOSE),
        Ordering::Relaxed,
    );
    if let Some(st) = state::get::<BioSsl>(o) {
        lock(&st).ssl = SslPtr(s);
    }
    // SAFETY: the caller's connection.
    let rbio = unsafe { rustyssl_private_SSL_get_rbio(s) };
    if !rbio.is_null() {
        // SAFETY: the connection's live read BIO.
        if unsafe { bio::BIO_up_ref(rbio) } == 0 {
            return 0;
        }
        if !next.is_null() {
            // SAFETY: two live BIOs.
            unsafe { bio::BIO_push(rbio, next) };
        }
        // SAFETY: as above; the reference taken is the chain's.
        unsafe { bio::BIO_set_next(b, rbio) };
    }
    o.init.store(1, Ordering::Relaxed);
    1
}

/// `BIO_C_DO_STATE_MACHINE`: the handshake, with its want-state as the retry flags.
///
/// # Safety
/// `b` is the live BIO behind `o`; `s` is a live connection.
unsafe fn do_handshake(b: *mut BIO, o: &bio::Bio, s: *mut SSL) -> c_long {
    o.clear_retry_flags();
    // SAFETY: the caller's guarantee.
    unsafe { set_reason(b, 0) };
    // SAFETY: as above.
    let ret = unsafe { rustyssl_private_SSL_do_handshake(s) };
    // SAFETY: as above.
    match unsafe { rustyssl_private_SSL_get_error(s, ret) } {
        SSL_ERROR_WANT_READ => o.set_flags(BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY),
        SSL_ERROR_WANT_WRITE => o.set_flags(BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY),
        SSL_ERROR_WANT_CONNECT => {
            o.set_flags(BIO_FLAGS_IO_SPECIAL | BIO_FLAGS_SHOULD_RETRY);
            // SAFETY: the BIO's own pointer.
            let next = unsafe { bio::BIO_next(b) };
            // SAFETY: null or the live next BIO.
            let reason = unsafe { bio::BIO_get_retry_reason(next) };
            // SAFETY: as above.
            unsafe { set_reason(b, reason) };
        }
        SSL_ERROR_WANT_X509_LOOKUP => {
            o.set_flags(BIO_FLAGS_IO_SPECIAL | BIO_FLAGS_SHOULD_RETRY);
            // SAFETY: as above.
            unsafe { set_reason(b, BIO_RR_SSL_X509_LOOKUP) };
        }
        _ => {}
    }
    c_long::from(ret)
}

/// `BIO_CTRL_RESET`: the connection shut down and cleared for another handshake in the same
/// role, then the reset passed on.
///
/// # Safety
/// `b` is a live BIO; `s` is a live connection.
unsafe fn reset(b: *mut BIO, s: *mut SSL, cmd: c_int, num: c_long, p: *mut c_void) -> c_long {
    // SAFETY: the caller's guarantee.
    let Some(x) = (unsafe { ssl(s) }) else {
        return 0;
    };
    // SAFETY: as above.
    unsafe { rustyssl_private_SSL_shutdown(s) };
    let role = x.state().handshake_func;
    match role {
        // SAFETY: as above.
        Some(Role::Connect) => unsafe { rustyssl_private_SSL_set_connect_state(s) },
        // SAFETY: as above.
        Some(Role::Accept) => unsafe { rustyssl_private_SSL_set_accept_state(s) },
        None => {}
    }
    // SAFETY: as above.
    if unsafe { rustyssl_private_SSL_clear(s) } == 0 {
        return 0;
    }
    // SAFETY: the BIO's own pointer.
    let next = unsafe { bio::BIO_next(b) };
    if !next.is_null() {
        // SAFETY: the live next BIO.
        return unsafe { bio::BIO_ctrl(next, cmd, num, p) };
    }
    // SAFETY: as above.
    let rbio = unsafe { rustyssl_private_SSL_get_rbio(s) };
    if rbio.is_null() {
        return 1;
    }
    // SAFETY: the connection's live read BIO.
    unsafe { bio::BIO_ctrl(rbio, cmd, num, p) }
}

/// `BIO_CTRL_DUP`: the copy gets a duplicate of the connection and the renegotiation settings.
///
/// # Safety
/// `s` is a live connection; `dup` is the live copy, an SSL BIO.
unsafe fn dup(o: &bio::Bio, s: *mut SSL, dup: *mut BIO) -> c_long {
    // SAFETY: the caller's guarantee.
    let Some(d) = (unsafe { object(dup) }) else {
        return 0;
    };
    let (Some(from), Some(to)) = (state::get::<BioSsl>(o), state::get::<BioSsl>(d)) else {
        return 0;
    };
    let old = lock(&to).ssl.0;
    // SAFETY: the copy's connection, which it owns (or null).
    unsafe { rustyssl_private_SSL_free(old) };
    // SAFETY: the caller's guarantee.
    let copy = unsafe { rustyssl_private_SSL_dup(s) };
    let f = lock(&from);
    let mut t = lock(&to);
    t.ssl = SslPtr(copy);
    t.num_renegotiates = f.num_renegotiates;
    t.renegotiate_count = f.renegotiate_count;
    t.byte_count = f.byte_count;
    t.renegotiate_timeout = f.renegotiate_timeout;
    t.last_time = f.last_time;
    c_long::from(!copy.is_null())
}

ffi_callback! {
    /// `ssl_ctrl`.
    ///
    /// # Safety
    /// `b` is a live BIO; `p` is what the command expects.
    pub(crate) unsafe extern "C" fn ssl_bio_ctrl(b: *mut BIO, cmd: c_int, num: c_long, p: *mut c_void) -> c_long
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(o) = (unsafe { object(b) }) else { return 0 };
        let Some(st) = state::get::<BioSsl>(o) else { return 0 };
        let s = lock(&st).ssl.0;
        if s.is_null() && cmd != BIO_C_SET_SSL {
            return 0;
        }
        match cmd {
            // SAFETY: the BIO's live connection.
            BIO_CTRL_RESET => unsafe { reset(b, s, cmd, num, p) },
            BIO_CTRL_INFO => 0,
            BIO_C_SSL_MODE => {
                if num != 0 {
                    // SAFETY: as above.
                    unsafe { rustyssl_private_SSL_set_connect_state(s) };
                } else {
                    // SAFETY: as above.
                    unsafe { rustyssl_private_SSL_set_accept_state(s) };
                }
                1
            }
            BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT => {
                let mut bs = lock(&st);
                let old = c_long::try_from(bs.renegotiate_timeout).unwrap_or(c_long::MAX);
                // As OpenSSL has it: anything under a minute becomes 5 seconds.
                let num = if num < 60 { 5 } else { num };
                bs.renegotiate_timeout = u64::try_from(num).unwrap_or(0);
                bs.last_time = now();
                old
            }
            BIO_C_SET_SSL_RENEGOTIATE_BYTES => {
                let mut bs = lock(&st);
                let old = c_long::try_from(bs.renegotiate_count).unwrap_or(c_long::MAX);
                if num >= 512 {
                    bs.renegotiate_count = u64::try_from(num).unwrap_or(0);
                }
                old
            }
            BIO_C_GET_SSL_NUM_RENEGOTIATES => lock(&st).num_renegotiates,
            // SAFETY: the caller's connection (or null).
            BIO_C_SET_SSL => unsafe { set_ssl(b, o, num, p.cast()) },
            BIO_C_GET_SSL => {
                if p.is_null() {
                    return 0;
                }
                // SAFETY: the caller's `SSL **`.
                unsafe { p.cast::<*mut SSL>().write(s) };
                1
            }
            BIO_CTRL_GET_CLOSE => c_long::from(o.shutdown.load(Ordering::Relaxed)),
            BIO_CTRL_SET_CLOSE => {
                o.shutdown
                    .store(c_int::try_from(num).unwrap_or(BIO_CLOSE), Ordering::Relaxed);
                1
            }
            BIO_CTRL_WPENDING => {
                // SAFETY: as above.
                let w = unsafe { rustyssl_private_SSL_get_wbio(s) };
                // SAFETY: null or the connection's live write BIO.
                unsafe { bio::BIO_ctrl(w, cmd, num, p) }
            }
            BIO_CTRL_PENDING => {
                // SAFETY: as above.
                let n = unsafe { rustyssl_private_SSL_pending(s) };
                if n != 0 {
                    return c_long::from(n);
                }
                // SAFETY: as above.
                let r = unsafe { rustyssl_private_SSL_get_rbio(s) };
                // SAFETY: null or the connection's live read BIO.
                unsafe { bio::BIO_ctrl(r, BIO_CTRL_PENDING, 0, ptr::null_mut()) }
            }
            BIO_CTRL_FLUSH => {
                o.clear_retry_flags();
                // SAFETY: as above.
                let w = unsafe { rustyssl_private_SSL_get_wbio(s) };
                // SAFETY: null or the connection's live write BIO.
                let ret = unsafe { bio::BIO_ctrl(w, cmd, num, p) };
                bio::copy_next_retry(o);
                ret
            }
            BIO_CTRL_PUSH => {
                // SAFETY: the BIO's own pointer.
                let next = unsafe { bio::BIO_next(b) };
                // SAFETY: as above.
                let r = unsafe { rustyssl_private_SSL_get_rbio(s) };
                if next.is_null() || next == r {
                    return 1;
                }
                // The connection takes a reference of its own to the BIO now after this one.
                // SAFETY: the live next BIO.
                if unsafe { bio::BIO_up_ref(next) } == 0 {
                    return 0;
                }
                // SAFETY: the connection and the reference just taken.
                unsafe { rustyssl_private_SSL_set_bio(s, next, next) };
                1
            }
            BIO_CTRL_POP => {
                // Only when this BIO is the one popped: the reference the push took goes.
                if b.cast::<c_void>() == p {
                    // SAFETY: as above.
                    unsafe { rustyssl_private_SSL_set_bio(s, ptr::null_mut(), ptr::null_mut()) };
                }
                1
            }
            // SAFETY: as above.
            BIO_C_DO_STATE_MACHINE => unsafe { do_handshake(b, o, s) },
            // SAFETY: as above; the copy is an SSL BIO (`BIO_dup_chain` made it so).
            BIO_CTRL_DUP => unsafe { dup(o, s, p.cast()) },
            BIO_CTRL_SET_CALLBACK => 0,
            BIO_CTRL_GET_RPOLL_DESCRIPTOR => {
                // SAFETY: as above; the caller's descriptor.
                c_long::from(unsafe { rustyssl_private_SSL_get_rpoll_descriptor(s, p.cast()) } != 0)
            }
            BIO_CTRL_GET_WPOLL_DESCRIPTOR => {
                // SAFETY: as above; the caller's descriptor.
                c_long::from(unsafe { rustyssl_private_SSL_get_wpoll_descriptor(s, p.cast()) } != 0)
            }
            _ => {
                // `BIO_C_GET_FD` and everything else: the read BIO's.
                let _ = BIO_C_GET_FD;
                // SAFETY: as above.
                let r = unsafe { rustyssl_private_SSL_get_rbio(s) };
                // SAFETY: null or the connection's live read BIO.
                unsafe { bio::BIO_ctrl(r, cmd, num, p) }
            }
        }
    }
}

ffi_callback! {
    /// `ssl_callback_ctrl`: the callback is the read BIO's.
    ///
    /// # Safety
    /// `b` is a live BIO.
    pub(crate) unsafe extern "C" fn ssl_bio_callback_ctrl(b: *mut BIO, cmd: c_int, fp: BIO_info_cb) -> c_long
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(o) = (unsafe { object(b) }) else { return 0 };
        if cmd != BIO_CTRL_SET_CALLBACK {
            return 0;
        }
        let s = ssl_of(o);
        // SAFETY: null or the BIO's live connection.
        let r = unsafe { rustyssl_private_SSL_get_rbio(s) };
        // SAFETY: null or the connection's live read BIO.
        unsafe { bio::BIO_callback_ctrl(r, cmd, fp) }
    }
}

static SSL_FILTER: Builtin = Builtin::new(BIO_TYPE_SSL, c"ssl", || Funcs {
    bwrite: Some(ssl_bio_write),
    bread: Some(ssl_bio_read),
    bputs: Some(ssl_bio_puts),
    ctrl: Some(ssl_bio_ctrl),
    create: Some(ssl_bio_new),
    destroy: Some(ssl_bio_free),
    callback_ctrl: Some(ssl_bio_callback_ctrl),
    ..Funcs::default()
});

ffi_export! {
    /// The SSL filter BIO's method.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_BIO_f_ssl() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        SSL_FILTER.get()
    }
}

ffi_export! {
    /// An SSL BIO with a new connection from `ctx`, a client's if `client`, which it owns.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_BIO_new_ssl(ctx: *mut SSL_CTX, client: c_int) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the built-in method.
        let b = unsafe { bio::BIO_new(SSL_FILTER.get()) };
        if b.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let s = unsafe { rustyssl_private_SSL_new(ctx) };
        if s.is_null() {
            // SAFETY: the BIO just made.
            unsafe { bio::BIO_free(b) };
            return ptr::null_mut();
        }
        if client != 0 {
            // SAFETY: the connection just made.
            unsafe { rustyssl_private_SSL_set_connect_state(s) };
        } else {
            // SAFETY: as above.
            unsafe { rustyssl_private_SSL_set_accept_state(s) };
        }
        // `BIO_set_ssl(ret, ssl, BIO_CLOSE)`.
        // SAFETY: the BIO and the connection it takes.
        unsafe { bio::BIO_ctrl(b, BIO_C_SET_SSL, c_long::from(BIO_CLOSE), s.cast()) };
        b
    }
}

ffi_export! {
    /// An SSL client BIO in front of a connect BIO.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_BIO_new_ssl_connect(ctx: *mut SSL_CTX) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: no preconditions.
        let method = unsafe { bio::connect::BIO_s_connect() };
        // SAFETY: the built-in method.
        let con = unsafe { bio::BIO_new(method) };
        if con.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let s = unsafe { rustyssl_private_BIO_new_ssl(ctx, 1) };
        if s.is_null() {
            // SAFETY: the BIO just made.
            unsafe { bio::BIO_free(con) };
            return ptr::null_mut();
        }
        // SAFETY: two live BIOs.
        unsafe { bio::BIO_push(s, con) }
    }
}

ffi_export! {
    /// A buffering BIO in front of `BIO_new_ssl_connect`'s chain.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_BIO_new_buffer_ssl_connect(ctx: *mut SSL_CTX) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: no preconditions.
        let method = unsafe { bio::buffer::BIO_f_buffer() };
        // SAFETY: the built-in method.
        let buf = unsafe { bio::BIO_new(method) };
        if buf.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let s = unsafe { rustyssl_private_BIO_new_ssl_connect(ctx) };
        if s.is_null() {
            // SAFETY: the BIO just made.
            unsafe { bio::BIO_free(buf) };
            return ptr::null_mut();
        }
        // SAFETY: two live BIOs.
        unsafe { bio::BIO_push(buf, s) }
    }
}

/// The connection of the first SSL BIO in `b`'s chain, or null.
///
/// # Safety
/// `b` is null or a live BIO chain.
unsafe fn find_ssl(b: *mut BIO) -> *mut SSL {
    // SAFETY: the caller's guarantee.
    let f = unsafe { bio::BIO_find_type(b, BIO_TYPE_SSL) };
    // SAFETY: null or a live BIO.
    unsafe { object(f) }.map_or(ptr::null_mut(), ssl_of)
}

ffi_export! {
    /// Copies the session of `f`'s SSL BIO to `t`'s: 1, or 0.
    ///
    /// # Safety
    /// `t` and `f` are NULL or live BIO chains.
    pub unsafe extern "C" fn rustyssl_private_BIO_ssl_copy_session_id(t: *mut BIO, f: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let to = unsafe { find_ssl(t) };
        // SAFETY: as above.
        let from = unsafe { find_ssl(f) };
        if to.is_null() || from.is_null() {
            return 0;
        }
        // SAFETY: two live connections.
        c_int::from(unsafe { rustyssl_private_SSL_copy_session_id(to, from) } != 0)
    }
}

ffi_export! {
    /// Shuts down the connection of every SSL BIO in the chain.
    ///
    /// # Safety
    /// `b` is NULL or a live BIO chain.
    pub unsafe extern "C" fn rustyssl_private_BIO_ssl_shutdown(b: *mut BIO)
    where failure = (), library = ERR_LIB_SSL
    {
        let mut b = b;
        while !b.is_null() {
            // SAFETY: a live BIO of the chain.
            if unsafe { bio::BIO_method_type(b) } == BIO_TYPE_SSL {
                // SAFETY: as above.
                let s = unsafe { object(b) }.map_or(ptr::null_mut(), ssl_of);
                if !s.is_null() {
                    // SAFETY: the BIO's live connection.
                    unsafe { rustyssl_private_SSL_shutdown(s) };
                }
            }
            // SAFETY: as above.
            b = unsafe { bio::BIO_next(b) };
        }
    }
}

ffi_export! {
    /// The read BIO's poll descriptor (a TLS connection's; QUIC isn't built).
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `desc` is valid for a write.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_rpoll_descriptor(s: *mut SSL, desc: *mut BIO_POLL_DESCRIPTOR) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let r = unsafe { rustyssl_private_SSL_get_rbio(s) };
        if r.is_null() {
            return 0;
        }
        // SAFETY: the connection's live read BIO; the caller's descriptor.
        unsafe { bio::BIO_get_rpoll_descriptor(r, desc) }
    }
}

ffi_export! {
    /// The write BIO's poll descriptor.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `desc` is valid for a write.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_wpoll_descriptor(s: *mut SSL, desc: *mut BIO_POLL_DESCRIPTOR) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let w = unsafe { rustyssl_private_SSL_get_wbio(s) };
        if w.is_null() {
            return 0;
        }
        // SAFETY: the connection's live write BIO; the caller's descriptor.
        unsafe { bio::BIO_get_wpoll_descriptor(w, desc) }
    }
}
