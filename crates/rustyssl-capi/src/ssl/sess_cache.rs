//! The session cache (OpenSSL's `ssl_sess.c`), a connection's session (`SSL_get_session`,
//! `SSL_set_session`, ...), and what the driver does with the core's session events
//! (`ssl_get_prev_session`'s lookup, `ssl_update_cache`, the removals).
//!
//! A context's cache is OpenSSL's: an `LHASH_OF(SSL_SESSION)` keyed by the protocol version
//! and the session ID (`SSL_CTX_sessions` hands it out), and a list in expiry order (latest
//! first), from whose tail sessions are evicted and flushed. The cache holds one reference to
//! each session it has. One mutex stands for the context's lock; it is never held while the
//! application's callbacks run (security rule 7), so the removal callbacks run just after
//! the lock is released rather than under it, and no session's own lock is held while the
//! table runs its hash and compare functions (which lock the sessions they look at).
//!
//! A connection keeps its session in [`Slot`]. The core keeps its own copy of the
//! negotiated session ([`rustyssl_tls::conn::Session`]); after a handshake (and each TLS 1.3
//! ticket) the driver turns it into an `SSL_SESSION` with the peer's certificates, as OpenSSL's
//! connection fills its `s->session` while the handshake runs.

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};
use std::ffi::CString;
use std::sync::{Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    ERR_LIB_SSL, OPENSSL_LHASH, SSL, SSL_CTRL_SESS_ACCEPT, SSL_CTRL_SESS_ACCEPT_GOOD,
    SSL_CTRL_SESS_ACCEPT_RENEGOTIATE, SSL_CTRL_SESS_CACHE_FULL, SSL_CTRL_SESS_CB_HIT,
    SSL_CTRL_SESS_CONNECT, SSL_CTRL_SESS_CONNECT_GOOD, SSL_CTRL_SESS_CONNECT_RENEGOTIATE,
    SSL_CTRL_SESS_HIT, SSL_CTRL_SESS_MISSES, SSL_CTRL_SESS_NUMBER, SSL_CTRL_SESS_TIMEOUTS, SSL_CTX,
    SSL_OP_NO_ANTI_REPLAY, SSL_OP_NO_TICKET, SSL_SENT_SHUTDOWN, SSL_SESS_CACHE_CLIENT,
    SSL_SESS_CACHE_NO_AUTO_CLEAR, SSL_SESS_CACHE_NO_INTERNAL_LOOKUP,
    SSL_SESS_CACHE_NO_INTERNAL_STORE, SSL_SESS_CACHE_SERVER, SSL_SESS_CACHE_UPDATE_TIME,
    SSL_SESSION, SSL_VERIFY_PEER, TLS1_3_VERSION,
};
use rustyssl_tls::conn::{Answer, Session};

use super::conn::{Ssl, SslState, ssl};
use super::ctx::{self, Ctx};
use super::session::{
    self, SESS_FLAG_EXTMS, SessData, from_time_t, max_id, sess, time_now, to_time_t, with,
};
use crate::evp::pkey::EVP_PKEY_up_ref;
use crate::ffi::ffi_export;
use crate::lhash::{
    OPENSSL_LH_delete, OPENSSL_LH_free, OPENSSL_LH_get_down_load, OPENSSL_LH_insert,
    OPENSSL_LH_new, OPENSSL_LH_num_items, OPENSSL_LH_retrieve, OPENSSL_LH_set_down_load,
};
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_value};
use crate::x509::cert::{X509_chain_up_ref, X509_up_ref, i2d_X509};

/// The cache's statistics (`ctx->stats`), counted as OpenSSL counts them.
#[derive(Debug, Default)]
pub(crate) struct Stats {
    pub(crate) connect: AtomicI32,
    pub(crate) connect_renegotiate: AtomicI32,
    pub(crate) connect_good: AtomicI32,
    pub(crate) accept: AtomicI32,
    pub(crate) accept_renegotiate: AtomicI32,
    pub(crate) accept_good: AtomicI32,
    pub(crate) miss: AtomicI32,
    pub(crate) timeout: AtomicI32,
    pub(crate) cache_full: AtomicI32,
    pub(crate) hit: AtomicI32,
    pub(crate) cb_hit: AtomicI32,
}

/// Counts one (`ssl_tsan_counter`).
fn count(c: &AtomicI32) {
    c.fetch_add(1, Ordering::Relaxed);
}

/// A context's session cache.
#[derive(Debug)]
pub(crate) struct Cache {
    /// The table (owned; it holds no references of its own: the list's are the cache's).
    lh: *mut OPENSSL_LHASH,
    /// The sessions in expiry order, latest first, each with the cache's reference; locking
    /// it is taking `ctx->lock`.
    list: Mutex<Vec<*mut SSL_SESSION>>,
    pub(crate) stats: Stats,
}

// SAFETY: the table and the sessions are changed only under the list's lock (the table has its
// own lock for its readers).
unsafe impl Send for Cache {}
// SAFETY: as above.
unsafe impl Sync for Cache {}

impl Cache {
    /// An empty cache (its table made with OpenSSL's hash and compare functions).
    pub(crate) fn new() -> Self {
        Self {
            // SAFETY: our callbacks, which take sessions.
            lh: unsafe { OPENSSL_LH_new(Some(hash), Some(compare)) },
            list: Mutex::new(Vec::new()),
            stats: Stats::default(),
        }
    }

    /// The list, locked (`ctx->lock`).
    fn lock(&self) -> MutexGuard<'_, Vec<*mut SSL_SESSION>> {
        self.list.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `SSL_CTX_sess_number`.
    fn number(&self) -> usize {
        // SAFETY: our table, or NULL.
        let n = unsafe { OPENSSL_LH_num_items(self.lh) };
        usize::try_from(n).unwrap_or(usize::MAX)
    }
}

impl Drop for Cache {
    fn drop(&mut self) {
        // The context's last `SSL_CTX_free` flushed the cache; a context that never got that
        // far has none.
        let left = core::mem::take(self.list.get_mut().unwrap_or_else(PoisonError::into_inner));
        for s in left {
            // SAFETY: the cache's reference.
            unsafe { session::free(s) };
        }
        // SAFETY: our table.
        unsafe { OPENSSL_LH_free(self.lh) };
    }
}

/// `ssl_session_hash`: the session ID's first four octets (zero-padded), little-endian.
unsafe extern "C" fn hash(p: *const c_void) -> c_ulong {
    // SAFETY: the table holds only sessions (and our keys).
    unsafe {
        with(p.cast(), 0, |d| {
            let mut b = [0u8; 4];
            for (dst, src) in b.iter_mut().zip(d.id()) {
                *dst = *src;
            }
            c_ulong::from(u32::from_le_bytes(b))
        })
    }
}

/// `ssl_session_cmp`: equal (0) for the same version and session ID.
unsafe extern "C" fn compare(a: *const c_void, b: *const c_void) -> c_int {
    if a == b {
        return 0;
    }
    // SAFETY: the table holds only sessions (and our keys); `a`'s fields are copied out before
    // `b` is locked.
    let ka = unsafe { with(a.cast(), None, |d| Some((d.ssl_version, d.id().to_vec()))) };
    // SAFETY: as above.
    let kb = unsafe { with(b.cast(), None, |d| Some((d.ssl_version, d.id().to_vec()))) };
    match (ka, kb) {
        (Some((va, ia)), Some((vb, ib))) if va == vb && ia == ib => 0,
        _ => 1,
    }
}

/// `SSL_SESSION_list_remove`: out of the list, with no owner.
fn list_remove(l: &mut Vec<*mut SSL_SESSION>, s: *mut SSL_SESSION) {
    if let Some(i) = l.iter().position(|&e| e == s) {
        l.remove(i);
        // SAFETY: a session of the cache (the cache's reference keeps it).
        unsafe { with(s, (), |d| d.owner = ptr::null_mut()) };
    }
}

/// `SSL_SESSION_list_add`: into its place in the expiry order (before the first session that
/// expires no later), owned by `c`.
fn list_add(l: &mut Vec<*mut SSL_SESSION>, c: *mut SSL_CTX, s: *mut SSL_SESSION) {
    list_remove(l, s);
    // SAFETY: the session the caller holds.
    let at = unsafe { with(s, 0, |d| d.calc_timeout) };
    let i = l
        .iter()
        // SAFETY: the cache's sessions.
        .position(|&e| at >= unsafe { with(e, 0, |d| d.calc_timeout) })
        .unwrap_or(l.len());
    l.insert(i, s);
    // SAFETY: as above.
    unsafe { with(s, (), |d| d.owner = c) };
}

/// The context's removal callback.
fn remove_cb(x: &Ctx) -> super::types::SessRemoveCb {
    x.state().remove_session_cb
}

/// Runs `f` on a session's fields; for a session in a cache, under the cache's lock, and
/// moves it to its new place in the expiry order (`SSL_SESSION_set_timeout`,
/// `SSL_SESSION_set_time_ex`). The expiry time is recalculated.
///
/// # Safety
/// `s` is a live session.
pub(crate) unsafe fn retime(s: *mut SSL_SESSION, f: impl FnOnce(&mut SessData)) {
    // SAFETY: the caller's guarantee.
    let owner = unsafe { with(s, ptr::null_mut(), |d| d.owner) };
    // SAFETY: a session's owner is a live context (its cache, flushed before it goes, holds
    // the session).
    let Some(x) = (unsafe { ctx::ctx(owner) }) else {
        // SAFETY: as above.
        unsafe {
            with(s, (), |d| {
                f(d);
                d.calculate_timeout();
            });
        };
        return;
    };
    let mut l = x.cache.lock();
    // SAFETY: as above.
    unsafe {
        with(s, (), |d| {
            f(d);
            d.calculate_timeout();
        });
    };
    if l.contains(&s) {
        list_add(&mut l, owner, s);
    }
}

/// `SSL_CTX_add_session`: 1 if added, 0 if it was there already (or on failure).
///
/// # Safety
/// `c` is the live context behind `x`; `s` a live session.
unsafe fn add(c: *mut SSL_CTX, x: &Ctx, s: *mut SSL_SESSION) -> c_int {
    // SAFETY: the caller's guarantee; the cache's reference.
    if !unsafe { session::up_ref(s) } {
        return 0;
    }
    let (mode, size) = {
        let st = x.state();
        (st.session_cache_mode, st.session_cache_size)
    };
    let mut evicted = Vec::new();
    let mut release = Vec::new();
    let ret = {
        let mut l = x.cache.lock();
        // SAFETY: our table; the session.
        let old: *mut SSL_SESSION = unsafe { OPENSSL_LH_insert(x.cache.lh, s.cast()) }.cast();
        let fresh = if !old.is_null() && old != s {
            // Another session with the same ID: it leaves the cache.
            list_remove(&mut l, old);
            release.push(old);
            true
        } else {
            // SAFETY: as above.
            old.is_null() && !unsafe { OPENSSL_LH_retrieve(x.cache.lh, s.cast()) }.is_null()
        };
        if mode & SSL_SESS_CACHE_UPDATE_TIME.cast_unsigned() != 0 {
            // SAFETY: the session.
            unsafe {
                with(s, (), |d| {
                    d.time = time_now();
                    d.calculate_timeout();
                });
            };
        }
        if fresh {
            if size > 0 {
                while x.cache.number() >= size {
                    let Some(&tail) = l.last() else { break };
                    // SAFETY: the cache's session.
                    if unsafe { take_locked(x, &mut l, tail) }.is_none() {
                        break;
                    }
                    evicted.push(tail);
                    count(&x.cache.stats.cache_full);
                }
            }
            list_add(&mut l, c, s);
            1
        } else {
            // There already: the extra reference goes back.
            release.push(s);
            0
        }
    };
    let cb = remove_cb(x);
    for e in evicted {
        if let Some(cb) = cb {
            // SAFETY: the application's callback with its context and the session; no lock is
            // held.
            unsafe { cb(c, e) };
        }
        // SAFETY: the cache's reference.
        unsafe { session::free(e) };
    }
    for r in release {
        // SAFETY: as above.
        unsafe { session::free(r) };
    }
    ret
}

/// Takes the session equal to `s` out of the table and the list, under the cache's lock:
/// the cache's object (whose reference the caller now has), or `None`. `s` is marked not
/// resumable either way.
///
/// # Safety
/// `s` is a live session.
unsafe fn take_locked(
    x: &Ctx,
    l: &mut Vec<*mut SSL_SESSION>,
    s: *mut SSL_SESSION,
) -> Option<*mut SSL_SESSION> {
    // SAFETY: our table; the caller's session as the key.
    let r: *mut SSL_SESSION = unsafe { OPENSSL_LH_retrieve(x.cache.lh, s.cast()) }.cast();
    let found = (!r.is_null()).then(|| {
        // SAFETY: our table; its session.
        unsafe { OPENSSL_LH_delete(x.cache.lh, r.cast()) };
        list_remove(l, r);
        r
    });
    // SAFETY: the caller's guarantee.
    unsafe { with(s, (), |d| d.not_resumable = true) };
    found
}

/// `SSL_CTX_remove_session` (`remove_session_lock`): for a session with an ID, takes it out
/// of the cache, marks it not resumable, and calls the removal callback; 1 if it was there.
///
/// # Safety
/// `c` is NULL or a live context; `s` NULL or a live session.
pub(crate) unsafe fn remove(c: *mut SSL_CTX, s: *mut SSL_SESSION) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(x) = (unsafe { ctx::ctx(c) }) else {
        return 0;
    };
    // SAFETY: as above.
    if unsafe { with(s, 0, |d| d.session_id_length) } == 0 {
        return 0;
    }
    let r = {
        let mut l = x.cache.lock();
        // SAFETY: the caller's session.
        unsafe { take_locked(x, &mut l, s) }
    };
    if let Some(cb) = remove_cb(x) {
        // SAFETY: the application's callback with its context and the session; no lock held.
        unsafe { cb(c, s) };
    }
    match r {
        Some(r) => {
            // SAFETY: the cache's reference.
            unsafe { session::free(r) };
            1
        }
        None => 0,
    }
}

/// `SSL_CTX_flush_sessions_ex`: removes the sessions expired at `t` (all for 0), each marked
/// not resumable and given to the removal callback.
///
/// # Safety
/// `c` is the live context behind `x`.
pub(crate) unsafe fn flush(c: *mut SSL_CTX, x: &Ctx, t: i64) {
    let at = from_time_t(t);
    let gone = {
        let mut l = x.cache.lock();
        // SAFETY: our table.
        let down = unsafe { OPENSSL_LH_get_down_load(x.cache.lh) };
        // SAFETY: as above.
        unsafe { OPENSSL_LH_set_down_load(x.cache.lh, 0) };
        let mut gone = Vec::new();
        while let Some(&tail) = l.last() {
            // SAFETY: the cache's session.
            let expired = t == 0 || at > unsafe { with(tail, 0, |d| d.calc_timeout) };
            if !expired {
                break;
            }
            // SAFETY: our table; the cache's session.
            unsafe { OPENSSL_LH_delete(x.cache.lh, tail.cast()) };
            list_remove(&mut l, tail);
            // SAFETY: as above.
            unsafe { with(tail, (), |d| d.not_resumable = true) };
            gone.push(tail);
        }
        // SAFETY: as above.
        unsafe { OPENSSL_LH_set_down_load(x.cache.lh, down) };
        gone
    };
    if let Some(cb) = remove_cb(x) {
        for &s in &gone {
            // SAFETY: the application's callback with its context and the session; no lock
            // is held.
            unsafe { cb(c, s) };
        }
    }
    for s in gone {
        // SAFETY: the cache's reference.
        unsafe { session::free(s) };
    }
}

/// The cache statistics' ctrl commands (`SSL_CTX_sess_number` ...), or `None` for another
/// command.
pub(crate) fn stat_ctrl(x: &Ctx, cmd: c_int) -> Option<c_long> {
    let s = &x.cache.stats;
    let v = match cmd {
        SSL_CTRL_SESS_NUMBER => return Some(ctx::as_long(x.cache.number())),
        SSL_CTRL_SESS_CONNECT => &s.connect,
        SSL_CTRL_SESS_CONNECT_GOOD => &s.connect_good,
        SSL_CTRL_SESS_CONNECT_RENEGOTIATE => &s.connect_renegotiate,
        SSL_CTRL_SESS_ACCEPT => &s.accept,
        SSL_CTRL_SESS_ACCEPT_GOOD => &s.accept_good,
        SSL_CTRL_SESS_ACCEPT_RENEGOTIATE => &s.accept_renegotiate,
        SSL_CTRL_SESS_HIT => &s.hit,
        SSL_CTRL_SESS_CB_HIT => &s.cb_hit,
        SSL_CTRL_SESS_MISSES => &s.miss,
        SSL_CTRL_SESS_TIMEOUTS => &s.timeout,
        SSL_CTRL_SESS_CACHE_FULL => &s.cache_full,
        _ => return None,
    };
    Some(c_long::from(v.load(Ordering::Relaxed)))
}

ffi_export! {
    /// Adds the session to the context's cache (evicting the oldest when full): 1 if added, 0
    /// if it was there already or for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `session` NULL or a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_add_session(ctx: *mut SSL_CTX, session: *mut SSL_SESSION) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ctx::ctx(ctx) }) else { return 0 };
        // SAFETY: as above.
        if unsafe { sess(session) }.is_none() {
            return 0;
        }
        // SAFETY: as above.
        unsafe { add(ctx, x, session) }
    }
}

ffi_export! {
    /// Removes the session from the context's cache, marking it not resumable: 1 if it was
    /// there.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `session` NULL or a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_remove_session(ctx: *mut SSL_CTX, session: *mut SSL_SESSION) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { remove(ctx, session) }
    }
}

ffi_export! {
    /// Removes the sessions expired at time `tm` (seconds since the epoch; all for 0).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_flush_sessions_ex(ctx: *mut SSL_CTX, tm: libc::time_t)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if let Some(x) = unsafe { ctx::ctx(ctx) } {
            // SAFETY: as above.
            unsafe { flush(ctx, x, tm) };
        }
    }
}

ffi_export! {
    /// `SSL_CTX_flush_sessions_ex` with a `long` time (deprecated in 3.4).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_flush_sessions(ctx: *mut SSL_CTX, tm: c_long)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if let Some(x) = unsafe { ctx::ctx(ctx) } {
            // SAFETY: as above.
            unsafe { flush(ctx, x, tm) };
        }
    }
}

ffi_export! {
    /// The context's session table (`LHASH_OF(SSL_SESSION)`), or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_sessions(ctx: *mut SSL_CTX) -> *mut rustyssl_abi::lhash_st_SSL_SESSION
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx::ctx(ctx) }.map_or(ptr::null_mut(), |x| x.cache.lh.cast())
    }
}

/// A connection's session (`s->session`) and what the handshake found.
#[derive(Debug)]
pub(crate) struct Slot {
    /// The session (a reference held), or NULL.
    pub(crate) session: *mut SSL_SESSION,
    /// A server's cache lookup (a reference held), adopted if the handshake resumes it.
    found: *mut SSL_SESSION,
    /// Whether `session` is this handshake's (it's made when the handshake has settled it).
    current: bool,
    /// Whether a handshake started whose end isn't counted yet.
    finishing: bool,
}

impl Default for Slot {
    fn default() -> Self {
        Self {
            session: ptr::null_mut(),
            found: ptr::null_mut(),
            current: true,
            finishing: false,
        }
    }
}

impl Slot {
    /// Takes the sessions out, to be freed with no lock held.
    fn take(&mut self) -> [*mut SSL_SESSION; 2] {
        [
            core::mem::replace(&mut self.session, ptr::null_mut()),
            core::mem::replace(&mut self.found, ptr::null_mut()),
        ]
    }
}

/// Frees sessions (each NULL or a reference given up); no lock may be held.
///
/// # Safety
/// As for `SSL_SESSION_free` on each.
unsafe fn free_all(list: impl IntoIterator<Item = *mut SSL_SESSION>) {
    for s in list {
        // SAFETY: the caller's guarantee.
        unsafe { session::free(s) };
    }
}

/// `ssl_clear_bad_session`'s test: a session of a connection that's past its handshake but
/// didn't send close_notify is bad.
fn is_bad(st: &SslState) -> bool {
    !st.sess.session.is_null()
        && st.shutdown & SSL_SENT_SHUTDOWN == 0
        && !(st.in_init || st.flow_uninited)
}

/// `ssl_clear_bad_session`: removes a bad session from the cache; whether it was bad.
///
/// # Safety
/// `x` is a live connection; no lock is held.
unsafe fn clear_bad_session(x: &Ssl) -> bool {
    let (bad, c, s) = {
        let st = x.state();
        (is_bad(&st), st.session_ctx, st.sess.session)
    };
    if bad {
        // SAFETY: the connection's context and session (a reference, kept by the connection
        // while this runs: the application can't free its connection in its own call).
        unsafe { remove(c, s) };
    }
    bad
}

/// `SSL_free`'s part: a bad session leaves the cache, and the sessions are freed. Run as the
/// connection's state goes (no lock held: the state is being dropped).
pub(crate) fn on_free(st: &mut SslState) {
    if is_bad(st) {
        // SAFETY: the connection's context (its reference is still held) and session.
        unsafe { remove(st.session_ctx, st.sess.session) };
    }
    let list = st.sess.take();
    // SAFETY: the connection's references.
    unsafe { free_all(list) };
}

/// `SSL_clear`'s part (`ossl_ssl_connection_reset`): a bad session leaves the cache and the
/// connection; a good one stays for the next handshake to resume.
///
/// # Safety
/// `x` is a live connection; no lock is held.
pub(crate) unsafe fn on_clear(x: &Ssl) {
    // SAFETY: the caller's guarantee.
    let bad = unsafe { clear_bad_session(x) };
    let list = {
        let mut st = x.state();
        let found = core::mem::replace(&mut st.sess.found, ptr::null_mut());
        let s = if bad {
            core::mem::replace(&mut st.sess.session, ptr::null_mut())
        } else {
            ptr::null_mut()
        };
        st.sess.current = true;
        [s, found]
    };
    // SAFETY: the connection's references.
    unsafe { free_all(list) };
}

ffi_export! {
    /// The connection's session (no reference taken), or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_session(s: *const SSL) -> *mut SSL_SESSION
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ssl(s) }.map_or(ptr::null_mut(), |x| x.state().sess.session)
    }
}

ffi_export! {
    /// The connection's session with a reference for the caller, or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get1_session(s: *mut SSL) -> *mut SSL_SESSION
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return ptr::null_mut() };
        // Under the connection's lock, so the session can't go between reading and counting.
        let st = x.state();
        let p = st.sess.session;
        // SAFETY: the connection's session, or NULL.
        if p.is_null() || !unsafe { session::up_ref(p) } {
            return ptr::null_mut();
        }
        p
    }
}

/// `SSL_set_session`.
///
/// # Safety
/// `x` is a live connection; `session` NULL or a live session.
unsafe fn set_session(x: &Ssl, session: *mut SSL_SESSION) -> bool {
    // SAFETY: the caller's guarantee.
    if !session.is_null() && !unsafe { session::up_ref(session) } {
        return false;
    }
    // SAFETY: as above.
    unsafe { clear_bad_session(x) };
    // SAFETY: as above.
    let verify = unsafe { with(session, None, |d| Some(d.verify_result)) };
    let old = {
        let mut st = x.state();
        if !core::ptr::eq(st.method, st.defltmeth) {
            let m = st.defltmeth;
            let same_version = st.method.version == m.version;
            st.method = m;
            if !same_version {
                st.version = m.idle_version();
            }
        }
        if let Some(v) = verify {
            st.verify_result = v;
        }
        st.sess.current = true;
        core::mem::replace(&mut st.sess.session, session)
    };
    // SAFETY: the connection's old reference.
    unsafe { session::free(old) };
    true
}

ffi_export! {
    /// Sets the session to resume (a reference taken; NULL clears it): 1, or 0. The old one,
    /// if bad, leaves the cache; the method goes back to the connection's default.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `session` NULL or a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_session(s: *mut SSL, session: *mut SSL_SESSION) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        // SAFETY: as above.
        c_int::from(unsafe { set_session(x, session) })
    }
}

ffi_export! {
    /// Whether the connection's session cache has a session with this ID (for the
    /// connection's version): 1, or 0 (also for an ID longer than 32 octets).
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `id` points to `id_len` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_has_matching_session_id(s: *const SSL, id: *const c_uchar, id_len: c_uint) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let Ok(n) = usize::try_from(id_len) else { return 0 };
        if n > max_id() || (id.is_null() && n > 0) {
            return 0;
        }
        let ids = if n == 0 {
            &[][..]
        } else {
            // SAFETY: the caller's `id_len` octets.
            unsafe { core::slice::from_raw_parts(id, n) }
        };
        let (c, version) = {
            let st = x.state();
            (st.session_ctx, live_version(&st))
        };
        // SAFETY: the connection's context.
        let Some(cx) = (unsafe { ctx::ctx(c) }) else { return 0 };
        c_int::from(!lookup_internal(cx, version, ids, false).is_null())
    }
}

/// The cache's session for (`version`, `id`), or NULL; with a reference for the caller if
/// `take_ref`.
fn lookup_internal(x: &Ctx, version: c_int, id: &[u8], take_ref: bool) -> *mut SSL_SESSION {
    let key = session::key_session(version, id);
    if key.is_null() {
        return ptr::null_mut();
    }
    let r = {
        let _l = x.cache.lock();
        // SAFETY: our table; the key.
        let r: *mut SSL_SESSION = unsafe { OPENSSL_LH_retrieve(x.cache.lh, key.cast()) }.cast();
        // SAFETY: the cache's session, kept by the lock while it's counted.
        if take_ref && !r.is_null() && !unsafe { session::up_ref(r) } {
            ptr::null_mut()
        } else {
            r
        }
    };
    // SAFETY: our key.
    unsafe { session::free_key(key) };
    r
}

ffi_export! {
    /// Makes `t` use `f`'s session, method, certificates, and session ID context: 1, or 0.
    /// (The certificates are copied rather than shared: a later change to one connection's
    /// isn't seen by the other.)
    ///
    /// # Safety
    /// `t` and `f` are NULL or live connections.
    pub unsafe extern "C" fn rustyssl_private_SSL_copy_session_id(t: *mut SSL, f: *const SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let (Some(tx), Some(fx)) = (unsafe { ssl(t) }, unsafe { ssl(f) }) else { return 0 };
        let fs = fx.state().sess.session;
        // SAFETY: `f`'s session, which `f` keeps while this runs.
        if !unsafe { set_session(tx, fs) } {
            return 0;
        }
        let (method, cert, sid_ctx) = {
            let st = fx.state();
            (st.method, st.cert.dup(), st.sid_ctx.clone())
        };
        let Some(cert) = cert else { return 0 };
        let old = {
            let mut st = tx.state();
            if !core::ptr::eq(st.method, method) {
                st.method = method;
            }
            st.sid_ctx = sid_ctx;
            core::mem::replace(&mut st.cert, cert)
        };
        drop(old);
        1
    }
}

ffi_export! {
    /// The PSK identity of the connection's session, or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_psk_identity(s: *const SSL) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return ptr::null() };
        let p = x.state().sess.session;
        // SAFETY: the connection's session; the string stays until a setter replaces it.
        unsafe { with(p, ptr::null(), |d| d.psk_identity.as_ref().map_or(ptr::null(), |c| c.as_ptr())) }
    }
}

ffi_export! {
    /// The PSK identity hint of the connection's session, or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_psk_identity_hint(s: *const SSL) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return ptr::null() };
        let p = x.state().sess.session;
        // SAFETY: as above.
        unsafe { with(p, ptr::null(), |d| d.psk_identity_hint.as_ref().map_or(ptr::null(), |c| c.as_ptr())) }
    }
}

/// The session for the core to resume (a client's `SSL_set_session`), if it's resumable.
pub(crate) fn offer(st: &SslState) -> Option<Session> {
    if st.server {
        return None;
    }
    // SAFETY: the connection's session, or NULL.
    unsafe {
        with(st.sess.session, None, |d| {
            d.is_resumable().then(|| to_core(d))
        })
    }
}

/// The DER of a certificate.
fn der_of(x: *mut rustyssl_abi::X509) -> Option<Vec<u8>> {
    let mut out: *mut c_uchar = ptr::null_mut();
    // SAFETY: a live certificate; our slot for its encoding.
    let n = unsafe { i2d_X509(x, &raw mut out) };
    let len = usize::try_from(n)
        .ok()
        .filter(|&n| n > 0 && !out.is_null())?;
    // SAFETY: the encoding's `n` octets.
    let v = unsafe { core::slice::from_raw_parts(out, len) }.to_vec();
    // SAFETY: the encoding, allocated by `i2d_X509`.
    unsafe { crate::mem::release(out.cast()) };
    Some(v)
}

/// A key's SubjectPublicKeyInfo DER, or `None` for NULL.
///
/// # Safety
/// `k` is NULL or a live key.
unsafe fn spki_der(k: *mut rustyssl_abi::EVP_PKEY) -> Option<Vec<u8>> {
    if k.is_null() {
        return None;
    }
    let mut out: *mut c_uchar = ptr::null_mut();
    // SAFETY: the caller's key; our slot for its encoding.
    let n = unsafe { crate::x509::pubkey::i2d_PUBKEY(k, &raw mut out) };
    let len = usize::try_from(n)
        .ok()
        .filter(|&n| n > 0 && !out.is_null())?;
    // SAFETY: the encoding's `n` octets.
    let v = unsafe { core::slice::from_raw_parts(out, len) }.to_vec();
    // SAFETY: the encoding, allocated by `i2d_PUBKEY`.
    unsafe { crate::mem::release(out.cast()) };
    Some(v)
}

/// A key decoded from its SubjectPublicKeyInfo DER in the connection's context's library
/// context (`tls_process_rpk`), or NULL.
fn spki_key(st: &SslState, der: &[u8]) -> *mut rustyssl_abi::EVP_PKEY {
    let Ok(len) = c_long::try_from(der.len()) else {
        return ptr::null_mut();
    };
    let mut p = der.as_ptr();
    // SAFETY: the connection's live context, or NULL.
    let (libctx, propq) = unsafe { ctx::ctx(st.ctx.cast_const()) }
        .map_or((ptr::null_mut(), ptr::null()), |c| {
            (c.libctx, c.propq_ptr())
        });
    // SAFETY: the key's octets (decoding runs no callbacks); the library context and
    // properties.
    unsafe { crate::x509::pubkey::d2i_PUBKEY_ex(ptr::null_mut(), &raw mut p, len, libctx, propq) }
}

/// A session's fields as the core's session.
fn to_core(d: &SessData) -> Session {
    let mut chain = Vec::new();
    if !d.peer.is_null()
        && let Some(v) = der_of(d.peer)
    {
        chain.push(v);
    }
    if !d.peer_chain.is_null() {
        // SAFETY: the session's stack.
        let n = unsafe { OPENSSL_sk_num(d.peer_chain.cast()) };
        for i in 0..n.max(0) {
            // SAFETY: an index in range.
            let c: *mut rustyssl_abi::X509 =
                unsafe { OPENSSL_sk_value(d.peer_chain.cast(), i) }.cast();
            if c.is_null() || c == d.peer {
                continue;
            }
            if let Some(v) = der_of(c) {
                chain.push(v);
            }
        }
    }
    Session {
        version: u16::try_from(d.ssl_version).unwrap_or(0),
        cipher_id: d.cipher_id(),
        session_id: d.id().to_vec(),
        sid_ctx: d.sid_ctx().to_vec(),
        master_key: d.master_key().to_vec(),
        ems: d.flags & SESS_FLAG_EXTMS != 0,
        ticket: d.tick.as_ref().map(|t| t.to_vec()),
        ticket_age_add: d.tick_age_add,
        ticket_lifetime_hint: d.tick_lifetime_hint,
        time: to_time_t(d.time),
        timeout: to_time_t(d.timeout),
        max_early_data: d.max_early_data,
        hostname: d.hostname.as_ref().map(|h| h.as_bytes().to_vec()),
        alpn: d.alpn_selected.as_ref().map(|a| a.to_vec()),
        peer_chain: chain,
        // SAFETY: the session's key, or NULL.
        peer_rpk: unsafe { spki_der(d.peer_rpk) },
        verify_result: d.verify_result,
        max_fragment_len_mode: d.max_fragment_len_mode,
        ext_flags: d.ext_flags,
        ticket_appdata: d.ticket_appdata.as_ref().map(|a| a.to_vec()),
    }
}

/// A new session object (one reference) from a core session, for a callback; NULL on failure.
///
/// # Safety
/// `x` is a live connection; no lock is held.
pub(crate) unsafe fn session_from_core(x: &Ssl, c: &Session) -> *mut SSL_SESSION {
    let d = {
        let st = x.state();
        from_core(&st, c, None, super::method::DEFAULT_TIMEOUT)
    };
    session::new_session(d)
}

/// A session's fields from the core's session, the connection's peer certificates, and the
/// negotiated group. The peer's references are taken here (under the connection's lock: no
/// callbacks run).
fn from_core(st: &SslState, c: &Session, group: Option<u16>, timeout: c_long) -> SessData {
    let mut d = SessData::new();
    d.ssl_version = c_int::from(c.version);
    d.cipher_id = c.cipher_id;
    d.cipher = rustyssl_tls::suites::by_id(c.cipher_id);
    let _ = d.set_id(
        c.session_id
            .get(..c.session_id.len().min(max_id()))
            .unwrap_or_default(),
    );
    let _ = d.set_sid_ctx(&c.sid_ctx);
    let _ = d.set_master_key(&c.master_key);
    if c.ems {
        d.flags |= SESS_FLAG_EXTMS;
    }
    d.tick = c.ticket.as_ref().map(|t| t.clone().into_boxed_slice());
    d.tick_age_add = c.ticket_age_add;
    d.tick_lifetime_hint = c.ticket_lifetime_hint;
    if c.time != 0 {
        d.time = from_time_t(c.time);
    }
    d.timeout = from_time_t(if c.timeout != 0 { c.timeout } else { timeout });
    d.calculate_timeout();
    d.max_early_data = c.max_early_data;
    d.hostname = c
        .hostname
        .as_ref()
        .and_then(|h| CString::new(h.clone()).ok());
    d.alpn_selected = c.alpn.as_ref().map(|a| a.clone().into_boxed_slice());
    d.verify_result = c_long::try_from(c.verify_result).unwrap_or(c_long::MAX);
    d.max_fragment_len_mode = c.max_fragment_len_mode;
    d.ext_flags = c.ext_flags;
    d.ticket_appdata = c
        .ticket_appdata
        .as_ref()
        .map(|a| a.clone().into_boxed_slice());
    d.kex_group = group.map_or(0, u32::from);
    if let Some(k) = &c.peer_rpk {
        d.peer_rpk = spki_key(st, k);
    }
    let p = &st.drv.peer;
    if p.from > 0 {
        if p.accepted {
            // SAFETY: the connection's stack, or NULL.
            let n = unsafe { OPENSSL_sk_num(p.chain.cast()) };
            if n > 0 {
                // SAFETY: an index in range.
                let leaf: *mut rustyssl_abi::X509 =
                    unsafe { OPENSSL_sk_value(p.chain.cast(), 0) }.cast();
                // SAFETY: the connection's certificate.
                if !leaf.is_null() && unsafe { X509_up_ref(leaf) } != 0 {
                    d.peer = leaf;
                }
            }
        }
        if !p.chain_no_leaf.is_null() {
            // SAFETY: the connection's stack.
            d.peer_chain = unsafe { X509_chain_up_ref(p.chain_no_leaf) };
        }
    } else if st.hit != 0 {
        // A resumed handshake sends no certificate: a session made from it (a TLS 1.3 ticket's)
        // keeps the resumed session's peer (`ssl_session_dup`).
        // SAFETY: the connection's session, or NULL.
        let (peer, chain, rpk) = unsafe {
            with(
                st.sess.session,
                (ptr::null_mut(), ptr::null_mut(), ptr::null_mut()),
                |o| (o.peer, o.peer_chain, o.peer_rpk),
            )
        };
        // SAFETY: the session's key, or NULL.
        if d.peer_rpk.is_null() && !rpk.is_null() && unsafe { EVP_PKEY_up_ref(rpk) } != 0 {
            d.peer_rpk = rpk;
        }
        // SAFETY: the session's certificate, or NULL.
        if !peer.is_null() && unsafe { X509_up_ref(peer) } != 0 {
            d.peer = peer;
        }
        if !chain.is_null() {
            // SAFETY: the session's stack.
            d.peer_chain = unsafe { X509_chain_up_ref(chain) };
        }
    }
    d
}

/// The connection's protocol version: the handshake's once it's negotiated (the mirror
/// follows only with the cipher).
fn live_version(st: &SslState) -> c_int {
    match st.drv.tls.as_ref().map(|c| c.negotiated().version) {
        Some(v) if v != 0 => c_int::from(v),
        _ => st.version,
    }
}

/// Whether two IDs are the same session's.
fn same_id(s: *mut SSL_SESSION, id: &[u8]) -> bool {
    // SAFETY: a connection's session, or NULL.
    unsafe { with(s, false, |d| d.id() == id) }
}

/// Settles the connection's session after the handshake (or a TLS 1.3 ticket, `ticket`):
/// keeps a resumed one, else makes one from the core's.
///
/// # Safety
/// `x` is a live connection; no lock is held.
unsafe fn settle(x: &Ssl, ticket: bool) {
    // `ssl_get_new_session`'s timeout: the session context's, or the method's.
    let sctx = x.state().session_ctx;
    // SAFETY: the connection's context.
    let ctx_timeout = unsafe { ctx::ctx(sctx) }.map_or(0, |c| c.state().session_timeout);
    let timeout = if ctx_timeout == 0 {
        super::method::DEFAULT_TIMEOUT
    } else {
        ctx_timeout
    };
    let made = {
        let mut st = x.state();
        let Some((neg_session, reused, version, group)) = st.drv.tls.as_ref().map(|c| {
            let n = c.negotiated();
            (n.session.clone(), n.reused, n.version, n.group)
        }) else {
            return;
        };
        let tls13 = c_int::from(version) == TLS1_3_VERSION;
        if !(ticket && tls13) {
            if st.sess.current {
                return;
            }
            if reused {
                if st.server {
                    let found = st.sess.found;
                    if !found.is_null() && same_id(found, &neg_session.session_id) {
                        st.sess.found = ptr::null_mut();
                        let old = core::mem::replace(&mut st.sess.session, found);
                        st.sess.current = true;
                        drop(st);
                        // SAFETY: the connection's old reference.
                        unsafe { session::free(old) };
                        return;
                    }
                } else if !st.sess.session.is_null() {
                    st.sess.current = true;
                    return;
                }
            }
        }
        st.sess.current = true;
        from_core(&st, &neg_session, group, timeout)
    };
    // Made with no lock held (the ex_data callbacks run).
    let s = session::new_session(made);
    if s.is_null() {
        return;
    }
    let old = core::mem::replace(&mut x.state().sess.session, s);
    // SAFETY: the connection's old reference.
    unsafe { session::free(old) };
}

/// `ssl_update_cache(s, mode)`.
///
/// # Safety
/// `s` is the live connection behind `x`; no lock is held.
unsafe fn update_cache(s: *mut SSL, x: &Ssl, mode: u32) {
    let (c, sp, server, verify_mode, hit, tls13, options, max_early_data) = {
        let st = x.state();
        let (hit, tls13) = st
            .drv
            .tls
            .as_ref()
            .map_or((false, false), |c| (c.negotiated().reused, c.is_tls13()));
        (
            st.session_ctx,
            st.sess.session,
            st.server,
            st.verify_mode,
            hit,
            tls13,
            st.options,
            st.max_early_data,
        )
    };
    // SAFETY: the connection's context.
    let Some(cx) = (unsafe { ctx::ctx(c) }) else {
        return;
    };
    // SAFETY: the connection's session, or NULL.
    let (id_len, not_resumable, sid_ctx_len) = unsafe {
        with(sp, (0, true, 0), |d| {
            (d.session_id_length, d.not_resumable, d.sid_ctx_length)
        })
    };
    if id_len == 0 || not_resumable {
        return;
    }
    if server && sid_ctx_len == 0 && verify_mode & SSL_VERIFY_PEER != 0 {
        return;
    }
    let (i, new_cb, rm_cb) = {
        let cs = cx.state();
        (
            cs.session_cache_mode,
            cs.new_session_cb,
            cs.remove_session_cb,
        )
    };
    if i & mode != 0 && (!hit || tls13) {
        if i & SSL_SESS_CACHE_NO_INTERNAL_STORE.cast_unsigned() == 0
            && (!tls13
                || !server
                || (max_early_data > 0 && options & SSL_OP_NO_ANTI_REPLAY == 0)
                || rm_cb.is_some()
                || options & SSL_OP_NO_TICKET != 0)
        {
            // SAFETY: the context and the connection's session.
            unsafe { add(c, cx, sp) };
        }
        if let Some(cb) = new_cb
            // SAFETY: as above; a reference for the callback.
            && unsafe { session::up_ref(sp) }
        {
            // SAFETY: the application's callback with its connection and the session; no
            // lock is held.
            if unsafe { cb(s, sp) } == 0 {
                // SAFETY: the callback didn't keep the reference.
                unsafe { session::free(sp) };
            }
        }
    }
    if i & SSL_SESS_CACHE_NO_AUTO_CLEAR.cast_unsigned() == 0 && i & mode == mode {
        let stat = if mode & SSL_SESS_CACHE_CLIENT.cast_unsigned() != 0 {
            &cx.cache.stats.connect_good
        } else {
            &cx.cache.stats.accept_good
        };
        if stat.load(Ordering::Relaxed) & 0xff == 0xff {
            let now = to_time_t(time_now());
            // SAFETY: the connection's context.
            unsafe { flush(c, cx, now) };
        }
    }
}

/// The connection's session context and context.
fn contexts(st: &SslState) -> (Option<&Ctx>, Option<&Ctx>) {
    // SAFETY: the connection holds a reference to each.
    let sc = unsafe { ctx::ctx(st.session_ctx) };
    // SAFETY: as above.
    let cc = unsafe { ctx::ctx(st.ctx) };
    (sc, cc)
}

/// The stats of a finished handshake (`tls_finish_handshake`): `connect_good` and a client's
/// `hit` on the session context, `accept_good` on the connection's context, and a server's
/// `hit` (OpenSSL counts it when the lookup succeeds).
fn count_finish(st: &mut SslState) {
    if !core::mem::replace(&mut st.sess.finishing, false) {
        return;
    }
    let hit = st.drv.tls.as_ref().is_some_and(|c| c.negotiated().reused);
    let (sc, cc) = contexts(st);
    if st.server {
        if hit && let Some(sc) = sc {
            count(&sc.cache.stats.hit);
        }
        if let Some(cc) = cc {
            count(&cc.cache.stats.accept_good);
        }
    } else if let Some(sc) = sc {
        if hit {
            count(&sc.cache.stats.hit);
        }
        count(&sc.cache.stats.connect_good);
    }
}

/// The core's `Event::UpdateCache`: after a TLS 1.2 handshake (`tls_finish_handshake`) or a
/// TLS 1.3 ticket (each a new session).
///
/// # Safety
/// `s` is the live connection behind `x`; no lock is held.
pub(crate) unsafe fn on_update_cache(s: *mut SSL, x: &Ssl, server: bool) {
    let tls13 = x.state().drv.tls.as_ref().is_some_and(|c| c.is_tls13());
    // SAFETY: the caller's guarantee.
    unsafe { settle(x, tls13) };
    let mode = if server {
        SSL_SESS_CACHE_SERVER
    } else {
        SSL_SESS_CACHE_CLIENT
    };
    // SAFETY: as above.
    unsafe { update_cache(s, x, mode.cast_unsigned()) };
    if !tls13 {
        count_finish(&mut x.state());
    }
}

/// The core's `Event::RemoveSession`: a TLS 1.3 client's handshake ended; its session leaves
/// a client cache (tickets are used once).
///
/// # Safety
/// `x` is a live connection; no lock is held.
pub(crate) unsafe fn on_remove_session(x: &Ssl) {
    // SAFETY: the caller's guarantee.
    unsafe { settle(x, false) };
    let (c, sp) = {
        let mut st = x.state();
        count_finish(&mut st);
        (st.session_ctx, st.sess.session)
    };
    // SAFETY: the connection's context.
    let mode = unsafe { ctx::ctx(c) }.map_or(0, |cx| cx.state().session_cache_mode);
    if mode & SSL_SESS_CACHE_CLIENT.cast_unsigned() != 0 {
        // SAFETY: the connection's context and session.
        unsafe { remove(c, sp) };
    }
}

/// The core's `Event::SessionRenewed`: the old session leaves a client cache (and can't be
/// resumed any more), and the connection's session is a new one with the new ticket.
///
/// # Safety
/// `x` is a live connection; no lock is held.
pub(crate) unsafe fn on_session_renewed(x: &Ssl) {
    let (c, sp, core) = {
        let st = x.state();
        let core = st.drv.tls.as_ref().map(|t| t.negotiated().session.clone());
        (st.session_ctx, st.sess.session, core)
    };
    // SAFETY: the connection's context.
    let mode = unsafe { ctx::ctx(c) }.map_or(0, |cx| cx.state().session_cache_mode);
    if mode & SSL_SESS_CACHE_CLIENT.cast_unsigned() != 0 && !sp.is_null() {
        // SAFETY: the connection's context and session.
        unsafe { remove(c, sp) };
    }
    let Some(core) = core else { return };
    // SAFETY: the caller's guarantee.
    let new = unsafe { session_from_core(x, &core) };
    if new.is_null() {
        return;
    }
    let old = core::mem::replace(&mut x.state().sess.session, new);
    // SAFETY: the connection's old reference.
    unsafe { session::free(old) };
}

/// A finished TLS 1.3 server handshake (no event of its own): the session is settled and
/// counted.
///
/// # Safety
/// `x` is a live connection; no lock is held.
pub(crate) unsafe fn on_finish_tls13_server(x: &Ssl) {
    // SAFETY: the caller's guarantee.
    unsafe { settle(x, false) };
    count_finish(&mut x.state());
}

/// A handshake's start (`tls_setup_handshake`): its session is yet to be settled, and the
/// connect or accept count (or the renegotiation count) goes up.
pub(crate) fn on_start(st: &mut SslState, first: bool) {
    st.sess.current = false;
    st.sess.finishing = true;
    let (sc, cc) = contexts(st);
    let stat = match (st.server, first) {
        (true, true) => sc.map(|c| &c.cache.stats.accept),
        (true, false) => cc.map(|c| &c.cache.stats.accept_renegotiate),
        (false, true) => sc.map(|c| &c.cache.stats.connect),
        (false, false) => sc.map(|c| &c.cache.stats.connect_renegotiate),
    };
    if let Some(s) = stat {
        count(s);
    }
}

/// A fatal error (an alert sent or received): the session leaves the cache.
///
/// # Safety
/// `x` is a live connection; no lock is held.
pub(crate) unsafe fn on_fatal(x: &Ssl) {
    let (c, sp) = {
        let st = x.state();
        (st.session_ctx, st.sess.session)
    };
    if !sp.is_null() {
        // SAFETY: the connection's context and session.
        unsafe { remove(c, sp) };
    }
}

/// The core's `Request::GetSession` (`lookup_sess_in_cache`): the internal cache, then the
/// application's lookup callback. The session found is kept for the handshake to adopt.
///
/// # Safety
/// `s` is the live connection behind `x`; no lock is held.
pub(crate) unsafe fn on_get_session(s: *mut SSL, x: &Ssl, id: &[u8]) -> Answer {
    let (c, version) = {
        let st = x.state();
        (st.session_ctx, live_version(&st))
    };
    // SAFETY: the connection's context.
    let Some(cx) = (unsafe { ctx::ctx(c) }) else {
        return Answer::Session(None);
    };
    if id.len() > max_id() {
        return Answer::Session(None);
    }
    let (mode, get_cb) = {
        let cs = cx.state();
        (cs.session_cache_mode, cs.get_session_cb)
    };
    let mut ret = ptr::null_mut();
    if mode & SSL_SESS_CACHE_NO_INTERNAL_LOOKUP.cast_unsigned() == 0 {
        ret = lookup_internal(cx, version, id, true);
        if ret.is_null() {
            count(&cx.cache.stats.miss);
        }
    }
    if ret.is_null()
        && let Some(cb) = get_cb
        && let Ok(n) = c_int::try_from(id.len())
    {
        let mut copy: c_int = 1;
        // SAFETY: the application's callback with its connection and the ID; no lock held.
        let r = unsafe { cb(s, id.as_ptr(), n, &raw mut copy) };
        // SAFETY: the callback's session, or NULL.
        let unusable = unsafe { with(r, true, |d| d.not_resumable) };
        if !r.is_null() && unusable {
            if copy == 0 {
                // SAFETY: the callback's reference.
                unsafe { session::free(r) };
            }
        } else if !r.is_null() {
            count(&cx.cache.stats.cb_hit);
            // SAFETY: as above.
            if copy == 0 || unsafe { session::up_ref(r) } {
                ret = r;
                if mode & SSL_SESS_CACHE_NO_INTERNAL_STORE.cast_unsigned() == 0 {
                    // SAFETY: the context and the session.
                    unsafe { add(c, cx, r) };
                }
            }
        }
    }
    if ret.is_null() {
        return Answer::Session(None);
    }
    // SAFETY: the session found (our reference).
    let core = unsafe { with(ret, None, |d| Some(to_core(d))) };
    let old = core::mem::replace(&mut x.state().sess.found, ret);
    // SAFETY: the connection's old reference.
    unsafe { session::free(old) };
    Answer::Session(core)
}

/// The core's `Request::RemoveSession` (a server's: a timed-out session from the cache, or
/// a TLS 1.3 single-use ticket's): whether it was in the cache.
///
/// # Safety
/// `x` is a live connection; no lock is held.
pub(crate) unsafe fn on_remove_request(x: &Ssl, id: &[u8]) -> Answer {
    let (c, version) = {
        let st = x.state();
        (st.session_ctx, live_version(&st))
    };
    // SAFETY: the connection's context.
    let Some(cx) = (unsafe { ctx::ctx(c) }) else {
        return Answer::Allowed(false);
    };
    if version != TLS1_3_VERSION {
        // `ssl_get_prev_session` removes a session only when it timed out.
        count(&cx.cache.stats.timeout);
    }
    let r = lookup_internal(cx, version, id, true);
    if r.is_null() {
        return Answer::Allowed(false);
    }
    // SAFETY: the context; the cache's session (our reference).
    let removed = unsafe { remove(c, r) } != 0;
    // SAFETY: our reference.
    unsafe { session::free(r) };
    Answer::Allowed(removed)
}
