//! `SSL_SESSION` (OpenSSL's `ssl_sess.c` and the session parts of `ssl_lib.c`): the object,
//! its getters and setters, copies, and the conversions to and from the core's
//! [`rustyssl_tls::conn::Session`].
//!
//! A session is shared by reference. Its fields live behind a mutex at a fixed address, so the
//! `get0` pointers (the session ID, the host name, the ticket...) stay valid until a setter
//! replaces what they point to, as in OpenSSL. Times are kept as OpenSSL keeps them
//! (`OSSL_TIME`: nanoseconds since the epoch).

use core::cell::UnsafeCell;
use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_uint, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};
use std::ffi::CString;
use std::sync::{Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    CRYPTO_EX_DATA, CRYPTO_EX_INDEX_SSL_SESSION, ERR_LIB_SSL, ERR_R_CRYPTO_LIB, EVP_PKEY,
    OPENSSL_INIT_LOAD_SSL_STRINGS, SSL_CIPHER, SSL_CTX, SSL_MAX_SID_CTX_LENGTH,
    SSL_MAX_SSL_SESSION_ID_LENGTH, SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG,
    SSL_R_SSL_SESSION_ID_TOO_LONG, SSL_SESSION, TLSEXT_max_fragment_length_DISABLED,
    TLSEXT_max_fragment_length_UNSPECIFIED, X509, stack_st_X509,
};
use rustyssl_tls::suites::Cipher;

use crate::err;
use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_up_ref};
use crate::ex_data::{
    CRYPTO_dup_ex_data, CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_new_ex_data,
    CRYPTO_set_ex_data,
};
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::x509::cert::{X509_free, X509_up_ref};

/// `TLS13_MAX_RESUMPTION_PSK_LENGTH` (`ssl_local.h`): the room for a master key or a TLS 1.3
/// resumption PSK.
pub(crate) const MAX_MASTER_KEY: usize = 512;
/// `SSL_SESS_FLAG_EXTMS` (`ssl_local.h`): the session used the Extended Master Secret.
pub(crate) const SESS_FLAG_EXTMS: u32 = 0x1;
/// `OSSL_TIME_SECOND`: an `OSSL_TIME` tick is a nanosecond.
pub(crate) const SECOND: u64 = 1_000_000_000;
/// `SSL_SESSION_new`'s timeout: 5 minutes and 4 seconds.
const DEFAULT_TIMEOUT_SECS: u64 = 60 * 5 + 4;

/// The session ID length limit as a `usize`.
pub(crate) fn max_id() -> usize {
    usize::try_from(SSL_MAX_SSL_SESSION_ID_LENGTH).unwrap_or(32)
}

/// The session ID context length limit as a `usize`.
pub(crate) fn max_sid_ctx() -> usize {
    usize::try_from(SSL_MAX_SID_CTX_LENGTH).unwrap_or(32)
}

/// `ossl_time_now`: now, in nanoseconds since the epoch (with OpenSSL's microsecond
/// precision).
pub(crate) fn time_now() -> u64 {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let us = u64::try_from(d.as_micros()).unwrap_or(u64::MAX);
    us.saturating_mul(1000)
}

/// `ossl_time_from_time_t`: seconds (a negative time is 0).
pub(crate) fn from_time_t(t: i64) -> u64 {
    u64::try_from(t).unwrap_or(0).saturating_mul(SECOND)
}

/// `ossl_time_to_time_t` (and `ossl_time2seconds`): whole seconds.
pub(crate) fn to_time_t(t: u64) -> i64 {
    i64::try_from(t / SECOND).unwrap_or(i64::MAX)
}

/// A session's fields (OpenSSL's `struct ssl_session_st`, with its field names).
#[derive(Debug)]
pub(crate) struct SessData {
    pub(crate) ssl_version: c_int,
    pub(crate) master_key: [u8; MAX_MASTER_KEY],
    pub(crate) master_key_length: usize,
    pub(crate) session_id: [u8; 32],
    pub(crate) session_id_length: usize,
    pub(crate) sid_ctx: [u8; 32],
    pub(crate) sid_ctx_length: usize,
    pub(crate) psk_identity_hint: Option<CString>,
    pub(crate) psk_identity: Option<CString>,
    pub(crate) not_resumable: bool,
    /// The peer's certificate (a reference held), or NULL.
    pub(crate) peer: *mut X509,
    /// The peer's chain (owned), or NULL.
    pub(crate) peer_chain: *mut stack_st_X509,
    /// The peer's raw public key (a reference held), or NULL.
    pub(crate) peer_rpk: *mut EVP_PKEY,
    pub(crate) verify_result: c_long,
    /// The timeout, in nanoseconds.
    pub(crate) timeout: u64,
    /// When the session was made (or its time last set), in nanoseconds since the epoch.
    pub(crate) time: u64,
    /// `time + timeout` (`calc_timeout`).
    pub(crate) calc_timeout: u64,
    pub(crate) compress_meth: c_uint,
    pub(crate) cipher: Option<&'static Cipher>,
    pub(crate) cipher_id: u32,
    pub(crate) kex_group: u32,
    pub(crate) flags: u32,
    pub(crate) hostname: Option<CString>,
    pub(crate) tick: Option<Box<[u8]>>,
    pub(crate) tick_lifetime_hint: u64,
    pub(crate) tick_age_add: u32,
    pub(crate) max_early_data: u32,
    pub(crate) alpn_selected: Option<Box<[u8]>>,
    pub(crate) max_fragment_len_mode: u8,
    pub(crate) srp_username: Option<CString>,
    pub(crate) ticket_appdata: Option<Box<[u8]>>,
    /// The core's TLS 1.3 key exchange modes (not in OpenSSL's encoding).
    pub(crate) ext_flags: u32,
    /// The context whose cache holds the session (`owner`), or NULL.
    pub(crate) owner: *mut SSL_CTX,
}

impl SessData {
    /// `SSL_SESSION_new`'s fields: a 304-second timeout from now, an unset verification
    /// result (1, never `X509_V_OK` by accident), the unspecified fragment length.
    pub(crate) fn new() -> Self {
        let mut d = Self {
            ssl_version: 0,
            master_key: [0; MAX_MASTER_KEY],
            master_key_length: 0,
            session_id: [0; 32],
            session_id_length: 0,
            sid_ctx: [0; 32],
            sid_ctx_length: 0,
            psk_identity_hint: None,
            psk_identity: None,
            not_resumable: false,
            peer: ptr::null_mut(),
            peer_chain: ptr::null_mut(),
            peer_rpk: ptr::null_mut(),
            verify_result: 1,
            timeout: DEFAULT_TIMEOUT_SECS.saturating_mul(SECOND),
            time: time_now(),
            calc_timeout: 0,
            compress_meth: 0,
            cipher: None,
            cipher_id: 0,
            kex_group: 0,
            flags: 0,
            hostname: None,
            tick: None,
            tick_lifetime_hint: 0,
            tick_age_add: 0,
            max_early_data: 0,
            alpn_selected: None,
            max_fragment_len_mode: u8::try_from(TLSEXT_max_fragment_length_UNSPECIFIED)
                .unwrap_or(u8::MAX),
            srp_username: None,
            ticket_appdata: None,
            ext_flags: 0,
            owner: ptr::null_mut(),
        };
        d.calculate_timeout();
        d
    }

    /// `ssl_session_calculate_timeout`.
    pub(crate) fn calculate_timeout(&mut self) {
        self.calc_timeout = self.time.saturating_add(self.timeout);
    }

    /// The session ID.
    pub(crate) fn id(&self) -> &[u8] {
        self.session_id
            .get(..self.session_id_length)
            .unwrap_or_default()
    }

    /// The session ID context.
    pub(crate) fn sid_ctx(&self) -> &[u8] {
        self.sid_ctx.get(..self.sid_ctx_length).unwrap_or_default()
    }

    /// The master key (or resumption PSK).
    pub(crate) fn master_key(&self) -> &[u8] {
        self.master_key
            .get(..self.master_key_length)
            .unwrap_or_default()
    }

    /// The cipher's id, from the cipher if one is set.
    pub(crate) fn cipher_id(&self) -> u32 {
        self.cipher.map_or(self.cipher_id, |c| c.id)
    }

    /// Sets the session ID (at most 32 octets).
    pub(crate) fn set_id(&mut self, id: &[u8]) -> bool {
        let Some(dst) = self.session_id.get_mut(..id.len()) else {
            return false;
        };
        dst.copy_from_slice(id);
        self.session_id_length = id.len();
        true
    }

    /// Sets the session ID context (at most 32 octets).
    pub(crate) fn set_sid_ctx(&mut self, v: &[u8]) -> bool {
        let Some(dst) = self.sid_ctx.get_mut(..v.len()) else {
            return false;
        };
        dst.copy_from_slice(v);
        self.sid_ctx_length = v.len();
        true
    }

    /// Sets the master key (at most [`MAX_MASTER_KEY`] octets).
    pub(crate) fn set_master_key(&mut self, v: &[u8]) -> bool {
        let Some(dst) = self.master_key.get_mut(..v.len()) else {
            return false;
        };
        dst.copy_from_slice(v);
        self.master_key_length = v.len();
        true
    }

    /// `SSL_SESSION_is_resumable`.
    pub(crate) fn is_resumable(&self) -> bool {
        !self.not_resumable
            && (self.session_id_length > 0 || self.tick.as_ref().is_some_and(|t| !t.is_empty()))
    }
}

impl Drop for SessData {
    fn drop(&mut self) {
        super::ctx::wipe(&mut self.master_key);
        super::ctx::wipe(&mut self.session_id);
        // SAFETY: our references and chain, each NULL or live.
        unsafe { X509_free(self.peer) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(self.peer_rpk) };
        // SAFETY: as above.
        unsafe { crate::x509::cert::OSSL_STACK_OF_X509_free(self.peer_chain) };
    }
}

/// A session (`SSL_SESSION`, shared by reference).
pub(crate) struct Sess {
    references: AtomicI32,
    /// The application's data, at a fixed address.
    ex_data: UnsafeCell<CRYPTO_EX_DATA>,
    data: Mutex<SessData>,
}

// SAFETY: the fields are behind the mutex; the application's data is set up as OpenSSL
// requires (its accessors take no lock).
unsafe impl Send for Sess {}
// SAFETY: as above.
unsafe impl Sync for Sess {}
// SAFETY: the raw pointers are owned references used under the session's lock.
unsafe impl Send for SessData {}

handle_type!(SSL_SESSION => Sess);

impl Sess {
    /// The fields, locked.
    pub(crate) fn data(&self) -> MutexGuard<'_, SessData> {
        self.data.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The application's data.
    pub(crate) fn ex_data(&self) -> *mut CRYPTO_EX_DATA {
        self.ex_data.get()
    }
}

/// The session behind `s`, or `None` for NULL.
///
/// # Safety
/// `s` is NULL or a live session.
pub(crate) unsafe fn sess<'a>(s: *const SSL_SESSION) -> Option<&'a Sess> {
    // SAFETY: the caller's guarantee.
    unsafe { SSL_SESSION::get(s) }
}

/// A new session with `data` and one reference (and its application data set up), or NULL.
pub(crate) fn new_session(data: SessData) -> *mut SSL_SESSION {
    let s = SSL_SESSION::new_handle(Sess {
        references: AtomicI32::new(1),
        // SAFETY: an all-zero `CRYPTO_EX_DATA` is the empty one `CRYPTO_new_ex_data` fills.
        ex_data: UnsafeCell::new(unsafe { core::mem::zeroed() }),
        data: Mutex::new(data),
    });
    // SAFETY: the new session.
    let Some(x) = (unsafe { sess(s) }) else {
        return ptr::null_mut();
    };
    // SAFETY: the new session and its own application data.
    if unsafe { CRYPTO_new_ex_data(CRYPTO_EX_INDEX_SSL_SESSION, s.cast(), x.ex_data()) } == 0 {
        // SAFETY: the new session's only reference.
        unsafe { SSL_SESSION::free(s) };
        return ptr::null_mut();
    }
    s
}

/// A lookup key for the cache (OpenSSL's on-stack `SSL_SESSION` with a version and an ID):
/// no application data, so no ex_data callbacks run; freed with [`free_key`].
pub(crate) fn key_session(ssl_version: c_int, id: &[u8]) -> *mut SSL_SESSION {
    let mut d = SessData::new();
    d.ssl_version = ssl_version;
    if !d.set_id(id) {
        return ptr::null_mut();
    }
    SSL_SESSION::new_handle(Sess {
        references: AtomicI32::new(1),
        // SAFETY: an all-zero `CRYPTO_EX_DATA` is an empty one, never handed out.
        ex_data: UnsafeCell::new(unsafe { core::mem::zeroed() }),
        data: Mutex::new(d),
    })
}

/// Frees a [`key_session`].
///
/// # Safety
/// `k` is NULL or a key from [`key_session`], no longer used.
pub(crate) unsafe fn free_key(k: *mut SSL_SESSION) {
    // SAFETY: the caller's guarantee (a key has no application data to free).
    unsafe { SSL_SESSION::free(k) };
}

/// A plain new session (`SSL_SESSION_new` without the library initialization).
pub(crate) fn blank() -> *mut SSL_SESSION {
    new_session(SessData::new())
}

ffi_export! {
    /// A new, empty session: a 304-second timeout from now; or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_new() -> *mut SSL_SESSION
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: no settings.
        if unsafe { super::rustyssl_private_OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS.cast_unsigned(), ptr::null()) } == 0 {
            return ptr::null_mut();
        }
        blank()
    }
}

ffi_export! {
    /// Adds a reference: 1 (0 for NULL).
    ///
    /// # Safety
    /// `ss` is NULL or a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_up_ref(ss: *mut SSL_SESSION) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { up_ref(ss) })
    }
}

/// Adds a reference to a session; false for NULL.
///
/// # Safety
/// `ss` is NULL or a live session.
pub(crate) unsafe fn up_ref(ss: *const SSL_SESSION) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(x) = (unsafe { sess(ss) }) else {
        return false;
    };
    x.references.fetch_add(1, Ordering::AcqRel);
    // SAFETY: as above.
    unsafe { SSL_SESSION::up_ref(ss) }
}

ffi_export! {
    /// Drops a reference; with the last, frees the application data and everything the session
    /// holds (its secrets wiped). Nothing for NULL.
    ///
    /// # Safety
    /// `ss` is NULL or a live session whose reference the caller gives up.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_free(ss: *mut SSL_SESSION)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { free(ss) };
    }
}

/// Drops a reference to a session (nothing for NULL); run with no lock held, as the last
/// reference runs the application's ex_data callbacks.
///
/// # Safety
/// `ss` is NULL or a live session whose reference the caller gives up.
pub(crate) unsafe fn free(ss: *mut SSL_SESSION) {
    // SAFETY: the caller's guarantee.
    let Some(held) = (unsafe { SSL_SESSION::hold(ss) }) else {
        return;
    };
    if held.references.fetch_sub(1, Ordering::AcqRel) == 1 {
        // SAFETY: the session's own application data; its last reference.
        unsafe { CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL_SESSION, ss.cast(), held.ex_data()) };
    }
    // SAFETY: the caller's reference; the hold keeps the session until this returns.
    unsafe { SSL_SESSION::free(ss) };
}

/// `ssl_session_dup_intern`: a copy with its own reference, not in any cache, sharing the
/// peer's certificates by reference; the ticket only if `ticket` (otherwise no ticket and no
/// lifetime hint). NULL on failure.
///
/// # Safety
/// `src` is a live session.
pub(crate) unsafe fn dup(src: *const SSL_SESSION, ticket: bool) -> *mut SSL_SESSION {
    // SAFETY: the caller's guarantee.
    let Some(s) = (unsafe { sess(src) }) else {
        return ptr::null_mut();
    };
    let copy = {
        let d = s.data();
        let mut n = SessData::new();
        n.ssl_version = d.ssl_version;
        n.master_key = d.master_key;
        n.master_key_length = d.master_key_length;
        n.session_id = d.session_id;
        n.session_id_length = d.session_id_length;
        n.sid_ctx = d.sid_ctx;
        n.sid_ctx_length = d.sid_ctx_length;
        n.psk_identity_hint.clone_from(&d.psk_identity_hint);
        n.psk_identity.clone_from(&d.psk_identity);
        n.not_resumable = d.not_resumable;
        n.verify_result = d.verify_result;
        n.timeout = d.timeout;
        n.time = d.time;
        n.calc_timeout = d.calc_timeout;
        n.compress_meth = d.compress_meth;
        n.cipher = d.cipher;
        n.cipher_id = d.cipher_id;
        n.kex_group = d.kex_group;
        n.flags = d.flags;
        n.hostname.clone_from(&d.hostname);
        if ticket {
            n.tick.clone_from(&d.tick);
            n.tick_lifetime_hint = d.tick_lifetime_hint;
        }
        n.tick_age_add = d.tick_age_add;
        n.max_early_data = d.max_early_data;
        n.alpn_selected.clone_from(&d.alpn_selected);
        n.max_fragment_len_mode = d.max_fragment_len_mode;
        n.srp_username.clone_from(&d.srp_username);
        n.ticket_appdata.clone_from(&d.ticket_appdata);
        n.ext_flags = d.ext_flags;
        if !d.peer.is_null() {
            // SAFETY: the original's certificate.
            if unsafe { X509_up_ref(d.peer) } == 0 {
                return ptr::null_mut();
            }
            n.peer = d.peer;
        }
        if !d.peer_chain.is_null() {
            // SAFETY: the original's chain.
            n.peer_chain = unsafe { crate::x509::cert::X509_chain_up_ref(d.peer_chain) };
            if n.peer_chain.is_null() {
                return ptr::null_mut();
            }
        }
        if !d.peer_rpk.is_null() {
            // SAFETY: the original's key.
            if unsafe { EVP_PKEY_up_ref(d.peer_rpk) } == 0 {
                return ptr::null_mut();
            }
            n.peer_rpk = d.peer_rpk;
        }
        n
    };
    let dest = new_session(copy);
    if dest.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the new session.
    let Some(dx) = (unsafe { sess(dest) }) else {
        return ptr::null_mut();
    };
    // SAFETY: both sessions' application data; no lock is held (the dup callbacks run).
    if unsafe { CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_SSL_SESSION, dx.ex_data(), s.ex_data()) } == 0 {
        err::raise(ERR_LIB_SSL, ERR_R_CRYPTO_LIB, "ssl_session_dup_intern");
        // SAFETY: the copy's only reference.
        unsafe { free(dest) };
        return ptr::null_mut();
    }
    dest
}

ffi_export! {
    /// A copy of the session (its ticket included), not in any cache; or NULL.
    ///
    /// # Safety
    /// `src` is a live session (as in OpenSSL, NULL is not allowed).
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_dup(src: *const SSL_SESSION) -> *mut SSL_SESSION
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { dup(src, true) }
    }
}

/// Runs `f` on the session's locked fields, or returns `default` for NULL.
///
/// # Safety
/// `s` is NULL or a live session.
pub(crate) unsafe fn with<R>(
    s: *const SSL_SESSION,
    default: R,
    f: impl FnOnce(&mut SessData) -> R,
) -> R {
    // SAFETY: the caller's guarantee.
    match unsafe { sess(s) } {
        Some(x) => f(&mut x.data()),
        None => default,
    }
}

ffi_export! {
    /// The session ID, with its length in `*len` (where `len` isn't NULL).
    ///
    /// # Safety
    /// `s` is a live session; `len` NULL or writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_get_id(s: *const SSL_SESSION, len: *mut c_uint) -> *const c_uchar
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        let f = |d: &mut SessData| {
            if !len.is_null() {
                // SAFETY: the caller's slot.
                unsafe { len.write(c_uint::try_from(d.session_id_length).unwrap_or(0)) };
            }
            d.session_id.as_ptr()
        };
        // SAFETY: the caller's guarantee.
        unsafe { with(s, ptr::null(), f) }
    }
}

ffi_export! {
    /// Sets the session ID (at most `SSL_MAX_SSL_SESSION_ID_LENGTH` octets): 1, or 0.
    ///
    /// # Safety
    /// `s` is a live session; `sid` points to `sid_len` octets (or `sid_len` is 0).
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_set1_id(s: *mut SSL_SESSION, sid: *const c_uchar, sid_len: c_uint) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        let n = usize::try_from(sid_len).unwrap_or(usize::MAX);
        if n > max_id() {
            err::raise(ERR_LIB_SSL, SSL_R_SSL_SESSION_ID_TOO_LONG, "SSL_SESSION_set1_id");
            return 0;
        }
        let v = if n == 0 || sid.is_null() {
            Vec::new()
        } else {
            // SAFETY: the caller's octets, copied before the session is locked (they may be
            // its own).
            unsafe { core::slice::from_raw_parts(sid, n) }.to_vec()
        };
        let f = |d: &mut SessData| {
            d.session_id_length = n;
            if let Some(dst) = d.session_id.get_mut(..v.len()) {
                dst.copy_from_slice(&v);
            }
            1
        };
        // SAFETY: the caller's guarantee.
        unsafe { with(s, 0, f) }
    }
}

ffi_export! {
    /// The session ID context, with its length in `*len` (where `len` isn't NULL).
    ///
    /// # Safety
    /// `s` is a live session; `len` NULL or writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_get0_id_context(s: *const SSL_SESSION, len: *mut c_uint) -> *const c_uchar
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        let f = |d: &mut SessData| {
            if !len.is_null() {
                // SAFETY: the caller's slot.
                unsafe { len.write(c_uint::try_from(d.sid_ctx_length).unwrap_or(0)) };
            }
            d.sid_ctx.as_ptr()
        };
        // SAFETY: the caller's guarantee.
        unsafe { with(s, ptr::null(), f) }
    }
}

ffi_export! {
    /// Sets the session ID context (at most `SSL_MAX_SID_CTX_LENGTH` octets): 1, or 0.
    ///
    /// # Safety
    /// `s` is a live session; `sid_ctx` points to `sid_ctx_len` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_set1_id_context(s: *mut SSL_SESSION, sid_ctx: *const c_uchar, sid_ctx_len: c_uint) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        let n = usize::try_from(sid_ctx_len).unwrap_or(usize::MAX);
        if n > max_sid_ctx() {
            err::raise(ERR_LIB_SSL, SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG, "SSL_SESSION_set1_id_context");
            return 0;
        }
        let v = if n == 0 || sid_ctx.is_null() {
            Vec::new()
        } else {
            // SAFETY: the caller's octets, copied first (they may be the session's own).
            unsafe { core::slice::from_raw_parts(sid_ctx, n) }.to_vec()
        };
        let f = |d: &mut SessData| {
            d.sid_ctx_length = n;
            if let Some(dst) = d.sid_ctx.get_mut(..v.len()) {
                dst.copy_from_slice(&v);
            }
            1
        };
        // SAFETY: the caller's guarantee.
        unsafe { with(s, 0, f) }
    }
}

ffi_export! {
    /// The compression method's id (always 0: the default build has none).
    ///
    /// # Safety
    /// `s` is a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_get_compress_id(s: *const SSL_SESSION) -> c_uint
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { with(s, 0, |d| d.compress_meth) }
    }
}

ffi_export! {
    /// Copies up to `outlen` octets of the master key (or TLS 1.3 resumption PSK) into `out`;
    /// returns how many, or its whole length for an `outlen` of 0.
    ///
    /// # Safety
    /// `session` is a live session; `out` has room for `outlen` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_get_master_key(session: *const SSL_SESSION, out: *mut c_uchar, outlen: usize) -> usize
    where failure = 0, library = ERR_LIB_SSL
    {
        let f = |d: &mut SessData| {
            if outlen == 0 {
                return d.master_key_length;
            }
            let n = outlen.min(d.master_key_length);
            if n > 0 && !out.is_null() {
                // SAFETY: the caller's room; the key's octets.
                unsafe { ptr::copy_nonoverlapping(d.master_key.as_ptr(), out, n) };
            }
            n
        };
        // SAFETY: the caller's guarantee.
        unsafe { with(session, 0, f) }
    }
}

ffi_export! {
    /// Sets the master key (at most 512 octets): 1, or 0.
    ///
    /// # Safety
    /// `sess` is a live session; `in_` points to `len` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_set1_master_key(sess: *mut SSL_SESSION, in_: *const c_uchar, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        if len > MAX_MASTER_KEY {
            return 0;
        }
        let v = if len == 0 || in_.is_null() {
            Vec::new()
        } else {
            // SAFETY: the caller's octets.
            unsafe { core::slice::from_raw_parts(in_, len) }.to_vec()
        };
        // SAFETY: the caller's guarantee.
        let r = unsafe { with(sess, 0, |d| c_int::from(d.set_master_key(&v))) };
        let mut v = v;
        super::ctx::wipe(&mut v);
        r
    }
}

ffi_export! {
    /// The session's timeout in seconds (0 for NULL).
    ///
    /// # Safety
    /// `s` is NULL or a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_get_timeout(s: *const SSL_SESSION) -> c_long
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { with(s, 0, |d| c_long::try_from(to_time_t(d.timeout)).unwrap_or(c_long::MAX)) }
    }
}

ffi_export! {
    /// Sets the timeout in seconds (a session in a cache moves to its new place in the expiry
    /// order): 1, or 0 for NULL or a negative time.
    ///
    /// # Safety
    /// `s` is NULL or a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_set_timeout(s: *mut SSL_SESSION, t: c_long) -> c_long
    where failure = 0, library = ERR_LIB_SSL
    {
        let Ok(secs) = u64::try_from(t) else { return 0 };
        // SAFETY: the caller's guarantee.
        if unsafe { sess(s) }.is_none() {
            return 0;
        }
        // SAFETY: the caller's live session.
        unsafe { super::sess_cache::retime(s, |d| d.timeout = secs.saturating_mul(SECOND)) };
        1
    }
}

ffi_export! {
    /// When the session was made, in seconds since the epoch (0 for NULL).
    ///
    /// # Safety
    /// `s` is NULL or a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_get_time_ex(s: *const SSL_SESSION) -> libc::time_t
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { with(s, 0, |d| libc::time_t::try_from(to_time_t(d.time)).unwrap_or(libc::time_t::MAX)) }
    }
}

ffi_export! {
    /// `SSL_SESSION_get_time_ex` as a `long` (deprecated in 3.4).
    ///
    /// # Safety
    /// `s` is NULL or a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_get_time(s: *const SSL_SESSION) -> c_long
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { with(s, 0, |d| c_long::try_from(to_time_t(d.time)).unwrap_or(c_long::MAX)) }
    }
}

ffi_export! {
    /// Sets when the session was made (seconds since the epoch; a session in a cache moves to
    /// its new place); returns `t` (0 for NULL).
    ///
    /// # Safety
    /// `s` is NULL or a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_set_time_ex(s: *mut SSL_SESSION, t: libc::time_t) -> libc::time_t
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { sess(s) }.is_none() {
            return 0;
        }
        let at = from_time_t(t);
        // SAFETY: the caller's live session.
        unsafe { super::sess_cache::retime(s, |d| d.time = at) };
        t
    }
}

ffi_export! {
    /// `SSL_SESSION_set_time_ex` with a `long` (deprecated in 3.4).
    ///
    /// # Safety
    /// `s` is NULL or a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_set_time(s: *mut SSL_SESSION, t: c_long) -> c_long
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { sess(s) }.is_none() {
            return 0;
        }
        let at = from_time_t(t);
        // SAFETY: the caller's live session.
        unsafe { super::sess_cache::retime(s, |d| d.time = at) };
        t
    }
}

ffi_export! {
    /// The session's protocol version.
    ///
    /// # Safety
    /// `s` is a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_get_protocol_version(s: *const SSL_SESSION) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { with(s, 0, |d| d.ssl_version) }
    }
}

ffi_export! {
    /// Sets the protocol version (not checked, as in OpenSSL): 1.
    ///
    /// # Safety
    /// `s` is a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_set_protocol_version(s: *mut SSL_SESSION, version: c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        let f = |d: &mut SessData| {
            d.ssl_version = version;
            1
        };
        // SAFETY: the caller's guarantee.
        unsafe { with(s, 0, f) }
    }
}

ffi_export! {
    /// The session's cipher, or NULL.
    ///
    /// # Safety
    /// `s` is a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_get0_cipher(s: *const SSL_SESSION) -> *const SSL_CIPHER
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { with(s, ptr::null(), |d| d.cipher.map_or(ptr::null(), super::ciphers::cipher_ptr)) }
    }
}

ffi_export! {
    /// Sets the session's cipher (NULL: none): 1.
    ///
    /// # Safety
    /// `s` is a live session; `cipher` NULL or one of the library's ciphers.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_set_cipher(s: *mut SSL_SESSION, cipher: *const SSL_CIPHER) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        let c = super::ciphers::cipher_of(cipher);
        let f = |d: &mut SessData| {
            d.cipher = c;
            1
        };
        // SAFETY: the caller's guarantee.
        unsafe { with(s, 0, f) }
    }
}

ffi_export! {
    /// The SNI host name the session was made for, or NULL.
    ///
    /// # Safety
    /// `s` is a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_get0_hostname(s: *const SSL_SESSION) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { with(s, ptr::null(), |d| d.hostname.as_ref().map_or(ptr::null(), |h| h.as_ptr())) }
    }
}

ffi_export! {
    /// Sets the host name (a copy; NULL: none): 1.
    ///
    /// # Safety
    /// `s` is a live session; `hostname` NULL or a NUL-terminated string.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_set1_hostname(s: *mut SSL_SESSION, hostname: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        let h = if hostname.is_null() {
            None
        } else {
            // SAFETY: the caller's string, copied before the session is locked.
            Some(unsafe { CStr::from_ptr(hostname) }.to_owned())
        };
        let f = |d: &mut SessData| {
            d.hostname = h;
            1
        };
        // SAFETY: the caller's guarantee.
        unsafe { with(s, 0, f) }
    }
}

ffi_export! {
    /// Whether the session has a ticket: 1 or 0.
    ///
    /// # Safety
    /// `s` is a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_has_ticket(s: *const SSL_SESSION) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { with(s, 0, |d| c_int::from(d.tick.as_ref().is_some_and(|t| !t.is_empty()))) }
    }
}

ffi_export! {
    /// The ticket's lifetime hint in seconds.
    ///
    /// # Safety
    /// `s` is a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_get_ticket_lifetime_hint(s: *const SSL_SESSION) -> core::ffi::c_ulong
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { with(s, 0, |d| core::ffi::c_ulong::try_from(d.tick_lifetime_hint).unwrap_or(core::ffi::c_ulong::MAX)) }
    }
}

ffi_export! {
    /// The ticket in `*tick` (where `tick` isn't NULL; NULL when there is none) and its length
    /// in `*len`.
    ///
    /// # Safety
    /// `s` is a live session; `len` writable (as in OpenSSL, not NULL); `tick` NULL or
    /// writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_get0_ticket(s: *const SSL_SESSION, tick: *mut *const c_uchar, len: *mut usize)
    where failure = (), library = ERR_LIB_SSL
    {
        let f = |d: &mut SessData| {
            let (p, n) = d.tick.as_ref().map_or((ptr::null(), 0), |t| (t.as_ptr(), t.len()));
            if !len.is_null() {
                // SAFETY: the caller's slot.
                unsafe { len.write(n) };
            }
            if !tick.is_null() {
                // SAFETY: as above.
                unsafe { tick.write(p) };
            }
        };
        // SAFETY: the caller's guarantee.
        unsafe { with(s, (), f) }
    }
}

ffi_export! {
    /// The most early data the session allows.
    ///
    /// # Safety
    /// `s` is a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_get_max_early_data(s: *const SSL_SESSION) -> u32
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { with(s, 0, |d| d.max_early_data) }
    }
}

ffi_export! {
    /// Sets the most early data the session allows: 1.
    ///
    /// # Safety
    /// `s` is a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_set_max_early_data(s: *mut SSL_SESSION, max_early_data: u32) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe {
            with(s, 0, |d| {
                d.max_early_data = max_early_data;
                1
            })
        }
    }
}

ffi_export! {
    /// The session's max_fragment_length mode (`TLSEXT_max_fragment_length_*`).
    ///
    /// # Safety
    /// `session` is a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_get_max_fragment_length(session: *const SSL_SESSION) -> u8
    where failure = 0, library = ERR_LIB_SSL
    {
        // An unspecified mode reads as disabled.
        let f = |d: &mut SessData| match d.max_fragment_len_mode {
            m if c_int::from(m) == TLSEXT_max_fragment_length_UNSPECIFIED => {
                u8::try_from(TLSEXT_max_fragment_length_DISABLED).unwrap_or(0)
            }
            m => m,
        };
        // SAFETY: the caller's guarantee.
        unsafe { with(session, 0, f) }
    }
}

ffi_export! {
    /// The ALPN protocol selected, in `*alpn` and `*len` (NULL and 0 when none).
    ///
    /// # Safety
    /// `s` is a live session; `alpn` and `len` writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_get0_alpn_selected(s: *const SSL_SESSION, alpn: *mut *const c_uchar, len: *mut usize)
    where failure = (), library = ERR_LIB_SSL
    {
        let f = |d: &mut SessData| {
            let (p, n) = d.alpn_selected.as_ref().map_or((ptr::null(), 0), |a| (a.as_ptr(), a.len()));
            if !alpn.is_null() {
                // SAFETY: the caller's slot.
                unsafe { alpn.write(p) };
            }
            if !len.is_null() {
                // SAFETY: as above.
                unsafe { len.write(n) };
            }
        };
        // SAFETY: the caller's guarantee.
        unsafe { with(s, (), f) }
    }
}

ffi_export! {
    /// Sets the ALPN protocol (a copy; NULL or empty: none): 1.
    ///
    /// # Safety
    /// `s` is a live session; `alpn` NULL or `len` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_set1_alpn_selected(s: *mut SSL_SESSION, alpn: *const c_uchar, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        let v = if alpn.is_null() || len == 0 {
            None
        } else {
            // SAFETY: the caller's octets, copied before the session is locked.
            Some(unsafe { core::slice::from_raw_parts(alpn, len) }.to_vec().into_boxed_slice())
        };
        let f = |d: &mut SessData| {
            d.alpn_selected = v;
            1
        };
        // SAFETY: the caller's guarantee.
        unsafe { with(s, 0, f) }
    }
}

ffi_export! {
    /// The peer's certificate (no reference taken), or NULL.
    ///
    /// # Safety
    /// `s` is a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_get0_peer(s: *mut SSL_SESSION) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { with(s, ptr::null_mut(), |d| d.peer) }
    }
}

ffi_export! {
    /// The peer's raw public key (no reference taken), or NULL.
    ///
    /// # Safety
    /// `s` is a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_get0_peer_rpk(s: *mut SSL_SESSION) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { with(s, ptr::null_mut(), |d| d.peer_rpk) }
    }
}

ffi_export! {
    /// Whether the session can be resumed: not marked otherwise, with a session ID or a
    /// ticket. 1 or 0.
    ///
    /// # Safety
    /// `s` is a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_is_resumable(s: *const SSL_SESSION) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { with(s, 0, |d| c_int::from(d.is_resumable())) }
    }
}

ffi_export! {
    /// Sets the application's ticket data (a copy; NULL or empty: none): 1, or 0.
    ///
    /// # Safety
    /// `ss` is a live session; `data` NULL or `len` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_set1_ticket_appdata(ss: *mut SSL_SESSION, data: *const c_void, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        let v = if data.is_null() || len == 0 {
            None
        } else {
            // SAFETY: the caller's octets, copied before the session is locked.
            Some(unsafe { core::slice::from_raw_parts(data.cast::<u8>(), len) }.to_vec().into_boxed_slice())
        };
        let f = |d: &mut SessData| {
            d.ticket_appdata = v;
            1
        };
        // SAFETY: the caller's guarantee.
        unsafe { with(ss, 0, f) }
    }
}

ffi_export! {
    /// The application's ticket data in `*data` and `*len` (NULL and 0 when none): 1.
    ///
    /// # Safety
    /// `ss` is a live session; `data` and `len` writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_get0_ticket_appdata(ss: *mut SSL_SESSION, data: *mut *mut c_void, len: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        let f = |d: &mut SessData| {
            let (p, n) = d
                .ticket_appdata
                .as_mut()
                .map_or((ptr::null_mut(), 0), |a| (a.as_mut_ptr().cast::<c_void>(), a.len()));
            if !data.is_null() {
                // SAFETY: the caller's slot.
                unsafe { data.write(p) };
            }
            if !len.is_null() {
                // SAFETY: as above.
                unsafe { len.write(n) };
            }
            1
        };
        // SAFETY: the caller's guarantee.
        unsafe { with(ss, 0, f) }
    }
}

ffi_export! {
    /// Sets the application's data at `idx`: 1, or 0.
    ///
    /// # Safety
    /// `ss` is a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_set_ex_data(ss: *mut SSL_SESSION, idx: c_int, data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { sess(ss) }) else { return 0 };
        // SAFETY: the session's own application data.
        unsafe { CRYPTO_set_ex_data(x.ex_data(), idx, data) }
    }
}

ffi_export! {
    /// The application's data at `idx`, or NULL.
    ///
    /// # Safety
    /// `ss` is a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_get_ex_data(ss: *const SSL_SESSION, idx: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { sess(ss) }) else { return ptr::null_mut() };
        // SAFETY: the session's own application data.
        unsafe { CRYPTO_get_ex_data(x.ex_data(), idx) }
    }
}
