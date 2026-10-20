//! The rest of the connection surface whose TLS behavior is fixed (`ssl_lib.c`, `ssl_ciph.c`):
//! compression (none is ever negotiated: the default build has no compression algorithm) and
//! the compression method list; asynchronous jobs (connections here never run in one); and
//! the QUIC calls, which on a TLS or DTLS connection (the QUIC methods aren't built yet) do
//! what OpenSSL's non-QUIC branches do: for DTLS, the event calls drive the retransmission
//! timer.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};

use libc::timeval;
use rustyssl_abi::{
    BIO_ADDR, COMP_METHOD, ERR_LIB_SSL, ERR_R_CRYPTO_LIB, NID_undef, SSL, SSL_COMP,
    SSL_CONN_CLOSE_INFO, SSL_CTX, SSL_R_COMPRESSION_ID_NOT_WITHIN_PRIVATE_RANGE,
    SSL_R_DUPLICATE_COMPRESSION_ID, SSL_R_UNSUPPORTED_PROTOCOL, SSL_READING, SSL_SHUTDOWN_EX_ARGS,
    SSL_STREAM_RESET_ARGS, SSL_STREAM_STATE_NONE, SSL_STREAM_TYPE_BIDI, SSL_WRITING,
    stack_st_SSL_COMP,
};

use super::conn::rustyssl_private_SSL_want;
use super::io::api::rustyssl_private_SSL_shutdown;
use crate::comp::{COMP_get_name, COMP_get_type};
use crate::err;
use crate::ffi::ffi_export;
use crate::stack::{OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value};

ffi_export! {
    /// The compression the connection writes with: none.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_current_compression(_s: *const SSL) -> *const COMP_METHOD
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        ptr::null()
    }
}

ffi_export! {
    /// The compression the connection reads with: none.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_current_expansion(_s: *const SSL) -> *const COMP_METHOD
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        ptr::null()
    }
}

/// `SSL_COMP` (`struct ssl_comp_st`): opaque to applications.
#[repr(C)]
struct SslComp {
    id: c_int,
    name: *const c_char,
    method: *mut COMP_METHOD,
}

/// The default library context's compression methods (`OSSL_LIB_CTX_COMP_METHODS`): a list
/// made empty, as the default build has no built-in compression.
static COMP_METHODS: AtomicPtr<stack_st_SSL_COMP> = AtomicPtr::new(ptr::null_mut());

/// Whether the list was made (it may since have been replaced, by NULL too).
static COMP_METHODS_INIT: std::sync::Once = std::sync::Once::new();

/// The list, made on first use.
fn comp_methods() -> *mut stack_st_SSL_COMP {
    COMP_METHODS_INIT.call_once(|| {
        // SAFETY: no preconditions.
        let new: *mut stack_st_SSL_COMP = unsafe { OPENSSL_sk_new_null() }.cast();
        COMP_METHODS.store(new, Ordering::Release);
    });
    COMP_METHODS.load(Ordering::Acquire)
}

ffi_export! {
    /// The compression methods offered (an empty list in the default build).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_COMP_get_compression_methods() -> *mut stack_st_SSL_COMP
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        comp_methods()
    }
}

ffi_export! {
    /// Replaces the compression method list with `meths`: the old one.
    ///
    /// # Safety
    /// `meths` is NULL or a list of `SSL_COMP`s.
    pub unsafe extern "C" fn rustyssl_private_SSL_COMP_set0_compression_methods(meths: *mut stack_st_SSL_COMP) -> *mut stack_st_SSL_COMP
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // The list is made first, so that the old one returned is it (as OpenSSL's exists).
        comp_methods();
        COMP_METHODS.swap(meths, Ordering::AcqRel)
    }
}

ffi_export! {
    /// Adds a compression method with a private-range `id` (193 to 255): 0 when added, 1
    /// otherwise (OpenSSL's inverted convention).
    ///
    /// # Safety
    /// `cm` is NULL or a live compression method that outlives the list.
    pub unsafe extern "C" fn rustyssl_private_SSL_COMP_add_compression_method(id: c_int, cm: *mut COMP_METHOD) -> c_int
    where failure = 1, library = ERR_LIB_SSL
    {
        const F: &str = "SSL_COMP_add_compression_method";
        let list = comp_methods();
        // SAFETY: the caller's method.
        if list.is_null() || cm.is_null() || unsafe { COMP_get_type(cm) } == NID_undef {
            return 1;
        }
        if !(193..=255).contains(&id) {
            err::raise(ERR_LIB_SSL, SSL_R_COMPRESSION_ID_NOT_WITHIN_PRIVATE_RANGE, F);
            return 1;
        }
        // SAFETY: the list.
        let n = unsafe { OPENSSL_sk_num(list.cast()) };
        for i in 0..n.max(0) {
            // SAFETY: an index of the list, whose entries are `SSL_COMP`s.
            let c: *const SslComp = unsafe { OPENSSL_sk_value(list.cast(), i) }.cast();
            // SAFETY: an entry of the list.
            if !c.is_null() && unsafe { (*c).id } == id {
                err::raise(ERR_LIB_SSL, SSL_R_DUPLICATE_COMPRESSION_ID, F);
                return 1;
            }
        }
        let c: *mut SslComp = crate::mem::alloc(core::mem::size_of::<SslComp>()).cast();
        if c.is_null() {
            return 1;
        }
        // SAFETY: the caller's method.
        let name = unsafe { COMP_get_name(cm) };
        // SAFETY: room for an entry, from CRYPTO_malloc (suitably aligned).
        unsafe { c.write(SslComp { id, name, method: cm }) };
        // SAFETY: the list takes the entry.
        if unsafe { OPENSSL_sk_push(list.cast(), c.cast::<c_void>()) } == 0 {
            // SAFETY: the entry nothing owns.
            unsafe { crate::mem::release(c.cast()) };
            err::raise(ERR_LIB_SSL, ERR_R_CRYPTO_LIB, F);
            return 1;
        }
        0
    }
}

ffi_export! {
    /// A compression method's name, or NULL.
    ///
    /// # Safety
    /// `comp` is NULL or a live method.
    pub unsafe extern "C" fn rustyssl_private_SSL_COMP_get_name(comp: *const COMP_METHOD) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        if comp.is_null() {
            return ptr::null();
        }
        // SAFETY: the caller's method.
        unsafe { COMP_get_name(comp) }
    }
}

ffi_export! {
    /// The list entry's name.
    ///
    /// # Safety
    /// `comp` is an entry of the compression method list.
    pub unsafe extern "C" fn rustyssl_private_SSL_COMP_get0_name(comp: *const SSL_COMP) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        let c: *const SslComp = comp.cast();
        // SAFETY: the caller's guarantee.
        unsafe { c.as_ref() }.map_or(ptr::null(), |c| c.name)
    }
}

ffi_export! {
    /// The list entry's id.
    ///
    /// # Safety
    /// `comp` is an entry of the compression method list.
    pub unsafe extern "C" fn rustyssl_private_SSL_COMP_get_id(comp: *const SSL_COMP) -> c_int
    where failure = -1, library = ERR_LIB_SSL
    {
        let c: *const SslComp = comp.cast();
        // SAFETY: the caller's guarantee.
        unsafe { c.as_ref() }.map_or(-1, |c| c.id)
    }
}

ffi_export! {
    /// Whether an asynchronous job is paused: never.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_waiting_for_async(_s: *mut SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        0
    }
}

ffi_export! {
    /// The wait context's file descriptors: 0, as no job has one.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_all_async_fds(_s: *mut SSL, _fds: *mut c_int, _numfds: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        0
    }
}

ffi_export! {
    /// The wait context's changed file descriptors: 0, as no job has one.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_changed_async_fds(_s: *mut SSL, _addfd: *mut c_int, _numaddfds: *mut usize, _delfd: *mut c_int, _numdelfds: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        0
    }
}

ffi_export! {
    /// The wait context's status: 0, as there is none.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_async_status(_s: *mut SSL, _status: *mut c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        0
    }
}

ffi_export! {
    /// Handles pending events: for DTLS, the retransmission timer (`DTLSv1_handle_timeout`; a
    /// timer that hasn't fired is success); nothing to do for TLS. 1, or 0 when the
    /// retransmission failed.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_handle_events(s: *mut SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if let Some(q) = unsafe { super::quic::of(s) } {
            // SAFETY: as above.
            return unsafe { super::quic::api::handle_events(q) };
        }
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { super::conn::ssl(s) }) else { return 1 };
        if !x.state().method.dtls {
            return 1;
        }
        // SAFETY: the live connection; no lock is held.
        c_int::from(unsafe { super::dtls::handle_timeout(s, x) } >= 0)
    }
}

ffi_export! {
    /// When events need handling: for DTLS with the retransmission timer running, when it fires
    /// (`DTLSv1_get_timeout`, finite); otherwise never (an infinite timeout, given as 1000000
    /// seconds). 1.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `tv` and `is_infinite` are valid for writes.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_event_timeout(s: *mut SSL, tv: *mut timeval, is_infinite: *mut c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if let Some(q) = unsafe { super::quic::of(s) } {
            // SAFETY: as above.
            return unsafe { super::quic::api::event_timeout(q, tv, is_infinite) };
        }
        // SAFETY: the caller's guarantee.
        if let Some(x) = unsafe { super::conn::ssl(s) }
            && !tv.is_null()
            // SAFETY: the live connection; `tv` is the caller's `struct timeval`.
            && unsafe {
                super::dtls::ssl_ctrl(
                    s,
                    x,
                    rustyssl_abi::DTLS_CTRL_GET_TIMEOUT,
                    0,
                    tv.cast::<c_void>(),
                )
            } == Some(1)
        {
            if !is_infinite.is_null() {
                // SAFETY: the caller's guarantee.
                unsafe { is_infinite.write(0) };
            }
            return 1;
        }
        if !tv.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe {
                tv.write(timeval {
                    tv_sec: 1_000_000,
                    tv_usec: 0,
                })
            };
        }
        if !is_infinite.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { is_infinite.write(1) };
        }
        1
    }
}

ffi_export! {
    /// Whether the connection waits to read (`SSL_want_read`).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_net_read_desired(s: *mut SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if let Some(q) = unsafe { super::quic::of(s) } {
            return super::quic::api::net_read_desired(q);
        }
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { rustyssl_private_SSL_want(s) } == SSL_READING)
    }
}

ffi_export! {
    /// Whether the connection waits to write (`SSL_want_write`).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_net_write_desired(s: *mut SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if let Some(q) = unsafe { super::quic::of(s) } {
            return super::quic::api::net_write_desired(q);
        }
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { rustyssl_private_SSL_want(s) } == SSL_WRITING)
    }
}

ffi_export! {
    /// Blocking mode is QUIC's: 0.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_blocking_mode(s: *mut SSL, blocking: c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if let Some(q) = unsafe { super::quic::of(s) } {
            return super::quic::api::set_blocking(q, blocking);
        }
        0
    }
}

ffi_export! {
    /// Blocking mode is QUIC's: -1.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_blocking_mode(s: *mut SSL) -> c_int
    where failure = -1, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if let Some(q) = unsafe { super::quic::of(s) } {
            return super::quic::api::get_blocking(q);
        }
        -1
    }
}

ffi_export! {
    /// The initial peer address is QUIC's: 0.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_set1_initial_peer_addr(s: *mut SSL, peer_addr: *const BIO_ADDR) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            // SAFETY: as above.
            return unsafe { super::quic::api::set_initial_peer(s, peer_addr) };
        }
        0
    }
}

ffi_export! {
    /// Concluding a stream is QUIC's: 0.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_stream_conclude(s: *mut SSL, flags: u64) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            // SAFETY: as above.
            return unsafe { super::quic::api::stream_conclude(s, flags) };
        }
        0
    }
}

ffi_export! {
    /// Streams are QUIC's: NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_new_stream(s: *mut SSL, flags: u64) -> *mut SSL
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            // SAFETY: as above.
            return unsafe { super::quic::api::new_stream(s, flags) };
        }
        ptr::null_mut()
    }
}

ffi_export! {
    /// Listeners are QUIC's: NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_get0_listener(s: *mut SSL) -> *mut SSL
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            return super::quic::api::get0_listener(s);
        }
        ptr::null_mut()
    }
}

ffi_export! {
    /// Domains are QUIC's: NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_get0_domain(s: *mut SSL) -> *mut SSL
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            return super::quic::api::get0_domain(s);
        }
        ptr::null_mut()
    }
}

ffi_export! {
    /// A TLS connection is one bidirectional stream.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_stream_type(s: *mut SSL) -> c_int
    where failure = BIDI, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            return super::quic::api::stream_type(s);
        }
        BIDI
    }
}

ffi_export! {
    /// Stream ids are QUIC's: `UINT64_MAX`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_stream_id(s: *mut SSL) -> u64
    where failure = u64::MAX, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            return super::quic::api::stream_id(s);
        }
        u64::MAX
    }
}

ffi_export! {
    /// Stream origins are QUIC's: -1.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_is_stream_local(s: *mut SSL) -> c_int
    where failure = -1, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            return super::quic::api::is_stream_local(s);
        }
        -1
    }
}

ffi_export! {
    /// Stream modes are QUIC's: 0.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_default_stream_mode(s: *mut SSL, mode: u32) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            return super::quic::api::set_default_stream_mode(s, mode);
        }
        0
    }
}

ffi_export! {
    /// Incoming stream policies are QUIC's: 0.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_incoming_stream_policy(s: *mut SSL, policy: c_int, aec: u64) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            return super::quic::api::set_incoming_stream_policy(s, policy, aec);
        }
        0
    }
}

ffi_export! {
    /// Streams are QUIC's: NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_accept_stream(s: *mut SSL, flags: u64) -> *mut SSL
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            // SAFETY: as above.
            return unsafe { super::quic::api::accept_stream(s, flags) };
        }
        ptr::null_mut()
    }
}

ffi_export! {
    /// Streams are QUIC's: 0.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_accept_stream_queue_len(s: *mut SSL) -> usize
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            return super::quic::api::accept_stream_queue_len(s);
        }
        0
    }
}

ffi_export! {
    /// Stream resets are QUIC's: 0.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_stream_reset(s: *mut SSL, args: *const SSL_STREAM_RESET_ARGS, args_len: usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            // SAFETY: as above.
            return unsafe { super::quic::api::stream_reset(s, args, args_len) };
        }
        0
    }
}

ffi_export! {
    /// Stream states are QUIC's: `SSL_STREAM_STATE_NONE`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_stream_read_state(s: *mut SSL) -> c_int
    where failure = SSL_STREAM_STATE_NONE, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            return super::quic::api::stream_state(s, false);
        }
        SSL_STREAM_STATE_NONE
    }
}

ffi_export! {
    /// Stream states are QUIC's: `SSL_STREAM_STATE_NONE`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_stream_write_state(s: *mut SSL) -> c_int
    where failure = SSL_STREAM_STATE_NONE, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            return super::quic::api::stream_state(s, true);
        }
        SSL_STREAM_STATE_NONE
    }
}

ffi_export! {
    /// Stream error codes are QUIC's: -1.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_stream_read_error_code(s: *mut SSL, app_error_code: *mut u64) -> c_int
    where failure = -1, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            // SAFETY: as above.
            return unsafe { super::quic::api::stream_error_code(s, false, app_error_code) };
        }
        -1
    }
}

ffi_export! {
    /// Stream error codes are QUIC's: -1.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_stream_write_error_code(s: *mut SSL, app_error_code: *mut u64) -> c_int
    where failure = -1, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            // SAFETY: as above.
            return unsafe { super::quic::api::stream_error_code(s, true, app_error_code) };
        }
        -1
    }
}

ffi_export! {
    /// Connection close information is QUIC's: -1.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_conn_close_info(s: *mut SSL, info: *mut SSL_CONN_CLOSE_INFO, info_len: usize) -> c_int
    where failure = -1, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            // SAFETY: as above.
            return unsafe { super::quic::api::conn_close_info(s, info, info_len) };
        }
        -1
    }
}

ffi_export! {
    /// Listeners are QUIC's: NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_new_listener(ctx: *mut SSL_CTX, flags: u64) -> *mut SSL
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::api::is_quic_ctx(ctx) } {
            // SAFETY: as above.
            return unsafe { super::quic::api::new_listener(ctx, flags) };
        }
        ptr::null_mut()
    }
}

ffi_export! {
    /// Listeners are QUIC's: NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_new_listener_from(s: *mut SSL, flags: u64) -> *mut SSL
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            return super::quic::api::new_listener_from(s, flags);
        }
        ptr::null_mut()
    }
}

ffi_export! {
    /// Listeners are QUIC's: NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_new_from_listener(s: *mut SSL, flags: u64) -> *mut SSL
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            // SAFETY: as above.
            return unsafe { super::quic::api::new_from_listener(s, flags) };
        }
        ptr::null_mut()
    }
}

ffi_export! {
    /// Listeners are QUIC's: NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_accept_connection(s: *mut SSL, flags: u64) -> *mut SSL
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            // SAFETY: as above.
            return unsafe { super::quic::api::accept_connection(s, flags) };
        }
        ptr::null_mut()
    }
}

ffi_export! {
    /// Listeners are QUIC's: 0.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_accept_connection_queue_len(s: *mut SSL) -> usize
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            return super::quic::api::accept_queue_len(s);
        }
        0
    }
}

ffi_export! {
    /// Listeners are QUIC's: 0.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_listen(s: *mut SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            return super::quic::api::listen(s);
        }
        0
    }
}

ffi_export! {
    /// Domains are QUIC's: NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_new_domain(ctx: *mut SSL_CTX, flags: u64) -> *mut SSL
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::api::is_quic_ctx(ctx) } {
            // SAFETY: as above.
            return unsafe { super::quic::api::new_domain(ctx, flags) };
        }
        ptr::null_mut()
    }
}

/// `SSL_STREAM_TYPE_BIDI` as an `int`.
const BIDI: c_int = SSL_STREAM_TYPE_BIDI.cast_signed();

ffi_export! {
    /// A TLS connection is its own connection object.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_get0_connection(s: *mut SSL) -> *mut SSL
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            return super::quic::api::get0_connection(s);
        }
        s
    }
}

ffi_export! {
    /// Whether `s` is a connection object: always, for TLS.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_is_connection(s: *mut SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            return c_int::from(super::quic::api::get0_connection(s) == s);
        }
        1
    }
}

ffi_export! {
    /// Whether `s` is a listener: only NULL, which `SSL_get0_listener` returns (as OpenSSL
    /// compares them).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_is_listener(s: *mut SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            return c_int::from(super::quic::api::get0_listener(s) == s);
        }
        c_int::from(s.is_null())
    }
}

ffi_export! {
    /// Whether `s` is a domain: only NULL, as for `SSL_is_listener`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_is_domain(s: *mut SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            return c_int::from(super::quic::api::get0_domain(s) == s);
        }
        c_int::from(s.is_null())
    }
}

ffi_export! {
    /// A QUIC value: TLS has none (`SSL_R_UNSUPPORTED_PROTOCOL`).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_value_uint(s: *mut SSL, class: u32, id: u32, value: *mut u64) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            // SAFETY: as above.
            return unsafe { super::quic::api::get_value(s, class, id, value) };
        }
        err::raise(ERR_LIB_SSL, SSL_R_UNSUPPORTED_PROTOCOL, "SSL_get_value_uint");
        0
    }
}

ffi_export! {
    /// A QUIC value: TLS has none (`SSL_R_UNSUPPORTED_PROTOCOL`).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_value_uint(s: *mut SSL, class: u32, id: u32, value: u64) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            return super::quic::api::set_value(s, class, id, value);
        }
        err::raise(ERR_LIB_SSL, SSL_R_UNSUPPORTED_PROTOCOL, "SSL_set_value_uint");
        0
    }
}

ffi_export! {
    /// `SSL_shutdown` for TLS (the flags and arguments are QUIC's).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_shutdown_ex(s: *mut SSL, flags: u64, args: *const SSL_SHUTDOWN_EX_ARGS, args_len: usize) -> c_int
    where failure = -1, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            // SAFETY: as above.
            return unsafe { super::quic::api::shutdown(s, flags, args, args_len) };
        }
        // SAFETY: the caller's guarantee.
        unsafe { rustyssl_private_SSL_shutdown(s) }
    }
}
