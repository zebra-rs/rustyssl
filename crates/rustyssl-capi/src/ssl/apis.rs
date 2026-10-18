//! The smaller connection calls of `ssl_lib.c` and `ssl_cert_comp.c`: the default cipher
//! strings, the record layer's state and buffers, `SSL_sendfile` (kTLS isn't in the default
//! build), certificate compression (no compression algorithm is either), the client
//! certificate engine (no engines), QUIC's domain flags and pending-connection callback on TLS
//! objects, and the expected raw public keys of RFC 7250.

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ENGINE, ERR_LIB_ENGINE, ERR_LIB_SSL, ERR_R_ENGINE_LIB, ERR_R_PASSED_NULL_PARAMETER,
    ERR_R_UNSUPPORTED, EVP_PKEY, SSL, SSL_CTX, SSL_R_PROTOCOL_IS_SHUTDOWN, SSL_R_UNINITIALIZED,
    SSL_SENT_SHUTDOWN, SSL_new_pending_conn_cb_fn,
};

use super::conn::ssl;
use super::ctx::ctx;
use super::dane::rustyssl_private_SSL_dane_tlsa_add;
use crate::err;
use crate::ffi::ffi_export;
use crate::mem;
use crate::x509::pubkey::i2d_PUBKEY;

ffi_export! {
    /// The default TLS 1.2 cipher string (`ALL:!COMPLEMENTOFDEFAULT:!eNULL`).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_OSSL_default_cipher_list() -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        rustyssl_tls::cipherstring::DEFAULT_CIPHER_LIST.as_ptr()
    }
}

ffi_export! {
    /// The default TLS 1.3 ciphersuites.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_OSSL_default_ciphersuites() -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        rustyssl_tls::cipherstring::DEFAULT_CIPHERSUITES.as_ptr()
    }
}

/// Whether the record layer is in the middle of a record's body (`SSL_ST_READ_BODY`).
fn reading_body(s: *const SSL) -> bool {
    // SAFETY: the caller's connection, NULL or live.
    let Some(x) = (unsafe { ssl(s) }) else {
        return false;
    };
    let st = x.state();
    st.drv.rec_left > 0
}

ffi_export! {
    /// The record layer's state, short form (`RH` reading a header, `RB` a body).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_rstate_string(s: *const SSL) -> *const c_char
    where failure = c"unknown".as_ptr(), library = ERR_LIB_SSL
    {
        if reading_body(s) { c"RB".as_ptr() } else { c"RH".as_ptr() }
    }
}

ffi_export! {
    /// The record layer's state, long form.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_rstate_string_long(s: *const SSL) -> *const c_char
    where failure = c"unknown".as_ptr(), library = ERR_LIB_SSL
    {
        if reading_body(s) { c"read body".as_ptr() } else { c"read header".as_ptr() }
    }
}

ffi_export! {
    /// Allocates the record layer's buffers: 1 (buffers are allocated as needed), 0 for NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_alloc_buffers(s: *mut SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { ssl(s) }.is_some())
    }
}

ffi_export! {
    /// Frees the record layer's buffers: 1, or 0 for NULL or while data is pending (a record
    /// half read, received data not yet read, or output not yet written).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_free_buffers(s: *mut SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let st = x.state();
        let d = &st.drv;
        let app = d.tls.as_ref().is_some_and(|c| c.pending_app() > 0 || c.buffered_input() > 0);
        c_int::from(!(d.rec_left > 0 || app || !d.out.is_empty() || d.wpend.is_some()))
    }
}

ffi_export! {
    /// `SSL_sendfile`: kTLS isn't in the default build, so this fails (after OpenSSL's checks).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_sendfile(s: *mut SSL, _fd: c_int, _offset: libc::off_t, _size: usize, _flags: c_int) -> isize
    where failure = -1, library = ERR_LIB_SSL
    {
        const F: &str = "SSL_sendfile";
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let mut st = x.state();
        if st.handshake_func.is_none() {
            drop(st);
            err::raise(ERR_LIB_SSL, SSL_R_UNINITIALIZED, F);
            return -1;
        }
        if st.shutdown & SSL_SENT_SHUTDOWN != 0 {
            st.rwstate = rustyssl_abi::SSL_NOTHING;
            drop(st);
            err::raise(ERR_LIB_SSL, SSL_R_PROTOCOL_IS_SHUTDOWN, F);
            return -1;
        }
        drop(st);
        // `BIO_get_ktls_send` is 0 for every BIO without kTLS.
        err::raise(ERR_LIB_SSL, SSL_R_UNINITIALIZED, F);
        -1
    }
}

ffi_export! {
    /// The certificate compression preference: 0, as the default build has no compression
    /// algorithm.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set1_cert_comp_preference(_ctx: *mut SSL_CTX, _algs: *mut c_int, _len: usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        0
    }
}

ffi_export! {
    /// As [`rustyssl_private_SSL_CTX_set1_cert_comp_preference`], for a connection.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_set1_cert_comp_preference(_s: *mut SSL, _algs: *mut c_int, _len: usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        0
    }
}

ffi_export! {
    /// Compresses the connection's certificates: 0 (no compression algorithm).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_compress_certs(_s: *mut SSL, _alg: c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        0
    }
}

ffi_export! {
    /// Compresses the context's certificates: 0 (no compression algorithm).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_compress_certs(_ctx: *mut SSL_CTX, _alg: c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        0
    }
}

ffi_export! {
    /// The connection's compressed certificate: none (length 0).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_get1_compressed_cert(_s: *mut SSL, _alg: c_int, _data: *mut *mut c_uchar, _orig_len: *mut usize) -> usize
    where failure = 0, library = ERR_LIB_SSL
    {
        0
    }
}

ffi_export! {
    /// The context's compressed certificate: none (length 0).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_get1_compressed_cert(_ctx: *mut SSL_CTX, _alg: c_int, _data: *mut *mut c_uchar, _orig_len: *mut usize) -> usize
    where failure = 0, library = ERR_LIB_SSL
    {
        0
    }
}

ffi_export! {
    /// Sets a precompressed certificate: 0 (no compression algorithm).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set1_compressed_cert(_ctx: *mut SSL_CTX, _algorithm: c_int, _comp_data: *mut c_uchar, _comp_length: usize, _orig_length: usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        0
    }
}

ffi_export! {
    /// As [`rustyssl_private_SSL_CTX_set1_compressed_cert`], for a connection.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_set1_compressed_cert(_s: *mut SSL, _algorithm: c_int, _comp_data: *mut c_uchar, _comp_length: usize, _orig_length: usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        0
    }
}

ffi_export! {
    /// The client certificate engine: rustyssl has no engines, so `ENGINE_init` fails (for NULL
    /// as OpenSSL's does) and so does this: 0.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_client_cert_engine(_ctx: *mut SSL_CTX, e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        if e.is_null() {
            err::raise(ERR_LIB_ENGINE, ERR_R_PASSED_NULL_PARAMETER, "engine_init");
        }
        err::raise(ERR_LIB_SSL, ERR_R_ENGINE_LIB, "SSL_CTX_set_client_cert_engine");
        0
    }
}

ffi_export! {
    /// QUIC's domain flags: unsupported on a TLS context, 0.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_domain_flags(_ctx: *mut SSL_CTX, _domain_flags: u64) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        err::raise_with_text(ERR_LIB_SSL, ERR_R_UNSUPPORTED, "SSL_CTX_set_domain_flags", "domain flags unsupported on this kind of SSL_CTX");
        0
    }
}

ffi_export! {
    /// QUIC's domain flags: unsupported on a TLS context, 0.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_get_domain_flags(_ctx: *const SSL_CTX, _domain_flags: *mut u64) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        err::raise_with_text(ERR_LIB_SSL, ERR_R_UNSUPPORTED, "SSL_CTX_get_domain_flags", "domain flags unsupported on this kind of SSL_CTX");
        0
    }
}

ffi_export! {
    /// QUIC's domain flags of a connection: 0 for a TLS one.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_domain_flags(_s: *const SSL, _domain_flags: *mut u64) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        0
    }
}

ffi_export! {
    /// Stores QUIC's new-pending-connection callback (never called for TLS).
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_new_pending_conn_cb(c: *mut SSL_CTX, cb: SSL_new_pending_conn_cb_fn, arg: *mut c_void)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(cx) = (unsafe { ctx(c) }) else { return };
        let mut cs = cx.state();
        cs.new_pending_conn_cb = cb;
        cs.new_pending_conn_arg = arg;
    }
}

ffi_export! {
    /// Adds the `ssl_conf` module: nothing to do, libcrypto adds it itself.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_add_ssl_module()
    where failure = (), library = ERR_LIB_SSL
    {}
}

ffi_export! {
    /// Adds a raw public key the peer may present (RFC 7250), as a DANE-EE SPKI record: 1, or 0
    /// when DANE isn't enabled on the connection or the record can't be added.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `rpk` NULL or a live key.
    pub unsafe extern "C" fn rustyssl_private_SSL_add_expected_rpk(s: *mut SSL, rpk: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        if !x.state().lists.dane.has_ctx() {
            return 0;
        }
        let mut data: *mut c_uchar = ptr::null_mut();
        // SAFETY: the caller's key; the slot.
        let n = unsafe { i2d_PUBKEY(rpk, &raw mut data) };
        let Ok(len) = usize::try_from(n) else { return 0 };
        if len == 0 {
            return 0;
        }
        // DANE-EE(3), SPKI(1), Full(0) (RFC 6698; `internal/dane.h`).
        let (usage, selector, mtype) = (3, 1, 0);
        // SAFETY: the connection; the encoding of `len` octets.
        let ret = unsafe { rustyssl_private_SSL_dane_tlsa_add(s, usage, selector, mtype, data, len) } > 0;
        // SAFETY: the encoding `i2d_PUBKEY` allocated.
        unsafe { mem::release(data.cast()) };
        c_int::from(ret)
    }
}

ffi_export! {
    /// The handshake's round-trip time in microseconds, from the last flight written to the
    /// peer's answer read: 1, 0 before both are seen, or -1 for NULL or an answer older than
    /// the flight.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `rtt` writable when both marks are seen.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_handshake_rtt(s: *const SSL, rtt: *mut u64) -> c_int
    where failure = -1, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return -1 };
        let (Some(write), Some(read)) = x.state().drv.rtt_times else { return 0 };
        let Some(d) = read.checked_duration_since(write) else { return -1 };
        if rtt.is_null() {
            return 1;
        }
        let us = u64::try_from(d.as_micros()).unwrap_or(u64::MAX);
        // SAFETY: the caller's slot.
        unsafe { rtt.write(us) };
        1
    }
}

ffi_export! {
    /// A TLS 1.3 server's handshake keeping no state across a HelloRetryRequest: the connection
    /// is cleared, then accepts. 1 when the ClientHello carried a good cookie (the handshake goes
    /// on with `SSL_accept`), 0 when a HelloRetryRequest with a cookie was sent (call again for
    /// the next ClientHello), -1 on an error.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_stateless(s: *mut SSL) -> c_int
    where failure = -1, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        // SAFETY: as above.
        if unsafe { super::conn::rustyssl_private_SSL_clear(s) } == 0 {
            return 0;
        }
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
        // SAFETY: as above.
        if !unsafe { super::io::ensure_core(s, x) } {
            return -1;
        }
        let set = |on: bool| {
            if let Some(c) = x.state().drv.tls.as_mut() {
                c.set_stateless(on);
            }
        };
        set(true);
        // SAFETY: as above.
        let ret = unsafe { super::io::api::rustyssl_private_SSL_accept(s) };
        set(false);
        let st = x.state();
        let Some(c) = st.drv.tls.as_ref() else { return -1 };
        if ret > 0 && c.cookie_ok() {
            return 1;
        }
        if c.hrr_pending() && c.error().is_none() && !st.drv.failed {
            return 0;
        }
        -1
    }
}

ffi_export! {
    /// Asks a TLS 1.3 server for one more session ticket, sent with the next write or
    /// handshake call: 1, or 0 (a client, before the first handshake's end, or not TLS 1.3).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_new_session_ticket(s: *mut SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let mut st = x.state();
        let pending = st.drv.wpend.is_some();
        let Some(c) = st.drv.tls.as_mut() else { return 0 };
        if !c.request_new_session_ticket(pending) {
            return 0;
        }
        let in_init = c.in_init();
        st.in_init = in_init;
        1
    }
}
