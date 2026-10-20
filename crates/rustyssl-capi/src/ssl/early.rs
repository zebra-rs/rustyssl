//! TLS 1.3 early data (0-RTT): `SSL_write_early_data` and `SSL_read_early_data` move the early
//! data state along around the handshake and the reads and writes (`ssl_lib.c`), and
//! `SSL_write_ex2`.

use core::ffi::{c_int, c_void};

use rustyssl_abi::{
    ERR_LIB_SSL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, SSL, SSL_EARLY_DATA_ACCEPTED,
    SSL_MODE_ENABLE_PARTIAL_WRITE, SSL_NOTHING, SSL_R_PROTOCOL_IS_SHUTDOWN, SSL_R_UNINITIALIZED,
    SSL_R_UNSUPPORTED_WRITE_FLAG, SSL_READ_EARLY_DATA_ERROR, SSL_READ_EARLY_DATA_FINISH,
    SSL_READ_EARLY_DATA_SUCCESS, SSL_SENT_SHUTDOWN,
};
use rustyssl_tls::conn::common::EarlyDataState as E;

use super::conn::{rustyssl_private_SSL_in_before, ssl};
use super::io::api::{
    rustyssl_private_SSL_accept, rustyssl_private_SSL_connect, rustyssl_private_SSL_read_ex,
    rustyssl_private_SSL_write_ex, write_internal,
};
use super::io::{Flush, flush, set_early_data_state};
use crate::err;
use crate::ffi::ffi_export;

/// The connection's early data state, or `None` for NULL.
fn state_of(s: *const SSL) -> Option<E> {
    // SAFETY: the caller's connection, NULL or live.
    unsafe { ssl(s) }.map(|x| x.state().drv.early_data_state)
}

/// Sets the connection's early data state.
fn set(s: *const SSL, e: E) {
    // SAFETY: as above.
    if let Some(x) = unsafe { ssl(s) } {
        set_early_data_state(&mut x.state(), e);
    }
}

ffi_export! {
    /// Writes early data (a client resuming a session that allows it): 1 with `*written`
    /// set, or 0. The first call starts the handshake; a server may also use it to write to the
    /// client before the client's Finished, after `SSL_read_early_data`.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `buf` holds `num` octets; `written` writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_write_early_data(s: *mut SSL, buf: *const c_void, num: usize, written: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            return 0;
        }
        const F: &str = "SSL_write_early_data";
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let mut eds = x.state().drv.early_data_state;
        if eds == E::None {
            let refuse = {
                let st = x.state();
                let session_max = st.sess.session;
                // SAFETY: the connection's session, or NULL.
                let max = unsafe { super::session::with(session_max, 0, |d| d.max_early_data) };
                st.server || (max == 0 && st.psk_use_session_cb.is_none())
            };
            // SAFETY: as above.
            if refuse || unsafe { rustyssl_private_SSL_in_before(s) } == 0 {
                err::raise(ERR_LIB_SSL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, F);
                return 0;
            }
            eds = E::ConnectRetry;
        }
        match eds {
            E::ConnectRetry | E::WriteRetry | E::WriteFlush => {}
            E::FinishedReading | E::ReadRetry => {
                // A server writing to an unauthenticated client.
                set(s, E::UnauthWriting);
                // SAFETY: the caller's guarantee.
                let ret = unsafe { rustyssl_private_SSL_write_ex(s, buf, num, written) };
                if ret != 0 {
                    // The buffered output goes out (`BIO_flush`).
                    // SAFETY: the live connection.
                    let _ = unsafe { flush(x) };
                }
                set(s, eds);
                return ret;
            }
            _ => {
                err::raise(ERR_LIB_SSL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, F);
                return 0;
            }
        }
        if eds == E::ConnectRetry {
            set(s, E::Connecting);
            // SAFETY: as above.
            if unsafe { rustyssl_private_SSL_connect(s) } <= 0 {
                set(s, E::ConnectRetry);
                return 0;
            }
            eds = E::WriteRetry;
        }
        if eds == E::WriteRetry {
            set(s, E::Writing);
            // No partial writes: the flush after the write may need retrying.
            let partial = {
                let mut st = x.state();
                let p = st.mode & SSL_MODE_ENABLE_PARTIAL_WRITE;
                st.mode &= !SSL_MODE_ENABLE_PARTIAL_WRITE;
                p
            };
            let mut tmp = 0usize;
            // SAFETY: as above.
            let ret = unsafe { write_internal(s, buf, num, &mut tmp, "SSL_write_ex") };
            x.state().mode |= partial;
            if ret <= 0 {
                set(s, E::WriteRetry);
                return 0;
            }
            set(s, E::WriteFlush);
        }
        // SAFETY: as above.
        if !matches!(unsafe { flush(x) }, Flush::Done) {
            return 0;
        }
        if !written.is_null() {
            // SAFETY: the caller's slot.
            unsafe { written.write(num) };
        }
        set(s, E::WriteRetry);
        1
    }
}

ffi_export! {
    /// Reads early data (a server): `SSL_READ_EARLY_DATA_SUCCESS` with `*readbytes` set,
    /// `SSL_READ_EARLY_DATA_FINISH` when there is no more (or none was accepted), or
    /// `SSL_READ_EARLY_DATA_ERROR`. The first call starts the handshake.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `buf` has room for `num` octets; `readbytes` writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_read_early_data(s: *mut SSL, buf: *mut c_void, num: usize, readbytes: *mut usize) -> c_int
    where failure = SSL_READ_EARLY_DATA_ERROR, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            err::raise(ERR_LIB_SSL, rustyssl_abi::ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, "SSL_read_early_data");
            return rustyssl_abi::SSL_READ_EARLY_DATA_ERROR;
        }
        const F: &str = "SSL_read_early_data";
        // SAFETY: the caller's guarantee.
        let server = unsafe { ssl(s) }.is_some_and(|x| x.state().server);
        let Some(mut eds) = state_of(s).filter(|_| server) else {
            err::raise(ERR_LIB_SSL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, F);
            return SSL_READ_EARLY_DATA_ERROR;
        };
        if eds == E::None {
            // SAFETY: as above.
            if unsafe { rustyssl_private_SSL_in_before(s) } == 0 {
                err::raise(ERR_LIB_SSL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, F);
                return SSL_READ_EARLY_DATA_ERROR;
            }
            eds = E::AcceptRetry;
        }
        if eds == E::AcceptRetry {
            set(s, E::Accepting);
            // SAFETY: as above.
            if unsafe { rustyssl_private_SSL_accept(s) } <= 0 {
                set(s, E::AcceptRetry);
                return SSL_READ_EARLY_DATA_ERROR;
            }
            eds = E::ReadRetry;
        }
        if eds != E::ReadRetry {
            err::raise(ERR_LIB_SSL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, F);
            return SSL_READ_EARLY_DATA_ERROR;
        }
        // SAFETY: as above.
        let accepted = unsafe { ssl(s) }.is_some_and(|x| {
            x.state().drv.tls.as_ref().is_some_and(|c| c.negotiated().early_data_status == SSL_EARLY_DATA_ACCEPTED)
        });
        if accepted {
            set(s, E::Reading);
            // SAFETY: as above.
            let ret = unsafe { rustyssl_private_SSL_read_ex(s, buf, num, readbytes) };
            // The state machine moves to FinishedReading at an EndOfEarlyData.
            if ret > 0 || state_of(s) != Some(E::FinishedReading) {
                set(s, E::ReadRetry);
                return if ret > 0 { SSL_READ_EARLY_DATA_SUCCESS } else { SSL_READ_EARLY_DATA_ERROR };
            }
        } else {
            set(s, E::FinishedReading);
        }
        if !readbytes.is_null() {
            // SAFETY: the caller's slot.
            unsafe { readbytes.write(0) };
        }
        SSL_READ_EARLY_DATA_FINISH
    }
}

ffi_export! {
    /// `SSL_write_ex` with flags: TLS takes none (`SSL_WRITE_FLAG_CONCLUDE` is QUIC's), so any
    /// flag fails with `SSL_R_UNSUPPORTED_WRITE_FLAG`. 1 with `*written` set, or 0.
    ///
    /// # Safety
    /// As for `SSL_write_ex`.
    pub unsafe extern "C" fn rustyssl_private_SSL_write_ex2(s: *mut SSL, buf: *const c_void, num: usize, flags: u64, written: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        const F: &str = "SSL_write_ex2";
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            let mut got = 0usize;
            // SAFETY: as above.
            let r = unsafe { super::quic::api::write(s, buf, num, flags, &mut got) };
            if !written.is_null() {
                // SAFETY: the caller's slot.
                unsafe { written.write(got) };
            }
            return r;
        }
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        {
            let mut st = x.state();
            if st.handshake_func.is_none() {
                drop(st);
                err::raise(ERR_LIB_SSL, SSL_R_UNINITIALIZED, F);
                return 0;
            }
            if st.shutdown & SSL_SENT_SHUTDOWN != 0 {
                st.rwstate = SSL_NOTHING;
                drop(st);
                err::raise(ERR_LIB_SSL, SSL_R_PROTOCOL_IS_SHUTDOWN, F);
                return 0;
            }
        }
        if flags != 0 {
            err::raise(ERR_LIB_SSL, SSL_R_UNSUPPORTED_WRITE_FLAG, F);
            return 0;
        }
        let mut got = 0usize;
        // SAFETY: the caller's guarantee.
        let r = unsafe { write_internal(s, buf, num, &mut got, F) };
        if r > 0 && !written.is_null() {
            // SAFETY: the caller's slot.
            unsafe { written.write(got) };
        }
        r.max(0)
    }
}
