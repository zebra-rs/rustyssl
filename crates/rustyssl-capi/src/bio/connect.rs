//! The connect BIO (`BIO_s_connect(3)`): resolves a host and service, connects to the first
//! address that accepts (blocking or not), and then reads and writes the socket. In datagram
//! mode (`BIO_set_sock_type(b, SOCK_DGRAM)`) it forwards to a datagram BIO on the connected
//! socket. A port of OpenSSL's `bss_conn.c`.
//!
//! The state machine calls the application's info callback after each state, so the state's
//! lock is never held across it, nor across any other call out.

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr;
use core::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use libc::{SOCK_DGRAM, SOCK_STREAM};
use rustyssl_abi::{
    BIO, BIO_ADDRINFO, BIO_C_DO_STATE_MACHINE, BIO_C_GET_CONNECT, BIO_C_GET_DGRAM_BIO,
    BIO_C_GET_FD, BIO_C_GET_SOCK_TYPE, BIO_C_SET_CONNECT, BIO_C_SET_CONNECT_MODE, BIO_C_SET_NBIO,
    BIO_C_SET_SOCK_TYPE, BIO_C_SET_TFO, BIO_CTRL_DGRAM_DETECT_PEER_ADDR, BIO_CTRL_DGRAM_GET_PEER,
    BIO_CTRL_DUP, BIO_CTRL_EOF, BIO_CTRL_FLUSH, BIO_CTRL_GET_CALLBACK, BIO_CTRL_GET_CLOSE,
    BIO_CTRL_GET_RPOLL_DESCRIPTOR, BIO_CTRL_GET_WPOLL_DESCRIPTOR, BIO_CTRL_PENDING, BIO_CTRL_RESET,
    BIO_CTRL_SET_CALLBACK, BIO_CTRL_SET_CLOSE, BIO_CTRL_WPENDING, BIO_FAMILY_IPANY,
    BIO_FAMILY_IPV4, BIO_FAMILY_IPV6, BIO_FLAGS_IN_EOF, BIO_FLAGS_IO_SPECIAL, BIO_FLAGS_RWS,
    BIO_FLAGS_SHOULD_RETRY, BIO_LOOKUP_CLIENT, BIO_METHOD, BIO_MSG, BIO_PARSE_PRIO_HOST,
    BIO_R_CONNECT_ERROR, BIO_R_LOOKUP_RETURNED_NOTHING, BIO_R_NBIO_CONNECT_ERROR,
    BIO_R_NO_HOSTNAME_OR_SERVICE_SPECIFIED, BIO_R_UNABLE_TO_CREATE_SOCKET,
    BIO_R_UNSUPPORTED_IP_FAMILY, BIO_RR_CONNECT, BIO_SOCK_KEEPALIVE, BIO_SOCK_NONBLOCK,
    BIO_SOCK_TFO, BIO_TYPE_CONNECT, BIO_info_cb, ERR_LIB_BIO, ERR_LIB_SYS,
    ERR_R_PASSED_NULL_PARAMETER, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED,
};

use super::accept::CString_;
use super::addr;
use super::method::{Builtin, Funcs};
use super::sock::{self, INVALID_SOCKET};
use super::state::{self, lock};
use super::{Bio, object};
use crate::ffi::{ffi_callback, ffi_export};
use crate::{err, errno};

// The states of OpenSSL's connect state machine.
const BIO_CONN_S_BEFORE: c_int = 1;
const BIO_CONN_S_GET_ADDR: c_int = 2;
const BIO_CONN_S_CREATE_SOCKET: c_int = 3;
const BIO_CONN_S_CONNECT: c_int = 4;
const BIO_CONN_S_OK: c_int = 5;
const BIO_CONN_S_BLOCKED_CONNECT: c_int = 6;
const BIO_CONN_S_CONNECT_ERROR: c_int = 7;

/// The state of a connect BIO (OpenSSL's `BIO_CONNECT`).
pub(crate) struct Connect {
    state: c_int,
    connect_family: c_int,
    connect_sock_type: c_int,
    param_hostname: CString_,
    param_service: CString_,
    connect_mode: c_int,
    tfo_first: bool,
    addr_first: *mut libc::addrinfo,
    addr_iter: *const libc::addrinfo,
    info_callback: BIO_info_cb,
    /// The datagram BIO on the socket, in datagram mode.
    dgram_bio: *mut BIO,
}

// SAFETY: the pointers are owned by the state (the lookup's result, the datagram BIO) or point
// into what it owns.
unsafe impl Send for Connect {}

impl Connect {
    fn free_lookup(&mut self) {
        // SAFETY: null or the state's own lookup result, freed once.
        unsafe { addr::BIO_ADDRINFO_free(self.addr_first.cast()) };
        self.addr_first = ptr::null_mut();
        self.addr_iter = ptr::null();
    }

    fn iter(&self) -> *const BIO_ADDRINFO {
        self.addr_iter.cast()
    }
}

impl Drop for Connect {
    fn drop(&mut self) {
        self.free_lookup();
        // SAFETY: null or the state's datagram BIO.
        unsafe { super::BIO_free(self.dgram_bio) };
    }
}

/// The connect BIO `b` and its state.
///
/// # Safety
/// `b` is null or a live BIO that outlives `'a`.
unsafe fn connect<'a>(b: *mut BIO) -> Option<(&'a Bio, Arc<Mutex<Connect>>)> {
    // SAFETY: the caller's guarantee.
    let object = unsafe { object(b) }?;
    Some((object, state::get::<Connect>(object)?))
}

ffi_callback! {
    /// Sets up a connect BIO with nothing to connect to yet.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn conn_new(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        object.init.store(0, Ordering::Relaxed);
        object.num.store(INVALID_SOCKET, Ordering::Relaxed);
        object.flags.store(0, Ordering::Relaxed);
        state::install(object, Connect {
            state: BIO_CONN_S_BEFORE,
            connect_family: BIO_FAMILY_IPANY,
            connect_sock_type: SOCK_STREAM,
            param_hostname: CString_::NONE,
            param_service: CString_::NONE,
            connect_mode: 0,
            tfo_first: false,
            addr_first: ptr::null_mut(),
            addr_iter: ptr::null(),
            info_callback: None,
            dgram_bio: ptr::null_mut(),
        });
        1
    }
}

/// OpenSSL's `conn_close_socket`: shuts down (once connected) and closes the socket.
fn close_socket(object: &Bio, state: &Mutex<Connect>) {
    let fd = object.num.load(Ordering::Relaxed);
    if fd != INVALID_SOCKET {
        if lock(state).state == BIO_CONN_S_OK {
            // SAFETY: the BIO's own socket.
            unsafe { libc::shutdown(fd, libc::SHUT_RDWR) };
        }
        // SAFETY: as above.
        unsafe { sock::BIO_closesocket(fd) };
        object.num.store(INVALID_SOCKET, Ordering::Relaxed);
    }
}

ffi_callback! {
    /// Frees a connect BIO, closing its socket unless `BIO_NOCLOSE`.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn conn_free(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((object, state)) = (unsafe { connect(b) }) else {
            return 0;
        };
        let dgram = core::mem::replace(&mut lock(&state).dgram_bio, ptr::null_mut());
        // SAFETY: null or the state's datagram BIO, freed once.
        unsafe { super::BIO_free(dgram) };
        if object.shutdown.load(Ordering::Relaxed) != 0 {
            close_socket(object, &state);
            object.flags.store(0, Ordering::Relaxed);
            object.init.store(0, Ordering::Relaxed);
        }
        drop(state);
        drop(state::remove::<Connect>(object));
        1
    }
}

/// The text of the host and service for error data (`%s` prints `<NULL>` for none).
fn host_service(state: &Mutex<Connect>) -> (String, String) {
    let s = lock(state);
    (s.param_hostname.text(), s.param_service.text())
}

/// OpenSSL's `conn_create_dgram_bio`: in datagram mode, a datagram BIO on the socket.
fn create_dgram_bio(object: &Bio, state: &Mutex<Connect>) -> bool {
    if lock(state).connect_sock_type != SOCK_DGRAM {
        return true;
    }
    // SAFETY: no preconditions; the connect BIO keeps the socket.
    let dgram = unsafe { super::dgram::BIO_new_dgram(object.num.load(Ordering::Relaxed), 0) };
    let mut s = lock(state);
    if dgram.is_null() {
        s.state = BIO_CONN_S_CONNECT_ERROR;
        return false;
    }
    // OpenSSL leaks the datagram BIO of an earlier connection; it's freed here.
    let old = core::mem::replace(&mut s.dgram_bio, dgram);
    drop(s);
    // SAFETY: null or the earlier datagram BIO, freed once.
    unsafe { super::BIO_free(old) };
    true
}

/// OpenSSL's `conn_state`: runs the state machine until connected, failed, or blocked, calling
/// the info callback after each state. Returns 1, 0 or less on failure, or -1 to retry.
///
/// # Safety
/// `b` is a live connect BIO.
#[expect(clippy::too_many_lines, reason = "one arm per state, as in OpenSSL")]
unsafe fn conn_state(b: *mut BIO, object: &Bio, state: &Mutex<Connect>) -> c_int {
    let mut ret: c_int = -1;
    let callback = lock(state).info_callback;
    let call = |ret: c_int| -> c_int {
        let current = lock(state).state;
        match callback {
            // SAFETY: the application's callback, which takes these arguments.
            Some(cb) => unsafe { cb(b, current, ret) },
            None => ret,
        }
    };
    loop {
        let current = lock(state).state;
        let exit = 'step: {
            match current {
                BIO_CONN_S_BEFORE => {
                    let (has_host, has_service) = {
                        let s = lock(state);
                        (
                            !s.param_hostname.ptr().is_null(),
                            !s.param_service.ptr().is_null(),
                        )
                    };
                    if !has_host && !has_service {
                        err::raise_with_text(
                            ERR_LIB_BIO,
                            BIO_R_NO_HOSTNAME_OR_SERVICE_SPECIFIED,
                            "conn_state",
                            "hostname=<NULL> service=<NULL>",
                        );
                        break 'step true;
                    }
                    lock(state).state = BIO_CONN_S_GET_ADDR;
                }
                BIO_CONN_S_GET_ADDR => {
                    let (family, sock_type, host, service) = {
                        let s = lock(state);
                        (
                            s.connect_family,
                            s.connect_sock_type,
                            s.param_hostname.ptr(),
                            s.param_service.ptr(),
                        )
                    };
                    let family = match family {
                        BIO_FAMILY_IPV6 => libc::AF_INET6,
                        BIO_FAMILY_IPV4 => libc::AF_INET,
                        BIO_FAMILY_IPANY => libc::AF_UNSPEC,
                        _ => {
                            err::raise(ERR_LIB_BIO, BIO_R_UNSUPPORTED_IP_FAMILY, "conn_state");
                            break 'step true;
                        }
                    };
                    let mut first = ptr::null_mut();
                    // SAFETY: the state's strings, which nothing frees during the lookup.
                    let ok = unsafe {
                        addr::BIO_lookup(
                            host,
                            service,
                            BIO_LOOKUP_CLIENT,
                            family,
                            sock_type,
                            &raw mut first,
                        )
                    };
                    let mut s = lock(state);
                    if ok == 0 {
                        break 'step true;
                    }
                    s.free_lookup();
                    s.addr_first = first.cast();
                    if first.is_null() {
                        drop(s);
                        err::raise(ERR_LIB_BIO, BIO_R_LOOKUP_RETURNED_NOTHING, "conn_state");
                        break 'step true;
                    }
                    s.addr_iter = s.addr_first;
                    s.state = BIO_CONN_S_CREATE_SOCKET;
                }
                BIO_CONN_S_CREATE_SOCKET => {
                    let iter = lock(state).iter();
                    // SAFETY: an entry of the state's lookup result, for each call.
                    let family = unsafe { addr::BIO_ADDRINFO_family(iter) };
                    // SAFETY: as above.
                    let socktype = unsafe { addr::BIO_ADDRINFO_socktype(iter) };
                    // SAFETY: as above.
                    let protocol = unsafe { addr::BIO_ADDRINFO_protocol(iter) };
                    // SAFETY: no preconditions.
                    ret = unsafe { sock::BIO_socket(family, socktype, protocol, 0) };
                    if ret == INVALID_SOCKET {
                        let (host, service) = host_service(state);
                        err::raise_with_text(
                            ERR_LIB_SYS,
                            errno::get(),
                            "conn_state",
                            &format!("calling socket({host}, {service})"),
                        );
                        err::raise(ERR_LIB_BIO, BIO_R_UNABLE_TO_CREATE_SOCKET, "conn_state");
                        break 'step true;
                    }
                    object.num.store(ret, Ordering::Relaxed);
                    lock(state).state = BIO_CONN_S_CONNECT;
                }
                BIO_CONN_S_CONNECT => {
                    object.clear_retry_flags();
                    // SAFETY: no preconditions.
                    unsafe { crate::err::ERR_set_mark() };
                    let (iter, mode) = {
                        let s = lock(state);
                        (s.iter(), s.connect_mode)
                    };
                    // SAFETY: an entry of the state's lookup result, for each call.
                    let socktype = unsafe { addr::BIO_ADDRINFO_socktype(iter) };
                    let opts = if socktype == SOCK_STREAM {
                        mode | BIO_SOCK_KEEPALIVE
                    } else {
                        mode
                    };
                    // SAFETY: as above.
                    let address = unsafe { addr::BIO_ADDRINFO_address(iter) };
                    // SAFETY: as above.
                    ret = unsafe {
                        sock::BIO_connect(object.num.load(Ordering::Relaxed), address, opts)
                    };
                    object.retry_reason.store(0, Ordering::Relaxed);
                    if ret == 0 {
                        // SAFETY: no preconditions.
                        if unsafe { sock::BIO_sock_should_retry(ret) } != 0 {
                            object.set_flags(BIO_FLAGS_IO_SPECIAL | BIO_FLAGS_SHOULD_RETRY);
                            lock(state).state = BIO_CONN_S_BLOCKED_CONNECT;
                            object.retry_reason.store(BIO_RR_CONNECT, Ordering::Relaxed);
                            // SAFETY: no preconditions.
                            unsafe { crate::err::ERR_pop_to_mark() };
                            break 'step true;
                        }
                        // SAFETY: as above.
                        let next = unsafe { addr::BIO_ADDRINFO_next(iter) };
                        lock(state).addr_iter = next.cast();
                        if !next.is_null() {
                            // SAFETY: the BIO's own socket.
                            unsafe { sock::BIO_closesocket(object.num.load(Ordering::Relaxed)) };
                            lock(state).state = BIO_CONN_S_CREATE_SOCKET;
                            // SAFETY: no preconditions.
                            unsafe { crate::err::ERR_pop_to_mark() };
                        } else {
                            // SAFETY: no preconditions.
                            unsafe { crate::err::ERR_clear_last_mark() };
                            let (host, service) = host_service(state);
                            err::raise_with_text(
                                ERR_LIB_SYS,
                                errno::get(),
                                "conn_state",
                                &format!("calling connect({host}, {service})"),
                            );
                            lock(state).state = BIO_CONN_S_CONNECT_ERROR;
                        }
                    } else {
                        // SAFETY: no preconditions.
                        unsafe { crate::err::ERR_clear_last_mark() };
                        if create_dgram_bio(object, state) {
                            lock(state).state = BIO_CONN_S_OK;
                        }
                    }
                }
                BIO_CONN_S_BLOCKED_CONNECT => {
                    let fd = object.num.load(Ordering::Relaxed);
                    // Wait until writable, without blocking, before asking for the error.
                    // SAFETY: no preconditions.
                    if unsafe { sock::BIO_socket_wait(fd, 0, libc_now()) } != 0 {
                        // SAFETY: no preconditions.
                        let i = unsafe { sock::BIO_sock_error(fd) };
                        if i != 0 {
                            object.clear_retry_flags();
                            let iter = lock(state).iter();
                            // SAFETY: an entry of the state's lookup result.
                            let next = unsafe { addr::BIO_ADDRINFO_next(iter) };
                            lock(state).addr_iter = next.cast();
                            if !next.is_null() {
                                // SAFETY: the BIO's own socket.
                                unsafe { sock::BIO_closesocket(fd) };
                                lock(state).state = BIO_CONN_S_CREATE_SOCKET;
                            } else {
                                let (host, service) = host_service(state);
                                err::raise_with_text(
                                    ERR_LIB_SYS,
                                    i,
                                    "conn_state",
                                    &format!("calling connect({host}, {service})"),
                                );
                                err::raise(ERR_LIB_BIO, BIO_R_NBIO_CONNECT_ERROR, "conn_state");
                                ret = 0;
                                break 'step true;
                            }
                        } else if create_dgram_bio(object, state) {
                            lock(state).state = BIO_CONN_S_OK;
                        }
                    }
                }
                BIO_CONN_S_CONNECT_ERROR => {
                    err::raise(ERR_LIB_BIO, BIO_R_CONNECT_ERROR, "conn_state");
                    ret = 0;
                    break 'step true;
                }
                BIO_CONN_S_OK => {
                    ret = 1;
                    break 'step true;
                }
                _ => break 'step true,
            }
            false
        };
        if exit {
            return call(ret);
        }
        if callback.is_some() {
            ret = call(ret);
            if ret == 0 {
                return ret;
            }
        }
    }
}

/// `time(NULL)`.
fn libc_now() -> libc::time_t {
    // SAFETY: a null pointer asks only for the result.
    unsafe { libc::time(ptr::null_mut()) }
}

/// Runs the state machine unless connected. Returns 1 when connected, else its result.
///
/// # Safety
/// `b` is a live connect BIO.
unsafe fn ensure_connected(b: *mut BIO, object: &Bio, state: &Mutex<Connect>) -> c_int {
    if lock(state).state == BIO_CONN_S_OK {
        return 1;
    }
    // SAFETY: the caller's guarantee.
    unsafe { conn_state(b, object, state) }
}

/// Forwards a read or write to the datagram BIO, copying its retry flags.
fn through_dgram(object: &Bio, dgram: *mut BIO, op: impl FnOnce() -> c_int) -> c_int {
    object.clear_retry_flags();
    let ret = op();
    // SAFETY: the state's datagram BIO, live while it holds it.
    if let Some(d) = unsafe { object_of(dgram) } {
        object.set_flags(d.flags() & (BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY));
    }
    ret
}

/// The object of a BIO the state owns.
///
/// # Safety
/// `b` is null or live.
unsafe fn object_of<'a>(b: *mut BIO) -> Option<&'a Bio> {
    // SAFETY: the caller's guarantee.
    unsafe { object(b) }
}

ffi_callback! {
    /// Reads from the connection, connecting first.
    ///
    /// # Safety
    /// `b` is a live BIO; `out` is null or valid for `len` bytes of writes.
    pub(crate) unsafe extern "C" fn conn_read(b: *mut BIO, out: *mut c_char, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((object, state)) = (unsafe { connect(b) }) else {
            return 0;
        };
        let mut ret = 0;
        if lock(&state).state != BIO_CONN_S_OK {
            // SAFETY: as above.
            ret = unsafe { conn_state(b, object, &state) };
            if ret <= 0 {
                return ret;
            }
        }
        let dgram = lock(&state).dgram_bio;
        if !dgram.is_null() {
            // SAFETY: the state's datagram BIO; the caller's buffer.
            return through_dgram(object, dgram, || unsafe { super::BIO_read(dgram, out.cast(), len) });
        }
        if out.is_null() {
            return ret;
        }
        // SAFETY: the caller's buffer.
        unsafe { sock::read_socket(object, object.num.load(Ordering::Relaxed), out, len) }
    }
}

ffi_callback! {
    /// Writes to the connection, connecting first.
    ///
    /// # Safety
    /// `b` is a live BIO; `data` is valid for `len` bytes of reads.
    pub(crate) unsafe extern "C" fn conn_write(b: *mut BIO, data: *const c_char, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((object, state)) = (unsafe { connect(b) }) else {
            return 0;
        };
        // SAFETY: as above.
        let ret = unsafe { ensure_connected(b, object, &state) };
        if ret <= 0 {
            return ret;
        }
        let dgram = lock(&state).dgram_bio;
        if !dgram.is_null() {
            // SAFETY: the state's datagram BIO; the caller's data.
            return through_dgram(object, dgram, || unsafe { super::BIO_write(dgram, data.cast(), len) });
        }
        // SAFETY: the caller's data.
        unsafe { sock::write_socket(object, object.num.load(Ordering::Relaxed), data, len) }
    }
}

ffi_callback! {
    /// Writes a string to the connection.
    ///
    /// # Safety
    /// `b` is a live BIO; `text` is a NUL-terminated string.
    pub(crate) unsafe extern "C" fn conn_puts(b: *mut BIO, text: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        if text.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let len = unsafe { CStr::from_ptr(text) }.count_bytes();
        let len = super::wrap_int(c_long::try_from(len).unwrap_or(c_long::MAX));
        // SAFETY: as above.
        unsafe { conn_write(b, text, len) }
    }
}

ffi_callback! {
    /// Reads a line from the connection a byte at a time, connecting first.
    ///
    /// # Safety
    /// `b` is a live BIO; `buf` is null or valid for `size` bytes of writes.
    pub(crate) unsafe extern "C" fn conn_gets(b: *mut BIO, buf: *mut c_char, size: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        if buf.is_null() {
            err::raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER, "conn_gets");
            return -1;
        }
        if size <= 0 {
            err::raise(ERR_LIB_BIO, rustyssl_abi::BIO_R_INVALID_ARGUMENT, "conn_gets");
            return -1;
        }
        // SAFETY: the caller's guarantee: at least one byte.
        unsafe { buf.write(0) };
        // SAFETY: the caller's guarantee.
        let Some((object, state)) = (unsafe { connect(b) }) else {
            err::raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER, "conn_gets");
            return -1;
        };
        // SAFETY: as above.
        let mut ret = unsafe { ensure_connected(b, object, &state) };
        if ret <= 0 {
            return ret;
        }
        if !lock(&state).dgram_bio.is_null() {
            err::raise(ERR_LIB_BIO, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, "conn_gets");
            return -1;
        }
        let fd = object.num.load(Ordering::Relaxed);
        errno::set(0);
        let mut at = buf;
        let mut left = size;
        while left > 1 {
            left -= 1;
            // SAFETY: inside the caller's buffer, before the byte kept for the NUL.
            ret = c_int::try_from(unsafe { libc::read(fd, at.cast(), 1) }).unwrap_or(-1);
            object.clear_retry_flags();
            if ret <= 0 {
                // SAFETY: no preconditions.
                if unsafe { sock::BIO_sock_should_retry(ret) } != 0 {
                    object.set_retry_read();
                } else if ret == 0 {
                    object.set_flags(BIO_FLAGS_IN_EOF);
                }
                break;
            }
            // SAFETY: the byte just read.
            let c = unsafe { at.cast::<u8>().read() };
            at = at.wrapping_add(1);
            if c == b'\n' {
                break;
            }
        }
        // SAFETY: inside the caller's buffer.
        unsafe { at.write(0) };
        let read = c_int::try_from(at.addr() - buf.addr()).unwrap_or(c_int::MAX);
        if ret > 0 || object.flags() & BIO_FLAGS_IN_EOF != 0 { read } else { ret }
    }
}

/// Gives `ptr` (a `const char **`) a string pointer.
///
/// # Safety
/// `ptr` is a `const char **`.
unsafe fn give(ptr: *mut c_void, value: *const c_char) {
    // SAFETY: the caller's guarantee.
    unsafe { ptr.cast::<*const c_char>().write(value) };
}

ffi_callback! {
    /// The connect BIO's controls: the host, service, address, family, mode, and socket type to
    /// connect with, connecting (`BIO_do_connect`), the socket, the peer address, poll
    /// descriptors, the info callback, and the datagram BIO.
    ///
    /// # Safety
    /// `b` is a live BIO; `ptr` is what the command expects.
    pub(crate) unsafe extern "C" fn conn_ctrl(b: *mut BIO, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((object, state)) = (unsafe { connect(b) }) else {
            return 0;
        };
        match cmd {
            BIO_CTRL_RESET => {
                lock(&state).state = BIO_CONN_S_BEFORE;
                close_socket(object, &state);
                lock(&state).free_lookup();
                object.flags.store(0, Ordering::Relaxed);
                0
            }
            // SAFETY: the caller's guarantee.
            BIO_C_DO_STATE_MACHINE => c_long::from(unsafe { ensure_connected(b, object, &state) }),
            BIO_C_GET_CONNECT => {
                if ptr.is_null() {
                    return 0;
                }
                let s = lock(&state);
                match num {
                    // SAFETY: the caller's guarantee: a `const char **`, for each.
                    0 => unsafe { give(ptr, s.param_hostname.ptr()) },
                    // SAFETY: as above.
                    1 => unsafe { give(ptr, s.param_service.ptr()) },
                    2 => {
                        // SAFETY: null or an entry of the state's lookup result.
                        let address = unsafe { addr::BIO_ADDRINFO_address(s.iter()) };
                        // SAFETY: as above.
                        unsafe { give(ptr, address.cast()) };
                    }
                    3 => {
                        // SAFETY: as above.
                        return match unsafe { addr::BIO_ADDRINFO_family(s.iter()) } {
                            libc::AF_INET6 => c_long::from(BIO_FAMILY_IPV6),
                            libc::AF_INET => c_long::from(BIO_FAMILY_IPV4),
                            0 => c_long::from(s.connect_family),
                            _ => -1,
                        };
                    }
                    4 => return c_long::from(s.connect_mode),
                    _ => return 0,
                }
                1
            }
            BIO_C_SET_CONNECT => {
                if ptr.is_null() {
                    return 1;
                }
                object.init.store(1, Ordering::Relaxed);
                match num {
                    0 => {
                        let mut s = lock(&state);
                        s.param_hostname.set(ptr::null_mut());
                        let mut host = ptr::null_mut();
                        let mut service = s.param_service.ptr();
                        // SAFETY: the caller's string; the outputs are locals.
                        let ret = unsafe { addr::BIO_parse_hostserv(ptr.cast(), &raw mut host, &raw mut service, BIO_PARSE_PRIO_HOST) };
                        s.param_hostname.0 = host;
                        if service != s.param_service.ptr() {
                            s.param_service.set(service);
                        }
                        c_long::from(ret)
                    }
                    1 => {
                        // SAFETY: the caller's string.
                        let copy = unsafe { crate::string::CRYPTO_strdup(ptr.cast(), c"bss_conn.c".as_ptr(), 0) };
                        lock(&state).param_service.set(copy);
                        c_long::from(!copy.is_null())
                    }
                    2 => {
                        let address = ptr.cast::<rustyssl_abi::BIO_ADDR>();
                        // SAFETY: the caller's address, for each call.
                        let host = unsafe { addr::BIO_ADDR_hostname_string(address, 1) };
                        // SAFETY: as above.
                        let service = unsafe { addr::BIO_ADDR_service_string(address, 1) };
                        let ok = !host.is_null() && !service.is_null();
                        let mut s = lock(&state);
                        if ok {
                            s.param_hostname.set(host);
                            s.param_service.set(service);
                            s.free_lookup();
                        } else {
                            drop(CString_(host));
                            drop(CString_(service));
                        }
                        c_long::from(ok)
                    }
                    3 => {
                        // SAFETY: the caller's guarantee: an `int`.
                        lock(&state).connect_family = unsafe { ptr.cast::<c_int>().read() };
                        1
                    }
                    _ => 0,
                }
            }
            BIO_C_SET_SOCK_TYPE => {
                let mut s = lock(&state);
                let wanted = super::wrap_int(num);
                if (num != c_long::from(SOCK_STREAM) && num != c_long::from(SOCK_DGRAM)) || s.state >= BIO_CONN_S_GET_ADDR {
                    return 0;
                }
                s.connect_sock_type = wanted;
                1
            }
            BIO_C_GET_SOCK_TYPE => c_long::from(lock(&state).connect_sock_type),
            BIO_C_GET_DGRAM_BIO => {
                let dgram = lock(&state).dgram_bio;
                if dgram.is_null() || ptr.is_null() {
                    return 0;
                }
                // SAFETY: the caller's guarantee: a `BIO **`.
                unsafe { ptr.cast::<*mut BIO>().write(dgram) };
                1
            }
            BIO_CTRL_DGRAM_GET_PEER | BIO_CTRL_DGRAM_DETECT_PEER_ADDR => {
                // Best effort.
                // SAFETY: the caller's guarantee.
                unsafe { ensure_connected(b, object, &state) };
                let s = lock(&state);
                if s.state < BIO_CONN_S_CREATE_SOCKET || s.addr_iter.is_null() {
                    return 0;
                }
                // SAFETY: an entry of the state's lookup result.
                let address = unsafe { addr::BIO_ADDRINFO_address(s.iter()) };
                if address.is_null() {
                    return 0;
                }
                // SAFETY: an address.
                let size = c_long::from(unsafe { addr::sockaddr_size(address.cast()) });
                let count = if num <= 0 || num > size { size } else { num };
                if !ptr.is_null() {
                    // SAFETY: the caller's guarantee: room for `count` bytes; the entry's
                    // address holds its family's size.
                    unsafe { ptr::copy_nonoverlapping(address.cast::<u8>(), ptr.cast::<u8>(), usize::try_from(count).unwrap_or(0)) };
                }
                count
            }
            BIO_CTRL_GET_RPOLL_DESCRIPTOR | BIO_CTRL_GET_WPOLL_DESCRIPTOR => {
                // SAFETY: the caller's guarantee.
                unsafe { ensure_connected(b, object, &state) };
                if lock(&state).state < BIO_CONN_S_CREATE_SOCKET {
                    return 0;
                }
                // SAFETY: the caller's guarantee: a poll descriptor.
                unsafe { sock::poll_descriptor(ptr, object.num.load(Ordering::Relaxed)) }
            }
            BIO_C_SET_NBIO => {
                let dgram = {
                    let mut s = lock(&state);
                    if num != 0 {
                        s.connect_mode |= BIO_SOCK_NONBLOCK;
                    } else {
                        s.connect_mode &= !BIO_SOCK_NONBLOCK;
                    }
                    s.dgram_bio
                };
                if dgram.is_null() {
                    return 1;
                }
                // SAFETY: the state's datagram BIO.
                unsafe { super::BIO_ctrl(dgram, BIO_C_SET_NBIO, num, ptr::null_mut()) }
            }
            BIO_C_SET_TFO => {
                let mut s = lock(&state);
                if num != 0 {
                    s.connect_mode |= BIO_SOCK_TFO;
                    s.tfo_first = true;
                } else {
                    s.connect_mode &= !BIO_SOCK_TFO;
                    s.tfo_first = false;
                }
                1
            }
            BIO_C_SET_CONNECT_MODE => {
                let mut s = lock(&state);
                s.connect_mode = super::wrap_int(num);
                s.tfo_first = num & c_long::from(BIO_SOCK_TFO) != 0;
                1
            }
            BIO_C_GET_FD => {
                if object.init.load(Ordering::Relaxed) == 0 {
                    return -1;
                }
                let fd = object.num.load(Ordering::Relaxed);
                if !ptr.is_null() {
                    // SAFETY: the caller's guarantee: an `int`.
                    unsafe { ptr.cast::<c_int>().write(fd) };
                }
                c_long::from(fd)
            }
            BIO_CTRL_GET_CLOSE => c_long::from(object.shutdown.load(Ordering::Relaxed)),
            BIO_CTRL_SET_CLOSE => {
                object.shutdown.store(super::wrap_int(num), Ordering::Relaxed);
                1
            }
            BIO_CTRL_PENDING | BIO_CTRL_WPENDING => 0,
            BIO_CTRL_FLUSH => 1,
            BIO_CTRL_DUP => {
                let copy = ptr.cast::<BIO>();
                let (host, service, family, mode, callback) = {
                    let s = lock(&state);
                    (s.param_hostname.ptr(), s.param_service.ptr(), s.connect_family, s.connect_mode, s.info_callback)
                };
                // SAFETY: BIO_dup_chain passes the new BIO; the strings are the state's, for
                // each call below.
                unsafe {
                    if !host.is_null() {
                        super::BIO_ctrl(copy, BIO_C_SET_CONNECT, 0, host.cast());
                    }
                }
                // SAFETY: as above.
                unsafe {
                    if !service.is_null() {
                        super::BIO_ctrl(copy, BIO_C_SET_CONNECT, 1, service.cast());
                    }
                }
                // SAFETY: as above.
                unsafe { super::BIO_int_ctrl(copy, BIO_C_SET_CONNECT, 3, family) };
                // SAFETY: as above.
                unsafe { super::BIO_ctrl(copy, BIO_C_SET_CONNECT_MODE, c_long::from(mode), ptr::null_mut()) };
                // SAFETY: as above.
                unsafe { super::BIO_callback_ctrl(copy, BIO_CTRL_SET_CALLBACK, callback) };
                1
            }
            BIO_CTRL_SET_CALLBACK => 0,
            BIO_CTRL_GET_CALLBACK => {
                if !ptr.is_null() {
                    // SAFETY: the caller's guarantee: a `BIO_info_cb **`.
                    unsafe { ptr.cast::<BIO_info_cb>().write(lock(&state).info_callback) };
                }
                1
            }
            BIO_CTRL_EOF => c_long::from(object.flags() & BIO_FLAGS_IN_EOF != 0),
            _ => 0,
        }
    }
}

ffi_callback! {
    /// Sets the info callback (`BIO_set_info_callback`).
    ///
    /// # Safety
    /// `b` is a live BIO.
    pub(crate) unsafe extern "C" fn conn_callback_ctrl(b: *mut BIO, cmd: c_int, fp: BIO_info_cb) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((_, state)) = (unsafe { connect(b) }) else {
            return 0;
        };
        if cmd != BIO_CTRL_SET_CALLBACK {
            return 0;
        }
        lock(&state).info_callback = fp;
        1
    }
}

/// The shared body of the message functions: forwarded to the datagram BIO.
///
/// # Safety
/// As for `BIO_sendmmsg`.
unsafe fn mmsg(
    b: *mut BIO,
    msg: *mut BIO_MSG,
    stride: usize,
    num_msg: usize,
    flags: u64,
    processed: *mut usize,
    send: bool,
) -> c_int {
    let set_zero = || {
        if !processed.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { processed.write(0) };
        }
    };
    // SAFETY: the caller's guarantee.
    let Some((object, state)) = (unsafe { connect(b) }) else {
        set_zero();
        err::raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER, "conn_sendmmsg");
        return 0;
    };
    // SAFETY: as above.
    if unsafe { ensure_connected(b, object, &state) } <= 0 {
        set_zero();
        return 0;
    }
    let dgram = lock(&state).dgram_bio;
    if dgram.is_null() {
        set_zero();
        err::raise(
            ERR_LIB_BIO,
            ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED,
            if send {
                "conn_sendmmsg"
            } else {
                "conn_recvmmsg"
            },
        );
        return 0;
    }
    if send {
        // SAFETY: the state's datagram BIO; the caller's messages.
        unsafe { super::BIO_sendmmsg(dgram, msg, stride, num_msg, flags, processed) }
    } else {
        // SAFETY: as above.
        unsafe { super::BIO_recvmmsg(dgram, msg, stride, num_msg, flags, processed) }
    }
}

ffi_callback! {
    /// Sends messages through the datagram BIO, connecting first.
    ///
    /// # Safety
    /// As for `BIO_sendmmsg`.
    pub(crate) unsafe extern "C" fn conn_sendmmsg(b: *mut BIO, msg: *mut BIO_MSG, stride: usize, num_msg: usize, flags: u64, processed: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { mmsg(b, msg, stride, num_msg, flags, processed, true) }
    }
}

ffi_callback! {
    /// Receives messages through the datagram BIO, connecting first.
    ///
    /// # Safety
    /// As for `BIO_recvmmsg`.
    pub(crate) unsafe extern "C" fn conn_recvmmsg(b: *mut BIO, msg: *mut BIO_MSG, stride: usize, num_msg: usize, flags: u64, processed: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { mmsg(b, msg, stride, num_msg, flags, processed, false) }
    }
}

static CONNECT: Builtin = Builtin::new(BIO_TYPE_CONNECT, c"socket connect", || Funcs {
    bputs: Some(conn_puts),
    bgets: Some(conn_gets),
    ctrl: Some(conn_ctrl),
    create: Some(conn_new),
    destroy: Some(conn_free),
    callback_ctrl: Some(conn_callback_ctrl),
    bsendmmsg: Some(conn_sendmmsg),
    brecvmmsg: Some(conn_recvmmsg),
    ..Funcs::classic(conn_write, conn_read)
});

ffi_export! {
    /// Returns the connect BIO's method.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_s_connect() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        CONNECT.get()
    }
}

ffi_export! {
    /// Returns a connect BIO for `str` (`host:service`, or a host), or null.
    ///
    /// # Safety
    /// `str` is a NUL-terminated string.
    pub unsafe extern "C" fn BIO_new_connect(str: *const c_char) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        // SAFETY: the built-in method.
        let b = unsafe { super::BIO_new(CONNECT.get()) };
        if b.is_null() {
            return b;
        }
        // SAFETY: a live connect BIO; BIO_set_conn_hostname passes the string.
        if unsafe { super::BIO_ctrl(b, BIO_C_SET_CONNECT, 0, str.cast_mut().cast()) } != 0 {
            return b;
        }
        // SAFETY: made above, freed once.
        unsafe { super::BIO_free(b) };
        ptr::null_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: OpenSSL writes the datagram BIO through a null pointer, and copies a
    /// negative (huge) count of the peer address.
    #[test]
    fn null_and_negative_arguments_are_safe() {
        // SAFETY: the built-in method.
        let b = unsafe { super::super::BIO_new(CONNECT.get()) };
        // SAFETY: a live BIO; null is refused.
        let ret = unsafe { super::super::BIO_ctrl(b, BIO_C_GET_DGRAM_BIO, 0, ptr::null_mut()) };
        assert_eq!(ret, 0);
        // SAFETY: as above; without a lookup there's no peer to copy.
        let ret =
            unsafe { super::super::BIO_ctrl(b, BIO_CTRL_DGRAM_GET_PEER, -1, ptr::null_mut()) };
        assert_eq!(ret, 0);
        // SAFETY: made above, freed once.
        unsafe { super::super::BIO_free(b) };
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }
}
