//! The socket helpers (`BIO_socket(3)`, `BIO_connect(3)`, `BIO_listen(3)`, `BIO_sock_init`,
//! ...), the socket BIO (`BIO_s_socket(3)`), and waiting on a BIO (`BIO_wait`,
//! `BIO_do_connect_retry`): ports of OpenSSL's `bio_sock.c`, `bio_sock2.c`, `bss_sock.c`, and
//! part of `bio_lib.c`, on Unix.
//!
//! Failures raise what OpenSSL raises: the system error with the call in the data (`calling
//! socket()`), then the BIO reason. TCP Fast Open (`BIO_SOCK_TFO`) follows OpenSSL's per-platform
//! paths: `TCP_FASTOPEN_CONNECT` and `TCP_FASTOPEN` on Linux; on macOS the
//! `net.inet.tcp.fastopen` sysctl, `connectx`, and `TCP_FASTOPEN`.

use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_uint, c_ushort, c_void};
use core::mem::size_of;
use core::ptr;
use core::sync::atomic::Ordering;

use libc::{
    AF_INET, AF_INET6, IPPROTO_TCP, SOCK_DGRAM, SOCK_STREAM, SOL_SOCKET, socklen_t, time_t,
};
use rustyssl_abi::{
    BIO, BIO_ADDR, BIO_C_DO_STATE_MACHINE, BIO_C_GET_CONNECT, BIO_C_GET_FD, BIO_C_SET_CONNECT,
    BIO_C_SET_FD, BIO_C_SET_NBIO, BIO_CTRL_DUP, BIO_CTRL_EOF, BIO_CTRL_FLUSH, BIO_CTRL_GET_CLOSE,
    BIO_CTRL_GET_RPOLL_DESCRIPTOR, BIO_CTRL_GET_WPOLL_DESCRIPTOR, BIO_CTRL_RESET,
    BIO_CTRL_SET_CLOSE, BIO_FLAGS_IN_EOF, BIO_FLAGS_READ, BIO_LOOKUP_SERVER, BIO_METHOD,
    BIO_PARSE_PRIO_SERV, BIO_POLL_DESCRIPTOR, BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD, BIO_R_ACCEPT_ERROR,
    BIO_R_ADDRINFO_ADDR_IS_NOT_AF_INET, BIO_R_CONNECT_ERROR, BIO_R_CONNECT_TIMEOUT,
    BIO_R_GETHOSTBYNAME_ADDR_IS_NOT_AF_INET, BIO_R_GETSOCKNAME_ERROR,
    BIO_R_GETSOCKNAME_TRUNCATED_ADDRESS, BIO_R_GETTING_SOCKTYPE, BIO_R_INVALID_SOCKET,
    BIO_R_LISTEN_V6_ONLY, BIO_R_NBIO_CONNECT_ERROR, BIO_R_NO_PORT_DEFINED, BIO_R_TRANSFER_ERROR,
    BIO_R_TRANSFER_TIMEOUT, BIO_R_UNABLE_TO_BIND_SOCKET, BIO_R_UNABLE_TO_CREATE_SOCKET,
    BIO_R_UNABLE_TO_KEEPALIVE, BIO_R_UNABLE_TO_LISTEN_SOCKET, BIO_R_UNABLE_TO_NODELAY,
    BIO_R_UNABLE_TO_REUSEADDR, BIO_R_UNABLE_TO_TFO, BIO_R_UNKNOWN_INFO_TYPE, BIO_SOCK_INFO_ADDRESS,
    BIO_SOCK_KEEPALIVE, BIO_SOCK_NODELAY, BIO_SOCK_NONBLOCK, BIO_SOCK_REUSEADDR, BIO_SOCK_TFO,
    BIO_SOCK_V6_ONLY, BIO_TYPE_SOCKET, BIO_sock_info_type, BIO_sock_info_u, ERR_LIB_BIO,
    ERR_LIB_SYS, ERR_R_BIO_LIB, ERR_R_PASSED_NULL_PARAMETER, ERR_R_SYS_LIB, hostent,
};

use super::addr::{self, Addr};
use super::method::{Builtin, Funcs};
use super::state::{self, lock};
use super::{Bio, object};
use crate::ffi::{ffi_callback, ffi_export};
use crate::{err, errno, mem};

/// OpenSSL's `INVALID_SOCKET` on Unix.
pub(crate) const INVALID_SOCKET: c_int = -1;

/// OpenSSL's `MAX_LISTEN`: the listen backlog, and Linux's TCP Fast Open queue.
const MAX_LISTEN: c_int = libc::SOMAXCONN;

/// Raises a system error for the failed `call` (`calling call()`) with `errno`, then, unless
/// it's 0, `reason` from the BIO library.
#[track_caller]
fn raise_sys(call: &str, reason: c_int, function: &str) {
    err::raise_with_text(
        ERR_LIB_SYS,
        errno::get(),
        function,
        &format!("calling {call}()"),
    );
    if reason != 0 {
        err::raise(ERR_LIB_BIO, reason, function);
    }
}

/// `setsockopt` of an `int`. Returns whether it succeeded.
fn set_int_option(sock: c_int, level: c_int, name: c_int, value: c_int) -> bool {
    let len = socklen_t::try_from(size_of::<c_int>()).unwrap_or(0);
    // SAFETY: the value is a local `int` of that length.
    unsafe { libc::setsockopt(sock, level, name, (&raw const value).cast(), len) == 0 }
}

ffi_export! {
    /// Sets up sockets: nothing to do on Unix. Returns 1.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_sock_init() -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        1
    }
}

ffi_export! {
    /// The socket's pending error (`SO_ERROR`), or `errno` if it can't be read.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_sock_error(sock: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        let mut value: c_int = 0;
        let mut len = socklen_t::try_from(size_of::<c_int>()).unwrap_or(0);
        // SAFETY: the value and its length are locals.
        let ret = unsafe { libc::getsockopt(sock, SOL_SOCKET, libc::SO_ERROR, (&raw mut value).cast(), &raw mut len) };
        if ret < 0 { errno::get() } else { value }
    }
}

ffi_export! {
    /// `ioctl` on a socket; on failure, raises the system error. Returns what `ioctl` does.
    ///
    /// # Safety
    /// `arg` is what the request `type_` expects.
    pub unsafe extern "C" fn BIO_socket_ioctl(fd: c_int, type_: c_long, arg: *mut c_void) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // The request as C converts the `long` to `ioctl`'s request type.
        let request = u64::from_ne_bytes(type_.to_ne_bytes());
        #[cfg(target_os = "linux")]
        let request = request as libc::Ioctl;
        // SAFETY: the caller's guarantee.
        let ret = unsafe { libc::ioctl(fd, request as _, arg) };
        if ret < 0 {
            raise_sys("ioctlsocket", 0, "BIO_socket_ioctl");
        }
        ret
    }
}

ffi_export! {
    /// Makes a socket non-blocking (`mode` not 0) or blocking, with `FIONBIO`. Returns 1, or 0
    /// with the system error raised.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_socket_nbio(s: c_int, mode: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        let mut on = mode;
        let request = c_long::from_ne_bytes(libc::FIONBIO.to_ne_bytes());
        // SAFETY: FIONBIO takes a pointer to an `int`.
        c_int::from(unsafe { BIO_socket_ioctl(s, request, (&raw mut on).cast()) } == 0)
    }
}

ffi_export! {
    /// Sets or clears `TCP_NODELAY`. Returns whether it succeeded.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_set_tcp_ndelay(s: c_int, on: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        c_int::from(set_int_option(s, IPPROTO_TCP, libc::TCP_NODELAY, on))
    }
}

ffi_export! {
    /// With `BIO_SOCK_INFO_ADDRESS`, stores the socket's local address (`getsockname`) in
    /// `info->addr`. Returns 1, or 0 with an error.
    ///
    /// # Safety
    /// `info` is valid, with `info->addr` a whole `BIO_ADDR`, for that type.
    pub unsafe extern "C" fn BIO_sock_info(sock: c_int, type_: BIO_sock_info_type, info: *mut BIO_sock_info_u) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        if type_ != BIO_SOCK_INFO_ADDRESS {
            err::raise(ERR_LIB_BIO, BIO_R_UNKNOWN_INFO_TYPE, "BIO_sock_info");
            return 0;
        }
        if info.is_null() {
            err::raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER, "BIO_sock_info");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let info = unsafe { info.read() };
        // SAFETY: the address member is the one for this type.
        let ap = unsafe { info.addr };
        if ap.is_null() {
            err::raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER, "BIO_sock_info");
            return 0;
        }
        let mut len = socklen_t::try_from(size_of::<Addr>()).unwrap_or(0);
        // SAFETY: as above: a whole BIO_ADDR, of `len` bytes.
        if unsafe { libc::getsockname(sock, ap.cast(), &raw mut len) } == -1 {
            raise_sys("getsockname", BIO_R_GETSOCKNAME_ERROR, "BIO_sock_info");
            return 0;
        }
        if usize::try_from(len).unwrap_or(usize::MAX) > size_of::<Addr>() {
            err::raise(ERR_LIB_BIO, BIO_R_GETSOCKNAME_TRUNCATED_ADDRESS, "BIO_sock_info");
            return 0;
        }
        1
    }
}

/// The current time, as C's `time(NULL)`.
fn now() -> time_t {
    // SAFETY: a null pointer asks only for the result.
    unsafe { libc::time(ptr::null_mut()) }
}

ffi_export! {
    /// Waits with `poll` until `fd` is readable (`for_read` not 0) or writable, at most until
    /// `max_time` (seconds since the epoch; 0 doesn't wait). Returns 1 when ready (or for 0),
    /// 0 on timeout, or -1 on error (and for a negative `fd`).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_socket_wait(fd: c_int, for_read: c_int, max_time: time_t) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        if fd < 0 {
            return -1;
        }
        if max_time == 0 {
            return 1;
        }
        let now = now();
        if max_time < now {
            return 0;
        }
        let mut poll = libc::pollfd {
            fd,
            events: if for_read != 0 { libc::POLLIN } else { libc::POLLOUT },
            revents: 0,
        };
        // OpenSSL converts the seconds left to `int` and multiplies by 1000 in `int`.
        let seconds = super::wrap_int(c_long::try_from(max_time - now).unwrap_or(c_long::MAX));
        let timeout = seconds.wrapping_mul(1000);
        // SAFETY: one local pollfd.
        unsafe { libc::poll(&raw mut poll, 1, timeout) }
    }
}

ffi_export! {
    /// Opens a socket. Returns it, or `INVALID_SOCKET` (-1) with the error raised.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_socket(domain: c_int, socktype: c_int, protocol: c_int, options: c_int) -> c_int
    where failure = INVALID_SOCKET, library = ERR_LIB_BIO
    {
        let _ = options;
        // SAFETY: no preconditions.
        let sock = unsafe { libc::socket(domain, socktype, protocol) };
        if sock == -1 {
            raise_sys("socket", BIO_R_UNABLE_TO_CREATE_SOCKET, "BIO_socket");
            return INVALID_SOCKET;
        }
        sock
    }
}

/// Sets `BIO_SOCK_NONBLOCK`, `BIO_SOCK_KEEPALIVE`, and `BIO_SOCK_NODELAY` from `options`, as
/// `BIO_connect` and `BIO_listen` do first. Returns whether all succeeded.
fn apply_options(sock: c_int, options: c_int, function: &str) -> bool {
    // SAFETY: no preconditions.
    if unsafe { BIO_socket_nbio(sock, c_int::from(options & BIO_SOCK_NONBLOCK != 0)) } == 0 {
        return false;
    }
    if options & BIO_SOCK_KEEPALIVE != 0 && !set_int_option(sock, SOL_SOCKET, libc::SO_KEEPALIVE, 1)
    {
        raise_sys("setsockopt", BIO_R_UNABLE_TO_KEEPALIVE, function);
        return false;
    }
    if options & BIO_SOCK_NODELAY != 0 && !set_int_option(sock, IPPROTO_TCP, libc::TCP_NODELAY, 1) {
        raise_sys("setsockopt", BIO_R_UNABLE_TO_NODELAY, function);
        return false;
    }
    true
}

/// macOS's TCP Fast Open switch: whether the `net.inet.tcp.fastopen` sysctl has `flag` (1 for
/// clients, 2 for servers). Raises `BIO_R_TFO_NO_KERNEL_SUPPORT` or `BIO_R_TFO_DISABLED`.
#[cfg(target_os = "macos")]
fn tfo_enabled(flag: c_int, function: &str) -> bool {
    let mut enabled: c_int = 0;
    let mut len = size_of::<c_int>();
    // SAFETY: the name is a C string; the value and its length are locals.
    let ret = unsafe {
        libc::sysctlbyname(
            c"net.inet.tcp.fastopen".as_ptr(),
            (&raw mut enabled).cast(),
            &raw mut len,
            ptr::null_mut(),
            0,
        )
    };
    if ret < 0 {
        err::raise(
            ERR_LIB_BIO,
            rustyssl_abi::BIO_R_TFO_NO_KERNEL_SUPPORT,
            function,
        );
        return false;
    }
    if enabled & flag == 0 {
        err::raise(ERR_LIB_BIO, rustyssl_abi::BIO_R_TFO_DISABLED, function);
        return false;
    }
    true
}

/// `BIO_connect` with `BIO_SOCK_TFO`: `Some(result)` if OpenSSL returns without `connect`
/// (macOS connects with `connectx`), else `None` to go on.
///
/// # Safety
/// `addr` is an address.
#[cfg(target_os = "macos")]
unsafe fn connect_tfo(sock: c_int, addr: *const Addr) -> Option<c_int> {
    if !tfo_enabled(1, "BIO_connect") {
        return Some(0);
    }
    // SAFETY: zero is a valid sa_endpoints_t.
    let mut endpoints: libc::sa_endpoints_t = unsafe { core::mem::zeroed() };
    endpoints.sae_dstaddr = addr.cast();
    // SAFETY: the caller's guarantee.
    endpoints.sae_dstaddrlen = unsafe { addr::sockaddr_size(addr) };
    // SAFETY: the endpoints point to the caller's address; the rest is null.
    let ret = unsafe {
        libc::connectx(
            sock,
            &raw const endpoints,
            libc::SAE_ASSOCID_ANY,
            libc::CONNECT_DATA_IDEMPOTENT | libc::CONNECT_RESUME_ON_READ_WRITE,
            ptr::null(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if ret == -1 {
        // SAFETY: no preconditions.
        if unsafe { BIO_sock_should_retry(-1) } == 0 {
            raise_sys("connectx", BIO_R_CONNECT_ERROR, "BIO_connect");
        }
        return Some(0);
    }
    Some(1)
}

/// As above, on Linux: `TCP_FASTOPEN_CONNECT`, then the usual `connect`.
///
/// # Safety
/// No preconditions.
#[cfg(target_os = "linux")]
unsafe fn connect_tfo(sock: c_int, addr: *const Addr) -> Option<c_int> {
    let _ = addr;
    if !set_int_option(sock, IPPROTO_TCP, libc::TCP_FASTOPEN_CONNECT, 1) {
        raise_sys("setsockopt", BIO_R_UNABLE_TO_TFO, "BIO_connect");
        return Some(0);
    }
    None
}

ffi_export! {
    /// Connects `sock` to `addr`, first applying the options (`BIO_SOCK_NONBLOCK`,
    /// `BIO_SOCK_KEEPALIVE`, `BIO_SOCK_NODELAY`, `BIO_SOCK_TFO`). Returns 1, or 0, with the
    /// error raised unless the failure is one to retry (a non-blocking connect in progress).
    ///
    /// # Safety
    /// `addr` is null or an address.
    pub unsafe extern "C" fn BIO_connect(sock: c_int, addr: *const BIO_ADDR, options: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        if sock == -1 {
            err::raise(ERR_LIB_BIO, BIO_R_INVALID_SOCKET, "BIO_connect");
            return 0;
        }
        if addr.is_null() {
            err::raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER, "BIO_connect");
            return 0;
        }
        if !apply_options(sock, options, "BIO_connect") {
            return 0;
        }
        if options & BIO_SOCK_TFO != 0 {
            // SAFETY: the caller's guarantee.
            if let Some(ret) = unsafe { connect_tfo(sock, addr.cast()) } {
                return ret;
            }
        }
        // SAFETY: the caller's guarantee.
        let len = unsafe { addr::sockaddr_size(addr.cast()) };
        // SAFETY: as above: the address holds `len` bytes.
        if unsafe { libc::connect(sock, addr.cast(), len) } == -1 {
            // SAFETY: no preconditions.
            if unsafe { BIO_sock_should_retry(-1) } == 0 {
                raise_sys("connect", BIO_R_CONNECT_ERROR, "BIO_connect");
            }
            return 0;
        }
        1
    }
}

ffi_export! {
    /// Binds `sock` to `addr`, first setting `SO_REUSEADDR` for `BIO_SOCK_REUSEADDR`. Returns 1,
    /// or 0 with the error raised.
    ///
    /// # Safety
    /// `addr` is null or an address.
    pub unsafe extern "C" fn BIO_bind(sock: c_int, addr: *const BIO_ADDR, options: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        if sock == -1 {
            err::raise(ERR_LIB_BIO, BIO_R_INVALID_SOCKET, "BIO_bind");
            return 0;
        }
        if addr.is_null() {
            err::raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER, "BIO_bind");
            return 0;
        }
        if options & BIO_SOCK_REUSEADDR != 0 && !set_int_option(sock, SOL_SOCKET, libc::SO_REUSEADDR, 1) {
            raise_sys("setsockopt", BIO_R_UNABLE_TO_REUSEADDR, "BIO_bind");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let len = unsafe { addr::sockaddr_size(addr.cast()) };
        // SAFETY: as above: the address holds `len` bytes.
        if unsafe { libc::bind(sock, addr.cast(), len) } != 0 {
            raise_sys("bind", BIO_R_UNABLE_TO_BIND_SOCKET, "BIO_bind");
            return 0;
        }
        1
    }
}

/// `BIO_listen`'s TCP Fast Open: `TCP_FASTOPEN` after `listen`, with macOS's sysctl check
/// first. Returns whether it succeeded.
fn listen_tfo(sock: c_int) -> bool {
    #[cfg(target_os = "macos")]
    let queue = {
        if !tfo_enabled(2, "BIO_listen") {
            return false;
        }
        1
    };
    #[cfg(target_os = "linux")]
    let queue = MAX_LISTEN;
    if !set_int_option(sock, IPPROTO_TCP, libc::TCP_FASTOPEN, queue) {
        raise_sys("setsockopt", BIO_R_UNABLE_TO_TFO, "BIO_listen");
        return false;
    }
    true
}

ffi_export! {
    /// Binds `sock` to `addr` and, for a stream socket, listens on it, first applying the
    /// options as `BIO_connect` does, and `IPV6_V6ONLY` (`BIO_SOCK_V6_ONLY`, else off) for an
    /// IPv6 address. Returns 1, or 0 with the error raised.
    ///
    /// # Safety
    /// `addr` is null or an address.
    pub unsafe extern "C" fn BIO_listen(sock: c_int, addr: *const BIO_ADDR, options: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        if sock == -1 {
            err::raise(ERR_LIB_BIO, BIO_R_INVALID_SOCKET, "BIO_listen");
            return 0;
        }
        if addr.is_null() {
            err::raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER, "BIO_listen");
            return 0;
        }
        let mut socktype: c_int = 0;
        let mut len = socklen_t::try_from(size_of::<c_int>()).unwrap_or(0);
        // SAFETY: the value and its length are locals.
        let ret = unsafe { libc::getsockopt(sock, SOL_SOCKET, libc::SO_TYPE, (&raw mut socktype).cast(), &raw mut len) };
        if ret != 0 || usize::try_from(len).ok() != Some(size_of::<c_int>()) {
            raise_sys("getsockopt", BIO_R_GETTING_SOCKTYPE, "BIO_listen");
            return 0;
        }
        if !apply_options(sock, options, "BIO_listen") {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        if unsafe { addr::family(addr.cast()) } == AF_INET6 {
            let v6_only = c_int::from(options & BIO_SOCK_V6_ONLY != 0);
            if !set_int_option(sock, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, v6_only) {
                raise_sys("setsockopt", BIO_R_LISTEN_V6_ONLY, "BIO_listen");
                return 0;
            }
        }
        // SAFETY: as above.
        if unsafe { BIO_bind(sock, addr, options) } == 0 {
            return 0;
        }
        // SAFETY: no preconditions.
        if socktype != SOCK_DGRAM && unsafe { libc::listen(sock, MAX_LISTEN) } == -1 {
            raise_sys("listen", BIO_R_UNABLE_TO_LISTEN_SOCKET, "BIO_listen");
            return 0;
        }
        if options & BIO_SOCK_TFO != 0 && socktype != SOCK_DGRAM && !listen_tfo(sock) {
            return 0;
        }
        1
    }
}

ffi_export! {
    /// Accepts a connection on `accept_sock`, storing the peer's address in `*addr` if it isn't
    /// null, and makes the new socket non-blocking for `BIO_SOCK_NONBLOCK`. Returns it, or
    /// `INVALID_SOCKET` (-1), with the error raised unless it's one to retry.
    ///
    /// # Safety
    /// `addr` is null or a whole `BIO_ADDR`.
    pub unsafe extern "C" fn BIO_accept_ex(accept_sock: c_int, addr: *mut BIO_ADDR, options: c_int) -> c_int
    where failure = INVALID_SOCKET, library = ERR_LIB_BIO
    {
        let mut local = Addr::unspecified();
        let addr = if addr.is_null() { (&raw mut local).cast() } else { addr };
        let mut len = socklen_t::try_from(size_of::<Addr>()).unwrap_or(0);
        // SAFETY: the address is a whole BIO_ADDR of `len` bytes.
        let sock = unsafe { libc::accept(accept_sock, addr.cast(), &raw mut len) };
        if sock == -1 {
            // SAFETY: no preconditions.
            if unsafe { BIO_sock_should_retry(sock) } == 0 {
                raise_sys("accept", BIO_R_ACCEPT_ERROR, "BIO_accept_ex");
            }
            return INVALID_SOCKET;
        }
        // SAFETY: no preconditions.
        if unsafe { BIO_socket_nbio(sock, c_int::from(options & BIO_SOCK_NONBLOCK != 0)) } == 0 {
            // SAFETY: the socket just accepted.
            unsafe { libc::close(sock) };
            return INVALID_SOCKET;
        }
        sock
    }
}

ffi_export! {
    /// Closes a socket. Returns 1, or 0 for a negative socket or a failed `close`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_closesocket(sock: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: closing a descriptor has no memory-safety preconditions.
        c_int::from(sock >= 0 && unsafe { libc::close(sock) } >= 0)
    }
}

ffi_export! {
    /// Whether `err` (an `errno` value) is a failure to retry: `EWOULDBLOCK`/`EAGAIN`,
    /// `ENOTCONN`, `EINTR`, `EPROTO`, `EINPROGRESS`, or `EALREADY`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_sock_non_fatal_error(err: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        c_int::from(matches!(
            err,
            libc::EWOULDBLOCK | libc::ENOTCONN | libc::EINTR | libc::EPROTO | libc::EINPROGRESS | libc::EALREADY
        ))
    }
}

ffi_export! {
    /// Whether a socket call that returned `i` (0 or -1) failed in a way to retry, judged by
    /// `errno`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_sock_should_retry(i: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        if i == 0 || i == -1 {
            // SAFETY: no preconditions.
            unsafe { BIO_sock_non_fatal_error(errno::get()) }
        } else {
            0
        }
    }
}

ffi_export! {
    /// Looks up the IPv4 address of `str` into `ip` (4 bytes). Returns 1, or 0 with the error
    /// raised (and `host=str` added to it).
    ///
    /// # Safety
    /// `str` is a NUL-terminated string; `ip` is valid for 4 bytes of writes.
    pub unsafe extern "C" fn BIO_get_host_ip(str: *const c_char, ip: *mut c_uchar) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(res) = (unsafe { addr::lookup_ipv4(str, ptr::null()) }) else {
            // SAFETY: the caller's guarantee.
            unsafe { add_host_data(str) };
            return 0;
        };
        let mut ret = 0;
        // SAFETY: a lookup's result.
        if unsafe { addr::BIO_ADDRINFO_family(res) } != AF_INET {
            err::raise(ERR_LIB_BIO, BIO_R_GETHOSTBYNAME_ADDR_IS_NOT_AF_INET, "BIO_get_host_ip");
        } else if !ip.is_null() {
            // SAFETY: as above.
            let address = unsafe { addr::BIO_ADDRINFO_address(res) };
            // SAFETY: as above; the caller's guarantee about `ip`.
            ret = unsafe { addr::ipv4_bytes(address, ip) };
        }
        // SAFETY: as above, freed once.
        unsafe { addr::BIO_ADDRINFO_free(res) };
        ret
    }
}

/// `ERR_add_error_data(2, "host=", str)`.
///
/// # Safety
/// `text` is null or a NUL-terminated string.
unsafe fn add_host_data(text: *const c_char) {
    // SAFETY: the caller's guarantee.
    let text = (!text.is_null()).then(|| unsafe { CStr::from_ptr(text) }.to_bytes());
    err::add_error_data([Some(&b"host="[..]), text]);
}

ffi_export! {
    /// Looks up the port of the service `str` into `*port_ptr`, in host order. Returns 1, or 0
    /// with the error raised (and `host=str` added to it).
    ///
    /// # Safety
    /// `str` is null or a NUL-terminated string; `port_ptr` is valid for a write.
    pub unsafe extern "C" fn BIO_get_port(str: *const c_char, port_ptr: *mut c_ushort) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        if str.is_null() {
            err::raise(ERR_LIB_BIO, BIO_R_NO_PORT_DEFINED, "BIO_get_port");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(res) = (unsafe { addr::lookup_ipv4(ptr::null(), str) }) else {
            // SAFETY: as above.
            unsafe { add_host_data(str) };
            return 0;
        };
        let mut ret = 0;
        // SAFETY: a lookup's result.
        if unsafe { addr::BIO_ADDRINFO_family(res) } != AF_INET {
            err::raise(ERR_LIB_BIO, BIO_R_ADDRINFO_ADDR_IS_NOT_AF_INET, "BIO_get_port");
        } else if !port_ptr.is_null() {
            // SAFETY: as above.
            let address = unsafe { addr::BIO_ADDRINFO_address(res) };
            // SAFETY: as above.
            let port = unsafe { addr::BIO_ADDR_rawport(address) };
            // SAFETY: the caller's guarantee.
            unsafe { port_ptr.write(u16::from_be(port)) };
            ret = 1;
        }
        // SAFETY: as above, freed once.
        unsafe { addr::BIO_ADDRINFO_free(res) };
        ret
    }
}

ffi_export! {
    /// The C library's `gethostbyname`.
    ///
    /// # Safety
    /// `name` is a NUL-terminated string; the result is the C library's static data.
    pub unsafe extern "C" fn BIO_gethostbyname(name: *const c_char) -> *mut hostent
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        unsafe extern "C" {
            fn gethostbyname(name: *const c_char) -> *mut hostent;
        }
        // SAFETY: the caller's guarantee.
        unsafe { gethostbyname(name) }
    }
}

ffi_export! {
    /// Opens a socket listening on `host` (a `host:service` spec, the service first without a
    /// colon), with `SO_REUSEADDR` if `bind_mode` isn't 0. Returns it, or -1.
    ///
    /// # Safety
    /// `host` is a NUL-terminated string.
    pub unsafe extern "C" fn BIO_get_accept_socket(host: *mut c_char, bind_mode: c_int) -> c_int
    where failure = INVALID_SOCKET, library = ERR_LIB_BIO
    {
        let (mut h, mut p) = (ptr::null_mut(), ptr::null_mut());
        // SAFETY: the caller's guarantee; the outputs are locals.
        if unsafe { addr::BIO_parse_hostserv(host, &raw mut h, &raw mut p, BIO_PARSE_PRIO_SERV) } == 0 {
            return INVALID_SOCKET;
        }
        let mut res = ptr::null_mut();
        let mut s = INVALID_SOCKET;
        // SAFETY: the parsed strings; `res` is a local.
        if unsafe { addr::BIO_lookup(h, p, BIO_LOOKUP_SERVER, libc::AF_UNSPEC, SOCK_STREAM, &raw mut res) } != 0 {
            // SAFETY: a lookup's result, for each call.
            let family = unsafe { addr::BIO_ADDRINFO_family(res) };
            // SAFETY: as above.
            let socktype = unsafe { addr::BIO_ADDRINFO_socktype(res) };
            // SAFETY: as above.
            let protocol = unsafe { addr::BIO_ADDRINFO_protocol(res) };
            // SAFETY: as above.
            let address = unsafe { addr::BIO_ADDRINFO_address(res) };
            // SAFETY: no preconditions.
            s = unsafe { BIO_socket(family, socktype, protocol, 0) };
            let options = if bind_mode != 0 { BIO_SOCK_REUSEADDR } else { 0 };
            // SAFETY: as above.
            if s != INVALID_SOCKET && unsafe { BIO_listen(s, address, options) } == 0 {
                // SAFETY: the socket opened above.
                unsafe { BIO_closesocket(s) };
                s = INVALID_SOCKET;
            }
        }
        // SAFETY: null or the lookup's result, freed once.
        unsafe { addr::BIO_ADDRINFO_free(res) };
        // SAFETY: null or the parsed strings, freed once.
        unsafe { mem::release(h.cast()) };
        // SAFETY: as above.
        unsafe { mem::release(p.cast()) };
        s
    }
}

ffi_export! {
    /// Accepts a connection on `sock`. Stores the peer as `host:port` in `*ip_port` (to free
    /// with `OPENSSL_free`) if `ip_port` isn't null. Returns the socket, -2 for a failure to
    /// retry, or -1 with the error raised.
    ///
    /// # Safety
    /// `ip_port` is null or valid for a write.
    pub unsafe extern "C" fn BIO_accept(sock: c_int, ip_port: *mut *mut c_char) -> c_int
    where failure = INVALID_SOCKET, library = ERR_LIB_BIO
    {
        let mut peer = Addr::unspecified();
        // SAFETY: a whole local address.
        let ret = unsafe { BIO_accept_ex(sock, (&raw mut peer).cast(), 0) };
        if ret == INVALID_SOCKET {
            // SAFETY: no preconditions.
            if unsafe { BIO_sock_should_retry(ret) } != 0 {
                return -2;
            }
            raise_sys("accept", BIO_R_ACCEPT_ERROR, "BIO_accept");
            return ret;
        }
        if ip_port.is_null() {
            return ret;
        }
        let peer = (&raw const peer).cast::<BIO_ADDR>();
        // SAFETY: the accepted peer's address, for each call.
        let host = unsafe { addr::BIO_ADDR_hostname_string(peer, 1) };
        // SAFETY: as above.
        let port = unsafe { addr::BIO_ADDR_service_string(peer, 1) };
        let mut joined = ptr::null_mut();
        if host.is_null() || port.is_null() {
            err::raise(ERR_LIB_BIO, ERR_R_BIO_LIB, "BIO_accept");
        } else {
            // SAFETY: both are NUL-terminated strings made above.
            let h = unsafe { CStr::from_ptr(host) }.to_bytes();
            // SAFETY: as above.
            let p = unsafe { CStr::from_ptr(port) }.to_bytes();
            joined = mem::alloc_zeroed(h.len() + p.len() + 2).cast::<u8>();
            if !joined.is_null() {
                let text = [h, b":", p].concat();
                // SAFETY: the block has room for the text and its NUL.
                unsafe { ptr::copy_nonoverlapping(text.as_ptr(), joined, text.len()) };
            }
        }
        // SAFETY: the caller's guarantee.
        unsafe { ip_port.write(joined.cast()) };
        let mut ret = ret;
        if joined.is_null() {
            // SAFETY: the socket accepted above.
            unsafe { BIO_closesocket(ret) };
            ret = INVALID_SOCKET;
        }
        // SAFETY: null or made above, freed once.
        unsafe { mem::release(host.cast()) };
        // SAFETY: as above.
        unsafe { mem::release(port.cast()) };
        ret
    }
}

/// The state of a socket BIO (OpenSSL's `struct bss_sock_st`): the peer of a TCP Fast Open
/// `sendto`, which OpenSSL keeps but on these platforms never uses for one.
pub(crate) struct Sock {
    tfo_peer: Addr,
    tfo_first: bool,
}

// SAFETY: plain bytes.
unsafe impl Send for Sock {}

ffi_callback! {
    /// Sets up a socket BIO with no socket yet.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn sock_new(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        object.init.store(0, Ordering::Relaxed);
        object.num.store(0, Ordering::Relaxed);
        object.flags.store(0, Ordering::Relaxed);
        state::install(object, Sock { tfo_peer: Addr::unspecified(), tfo_first: false });
        1
    }
}

ffi_callback! {
    /// Frees a socket BIO, closing its socket if it owns it.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn sock_free(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        if object.shutdown.load(Ordering::Relaxed) != 0 {
            if object.init.load(Ordering::Relaxed) != 0 {
                // SAFETY: the BIO's own socket.
                unsafe { BIO_closesocket(object.num.load(Ordering::Relaxed)) };
            }
            object.init.store(0, Ordering::Relaxed);
            object.flags.store(0, Ordering::Relaxed);
        }
        drop(state::remove::<Sock>(object));
        1
    }
}

/// Reads from a socket descriptor into a BIO's buffer, as OpenSSL's socket BIOs do: `errno`
/// cleared first, then the retry flags or `BIO_FLAGS_IN_EOF` set from the result.
///
/// # Safety
/// `out` is valid for `len` bytes of writes.
pub(crate) unsafe fn read_socket(object: &Bio, fd: c_int, out: *mut c_char, len: c_int) -> c_int {
    errno::set(0);
    // SAFETY: the caller's guarantee.
    let ret = unsafe { libc::read(fd, out.cast(), usize::try_from(len).unwrap_or(0)) };
    let ret = c_int::try_from(ret).unwrap_or(-1);
    object.clear_retry_flags();
    if ret <= 0 {
        // SAFETY: no preconditions.
        if unsafe { BIO_sock_should_retry(ret) } != 0 {
            object.set_retry_read();
        } else if ret == 0 {
            object.set_flags(BIO_FLAGS_IN_EOF);
        }
    }
    ret
}

/// Writes to a socket descriptor, as OpenSSL's socket BIOs do: `errno` cleared first, then the
/// retry flags set from the result.
///
/// # Safety
/// `data` is valid for `len` bytes of reads.
pub(crate) unsafe fn write_socket(
    object: &Bio,
    fd: c_int,
    data: *const c_char,
    len: c_int,
) -> c_int {
    errno::set(0);
    // SAFETY: the caller's guarantee.
    let ret = unsafe { libc::write(fd, data.cast(), usize::try_from(len).unwrap_or(0)) };
    let ret = c_int::try_from(ret).unwrap_or(-1);
    object.clear_retry_flags();
    // SAFETY: no preconditions.
    if ret <= 0 && unsafe { BIO_sock_should_retry(ret) } != 0 {
        object.set_retry_write();
    }
    ret
}

ffi_callback! {
    /// Reads from the socket.
    ///
    /// # Safety
    /// `b` is a live BIO; `out` is null or valid for `len` bytes of writes.
    pub(crate) unsafe extern "C" fn sock_read(b: *mut BIO, out: *mut c_char, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        if out.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { read_socket(object, object.num.load(Ordering::Relaxed), out, len) }
    }
}

ffi_callback! {
    /// Writes to the socket.
    ///
    /// # Safety
    /// `b` is a live BIO; `data` is valid for `len` bytes of reads.
    pub(crate) unsafe extern "C" fn sock_write(b: *mut BIO, data: *const c_char, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        // SAFETY: the caller's guarantee.
        unsafe { write_socket(object, object.num.load(Ordering::Relaxed), data, len) }
    }
}

ffi_callback! {
    /// Writes a string to the socket.
    ///
    /// # Safety
    /// `b` is a live BIO; `text` is a NUL-terminated string.
    pub(crate) unsafe extern "C" fn sock_puts(b: *mut BIO, text: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        if text.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let len = unsafe { CStr::from_ptr(text) }.count_bytes();
        let len = super::wrap_int(c_long::try_from(len).unwrap_or(c_long::MAX));
        // SAFETY: as above.
        unsafe { sock_write(b, text, len) }
    }
}

/// Fills a poll descriptor with the BIO's socket. Returns 1, or 0 if it has none.
///
/// # Safety
/// `ptr` is null or a `BIO_POLL_DESCRIPTOR`.
pub(crate) unsafe fn poll_descriptor(ptr: *mut c_void, fd: c_int) -> c_long {
    let pd = ptr.cast::<BIO_POLL_DESCRIPTOR>();
    if pd.is_null() {
        return 0;
    }
    // SAFETY: zero is a valid descriptor.
    let mut descriptor: BIO_POLL_DESCRIPTOR = unsafe { core::mem::zeroed() };
    descriptor.type_ = BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD.cast_unsigned();
    descriptor.value.fd = fd;
    // SAFETY: the caller's guarantee.
    unsafe { pd.write(descriptor) };
    1
}

ffi_callback! {
    /// The socket BIO's controls: its socket (`BIO_set_fd`, `BIO_get_fd`), the close flag, the
    /// end of input, poll descriptors, and the TCP Fast Open peer.
    ///
    /// # Safety
    /// `b` is a live BIO; `ptr` is what the command expects.
    pub(crate) unsafe extern "C" fn sock_ctrl(b: *mut BIO, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        let state = state::get::<Sock>(object);
        match cmd {
            BIO_C_SET_FD => {
                if ptr.is_null() {
                    return 0;
                }
                if object.shutdown.load(Ordering::Relaxed) != 0 {
                    if object.init.load(Ordering::Relaxed) != 0 {
                        // SAFETY: the BIO's own socket.
                        unsafe { BIO_closesocket(object.num.load(Ordering::Relaxed)) };
                    }
                    object.flags.store(0, Ordering::Relaxed);
                }
                // SAFETY: the caller's guarantee: an `int`.
                object.num.store(unsafe { ptr.cast::<c_int>().read() }, Ordering::Relaxed);
                object.shutdown.store(super::wrap_int(num), Ordering::Relaxed);
                object.init.store(1, Ordering::Relaxed);
                if let Some(state) = state {
                    let mut s = lock(&state);
                    s.tfo_first = false;
                    s.tfo_peer = Addr::unspecified();
                }
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
            BIO_CTRL_DUP | BIO_CTRL_FLUSH => 1,
            BIO_CTRL_GET_RPOLL_DESCRIPTOR | BIO_CTRL_GET_WPOLL_DESCRIPTOR => {
                if object.init.load(Ordering::Relaxed) == 0 {
                    return 0;
                }
                // SAFETY: the caller's guarantee.
                unsafe { poll_descriptor(ptr, object.num.load(Ordering::Relaxed)) }
            }
            BIO_CTRL_EOF => c_long::from(object.flags() & BIO_FLAGS_IN_EOF != 0),
            BIO_C_GET_CONNECT => {
                let Some(state) = state.filter(|_| !ptr.is_null() && num == 2) else {
                    return 0;
                };
                // The peer stays at this address for the BIO's life.
                let peer = (&raw const lock(&state).tfo_peer).cast::<c_char>();
                // SAFETY: the caller's guarantee: a `const char **`.
                unsafe { ptr.cast::<*const c_char>().write(peer) };
                1
            }
            BIO_C_SET_CONNECT => {
                let Some(state) = state.filter(|_| !ptr.is_null() && num == 2) else {
                    return 0;
                };
                let mut s = lock(&state);
                // SAFETY: the caller's guarantee: an address.
                let ok = unsafe { addr::make(&raw mut s.tfo_peer, ptr.cast()) };
                if ok {
                    s.tfo_first = true;
                }
                c_long::from(ok)
            }
            _ => 0,
        }
    }
}

static SOCKET: Builtin = Builtin::new(BIO_TYPE_SOCKET, c"socket", || Funcs {
    bputs: Some(sock_puts),
    ctrl: Some(sock_ctrl),
    create: Some(sock_new),
    destroy: Some(sock_free),
    ..Funcs::classic(sock_write, sock_read)
});

ffi_export! {
    /// Returns the socket BIO's method: reads and writes on a connected socket.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_s_socket() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        SOCKET.get()
    }
}

ffi_export! {
    /// Returns a socket BIO on `fd`, closing it when freed if `close_flag` is `BIO_CLOSE`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_new_socket(fd: c_int, close_flag: c_int) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        // SAFETY: the built-in method.
        let b = unsafe { super::BIO_new(SOCKET.get()) };
        if !b.is_null() {
            // SAFETY: a live BIO; BIO_int_ctrl passes the descriptor by pointer, as
            // BIO_set_fd does.
            unsafe { super::BIO_int_ctrl(b, BIO_C_SET_FD, c_long::from(close_flag), fd) };
        }
        b
    }
}

/// OpenSSL's `bio_wait`: waits for `bio`'s socket (`BIO_get_fd`) with `BIO_socket_wait`, or
/// without one sleeps at most `nap_milliseconds`. Returns 1, 0 on timeout, or -1.
///
/// # Safety
/// `bio` is a live BIO.
unsafe fn bio_wait(bio: *mut BIO, max_time: time_t, nap_milliseconds: c_uint) -> c_int {
    if max_time == 0 {
        return 1;
    }
    let mut fd: c_int = -1;
    // SAFETY: the caller's guarantee; BIO_get_fd stores an `int`.
    if unsafe { super::BIO_ctrl(bio, BIO_C_GET_FD, 0, (&raw mut fd).cast()) } > 0 {
        // SAFETY: as above.
        let should_read = unsafe { object(bio) }.is_some_and(|o| o.flags() & BIO_FLAGS_READ != 0);
        // SAFETY: no preconditions.
        let ret = unsafe { BIO_socket_wait(fd, c_int::from(should_read), max_time) };
        if ret != -1 {
            return ret;
        }
    }
    let sec_diff = max_time - now();
    if sec_diff < 0 {
        return 0;
    }
    let mut nap = nap_milliseconds;
    if sec_diff == 0 {
        nap = nap.min(1000);
    } else {
        let limit = u64::try_from(sec_diff)
            .unwrap_or(u64::MAX)
            .saturating_mul(1000);
        if limit < u64::from(nap) {
            nap = c_uint::try_from(limit).unwrap_or(c_uint::MAX);
        }
    }
    crate::sleep::sleep_millis(u64::from(nap));
    1
}

ffi_export! {
    /// Waits for `bio` at most until `max_time` (0 doesn't wait): on its socket if it has one,
    /// else by sleeping at most `nap_milliseconds`. Returns 1, or 0 on timeout or -1 on error,
    /// with `BIO_R_TRANSFER_TIMEOUT` or `BIO_R_TRANSFER_ERROR` raised.
    ///
    /// # Safety
    /// `bio` is a live BIO.
    pub unsafe extern "C" fn BIO_wait(bio: *mut BIO, max_time: time_t, nap_milliseconds: c_uint) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let ret = unsafe { bio_wait(bio, max_time, nap_milliseconds) };
        if ret <= 0 {
            let reason = if ret == 0 { BIO_R_TRANSFER_TIMEOUT } else { BIO_R_TRANSFER_ERROR };
            err::raise(ERR_LIB_BIO, reason, "BIO_wait");
        }
        ret
    }
}

ffi_export! {
    /// Connects `bio` with `BIO_do_connect` until it succeeds, fails, or `timeout` seconds pass
    /// (0: no timeout, blocking; negative: one try). Non-blocking BIOs are polled, sleeping
    /// `nap_milliseconds` (100 if negative) between tries. Connection errors are retried after
    /// a `BIO_reset`. Returns 1, 0 on timeout, or -1 on error.
    ///
    /// # Safety
    /// `bio` is null or a live BIO.
    pub unsafe extern "C" fn BIO_do_connect_retry(bio: *mut BIO, timeout: c_int, nap_milliseconds: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        if bio.is_null() {
            err::raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER, "BIO_do_connect_retry");
            return -1;
        }
        let blocking = timeout <= 0;
        let max_time = if timeout > 0 { now() + time_t::from(timeout) } else { 0 };
        let nap = if nap_milliseconds < 0 { 100 } else { nap_milliseconds };
        // SAFETY: the caller's guarantee, for each call on `bio` below.
        unsafe { super::BIO_ctrl(bio, BIO_C_SET_NBIO, c_long::from(!blocking), ptr::null_mut()) };
        loop {
            // SAFETY: no preconditions.
            unsafe { crate::err::ERR_set_mark() };
            // SAFETY: as above.
            let rv = super::wrap_int(unsafe { super::BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, ptr::null_mut()) });
            if rv > 0 {
                // SAFETY: no preconditions.
                unsafe { crate::err::ERR_clear_last_mark() };
                return rv;
            }
            // SAFETY: no preconditions.
            let code = unsafe { crate::err::ERR_peek_last_error() };
            let reason = crate::err::strings::reason_of(code);
            // SAFETY: as above.
            let mut do_retry = unsafe { object(bio) }.is_some_and(|o| o.flags() & rustyssl_abi::BIO_FLAGS_SHOULD_RETRY != 0);
            if crate::err::library_of(code) == ERR_LIB_BIO {
                let retryable = [ERR_R_SYS_LIB, BIO_R_CONNECT_ERROR, BIO_R_NBIO_CONNECT_ERROR];
                if retryable.iter().any(|r| core::ffi::c_ulong::from(r.unsigned_abs()) == reason) {
                    // SAFETY: as above.
                    unsafe { super::BIO_ctrl(bio, BIO_CTRL_RESET, 0, ptr::null_mut()) };
                    do_retry = true;
                }
            }
            if timeout >= 0 && do_retry {
                // SAFETY: no preconditions.
                unsafe { crate::err::ERR_pop_to_mark() };
                // SAFETY: as above.
                let waited = unsafe { bio_wait(bio, max_time, nap.unsigned_abs()) };
                if waited > 0 {
                    continue;
                }
                let reason = if waited == 0 { BIO_R_CONNECT_TIMEOUT } else { BIO_R_CONNECT_ERROR };
                err::raise(ERR_LIB_BIO, reason, "BIO_do_connect_retry");
                return waited;
            }
            // SAFETY: no preconditions.
            unsafe { crate::err::ERR_clear_last_mark() };
            if code == 0 {
                err::raise(ERR_LIB_BIO, BIO_R_CONNECT_ERROR, "BIO_do_connect_retry");
            }
            return -1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: OpenSSL dereferences these null pointers.
    #[test]
    fn null_addresses_and_descriptors_are_refused() {
        let null = ptr::null();
        // SAFETY: null is refused before use, for each call.
        assert_eq!(unsafe { BIO_connect(0, null, 0) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { BIO_bind(0, null, 0) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { BIO_listen(0, null, 0) }, 0);
        // SAFETY: as above.
        let ret = unsafe { BIO_sock_info(0, BIO_SOCK_INFO_ADDRESS, ptr::null_mut()) };
        assert_eq!(ret, 0);
        // SAFETY: the built-in method.
        let b = unsafe { super::super::BIO_new(SOCKET.get()) };
        // SAFETY: a live BIO; the null descriptor pointer is refused.
        let ret = unsafe { super::super::BIO_ctrl(b, BIO_C_SET_FD, 0, ptr::null_mut()) };
        assert_eq!(ret, 0);
        // SAFETY: made above, freed once.
        unsafe { super::super::BIO_free(b) };
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }
}
