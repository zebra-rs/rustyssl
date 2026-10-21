//! Sockets for the TLS commands (`apps/lib/s_socket.c`): addresses and lookups (`BIO_ADDR`,
//! `BIO_ADDRINFO`), socket calls, `select`, raw descriptor reads and writes, and the socket,
//! datagram, SSL and filter `BIO`s.

use core::ffi::{c_char, c_int, c_long};

use crate::abi::*;
use crate::bio::Bio;
use crate::ffi;
use crate::ssl::{BioRef, SslRef};
use crate::util::{cstring, take_string};

/// An owned `BIO_ADDR`.
pub struct Addr(core::ptr::NonNull<BIO_ADDR>);

impl Drop for Addr {
    fn drop(&mut self) {
        // SAFETY: owned, freed once.
        unsafe { ffi::BIO_ADDR_free(self.0.as_ptr()) };
    }
}

impl Addr {
    /// `BIO_ADDR_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        core::ptr::NonNull::new(unsafe { ffi::BIO_ADDR_new() }).map(Self)
    }
    /// The address, for the C API.
    pub fn as_ptr(&self) -> *mut BIO_ADDR {
        self.0.as_ptr()
    }
    fn dup(p: *const BIO_ADDR) -> Option<Self> {
        // SAFETY: p is a live address.
        core::ptr::NonNull::new(unsafe { ffi::BIO_ADDR_dup(p) }).map(Self)
    }
    /// `BIO_ADDR_family`.
    pub fn family(&self) -> c_int {
        // SAFETY: the address is live.
        unsafe { ffi::BIO_ADDR_family(self.as_ptr()) }
    }
    /// `BIO_ADDR_rawaddress`: the raw address octets.
    pub fn rawaddress(&self) -> Option<Vec<u8>> {
        let mut len = 0usize;
        // SAFETY: a NULL buffer asks for the length.
        if unsafe { ffi::BIO_ADDR_rawaddress(self.as_ptr(), core::ptr::null_mut(), &mut len) } == 0
        {
            return None;
        }
        let mut v = vec![0u8; len];
        // SAFETY: v has room for len bytes.
        if unsafe {
            ffi::BIO_ADDR_rawaddress(self.as_ptr(), v.as_mut_ptr().cast(), core::ptr::null_mut())
        } == 0
        {
            return None;
        }
        Some(v)
    }
    /// `BIO_ADDR_rawport` (network byte order).
    pub fn rawport(&self) -> u16 {
        // SAFETY: the address is live.
        unsafe { ffi::BIO_ADDR_rawport(self.as_ptr()) }
    }
    /// `BIO_ADDR_hostname_string(a, 1)`.
    pub fn hostname_string(&self) -> Option<String> {
        // SAFETY: the address is live; the string is ours.
        take_string(unsafe { ffi::BIO_ADDR_hostname_string(self.as_ptr(), 1) })
    }
    /// `BIO_ADDR_service_string(a, 1)`.
    pub fn service_string(&self) -> Option<String> {
        // SAFETY: as above.
        take_string(unsafe { ffi::BIO_ADDR_service_string(self.as_ptr(), 1) })
    }
}

/// An owned `BIO_ADDRINFO` list.
pub struct AddrInfo(core::ptr::NonNull<BIO_ADDRINFO>);

impl Drop for AddrInfo {
    fn drop(&mut self) {
        // SAFETY: owned, freed once.
        unsafe { ffi::BIO_ADDRINFO_free(self.0.as_ptr()) };
    }
}

/// One entry of an [`AddrInfo`] list.
#[derive(Clone, Copy)]
pub struct AddrInfoRef<'a>(*const BIO_ADDRINFO, core::marker::PhantomData<&'a ()>);

impl AddrInfo {
    /// `BIO_lookup_ex(host, service, lookup_type, family, socktype, protocol)`.
    pub fn lookup_ex(
        host: Option<&str>,
        service: Option<&str>,
        lookup_type: BIO_lookup_type,
        family: c_int,
        socktype: c_int,
        protocol: c_int,
    ) -> Option<Self> {
        let h = match host {
            Some(h) => Some(cstring(h)?),
            None => None,
        };
        let s = match service {
            Some(s) => Some(cstring(s)?),
            None => None,
        };
        let mut res: *mut BIO_ADDRINFO = core::ptr::null_mut();
        // SAFETY: the strings are valid or NULL; res is a valid out-pointer.
        let r = unsafe {
            ffi::BIO_lookup_ex(
                h.as_ref().map_or(core::ptr::null(), |h| h.as_ptr()),
                s.as_ref().map_or(core::ptr::null(), |s| s.as_ptr()),
                c_int::try_from(lookup_type).ok()?,
                family,
                socktype,
                protocol,
                &mut res,
            )
        };
        if r == 0 {
            return None;
        }
        core::ptr::NonNull::new(res).map(Self)
    }
    /// The entries, in order.
    pub fn iter(&self) -> Vec<AddrInfoRef<'_>> {
        let mut out = Vec::new();
        let mut p: *const BIO_ADDRINFO = self.0.as_ptr();
        while !p.is_null() {
            out.push(AddrInfoRef(p, core::marker::PhantomData));
            // SAFETY: p is a live entry of the list.
            p = unsafe { ffi::BIO_ADDRINFO_next(p) };
        }
        out
    }
}

impl AddrInfoRef<'_> {
    /// `BIO_ADDRINFO_family`.
    pub fn family(self) -> c_int {
        // SAFETY: the entry is live.
        unsafe { ffi::BIO_ADDRINFO_family(self.0) }
    }
    /// `BIO_ADDRINFO_socktype`.
    pub fn socktype(self) -> c_int {
        // SAFETY: as above.
        unsafe { ffi::BIO_ADDRINFO_socktype(self.0) }
    }
    /// `BIO_ADDRINFO_protocol`.
    pub fn protocol(self) -> c_int {
        // SAFETY: as above.
        unsafe { ffi::BIO_ADDRINFO_protocol(self.0) }
    }
    fn address(self) -> *const BIO_ADDR {
        // SAFETY: as above; the address is owned by the entry.
        unsafe { ffi::BIO_ADDRINFO_address(self.0) }
    }
    /// `BIO_ADDR_dup(BIO_ADDRINFO_address(ai))`.
    pub fn address_dup(self) -> Option<Addr> {
        Addr::dup(self.address())
    }
    /// `BIO_ADDR_hostname_string(BIO_ADDRINFO_address(ai), 1)`.
    pub fn hostname_string(self) -> Option<String> {
        // SAFETY: the address is live; the string is ours.
        take_string(unsafe { ffi::BIO_ADDR_hostname_string(self.address(), 1) })
    }
    /// `BIO_ADDR_rawport(BIO_ADDRINFO_address(ai))`.
    pub fn rawport(self) -> u16 {
        // SAFETY: as above.
        unsafe { ffi::BIO_ADDR_rawport(self.address()) }
    }
    /// `BIO_connect(sock, address, options)`.
    pub fn connect(self, sock: c_int, options: c_int) -> bool {
        // SAFETY: the address is live.
        unsafe { ffi::BIO_connect(sock, self.address(), options) == 1 }
    }
    /// `BIO_bind(sock, address, options)`.
    pub fn bind(self, sock: c_int, options: c_int) -> bool {
        // SAFETY: as above.
        unsafe { ffi::BIO_bind(sock, self.address(), options) == 1 }
    }
    /// `BIO_listen(sock, address, options)`.
    pub fn listen(self, sock: c_int, options: c_int) -> bool {
        // SAFETY: as above.
        unsafe { ffi::BIO_listen(sock, self.address(), options) == 1 }
    }
}

/// `BIO_sock_init()`.
pub fn sock_init() -> bool {
    // SAFETY: no arguments.
    unsafe { ffi::BIO_sock_init() == 1 }
}

/// `BIO_socket(family, type, protocol, 0)`.
pub fn socket(family: c_int, socktype: c_int, protocol: c_int) -> c_int {
    // SAFETY: plain integers.
    unsafe { ffi::BIO_socket(family, socktype, protocol, 0) }
}

/// `BIO_closesocket`.
pub fn closesocket(sock: c_int) {
    // SAFETY: plain integer; closing an invalid descriptor fails harmlessly.
    unsafe { ffi::BIO_closesocket(sock) };
}

/// `BIO_connect(sock, addr, options)`.
pub fn connect_addr(sock: c_int, addr: &Addr, options: c_int) -> bool {
    // SAFETY: the address is live.
    unsafe { ffi::BIO_connect(sock, addr.as_ptr(), options) == 1 }
}

/// `BIO_accept_ex(sock, peer, 0)`.
pub fn accept_ex(sock: c_int, peer: Option<&Addr>) -> c_int {
    let p = peer.map_or(core::ptr::null_mut(), Addr::as_ptr);
    // SAFETY: p is a live address or NULL.
    unsafe { ffi::BIO_accept_ex(sock, p, 0) }
}

/// `BIO_sock_should_retry(i)`.
pub fn sock_should_retry(i: c_int) -> bool {
    // SAFETY: plain integer.
    unsafe { ffi::BIO_sock_should_retry(i) != 0 }
}

/// `BIO_set_tcp_ndelay`.
pub fn set_tcp_ndelay(sock: c_int, on: c_int) {
    // SAFETY: plain integers.
    unsafe { ffi::BIO_set_tcp_ndelay(sock, on) };
}

/// `BIO_socket_nbio`.
pub fn socket_nbio(sock: c_int, mode: c_int) -> bool {
    // SAFETY: plain integers.
    unsafe { ffi::BIO_socket_nbio(sock, mode) == 1 }
}

/// `BIO_sock_info(sock, BIO_SOCK_INFO_ADDRESS, ...)`: the socket's own address.
pub fn sock_address(sock: c_int) -> Option<Addr> {
    let a = Addr::new()?;
    let mut info = BIO_sock_info_u { addr: a.as_ptr() };
    // SAFETY: info holds a live address the call fills in.
    (unsafe { ffi::BIO_sock_info(sock, BIO_SOCK_INFO_ADDRESS, &mut info) } == 1).then_some(a)
}

/// `BIO_parse_hostserv(hostserv, &host, &service, prio)`: `None` when it fails, else the
/// parts it set. `want_host` false passes NULL for the host.
pub fn parse_hostserv(
    s: &str,
    want_host: bool,
    prio: BIO_hostserv_priorities,
) -> Option<(c_int, Option<String>, Option<String>)> {
    let c = cstring(s)?;
    let mut h: *mut c_char = core::ptr::null_mut();
    let mut p: *mut c_char = core::ptr::null_mut();
    let hp: *mut *mut c_char = if want_host {
        &mut h
    } else {
        core::ptr::null_mut()
    };
    // SAFETY: c is a valid C string; the out-pointers are valid or NULL.
    let r = unsafe { ffi::BIO_parse_hostserv(c.as_ptr(), hp, &mut p, prio) };
    Some((r, take_string(h), take_string(p)))
}

/// The last socket error (`errno`).
pub fn last_socket_error() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Sets `errno` (the C code saves and restores it around calls).
pub fn set_errno(e: c_int) {
    // SAFETY: no arguments; the result is this thread's errno.
    let p = unsafe { libc::__errno_location() };
    // SAFETY: p points to this thread's errno.
    unsafe { *p = e };
}

/// `shutdown(sock, SHUT_WR)`.
pub fn shutdown_wr(sock: c_int) {
    // SAFETY: plain integers; an invalid descriptor fails harmlessly.
    unsafe { libc::shutdown(sock, libc::SHUT_WR) };
}

/// `setsockopt(fd, SOL_SOCKET, SO_LINGER, {1, 0})`.
pub fn set_no_linger(fd: c_int) {
    let l = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    let len = libc::socklen_t::try_from(core::mem::size_of::<libc::linger>()).unwrap_or(0);
    // SAFETY: l is valid for len bytes.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&raw const l).cast(),
            len,
        )
    };
}

/// `read(fd, buf, len)` (`raw_read_stdin`, `readsocket`).
pub fn read_fd(fd: c_int, buf: &mut [u8]) -> isize {
    // SAFETY: buf is writable for its length.
    unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) }
}

/// `write(fd, buf, len)` (`raw_write_stdout`).
pub fn write_fd(fd: c_int, buf: &[u8]) -> isize {
    // SAFETY: buf is valid for its length.
    unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) }
}

/// `getpid()`.
pub fn getpid() -> c_int {
    // SAFETY: no arguments.
    unsafe { libc::getpid() }
}

/// `unlink(path)`.
pub fn unlink(path: &str) {
    if let Some(c) = cstring(path) {
        // SAFETY: a valid C string.
        unsafe { libc::unlink(c.as_ptr()) };
    }
}

/// `select(width, read, write, NULL, timeout)` over the given descriptors: the result, and
/// which of each set are ready. `timeout` `None` waits forever.
pub fn select(
    read: &[c_int],
    write: &[c_int],
    timeout: Option<std::time::Duration>,
) -> (c_int, Vec<bool>, Vec<bool>) {
    // SAFETY: an all-zero fd_set is a valid empty set.
    let mut rfds: libc::fd_set = unsafe { core::mem::zeroed() };
    // SAFETY: as above.
    let mut wfds: libc::fd_set = unsafe { core::mem::zeroed() };
    let mut width = 0;
    let valid = |fd: c_int| (0..c_int::try_from(libc::FD_SETSIZE).unwrap_or(1024)).contains(&fd);
    for &fd in read {
        if valid(fd) {
            // SAFETY: fd is within FD_SETSIZE; rfds is a valid set.
            unsafe { libc::FD_SET(fd, &mut rfds) };
            width = width.max(fd + 1);
        }
    }
    for &fd in write {
        if valid(fd) {
            // SAFETY: as above.
            unsafe { libc::FD_SET(fd, &mut wfds) };
            width = width.max(fd + 1);
        }
    }
    let mut tv = timeout.map(|d| libc::timeval {
        tv_sec: libc::time_t::try_from(d.as_secs()).unwrap_or(libc::time_t::MAX),
        tv_usec: libc::suseconds_t::from(d.subsec_micros()),
    });
    let tvp = tv
        .as_mut()
        .map_or(core::ptr::null_mut(), core::ptr::from_mut);
    // SAFETY: the sets and the timeout are valid for the call.
    let r = unsafe { libc::select(width, &mut rfds, &mut wfds, core::ptr::null_mut(), tvp) };
    // SAFETY: the sets are valid; FD_ISSET only reads them.
    let rr = read
        .iter()
        .map(|&fd| r > 0 && valid(fd) && unsafe { libc::FD_ISSET(fd, &rfds) })
        .collect();
    // SAFETY: as above.
    let ww = write
        .iter()
        .map(|&fd| r > 0 && valid(fd) && unsafe { libc::FD_ISSET(fd, &wfds) })
        .collect();
    (r, rr, ww)
}

impl Bio {
    /// `BIO_new_socket(sock, BIO_NOCLOSE)`.
    pub fn new_socket(sock: c_int) -> Option<Bio> {
        // SAFETY: plain integers; the BIO doesn't close the socket.
        Bio::from_ptr(unsafe { ffi::BIO_new_socket(sock, BIO_NOCLOSE) })
    }
    /// `BIO_new_dgram(sock, BIO_NOCLOSE)`.
    pub fn new_dgram(sock: c_int) -> Option<Bio> {
        // SAFETY: as above.
        Bio::from_ptr(unsafe { ffi::BIO_new_dgram(sock, BIO_NOCLOSE) })
    }
    /// `BIO_new(BIO_s_null())`.
    pub fn new_null() -> Option<Bio> {
        // SAFETY: no arguments; a static method.
        let m = unsafe { ffi::BIO_s_null() };
        // SAFETY: m is a valid method.
        Bio::from_ptr(unsafe { ffi::BIO_new(m) })
    }
    /// `BIO_new(BIO_f_nbio_test())`.
    pub fn new_nbio_test() -> Option<Bio> {
        // SAFETY: no arguments; a static method.
        let m = unsafe { ffi::BIO_f_nbio_test() };
        // SAFETY: m is a valid method.
        Bio::from_ptr(unsafe { ffi::BIO_new(m) })
    }
    /// `BIO_new(BIO_f_ssl())`.
    pub fn new_ssl_filter() -> Option<Bio> {
        // SAFETY: no arguments; a static method.
        let m = unsafe { ffi::BIO_f_ssl() };
        // SAFETY: m is a valid method.
        Bio::from_ptr(unsafe { ffi::BIO_new(m) })
    }
    /// `BIO_new(BIO_s_connect())`.
    pub fn new_connect() -> Option<Bio> {
        // SAFETY: no arguments; a static method.
        let m = unsafe { ffi::BIO_s_connect() };
        // SAFETY: m is a valid method.
        Bio::from_ptr(unsafe { ffi::BIO_new(m) })
    }
    /// `BIO_ctrl(b, cmd, larg, NULL)`.
    pub fn ctrl_long(&self, cmd: c_int, larg: c_long) -> c_long {
        // SAFETY: the commands callers use take no pointer.
        unsafe { ffi::BIO_ctrl(self.as_ptr(), cmd, larg, core::ptr::null_mut()) }
    }
    /// `BIO_set_conn_hostname(b, name)`.
    pub fn set_conn_hostname(&self, name: &str) -> c_long {
        let Some(c) = cstring(name) else { return 0 };
        // SAFETY: the BIO copies the name.
        unsafe {
            ffi::BIO_ctrl(
                self.as_ptr(),
                BIO_C_SET_CONNECT,
                0,
                c.as_ptr().cast_mut().cast(),
            )
        }
    }
    /// `BIO_set_conn_address(b, addr)`.
    pub fn set_conn_address(&self, addr: &Addr) -> c_long {
        // SAFETY: the BIO copies the address.
        unsafe { ffi::BIO_ctrl(self.as_ptr(), BIO_C_SET_CONNECT, 3, addr.as_ptr().cast()) }
    }
    /// `BIO_ctrl_set_connected(b, addr)`.
    pub fn set_connected(&self, addr: &Addr) -> c_long {
        // SAFETY: as above.
        unsafe {
            ffi::BIO_ctrl(
                self.as_ptr(),
                BIO_CTRL_DGRAM_SET_CONNECTED,
                0,
                addr.as_ptr().cast(),
            )
        }
    }
    /// `BIO_dgram_get_peer(b, addr)`.
    pub fn dgram_get_peer(&self, addr: &Addr) -> c_long {
        // SAFETY: the BIO fills in the address.
        unsafe {
            ffi::BIO_ctrl(
                self.as_ptr(),
                BIO_CTRL_DGRAM_GET_PEER,
                0,
                addr.as_ptr().cast(),
            )
        }
    }
    /// `BIO_ctrl(b, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT / _SEND_TIMEOUT, 0, &tv)`.
    pub fn dgram_set_timeout(&self, cmd: c_int, usec: libc::suseconds_t) {
        let mut tv = libc::timeval {
            tv_sec: 0,
            tv_usec: usec,
        };
        // SAFETY: tv is valid for the call.
        unsafe { ffi::BIO_ctrl(self.as_ptr(), cmd, 0, (&raw mut tv).cast()) };
    }
    /// `BIO_get_fd(b, NULL)`.
    pub fn fd(&self) -> c_int {
        let mut fd: c_int = -1;
        // SAFETY: fd is a valid out-pointer.
        unsafe { ffi::BIO_ctrl(self.as_ptr(), BIO_C_GET_FD, 0, (&raw mut fd).cast()) };
        fd
    }
    /// `BIO_set_ssl(b, ssl, BIO_CLOSE)`: the BIO takes the connection.
    pub fn set_ssl(&self, ssl: crate::ssl::Ssl) {
        let p = ssl.into_ptr();
        // SAFETY: the BIO now owns the connection.
        unsafe {
            ffi::BIO_ctrl(
                self.as_ptr(),
                BIO_C_SET_SSL,
                c_long::from(BIO_CLOSE),
                p.cast(),
            )
        };
    }
    /// `BIO_set_write_buffer_size`.
    pub fn set_write_buffer_size(&self, n: c_long) -> c_long {
        // SAFETY: an int argument.
        unsafe { ffi::BIO_int_ctrl(self.as_ptr(), BIO_C_SET_BUFF_SIZE, n, 1) }
    }
    /// `BIO_do_handshake`.
    pub fn do_handshake(&self) -> c_long {
        self.ctrl_long(BIO_C_DO_STATE_MACHINE, 0)
    }
    /// `BIO_should_retry`.
    pub fn should_retry(&self) -> bool {
        // SAFETY: the BIO is live.
        unsafe { ffi::BIO_test_flags(self.as_ptr(), BIO_FLAGS_SHOULD_RETRY) != 0 }
    }
    /// `BIO_should_io_special`.
    pub fn should_io_special(&self) -> bool {
        // SAFETY: as above.
        unsafe { ffi::BIO_test_flags(self.as_ptr(), BIO_FLAGS_IO_SPECIAL) != 0 }
    }
    /// `BIO_get_retry_reason`.
    pub fn retry_reason(&self) -> c_int {
        // SAFETY: as above.
        unsafe { ffi::BIO_get_retry_reason(self.as_ptr()) }
    }
    /// `BIO_eof`.
    pub fn eof(&self) -> bool {
        self.ctrl_long(BIO_CTRL_EOF, 0) != 0
    }
    /// `BIO_tell`.
    pub fn tell(&self) -> c_long {
        self.ctrl_long(BIO_C_FILE_TELL, 0)
    }
    /// `BIO_get_buffer_num_lines`.
    pub fn buffer_num_lines(&self) -> c_long {
        self.ctrl_long(BIO_C_GET_BUFF_NUM_LINES, 0)
    }
    /// `BIO_get_ktls_send` / `_recv`.
    pub fn ktls(&self, send: bool) -> bool {
        self.ctrl_long(
            if send {
                BIO_CTRL_GET_KTLS_SEND
            } else {
                BIO_CTRL_GET_KTLS_RECV
            },
            0,
        ) != 0
    }
    /// `BIO_number_read`.
    pub fn number_read(&self) -> u64 {
        // SAFETY: the BIO is live.
        unsafe { ffi::BIO_number_read(self.as_ptr()) }
    }
    /// `BIO_number_written`.
    pub fn number_written(&self) -> u64 {
        // SAFETY: as above.
        unsafe { ffi::BIO_number_written(self.as_ptr()) }
    }
    /// `BIO_read_ex`: whether it read, and how much.
    pub fn read_ex(&self, buf: &mut [u8]) -> (bool, usize) {
        let mut n = 0usize;
        // SAFETY: buf is writable for its length.
        let r =
            unsafe { ffi::BIO_read_ex(self.as_ptr(), buf.as_mut_ptr().cast(), buf.len(), &mut n) };
        (r == 1, n)
    }
    /// `BIO_gets(b, buf, size)` into a caller's buffer (C semantics: NUL-terminated).
    pub fn gets_into(&self, buf: &mut [u8]) -> c_int {
        let n = c_int::try_from(buf.len()).unwrap_or(c_int::MAX);
        // SAFETY: buf is writable for n bytes.
        unsafe { ffi::BIO_gets(self.as_ptr(), buf.as_mut_ptr().cast(), n) }
    }
    /// `BIO_pop(b)` of this BIO from its chain (the rest stays owned by its owner).
    pub fn pop_from_chain(&self) {
        // SAFETY: the BIO is live.
        unsafe { ffi::BIO_pop(self.as_ptr()) };
    }
    /// `BIO_push(self, next)` without giving up `next` (the C code's `BIO_push(fbio, sbio)`
    /// with `sbio` still owned elsewhere; undone with [`Bio::pop_from_chain`]).
    pub fn push_borrowed(&self, next: &Bio) {
        // SAFETY: both are live; the caller pops `next` again before either is freed.
        unsafe { ffi::BIO_push(self.as_ptr(), next.as_ptr()) };
    }
    /// The callback argument as a `BIO` (`BIO_get_callback_arg`).
    pub fn callback_arg_bio(&self) -> Option<BioRef<'_>> {
        // SAFETY: the BIO is live; callers only ever set a BIO (or NULL) as the argument.
        BioRef::new(unsafe { ffi::BIO_get_callback_arg(self.as_ptr()) }.cast())
    }
    /// `BIO_set_callback_arg(b, arg)` with a `BIO` (or NULL).
    pub fn set_callback_arg_bio(&self, arg: Option<&Bio>) {
        let p = arg.map_or(core::ptr::null_mut(), Bio::as_ptr);
        // SAFETY: the argument is a live BIO the caller keeps alive while it is set.
        unsafe { ffi::BIO_set_callback_arg(self.as_ptr(), p.cast()) };
    }
    /// The connection of an SSL `BIO` (`BIO_get_ssl`).
    pub fn ssl(&self) -> Option<SslRef<'_>> {
        let mut s: *mut SSL = core::ptr::null_mut();
        // SAFETY: s is a valid out-pointer.
        unsafe { ffi::BIO_ctrl(self.as_ptr(), BIO_C_GET_SSL, 0, (&raw mut s).cast()) };
        SslRef::new(s)
    }
}

/// `ERR_print_errors` into a BIO lent by the library.
pub fn print_errors_to(bio: &Bio) {
    crate::err::print_errors(bio);
}

/// `BIO_puts(bio, s)` for any BIO.
pub fn puts(bio: &Bio, s: &str) -> c_int {
    let Some(c) = cstring(s) else { return -1 };
    // SAFETY: a valid C string.
    unsafe { ffi::BIO_puts(bio.as_ptr(), c.as_ptr()) }
}

/// The platform's socket constants the commands use.
pub mod consts {
    pub use libc::{
        AF_INET, AF_INET6, AF_UNIX, AF_UNSPEC, EISCONN, IPPROTO_SCTP, IPPROTO_TCP, SOCK_DGRAM,
        SOCK_STREAM,
    };
}
