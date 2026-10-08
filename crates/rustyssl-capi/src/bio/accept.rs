//! The accept BIO (`BIO_s_accept(3)`): listens on an address and, on the first read or write
//! (or `BIO_do_accept`), accepts a connection and pushes a socket BIO for it, behind a copy of
//! the chain set with `BIO_set_accept_bios`, onto itself. A port of OpenSSL's `bss_acpt.c`.
//!
//! The state machine calls out to other BIO functions (`BIO_push` onto this BIO runs its own
//! control function), so the state's lock is never held across one.

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr;
use core::sync::atomic::Ordering;

use rustyssl_abi::{
    BIO, BIO_C_DO_STATE_MACHINE, BIO_C_GET_ACCEPT, BIO_C_GET_BIND_MODE, BIO_C_GET_FD,
    BIO_C_SET_ACCEPT, BIO_C_SET_BIND_MODE, BIO_C_SET_FD, BIO_C_SET_NBIO, BIO_CLOSE, BIO_CTRL_DUP,
    BIO_CTRL_EOF, BIO_CTRL_FLUSH, BIO_CTRL_GET_CLOSE, BIO_CTRL_PENDING, BIO_CTRL_RESET,
    BIO_CTRL_SET_CLOSE, BIO_CTRL_WPENDING, BIO_FAMILY_IPANY, BIO_FAMILY_IPV4, BIO_FAMILY_IPV6,
    BIO_FLAGS_IO_SPECIAL, BIO_FLAGS_SHOULD_RETRY, BIO_LOOKUP_SERVER, BIO_METHOD,
    BIO_PARSE_PRIO_SERV, BIO_R_LOOKUP_RETURNED_NOTHING, BIO_R_NO_ACCEPT_ADDR_OR_SERVICE_SPECIFIED,
    BIO_R_UNABLE_TO_CREATE_SOCKET, BIO_R_UNSUPPORTED_IP_FAMILY, BIO_RR_ACCEPT,
    BIO_SOCK_INFO_ADDRESS, BIO_SOCK_NONBLOCK, BIO_SOCK_TFO, BIO_TYPE_ACCEPT, BIO_sock_info_u,
    ERR_LIB_BIO, ERR_LIB_SYS,
};

use super::addr::{self, Addr};
use super::method::{Builtin, Funcs};
use super::sock::{self, INVALID_SOCKET};
use super::state::{self, lock};
use super::{Bio, object};
use crate::ffi::{ffi_callback, ffi_export};
use crate::{err, errno, mem};

// The states of OpenSSL's accept state machine.
const ACPT_S_BEFORE: c_int = 1;
const ACPT_S_GET_ADDR: c_int = 2;
const ACPT_S_CREATE_SOCKET: c_int = 3;
const ACPT_S_LISTEN: c_int = 4;
const ACPT_S_ACCEPT: c_int = 5;
const ACPT_S_OK: c_int = 6;

/// A string from `OPENSSL_malloc` that the state owns; the getters hand out its pointer.
pub(crate) struct CString_(*mut c_char);

impl CString_ {
    const NONE: Self = Self(ptr::null_mut());

    fn ptr(&self) -> *mut c_char {
        self.0
    }

    /// Replaces the string, freeing the old one.
    fn set(&mut self, new: *mut c_char) {
        // SAFETY: the old string is owned here, freed once.
        unsafe { mem::release(self.0.cast()) };
        self.0 = new;
    }

    /// The text, `<NULL>` for none, as OpenSSL's `%s` prints it.
    fn text(&self) -> String {
        if self.0.is_null() {
            return "<NULL>".to_owned();
        }
        // SAFETY: an owned NUL-terminated string.
        String::from_utf8_lossy(unsafe { CStr::from_ptr(self.0) }.to_bytes()).into_owned()
    }
}

impl Drop for CString_ {
    fn drop(&mut self) {
        self.set(ptr::null_mut());
    }
}

/// The state of an accept BIO (OpenSSL's `BIO_ACCEPT`).
pub(crate) struct Accept {
    state: c_int,
    accept_family: c_int,
    /// Options for `BIO_listen`.
    bind_mode: c_int,
    /// Options for the accepted sockets.
    accepted_mode: c_int,
    param_addr: CString_,
    param_serv: CString_,
    accept_sock: c_int,
    addr_first: *mut libc::addrinfo,
    addr_iter: *const libc::addrinfo,
    cache_accepting_addr: Addr,
    cache_accepting_name: CString_,
    cache_accepting_serv: CString_,
    cache_peer_addr: Addr,
    cache_peer_name: CString_,
    cache_peer_serv: CString_,
    /// Copied in front of each accepted connection.
    bio_chain: *mut BIO,
}

// SAFETY: the pointers are owned by the state (the lookup's result, the chain) or point into
// what it owns; nothing here is tied to a thread.
unsafe impl Send for Accept {}

impl Accept {
    fn free_lookup(&mut self) {
        // SAFETY: null or the state's own lookup result, freed once.
        unsafe { addr::BIO_ADDRINFO_free(self.addr_first.cast()) };
        self.addr_first = ptr::null_mut();
        self.addr_iter = ptr::null();
    }
}

impl Drop for Accept {
    fn drop(&mut self) {
        self.free_lookup();
        // SAFETY: null or the chain handed over with BIO_set_accept_bios.
        unsafe { super::BIO_free(self.bio_chain) };
    }
}

/// The accept BIO `b` and its state.
///
/// # Safety
/// `b` is null or a live BIO that outlives `'a`.
unsafe fn accept<'a>(b: *mut BIO) -> Option<(&'a Bio, std::sync::Arc<std::sync::Mutex<Accept>>)> {
    // SAFETY: the caller's guarantee.
    let object = unsafe { object(b) }?;
    Some((object, state::get::<Accept>(object)?))
}

ffi_callback! {
    /// Sets up an accept BIO with nothing to listen on yet.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn acpt_new(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        object.init.store(0, Ordering::Relaxed);
        object.num.store(INVALID_SOCKET, Ordering::Relaxed);
        object.flags.store(0, Ordering::Relaxed);
        state::install(object, Accept {
            state: ACPT_S_BEFORE,
            accept_family: BIO_FAMILY_IPANY,
            bind_mode: 0,
            accepted_mode: 0,
            param_addr: CString_::NONE,
            param_serv: CString_::NONE,
            accept_sock: INVALID_SOCKET,
            addr_first: ptr::null_mut(),
            addr_iter: ptr::null(),
            cache_accepting_addr: Addr::unspecified(),
            cache_accepting_name: CString_::NONE,
            cache_accepting_serv: CString_::NONE,
            cache_peer_addr: Addr::unspecified(),
            cache_peer_name: CString_::NONE,
            cache_peer_serv: CString_::NONE,
            bio_chain: ptr::null_mut(),
        });
        object.shutdown.store(1, Ordering::Relaxed);
        1
    }
}

/// OpenSSL's `acpt_close_socket`: shuts down and closes the listening socket.
fn close_socket(object: &Bio, state: &std::sync::Mutex<Accept>) {
    let mut s = lock(state);
    if s.accept_sock != INVALID_SOCKET {
        // SAFETY: the BIO's own socket.
        unsafe { libc::shutdown(s.accept_sock, libc::SHUT_RDWR) };
        // SAFETY: as above.
        unsafe { libc::close(s.accept_sock) };
        s.accept_sock = INVALID_SOCKET;
        object.num.store(INVALID_SOCKET, Ordering::Relaxed);
    }
}

ffi_callback! {
    /// Frees an accept BIO, closing its socket unless `BIO_NOCLOSE` (OpenSSL then also keeps
    /// its state, leaking it; it's freed here, docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn acpt_free(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((object, state)) = (unsafe { accept(b) }) else {
            return 0;
        };
        if object.shutdown.load(Ordering::Relaxed) != 0 {
            close_socket(object, &state);
            object.flags.store(0, Ordering::Relaxed);
            object.init.store(0, Ordering::Relaxed);
        }
        drop(state);
        drop(state::remove::<Accept>(object));
        1
    }
}

/// The address family for the lookup, from `BIO_set_accept_ip_family`'s value.
fn lookup_family(family: c_int) -> Option<c_int> {
    match family {
        BIO_FAMILY_IPV6 => Some(libc::AF_INET6),
        BIO_FAMILY_IPV4 => Some(libc::AF_INET),
        BIO_FAMILY_IPANY => Some(libc::AF_UNSPEC),
        _ => None,
    }
}

/// OpenSSL's `acpt_state`: runs the state machine until it listens, accepts, fails, or has to
/// be retried. Returns 1, 0 or less on failure, or -1 to retry.
///
/// # Safety
/// `b` is a live accept BIO.
unsafe fn acpt_state(b: *mut BIO, object: &Bio, state: &std::sync::Mutex<Accept>) -> c_int {
    loop {
        let current = lock(state).state;
        match current {
            ACPT_S_BEFORE => {
                let mut s = lock(state);
                if s.param_addr.ptr().is_null() && s.param_serv.ptr().is_null() {
                    drop(s);
                    err::raise_with_text(
                        ERR_LIB_BIO,
                        BIO_R_NO_ACCEPT_ADDR_OR_SERVICE_SPECIFIED,
                        "acpt_state",
                        "hostname=<NULL>, service=<NULL>",
                    );
                    return -1;
                }
                // A new bind makes the cached names obsolete.
                s.cache_accepting_name.set(ptr::null_mut());
                s.cache_accepting_serv.set(ptr::null_mut());
                s.cache_peer_name.set(ptr::null_mut());
                s.cache_peer_serv.set(ptr::null_mut());
                s.state = ACPT_S_GET_ADDR;
            }
            ACPT_S_GET_ADDR => {
                let (family, host, serv) = {
                    let s = lock(state);
                    (s.accept_family, s.param_addr.ptr(), s.param_serv.ptr())
                };
                let Some(family) = lookup_family(family) else {
                    err::raise(ERR_LIB_BIO, BIO_R_UNSUPPORTED_IP_FAMILY, "acpt_state");
                    return -1;
                };
                let mut first = ptr::null_mut();
                // SAFETY: the state's strings, which nothing frees during the lookup.
                let ok = unsafe {
                    addr::BIO_lookup(
                        host,
                        serv,
                        BIO_LOOKUP_SERVER,
                        family,
                        libc::SOCK_STREAM,
                        &raw mut first,
                    )
                };
                let mut s = lock(state);
                if ok == 0 {
                    return -1;
                }
                s.free_lookup();
                s.addr_first = first.cast();
                if first.is_null() {
                    drop(s);
                    err::raise(ERR_LIB_BIO, BIO_R_LOOKUP_RETURNED_NOTHING, "acpt_state");
                    return -1;
                }
                s.addr_iter = s.addr_first;
                s.state = ACPT_S_CREATE_SOCKET;
            }
            ACPT_S_CREATE_SOCKET => {
                let iter = lock(state).addr_iter.cast::<rustyssl_abi::BIO_ADDRINFO>();
                // SAFETY: no preconditions.
                unsafe { crate::err::ERR_set_mark() };
                // SAFETY: an entry of the state's lookup result, for each call.
                let family = unsafe { addr::BIO_ADDRINFO_family(iter) };
                // SAFETY: as above.
                let socktype = unsafe { addr::BIO_ADDRINFO_socktype(iter) };
                // SAFETY: as above.
                let protocol = unsafe { addr::BIO_ADDRINFO_protocol(iter) };
                // SAFETY: no preconditions.
                let s_fd = unsafe { sock::BIO_socket(family, socktype, protocol, 0) };
                let mut s = lock(state);
                if s_fd == INVALID_SOCKET {
                    // SAFETY: as above.
                    s.addr_iter = unsafe { addr::BIO_ADDRINFO_next(iter) }.cast();
                    if !s.addr_iter.is_null() {
                        // SAFETY: no preconditions.
                        unsafe { crate::err::ERR_pop_to_mark() };
                        continue;
                    }
                    let text = format!(
                        "calling socket({}, {})",
                        s.param_addr.text(),
                        s.param_serv.text()
                    );
                    drop(s);
                    // SAFETY: no preconditions.
                    unsafe { crate::err::ERR_clear_last_mark() };
                    err::raise_with_text(ERR_LIB_SYS, errno::get(), "acpt_state", &text);
                    err::raise(ERR_LIB_BIO, BIO_R_UNABLE_TO_CREATE_SOCKET, "acpt_state");
                    return -1;
                }
                s.accept_sock = s_fd;
                object.num.store(s_fd, Ordering::Relaxed);
                s.state = ACPT_S_LISTEN;
            }
            ACPT_S_LISTEN => {
                let (sock_fd, iter, mode) = {
                    let s = lock(state);
                    (
                        s.accept_sock,
                        s.addr_iter.cast::<rustyssl_abi::BIO_ADDRINFO>(),
                        s.bind_mode,
                    )
                };
                // SAFETY: an entry of the state's lookup result.
                let address = unsafe { addr::BIO_ADDRINFO_address(iter) };
                let mut local = Addr::unspecified();
                let mut info = BIO_sock_info_u {
                    addr: (&raw mut local).cast(),
                };
                // SAFETY: as above; `info` points to a whole local address.
                let ok = unsafe { sock::BIO_listen(sock_fd, address, mode) } != 0
                    && unsafe {
                        sock::BIO_sock_info(sock_fd, BIO_SOCK_INFO_ADDRESS, &raw mut info)
                    } != 0;
                if !ok {
                    // SAFETY: the BIO's own socket.
                    unsafe { sock::BIO_closesocket(sock_fd) };
                    lock(state).accept_sock = INVALID_SOCKET;
                    object.num.store(INVALID_SOCKET, Ordering::Relaxed);
                    return -1;
                }
                let local_ptr = (&raw const local).cast::<rustyssl_abi::BIO_ADDR>();
                // SAFETY: the local address just filled, for each call.
                let name = unsafe { addr::BIO_ADDR_hostname_string(local_ptr, 1) };
                // SAFETY: as above.
                let serv = unsafe { addr::BIO_ADDR_service_string(local_ptr, 1) };
                let mut s = lock(state);
                s.cache_accepting_addr = local;
                s.cache_accepting_name.set(name);
                s.cache_accepting_serv.set(serv);
                s.state = ACPT_S_ACCEPT;
                return 1;
            }
            ACPT_S_ACCEPT => {
                if !object.next().is_null() {
                    lock(state).state = ACPT_S_OK;
                    continue;
                }
                object.clear_retry_flags();
                object.retry_reason.store(0, Ordering::Relaxed);
                let (listening, mode) = {
                    let mut s = lock(state);
                    s.cache_peer_name.set(ptr::null_mut());
                    s.cache_peer_serv.set(ptr::null_mut());
                    (s.accept_sock, s.accepted_mode)
                };
                let mut peer = Addr::unspecified();
                // SAFETY: a whole local address.
                let s_fd = unsafe { sock::BIO_accept_ex(listening, (&raw mut peer).cast(), mode) };
                if s_fd < 0 {
                    // SAFETY: no preconditions.
                    if unsafe { sock::BIO_sock_should_retry(s_fd) } != 0 {
                        object.set_flags(BIO_FLAGS_IO_SPECIAL | BIO_FLAGS_SHOULD_RETRY);
                        object.retry_reason.store(BIO_RR_ACCEPT, Ordering::Relaxed);
                        return -1;
                    }
                    return s_fd;
                }
                // SAFETY: no preconditions; the BIO owns the new socket.
                let accepted = unsafe { sock::BIO_new_socket(s_fd, BIO_CLOSE) };
                if accepted.is_null() {
                    // SAFETY: the socket accepted above.
                    unsafe { sock::BIO_closesocket(s_fd) };
                    return -1;
                }
                // SAFETY: a live BIO just made.
                if let Some(new) = unsafe { super::object(accepted) } {
                    let callbacks = object.callbacks();
                    new.update_callbacks(|c| *c = callbacks);
                }
                let chain = lock(state).bio_chain;
                let mut top = accepted;
                if !chain.is_null() {
                    // SAFETY: the state's chain, live while it holds it.
                    let copy = unsafe { super::BIO_dup_chain(chain) };
                    // SAFETY: the copy is null or live; `accepted` is live.
                    if copy.is_null() || unsafe { super::BIO_push(copy, accepted) }.is_null() {
                        // SAFETY: made above, freed once.
                        unsafe { super::BIO_free(accepted) };
                        return -1;
                    }
                    top = copy;
                }
                // SAFETY: the caller's guarantee; `top` is live.
                if unsafe { super::BIO_push(b, top) }.is_null() {
                    // SAFETY: made above, freed once.
                    unsafe { super::BIO_free(top) };
                    return -1;
                }
                let peer_ptr = (&raw const peer).cast::<rustyssl_abi::BIO_ADDR>();
                // SAFETY: the accepted peer's address, for each call.
                let name = unsafe { addr::BIO_ADDR_hostname_string(peer_ptr, 1) };
                // SAFETY: as above.
                let serv = unsafe { addr::BIO_ADDR_service_string(peer_ptr, 1) };
                let mut s = lock(state);
                s.cache_peer_addr = peer;
                s.cache_peer_name.set(name);
                s.cache_peer_serv.set(serv);
                s.state = ACPT_S_OK;
                return 1;
            }
            ACPT_S_OK => {
                if object.next().is_null() {
                    lock(state).state = ACPT_S_ACCEPT;
                    continue;
                }
                return 1;
            }
            _ => return 0,
        }
    }
}

/// Reads or writes through the accepted connection, accepting one first if there's none.
///
/// # Safety
/// `b` is a live BIO; `op` reads or writes the next BIO as the caller's buffer allows.
unsafe fn through_connection(b: *mut BIO, op: impl FnOnce(*mut BIO) -> c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some((object, state)) = (unsafe { accept(b) }) else {
        return 0;
    };
    object.clear_retry_flags();
    while object.next().is_null() {
        // SAFETY: as above.
        let ret = unsafe { acpt_state(b, object, &state) };
        if ret <= 0 {
            return ret;
        }
    }
    let ret = op(object.next());
    super::copy_next_retry(object);
    ret
}

ffi_callback! {
    /// Reads from the accepted connection, accepting one first.
    ///
    /// # Safety
    /// `b` is a live BIO; `out` is valid for `len` bytes of writes.
    pub(crate) unsafe extern "C" fn acpt_read(b: *mut BIO, out: *mut c_char, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        let op = |next| {
            // SAFETY: the caller's guarantee about the buffer; the next BIO is live.
            unsafe { super::BIO_read(next, out.cast(), len) }
        };
        // SAFETY: the caller's guarantee.
        unsafe { through_connection(b, op) }
    }
}

ffi_callback! {
    /// Writes to the accepted connection, accepting one first.
    ///
    /// # Safety
    /// `b` is a live BIO; `data` is valid for `len` bytes of reads.
    pub(crate) unsafe extern "C" fn acpt_write(b: *mut BIO, data: *const c_char, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        let op = |next| {
            // SAFETY: the caller's guarantee about the buffer; the next BIO is live.
            unsafe { super::BIO_write(next, data.cast(), len) }
        };
        // SAFETY: the caller's guarantee.
        unsafe { through_connection(b, op) }
    }
}

ffi_callback! {
    /// Writes a string to the accepted connection.
    ///
    /// # Safety
    /// `b` is a live BIO; `text` is a NUL-terminated string.
    pub(crate) unsafe extern "C" fn acpt_puts(b: *mut BIO, text: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        if text.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let len = unsafe { CStr::from_ptr(text) }.count_bytes();
        let len = super::wrap_int(c_long::try_from(len).unwrap_or(c_long::MAX));
        // SAFETY: as above.
        unsafe { acpt_write(b, text, len) }
    }
}

/// Stores a string pointer for `BIO_get_accept_name` and the like.
///
/// # Safety
/// `ptr` is a `char **`.
unsafe fn give(ptr: *mut c_void, value: *mut c_char) {
    // SAFETY: the caller's guarantee.
    unsafe { ptr.cast::<*mut c_char>().write(value) };
}

ffi_callback! {
    /// The accept BIO's controls: what to listen on and how, the listening socket, the names
    /// of the listening and the accepted addresses, the chain put in front of each connection,
    /// and starting (`BIO_do_accept`) or resetting the state machine.
    ///
    /// # Safety
    /// `b` is a live BIO; `ptr` is what the command expects.
    pub(crate) unsafe extern "C" fn acpt_ctrl(b: *mut BIO, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((object, state)) = (unsafe { accept(b) }) else {
            return 0;
        };
        match cmd {
            BIO_CTRL_RESET => {
                lock(&state).state = ACPT_S_BEFORE;
                close_socket(object, &state);
                lock(&state).free_lookup();
                object.flags.store(0, Ordering::Relaxed);
                0
            }
            // SAFETY: the caller's guarantee.
            BIO_C_DO_STATE_MACHINE => c_long::from(unsafe { acpt_state(b, object, &state) }),
            BIO_C_SET_ACCEPT => {
                if ptr.is_null() {
                    let mut s = lock(&state);
                    match num {
                        2 => s.bind_mode &= !BIO_SOCK_NONBLOCK,
                        5 => s.bind_mode &= !BIO_SOCK_TFO,
                        _ => {}
                    }
                    return 1;
                }
                match num {
                    0 => {
                        let mut s = lock(&state);
                        s.param_addr.set(ptr::null_mut());
                        let mut host = ptr::null_mut();
                        let mut serv = s.param_serv.ptr();
                        // SAFETY: the caller's guarantee: a string; the outputs are locals.
                        let ret = unsafe { addr::BIO_parse_hostserv(ptr.cast(), &raw mut host, &raw mut serv, BIO_PARSE_PRIO_SERV) };
                        s.param_addr.0 = host;
                        if serv != s.param_serv.ptr() {
                            s.param_serv.set(serv);
                        }
                        if ret > 0 {
                            object.init.store(1, Ordering::Relaxed);
                        }
                        c_long::from(ret)
                    }
                    1 => {
                        // SAFETY: the caller's guarantee: a string.
                        let copy = unsafe { crate::string::CRYPTO_strdup(ptr.cast(), c"bss_acpt.c".as_ptr(), 0) };
                        lock(&state).param_serv.set(copy);
                        if copy.is_null() {
                            return 0;
                        }
                        object.init.store(1, Ordering::Relaxed);
                        1
                    }
                    2 => {
                        lock(&state).bind_mode |= BIO_SOCK_NONBLOCK;
                        1
                    }
                    3 => {
                        let old = core::mem::replace(&mut lock(&state).bio_chain, ptr.cast());
                        // SAFETY: null or the chain handed over before, freed once.
                        unsafe { super::BIO_free(old) };
                        1
                    }
                    4 => {
                        // SAFETY: the caller's guarantee: an `int`.
                        lock(&state).accept_family = unsafe { ptr.cast::<c_int>().read() };
                        1
                    }
                    5 => {
                        lock(&state).bind_mode |= BIO_SOCK_TFO;
                        1
                    }
                    _ => 1,
                }
            }
            BIO_C_SET_NBIO => {
                let mut s = lock(&state);
                if num != 0 {
                    s.accepted_mode |= BIO_SOCK_NONBLOCK;
                } else {
                    s.accepted_mode &= !BIO_SOCK_NONBLOCK;
                }
                1
            }
            BIO_C_SET_FD => {
                if ptr.is_null() {
                    return 0;
                }
                // SAFETY: the caller's guarantee: an `int`.
                let fd = unsafe { ptr.cast::<c_int>().read() };
                object.num.store(fd, Ordering::Relaxed);
                {
                    let mut s = lock(&state);
                    s.accept_sock = fd;
                    s.state = ACPT_S_ACCEPT;
                }
                object.shutdown.store(super::wrap_int(num), Ordering::Relaxed);
                object.init.store(1, Ordering::Relaxed);
                1
            }
            BIO_C_GET_FD => {
                if object.init.load(Ordering::Relaxed) == 0 {
                    return -1;
                }
                let fd = lock(&state).accept_sock;
                if !ptr.is_null() {
                    // SAFETY: the caller's guarantee: an `int`.
                    unsafe { ptr.cast::<c_int>().write(fd) };
                }
                c_long::from(fd)
            }
            BIO_C_GET_ACCEPT => {
                if object.init.load(Ordering::Relaxed) == 0 {
                    return -1;
                }
                let s = lock(&state);
                let value = match num {
                    0 => s.cache_accepting_name.ptr(),
                    1 => s.cache_accepting_serv.ptr(),
                    2 => s.cache_peer_name.ptr(),
                    3 => s.cache_peer_serv.ptr(),
                    4 => {
                        // SAFETY: null or an entry of the state's lookup result.
                        let family = unsafe { addr::BIO_ADDRINFO_family(s.addr_iter.cast()) };
                        return match family {
                            libc::AF_INET6 => c_long::from(BIO_FAMILY_IPV6),
                            libc::AF_INET => c_long::from(BIO_FAMILY_IPV4),
                            0 => c_long::from(s.accept_family),
                            _ => -1,
                        };
                    }
                    _ => return -1,
                };
                if ptr.is_null() {
                    return -1;
                }
                // SAFETY: the caller's guarantee: a `char **`.
                unsafe { give(ptr, value) };
                1
            }
            BIO_CTRL_GET_CLOSE => c_long::from(object.shutdown.load(Ordering::Relaxed)),
            BIO_CTRL_SET_CLOSE => {
                object.shutdown.store(super::wrap_int(num), Ordering::Relaxed);
                1
            }
            BIO_CTRL_PENDING | BIO_CTRL_WPENDING => 0,
            BIO_CTRL_FLUSH | BIO_CTRL_DUP => 1,
            BIO_C_SET_BIND_MODE => {
                lock(&state).bind_mode = super::wrap_int(num);
                1
            }
            BIO_C_GET_BIND_MODE => c_long::from(lock(&state).bind_mode),
            BIO_CTRL_EOF => {
                let next = object.next();
                if next.is_null() {
                    return 0;
                }
                // SAFETY: the caller's guarantee about `ptr`; the next BIO is live.
                unsafe { super::BIO_ctrl(next, cmd, num, ptr) }
            }
            _ => 0,
        }
    }
}

static ACCEPT: Builtin = Builtin::new(BIO_TYPE_ACCEPT, c"socket accept", || Funcs {
    bputs: Some(acpt_puts),
    ctrl: Some(acpt_ctrl),
    create: Some(acpt_new),
    destroy: Some(acpt_free),
    ..Funcs::classic(acpt_write, acpt_read)
});

ffi_export! {
    /// Returns the accept BIO's method.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_s_accept() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        ACCEPT.get()
    }
}

ffi_export! {
    /// Returns an accept BIO for `str` (`host:service`, or a service alone), or null.
    ///
    /// # Safety
    /// `str` is a NUL-terminated string.
    pub unsafe extern "C" fn BIO_new_accept(str: *const c_char) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        // SAFETY: the built-in method.
        let b = unsafe { super::BIO_new(ACCEPT.get()) };
        if b.is_null() {
            return b;
        }
        // SAFETY: a live accept BIO; BIO_set_accept_name passes the string.
        if unsafe { super::BIO_ctrl(b, BIO_C_SET_ACCEPT, 0, str.cast_mut().cast()) } > 0 {
            return b;
        }
        // SAFETY: made above, freed once.
        unsafe { super::BIO_free(b) };
        ptr::null_mut()
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::AtomicUsize;

    use rustyssl_abi::{BIO_CB_FREE, BIO_NOCLOSE};

    use super::*;

    static FREED: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn count_frees(
        _: *mut BIO,
        oper: c_int,
        _: *const c_char,
        _: usize,
        _: c_int,
        _: c_long,
        ret: c_int,
        _: *mut usize,
    ) -> c_long {
        if oper == BIO_CB_FREE {
            FREED.fetch_add(1, Ordering::Relaxed);
        }
        c_long::from(ret)
    }

    /// docs/DEVIATIONS.md: with `BIO_NOCLOSE`, OpenSSL keeps the socket open and leaks the
    /// state, chain included; the socket stays open here too, but the state is freed.
    #[test]
    #[cfg_attr(miri, ignore = "opens a socket")]
    fn noclose_keeps_the_socket_and_frees_the_state() {
        // SAFETY: the built-in method.
        let b = unsafe { super::super::BIO_new(ACCEPT.get()) };
        // SAFETY: the built-in method.
        let chain = unsafe { super::super::BIO_new(super::super::mem::MEM.get()) };
        // SAFETY: a live BIO and a callback of the right type.
        unsafe { super::super::BIO_set_callback_ex(chain, Some(count_frees)) };
        // SAFETY: a live accept BIO, which takes the chain.
        unsafe { super::super::BIO_ctrl(b, BIO_C_SET_ACCEPT, 3, chain.cast()) };
        // SAFETY: no preconditions.
        let fd = unsafe { sock::BIO_socket(libc::AF_INET, libc::SOCK_STREAM, 0, 0) };
        assert!(fd >= 0);
        // SAFETY: a live BIO; BIO_set_fd passes the descriptor by pointer.
        unsafe { super::super::BIO_int_ctrl(b, BIO_C_SET_FD, c_long::from(BIO_NOCLOSE), fd) };
        // SAFETY: a live BIO, freed once.
        unsafe { super::super::BIO_free(b) };
        assert_eq!(FREED.load(Ordering::Relaxed), 1);
        // SAFETY: the socket, which must still be open.
        assert_ne!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
        // SAFETY: as above.
        unsafe { libc::close(fd) };
    }

    /// docs/DEVIATIONS.md: OpenSSL reads the descriptor through null.
    #[test]
    fn a_null_descriptor_is_refused() {
        // SAFETY: the built-in method.
        let b = unsafe { super::super::BIO_new(ACCEPT.get()) };
        // SAFETY: a live BIO; the null pointer is refused.
        let ret = unsafe { super::super::BIO_ctrl(b, BIO_C_SET_FD, 0, ptr::null_mut()) };
        assert_eq!(ret, 0);
        // SAFETY: made above, freed once.
        unsafe { super::super::BIO_free(b) };
    }
}
