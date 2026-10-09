//! The datagram BIO (`BIO_s_datagram(3)`): a UDP socket with a peer, MTU handling, receive
//! timeouts for DTLS, the local address of each message, and `BIO_sendmmsg`/`BIO_recvmmsg`.
//! A port of OpenSSL's `bss_dgram.c` (SCTP is off in OpenSSL's default build) on Unix.
//!
//! What OpenSSL compiles in differs by platform, and so does this:
//! - **Linux:** messages go in batches of up to 64 through `sendmmsg`/`recvmmsg`; the MTU is
//!   queried with `IP_MTU`/`IPV6_MTU` and discovery set with `IP_MTU_DISCOVER`; IPv4's
//!   don't-fragment is `IP_MTU_DISCOVER` with `IP_PMTUDISC_PROBE`.
//! - **macOS:** one message per call through `sendmsg`/`recvmsg`; no MTU queries;
//!   don't-fragment is `IP_DONTFRAG`.
//! - **Both:** local addresses come from `IP_PKTINFO` and `IPV6_RECVPKTINFO` control
//!   messages, and IPv6's don't-fragment is `IPV6_DONTFRAG`.

use core::ffi::{CStr, c_char, c_int, c_long, c_uint, c_void};
use core::mem::size_of;
use core::ptr;
use core::sync::atomic::Ordering;
use std::sync::Mutex;

use libc::{AF_INET, AF_INET6, AF_UNSPEC, IPPROTO_IP, IPPROTO_IPV6, SOL_SOCKET, socklen_t};
use rustyssl_abi::{
    BIO, BIO_ADDR, BIO_C_GET_FD, BIO_C_SET_FD, BIO_C_SET_NBIO, BIO_CTRL_DGRAM_CONNECT,
    BIO_CTRL_DGRAM_DETECT_PEER_ADDR, BIO_CTRL_DGRAM_GET_EFFECTIVE_CAPS,
    BIO_CTRL_DGRAM_GET_FALLBACK_MTU, BIO_CTRL_DGRAM_GET_LOCAL_ADDR_CAP,
    BIO_CTRL_DGRAM_GET_LOCAL_ADDR_ENABLE, BIO_CTRL_DGRAM_GET_MTU, BIO_CTRL_DGRAM_GET_MTU_OVERHEAD,
    BIO_CTRL_DGRAM_GET_PEER, BIO_CTRL_DGRAM_GET_RECV_TIMEOUT, BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP,
    BIO_CTRL_DGRAM_GET_SEND_TIMEOUT, BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP,
    BIO_CTRL_DGRAM_MTU_DISCOVER, BIO_CTRL_DGRAM_MTU_EXCEEDED, BIO_CTRL_DGRAM_QUERY_MTU,
    BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE, BIO_CTRL_DGRAM_SET_CONNECTED,
    BIO_CTRL_DGRAM_SET_DONT_FRAG, BIO_CTRL_DGRAM_SET_LOCAL_ADDR_ENABLE, BIO_CTRL_DGRAM_SET_MTU,
    BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT, BIO_CTRL_DGRAM_SET_PEEK_MODE, BIO_CTRL_DGRAM_SET_PEER,
    BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, BIO_CTRL_DUP, BIO_CTRL_FLUSH,
    BIO_CTRL_GET_CLOSE, BIO_CTRL_GET_RPOLL_DESCRIPTOR, BIO_CTRL_GET_WPOLL_DESCRIPTOR,
    BIO_CTRL_INFO, BIO_CTRL_PENDING, BIO_CTRL_RESET, BIO_CTRL_SET_CLOSE, BIO_CTRL_WPENDING,
    BIO_DGRAM_CAP_HANDLES_DST_ADDR, BIO_DGRAM_CAP_HANDLES_SRC_ADDR,
    BIO_DGRAM_CAP_PROVIDES_DST_ADDR, BIO_DGRAM_CAP_PROVIDES_SRC_ADDR, BIO_METHOD, BIO_MSG,
    BIO_R_LOCAL_ADDR_NOT_AVAILABLE, BIO_R_NON_FATAL, BIO_R_PORT_MISMATCH, BIO_TYPE_DGRAM,
    ERR_LIB_BIO, ERR_LIB_SYS, ERR_R_INTERNAL_ERROR,
};

use super::addr::{self, Addr};
use super::method::{Builtin, Funcs};
use super::sock;
use super::state::{self, lock};
use super::{Bio, object};
use crate::ffi::{ffi_callback, ffi_export};
use crate::{err, errno};

/// The size OpenSSL gives the control buffer of each message (`BIO_CMSG_ALLOC_LEN`).
#[cfg(target_os = "macos")]
const CMSG_ALLOC_LEN: u32 = 64;
#[cfg(target_os = "linux")]
const CMSG_ALLOC_LEN: u32 = 40;

/// A control buffer, aligned for `struct cmsghdr`.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct Control([u8; 64]);

/// One nanosecond-tick time (OpenSSL's `OSSL_TIME`).
type Time = u64;

const TIME_SECOND: Time = 1_000_000_000;
const TIME_US: Time = 1_000;

/// OpenSSL's `ossl_time_now`: `gettimeofday` in ticks.
fn time_now() -> Time {
    // SAFETY: zero is a valid timeval.
    let mut tv: libc::timeval = unsafe { core::mem::zeroed() };
    // SAFETY: a local timeval; no time zone.
    if unsafe { libc::gettimeofday(&raw mut tv, ptr::null_mut()) } < 0 {
        err::raise_with_text(
            ERR_LIB_SYS,
            errno::get(),
            "ossl_time_now",
            "calling gettimeofday()",
        );
        return 0;
    }
    time_from_timeval(tv)
}

/// OpenSSL's `ossl_time_from_timeval` (0 for a negative time).
fn time_from_timeval(tv: libc::timeval) -> Time {
    let Ok(sec) = u64::try_from(tv.tv_sec) else {
        return 0;
    };
    let usec = u64::try_from(tv.tv_usec).unwrap_or(0);
    sec.wrapping_mul(TIME_SECOND)
        .wrapping_add(usec.wrapping_mul(TIME_US))
}

/// OpenSSL's `ossl_time_to_timeval`, rounding nanoseconds up.
fn time_to_timeval(t: Time) -> libc::timeval {
    let t = t.checked_add(TIME_US - 1).unwrap_or(Time::MAX);
    // SAFETY: zero is a valid timeval.
    let mut tv: libc::timeval = unsafe { core::mem::zeroed() };
    tv.tv_sec = libc::time_t::try_from(t / TIME_SECOND).unwrap_or(libc::time_t::MAX);
    tv.tv_usec = libc::suseconds_t::try_from((t % TIME_SECOND) / TIME_US).unwrap_or(0);
    tv
}

/// The state of a datagram BIO (OpenSSL's `bio_dgram_data`).
pub(crate) struct Dgram {
    peer: Addr,
    local_addr: Addr,
    connected: bool,
    /// The `errno` of the last read or write to retry.
    errno: c_int,
    mtu: c_uint,
    next_timeout: Time,
    socket_timeout: Time,
    peekmode: c_uint,
    local_addr_enabled: bool,
}

// SAFETY: plain values.
unsafe impl Send for Dgram {}

/// The datagram BIO `b` and its state.
///
/// # Safety
/// `b` is null or a live BIO that outlives `'a`.
unsafe fn dgram<'a>(b: *mut BIO) -> Option<(&'a Bio, std::sync::Arc<Mutex<Dgram>>)> {
    // SAFETY: the caller's guarantee.
    let object = unsafe { object(b) }?;
    Some((object, state::get::<Dgram>(object)?))
}

ffi_callback! {
    /// Sets up a datagram BIO with no socket yet.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn dgram_new(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        state::install(object, Dgram {
            peer: Addr::unspecified(),
            local_addr: Addr::unspecified(),
            connected: false,
            errno: 0,
            mtu: 0,
            next_timeout: 0,
            socket_timeout: 0,
            peekmode: 0,
            local_addr_enabled: false,
        });
        1
    }
}

/// OpenSSL's `dgram_clear`: closes the socket if the BIO owns it.
fn clear(object: &Bio) {
    if object.shutdown.load(Ordering::Relaxed) != 0 {
        if object.init.load(Ordering::Relaxed) != 0 {
            // SAFETY: the BIO's own socket.
            unsafe { sock::BIO_closesocket(object.num.load(Ordering::Relaxed)) };
        }
        object.init.store(0, Ordering::Relaxed);
        object.flags.store(0, Ordering::Relaxed);
    }
}

ffi_callback! {
    /// Frees a datagram BIO, closing its socket if it owns it.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn dgram_free(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        clear(object);
        drop(state::remove::<Dgram>(object));
        1
    }
}

/// Gets or sets a `timeval` socket option, raising the system error on failure.
fn set_timeval(fd: c_int, name: c_int, tv: &libc::timeval) {
    let len = socklen_t::try_from(size_of::<libc::timeval>()).unwrap_or(0);
    // SAFETY: a timeval of that length.
    if unsafe { libc::setsockopt(fd, SOL_SOCKET, name, ptr::from_ref(tv).cast(), len) } < 0 {
        err::raise_with_text(
            ERR_LIB_SYS,
            errno::get(),
            "dgram_ctrl",
            "calling setsockopt()",
        );
    }
}

/// OpenSSL's `dgram_adjust_rcv_timeout`: with a DTLS timer set, shortens the receive timeout to
/// the time left on it (at least a microsecond), remembering the socket's own.
fn adjust_rcv_timeout(fd: c_int, state: &Mutex<Dgram>) {
    let next = lock(state).next_timeout;
    if next == 0 {
        return;
    }
    // SAFETY: zero is a valid timeval.
    let mut tv: libc::timeval = unsafe { core::mem::zeroed() };
    let mut len = socklen_t::try_from(size_of::<libc::timeval>()).unwrap_or(0);
    // SAFETY: a local timeval of that length.
    if unsafe {
        libc::getsockopt(
            fd,
            SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw mut tv).cast(),
            &raw mut len,
        )
    } < 0
    {
        err::raise_with_text(
            ERR_LIB_SYS,
            errno::get(),
            "dgram_adjust_rcv_timeout",
            "calling getsockopt()",
        );
    } else {
        lock(state).socket_timeout = time_from_timeval(tv);
    }
    let left = next.saturating_sub(time_now()).max(TIME_US);
    let socket_timeout = lock(state).socket_timeout;
    if socket_timeout == 0 || socket_timeout >= left {
        set_timeval(fd, libc::SO_RCVTIMEO, &time_to_timeval(left));
    }
}

/// OpenSSL's `dgram_reset_rcv_timeout`: restores the socket's receive timeout after a read.
fn reset_rcv_timeout(fd: c_int, state: &Mutex<Dgram>) {
    let (next, socket_timeout) = {
        let s = lock(state);
        (s.next_timeout, s.socket_timeout)
    };
    if next != 0 {
        set_timeval(fd, libc::SO_RCVTIMEO, &time_to_timeval(socket_timeout));
    }
}

/// OpenSSL's `dgram_update_local_addr`: the socket's local address, or none.
fn update_local_addr(fd: c_int, state: &Mutex<Dgram>) {
    let mut local = Addr::unspecified();
    let mut len = socklen_t::try_from(size_of::<Addr>()).unwrap_or(0);
    // SAFETY: a whole local address of `len` bytes.
    if unsafe { libc::getsockname(fd, (&raw mut local).cast(), &raw mut len) } < 0 {
        local = Addr::unspecified();
    }
    lock(state).local_addr = local;
}

/// OpenSSL's `BIO_dgram_should_retry`.
fn should_retry(ret: isize) -> bool {
    // SAFETY: no preconditions.
    (ret == 0 || ret == -1) && unsafe { BIO_dgram_non_fatal_error(errno::get()) } != 0
}

ffi_callback! {
    /// Reads one datagram (peeking in peek mode). Unless connected, its sender becomes the peer
    /// (`BIO_dgram_set_peer`).
    ///
    /// # Safety
    /// `b` is a live BIO; `out` is null or valid for `len` bytes of writes.
    pub(crate) unsafe extern "C" fn dgram_read(b: *mut BIO, out: *mut c_char, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((object, state)) = (unsafe { dgram(b) }) else {
            return 0;
        };
        if out.is_null() {
            return 0;
        }
        let fd = object.num.load(Ordering::Relaxed);
        errno::set(0);
        let mut peer = Addr::unspecified();
        let mut peer_len = socklen_t::try_from(size_of::<Addr>()).unwrap_or(0);
        adjust_rcv_timeout(fd, &state);
        let (flags, connected) = {
            let s = lock(&state);
            (if s.peekmode != 0 { libc::MSG_PEEK } else { 0 }, s.connected)
        };
        // SAFETY: the caller's buffer; a whole local address.
        let ret = unsafe {
            libc::recvfrom(fd, out.cast(), usize::try_from(len).unwrap_or(0), flags, (&raw mut peer).cast(), &raw mut peer_len)
        };
        if !connected && ret >= 0 {
            // SAFETY: a live BIO and a whole address.
            unsafe { super::BIO_ctrl(b, BIO_CTRL_DGRAM_SET_PEER, 0, (&raw mut peer).cast()) };
        }
        object.clear_retry_flags();
        if ret < 0 && should_retry(ret) {
            object.set_retry_read();
            lock(&state).errno = errno::get();
        }
        reset_rcv_timeout(fd, &state);
        c_int::try_from(ret).unwrap_or(-1)
    }
}

ffi_callback! {
    /// Writes one datagram, to the connected peer or with `sendto` to the peer set.
    ///
    /// # Safety
    /// `b` is a live BIO; `data` is valid for `len` bytes of reads.
    pub(crate) unsafe extern "C" fn dgram_write(b: *mut BIO, data: *const c_char, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((object, state)) = (unsafe { dgram(b) }) else {
            return 0;
        };
        let fd = object.num.load(Ordering::Relaxed);
        let size = usize::try_from(len).unwrap_or(0);
        errno::set(0);
        let (connected, peer) = {
            let s = lock(&state);
            (s.connected, s.peer)
        };
        let ret = if connected {
            // SAFETY: the caller's buffer.
            unsafe { libc::write(fd, data.cast(), size) }
        } else {
            // SAFETY: a whole local address.
            let peer_len = unsafe { addr::sockaddr_size(&raw const peer) };
            // SAFETY: the caller's buffer; the address holds `peer_len` bytes.
            unsafe { libc::sendto(fd, data.cast(), size, 0, (&raw const peer).cast(), peer_len) }
        };
        object.clear_retry_flags();
        if ret <= 0 && should_retry(ret) {
            object.set_retry_write();
            lock(&state).errno = errno::get();
        }
        c_int::try_from(ret).unwrap_or(-1)
    }
}

ffi_callback! {
    /// Writes a string as one datagram.
    ///
    /// # Safety
    /// `b` is a live BIO; `text` is a NUL-terminated string.
    pub(crate) unsafe extern "C" fn dgram_puts(b: *mut BIO, text: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        if text.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let len = unsafe { CStr::from_ptr(text) }.count_bytes();
        let len = super::wrap_int(c_long::try_from(len).unwrap_or(c_long::MAX));
        // SAFETY: as above.
        unsafe { dgram_write(b, text, len) }
    }
}

/// Whether an IPv6 address is an IPv4-mapped one (`IN6_IS_ADDR_V4MAPPED`).
fn is_v4_mapped(ap: &Addr) -> bool {
    let mut raw = [0u8; 16];
    let mut len = 0;
    // SAFETY: a whole address; the buffer holds any raw address of this family.
    let ok = unsafe {
        addr::BIO_ADDR_rawaddress(
            ptr::from_ref(ap).cast(),
            raw.as_mut_ptr().cast(),
            &raw mut len,
        )
    } != 0;
    ok && len == 16 && raw[..10].iter().all(|b| *b == 0) && raw[10] == 0xff && raw[11] == 0xff
}

/// OpenSSL's `dgram_get_mtu_overhead`: the IP and UDP header sizes for the peer.
fn mtu_overhead(ap: &Addr) -> c_long {
    // SAFETY: a whole address.
    match unsafe { addr::family(ap) } {
        AF_INET6 if !is_v4_mapped(ap) => 48,
        _ => 28,
    }
}

/// Sets an `int` socket option, raising the system error on failure. Returns `setsockopt`'s
/// result.
fn set_option(fd: c_int, level: c_int, name: c_int, value: c_int) -> c_long {
    let len = socklen_t::try_from(size_of::<c_int>()).unwrap_or(0);
    // SAFETY: a local int of that length.
    let ret = unsafe { libc::setsockopt(fd, level, name, (&raw const value).cast(), len) };
    if ret < 0 {
        err::raise_with_text(
            ERR_LIB_SYS,
            errno::get(),
            "dgram_ctrl",
            "calling setsockopt()",
        );
    }
    c_long::from(ret)
}

/// OpenSSL's `enable_local_addr`: turns on receiving each datagram's destination address.
/// Returns 1, or 0 on failure or for another family.
fn enable_local_addr(fd: c_int, family: c_int, enable: c_int) -> c_int {
    let len = socklen_t::try_from(size_of::<c_int>()).unwrap_or(0);
    let (level, name) = match family {
        AF_INET => (IPPROTO_IP, libc::IP_PKTINFO),
        AF_INET6 => (IPPROTO_IPV6, libc::IPV6_RECVPKTINFO),
        _ => return 0,
    };
    // SAFETY: a local int of that length.
    c_int::from(unsafe { libc::setsockopt(fd, level, name, (&raw const enable).cast(), len) } >= 0)
}

/// The family of the socket's local address.
fn sock_family(state: &Mutex<Dgram>) -> c_int {
    let local = lock(state).local_addr;
    // SAFETY: a whole address.
    unsafe { addr::family(&raw const local) }
}

/// Copies an address into the caller's buffer for `BIO_dgram_get_peer` and the like: `num`
/// bytes, or the whole address if `num` is 0, larger, or negative (OpenSSL's would copy a huge
/// count, docs/DEVIATIONS.md). Returns the count.
///
/// # Safety
/// `ptr` is valid for the count's bytes of writes.
unsafe fn copy_address(ap: &Addr, ptr: *mut c_void, num: c_long) -> c_long {
    // SAFETY: a whole address.
    let size = c_long::from(unsafe { addr::sockaddr_size(ap) });
    let count = if num <= 0 || num > size { size } else { num };
    if !ptr.is_null() {
        // SAFETY: the caller's guarantee; the address has `size` bytes, at least `count`.
        unsafe {
            ptr::copy_nonoverlapping(
                ptr::from_ref(ap).cast::<u8>(),
                ptr.cast::<u8>(),
                usize::try_from(count).unwrap_or(0),
            )
        };
    }
    count
}

/// `BIO_CTRL_DGRAM_MTU_DISCOVER`: Linux sets `IP_PMTUDISC_DO`; elsewhere -1.
#[cfg(target_os = "linux")]
fn mtu_discover(fd: c_int) -> c_long {
    let mut local = Addr::unspecified();
    let mut len = socklen_t::try_from(size_of::<Addr>()).unwrap_or(0);
    // SAFETY: a whole local address.
    if unsafe { libc::getsockname(fd, (&raw mut local).cast(), &raw mut len) } < 0 {
        return 0;
    }
    // SAFETY: as above.
    match unsafe { addr::family(&raw const local) } {
        AF_INET => set_option(fd, IPPROTO_IP, libc::IP_MTU_DISCOVER, libc::IP_PMTUDISC_DO),
        AF_INET6 => set_option(
            fd,
            IPPROTO_IPV6,
            libc::IPV6_MTU_DISCOVER,
            libc::IPV6_PMTUDISC_DO,
        ),
        _ => -1,
    }
}

#[cfg(target_os = "macos")]
fn mtu_discover(_fd: c_int) -> c_long {
    -1
}

/// `BIO_CTRL_DGRAM_QUERY_MTU`: Linux asks the kernel and subtracts the headers; elsewhere 0.
#[cfg(target_os = "linux")]
fn query_mtu(fd: c_int, state: &Mutex<Dgram>) -> c_long {
    let mut local = Addr::unspecified();
    let mut len = socklen_t::try_from(size_of::<Addr>()).unwrap_or(0);
    // SAFETY: a whole local address.
    if unsafe { libc::getsockname(fd, (&raw mut local).cast(), &raw mut len) } < 0 {
        return 0;
    }
    // SAFETY: as above.
    let (level, name) = match unsafe { addr::family(&raw const local) } {
        AF_INET => (IPPROTO_IP, libc::IP_MTU),
        AF_INET6 => (IPPROTO_IPV6, libc::IPV6_MTU),
        _ => return 0,
    };
    let mut value: c_int = 0;
    let mut value_len = socklen_t::try_from(size_of::<c_int>()).unwrap_or(0);
    // SAFETY: a local int of that length.
    if unsafe { libc::getsockopt(fd, level, name, (&raw mut value).cast(), &raw mut value_len) } < 0
        || value < 0
    {
        return 0;
    }
    let mtu = c_long::from(value) - mtu_overhead(&local);
    let mtu = c_uint::try_from(mtu & 0xFFFF_FFFF).unwrap_or(0);
    lock(state).mtu = mtu;
    c_long::from(mtu)
}

#[cfg(target_os = "macos")]
fn query_mtu(_fd: c_int, _state: &Mutex<Dgram>) -> c_long {
    0
}

/// `BIO_CTRL_DGRAM_SET_DONT_FRAG` for an IPv4 peer.
#[cfg(target_os = "linux")]
fn dont_frag_v4(fd: c_int, on: bool) -> c_long {
    let value = if on {
        libc::IP_PMTUDISC_PROBE
    } else {
        libc::IP_PMTUDISC_DONT
    };
    set_option(fd, IPPROTO_IP, libc::IP_MTU_DISCOVER, value)
}

#[cfg(target_os = "macos")]
fn dont_frag_v4(fd: c_int, on: bool) -> c_long {
    set_option(fd, IPPROTO_IP, libc::IP_DONTFRAG, c_int::from(on))
}

/// A `getsockopt` of a `timeval` into the caller's `ptr` for the timeout getters.
///
/// # Safety
/// `ptr` is null (the call fails) or a `struct timeval`.
unsafe fn get_timeout(fd: c_int, name: c_int, ptr: *mut c_void) -> c_long {
    let mut len = socklen_t::try_from(size_of::<libc::timeval>()).unwrap_or(0);
    // SAFETY: the caller's guarantee.
    let ret = unsafe { libc::getsockopt(fd, SOL_SOCKET, name, ptr, &raw mut len) };
    if ret < 0 {
        err::raise_with_text(
            ERR_LIB_SYS,
            errno::get(),
            "dgram_ctrl",
            "calling getsockopt()",
        );
        return c_long::from(ret);
    }
    if usize::try_from(len).ok() != Some(size_of::<libc::timeval>()) {
        let text = if name == libc::SO_RCVTIMEO {
            "Unexpected getsockopt(SO_RCVTIMEO) return size"
        } else {
            "Unexpected getsockopt(SO_SNDTIMEO) return size"
        };
        err::raise_with_text(ERR_LIB_BIO, ERR_R_INTERNAL_ERROR, "dgram_ctrl", text);
        return -1;
    }
    c_long::from(len)
}

/// A `setsockopt` of the caller's `timeval` for the timeout setters.
///
/// # Safety
/// `ptr` is null (the call fails) or a `struct timeval`.
unsafe fn set_timeout(fd: c_int, name: c_int, ptr: *mut c_void) -> c_long {
    let len = socklen_t::try_from(size_of::<libc::timeval>()).unwrap_or(0);
    // SAFETY: the caller's guarantee.
    let ret = unsafe { libc::setsockopt(fd, SOL_SOCKET, name, ptr, len) };
    if ret < 0 {
        err::raise_with_text(
            ERR_LIB_SYS,
            errno::get(),
            "dgram_ctrl",
            "calling setsockopt()",
        );
    }
    c_long::from(ret)
}

/// Reads the caller's address argument, as `BIO_ADDR_make(..., BIO_ADDR_sockaddr(ptr))` does.
/// A null pointer (OpenSSL's would crash, docs/DEVIATIONS.md) makes an unspecified address.
///
/// # Safety
/// `ptr` is null or an address.
unsafe fn address_from(ptr: *mut c_void) -> Addr {
    let mut ap = Addr::unspecified();
    if !ptr.is_null() {
        // SAFETY: the caller's guarantee; `ap` is a whole address.
        unsafe { addr::make(&raw mut ap, ptr.cast()) };
    }
    ap
}

ffi_callback! {
    /// The datagram BIO's controls: its socket, the peer and connection, MTU queries and
    /// settings, timeouts and timer expiry, peek mode, local addresses, and poll descriptors.
    /// Negative results are returned as -1, as in OpenSSL.
    ///
    /// # Safety
    /// `b` is a live BIO; `ptr` is what the command expects.
    pub(crate) unsafe extern "C" fn dgram_ctrl(b: *mut BIO, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((object, state)) = (unsafe { dgram(b) }) else {
            return 0;
        };
        let fd = object.num.load(Ordering::Relaxed);
        // SAFETY: the caller's guarantee, for `ptr` in each command.
        let ret = unsafe { control(object, &state, fd, cmd, num, ptr) };
        if ret < 0 { -1 } else { ret }
    }
}

/// The body of [`dgram_ctrl`], before the normalization of errors.
///
/// # Safety
/// As for [`dgram_ctrl`].
#[expect(clippy::too_many_lines, reason = "one arm per control, as in OpenSSL")]
unsafe fn control(
    object: &Bio,
    state: &Mutex<Dgram>,
    fd: c_int,
    cmd: c_int,
    num: c_long,
    ptr: *mut c_void,
) -> c_long {
    match cmd {
        BIO_CTRL_RESET | BIO_CTRL_INFO => 0,
        BIO_C_SET_FD => {
            if ptr.is_null() {
                return 0;
            }
            clear(object);
            // SAFETY: the caller's guarantee: an `int`.
            let new_fd = unsafe { ptr.cast::<c_int>().read() };
            object.num.store(new_fd, Ordering::Relaxed);
            object
                .shutdown
                .store(super::wrap_int(num), Ordering::Relaxed);
            object.init.store(1, Ordering::Relaxed);
            update_local_addr(new_fd, state);
            let mut peer = Addr::unspecified();
            let mut len = socklen_t::try_from(size_of::<Addr>()).unwrap_or(0);
            // SAFETY: a whole local address.
            if unsafe { libc::getpeername(new_fd, (&raw mut peer).cast(), &raw mut len) } == 0 {
                let mut s = lock(state);
                // SAFETY: both are whole addresses.
                unsafe { addr::make(&raw mut s.peer, &raw const peer) };
                s.connected = true;
            }
            if lock(state).local_addr_enabled
                && enable_local_addr(new_fd, sock_family(state), 1) < 1
            {
                lock(state).local_addr_enabled = false;
            }
            1
        }
        BIO_C_GET_FD => {
            if object.init.load(Ordering::Relaxed) == 0 {
                return -1;
            }
            if !ptr.is_null() {
                // SAFETY: the caller's guarantee: an `int`.
                unsafe { ptr.cast::<c_int>().write(fd) };
            }
            c_long::from(fd)
        }
        BIO_CTRL_GET_CLOSE => c_long::from(object.shutdown.load(Ordering::Relaxed)),
        BIO_CTRL_SET_CLOSE => {
            object
                .shutdown
                .store(super::wrap_int(num), Ordering::Relaxed);
            1
        }
        BIO_CTRL_PENDING | BIO_CTRL_WPENDING => 0,
        BIO_CTRL_DUP | BIO_CTRL_FLUSH => 1,
        BIO_CTRL_DGRAM_CONNECT | BIO_CTRL_DGRAM_SET_PEER => {
            // SAFETY: the caller's guarantee: an address.
            lock(state).peer = unsafe { address_from(ptr) };
            1
        }
        BIO_CTRL_DGRAM_MTU_DISCOVER => mtu_discover(fd),
        BIO_CTRL_DGRAM_QUERY_MTU => query_mtu(fd, state),
        BIO_CTRL_DGRAM_GET_FALLBACK_MTU => {
            let peer = lock(state).peer;
            // SAFETY: a whole address.
            let base = match unsafe { addr::family(&raw const peer) } {
                AF_INET6 if !is_v4_mapped(&peer) => 1280,
                _ => 576,
            };
            base - mtu_overhead(&peer)
        }
        BIO_CTRL_DGRAM_GET_MTU => c_long::from(lock(state).mtu),
        BIO_CTRL_DGRAM_SET_MTU => {
            lock(state).mtu = c_uint::try_from(num & 0xFFFF_FFFF).unwrap_or(0);
            num
        }
        BIO_CTRL_DGRAM_SET_CONNECTED => {
            let mut s = lock(state);
            if ptr.is_null() {
                s.connected = false;
                s.peer = Addr::unspecified();
            } else {
                s.connected = true;
                // SAFETY: the caller's guarantee: an address.
                s.peer = unsafe { address_from(ptr) };
            }
            1
        }
        BIO_CTRL_DGRAM_GET_PEER => {
            let peer = lock(state).peer;
            // SAFETY: the caller's guarantee: room for the address.
            unsafe { copy_address(&peer, ptr, num) }
        }
        BIO_CTRL_DGRAM_DETECT_PEER_ADDR => {
            let mut peer = lock(state).peer;
            // SAFETY: a whole address.
            if unsafe { addr::family(&raw const peer) } == AF_UNSPEC {
                let mut found = Addr::unspecified();
                let mut len = socklen_t::try_from(size_of::<libc::sockaddr>()).unwrap_or(0);
                // SAFETY: a whole local address, of more than `len` bytes.
                let ok =
                    unsafe { libc::getpeername(fd, (&raw mut found).cast(), &raw mut len) } == 0;
                // SAFETY: as above.
                if !ok || unsafe { addr::family(&raw const found) } == AF_UNSPEC {
                    return 0;
                }
                peer = found;
            }
            // SAFETY: the caller's guarantee: room for the address.
            unsafe { copy_address(&peer, ptr, num) }
        }
        BIO_C_SET_NBIO => {
            // SAFETY: no preconditions.
            if unsafe { sock::BIO_socket_nbio(fd, c_int::from(num != 0)) } == 0 {
                0
            } else {
                1
            }
        }
        BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT => {
            if !ptr.is_null() {
                // SAFETY: the caller's guarantee: a `struct timeval`.
                let tv = unsafe { ptr.cast::<libc::timeval>().read_unaligned() };
                lock(state).next_timeout = time_from_timeval(tv);
            }
            1
        }
        // SAFETY: the caller's guarantee: a `struct timeval`, for each of these.
        BIO_CTRL_DGRAM_SET_RECV_TIMEOUT => unsafe { set_timeout(fd, libc::SO_RCVTIMEO, ptr) },
        // SAFETY: as above.
        BIO_CTRL_DGRAM_GET_RECV_TIMEOUT => unsafe { get_timeout(fd, libc::SO_RCVTIMEO, ptr) },
        // SAFETY: as above.
        BIO_CTRL_DGRAM_SET_SEND_TIMEOUT => unsafe { set_timeout(fd, libc::SO_SNDTIMEO, ptr) },
        // SAFETY: as above.
        BIO_CTRL_DGRAM_GET_SEND_TIMEOUT => unsafe { get_timeout(fd, libc::SO_SNDTIMEO, ptr) },
        BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP | BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP => {
            let mut s = lock(state);
            if s.errno == libc::EAGAIN {
                s.errno = 0;
                1
            } else {
                0
            }
        }
        BIO_CTRL_DGRAM_MTU_EXCEEDED => {
            let mut s = lock(state);
            if s.errno == libc::EMSGSIZE {
                s.errno = 0;
                1
            } else {
                0
            }
        }
        BIO_CTRL_DGRAM_SET_DONT_FRAG => {
            let peer = lock(state).peer;
            // SAFETY: a whole address.
            match unsafe { addr::family(&raw const peer) } {
                AF_INET => dont_frag_v4(fd, num != 0),
                AF_INET6 => {
                    set_option(fd, IPPROTO_IPV6, libc::IPV6_DONTFRAG, c_int::from(num != 0))
                }
                _ => -1,
            }
        }
        BIO_CTRL_DGRAM_GET_MTU_OVERHEAD => mtu_overhead(&lock(state).peer),
        BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE | BIO_CTRL_DGRAM_SET_PEEK_MODE => {
            lock(state).peekmode = c_uint::try_from(num & 0xFFFF_FFFF).unwrap_or(0);
            1
        }
        BIO_CTRL_DGRAM_GET_LOCAL_ADDR_CAP => 1,
        BIO_CTRL_DGRAM_SET_LOCAL_ADDR_ENABLE => {
            let enable = num > 0;
            if enable != lock(state).local_addr_enabled {
                if enable_local_addr(fd, sock_family(state), c_int::from(enable)) < 1 {
                    return 0;
                }
                lock(state).local_addr_enabled = enable;
            }
            1
        }
        BIO_CTRL_DGRAM_GET_LOCAL_ADDR_ENABLE => {
            if !ptr.is_null() {
                // SAFETY: the caller's guarantee: an `int`.
                unsafe {
                    ptr.cast::<c_int>()
                        .write(c_int::from(lock(state).local_addr_enabled))
                };
            }
            1
        }
        BIO_CTRL_DGRAM_GET_EFFECTIVE_CAPS => c_long::from(
            BIO_DGRAM_CAP_HANDLES_DST_ADDR
                | BIO_DGRAM_CAP_HANDLES_SRC_ADDR
                | BIO_DGRAM_CAP_PROVIDES_DST_ADDR
                | BIO_DGRAM_CAP_PROVIDES_SRC_ADDR,
        ),
        // SAFETY: the caller's guarantee: a poll descriptor.
        BIO_CTRL_GET_RPOLL_DESCRIPTOR | BIO_CTRL_GET_WPOLL_DESCRIPTOR => unsafe {
            sock::poll_descriptor(ptr, fd)
        },
        _ => 0,
    }
}

/// A control-message length in the platform's type (`socklen_t` or `size_t`).
fn c_size<T: TryFrom<u32> + Default>(len: u32) -> T {
    T::try_from(len).unwrap_or_default()
}

/// A pointer to the field at `offset` of the struct at `base`.
fn field_at<T>(base: *mut u8, offset: usize) -> *mut T {
    base.wrapping_add(offset).cast()
}

/// The `n`th message of an array with the given stride (OpenSSL's `BIO_MSG_N`).
fn nth(msg: *mut BIO_MSG, stride: usize, n: usize) -> *mut BIO_MSG {
    msg.cast::<u8>().wrapping_add(n.wrapping_mul(stride)).cast()
}

/// OpenSSL's `translate_msg`: the `msghdr` for a message. Unless connected, the peer is the
/// message's, with the size of the socket's family.
fn translate_msg(
    m: &BIO_MSG,
    connected: bool,
    family: c_int,
    iov: &mut libc::iovec,
    control: &mut Control,
) -> libc::msghdr {
    iov.iov_base = m.data;
    iov.iov_len = m.data_len;
    // SAFETY: zero is a valid msghdr.
    let mut mh: libc::msghdr = unsafe { core::mem::zeroed() };
    if !connected && !m.peer.is_null() {
        mh.msg_name = m.peer.cast();
        mh.msg_namelen = match family {
            AF_INET => socklen_t::try_from(size_of::<libc::sockaddr_in>()).unwrap_or(0),
            AF_INET6 => socklen_t::try_from(size_of::<libc::sockaddr_in6>()).unwrap_or(0),
            _ => 0,
        };
    }
    mh.msg_iov = ptr::from_mut(iov);
    mh.msg_iovlen = 1;
    if !m.local.is_null() {
        mh.msg_control = control.0.as_mut_ptr().cast();
        mh.msg_controllen = c_size(CMSG_ALLOC_LEN);
    }
    mh
}

/// OpenSSL's `extract_local`: the destination address from a received message's control data,
/// written into `local` field by field (family, address, port, and for IPv6 the scope).
///
/// # Safety
/// `mh` describes a received message with its control buffer; `local` is a whole `BIO_ADDR`.
unsafe fn extract_local(
    mh: &libc::msghdr,
    family: c_int,
    bound: &Addr,
    local: *mut BIO_ADDR,
) -> bool {
    // SAFETY: the caller's guarantee, for each CMSG step.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(mh) };
    while !cmsg.is_null() {
        // SAFETY: a control message inside the buffer.
        let header = unsafe { cmsg.read_unaligned() };
        // SAFETY: as above.
        let data = unsafe { libc::CMSG_DATA(cmsg) };
        if family == AF_INET
            && header.cmsg_level == IPPROTO_IP
            && header.cmsg_type == libc::IP_PKTINFO
        {
            // SAFETY: an IP_PKTINFO message holds an in_pktinfo.
            let info = unsafe { data.cast::<libc::in_pktinfo>().read_unaligned() };
            // SAFETY: the bound address is IPv4.
            let port = unsafe { bound.s_in.sin_port };
            // SAFETY: the caller's guarantee: a whole BIO_ADDR, for each field.
            unsafe {
                field_at::<libc::in_addr>(
                    local.cast(),
                    core::mem::offset_of!(libc::sockaddr_in, sin_addr),
                )
                .write_unaligned(info.ipi_addr)
            };
            // SAFETY: as above.
            unsafe {
                field_at::<libc::sa_family_t>(
                    local.cast(),
                    core::mem::offset_of!(libc::sockaddr_in, sin_family),
                )
                .write_unaligned(libc::sa_family_t::try_from(AF_INET).unwrap_or(0))
            };
            // SAFETY: as above.
            unsafe {
                field_at::<u16>(
                    local.cast(),
                    core::mem::offset_of!(libc::sockaddr_in, sin_port),
                )
                .write_unaligned(port)
            };
            return true;
        }
        if family == AF_INET6
            && header.cmsg_level == IPPROTO_IPV6
            && header.cmsg_type == libc::IPV6_PKTINFO
        {
            // SAFETY: an IPV6_PKTINFO message holds an in6_pktinfo.
            let info = unsafe { data.cast::<libc::in6_pktinfo>().read_unaligned() };
            // SAFETY: the bound address is IPv6.
            let (port, scope) = unsafe { (bound.s_in6.sin6_port, bound.s_in6.sin6_scope_id) };
            // SAFETY: the caller's guarantee: a whole BIO_ADDR, for each field.
            unsafe {
                field_at::<libc::in6_addr>(
                    local.cast(),
                    core::mem::offset_of!(libc::sockaddr_in6, sin6_addr),
                )
                .write_unaligned(info.ipi6_addr)
            };
            // SAFETY: as above.
            unsafe {
                field_at::<libc::sa_family_t>(
                    local.cast(),
                    core::mem::offset_of!(libc::sockaddr_in6, sin6_family),
                )
                .write_unaligned(libc::sa_family_t::try_from(AF_INET6).unwrap_or(0))
            };
            // SAFETY: as above.
            unsafe {
                field_at::<u16>(
                    local.cast(),
                    core::mem::offset_of!(libc::sockaddr_in6, sin6_port),
                )
                .write_unaligned(port)
            };
            // SAFETY: as above.
            unsafe {
                field_at::<u32>(
                    local.cast(),
                    core::mem::offset_of!(libc::sockaddr_in6, sin6_scope_id),
                )
                .write_unaligned(scope)
            };
            // SAFETY: as above.
            unsafe {
                field_at::<u32>(
                    local.cast(),
                    core::mem::offset_of!(libc::sockaddr_in6, sin6_flowinfo),
                )
                .write_unaligned(0)
            };
            return true;
        }
        // SAFETY: as above.
        cmsg = unsafe { libc::CMSG_NXTHDR(mh, cmsg) };
    }
    false
}

/// OpenSSL's `pack_local`: the source address for a message to send, as an `IP_PKTINFO` or
/// `IPV6_PKTINFO` control message. The port (and IPv6 scope) must be 0 or the bound one.
///
/// # Safety
/// `mh`'s control buffer has room for the message; `local` is an address.
unsafe fn pack_local(
    mh: &mut libc::msghdr,
    family: c_int,
    bound: &Addr,
    local: *const BIO_ADDR,
) -> bool {
    // SAFETY: the caller's guarantee.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(mh) };
    if cmsg.is_null() {
        return false;
    }
    let mut want = Addr::unspecified();
    // SAFETY: the caller's guarantee; `want` is a whole address.
    unsafe {
        ptr::copy_nonoverlapping(
            local.cast::<u8>(),
            (&raw mut want).cast::<u8>(),
            size_of::<libc::sockaddr_in6>().min(size_of::<Addr>()),
        )
    };
    if family == AF_INET {
        let size = size_of::<libc::in_pktinfo>();
        // SAFETY: zero is a valid in_pktinfo.
        let mut info: libc::in_pktinfo = unsafe { core::mem::zeroed() };
        // SAFETY: an IPv4 address.
        info.ipi_spec_dst = unsafe { want.s_in.sin_addr };
        // SAFETY: as above, for both.
        let (port, bound_port) = unsafe { (want.s_in.sin_port, bound.s_in.sin_port) };
        if port != 0 && bound_port != port {
            err::raise(ERR_LIB_BIO, BIO_R_PORT_MISMATCH, "pack_local");
            return false;
        }
        // SAFETY: the caller's guarantee: the control buffer has room.
        unsafe {
            write_cmsg(
                mh,
                cmsg,
                IPPROTO_IP,
                libc::IP_PKTINFO,
                ptr::from_ref(&info).cast(),
                size,
            )
        };
        return true;
    }
    if family == AF_INET6 {
        let size = size_of::<libc::in6_pktinfo>();
        // SAFETY: zero is a valid in6_pktinfo.
        let mut info: libc::in6_pktinfo = unsafe { core::mem::zeroed() };
        // SAFETY: an IPv6 address, for each read.
        info.ipi6_addr = unsafe { want.s_in6.sin6_addr };
        // SAFETY: as above.
        let (port, bound_port) = unsafe { (want.s_in6.sin6_port, bound.s_in6.sin6_port) };
        // SAFETY: as above.
        let (scope, bound_scope) = unsafe { (want.s_in6.sin6_scope_id, bound.s_in6.sin6_scope_id) };
        if (port != 0 && bound_port != port) || (scope != 0 && bound_scope != scope) {
            err::raise(ERR_LIB_BIO, BIO_R_PORT_MISMATCH, "pack_local");
            return false;
        }
        // SAFETY: as above.
        unsafe {
            write_cmsg(
                mh,
                cmsg,
                IPPROTO_IPV6,
                libc::IPV6_PKTINFO,
                ptr::from_ref(&info).cast(),
                size,
            )
        };
        return true;
    }
    false
}

/// Fills one control message with `len` bytes of `data`, and sizes the buffer to it.
///
/// # Safety
/// `cmsg` is the first header of `mh`'s control buffer, which has room for the message.
unsafe fn write_cmsg(
    mh: &mut libc::msghdr,
    cmsg: *mut libc::cmsghdr,
    level: c_int,
    kind: c_int,
    data: *const u8,
    len: usize,
) {
    let len32 = u32::try_from(len).unwrap_or(0);
    // SAFETY: zero is a valid cmsghdr.
    let mut header: libc::cmsghdr = unsafe { core::mem::zeroed() };
    // SAFETY: no preconditions.
    header.cmsg_len = c_size(unsafe { libc::CMSG_LEN(len32) });
    header.cmsg_level = level;
    header.cmsg_type = kind;
    // SAFETY: the caller's guarantee.
    unsafe { cmsg.write_unaligned(header) };
    // SAFETY: as above.
    let at = unsafe { libc::CMSG_DATA(cmsg) };
    // SAFETY: as above: the data fits after the header.
    unsafe { ptr::copy_nonoverlapping(data, at, len) };
    // SAFETY: no preconditions.
    mh.msg_controllen = c_size(unsafe { libc::CMSG_SPACE(len32) });
}

/// The state's view for the message functions: connected, the socket's family, the bound
/// address, and whether local addresses are on.
fn msg_view(state: &Mutex<Dgram>) -> (bool, c_int, Addr, bool) {
    let s = lock(state);
    // SAFETY: a whole address.
    let family = unsafe { addr::family(&raw const s.local_addr) };
    (s.connected, family, s.local_addr, s.local_addr_enabled)
}

/// Stores the count of messages processed.
///
/// # Safety
/// `processed` is null or valid for a write.
unsafe fn processed_set(processed: *mut usize, n: usize) {
    if !processed.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { processed.write(n) };
    }
}

/// Fails a message call with `BIO_R_LOCAL_ADDR_NOT_AVAILABLE`.
///
/// # Safety
/// As for [`processed_set`].
unsafe fn no_local(processed: *mut usize) -> c_int {
    err::raise(
        ERR_LIB_BIO,
        BIO_R_LOCAL_ADDR_NOT_AVAILABLE,
        "dgram_sendmmsg",
    );
    // SAFETY: the caller's guarantee.
    unsafe { processed_set(processed, 0) };
    0
}

/// The most messages one call sends or receives (OpenSSL's `BIO_MAX_MSGS_PER_CALL` on Linux,
/// one with `sendmsg`/`recvmsg` on macOS).
#[cfg(target_os = "linux")]
const MAX_MSGS: usize = 64;
#[cfg(target_os = "macos")]
const MAX_MSGS: usize = 1;

/// Sends or receives a batch: Linux's `sendmmsg`/`recvmmsg`.
///
/// # Safety
/// The headers point to valid buffers.
#[cfg(target_os = "linux")]
unsafe fn transfer(
    fd: c_int,
    headers: &mut [libc::msghdr],
    send: bool,
) -> Result<Vec<usize>, c_int> {
    let mut batch: Vec<libc::mmsghdr> = headers
        .iter()
        .map(|h| libc::mmsghdr {
            msg_hdr: *h,
            msg_len: 0,
        })
        .collect();
    let count = c_uint::try_from(batch.len()).unwrap_or(0);
    let ret = if send {
        // SAFETY: the caller's guarantee.
        unsafe { libc::sendmmsg(fd, batch.as_mut_ptr(), count, 0) }
    } else {
        // SAFETY: as above.
        unsafe { libc::recvmmsg(fd, batch.as_mut_ptr(), count, 0, ptr::null_mut()) }
    };
    let Ok(done) = usize::try_from(ret) else {
        return Err(errno::get());
    };
    for (h, m) in headers.iter_mut().zip(&batch) {
        *h = m.msg_hdr;
    }
    Ok(batch
        .iter()
        .take(done)
        .map(|m| usize::try_from(m.msg_len).unwrap_or(0))
        .collect())
}

/// As above, on macOS: one message with `sendmsg`/`recvmsg`.
///
/// # Safety
/// As above.
#[cfg(target_os = "macos")]
unsafe fn transfer(
    fd: c_int,
    headers: &mut [libc::msghdr],
    send: bool,
) -> Result<Vec<usize>, c_int> {
    let Some(header) = headers.first_mut() else {
        return Ok(Vec::new());
    };
    let ret = if send {
        // SAFETY: the caller's guarantee.
        unsafe { libc::sendmsg(fd, header, 0) }
    } else {
        // SAFETY: as above.
        unsafe { libc::recvmsg(fd, header, 0) }
    };
    usize::try_from(ret)
        .map(|n| vec![n])
        .map_err(|_| errno::get())
}

/// The shared body of [`dgram_sendmmsg`] and [`dgram_recvmmsg`].
///
/// # Safety
/// As for those.
unsafe fn mmsg(
    b: *mut BIO,
    msg: *mut BIO_MSG,
    stride: usize,
    num_msg: usize,
    processed: *mut usize,
    send: bool,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some((object, state)) = (unsafe { dgram(b) }) else {
        // SAFETY: as above.
        unsafe { processed_set(processed, 0) };
        return 0;
    };
    if num_msg == 0 {
        // SAFETY: as above.
        unsafe { processed_set(processed, 0) };
        return 1;
    }
    let count = num_msg.min(MAX_MSGS);
    let (connected, family, bound, local_enabled) = msg_view(&state);
    let mut iovs: Vec<libc::iovec> = vec![
        libc::iovec {
            iov_base: ptr::null_mut(),
            iov_len: 0
        };
        count
    ];
    let mut controls = vec![Control([0; 64]); count];
    let mut headers = Vec::with_capacity(count);
    for i in 0..count {
        // SAFETY: the caller's guarantee: `num_msg` messages at that stride.
        let m = unsafe { nth(msg, stride, i).read_unaligned() };
        let (Some(iov), Some(control)) = (iovs.get_mut(i), controls.get_mut(i)) else {
            break;
        };
        let mut mh = translate_msg(&m, connected, family, iov, control);
        if !m.local.is_null() {
            if !local_enabled {
                // SAFETY: as above.
                return unsafe { no_local(processed) };
            }
            // SAFETY: the control buffer has room; the caller's local address.
            if send && !unsafe { pack_local(&mut mh, family, &bound, m.local) } {
                // SAFETY: as above.
                return unsafe { no_local(processed) };
            }
        }
        headers.push(mh);
    }
    let fd = object.num.load(Ordering::Relaxed);
    // SAFETY: the headers point to the caller's buffers and the local control buffers.
    let lengths = match unsafe { transfer(fd, &mut headers, send) } {
        Ok(lengths) => lengths,
        Err(code) => {
            err::raise(
                ERR_LIB_SYS,
                code,
                if send {
                    "dgram_sendmmsg"
                } else {
                    "dgram_recvmmsg"
                },
            );
            // SAFETY: as above.
            unsafe { processed_set(processed, 0) };
            return 0;
        }
    };
    for (i, (len, mh)) in lengths.iter().zip(&headers).enumerate() {
        let at = nth(msg, stride, i);
        // SAFETY: the caller's guarantee, as above.
        let mut m = unsafe { at.read_unaligned() };
        m.data_len = *len;
        m.flags = 0;
        // SAFETY: as above.
        unsafe { at.write_unaligned(m) };
        // SAFETY: the received control data and the caller's local address.
        if !send && !m.local.is_null() && !unsafe { extract_local(mh, family, &bound, m.local) } {
            // SAFETY: as above.
            unsafe { addr::BIO_ADDR_clear(m.local) };
        }
    }
    // SAFETY: as above.
    unsafe { processed_set(processed, lengths.len()) };
    1
}

ffi_callback! {
    /// Sends messages, each to its own peer unless connected and from its own local address if
    /// enabled: up to 64 per call on Linux, one on macOS.
    ///
    /// # Safety
    /// `b` is a live BIO; `msg` holds `num_msg` messages at `stride`; `processed` is valid for a
    /// write.
    pub(crate) unsafe extern "C" fn dgram_sendmmsg(b: *mut BIO, msg: *mut BIO_MSG, stride: usize, num_msg: usize, flags: u64, processed: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        let _ = flags;
        // SAFETY: the caller's guarantee.
        unsafe { mmsg(b, msg, stride, num_msg, processed, true) }
    }
}

ffi_callback! {
    /// Receives messages, with each sender and, if enabled, destination address.
    ///
    /// # Safety
    /// As for `dgram_sendmmsg`.
    pub(crate) unsafe extern "C" fn dgram_recvmmsg(b: *mut BIO, msg: *mut BIO_MSG, stride: usize, num_msg: usize, flags: u64, processed: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        let _ = flags;
        // SAFETY: the caller's guarantee.
        unsafe { mmsg(b, msg, stride, num_msg, processed, false) }
    }
}

static DATAGRAM: Builtin = Builtin::new(BIO_TYPE_DGRAM, c"datagram socket", || Funcs {
    bputs: Some(dgram_puts),
    ctrl: Some(dgram_ctrl),
    create: Some(dgram_new),
    destroy: Some(dgram_free),
    bsendmmsg: Some(dgram_sendmmsg),
    brecvmmsg: Some(dgram_recvmmsg),
    ..Funcs::classic(dgram_write, dgram_read)
});

ffi_export! {
    /// Returns the datagram BIO's method.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_s_datagram() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        DATAGRAM.get()
    }
}

ffi_export! {
    /// Returns a datagram BIO on `fd`, closing it when freed if `close_flag` is `BIO_CLOSE`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_new_dgram(fd: c_int, close_flag: c_int) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        // SAFETY: the built-in method.
        let b = unsafe { super::BIO_new(DATAGRAM.get()) };
        if !b.is_null() {
            // SAFETY: a live BIO; BIO_int_ctrl passes the descriptor by pointer, as BIO_set_fd
            // does.
            unsafe { super::BIO_int_ctrl(b, BIO_C_SET_FD, c_long::from(close_flag), fd) };
        }
        b
    }
}

ffi_export! {
    /// Whether `err` (an `errno` value) is a datagram failure to retry: `EWOULDBLOCK`/`EAGAIN`,
    /// `EINTR`, `EPROTO`, `EINPROGRESS`, or `EALREADY` (unlike sockets, not `ENOTCONN`).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_dgram_non_fatal_error(err: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        c_int::from(matches!(err, libc::EWOULDBLOCK | libc::EINTR | libc::EPROTO | libc::EINPROGRESS | libc::EALREADY))
    }
}

ffi_export! {
    /// Whether an error code is one to retry: a system error that `BIO_sock_non_fatal_error`
    /// accepts, or `BIO_R_NON_FATAL`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_err_is_non_fatal(errcode: c_uint) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        let code = core::ffi::c_ulong::from(errcode);
        let reason = crate::err::strings::reason_of(code);
        if errcode & rustyssl_abi::ERR_SYSTEM_FLAG != 0 {
            // SAFETY: no preconditions.
            return unsafe { sock::BIO_sock_non_fatal_error(c_int::try_from(reason).unwrap_or(0)) };
        }
        c_int::from(crate::err::library_of(code) == ERR_LIB_BIO && reason == core::ffi::c_ulong::from(BIO_R_NON_FATAL.unsigned_abs()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: OpenSSL copies a negative (huge) count, and dereferences these null
    /// pointers.
    #[test]
    fn negative_counts_and_null_arguments_are_safe() {
        // SAFETY: the built-in method.
        let b = unsafe { super::super::BIO_new(DATAGRAM.get()) };
        let mut out = Addr::unspecified();
        let at = (&raw mut out).cast::<c_void>();
        // SAFETY: a live BIO; the buffer holds a whole address.
        let copied = unsafe { super::super::BIO_ctrl(b, BIO_CTRL_DGRAM_GET_PEER, -1, at) };
        // SAFETY: a whole address.
        let size = unsafe { addr::sockaddr_size(&raw const out) };
        assert_eq!(copied, c_long::from(size));
        for cmd in [
            BIO_CTRL_DGRAM_SET_PEER,
            BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT,
            BIO_CTRL_DGRAM_GET_LOCAL_ADDR_ENABLE,
        ] {
            // SAFETY: a live BIO; the null pointers are ignored.
            let ret = unsafe { super::super::BIO_ctrl(b, cmd, 0, ptr::null_mut()) };
            assert_eq!(ret, 1);
        }
        // SAFETY: as above.
        let ret = unsafe { super::super::BIO_ctrl(b, BIO_C_SET_FD, 0, ptr::null_mut()) };
        assert_eq!(ret, 0);
        // SAFETY: made above, freed once.
        unsafe { super::super::BIO_free(b) };
    }
}
