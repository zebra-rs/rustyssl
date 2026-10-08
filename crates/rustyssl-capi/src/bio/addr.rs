//! Socket addresses and name lookups (`BIO_ADDR(3)`, `BIO_ADDRINFO(3)`, `BIO_lookup(3)`,
//! `BIO_parse_hostserv(3)`), a port of OpenSSL's `bio_addr.c` on Unix.
//!
//! A `BIO_ADDR` is OpenSSL's union of the IPv4, IPv6, and Unix-domain socket addresses,
//! allocated with `OPENSSL_zalloc`. A `BIO_ADDRINFO` is the C library's `struct addrinfo`, from
//! `getaddrinfo` and freed with `freeaddrinfo`, except for Unix-domain lookups, which build a
//! one-entry list themselves. `BIO_ADDRINFO_address` hands out the entry's `struct sockaddr` as
//! a `BIO_ADDR`, so a `BIO_ADDR` pointer may point at no more than its family's address:
//! nothing here reads more of one than its family's size.

use core::ffi::{CStr, c_char, c_int, c_uchar, c_ushort, c_void};
use core::mem::size_of;
use core::ptr;

use libc::{
    AF_INET, AF_INET6, AF_UNIX, AF_UNSPEC, IPPROTO_TCP, IPPROTO_UDP, SOCK_DGRAM, SOCK_STREAM,
};
use rustyssl_abi::{
    BIO_ADDR, BIO_ADDRINFO, BIO_LOOKUP_SERVER, BIO_PARSE_PRIO_HOST,
    BIO_R_AMBIGUOUS_HOST_OR_SERVICE, BIO_R_MALFORMED_HOST_OR_SERVICE,
    BIO_R_UNSUPPORTED_PROTOCOL_FAMILY, BIO_hostserv_priorities, BIO_lookup_type, ERR_LIB_BIO,
    ERR_LIB_SYS, ERR_R_BIO_LIB, ERR_R_PASSED_NULL_PARAMETER, ERR_R_SYS_LIB,
};

use crate::ffi::ffi_export;
use crate::{err, errno, mem};

/// OpenSSL's `union bio_addr_st`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) union Addr {
    pub(crate) sa: libc::sockaddr,
    pub(crate) s_in6: libc::sockaddr_in6,
    pub(crate) s_in: libc::sockaddr_in,
    pub(crate) s_un: libc::sockaddr_un,
}

impl Addr {
    /// An address with no family (`AF_UNSPEC`).
    pub(crate) fn unspecified() -> Self {
        // SAFETY: all-zero bytes are a valid value of each member, and AF_UNSPEC is 0.
        unsafe { core::mem::zeroed() }
    }
}

/// The size of each member's address.
const SIZE_IN: usize = size_of::<libc::sockaddr_in>();
const SIZE_IN6: usize = size_of::<libc::sockaddr_in6>();
const SIZE_UN: usize = size_of::<libc::sockaddr_un>();

/// The size of a Unix-domain address's path field.
const PATH_ROOM: usize = SIZE_UN - core::mem::offset_of!(libc::sockaddr_un, sun_path);

/// `getnameinfo`'s buffer sizes (`NI_MAXHOST`, `NI_MAXSERV`).
const NI_MAXHOST: usize = 1025;
const NI_MAXSERV: usize = 32;

/// The family of the address at `ap`.
///
/// # Safety
/// `ap` points to at least a `struct sockaddr`'s family.
pub(crate) unsafe fn family(ap: *const Addr) -> c_int {
    let at = field::<libc::sa_family_t>(ap, core::mem::offset_of!(libc::sockaddr, sa_family));
    // SAFETY: the caller's guarantee; the family is at the same place in every member.
    c_int::from(unsafe { at.read_unaligned() })
}

/// A pointer to the field at `offset` of the address at `ap` (every member starts at 0).
fn field<T>(ap: *const Addr, offset: usize) -> *const T {
    ap.cast::<u8>().wrapping_add(offset).cast()
}

/// The size of the address at `ap` (OpenSSL's `BIO_ADDR_sockaddr_size`): its family's, or the
/// whole union's for another family.
///
/// # Safety
/// As for [`family`].
pub(crate) unsafe fn sockaddr_size(ap: *const Addr) -> libc::socklen_t {
    // SAFETY: the caller's guarantee.
    let size = match unsafe { family(ap) } {
        AF_INET => SIZE_IN,
        AF_INET6 => SIZE_IN6,
        AF_UNIX => SIZE_UN,
        _ => size_of::<Addr>(),
    };
    libc::socklen_t::try_from(size).unwrap_or(0)
}

/// OpenSSL's `BIO_ADDR_make`: sets `ap` to the address `sa` (zeroing the rest). Returns
/// whether its family is one a `BIO_ADDR` holds; `ap` is zeroed either way.
///
/// # Safety
/// `ap` is a whole `BIO_ADDR`, valid for writes; `sa` holds an address of its family's size.
pub(crate) unsafe fn make(ap: *mut Addr, sa: *const Addr) -> bool {
    // SAFETY: the caller's guarantee, for each access.
    unsafe { ap.write(Addr::unspecified()) };
    // SAFETY: as above.
    let size = match unsafe { family(sa) } {
        AF_INET => SIZE_IN,
        AF_INET6 => SIZE_IN6,
        AF_UNIX => SIZE_UN,
        _ => return false,
    };
    // SAFETY: as above; both hold `size` bytes.
    unsafe { ptr::copy_nonoverlapping(sa.cast::<u8>(), ap.cast::<u8>(), size) };
    true
}

/// A NUL-terminated string copied into `OPENSSL_malloc` memory, as `OPENSSL_strdup` does.
fn c_strdup(text: &[u8]) -> *mut c_char {
    let copy = mem::alloc(text.len() + 1).cast::<u8>();
    if !copy.is_null() {
        // SAFETY: the block has room for the text and the NUL.
        unsafe { ptr::copy_nonoverlapping(text.as_ptr(), copy, text.len()) };
        let end = copy.wrapping_add(text.len());
        // SAFETY: as above.
        unsafe { end.write(0) };
    }
    copy.cast()
}

/// The bytes of a NUL-terminated C buffer, up to its NUL.
fn until_nul(buf: &[u8]) -> &[u8] {
    CStr::from_bytes_until_nul(buf).map_or(buf, CStr::to_bytes)
}

ffi_export! {
    /// Returns a new address with no family (`AF_UNSPEC`), or null.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_ADDR_new() -> *mut BIO_ADDR
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        let ap = mem::alloc_zeroed(size_of::<Addr>()).cast::<Addr>();
        if !ap.is_null() {
            // SAFETY: a fresh, zeroed block of the union's size.
            unsafe { ap.write(Addr::unspecified()) };
        }
        ap.cast()
    }
}

ffi_export! {
    /// Frees an address made by `BIO_ADDR_new`; null does nothing.
    ///
    /// # Safety
    /// `ap` is null or from `BIO_ADDR_new`/`BIO_ADDR_dup`, not used afterwards.
    pub unsafe extern "C" fn BIO_ADDR_free(ap: *mut BIO_ADDR)
    where failure = (), library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { mem::release(ap.cast()) };
    }
}

ffi_export! {
    /// Makes `ap` an address with no family.
    ///
    /// # Safety
    /// `ap` is null (OpenSSL's would crash) or a whole `BIO_ADDR`.
    pub unsafe extern "C" fn BIO_ADDR_clear(ap: *mut BIO_ADDR)
    where failure = (), library = ERR_LIB_BIO
    {
        if !ap.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { ap.cast::<Addr>().write(Addr::unspecified()) };
        }
    }
}

ffi_export! {
    /// Copies `src` into `dst`. Returns 1, or 0 for a null argument or a family a `BIO_ADDR`
    /// doesn't hold.
    ///
    /// # Safety
    /// `dst` is null or a whole `BIO_ADDR`; `src` is null or an address.
    pub unsafe extern "C" fn BIO_ADDR_copy(dst: *mut BIO_ADDR, src: *const BIO_ADDR) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        if dst.is_null() || src.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        if unsafe { family(src.cast()) } == AF_UNSPEC {
            // SAFETY: as above.
            unsafe { dst.cast::<Addr>().write(Addr::unspecified()) };
            return 1;
        }
        // SAFETY: as above.
        c_int::from(unsafe { make(dst.cast(), src.cast()) })
    }
}

ffi_export! {
    /// Returns a new copy of `ap`, or null (also for null).
    ///
    /// # Safety
    /// `ap` is null or an address.
    pub unsafe extern "C" fn BIO_ADDR_dup(ap: *const BIO_ADDR) -> *mut BIO_ADDR
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        if ap.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let copy = unsafe { BIO_ADDR_new() };
        // SAFETY: the caller's guarantee; the copy is a whole BIO_ADDR or null.
        if !copy.is_null() && unsafe { BIO_ADDR_copy(copy, ap) } == 0 {
            // SAFETY: made above.
            unsafe { BIO_ADDR_free(copy) };
            return ptr::null_mut();
        }
        copy
    }
}

ffi_export! {
    /// Sets `ap` from a raw address: for `AF_INET` and `AF_INET6`, `wherelen` bytes of address
    /// (4 or 16) and a port in network order; for `AF_UNIX`, a path of `wherelen` bytes.
    /// Returns 1, or 0 for another family or a wrong length.
    ///
    /// # Safety
    /// `ap` is a whole `BIO_ADDR`; `where_` is valid for `wherelen` bytes (a NUL-terminated
    /// path for `AF_UNIX`).
    pub unsafe extern "C" fn BIO_ADDR_rawmake(ap: *mut BIO_ADDR, family: c_int, where_: *const c_void, wherelen: usize, port: c_ushort) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        let ap = ap.cast::<Addr>();
        if ap.is_null() || where_.is_null() {
            return 0;
        }
        let family_value = libc::sa_family_t::try_from(family).unwrap_or(0);
        match family {
            AF_UNIX => {
                if wherelen.saturating_add(1) > PATH_ROOM {
                    return 0;
                }
                // SAFETY: zero is a valid address.
                let mut s_un: libc::sockaddr_un = unsafe { core::mem::zeroed() };
                s_un.sun_family = family_value;
                // OpenSSL copies the path with `strncpy`, up to its NUL or the room for one.
                // SAFETY: the caller's guarantee; the path field has PATH_ROOM bytes.
                unsafe { libc::strncpy(s_un.sun_path.as_mut_ptr(), where_.cast(), PATH_ROOM - 1) };
                // SAFETY: the caller's guarantee: `ap` is a whole union.
                unsafe { ap.cast::<libc::sockaddr_un>().write_unaligned(s_un) };
                1
            }
            AF_INET => {
                if wherelen != size_of::<libc::in_addr>() {
                    return 0;
                }
                // SAFETY: zero is a valid address.
                let mut s_in: libc::sockaddr_in = unsafe { core::mem::zeroed() };
                s_in.sin_family = family_value;
                s_in.sin_port = port;
                // SAFETY: the caller's guarantee: 4 bytes of address.
                s_in.sin_addr = unsafe { where_.cast::<libc::in_addr>().read_unaligned() };
                // SAFETY: as above: `ap` is a whole union.
                unsafe { ap.cast::<libc::sockaddr_in>().write_unaligned(s_in) };
                1
            }
            AF_INET6 => {
                if wherelen != size_of::<libc::in6_addr>() {
                    return 0;
                }
                // SAFETY: zero is a valid address.
                let mut s_in6: libc::sockaddr_in6 = unsafe { core::mem::zeroed() };
                s_in6.sin6_family = family_value;
                s_in6.sin6_port = port;
                // SAFETY: the caller's guarantee: 16 bytes of address.
                s_in6.sin6_addr = unsafe { where_.cast::<libc::in6_addr>().read_unaligned() };
                // SAFETY: as above.
                unsafe { ap.cast::<libc::sockaddr_in6>().write_unaligned(s_in6) };
                1
            }
            _ => 0,
        }
    }
}

ffi_export! {
    /// The address's family (`AF_INET`, `AF_INET6`, `AF_UNIX`, or `AF_UNSPEC`); -1 for null
    /// (OpenSSL's would crash).
    ///
    /// # Safety
    /// `ap` is null or an address.
    pub unsafe extern "C" fn BIO_ADDR_family(ap: *const BIO_ADDR) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        if ap.is_null() {
            return -1;
        }
        // SAFETY: the caller's guarantee.
        unsafe { family(ap.cast()) }
    }
}

ffi_export! {
    /// Copies the raw address (4 or 16 bytes, or the path without its NUL) to `p` if it isn't
    /// null, and its length to `*l` if `l` isn't null. Returns 1, or 0 for another family.
    ///
    /// # Safety
    /// `ap` is null or an address; `p` is null or has room for the raw address; `l` is null or
    /// valid for a write.
    pub unsafe extern "C" fn BIO_ADDR_rawaddress(ap: *const BIO_ADDR, p: *mut c_void, l: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        let ap = ap.cast::<Addr>();
        if ap.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let fam = unsafe { family(ap) };
        let (from, len): (*const u8, usize) = match fam {
            AF_INET => (
                field(ap, core::mem::offset_of!(libc::sockaddr_in, sin_addr)),
                size_of::<libc::in_addr>(),
            ),
            AF_INET6 => (
                field(ap, core::mem::offset_of!(libc::sockaddr_in6, sin6_addr)),
                size_of::<libc::in6_addr>(),
            ),
            AF_UNIX => {
                let path = field::<c_char>(ap, core::mem::offset_of!(libc::sockaddr_un, sun_path));
                // A path that fills the field has no NUL; OpenSSL's strlen reads past it.
                // SAFETY: as above.
                (path.cast(), unsafe { libc::strnlen(path, PATH_ROOM) })
            }
            _ => return 0,
        };
        if !p.is_null() {
            // SAFETY: the caller's guarantee about `p`; `from` holds `len` bytes.
            unsafe { ptr::copy_nonoverlapping(from, p.cast::<u8>(), len) };
        }
        if !l.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { l.write(len) };
        }
        1
    }
}

ffi_export! {
    /// The port in network order, or 0 for a family without ports.
    ///
    /// # Safety
    /// `ap` is null or an address.
    pub unsafe extern "C" fn BIO_ADDR_rawport(ap: *const BIO_ADDR) -> c_ushort
    where failure = 0, library = ERR_LIB_BIO
    {
        let ap = ap.cast::<Addr>();
        if ap.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        match unsafe { family(ap) } {
            AF_INET => {
                let at = field::<c_ushort>(ap, core::mem::offset_of!(libc::sockaddr_in, sin_port));
                // SAFETY: as above: an address of this family.
                unsafe { at.read_unaligned() }
            }
            AF_INET6 => {
                let at = field::<c_ushort>(ap, core::mem::offset_of!(libc::sockaddr_in6, sin6_port));
                // SAFETY: as above.
                unsafe { at.read_unaligned() }
            }
            _ => 0,
        }
    }
}

/// OpenSSL's `addr_strings`: the host and service of `ap` from `getnameinfo`, numeric if asked,
/// copied with `OPENSSL_strdup`. Raises the lookup's error and returns `None` on failure.
///
/// # Safety
/// `ap` is an address.
unsafe fn addr_strings(
    ap: *const Addr,
    numeric: bool,
    function: &str,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut host = [0u8; NI_MAXHOST];
    let mut serv = [0u8; NI_MAXSERV];
    let flags = if numeric {
        libc::NI_NUMERICHOST | libc::NI_NUMERICSERV
    } else {
        0
    };
    // SAFETY: the caller's guarantee.
    let size = unsafe { sockaddr_size(ap) };
    // SAFETY: the caller's guarantee; the buffers are valid for their sizes.
    let ret = unsafe {
        libc::getnameinfo(
            ap.cast(),
            size,
            host.as_mut_ptr().cast(),
            libc::socklen_t::try_from(host.len()).unwrap_or(0),
            serv.as_mut_ptr().cast(),
            libc::socklen_t::try_from(serv.len()).unwrap_or(0),
            flags,
        )
    };
    if ret != 0 {
        raise_gai(ret, 0, "getnameinfo", function);
        return None;
    }
    let mut service = until_nul(&serv).to_vec();
    if service.is_empty() {
        // SAFETY: the caller's guarantee.
        let port = u16::from_be(unsafe { BIO_ADDR_rawport(ap.cast()) });
        service = port.to_string().into_bytes();
    }
    Some((until_nul(&host).to_vec(), service))
}

/// Raises a `getaddrinfo`/`getnameinfo` failure as OpenSSL does: a system error for
/// `EAI_SYSTEM`, else `ERR_R_SYS_LIB` with `gai_strerror`'s text (of `shown`, if not 0).
#[track_caller]
fn raise_gai(ret: c_int, shown: c_int, call: &str, function: &str) {
    if ret == libc::EAI_SYSTEM {
        err::raise_with_text(
            ERR_LIB_SYS,
            errno::get(),
            function,
            &format!("calling {call}()"),
        );
        return;
    }
    let code = if shown != 0 { shown } else { ret };
    // SAFETY: no preconditions.
    let message = unsafe { libc::gai_strerror(code) };
    // SAFETY: gai_strerror returns a static string.
    let text = unsafe { CStr::from_ptr(message) };
    err::raise_with_bytes(ERR_LIB_BIO, ERR_R_SYS_LIB, function, text.to_bytes());
}

ffi_export! {
    /// The address's host as a string from `getnameinfo` (numeric if `numeric` isn't 0), to free
    /// with `OPENSSL_free`; null on failure.
    ///
    /// # Safety
    /// `ap` is null or an address.
    pub unsafe extern "C" fn BIO_ADDR_hostname_string(ap: *const BIO_ADDR, numeric: c_int) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        if ap.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        unsafe { addr_strings(ap.cast(), numeric != 0, "addr_strings") }.map_or(ptr::null_mut(), |(host, _)| c_strdup(&host))
    }
}

ffi_export! {
    /// The address's service (port) as a string from `getnameinfo` (numeric if `numeric` isn't
    /// 0), to free with `OPENSSL_free`; null on failure.
    ///
    /// # Safety
    /// `ap` is null or an address.
    pub unsafe extern "C" fn BIO_ADDR_service_string(ap: *const BIO_ADDR, numeric: c_int) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        if ap.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        unsafe { addr_strings(ap.cast(), numeric != 0, "addr_strings") }.map_or(ptr::null_mut(), |(_, serv)| c_strdup(&serv))
    }
}

ffi_export! {
    /// The path of a Unix-domain address, to free with `OPENSSL_free`; null for another family.
    ///
    /// # Safety
    /// `ap` is null or an address.
    pub unsafe extern "C" fn BIO_ADDR_path_string(ap: *const BIO_ADDR) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        let mut len = 0;
        // SAFETY: the caller's guarantee; the path is copied out below.
        if ap.is_null() || unsafe { family(ap.cast()) } != AF_UNIX || unsafe { BIO_ADDR_rawaddress(ap, ptr::null_mut(), &raw mut len) } == 0 {
            return ptr::null_mut();
        }
        let mut path = vec![0u8; len];
        // SAFETY: as above; `path` has room for it.
        unsafe { BIO_ADDR_rawaddress(ap, path.as_mut_ptr().cast(), &raw mut len) };
        c_strdup(&path)
    }
}

/// The address info entry behind `bai`.
///
/// # Safety
/// `bai` is null or an entry of a `BIO_lookup` result.
unsafe fn entry<'a>(bai: *const BIO_ADDRINFO) -> Option<&'a libc::addrinfo> {
    // SAFETY: the caller's guarantee: a BIO_ADDRINFO is a `struct addrinfo`.
    unsafe { bai.cast::<libc::addrinfo>().as_ref() }
}

ffi_export! {
    /// The next entry of a lookup's result, or null at its end (or for null).
    ///
    /// # Safety
    /// `bai` is null or an entry of a `BIO_lookup` result.
    pub unsafe extern "C" fn BIO_ADDRINFO_next(bai: *const BIO_ADDRINFO) -> *const BIO_ADDRINFO
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { entry(bai) }.map_or(ptr::null(), |e| e.ai_next.cast_const().cast())
    }
}

ffi_export! {
    /// The entry's address family, or 0 for null.
    ///
    /// # Safety
    /// `bai` is null or an entry of a `BIO_lookup` result.
    pub unsafe extern "C" fn BIO_ADDRINFO_family(bai: *const BIO_ADDRINFO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { entry(bai) }.map_or(0, |e| e.ai_family)
    }
}

ffi_export! {
    /// The entry's socket type, or 0 for null.
    ///
    /// # Safety
    /// `bai` is null or an entry of a `BIO_lookup` result.
    pub unsafe extern "C" fn BIO_ADDRINFO_socktype(bai: *const BIO_ADDRINFO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { entry(bai) }.map_or(0, |e| e.ai_socktype)
    }
}

ffi_export! {
    /// The entry's protocol; if it has none, TCP for a stream socket and UDP for a datagram
    /// socket (not for Unix-domain entries); 0 for null.
    ///
    /// # Safety
    /// `bai` is null or an entry of a `BIO_lookup` result.
    pub unsafe extern "C" fn BIO_ADDRINFO_protocol(bai: *const BIO_ADDRINFO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(e) = (unsafe { entry(bai) }) else {
            return 0;
        };
        if e.ai_protocol != 0 {
            return e.ai_protocol;
        }
        if e.ai_family == AF_UNIX {
            return 0;
        }
        match e.ai_socktype {
            SOCK_STREAM => IPPROTO_TCP,
            SOCK_DGRAM => IPPROTO_UDP,
            _ => 0,
        }
    }
}

ffi_export! {
    /// The entry's address, or null for null.
    ///
    /// # Safety
    /// `bai` is null or an entry of a `BIO_lookup` result.
    pub unsafe extern "C" fn BIO_ADDRINFO_address(bai: *const BIO_ADDRINFO) -> *const BIO_ADDR
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { entry(bai) }.map_or(ptr::null(), |e| e.ai_addr.cast_const().cast())
    }
}

ffi_export! {
    /// Frees a lookup's result: with `freeaddrinfo`, or entry by entry for a Unix-domain one.
    ///
    /// # Safety
    /// `bai` is null or the first entry of a `BIO_lookup` result, not used afterwards.
    pub unsafe extern "C" fn BIO_ADDRINFO_free(bai: *mut BIO_ADDRINFO)
    where failure = (), library = ERR_LIB_BIO
    {
        let mut bai = bai.cast::<libc::addrinfo>();
        // SAFETY: the caller's guarantee.
        let Some(first) = (unsafe { bai.as_ref() }) else {
            return;
        };
        if first.ai_family != AF_UNIX {
            // SAFETY: from getaddrinfo, as only Unix-domain lists are built here.
            unsafe { libc::freeaddrinfo(bai) };
            return;
        }
        while !bai.is_null() {
            // SAFETY: an entry built by `wrap_unix`, from this allocator.
            let entry = unsafe { bai.read() };
            let (next, addr) = (entry.ai_next, entry.ai_addr);
            // SAFETY: as above.
            unsafe { mem::release(addr.cast()) };
            // SAFETY: as above.
            unsafe { mem::release(bai.cast()) };
            bai = next;
        }
    }
}

/// The text of a host or service spec between `start` and `end`, `None` if empty or `*`.
fn part(text: &[u8]) -> Option<&[u8]> {
    if text.is_empty() || text == b"*" {
        None
    } else {
        Some(text)
    }
}

ffi_export! {
    /// Splits `host:service` (`[host]:service` for IPv6) into `*host` and `*service`, each
    /// copied with `OPENSSL_strdup` or set to null for an empty part or `*`. Without a colon,
    /// the whole is the host or the service as `hostserv_prio` says, and the other is left
    /// alone. Returns 1, or 0 with `BIO_R_AMBIGUOUS_HOST_OR_SERVICE` for several colons
    /// outside brackets or `BIO_R_MALFORMED_HOST_OR_SERVICE`.
    ///
    /// # Safety
    /// `hostserv` is null (an error; OpenSSL's would crash) or a NUL-terminated string; `host`
    /// and `service` are null or valid for a write.
    pub unsafe extern "C" fn BIO_parse_hostserv(hostserv: *const c_char, host: *mut *mut c_char, service: *mut *mut c_char, hostserv_prio: BIO_hostserv_priorities) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        if hostserv.is_null() {
            err::raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER, "BIO_parse_hostserv");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let spec = unsafe { CStr::from_ptr(hostserv) }.to_bytes();
        let malformed = || {
            err::raise(ERR_LIB_BIO, BIO_R_MALFORMED_HOST_OR_SERVICE, "BIO_parse_hostserv");
            0
        };
        let (h, p): (Option<&[u8]>, Option<&[u8]>) = if let Some(rest) = spec.strip_prefix(b"[") {
            let Some(close) = rest.iter().position(|c| *c == b']') else {
                return malformed();
            };
            let (h, after) = rest.split_at(close);
            let after = after.get(1..).unwrap_or_default();
            match after.split_first() {
                None => (Some(h), None),
                Some((b':', serv)) => (Some(h), Some(serv)),
                Some(_) => return malformed(),
            }
        } else {
            let first = spec.iter().position(|c| *c == b':');
            let last = spec.iter().rposition(|c| *c == b':');
            if first != last {
                err::raise(ERR_LIB_BIO, BIO_R_AMBIGUOUS_HOST_OR_SERVICE, "BIO_parse_hostserv");
                return 0;
            }
            match first {
                Some(at) => (spec.get(..at), spec.get(at + 1..)),
                None if hostserv_prio == BIO_PARSE_PRIO_HOST => (Some(spec), None),
                None => (None, Some(spec)),
            }
        };
        if p.is_some_and(|p| p.contains(&b':')) {
            return malformed();
        }
        let mut new_host = ptr::null_mut();
        if let (Some(h), false) = (h, host.is_null()) {
            if let Some(h) = part(h) {
                new_host = c_strdup(h);
                if new_host.is_null() {
                    return 0;
                }
            }
            // SAFETY: the caller's guarantee.
            unsafe { host.write(new_host) };
        }
        if let (Some(p), false) = (p, service.is_null()) {
            let mut new_service = ptr::null_mut();
            if let Some(p) = part(p) {
                new_service = c_strdup(p);
                if new_service.is_null() {
                    if h.is_some() && !host.is_null() {
                        // SAFETY: the copy made above, which this function still owns.
                        unsafe { mem::release(new_host.cast()) };
                        // SAFETY: the caller's guarantee.
                        unsafe { host.write(ptr::null_mut()) };
                    }
                    return 0;
                }
            }
            // SAFETY: the caller's guarantee.
            unsafe { service.write(new_service) };
        }
        1
    }
}

/// OpenSSL's `addrinfo_wrap` for a Unix-domain path: a one-entry list, built here.
///
/// # Safety
/// `path` is a NUL-terminated string.
unsafe fn wrap_unix(socktype: c_int, path: *const c_char) -> *mut libc::addrinfo {
    let bai = mem::alloc_zeroed(size_of::<libc::addrinfo>()).cast::<libc::addrinfo>();
    if bai.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: no preconditions.
    let addr = unsafe { BIO_ADDR_new() };
    // SAFETY: the caller's guarantee; a whole BIO_ADDR or null.
    let len = unsafe { libc::strlen(path) };
    // SAFETY: as above.
    if addr.is_null() || unsafe { BIO_ADDR_rawmake(addr, AF_UNIX, path.cast(), len, 0) } == 0 {
        // SAFETY: made above.
        unsafe { BIO_ADDR_free(addr) };
        // SAFETY: as above.
        unsafe { mem::release(bai.cast()) };
        return ptr::null_mut();
    }
    // SAFETY: a fresh, zeroed entry.
    let e = unsafe { &mut *bai };
    e.ai_family = AF_UNIX;
    e.ai_socktype = socktype;
    e.ai_protocol = 0;
    e.ai_addr = addr.cast();
    bai
}

ffi_export! {
    /// `BIO_lookup_ex` with any protocol.
    ///
    /// # Safety
    /// As for `BIO_lookup_ex`.
    pub unsafe extern "C" fn BIO_lookup(host: *const c_char, service: *const c_char, lookup_type: BIO_lookup_type, family: c_int, socktype: c_int, res: *mut *mut BIO_ADDRINFO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        let lookup_type = c_int::try_from(lookup_type).unwrap_or(c_int::MAX);
        // SAFETY: the caller's guarantee.
        unsafe { BIO_lookup_ex(host, service, lookup_type, family, socktype, 0, res) }
    }
}

ffi_export! {
    /// Looks up `host` and `service` (either may be null) with `getaddrinfo`, for a client or,
    /// with `BIO_LOOKUP_SERVER`, a server to bind (`AI_PASSIVE`). With `AF_UNSPEC` and a host,
    /// only families the machine has addresses for are returned (`AI_ADDRCONFIG`), unless that
    /// finds nothing, when the host is retried as a numeric address. `AF_UNIX` makes one entry
    /// for the path `host`. Stores the list in `*res`, to free with `BIO_ADDRINFO_free`.
    /// Returns 1, or 0 with the error raised.
    ///
    /// # Safety
    /// `host` and `service` are null or NUL-terminated strings (`host` isn't null for
    /// `AF_UNIX`); `res` is valid for a write.
    pub unsafe extern "C" fn BIO_lookup_ex(host: *const c_char, service: *const c_char, lookup_type: c_int, family: c_int, socktype: c_int, protocol: c_int, res: *mut *mut BIO_ADDRINFO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        if ![AF_INET, AF_INET6, AF_UNIX, AF_UNSPEC].contains(&family) {
            err::raise(ERR_LIB_BIO, BIO_R_UNSUPPORTED_PROTOCOL_FAMILY, "BIO_lookup_ex");
            return 0;
        }
        if res.is_null() {
            err::raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER, "BIO_lookup_ex");
            return 0;
        }
        if family == AF_UNIX {
            if host.is_null() {
                err::raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER, "BIO_lookup_ex");
                return 0;
            }
            // SAFETY: the caller's guarantee.
            let list = unsafe { wrap_unix(socktype, host) };
            if list.is_null() {
                err::raise(ERR_LIB_BIO, ERR_R_BIO_LIB, "BIO_lookup_ex");
                return 0;
            }
            // SAFETY: as above.
            unsafe { res.write(list.cast()) };
            return 1;
        }
        // SAFETY: an all-zero addrinfo is the empty hints.
        let mut hints: libc::addrinfo = unsafe { core::mem::zeroed() };
        hints.ai_family = family;
        hints.ai_socktype = socktype;
        hints.ai_protocol = protocol;
        if !host.is_null() && family == AF_UNSPEC {
            hints.ai_flags |= libc::AI_ADDRCONFIG;
        }
        if lookup_type == c_int::try_from(BIO_LOOKUP_SERVER).unwrap_or(-1) {
            hints.ai_flags |= libc::AI_PASSIVE;
        }
        let mut old_ret = 0;
        loop {
            let mut list = ptr::null_mut();
            // SAFETY: the caller's guarantee about the strings; `list` is a local.
            let ret = unsafe { libc::getaddrinfo(host, service, &raw const hints, &raw mut list) };
            match ret {
                0 => {
                    // SAFETY: the caller's guarantee.
                    unsafe { res.write(list.cast()) };
                    return 1;
                }
                libc::EAI_SYSTEM => {
                    err::raise_with_text(ERR_LIB_SYS, errno::get(), "BIO_lookup_ex", "calling getaddrinfo()");
                    err::raise(ERR_LIB_BIO, ERR_R_SYS_LIB, "BIO_lookup_ex");
                    return 0;
                }
                libc::EAI_MEMORY => {
                    raise_gai(ret, old_ret, "getaddrinfo", "BIO_lookup_ex");
                    return 0;
                }
                _ => {
                    if hints.ai_flags & libc::AI_ADDRCONFIG != 0 {
                        hints.ai_flags &= !libc::AI_ADDRCONFIG;
                        hints.ai_flags |= libc::AI_NUMERICHOST;
                        old_ret = ret;
                        continue;
                    }
                    raise_gai(ret, old_ret, "getaddrinfo", "BIO_lookup_ex");
                    return 0;
                }
            }
        }
    }
}

/// Helpers for the deprecated `BIO_get_host_ip` and `BIO_get_port`: the IPv4 address or port of
/// a client lookup's first entry.
///
/// # Safety
/// `host` and `service` are null or NUL-terminated strings.
pub(crate) unsafe fn lookup_ipv4(
    host: *const c_char,
    service: *const c_char,
) -> Option<*mut BIO_ADDRINFO> {
    let mut res = ptr::null_mut();
    // SAFETY: the caller's guarantee; `res` is a local.
    let ok = unsafe {
        BIO_lookup(
            host,
            service,
            rustyssl_abi::BIO_LOOKUP_CLIENT,
            AF_INET,
            SOCK_STREAM,
            &raw mut res,
        )
    };
    (ok != 0).then_some(res)
}

/// A raw address's bytes for `BIO_get_host_ip`.
///
/// # Safety
/// `ap` is an address; `ip` is valid for 4 bytes of writes.
pub(crate) unsafe fn ipv4_bytes(ap: *const BIO_ADDR, ip: *mut c_uchar) -> c_int {
    let mut len = 0;
    // SAFETY: the caller's guarantee.
    if unsafe { BIO_ADDR_rawaddress(ap, ptr::null_mut(), &raw mut len) } == 0 || len != 4 {
        return 0;
    }
    // SAFETY: as above; 4 bytes.
    unsafe { BIO_ADDR_rawaddress(ap, ip.cast(), &raw mut len) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: OpenSSL dereferences these null pointers.
    #[test]
    fn null_addresses_and_specs_are_refused() {
        let null = ptr::null_mut();
        // SAFETY: null is refused before use, for each call.
        unsafe { BIO_ADDR_clear(null) };
        // SAFETY: as above.
        assert_eq!(unsafe { BIO_ADDR_family(null) }, -1);
        // SAFETY: as above.
        let made = unsafe { BIO_ADDR_rawmake(null, AF_INET, ptr::null(), 4, 0) };
        assert_eq!(made, 0);
        // SAFETY: as above.
        let parsed =
            unsafe { BIO_parse_hostserv(ptr::null(), ptr::null_mut(), ptr::null_mut(), 0) };
        assert_eq!(parsed, 0);
        let mut res = ptr::null_mut();
        // SAFETY: as above; `res` is a local.
        let looked =
            unsafe { BIO_lookup_ex(ptr::null(), ptr::null(), 0, AF_UNIX, 0, 0, &raw mut res) };
        assert_eq!(looked, 0);
        // SAFETY: as above.
        let no_res = unsafe {
            BIO_lookup_ex(
                ptr::null(),
                c"1".as_ptr(),
                0,
                AF_INET,
                0,
                0,
                ptr::null_mut(),
            )
        };
        assert_eq!(no_res, 0);
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }

    /// docs/DEVIATIONS.md: OpenSSL's `strlen` reads past a path that fills its field.
    #[test]
    fn a_path_without_its_nul_is_bounded() {
        let mut ap = Addr::unspecified();
        // SAFETY: a local union.
        let un = unsafe { &mut ap.s_un };
        un.sun_family = libc::sa_family_t::try_from(AF_UNIX).unwrap();
        un.sun_path.fill(0x61);
        let mut len = 0;
        // SAFETY: a whole local address.
        let ret =
            unsafe { BIO_ADDR_rawaddress((&raw const ap).cast(), ptr::null_mut(), &raw mut len) };
        assert_eq!((ret, len), (1, PATH_ROOM));
    }
}
