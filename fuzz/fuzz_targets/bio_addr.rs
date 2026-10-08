//! Fuzzes the address parsers through their C ABI: `BIO_parse_hostserv` against a model of
//! its rules, and `BIO_ADDR_rawmake` with arbitrary raw addresses, whose raw address, port,
//! and numeric strings must round-trip.

#![no_main]

use core::ffi::{CStr, c_char, c_int, c_uint, c_ushort, c_void};

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::BIO_ADDR;
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn BIO_parse_hostserv(spec: *const c_char, host: *mut *mut c_char, service: *mut *mut c_char, prio: c_uint) -> c_int;
    fn BIO_ADDR_new() -> *mut BIO_ADDR;
    fn BIO_ADDR_free(a: *mut BIO_ADDR);
    fn BIO_ADDR_rawmake(a: *mut BIO_ADDR, family: c_int, data: *const c_void, len: usize, port: c_ushort) -> c_int;
    fn BIO_ADDR_rawaddress(a: *const BIO_ADDR, p: *mut c_void, l: *mut usize) -> c_int;
    fn BIO_ADDR_rawport(a: *const BIO_ADDR) -> c_ushort;
    fn BIO_ADDR_hostname_string(a: *const BIO_ADDR, numeric: c_int) -> *mut c_char;
    fn BIO_ADDR_service_string(a: *const BIO_ADDR, numeric: c_int) -> *mut c_char;
    fn CRYPTO_free(p: *mut c_void, file: *const c_char, line: c_int);
    fn ERR_clear_error();
}

/// Takes an `OPENSSL_malloc`'d string, freeing it.
fn take(text: *mut c_char) -> Option<Vec<u8>> {
    if text.is_null() {
        return None;
    }
    // SAFETY: a NUL-terminated string from the library.
    let bytes = unsafe { CStr::from_ptr(text) }.to_bytes().to_vec();
    // SAFETY: allocated by the library, freed once.
    unsafe { CRYPTO_free(text.cast(), c"fuzz".as_ptr(), 0) };
    Some(bytes)
}

/// The model: `Some((host, service))` as the parse should give them, each `None` for null and
/// the outer `None` for untouched; `None` overall for a failure.
type Part = Option<Option<Vec<u8>>>;

fn model(spec: &[u8], prio_service: bool) -> Option<(Part, Part)> {
    let part = |p: &[u8]| if p.is_empty() || p == b"*" { None } else { Some(p.to_vec()) };
    let (h, p): (Option<&[u8]>, Option<&[u8]>) = if let Some(rest) = spec.strip_prefix(b"[") {
        let close = rest.iter().position(|c| *c == b']')?;
        let after = &rest[close + 1..];
        match after.split_first() {
            None => (Some(&rest[..close]), None),
            Some((b':', serv)) => (Some(&rest[..close]), Some(serv)),
            Some(_) => return None,
        }
    } else {
        let colons = spec.iter().filter(|c| **c == b':').count();
        if colons > 1 {
            return None;
        }
        match spec.iter().position(|c| *c == b':') {
            Some(at) => (Some(&spec[..at]), Some(&spec[at + 1..])),
            None if prio_service => (None, Some(spec)),
            None => (Some(spec), None),
        }
    };
    if p.is_some_and(|p| p.contains(&b':')) {
        return None;
    }
    Some((h.map(part), p.map(part)))
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode & 1 == 0 {
        let spec: Vec<u8> = rest.iter().copied().take_while(|b| *b != 0).chain([0]).collect();
        let prio_service = mode & 2 != 0;
        let untouched = c"-".as_ptr().cast_mut();
        let (mut host, mut service) = (untouched, untouched);
        // SAFETY: a NUL-terminated spec and local outputs.
        let ret = unsafe { BIO_parse_hostserv(spec.as_ptr().cast(), &mut host, &mut service, c_uint::from(prio_service)) };
        // SAFETY: no preconditions.
        unsafe { ERR_clear_error() };
        let got = |p: *mut c_char| if p == untouched { None } else { Some(take(p)) };
        let result = (ret == 1).then(|| (got(host), got(service)));
        assert_eq!(result, model(&spec[..spec.len() - 1], prio_service));
        return;
    }
    let family = match mode >> 1 & 3 {
        0 => libc::AF_INET,
        1 => libc::AF_INET6,
        2 => libc::AF_UNIX,
        _ => 12345,
    };
    let port = u16::from_le_bytes([rest.first().copied().unwrap_or(0), rest.get(1).copied().unwrap_or(0)]);
    let raw: Vec<u8> = rest.iter().skip(2).copied().take_while(|b| *b != 0).chain([0]).collect();
    let len = raw.len() - 1;
    // SAFETY: no preconditions.
    let a = unsafe { BIO_ADDR_new() };
    // SAFETY: a whole address; `raw` holds `len` bytes and a NUL.
    let ok = unsafe { BIO_ADDR_rawmake(a, family, raw.as_ptr().cast(), len, port) };
    if ok == 1 {
        let mut back = [0u8; 128];
        let mut back_len = 0;
        // SAFETY: the buffer has room for any raw address.
        assert_eq!(unsafe { BIO_ADDR_rawaddress(a, back.as_mut_ptr().cast(), &mut back_len) }, 1);
        assert_eq!(&back[..back_len], &raw[..len]);
        if family != libc::AF_UNIX {
            // SAFETY: a live address.
            assert_eq!(unsafe { BIO_ADDR_rawport(a) }, port);
            // `getnameinfo` refuses some addresses (macOS, some multicast scopes); then both
            // strings fail, as in OpenSSL.
            // SAFETY: as above.
            let service = take(unsafe { BIO_ADDR_service_string(a, 1) });
            // SAFETY: as above.
            let host = take(unsafe { BIO_ADDR_hostname_string(a, 1) });
            // SAFETY: no preconditions.
            unsafe { ERR_clear_error() };
            assert_eq!(service.is_some(), host.is_some());
            if let Some(service) = service {
                assert_eq!(service, u16::from_be(port).to_string().into_bytes());
            }
        }
    } else {
        let expected_len = match family {
            libc::AF_INET => Some(4),
            libc::AF_INET6 => Some(16),
            _ => None,
        };
        assert!(family == libc::AF_UNIX || expected_len != Some(len));
    }
    // SAFETY: made above, freed once.
    unsafe { BIO_ADDR_free(a) };
});
