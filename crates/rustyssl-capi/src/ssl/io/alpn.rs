//! `SSL_select_next_proto`: the protocol both lists share (ALPN and NPN wire format, each entry
//! a length octet and that many octets).

use core::ffi::{c_int, c_uchar, c_uint};
use core::ptr;

use rustyssl_abi::{ERR_LIB_SSL, OPENSSL_NPN_NEGOTIATED, OPENSSL_NPN_NO_OVERLAP};

use crate::ffi::ffi_export;

/// The entries of a length-prefixed list, stopping at the first that doesn't fit (trailing
/// octets are ignored, as OpenSSL ignores them).
fn entries(mut list: &[u8]) -> impl Iterator<Item = (usize, &[u8])> {
    let mut at = 0usize;
    core::iter::from_fn(move || {
        let (&n, rest) = list.split_first()?;
        let entry = rest.get(..usize::from(n))?;
        let start = at.checked_add(1)?;
        at = start.checked_add(usize::from(n))?;
        list = rest.get(usize::from(n)..)?;
        Some((start, entry))
    })
}

/// The first of `server`'s non-empty protocols that `client` also lists: `(true, offset, len)`
/// into `server`; otherwise `(false, offset, len)` of the client's first protocol (the
/// "opportunistic" fallback), or `None` if the client's list has no usable first entry.
pub(crate) fn select(server: &[u8], client: &[u8]) -> Option<(bool, usize, usize)> {
    let (cstart, first) = entries(client).next()?;
    if first.is_empty() {
        return None;
    }
    for (sstart, s) in entries(server) {
        if s.is_empty() {
            continue;
        }
        if entries(client).any(|(_, c)| c == s) {
            return Some((true, sstart, s.len()));
        }
    }
    Some((false, cstart, first.len()))
}

/// A list's octets from a pointer and length, empty for NULL.
///
/// # Safety
/// `p` is NULL or points to `len` readable octets.
unsafe fn list<'a>(p: *const c_uchar, len: c_uint) -> &'a [u8] {
    let Ok(n) = usize::try_from(len) else {
        return &[];
    };
    if p.is_null() || n == 0 {
        return &[];
    }
    // SAFETY: the caller's guarantee.
    unsafe { core::slice::from_raw_parts(p, n) }
}

ffi_export! {
    /// Picks the protocol: `OPENSSL_NPN_NEGOTIATED` with `*out` in `server` (the first of the
    /// server's that the client lists), or `OPENSSL_NPN_NO_OVERLAP` with `*out` the client's
    /// first protocol (NULL and 0 if the client's list is empty or malformed).
    ///
    /// # Safety
    /// `out` and `outlen` are writable; `server` and `client` hold their lengths' octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_select_next_proto(out: *mut *mut c_uchar, outlen: *mut c_uchar, server: *const c_uchar, server_len: c_uint, client: *const c_uchar, client_len: c_uint) -> c_int
    where failure = OPENSSL_NPN_NO_OVERLAP, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let srv = unsafe { list(server, server_len) };
        // SAFETY: as above.
        let cli = unsafe { list(client, client_len) };
        let (ret, p, n) = match select(srv, cli) {
            Some((true, at, n)) => (OPENSSL_NPN_NEGOTIATED, srv.get(at..).map_or(ptr::null(), <[u8]>::as_ptr), n),
            Some((false, at, n)) => (OPENSSL_NPN_NO_OVERLAP, cli.get(at..).map_or(ptr::null(), <[u8]>::as_ptr), n),
            None => (OPENSSL_NPN_NO_OVERLAP, ptr::null(), 0),
        };
        if !out.is_null() {
            // SAFETY: the caller's slot; the pointer is into its own list (OpenSSL's signature
            // drops the const).
            unsafe { out.write(p.cast_mut()) };
        }
        if !outlen.is_null() {
            // SAFETY: as above; an entry's length fits its length octet.
            unsafe { outlen.write(u8::try_from(n).unwrap_or(0)) };
        }
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::select;

    #[test]
    fn picks_the_servers_preference() {
        let server = b"\x02h2\x08http/1.1";
        let client = b"\x08http/1.1\x02h2";
        assert_eq!(select(server, client), Some((true, 1, 2)));
    }

    #[test]
    fn falls_back_to_the_clients_first() {
        assert_eq!(select(b"\x03foo", b"\x02h2\x03bar"), Some((false, 1, 2)));
        // Empty and malformed client lists have no fallback.
        assert_eq!(select(b"\x02h2", b""), None);
        assert_eq!(select(b"\x02h2", b"\x00\x02h2"), None);
        assert_eq!(select(b"\x02h2", b"\x05h2"), None);
    }

    #[test]
    fn skips_empty_and_ignores_trailing_octets() {
        assert_eq!(select(b"\x00\x02h2\x09", b"\x02h2\x07"), Some((true, 2, 2)));
    }
}
