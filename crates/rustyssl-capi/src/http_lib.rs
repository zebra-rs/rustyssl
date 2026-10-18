//! URL parsing (`OSSL_parse_url` of `http_lib.c`): a URL's scheme, user, host, port, path,
//! query, and fragment; `OSSL_HTTP_parse_url`, which takes only HTTP(S) and defaults the port;
//! and `OSSL_HTTP_adapt_proxy`, the proxy for a server unless `no_proxy` lists it.
//!
//! As OpenSSL's:
//! - A scheme is letters, digits, `+`, `-`, and `.` after a letter, before `://`.
//! - A bracketed host (`[::1]`) keeps its brackets; the port defaults to 0, reads as `%u`
//!   (leading space and a sign allowed), and must be at most 65535.
//! - The path is given a leading `/`; without a query asked for, a query stays in the path
//!   (up to a fragment).

use core::ffi::{CStr, c_char, c_int};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_HTTP, ERR_R_PASSED_NULL_PARAMETER, HTTP_R_ERROR_PARSING_URL,
    HTTP_R_INVALID_PORT_NUMBER, HTTP_R_INVALID_URL_PATH, HTTP_R_INVALID_URL_SCHEME,
    OPENSSL_HTTP_PROXY, OPENSSL_HTTPS_PROXY, OPENSSL_NO_PROXY, OSSL_HTTP_NAME, OSSL_HTTP_PORT,
    OSSL_HTTPS_NAME, OSSL_HTTPS_PORT,
};

use crate::err;
use crate::ffi::ffi_export;
use crate::mem;

/// A URL's parts, as offsets into it.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Url {
    pub(crate) scheme: (usize, usize),
    pub(crate) user: (usize, usize),
    pub(crate) host: (usize, usize),
    /// `None` for the default port, `"0"`.
    pub(crate) port: Option<(usize, usize)>,
    pub(crate) port_num: u32,
    pub(crate) path: (usize, usize),
    pub(crate) query: (usize, usize),
    pub(crate) frag: (usize, usize),
}

/// Why a URL didn't parse: the error OpenSSL raises.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UrlError {
    /// `HTTP_R_INVALID_PORT_NUMBER`, with the text from the port on.
    Port(usize),
    /// `HTTP_R_INVALID_URL_PATH`, then `HTTP_R_ERROR_PARSING_URL`.
    Path,
    /// `HTTP_R_ERROR_PARSING_URL`.
    Parse,
}

/// `sscanf(s, "%u")`: a number after optional space and sign, or `None` for none; values past
/// `u32` (or negative ones, which wrap) are `Some(u64::MAX)`.
fn scan_u(s: &[u8]) -> Option<u64> {
    let mut i = s
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .unwrap_or(s.len());
    let mut negative = false;
    if let Some(&c) = s.get(i)
        && (c == b'+' || c == b'-')
    {
        negative = c == b'-';
        i = i.saturating_add(1);
    }
    let digits = s.get(i..).unwrap_or_default();
    let n = digits.iter().take_while(|c| c.is_ascii_digit()).count();
    if n == 0 {
        return None;
    }
    let mut v: u64 = 0;
    for &d in digits.get(..n).unwrap_or_default() {
        v = v
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(d.saturating_sub(b'0'))))
            .unwrap_or(u64::MAX);
    }
    Some(if negative && v != 0 { u64::MAX } else { v })
}

/// The first of `set` in `s` from `from`, or `s.len()`.
fn find_any(s: &[u8], from: usize, set: &[u8]) -> usize {
    s.get(from..)
        .and_then(|t| t.iter().position(|c| set.contains(c)))
        .and_then(|i| i.checked_add(from))
        .unwrap_or(s.len())
}

/// Parses a URL as `OSSL_parse_url` does; `with_query` is whether the query is asked for.
pub(crate) fn parse(url: &[u8], with_query: bool) -> Result<Url, UrlError> {
    let mut u = Url::default();
    let mut p = 0usize;
    if url.first().is_some_and(u8::is_ascii_alphabetic) {
        let end = url
            .iter()
            .position(|c| !(c.is_ascii_alphanumeric() || b"+-.".contains(c)))
            .unwrap_or(url.len());
        if url.get(end..).is_some_and(|r| r.starts_with(b"://")) {
            u.scheme = (0, end);
            p = end.saturating_add(3);
        }
    }
    let authority_end = find_any(url, p, b"/?#");
    let at = url
        .get(p..authority_end)
        .and_then(|a| a.iter().position(|&c| c == b'@'))
        .and_then(|i| i.checked_add(p));
    let host = match at {
        Some(at) => {
            u.user = (p, at);
            at.saturating_add(1)
        }
        None => {
            u.user = (p, p);
            p
        }
    };
    let host_end = if url.get(host) == Some(&b'[') {
        let from = host.saturating_add(1);
        let close = url
            .get(from..authority_end)
            .and_then(|a| a.iter().position(|&c| c == b']'))
            .ok_or(UrlError::Parse)?;
        from.saturating_add(close).saturating_add(1)
    } else {
        find_any(url, host, b":/?#")
    };
    u.host = (host, host_end);
    p = host_end;
    if url.get(p) == Some(&b':') {
        p = p.saturating_add(1);
        let rest = url.get(p..).unwrap_or_default();
        let num = scan_u(rest)
            .filter(|&n| n <= 65535)
            .ok_or(UrlError::Port(p))?;
        u.port_num = u32::try_from(num).unwrap_or(0);
        let digits = rest.iter().take_while(|c| c.is_ascii_digit()).count();
        u.port = Some((p, p.saturating_add(digits)));
        p = p.saturating_add(digits);
    }
    let path = p;
    if !matches!(url.get(path), None | Some(b'/' | b'?' | b'#')) {
        return Err(UrlError::Path);
    }
    let end = url.len();
    let (mut path_end, mut query, mut query_end, mut frag) = (end, end, end, end);
    if let Some(q) = url.get(p..).and_then(|t| t.iter().position(|&c| c == b'?')) {
        p = p.saturating_add(q);
        if with_query {
            path_end = p;
            query = p.saturating_add(1);
        }
    }
    if let Some(h) = url.get(p..).and_then(|t| t.iter().position(|&c| c == b'#')) {
        let hash = p.saturating_add(h);
        if query == path_end {
            path_end = hash;
        }
        query_end = hash;
        frag = hash.saturating_add(1);
    }
    u.path = (path, path_end);
    u.query = (query, query_end);
    u.frag = (frag, end);
    Ok(u)
}

/// A copy of `url[range]` and a NUL, in C memory, into `*dest` if it's asked for: false if it
/// can't be made.
///
/// # Safety
/// `dest` is NULL or writable.
unsafe fn put(dest: *mut *mut c_char, url: &[u8], range: (usize, usize)) -> bool {
    if dest.is_null() {
        return true;
    }
    let part = url.get(range.0..range.1).unwrap_or_default();
    let copy = copy_with_nul(b"", part);
    // SAFETY: the caller's slot.
    unsafe { *dest = copy };
    !copy.is_null()
}

/// `prefix` and `part` and a NUL, in C memory, or NULL.
fn copy_with_nul(prefix: &[u8], part: &[u8]) -> *mut c_char {
    let Some(n) = prefix
        .len()
        .checked_add(part.len())
        .and_then(|n| n.checked_add(1))
    else {
        return ptr::null_mut();
    };
    let p = mem::alloc(n).cast::<u8>();
    if !p.is_null() {
        // SAFETY: the new block holds `n` octets.
        let block = unsafe { core::slice::from_raw_parts_mut(p, n) };
        let (head, rest) = block.split_at_mut(prefix.len());
        head.copy_from_slice(prefix);
        if let Some((last, body)) = rest.split_last_mut() {
            body.copy_from_slice(part);
            *last = 0;
        }
    }
    p.cast()
}

/// Frees a part made here and clears its slot.
///
/// # Safety
/// `slot` is NULL or holds NULL or C memory made here.
unsafe fn clear(slot: *mut *mut c_char) {
    if !slot.is_null() {
        // SAFETY: the caller's guarantee.
        let part = unsafe { *slot };
        // SAFETY: C memory made here, or NULL.
        unsafe { mem::release(part.cast()) };
        // SAFETY: as above.
        unsafe { *slot = ptr::null_mut() };
    }
}

ffi_export! {
    /// Splits the URL into its parts, each a copy in C memory for the caller to free (NULL
    /// slots are skipped; the path gets a leading `/`, the port defaults to "0"): 1, or 0
    /// (`HTTP_R_ERROR_PARSING_URL`, `HTTP_R_INVALID_PORT_NUMBER`, `HTTP_R_INVALID_URL_PATH`).
    ///
    /// # Safety
    /// `url` is NULL or a C string; each output is NULL or writable.
    pub unsafe extern "C" fn OSSL_parse_url(url: *const c_char, pscheme: *mut *mut c_char, puser: *mut *mut c_char, phost: *mut *mut c_char, pport: *mut *mut c_char, pport_num: *mut c_int, ppath: *mut *mut c_char, pquery: *mut *mut c_char, pfrag: *mut *mut c_char) -> c_int
    where failure = 0, library = ERR_LIB_HTTP
    {
        const F: &str = "OSSL_parse_url";
        let slots = [pscheme, puser, phost, pport, ppath, pfrag, pquery];
        for s in slots {
            if !s.is_null() {
                // SAFETY: the caller's slot.
                unsafe { *s = ptr::null_mut() };
            }
        }
        if !pport_num.is_null() {
            // SAFETY: the caller's slot.
            unsafe { *pport_num = 0 };
        }
        if url.is_null() {
            err::raise(ERR_LIB_HTTP, ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        }
        // SAFETY: the caller's C string.
        let text = unsafe { CStr::from_ptr(url) }.to_bytes();
        let u = match parse(text, !pquery.is_null()) {
            Ok(u) => u,
            Err(e) => {
                match e {
                    UrlError::Port(at) => {
                        let shown = String::from_utf8_lossy(text.get(at..).unwrap_or_default()).into_owned();
                        err::raise_with_text(ERR_LIB_HTTP, HTTP_R_INVALID_PORT_NUMBER, F, &shown);
                    }
                    UrlError::Path => {
                        err::raise(ERR_LIB_HTTP, HTTP_R_INVALID_URL_PATH, F);
                        err::raise(ERR_LIB_HTTP, HTTP_R_ERROR_PARSING_URL, F);
                    }
                    UrlError::Parse => err::raise(ERR_LIB_HTTP, HTTP_R_ERROR_PARSING_URL, F),
                }
                return 0;
            }
        };
        let port_ok = if pport.is_null() {
            true
        } else {
            let port = match u.port {
                Some((a, b)) => text.get(a..b).unwrap_or_default(),
                None => b"0",
            };
            let copy = copy_with_nul(b"", port);
            // SAFETY: the caller's slot.
            unsafe { *pport = copy };
            !copy.is_null()
        };
        // SAFETY: the caller's slots.
        let mut ok = port_ok && unsafe {
            put(pscheme, text, u.scheme)
        };
        // SAFETY: as above.
        ok = ok && unsafe { put(phost, text, u.host) };
        // SAFETY: as above.
        ok = ok && unsafe { put(puser, text, u.user) };
        // SAFETY: as above.
        ok = ok && unsafe { put(pquery, text, u.query) };
        // SAFETY: as above.
        ok = ok && unsafe { put(pfrag, text, u.frag) };
        if ok && !pport_num.is_null() {
            // SAFETY: as above.
            unsafe { *pport_num = c_int::try_from(u.port_num).unwrap_or(0) };
        }
        if ok && !ppath.is_null() {
            let path = text.get(u.path.0..u.path.1).unwrap_or_default();
            let copy = if path.first() == Some(&b'/') { copy_with_nul(b"", path) } else { copy_with_nul(b"/", path) };
            // SAFETY: as above.
            unsafe { *ppath = copy };
            ok = !copy.is_null();
        }
        if !ok {
            for s in slots {
                // SAFETY: the caller's slots, holding NULL or parts made here.
                unsafe { clear(s) };
            }
            return 0;
        }
        1
    }
}

ffi_export! {
    /// Splits an HTTP(S) URL as [`OSSL_parse_url`] does, refusing other schemes and giving the
    /// default port (80, or 443 for HTTPS) for none; `*pssl` says whether it is HTTPS: 1, or 0
    /// (`HTTP_R_INVALID_URL_SCHEME`).
    ///
    /// # Safety
    /// `url` is NULL or a C string; each output is NULL or writable.
    pub unsafe extern "C" fn OSSL_HTTP_parse_url(url: *const c_char, pssl: *mut c_int, puser: *mut *mut c_char, phost: *mut *mut c_char, pport: *mut *mut c_char, pport_num: *mut c_int, ppath: *mut *mut c_char, pquery: *mut *mut c_char, pfrag: *mut *mut c_char) -> c_int
    where failure = 0, library = ERR_LIB_HTTP
    {
        // SAFETY: the caller's slot, or NULL.
        if let Some(p) = unsafe { pport.as_mut() } {
            *p = ptr::null_mut();
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { pssl.as_mut() } {
            *p = 0;
        }
        let (mut scheme, mut port): (*mut c_char, *mut c_char) = (ptr::null_mut(), ptr::null_mut());
        // SAFETY: the caller's URL and slots; rooms for the scheme and the port.
        if unsafe { OSSL_parse_url(url, &raw mut scheme, puser, phost, &raw mut port, pport_num, ppath, pquery, pfrag) } == 0 {
            return 0;
        }
        // SAFETY: made by `OSSL_parse_url`.
        let s = unsafe { CStr::from_ptr(scheme) }.to_bytes();
        let ssl = s == OSSL_HTTPS_NAME.to_bytes();
        let ok = if ssl || s.is_empty() || s == OSSL_HTTP_NAME.to_bytes() {
            if ssl {
                // SAFETY: as above.
                if let Some(p) = unsafe { pssl.as_mut() } {
                    *p = 1;
                }
            }
            true
        } else {
            err::raise(ERR_LIB_HTTP, HTTP_R_INVALID_URL_SCHEME, "OSSL_HTTP_parse_url");
            false
        };
        // SAFETY: from `CRYPTO_malloc`.
        unsafe { mem::release(scheme.cast()) };
        // SAFETY: as above.
        let ok = ok && unsafe { set_port(port, ssl, pport, pport_num) };
        if !ok {
            for s in [puser, phost, ppath, pquery, pfrag] {
                // SAFETY: the caller's slots, holding NULL or parts made here.
                unsafe { clear(s) };
            }
            return 0;
        }
        1
    }
}

/// The port for [`OSSL_HTTP_parse_url`]: the URL's, or for `"0"` the scheme's default; into
/// `*pport` (or freed) and `*pport_num`.
///
/// # Safety
/// `port` is a C string from `CRYPTO_malloc`; the slots are NULL or writable.
unsafe fn set_port(
    port: *mut c_char,
    ssl: bool,
    pport: *mut *mut c_char,
    pport_num: *mut c_int,
) -> bool {
    // SAFETY: the caller's string.
    if unsafe { CStr::from_ptr(port) }.to_bytes() != b"0" {
        // SAFETY: the caller's slot, or NULL.
        match unsafe { pport.as_mut() } {
            Some(p) => *p = port,
            // SAFETY: from `CRYPTO_malloc`.
            None => unsafe { mem::release(port.cast()) },
        }
        return true;
    }
    // SAFETY: as above.
    unsafe { mem::release(port.cast()) };
    let (def, num) = if ssl {
        (OSSL_HTTPS_PORT, 443)
    } else {
        (OSSL_HTTP_PORT, 80)
    };
    // SAFETY: the caller's slot, or NULL.
    if let Some(p) = unsafe { pport_num.as_mut() } {
        *p = num;
    }
    // SAFETY: as above.
    if let Some(p) = unsafe { pport.as_mut() } {
        // SAFETY: a static C string.
        *p = unsafe { crate::string::CRYPTO_strdup(def.as_ptr(), c"http_lib.c".as_ptr(), 0) };
        return !p.is_null();
    }
    true
}

/// `ossl_isspace`.
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// `use_proxy`: whether `server` (brackets stripped) is not in `no_proxy` (by default the
/// `no_proxy`, then `NO_PROXY`, environment variable), a list separated by space or commas.
///
/// # Safety
/// `no_proxy` is NULL or a C string; `server` a C string.
unsafe fn use_proxy(no_proxy: *const c_char, server: *const c_char) -> bool {
    /// `NI_MAXHOST`.
    const MAXHOST: usize = 1025;
    // SAFETY: the caller's string.
    let mut host = unsafe { CStr::from_ptr(server) }.to_bytes();
    let sl = host.len();
    if (2..MAXHOST + 2).contains(&sl) && host.first() == Some(&b'[') && host.last() == Some(&b']') {
        host = host.get(1..sl - 1).unwrap_or_default();
    }
    if host.is_empty() {
        return true;
    }
    let list = if no_proxy.is_null() {
        let p = crate::init::safe_getenv_ptr(c"no_proxy");
        if p.is_null() {
            crate::init::safe_getenv_ptr(OPENSSL_NO_PROXY)
        } else {
            p
        }
    } else {
        no_proxy
    };
    if list.is_null() {
        return true;
    }
    // SAFETY: a C string.
    let list = unsafe { CStr::from_ptr(list) }.to_bytes();
    let found = (0..list.len()).any(|i| {
        let at = list.get(i..).unwrap_or_default();
        let before = i
            .checked_sub(1)
            .and_then(|b| list.get(b))
            .is_none_or(|&c| is_space(c) || c == b',');
        let after = at.get(host.len()).is_none_or(|&c| is_space(c) || c == b',');
        at.starts_with(host) && before && after
    });
    !found
}

ffi_export! {
    /// The proxy to reach `server` through: `proxy`, or the `https_proxy`/`http_proxy` (then
    /// upper-case) environment variable; NULL for none, an empty one, or a server `no_proxy`
    /// lists.
    ///
    /// # Safety
    /// `proxy` and `no_proxy` are NULL or C strings; `server` NULL or one.
    pub unsafe extern "C" fn OSSL_HTTP_adapt_proxy(proxy: *const c_char, no_proxy: *const c_char, server: *const c_char, use_ssl: c_int) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_HTTP
    {
        let mut proxy = proxy;
        if proxy.is_null() {
            proxy = crate::init::safe_getenv_ptr(if use_ssl != 0 { c"https_proxy" } else { c"http_proxy" });
        }
        if proxy.is_null() {
            proxy = crate::init::safe_getenv_ptr(if use_ssl != 0 { OPENSSL_HTTPS_PROXY } else { OPENSSL_HTTP_PROXY });
        }
        // SAFETY: a C string, or NULL.
        if proxy.is_null() || unsafe { *proxy } == 0 {
            return ptr::null();
        }
        if server.is_null() {
            // `ossl_assert(server != NULL)`, a plain check in release builds: no proxy.
            return ptr::null();
        }
        // SAFETY: the caller's strings.
        if !unsafe { use_proxy(no_proxy, server) } {
            return ptr::null();
        }
        proxy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn part(url: &[u8], r: (usize, usize)) -> &[u8] {
        url.get(r.0..r.1).unwrap_or_default()
    }

    #[test]
    fn urls() {
        let url = b"https://user@[::1]:8443/a/b?q=1#frag";
        let u = parse(url, true).unwrap_or_default();
        assert_eq!(part(url, u.scheme), b"https");
        assert_eq!(part(url, u.user), b"user");
        assert_eq!(part(url, u.host), b"[::1]");
        assert_eq!(u.port_num, 8443);
        assert_eq!(part(url, u.path), b"/a/b");
        assert_eq!(part(url, u.query), b"q=1");
        assert_eq!(part(url, u.frag), b"frag");
        let u = parse(url, false).unwrap_or_default();
        assert_eq!(part(url, u.path), b"/a/b?q=1");
        assert_eq!(parse(b"http://h:99999/", true), Err(UrlError::Port(9)));
        assert_eq!(parse(b"http://h:80x", true), Err(UrlError::Path));
        assert_eq!(parse(b"http://[::1/", true), Err(UrlError::Parse));
    }
}
