//! HTTP for `ocsp` and `cmp`: the server side of `apps/lib/http_server.c` (an accept `BIO`
//! and its connections), the client side of `apps.c`'s `app_http_*` (`OSSL_HTTP_transfer`
//! and `OSSL_HTTP_get`, with `app_http_tls_cb` for TLS), and the request headers.

use core::ffi::{c_char, c_int, c_long, c_void};
use std::ffi::CString;

use crate::abi::{
    BIO, BIO_C_DO_STATE_MACHINE, BIO_C_GET_FD, BIO_C_SET_ACCEPT, BIO_C_SET_BIND_MODE,
    BIO_C_SET_SSL, BIO_CLOSE, BIO_FAMILY_IPANY, BIO_FLAGS_BASE64_NO_NL, BIO_SOCK_INFO_ADDRESS,
    BIO_SOCK_REUSEADDR, CONF_VALUE, SSL_CTRL_SET_TLSEXT_HOSTNAME, SSL_CTX,
    TLSEXT_NAMETYPE_host_name, stack_st_CONF_VALUE,
};
use crate::bio::Bio;
use crate::ffi;
use crate::util::{cstring, take_string};

/// An optional C string: `Err` if it holds a NUL.
fn opt_c(s: Option<&str>) -> Result<Option<CString>, ()> {
    s.map(|s| cstring(s).ok_or(())).transpose()
}

fn ptr_of(c: &Option<CString>) -> *const c_char {
    c.as_ref().map_or(core::ptr::null(), |c| c.as_ptr())
}

/// `BIO_ctrl(b, cmd, larg, parg)`.
fn ctrl(b: *mut BIO, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long {
    // SAFETY: b is a live BIO; each caller passes the argument its command takes.
    unsafe { ffi::BIO_ctrl(b, cmd, larg, parg) }
}

/// The accept `BIO` of `http_server_init`: on `*:port` (IPv4 and IPv6), reusing the address,
/// each connection through a buffering `BIO`. `Err` names the step that failed (its log
/// message), the accept `BIO` freed.
pub fn accept_bio(port: &str) -> Result<Bio, AcceptError> {
    // BIO_snprintf(name, sizeof(name), "*:%s", port) into a 40-byte buffer.
    let mut name = format!("*:{port}");
    while name.len() > 39 {
        name.pop();
    }
    let name = cstring(&name).ok_or(AcceptError::Setup)?;
    let buf = Bio::new_buffer().ok_or(AcceptError::Alloc)?;
    // SAFETY: no arguments; the result is a static method table.
    let method = unsafe { ffi::BIO_s_accept() };
    // SAFETY: method is a valid method table.
    let acbio = Bio::from_ptr(unsafe { ffi::BIO_new(method) }).ok_or(AcceptError::Setup)?;
    let a = acbio.as_ptr();
    let mut family: c_int = BIO_FAMILY_IPANY;
    if ctrl(a, BIO_C_SET_ACCEPT, 4, (&mut family as *mut c_int).cast()) <= 0
        || ctrl(
            a,
            BIO_C_SET_BIND_MODE,
            c_long::from(BIO_SOCK_REUSEADDR),
            core::ptr::null_mut(),
        ) <= 0
        || ctrl(a, BIO_C_SET_ACCEPT, 0, name.as_ptr().cast_mut().cast()) <= 0
    {
        return Err(AcceptError::Setup);
    }
    // BIO_set_accept_bios: the accept BIO takes the buffering BIO.
    ctrl(a, BIO_C_SET_ACCEPT, 3, buf.into_ptr().cast());
    if ctrl(a, BIO_C_DO_STATE_MACHINE, 0, core::ptr::null_mut()) <= 0 {
        return Err(AcceptError::Accept(acbio));
    }
    Ok(acbio)
}

/// Why [`accept_bio`] failed.
pub enum AcceptError {
    /// The buffering `BIO` couldn't be made (nothing logged upstream).
    Alloc,
    /// Setting up the accept `BIO` failed.
    Setup,
    /// Binding the port failed (the `BIO`, for its socket's report... it is freed by the
    /// caller).
    Accept(Bio),
}

/// `BIO_get_fd(b, NULL)`.
pub fn bio_fd(b: &Bio) -> c_int {
    ctrl(b.as_ptr(), BIO_C_GET_FD, 0, core::ptr::null_mut())
        .try_into()
        .unwrap_or(-1)
}

/// `BIO_do_accept(b) > 0`.
pub fn do_accept(b: &Bio) -> bool {
    ctrl(b.as_ptr(), BIO_C_DO_STATE_MACHINE, 0, core::ptr::null_mut()) > 0
}

/// `BIO_pop(acbio)`: the connection just accepted, now the caller's.
pub fn pop(acbio: &Bio) -> Option<Bio> {
    // SAFETY: the accept BIO is live; the BIO popped off it is owned by the caller.
    Bio::from_ptr(unsafe { ffi::BIO_pop(acbio.as_ptr()) })
}

/// `get_sock_info_address` of `s_socket.c`: the socket's numeric host and service.
pub fn sock_info_address(fd: c_int) -> (Option<String>, Option<String>) {
    // SAFETY: no arguments.
    let addr = unsafe { ffi::BIO_ADDR_new() };
    if addr.is_null() {
        return (None, None);
    }
    let mut info = addr;
    // SAFETY: the union BIO_sock_info_u's only member is the BIO_ADDR pointer.
    let ok = unsafe {
        ffi::BIO_sock_info(
            fd,
            BIO_SOCK_INFO_ADDRESS,
            (&mut info as *mut *mut crate::abi::BIO_ADDR).cast(),
        )
    } == 1;
    let r = if ok {
        // SAFETY: addr is live; the strings are the caller's.
        let h = take_string(unsafe { ffi::BIO_ADDR_hostname_string(addr, 1) });
        // SAFETY: as above.
        let s = take_string(unsafe { ffi::BIO_ADDR_service_string(addr, 1) });
        (h, s)
    } else {
        (None, None)
    };
    // SAFETY: addr is owned here.
    unsafe { ffi::BIO_ADDR_free(addr) };
    r
}

/// A read-only memory `BIO` over a copy of `data`, base64-decoding without newlines
/// (`http_server_get_asn1_req`'s GET body).
pub fn base64_reader(data: &[u8]) -> Option<Bio> {
    let mem = Bio::from_bytes(data)?;
    // SAFETY: no arguments; the result is a static method table.
    let method = unsafe { ffi::BIO_f_base64() };
    // SAFETY: method is a valid method table.
    let b64 = Bio::from_ptr(unsafe { ffi::BIO_new(method) })?;
    // SAFETY: b64 is live.
    unsafe { ffi::BIO_set_flags(b64.as_ptr(), BIO_FLAGS_BASE64_NO_NL) };
    Some(b64.push(mem))
}

/// A URL's parts (`OSSL_HTTP_parse_url`).
pub struct Url {
    pub use_ssl: bool,
    pub host: String,
    pub port: String,
    pub path: String,
}

/// `OSSL_HTTP_parse_url(url, &ssl, NULL, &host, &port, NULL, &path, NULL, NULL)`.
pub fn parse_url(url: &str) -> Option<Url> {
    let u = cstring(url)?;
    let mut ssl: c_int = 0;
    let (mut host, mut port, mut path) = (
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    );
    // SAFETY: u is a C string; every output is a valid local; the strings are the caller's.
    let ok = unsafe {
        ffi::OSSL_HTTP_parse_url(
            u.as_ptr(),
            &mut ssl,
            core::ptr::null_mut(),
            &mut host,
            &mut port,
            core::ptr::null_mut(),
            &mut path,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    } == 1;
    let (h, p, pa) = (take_string(host), take_string(port), take_string(path));
    ok.then(|| Url {
        use_ssl: ssl != 0,
        host: h.unwrap_or_default(),
        port: p.unwrap_or_default(),
        path: pa.unwrap_or_default(),
    })
}

/// A `STACK_OF(CONF_VALUE)` of HTTP headers (`X509V3_add_value`).
pub struct Headers(*mut stack_st_CONF_VALUE);

unsafe extern "C" fn free_conf_value(p: *mut c_void) {
    // SAFETY: called by sk_pop_free with each member, a CONF_VALUE.
    unsafe { ffi::X509V3_conf_free(p.cast::<CONF_VALUE>()) };
}

impl Default for Headers {
    fn default() -> Self {
        Self(core::ptr::null_mut())
    }
}

impl Drop for Headers {
    fn drop(&mut self) {
        // SAFETY: the stack (NULL allowed) and its values are owned here.
        unsafe { ffi::OPENSSL_sk_pop_free(self.0.cast(), Some(free_conf_value)) };
    }
}

impl Headers {
    /// `X509V3_add_value(name, value, &headers)`.
    pub fn add(&mut self, name: &str, value: &str) -> bool {
        let (Some(n), Some(v)) = (cstring(name), cstring(value)) else {
            return false;
        };
        // SAFETY: the strings are valid; the stack is NULL or owned here (made if NULL).
        unsafe { ffi::X509V3_add_value(n.as_ptr(), v.as_ptr(), &mut self.0) == 1 }
    }

    pub(crate) fn as_ptr(&self) -> *mut stack_st_CONF_VALUE {
        self.0
    }
}

/// An owned `SSL_CTX`.
pub struct SslCtx(core::ptr::NonNull<SSL_CTX>);

impl Drop for SslCtx {
    fn drop(&mut self) {
        // SAFETY: the context is owned here and freed once.
        unsafe { ffi::SSL_CTX_free(self.0.as_ptr()) };
    }
}

impl SslCtx {
    /// `SSL_CTX_new(TLS_client_method())`.
    pub fn new_client() -> Option<Self> {
        // SAFETY: no arguments; a static method table.
        let m = unsafe { ffi::TLS_client_method() };
        // SAFETY: m is a valid method.
        core::ptr::NonNull::new(unsafe { ffi::SSL_CTX_new(m) }).map(Self)
    }

    /// Takes ownership of a context the caller got from the library.
    pub fn from_raw(p: *mut SSL_CTX) -> Option<Self> {
        core::ptr::NonNull::new(p).map(Self)
    }

    pub fn as_ptr(&self) -> *mut SSL_CTX {
        self.0.as_ptr()
    }
}

/// `APP_HTTP_TLS_INFO` of `apps.h`, as `app_http_tls_cb` reads it (it lives at a stable
/// address while the transfer uses it).
pub struct TlsInfo {
    server: CString,
    port: CString,
    use_proxy: bool,
    timeout: c_long,
    ssl_ctx: *mut SSL_CTX,
    prog: CString,
}

impl TlsInfo {
    /// The info for a transfer to `server:port` (`ssl_ctx` borrowed for its lifetime).
    pub fn new(
        server: &str,
        port: &str,
        use_proxy: bool,
        timeout: c_long,
        ssl_ctx: Option<&SslCtx>,
        prog: &str,
    ) -> Option<Box<Self>> {
        Some(Box::new(Self {
            server: cstring(server)?,
            port: cstring(port)?,
            use_proxy,
            timeout,
            ssl_ctx: ssl_ctx.map_or(core::ptr::null_mut(), SslCtx::as_ptr),
            prog: cstring(prog)?,
        }))
    }

    /// The callback's argument.
    pub fn as_arg(&self) -> *mut c_void {
        (self as *const Self).cast_mut().cast()
    }
}

/// `tls_error_hint` of `apps.c`.
fn tls_error_hint() -> Option<&'static str> {
    use crate::abi::{
        ERR_LIB_SSL, SSL_AD_REASON_OFFSET, SSL_R_CERTIFICATE_VERIFY_FAILED, SSL_R_UNKNOWN_PROTOCOL,
        SSL_R_WRONG_VERSION_NUMBER, SSL3_AD_HANDSHAKE_FAILURE, TLS1_AD_UNKNOWN_CA,
    };
    let e = crate::err::peek_last_error();
    if crate::err::lib(e) != ERR_LIB_SSL {
        return None;
    }
    let r = crate::err::reason(e);
    let ad = |a: c_int| c_int::try_from(SSL_AD_REASON_OFFSET).unwrap_or(0) + a;
    match r {
        SSL_R_WRONG_VERSION_NUMBER => {
            Some("The server does not support (a suitable version of) TLS")
        }
        SSL_R_UNKNOWN_PROTOCOL => Some("The server does not support HTTPS"),
        SSL_R_CERTIFICATE_VERIFY_FAILED => Some(
            "Cannot authenticate server via its TLS certificate, likely due to mismatch with our trusted TLS certs or missing revocation status",
        ),
        x if x == ad(TLS1_AD_UNKNOWN_CA) => Some(
            "Server did not accept our TLS certificate, likely due to mismatch with server's trust anchor or missing revocation status",
        ),
        x if x == ad(SSL3_AD_HANDSHAKE_FAILURE) => Some(
            "TLS handshake failure. Possibly the server requires our TLS certificate but did not receive it",
        ),
        _ => None,
    }
}

/// `app_http_tls_cb` of `apps.c`: TLS over the connection (also through an HTTPS proxy),
/// or its shutdown.
///
/// # Safety
/// `arg` is a live [`TlsInfo`]; `bio` the library's connection.
pub unsafe extern "C" fn app_http_tls_cb(
    bio: *mut BIO,
    arg: *mut c_void,
    connect: c_int,
    _detail: c_int,
) -> *mut BIO {
    // SAFETY: the caller's guarantee.
    let info = unsafe { &*arg.cast::<TlsInfo>() };
    let ssl_ctx = info.ssl_ctx;
    if ssl_ctx.is_null() {
        return bio;
    }
    if connect != 0 {
        // SAFETY: ssl_ctx is live; the store and its parameters are owned by it.
        let ts = unsafe { ffi::SSL_CTX_get_cert_store(ssl_ctx) };
        let vpm = if ts.is_null() {
            core::ptr::null_mut()
        } else {
            // SAFETY: ts is live.
            unsafe { ffi::X509_STORE_get0_param(ts) }
        };
        let host = if vpm.is_null() {
            core::ptr::null_mut()
        } else {
            // SAFETY: vpm is live; the name is owned by it.
            unsafe { ffi::X509_VERIFY_PARAM_get0_host(vpm, 0) }
        };
        if info.use_proxy {
            let err = Bio::new_fd(2, false);
            // SAFETY: the BIO and strings are live; no proxy credentials.
            let ok = unsafe {
                ffi::OSSL_HTTP_proxy_connect(
                    bio,
                    info.server.as_ptr(),
                    info.port.as_ptr(),
                    core::ptr::null(),
                    core::ptr::null(),
                    c_int::try_from(info.timeout).unwrap_or(c_int::MAX),
                    err.as_ref().map_or(core::ptr::null_mut(), Bio::as_ptr),
                    info.prog.as_ptr(),
                )
            };
            if ok != 1 {
                return core::ptr::null_mut();
            }
        }
        // SAFETY: no arguments; a static method table.
        let m = unsafe { ffi::BIO_f_ssl() };
        // SAFETY: m is valid.
        let sbio = unsafe { ffi::BIO_new(m) };
        if sbio.is_null() {
            return core::ptr::null_mut();
        }
        // SAFETY: ssl_ctx is live.
        let ssl = unsafe { ffi::SSL_new(ssl_ctx) };
        if ssl.is_null() {
            // SAFETY: sbio is owned here.
            unsafe { ffi::BIO_free(sbio) };
            return core::ptr::null_mut();
        }
        if !vpm.is_null() {
            // SAFETY: ssl is live; host NULL or a C string (SSL_set_tlsext_host_name).
            unsafe {
                ffi::SSL_ctrl(
                    ssl,
                    SSL_CTRL_SET_TLSEXT_HOSTNAME,
                    c_long::from(TLSEXT_NAMETYPE_host_name),
                    host.cast(),
                )
            };
        }
        // SAFETY: ssl is live.
        unsafe { ffi::SSL_set_connect_state(ssl) };
        // BIO_set_ssl(sbio, ssl, BIO_CLOSE): the SSL BIO takes the connection object.
        ctrl(sbio, BIO_C_SET_SSL, c_long::from(BIO_CLOSE), ssl.cast());
        // SAFETY: both are live; the chain is the library's.
        unsafe { ffi::BIO_push(sbio, bio) }
    } else {
        if bio.is_null() {
            return bio;
        }
        if let Some(hint) = tls_error_hint()
            && let Some(err) = Bio::new_fd(2, false)
        {
            let _ = err.write_all(format!("{hint}\n").as_bytes());
        }
        crate::err::set_mark();
        // SAFETY: bio is the SSL BIO pushed above.
        unsafe { ffi::BIO_ssl_shutdown(bio) };
        // SAFETY: as above; cbio is the connection BIO under it.
        let cbio = unsafe { ffi::BIO_pop(bio) };
        // SAFETY: the SSL BIO alone is freed.
        unsafe { ffi::BIO_free(bio) };
        crate::err::pop_to_mark();
        cbio
    }
}

/// `OSSL_HTTP_adapt_proxy(proxy, no_proxy, server, use_ssl) != NULL`.
pub fn adapt_proxy(
    proxy: Option<&str>,
    no_proxy: Option<&str>,
    server: &str,
    use_ssl: bool,
) -> bool {
    let (Ok(p), Ok(n), Some(s)) = (opt_c(proxy), opt_c(no_proxy), cstring(server)) else {
        return false;
    };
    // SAFETY: the strings are NULL or valid; the result is borrowed (from the arguments or
    // the environment) and only compared with NULL.
    !unsafe { ffi::OSSL_HTTP_adapt_proxy(ptr_of(&p), ptr_of(&n), s.as_ptr(), c_int::from(use_ssl)) }
        .is_null()
}

/// `OSSL_HTTP_adapt_proxy(proxy, no_proxy, server, use_ssl)`: the proxy to use, if any.
pub fn adapt_proxy_host(
    proxy: Option<&str>,
    no_proxy: Option<&str>,
    server: &str,
    use_ssl: bool,
) -> Option<String> {
    let (Ok(p), Ok(n), Some(s)) = (opt_c(proxy), opt_c(no_proxy), cstring(server)) else {
        return None;
    };
    // SAFETY: the strings are NULL or valid; the result is NULL or a string borrowed from
    // the arguments or the environment, copied before they go.
    crate::util::string_at(unsafe {
        ffi::OSSL_HTTP_adapt_proxy(ptr_of(&p), ptr_of(&n), s.as_ptr(), c_int::from(use_ssl))
    })
}

/// The arguments of an HTTP POST (`app_http_post_asn1`'s transfer).
pub struct Post<'a> {
    pub host: &'a str,
    pub port: Option<&'a str>,
    pub path: Option<&'a str>,
    pub proxy: Option<&'a str>,
    pub no_proxy: Option<&'a str>,
    pub ssl_ctx: Option<&'a SslCtx>,
    pub headers: &'a Headers,
    pub content_type: &'a str,
    pub expected_content_type: &'a str,
    pub timeout: c_long,
    pub prog: &'a str,
}

/// `OSSL_HTTP_transfer` of `app_http_post_asn1`: the request's DER in, the response
/// `BIO` out (`None` is NULL, which the caller's `d2i` reports).
pub fn post(p: &Post<'_>, req: &Bio) -> Option<Bio> {
    let use_ssl = p.ssl_ctx.is_some();
    let use_proxy = adapt_proxy(p.proxy, p.no_proxy, p.host, use_ssl);
    let info = TlsInfo::new(
        p.host,
        p.port.unwrap_or_default(),
        use_proxy,
        p.timeout,
        p.ssl_ctx,
        p.prog,
    )?;
    let (host, port, path) = (cstring(p.host)?, opt_c(p.port).ok()?, opt_c(p.path).ok()?);
    let (proxy, no_proxy) = (opt_c(p.proxy).ok()?, opt_c(p.no_proxy).ok()?);
    let (ct, ect) = (cstring(p.content_type)?, cstring(p.expected_content_type)?);
    // TlsInfo's server and port are what upstream's info holds: the strings given.
    let max = usize::try_from(crate::abi::OSSL_HTTP_DEFAULT_MAX_RESP_LEN).unwrap_or(usize::MAX);
    // SAFETY: every pointer is NULL or valid for the call; the callback's argument is the
    // live info; the response BIO is the caller's.
    let rsp = unsafe {
        ffi::OSSL_HTTP_transfer(
            core::ptr::null_mut(),
            host.as_ptr(),
            ptr_of(&port),
            ptr_of(&path),
            c_int::from(use_ssl),
            ptr_of(&proxy),
            ptr_of(&no_proxy),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            Some(app_http_tls_cb),
            info.as_arg(),
            0,
            p.headers.as_ptr(),
            ct.as_ptr(),
            req.as_ptr(),
            ect.as_ptr(),
            1,
            max,
            c_int::try_from(p.timeout).unwrap_or(c_int::MAX),
            0,
        )
    };
    Bio::from_ptr(rsp)
}

/// The library's error for a NULL argument, as `app_http_get_asn1` raises them.
pub fn raise_null(data: Option<&str>) {
    let lib = crate::abi::ERR_LIB_HTTP;
    let reason = crate::abi::ERR_R_PASSED_NULL_PARAMETER;
    raise(lib, reason, data);
}

/// `ERR_raise_data(ERR_LIB_HTTP, ERR_R_PASSED_INVALID_ARGUMENT, data)`.
pub fn raise_invalid(data: &str) {
    raise(
        crate::abi::ERR_LIB_HTTP,
        crate::abi::ERR_R_PASSED_INVALID_ARGUMENT,
        Some(data),
    );
}

fn raise(lib: c_int, reason: c_int, data: Option<&str>) {
    // SAFETY: no pointer arguments.
    unsafe { ffi::ERR_new() };
    // SAFETY: the strings are static C strings.
    unsafe {
        ffi::ERR_set_debug(
            c"apps/lib/apps.c".as_ptr(),
            0,
            c"app_http_get_asn1".as_ptr(),
        )
    };
    match data.and_then(cstring) {
        Some(d) => {
            let f = ffi::ERR_set_error();
            // SAFETY: a "%s" format with one C string argument.
            unsafe { f(lib, reason, c"%s".as_ptr(), d.as_ptr()) };
        }
        None => {
            let f = ffi::ERR_set_error();
            // SAFETY: no format.
            unsafe { f(lib, reason, core::ptr::null()) };
        }
    }
}

/// `OSSL_HTTP_get` of `app_http_get_asn1`: the response `BIO` for `url` (`None` is NULL).
#[allow(clippy::too_many_arguments)]
pub fn get(
    url: &str,
    server: &str,
    port: &str,
    proxy: Option<&str>,
    no_proxy: Option<&str>,
    ssl_ctx: Option<&SslCtx>,
    use_proxy: bool,
    headers: &Headers,
    timeout: c_long,
    expected_content_type: Option<&str>,
    prog: &str,
) -> Option<Bio> {
    let info = TlsInfo::new(server, port, use_proxy, timeout, ssl_ctx, prog)?;
    let u = cstring(url)?;
    let (proxy, no_proxy, ect) = (
        opt_c(proxy).ok()?,
        opt_c(no_proxy).ok()?,
        opt_c(expected_content_type).ok()?,
    );
    let max = usize::try_from(crate::abi::OSSL_HTTP_DEFAULT_MAX_RESP_LEN).unwrap_or(usize::MAX);
    // SAFETY: as for post.
    Bio::from_ptr(unsafe {
        ffi::OSSL_HTTP_get(
            u.as_ptr(),
            ptr_of(&proxy),
            ptr_of(&no_proxy),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            Some(app_http_tls_cb),
            info.as_arg(),
            0,
            headers.as_ptr(),
            ptr_of(&ect),
            1,
            max,
            c_int::try_from(timeout).unwrap_or(c_int::MAX),
        )
    })
}

/// `getpid()`.
pub fn getpid() -> i32 {
    std::process::id().try_into().unwrap_or(0)
}

/// A string's bytes before its first NUL (C's view of it).
pub fn c_view(s: &str) -> &str {
    s.split('\0').next().unwrap_or_default()
}
