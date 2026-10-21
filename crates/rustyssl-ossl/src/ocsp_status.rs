//! OCSP stapling for `s_server` (`cert_status_cb` of `apps/s_server.c`): responses read from
//! files, matched to certificates, or fetched from a responder (`process_responder` of
//! `apps/ocsp.c`, with `app_http_tls_cb` of `apps/lib/apps.c`), and set on the connection.

use core::ffi::{c_char, c_int, c_long, c_void};

use crate::abi::*;
use crate::bio::Bio;
use crate::ffi;
pub use crate::ocsp::CertId;
pub use crate::ocsp::OcspRequest;
pub use crate::ocsp::OcspResponse;
use crate::ssl::{CertRef, SslRef};
use crate::util::{cstring, string_at, take_string};
use crate::x509::Cert;

impl OcspResponse {
    /// `OCSP_RESPONSE_print(bio, rsp, flags)`.
    pub fn print_with_flags(&self, bio: &Bio, flags: core::ffi::c_ulong) {
        // SAFETY: both are live.
        unsafe { ffi::OCSP_RESPONSE_print(bio.as_ptr(), self.as_ptr(), flags) };
    }
    /// Whether the response's basic response has a status for `id` (`OCSP_resp_find`).
    pub fn find(&self, id: &CertId) -> bool {
        // SAFETY: the response is live; the result is ours.
        let bs = unsafe { ffi::OCSP_response_get1_basic(self.as_ptr()) };
        if bs.is_null() {
            return false;
        }
        // SAFETY: both are live.
        let found = unsafe { ffi::OCSP_resp_find(bs, id.as_ptr(), -1) };
        // SAFETY: bs is ours.
        unsafe { ffi::OCSP_BASICRESP_free(bs) };
        found > -1
    }
}

impl CertId {
    /// `OCSP_cert_to_id(NULL, subject, issuer)`.
    pub fn new(subject: &Cert, issuer: &Cert) -> Option<Self> {
        // SAFETY: both are live; the result is ours.
        Self::from_ptr(unsafe {
            ffi::OCSP_cert_to_id(core::ptr::null(), subject.as_ptr(), issuer.as_ptr())
        })
    }
}

impl OcspRequest {
    /// `OCSP_request_add0_id`: the request takes the ID.
    pub fn add0_id(&self, id: CertId) -> bool {
        // SAFETY: both are live; on success the request owns the ID.
        if unsafe { ffi::OCSP_request_add0_id(self.as_ptr(), id.as_ptr()) }.is_null() {
            return false;
        }
        let _ = id.into_ptr();
        true
    }
}

impl SslRef<'_> {
    /// `SSL_set0_tlsext_status_ocsp_resp_ex(s, sk)`: the connection takes the list (NULL
    /// entries for certificates without a response).
    pub fn set0_tlsext_status_ocsp_resp_ex(self, list: Vec<Option<OcspResponse>>) -> bool {
        // SAFETY: a new empty stack.
        let sk = unsafe { ffi::OPENSSL_sk_new_null() };
        if sk.is_null() {
            return false;
        }
        for r in list {
            let p = r.map_or(core::ptr::null_mut(), OcspResponse::into_ptr);
            // SAFETY: the stack takes the response (or NULL).
            unsafe { ffi::OPENSSL_sk_push(sk, p.cast()) };
        }
        // SAFETY: the connection takes the stack.
        unsafe {
            ffi::SSL_ctrl(
                self.as_ptr(),
                SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP_EX,
                0,
                sk.cast(),
            ) != 0
        }
    }

    /// `SSL_get_tlsext_status_exts`: the request's extensions, added to `req`
    /// (`OCSP_REQUEST_add_ext`); false if one can't be.
    pub fn add_status_exts_to(self, req: &OcspRequest) -> bool {
        let mut exts: *mut OPENSSL_STACK = core::ptr::null_mut();
        // SAFETY: exts is a valid out-pointer; the stack is owned by the connection.
        unsafe {
            ffi::SSL_ctrl(
                self.as_ptr(),
                SSL_CTRL_GET_TLSEXT_STATUS_REQ_EXTS,
                0,
                (&raw mut exts).cast(),
            )
        };
        // SAFETY: NULL (-1) or a live stack.
        let n = unsafe { ffi::OPENSSL_sk_num(exts) };
        for i in 0..n.max(0) {
            // SAFETY: i in range; the members are extensions.
            let e = unsafe { ffi::OPENSSL_sk_value(exts, i) };
            // SAFETY: both are live; the request copies the extension.
            if unsafe { ffi::OCSP_REQUEST_add_ext(req.as_ptr(), e.cast(), -1) } == 0 {
                return false;
            }
        }
        true
    }
}

/// `X509_get1_ocsp(x)`: the AIA OCSP URLs.
pub fn cert_ocsp_urls(x: &Cert) -> Option<Vec<String>> {
    // SAFETY: the certificate is live; the stack is ours.
    let sk = unsafe { ffi::X509_get1_ocsp(x.as_ptr()) };
    if sk.is_null() {
        return None;
    }
    let st = sk.cast::<OPENSSL_STACK>();
    // SAFETY: a live stack.
    let n = unsafe { ffi::OPENSSL_sk_num(st) };
    // SAFETY: i in range; the members are C strings.
    let v = (0..n.max(0))
        .filter_map(|i| string_at(unsafe { ffi::OPENSSL_sk_value(st, i) }.cast()))
        .collect();
    // SAFETY: ours (X509_email_free frees the strings and the stack).
    unsafe { ffi::X509_email_free(sk) };
    Some(v)
}

/// `OSSL_HTTP_parse_url(url, &use_ssl, NULL, &host, &port, NULL, &path, NULL, NULL)`.
pub fn parse_url(url: &str) -> Option<(bool, String, String, String)> {
    let u = cstring(url)?;
    let mut ssl: c_int = 0;
    let (mut host, mut port, mut path): (*mut c_char, *mut c_char, *mut c_char) = (
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    );
    // SAFETY: valid out-pointers; the strings are ours.
    let r = unsafe {
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
    };
    let (h, p, pa) = (take_string(host), take_string(port), take_string(path));
    if r == 0 {
        return None;
    }
    Some((
        ssl != 0,
        h.unwrap_or_default(),
        p.unwrap_or_default(),
        pa.unwrap_or_default(),
    ))
}

/// `X509_name_cmp(X509_get_issuer_name(x), X509_get_subject_name(y)) == 0`.
pub fn issued_by_name(x: &Cert, y: &Cert) -> bool {
    // SAFETY: both are live; the names are owned by them.
    let a = unsafe { ffi::X509_get_issuer_name(x.as_ptr()) };
    // SAFETY: as above.
    let b = unsafe { ffi::X509_get_subject_name(y.as_ptr()) };
    // SAFETY: both names are live.
    unsafe { ffi::X509_NAME_cmp(a, b) == 0 }
}

/// The issuer of `x` in the context's trust store (`X509_STORE_CTX_get_obj_by_subject`):
/// `None` if the store context can't be set up, `Some(None)` if there is none.
pub fn issuer_in_store(s: SslRef<'_>, x: &Cert) -> Option<Option<Cert>> {
    // SAFETY: no arguments.
    let ctx = unsafe { ffi::X509_STORE_CTX_new() };
    if ctx.is_null() {
        return None;
    }
    // SAFETY: the context is live; the store is owned by it.
    let st = unsafe { ffi::SSL_CTX_get_cert_store(s.ctx().as_ptr()) };
    // SAFETY: all live.
    let ok =
        unsafe { ffi::X509_STORE_CTX_init(ctx, st, core::ptr::null_mut(), core::ptr::null_mut()) }
            == 1;
    let result = if ok {
        // SAFETY: x is live; the name is owned by it.
        let iname = unsafe { ffi::X509_get_issuer_name(x.as_ptr()) };
        // SAFETY: live context and name; the object is ours.
        let obj = unsafe { ffi::X509_STORE_CTX_get_obj_by_subject(ctx, X509_LU_X509, iname) };
        if obj.is_null() {
            Some(None)
        } else {
            // SAFETY: obj is live; the certificate is owned by it, and up-referenced here.
            let c = unsafe { ffi::X509_OBJECT_get0_X509(obj) };
            // SAFETY: c is live.
            let cert = if !c.is_null() && unsafe { ffi::X509_up_ref(c) } == 1 {
                Cert::from_raw(c)
            } else {
                None
            };
            // SAFETY: obj is ours.
            unsafe { ffi::X509_OBJECT_free(obj) };
            Some(cert)
        }
    } else {
        None
    };
    // SAFETY: ctx is ours.
    unsafe { ffi::X509_STORE_CTX_free(ctx) };
    result
}

/// The server's certificate (`SSL_get_certificate`) as an owned reference.
pub fn up_ref_cert(c: &CertRef<'_>) -> Option<Cert> {
    // SAFETY: the certificate is live.
    if unsafe { ffi::X509_up_ref(c.as_ptr()) } != 1 {
        return None;
    }
    Cert::from_raw(c.as_ptr())
}

/// `APP_HTTP_TLS_INFO`.
#[repr(C)]
struct TlsInfo {
    server: *const c_char,
    port: *const c_char,
    use_proxy: c_int,
    timeout: c_long,
    ssl_ctx: *mut SSL_CTX,
    prog: *const c_char,
    bio_err: *mut BIO,
}

/// `tls_error_hint` of `apps.c`.
fn tls_error_hint() -> Option<&'static str> {
    // SAFETY: no arguments.
    let mut e = unsafe { ffi::ERR_peek_error() };
    let lib = |e: core::ffi::c_ulong| {
        (e >> ERR_LIB_OFFSET) & core::ffi::c_ulong::from(ERR_LIB_MASK.cast_unsigned())
    };
    let ssl = core::ffi::c_ulong::from(ERR_LIB_SSL.cast_unsigned());
    if crate::err::is_system_error(e) || lib(e) != ssl {
        // SAFETY: as above.
        e = unsafe { ffi::ERR_peek_last_error() };
    }
    if crate::err::is_system_error(e) || lib(e) != ssl {
        return None;
    }
    let r = crate::err::reason(e);
    Some(match r {
        SSL_R_WRONG_VERSION_NUMBER => "The server does not support (a suitable version of) TLS",
        SSL_R_UNKNOWN_PROTOCOL => "The server does not support HTTPS",
        SSL_R_CERTIFICATE_VERIFY_FAILED => {
            "Cannot authenticate server via its TLS certificate, likely due to mismatch with our trusted TLS certs or missing revocation status"
        }
        x if x == SSL_AD_REASON_OFFSET + TLS1_AD_UNKNOWN_CA => {
            "Server did not accept our TLS certificate, likely due to mismatch with server's trust anchor or missing revocation status"
        }
        x if x == SSL_AD_REASON_OFFSET + SSL3_AD_HANDSHAKE_FAILURE => {
            "TLS handshake failure. Possibly the server requires our TLS certificate but did not receive it"
        }
        _ => return None,
    })
}

/// `app_http_tls_cb`.
unsafe extern "C" fn http_tls_cb(
    bio: *mut BIO,
    arg: *mut c_void,
    connect: c_int,
    _detail: c_int,
) -> *mut BIO {
    // SAFETY: arg is the TlsInfo process_responder passes, alive during the transfer.
    let info = unsafe { &*arg.cast::<TlsInfo>() };
    if info.ssl_ctx.is_null() {
        return bio;
    }
    if connect != 0 {
        // SAFETY: the context is live; the store and its parameters are owned by it.
        let ts = unsafe { ffi::SSL_CTX_get_cert_store(info.ssl_ctx) };
        // SAFETY: as above.
        let vpm = unsafe { ffi::X509_STORE_get0_param(ts) };
        let host = if vpm.is_null() {
            core::ptr::null()
        } else {
            // SAFETY: vpm is live.
            unsafe { ffi::X509_VERIFY_PARAM_get0_host(vpm, 0) }.cast_const()
        };
        if info.use_proxy != 0
            // SAFETY: the strings and BIOs are live.
            && unsafe {
                ffi::OSSL_HTTP_proxy_connect(
                    bio,
                    info.server,
                    info.port,
                    core::ptr::null(),
                    core::ptr::null(),
                    c_int::try_from(info.timeout).unwrap_or(0),
                    info.bio_err,
                    info.prog,
                )
            } == 0
        {
            return core::ptr::null_mut();
        }
        // SAFETY: a static method.
        let m = unsafe { ffi::BIO_f_ssl() };
        // SAFETY: m is valid.
        let sbio = unsafe { ffi::BIO_new(m) };
        if sbio.is_null() {
            return core::ptr::null_mut();
        }
        // SAFETY: the context is live.
        let ssl = unsafe { ffi::SSL_new(info.ssl_ctx) };
        if ssl.is_null() {
            // SAFETY: sbio is ours.
            unsafe { ffi::BIO_free(sbio) };
            return core::ptr::null_mut();
        }
        if !vpm.is_null() {
            // SAFETY: host is NULL or a string owned by the parameters.
            unsafe {
                ffi::SSL_ctrl(
                    ssl,
                    SSL_CTRL_SET_TLSEXT_HOSTNAME,
                    c_long::from(TLSEXT_NAMETYPE_host_name),
                    host.cast_mut().cast(),
                )
            };
        }
        // SAFETY: ssl is ours.
        unsafe { ffi::SSL_set_connect_state(ssl) };
        // SAFETY: the BIO takes the connection.
        unsafe { ffi::BIO_ctrl(sbio, BIO_C_SET_SSL, c_long::from(BIO_CLOSE), ssl.cast()) };
        // SAFETY: both live; the chain now holds bio.
        unsafe { ffi::BIO_push(sbio, bio) }
    } else {
        if bio.is_null() {
            return bio;
        }
        if let Some(hint) = tls_error_hint()
            && !info.bio_err.is_null()
            && let Some(c) = cstring(&format!("{hint}\n"))
        {
            // SAFETY: a live BIO and a valid string.
            unsafe { ffi::BIO_puts(info.bio_err, c.as_ptr()) };
        }
        crate::err::set_mark();
        // SAFETY: bio is the SSL BIO pushed above.
        unsafe { ffi::BIO_ssl_shutdown(bio) };
        // SAFETY: as above.
        let cbio = unsafe { ffi::BIO_pop(bio) };
        // SAFETY: the SSL BIO is ours now.
        unsafe { ffi::BIO_free(bio) };
        crate::err::pop_to_mark();
        cbio
    }
}

/// `process_responder(req, host, port, path, proxy, no_proxy, use_ssl, NULL, timeout)`
/// (the "Error querying OCSP responder" message left to the caller, for `None`).
#[allow(clippy::too_many_arguments)]
pub fn process_responder(
    req: &OcspRequest,
    host: &str,
    port: &str,
    path: &str,
    proxy: Option<&str>,
    no_proxy: Option<&str>,
    use_ssl: bool,
    timeout: c_int,
    bio_err: Option<&Bio>,
    prog: &str,
) -> Option<OcspResponse> {
    let mut ctx: *mut SSL_CTX = core::ptr::null_mut();
    if use_ssl {
        // SAFETY: no arguments.
        let m = unsafe { ffi::TLS_client_method() };
        // SAFETY: a static method.
        ctx = unsafe { ffi::SSL_CTX_new(m) };
        if ctx.is_null() {
            if let Some(b) = bio_err {
                let _ = b.write_all(b"Error creating SSL context.\n");
            }
            return None;
        }
    }
    let c = |s: Option<&str>| match s {
        Some(s) => cstring(s).map(Some),
        None => Some(None),
    };
    let (Some(h), Some(p), Some(pa), Some(px), Some(npx), Some(pr)) = (
        cstring(host),
        cstring(port),
        cstring(path),
        c(proxy),
        c(no_proxy),
        cstring(prog),
    ) else {
        return None;
    };
    let ptr = |x: &Option<std::ffi::CString>| x.as_ref().map_or(core::ptr::null(), |x| x.as_ptr());
    // SAFETY: a static item.
    let req_it = unsafe { ffi::OCSP_REQUEST_it() };
    // SAFETY: as above.
    let rsp_it = unsafe { ffi::OCSP_RESPONSE_it() };
    // SAFETY: the request is live; the BIO is ours.
    let req_mem = unsafe { ffi::ASN1_item_i2d_mem_bio(req_it, req.as_ptr().cast()) };
    if req_mem.is_null() {
        // SAFETY: ctx is NULL or ours.
        unsafe { ffi::SSL_CTX_free(ctx) };
        return None;
    }
    // SAFETY: valid strings or NULL.
    let use_proxy = !unsafe {
        ffi::OSSL_HTTP_adapt_proxy(ptr(&px), ptr(&npx), h.as_ptr(), c_int::from(use_ssl))
    }
    .is_null();
    let mut info = TlsInfo {
        server: h.as_ptr(),
        port: p.as_ptr(),
        use_proxy: c_int::from(use_proxy),
        timeout: c_long::from(timeout),
        ssl_ctx: ctx,
        prog: pr.as_ptr(),
        bio_err: bio_err.map_or(core::ptr::null_mut(), Bio::as_ptr),
    };
    // SAFETY: every pointer is valid for the transfer; info outlives it.
    let rsp = unsafe {
        ffi::OSSL_HTTP_transfer(
            core::ptr::null_mut(),
            h.as_ptr(),
            p.as_ptr(),
            pa.as_ptr(),
            c_int::from(use_ssl),
            ptr(&px),
            ptr(&npx),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            Some(http_tls_cb),
            (&raw mut info).cast(),
            0,
            core::ptr::null(),
            c"application/ocsp-request".as_ptr(),
            req_mem,
            c"application/ocsp-response".as_ptr(),
            1,
            OSSL_HTTP_DEFAULT_MAX_RESP_LEN.try_into().unwrap_or(0),
            timeout,
            0,
        )
    };
    // SAFETY: ours.
    unsafe { ffi::BIO_free(req_mem) };
    // SAFETY: rsp is NULL or a live BIO; the result is ours.
    let res = unsafe { ffi::ASN1_item_d2i_bio(rsp_it, rsp, core::ptr::null_mut()) };
    // SAFETY: ours (NULL is fine).
    unsafe { ffi::BIO_free(rsp) };
    // SAFETY: ctx is NULL or ours.
    unsafe { ffi::SSL_CTX_free(ctx) };
    OcspResponse::from_ptr(res.cast())
}
