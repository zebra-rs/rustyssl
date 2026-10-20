//! Custom TLS extensions (`extensions_cust.c`): the application's add, free, and parse
//! callbacks, in the old API (`SSL_CTX_add_client_custom_ext`, `_add_server_custom_ext`) and
//! the new one with contexts (`SSL_CTX_add_custom_ext`), and the server information
//! extensions of `SSL_CTX_use_serverinfo*` (`ssl_rsa.c`), which register their own.
//!
//! The extensions are part of a certificate configuration (`CERT`'s `custext`): a connection
//! gets a copy of its context's when it's made. The core asks for each extension's contents
//! and hands over what it receives ([`Request::CustomExt`]); the callbacks run with no lock
//! held.

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_SSL, ERR_R_BUF_LIB, ERR_R_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER, ERR_R_SYS_LIB,
    SSL, SSL_AD_DECODE_ERROR, SSL_AD_INTERNAL_ERROR, SSL_CTX, SSL_EXT_CLIENT_HELLO,
    SSL_EXT_IGNORE_ON_RESUMPTION, SSL_EXT_TLS1_2_AND_BELOW_ONLY, SSL_EXT_TLS1_2_SERVER_HELLO,
    SSL_EXT_TLS1_3_CERTIFICATE, SSL_R_BAD_DATA, SSL_R_INVALID_SERVERINFO_DATA,
    SSL_R_NO_PEM_EXTENSIONS, SSL_R_PEM_NAME_BAD_PREFIX, SSL_R_PEM_NAME_TOO_SHORT, SSL_SERVERINFOV1,
    SSL_SERVERINFOV2, SSL_custom_ext_add_cb_ex, SSL_custom_ext_free_cb_ex,
    SSL_custom_ext_parse_cb_ex, X509, custom_ext_add_cb, custom_ext_free_cb, custom_ext_parse_cb,
};
use rustyssl_tls::conn::Answer;
use rustyssl_tls::conn::config::CustomExt;

use super::conn::Ssl;
use super::ctx::ctx;
use crate::err;
use crate::ffi::ffi_export;
use crate::x509::cert::{X509_free, d2i_X509};

/// The context of the server information extensions of version 1 (`SYNTHV1CONTEXT`,
/// `ssl_local.h`): those of the old API.
const SYNTHV1CONTEXT: u32 = (SSL_EXT_TLS1_2_AND_BELOW_ONLY
    | SSL_EXT_CLIENT_HELLO
    | SSL_EXT_TLS1_2_SERVER_HELLO
    | SSL_EXT_IGNORE_ON_RESUMPTION)
    .cast_unsigned();

/// `SSL_EXT_CLIENT_HELLO` and `SSL_EXT_TLS1_3_CERTIFICATE` as the contexts' type.
const CLIENT_HELLO: u32 = SSL_EXT_CLIENT_HELLO.cast_unsigned();
/// See [`CLIENT_HELLO`].
const TLS1_3_CERTIFICATE: u32 = SSL_EXT_TLS1_3_CERTIFICATE.cast_unsigned();
/// `SSL_SERVERINFOV1` and `SSL_SERVERINFOV2` as the version's type.
const V1: c_uint = SSL_SERVERINFOV1.cast_unsigned();
/// See [`V1`].
const V2: c_uint = SSL_SERVERINFOV2.cast_unsigned();

/// An extension's callbacks.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Callbacks {
    /// The old API's (wrapped: a missing add callback sends an empty extension, a missing
    /// parse callback accepts anything).
    Old {
        add: custom_ext_add_cb,
        free: custom_ext_free_cb,
        add_arg: *mut c_void,
        parse: custom_ext_parse_cb,
        parse_arg: *mut c_void,
    },
    /// The new API's.
    New {
        add: SSL_custom_ext_add_cb_ex,
        free: SSL_custom_ext_free_cb_ex,
        add_arg: *mut c_void,
        parse: SSL_custom_ext_parse_cb_ex,
        parse_arg: *mut c_void,
    },
    /// A server information extension (`serverinfo_srv_add_cb`, `serverinfoex_srv_add_cb`):
    /// sent from the chosen certificate's server information, received only empty.
    ServerInfo,
}

/// One registered extension (`custom_ext_method`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Method {
    pub(crate) typ: u16,
    pub(crate) context: u32,
    /// `Some(true)`: the server's (`ENDPOINT_SERVER`), `Some(false)`: the client's, `None`:
    /// both.
    pub(crate) role: Option<bool>,
    pub(crate) cbs: Callbacks,
}

impl Method {
    /// The core's view.
    pub(crate) fn for_core(&self) -> CustomExt {
        let (has_add, has_parse) = match self.cbs {
            Callbacks::Old { .. } | Callbacks::ServerInfo => (true, true),
            Callbacks::New { add, parse, .. } => (add.is_some(), parse.is_some()),
        };
        CustomExt {
            typ: self.typ,
            context: self.context,
            server: self.role,
            has_add,
            has_parse,
        }
    }
}

/// `custom_ext_find`.
pub(crate) fn find(exts: &[Method], role: Option<bool>, typ: u16) -> bool {
    exts.iter()
        .any(|m| m.typ == typ && (role.is_none() || m.role.is_none() || m.role == role))
}

/// `SSL_extension_supported`: the extensions libssl handles itself.
fn supported(typ: c_uint) -> bool {
    use rustyssl_abi as a;
    [
        a::TLSEXT_TYPE_application_layer_protocol_negotiation,
        a::TLSEXT_TYPE_ec_point_formats,
        a::TLSEXT_TYPE_supported_groups,
        a::TLSEXT_TYPE_key_share,
        a::TLSEXT_TYPE_next_proto_neg,
        a::TLSEXT_TYPE_padding,
        a::TLSEXT_TYPE_renegotiate,
        a::TLSEXT_TYPE_max_fragment_length,
        a::TLSEXT_TYPE_server_name,
        a::TLSEXT_TYPE_session_ticket,
        a::TLSEXT_TYPE_signature_algorithms,
        a::TLSEXT_TYPE_srp,
        a::TLSEXT_TYPE_status_request,
        a::TLSEXT_TYPE_signed_certificate_timestamp,
        a::TLSEXT_TYPE_use_srtp,
        a::TLSEXT_TYPE_encrypt_then_mac,
        a::TLSEXT_TYPE_supported_versions,
        a::TLSEXT_TYPE_extended_master_secret,
        a::TLSEXT_TYPE_psk_kex_modes,
        a::TLSEXT_TYPE_cookie,
        a::TLSEXT_TYPE_early_data,
        a::TLSEXT_TYPE_certificate_authorities,
        a::TLSEXT_TYPE_psk,
        a::TLSEXT_TYPE_post_handshake_auth,
        a::TLSEXT_TYPE_compress_certificate,
        a::TLSEXT_TYPE_client_cert_type,
        a::TLSEXT_TYPE_server_cert_type,
    ]
    .into_iter()
    .any(|t| c_uint::try_from(t).is_ok_and(|t| t == typ))
}

/// `ossl_tls_add_custom_ext_intern` for a context: 1, or 0 when refused.
///
/// # Safety
/// `c` is NULL or a live context.
unsafe fn add_intern(
    c: *mut SSL_CTX,
    role: Option<bool>,
    typ: c_uint,
    context: c_uint,
    cbs: Callbacks,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(cx) = (unsafe { ctx(c) }) else {
        return 0;
    };
    if let Callbacks::New {
        add: None,
        free: Some(_),
        ..
    } = cbs
    {
        // The free callback would never be called.
        return 0;
    }
    let sct = c_uint::try_from(rustyssl_abi::TLSEXT_TYPE_signed_certificate_timestamp).unwrap_or(0);
    let mut cs = cx.state();
    // Built-in SCT validation and the application's SCT extension don't mix.
    if typ == sct && context & CLIENT_HELLO != 0 && cs.ct.callback.is_some() {
        return 0;
    }
    if supported(typ) && typ != sct {
        return 0;
    }
    let Ok(typ) = u16::try_from(typ) else {
        return 0;
    };
    if find(&cs.cert.custext, role, typ) {
        return 0;
    }
    cs.cert.custext.push(Method {
        typ,
        context,
        role,
        cbs,
    });
    1
}

ffi_export! {
    /// Adds a client extension with the old callbacks (ClientHello and TLS 1.2 ServerHello,
    /// TLS 1.2 and below, not on resumption): 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; the callbacks are the application's.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_add_client_custom_ext(ctx: *mut SSL_CTX, ext_type: c_uint, add_cb: custom_ext_add_cb, free_cb: custom_ext_free_cb, add_arg: *mut c_void, parse_cb: custom_ext_parse_cb, parse_arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        let cbs = Callbacks::Old { add: add_cb, free: free_cb, add_arg, parse: parse_cb, parse_arg };
        // SAFETY: the caller's guarantee.
        unsafe { add_intern(ctx, Some(false), ext_type, SYNTHV1CONTEXT, cbs) }
    }
}

ffi_export! {
    /// As [`rustyssl_private_SSL_CTX_add_client_custom_ext`], for a server.
    ///
    /// # Safety
    /// As there.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_add_server_custom_ext(ctx: *mut SSL_CTX, ext_type: c_uint, add_cb: custom_ext_add_cb, free_cb: custom_ext_free_cb, add_arg: *mut c_void, parse_cb: custom_ext_parse_cb, parse_arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        let cbs = Callbacks::Old { add: add_cb, free: free_cb, add_arg, parse: parse_cb, parse_arg };
        // SAFETY: the caller's guarantee.
        unsafe { add_intern(ctx, Some(true), ext_type, SYNTHV1CONTEXT, cbs) }
    }
}

ffi_export! {
    /// Adds an extension for both roles in the messages of `context` (`SSL_EXT_*`): 1, or 0
    /// (an extension libssl handles, a duplicate, a free callback without an add callback, or
    /// an SCT extension with CT validation on).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; the callbacks are the application's.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_add_custom_ext(ctx: *mut SSL_CTX, ext_type: c_uint, context: c_uint, add_cb: SSL_custom_ext_add_cb_ex, free_cb: SSL_custom_ext_free_cb_ex, add_arg: *mut c_void, parse_cb: SSL_custom_ext_parse_cb_ex, parse_arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        let cbs = Callbacks::New { add: add_cb, free: free_cb, add_arg, parse: parse_cb, parse_arg };
        // SAFETY: the caller's guarantee.
        unsafe { add_intern(ctx, None, ext_type, context, cbs) }
    }
}

ffi_export! {
    /// Whether the context has a client extension of `ext_type`.
    ///
    /// # Safety
    /// `ctx` is a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_has_client_custom_ext(ctx: *const SSL_CTX, ext_type: c_uint) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(cx) = (unsafe { super::ctx::ctx(ctx) }) else { return 0 };
        let Ok(typ) = u16::try_from(ext_type) else { return 0 };
        c_int::from(find(&cx.state().cert.custext, Some(false), typ))
    }
}

ffi_export! {
    /// Whether libssl handles extensions of `ext_type` itself.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_extension_supported(ext_type: c_uint) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        c_int::from(supported(ext_type))
    }
}

/// Whether the context has a client SCT extension (`SSL_CTX_has_client_custom_ext` for
/// `TLSEXT_TYPE_signed_certificate_timestamp`), which rules out CT validation.
pub(crate) fn has_client_sct(exts: &[Method]) -> bool {
    u16::try_from(rustyssl_abi::TLSEXT_TYPE_signed_certificate_timestamp)
        .is_ok_and(|t| find(exts, Some(false), t))
}

/// The extension's data of type `typ` in server information (version 2), if any; `Err` for
/// malformed data (`serverinfo_find_extension`).
fn serverinfo_find(info: &[u8], typ: u16) -> Result<Option<&[u8]>, ()> {
    let mut rest = info;
    while !rest.is_empty() {
        let (head, tail) = rest.split_at_checked(8).ok_or(())?;
        let [_, _, _, _, t0, t1, l0, l1] = <[u8; 8]>::try_from(head).map_err(|_| ())?;
        let len = usize::from(u16::from_be_bytes([l0, l1]));
        let (data, next) = tail.split_at_checked(len).ok_or(())?;
        if u16::from_be_bytes([t0, t1]) == typ {
            return Ok(Some(data));
        }
        rest = next;
    }
    Ok(None)
}

/// `serverinfo_process_buffer`: the types (and contexts) of well-formed server information of
/// `version`, or `None`.
fn serverinfo_parse(version: c_uint, info: &[u8]) -> Option<Vec<(u32, u16)>> {
    if info.is_empty() || (version != V1 && version != V2) {
        return None;
    }
    let ctx_len = if version == V2 { 4 } else { 0 };
    let mut out = Vec::new();
    let mut rest = info;
    while !rest.is_empty() {
        let (c, tail) = rest.split_at_checked(ctx_len)?;
        let context = c.iter().fold(0u32, |a, &b| (a << 8) | u32::from(b));
        let (t, tail) = tail.split_at_checked(2)?;
        let (l, tail) = tail.split_at_checked(2)?;
        let typ = u16::from_be_bytes(<[u8; 2]>::try_from(t).ok()?);
        let len = usize::from(u16::from_be_bytes(<[u8; 2]>::try_from(l).ok()?));
        let (_, next) = tail.split_at_checked(len)?;
        out.push((context, typ));
        rest = next;
    }
    Some(out)
}

/// `extension_append` for version 1 data: each extension gets the synthetic context.
fn serverinfo_v1_to_v2(info: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(info.len().saturating_add(4));
    out.extend_from_slice(&SYNTHV1CONTEXT.to_be_bytes());
    out.extend_from_slice(info);
    out
}

/// `SSL_CTX_use_serverinfo_ex` on bytes the caller checked.
///
/// # Safety
/// `c` is a live context.
unsafe fn use_serverinfo(c: *mut SSL_CTX, version: c_uint, info: &[u8]) -> c_int {
    const F: &str = "SSL_CTX_use_serverinfo_ex";
    if version == V1 {
        // SAFETY: the caller's guarantee.
        return unsafe { use_serverinfo(c, V2, &serverinfo_v1_to_v2(info)) };
    }
    let Some(exts) = serverinfo_parse(version, info) else {
        err::raise(ERR_LIB_SSL, SSL_R_INVALID_SERVERINFO_DATA, F);
        return 0;
    };
    // SAFETY: the caller's guarantee.
    let Some(cx) = (unsafe { ctx(c) }) else {
        return 0;
    };
    {
        let mut cs = cx.state();
        let Some(slot) = cs.cert.current_mut() else {
            drop(cs);
            err::raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR, F);
            return 0;
        };
        slot.serverinfo = Some(info.to_vec());
    }
    for (context, typ) in exts {
        let (role, context) = if context == SYNTHV1CONTEXT {
            (Some(true), SYNTHV1CONTEXT)
        } else {
            (None, context)
        };
        // SAFETY: as above.
        if unsafe { add_intern(c, role, c_uint::from(typ), context, Callbacks::ServerInfo) } == 0 {
            err::raise(ERR_LIB_SSL, SSL_R_INVALID_SERVERINFO_DATA, F);
            return 0;
        }
    }
    1
}

ffi_export! {
    /// Sets the current certificate's server information (version 1: type, length, data per
    /// extension; version 2: a 4-octet context first) and registers its extensions: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `serverinfo` NULL or `serverinfo_length` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_use_serverinfo_ex(ctx: *mut SSL_CTX, version: c_uint, serverinfo: *const c_uchar, serverinfo_length: usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        if ctx.is_null() || serverinfo.is_null() || serverinfo_length == 0 {
            err::raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER, "SSL_CTX_use_serverinfo_ex");
            return 0;
        }
        // SAFETY: the caller's `serverinfo_length` octets.
        let info = unsafe { core::slice::from_raw_parts(serverinfo, serverinfo_length) };
        // SAFETY: the caller's guarantee.
        unsafe { use_serverinfo(ctx, version, info) }
    }
}

ffi_export! {
    /// Version 1 server information (`SSL_CTX_use_serverinfo_ex` with `V1`).
    ///
    /// # Safety
    /// As for `SSL_CTX_use_serverinfo_ex`.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_use_serverinfo(ctx: *mut SSL_CTX, serverinfo: *const c_uchar, serverinfo_length: usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { rustyssl_private_SSL_CTX_use_serverinfo_ex(ctx, V1, serverinfo, serverinfo_length) }
    }
}

/// `NAME_PREFIX1` and `NAME_PREFIX2` (`ssl_rsa.c`): the PEM names of version 1 and 2 server
/// information.
const NAME_PREFIX1: &[u8] = b"SERVERINFO FOR ";
const NAME_PREFIX2: &[u8] = b"SERVERINFOV2 FOR ";

ffi_export! {
    /// Server information from a PEM file of `SERVERINFO FOR ...` (version 1) and
    /// `SERVERINFOV2 FOR ...` blocks: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `file` NULL or a string.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_use_serverinfo_file(ctx: *mut SSL_CTX, file: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        use crate::bio::file::BIO_s_file;
        use crate::bio::{BIO_ctrl, BIO_free, BIO_new};
        const F: &str = "SSL_CTX_use_serverinfo_file";
        if ctx.is_null() || file.is_null() {
            err::raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        }
        // SAFETY: no preconditions.
        let meth = unsafe { BIO_s_file() };
        // SAFETY: a built-in method.
        let bin = unsafe { BIO_new(meth) };
        if bin.is_null() {
            err::raise(ERR_LIB_SSL, ERR_R_BUF_LIB, F);
            return 0;
        }
        let mode = core::ffi::c_long::from(rustyssl_abi::BIO_CLOSE | rustyssl_abi::BIO_FP_READ);
        // SAFETY: the new BIO; the caller's string (`BIO_read_filename`).
        if unsafe { BIO_ctrl(bin, rustyssl_abi::BIO_C_SET_FILENAME, mode, file.cast_mut().cast()) } <= 0 {
            err::raise(ERR_LIB_SSL, ERR_R_SYS_LIB, F);
            // SAFETY: ours.
            unsafe { BIO_free(bin) };
            return 0;
        }
        // SAFETY: the new BIO, read to its end and freed.
        let ret = unsafe { serverinfo_file(ctx, bin) };
        // SAFETY: ours.
        unsafe { BIO_free(bin) };
        ret
    }
}

/// The blocks of a server information file, then `SSL_CTX_use_serverinfo_ex`.
///
/// # Safety
/// `ctx` is a live context; `bin` a live BIO.
unsafe fn serverinfo_file(ctx: *mut SSL_CTX, bin: *mut rustyssl_abi::BIO) -> c_int {
    const F: &str = "SSL_CTX_use_serverinfo_file";
    let mut info = Vec::new();
    let mut count = 0usize;
    loop {
        // SAFETY: the caller's BIO.
        let Some((name, data)) = (unsafe { read_block(bin) }) else {
            if count == 0 {
                err::raise(ERR_LIB_SSL, SSL_R_NO_PEM_EXTENSIONS, F);
                return 0;
            }
            break;
        };
        if name.len() < NAME_PREFIX1.len() {
            err::raise(ERR_LIB_SSL, SSL_R_PEM_NAME_TOO_SHORT, F);
            return 0;
        }
        let version = if name.starts_with(NAME_PREFIX1) {
            V1
        } else {
            if name.len() < NAME_PREFIX2.len() {
                err::raise(ERR_LIB_SSL, SSL_R_PEM_NAME_TOO_SHORT, F);
                return 0;
            }
            if !name.starts_with(NAME_PREFIX2) {
                err::raise(ERR_LIB_SSL, SSL_R_PEM_NAME_BAD_PREFIX, F);
                return 0;
            }
            V2
        };
        // The header's length must match: type and length (and the context, version 2).
        let head = if version == V1 { 4 } else { 8 };
        let plausible = data.len() >= head
            && data
                .get(head.saturating_sub(2)..head)
                .and_then(|l| <[u8; 2]>::try_from(l).ok())
                .is_some_and(|l| {
                    usize::from(u16::from_be_bytes(l)) == data.len().saturating_sub(head)
                });
        if !plausible {
            err::raise(ERR_LIB_SSL, SSL_R_BAD_DATA, F);
            return 0;
        }
        if version == V1 {
            info.extend_from_slice(&serverinfo_v1_to_v2(&data));
        } else {
            info.extend_from_slice(&data);
        }
        count = count.saturating_add(1);
    }
    // SAFETY: the caller's guarantee.
    unsafe { use_serverinfo(ctx, V2, &info) }
}

/// The next PEM block's name and data (`PEM_read_bio`), or `None` at the end (or a bad block).
///
/// # Safety
/// `bin` is a live BIO.
unsafe fn read_block(bin: *mut rustyssl_abi::BIO) -> Option<(Vec<u8>, Vec<u8>)> {
    let (mut name, mut header): (*mut c_char, *mut c_char) = (ptr::null_mut(), ptr::null_mut());
    let mut data: *mut c_uchar = ptr::null_mut();
    let mut len: core::ffi::c_long = 0;
    // SAFETY: the caller's BIO; our slots.
    let ok = unsafe {
        crate::pem::PEM_read_bio(
            bin,
            &raw mut name,
            &raw mut header,
            &raw mut data,
            &raw mut len,
        )
    } != 0;
    let out = if ok && !name.is_null() {
        // SAFETY: the NUL-terminated name it allocated.
        let n = unsafe { core::ffi::CStr::from_ptr(name) }
            .to_bytes()
            .to_vec();
        let d = match usize::try_from(len) {
            Ok(l) if l > 0 && !data.is_null() => {
                // SAFETY: the `len` octets it allocated.
                unsafe { core::slice::from_raw_parts(data, l) }.to_vec()
            }
            _ => Vec::new(),
        };
        Some((n, d))
    } else {
        None
    };
    // SAFETY: what it allocated, or NULL.
    unsafe { crate::mem::release(name.cast()) };
    // SAFETY: as above.
    unsafe { crate::mem::release(header.cast()) };
    // SAFETY: as above.
    unsafe { crate::mem::release(data.cast()) };
    out
}

/// The alert a callback set (`*al`), as the core takes it.
fn alert_of(al: c_int) -> Option<u8> {
    u8::try_from(al).ok()
}

/// A certificate for the callbacks' `x`: the DER decoded (owned; freed by [`free_x`]), or NULL.
fn x509_of(der: Option<&[u8]>) -> *mut X509 {
    let Some(der) = der else {
        return ptr::null_mut();
    };
    let Ok(len) = core::ffi::c_long::try_from(der.len()) else {
        return ptr::null_mut();
    };
    let mut p = der.as_ptr();
    // SAFETY: `len` octets at `p`.
    unsafe { d2i_X509(ptr::null_mut(), &raw mut p, len) }
}

/// Frees what [`x509_of`] made.
fn free_x(x: *mut X509) {
    // SAFETY: ours, or NULL.
    unsafe { X509_free(x) };
}

/// The chosen server certificate's server information (`ssl_get_server_cert_serverinfo`).
fn chosen_serverinfo(x: &Ssl) -> Option<Vec<u8>> {
    let st = x.state();
    let c = st.drv.tls.as_ref()?;
    let i = c.negotiated().own_cert?;
    let slot = c.config().certs.get(i)?.slot;
    st.cert.pkeys.get(slot)?.serverinfo.clone()
}

/// Answers the core's request for extension `index` (its contents to add, or what was received
/// to parse), calling the application's callbacks with no lock held.
///
/// # Safety
/// `s` is the live connection behind `x`.
#[expect(clippy::too_many_arguments, reason = "the request's fields")]
pub(crate) unsafe fn answer(
    s: *mut SSL,
    x: &Ssl,
    index: usize,
    typ: u16,
    context: u32,
    body: Option<&[u8]>,
    chainidx: usize,
    cert: Option<&[u8]>,
) -> Answer {
    let internal = Answer::Fail {
        alert: alert_of(SSL_AD_INTERNAL_ERROR),
        reason: ERR_R_INTERNAL_ERROR,
    };
    let Some(m) = x.state().cert.custext.get(index).copied() else {
        return internal;
    };
    let ext_type = c_uint::from(typ);
    match (m.cbs, body) {
        (Callbacks::ServerInfo, None) => {
            // Only the first certificate's entry carries the extensions.
            if context & TLS1_3_CERTIFICATE != 0 && chainidx > 0 {
                return Answer::CustomExt(None);
            }
            let Some(info) = chosen_serverinfo(x) else {
                return Answer::CustomExt(None);
            };
            match serverinfo_find(&info, typ) {
                Ok(Some(d)) => Answer::CustomExt(Some(d.to_vec())),
                Ok(None) => Answer::CustomExt(None),
                Err(()) => internal,
            }
        }
        (Callbacks::ServerInfo, Some(b)) => {
            if b.is_empty() {
                Answer::Continue
            } else {
                Answer::Fail {
                    alert: alert_of(SSL_AD_DECODE_ERROR),
                    reason: 0,
                }
            }
        }
        (
            Callbacks::Old {
                add, free, add_arg, ..
            },
            None,
        ) => {
            let Some(add) = add else {
                return Answer::CustomExt(Some(Vec::new()));
            };
            let mut out: *const c_uchar = ptr::null();
            let mut outlen = 0usize;
            let mut al = SSL_AD_INTERNAL_ERROR;
            // SAFETY: the application's callback with its connection and our slots; no lock
            // is held.
            let r = unsafe {
                add(
                    s,
                    ext_type,
                    &raw mut out,
                    &raw mut outlen,
                    &raw mut al,
                    add_arg,
                )
            };
            // SAFETY: what the callback gave.
            let a = unsafe { added(r, out, outlen, al) };
            if r > 0
                && let Some(f) = free
            {
                // SAFETY: the application's free callback for what its add callback gave.
                unsafe { f(s, ext_type, out, add_arg) };
            }
            a
        }
        (
            Callbacks::New {
                add, free, add_arg, ..
            },
            None,
        ) => {
            let Some(add) = add else {
                return Answer::CustomExt(Some(Vec::new()));
            };
            let mut out: *const c_uchar = ptr::null();
            let mut outlen = 0usize;
            let mut al = SSL_AD_INTERNAL_ERROR;
            let xc = x509_of(cert);
            // SAFETY: as above, with the certificate (or NULL).
            let r = unsafe {
                add(
                    s,
                    ext_type,
                    context,
                    &raw mut out,
                    &raw mut outlen,
                    xc,
                    chainidx,
                    &raw mut al,
                    add_arg,
                )
            };
            free_x(xc);
            // SAFETY: as above.
            let a = unsafe { added(r, out, outlen, al) };
            if r > 0
                && let Some(f) = free
            {
                // SAFETY: as above.
                unsafe { f(s, ext_type, context, out, add_arg) };
            }
            a
        }
        (
            Callbacks::Old {
                parse, parse_arg, ..
            },
            Some(b),
        ) => {
            let Some(parse) = parse else {
                return Answer::Continue;
            };
            let mut al = 0;
            // SAFETY: the application's callback with the received octets; no lock is held.
            let r = unsafe { parse(s, ext_type, b.as_ptr(), b.len(), &raw mut al, parse_arg) };
            parsed(r, al)
        }
        (
            Callbacks::New {
                parse, parse_arg, ..
            },
            Some(b),
        ) => {
            let Some(parse) = parse else {
                return Answer::Continue;
            };
            let mut al = 0;
            let xc = x509_of(cert);
            // SAFETY: as above, with the certificate (or NULL).
            let r = unsafe {
                parse(
                    s,
                    ext_type,
                    context,
                    b.as_ptr(),
                    b.len(),
                    xc,
                    chainidx,
                    &raw mut al,
                    parse_arg,
                )
            };
            free_x(xc);
            parsed(r, al)
        }
    }
}

/// An add callback's result: the contents copied, skipped, or failed.
///
/// # Safety
/// `out` is NULL or `outlen` octets when `r` is positive.
unsafe fn added(r: c_int, out: *const c_uchar, outlen: usize, al: c_int) -> Answer {
    if r < 0 {
        return Answer::Fail {
            alert: alert_of(al),
            reason: 0,
        };
    }
    if r == 0 {
        return Answer::CustomExt(None);
    }
    let body = if out.is_null() || outlen == 0 {
        Vec::new()
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { core::slice::from_raw_parts(out, outlen) }.to_vec()
    };
    Answer::CustomExt(Some(body))
}

/// A parse callback's result.
fn parsed(r: c_int, al: c_int) -> Answer {
    if r <= 0 {
        Answer::Fail {
            alert: alert_of(al),
            reason: 0,
        }
    } else {
        Answer::Continue
    }
}
