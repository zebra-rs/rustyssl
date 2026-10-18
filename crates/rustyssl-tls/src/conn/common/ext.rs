//! The extension framework (`extensions.c`, `extensions_cust.c`): which extensions are relevant
//! to a message, constructing a message's extension block (the application's custom extensions
//! first, then the built-in ones in `ext_defs[]` order), collecting a received block, parsing it
//! in `ext_defs[]` order (not received order), and the per-extension initialisers and
//! finalisers. The client's and server's own handlers (`tls_construct_ctos_*`,
//! `tls_parse_stoc_*` in `conn::client`; `tls_construct_stoc_*`, `tls_parse_ctos_*` in
//! `conn::server`) are dispatched from here; the handlers both sides share are here.
//!
//! The state machine yields at every callback (ADR 0002), so a parse or a construction may stop
//! at a request and run again after the answer: received extensions keep their `parsed` flags
//! in [`Received`] (the state machine drops them when the next message is read), finalisers
//! already run are skipped, and answers already given are reused ([`super::ask_once`]).

use core::ffi::c_int;

use rustyssl_abi as abi;
use subtle::ConstantTimeEq;

use super::keys;
use super::{
    CERT_TYPE_CTOS_NONE, EarlyDataState, Hrr, KEX_MODE_FLAG_KE, KEX_MODE_FLAG_KE_DHE,
    KEX_MODE_FLAG_NONE, Pha, STATUSTYPE_NOTHING, ask_once,
};
use crate::codec::Writer;
use crate::conn::funcs::{self, Ext};
use crate::conn::{Answer, Connection, Request, client, server};
use crate::consts::context as cx;
use crate::consts::ext as t;
use crate::crypto::{HashAlg, Provider};
use crate::error::{Error, InFunc, Result};
use crate::keysched::{Schedule13, hash_of};
use crate::msgs::ext::{self as mx, EXT_DEFS, Policy};
use crate::suites::masks::{SSL_aECDSA, SSL_kECDHE};

/// `SSL_EXT_FLAG_RECEIVED` (`ssl_local.h`).
pub const FLAG_RECEIVED: u8 = 0x1;
/// `SSL_EXT_FLAG_SENT`.
pub const FLAG_SENT: u8 = 0x2;

/// The number of built-in extensions (`OSSL_NELEM(ext_defs)`).
pub const BUILTIN: usize = EXT_DEFS.len();

/// The extensions sent and received in this handshake (`s->ext.extflags`, and each custom
/// extension's `ext_flags`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Flags {
    /// One entry per [`EXT_DEFS`] entry.
    pub builtin: [u8; BUILTIN],
    /// One entry per configured custom extension.
    pub custom: Vec<u8>,
}

impl Flags {
    /// Cleared flags for `custom` custom extensions.
    #[must_use]
    pub fn new(custom: usize) -> Self {
        Self {
            builtin: [0; BUILTIN],
            custom: vec![0; custom],
        }
    }

    /// Whether the built-in extension `typ` was sent.
    #[must_use]
    pub fn sent(&self, typ: u16) -> bool {
        index_of(typ)
            .and_then(|i| self.builtin.get(i))
            .is_some_and(|f| f & FLAG_SENT != 0)
    }
}

/// One received extension (`RAW_EXTENSION`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawExt {
    /// Its type.
    pub typ: u16,
    /// Its body.
    pub body: Vec<u8>,
    /// Where the body starts in the block's contents (the PSK binders' offset).
    pub offset: usize,
    /// Its position among the recognised extensions received (`received_order`).
    pub received_order: usize,
    /// Whether it was parsed.
    pub parsed: bool,
}

/// A received extension block (`RAW_EXTENSION` array): built-in extensions at their
/// [`EXT_DEFS`] index, custom ones after, in registration order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Received {
    /// The message's context (`SSL_EXT_*`).
    pub context: u32,
    /// The certificate's index in its chain (Certificate entries), else 0.
    pub chainidx: usize,
    /// The extensions by index.
    pub exts: Vec<Option<RawExt>>,
    /// The next finaliser to run.
    next_final: usize,
    /// Whether parsing (and finalising) completed.
    pub done: bool,
}

impl Received {
    /// The built-in extension `typ`, if it was received.
    #[must_use]
    pub fn get(&self, typ: u16) -> Option<&RawExt> {
        index_of(typ)
            .and_then(|i| self.exts.get(i))
            .and_then(Option::as_ref)
    }

    /// Whether the extension at `idx` was received.
    #[must_use]
    pub fn present(&self, idx: usize) -> bool {
        self.exts.get(idx).is_some_and(Option::is_some)
    }
}

/// What a handler is given: the message's context, the certificate's index in its chain (for
/// Certificate entries), and how many octets of the extension block's contents are already
/// written (constructing; for the padding extension).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ctx {
    /// `SSL_EXT_*` of the message.
    pub context: u32,
    /// The certificate's index in its chain.
    pub chainidx: usize,
    /// The block's contents written so far.
    pub written: usize,
    /// A ClientHello's highest version (`max_version`), else 0.
    pub max_version: u16,
}

/// A constructor's result (`EXT_RETURN`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExtReturn {
    /// `EXT_RETURN_NOT_SENT`.
    NotSent,
    /// `EXT_RETURN_SENT`, with the extension's body.
    Sent(Vec<u8>),
    /// Waiting for an answer to a request; the construction runs again after it.
    Wait,
}

/// A parser's, initialiser's, or finaliser's result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Done.
    Done,
    /// Waiting for an answer to a request; the parse runs again after it.
    Wait,
}

/// The [`EXT_DEFS`] index of `typ`.
#[must_use]
pub fn index_of(typ: u16) -> Option<usize> {
    EXT_DEFS.iter().position(|d| d.typ == typ)
}

/// The endpoint a context's custom extensions are looked up for (`ENDPOINT`): a ClientHello is
/// received by the server's extensions, a TLS 1.2 ServerHello by the client's; anything else by
/// either (`None`).
fn endpoint(context: u32) -> Option<bool> {
    if context & cx::CLIENT_HELLO != 0 {
        Some(true)
    } else if context & cx::TLS1_2_SERVER_HELLO != 0 {
        Some(false)
    } else {
        None
    }
}

/// `custom_ext_find`: the configured custom extension of type `typ` for `role` (`None`: any).
fn custom_find(c: &Connection, role: Option<bool>, typ: u16) -> Option<usize> {
    c.cfg
        .custom_exts
        .iter()
        .position(|m| m.typ == typ && (role.is_none() || m.server.is_none() || m.server == role))
}

/// `extension_is_relevant`: whether an extension of context `extctx` applies to a message of
/// context `thisctx` at this version (a HelloRetryRequest is TLS 1.3), given resumption.
#[must_use]
pub fn relevant(c: &Connection, extctx: u32, thisctx: u32) -> bool {
    let is_tls13 = thisctx & cx::TLS1_3_HELLO_RETRY_REQUEST != 0 || c.is_tls13();
    let ssl3 = c_int::from(c.neg.version) == abi::SSL3_VERSION;
    !((c.cfg.dtls && extctx & cx::TLS_IMPLEMENTATION_ONLY != 0)
        || (ssl3 && extctx & cx::SSL3_ALLOWED == 0)
        || (is_tls13 && extctx & cx::TLS1_2_AND_BELOW_ONLY != 0)
        || (!is_tls13 && extctx & cx::TLS1_3_ONLY != 0 && thisctx & cx::CLIENT_HELLO == 0)
        || (c.cfg.server && !is_tls13 && extctx & cx::TLS1_3_ONLY != 0)
        || (c.neg.reused && extctx & cx::IGNORE_ON_RESUMPTION != 0))
}

/// `should_add_extension`: whether to construct an extension of context `extctx` for a message
/// of context `thisctx` (a ClientHello offering at most `max_version`).
#[must_use]
pub fn should_add(c: &Connection, extctx: u32, thisctx: u32, max_version: u16) -> bool {
    if extctx & thisctx == 0 {
        return false;
    }
    relevant(c, extctx, thisctx)
        && !(extctx & cx::TLS1_3_ONLY != 0
            && thisctx & cx::CLIENT_HELLO != 0
            && (c.cfg.dtls || c_int::from(max_version) < abi::TLS1_3_VERSION))
}

/// The contexts in which a response carries only custom extensions the peer sent.
const RESPONSES: u32 = cx::TLS1_2_SERVER_HELLO
    | cx::TLS1_3_SERVER_HELLO
    | cx::TLS1_3_ENCRYPTED_EXTENSIONS
    | cx::TLS1_3_CERTIFICATE
    | cx::TLS1_3_RAW_PUBLIC_KEY
    | cx::TLS1_3_HELLO_RETRY_REQUEST;

/// The contexts whose extensions are requests the peer answers (`SSL_EXT_FLAG_SENT` is kept).
const REQUESTS: u32 =
    cx::CLIENT_HELLO | cx::TLS1_3_CERTIFICATE_REQUEST | cx::TLS1_3_NEW_SESSION_TICKET;

/// Writes one extension.
fn put(w: &mut Writer, typ: u16, body: &[u8]) -> Result<()> {
    w.u16(typ);
    w.vec(2, body).map_err(|_| Error::internal())
}

/// `tls_construct_extensions`: the extension block (with its 2-octet length) for a message of
/// `context`, for the certificate at `chainidx` of its chain (Certificate entries). The custom
/// extensions come first (`custom_ext_add`), then the built-in ones. An empty block is left out
/// of a ClientHello and a TLS 1.2 ServerHello (`WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH`): the
/// result is then empty. `None` while waiting for an answer.
///
/// # Errors
/// No version to offer (a ClientHello: an internal-error alert with the reason), a custom
/// extension's callback failed (`SSL_R_CALLBACK_FAILED` with its alert), or a handler's error.
pub fn construct(
    c: &mut Connection,
    p: &dyn Provider,
    context: u32,
    chainidx: usize,
) -> Result<Option<Vec<u8>>> {
    let mut max_version = 0;
    if context & cx::CLIENT_HELLO != 0 {
        let (_, max, _) =
            super::version::min_max(c).map_err(|r| Error::alert(abi::SSL_AD_INTERNAL_ERROR, r))?;
        max_version = max;
        for f in &mut c.hs.sh.ext.custom {
            *f &= !(FLAG_SENT | FLAG_RECEIVED);
        }
    }
    let mut w = Writer::new();
    if !custom_add(c, context, chainidx, max_version, &mut w).in_func("custom_ext_add")? {
        return Ok(None);
    }
    for (i, d) in EXT_DEFS.iter().enumerate() {
        if !should_add(c, d.context, context, max_version) {
            continue;
        }
        let x = Ctx {
            context,
            chainidx,
            written: w.len(),
            max_version,
        };
        let func = funcs::ext(c.cfg.server, Ext::Construct, d.typ);
        match construct_one(c, p, d.typ, &x).in_func(func.unwrap_or("tls_construct_extensions"))? {
            ExtReturn::NotSent => {}
            ExtReturn::Wait => return Ok(None),
            ExtReturn::Sent(body) => {
                put(&mut w, d.typ, &body)?;
                if context & REQUESTS != 0
                    && let Some(f) = c.hs.sh.ext.builtin.get_mut(i)
                {
                    *f |= FLAG_SENT;
                }
            }
        }
    }
    let contents = w.into_bytes();
    if contents.is_empty() && context & (cx::CLIENT_HELLO | cx::TLS1_2_SERVER_HELLO) != 0 {
        return Ok(Some(Vec::new()));
    }
    let mut out = Writer::new();
    out.vec(2, &contents).map_err(|_| Error::internal())?;
    Ok(Some(out.into_bytes()))
}

/// The certificate a Certificate entry's extensions belong to (the `x` of the callbacks).
fn cert_of(c: &Connection, context: u32) -> Option<Vec<u8>> {
    if context & cx::TLS1_3_CERTIFICATE == 0 {
        return None;
    }
    c.ext_cert.clone()
}

/// `custom_ext_add`. `false` while waiting for an answer.
fn custom_add(
    c: &mut Connection,
    context: u32,
    chainidx: usize,
    max_version: u16,
    w: &mut Writer,
) -> Result<bool> {
    for i in 0..c.cfg.custom_exts.len() {
        let Some(m) = c.cfg.custom_exts.get(i).cloned() else {
            continue;
        };
        if !should_add(c, m.context, context, max_version) {
            continue;
        }
        let flags = c.hs.sh.ext.custom.get(i).copied().unwrap_or(0);
        if context & RESPONSES != 0 && flags & FLAG_RECEIVED == 0 {
            continue;
        }
        if context & cx::CLIENT_HELLO == 0 && !m.has_add {
            continue;
        }
        let mut body = Vec::new();
        if m.has_add {
            let r = Request::CustomExt {
                index: i,
                typ: m.typ,
                context,
                body: None,
                chainidx,
                cert: cert_of(c, context),
            };
            match ask_once(c, r, chainidx) {
                None => return Ok(false),
                Some(Answer::CustomExt(None)) => continue,
                Some(Answer::CustomExt(Some(b))) => body = b,
                Some(Answer::Fail { alert, .. }) => {
                    let al = alert.map_or(abi::SSL_AD_INTERNAL_ERROR, c_int::from);
                    return Err(Error::alert(al, abi::SSL_R_CALLBACK_FAILED));
                }
                Some(_) => return Err(Error::internal()),
            }
        }
        put(w, m.typ, &body)?;
        if context & cx::CLIENT_HELLO != 0
            && let Some(f) = c.hs.sh.ext.custom.get_mut(i)
        {
            if *f & FLAG_SENT != 0 {
                return Err(Error::internal());
            }
            *f |= FLAG_SENT;
        }
    }
    Ok(true)
}

/// `tls_collect_extensions`: records a received block's contents (without its 2-octet length)
/// for a message of `context` (and, for a Certificate entry, `chainidx`), checking it as
/// OpenSSL does ([`mx::collect`]), then, with `init`, runs the initialisers of the built-in
/// extensions relevant to the message. A block already collected for the message (a parse
/// resumed after a request) is kept as it is.
///
/// # Errors
/// As [`mx::collect`].
pub fn collect(
    c: &mut Connection,
    contents: &[u8],
    context: u32,
    chainidx: usize,
    init: bool,
) -> Result<()> {
    if c.hs
        .sh
        .received
        .iter()
        .any(|r| r.context == context && r.chainidx == chainidx)
    {
        return Ok(());
    }
    if context & cx::CLIENT_HELLO != 0 {
        for f in &mut c.hs.sh.ext.custom {
            *f &= !(FLAG_SENT | FLAG_RECEIVED);
        }
    }
    let role = endpoint(context);
    let exts = {
        let custom = |typ: u16| {
            custom_find(c, role, typ)
                .and_then(|i| c.cfg.custom_exts.get(i))
                .map(|m| m.context)
        };
        let flags = &c.hs.sh.ext;
        let sent = |typ: u16| flags.sent(typ);
        let policy = Policy {
            dtls: c.cfg.dtls,
            custom: &custom,
            sent: Some(&sent),
        };
        mx::collect(contents, context, &policy).in_func("tls_collect_extensions")?
    };
    let n = BUILTIN.saturating_add(c.cfg.custom_exts.len());
    let mut raw: Vec<Option<RawExt>> = vec![None; n];
    let mut order = 0usize;
    for e in exts {
        let idx = match index_of(e.typ) {
            Some(i) => Some(i),
            None => custom_find(c, role, e.typ).and_then(|i| BUILTIN.checked_add(i)),
        };
        let Some(slot) = idx.and_then(|i| raw.get_mut(i)) else {
            continue;
        };
        *slot = Some(RawExt {
            typ: e.typ,
            body: e.body,
            offset: e.offset,
            received_order: order,
            parsed: false,
        });
        order = order.saturating_add(1);
    }
    c.hs.sh.received.push(Received {
        context,
        chainidx,
        exts: raw,
        next_final: 0,
        done: false,
    });
    if init {
        for (i, d) in EXT_DEFS.iter().enumerate() {
            if d.context & context != 0 && relevant(c, d.context, context) {
                init_one(c, i, context);
            }
        }
    }
    Ok(())
}

/// The block collected for `context` and `chainidx`, if any.
#[must_use]
pub fn received(c: &Connection, context: u32, chainidx: usize) -> Option<&Received> {
    c.hs.sh
        .received
        .iter()
        .find(|r| r.context == context && r.chainidx == chainidx)
}

/// The position of the block collected for `context` and `chainidx`.
fn received_pos(c: &Connection, context: u32, chainidx: usize) -> Result<usize> {
    c.hs.sh
        .received
        .iter()
        .position(|r| r.context == context && r.chainidx == chainidx)
        .ok_or_else(Error::internal)
}

/// `tls_parse_extension`: parses the collected extension at `idx` (an [`EXT_DEFS`] index, or
/// [`BUILTIN`] plus a custom extension's index) if it was received and not yet parsed, with the
/// role's parser (or the custom extension's callback).
///
/// # Errors
/// The parser's error.
pub fn parse_extension(
    c: &mut Connection,
    p: &dyn Provider,
    idx: usize,
    context: u32,
    chainidx: usize,
) -> Result<Step> {
    let pos = received_pos(c, context, chainidx)?;
    let Some(e) =
        c.hs.sh
            .received
            .get(pos)
            .and_then(|r| r.exts.get(idx))
            .and_then(Option::as_ref)
    else {
        return Ok(Step::Done);
    };
    if e.parsed {
        return Ok(Step::Done);
    }
    let (typ, body) = (e.typ, e.body.clone());
    let x = Ctx {
        context,
        chainidx,
        written: 0,
        max_version: 0,
    };
    let step = match EXT_DEFS.get(idx) {
        Some(d) if !relevant(c, d.context, context) => Step::Done,
        Some(d) => {
            let func = funcs::ext(c.cfg.server, Ext::Parse, d.typ);
            parse_one(c, p, d.typ, &body, &x).in_func(func.unwrap_or("tls_parse_extension"))?
        }
        None => custom_parse(c, context, typ, &body, chainidx).in_func("custom_ext_parse")?,
    };
    if step == Step::Done
        && let Some(e) =
            c.hs.sh
                .received
                .get_mut(pos)
                .and_then(|r| r.exts.get_mut(idx))
                .and_then(Option::as_mut)
    {
        e.parsed = true;
    }
    Ok(step)
}

/// `tls_parse_all_extensions`: parses every collected extension in index order, then, with
/// `fin`, runs the built-in finalisers of the message's context (each told whether its
/// extension was received).
///
/// # Errors
/// A parser's or finaliser's error.
pub fn parse_all(
    c: &mut Connection,
    p: &dyn Provider,
    context: u32,
    chainidx: usize,
    fin: bool,
) -> Result<Step> {
    let pos = received_pos(c, context, chainidx)?;
    if c.hs.sh.received.get(pos).is_some_and(|r| r.done) {
        return Ok(Step::Done);
    }
    let n = BUILTIN.saturating_add(c.cfg.custom_exts.len());
    for i in 0..n {
        if parse_extension(c, p, i, context, chainidx)? == Step::Wait {
            return Ok(Step::Wait);
        }
    }
    if fin {
        loop {
            let Some(r) = c.hs.sh.received.get(pos) else {
                return Err(Error::internal());
            };
            let i = r.next_final;
            let Some(d) = EXT_DEFS.get(i) else { break };
            let sent = r.present(i);
            let func = funcs::ext(c.cfg.server, Ext::Final, d.typ);
            if d.context & context != 0
                && final_one(c, p, d.typ, context, sent)
                    .in_func(func.unwrap_or("tls_parse_all_extensions"))?
                    == Step::Wait
            {
                return Ok(Step::Wait);
            }
            if let Some(r) = c.hs.sh.received.get_mut(pos) {
                r.next_final = i.saturating_add(1);
            }
        }
    }
    if let Some(r) = c.hs.sh.received.get_mut(pos) {
        r.done = true;
    }
    Ok(Step::Done)
}

/// `custom_ext_parse`.
pub(crate) fn custom_parse(
    c: &mut Connection,
    context: u32,
    typ: u16,
    body: &[u8],
    chainidx: usize,
) -> Result<Step> {
    let role = if context & (cx::CLIENT_HELLO | cx::TLS1_2_SERVER_HELLO) != 0 {
        Some(c.cfg.server)
    } else {
        None
    };
    let Some(i) = custom_find(c, role, typ) else {
        return Ok(Step::Done);
    };
    let Some(m) = c.cfg.custom_exts.get(i).cloned() else {
        return Ok(Step::Done);
    };
    if !relevant(c, m.context, context) {
        return Ok(Step::Done);
    }
    let flags = c.hs.sh.ext.custom.get(i).copied().unwrap_or(0);
    if context
        & (cx::TLS1_2_SERVER_HELLO | cx::TLS1_3_SERVER_HELLO | cx::TLS1_3_ENCRYPTED_EXTENSIONS)
        != 0
        && flags & FLAG_SENT == 0
    {
        return Err(Error::alert(
            abi::TLS1_AD_UNSUPPORTED_EXTENSION,
            abi::SSL_R_BAD_EXTENSION,
        ));
    }
    if context & (cx::CLIENT_HELLO | cx::TLS1_3_CERTIFICATE_REQUEST) != 0
        && let Some(f) = c.hs.sh.ext.custom.get_mut(i)
    {
        *f |= FLAG_RECEIVED;
    }
    if !m.has_parse {
        return Ok(Step::Done);
    }
    let r = Request::CustomExt {
        index: i,
        typ,
        context,
        body: Some(body.to_vec()),
        chainidx,
        cert: cert_of(c, context),
    };
    match ask_once(c, r, chainidx) {
        None => Ok(Step::Wait),
        Some(Answer::Continue) => Ok(Step::Done),
        Some(Answer::Fail { alert, .. }) => {
            let al = alert.map_or(abi::SSL_AD_INTERNAL_ERROR, c_int::from);
            Err(Error::alert(al, abi::SSL_R_BAD_EXTENSION))
        }
        Some(_) => Err(Error::internal()),
    }
}

/// The role's constructor for the built-in extension `typ` (`construct_ctos` on a client,
/// `construct_stoc` on a server).
fn construct_one(c: &mut Connection, p: &dyn Provider, typ: u16, x: &Ctx) -> Result<ExtReturn> {
    match typ {
        t::SIGNATURE_ALGORITHMS => return construct_sig_algs(c),
        t::COMPRESS_CERTIFICATE => return Ok(construct_compress_certificate()),
        t::CERTIFICATE_AUTHORITIES => return construct_certificate_authorities(c),
        _ => {}
    }
    if c.cfg.server {
        match typ {
            t::RENEGOTIATE => server::ext_construct_renegotiate(c, p, x),
            t::SERVER_NAME => server::ext_construct_server_name(c, p, x),
            t::MAX_FRAGMENT_LENGTH => server::ext_construct_maxfragmentlen(c, p, x),
            t::EC_POINT_FORMATS => server::ext_construct_ec_pt_formats(c, p, x),
            t::SUPPORTED_GROUPS => server::ext_construct_supported_groups(c, p, x),
            t::SESSION_TICKET => server::ext_construct_session_ticket(c, p, x),
            t::STATUS_REQUEST => server::ext_construct_status_request(c, p, x),
            t::NEXT_PROTO_NEG => server::ext_construct_next_proto_neg(c, p, x),
            t::ALPN => server::ext_construct_alpn(c, p, x),
            t::USE_SRTP => server::ext_construct_use_srtp(c, p, x),
            t::ENCRYPT_THEN_MAC => server::ext_construct_etm(c, p, x),
            t::EXTENDED_MASTER_SECRET => server::ext_construct_ems(c, p, x),
            t::CLIENT_CERT_TYPE => server::ext_construct_client_cert_type(c, p, x),
            t::SERVER_CERT_TYPE => server::ext_construct_server_cert_type(c, p, x),
            t::SUPPORTED_VERSIONS => server::ext_construct_supported_versions(c, p, x),
            t::KEY_SHARE => server::ext_construct_key_share(c, p, x),
            t::COOKIE => server::ext_construct_cookie(c, p, x),
            t::CRYPTOPRO_BUG => server::ext_construct_cryptopro_bug(c, p, x),
            t::EARLY_DATA => server::ext_construct_early_data(c, p, x),
            t::PRE_SHARED_KEY => server::ext_construct_psk(c, p, x),
            _ => Ok(ExtReturn::NotSent),
        }
    } else {
        match typ {
            t::RENEGOTIATE => client::ext_construct_renegotiate(c, p, x),
            t::SERVER_NAME => client::ext_construct_server_name(c, p, x),
            t::MAX_FRAGMENT_LENGTH => client::ext_construct_maxfragmentlen(c, p, x),
            t::SRP => client::ext_construct_srp(c, p, x),
            t::EC_POINT_FORMATS => client::ext_construct_ec_pt_formats(c, p, x),
            t::SUPPORTED_GROUPS => client::ext_construct_supported_groups(c, p, x),
            t::SESSION_TICKET => client::ext_construct_session_ticket(c, p, x),
            t::STATUS_REQUEST => client::ext_construct_status_request(c, p, x),
            t::NEXT_PROTO_NEG => client::ext_construct_npn(c, p, x),
            t::ALPN => client::ext_construct_alpn(c, p, x),
            t::USE_SRTP => client::ext_construct_use_srtp(c, p, x),
            t::ENCRYPT_THEN_MAC => client::ext_construct_etm(c, p, x),
            t::SIGNED_CERTIFICATE_TIMESTAMP => client::ext_construct_sct(c, p, x),
            t::EXTENDED_MASTER_SECRET => client::ext_construct_ems(c, p, x),
            t::POST_HANDSHAKE_AUTH => client::ext_construct_post_handshake_auth(c, p, x),
            t::CLIENT_CERT_TYPE => client::ext_construct_client_cert_type(c, p, x),
            t::SERVER_CERT_TYPE => client::ext_construct_server_cert_type(c, p, x),
            t::SUPPORTED_VERSIONS => client::ext_construct_supported_versions(c, p, x),
            t::PSK_KEY_EXCHANGE_MODES => client::ext_construct_psk_kex_modes(c, p, x),
            t::KEY_SHARE => client::ext_construct_key_share(c, p, x),
            t::COOKIE => client::ext_construct_cookie(c, p, x),
            t::EARLY_DATA => client::ext_construct_early_data(c, p, x),
            t::PADDING => client::ext_construct_padding(c, p, x),
            t::PRE_SHARED_KEY => client::ext_construct_psk(c, p, x),
            _ => Ok(ExtReturn::NotSent),
        }
    }
}

/// The role's parser for the built-in extension `typ` (`parse_ctos` on a server, `parse_stoc`
/// on a client); an extension without one is accepted unread.
fn parse_one(c: &mut Connection, p: &dyn Provider, typ: u16, body: &[u8], x: &Ctx) -> Result<Step> {
    match typ {
        t::SIGNATURE_ALGORITHMS => return parse_sig_algs(c, body, false),
        t::SIGNATURE_ALGORITHMS_CERT => return parse_sig_algs(c, body, true),
        t::COMPRESS_CERTIFICATE => return Ok(Step::Done),
        t::CERTIFICATE_AUTHORITIES => return parse_certificate_authorities(c, body),
        _ => {}
    }
    if c.cfg.server {
        match typ {
            t::RENEGOTIATE => server::ext_parse_renegotiate(c, p, body, x),
            t::SERVER_NAME => server::ext_parse_server_name(c, p, body, x),
            t::MAX_FRAGMENT_LENGTH => server::ext_parse_maxfragmentlen(c, p, body, x),
            t::SRP => server::ext_parse_srp(c, p, body, x),
            t::EC_POINT_FORMATS => server::ext_parse_ec_pt_formats(c, p, body, x),
            t::SUPPORTED_GROUPS => server::ext_parse_supported_groups(c, p, body, x),
            t::SESSION_TICKET => server::ext_parse_session_ticket(c, p, body, x),
            t::STATUS_REQUEST => server::ext_parse_status_request(c, p, body, x),
            t::NEXT_PROTO_NEG => server::ext_parse_npn(c, p, body, x),
            t::ALPN => server::ext_parse_alpn(c, p, body, x),
            t::USE_SRTP => server::ext_parse_use_srtp(c, p, body, x),
            t::ENCRYPT_THEN_MAC => server::ext_parse_etm(c, p, body, x),
            t::EXTENDED_MASTER_SECRET => server::ext_parse_ems(c, p, body, x),
            t::POST_HANDSHAKE_AUTH => server::ext_parse_post_handshake_auth(c, p, body, x),
            t::CLIENT_CERT_TYPE => server::ext_parse_client_cert_type(c, p, body, x),
            t::SERVER_CERT_TYPE => server::ext_parse_server_cert_type(c, p, body, x),
            t::PSK_KEY_EXCHANGE_MODES => server::ext_parse_psk_kex_modes(c, p, body, x),
            t::KEY_SHARE => server::ext_parse_key_share(c, p, body, x),
            t::COOKIE => server::ext_parse_cookie(c, p, body, x),
            t::EARLY_DATA => server::ext_parse_early_data(c, p, body, x),
            t::PRE_SHARED_KEY => server::ext_parse_psk(c, p, body, x),
            // No parser for the role: a custom extension may take it (`tls_parse_extension`;
            // the server's signed_certificate_timestamp, say).
            _ => custom_parse(c, x.context, typ, body, x.chainidx).in_func("custom_ext_parse"),
        }
    } else {
        match typ {
            t::RENEGOTIATE => client::ext_parse_renegotiate(c, p, body, x),
            t::SERVER_NAME => client::ext_parse_server_name(c, p, body, x),
            t::MAX_FRAGMENT_LENGTH => client::ext_parse_maxfragmentlen(c, p, body, x),
            t::EC_POINT_FORMATS => client::ext_parse_ec_pt_formats(c, p, body, x),
            t::SESSION_TICKET => client::ext_parse_session_ticket(c, p, body, x),
            t::STATUS_REQUEST => client::ext_parse_status_request(c, p, body, x),
            t::NEXT_PROTO_NEG => client::ext_parse_npn(c, p, body, x),
            t::ALPN => client::ext_parse_alpn(c, p, body, x),
            t::USE_SRTP => client::ext_parse_use_srtp(c, p, body, x),
            t::ENCRYPT_THEN_MAC => client::ext_parse_etm(c, p, body, x),
            t::SIGNED_CERTIFICATE_TIMESTAMP => client::ext_parse_sct(c, p, body, x),
            t::EXTENDED_MASTER_SECRET => client::ext_parse_ems(c, p, body, x),
            t::CLIENT_CERT_TYPE => client::ext_parse_client_cert_type(c, p, body, x),
            t::SERVER_CERT_TYPE => client::ext_parse_server_cert_type(c, p, body, x),
            t::SUPPORTED_VERSIONS => client::ext_parse_supported_versions(c, p, body, x),
            t::KEY_SHARE => client::ext_parse_key_share(c, p, body, x),
            t::COOKIE => client::ext_parse_cookie(c, p, body, x),
            t::EARLY_DATA => client::ext_parse_early_data(c, p, body, x),
            t::PRE_SHARED_KEY => client::ext_parse_psk(c, p, body, x),
            _ => custom_parse(c, x.context, typ, body, x.chainidx).in_func("custom_ext_parse"),
        }
    }
}

/// The initialiser of the extension at `idx` (`init_*`): clears what parsing the extension
/// sets, so that a missing extension leaves nothing behind.
fn init_one(c: &mut Connection, idx: usize, _context: u32) {
    let Some(d) = EXT_DEFS.get(idx) else { return };
    let server = c.cfg.server;
    let sh = &mut c.hs.sh;
    match d.typ {
        t::SERVER_NAME => {
            if server {
                sh.servername_done = false;
                c.neg.servername = None;
            }
        }
        t::SRP => sh.srp_login = None,
        t::EC_POINT_FORMATS => sh.peer_ecpointformats = None,
        t::SESSION_TICKET => {
            if !server {
                sh.ticket_expected = false;
            }
        }
        t::STATUS_REQUEST => {
            if server {
                sh.status_type = STATUSTYPE_NOTHING;
            } else {
                c.neg.ocsp_response = None;
            }
        }
        t::NEXT_PROTO_NEG => sh.npn_seen = false,
        t::ALPN => {
            c.neg.alpn = None;
            if server {
                sh.alpn_proposed = None;
            }
        }
        t::USE_SRTP => {
            if server {
                sh.srtp_profile = None;
            }
        }
        t::ENCRYPT_THEN_MAC => sh.use_etm = false,
        t::EXTENDED_MASTER_SECRET => {
            if sh.flags & abi::TLS1_FLAGS_RECEIVED_EXTMS != 0 {
                sh.flags &= !abi::TLS1_FLAGS_RECEIVED_EXTMS;
                sh.flags |= abi::TLS1_FLAGS_REQUIRED_EXTMS;
            }
        }
        t::SIGNATURE_ALGORITHMS_CERT => sh.peer_cert_sigalgs = None,
        t::POST_HANDSHAKE_AUTH => sh.pha = Pha::None,
        t::CLIENT_CERT_TYPE => {
            if server {
                sh.client_cert_type_ctos = CERT_TYPE_CTOS_NONE;
                c.neg.client_cert_type = x509();
            }
        }
        t::SERVER_CERT_TYPE => {
            if server {
                sh.server_cert_type_ctos = CERT_TYPE_CTOS_NONE;
                c.neg.server_cert_type = x509();
            }
        }
        t::SIGNATURE_ALGORITHMS => {
            sh.peer_sigalgs = None;
            c.neg.peer_sigalgs.clear();
        }
        t::PSK_KEY_EXCHANGE_MODES => sh.psk_kex_mode = KEX_MODE_FLAG_NONE,
        t::COMPRESS_CERTIFICATE => sh.compress_certificate_from_peer.clear(),
        t::CERTIFICATE_AUTHORITIES => c.neg.peer_ca_names = None,
        _ => {}
    }
}

/// `TLSEXT_cert_type_x509`.
fn x509() -> u8 {
    u8::try_from(abi::TLSEXT_cert_type_x509).unwrap_or(0)
}

/// The finaliser of the built-in extension `typ` (`final_*`), told whether it was received.
fn final_one(
    c: &mut Connection,
    p: &dyn Provider,
    typ: u16,
    context: u32,
    sent: bool,
) -> Result<Step> {
    match typ {
        t::RENEGOTIATE => final_renegotiate(c, sent).map(|()| Step::Done),
        t::SERVER_NAME => final_server_name(c, p, sent),
        t::MAX_FRAGMENT_LENGTH => {
            final_maxfragmentlen(c);
            Ok(Step::Done)
        }
        t::EC_POINT_FORMATS => final_ec_pt_formats(c).map(|()| Step::Done),
        t::ALPN => final_alpn(c, p, sent),
        t::EXTENDED_MASTER_SECRET => final_ems(c).map(|()| Step::Done),
        t::SIGNATURE_ALGORITHMS => final_sig_algs(c, sent).map(|()| Step::Done),
        t::SUPPORTED_VERSIONS => final_supported_versions(context, sent).map(|()| Step::Done),
        t::KEY_SHARE => final_key_share(c, p, context, sent).map(|()| Step::Done),
        t::EARLY_DATA => final_early_data(c, p, context, sent),
        t::PRE_SHARED_KEY => final_psk(c, sent).map(|()| Step::Done),
        _ => Ok(Step::Done),
    }
}

/// `final_renegotiate`: secure renegotiation is required unless the options allow legacy peers
/// (a client: `SSL_OP_LEGACY_SERVER_CONNECT` or unsafe legacy renegotiation; a server only
/// when renegotiating).
fn final_renegotiate(c: &Connection, sent: bool) -> Result<()> {
    let o = c.cfg.options;
    let unsafe_ok = o & abi::SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION != 0;
    let fail = Error::alert(
        abi::SSL_AD_HANDSHAKE_FAILURE,
        abi::SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED,
    );
    if !c.cfg.server {
        if o & abi::SSL_OP_LEGACY_SERVER_CONNECT == 0 && !unsafe_ok && !sent {
            return Err(fail);
        }
        return Ok(());
    }
    if c.renegotiate && !unsafe_ok && !sent {
        return Err(fail);
    }
    Ok(())
}

/// `final_server_name`: the servername callback ([`Request::Servername`], answered with
/// [`Answer::Tlsext`]); a server records the name in a new session when the callback
/// accepted it, and stops a TLS 1.2 ticket the callback turned off (a new session then gets a
/// new session ID). A fatal result fails with
/// `SSL_R_CALLBACK_FAILED` and the callback's alert; a warning is sent below TLS 1.3.
fn final_server_name(c: &mut Connection, p: &dyn Provider, sent: bool) -> Result<Step> {
    let no_ticket = |c: &Connection| c.cfg.options & abi::SSL_OP_NO_TICKET != 0;
    let was_ticket = *c.hs.sh.was_ticket.get_or_insert(!no_ticket(c));
    let (ret, altmp) = if c.cfg.callbacks.servername {
        match c.ask(Request::Servername) {
            None => return Ok(Step::Wait),
            Some(Answer::Tlsext { ret, alert }) => (ret, alert),
            Some(Answer::Continue) => (abi::SSL_TLSEXT_ERR_OK, abi::SSL_AD_UNRECOGNIZED_NAME),
            Some(Answer::Fail { alert, .. }) => (
                abi::SSL_TLSEXT_ERR_ALERT_FATAL,
                alert.map_or(abi::SSL_AD_UNRECOGNIZED_NAME, c_int::from),
            ),
            Some(_) => return Err(Error::internal()),
        }
    } else {
        (abi::SSL_TLSEXT_ERR_NOACK, abi::SSL_AD_UNRECOGNIZED_NAME)
    };
    c.hs.sh.was_ticket = None;
    if c.cfg.server && sent && ret == abi::SSL_TLSEXT_ERR_OK && !c.neg.reused {
        c.neg.session.hostname.clone_from(&c.neg.servername);
    }
    if ret == abi::SSL_TLSEXT_ERR_OK && c.hs.sh.ticket_expected && was_ticket && no_ticket(c) {
        c.hs.sh.ticket_expected = false;
        if !c.neg.reused {
            let s = &mut c.neg.session;
            s.ticket = None;
            s.ticket_lifetime_hint = 0;
            s.ticket_age_add = 0;
            // `ssl_generate_session_id`: without a ticket coming, the session needs an ID.
            s.session_id = crate::conn::server::random_id(p)?;
        }
    }
    match ret {
        abi::SSL_TLSEXT_ERR_ALERT_FATAL => Err(Error::alert(altmp, abi::SSL_R_CALLBACK_FAILED)),
        abi::SSL_TLSEXT_ERR_ALERT_WARNING => {
            if !c.is_tls13() {
                let level = u8::try_from(abi::SSL3_AL_WARNING).map_err(|_| Error::internal())?;
                let desc = u8::try_from(altmp).map_err(|_| Error::internal())?;
                c.send_alert(p, level, desc)?;
            }
            c.hs.sh.servername_done = false;
            Ok(Step::Done)
        }
        abi::SSL_TLSEXT_ERR_NOACK => {
            c.hs.sh.servername_done = false;
            Ok(Step::Done)
        }
        _ => Ok(Step::Done),
    }
}

/// `final_maxfragmentlen`: an unspecified mode becomes disabled; a negotiated one limits both
/// directions' records (`GET_MAX_FRAGMENT_LENGTH`, `ssl_get_max_send_fragment`).
fn final_maxfragmentlen(c: &mut Connection) {
    let unspecified = u8::try_from(abi::TLSEXT_max_fragment_length_UNSPECIFIED).unwrap_or(u8::MAX);
    let s = &mut c.neg.session;
    if s.max_fragment_len_mode == unspecified {
        s.max_fragment_len_mode =
            u8::try_from(abi::TLSEXT_max_fragment_length_DISABLED).unwrap_or(0);
    }
    if let Some(len) = max_fragment_length(s.max_fragment_len_mode) {
        c.rr.max_frag_len = len;
        c.rw.max_frag_len = c.cfg.max_send_fragment.min(len);
    }
}

/// `GET_MAX_FRAGMENT_LENGTH` for a valid mode (`USE_MAX_FRAGMENT_LENGTH_EXT`).
#[must_use]
pub fn max_fragment_length(mode: u8) -> Option<usize> {
    let first = u8::try_from(abi::TLSEXT_max_fragment_length_512).ok()?;
    let last = u8::try_from(abi::TLSEXT_max_fragment_length_4096).ok()?;
    if !(first..=last).contains(&mode) {
        return None;
    }
    512usize.checked_shl(u32::from(mode.checked_sub(1)?))
}

/// `final_ec_pt_formats` (client): with an ECDHE or ECDSA suite, a server's ec_point_formats
/// must include uncompressed.
fn final_ec_pt_formats(c: &Connection) -> Result<()> {
    if c.cfg.server {
        return Ok(());
    }
    let cp = c.hs.new_cipher.ok_or_else(Error::internal)?;
    let own = super::groups::formats(c);
    let uncompressed = u8::try_from(abi::TLSEXT_ECPOINTFORMAT_uncompressed).unwrap_or(0);
    if let Some(peer) = &c.hs.sh.peer_ecpointformats
        && !own.is_empty()
        && !peer.is_empty()
        && (cp.mkey & SSL_kECDHE != 0 || cp.auth & SSL_aECDSA != 0)
        && !peer.contains(&uncompressed)
    {
        return Err(Error::alert(
            abi::SSL_AD_ILLEGAL_PARAMETER,
            abi::SSL_R_TLS_INVALID_ECPOINTFORMAT_LIST,
        ));
    }
    Ok(())
}

/// `final_alpn`: a client resuming a session that had ALPN, answered without it, can't send
/// early data; a TLS 1.3 server selects the protocol (`tls_handle_alpn`).
fn final_alpn(c: &mut Connection, p: &dyn Provider, sent: bool) -> Result<Step> {
    if !c.cfg.server && !sent && c.neg.reused && c.neg.session.alpn.is_some() {
        c.hs.sh.early_data_ok = false;
    }
    if !c.cfg.server || !c.is_tls13() {
        return Ok(Step::Done);
    }
    server::handle_alpn(c, p)
}

/// `final_ems`: once Extended Master Secret was used it is required (renegotiation), and a
/// resumed session must agree with the ServerHello.
fn final_ems(c: &Connection) -> Result<()> {
    let f = c.hs.sh.flags;
    let received = f & abi::TLS1_FLAGS_RECEIVED_EXTMS != 0;
    let fail = Error::alert(abi::SSL_AD_HANDSHAKE_FAILURE, abi::SSL_R_INCONSISTENT_EXTMS);
    if !received && f & abi::TLS1_FLAGS_REQUIRED_EXTMS != 0 {
        return Err(fail);
    }
    if !c.cfg.server && c.neg.reused && received != c.neg.session.ems {
        return Err(fail);
    }
    Ok(())
}

/// `final_sig_algs`: a full TLS 1.3 handshake needs signature_algorithms.
fn final_sig_algs(c: &Connection, sent: bool) -> Result<()> {
    if !sent && c.is_tls13() && !c.neg.reused {
        return Err(Error::alert(
            abi::TLS13_AD_MISSING_EXTENSION,
            abi::SSL_R_MISSING_SIGALGS_EXTENSION,
        ));
    }
    Ok(())
}

/// `final_supported_versions`: a HelloRetryRequest must carry supported_versions.
fn final_supported_versions(context: u32, sent: bool) -> Result<()> {
    if !sent && context == cx::TLS1_3_HELLO_RETRY_REQUEST {
        return Err(Error::alert(
            abi::TLS13_AD_MISSING_EXTENSION,
            abi::SSL_R_MISSING_SUPPORTED_VERSIONS_EXTENSION,
        ));
    }
    Ok(())
}

/// `final_key_share`: TLS 1.3's key exchange outcome. A client without a server share must be
/// resuming with psk_ke (and then derives the handshake secret without a shared secret). A
/// server without a usable client share asks for one in a HelloRetryRequest when it can
/// (`group_id_candidate`), or must be resuming with psk_ke; a stateless server without a valid
/// cookie always sends a HelloRetryRequest.
fn final_key_share(c: &mut Connection, p: &dyn Provider, context: u32, sent: bool) -> Result<()> {
    if !c.is_tls13() || context & cx::TLS1_3_HELLO_RETRY_REQUEST != 0 {
        return Ok(());
    }
    let mode = c.hs.sh.psk_kex_mode;
    let hit = c.neg.reused;
    if !c.cfg.server {
        if !sent {
            if mode & KEX_MODE_FLAG_KE == 0 {
                return Err(Error::alert(
                    abi::SSL_AD_ILLEGAL_PARAMETER,
                    abi::SSL_R_NO_SUITABLE_KEY_SHARE,
                ));
            }
            if !hit {
                return Err(Error::alert(
                    abi::SSL_AD_MISSING_EXTENSION,
                    abi::SSL_R_NO_SUITABLE_KEY_SHARE,
                ));
            }
            keys::generate_handshake_secret(c, p, None)?;
        }
        return Ok(());
    }
    let sh = &mut c.hs.sh;
    let stateless = sh.flags & abi::TLS1_FLAGS_STATELESS != 0 && !sh.cookie_ok;
    if sh.peer_tmp.is_some() {
        if stateless {
            if sh.hrr != Hrr::None {
                return Err(Error::internal());
            }
            sh.hrr = Hrr::Pending;
            return Ok(());
        }
    } else {
        if sh.hrr == Hrr::None
            && sent
            && (!hit || mode & KEX_MODE_FLAG_KE_DHE != 0)
            && sh.group_id_candidate != 0
        {
            sh.group_id = sh.group_id_candidate;
            sh.hrr = Hrr::Pending;
            return Ok(());
        }
        if !hit || mode & KEX_MODE_FLAG_KE == 0 {
            let al = if sent {
                abi::SSL_AD_HANDSHAKE_FAILURE
            } else {
                abi::SSL_AD_MISSING_EXTENSION
            };
            return Err(Error::alert(al, abi::SSL_R_NO_SUITABLE_KEY_SHARE));
        }
        if stateless {
            if sh.hrr != Hrr::None {
                return Err(Error::internal());
            }
            sh.hrr = Hrr::Pending;
            return Ok(());
        }
    }
    if sh.hrr == Hrr::Pending {
        sh.hrr = Hrr::Complete;
    }
    Ok(())
}

/// `final_early_data`: a client's EncryptedExtensions may accept early data only when it could
/// be sent; a server accepts it (installing the early read keys) when it is allowed, resuming,
/// accepting, without a HelloRetryRequest, and the application agrees
/// ([`Request::AllowEarlyData`]).
fn final_early_data(
    c: &mut Connection,
    p: &dyn Provider,
    context: u32,
    sent: bool,
) -> Result<Step> {
    if !sent {
        return Ok(Step::Done);
    }
    if !c.cfg.server {
        if context == cx::TLS1_3_ENCRYPTED_EXTENSIONS && !c.hs.sh.early_data_ok {
            return Err(Error::alert(
                abi::SSL_AD_ILLEGAL_PARAMETER,
                abi::SSL_R_BAD_EARLY_DATA,
            ));
        }
        return Ok(Step::Done);
    }
    let sh = &c.hs.sh;
    let mut accept = c.cfg.max_early_data != 0
        && c.neg.reused
        && sh.early_data_state == EarlyDataState::Accepting
        && sh.early_data_ok
        && sh.hrr == Hrr::None;
    if accept && c.cfg.callbacks.allow_early_data {
        match ask_once(c, Request::AllowEarlyData, 0) {
            None => return Ok(Step::Wait),
            Some(Answer::Allowed(ok)) => accept = ok,
            Some(Answer::Continue) => {}
            Some(_) => accept = false,
        }
    }
    if accept {
        c.neg.early_data_status = abi::SSL_EARLY_DATA_ACCEPTED;
        // Shared fix (tls-server): the early keys are the resumed session's suite's
        // (`tls13_change_cipher_state` uses `s->session->cipher` for early data).
        let early_cipher = crate::suites::by_id(c.neg.session.cipher_id);
        keys::change_cipher_state13(
            c,
            p,
            abi::SSL3_CC_EARLY | abi::SSL3_CHANGE_CIPHER_SERVER_READ,
            early_cipher,
        )?;
    } else {
        c.neg.early_data_status = abi::SSL_EARLY_DATA_REJECTED;
    }
    Ok(Step::Done)
}

/// `final_psk` (server): a pre_shared_key needs psk_key_exchange_modes in the ClientHello.
fn final_psk(c: &Connection, sent: bool) -> Result<()> {
    if !c.cfg.server || !sent {
        return Ok(());
    }
    let modes = index_of(t::PSK_KEY_EXCHANGE_MODES).unwrap_or(usize::MAX);
    let has = received(c, cx::CLIENT_HELLO, 0).is_some_and(|r| r.present(modes));
    if !has {
        return Err(Error::alert(
            abi::TLS13_AD_MISSING_EXTENSION,
            abi::SSL_R_MISSING_PSK_KEX_MODES_EXTENSION,
        ));
    }
    Ok(())
}

/// `tls_construct_ctos_sig_algs`, which a server also uses for its TLS 1.3 CertificateRequest:
/// the schemes this end accepts (`tls12_get_psigalgs`, filtered by `tls12_copy_sigalgs`),
/// unless the client offers less than TLS 1.2 (or a fixed-version method uses less).
///
/// # Errors
/// No usable scheme (OpenSSL raises `SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM` and fails with an
/// internal error).
pub fn construct_sig_algs(c: &Connection) -> Result<ExtReturn> {
    let tls12 = super::version::of(abi::TLS1_2_VERSION);
    let level = super::version::tls_level;
    if level(c.hs.sh.client_version) < tls12
        || (c.cfg.method_version != super::version::ANY && level(c.neg.version) < tls12)
    {
        return Ok(ExtReturn::NotSent);
    }
    let list = super::sigalgs::psigalgs(c, true);
    let schemes = super::sigalgs::copy_sigalgs(c, &list).map_err(|_| Error::internal())?;
    Ok(ExtReturn::Sent(mx::signature_algorithms::encode(&schemes)?))
}

/// `tls_parse_ctos_sig_algs` and `tls_parse_ctos_sig_algs_cert` (both sides): the peer's
/// schemes, kept unless a server is resuming.
fn parse_sig_algs(c: &mut Connection, body: &[u8], cert: bool) -> Result<Step> {
    let list = mx::signature_algorithms::parse(body)?;
    if (!c.cfg.server || !c.neg.reused) && !super::sigalgs::save(c, &list, cert) {
        return Err(Error::decode(abi::SSL_R_BAD_EXTENSION));
    }
    Ok(Step::Done)
}

/// `tls_construct_compress_certificate`: never sent, as the default build has no compression
/// algorithm (`OPENSSL_NO_COMP_ALG`).
fn construct_compress_certificate() -> ExtReturn {
    ExtReturn::NotSent
}

/// `tls_construct_certificate_authorities`: the CA names (`get_ca_names`: the configuration's
/// `ca_names`), when there are any; `SSL_OP_DISABLE_TLSEXT_CA_NAMES` sends an empty list.
fn construct_certificate_authorities(c: &Connection) -> Result<ExtReturn> {
    if c.cfg.ca_names.is_empty() {
        return Ok(ExtReturn::NotSent);
    }
    Ok(ExtReturn::Sent(super::cert::construct_ca_names(
        c,
        &c.cfg.ca_names,
    )?))
}

/// `tls_parse_certificate_authorities`: the peer's CA names (`parse_ca_names`), filling the
/// body (`SSL_R_BAD_EXTENSION`).
fn parse_certificate_authorities(c: &mut Connection, body: &[u8]) -> Result<Step> {
    let mut rd = crate::codec::Reader::new(body);
    super::cert::parse_ca_names(c, &mut rd)?;
    if !rd.is_empty() {
        return Err(Error::decode(abi::SSL_R_BAD_EXTENSION));
    }
    Ok(Step::Done)
}

/// `tls_psk_do_binder`: the PSK binder over `msg_prefix` (the ClientHello up to its binders),
/// after a HelloRetryRequest prefixed with the transcript so far (the synthetic message_hash
/// and the HelloRetryRequest; a server leaves the second ClientHello it already added out).
/// With `binder_in` it is checked in constant time instead (`SSL_R_BINDER_DOES_NOT_VERIFY`,
/// decrypt-error). Returns the early-secret schedule made from `psk` with the binder.
///
/// # Errors
/// As above, or the provider failed.
pub fn psk_do_binder(
    c: &Connection,
    p: &dyn Provider,
    hash: HashAlg,
    msg_prefix: &[u8],
    psk: &[u8],
    external: bool,
    binder_in: Option<&[u8]>,
) -> Result<(Schedule13, Vec<u8>)> {
    let schedule = Schedule13::new(p, hash, Some(psk))?;
    let mut data = Vec::new();
    if c.hs.sh.hrr == Hrr::Pending {
        let buf =
            c.hs.transcript
                .buffered()
                .filter(|b| !b.is_empty())
                .ok_or(Error::alert(
                    abi::SSL_AD_INTERNAL_ERROR,
                    abi::SSL_R_BAD_HANDSHAKE_LENGTH,
                ))?;
        let keep = if c.cfg.server {
            two_messages(buf).ok_or_else(Error::internal)?
        } else {
            buf.len()
        };
        data.extend_from_slice(buf.get(..keep).ok_or_else(Error::internal)?);
    }
    data.extend_from_slice(msg_prefix);
    let th = hash_of(p, hash, &data)?;
    let binder = schedule.binder(p, !external, &th)?;
    if let Some(b) = binder_in
        && !bool::from(binder.as_slice().ct_eq(b))
    {
        return Err(Error::alert(
            abi::SSL_AD_DECRYPT_ERROR,
            abi::SSL_R_BINDER_DOES_NOT_VERIFY,
        ));
    }
    Ok((schedule, binder))
}

/// The length of the first two handshake messages in `buf`.
fn two_messages(buf: &[u8]) -> Option<usize> {
    let mut rd = crate::codec::Reader::new(buf);
    for _ in 0..2 {
        rd.u8().ok()?;
        rd.vec24().ok()?;
    }
    buf.len().checked_sub(rd.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::config::CustomExt;
    use crate::conn::{Config, Connection};

    fn conn(server: bool) -> Connection {
        let mut c = Connection::new(Config {
            server,
            ..Config::default()
        });
        c.hs.sh.ext = Flags::new(0);
        c
    }

    #[test]
    fn relevance_follows_version_and_role() {
        let mut c = conn(false);
        let tls13 = super::super::version::of(abi::TLS1_3_VERSION);
        c.neg.version = tls13;
        assert!(!relevant(
            &c,
            cx::CLIENT_HELLO | cx::TLS1_2_AND_BELOW_ONLY,
            cx::CLIENT_HELLO
        ));
        assert!(relevant(
            &c,
            cx::CLIENT_HELLO | cx::TLS1_3_ONLY,
            cx::CLIENT_HELLO
        ));
        c.neg.version = super::super::version::of(abi::TLS1_2_VERSION);
        // A TLS 1.3-only extension stays relevant to a TLS 1.2 client's ClientHello...
        assert!(relevant(
            &c,
            cx::CLIENT_HELLO | cx::TLS1_3_ONLY,
            cx::CLIENT_HELLO
        ));
        // ...but a ClientHello offering at most TLS 1.2 doesn't carry it.
        assert!(!should_add(
            &c,
            cx::CLIENT_HELLO | cx::TLS1_3_ONLY,
            cx::CLIENT_HELLO,
            c.neg.version
        ));
        assert!(should_add(
            &c,
            cx::CLIENT_HELLO | cx::TLS1_3_ONLY,
            cx::CLIENT_HELLO,
            tls13
        ));
        // A HelloRetryRequest is TLS 1.3 whatever the version so far.
        assert!(!relevant(
            &c,
            cx::TLS1_2_AND_BELOW_ONLY | cx::TLS1_3_HELLO_RETRY_REQUEST,
            cx::TLS1_3_HELLO_RETRY_REQUEST
        ));
        let mut s = conn(true);
        s.neg.version = super::super::version::of(abi::TLS1_2_VERSION);
        assert!(!relevant(
            &s,
            cx::CLIENT_HELLO | cx::TLS1_3_ONLY,
            cx::CLIENT_HELLO
        ));
        s.neg.reused = true;
        assert!(!relevant(
            &s,
            cx::CLIENT_HELLO | cx::IGNORE_ON_RESUMPTION,
            cx::CLIENT_HELLO
        ));
    }

    #[test]
    fn collect_indexes_by_definition_and_checks_responses() {
        let mut c = conn(true);
        c.neg.version = super::super::version::of(abi::TLS1_2_VERSION);
        // ALPN (index 9) then server_name (index 1), received in that order.
        let block = [
            0x00, 0x10, 0x00, 0x03, 0x02, b'h', b'2', 0x00, 0x00, 0x00, 0x00,
        ];
        collect(&mut c, &block, cx::CLIENT_HELLO, 0, false).unwrap();
        let r = received(&c, cx::CLIENT_HELLO, 0).unwrap();
        assert_eq!(r.get(t::ALPN).unwrap().received_order, 0);
        assert_eq!(r.get(t::SERVER_NAME).unwrap().received_order, 1);
        assert_eq!(r.get(t::ALPN).unwrap().offset, 4);
        // Collecting again for the same message keeps what was collected.
        collect(&mut c, &[], cx::CLIENT_HELLO, 0, false).unwrap();
        assert!(
            received(&c, cx::CLIENT_HELLO, 0)
                .unwrap()
                .get(t::ALPN)
                .is_some()
        );

        // A client gets an extension it didn't send.
        let mut cl = conn(false);
        cl.neg.version = super::super::version::of(abi::TLS1_2_VERSION);
        let e = collect(
            &mut cl,
            &[0x00, 0x16, 0x00, 0x00],
            cx::TLS1_2_SERVER_HELLO,
            0,
            false,
        )
        .unwrap_err();
        assert_eq!(
            e,
            Error::alert(
                abi::SSL_AD_UNSUPPORTED_EXTENSION,
                abi::SSL_R_UNSOLICITED_EXTENSION
            )
        );
        cl.hs.sh.ext.builtin[index_of(t::ENCRYPT_THEN_MAC).unwrap()] |= FLAG_SENT;
        collect(
            &mut cl,
            &[0x00, 0x16, 0x00, 0x00],
            cx::TLS1_2_SERVER_HELLO,
            0,
            false,
        )
        .unwrap();
    }

    #[test]
    fn init_clears_and_final_checks() {
        let mut c = conn(false);
        c.neg.version = super::super::version::of(abi::TLS1_2_VERSION);
        c.hs.sh.flags = abi::TLS1_FLAGS_RECEIVED_EXTMS;
        c.hs.sh.use_etm = true;
        c.neg.alpn = Some(b"h2".to_vec());
        collect(&mut c, &[], cx::TLS1_2_SERVER_HELLO, 0, true).unwrap();
        assert!(!c.hs.sh.use_etm);
        assert_eq!(c.neg.alpn, None);
        // Extended Master Secret was used before, so it is required now.
        assert_eq!(c.hs.sh.flags, abi::TLS1_FLAGS_REQUIRED_EXTMS);
        assert_eq!(
            final_ems(&c).unwrap_err(),
            Error::alert(abi::SSL_AD_HANDSHAKE_FAILURE, abi::SSL_R_INCONSISTENT_EXTMS)
        );
        // A client needs renegotiation_info unless legacy servers are allowed.
        assert_eq!(
            final_renegotiate(&c, false).unwrap_err(),
            Error::alert(
                abi::SSL_AD_HANDSHAKE_FAILURE,
                abi::SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED
            )
        );
        c.cfg.options |= abi::SSL_OP_LEGACY_SERVER_CONNECT;
        final_renegotiate(&c, false).unwrap();
        assert_eq!(
            final_supported_versions(cx::TLS1_3_HELLO_RETRY_REQUEST, false)
                .unwrap_err()
                .reason,
            abi::SSL_R_MISSING_SUPPORTED_VERSIONS_EXTENSION
        );
    }

    #[test]
    fn custom_extensions_ask_once_and_lead() {
        let mut c = Connection::new(Config {
            custom_exts: vec![CustomExt {
                typ: 1000,
                context: cx::CLIENT_HELLO | cx::TLS1_2_SERVER_HELLO,
                server: None,
                has_add: true,
                has_parse: true,
            }],
            ..Config::default()
        });
        c.hs.sh.ext = Flags::new(1);
        let mut w = Writer::new();
        let r = Request::CustomExt {
            index: 0,
            typ: 1000,
            context: cx::CLIENT_HELLO,
            body: None,
            chainidx: 0,
            cert: None,
        };
        let tls13 = super::super::version::of(abi::TLS1_3_VERSION);
        assert!(!custom_add(&mut c, cx::CLIENT_HELLO, 0, tls13, &mut w).unwrap());
        assert_eq!(c.pending, Some(r));
        c.answer(Answer::CustomExt(Some(vec![7])));
        assert!(custom_add(&mut c, cx::CLIENT_HELLO, 0, tls13, &mut w).unwrap());
        assert_eq!(w.bytes(), [0x03, 0xe8, 0x00, 0x01, 7]);
        assert_eq!(c.hs.sh.ext.custom, [FLAG_SENT]);
        // Re-run (as after a later request in the same message): the answer is reused.
        c.hs.sh.ext.custom[0] = 0;
        let mut w2 = Writer::new();
        assert!(custom_add(&mut c, cx::CLIENT_HELLO, 0, tls13, &mut w2).unwrap());
        assert_eq!(w2.bytes(), w.bytes());
    }

    #[test]
    fn max_fragment_lengths() {
        assert_eq!(max_fragment_length(1), Some(512));
        assert_eq!(max_fragment_length(4), Some(4096));
        assert_eq!(max_fragment_length(0), None);
        assert_eq!(max_fragment_length(5), None);
    }
}
