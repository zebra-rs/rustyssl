//! Extensions: the framing every extension block shares, OpenSSL's table of the extensions it
//! implements (`ext_defs[]` in `extensions.c`), its collection rules, and a typed parser and
//! encoder for each extension libssl handles.
//!
//! Each typed parser checks the structure the way OpenSSL's `tls_parse_ctos_*` and
//! `tls_parse_stoc_*` functions do, in the same order and with the same alert and reason. Those
//! functions also make checks that depend on the connection (whether the extension was sent,
//! whether the session is resumed); OpenSSL makes some of them before looking at the octets, so
//! the state machine makes those first and then calls the parser here.

use crate::codec::{Reader, TooLong, Writer};
use crate::consts::{context, ext};
use crate::error::{Error, Result};
use crate::msgs::{OrAlert, ad, r};

/// One extension: its type and its octets, as received or to be sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extension {
    /// The extension type.
    pub typ: u16,
    /// The extension's body.
    pub body: Vec<u8>,
    /// Where the body starts within the extension block's contents (after the block's
    /// 2-octet length), for the PSK binders' offset; 0 for an extension made locally.
    pub offset: usize,
}

impl Extension {
    /// An extension to send.
    #[must_use]
    pub fn new(typ: u16, body: Vec<u8>) -> Self {
        Self {
            typ,
            body,
            offset: 0,
        }
    }
}

/// Splits an extension block's contents (without its 2-octet length) into its extensions, in
/// received order, checking only the framing: a truncated type or length is OpenSSL's
/// `SSL_R_BAD_EXTENSION` with a decode-error alert (`tls_collect_extensions`). Duplicates are
/// kept; [`collect`] rejects the ones OpenSSL rejects.
///
/// # Errors
/// The framing is broken.
pub fn split(contents: &[u8]) -> Result<Vec<Extension>> {
    let e = Error::alert(ad::DECODE_ERROR, r::BAD_EXTENSION);
    let mut rd = Reader::new(contents);
    let mut out = Vec::new();
    while !rd.is_empty() {
        let typ = rd.u16().or_alert(e)?;
        let len = rd.u16().or_alert(e)?;
        let offset = contents.len().saturating_sub(rd.len());
        let body = rd.take(usize::from(len)).or_alert(e)?;
        out.push(Extension {
            typ,
            body: body.to_vec(),
            offset,
        });
    }
    Ok(out)
}

/// Writes an extension block: the 2-octet length and each extension in order.
///
/// # Errors
/// The block or an extension is longer than 65535 octets.
pub fn write_block(w: &mut Writer, exts: &[Extension]) -> core::result::Result<(), TooLong> {
    let o = w.open(2);
    for x in exts {
        w.u16(x.typ);
        w.vec(2, &x.body)?;
    }
    w.close(o)
}

/// An extension OpenSSL implements, with the contexts it may appear in (`SSL_EXT_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtDef {
    /// The extension type.
    pub typ: u16,
    /// Where it may appear, and its version restrictions.
    pub context: u32,
}

const CH: u32 = context::CLIENT_HELLO;
const SH12: u32 = context::TLS1_2_SERVER_HELLO;
const SH13: u32 = context::TLS1_3_SERVER_HELLO;
const EE: u32 = context::TLS1_3_ENCRYPTED_EXTENSIONS;
const HRR: u32 = context::TLS1_3_HELLO_RETRY_REQUEST;
const CERT: u32 = context::TLS1_3_CERTIFICATE;
const CR: u32 = context::TLS1_3_CERTIFICATE_REQUEST;
const NST: u32 = context::TLS1_3_NEW_SESSION_TICKET;
const SSL3: u32 = context::SSL3_ALLOWED;
const LE12: u32 = context::TLS1_2_AND_BELOW_ONLY;
const ONLY13: u32 = context::TLS1_3_ONLY;
const DTLS: u32 = context::DTLS_ONLY;
const IMPL: u32 = context::TLS_IMPLEMENTATION_ONLY;

/// OpenSSL 3.5's built-in extensions in its order (`ext_defs[]`), which is also the order its
/// ClientHello sends them in. The default build has SRP, OCSP, NPN, SRTP, CT, and GOST.
pub const EXT_DEFS: [ExtDef; 29] = [
    ExtDef {
        typ: ext::RENEGOTIATE,
        context: CH | SH12 | SSL3 | LE12,
    },
    ExtDef {
        typ: ext::SERVER_NAME,
        context: CH | SH12 | EE,
    },
    ExtDef {
        typ: ext::MAX_FRAGMENT_LENGTH,
        context: CH | SH12 | EE,
    },
    ExtDef {
        typ: ext::SRP,
        context: CH | LE12,
    },
    ExtDef {
        typ: ext::EC_POINT_FORMATS,
        context: CH | SH12 | LE12,
    },
    ExtDef {
        typ: ext::SUPPORTED_GROUPS,
        context: CH | EE | SH12,
    },
    ExtDef {
        typ: ext::SESSION_TICKET,
        context: CH | SH12 | LE12,
    },
    ExtDef {
        typ: ext::STATUS_REQUEST,
        context: CH | SH12 | CERT | CR,
    },
    ExtDef {
        typ: ext::NEXT_PROTO_NEG,
        context: CH | SH12 | LE12,
    },
    ExtDef {
        typ: ext::ALPN,
        context: CH | SH12 | EE,
    },
    ExtDef {
        typ: ext::USE_SRTP,
        context: CH | SH12 | EE | DTLS,
    },
    ExtDef {
        typ: ext::ENCRYPT_THEN_MAC,
        context: CH | SH12 | LE12,
    },
    ExtDef {
        typ: ext::SIGNED_CERTIFICATE_TIMESTAMP,
        context: CH | SH12 | CERT | CR,
    },
    ExtDef {
        typ: ext::EXTENDED_MASTER_SECRET,
        context: CH | SH12 | LE12,
    },
    ExtDef {
        typ: ext::SIGNATURE_ALGORITHMS_CERT,
        context: CH | CR,
    },
    ExtDef {
        typ: ext::POST_HANDSHAKE_AUTH,
        context: CH | ONLY13,
    },
    ExtDef {
        typ: ext::CLIENT_CERT_TYPE,
        context: CH | EE | SH12,
    },
    ExtDef {
        typ: ext::SERVER_CERT_TYPE,
        context: CH | EE | SH12,
    },
    ExtDef {
        typ: ext::SIGNATURE_ALGORITHMS,
        context: CH | CR,
    },
    ExtDef {
        typ: ext::SUPPORTED_VERSIONS,
        context: CH | SH13 | HRR | IMPL,
    },
    ExtDef {
        typ: ext::PSK_KEY_EXCHANGE_MODES,
        context: CH | IMPL | ONLY13,
    },
    ExtDef {
        typ: ext::KEY_SHARE,
        context: CH | SH13 | HRR | IMPL | ONLY13,
    },
    ExtDef {
        typ: ext::COOKIE,
        context: CH | HRR | IMPL | ONLY13,
    },
    ExtDef {
        typ: ext::CRYPTOPRO_BUG,
        context: CH | SH12 | LE12,
    },
    ExtDef {
        typ: ext::COMPRESS_CERTIFICATE,
        context: CH | CR | IMPL | ONLY13,
    },
    ExtDef {
        typ: ext::EARLY_DATA,
        context: CH | EE | NST | ONLY13,
    },
    ExtDef {
        typ: ext::CERTIFICATE_AUTHORITIES,
        context: CH | CR | ONLY13,
    },
    ExtDef {
        typ: ext::PADDING,
        context: CH,
    },
    ExtDef {
        typ: ext::PRE_SHARED_KEY,
        context: CH | SH13 | IMPL | ONLY13,
    },
];

/// The built-in definition of `typ`, if OpenSSL implements it.
#[must_use]
pub fn ext_def(typ: u16) -> Option<&'static ExtDef> {
    EXT_DEFS.iter().find(|d| d.typ == typ)
}

/// What [`collect`] needs to know about the connection.
pub struct Policy<'a> {
    /// Whether the connection is DTLS.
    pub dtls: bool,
    /// The context of an application's custom extension of this type for this direction
    /// (`custom_ext_find`), if one is registered.
    pub custom: &'a dyn Fn(u16) -> Option<u32>,
    /// Whether a built-in extension of this type was sent (`SSL_EXT_FLAG_SENT`), for the
    /// unsolicited-extension check on responses; `None` skips that check.
    pub sent: Option<&'a dyn Fn(u16) -> bool>,
}

/// `validate_context`: whether an extension defined for `extctx` may appear in `thisctx`.
fn valid_in(extctx: u32, thisctx: u32, dtls: bool) -> bool {
    if thisctx & extctx == 0 {
        return false;
    }
    if dtls {
        extctx & context::TLS_ONLY == 0
    } else {
        extctx & context::DTLS_ONLY == 0
    }
}

/// `tls_collect_extensions`: an extension block's contents checked as OpenSSL checks them for
/// a message of context `thisctx`. A recognized extension (built in, or custom) not allowed
/// here, a recognized one repeated, or a pre_shared_key that isn't last in a ClientHello is
/// `SSL_R_BAD_EXTENSION` with an illegal-parameter alert; a built-in one in a response that
/// wasn't sent is `SSL_R_UNSOLICITED_EXTENSION` with unsupported-extension (except the cookie,
/// renegotiation_info, signed_certificate_timestamp, and a TLS 1.2 ServerHello's
/// cryptopro_bug, as in OpenSSL). Unrecognized extensions are skipped by OpenSSL (even
/// repeated), and are returned here in their place.
///
/// # Errors
/// As above, or broken framing ([`split`]).
pub fn collect(contents: &[u8], thisctx: u32, policy: &Policy<'_>) -> Result<Vec<Extension>> {
    let exts = split(contents)?;
    check(&exts, thisctx, policy)?;
    Ok(exts)
}

/// [`collect`]'s checks on extensions already [`split`].
///
/// # Errors
/// As for [`collect`].
pub fn check(exts: &[Extension], thisctx: u32, policy: &Policy<'_>) -> Result<()> {
    let bad = Error::alert(ad::ILLEGAL_PARAMETER, r::BAD_EXTENSION);
    let mut seen: Vec<u16> = Vec::new();
    let count = exts.len();
    for (i, x) in exts.iter().enumerate() {
        let recognized = match ext_def(x.typ) {
            Some(d) => {
                if !valid_in(d.context, thisctx, policy.dtls) {
                    return Err(bad);
                }
                Some(true)
            }
            None => match (policy.custom)(x.typ) {
                Some(c) => {
                    if !valid_in(c, thisctx, policy.dtls) {
                        return Err(bad);
                    }
                    Some(false)
                }
                None => None,
            },
        };
        let last = i.checked_add(1) == Some(count);
        if recognized.is_some() && seen.contains(&x.typ) {
            return Err(bad);
        }
        if x.typ == ext::PRE_SHARED_KEY && thisctx & context::CLIENT_HELLO != 0 && !last {
            return Err(bad);
        }
        let Some(builtin) = recognized else { continue };
        seen.push(x.typ);
        let request = context::CLIENT_HELLO
            | context::TLS1_3_CERTIFICATE_REQUEST
            | context::TLS1_3_NEW_SESSION_TICKET;
        if builtin
            && thisctx & request == 0
            && x.typ != ext::COOKIE
            && x.typ != ext::RENEGOTIATE
            && x.typ != ext::SIGNED_CERTIFICATE_TIMESTAMP
            && !(thisctx & context::TLS1_2_SERVER_HELLO != 0 && x.typ == ext::CRYPTOPRO_BUG)
            && policy.sent.is_some_and(|sent| !sent(x.typ))
        {
            return Err(Error::alert(
                ad::UNSUPPORTED_EXTENSION,
                r::UNSOLICITED_EXTENSION,
            ));
        }
    }
    Ok(())
}

/// The contents of an extension block (without its length) for `exts`.
///
/// # Errors
/// An extension is longer than 65535 octets.
pub fn encode_contents(exts: &[Extension]) -> Result<Vec<u8>> {
    body(|w| {
        for x in exts {
            w.u16(x.typ);
            w.vec(2, &x.body)?;
        }
        Ok(())
    })
}

/// Fails with `err` unless `body` is empty: the zero-length extensions (encrypt_then_mac,
/// extended_master_secret, post_handshake_auth, early_data in a ClientHello or
/// EncryptedExtensions, a server's server_name and session_ticket).
///
/// # Errors
/// `body` isn't empty.
pub fn expect_empty(body: &[u8], err: Error) -> Result<()> {
    if body.is_empty() { Ok(()) } else { Err(err) }
}

/// A list of 16-bit values (`tls1_save_u16`): `None` when the octets are empty or odd.
#[must_use]
pub fn u16_list(octets: &[u8]) -> Option<Vec<u16>> {
    if octets.is_empty() || !octets.len().is_multiple_of(2) {
        return None;
    }
    let mut rd = Reader::new(octets);
    let mut out = Vec::with_capacity(octets.len() / 2);
    while !rd.is_empty() {
        out.push(rd.u16().ok()?);
    }
    Some(out)
}

/// Writes a list of 16-bit values with a `width`-octet length.
///
/// # Errors
/// The list is too long for the prefix.
pub fn write_u16_list(
    w: &mut Writer,
    width: usize,
    list: &[u16],
) -> core::result::Result<(), TooLong> {
    let o = w.open(width);
    for v in list {
        w.u16(*v);
    }
    w.close(o)
}

/// Encodes with a closure into a fresh body.
fn body(f: impl FnOnce(&mut Writer) -> core::result::Result<(), TooLong>) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    f(&mut w).map_err(|_| Error::internal())?;
    Ok(w.into_bytes())
}

/// renegotiation_info (RFC 5746).
pub mod renegotiate {
    use super::*;

    /// The client's: its last Finished (empty on the first handshake). A short vector is
    /// `SSL_R_RENEGOTIATION_ENCODING_ERR` with decode-error (`tls_parse_ctos_renegotiate`).
    /// OpenSSL ignores octets after the vector.
    ///
    /// # Errors
    /// As above.
    pub fn parse_client(b: &[u8]) -> Result<Vec<u8>> {
        let e = Error::alert(ad::DECODE_ERROR, r::RENEGOTIATION_ENCODING_ERR);
        Ok(Reader::new(b).vec8().or_alert(e)?.rest().to_vec())
    }

    /// The server's: the client's and its own last Finished concatenated, which must fill the
    /// body exactly (`tls_parse_stoc_renegotiate`'s first two checks).
    ///
    /// # Errors
    /// The length is missing or doesn't match: `SSL_R_RENEGOTIATION_ENCODING_ERR`.
    pub fn parse_server(b: &[u8]) -> Result<Vec<u8>> {
        let e = Error::alert(ad::DECODE_ERROR, r::RENEGOTIATION_ENCODING_ERR);
        let mut rd = Reader::new(b);
        let v = rd.vec8().or_alert(e)?;
        rd.end().or_alert(e)?;
        Ok(v.rest().to_vec())
    }

    /// The body for `finished` (the client's, or both concatenated for the server).
    ///
    /// # Errors
    /// Longer than 255 octets (never: Finished values are at most 64 octets).
    pub fn encode(finished: &[u8]) -> Result<Vec<u8>> {
        body(|w| w.vec(1, finished))
    }
}

/// server_name (RFC 6066).
pub mod server_name {
    use super::*;

    /// The client's: exactly one host_name entry, as OpenSSL requires (a list with anything
    /// else, or more, is `SSL_R_BAD_EXTENSION` with decode-error). The name's length and
    /// contents (at most 255 octets, no NUL) are checked by the caller, only when not resuming
    /// TLS 1.2, with an unrecognized-name alert.
    ///
    /// # Errors
    /// As above.
    pub fn parse_client(b: &[u8]) -> Result<Vec<u8>> {
        let e = Error::alert(ad::DECODE_ERROR, r::BAD_EXTENSION);
        let mut rd = Reader::new(b);
        let mut sni = rd.vec16().or_alert(e)?;
        rd.end().or_alert(e)?;
        if sni.is_empty() {
            return Err(e);
        }
        let typ = sni.u8().or_alert(e)?;
        if c_int_of(typ) != rustyssl_abi::TLSEXT_NAMETYPE_host_name {
            return Err(e);
        }
        let host = sni.vec16().or_alert(e)?;
        sni.end().or_alert(e)?;
        Ok(host.rest().to_vec())
    }

    /// The client's body for `host`.
    ///
    /// # Errors
    /// The name is too long for its vector.
    pub fn encode_client(host: &[u8]) -> Result<Vec<u8>> {
        body(|w| {
            let o = w.open(2);
            w.u8(0);
            w.vec(2, host)?;
            w.close(o)
        })
    }

    fn c_int_of(v: u8) -> core::ffi::c_int {
        core::ffi::c_int::from(v)
    }
}

/// max_fragment_length (RFC 6066).
pub mod max_fragment_length {
    use super::*;

    /// One octet, 1 to 4; anything else is OpenSSL's error: a wrong length is
    /// `SSL_R_BAD_EXTENSION` (decode-error), a bad value
    /// `SSL_R_SSL3_EXT_INVALID_MAX_FRAGMENT_LENGTH` (illegal-parameter).
    ///
    /// # Errors
    /// As above.
    pub fn parse(b: &[u8]) -> Result<u8> {
        let [v] = b else {
            return Err(Error::alert(ad::DECODE_ERROR, r::BAD_EXTENSION));
        };
        if !(1..=4).contains(v) {
            return Err(Error::alert(
                ad::ILLEGAL_PARAMETER,
                r::SSL3_EXT_INVALID_MAX_FRAGMENT_LENGTH,
            ));
        }
        Ok(*v)
    }
}

/// srp (RFC 5054): the client's login name.
pub mod srp {
    use super::*;

    /// A 1-octet-length name filling the body, with no NUL octets; `SSL_R_BAD_EXTENSION`
    /// with decode-error otherwise.
    ///
    /// # Errors
    /// As above.
    pub fn parse(b: &[u8]) -> Result<Vec<u8>> {
        let e = Error::alert(ad::DECODE_ERROR, r::BAD_EXTENSION);
        let mut rd = Reader::new(b);
        let v = rd.vec8().or_alert(e)?;
        rd.end().or_alert(e)?;
        if v.rest().contains(&0) {
            return Err(e);
        }
        Ok(v.rest().to_vec())
    }

    /// The body for `login`.
    ///
    /// # Errors
    /// The name is longer than 255 octets.
    pub fn encode(login: &[u8]) -> Result<Vec<u8>> {
        body(|w| w.vec(1, login))
    }
}

/// ec_point_formats (RFC 8422).
pub mod ec_point_formats {
    use super::*;

    /// The client's list: non-empty, filling the body (`SSL_R_BAD_EXTENSION`, decode-error).
    ///
    /// # Errors
    /// As above.
    pub fn parse_client(b: &[u8]) -> Result<Vec<u8>> {
        let e = Error::alert(ad::DECODE_ERROR, r::BAD_EXTENSION);
        let mut rd = Reader::new(b);
        let v = rd.vec8().or_alert(e)?;
        rd.end().or_alert(e)?;
        if v.is_empty() {
            return Err(e);
        }
        Ok(v.rest().to_vec())
    }

    /// The server's list: filling the body (`SSL_R_BAD_EXTENSION`), and non-empty
    /// (`SSL_R_BAD_LENGTH`), both decode-error. The caller checks it only when not resuming.
    ///
    /// # Errors
    /// As above.
    pub fn parse_server(b: &[u8]) -> Result<Vec<u8>> {
        let mut rd = Reader::new(b);
        let v = rd
            .vec8()
            .or_alert(Error::alert(ad::DECODE_ERROR, r::BAD_EXTENSION))?;
        rd.end()
            .or_alert(Error::alert(ad::DECODE_ERROR, r::BAD_EXTENSION))?;
        if v.is_empty() {
            return Err(Error::alert(ad::DECODE_ERROR, r::BAD_LENGTH));
        }
        Ok(v.rest().to_vec())
    }

    /// The body for `formats`.
    ///
    /// # Errors
    /// More than 255 formats.
    pub fn encode(formats: &[u8]) -> Result<Vec<u8>> {
        body(|w| w.vec(1, formats))
    }
}

/// A 2-octet-length list of 16-bit values that must be non-empty and fill the body
/// (supported_groups, signature_algorithms, signature_algorithms_cert), as raw octets: `even`
/// also requires an even length (supported_groups); the signature-algorithm lists check that
/// later (`tls1_save_sigalgs`, and only with TLS 1.2 and later), so they get the octets.
fn nonempty_list16(b: &[u8], even: bool) -> Result<Vec<u8>> {
    let e = Error::alert(ad::DECODE_ERROR, r::BAD_EXTENSION);
    let mut rd = Reader::new(b);
    let v = rd.vec16().or_alert(e)?;
    rd.end().or_alert(e)?;
    if v.is_empty() || (even && !v.len().is_multiple_of(2)) {
        return Err(e);
    }
    Ok(v.rest().to_vec())
}

/// supported_groups.
pub mod supported_groups {
    use super::*;

    /// The groups (the client's, or a TLS 1.3 server's in EncryptedExtensions): a non-empty,
    /// even-length list filling the body; `SSL_R_BAD_EXTENSION` with decode-error otherwise.
    ///
    /// # Errors
    /// As above.
    pub fn parse(b: &[u8]) -> Result<Vec<u16>> {
        let raw = nonempty_list16(b, true)?;
        u16_list(&raw).ok_or(Error::alert(ad::DECODE_ERROR, r::BAD_EXTENSION))
    }

    /// The body for `groups`.
    ///
    /// # Errors
    /// The list is too long.
    pub fn encode(groups: &[u16]) -> Result<Vec<u8>> {
        body(|w| write_u16_list(w, 2, groups))
    }
}

/// signature_algorithms and signature_algorithms_cert.
pub mod signature_algorithms {
    use super::*;

    /// The list's octets: non-empty and filling the body (`SSL_R_BAD_EXTENSION`, decode-error).
    /// Turn them into schemes with [`u16_list`], which fails on an odd length, as OpenSSL's
    /// `tls1_save_sigalgs` does (with the same error) when TLS 1.2 or later is in use.
    ///
    /// # Errors
    /// As above.
    pub fn parse(b: &[u8]) -> Result<Vec<u8>> {
        nonempty_list16(b, false)
    }

    /// The body for `schemes`.
    ///
    /// # Errors
    /// The list is too long.
    pub fn encode(schemes: &[u16]) -> Result<Vec<u8>> {
        body(|w| write_u16_list(w, 2, schemes))
    }
}

/// status_request (RFC 6066).
pub mod status_request {
    use super::*;

    /// A client's status request.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Request {
        /// OCSP, with the responder IDs (each a DER `ResponderID`) and the request extensions
        /// (DER `Extensions`, or empty).
        Ocsp {
            /// The responder IDs, each non-empty.
            responder_ids: Vec<Vec<u8>>,
            /// The DER of the request extensions, or empty.
            extensions: Vec<u8>,
        },
        /// Another status type, which OpenSSL ignores (without reading further).
        Other(u8),
    }

    /// The client's request (`tls_parse_ctos_status_request`): any structural fault is
    /// `SSL_R_BAD_EXTENSION` with decode-error. The DER of each responder ID and of the
    /// extensions is the caller's to decode, with the same error if it doesn't, or doesn't
    /// fill its vector.
    ///
    /// # Errors
    /// As above.
    pub fn parse(b: &[u8]) -> Result<Request> {
        let e = Error::alert(ad::DECODE_ERROR, r::BAD_EXTENSION);
        let mut rd = Reader::new(b);
        let typ = rd.u8().or_alert(e)?;
        if core::ffi::c_int::from(typ) != rustyssl_abi::TLSEXT_STATUSTYPE_ocsp {
            return Ok(Request::Other(typ));
        }
        let mut ids = rd.vec16().or_alert(e)?;
        let mut responder_ids = Vec::new();
        while !ids.is_empty() {
            let id = ids.vec16().or_alert(e)?;
            if id.is_empty() {
                return Err(e);
            }
            responder_ids.push(id.rest().to_vec());
        }
        let exts = rd.vec16().or_alert(e)?;
        rd.end().or_alert(e)?;
        Ok(Request::Ocsp {
            responder_ids,
            extensions: exts.rest().to_vec(),
        })
    }

    /// The body for `req`.
    ///
    /// # Errors
    /// A vector is too long.
    pub fn encode(req: &Request) -> Result<Vec<u8>> {
        body(|w| match req {
            Request::Ocsp {
                responder_ids,
                extensions,
            } => {
                w.u8(1);
                let o = w.open(2);
                for id in responder_ids {
                    w.vec(2, id)?;
                }
                w.close(o)?;
                w.vec(2, extensions)
            }
            Request::Other(t) => {
                w.u8(*t);
                Ok(())
            }
        })
    }
}

/// application_layer_protocol_negotiation (RFC 7301).
pub mod alpn {
    use super::*;

    /// The client's list: at least two octets, each protocol non-empty, filling the body;
    /// `SSL_R_BAD_EXTENSION` with decode-error otherwise (`tls_parse_ctos_alpn`). Returns the
    /// list's octets (each name with its length), as OpenSSL keeps them for the selection
    /// callback.
    ///
    /// # Errors
    /// As above.
    pub fn parse_client(b: &[u8]) -> Result<Vec<u8>> {
        let e = Error::alert(ad::DECODE_ERROR, r::BAD_EXTENSION);
        let mut rd = Reader::new(b);
        let list = rd.vec16().or_alert(e)?;
        rd.end().or_alert(e)?;
        if list.len() < 2 {
            return Err(e);
        }
        let mut each = list;
        while !each.is_empty() {
            if each.vec8().or_alert(e)?.is_empty() {
                return Err(e);
            }
        }
        Ok(list.rest().to_vec())
    }

    /// The protocols in a list's octets.
    #[must_use]
    pub fn names(list: &[u8]) -> Vec<Vec<u8>> {
        let mut rd = Reader::new(list);
        let mut out = Vec::new();
        while let Ok(v) = rd.vec8() {
            out.push(v.rest().to_vec());
        }
        out
    }

    /// The server's selection: a list of exactly one protocol filling the body (the name may
    /// be empty here; the caller fails to find it among those offered). `SSL_R_BAD_EXTENSION`
    /// with decode-error otherwise (`tls_parse_stoc_alpn`).
    ///
    /// # Errors
    /// As above.
    pub fn parse_server(b: &[u8]) -> Result<Vec<u8>> {
        let e = Error::alert(ad::DECODE_ERROR, r::BAD_EXTENSION);
        let mut rd = Reader::new(b);
        let mut list = rd.vec16().or_alert(e)?;
        rd.end().or_alert(e)?;
        let name = list.vec8().or_alert(e)?;
        list.end().or_alert(e)?;
        Ok(name.rest().to_vec())
    }

    /// The client's body for `protocols` (each name without its length).
    ///
    /// # Errors
    /// A name or the list is too long.
    pub fn encode_client(protocols: &[Vec<u8>]) -> Result<Vec<u8>> {
        body(|w| {
            let o = w.open(2);
            for p in protocols {
                w.vec(1, p)?;
            }
            w.close(o)
        })
    }

    /// The client's body from a list already in wire form (each name with its length).
    ///
    /// # Errors
    /// The list is too long.
    pub fn encode_wire(list: &[u8]) -> Result<Vec<u8>> {
        body(|w| w.vec(2, list))
    }

    /// The server's body for `protocol`.
    ///
    /// # Errors
    /// The name is longer than 255 octets.
    pub fn encode_server(protocol: &[u8]) -> Result<Vec<u8>> {
        body(|w| {
            let o = w.open(2);
            w.vec(1, protocol)?;
            w.close(o)
        })
    }
}

/// next_protocol_negotiation (the NPN draft): the server's list.
pub mod npn {
    use super::*;

    /// The server's protocols (`ssl_next_proto_validate`): a sequence of non-empty
    /// 1-octet-length names filling the body; `SSL_R_BAD_EXTENSION` with decode-error
    /// otherwise. The client's extension is empty and OpenSSL doesn't look at it.
    ///
    /// # Errors
    /// As above.
    pub fn parse_server(b: &[u8]) -> Result<Vec<Vec<u8>>> {
        let e = Error::alert(ad::DECODE_ERROR, r::BAD_EXTENSION);
        let mut rd = Reader::new(b);
        let mut out = Vec::new();
        while !rd.is_empty() {
            let p = rd.vec8().or_alert(e)?;
            if p.is_empty() {
                return Err(e);
            }
            out.push(p.rest().to_vec());
        }
        Ok(out)
    }

    /// The server's body for `protocols`.
    ///
    /// # Errors
    /// A name is longer than 255 octets.
    pub fn encode_server(protocols: &[Vec<u8>]) -> Result<Vec<u8>> {
        body(|w| {
            for p in protocols {
                w.vec(1, p)?;
            }
            Ok(())
        })
    }
}

/// use_srtp (RFC 5764).
pub mod use_srtp {
    use super::*;

    /// The client's offer: the protection profiles and the MKI.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Offer {
        /// The profiles, in the client's order.
        pub profiles: Vec<u16>,
        /// The MKI.
        pub mki: Vec<u8>,
    }

    /// The client's offer (`tls_parse_ctos_use_srtp`): an even-length profile list
    /// (`SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST`), then a 1-octet-length MKI that must end the
    /// body (`SSL_R_BAD_SRTP_MKI_VALUE`), all with decode-error. OpenSSL looks at it only when
    /// it has profiles of its own.
    ///
    /// # Errors
    /// As above.
    pub fn parse_client(b: &[u8]) -> Result<Offer> {
        let lst = Error::alert(ad::DECODE_ERROR, r::BAD_SRTP_PROTECTION_PROFILE_LIST);
        let mki_e = Error::alert(ad::DECODE_ERROR, r::BAD_SRTP_MKI_VALUE);
        let mut rd = Reader::new(b);
        let ct = rd.u16().or_alert(lst)?;
        if !ct.is_multiple_of(2) {
            return Err(lst);
        }
        let mut sub = Reader::new(rd.take(usize::from(ct)).or_alert(lst)?);
        let mut profiles = Vec::new();
        while !sub.is_empty() {
            profiles.push(sub.u16().or_alert(lst)?);
        }
        let mki_len = rd.u8().or_alert(lst)?;
        let mki = rd.take(usize::from(mki_len)).or_alert(mki_e)?;
        rd.end().or_alert(mki_e)?;
        Ok(Offer {
            profiles,
            mki: mki.to_vec(),
        })
    }

    /// The server's choice (`tls_parse_stoc_use_srtp`): a list of exactly one profile and an
    /// empty MKI. The wrong shape is `SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST` with
    /// decode-error, a non-empty MKI `SSL_R_BAD_SRTP_MKI_VALUE` with illegal-parameter.
    ///
    /// # Errors
    /// As above.
    pub fn parse_server(b: &[u8]) -> Result<u16> {
        let lst = Error::alert(ad::DECODE_ERROR, r::BAD_SRTP_PROTECTION_PROFILE_LIST);
        let mut rd = Reader::new(b);
        let ct = rd.u16().or_alert(lst)?;
        if ct != 2 {
            return Err(lst);
        }
        let id = rd.u16().or_alert(lst)?;
        let mki = rd.u8().or_alert(lst)?;
        rd.end().or_alert(lst)?;
        if mki != 0 {
            return Err(Error::alert(ad::ILLEGAL_PARAMETER, r::BAD_SRTP_MKI_VALUE));
        }
        Ok(id)
    }

    /// The client's body.
    ///
    /// # Errors
    /// A vector is too long.
    pub fn encode_client(offer: &Offer) -> Result<Vec<u8>> {
        body(|w| {
            write_u16_list(w, 2, &offer.profiles)?;
            w.vec(1, &offer.mki)
        })
    }

    /// The server's body for `profile`.
    ///
    /// # Errors
    /// Never.
    pub fn encode_server(profile: u16) -> Result<Vec<u8>> {
        body(|w| {
            write_u16_list(w, 2, &[profile])?;
            w.u8(0);
            Ok(())
        })
    }
}

/// supported_versions.
pub mod supported_versions {
    use super::*;

    /// The client's list (`ssl_choose_server_version`): a 1-octet-length list of 16-bit
    /// versions filling the body. A broken length or an odd count is `SSL_R_LENGTH_MISMATCH`,
    /// which OpenSSL sends with a protocol-version alert.
    ///
    /// # Errors
    /// As above.
    pub fn parse_client(b: &[u8]) -> Result<Vec<u16>> {
        let e = Error::alert(ad::PROTOCOL_VERSION, r::LENGTH_MISMATCH);
        let mut rd = Reader::new(b);
        let mut list = rd.vec8().or_alert(e)?;
        rd.end().or_alert(e)?;
        let mut out = Vec::new();
        while list.len() >= 2 {
            out.push(list.u16().or_alert(e)?);
        }
        list.end().or_alert(e)?;
        Ok(out)
    }

    /// The server's version: exactly two octets; `SSL_R_LENGTH_MISMATCH` with decode-error
    /// otherwise (`tls_parse_stoc_supported_versions`).
    ///
    /// # Errors
    /// As above.
    pub fn parse_server(b: &[u8]) -> Result<u16> {
        let e = Error::alert(ad::DECODE_ERROR, r::LENGTH_MISMATCH);
        let mut rd = Reader::new(b);
        let v = rd.u16().or_alert(e)?;
        rd.end().or_alert(e)?;
        Ok(v)
    }

    /// The client's body.
    ///
    /// # Errors
    /// More than 127 versions.
    pub fn encode_client(versions: &[u16]) -> Result<Vec<u8>> {
        body(|w| write_u16_list(w, 1, versions))
    }

    /// The server's body.
    ///
    /// # Errors
    /// Never.
    pub fn encode_server(version: u16) -> Result<Vec<u8>> {
        body(|w| {
            w.u16(version);
            Ok(())
        })
    }
}

/// psk_key_exchange_modes.
pub mod psk_key_exchange_modes {
    use super::*;

    /// The modes: a non-empty 1-octet-length list filling the body; `SSL_R_BAD_EXTENSION` with
    /// decode-error otherwise.
    ///
    /// # Errors
    /// As above.
    pub fn parse(b: &[u8]) -> Result<Vec<u8>> {
        let e = Error::alert(ad::DECODE_ERROR, r::BAD_EXTENSION);
        let mut rd = Reader::new(b);
        let v = rd.vec8().or_alert(e)?;
        rd.end().or_alert(e)?;
        if v.is_empty() {
            return Err(e);
        }
        Ok(v.rest().to_vec())
    }

    /// The body for `modes`.
    ///
    /// # Errors
    /// More than 255 modes.
    pub fn encode(modes: &[u8]) -> Result<Vec<u8>> {
        body(|w| w.vec(1, modes))
    }
}

/// key_share.
pub mod key_share {
    use super::*;

    /// One key share: a group and its encoded public value.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Entry {
        /// The group.
        pub group: u16,
        /// The encoded share (for a KEM, the client's encapsulation key or the server's
        /// ciphertext).
        pub key: Vec<u8>,
    }

    /// The client's shares (`extract_keyshares`): a 2-octet-length list filling the body, each
    /// entry a group and a non-empty 2-octet-length share; `SSL_R_LENGTH_MISMATCH` with
    /// decode-error otherwise. The list may be empty (the client asks for a
    /// HelloRetryRequest). Order and membership checks are the caller's.
    ///
    /// # Errors
    /// As above.
    pub fn parse_client(b: &[u8]) -> Result<Vec<Entry>> {
        let e = Error::alert(ad::DECODE_ERROR, r::LENGTH_MISMATCH);
        let mut rd = Reader::new(b);
        let mut list = rd.vec16().or_alert(e)?;
        rd.end().or_alert(e)?;
        let mut out = Vec::new();
        while !list.is_empty() {
            let group = list.u16().or_alert(e)?;
            let key = list.vec16().or_alert(e)?;
            if key.is_empty() {
                return Err(e);
            }
            out.push(Entry {
                group,
                key: key.rest().to_vec(),
            });
        }
        Ok(out)
    }

    /// The server's share in a ServerHello (`tls_parse_stoc_key_share`): a group and a
    /// non-empty share filling the body; `SSL_R_LENGTH_MISMATCH` with decode-error otherwise.
    /// (OpenSSL checks the group against the client's before reading the share; the caller
    /// can read the group first with [`group`].)
    ///
    /// # Errors
    /// As above.
    pub fn parse_server(b: &[u8]) -> Result<Entry> {
        let e = Error::alert(ad::DECODE_ERROR, r::LENGTH_MISMATCH);
        let mut rd = Reader::new(b);
        let group = rd.u16().or_alert(e)?;
        let key = rd.vec16().or_alert(e)?;
        rd.end().or_alert(e)?;
        if key.is_empty() {
            return Err(e);
        }
        Ok(Entry {
            group,
            key: key.rest().to_vec(),
        })
    }

    /// The group at the start of a server's share, or of a HelloRetryRequest's
    /// (`SSL_R_LENGTH_MISMATCH` with decode-error if missing).
    ///
    /// # Errors
    /// As above.
    pub fn group(b: &[u8]) -> Result<u16> {
        Reader::new(b)
            .u16()
            .or_alert(Error::alert(ad::DECODE_ERROR, r::LENGTH_MISMATCH))
    }

    /// A HelloRetryRequest's group: exactly two octets (`SSL_R_LENGTH_MISMATCH`,
    /// decode-error).
    ///
    /// # Errors
    /// As above.
    pub fn parse_hrr(b: &[u8]) -> Result<u16> {
        let e = Error::alert(ad::DECODE_ERROR, r::LENGTH_MISMATCH);
        let mut rd = Reader::new(b);
        let g = rd.u16().or_alert(e)?;
        rd.end().or_alert(e)?;
        Ok(g)
    }

    /// The client's body.
    ///
    /// # Errors
    /// A share or the list is too long.
    pub fn encode_client(entries: &[Entry]) -> Result<Vec<u8>> {
        body(|w| {
            let o = w.open(2);
            for x in entries {
                w.u16(x.group);
                w.vec(2, &x.key)?;
            }
            w.close(o)
        })
    }

    /// The server's body.
    ///
    /// # Errors
    /// The share is too long.
    pub fn encode_server(entry: &Entry) -> Result<Vec<u8>> {
        body(|w| {
            w.u16(entry.group);
            w.vec(2, &entry.key)
        })
    }

    /// A HelloRetryRequest's body for `group`.
    ///
    /// # Errors
    /// Never.
    pub fn encode_hrr(group: u16) -> Result<Vec<u8>> {
        body(|w| {
            w.u16(group);
            Ok(())
        })
    }
}

/// cookie (TLS 1.3).
pub mod cookie {
    use super::*;

    /// The cookie: a 2-octet-length vector filling the body; `SSL_R_LENGTH_MISMATCH` with
    /// decode-error otherwise (both directions; a server's own stateless cookie format is the
    /// state machine's).
    ///
    /// # Errors
    /// As above.
    pub fn parse(b: &[u8]) -> Result<Vec<u8>> {
        let e = Error::alert(ad::DECODE_ERROR, r::LENGTH_MISMATCH);
        let mut rd = Reader::new(b);
        let v = rd.vec16().or_alert(e)?;
        rd.end().or_alert(e)?;
        Ok(v.rest().to_vec())
    }

    /// The body for `cookie`.
    ///
    /// # Errors
    /// The cookie is too long.
    pub fn encode(cookie: &[u8]) -> Result<Vec<u8>> {
        body(|w| w.vec(2, cookie))
    }
}

/// early_data in a NewSessionTicket: the most early data the ticket allows.
pub mod early_data {
    use super::*;

    /// Exactly four octets; `SSL_R_INVALID_MAX_EARLY_DATA` with decode-error otherwise. (A
    /// value other than 0xffffffff with QUIC is the caller's illegal-parameter.)
    ///
    /// # Errors
    /// As above.
    pub fn parse_ticket(b: &[u8]) -> Result<u32> {
        let e = Error::alert(ad::DECODE_ERROR, r::INVALID_MAX_EARLY_DATA);
        let mut rd = Reader::new(b);
        let v = rd.u32().or_alert(e)?;
        rd.end().or_alert(e)?;
        Ok(v)
    }

    /// A ticket's body.
    ///
    /// # Errors
    /// Never.
    pub fn encode_ticket(max: u32) -> Result<Vec<u8>> {
        body(|w| {
            w.u32(max);
            Ok(())
        })
    }
}

/// pre_shared_key.
pub mod psk {
    use super::*;

    /// One offered identity.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Identity {
        /// The identity (a ticket, or an external PSK's name).
        pub identity: Vec<u8>,
        /// The obfuscated ticket age.
        pub obfuscated_ticket_age: u32,
    }

    /// The client's offer, as OpenSSL reads it: the identities' vector, and what follows it
    /// (the binders), each parsed only as far as the server goes (`tls_parse_ctos_psk`).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Offer {
        identities: Vec<u8>,
        after: Vec<u8>,
        binders_offset: usize,
    }

    impl Offer {
        /// The offer's identities' vector (a short or overlong vector is `SSL_R_BAD_EXTENSION`
        /// with decode-error). Nothing after it is looked at yet.
        ///
        /// # Errors
        /// As above.
        pub fn parse(b: &[u8]) -> Result<Self> {
            let e = Error::alert(ad::DECODE_ERROR, r::BAD_EXTENSION);
            let mut rd = Reader::new(b);
            let ids = rd.vec16().or_alert(e)?;
            let binders_offset = b.len().saturating_sub(rd.len());
            Ok(Self {
                identities: ids.rest().to_vec(),
                after: rd.rest().to_vec(),
                binders_offset,
            })
        }

        /// The identities in order, each decoded as the server reaches it: a truncated entry
        /// or an empty identity is `SSL_R_BAD_EXTENSION` with decode-error.
        #[must_use]
        pub fn identities(&self) -> Identities<'_> {
            Identities {
                rd: Reader::new(&self.identities),
                failed: false,
            }
        }

        /// Where the binders' vector starts within the extension's body.
        #[must_use]
        pub fn binders_offset(&self) -> usize {
            self.binders_offset
        }

        /// The binder for identity `index`: the binders' vector, then each binder up to
        /// `index`, as OpenSSL reads them (octets after the vector are never looked at). A
        /// truncated vector or binder is `SSL_R_BAD_EXTENSION` with decode-error.
        ///
        /// # Errors
        /// As above.
        pub fn binder(&self, index: usize) -> Result<Vec<u8>> {
            let e = Error::alert(ad::DECODE_ERROR, r::BAD_EXTENSION);
            let mut binders = Reader::new(&self.after).vec16().or_alert(e)?;
            let mut b = binders.vec8().or_alert(e)?;
            for _ in 0..index {
                b = binders.vec8().or_alert(e)?;
            }
            Ok(b.rest().to_vec())
        }
    }

    /// The identities of an [`Offer`].
    pub struct Identities<'a> {
        rd: Reader<'a>,
        failed: bool,
    }

    impl Iterator for Identities<'_> {
        type Item = Result<Identity>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.failed || self.rd.is_empty() {
                return None;
            }
            let e = Error::alert(ad::DECODE_ERROR, r::BAD_EXTENSION);
            let one = (|| {
                let id = self.rd.vec16().or_alert(e)?;
                let age = self.rd.u32().or_alert(e)?;
                if id.is_empty() {
                    return Err(e);
                }
                Ok(Identity {
                    identity: id.rest().to_vec(),
                    obfuscated_ticket_age: age,
                })
            })();
            if one.is_err() {
                self.failed = true;
            }
            Some(one)
        }
    }

    /// A complete offer, decoded strictly (every identity and binder, nothing left over), as
    /// the codec's own tests and a client re-reading its own offer use it.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Strict {
        /// The identities.
        pub identities: Vec<Identity>,
        /// The binders, one per identity.
        pub binders: Vec<Vec<u8>>,
    }

    impl Strict {
        /// Decodes `b` completely.
        ///
        /// # Errors
        /// Any structural fault: `SSL_R_BAD_EXTENSION` with decode-error.
        pub fn parse(b: &[u8]) -> Result<Self> {
            let e = Error::alert(ad::DECODE_ERROR, r::BAD_EXTENSION);
            let offer = Offer::parse(b)?;
            let identities = offer.identities().collect::<Result<Vec<_>>>()?;
            let mut rd = Reader::new(&offer.after);
            let mut list = rd.vec16().or_alert(e)?;
            rd.end().or_alert(e)?;
            let mut binders = Vec::new();
            while !list.is_empty() {
                binders.push(list.vec8().or_alert(e)?.rest().to_vec());
            }
            Ok(Self {
                identities,
                binders,
            })
        }

        /// The body.
        ///
        /// # Errors
        /// A vector is too long.
        pub fn encode(&self) -> Result<Vec<u8>> {
            body(|w| {
                let o = w.open(2);
                for i in &self.identities {
                    w.vec(2, &i.identity)?;
                    w.u32(i.obfuscated_ticket_age);
                }
                w.close(o)?;
                let o = w.open(2);
                for b in &self.binders {
                    w.vec(1, b)?;
                }
                w.close(o)
            })
        }

        /// The length of the binders' part of the encoding (their vector with its length), the
        /// part a ClientHello's binders are computed without.
        #[must_use]
        pub fn binders_len(&self) -> usize {
            self.binders
                .iter()
                .fold(2usize, |n, b| n.saturating_add(1).saturating_add(b.len()))
        }
    }

    /// The server's choice: exactly two octets, the identity's index; `SSL_R_LENGTH_MISMATCH`
    /// with decode-error otherwise (`tls_parse_stoc_psk`).
    ///
    /// # Errors
    /// As above.
    pub fn parse_server(b: &[u8]) -> Result<u16> {
        let e = Error::alert(ad::DECODE_ERROR, r::LENGTH_MISMATCH);
        let mut rd = Reader::new(b);
        let v = rd.u16().or_alert(e)?;
        rd.end().or_alert(e)?;
        Ok(v)
    }

    /// The server's body.
    ///
    /// # Errors
    /// Never.
    pub fn encode_server(index: u16) -> Result<Vec<u8>> {
        body(|w| {
            w.u16(index);
            Ok(())
        })
    }
}

/// certificate_authorities (TLS 1.3), and the CA list of a TLS 1.2 CertificateRequest.
pub mod certificate_authorities {
    use super::*;

    /// The distinguished names' DER, as `parse_ca_names` reads them: a 2-octet-length list of
    /// 2-octet-length names (`SSL_R_LENGTH_MISMATCH` with decode-error). The caller decodes
    /// each name (a failure is `ERR_R_ASN1_LIB`, one that doesn't fill its vector
    /// `SSL_R_CA_DN_LENGTH_MISMATCH`, both decode-error). The reader is left after the list.
    ///
    /// # Errors
    /// As above.
    pub fn read(rd: &mut Reader<'_>) -> Result<Vec<Vec<u8>>> {
        let e = Error::alert(ad::DECODE_ERROR, r::LENGTH_MISMATCH);
        let mut list = rd.vec16().or_alert(e)?;
        let mut out = Vec::new();
        while !list.is_empty() {
            out.push(list.vec16().or_alert(e)?.rest().to_vec());
        }
        Ok(out)
    }

    /// The extension's names (`tls_parse_certificate_authorities`): the list, which must fill
    /// the body (`SSL_R_BAD_EXTENSION` with decode-error).
    ///
    /// # Errors
    /// As above, or as for [`read`].
    pub fn parse(b: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut rd = Reader::new(b);
        let names = read(&mut rd)?;
        rd.end()
            .or_alert(Error::alert(ad::DECODE_ERROR, r::BAD_EXTENSION))?;
        Ok(names)
    }

    /// Writes the list of `names` (each DER).
    ///
    /// # Errors
    /// A name or the list is too long.
    pub fn write(w: &mut Writer, names: &[Vec<u8>]) -> core::result::Result<(), TooLong> {
        let o = w.open(2);
        for n in names {
            w.vec(2, n)?;
        }
        w.close(o)
    }

    /// The extension's body.
    ///
    /// # Errors
    /// A name or the list is too long.
    pub fn encode(names: &[Vec<u8>]) -> Result<Vec<u8>> {
        body(|w| write(w, names))
    }
}

/// compress_certificate (RFC 8879).
pub mod compress_certificate {
    use super::*;

    /// The algorithms: a non-empty 1-octet-length list filling the body
    /// (`SSL_R_BAD_EXTENSION`, decode-error), read as 16-bit values; an odd octet left over is
    /// the same error (`tls_parse_compress_certificate`). OpenSSL ignores the extension when
    /// it has no compression algorithm (the default build has none), before reading it.
    ///
    /// # Errors
    /// As above.
    pub fn parse(b: &[u8]) -> Result<Vec<u16>> {
        let e = Error::alert(ad::DECODE_ERROR, r::BAD_EXTENSION);
        let mut rd = Reader::new(b);
        let mut v = rd.vec8().or_alert(e)?;
        rd.end().or_alert(e)?;
        if v.is_empty() {
            return Err(e);
        }
        let mut out = Vec::new();
        while v.len() >= 2 {
            out.push(v.u16().or_alert(e)?);
        }
        v.end().or_alert(e)?;
        Ok(out)
    }

    /// The body for `algorithms`.
    ///
    /// # Errors
    /// More than 127 algorithms.
    pub fn encode(algorithms: &[u16]) -> Result<Vec<u8>> {
        body(|w| write_u16_list(w, 1, algorithms))
    }
}

/// client_certificate_type and server_certificate_type (RFC 7250).
pub mod cert_type {
    use super::*;

    /// The client's list: a non-empty 1-octet-length list filling the body
    /// (`SSL_R_BAD_EXTENSION`, decode-error).
    ///
    /// # Errors
    /// As above.
    pub fn parse_client(b: &[u8]) -> Result<Vec<u8>> {
        let e = Error::alert(ad::DECODE_ERROR, r::BAD_EXTENSION);
        let mut rd = Reader::new(b);
        let v = rd.vec8().or_alert(e)?;
        rd.end().or_alert(e)?;
        if v.is_empty() {
            return Err(e);
        }
        Ok(v.rest().to_vec())
    }

    /// The server's choice: exactly one octet (`SSL_R_BAD_EXTENSION`, decode-error).
    ///
    /// # Errors
    /// As above.
    pub fn parse_server(b: &[u8]) -> Result<u8> {
        match b {
            [v] => Ok(*v),
            _ => Err(Error::alert(ad::DECODE_ERROR, r::BAD_EXTENSION)),
        }
    }

    /// The client's body for `types`.
    ///
    /// # Errors
    /// More than 255 types.
    pub fn encode_client(types: &[u8]) -> Result<Vec<u8>> {
        body(|w| w.vec(1, types))
    }
}

/// padding (RFC 7685).
pub mod padding {
    /// The body that brings a ClientHello out of the 256..=511 range F5 load balancers
    /// mishandle, as OpenSSL does (`tls_construct_ctos_padding`, with `SSL_OP_TLSEXT_PADDING`):
    /// `hello_len` is what's written so far, handshake header included, plus (when a TLS 1.3
    /// ticket will be offered) the PSK extension still to come: its overhead before the binder,
    /// the ticket's length, and the binder's. `None` when no padding is needed. The extension's
    /// own four header octets are counted.
    #[must_use]
    pub fn body_for(hello_len: usize) -> Option<Vec<u8>> {
        if hello_len > 0xff && hello_len < 0x200 {
            let n = 0x200usize.saturating_sub(hello_len);
            let n = if n > 4 { n.saturating_sub(4) } else { 1 };
            Some(vec![0; n])
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn none(_: u16) -> Option<u32> {
        None
    }

    #[test]
    fn framing_keeps_order_and_offsets() {
        let block = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0xff, 0x01, 0x00, 0x00];
        let exts = split(&block).unwrap();
        assert_eq!(exts.len(), 2);
        assert_eq!(exts[0].typ, ext::SUPPORTED_VERSIONS);
        assert_eq!(exts[0].body, [3, 4]);
        assert_eq!(exts[0].offset, 4);
        assert_eq!(exts[1].offset, 10);
        assert_eq!(
            split(&[0x00]).unwrap_err(),
            Error::alert(ad::DECODE_ERROR, r::BAD_EXTENSION)
        );
        assert_eq!(
            split(&[0, 1, 0, 3, 0]).unwrap_err().reason,
            r::BAD_EXTENSION
        );
        let mut w = Writer::new();
        write_block(&mut w, &exts).unwrap();
        assert_eq!(w.bytes().get(2..), Some(&block[..]));
    }

    #[test]
    fn collection_rejects_what_openssl_rejects() {
        let policy = Policy {
            dtls: false,
            custom: &none,
            sent: None,
        };
        let bad = Error::alert(ad::ILLEGAL_PARAMETER, r::BAD_EXTENSION);
        // A recognized extension twice.
        let twice = [0, 0x17, 0, 0, 0, 0x17, 0, 0];
        assert_eq!(collect(&twice, CH, &policy).unwrap_err(), bad);
        // An unknown one twice is fine.
        let unknown = [0xaa, 0xaa, 0, 0, 0xaa, 0xaa, 0, 0];
        assert_eq!(collect(&unknown, CH, &policy).unwrap().len(), 2);
        // pre_shared_key not last.
        let psk = [0, 0x29, 0, 0, 0, 0x17, 0, 0];
        assert_eq!(collect(&psk, CH, &policy).unwrap_err(), bad);
        // key_share in a TLS 1.2 ServerHello context.
        let ks = [0, 0x33, 0, 0];
        assert_eq!(collect(&ks, SH12, &policy).unwrap_err(), bad);
        // use_srtp is DTLS-only.
        let srtp = [0, 0x0e, 0, 0];
        assert_eq!(collect(&srtp, CH, &policy).unwrap_err(), bad);
        let dtls = Policy {
            dtls: true,
            custom: &none,
            sent: None,
        };
        assert!(collect(&srtp, CH, &dtls).is_ok());
        // An unsolicited extension in a response.
        let never = |_: u16| false;
        let resp = Policy {
            dtls: false,
            custom: &none,
            sent: Some(&never),
        };
        let alpn = [0, 0x10, 0, 0];
        assert_eq!(
            collect(&alpn, EE, &resp).unwrap_err(),
            Error::alert(ad::UNSUPPORTED_EXTENSION, r::UNSOLICITED_EXTENSION)
        );
        let reneg = [0xff, 0x01, 0, 0];
        assert!(collect(&reneg, SH12, &resp).is_ok());
    }

    #[test]
    fn the_table_matches_openssls_order() {
        assert_eq!(EXT_DEFS.first().unwrap().typ, ext::RENEGOTIATE);
        assert_eq!(EXT_DEFS.last().unwrap().typ, ext::PRE_SHARED_KEY);
        let mut types: Vec<u16> = EXT_DEFS.iter().map(|d| d.typ).collect();
        types.sort_unstable();
        types.dedup();
        assert_eq!(types.len(), EXT_DEFS.len());
    }

    #[test]
    fn server_name() {
        let b = server_name::encode_client(b"server").unwrap();
        assert_eq!(b, [0, 9, 0, 0, 6, b's', b'e', b'r', b'v', b'e', b'r']);
        assert_eq!(server_name::parse_client(&b).unwrap(), b"server");
        let e = Error::alert(ad::DECODE_ERROR, r::BAD_EXTENSION);
        assert_eq!(server_name::parse_client(&[0, 0]).unwrap_err(), e);
        assert_eq!(
            server_name::parse_client(&[0, 4, 1, 0, 1, b'a']).unwrap_err(),
            e
        );
        // Two names: the first must fill the list.
        assert_eq!(
            server_name::parse_client(&[0, 8, 0, 0, 1, b'a', 0, 0, 1, b'b']).unwrap_err(),
            e
        );
    }

    #[test]
    fn small_ones() {
        assert_eq!(max_fragment_length::parse(&[2]).unwrap(), 2);
        assert_eq!(
            max_fragment_length::parse(&[5]).unwrap_err().reason,
            r::SSL3_EXT_INVALID_MAX_FRAGMENT_LENGTH
        );
        assert_eq!(
            max_fragment_length::parse(&[2, 2]).unwrap_err().reason,
            r::BAD_EXTENSION
        );
        assert_eq!(
            ec_point_formats::parse_server(&[0]).unwrap_err().reason,
            r::BAD_LENGTH
        );
        assert_eq!(
            ec_point_formats::parse_client(&[0]).unwrap_err().reason,
            r::BAD_EXTENSION
        );
        assert_eq!(
            supported_groups::parse(&[0, 3, 0, 0x17, 0])
                .unwrap_err()
                .reason,
            r::BAD_EXTENSION
        );
        assert_eq!(supported_groups::parse(&[0, 2, 0, 0x17]).unwrap(), [0x17]);
        assert_eq!(signature_algorithms::parse(&[0, 1, 4]).unwrap(), [4]);
        assert_eq!(u16_list(&[4]), None);
        assert_eq!(
            supported_versions::parse_client(&[3, 3, 4, 3])
                .unwrap_err()
                .alert,
            Some(70)
        );
        assert_eq!(
            supported_versions::parse_client(&[4, 3, 4, 3, 3]).unwrap(),
            [0x0304, 0x0303]
        );
        assert_eq!(
            supported_versions::parse_server(&[3, 4, 0])
                .unwrap_err()
                .reason,
            r::LENGTH_MISMATCH
        );
        assert_eq!(psk_key_exchange_modes::parse(&[1, 1]).unwrap(), [1]);
        assert_eq!(cert_type::parse_server(&[2]).unwrap(), 2);
        assert_eq!(
            compress_certificate::parse(&[3, 0, 1, 0])
                .unwrap_err()
                .reason,
            r::BAD_EXTENSION
        );
        assert_eq!(
            compress_certificate::parse(&[4, 0, 1, 0, 2]).unwrap(),
            [1, 2]
        );
        assert_eq!(early_data::parse_ticket(&[0, 0, 0x40, 0]).unwrap(), 0x4000);
        assert_eq!(cookie::parse(&[0, 1, 9]).unwrap(), [9]);
        assert_eq!(
            renegotiate::parse_server(&[1, 9, 9]).unwrap_err().reason,
            r::RENEGOTIATION_ENCODING_ERR
        );
        assert_eq!(renegotiate::parse_client(&[0, 9]).unwrap(), b"");
        assert_eq!(padding::body_for(300).map(|v| v.len()), Some(208));
        assert_eq!(padding::body_for(509).map(|v| v.len()), Some(1));
        assert_eq!(padding::body_for(200), None);
    }

    #[test]
    fn alpn_and_srtp() {
        let b = alpn::encode_client(&[b"h2".to_vec(), b"http/1.1".to_vec()]).unwrap();
        let list = alpn::parse_client(&b).unwrap();
        assert_eq!(alpn::names(&list), [b"h2".to_vec(), b"http/1.1".to_vec()]);
        assert_eq!(
            alpn::parse_client(&[0, 1, 0]).unwrap_err().reason,
            r::BAD_EXTENSION
        );
        assert_eq!(
            alpn::parse_client(&[0, 2, 0, 0]).unwrap_err().reason,
            r::BAD_EXTENSION
        );
        assert_eq!(
            alpn::parse_server(&alpn::encode_server(b"h2").unwrap()).unwrap(),
            b"h2"
        );
        let offer = use_srtp::Offer {
            profiles: vec![1, 2],
            mki: vec![],
        };
        assert_eq!(
            use_srtp::parse_client(&use_srtp::encode_client(&offer).unwrap()).unwrap(),
            offer
        );
        assert_eq!(
            use_srtp::parse_client(&[0, 1, 0, 0]).unwrap_err().reason,
            r::BAD_SRTP_PROTECTION_PROFILE_LIST
        );
        assert_eq!(
            use_srtp::parse_client(&[0, 2, 0, 1, 0, 9])
                .unwrap_err()
                .reason,
            r::BAD_SRTP_MKI_VALUE
        );
        assert_eq!(
            use_srtp::parse_server(&[0, 2, 0, 1, 1]).unwrap_err().alert,
            Some(47)
        );
        assert_eq!(
            use_srtp::parse_server(&use_srtp::encode_server(7).unwrap()).unwrap(),
            7
        );
    }

    #[test]
    fn key_shares() {
        let entries = vec![
            key_share::Entry {
                group: 0x1d,
                key: vec![1; 32],
            },
            key_share::Entry {
                group: 0x17,
                key: vec![4; 65],
            },
        ];
        let b = key_share::encode_client(&entries).unwrap();
        assert_eq!(key_share::parse_client(&b).unwrap(), entries);
        assert_eq!(key_share::parse_client(&[0, 0]).unwrap(), []);
        assert_eq!(
            key_share::parse_client(&[0, 4, 0, 0x1d, 0, 0])
                .unwrap_err()
                .reason,
            r::LENGTH_MISMATCH
        );
        let s = key_share::encode_server(&entries[0]).unwrap();
        assert_eq!(key_share::parse_server(&s).unwrap(), entries[0]);
        assert_eq!(key_share::parse_hrr(&[0, 0x17]).unwrap(), 0x17);
        assert_eq!(
            key_share::parse_hrr(&[0, 0x17, 0]).unwrap_err().reason,
            r::LENGTH_MISMATCH
        );
    }

    #[test]
    fn psk_offers_are_read_lazily() {
        let strict = psk::Strict {
            identities: vec![
                psk::Identity {
                    identity: b"one".to_vec(),
                    obfuscated_ticket_age: 7,
                },
                psk::Identity {
                    identity: b"two".to_vec(),
                    obfuscated_ticket_age: 8,
                },
            ],
            binders: vec![vec![1; 32], vec![2; 32]],
        };
        let b = strict.encode().unwrap();
        assert_eq!(psk::Strict::parse(&b).unwrap(), strict);
        let offer = psk::Offer::parse(&b).unwrap();
        assert_eq!(offer.binders_offset(), b.len() - strict.binders_len());
        assert_eq!(offer.binder(1).unwrap(), vec![2; 32]);
        let ids: Vec<_> = offer.identities().collect::<Result<_>>().unwrap();
        assert_eq!(ids, strict.identities);
        // A broken second identity is only seen when reached; trailing octets after the
        // binders are never seen.
        let mut lazy = vec![0, 10, 0, 1, b'a', 0, 0, 0, 1, 0, 0, 9];
        lazy.extend_from_slice(&[0, 2, 1, 5, 0xee, 0xee]);
        let offer = psk::Offer::parse(&lazy).unwrap();
        let mut it = offer.identities();
        assert!(it.next().unwrap().is_ok());
        assert_eq!(it.next().unwrap().unwrap_err().reason, r::BAD_EXTENSION);
        assert!(it.next().is_none());
        assert_eq!(offer.binder(0).unwrap(), [5]);
        assert!(psk::Strict::parse(&lazy).is_err());
        assert_eq!(psk::parse_server(&[0, 1]).unwrap(), 1);
    }

    #[test]
    fn status_requests() {
        let req = status_request::Request::Ocsp {
            responder_ids: vec![vec![0x30, 0]],
            extensions: vec![],
        };
        let b = status_request::encode(&req).unwrap();
        assert_eq!(status_request::parse(&b).unwrap(), req);
        let empty = status_request::Request::Ocsp {
            responder_ids: vec![],
            extensions: vec![],
        };
        assert_eq!(status_request::encode(&empty).unwrap(), [1, 0, 0, 0, 0]);
        assert_eq!(
            status_request::parse(&[2, 9, 9]).unwrap(),
            status_request::Request::Other(2)
        );
        assert_eq!(
            status_request::parse(&[1, 0, 2, 0, 0, 0, 0])
                .unwrap_err()
                .reason,
            r::BAD_EXTENSION
        );
    }

    #[test]
    fn ca_names() {
        let names = vec![vec![0x30, 0], vec![0x30, 2, 0x31, 0]];
        let b = certificate_authorities::encode(&names).unwrap();
        assert_eq!(certificate_authorities::parse(&b).unwrap(), names);
        let mut extra = b.clone();
        extra.push(0);
        assert_eq!(
            certificate_authorities::parse(&extra).unwrap_err().reason,
            r::BAD_EXTENSION
        );
        assert_eq!(
            certificate_authorities::parse(&[0, 3, 0, 9])
                .unwrap_err()
                .reason,
            r::LENGTH_MISMATCH
        );
    }
}
