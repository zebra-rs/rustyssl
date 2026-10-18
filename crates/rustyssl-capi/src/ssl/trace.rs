//! `SSL_trace` (`ssl/t1_trce.c`), the message callback that prints a readable trace of every
//! record and handshake message. The default build has it (ssl-trace isn't disabled), so it is
//! ported in full: the output is the reference's byte for byte.
//!
//! The messages are the peer's as well as ours, so every read is bounded: a message that ends
//! early stops its printing with the reference's "Message length parse error!".
#![allow(
    non_upper_case_globals,
    reason = "OpenSSL's constant names, matched as patterns"
)]

mod tables;

use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    BIO, ERR_LIB_SSL, OSSL_LIB_CTX, SSL, SSL3_MT_CERTIFICATE, SSL3_MT_CERTIFICATE_REQUEST,
    SSL3_MT_CLIENT_HELLO, SSL3_MT_ENCRYPTED_EXTENSIONS, SSL3_MT_NEWSESSION_TICKET,
    SSL3_MT_SERVER_HELLO,
};
use rustyssl_tls::suites::masks::{
    SSL_PSK, SSL_kDHE, SSL_kDHEPSK, SSL_kECDHE, SSL_kECDHEPSK, SSL_kGOST, SSL_kGOST18, SSL_kPSK,
    SSL_kRSA, SSL_kRSAPSK, SSL_kSRP,
};

use self::tables::{
    CERT_TYPE, CIPHERS, COMP, COMP_CERT, CONTENT, CTYPE, EXTS, GROUPS, HANDSHAKE, KEY_UPDATE, MFL,
    POINT, PSK_KEX_MODES, SIGALG, VERSION,
};
use super::conn::{ctx_of, ssl};
use crate::bio::BIO_write;
use crate::bio::dump::BIO_dump_indent;
use crate::evp::pkey::EVP_PKEY_free;
use crate::evp::pkey::print::EVP_PKEY_print_public;
use crate::ffi::ffi_export;
use crate::pem_pkey::PEM_write_bio_X509;
use crate::x509::cert::{X509_free, X509_new_ex, d2i_X509};
use crate::x509::name::{X509_NAME_free, X509_NAME_print_ex, d2i_X509_NAME};
use crate::x509::pubkey::d2i_PUBKEY_ex;
use crate::x509::tprint::X509_print_ex;

/// `EXPLICIT_PRIME_CURVE_TYPE` (`ssl_local.h`).
const EXPLICIT_PRIME_CURVE_TYPE: u8 = 1;
/// `EXPLICIT_CHAR2_CURVE_TYPE` (`ssl_local.h`).
const EXPLICIT_CHAR2_CURVE_TYPE: u8 = 2;
/// `NAMED_CURVE_TYPE` (`ssl_local.h`).
const NAMED_CURVE_TYPE: u8 = 3;

/// A message type constant as its octet.
fn mt(v: c_int) -> u8 {
    u8::try_from(v).unwrap_or(0)
}

/// What the trace needs to know about the connection.
struct Conn {
    dtls: bool,
    tls13: bool,
    use_sigalgs: bool,
    version: c_int,
    /// The negotiating cipher's key exchange (`s->s3.tmp.new_cipher->algorithm_mkey`).
    mkey: u32,
    client_cert_type: u8,
    server_cert_type: u8,
    libctx: *mut OSSL_LIB_CTX,
    propq: Option<CString>,
}

impl Conn {
    fn propq(&self) -> *const c_char {
        self.propq.as_ref().map_or(ptr::null(), |p| p.as_ptr())
    }
}

/// Where the trace goes.
struct Out(*mut BIO);

impl Out {
    fn bytes(&self, b: &[u8]) {
        for chunk in b.chunks(1 << 20) {
            let Ok(n) = c_int::try_from(chunk.len()) else {
                return;
            };
            // SAFETY: the callback's BIO; the chunk's octets. No lock is held.
            unsafe { BIO_write(self.0, chunk.as_ptr().cast(), n) };
        }
    }

    fn puts(&self, s: &str) {
        self.bytes(s.as_bytes());
    }

    /// `BIO_indent(bio, indent, 80)`.
    fn indent(&self, indent: usize) {
        self.puts(&" ".repeat(indent.min(80)));
    }

    /// `ssl_print_hex`.
    fn hex(&self, indent: usize, name: &str, msg: &[u8]) {
        self.indent(indent);
        let mut s = format!("{name} (len={}): ", len_int(msg.len()));
        for b in msg {
            s.push_str(&format!("{b:02X}"));
        }
        s.push('\n');
        self.puts(&s);
    }

    /// `BIO_dump_indent`.
    fn dump(&self, msg: &[u8], indent: usize) {
        let Ok(n) = c_int::try_from(msg.len()) else {
            return;
        };
        let ind = c_int::try_from(indent).unwrap_or(0);
        // SAFETY: the BIO; the message's octets.
        unsafe { BIO_dump_indent(self.0, msg.as_ptr().cast(), n, ind) };
    }
}

/// A length as C's `(int)` cast prints it.
fn len_int(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// `do_ssl_trace_str`.
fn trace_str(val: c_int, tbl: &[(c_int, &'static str)]) -> &'static str {
    tbl.iter()
        .find(|(n, _)| *n == val)
        .map_or("UNKNOWN", |(_, s)| s)
}

/// The first `n` octets as a big-endian number, if there are that many.
fn be(msg: &[u8], n: usize) -> Option<usize> {
    msg.get(..n)
        .map(|b| b.iter().fold(0usize, |a, &x| (a << 8) | usize::from(x)))
}

/// A big-endian number as the trace prints it (an `int`).
fn int(v: usize) -> c_int {
    c_int::try_from(v).unwrap_or(c_int::MAX)
}

/// `do_ssl_trace_list`.
fn trace_list(
    o: &Out,
    indent: usize,
    msg: &[u8],
    vlen: usize,
    tbl: &[(c_int, &'static str)],
) -> bool {
    if vlen == 0 || !msg.len().is_multiple_of(vlen) {
        return false;
    }
    for item in msg.chunks(vlen) {
        let val = int(be(item, vlen).unwrap_or(0));
        o.indent(indent);
        o.puts(&format!("{} ({val})\n", trace_str(val, tbl)));
    }
    true
}

/// `ssl_print_hexbuf`: a vector with an `nlen`-octet length, printed and taken off `msg`.
fn hexbuf(o: &Out, indent: usize, name: &str, nlen: usize, msg: &mut &[u8]) -> bool {
    let Some(blen) = be(msg, nlen) else {
        return false;
    };
    let Some(body) = msg.get(nlen..nlen.saturating_add(blen)) else {
        return false;
    };
    o.hex(indent, name, body);
    *msg = msg.get(nlen.saturating_add(blen)..).unwrap_or_default();
    true
}

/// `ssl_print_version`.
fn version(o: &Out, indent: usize, name: &str, msg: &mut &[u8]) -> Option<usize> {
    let vers = be(msg, 2)?;
    o.indent(indent);
    o.puts(&format!(
        "{name}=0x{vers:x} ({})\n",
        trace_str(int(vers), VERSION)
    ));
    *msg = msg.get(2..).unwrap_or_default();
    Some(vers)
}

/// `ssl_print_random`.
fn random(o: &Out, indent: usize, msg: &mut &[u8]) -> bool {
    let (Some(tm), Some(rest)) = (be(msg, 4), msg.get(4..32)) else {
        return false;
    };
    o.indent(indent);
    o.puts("Random:\n");
    o.indent(indent.saturating_add(2));
    o.puts(&format!("gmt_unix_time=0x{tm:08X}\n"));
    o.hex(indent.saturating_add(2), "random_bytes", rest);
    *msg = msg.get(32..).unwrap_or_default();
    true
}

/// `ssl_print_signature`.
fn signature(o: &Out, indent: usize, c: &Conn, msg: &mut &[u8]) -> bool {
    let Some(sigalg) = be(msg, 2) else {
        return false;
    };
    if c.use_sigalgs {
        o.indent(indent);
        o.puts(&format!(
            "Signature Algorithm: {} (0x{sigalg:04x})\n",
            trace_str(int(sigalg), SIGALG)
        ));
        *msg = msg.get(2..).unwrap_or_default();
    }
    hexbuf(o, indent, "Signature", 2, msg)
}

/// `ssl_print_extension`.
#[expect(
    clippy::too_many_lines,
    reason = "one case per extension, as in t1_trce.c"
)]
fn extension(o: &Out, indent: usize, server: bool, mtype: u8, extype: usize, ext: &[u8]) -> bool {
    use rustyssl_abi::{
        TLSEXT_TYPE_application_layer_protocol_negotiation, TLSEXT_TYPE_client_cert_type,
        TLSEXT_TYPE_compress_certificate, TLSEXT_TYPE_early_data, TLSEXT_TYPE_ec_point_formats,
        TLSEXT_TYPE_key_share, TLSEXT_TYPE_max_fragment_length, TLSEXT_TYPE_psk_kex_modes,
        TLSEXT_TYPE_renegotiate, TLSEXT_TYPE_server_cert_type, TLSEXT_TYPE_session_ticket,
        TLSEXT_TYPE_signature_algorithms, TLSEXT_TYPE_supported_groups,
        TLSEXT_TYPE_supported_versions,
    };
    let extlen = ext.len();
    let ind2 = indent.saturating_add(2);
    let ind4 = indent.saturating_add(4);
    o.indent(indent);
    let ty = int(extype);
    o.puts(&format!(
        "extension_type={}({ty}), length={}\n",
        trace_str(ty, EXTS),
        len_int(extlen)
    ));
    // A vector after an `n`-octet length that must fill the extension.
    let sole = |n: usize| -> Option<&[u8]> {
        let xlen = be(ext, n)?;
        if extlen != xlen.checked_add(n)? {
            return None;
        }
        ext.get(n..)
    };
    match ty {
        TLSEXT_TYPE_compress_certificate => {
            sole(1).is_some_and(|l| trace_list(o, ind2, l, 2, COMP_CERT))
        }
        TLSEXT_TYPE_max_fragment_length => extlen >= 1 && trace_list(o, ind2, ext, 1, MFL),
        TLSEXT_TYPE_ec_point_formats => sole(1).is_some_and(|l| trace_list(o, ind2, l, 1, POINT)),
        TLSEXT_TYPE_supported_groups => sole(2).is_some_and(|l| trace_list(o, ind2, l, 2, GROUPS)),
        TLSEXT_TYPE_application_layer_protocol_negotiation => {
            let Some(mut l) = sole(2) else { return false };
            while let Some((&plen, rest)) = l.split_first() {
                let plen = usize::from(plen);
                let Some(p) = rest.get(..plen) else {
                    return false;
                };
                o.indent(ind2);
                o.bytes(p);
                o.puts("\n");
                l = rest.get(plen..).unwrap_or_default();
            }
            true
        }
        TLSEXT_TYPE_signature_algorithms => {
            let Some(l) = sole(2) else { return false };
            if !l.len().is_multiple_of(2) {
                return false;
            }
            for s in l.chunks(2) {
                let sigalg = be(s, 2).unwrap_or(0);
                o.indent(ind2);
                o.puts(&format!(
                    "{} (0x{sigalg:04x})\n",
                    trace_str(int(sigalg), SIGALG)
                ));
            }
            true
        }
        TLSEXT_TYPE_renegotiate => {
            let Some(l) = sole(1) else { return false };
            if l.is_empty() {
                o.indent(ind4);
                o.puts("<EMPTY>\n");
                return true;
            }
            let mut xlen = l.len();
            if server {
                if !xlen.is_multiple_of(2) {
                    return false;
                }
                xlen /= 2;
            }
            o.hex(
                ind4,
                "client_verify_data",
                l.get(..xlen).unwrap_or_default(),
            );
            if server {
                o.hex(
                    ind4,
                    "server_verify_data",
                    l.get(xlen..).unwrap_or_default(),
                );
            }
            true
        }
        TLSEXT_TYPE_session_ticket => {
            if extlen != 0 {
                o.hex(ind4, "ticket", ext);
            }
            true
        }
        TLSEXT_TYPE_key_share => {
            if server && extlen == 2 {
                // A HelloRetryRequest's selected group.
                let g = int(be(ext, 2).unwrap_or(0));
                o.indent(ind4);
                o.puts(&format!("NamedGroup: {} ({g})\n", trace_str(g, GROUPS)));
                return true;
            }
            if extlen < 2 {
                return false;
            }
            let mut l = if server {
                ext
            } else {
                let Some(l) = sole(2) else { return false };
                l
            };
            while !l.is_empty() {
                let (Some(g), Some(share_len)) = (be(l, 2), l.get(2..).and_then(|r| be(r, 2)))
                else {
                    return false;
                };
                let rest = l.get(4..).unwrap_or_default();
                let Some(share) = rest.get(..share_len) else {
                    return false;
                };
                let g = int(g);
                o.indent(ind4);
                o.puts(&format!("NamedGroup: {} ({g})\n", trace_str(g, GROUPS)));
                o.hex(ind4, "key_exchange: ", share);
                l = rest.get(share_len..).unwrap_or_default();
            }
            true
        }
        TLSEXT_TYPE_supported_versions => {
            if server {
                if extlen != 2 {
                    return false;
                }
                let v = int(be(ext, 2).unwrap_or(0));
                o.indent(ind4);
                o.puts(&format!("{} ({v})\n", trace_str(v, VERSION)));
                return true;
            }
            sole(1).is_some_and(|l| trace_list(o, ind2, l, 2, VERSION))
        }
        TLSEXT_TYPE_psk_kex_modes => {
            sole(1).is_some_and(|l| trace_list(o, ind2, l, 1, PSK_KEX_MODES))
        }
        TLSEXT_TYPE_early_data => {
            if mtype != mt(SSL3_MT_NEWSESSION_TICKET) {
                return true;
            }
            if extlen != 4 {
                return false;
            }
            o.indent(ind2);
            o.puts(&format!("max_early_data={}\n", be(ext, 4).unwrap_or(0)));
            true
        }
        TLSEXT_TYPE_server_cert_type | TLSEXT_TYPE_client_cert_type => {
            if server {
                return extlen == 1 && trace_list(o, ind2, ext, 1, CERT_TYPE);
            }
            sole(1).is_some_and(|l| trace_list(o, ind2, l, 1, CERT_TYPE))
        }
        _ => {
            o.dump(ext, ind2);
            true
        }
    }
}

/// `ssl_print_extensions`.
fn extensions(o: &Out, indent: usize, server: bool, mtype: u8, msg: &mut &[u8]) -> bool {
    o.indent(indent);
    if msg.is_empty() {
        o.puts("No extensions\n");
        return true;
    }
    let Some(extslen) = be(msg, 2) else {
        return false;
    };
    let after = msg.get(2..).unwrap_or_default();
    if extslen == 0 {
        o.puts("No extensions\n");
        *msg = after;
        return true;
    }
    let Some(mut exts) = after.get(..extslen) else {
        return false;
    };
    o.puts(&format!("extensions, length = {}\n", int(extslen)));
    let rest = after.get(extslen..).unwrap_or_default();
    while !exts.is_empty() {
        let (Some(extype), Some(extlen)) = (be(exts, 2), exts.get(2..).and_then(|r| be(r, 2)))
        else {
            return false;
        };
        let Some(body) = exts.get(4..4usize.saturating_add(extlen)) else {
            o.puts(&format!(
                "extensions, extype = {}, extlen = {}\n",
                int(extype),
                int(extlen)
            ));
            o.dump(exts, indent.saturating_add(2));
            return false;
        };
        if !extension(o, indent.saturating_add(2), server, mtype, extype, body) {
            return false;
        }
        exts = exts
            .get(4usize.saturating_add(extlen)..)
            .unwrap_or_default();
    }
    *msg = rest;
    true
}

/// `ssl_print_client_hello`.
fn client_hello(o: &Out, c: &Conn, indent: usize, mut msg: &[u8]) -> bool {
    if version(o, indent, "client_version", &mut msg).is_none()
        || !random(o, indent, &mut msg)
        || !hexbuf(o, indent, "session_id", 1, &mut msg)
    {
        return false;
    }
    if c.dtls && !hexbuf(o, indent, "cookie", 1, &mut msg) {
        return false;
    }
    let Some(len) = be(msg, 2) else { return false };
    msg = msg.get(2..).unwrap_or_default();
    o.indent(indent);
    o.puts(&format!("cipher_suites (len={})\n", int(len)));
    let Some(suites) = msg.get(..len) else {
        return false;
    };
    if !len.is_multiple_of(2) {
        return false;
    }
    for cs in suites.chunks(2) {
        let (a, b) = (
            cs.first().copied().unwrap_or(0),
            cs.get(1).copied().unwrap_or(0),
        );
        let v = int(be(cs, 2).unwrap_or(0));
        o.indent(indent.saturating_add(2));
        o.puts(&format!(
            "{{0x{a:02X}, 0x{b:02X}}} {}\n",
            trace_str(v, CIPHERS)
        ));
    }
    msg = msg.get(len..).unwrap_or_default();
    let Some((&clen, rest)) = msg.split_first() else {
        return false;
    };
    let clen = usize::from(clen);
    let Some(comps) = rest.get(..clen) else {
        return false;
    };
    o.indent(indent);
    o.puts(&format!("compression_methods (len={clen})\n"));
    for &m in comps {
        o.indent(indent.saturating_add(2));
        o.puts(&format!(
            "{} (0x{m:02X})\n",
            trace_str(c_int::from(m), COMP)
        ));
    }
    msg = rest.get(clen..).unwrap_or_default();
    extensions(o, indent, false, mt(SSL3_MT_CLIENT_HELLO), &mut msg)
}

/// `dtls_print_hello_vfyrequest`.
fn hello_verify_request(o: &Out, indent: usize, mut msg: &[u8]) -> bool {
    version(o, indent, "server_version", &mut msg).is_some()
        && hexbuf(o, indent, "cookie", 1, &mut msg)
}

/// `ssl_print_server_hello`.
fn server_hello(o: &Out, indent: usize, mut msg: &[u8]) -> bool {
    let tls13 = usize::try_from(rustyssl_abi::TLS1_3_VERSION).unwrap_or(0);
    let Some(vers) = version(o, indent, "server_version", &mut msg) else {
        return false;
    };
    if !random(o, indent, &mut msg) {
        return false;
    }
    if vers != tls13 && !hexbuf(o, indent, "session_id", 1, &mut msg) {
        return false;
    }
    let Some(cs) = msg.get(..2) else { return false };
    let (a, b) = (
        cs.first().copied().unwrap_or(0),
        cs.get(1).copied().unwrap_or(0),
    );
    o.indent(indent);
    o.puts(&format!(
        "cipher_suite {{0x{a:02X}, 0x{b:02X}}} {}\n",
        trace_str(int(be(cs, 2).unwrap_or(0)), CIPHERS)
    ));
    msg = msg.get(2..).unwrap_or_default();
    if vers != tls13 {
        let Some((&m, rest)) = msg.split_first() else {
            return false;
        };
        o.indent(indent);
        o.puts(&format!(
            "compression_method: {} (0x{m:02X})\n",
            trace_str(c_int::from(m), COMP)
        ));
        msg = rest;
    }
    extensions(o, indent, true, mt(SSL3_MT_SERVER_HELLO), &mut msg)
}

/// `ssl_get_keyex`.
fn keyex(c: &Conn) -> (&'static str, u32) {
    let k = c.mkey;
    for (bit, name) in [
        (SSL_kRSA, "rsa"),
        (SSL_kDHE, "DHE"),
        (SSL_kECDHE, "ECDHE"),
        (SSL_kPSK, "PSK"),
        (SSL_kRSAPSK, "RSAPSK"),
        (SSL_kDHEPSK, "DHEPSK"),
        (SSL_kECDHEPSK, "ECDHEPSK"),
        (SSL_kSRP, "SRP"),
        (SSL_kGOST, "GOST"),
        (SSL_kGOST18, "GOST18"),
    ] {
        if k & bit != 0 {
            return (name, bit);
        }
    }
    ("UNKNOWN", 0)
}

/// `ssl_print_client_keyex`.
fn client_keyex(o: &Out, indent: usize, c: &Conn, mut msg: &[u8]) -> bool {
    let (name, id) = keyex(c);
    let ind2 = indent.saturating_add(2);
    o.indent(indent);
    o.puts(&format!("KeyExchangeAlgorithm={name}\n"));
    if id & SSL_PSK != 0 && !hexbuf(o, ind2, "psk_identity", 2, &mut msg) {
        return false;
    }
    match id {
        SSL_kRSA | SSL_kRSAPSK => {
            if !hexbuf(o, ind2, "EncryptedPreMasterSecret", 2, &mut msg) {
                return false;
            }
        }
        SSL_kDHE | SSL_kDHEPSK => {
            if !hexbuf(o, ind2, "dh_Yc", 2, &mut msg) {
                return false;
            }
        }
        SSL_kECDHE | SSL_kECDHEPSK => {
            if !hexbuf(o, ind2, "ecdh_Yc", 1, &mut msg) {
                return false;
            }
        }
        SSL_kGOST => {
            o.hex(ind2, "GostKeyTransportBlob", msg);
            msg = &[];
        }
        SSL_kGOST18 => {
            o.hex(ind2, "GOST-wrapped PreMasterSecret", msg);
            msg = &[];
        }
        _ => {}
    }
    msg.is_empty()
}

/// `ssl_print_server_keyex`.
fn server_keyex(o: &Out, indent: usize, c: &Conn, mut msg: &[u8]) -> bool {
    let (name, id) = keyex(c);
    let ind2 = indent.saturating_add(2);
    o.indent(indent);
    o.puts(&format!("KeyExchangeAlgorithm={name}\n"));
    if id & SSL_PSK != 0 && !hexbuf(o, ind2, "psk_identity_hint", 2, &mut msg) {
        return false;
    }
    match id {
        SSL_kRSA => {
            if !hexbuf(o, ind2, "rsa_modulus", 2, &mut msg)
                || !hexbuf(o, ind2, "rsa_exponent", 2, &mut msg)
            {
                return false;
            }
        }
        SSL_kDHE | SSL_kDHEPSK => {
            if !hexbuf(o, ind2, "dh_p", 2, &mut msg)
                || !hexbuf(o, ind2, "dh_g", 2, &mut msg)
                || !hexbuf(o, ind2, "dh_Ys", 2, &mut msg)
            {
                return false;
            }
        }
        SSL_kECDHE | SSL_kECDHEPSK => {
            let Some(&ty) = msg.first() else { return false };
            o.indent(ind2);
            if ty == EXPLICIT_PRIME_CURVE_TYPE {
                o.puts("explicit_prime\n");
            } else if ty == EXPLICIT_CHAR2_CURVE_TYPE {
                o.puts("explicit_char2\n");
            } else if ty == NAMED_CURVE_TYPE {
                let Some(curve) = msg.get(1..).and_then(|r| be(r, 2)) else {
                    return false;
                };
                let curve = int(curve);
                o.puts(&format!(
                    "named_curve: {} ({curve})\n",
                    trace_str(curve, GROUPS)
                ));
                msg = msg.get(3..).unwrap_or_default();
                if !hexbuf(o, ind2, "point", 1, &mut msg) {
                    return false;
                }
            } else {
                o.puts(&format!("UNKNOWN CURVE PARAMETER TYPE {ty}\n"));
                return false;
            }
        }
        _ => {}
    }
    if id & SSL_PSK == 0 {
        // As in t1_trce.c, the signature's own failure isn't reported.
        signature(o, indent, c, &mut msg);
    }
    msg.is_empty()
}

/// `ssl_print_certificate`: one certificate entry, taken off `msg`.
fn certificate(o: &Out, c: &Conn, indent: usize, msg: &mut &[u8]) -> bool {
    let Some(clen) = be(msg, 3) else { return false };
    let Some(der) = msg.get(3..3usize.saturating_add(clen)) else {
        return false;
    };
    o.indent(indent);
    o.puts(&format!("ASN.1Cert, length={}", int(clen)));
    // SAFETY: the connection's library context and properties.
    let mut x = unsafe { X509_new_ex(c.libctx, c.propq()) };
    let mut q: *const c_uchar = der.as_ptr();
    let Ok(dlen) = c_long::try_from(der.len()) else {
        return false;
    };
    // SAFETY: the certificate's octets; the object made above.
    if !x.is_null() && unsafe { d2i_X509(&raw mut x, &raw mut q, dlen) }.is_null() {
        // SAFETY: made above (d2i frees nothing it didn't make).
        unsafe { X509_free(x) };
        x = ptr::null_mut();
    }
    if x.is_null() {
        o.puts("<UNPARSABLE CERTIFICATE>\n");
    } else {
        o.puts("\n------details-----\n");
        let flags = c_ulong::try_from(rustyssl_abi::XN_FLAG_ONELINE).unwrap_or(0);
        // SAFETY: the BIO; the certificate decoded above.
        unsafe { X509_print_ex(o.0, x, flags, 0) };
        // SAFETY: as above.
        unsafe { PEM_write_bio_X509(o.0, x) };
        o.puts("------------------\n");
        // SAFETY: decoded above, freed once.
        unsafe { X509_free(x) };
    }
    if !core::ptr::eq(q, der.as_ptr().wrapping_add(der.len())) {
        o.puts("<TRAILING GARBAGE AFTER CERTIFICATE>\n");
    }
    *msg = msg.get(3usize.saturating_add(clen)..).unwrap_or_default();
    true
}

/// `ssl_print_raw_public_key`.
fn raw_public_key(o: &Out, c: &Conn, indent: usize, msg: &mut &[u8]) -> bool {
    // In TLS 1.2 and earlier the key is the whole payload, without its own length.
    let has_spki_len = if c.dtls {
        // DTLS_VERSION_GT(version, DTLS1_2_VERSION): DTLS versions count down.
        c.version < rustyssl_abi::DTLS1_2_VERSION && c.version != rustyssl_abi::DTLS1_BAD_VER
    } else {
        c.version > rustyssl_abi::TLS1_2_VERSION
    };
    let key: &[u8];
    if has_spki_len {
        let Some(clen) = be(msg, 3) else { return false };
        let Some(k) = msg.get(3..3usize.saturating_add(clen)) else {
            return false;
        };
        key = k;
        *msg = msg.get(3usize.saturating_add(clen)..).unwrap_or_default();
    } else {
        key = msg;
        *msg = &[];
    }
    o.indent(indent);
    o.puts(&format!("raw_public_key, length={}\n", len_int(key.len())));
    let Ok(klen) = c_long::try_from(key.len()) else {
        return false;
    };
    let mut p: *const c_uchar = key.as_ptr();
    // SAFETY: the key's octets; the connection's library context and properties.
    let pkey = unsafe { d2i_PUBKEY_ex(ptr::null_mut(), &raw mut p, klen, c.libctx, c.propq()) };
    if pkey.is_null() {
        return false;
    }
    let ind = c_int::try_from(indent.saturating_add(2)).unwrap_or(0);
    // SAFETY: the BIO; the key decoded above.
    unsafe { EVP_PKEY_print_public(o.0, pkey, ind, ptr::null_mut()) };
    // SAFETY: decoded above, freed once.
    unsafe { EVP_PKEY_free(pkey) };
    true
}

/// `ssl_print_certificates`.
fn certificates(o: &Out, c: &Conn, server: bool, indent: usize, mut msg: &[u8]) -> bool {
    if c.tls13 && !hexbuf(o, indent, "context", 1, &mut msg) {
        return false;
    }
    let Some(clen) = be(msg, 3) else { return false };
    if msg.len() != clen.saturating_add(3) {
        return false;
    }
    let mut list = msg.get(3..).unwrap_or_default();
    let rpk = u8::try_from(rustyssl_abi::TLSEXT_cert_type_rpk).unwrap_or(2);
    if (server && c.server_cert_type == rpk) || (!server && c.client_cert_type == rpk) {
        if !raw_public_key(o, c, indent, &mut list) {
            return false;
        }
        return !c.tls13
            || extensions(
                o,
                indent.saturating_add(2),
                server,
                mt(SSL3_MT_CERTIFICATE),
                &mut list,
            );
    }
    o.indent(indent);
    o.puts(&format!("certificate_list, length={}\n", int(clen)));
    while !list.is_empty() {
        if !certificate(o, c, indent.saturating_add(2), &mut list) {
            return false;
        }
        if c.tls13
            && !extensions(
                o,
                indent.saturating_add(2),
                server,
                mt(SSL3_MT_CERTIFICATE),
                &mut list,
            )
        {
            return false;
        }
    }
    true
}

/// `ssl_print_compressed_certificates` (the default build has no compression algorithm, so the
/// certificates are only dumped).
fn compressed_certificates(o: &Out, indent: usize, msg: &[u8]) -> bool {
    let (Some(alg), Some(uclen), Some(clen)) = (
        be(msg, 2),
        msg.get(2..).and_then(|r| be(r, 3)),
        msg.get(5..).and_then(|r| be(r, 3)),
    ) else {
        return false;
    };
    if msg.len() != clen.saturating_add(8) {
        return false;
    }
    let data = msg.get(8..).unwrap_or_default();
    o.indent(indent);
    o.puts(&format!(
        "Compression type={} (0x{alg:04x})\n",
        trace_str(int(alg), COMP_CERT)
    ));
    o.indent(indent);
    o.puts(&format!("Uncompressed length={}\n", int(uclen)));
    o.indent(indent);
    if clen > 0 {
        let (u, cl) = (
            f64::from(u32::try_from(uclen).unwrap_or(0)),
            f64::from(u32::try_from(clen).unwrap_or(1)),
        );
        // C prints the float quotient with "%f" (as a double after promotion).
        #[expect(clippy::cast_possible_truncation, reason = "the C code divides floats")]
        let ratio = f64::from((u as f32) / (cl as f32));
        o.puts(&format!(
            "Compressed length={}, Ratio={ratio:.6}:1\n",
            int(clen)
        ));
    } else {
        o.puts(&format!("Compressed length={}, Ratio=unknown\n", int(clen)));
    }
    o.dump(data, indent);
    true
}

/// `ssl_print_cert_request`.
fn cert_request(o: &Out, indent: usize, c: &Conn, mut msg: &[u8]) -> bool {
    let ind2 = indent.saturating_add(2);
    if c.tls13 {
        return hexbuf(o, indent, "request_context", 1, &mut msg)
            && extensions(o, indent, true, mt(SSL3_MT_CERTIFICATE_REQUEST), &mut msg);
    }
    let Some((&xlen, rest)) = msg.split_first() else {
        return false;
    };
    let xlen = usize::from(xlen);
    let Some(types) = rest.get(..xlen) else {
        return false;
    };
    o.indent(indent);
    o.puts(&format!("certificate_types (len={xlen})\n"));
    if !trace_list(o, ind2, types, 1, CTYPE) {
        return false;
    }
    msg = rest.get(xlen..).unwrap_or_default();
    if c.use_sigalgs {
        let Some(xlen) = be(msg, 2) else { return false };
        let Some(algs) = msg.get(2..2usize.saturating_add(xlen)) else {
            return false;
        };
        if !xlen.is_multiple_of(2) {
            return false;
        }
        o.indent(indent);
        o.puts(&format!("signature_algorithms (len={})\n", int(xlen)));
        for s in algs.chunks(2) {
            let sigalg = be(s, 2).unwrap_or(0);
            o.indent(ind2);
            o.puts(&format!(
                "{} (0x{sigalg:04x})\n",
                trace_str(int(sigalg), SIGALG)
            ));
        }
        msg = msg.get(2usize.saturating_add(xlen)..).unwrap_or_default();
    }
    let Some(xlen) = be(msg, 2) else { return false };
    o.indent(indent);
    let Some(mut names) = msg.get(2..2usize.saturating_add(xlen)) else {
        return false;
    };
    let rest = msg.get(2usize.saturating_add(xlen)..).unwrap_or_default();
    o.puts(&format!("certificate_authorities (len={})\n", int(xlen)));
    while !names.is_empty() {
        let Some(dlen) = be(names, 2) else {
            return false;
        };
        let Some(dn) = names.get(2..2usize.saturating_add(dlen)) else {
            return false;
        };
        o.indent(ind2);
        o.puts(&format!("DistinguishedName (len={}): ", int(dlen)));
        let mut p: *const c_uchar = dn.as_ptr();
        let Ok(l) = c_long::try_from(dn.len()) else {
            return false;
        };
        // SAFETY: the name's octets.
        let nm = unsafe { d2i_X509_NAME(ptr::null_mut(), &raw mut p, l) };
        if nm.is_null() {
            o.puts("<UNPARSABLE DN>\n");
        } else {
            let flags = c_ulong::try_from(rustyssl_abi::XN_FLAG_ONELINE).unwrap_or(0);
            // SAFETY: the BIO; the name decoded above.
            unsafe { X509_NAME_print_ex(o.0, nm, 0, flags) };
            o.puts("\n");
            // SAFETY: decoded above, freed once.
            unsafe { X509_NAME_free(nm) };
        }
        names = names.get(2usize.saturating_add(dlen)..).unwrap_or_default();
    }
    msg = rest;
    if c.tls13 && !hexbuf(o, indent, "request_extensions", 2, &mut msg) {
        return false;
    }
    msg.is_empty()
}

/// `ssl_print_ticket`.
fn ticket(o: &Out, indent: usize, c: &Conn, mut msg: &[u8]) -> bool {
    let ind2 = indent.saturating_add(2);
    if msg.is_empty() {
        o.indent(ind2);
        o.puts("No Ticket\n");
        return true;
    }
    let Some(life) = be(msg, 4) else { return false };
    msg = msg.get(4..).unwrap_or_default();
    o.indent(ind2);
    o.puts(&format!("ticket_lifetime_hint={life}\n"));
    if c.tls13 {
        let Some(age_add) = be(msg, 4) else {
            return false;
        };
        msg = msg.get(4..).unwrap_or_default();
        o.indent(ind2);
        o.puts(&format!("ticket_age_add={age_add}\n"));
        if !hexbuf(o, ind2, "ticket_nonce", 1, &mut msg) {
            return false;
        }
    }
    if !hexbuf(o, ind2, "ticket", 2, &mut msg) {
        return false;
    }
    if c.tls13 && !extensions(o, ind2, false, mt(SSL3_MT_NEWSESSION_TICKET), &mut msg) {
        return false;
    }
    msg.is_empty()
}

/// `ssl_print_handshake`.
fn handshake(o: &Out, c: &Conn, server: bool, msg: &[u8], indent: usize) -> bool {
    use rustyssl_abi::{
        DTLS1_MT_HELLO_VERIFY_REQUEST, SSL3_MT_CERTIFICATE_VERIFY, SSL3_MT_CLIENT_KEY_EXCHANGE,
        SSL3_MT_COMPRESSED_CERTIFICATE, SSL3_MT_END_OF_EARLY_DATA, SSL3_MT_FINISHED,
        SSL3_MT_KEY_UPDATE, SSL3_MT_SERVER_DONE, SSL3_MT_SERVER_KEY_EXCHANGE,
    };
    let (Some(&htype), Some(hlen)) = (msg.first(), msg.get(1..).and_then(|r| be(r, 3))) else {
        return false;
    };
    o.indent(indent);
    o.puts(&format!(
        "{}, Length={}\n",
        trace_str(c_int::from(htype), HANDSHAKE),
        int(hlen)
    ));
    let mut body = msg.get(4..).unwrap_or_default();
    if c.dtls {
        let (Some(seq), Some(off), Some(flen)) = (
            be(body, 2),
            body.get(2..).and_then(|r| be(r, 3)),
            body.get(5..).and_then(|r| be(r, 3)),
        ) else {
            return false;
        };
        o.indent(indent);
        o.puts(&format!(
            "message_seq={}, fragment_offset={}, fragment_length={}\n",
            int(seq),
            int(off),
            int(flen)
        ));
        body = body.get(8..).unwrap_or_default();
    }
    if body.len() < hlen {
        return false;
    }
    let ind2 = indent.saturating_add(2);
    let t = c_int::from(htype);
    match t {
        SSL3_MT_CLIENT_HELLO => client_hello(o, c, ind2, body),
        DTLS1_MT_HELLO_VERIFY_REQUEST => hello_verify_request(o, ind2, body),
        SSL3_MT_SERVER_HELLO => server_hello(o, ind2, body),
        SSL3_MT_SERVER_KEY_EXCHANGE => server_keyex(o, ind2, c, body),
        SSL3_MT_CLIENT_KEY_EXCHANGE => client_keyex(o, ind2, c, body),
        SSL3_MT_CERTIFICATE => certificates(o, c, server, ind2, body),
        SSL3_MT_COMPRESSED_CERTIFICATE => compressed_certificates(o, ind2, body),
        SSL3_MT_CERTIFICATE_VERIFY => signature(o, ind2, c, &mut body),
        SSL3_MT_CERTIFICATE_REQUEST => cert_request(o, ind2, c, body),
        SSL3_MT_FINISHED => {
            o.hex(ind2, "verify_data", body);
            true
        }
        SSL3_MT_END_OF_EARLY_DATA | SSL3_MT_SERVER_DONE => {
            if !body.is_empty() {
                o.hex(ind2, "unexpected value", body);
            }
            true
        }
        SSL3_MT_NEWSESSION_TICKET => ticket(o, ind2, c, body),
        SSL3_MT_ENCRYPTED_EXTENSIONS => {
            extensions(o, ind2, true, mt(SSL3_MT_ENCRYPTED_EXTENSIONS), &mut body)
        }
        SSL3_MT_KEY_UPDATE => {
            if body.len() != 1 {
                o.hex(ind2, "unexpected value", body);
                return false;
            }
            trace_list(o, ind2, body, 1, KEY_UPDATE)
        }
        _ => {
            o.indent(ind2);
            o.puts("Unsupported, hex dump follows:\n");
            o.dump(body, indent.saturating_add(4));
            true
        }
    }
}

/// The connection's state the trace reads, copied with the lock held briefly (no C runs under
/// it).
///
/// # Safety
/// `s` is NULL or a live connection.
unsafe fn conn_of(s: *const SSL) -> Option<(Conn, bool)> {
    // SAFETY: the caller's guarantee.
    let x = unsafe { ssl(s) }?;
    let st = x.state();
    let dtls = st.method.dtls;
    let core = st.drv.tls.as_deref();
    // The negotiated version, once the hello that chooses it has been processed. OpenSSL then
    // also switches the connection's method to that version's.
    let negotiated = core
        .map(|c| c.negotiated())
        .filter(|n| n.cipher.is_some())
        .map(|n| c_int::from(n.version));
    // `s->version`: before that, a flexible method's highest version.
    let version = negotiated.unwrap_or(st.version);
    // `s->method->version`: before that, the method's own (TLS_ANY_VERSION when flexible).
    let method_version = negotiated.unwrap_or(st.method.version);
    // `SSL_CONNECTION_IS_TLS13`.
    let tls13 = !dtls
        && method_version >= rustyssl_abi::TLS1_3_VERSION
        && method_version != rustyssl_abi::TLS_ANY_VERSION;
    // `SSL_USE_SIGALGS`: the method's encryption has the SIGALGS flag (TLS 1.2 and 1.3, DTLS
    // 1.2, and the flexible methods, whose encryption is TLS 1.2's or DTLS 1.2's).
    let use_sigalgs = if dtls {
        method_version == rustyssl_abi::DTLS1_2_VERSION
            || method_version == rustyssl_abi::DTLS_ANY_VERSION
    } else {
        method_version >= rustyssl_abi::TLS1_2_VERSION
    };
    let mkey = core
        .and_then(|c| c.handshake().new_cipher)
        .map_or(0, |cp| cp.mkey);
    let (client_cert_type, server_cert_type) = core.map_or((0, 0), |c| {
        (
            c.negotiated().client_cert_type,
            c.negotiated().server_cert_type,
        )
    });
    // SAFETY: the connection's reference keeps its context alive.
    let ctx = unsafe { ctx_of(&st) };
    let (libctx, propq) = ctx.map_or((ptr::null_mut(), None), |c| (c.libctx, c.propq.clone()));
    let server = st.server;
    Some((
        Conn {
            dtls,
            tls13,
            use_sigalgs,
            version,
            mkey,
            client_cert_type,
            server_cert_type,
            libctx,
            propq,
        },
        server,
    ))
}

/// `SSL_trace`'s work, on a message's octets.
fn trace(o: &Out, c: &Conn, server_end: bool, write_p: bool, content_type: c_int, msg: &[u8]) {
    use rustyssl_abi::{
        DTLS1_RT_HEADER_LENGTH, SSL3_RT_ALERT, SSL3_RT_CHANGE_CIPHER_SPEC, SSL3_RT_HANDSHAKE,
        SSL3_RT_HEADER, SSL3_RT_HEADER_LENGTH, SSL3_RT_INNER_CONTENT_TYPE,
    };
    match content_type {
        SSL3_RT_HEADER => {
            let min = if c.dtls {
                DTLS1_RT_HEADER_LENGTH
            } else {
                SSL3_RT_HEADER_LENGTH
            };
            o.puts(if write_p { "Sent" } else { "Received" });
            if msg.len() < usize::try_from(min).unwrap_or(usize::MAX) {
                o.hex(0, " too short message", msg);
            } else {
                let hvers = int(msg.get(1..).and_then(|r| be(r, 2)).unwrap_or(0));
                o.puts(&format!(
                    " TLS Record\nHeader:\n  Version = {} (0x{hvers:x})\n",
                    trace_str(hvers, VERSION)
                ));
                if c.dtls {
                    let w = |i: usize| msg.get(i..).and_then(|r| be(r, 2)).unwrap_or(0);
                    o.puts(&format!(
                        "  epoch={}, sequence_number={:04x}{:04x}{:04x}\n",
                        w(3),
                        w(5),
                        w(7),
                        w(9)
                    ));
                }
                let ty = msg.first().copied().unwrap_or(0);
                let len = msg
                    .get(msg.len().saturating_sub(2)..)
                    .and_then(|r| be(r, 2))
                    .unwrap_or(0);
                o.puts(&format!(
                    "  Content Type = {} ({ty})\n  Length = {}",
                    trace_str(c_int::from(ty), CONTENT),
                    int(len)
                ));
            }
        }
        SSL3_RT_INNER_CONTENT_TYPE => {
            let ty = msg.first().copied().unwrap_or(0);
            o.puts(&format!(
                "  Inner Content Type = {} ({ty})",
                trace_str(c_int::from(ty), CONTENT)
            ));
        }
        SSL3_RT_HANDSHAKE => {
            if !handshake(o, c, if server_end { write_p } else { !write_p }, msg, 4) {
                o.puts("Message length parse error!\n");
            }
        }
        SSL3_RT_CHANGE_CIPHER_SPEC => {
            if msg == [1] {
                o.puts("    change_cipher_spec (1)\n");
            } else {
                o.hex(4, "unknown value", msg);
            }
        }
        SSL3_RT_ALERT => {
            if let &[level, desc] = msg {
                let lname = alert_string(true, c_int::from(level) << 8);
                let dname = alert_string(false, c_int::from(desc));
                o.puts(&format!(
                    "    Level={lname}({level}), description={dname}({desc})\n"
                ));
            } else {
                o.puts("    Illegal Alert Length\n");
            }
        }
        _ => {}
    }
    o.puts("\n");
}

/// `SSL_alert_type_string_long` / `SSL_alert_desc_string_long`.
fn alert_string(level: bool, value: c_int) -> String {
    let p = if level {
        // SAFETY: no preconditions.
        unsafe { super::io::strings::rustyssl_private_SSL_alert_type_string_long(value) }
    } else {
        // SAFETY: no preconditions.
        unsafe { super::io::strings::rustyssl_private_SSL_alert_desc_string_long(value) }
    };
    if p.is_null() {
        return String::new();
    }
    // SAFETY: a static NUL-terminated string.
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

ffi_export! {
    /// The message callback that prints a readable trace of every record and handshake message
    /// to the BIO given as its argument (`SSL_set_msg_callback_arg`).
    ///
    /// # Safety
    /// `buf` holds `msglen` octets (or is NULL with 0); `ssl` is NULL or a live connection;
    /// `arg` is a live BIO when `ssl` is.
    pub unsafe extern "C" fn rustyssl_private_SSL_trace(write_p: c_int, _version: c_int, content_type: c_int, buf: *const c_void, msglen: usize, ssl: *mut SSL, arg: *mut c_void)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some((c, server_end)) = (unsafe { conn_of(ssl) }) else { return };
        let msg: &[u8] = if buf.is_null() || msglen == 0 {
            &[]
        } else {
            // SAFETY: the caller's `msglen` octets.
            unsafe { core::slice::from_raw_parts(buf.cast::<u8>(), msglen) }
        };
        let o = Out(arg.cast());
        trace(&o, &c, server_end, write_p != 0, content_type, msg);
    }
}
