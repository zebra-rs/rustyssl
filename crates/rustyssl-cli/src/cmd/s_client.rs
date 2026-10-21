//! `openssl s_client` (`apps/s_client.c`).
//!
//! Standard output is upstream's `stdout` `FILE`: `bio_c_out` writes to a buffer flushed
//! where upstream flushes it (and at exit), while the data read from the server goes to the
//! descriptor directly (`raw_write_stdout`), so the two interleave as upstream's do.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use rustyssl_ossl::abi::*;
use rustyssl_ossl::sock::consts::{
    AF_INET, AF_INET6, AF_UNIX, AF_UNSPEC, EISCONN, SOCK_DGRAM, SOCK_STREAM,
};
use rustyssl_ossl::sock::{self, Addr};
use rustyssl_ossl::ssl::{
    self, BioRef, ConfCtx, MdRef, Method, Session, SessionRef, Ssl, SslCtx, SslRef,
};
use rustyssl_ossl::ssl_cb::{self, MsgCallback};
use rustyssl_ossl::verify::VerifyParam;
use rustyssl_ossl::x509::CrlStack;
use rustyssl_ossl::{Bio, err};

use crate::generated::options::S;
use crate::generated::options::s_client::{OPTIONS, Opt};
use crate::lib::opt::{self, Parser, eprintf, fmt_flags, format};
use crate::lib::s_cb::{self, SrpArg};
use crate::lib::s_socket::{self, do_ssl_shutdown};
use crate::lib::{app_libctx, app_rand, apps, engine, io};

/// `BUFSIZZ`.
const BUFSIZZ: usize = 1024 * 16;
/// `S_CLIENT_IRC_READ_TIMEOUT`.
const S_CLIENT_IRC_READ_TIMEOUT: u64 = 8;
/// `DGRAM_RCV_TIMEOUT` and `DGRAM_SND_TIMEOUT` of `apps/timeouts.h`, in microseconds.
const DGRAM_TIMEOUT: i64 = 250_000;
/// `PORT` of `s_apps.h`.
const PORT: &str = "4433";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Proto {
    Off,
    Smtp,
    Pop3,
    Imap,
    Ftp,
    Telnet,
    Xmpp,
    XmppServer,
    Irc,
    Mysql,
    Postgres,
    Lmtp,
    Nntp,
    Sieve,
    Ldap,
}

const SERVICES: [(&str, Proto); 14] = [
    ("smtp", Proto::Smtp),
    ("pop3", Proto::Pop3),
    ("imap", Proto::Imap),
    ("ftp", Proto::Ftp),
    ("xmpp", Proto::Xmpp),
    ("xmpp-server", Proto::XmppServer),
    ("telnet", Proto::Telnet),
    ("irc", Proto::Irc),
    ("mysql", Proto::Mysql),
    ("postgres", Proto::Postgres),
    ("lmtp", Proto::Lmtp),
    ("nntp", Proto::Nntp),
    ("sieve", Proto::Sieve),
    ("ldap", Proto::Ldap),
];

/// `cert_type_rpk`.
const CERT_TYPE_RPK: [u8; 2] = [
    TLSEXT_cert_type_rpk.to_le_bytes()[0],
    TLSEXT_cert_type_x509.to_le_bytes()[0],
];

/// The low octet of `x`.
fn byte(x: u64) -> u8 {
    x.to_le_bytes()[0]
}

/// The globals of `s_client.c` the callbacks read.
struct State {
    c_debug: bool,
    c_showcerts: bool,
    c_quiet: bool,
    keymatexportlabel: Option<String>,
    keymatexportlen: i32,
    bio_c_out: Option<Rc<Bio>>,
    sess_out: Option<String>,
    psksess: Option<Session>,
    psk_identity: String,
    psk_key: Option<String>,
    enable_server_rpk: bool,
    next_proto_on: bool,
}

thread_local! {
    static ST: RefCell<State> = RefCell::new(State {
        c_debug: false,
        c_showcerts: false,
        c_quiet: false,
        keymatexportlabel: None,
        keymatexportlen: 20,
        bio_c_out: None,
        sess_out: None,
        psksess: None,
        psk_identity: "Client_identity".to_owned(),
        psk_key: None,
        enable_server_rpk: false,
        next_proto_on: false,
    });
}

fn bio_c_out() -> Option<Rc<Bio>> {
    ST.with(|s| s.borrow().bio_c_out.clone())
}

fn cout(text: &str) {
    if let Some(b) = bio_c_out() {
        let _ = b.write_all(text.as_bytes());
    }
}

fn eputs(text: &str) {
    if let Some(b) = io::bio_err() {
        let _ = b.write_all(text.as_bytes());
    }
}

/// Standard output as upstream's buffered `stdout`.
fn stdout_buffer() -> Option<Rc<Bio>> {
    thread_local! {
        static OUT: RefCell<Option<Rc<Bio>>> = const { RefCell::new(None) };
    }
    OUT.with(|o| {
        let mut o = o.borrow_mut();
        if o.is_none() {
            let b = Bio::new_buffer()?;
            let fd = Bio::new_fd(1, false)?;
            *o = Some(Rc::new(b.push(fd)));
        }
        o.clone()
    })
}

/// `raw_write_stdout`.
fn raw_write_stdout(buf: &[u8]) -> isize {
    sock::write_fd(1, buf)
}

/// `raw_read_stdin`.
fn raw_read_stdin(buf: &mut [u8]) -> isize {
    sock::read_fd(0, buf)
}

fn psk_client_cb(_s: SslRef<'_>, hint: Option<&str>, identity: &mut [u8], psk: &mut [u8]) -> u32 {
    let (debug, ident, key) = ST.with(|s| {
        let s = s.borrow();
        (s.c_debug, s.psk_identity.clone(), s.psk_key.clone())
    });
    if debug {
        cout("psk_client_cb\n");
    }
    match hint {
        None => {
            if debug {
                cout("NULL received PSK identity hint, continuing anyway\n");
            }
        }
        Some(h) => {
            if debug {
                cout(&format!("Received PSK identity hint '{h}'\n"));
            }
        }
    }
    // BIO_snprintf(identity, max_identity_len, "%s", psk_identity).
    let max = identity.len();
    let n = ident.len();
    if max == 0 || n > max {
        if debug {
            eputs("Error in PSK client callback\n");
        }
        return 0;
    }
    let copy = n.min(max.saturating_sub(1));
    if let (Some(dst), Some(src)) = (identity.get_mut(..copy), ident.as_bytes().get(..copy)) {
        dst.copy_from_slice(src);
    }
    if let Some(z) = identity.get_mut(copy) {
        *z = 0;
    }
    if debug {
        let shown = String::from_utf8_lossy(identity.get(..copy).unwrap_or_default());
        cout(&format!("created identity '{shown}' len={n}\n"));
    }
    let key_hex = key.unwrap_or_default();
    let Some(k) = rustyssl_ossl::crypto::hexstr2buf(&key_hex) else {
        eputs(&format!(
            "Could not convert PSK key '{key_hex}' to buffer\n"
        ));
        return 0;
    };
    if psk.len() > i32::MAX as usize || k.len() > psk.len() {
        eputs(&format!(
            "psk buffer of callback is too small ({}) for key ({})\n",
            psk.len(),
            k.len()
        ));
        return 0;
    }
    if let Some(dst) = psk.get_mut(..k.len()) {
        dst.copy_from_slice(&k);
    }
    if debug {
        cout(&format!("created PSK len={}\n", k.len()));
    }
    u32::try_from(k.len()).unwrap_or(0)
}

/// `tls13_aes128gcmsha256_id`.
const TLS13_AES128GCMSHA256_ID: [u8; 2] = [0x13, 0x01];

fn psk_use_session_cb(s: SslRef<'_>, md: Option<MdRef>) -> Result<Option<(Session, Vec<u8>)>, ()> {
    let (psksess, ident, key) = ST.with(|st| {
        let st = st.borrow();
        (
            st.psksess.as_ref().map(|p| p.r().up_ref()),
            st.psk_identity.clone(),
            st.psk_key.clone(),
        )
    });
    let usesess = match psksess {
        Some(Some(sess)) => sess,
        Some(None) => return Err(()),
        None => {
            let key_hex = key.unwrap_or_default();
            let Some(k) = rustyssl_ossl::crypto::hexstr2buf(&key_hex) else {
                eputs(&format!(
                    "Could not convert PSK key '{key_hex}' to buffer\n"
                ));
                return Err(());
            };
            // We default to SHA-256.
            let Some(cipher) = s.cipher_find(&TLS13_AES128GCMSHA256_ID) else {
                eputs("Error finding suitable ciphersuite\n");
                return Err(());
            };
            let sess = Session::new().ok_or(())?;
            let r = sess.r();
            if !r.set1_master_key(&k)
                || !r.set_cipher(cipher)
                || !r.set_protocol_version(TLS1_3_VERSION)
            {
                return Err(());
            }
            sess
        }
    };
    let cipher = usesess.r().cipher().ok_or(())?;
    if md.is_some() && cipher.handshake_digest() != md {
        // PSK not usable, ignore it.
        return Ok(None);
    }
    Ok(Some((usesess, ident.into_bytes())))
}

fn ssl_servername_cb(s: SslRef<'_>, _ad: &mut i32) -> i32 {
    if s.servername_type() == -1 {
        eputs("Can't use SSL_get_servername\n");
    }
    SSL_TLSEXT_ERR_OK
}

fn next_proto_cb(_s: SslRef<'_>, input: &[u8]) {
    if ST.with(|s| s.borrow().c_quiet) {
        return;
    }
    let Some(out) = bio_c_out() else { return };
    let _ = out.write_all(b"Protocols advertised by server: ");
    let mut i = 0usize;
    while let Some(&l) = input.get(i) {
        if i > 0 {
            let _ = out.write_all(b", ");
        }
        let end = (i + 1 + usize::from(l)).min(input.len());
        let _ = out.write_all(input.get(i + 1..end).unwrap_or_default());
        i += usize::from(l) + 1;
    }
    let _ = out.write_all(b"\n");
}

fn serverinfo_cli_parse_cb(_s: SslRef<'_>, ext_type: u32, input: &[u8]) -> i32 {
    // Reconstruct the type/len fields prior to the extension data.
    let inlen = input.len() & 0xffff;
    let mut ext = Vec::with_capacity(4 + inlen);
    let l = inlen as u64;
    let t = u64::from(ext_type);
    ext.extend_from_slice(&[byte(t >> 8), byte(t), byte(l >> 8), byte(l)]);
    ext.extend_from_slice(input.get(..inlen).unwrap_or_default());
    let name = format!("SERVERINFO FOR EXTENSION {ext_type}");
    if let Some(out) = bio_c_out() {
        ssl::pem_write(&out, &name, &ext);
    }
    1
}

/// `hexdecode`: hex with optional white space; `None` on a bad digit or an odd count.
fn hexdecode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut byte = 0u8;
    let mut nibble = false;
    for c in input.bytes() {
        if c.is_ascii_whitespace() {
            continue;
        }
        let x = ssl::hexchar2int(c);
        let Ok(x) = u8::try_from(x) else {
            return None;
        };
        byte |= x;
        nibble = !nibble;
        if !nibble {
            out.push(byte);
            byte = 0;
        } else {
            byte <<= 4;
        }
    }
    if nibble {
        return None;
    }
    Some(out)
}

/// `checked_uint8`: a decimal 0..255 followed by white space; the rest after the space.
fn checked_uint8(input: &str) -> Option<(u8, &str)> {
    let digits_end = input
        .char_indices()
        .find(|&(i, c)| !(c.is_ascii_digit() || (i == 0 && (c == '-' || c == '+'))))
        .map_or(input.len(), |(i, _)| i);
    let (num, rest) = input.split_at(digits_end);
    let v: i64 = num.parse().ok()?;
    if !rest.starts_with(|c: char| c.is_ascii_whitespace()) {
        return None;
    }
    let b = u8::try_from(v).ok()?;
    Some((b, rest.trim_start()))
}

fn tlsa_import_rr(con: SslRef<'_>, rrdata: &str, prog: &str) -> bool {
    let mut cp = rrdata;
    let mut vals = [0u8; 3];
    for (i, name) in ["usage", "selector", "mtype"].iter().enumerate() {
        match checked_uint8(cp) {
            Some((v, rest)) => {
                if let Some(slot) = vals.get_mut(i) {
                    *slot = v;
                }
                cp = rest;
            }
            None => {
                eputs(&format!(
                    "{prog}: warning: bad TLSA {name} field in: {rrdata}\n"
                ));
                return false;
            }
        }
    }
    let data = match hexdecode(cp) {
        Some(d) if !d.is_empty() => d,
        _ => {
            eputs(&format!(
                "{prog}: warning: bad TLSA data field in: {rrdata}\n"
            ));
            return false;
        }
    };
    let ret = con.dane_tlsa_add(vals[0], vals[1], vals[2], &data);
    if ret == 0 {
        io::print_errors();
        eputs(&format!(
            "{prog}: warning: unusable TLSA rrdata: {rrdata}\n"
        ));
        return false;
    }
    if ret < 0 {
        io::print_errors();
        eputs(&format!(
            "{prog}: warning: error loading TLSA rrdata: {rrdata}\n"
        ));
        return false;
    }
    true
}

fn tlsa_import_rrset(con: SslRef<'_>, rrset: &[String], prog: &str) -> bool {
    let mut count = 0;
    for rr in rrset {
        if tlsa_import_rr(con, rr, prog) {
            count += 1;
        }
    }
    count > 0
}

fn new_session_cb(s: SslRef<'_>, sess: SessionRef<'_>) -> i32 {
    if let Some(f) = ST.with(|st| st.borrow().sess_out.clone()) {
        match Bio::new_file(&f, "w") {
            None => eputs(&format!("Error writing session file {f}\n")),
            Some(b) => {
                sess.write_pem(&b);
            }
        }
    }
    // Session data is dumped on connection for TLS 1.2 and below, and on arrival of the
    // NewSessionTicket for TLS 1.3.
    if s.version() == TLS1_3_VERSION
        && let Some(out) = bio_c_out()
    {
        let _ = out.write_all(b"---\nPost-Handshake New Session Ticket arrived:\n");
        sess.print(&out);
        let _ = out.write_all(b"---\n");
    }
    // Always "fail", so that the reference is freed again.
    0
}

fn ocsp_resp_cb(s: SslRef<'_>) -> i32 {
    let Some(arg) = bio_c_out() else { return 1 };
    if s.version() >= TLS1_3_VERSION {
        let resps = s.tlsext_status_ocsp_resp_ex();
        let _ = arg.write_all(b"OCSP responses: ");
        let Some(resps) = resps else {
            let _ = arg.write_all(b"no responses sent\n");
            return 1;
        };
        let _ = arg.write_all(format!("number of responses: {}", resps.len()).as_bytes());
        for r in &resps {
            print_ocsp_response(&arg, r.as_deref());
        }
    } else {
        let resp = s.tlsext_status_ocsp_resp();
        let _ = arg.write_all(b"OCSP response: ");
        let Some(der) = resp else {
            let _ = arg.write_all(b"no OCSP response received\n");
            return 1;
        };
        let mut b = Vec::new();
        b.extend_from_slice(b"\n======================================\n");
        if let Some(mem) = Bio::new_mem() {
            if !ssl::ocsp_response_print(&mem, &der, 0) {
                let _ = arg.write_all(b"OCSP response parse error\n");
                ssl::bio_dump_indent(&arg, &der, 4);
                return 0;
            }
            b.extend_from_slice(&mem.read_to_end());
        }
        b.extend_from_slice(b"\n======================================\n");
        let _ = arg.write_all(&b);
    }
    1
}

fn print_ocsp_response(bp: &Bio, der: Option<&[u8]>) {
    let Some(der) = der else {
        let _ = bp.write_all(b"no OCSP response to print\n");
        return;
    };
    let _ = bp.write_all(b"\n======================================\n");
    ssl::ocsp_response_print(bp, der, 0);
    let _ = bp.write_all(b"\n======================================\n");
}

/// `ldap_ExtendedResponse_parse`: the LDAP result code, or -1.
fn ldap_extended_response_parse(buf: &[u8]) -> i64 {
    let mut cur = buf;
    // SEQUENCE.
    let (inf, len, tag, _, used) = ssl::asn1_get_object(cur, i64::try_from(cur.len()).unwrap_or(0));
    cur = cur.get(used..).unwrap_or_default();
    let rem = i64::try_from(cur.len()).unwrap_or(0);
    if inf != V_ASN1_CONSTRUCTED || tag != V_ASN1_SEQUENCE || len > rem {
        eputs("Unexpected LDAP response\n");
        return -1;
    }
    let rem = len;
    // MessageID.
    let (inf, len, tag, _, used) = ssl::asn1_get_object(cur, rem);
    cur = cur.get(used..).unwrap_or_default();
    if inf != V_ASN1_UNIVERSAL
        || tag != V_ASN1_INTEGER
        || len > i64::try_from(cur.len()).unwrap_or(0)
    {
        eputs("No MessageID\n");
        return -1;
    }
    cur = cur
        .get(usize::try_from(len).unwrap_or(0)..)
        .unwrap_or_default();
    // [APPLICATION 24].
    let (inf, _, tag, xclass, used) =
        ssl::asn1_get_object(cur, i64::try_from(cur.len()).unwrap_or(0));
    cur = cur.get(used..).unwrap_or_default();
    if inf != V_ASN1_CONSTRUCTED || xclass != V_ASN1_APPLICATION || tag != 24 {
        eputs("Not ExtendedResponse\n");
        return -1;
    }
    // resultCode.
    let (inf, len, tag, _, used) = ssl::asn1_get_object(cur, i64::try_from(cur.len()).unwrap_or(0));
    cur = cur.get(used..).unwrap_or_default();
    if inf != V_ASN1_UNIVERSAL
        || tag != V_ASN1_ENUMERATED
        || len == 0
        || len > i64::try_from(cur.len()).unwrap_or(0)
    {
        eputs("Not LDAPResult\n");
        return -1;
    }
    let mut ret: i64 = 0;
    for &b in cur.iter().take(usize::try_from(len).unwrap_or(0)) {
        ret = (ret << 8) | i64::from(b);
    }
    ret
}

/// `is_dNS_name`: whether `host` looks like a DNS name with two or more labels.
fn is_dns_name(host: &str) -> bool {
    const MAX_LABEL_LENGTH: usize = 63;
    let h = host.as_bytes();
    let length = h.len();
    let mut isdnsname = false;
    let mut label_length = 0usize;
    let mut all_numeric = true;
    let mut i = 0;
    while i < length && label_length < MAX_LABEL_LENGTH {
        let c = h.get(i).copied().unwrap_or(0);
        if c.is_ascii_alphabetic() || c == b'_' {
            label_length += 1;
            all_numeric = false;
            i += 1;
            continue;
        }
        if c.is_ascii_digit() {
            label_length += 1;
            i += 1;
            continue;
        }
        // Dot and hyphen cannot be first or last.
        if i > 0 && i < length - 1 {
            if c == b'-' {
                label_length += 1;
                i += 1;
                continue;
            }
            let next = h.get(i + 1).copied().unwrap_or(0);
            let prev = h.get(i - 1).copied().unwrap_or(0);
            if c == b'.' && next != b'.' && prev != b'-' && next != b'-' {
                label_length = 0;
                isdnsname = true;
                i += 1;
                continue;
            }
        }
        isdnsname = false;
        break;
    }
    isdnsname && !all_numeric && label_length != MAX_LABEL_LENGTH
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CmdMode {
    None,
    Basic,
    Advanced,
}

/// What processing the user's data asks for.
enum UserData {
    BadArgument,
    Shut,
    Restart,
    NoData,
    Continue,
}

/// `struct user_data_st`.
struct UserBuf {
    buf: Vec<u8>,
    buflen: usize,
    bufoff: usize,
    mode: CmdMode,
    isfin: bool,
}

impl UserBuf {
    fn new(mode: CmdMode) -> Self {
        Self {
            buf: vec![0; BUFSIZZ],
            buflen: 0,
            bufoff: 0,
            mode,
            isfin: false,
        }
    }

    fn add(&mut self, i: usize) -> bool {
        // One byte stays for a NUL terminator.
        if self.buflen != 0 || i >= self.buf.len() {
            return false;
        }
        self.buflen = i;
        self.bufoff = 0;
        true
    }

    fn has_data(&self) -> bool {
        self.buflen > 0
    }
}

fn user_data_execute(con: SslRef<'_>, ud: &mut UserBuf, cmd: u8, arg: Option<&str>) -> UserData {
    match cmd {
        b'h' => {
            // Only in advanced mode, so the advanced help.
            let mut t = String::from("Enter text to send to the peer followed by <enter>\n");
            t.push_str("To issue a command insert {cmd} or {cmd:arg} anywhere in the text\n");
            t.push_str("Entering {{ will send { to the peer\n");
            t.push_str("The following commands are available\n");
            t.push_str("  {help}: Get this help text\n");
            t.push_str("  {quit}: Close the connection to the peer\n");
            t.push_str("  {reconnect}: Reconnect to the peer\n");
            if con.is_quic() {
                t.push_str("  {fin}: Send FIN on the stream. No further writing is possible\n");
            } else if con.version() == TLS1_3_VERSION {
                t.push_str("  {keyup:req|noreq}: Send a Key Update message\n");
                t.push_str("                     Arguments:\n");
                t.push_str("                     req   = peer update requested (default)\n");
                t.push_str("                     noreq = peer update not requested\n");
            } else {
                t.push_str("  {reneg}: Attempt to renegotiate\n");
            }
            t.push('\n');
            eputs(&t);
            return UserData::NoData;
        }
        b'q' => {
            eputs("DONE\n");
            return UserData::Shut;
        }
        b'c' => {
            eputs("RECONNECTING\n");
            do_ssl_shutdown(con);
            con.set_connect_state();
            sock::closesocket(con.fd());
            return UserData::Restart;
        }
        b'r' => {
            eputs("RENEGOTIATING\n");
            if con.renegotiate() != 0 {
                return UserData::Continue;
            }
        }
        b'k' => {
            let a = arg.unwrap_or_default();
            let t = if a.eq_ignore_ascii_case("req") {
                SSL_KEY_UPDATE_REQUESTED
            } else if a.eq_ignore_ascii_case("noreq") {
                SSL_KEY_UPDATE_NOT_REQUESTED
            } else {
                return UserData::BadArgument;
            };
            eputs("KEYUPDATE\n");
            if con.key_update(t) {
                return UserData::Continue;
            }
        }
        b'f' if con.stream_conclude() => {
            ud.isfin = true;
            return UserData::NoData;
        }
        _ => {}
    }
    eputs("ERROR\n");
    UserData::Shut
}

/// `user_data_process`: what to send (offset and length in the buffer), and what to do.
fn user_data_process(
    con: SslRef<'_>,
    ud: &mut UserBuf,
    len: &mut usize,
    off: &mut usize,
) -> UserData {
    if ud.buflen == 0 {
        *len = 0;
        *off = 0;
        return UserData::NoData;
    }
    let mut buf_start = ud.bufoff;
    let mut outlen = ud.buflen;
    if ud.mode == CmdMode::Basic {
        let c = ud.buf.get(buf_start).copied().unwrap_or(0);
        let cmd = match c {
            b'Q' => Some((b'q', None)),
            b'C' => Some((b'c', None)),
            b'R' => Some((b'r', None)),
            b'K' => Some((b'k', Some("req"))),
            b'k' => Some((b'k', Some("noreq"))),
            _ => None,
        };
        if let Some((cmd, arg)) = cmd {
            ud.buflen = 0;
            ud.bufoff = 0;
            *len = 0;
            *off = 0;
            return user_data_execute(con, ud, cmd, arg);
        }
    } else if ud.mode == CmdMode::Advanced {
        // The command text is NUL-terminated at the data's end.
        if let Some(z) = ud.buf.get_mut(buf_start + outlen) {
            *z = 0;
        }
        let find = |buf: &[u8], from: usize, c: u8| -> Option<usize> {
            let end = buf
                .iter()
                .skip(from)
                .position(|&b| b == 0)
                .map_or(buf.len(), |p| from + p);
            buf.get(from..end)?
                .iter()
                .position(|&b| b == c)
                .map(|p| from + p)
        };
        let mut cmd_start = find(&ud.buf, buf_start, b'{');
        while cmd_start == Some(buf_start) && ud.buf.get(buf_start + 1) == Some(&b'{') {
            // The "{" is escaped, so skip it.
            let cs = buf_start + 2;
            buf_start += 1;
            ud.bufoff += 1;
            ud.buflen -= 1;
            outlen -= 1;
            cmd_start = find(&ud.buf, cs, b'{');
        }
        if cmd_start == Some(buf_start) {
            // Command detected.
            let cs = buf_start;
            let Some(cmd_end) = find(&ud.buf, cs, b'}') else {
                // Malformed command.
                if let Some(z) = ud.buf.get_mut(cs + outlen - 1) {
                    *z = 0;
                }
                let end = ud
                    .buf
                    .iter()
                    .skip(cs)
                    .position(|&b| b == 0)
                    .map_or(ud.buf.len(), |p| cs + p);
                let text =
                    String::from_utf8_lossy(ud.buf.get(cs..end).unwrap_or_default()).into_owned();
                eputs(&format!(
                    "ERROR PROCESSING COMMAND. REST OF LINE IGNORED: {text}\n"
                ));
                ud.buflen = 0;
                ud.bufoff = 0;
                *len = 0;
                *off = 0;
                return UserData::NoData;
            };
            let inner = String::from_utf8_lossy(ud.buf.get(cs + 1..cmd_end).unwrap_or_default())
                .into_owned();
            let (cmd_name, mut arg) = match inner.split_once(':') {
                Some((c, a)) => (c.to_owned(), Some(a.to_owned())),
                None => (inner.clone(), None),
            };
            let mut cmd = None;
            if cmd_name.eq_ignore_ascii_case("help") {
                cmd = Some(b'h');
            } else if cmd_name.eq_ignore_ascii_case("quit") {
                cmd = Some(b'q');
            } else if cmd_name.eq_ignore_ascii_case("reconnect") {
                cmd = Some(b'c');
            } else if con.is_quic() && cmd_name.eq_ignore_ascii_case("fin") {
                cmd = Some(b'f');
            }
            if con.version() == TLS1_3_VERSION {
                if cmd_name.eq_ignore_ascii_case("keyup") {
                    cmd = Some(b'k');
                    if arg.is_none() {
                        arg = Some("req".to_owned());
                    }
                }
            } else if cmd_name.eq_ignore_ascii_case("reneg") {
                cmd = Some(b'r');
            }
            let ret = match cmd {
                None => {
                    eputs(&format!("UNRECOGNISED COMMAND (IGNORED): {cmd_name}\n"));
                    UserData::NoData
                }
                Some(c) => match user_data_execute(con, ud, c, arg.as_deref()) {
                    UserData::BadArgument => {
                        eputs(&format!(
                            "BAD ARGUMENT (COMMAND IGNORED): {}\n",
                            arg.as_deref().unwrap_or("<NULL>")
                        ));
                        UserData::NoData
                    }
                    r => r,
                },
            };
            let oldoff = ud.bufoff;
            ud.bufoff = cmd_end + 1;
            ud.buflen -= ud.bufoff - oldoff;
            if cs == 0 && ud.buflen == 1 && ud.buf.get(ud.bufoff) == Some(&b'\n') {
                // The command was the whole line: the final newline is suppressed.
                ud.bufoff = 0;
                ud.buflen = 0;
            }
            *len = 0;
            *off = 0;
            return ret;
        } else if let Some(c) = cmd_start {
            // A command later on the line: send what comes before it first.
            outlen = c - buf_start;
        }
    }
    if ud.isfin {
        ud.buflen = 0;
        ud.bufoff = 0;
        *len = 0;
        *off = 0;
        return UserData::NoData;
    }
    *len = outlen;
    *off = ud.bufoff;
    ud.buflen -= outlen;
    if ud.buflen == 0 {
        ud.bufoff = 0;
    } else {
        ud.bufoff += outlen;
    }
    UserData::Continue
}

fn print_cert_key_info(bio: &Bio, cert: &rustyssl_ossl::x509::Cert) {
    let Some(pkey) = ssl::cert_pubkey(cert) else {
        return;
    };
    let keyalg = pkey
        .type_name()
        .or_else(|| ssl::nid2ln(pkey.base_id()))
        .unwrap_or_else(|| "<NULL>".to_owned());
    let curve = if pkey.id() == EVP_PKEY_EC {
        pkey.group_name()
    } else {
        None
    };
    let sigalg = ssl::nid2ln(ssl::cert_signature_nid(cert)).unwrap_or_else(|| "<NULL>".to_owned());
    let text = match curve {
        Some(c) => format!("   a:PKEY: {keyalg}, ({c}); sigalg: {sigalg}\n"),
        None => format!(
            "   a:PKEY: {keyalg}, {} (bit); sigalg: {sigalg}\n",
            pkey.bits()
        ),
    };
    let _ = bio.write_all(text.as_bytes());
}

fn print_stuff(bio: &Bio, s: SslRef<'_>, full: bool) {
    let (showcerts, label, explen, server_rpk, next_proto_on) = ST.with(|st| {
        let st = st.borrow();
        (
            st.c_showcerts,
            st.keymatexportlabel.clone(),
            st.keymatexportlen,
            st.enable_server_rpk,
            st.next_proto_on,
        )
    });
    let p = |t: &str| {
        let _ = bio.write_all(t.as_bytes());
    };
    let istls13 = s.version() == TLS1_3_VERSION;
    let mut peer = None;
    if full {
        let mut got_a_chain = false;
        if let Some(sk) = s.peer_cert_chain() {
            got_a_chain = true;
            p("---\nCertificate chain\n");
            for (i, c) in sk.iter().enumerate() {
                p(&format!("{i:2} s:"));
                rustyssl_ossl::x509::name_print_ex(bio, c.subject_name(), 0, apps::get_nameopt());
                p("\n");
                p("   i:");
                rustyssl_ossl::x509::name_print_ex(bio, c.issuer_name(), 0, apps::get_nameopt());
                p("\n");
                print_cert_key_info(bio, c);
                p("   v:NotBefore: ");
                ssl::print_cert_time(bio, c, false);
                p("; NotAfter: ");
                ssl::print_cert_time(bio, c, true);
                p("\n");
                if showcerts {
                    ssl::write_cert_pem(bio, c);
                }
            }
        }
        p("---\n");
        peer = s.peer_certificate();
        match &peer {
            Some(x) => {
                p("Server certificate\n");
                // Redundant if we showed the whole chain.
                if !(showcerts && got_a_chain) {
                    ssl::write_cert_pem(bio, x);
                }
                apps::dump_cert_text(bio, x);
            }
            None => p("no peer certificate available\n"),
        }
        // RPK information only when configured.
        if s.negotiated_client_cert_type() == TLSEXT_cert_type_rpk {
            p("Client-to-server raw public key negotiated\n");
        }
        if s.negotiated_server_cert_type() == TLSEXT_cert_type_rpk {
            p("Server-to-client raw public key negotiated\n");
        }
        if server_rpk {
            match s.peer_rpk() {
                Some(k) => {
                    p("Server raw public key\n");
                    k.print_public(bio, 2);
                }
                None => p("no peer rpk available\n"),
            }
        }
        s_cb::print_ca_names(bio, s);
        s_cb::ssl_print_sigalgs(bio, s);
        s_cb::ssl_print_tmp_key(bio, s);
        // No SCTs come with an anonymous or resumed session.
        if peer.is_some() && !s.session_reused() && s.ct_is_enabled() {
            s.print_peer_scts(bio);
        }
        let rb = s.rbio().map_or(0, |b| b.number_read());
        let wb = s.wbio().map_or(0, |b| b.number_written());
        p(&format!(
            "---\nSSL handshake has read {rb} bytes and written {wb} bytes\n"
        ));
    }
    s_cb::print_verify_detail(s, bio);
    p(if s.session_reused() {
        "---\nReused, "
    } else {
        "---\nNew, "
    });
    let c = s.current_cipher();
    let cver = c
        .and_then(|c| c.version())
        .unwrap_or_else(|| "(NONE)".to_owned());
    let cname = c
        .and_then(|c| c.name())
        .unwrap_or_else(|| "(NONE)".to_owned());
    p(&format!("{cver}, Cipher is {cname}\n"));
    p(&format!("Protocol: {}\n", s.version_str()));
    if let Some(x) = &peer {
        let bits = ssl::cert_pubkey(x).map_or(0, |k| k.bits());
        p(&format!("Server public key is {bits} bit\n"));
    }
    s_cb::ssl_print_secure_renegotiation_notes(bio, s);
    let (comp, exp) = s.compression();
    p(&format!(
        "Compression: {}\n",
        comp.as_deref().unwrap_or("NONE")
    ));
    p(&format!(
        "Expansion: {}\n",
        exp.as_deref().unwrap_or("NONE")
    ));
    if next_proto_on && let Some(status) = ssl_cb::next_proto_status() {
        let proto = s.next_proto_negotiated().unwrap_or_default();
        p(&format!("Next protocol: ({status}) "));
        let _ = bio.write_all(&proto);
        p("\n");
    } else if next_proto_on {
        let proto = s.next_proto_negotiated().unwrap_or_default();
        p("Next protocol: (-1) ");
        let _ = bio.write_all(&proto);
        p("\n");
    }
    let alpn = s.alpn_selected();
    if alpn.is_empty() {
        p("No ALPN negotiated\n");
    } else {
        p("ALPN protocol: ");
        let _ = bio.write_all(&alpn);
        p("\n");
    }
    if let Some(name) = s.selected_srtp_profile() {
        p(&format!("SRTP Extension negotiated, profile={name}\n"));
    }
    if istls13 {
        match s.early_data_status() {
            SSL_EARLY_DATA_NOT_SENT => p("Early data was not sent\n"),
            SSL_EARLY_DATA_REJECTED => p("Early data was rejected\n"),
            SSL_EARLY_DATA_ACCEPTED => p("Early data was accepted\n"),
            _ => {}
        }
        // The verification result now too: a NewSessionTicket may come late or never.
        let vr = s.verify_result();
        p(&format!(
            "Verify return code: {vr} ({})\n",
            ssl::verify_cert_error_string(vr)
        ));
    } else if let Some(sess) = s.session() {
        // In TLSv1.3 we do this on arrival of a NewSessionTicket.
        sess.print(bio);
    }
    if s.session().is_some()
        && let Some(label) = &label
    {
        p("Keying material exporter:\n");
        p(&format!("    Label: '{label}'\n"));
        p(&format!("    Length: {explen} bytes\n"));
        match s.export_keying_material(usize::try_from(explen).unwrap_or(0), label) {
            None => p("    Error\n"),
            Some(m) => {
                let hex: String = m.iter().map(|b| format!("{b:02X}")).collect();
                p(&format!("    Keying material: {hex}\n"));
            }
        }
    }
    p("---\n");
    // Flush, or debugging output gets mixed with the HTTP response.
    bio.flush();
}

/// What ends the connection loop.
enum Exit {
    /// `goto shut`.
    Shut,
    /// `goto end`.
    End,
}

pub fn main(argv: &[String]) -> i32 {
    let stdout = stdout_buffer();
    let ret = run(argv);
    // stdout is flushed at exit.
    if let Some(o) = &stdout {
        o.flush();
    }
    ST.with(|s| {
        let mut s = s.borrow_mut();
        s.bio_c_out = None;
        s.psksess = None;
    });
    ret
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum ConnectType {
    Inet,
    Unix,
    Unknown,
}

#[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
fn run(argv: &[String]) -> i32 {
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let ret = 1;
    let Some(vpm) = VerifyParam::new() else {
        eprintf!("{prog}: out of memory\n");
        return 1;
    };
    let Some(cctx) = ConfCtx::new() else {
        eprintf!("{prog}: out of memory\n");
        return 1;
    };
    cctx.set_flags((SSL_CONF_FLAG_CLIENT | SSL_CONF_FLAG_CMDLINE).cast_unsigned());

    let mut ssl_args: Vec<(String, Option<String>)> = Vec::new();
    let mut exc: s_cb::ExcertList = None;
    let mut meth = Method::tls_client();
    let (mut ca_path, mut ca_file, mut ca_store): (Option<String>, Option<String>, Option<String>) =
        (None, None, None);
    let (mut proxystr, mut proxyuser, mut proxypassarg): (
        Option<String>,
        Option<String>,
        Option<String>,
    ) = (None, None, None);
    let (mut connectstr, mut bindstr): (Option<String>, Option<String>) = (None, None);
    let (mut cert_file, mut key_file, mut chain_file): (
        Option<String>,
        Option<String>,
        Option<String>,
    ) = (None, None, None);
    let (mut ch_ca_path, mut ch_ca_file, mut ch_ca_store): (
        Option<String>,
        Option<String>,
        Option<String>,
    ) = (None, None, None);
    let mut host: Option<String> = None;
    let mut port: Option<String> = Some(PORT.to_owned());
    let mut passarg: Option<String> = None;
    let (mut vfy_ca_path, mut vfy_ca_file, mut vfy_ca_store): (
        Option<String>,
        Option<String>,
        Option<String>,
    ) = (None, None, None);
    let mut req_ca_file: Option<String> = None;
    let (mut sess_in, mut crl_file): (Option<String>, Option<String>) = (None, None);
    let mut protohost: Option<String> = None;
    let (mut no_ca_path, mut no_ca_file, mut no_ca_store) = (false, false, false);
    let mut build_chain = false;
    let mut cert_format = format::UNDEF;
    let mut key_format = format::UNDEF;
    let mut crlf = false;
    let mut full_log = 1;
    let mut prexit = false;
    let mut nointeractive = false;
    let mut sdebug = 0;
    let mut reconnect = 0;
    let mut verify = SSL_VERIFY_NONE;
    let mut vpmtouched = 0;
    let mut nbio_test = false;
    let mut state = false;
    let mut cmdmode = CmdMode::Basic;
    let mut socket_family = AF_UNSPEC;
    let mut socket_type = SOCK_STREAM;
    let protocol = 0;
    let mut starttls_proto = Proto::Off;
    let mut crl_format = format::UNDEF;
    let mut crl_download = false;
    let mut read_buf_len = 0;
    let mut fallback_scsv = false;
    let mut enable_timeouts = false;
    let mut socket_mtu: i64 = 0;
    let mut e = None;
    let mut ssl_client_engine = None;
    let mut servername: Option<String> = None;
    let mut noservername = false;
    let mut alpn_in: Option<String> = None;
    let mut ssl_config: Option<String> = None;
    let mut serverinfo_types: Vec<u16> = Vec::new();
    let mut next_proto_neg_in: Option<String> = None;
    let mut srppass: Option<String> = None;
    let mut srp_lateuser = false;
    let mut srp_arg = SrpArg {
        strength: 1024,
        ..SrpArg::default()
    };
    let mut srtp_profiles: Option<String> = None;
    let mut ctlog_file: Option<String> = None;
    let mut ct_validation = false;
    let (mut min_version, mut max_version, mut prot_opt, mut no_prot_opt) = (0, 0, 0, 0);
    let mut async_ = false;
    let (mut max_send_fragment, mut split_send_fragment, mut max_pipelines) = (0u32, 0u32, 0u32);
    let mut connect_type = ConnectType::Unknown;
    let mut count4or6 = 0;
    let mut maxfraglen: u8 = 0;
    let (mut c_nbio, mut c_msg, mut c_ign_eof, mut c_brief) = (false, 0, false, false);
    let mut c_tlsextdebug = false;
    let mut c_status_req = false;
    let mut bio_c_msg: Option<Rc<Bio>> = None;
    let (mut keylog_file, mut early_data_file): (Option<String>, Option<String>) = (None, None);
    let (mut isdtls, mut isquic) = (false, false);
    let mut psksessf: Option<String> = None;
    let mut enable_pha = false;
    let mut enable_client_rpk = false;
    let mut ignore_unexpected_eof = false;
    let mut tfo = false;
    let mut dane_tlsa_domain: Option<String> = None;
    let mut dane_tlsa_rrset: Option<Vec<String>> = None;
    let mut dane_ee_no_name = false;
    let mut keymatexportlabel: Option<String> = None;
    let mut keymatexportlen = 20;
    let mut c_quiet = false;
    let mut c_debug = false;
    let mut c_showcerts = false;
    let mut sess_out: Option<String> = None;
    let mut psk_identity = "Client_identity".to_owned();
    let mut psk_key: Option<String> = None;
    let mut enable_server_rpk = false;

    let opthelp = |prog: &str| {
        eprintf!("{prog}: Use -help for summary.\n");
    };
    loop {
        let o = p.next();
        if o == Opt::EOF {
            break;
        }
        // Check for intermixing flags.
        let is_inet = matches!(o, Opt::_4 | Opt::_6 | Opt::HOST | Opt::PORT | Opt::CONNECT);
        if connect_type == ConnectType::Unix && is_inet {
            eprintf!("{prog}: Intermixed protocol flags (unix and internet domains)\n");
            return 1;
        }
        if connect_type == ConnectType::Inet && o == Opt::UNIX {
            eprintf!("{prog}: Intermixed protocol flags (internet and unix domains)\n");
            return 1;
        }
        let is_prot = matches!(
            o,
            Opt::SSL3
                | Opt::TLS1
                | Opt::TLS1_1
                | Opt::TLS1_2
                | Opt::TLS1_3
                | Opt::DTLS
                | Opt::DTLS1
                | Opt::DTLS1_2
                | Opt::QUIC
        );
        if is_prot {
            prot_opt += 1;
            if prot_opt > 1 {
                eprintf!("Cannot supply multiple protocol flags\n");
                return 1;
            }
        }
        if matches!(
            o,
            Opt::OPT_S(S::NOSSL3 | S::NOTLS1 | S::NOTLS1_1 | S::NOTLS1_2 | S::NOTLS1_3)
        ) {
            no_prot_opt += 1;
        }
        if prot_opt == 1 && no_prot_opt > 0 {
            eprintf!("Cannot supply both a protocol flag and '-no_<prot>'\n");
            return 1;
        }
        let arg = p.arg().to_owned();
        match o {
            Opt::EOF => break,
            Opt::ERR => {
                opthelp(&prog);
                return 1;
            }
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::_4 => {
                connect_type = ConnectType::Inet;
                socket_family = AF_INET;
                count4or6 += 1;
            }
            Opt::_6 => {
                connect_type = ConnectType::Inet;
                socket_family = AF_INET6;
                count4or6 += 1;
            }
            Opt::HOST => {
                connect_type = ConnectType::Inet;
                host = Some(arg);
            }
            Opt::PORT => {
                connect_type = ConnectType::Inet;
                port = Some(arg);
            }
            Opt::CONNECT => {
                connect_type = ConnectType::Inet;
                connectstr = Some(arg);
            }
            Opt::BIND => bindstr = Some(arg),
            Opt::PROXY => proxystr = Some(arg),
            Opt::PROXY_USER => proxyuser = Some(arg),
            Opt::PROXY_PASS => proxypassarg = Some(arg),
            Opt::UNIX => {
                connect_type = ConnectType::Unix;
                socket_family = AF_UNIX;
                host = Some(arg);
            }
            Opt::XMPPHOST | Opt::PROTOHOST => protohost = Some(arg),
            Opt::VERIFY => {
                verify = SSL_VERIFY_PEER;
                let d = apps::atoi(&arg);
                s_cb::set_verify_args(|a| a.depth = d);
                if !c_quiet {
                    eprintf!("verify depth is {d}\n");
                }
            }
            Opt::CERT => cert_file = Some(arg),
            Opt::NAMEOPT => {
                if !apps::set_nameopt(Some(&arg)) {
                    return 1;
                }
            }
            Opt::CRL => crl_file = Some(arg),
            Opt::CRL_DOWNLOAD => crl_download = true,
            Opt::SESS_OUT => sess_out = Some(arg),
            Opt::SESS_IN => sess_in = Some(arg),
            Opt::CERTFORM => match opt::parse_format(&arg, fmt_flags::ANY) {
                Some(f) => cert_format = f,
                None => {
                    opthelp(&prog);
                    return 1;
                }
            },
            Opt::CRLFORM => match opt::parse_format(&arg, fmt_flags::PEMDER) {
                Some(f) => crl_format = f,
                None => {
                    opthelp(&prog);
                    return 1;
                }
            },
            Opt::VERIFY_RET_ERROR => {
                verify = SSL_VERIFY_PEER;
                s_cb::set_verify_args(|a| a.return_error = true);
            }
            Opt::VERIFY_QUIET => s_cb::set_verify_args(|a| a.quiet = true),
            Opt::BRIEF => {
                c_brief = true;
                c_quiet = true;
                s_cb::set_verify_args(|a| a.quiet = true);
            }
            Opt::OPT_S(_) => ssl_args.push((p.flag().to_owned(), p.arg_opt().map(str::to_owned))),
            Opt::OPT_V(v) => {
                if !opt::verify(v, &arg, (&vpm).into()) {
                    return 1;
                }
                vpmtouched += 1;
            }
            Opt::OPT_X(x) => {
                if !s_cb::args_excert(x, &arg, &mut exc) {
                    return 1;
                }
            }
            Opt::IGNORE_UNEXPECTED_EOF => ignore_unexpected_eof = true,
            Opt::PREXIT => prexit = true,
            Opt::NO_INTERACTIVE => nointeractive = true,
            Opt::CRLF => crlf = true,
            Opt::QUIET => {
                c_quiet = true;
                c_ign_eof = true;
            }
            Opt::NBIO => c_nbio = true,
            Opt::NOCMDS => cmdmode = CmdMode::None,
            Opt::ADV => cmdmode = CmdMode::Advanced,
            Opt::ENGINE => e = engine::setup_engine(Some(&arg), true),
            Opt::SSL_CLIENT_ENGINE => {
                ssl_client_engine = engine::setup_engine(Some(&arg), false);
                if ssl_client_engine.is_none() {
                    eprintf!("Error getting client auth engine\n");
                    opthelp(&prog);
                    return 1;
                }
            }
            Opt::OPT_R(r) => {
                if !app_rand::opt_rand(r, &arg) {
                    return 1;
                }
            }
            Opt::OPT_PROV(pr) => {
                if !app_libctx::opt_provider(pr, &arg) {
                    return 1;
                }
            }
            Opt::IGN_EOF => c_ign_eof = true,
            Opt::NO_IGN_EOF => c_ign_eof = false,
            Opt::DEBUG => c_debug = true,
            Opt::TLSEXTDEBUG => c_tlsextdebug = true,
            Opt::STATUS => c_status_req = true,
            Opt::STATUS_OCSP_CHECK_LEAF => {
                c_status_req = true;
                rustyssl_ossl::verify::ParamRef::from(&vpm)
                    .set_flags(u64::from(X509_V_FLAG_OCSP_RESP_CHECK.cast_unsigned()));
                vpmtouched += 1;
            }
            Opt::STATUS_OCSP_CHECK_ALL => {
                c_status_req = true;
                rustyssl_ossl::verify::ParamRef::from(&vpm).set_flags(u64::from(
                    (X509_V_FLAG_OCSP_RESP_CHECK | X509_V_FLAG_OCSP_RESP_CHECK_ALL).cast_unsigned(),
                ));
                vpmtouched += 1;
            }
            Opt::WDEBUG => {}
            Opt::MSG => c_msg = 1,
            Opt::MSGFILE => match Bio::new_file(&arg, "w") {
                Some(b) => bio_c_msg = Some(Rc::new(b)),
                None => {
                    eprintf!("Error writing file {arg}\n");
                    return 1;
                }
            },
            Opt::TRACE => c_msg = 2,
            Opt::SECURITY_DEBUG => sdebug = 1,
            Opt::SECURITY_DEBUG_VERBOSE => sdebug = 2,
            Opt::SHOWCERTS => c_showcerts = true,
            Opt::NBIO_TEST => nbio_test = true,
            Opt::STATE => state = true,
            Opt::PSK_IDENTITY => psk_identity = arg,
            Opt::PSK => {
                if !arg.bytes().all(|b| b.is_ascii_hexdigit()) {
                    eprintf!("Not a hex number '{arg}'\n");
                    return 1;
                }
                psk_key = Some(arg);
            }
            Opt::PSK_SESS => psksessf = Some(arg),
            Opt::SRPUSER => {
                srp_arg.srplogin = Some(arg);
                min_version = min_version.max(TLS1_VERSION);
            }
            Opt::SRPPASS => {
                srppass = Some(arg);
                min_version = min_version.max(TLS1_VERSION);
            }
            Opt::SRP_STRENGTH => {
                srp_arg.strength = apps::atoi(&arg);
                eprintf!("SRP minimal length for N is {}\n", srp_arg.strength);
                min_version = min_version.max(TLS1_VERSION);
            }
            Opt::SRP_LATEUSER => {
                srp_lateuser = true;
                min_version = min_version.max(TLS1_VERSION);
            }
            Opt::SRP_MOREGROUPS => {
                srp_arg.amp = true;
                min_version = min_version.max(TLS1_VERSION);
            }
            Opt::SSL_CONFIG => ssl_config = Some(arg),
            Opt::SSL3 | Opt::TLS1_3 | Opt::TLS1_2 | Opt::TLS1_1 | Opt::TLS1 => {
                let v = match o {
                    Opt::SSL3 => SSL3_VERSION,
                    Opt::TLS1_3 => TLS1_3_VERSION,
                    Opt::TLS1_2 => TLS1_2_VERSION,
                    Opt::TLS1_1 => TLS1_1_VERSION,
                    _ => TLS1_VERSION,
                };
                min_version = v;
                max_version = v;
                socket_type = SOCK_STREAM;
                isdtls = false;
                isquic = false;
            }
            Opt::DTLS => {
                meth = Method::dtls_client();
                socket_type = SOCK_DGRAM;
                isdtls = true;
                isquic = false;
            }
            Opt::DTLS1 | Opt::DTLS1_2 => {
                meth = Method::dtls_client();
                let v = if o == Opt::DTLS1 {
                    DTLS1_VERSION
                } else {
                    DTLS1_2_VERSION
                };
                min_version = v;
                max_version = v;
                socket_type = SOCK_DGRAM;
                isdtls = true;
                isquic = false;
            }
            Opt::QUIC => {
                meth = Method::quic_client();
                min_version = 0;
                max_version = 0;
                socket_type = SOCK_DGRAM;
                isdtls = false;
                isquic = true;
            }
            Opt::SCTP | Opt::SCTP_LABEL_BUG | Opt::KTLS => {}
            Opt::TIMEOUT => enable_timeouts = true,
            Opt::MTU => socket_mtu = atol(&arg),
            Opt::FALLBACKSCSV => fallback_scsv = true,
            Opt::KEYFORM => match opt::parse_format(&arg, fmt_flags::ANY) {
                Some(f) => key_format = f,
                None => {
                    opthelp(&prog);
                    return 1;
                }
            },
            Opt::PASS => passarg = Some(arg),
            Opt::CERT_CHAIN => chain_file = Some(arg),
            Opt::KEY => key_file = Some(arg),
            Opt::RECONNECT => reconnect = 5,
            Opt::CAPATH => ca_path = Some(arg),
            Opt::NOCAPATH => no_ca_path = true,
            Opt::CHAINCAPATH => ch_ca_path = Some(arg),
            Opt::VERIFYCAPATH => vfy_ca_path = Some(arg),
            Opt::BUILD_CHAIN => build_chain = true,
            Opt::REQCAFILE => req_ca_file = Some(arg),
            Opt::CAFILE => ca_file = Some(arg),
            Opt::NOCAFILE => no_ca_file = true,
            Opt::NOCT => ct_validation = false,
            Opt::CT => ct_validation = true,
            Opt::CTLOG_FILE => ctlog_file = Some(arg),
            Opt::CHAINCAFILE => ch_ca_file = Some(arg),
            Opt::VERIFYCAFILE => vfy_ca_file = Some(arg),
            Opt::CASTORE => ca_store = Some(arg),
            Opt::NOCASTORE => no_ca_store = true,
            Opt::CHAINCASTORE => ch_ca_store = Some(arg),
            Opt::VERIFYCASTORE => vfy_ca_store = Some(arg),
            Opt::DANE_TLSA_DOMAIN => dane_tlsa_domain = Some(arg),
            Opt::DANE_TLSA_RRDATA => dane_tlsa_rrset.get_or_insert_with(Vec::new).push(arg),
            Opt::DANE_EE_NO_NAME => dane_ee_no_name = true,
            Opt::NEXTPROTONEG => next_proto_neg_in = Some(arg),
            Opt::ALPN => alpn_in = Some(arg),
            Opt::SERVERINFO => {
                for part in arg.split(',') {
                    serverinfo_types.push(u16::try_from(apps::atoi(part) & 0xffff).unwrap_or(0));
                    if serverinfo_types.len() == 100 {
                        break;
                    }
                }
            }
            Opt::STARTTLS => match opt::pair(&arg, &SERVICES) {
                Some(s) => starttls_proto = s,
                None => return 1,
            },
            Opt::TFO => tfo = true,
            Opt::SERVERNAME => servername = Some(arg),
            Opt::NOSERVERNAME => noservername = true,
            Opt::USE_SRTP => srtp_profiles = Some(arg),
            Opt::KEYMATEXPORT => keymatexportlabel = Some(arg),
            Opt::KEYMATEXPORTLEN => keymatexportlen = apps::atoi(&arg),
            Opt::ASYNC => async_ = true,
            Opt::MAXFRAGLEN => {
                let len = apps::atoi(&arg);
                maxfraglen = match len {
                    512 => TLSEXT_max_fragment_length_512.to_le_bytes()[0],
                    1024 => TLSEXT_max_fragment_length_1024.to_le_bytes()[0],
                    2048 => TLSEXT_max_fragment_length_2048.to_le_bytes()[0],
                    4096 => TLSEXT_max_fragment_length_4096.to_le_bytes()[0],
                    _ => {
                        // %u of an int.
                        eprintf!(
                            "{prog}: Max Fragment Len {} is out of permitted values",
                            len.cast_unsigned()
                        );
                        opthelp(&prog);
                        return 1;
                    }
                };
            }
            Opt::MAX_SEND_FRAG => max_send_fragment = apps::atoi(&arg).cast_unsigned(),
            Opt::SPLIT_SEND_FRAG => split_send_fragment = apps::atoi(&arg).cast_unsigned(),
            Opt::MAX_PIPELINES => max_pipelines = apps::atoi(&arg).cast_unsigned(),
            Opt::READ_BUF => read_buf_len = apps::atoi(&arg),
            Opt::KEYLOG_FILE => keylog_file = Some(arg),
            Opt::EARLY_DATA => early_data_file = Some(arg),
            Opt::ENABLE_PHA => enable_pha = true,
            Opt::ENABLE_SERVER_RPK => enable_server_rpk = true,
            Opt::ENABLE_CLIENT_RPK => enable_client_rpk = true,
        }
    }

    // The optional argument is the connect string if -connect isn't used.
    if p.num_rest() == 1 {
        // -connect and a separate argument don't go together.
        if connectstr.is_some() {
            eprintf!("{prog}: cannot provide both -connect option and target parameter\n");
            opthelp(&prog);
            return 1;
        }
        connect_type = ConnectType::Inet;
        connectstr = p.rest().first().cloned();
    } else if !p.check_rest_arg(None) {
        opthelp(&prog);
        return 1;
    }
    let _ = connect_type;
    if !app_rand::load() {
        return 1;
    }
    if c_ign_eof {
        cmdmode = CmdMode::None;
    }
    if count4or6 >= 2 {
        eprintf!("{prog}: Can't use both -4 and -6\n");
        opthelp(&prog);
        return 1;
    }
    if noservername {
        if servername.is_some() {
            eprintf!("{prog}: Can't use -servername and -noservername together\n");
            opthelp(&prog);
            return 1;
        }
        if dane_tlsa_domain.is_some() {
            eprintf!("{prog}: Can't use -dane_tlsa_domain and -noservername together\n");
            opthelp(&prog);
            return 1;
        }
    }
    if min_version == TLS1_3_VERSION && next_proto_neg_in.is_some() {
        eprintf!("Cannot supply -nextprotoneg with TLSv1.3\n");
        opthelp(&prog);
        return 1;
    }
    if let Some(cs) = &connectstr {
        match sock::parse_hostserv(cs, true, BIO_PARSE_PRIO_HOST) {
            Some((r, h, s)) if r != 0 => {
                if h.is_some() {
                    host = h;
                }
                if s.is_some() {
                    port = s;
                }
            }
            Some(_) => {
                eprintf!("{prog}: -connect argument or target parameter malformed or ambiguous\n");
                return 1;
            }
            None => return 1,
        }
    }
    let (mut thost, mut tport) = (None, None);
    if let Some(ps) = &proxystr {
        if host.is_none() || port.is_none() {
            eprintf!("{prog}: -proxy requires use of -connect or target parameter\n");
            opthelp(&prog);
            return 1;
        }
        if servername.is_none() && !noservername {
            servername = host.clone();
        }
        // The target host and port, for the proxy's CONNECT.
        thost = host.clone();
        tport = port.clone();
        match sock::parse_hostserv(ps, true, BIO_PARSE_PRIO_HOST) {
            Some((r, h, s)) => {
                if h.is_some() {
                    host = h;
                }
                if s.is_some() {
                    port = s;
                }
                if r == 0 {
                    eprintf!("{prog}: -proxy argument malformed or ambiguous\n");
                    return 1;
                }
            }
            None => return 1,
        }
    }
    let (mut bindhost, mut bindport) = (None, None);
    if let Some(bs) = &bindstr {
        match sock::parse_hostserv(bs, true, BIO_PARSE_PRIO_HOST) {
            Some((r, h, s)) if r != 0 => {
                bindhost = h;
                bindport = s;
            }
            _ => {
                eprintf!("{prog}: -bind argument parameter malformed or ambiguous\n");
                return 1;
            }
        }
    }
    if socket_family == AF_UNIX && socket_type != SOCK_STREAM {
        eprintf!("Can't use unix sockets and datagrams together\n");
        return 1;
    }
    let next_proto = match &next_proto_neg_in {
        Some(n) => match s_cb::next_protos_parse(n) {
            Some(v) => Some(v),
            None => {
                eprintf!("Error parsing -nextprotoneg argument\n");
                return 1;
            }
        },
        None => None,
    };
    let Some((pass, _)) = apps::app_passwd(passarg.as_deref(), None) else {
        eprintf!("Error getting private key password\n");
        return 1;
    };
    let pass = pass.map(|p| p.as_str().to_owned());
    let Some((proxypass, _)) = apps::app_passwd(proxypassarg.as_deref(), None) else {
        eprintf!("Error getting proxy password\n");
        return 1;
    };
    let proxypass = proxypass.map(|p| p.as_str().to_owned());
    if proxypass.is_some() && proxyuser.is_none() {
        eprintf!("Error: Must specify proxy_user with proxy_pass\n");
        return 1;
    }
    if key_file.is_none() {
        key_file = cert_file.clone();
    }
    let mut key = None;
    if let Some(kf) = &key_file {
        key = apps::load_key(
            Some(kf),
            key_format,
            false,
            pass.as_deref(),
            e.as_ref(),
            Some("client certificate private key"),
        );
        if key.is_none() {
            return 1;
        }
    }
    let mut cert = None;
    if let Some(cf) = &cert_file {
        cert = apps::load_cert_pass(
            Some(cf),
            cert_format,
            true,
            pass.as_deref(),
            Some("client certificate"),
        );
        if cert.is_none() {
            return 1;
        }
    }
    let mut chain = None;
    if let Some(chf) = &chain_file {
        let (ok, c) = apps::load_certs(
            Some(chf),
            false,
            None,
            pass.as_deref(),
            Some("client certificate chain"),
        );
        if !ok {
            return 1;
        }
        chain = c;
    }
    let mut crls: Option<CrlStack> = None;
    if let Some(cf) = &crl_file {
        let Some(crl) = apps::load_crl(Some(cf), crl_format, false, Some("CRL")) else {
            return 1;
        };
        let Some(st) = CrlStack::new() else { return 1 };
        if !st.push(crl) {
            eprintf!("Error adding CRL\n");
            return 1;
        }
        crls = Some(st);
    }
    if !s_cb::load_excert(&mut exc) {
        return 1;
    }
    let stdout = stdout_buffer();
    let bio_c_out: Rc<Bio> = if c_quiet && !c_debug {
        let Some(null) = Bio::new_null() else {
            eprintf!("Unable to create BIO\n");
            return 1;
        };
        if c_msg != 0 && bio_c_msg.is_none() {
            match &stdout {
                Some(o) => bio_c_msg = Some(o.clone()),
                None => {
                    eprintf!("Out of memory\n");
                    return 1;
                }
            }
        }
        Rc::new(null)
    } else {
        match &stdout {
            Some(o) => o.clone(),
            None => {
                eprintf!("Unable to create BIO\n");
                return 1;
            }
        }
    };
    ST.with(|s| {
        let mut s = s.borrow_mut();
        s.c_debug = c_debug;
        s.c_showcerts = c_showcerts;
        s.c_quiet = c_quiet;
        s.keymatexportlabel = keymatexportlabel.clone();
        s.keymatexportlen = keymatexportlen;
        s.bio_c_out = Some(bio_c_out.clone());
        s.sess_out = sess_out.clone();
        s.psk_identity = psk_identity.clone();
        s.psk_key = psk_key.clone();
        s.enable_server_rpk = enable_server_rpk;
        s.next_proto_on = next_proto.is_some();
    });
    let Some((srppassin, _)) = apps::app_passwd(srppass.as_deref(), None) else {
        eprintf!("Error getting password\n");
        return 1;
    };
    srp_arg.srppassin = srppassin.map(|p| p.as_str().to_owned());

    let libctx = app_libctx::libctx();
    let Some(ctx) = SslCtx::new_ex(libctx.as_deref(), app_libctx::propq().as_deref(), meth) else {
        return end(ret);
    };
    let c = ctx.r();
    c.clear_mode(SSL_MODE_AUTO_RETRY.into());
    if sdebug != 0 {
        s_cb::ssl_ctx_security_debug(c, sdebug);
    }
    if !s_cb::config_ctx(&cctx, &ssl_args, c) {
        return end(ret);
    }
    if let Some(sc) = &ssl_config
        && !c.config(sc)
    {
        eprintf!("Error using configuration \"{sc}\"\n");
        return end(ret);
    }
    if min_version != 0 && !c.set_min_proto_version(min_version) {
        return end(ret);
    }
    if max_version != 0 && !c.set_max_proto_version(max_version) {
        return end(ret);
    }
    if ignore_unexpected_eof {
        c.set_options(SSL_OP_IGNORE_UNEXPECTED_EOF);
    }
    if vpmtouched > 0 && !c.set1_param(&vpm) {
        eprintf!("Error setting verify params\n");
        return end(ret);
    }
    if async_ {
        c.set_mode(SSL_MODE_ASYNC.into());
    }
    if max_send_fragment > 0 && !c.set_max_send_fragment(max_send_fragment) {
        eprintf!("{prog}: Max send fragment size {max_send_fragment} is out of permitted range\n");
        return end(ret);
    }
    if split_send_fragment > 0 && !c.set_split_send_fragment(split_send_fragment) {
        eprintf!(
            "{prog}: Split send fragment size {split_send_fragment} is out of permitted range\n"
        );
        return end(ret);
    }
    if max_pipelines > 0 && !c.set_max_pipelines(max_pipelines) {
        eprintf!("{prog}: Max pipelines {max_pipelines} is out of permitted range\n");
        return end(ret);
    }
    if read_buf_len > 0 {
        c.set_default_read_buffer_len(usize::try_from(read_buf_len).unwrap_or(0));
    }
    if maxfraglen > 0 && !c.set_tlsext_max_fragment_length(maxfraglen) {
        eprintf!("{prog}: Max Fragment Length code {maxfraglen} is out of permitted values\n");
        return end(ret);
    }
    if !s_cb::ssl_load_stores(
        c,
        vfy_ca_path.as_deref(),
        vfy_ca_file.as_deref(),
        vfy_ca_store.as_deref(),
        ch_ca_path.as_deref(),
        ch_ca_file.as_deref(),
        ch_ca_store.as_deref(),
        crls.as_ref(),
        crl_download,
    ) {
        eprintf!("Error loading store locations\n");
        return end(ret);
    }
    if let Some(rf) = &req_ca_file
        && !c.set0_ca_list_from_file(rf)
    {
        eprintf!("Error loading CA names\n");
        return end(ret);
    }
    if let Some(eng) = ssl_client_engine.take() {
        if !c.set_client_cert_engine(&eng) {
            eprintf!("Error setting client auth engine\n");
            return end(ret);
        }
        drop(eng);
    }
    if psk_key.is_some() {
        if c_debug {
            cout("PSK key given, setting client callback\n");
        }
        c.set_psk_client_callback(psk_client_cb);
    }
    if let Some(f) = &psksessf {
        let Some(b) = Bio::new_file(f, "r") else {
            eprintf!("Can't open PSK session file {f}\n");
            return end(ret);
        };
        let Some(sess) = Session::read_pem(&b) else {
            eprintf!("Can't read PSK session file {f}\n");
            return end(ret);
        };
        ST.with(|s| s.borrow_mut().psksess = Some(sess));
    }
    if psk_key.is_some() || ST.with(|s| s.borrow().psksess.is_some()) {
        c.set_psk_use_session_callback(psk_use_session_cb);
    }
    if let Some(sp) = &srtp_profiles
        && c.set_tlsext_use_srtp(sp) != 0
    {
        eprintf!("Error setting SRTP profile\n");
        return end(ret);
    }
    if exc.is_some() {
        s_cb::ssl_ctx_set_excert(c, exc.take());
    }
    if let Some(np) = next_proto.clone() {
        c.set_next_proto_select_cb(np, next_proto_cb);
    }
    if let Some(a) = &alpn_in {
        let Some(alpn) = s_cb::next_protos_parse(a) else {
            eprintf!("Error parsing -alpn argument\n");
            return end(ret);
        };
        if c.set_alpn_protos(&alpn) != 0 {
            eprintf!("Error setting ALPN\n");
            return end(ret);
        }
    }
    for &t in &serverinfo_types {
        if !c.add_client_custom_ext(u32::from(t), serverinfo_cli_parse_cb) {
            eprintf!("Warning: Unable to add custom extension {t}, skipping\n");
        }
    }
    if state {
        c.set_info_callback(s_cb::apps_ssl_info_callback);
    }
    // SCT processing, without early termination.
    if ct_validation && !c.enable_ct(SSL_CT_VALIDATION_PERMISSIVE.cast_signed()) {
        return end(ret);
    }
    if !s_cb::ctx_set_ctlog_list_file(c, ctlog_file.as_deref()) {
        if ct_validation {
            return end(ret);
        }
        // Without CT validation the log list isn't needed: it's loaded only to name the
        // logs of SCTs seen anyway.
        err::clear();
    }
    c.set_verify(verify, Some(s_cb::verify_callback));
    if !s_cb::ctx_set_verify_locations(
        c,
        ca_file.as_deref(),
        no_ca_file,
        ca_path.as_deref(),
        no_ca_path,
        ca_store.as_deref(),
        no_ca_store,
    ) {
        return end(ret);
    }
    s_cb::ssl_ctx_add_crls(c, crls.as_ref(), crl_download);
    if !s_cb::set_cert_key_stuff(c, cert.as_ref(), key.as_ref(), chain.as_ref(), build_chain) {
        return end(ret);
    }
    if !noservername {
        c.set_servername_callback(ssl_servername_cb);
    }
    if srp_arg.srplogin.is_some()
        && !s_cb::set_up_srp_arg(c, &srp_arg, srp_lateuser, c_msg != 0, c_debug)
    {
        return end(ret);
    }
    if dane_tlsa_domain.is_some() && c.dane_enable() <= 0 {
        eprintf!("{prog}: Error enabling DANE TLSA authentication.\n");
        return end(ret);
    }
    // TLS 1.3 tickets come any time after the handshake: a callback writes the session out.
    c.set_session_cache_mode((SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE).into());
    c.sess_set_new_cb(new_session_cb);
    if s_cb::set_keylog_file(Some(c), keylog_file.as_deref()) {
        return end(ret);
    }
    let Some(con_owned) = Ssl::new(c) else {
        return end(ret);
    };
    let con = con_owned.r();
    if enable_pha {
        con.set_post_handshake_auth(1);
    }
    if enable_client_rpk && !con.set1_client_cert_type(&CERT_TYPE_RPK) {
        eprintf!("Error setting client certificate types\n");
        return end_con(ret, con, prexit);
    }
    if enable_server_rpk && !con.set1_server_cert_type(&CERT_TYPE_RPK) {
        eprintf!("Error setting server certificate types\n");
        return end_con(ret, con, prexit);
    }
    if let Some(si) = &sess_in {
        let Some(b) = Bio::new_file(si, "r") else {
            eprintf!("Can't open session file {si}\n");
            return end_con(ret, con, prexit);
        };
        let Some(sess) = Session::read_pem(&b) else {
            eprintf!("Can't open session file {si}\n");
            return end_con(ret, con, prexit);
        };
        if !con.set_session(&sess) {
            eprintf!("Can't set session\n");
            return end_con(ret, con, prexit);
        }
    }
    if fallback_scsv {
        con.set_mode(SSL_MODE_SEND_FALLBACK_SCSV.into());
    }
    if !noservername && (servername.is_some() || dane_tlsa_domain.is_none()) {
        if servername.is_none() {
            match &host {
                None => servername = Some("localhost".to_owned()),
                Some(h) if is_dns_name(h) => servername = Some(h.clone()),
                _ => {}
            }
        }
        if let Some(sn) = &servername
            && !con.set_tlsext_host_name(sn)
        {
            eprintf!("Unable to set TLS servername extension.\n");
            return end_con(ret, con, prexit);
        }
    }
    if let Some(d) = &dane_tlsa_domain {
        if con.dane_enable(d) <= 0 {
            eprintf!("{prog}: Error enabling DANE TLSA authentication.\n");
            return end_con(ret, con, prexit);
        }
        let Some(rrset) = &dane_tlsa_rrset else {
            eprintf!(
                "{prog}: DANE TLSA authentication requires at least one -dane_tlsa_rrdata option.\n"
            );
            return end_con(ret, con, prexit);
        };
        if !tlsa_import_rrset(con, rrset, &prog) {
            eprintf!("{prog}: Failed to import any TLSA records.\n");
            return end_con(ret, con, prexit);
        }
        if dane_ee_no_name {
            con.dane_set_flags(DANE_FLAG_NO_DANE_EE_NAMECHECKS.cast_unsigned());
        }
    } else if dane_tlsa_rrset.is_some() {
        eprintf!("{prog}: DANE TLSA authentication requires the -dane_tlsa_domain option.\n");
        return end_con(ret, con, prexit);
    }
    if isdtls && tfo {
        eprintf!("{prog}: DTLS does not support the -tfo option\n");
        return end_con(ret, con, prexit);
    }
    if isquic && tfo {
        eprintf!("{prog}: QUIC does not support the -tfo option\n");
        return end_con(ret, con, prexit);
    }
    if isquic && alpn_in.is_none() {
        eprintf!(
            "{prog}: QUIC requires ALPN to be specified (e.g. \"h3\" for HTTP/3) via the -alpn option\n"
        );
        return end_con(ret, con, prexit);
    }
    if tfo {
        cout("Connecting via TFO\n");
    }

    let mut sbuf = vec![0u8; BUFSIZZ];
    let mut mbuf: Vec<u8> = Vec::new();
    let mut in_init = true;
    let mut sock_fd;
    let conn = Conn {
        con,
        isdtls,
        isquic,
        tfo,
    };
    'restart: loop {
        // A fresh connection: the socket, its BIO, and the protocol's preamble.
        let client = match s_socket::init_client(
            host.as_deref(),
            port.as_deref(),
            bindhost.as_deref(),
            bindport.as_deref(),
            socket_family,
            socket_type,
            protocol,
            tfo,
            !isquic,
            true,
        ) {
            Ok(cl) => cl,
            Err(s) => {
                eprintf!("connect:errno={}\n", sock::last_socket_error());
                sock::closesocket(s);
                return end_con(ret, con, prexit);
            }
        };
        sock_fd = client.sock;
        let peer_addr: Option<Addr> = client.peer;
        cout(&format!("CONNECTED({sock_fd:08X})\n"));
        // QUIC always uses a non-blocking socket, and non-blocking mode on the SSL.
        if c_nbio || isquic {
            if !sock::socket_nbio(sock_fd, 1) {
                return end_con(ret, con, prexit);
            }
            if c_nbio {
                if isquic && !con.set_blocking_mode(0) {
                    return end_con(ret, con, prexit);
                }
                cout("Turned on non blocking io\n");
            }
        }
        let mut sbio;
        if isdtls {
            let Some(b) = Bio::new_dgram(sock_fd) else {
                eprintf!("memory allocation failure\n");
                sock::closesocket(sock_fd);
                return end_con(ret, con, prexit);
            };
            sbio = b;
            let Some(local) = sock::sock_address(sock_fd) else {
                eprintf!("getsockname:errno={}\n", sock::last_socket_error());
                sock::closesocket(sock_fd);
                return end_con(ret, con, prexit);
            };
            let _ = sbio.set_connected(&local);
            if enable_timeouts {
                sbio.dgram_set_timeout(BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, DGRAM_TIMEOUT);
                sbio.dgram_set_timeout(BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, DGRAM_TIMEOUT);
            }
            if socket_mtu != 0 {
                let min = con.dtls_link_min_mtu();
                if socket_mtu < min {
                    eprintf!("MTU too small. Must be at least {min}\n");
                    drop(sbio);
                    return shut_and_end(&conn, 1, sock_fd, in_init, full_log, prexit);
                }
                con.set_options(SSL_OP_NO_QUERY_MTU);
                if !con.dtls_set_link_mtu(socket_mtu) {
                    eprintf!("Failed to set MTU\n");
                    drop(sbio);
                    return shut_and_end(&conn, 1, sock_fd, in_init, full_log, prexit);
                }
            } else {
                // MTU discovery.
                sbio.ctrl_long(BIO_CTRL_DGRAM_MTU_DISCOVER, 0);
            }
        } else if isquic {
            let Some(b) = Bio::new_dgram(sock_fd) else {
                eprintf!("Unable to create BIO\n");
                sock::closesocket(sock_fd);
                return end_con(ret, con, prexit);
            };
            sbio = b;
            if !peer_addr
                .as_ref()
                .is_some_and(|a| con.set1_initial_peer_addr(a))
            {
                eprintf!("Failed to set the initial peer address\n");
                return shut_and_end(&conn, 1, sock_fd, in_init, full_log, prexit);
            }
        } else {
            let Some(b) = Bio::new_socket(sock_fd) else {
                eprintf!("Unable to create BIO\n");
                sock::closesocket(sock_fd);
                return end_con(ret, con, prexit);
            };
            sbio = b;
        }
        if tfo && let Some(a) = &peer_addr {
            let _ = sbio.set_conn_address(a);
            sbio.ctrl_long(BIO_C_SET_TFO, 1);
        }
        if nbio_test {
            let Some(test) = Bio::new_nbio_test() else {
                eprintf!("Unable to create BIO\n");
                return shut_and_end(&conn, 1, sock_fd, in_init, full_log, prexit);
            };
            sbio = test.push(sbio);
        }
        if c_debug {
            sbio.set_callback_ex(s_cb::bio_dump_callback);
            sbio.set_callback_arg_bio(Some(&bio_c_out));
        }
        if c_msg != 0 {
            let cb = if c_msg == 2 {
                MsgCallback::Trace
            } else {
                MsgCallback::Rust(s_cb::msg_cb)
            };
            let target = bio_c_msg.clone().unwrap_or_else(|| bio_c_out.clone());
            con.set_msg_callback(cb, &target);
            MSG_TARGET.with(|t| *t.borrow_mut() = Some(target));
        }
        if c_tlsextdebug {
            con.set_tlsext_debug_callback(s_cb::tlsext_cb, &bio_c_out);
        }
        if c_status_req {
            con.set_tlsext_status_type_ocsp();
            c.set_tlsext_status_cb(ocsp_resp_cb);
        }
        con.set_bio(sbio);
        con.set_connect_state();

        let mut read_tty = true;
        let mut write_tty = false;
        let mut read_ssl = true;
        let mut write_ssl = true;
        let mut first_loop = true;
        let mut cbuf_len = 0usize;
        let mut cbuf_off = 0usize;
        let mut sbuf_len = 0usize;
        let mut sbuf_off = 0usize;
        let mut at_eof = false;

        let Some(sb) = con.rbio() else {
            return end_con(ret, con, prexit);
        };
        if let Some(ps) = &proxystr {
            let _ = ps;
            // The connect string's target host and port.
            if !ssl::http_proxy_connect(
                &sb,
                thost.as_deref().unwrap_or_default(),
                tport.as_deref().unwrap_or_default(),
                proxyuser.as_deref(),
                proxypass.as_deref(),
                0,
                io::bio_err(),
                &prog,
            ) {
                return shut_and_end(&conn, ret, sock_fd, in_init, full_log, prexit);
            }
        }
        match starttls(
            &sb,
            starttls_proto,
            protohost.as_deref(),
            host.as_deref(),
            &mut mbuf,
            &mut sbuf,
            con,
        ) {
            Ok(()) => {}
            Err(Exit::Shut) => return shut_and_end(&conn, ret, sock_fd, in_init, full_log, prexit),
            Err(Exit::End) => return end_con(ret, con, prexit),
        }
        if let Some(edf) = &early_data_file {
            let session_ok = con.session().is_some_and(|s| s.max_early_data() > 0)
                || ST.with(|s| {
                    s.borrow()
                        .psksess
                        .as_ref()
                        .is_some_and(|p| p.r().max_early_data() > 0)
                });
            if session_ok {
                let Some(edfile) = Bio::new_file(edf, "r") else {
                    eprintf!("Cannot open early data file\n");
                    return shut_and_end(&conn, ret, sock_fd, in_init, full_log, prexit);
                };
                let mut finish = false;
                let mut cbuf = vec![0u8; BUFSIZZ];
                while !finish {
                    let (ok, readbytes) = edfile.read_ex(&mut cbuf);
                    if !ok {
                        finish = true;
                    }
                    loop {
                        let (w, _) =
                            con.write_early_data(cbuf.get(..readbytes).unwrap_or_default());
                        if w {
                            break;
                        }
                        match con.get_error(0) {
                            SSL_ERROR_WANT_WRITE | SSL_ERROR_WANT_ASYNC | SSL_ERROR_WANT_READ => {
                                continue;
                            }
                            _ => {
                                eprintf!("Error writing early data\n");
                                return shut_and_end(
                                    &conn, ret, sock_fd, in_init, full_log, prexit,
                                );
                            }
                        }
                    }
                }
            }
        }

        let mut ud = UserBuf::new(cmdmode);
        loop {
            let timeout = if (isdtls || isquic)
                && let Some(Some(t)) = con.event_timeout()
            {
                Some(t)
            } else {
                None
            };
            let mut tty_on = false;
            if !con.is_init_finished()
                && con.total_renegotiations() == 0
                && con.key_update_type() == SSL_KEY_UPDATE_NONE
            {
                in_init = true;
            } else {
                tty_on = true;
                if in_init {
                    in_init = false;
                    if c_brief {
                        eputs("CONNECTION ESTABLISHED\n");
                        s_cb::print_ssl_summary(con);
                    }
                    print_stuff(&bio_c_out, con, full_log > 0);
                    if full_log > 0 {
                        full_log -= 1;
                    }
                    if starttls_proto != Proto::Off {
                        if let Some(be) = io::bio_err() {
                            let _ = be.write_all(&mbuf);
                        }
                        // We don't need to know any more.
                        if reconnect == 0 {
                            starttls_proto = Proto::Off;
                        }
                    }
                    if reconnect > 0 {
                        reconnect -= 1;
                        cout("drop connection and then reconnect\n");
                        do_ssl_shutdown(con);
                        con.set_connect_state();
                        sock::closesocket(con.fd());
                        continue 'restart;
                    }
                }
            }
            if !write_ssl {
                loop {
                    match user_data_process(con, &mut ud, &mut cbuf_len, &mut cbuf_off) {
                        UserData::Shut => {
                            return shut_and_end(&conn, 0, sock_fd, in_init, full_log, prexit);
                        }
                        UserData::Restart => continue 'restart,
                        UserData::NoData => {}
                        UserData::Continue => write_ssl = true,
                        UserData::BadArgument => {
                            eputs("ERROR\n");
                            return shut_and_end(&conn, 0, sock_fd, in_init, full_log, prexit);
                        }
                    }
                    if !(!write_ssl && cbuf_len == 0 && ud.has_data()) {
                        break;
                    }
                }
                read_tty = cbuf_len == 0;
            }
            let ssl_pending = read_ssl && con.has_pending();
            let fd = con.fd();
            let (mut rd, mut wr) = (Vec::new(), Vec::new());
            let (mut sel_r, mut sel_w): (Vec<bool>, Vec<bool>) = (Vec::new(), Vec::new());
            if !ssl_pending {
                if tty_on {
                    // select returns at EOF too: the flag stops the loop spinning.
                    if read_tty && !at_eof {
                        rd.push(0);
                    }
                    if write_tty {
                        wr.push(1);
                    }
                }
                // For QUIC the network descriptors only wake select up;
                // SSL_handle_events does the work.
                if (!isquic && read_ssl) || (isquic && con.net_read_desired()) {
                    rd.push(fd);
                }
                if (!isquic && write_ssl) || (isquic && (first_loop || con.net_write_desired())) {
                    wr.push(fd);
                }
                let (i, r, w) = sock::select(&rd, &wr, timeout);
                if i < 0 {
                    eprintf!("bad select {}\n", sock::last_socket_error());
                    return shut_and_end(&conn, ret, sock_fd, in_init, full_log, prexit);
                }
                sel_r = r;
                sel_w = w;
            }
            let isset = |list: &[i32], set: &[bool], f: i32| {
                list.iter().zip(set.iter()).any(|(&x, &s)| x == f && s)
            };
            let ssl_readable = isset(&rd, &sel_r, fd);
            let ssl_writable = isset(&wr, &sel_w, fd);
            if timeout.is_some() {
                con.handle_events();
                if isdtls && !ssl_readable && !ssl_writable {
                    eputs("TIMEOUT occurred\n");
                }
            }
            if !ssl_pending
                && ((!isquic && ssl_writable) || (isquic && (cbuf_len > 0 || first_loop)))
            {
                let data = ud
                    .buf
                    .get(cbuf_off..cbuf_off + cbuf_len)
                    .unwrap_or_default()
                    .to_vec();
                let k = con.write(&data);
                match con.get_error(k) {
                    SSL_ERROR_NONE => {
                        let kk = usize::try_from(k).unwrap_or(0);
                        cbuf_off += kk;
                        cbuf_len = cbuf_len.saturating_sub(kk);
                        if k <= 0 {
                            return end_con(ret, con, prexit);
                        }
                        // A write(con, NULL, 0) is done.
                        if cbuf_len == 0 {
                            read_tty = true;
                            write_ssl = false;
                        } else {
                            read_tty = false;
                            write_ssl = true;
                        }
                    }
                    SSL_ERROR_WANT_WRITE => {
                        cout("write W BLOCK\n");
                        write_ssl = true;
                        read_tty = false;
                    }
                    SSL_ERROR_WANT_ASYNC => {
                        cout("write A BLOCK\n");
                        s_cb::wait_for_async(con);
                        write_ssl = true;
                        read_tty = false;
                    }
                    SSL_ERROR_WANT_READ => {
                        cout("write R BLOCK\n");
                        write_tty = false;
                        read_ssl = true;
                        write_ssl = false;
                    }
                    SSL_ERROR_WANT_X509_LOOKUP => cout("write X BLOCK\n"),
                    SSL_ERROR_ZERO_RETURN => {
                        if cbuf_len != 0 {
                            cout("shutdown\n");
                            return shut_and_end(&conn, 0, sock_fd, in_init, full_log, prexit);
                        }
                        read_tty = true;
                        write_ssl = false;
                    }
                    SSL_ERROR_SYSCALL => {
                        if k != 0 || cbuf_len != 0 {
                            let sockerr = sock::last_socket_error();
                            if !tfo || sockerr != EISCONN {
                                eprintf!("write:errno={sockerr}\n");
                                return shut_and_end(
                                    &conn, ret, sock_fd, in_init, full_log, prexit,
                                );
                            }
                        } else {
                            read_tty = true;
                            write_ssl = false;
                        }
                    }
                    SSL_ERROR_WANT_ASYNC_JOB | SSL_ERROR_SSL => {
                        return shut_and_end(&conn, ret, sock_fd, in_init, full_log, prexit);
                    }
                    _ => {}
                }
            } else if !ssl_pending && isset(&wr, &sel_w, 1) {
                let i =
                    raw_write_stdout(sbuf.get(sbuf_off..sbuf_off + sbuf_len).unwrap_or_default());
                if i <= 0 {
                    cout("DONE\n");
                    return shut_and_end(&conn, 0, sock_fd, in_init, full_log, prexit);
                }
                let i = usize::try_from(i).unwrap_or(0);
                sbuf_len = sbuf_len.saturating_sub(i);
                sbuf_off += i;
                if sbuf_len == 0 {
                    read_ssl = true;
                    write_tty = false;
                }
            } else if ssl_pending || (!isquic && ssl_readable) {
                let k = con.read(&mut sbuf);
                match con.get_error(k) {
                    SSL_ERROR_NONE => {
                        if k <= 0 {
                            return end_con(ret, con, prexit);
                        }
                        sbuf_off = 0;
                        sbuf_len = usize::try_from(k).unwrap_or(0);
                        read_ssl = false;
                        write_tty = true;
                    }
                    SSL_ERROR_WANT_ASYNC => {
                        cout("read A BLOCK\n");
                        s_cb::wait_for_async(con);
                        write_tty = false;
                        read_ssl = true;
                        if !read_tty && !write_ssl {
                            write_ssl = true;
                        }
                    }
                    SSL_ERROR_WANT_WRITE => {
                        cout("read W BLOCK\n");
                        write_ssl = true;
                        read_tty = false;
                    }
                    SSL_ERROR_WANT_READ => {
                        cout("read R BLOCK\n");
                        write_tty = false;
                        read_ssl = true;
                        if !read_tty && !write_ssl {
                            write_ssl = true;
                        }
                    }
                    SSL_ERROR_WANT_X509_LOOKUP => cout("read X BLOCK\n"),
                    SSL_ERROR_SYSCALL => {
                        let r = sock::last_socket_error();
                        if c_brief {
                            eputs("CONNECTION CLOSED BY SERVER\n");
                        } else {
                            eprintf!("read:errno={r}\n");
                        }
                        return shut_and_end(&conn, r, sock_fd, in_init, full_log, prexit);
                    }
                    SSL_ERROR_ZERO_RETURN => {
                        cout("closed\n");
                        return shut_and_end(&conn, 0, sock_fd, in_init, full_log, prexit);
                    }
                    SSL_ERROR_WANT_ASYNC_JOB | SSL_ERROR_SSL => {
                        return shut_and_end(&conn, ret, sock_fd, in_init, full_log, prexit);
                    }
                    _ => {}
                }
            } else if nointeractive {
                // Don't wait for input in the non-interactive mode.
                return shut_and_end(&conn, 0, sock_fd, in_init, full_log, prexit);
            } else if isset(&rd, &sel_r, 0) {
                let i = if crlf {
                    let half = (BUFSIZZ - 1) / 2;
                    let mut tmp = vec![0u8; half];
                    let n = raw_read_stdin(&mut tmp);
                    let mut out = Vec::new();
                    if n > 0 {
                        for &b in tmp
                            .get(..usize::try_from(n).unwrap_or(0))
                            .unwrap_or_default()
                        {
                            if b == b'\n' {
                                out.push(b'\r');
                            }
                            out.push(b);
                        }
                    }
                    if let Some(dst) = ud.buf.get_mut(..out.len()) {
                        dst.copy_from_slice(&out);
                    }
                    if n > 0 {
                        isize::try_from(out.len()).unwrap_or(0)
                    } else {
                        n
                    }
                } else {
                    let end = BUFSIZZ - 1;
                    raw_read_stdin(ud.buf.get_mut(..end).unwrap_or_default())
                };
                if i == 0 {
                    at_eof = true;
                }
                if !c_ign_eof && i <= 0 {
                    eputs("DONE\n");
                    return shut_and_end(&conn, 0, sock_fd, in_init, full_log, prexit);
                }
                if i > 0 && !ud.add(usize::try_from(i).unwrap_or(0)) {
                    return shut_and_end(&conn, 0, sock_fd, in_init, full_log, prexit);
                }
                read_tty = false;
            }
            first_loop = false;
        }
    }
}

thread_local! {
    /// The message callback's BIO, kept alive while the connection may use it.
    static MSG_TARGET: RefCell<Option<Rc<Bio>>> = const { RefCell::new(None) };
}

/// What `shut:` needs of the connection.
struct Conn<'a> {
    con: SslRef<'a>,
    isdtls: bool,
    isquic: bool,
    #[allow(dead_code)]
    tfo: bool,
}

/// `atol`.
fn atol(s: &str) -> i64 {
    let t = s.trim_start();
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, t.get(1..).unwrap_or_default()),
        Some(b'+') => (false, t.get(1..).unwrap_or_default()),
        _ => (false, t),
    };
    let n: i64 = digits
        .bytes()
        .take_while(u8::is_ascii_digit)
        .fold(0i64, |a, d| {
            a.wrapping_mul(10).wrapping_add(i64::from(d - b'0'))
        });
    if neg { -n } else { n }
}

/// The `shut:` label, then `end:`.
fn shut_and_end(
    conn: &Conn<'_>,
    ret: i32,
    sock_fd: i32,
    in_init: bool,
    full_log: i32,
    prexit: bool,
) -> i32 {
    let con = conn.con;
    if ret > 0 {
        // Any errors accumulated so far.
        io::print_errors();
    }
    if in_init && let Some(out) = bio_c_out() {
        print_stuff(&out, con, full_log > 0);
    }
    do_ssl_shutdown(con);
    // TCP only: half-close first, so a pending alert reaches the peer, then drain.
    if !conn.isdtls && !conn.isquic {
        sock::shutdown_wr(con.fd());
        let deadline = std::time::Instant::now() + Duration::from_micros(500_000);
        let mut sink = vec![0u8; BUFSIZZ];
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            let (r, ready, _) = sock::select(&[sock_fd], &[], Some(left));
            if !(r > 0 && ready.first() == Some(&true)) {
                break;
            }
            let Some(sb) = con.rbio() else { break };
            if sb.read(&mut sink) <= 0 {
                break;
            }
        }
    }
    sock::closesocket(con.fd());
    end_con(ret, con, prexit)
}

/// The `end:` label with a connection.
fn end_con(ret: i32, con: SslRef<'_>, prexit: bool) -> i32 {
    if ret > 0 {
        // Any new or remaining errors.
        io::print_errors();
    }
    if prexit && let Some(out) = bio_c_out() {
        print_stuff(&out, con, true);
    }
    finish(ret)
}

/// The `end:` label without one.
fn end(ret: i32) -> i32 {
    if ret > 0 {
        io::print_errors();
    }
    finish(ret)
}

fn finish(ret: i32) -> i32 {
    s_cb::set_keylog_file(None, None);
    MSG_TARGET.with(|t| *t.borrow_mut() = None);
    ret
}

/// The STARTTLS preamble of `-starttls`.
#[allow(clippy::too_many_lines)]
fn starttls(
    sbio: &BioRef<'_>,
    proto: Proto,
    protohost: Option<&str>,
    host: Option<&str>,
    mbuf: &mut Vec<u8>,
    sbuf: &mut [u8],
    con: SslRef<'_>,
) -> Result<(), Exit> {
    let sbio: &Bio = sbio;
    let w = |b: &Bio, s: &str| {
        let _ = b.write_all(s.as_bytes());
    };
    let gets = |fbio: &Bio, m: &mut Vec<u8>| -> i32 {
        let mut buf = vec![0u8; BUFSIZZ];
        let n = fbio.gets_into(&mut buf);
        let len = buf.iter().position(|&b| b == 0).unwrap_or(0);
        buf.truncate(len);
        *m = buf;
        n
    };
    let contains = |m: &[u8], s: &[u8]| m.windows(s.len()).any(|x| x == s);
    match proto {
        Proto::Off => {}
        Proto::Lmtp | Proto::Smtp => {
            // A buffering BIO for BIO_gets during the chit-chat, removed afterwards.
            let mut foundit = false;
            let Some(fbio) = Bio::new_buffer() else {
                eprintf!("Unable to create BIO\n");
                return Err(Exit::Shut);
            };
            fbio.push_borrowed(sbio);
            // Wait for the multi-line greeting to end.
            loop {
                let n = gets(&fbio, mbuf);
                if !(n > 3 && mbuf.get(3) == Some(&b'-')) {
                    break;
                }
            }
            let ph = protohost.unwrap_or("mail.example.com");
            if proto == Proto::Lmtp {
                w(&fbio, &format!("LHLO {ph}\r\n"));
            } else {
                w(&fbio, &format!("EHLO {ph}\r\n"));
            }
            fbio.flush();
            // Wait for the multi-line LHLO/EHLO response to end.
            loop {
                let n = gets(&fbio, mbuf);
                if contains(mbuf, b"STARTTLS") {
                    foundit = true;
                }
                if !(n > 3 && mbuf.get(3) == Some(&b'-')) {
                    break;
                }
            }
            fbio.flush();
            fbio.pop_from_chain();
            drop(fbio);
            if !foundit {
                eprintf!("Didn't find STARTTLS in server response, trying anyway...\n");
            }
            w(sbio, "STARTTLS\r\n");
            sbio.read(sbuf);
        }
        Proto::Pop3 => {
            let mut tmp = vec![0u8; BUFSIZZ];
            sbio.read(&mut tmp);
            w(sbio, "STLS\r\n");
            if sbio.read(sbuf) < 0 {
                eprintf!("BIO_read failed\n");
                return Err(Exit::End);
            }
        }
        Proto::Imap => {
            let mut foundit = false;
            let Some(fbio) = Bio::new_buffer() else {
                eprintf!("Unable to create BIO\n");
                return Err(Exit::Shut);
            };
            fbio.push_borrowed(sbio);
            gets(&fbio, mbuf);
            // STARTTLS command requires CAPABILITY...
            w(&fbio, ". CAPABILITY\r\n");
            fbio.flush();
            // Wait for the multi-line CAPABILITY response.
            loop {
                let n = gets(&fbio, mbuf);
                if contains(mbuf, b"STARTTLS") {
                    foundit = true;
                }
                if !(n > 3 && mbuf.first() != Some(&b'.')) {
                    break;
                }
            }
            fbio.flush();
            fbio.pop_from_chain();
            drop(fbio);
            if !foundit {
                eprintf!("Didn't find STARTTLS in server response, trying anyway...\n");
            }
            w(sbio, ". STARTTLS\r\n");
            sbio.read(sbuf);
        }
        Proto::Ftp => {
            let Some(fbio) = Bio::new_buffer() else {
                eprintf!("Unable to create BIO\n");
                return Err(Exit::Shut);
            };
            fbio.push_borrowed(sbio);
            // Wait for the multi-line response to end.
            loop {
                let n = gets(&fbio, mbuf);
                let digits = mbuf.iter().take(3).all(u8::is_ascii_digit) && mbuf.len() >= 3;
                if !(n > 3 && (!digits || mbuf.get(3) != Some(&b' '))) {
                    break;
                }
            }
            fbio.flush();
            fbio.pop_from_chain();
            drop(fbio);
            w(sbio, "AUTH TLS\r\n");
            sbio.read(sbuf);
        }
        Proto::Xmpp | Proto::XmppServer => {
            let kind = if proto == Proto::Xmpp {
                "client"
            } else {
                "server"
            };
            let to = protohost.or(host).unwrap_or("<NULL>");
            w(
                sbio,
                &format!(
                    "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:{kind}' to='{to}' version='1.0'>"
                ),
            );
            let mut buf = vec![0u8; BUFSIZZ - 1];
            let seen = sbio.read(&mut buf);
            if seen < 0 {
                eprintf!("BIO_read failed\n");
                return Err(Exit::End);
            }
            let mut m = buf
                .get(..usize::try_from(seen).unwrap_or(0))
                .unwrap_or_default()
                .to_vec();
            while !contains(&m, b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'")
                && !contains(&m, b"<starttls xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"")
            {
                let seen = sbio.read(&mut buf);
                if seen <= 0 {
                    return Err(Exit::Shut);
                }
                m = buf
                    .get(..usize::try_from(seen).unwrap_or(0))
                    .unwrap_or_default()
                    .to_vec();
            }
            w(sbio, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
            let seen = sbio.read(&mut buf);
            if seen < 0 {
                eprintf!("BIO_read failed\n");
                return Err(Exit::Shut);
            }
            let s = buf
                .get(..usize::try_from(seen).unwrap_or(0))
                .unwrap_or_default();
            if !contains(s, b"<proceed") {
                return Err(Exit::Shut);
            }
            mbuf.clear();
        }
        Proto::Telnet => {
            const TLS_DO: [u8; 3] = [255, 253, 46];
            const TLS_WILL: [u8; 3] = [255, 251, 46];
            const TLS_FOLLOWS: [u8; 6] = [255, 250, 46, 1, 255, 240];
            let mut buf = vec![0u8; BUFSIZZ];
            // The server should demand START_TLS.
            let n = sbio.read(&mut buf);
            if n != 3 || buf.get(..3) != Some(&TLS_DO[..]) {
                return Err(Exit::Shut);
            }
            // Agree, and send the FOLLOWS sub-command.
            sbio.write(&TLS_WILL);
            sbio.write(&TLS_FOLLOWS);
            sbio.flush();
            // The server sends FOLLOWS too.
            let n = sbio.read(&mut buf);
            if n != 6 || buf.get(..6) != Some(&TLS_FOLLOWS[..]) {
                return Err(Exit::Shut);
            }
        }
        Proto::Irc => {
            let Some(fbio) = Bio::new_buffer() else {
                eprintf!("Unable to create BIO\n");
                return Err(Exit::End);
            };
            fbio.push_borrowed(sbio);
            w(&fbio, "STARTTLS\r\n");
            fbio.flush();
            let fd = con.fd();
            let mut numeric;
            loop {
                numeric = 0;
                // An IRCd that doesn't answer within the timeout doesn't support STARTTLS
                // (many say nothing at all).
                if fbio.buffer_num_lines() == 0 && fbio.pending() == 0 && sbio.pending() == 0 {
                    let (r, _, _) = sock::select(
                        &[fd],
                        &[],
                        Some(Duration::from_secs(S_CLIENT_IRC_READ_TIMEOUT)),
                    );
                    if r < 1 {
                        eprintf!(
                            "Timeout waiting for response ({S_CLIENT_IRC_READ_TIMEOUT} seconds).\n"
                        );
                        break;
                    }
                }
                let n = gets(&fbio, mbuf);
                let text = String::from_utf8_lossy(mbuf).into_owned();
                let parsed = text.split_whitespace().nth(1).and_then(|w| {
                    let d: String = w
                        .chars()
                        .take_while(|c| c.is_ascii_digit() || *c == '-' || *c == '+')
                        .collect();
                    d.parse::<i32>().ok()
                });
                let Some(num) = parsed.filter(|_| n >= 1) else {
                    break;
                };
                numeric = num;
                // :example.net 451 STARTTLS :You have not registered
                // :example.net 421 STARTTLS :Unknown command
                if (numeric == 451 || numeric == 421) && text.contains("STARTTLS") {
                    eprintf!("STARTTLS not supported: {text}");
                    break;
                }
                if numeric == 691 {
                    eprintf!("STARTTLS negotiation failed: ");
                    break;
                }
                if numeric == 670 {
                    break;
                }
            }
            fbio.flush();
            fbio.pop_from_chain();
            drop(fbio);
            if numeric != 670 {
                eprintf!("Server does not support STARTTLS.\n");
                return Err(Exit::Shut);
            }
        }
        Proto::Mysql => {
            // The SSL request packet.
            const SSL_REQ: [u8; 36] = [
                0x20, 0x00, 0x00, 0x01, 0x85, 0xae, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x01, 0x21, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            let ssl_flg = 0x800;
            let bytes = sbio.read(sbuf);
            let packet: &[u8] = sbuf;
            let at = |i: usize| i32::from(packet.get(i).copied().unwrap_or(0));
            if bytes < 0 {
                eprintf!("BIO_read failed\n");
                return Err(Exit::Shut);
            } else if bytes < 21 {
                eprintf!("MySQL packet too short.\n");
                return Err(Exit::Shut);
            } else if bytes != 4 + at(0) + (at(1) << 8) + (at(2) << 16) {
                eprintf!("MySQL packet length does not match.\n");
                return Err(Exit::Shut);
            } else if at(4) != 0xA {
                eprintf!("Only MySQL protocol version 10 is supported.\n");
                return Err(Exit::Shut);
            }
            let bytes = usize::try_from(bytes).unwrap_or(0);
            let mut pos = 5usize;
            // The server version, NUL-terminated.
            loop {
                if pos >= bytes {
                    eprintf!("Cannot confirm server version. ");
                    return Err(Exit::Shut);
                }
                let c = packet.get(pos).copied().unwrap_or(0);
                pos += 1;
                if c == 0 {
                    break;
                }
            }
            // At least 15 bytes left.
            if pos + 15 > bytes {
                eprintf!("MySQL server handshake packet is broken.\n");
                return Err(Exit::Shut);
            }
            pos += 12; // connection id and salt
            let filler = packet.get(pos).copied().unwrap_or(0);
            pos += 1;
            if filler != 0 {
                eprintf!("MySQL packet is broken.\n");
                return Err(Exit::Shut);
            }
            // Capability flags.
            if (at(pos) + (at(pos + 1) << 8)) & ssl_flg == 0 {
                eprintf!("MySQL server does not support SSL.\n");
                return Err(Exit::Shut);
            }
            sbio.write(&SSL_REQ);
            sbio.flush();
        }
        Proto::Postgres => {
            const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 4, 210, 22, 47];
            sbio.write(&SSL_REQUEST);
            sbio.flush();
            // A single S if SSL is enabled.
            let bytes = sbio.read(sbuf);
            if bytes != 1 || sbuf.first() != Some(&b'S') {
                return Err(Exit::Shut);
            }
        }
        Proto::Nntp => {
            let mut foundit = false;
            let Some(fbio) = Bio::new_buffer() else {
                eprintf!("Unable to create BIO\n");
                return Err(Exit::End);
            };
            fbio.push_borrowed(sbio);
            gets(&fbio, mbuf);
            // STARTTLS command requires CAPABILITIES...
            w(&fbio, "CAPABILITIES\r\n");
            fbio.flush();
            gets(&fbio, mbuf);
            // No point in parsing the CAPABILITIES response if there is none.
            if contains(mbuf, b"101") {
                loop {
                    let n = gets(&fbio, mbuf);
                    if contains(mbuf, b"STARTTLS") {
                        foundit = true;
                    }
                    if !(n > 1 && mbuf.first() != Some(&b'.')) {
                        break;
                    }
                }
            }
            fbio.flush();
            fbio.pop_from_chain();
            drop(fbio);
            if !foundit {
                eprintf!("Didn't find STARTTLS in server response, trying anyway...\n");
            }
            w(sbio, "STARTTLS\r\n");
            let mut buf = vec![0u8; BUFSIZZ - 1];
            let n = sbio.read(&mut buf);
            if n < 0 {
                eprintf!("BIO_read failed\n");
                return Err(Exit::End);
            }
            *mbuf = buf
                .get(..usize::try_from(n).unwrap_or(0))
                .unwrap_or_default()
                .to_vec();
            if !contains(mbuf, b"382") {
                eprintf!("STARTTLS failed: {}", c_str(mbuf));
                return Err(Exit::Shut);
            }
        }
        Proto::Sieve => {
            let mut foundit = false;
            let Some(fbio) = Bio::new_buffer() else {
                eprintf!("Unable to create BIO\n");
                return Err(Exit::End);
            };
            fbio.push_borrowed(sbio);
            // Wait for the multi-line response to end.
            loop {
                let n = gets(&fbio, mbuf);
                // Capabilities are case-insensitive (RFC 5804, 1.7).
                if n > 1 && mbuf.first() == Some(&b'"') {
                    mbuf.make_ascii_uppercase();
                    if mbuf.starts_with(b"\"STARTTLS\"") {
                        foundit = true;
                    }
                }
                if !(n > 1 && mbuf.first() == Some(&b'"')) {
                    break;
                }
            }
            fbio.flush();
            fbio.pop_from_chain();
            drop(fbio);
            if !foundit {
                eprintf!("Didn't find STARTTLS in server response, trying anyway...\n");
            }
            w(sbio, "STARTTLS\r\n");
            let mut buf = vec![0u8; BUFSIZZ - 1];
            let n = sbio.read(&mut buf);
            if n < 0 {
                eprintf!("BIO_read failed\n");
                return Err(Exit::End);
            }
            *mbuf = buf
                .get(..usize::try_from(n).unwrap_or(0))
                .unwrap_or_default()
                .to_vec();
            if n < 2 {
                eprintf!("STARTTLS failed: {}", c_str(mbuf));
                return Err(Exit::Shut);
            }
            // Response codes are case-insensitive (RFC 5804, 2.2).
            if !mbuf.get(..2).is_some_and(|p| p.eq_ignore_ascii_case(b"OK")) {
                eprintf!("STARTTLS not supported: {}", c_str(mbuf));
                return Err(Exit::Shut);
            }
        }
        Proto::Ldap => {
            // The StartTLS operation of RFC 4511.
            const LDAP_TLS_GENCONF: &str = "asn1=SEQUENCE:LDAPMessage\n[LDAPMessage]\nmessageID=INTEGER:1\nextendedReq=EXPLICIT:23A,IMPLICIT:0C,FORMAT:ASCII,OCT:1.3.6.1.4.1.1466.20037\n";
            let seq = match ssl::asn1_generate_sequence(LDAP_TLS_GENCONF, "default", "asn1") {
                Err(l) if l <= 0 => {
                    eprintf!("NCONF_load_bio failed\n");
                    return Err(Exit::End);
                }
                Err(l) => {
                    eprintf!("Error on line {l}\n");
                    return Err(Exit::End);
                }
                Ok(None) => {
                    eprintf!("ASN1_generate_nconf failed\n");
                    return Err(Exit::End);
                }
                Ok(Some(s)) => s,
            };
            sbio.write(&seq);
            sbio.flush();
            let mut buf = vec![0u8; BUFSIZZ];
            let n = sbio.read(&mut buf);
            if n < 0 {
                eprintf!("BIO_read failed\n");
                return Err(Exit::End);
            }
            let result = ldap_extended_response_parse(
                buf.get(..usize::try_from(n).unwrap_or(0))
                    .unwrap_or_default(),
            );
            if result < 0 {
                eprintf!("ldap_ExtendedResponse_parse failed\n");
                return Err(Exit::Shut);
            } else if result > 0 {
                eprintf!("STARTTLS failed, LDAP Result Code: {result}\n");
                return Err(Exit::Shut);
            }
            mbuf.clear();
        }
    }
    Ok(())
}

/// A buffer as `%s` prints it: up to its first NUL.
fn c_str(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(b.get(..end).unwrap_or_default()).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_names() {
        assert!(is_dns_name("example.com"));
        assert!(!is_dns_name("localhost"));
        assert!(!is_dns_name("127.0.0.1"));
        assert!(!is_dns_name("a..b"));
        assert!(!is_dns_name("-a.b"));
        assert!(is_dns_name("a_b.c"));
    }

    #[test]
    fn tlsa_fields() {
        assert_eq!(checked_uint8("3 1 1 ab"), Some((3, "1 1 ab")));
        assert_eq!(checked_uint8("256 1"), None);
        assert_eq!(checked_uint8("3"), None);
        assert_eq!(hexdecode("ab cd"), Some(vec![0xab, 0xcd]));
        assert_eq!(hexdecode("abc"), None);
        assert_eq!(hexdecode("zz"), None);
    }

    #[test]
    fn ldap_response() {
        // SEQUENCE { INTEGER 1, [APPLICATION 24] { ENUMERATED 0, ... } }
        let ok = [
            0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
        ];
        assert_eq!(ldap_extended_response_parse(&ok), 0);
    }
}
