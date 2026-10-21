//! `openssl s_server` (`apps/s_server.c`).
//!
//! Standard output is upstream's `stdout` `FILE`: `bio_s_out` and `printf` write to a buffer
//! flushed where upstream flushes it (and at exit), while what the client sends goes to the
//! descriptor directly (`raw_write_stdout`), so the two interleave as upstream's do.

use std::cell::RefCell;
use std::rc::Rc;

use rustyssl_ossl::abi::*;
use rustyssl_ossl::ocsp_status::{self, CertId, OcspRequest, OcspResponse};
use rustyssl_ossl::sock;
use rustyssl_ossl::sock::consts::{AF_INET, AF_INET6, AF_UNIX, AF_UNSPEC, SOCK_DGRAM, SOCK_STREAM};
use rustyssl_ossl::ssl::{self, ConfCtx, Method, Session, SessionRef, Ssl, SslCtx, SslRef};
use rustyssl_ossl::ssl_cb::{BioCbArgs, MsgCallback};
use rustyssl_ossl::verify::VerifyParam;
use rustyssl_ossl::x509::CrlStack;
use rustyssl_ossl::{Bio, err};

use crate::generated::options::S;
use crate::generated::options::s_server::{OPTIONS, Opt};
use crate::lib::opt::{self, Parser, eprintf, fmt_flags, format};
use crate::lib::s_cb;
use crate::lib::s_socket::{self, do_ssl_shutdown};
use crate::lib::{app_libctx, app_rand, apps, engine, io};

/// `bufsize`.
const BUFSIZE: usize = 16 * 1024;
/// `DGRAM_RCV_TIMEOUT` and `DGRAM_SND_TIMEOUT` of `apps/timeouts.h`, in microseconds.
const DGRAM_TIMEOUT: i64 = 250_000;
/// `PORT` of `s_apps.h`.
const PORT: &str = "4433";
const TEST_CERT: &str = "server.pem";
const TEST_CERT2: &str = "server2.pem";
/// `MAX_SESSION_ID_ATTEMPTS`.
const MAX_SESSION_ID_ATTEMPTS: u32 = 10;

const CERT_TYPE_RPK: [u8; 2] = [
    TLSEXT_cert_type_rpk.to_le_bytes()[0],
    TLSEXT_cert_type_x509.to_le_bytes()[0],
];

/// `tlsextstatusctx`.
#[derive(Clone, Default)]
struct StatusCtx {
    timeout: i32,
    sk_resp_in: Option<Vec<String>>,
    host: Option<String>,
    path: Option<String>,
    port: Option<String>,
    proxy: Option<String>,
    no_proxy: Option<String>,
    use_ssl: bool,
    verbose: bool,
    status_all: bool,
}

/// The globals of `s_server.c` the callbacks and bodies read.
struct State {
    s_nbio: bool,
    s_nbio_test: bool,
    s_crlf: bool,
    ctx: Option<Rc<SslCtx>>,
    ctx2: Option<Rc<SslCtx>>,
    www: i32,
    bio_s_out: Option<Rc<Bio>>,
    bio_s_msg: Option<Rc<Bio>>,
    s_debug: bool,
    s_tlsextdebug: bool,
    s_msg: i32,
    s_quiet: bool,
    s_ign_eof: bool,
    s_brief: bool,
    keymatexportlabel: Option<String>,
    keymatexportlen: i32,
    async_: bool,
    session_id_prefix: Option<String>,
    enable_client_rpk: bool,
    enable_timeouts: bool,
    socket_mtu: i64,
    dtlslisten: bool,
    stateless: bool,
    early_data: bool,
    psksess: Option<Session>,
    psk_identity: String,
    psk_key: Option<String>,
    http_server_binmode: bool,
    local_argv: Vec<String>,
    accept_socket: i32,
    tlscstatp: StatusCtx,
    servername: Option<String>,
    servername_debug: bool,
    extension_error: i32,
    /// The external session cache (`simple_ssl_session`), newest first.
    sessions: Vec<(Vec<u8>, Vec<u8>)>,
    /// `read_counter` of `sv_body`, counted while it is `Some`.
    read_counter: Option<u32>,
    context: Option<String>,
}

thread_local! {
    static ST: RefCell<State> = RefCell::new(State {
        s_nbio: false,
        s_nbio_test: false,
        s_crlf: false,
        ctx: None,
        ctx2: None,
        www: 0,
        bio_s_out: None,
        bio_s_msg: None,
        s_debug: false,
        s_tlsextdebug: false,
        s_msg: 0,
        s_quiet: false,
        s_ign_eof: false,
        s_brief: false,
        keymatexportlabel: None,
        keymatexportlen: 20,
        async_: false,
        session_id_prefix: None,
        enable_client_rpk: false,
        enable_timeouts: false,
        socket_mtu: 0,
        dtlslisten: false,
        stateless: false,
        early_data: false,
        psksess: None,
        psk_identity: "Client_identity".to_owned(),
        psk_key: None,
        http_server_binmode: false,
        local_argv: Vec::new(),
        accept_socket: -1,
        tlscstatp: StatusCtx { timeout: -1, ..StatusCtx::default() },
        servername: None,
        servername_debug: false,
        extension_error: SSL_TLSEXT_ERR_ALERT_WARNING,
        sessions: Vec::new(),
        read_counter: None,
        context: None,
    });
}

fn st<T>(f: impl FnOnce(&State) -> T) -> T {
    ST.with(|s| f(&s.borrow()))
}

fn st_mut<T>(f: impl FnOnce(&mut State) -> T) -> T {
    ST.with(|s| f(&mut s.borrow_mut()))
}

fn bio_s_out() -> Option<Rc<Bio>> {
    st(|s| s.bio_s_out.clone())
}

fn sout(text: &str) {
    if let Some(b) = bio_s_out() {
        let _ = b.write_all(text.as_bytes());
    }
}

fn sflush() {
    if let Some(b) = bio_s_out() {
        b.flush();
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

/// `printf` to standard output.
fn printf(text: &str) {
    if let Some(o) = stdout_buffer() {
        let _ = o.write_all(text.as_bytes());
    }
}

fn raw_write_stdout(buf: &[u8]) -> isize {
    sock::write_fd(1, buf)
}

fn raw_read_stdin(buf: &mut [u8]) -> isize {
    sock::read_fd(0, buf)
}

fn psk_server_cb(s: SslRef<'_>, identity: Option<&str>, psk: &mut [u8]) -> u32 {
    let (debug, ident, key) = st(|s| (s.s_debug, s.psk_identity.clone(), s.psk_key.clone()));
    if debug {
        sout("psk_server_cb\n");
    }
    if !s.is_dtls() && s.version() >= TLS1_3_VERSION {
        // For TLS 1.2 and below; TLS 1.3 uses psk_find_session_cb.
        return 0;
    }
    let Some(identity) = identity else {
        eputs("Error: client did not send PSK identity\n");
        if debug {
            eputs("Error in PSK server callback\n");
        }
        if let Some(b) = io::bio_err() {
            b.flush();
        }
        sflush();
        return 0;
    };
    if debug {
        sout(&format!(
            "identity_len={} identity={identity}\n",
            identity.len()
        ));
    }
    // Here we could look up the identity, e.g. in a database.
    if identity != ident {
        sout(&format!(
            "PSK warning: client identity not what we expected (got '{identity}' expected '{ident}')\n"
        ));
    } else if debug {
        sout("PSK client identity found\n");
    }
    let key_hex = key.unwrap_or_default();
    let Some(k) = rustyssl_ossl::crypto::hexstr2buf(&key_hex) else {
        eputs(&format!(
            "Could not convert PSK key '{key_hex}' to buffer\n"
        ));
        return 0;
    };
    if k.len() > psk.len() {
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
        sout(&format!("fetched PSK len={}\n", k.len()));
    }
    u32::try_from(k.len()).unwrap_or(0)
}

/// `tls13_aes128gcmsha256_id`.
const TLS13_AES128GCMSHA256_ID: [u8; 2] = [0x13, 0x01];

fn psk_find_session_cb(s: SslRef<'_>, identity: &[u8]) -> Result<Option<Session>, ()> {
    let (ident, key, psksess) = st(|st| {
        (
            st.psk_identity.clone(),
            st.psk_key.clone(),
            st.psksess.as_ref().map(|p| p.r().up_ref()),
        )
    });
    if ident.as_bytes() != identity {
        return Ok(None);
    }
    if let Some(sess) = psksess {
        return sess.map(Some).ok_or(());
    }
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
    let tmp = Session::new().ok_or(())?;
    let r = tmp.r();
    if !r.set1_master_key(&k) || !r.set_cipher(cipher) || !r.set_protocol_version(s.version()) {
        return Err(());
    }
    Ok(Some(tmp))
}

fn ssl_servername_cb(s: SslRef<'_>, _ad: &mut i32) -> i32 {
    let servername = s.servername();
    let (want, debug, ext_err, ctx2) = st(|st| {
        (
            st.servername.clone(),
            st.servername_debug,
            st.extension_error,
            st.ctx2.clone(),
        )
    });
    if let Some(sn) = &servername
        && debug
    {
        let mut t = String::from("Hostname in TLS extension: \"");
        for &uc in sn {
            if uc & !127 == 0 && (uc.is_ascii_graphic() || uc == b' ') {
                t.push(char::from(uc));
            } else {
                t.push_str(&format!("\\x{uc:02x}"));
            }
        }
        t.push_str("\"\n");
        sout(&t);
    }
    let Some(want) = want else {
        return SSL_TLSEXT_ERR_NOACK;
    };
    if let Some(sn) = &servername {
        if !String::from_utf8_lossy(sn).eq_ignore_ascii_case(&want) {
            return ext_err;
        }
        if let Some(c2) = ctx2 {
            sout("Switching server context.\n");
            s.set_ssl_ctx(c2.r());
        }
    }
    SSL_TLSEXT_ERR_OK
}

/// `bring_ocsp_resp_in_correct_order`.
fn bring_ocsp_resp_in_correct_order(
    s: SslRef<'_>,
    srctx: &StatusCtx,
    mut unordered: Vec<Option<OcspResponse>>,
) -> Result<Vec<Option<OcspResponse>>, i32> {
    let server_chain = s.chain_certs();
    let mut num = 1usize;
    // DTLS 1.3 isn't considered yet.
    if let Some(ch) = &server_chain
        && srctx.status_all
        && !s.is_dtls()
        && s.version() >= TLS1_3_VERSION
    {
        num = ch.len() + 1;
    }
    // TLS < 1.3 servers can be configured without a certificate.
    let Some(first) = s.certificate().and_then(|c| ocsp_status::up_ref_cert(&c)) else {
        return Ok(Vec::new());
    };
    let chain: Vec<_> = server_chain
        .unwrap_or_default()
        .iter()
        .filter_map(ocsp_status::up_ref_cert)
        .collect();
    let mut out = Vec::with_capacity(num);
    for i in 0..num {
        let ssl_cert = if i == 0 {
            Some(&first)
        } else {
            chain.get(i - 1)
        };
        // The issuer is next in the chain.
        let issuer = chain.get(i);
        // Without the root in the chain, the last remaining response is taken to be its.
        if issuer.is_none() && i == num - 1 && unordered.len() == 1 {
            out.push(unordered.remove(0));
            continue;
        }
        let id = match (ssl_cert, issuer) {
            (Some(c), Some(is)) => CertId::new(c, is),
            _ => None,
        };
        let Some(id) = id else {
            out.push(None);
            continue;
        };
        // Find the response for this certificate.
        let mut found = None;
        for (j, r) in unordered.iter().enumerate() {
            if r.as_ref().is_some_and(|r| r.find(&id)) {
                found = Some(j);
                break;
            }
        }
        out.push(found.and_then(|j| unordered.remove(j)));
    }
    Ok(out)
}

/// `get_ocsp_resp_from_files`.
fn get_ocsp_resp_from_files(
    s: SslRef<'_>,
    srctx: &StatusCtx,
) -> Result<Vec<Option<OcspResponse>>, i32> {
    let files = srctx.sk_resp_in.clone().unwrap_or_default();
    let mut unordered = Vec::with_capacity(files.len());
    // As many responses as files.
    for respfile in &files {
        let Some(derbio) = apps::bio_open_default(Some(respfile), 'r', format::ASN1) else {
            eputs(&format!(
                "cert_status: Cannot open OCSP response file {respfile}\n"
            ));
            return Err(SSL_TLSEXT_ERR_ALERT_FATAL);
        };
        let Some(resp) = OcspResponse::read_der(&derbio) else {
            eputs(&format!(
                "cert_status: Error reading OCSP response from file {respfile}\n"
            ));
            return Err(SSL_TLSEXT_ERR_ALERT_FATAL);
        };
        unordered.push(Some(resp));
    }
    bring_ocsp_resp_in_correct_order(s, srctx, unordered)
}

/// `get_ocsp_resp_from_responder_single`: the response, or `SSL_TLSEXT_ERR_*`.
fn get_ocsp_resp_from_responder_single(
    s: SslRef<'_>,
    x: &rustyssl_ossl::x509::Cert,
    srctx: &StatusCtx,
) -> Result<OcspResponse, i32> {
    let (host, port, path, use_ssl);
    match ocsp_status::cert_ocsp_urls(x) {
        Some(aia) => {
            let url = aia.first().cloned().unwrap_or_default();
            let Some((ssl_, h, p, pa)) = ocsp_status::parse_url(&url) else {
                eputs("cert_status: can't parse AIA URL\n");
                return Err(SSL_TLSEXT_ERR_ALERT_FATAL);
            };
            if srctx.verbose {
                eputs(&format!("cert_status: AIA URL: {url}\n"));
            }
            (host, port, path, use_ssl) = (h, p, pa, ssl_);
        }
        None => {
            let Some(h) = &srctx.host else {
                eputs("cert_status: no AIA and no default responder URL\n");
                return Err(SSL_TLSEXT_ERR_NOACK);
            };
            host = h.clone();
            path = srctx.path.clone().unwrap_or_default();
            port = srctx.port.clone().unwrap_or_default();
            use_ssl = srctx.use_ssl;
        }
    }
    let Some(chain) = s.ctx().chain_certs() else {
        return Err(SSL_TLSEXT_ERR_ALERT_FATAL);
    };
    let mut id = None;
    for c in &chain {
        // The untrusted chain (-cert_chain) first.
        if ocsp_status::issued_by_name(x, c) {
            id = CertId::new(x, c);
            break;
        }
    }
    if id.is_none() {
        match ocsp_status::issuer_in_store(s, x) {
            None => return Err(SSL_TLSEXT_ERR_ALERT_FATAL),
            Some(None) => {
                eputs("cert_status: Can't retrieve issuer certificate.\n");
                return Err(SSL_TLSEXT_ERR_NOACK);
            }
            Some(Some(issuer)) => id = CertId::new(x, &issuer),
        }
    }
    let Some(id) = id else {
        return Err(SSL_TLSEXT_ERR_ALERT_FATAL);
    };
    let Some(req) = OcspRequest::new() else {
        return Err(SSL_TLSEXT_ERR_ALERT_FATAL);
    };
    if !req.add0_id(id) {
        return Err(SSL_TLSEXT_ERR_ALERT_FATAL);
    }
    // Any extensions of the request.
    if !s.add_status_exts_to(&req) {
        return Err(SSL_TLSEXT_ERR_ALERT_FATAL);
    }
    let resp = ocsp_status::process_responder(
        &req,
        &host,
        &port,
        &path,
        srctx.proxy.as_deref(),
        srctx.no_proxy.as_deref(),
        use_ssl,
        srctx.timeout,
        io::bio_err(),
        &opt::prog(),
    );
    match resp {
        Some(r) => Ok(r),
        None => {
            eputs("Error querying OCSP responder\n");
            eputs("cert_status: error querying responder\n");
            Err(SSL_TLSEXT_ERR_NOACK)
        }
    }
}

/// `get_ocsp_resp_from_responder`.
fn get_ocsp_resp_from_responder(
    s: SslRef<'_>,
    srctx: &StatusCtx,
) -> Result<Vec<Option<OcspResponse>>, i32> {
    let server_chain = s.chain_certs();
    let num = match &server_chain {
        Some(ch) if srctx.status_all && !s.is_dtls() && s.version() >= TLS1_3_VERSION => {
            ch.len() + 1
        }
        _ => 1,
    };
    let Some(first) = s.certificate().and_then(|c| ocsp_status::up_ref_cert(&c)) else {
        return Ok(Vec::new());
    };
    let chain: Vec<_> = server_chain
        .unwrap_or_default()
        .iter()
        .filter_map(ocsp_status::up_ref_cert)
        .collect();
    let mut out = Vec::with_capacity(num);
    for i in 0..num {
        let cert = if i == 0 {
            Some(&first)
        } else {
            chain.get(i - 1)
        };
        let resp = cert.and_then(|c| get_ocsp_resp_from_responder_single(s, c, srctx).ok());
        out.push(resp);
    }
    Ok(out)
}

/// `cert_status_cb`.
fn cert_status_cb(s: SslRef<'_>) -> i32 {
    let srctx = st(|st| st.tlscstatp.clone());
    if srctx.verbose {
        eputs("cert_status: callback called\n");
    }
    let existing = s.tlsext_status_ocsp_resp_ex();
    if existing.as_ref().is_none_or(Vec::is_empty) {
        let got = if srctx.sk_resp_in.is_some() {
            get_ocsp_resp_from_files(s, &srctx).ok()
        } else {
            match get_ocsp_resp_from_responder(s, &srctx) {
                Ok(v) => Some(v),
                Err(r) => {
                    io::print_errors();
                    return r;
                }
            }
        };
        if srctx.verbose {
            print_sent(got.as_deref());
        }
        let _ = s.set0_tlsext_status_ocsp_resp_ex(got.unwrap_or_default());
        return SSL_TLSEXT_ERR_OK;
    }
    if srctx.verbose {
        // The responses already set on the connection.
        eputs("cert_status: ocsp response sent:\n");
        let list = existing.unwrap_or_default();
        eputs(&format!(
            "cert_status: number of responses: {}\n",
            list.len()
        ));
        for (i, r) in list.iter().enumerate() {
            match r {
                Some(der) => {
                    if let Some(be) = io::bio_err() {
                        ssl::ocsp_response_print(be, der, 2);
                    }
                }
                None => eputs(&format!(
                    "cert_status: no ocsp response for certificate with index {i}\n"
                )),
            }
        }
    }
    SSL_TLSEXT_ERR_OK
}

/// The verbose report of the responses set; `None` is upstream's NULL stack (count -1).
fn print_sent(list: Option<&[Option<OcspResponse>]>) {
    eputs("cert_status: ocsp response sent:\n");
    let Some(list) = list else {
        eputs("cert_status: number of responses: -1\n");
        return;
    };
    eputs(&format!(
        "cert_status: number of responses: {}\n",
        list.len()
    ));
    for (i, r) in list.iter().enumerate() {
        match r {
            Some(resp) => {
                if let Some(be) = io::bio_err() {
                    resp.print(be, 2);
                }
            }
            None => eputs(&format!(
                "cert_status: no ocsp response for certificate with index {i}\n"
            )),
        }
    }
}

fn alpn_cb(_s: SslRef<'_>, input: &[u8], selected: Option<&[u8]>) {
    if st(|s| s.s_quiet) {
        return;
    }
    let Some(out) = bio_s_out() else { return };
    match selected {
        None => {
            let _ = out.write_all(b"ALPN protocols advertised by the client: ");
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
        Some(sel) => {
            let _ = out.write_all(b"ALPN protocols selected: ");
            let _ = out.write_all(sel);
            let _ = out.write_all(b"\n");
        }
    }
}

fn not_resumable_sess_cb(_s: SslRef<'_>, is_forward_secure: i32) -> i32 {
    // Resumption is disabled for sessions with forward-secure ciphers.
    is_forward_secure
}

fn generate_session_id(s: SslRef<'_>, id: &mut [u8]) -> i32 {
    let prefix = st(|st| st.session_id_prefix.clone()).unwrap_or_default();
    let mut count = 0;
    loop {
        if !ssl::rand_bytes(id) {
            return 0;
        }
        // The prefix, clipped if it's too long.
        let n = prefix.len().min(id.len());
        if let (Some(dst), Some(src)) = (id.get_mut(..n), prefix.as_bytes().get(..n)) {
            dst.copy_from_slice(src);
        }
        count += 1;
        if !(s.has_matching_session_id(id) && count < MAX_SESSION_ID_ATTEMPTS) {
            break;
        }
    }
    i32::from(count < MAX_SESSION_ID_ATTEMPTS)
}

fn add_session(_s: SslRef<'_>, session: SessionRef<'_>) -> i32 {
    let Some(der) = session.to_der() else {
        eputs("Error encoding session\n");
        return 0;
    };
    let id = session.id();
    st_mut(|st| st.sessions.insert(0, (id, der)));
    eputs("New session added to external cache\n");
    0
}

fn get_session(_s: SslRef<'_>, id: &[u8]) -> Option<Session> {
    let der = st(|st| {
        st.sessions
            .iter()
            .find(|(i, _)| i == id)
            .map(|(_, d)| d.clone())
    });
    match der {
        Some(d) => {
            eputs("Lookup session: cache hit\n");
            let libctx = app_libctx::libctx();
            Session::from_der(&d, libctx.as_deref(), app_libctx::propq().as_deref())
        }
        None => {
            eputs("Lookup session: cache miss\n");
            None
        }
    }
}

fn del_session(session: SessionRef<'_>) {
    let id = session.id();
    st_mut(|st| {
        if let Some(i) = st.sessions.iter().position(|(x, _)| *x == id) {
            st.sessions.remove(i);
        }
    });
}

fn init_session_cache_ctx(sctx: rustyssl_ossl::ssl::CtxRef<'_>) {
    sctx.set_session_cache_mode((SSL_SESS_CACHE_NO_INTERNAL | SSL_SESS_CACHE_SERVER).into());
    sctx.sess_set_new_cb(add_session);
    sctx.sess_set_get_cb(get_session);
    sctx.sess_set_remove_cb(del_session);
}

fn print_stats(bio: &Bio, ctx: rustyssl_ossl::ssl::CtxRef<'_>) {
    let n = |cmd| ctx.sess_stat(cmd);
    let mut t = String::new();
    t.push_str(&format!(
        "{:4} items in the session cache\n",
        n(SSL_CTRL_SESS_NUMBER)
    ));
    t.push_str(&format!(
        "{:4} client connects (SSL_connect())\n",
        n(SSL_CTRL_SESS_CONNECT)
    ));
    t.push_str(&format!(
        "{:4} client renegotiates (SSL_connect())\n",
        n(SSL_CTRL_SESS_CONNECT_RENEGOTIATE)
    ));
    t.push_str(&format!(
        "{:4} client connects that finished\n",
        n(SSL_CTRL_SESS_CONNECT_GOOD)
    ));
    t.push_str(&format!(
        "{:4} server accepts (SSL_accept())\n",
        n(SSL_CTRL_SESS_ACCEPT)
    ));
    t.push_str(&format!(
        "{:4} server renegotiates (SSL_accept())\n",
        n(SSL_CTRL_SESS_ACCEPT_RENEGOTIATE)
    ));
    t.push_str(&format!(
        "{:4} server accepts that finished\n",
        n(SSL_CTRL_SESS_ACCEPT_GOOD)
    ));
    t.push_str(&format!("{:4} session cache hits\n", n(SSL_CTRL_SESS_HIT)));
    t.push_str(&format!(
        "{:4} session cache misses\n",
        n(SSL_CTRL_SESS_MISSES)
    ));
    t.push_str(&format!(
        "{:4} session cache timeouts\n",
        n(SSL_CTRL_SESS_TIMEOUTS)
    ));
    t.push_str(&format!(
        "{:4} callback cache hits\n",
        n(SSL_CTRL_SESS_CB_HIT)
    ));
    t.push_str(&format!(
        "{:4} cache full overflows ({} allowed)\n",
        n(SSL_CTRL_SESS_CACHE_FULL),
        ctx.sess_get_cache_size()
    ));
    let _ = bio.write_all(t.as_bytes());
}

/// `count_reads_callback`: counts the reads during `init_ssl_connection`, and dumps them with
/// `-debug`.
fn count_reads_callback(a: &BioCbArgs<'_>) -> core::ffi::c_long {
    if a.cmd == BIO_CB_READ || a.cmd == BIO_CB_GETS {
        st_mut(|s| {
            if let Some(c) = s.read_counter.as_mut() {
                *c += 1;
            }
        });
    }
    if st(|s| s.s_debug)
        && let Some(out) = bio_s_out()
    {
        s_cb::bio_dump(&out, a);
    }
    core::ffi::c_long::from(a.ret)
}

fn is_retryable(con: SslRef<'_>, i: i32) -> bool {
    let e = con.get_error(i);
    // Not fatal: retryable.
    e != SSL_ERROR_SSL && e != SSL_ERROR_SYSCALL && e != SSL_ERROR_ZERO_RETURN
}

fn close_accept_socket() {
    eputs("shutdown accept socket\n");
    let s = st(|s| s.accept_socket);
    if s >= 0 {
        sock::closesocket(s);
    }
}

fn init_ssl_connection(con: SslRef<'_>) -> i32 {
    let (dtlslisten, stateless) = st(|s| (s.dtlslisten, s.stateless));
    let mut i;
    let mut retry = false;
    if dtlslisten || stateless {
        if dtlslisten {
            let (r, client) = con.dtls_listen();
            i = r;
            if client.is_none() {
                eputs("ERROR - memory\n");
                return 0;
            }
            if i > 0 {
                let wbio = con.wbio();
                let fd = wbio.as_ref().map_or(-1, |b| b.fd());
                let ok = match (&wbio, &client) {
                    (Some(_), Some(c)) => sock::connect_addr(fd, c, 0),
                    _ => false,
                };
                if !ok {
                    eputs("ERROR - unable to connect\n");
                    return 0;
                }
                if let (Some(w), Some(c)) = (&wbio, &client) {
                    let _ = w.set_connected(c);
                }
                st_mut(|s| s.dtlslisten = false);
                i = con.accept();
            }
        } else {
            i = con.stateless();
            if i > 0 {
                st_mut(|s| s.stateless = false);
                i = con.accept();
            }
        }
    } else {
        loop {
            i = con.accept();
            if i <= 0 {
                retry = is_retryable(con, i);
            }
            while i <= 0 && con.get_error(i) == SSL_ERROR_WANT_X509_LOOKUP {
                let login = s_cb::srp_login().unwrap_or_else(|| "<NULL>".to_owned());
                sout(&format!("LOOKUP during accept {login}\n"));
                if let Some(o) = bio_s_out() {
                    s_cb::lookup_srp_user(&o);
                }
                i = con.accept();
                if i <= 0 {
                    retry = is_retryable(con, i);
                }
            }
            if !(i < 0 && con.waiting_for_async()) {
                break;
            }
        }
    }
    if i <= 0 {
        if ((dtlslisten || stateless) && i == 0) || (!dtlslisten && !stateless && retry) {
            sout("DELAY\n");
            return 1;
        }
        eputs("ERROR\n");
        let verify_err = con.verify_result();
        if verify_err != core::ffi::c_long::from(X509_V_OK) {
            eputs(&format!(
                "verify error:{}\n",
                ssl::verify_cert_error_string(verify_err)
            ));
        }
        // Always print any error messages.
        io::print_errors();
        return 0;
    }
    print_connection_info(con);
    1
}

fn print_connection_info(con: SslRef<'_>) {
    let Some(out) = bio_s_out() else { return };
    let (brief, label, explen, client_rpk) = st(|s| {
        (
            s.s_brief,
            s.keymatexportlabel.clone(),
            s.keymatexportlen,
            s.enable_client_rpk,
        )
    });
    let p = |t: &str| {
        let _ = out.write_all(t.as_bytes());
    };
    if brief {
        s_cb::print_ssl_summary(con);
    }
    if let Some(sess) = con.session() {
        sess.write_pem(&out);
    }
    if let Some(peer) = con.peer_certificate() {
        p("Client certificate\n");
        ssl::write_cert_pem(&out, &peer);
        apps::dump_cert_text(&out, &peer);
    }
    // RPK information only when configured.
    if con.negotiated_server_cert_type() == TLSEXT_cert_type_rpk {
        p("Server-to-client raw public key negotiated\n");
    }
    if con.negotiated_client_cert_type() == TLSEXT_cert_type_rpk {
        p("Client-to-server raw public key negotiated\n");
    }
    if client_rpk && let Some(k) = con.peer_rpk() {
        p("Client raw public key\n");
        k.print_public(&out, 2);
    }
    if let Some(sc) = con.shared_ciphers(8192) {
        p(&format!("Shared ciphers:{sc}\n"));
    }
    let name = con.current_cipher().and_then(|c| c.name());
    s_cb::ssl_print_sigalgs(&out, con);
    s_cb::ssl_print_point_formats(&out, con);
    s_cb::ssl_print_groups(&out, con, false);
    s_cb::print_ca_names(&out, con);
    p(&format!(
        "CIPHER is {}\n",
        name.as_deref().unwrap_or("(NONE)")
    ));
    if let Some(np) = con.next_proto_negotiated() {
        p("NEXTPROTO is ");
        let _ = out.write_all(&np);
        p("\n");
    }
    if let Some(name) = con.selected_srtp_profile() {
        p(&format!("SRTP Extension negotiated, profile={name}\n"));
    }
    if con.session_reused() {
        p("Reused session-id\n");
    }
    s_cb::ssl_print_secure_renegotiation_notes(&out, con);
    if con.options() & SSL_OP_NO_RENEGOTIATION != 0 {
        p("Renegotiation is DISABLED\n");
    }
    if let Some(label) = &label {
        p("Keying material exporter:\n");
        p(&format!("    Label: '{label}'\n"));
        p(&format!("    Length: {explen} bytes\n"));
        match con.export_keying_material(usize::try_from(explen).unwrap_or(0), label) {
            None => p("    Error\n"),
            Some(m) => {
                let hex: String = m.iter().map(|b| format!("{b:02X}")).collect();
                p(&format!("    Keying material: {hex}\n"));
            }
        }
    }
    out.flush();
}

/// Sets up a connection's debugging callbacks (`-tlsextdebug`, `-msg`, `-trace`).
fn set_msg_and_tlsext(con: SslRef<'_>) {
    let (msg, tlsext, out, mbio) = st(|s| {
        (
            s.s_msg,
            s.s_tlsextdebug,
            s.bio_s_out.clone(),
            s.bio_s_msg.clone(),
        )
    });
    let Some(out) = out else { return };
    if msg != 0 {
        let cb = if msg == 2 {
            MsgCallback::Trace
        } else {
            MsgCallback::Rust(s_cb::msg_cb)
        };
        let target = mbio.unwrap_or_else(|| out.clone());
        con.set_msg_callback(cb, &target);
    }
    let _ = tlsext;
}

fn set_tlsext_debug(con: SslRef<'_>) {
    if st(|s| s.s_tlsextdebug)
        && let Some(out) = bio_s_out()
    {
        con.set_tlsext_debug_callback(s_cb::tlsext_cb, &out);
    }
}

/// `sv_body`.
#[allow(clippy::too_many_lines)]
fn sv_body(s: i32, stype: i32, _prot: i32) -> i32 {
    let mut ret = 1;
    let isdtls = stype == SOCK_DGRAM;
    let (s_nbio, s_quiet, s_nbio_test, ctx, context, s_crlf, s_brief, early_data, async_) =
        st(|st| {
            (
                st.s_nbio,
                st.s_quiet,
                st.s_nbio_test,
                st.ctx.clone(),
                st.context.clone(),
                st.s_crlf,
                st.s_brief,
                st.early_data,
                st.async_,
            )
        });
    let mut buf = vec![0u8; BUFSIZE];
    if s_nbio {
        if !sock::socket_nbio(s, 1) {
            io::print_errors();
        } else if !s_quiet {
            eputs("Turned on non blocking io\n");
        }
    }
    let Some(ctx) = ctx else { return -1 };
    let Some(con_owned) = Ssl::new(ctx.r()) else {
        return sv_end(None, -1);
    };
    let con = con_owned.r();
    set_tlsext_debug(con);
    if let Some(c) = &context
        && !con.set_session_id_context(c.as_bytes())
    {
        eputs("Error setting session id context\n");
        return sv_end(Some(con), -1);
    }
    if !con.clear() {
        eputs("Error clearing SSL connection\n");
        return sv_end(Some(con), -1);
    }
    let sbio = if isdtls {
        let Some(b) = Bio::new_dgram(s) else {
            eputs("Unable to create BIO\n");
            io::print_errors();
            return sv_end(Some(con), ret);
        };
        let (enable_timeouts, socket_mtu) = st(|st| (st.enable_timeouts, st.socket_mtu));
        if enable_timeouts {
            b.dgram_set_timeout(BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, DGRAM_TIMEOUT);
            b.dgram_set_timeout(BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, DGRAM_TIMEOUT);
        }
        if socket_mtu != 0 {
            let min = con.dtls_link_min_mtu();
            if socket_mtu < min {
                eputs(&format!("MTU too small. Must be at least {min}\n"));
                return sv_end(Some(con), -1);
            }
            con.set_options(SSL_OP_NO_QUERY_MTU);
            if !con.dtls_set_link_mtu(socket_mtu) {
                eputs("Failed to set MTU\n");
                return sv_end(Some(con), -1);
            }
        } else {
            // MTU discovery.
            b.ctrl_long(BIO_CTRL_DGRAM_MTU_DISCOVER, 0);
        }
        // Cookie exchange.
        con.set_options(SSL_OP_COOKIE_EXCHANGE);
        b
    } else {
        let Some(b) = Bio::new_socket(s) else {
            eputs("Unable to create BIO\n");
            io::print_errors();
            return sv_end(Some(con), ret);
        };
        b
    };
    let sbio = if s_nbio_test {
        let Some(test) = Bio::new_nbio_test() else {
            eputs("Unable to create BIO\n");
            return sv_end(Some(con), -1);
        };
        test.push(sbio)
    } else {
        sbio
    };
    con.set_bio(sbio);
    con.set_accept_state();
    if let Some(rb) = con.rbio() {
        rb.set_callback_ex(count_reads_callback);
    }
    set_msg_and_tlsext(con);
    set_tlsext_debug(con);

    if early_data {
        let mut write_header = true;
        let mut edret = SSL_READ_EARLY_DATA_ERROR;
        while edret != SSL_READ_EARLY_DATA_FINISH {
            let readbytes;
            loop {
                let (r, n) = con.read_early_data(&mut buf);
                edret = r;
                if edret != SSL_READ_EARLY_DATA_ERROR {
                    readbytes = n;
                    break;
                }
                match con.get_error(0) {
                    SSL_ERROR_WANT_WRITE | SSL_ERROR_WANT_ASYNC | SSL_ERROR_WANT_READ => continue,
                    _ => {
                        eputs("Error reading early data\n");
                        io::print_errors();
                        return sv_end(Some(con), ret);
                    }
                }
            }
            if readbytes > 0 {
                if write_header {
                    sout("Early data received:\n");
                    write_header = false;
                }
                raw_write_stdout(buf.get(..readbytes).unwrap_or_default());
                sflush();
            }
        }
        if write_header {
            if con.early_data_status() == SSL_EARLY_DATA_NOT_SENT {
                sout("No early data received\n");
            } else {
                sout("Early data was rejected\n");
            }
        } else {
            sout("\nEnd of early data\n");
        }
        if con.is_init_finished() {
            print_connection_info(con);
        }
    }

    loop {
        let mut read_from_terminal = false;
        let mut read_from_sslcon = con.has_pending() || (async_ && con.waiting_for_async());
        if !read_from_sslcon {
            let timeout = if con.is_dtls() {
                con.dtls_timeout()
            } else {
                None
            };
            let (i, r, _) = sock::select(&[0, s], &[], timeout);
            if con.is_dtls() && con.dtls_handle_timeout() > 0 {
                eputs("TIMEOUT occurred\n");
            }
            if i <= 0 {
                continue;
            }
            if r.first() == Some(&true) {
                read_from_terminal = true;
            }
            if r.get(1) == Some(&true) {
                read_from_sslcon = true;
            }
        }
        if read_from_terminal {
            let mut i: isize;
            if s_crlf {
                let half = BUFSIZE / 2;
                let mut tmp = vec![0u8; half];
                i = raw_read_stdin(&mut tmp);
                if i > 0 {
                    let mut out = Vec::new();
                    for &b in tmp
                        .get(..usize::try_from(i).unwrap_or(0))
                        .unwrap_or_default()
                    {
                        if b == b'\n' {
                            out.push(b'\r');
                        }
                        out.push(b);
                    }
                    if let Some(dst) = buf.get_mut(..out.len()) {
                        dst.copy_from_slice(&out);
                    }
                    i = isize::try_from(out.len()).unwrap_or(0);
                }
            } else {
                i = raw_read_stdin(&mut buf);
            }
            if !s_quiet && !s_brief {
                let b0 = buf.first().copied().unwrap_or(0);
                let b1 = buf.get(1).copied().unwrap_or(0);
                let eol = b1 == b'\n' || b1 == b'\r';
                if i <= 0 || b0 == b'Q' {
                    sout("DONE\n");
                    sflush();
                    sock::closesocket(s);
                    close_accept_socket();
                    return sv_end(Some(con), -11);
                }
                if b0 == b'q' {
                    sout("DONE\n");
                    sflush();
                    if con.version() != DTLS1_VERSION {
                        sock::closesocket(s);
                    }
                    return sv_end(Some(con), ret);
                }
                if b0 == b'r' && eol {
                    con.renegotiate();
                    let r = con.do_handshake();
                    printf(&format!("SSL_do_handshake -> {r}\n"));
                    continue;
                }
                if b0 == b'R' && eol {
                    con.set_verify_mode(SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE);
                    con.renegotiate();
                    let r = con.do_handshake();
                    printf(&format!("SSL_do_handshake -> {r}\n"));
                    continue;
                }
                if (b0 == b'K' || b0 == b'k') && eol {
                    con.key_update(if b0 == b'K' {
                        SSL_KEY_UPDATE_REQUESTED
                    } else {
                        SSL_KEY_UPDATE_NOT_REQUESTED
                    });
                    let r = con.do_handshake();
                    printf(&format!("SSL_do_handshake -> {r}\n"));
                    continue;
                }
                if b0 == b'c' && eol {
                    con.set_verify_mode(SSL_VERIFY_PEER);
                    if con.verify_client_post_handshake() == 0 {
                        printf("Failed to initiate request\n");
                        io::print_errors();
                    } else {
                        let r = con.do_handshake();
                        printf(&format!("SSL_do_handshake -> {r}\n"));
                    }
                    continue;
                }
                if b0 == b'P'
                    && let Some(w) = con.wbio()
                {
                    let _ = w.write_all(b"Lets print some clear text\n");
                }
                if b0 == b'S'
                    && let Some(out) = bio_s_out()
                {
                    print_stats(&out, con.ctx());
                }
            }
            let mut l = 0usize;
            let mut remaining = usize::try_from(i).unwrap_or(0);
            loop {
                let mut k = con.write(buf.get(l..l + remaining).unwrap_or_default());
                while con.get_error(k) == SSL_ERROR_WANT_X509_LOOKUP {
                    sout("LOOKUP renego during write\n");
                    if let Some(o) = bio_s_out() {
                        s_cb::lookup_srp_user(&o);
                    }
                    k = con.write(buf.get(l..l + remaining).unwrap_or_default());
                }
                match con.get_error(k) {
                    SSL_ERROR_NONE => {}
                    SSL_ERROR_WANT_ASYNC => {
                        sout("Write BLOCK (Async)\n");
                        sflush();
                        s_cb::wait_for_async(con);
                    }
                    SSL_ERROR_WANT_WRITE | SSL_ERROR_WANT_READ | SSL_ERROR_WANT_X509_LOOKUP => {
                        sout("Write BLOCK\n");
                        sflush();
                    }
                    SSL_ERROR_WANT_ASYNC_JOB | SSL_ERROR_SYSCALL | SSL_ERROR_SSL => {
                        sout("ERROR\n");
                        sflush();
                        io::print_errors();
                        return sv_end(Some(con), 1);
                    }
                    SSL_ERROR_ZERO_RETURN => {
                        sout("DONE\n");
                        sflush();
                        return sv_end(Some(con), 1);
                    }
                    _ => {}
                }
                if k > 0 {
                    let kk = usize::try_from(k).unwrap_or(0);
                    l += kk;
                    remaining = remaining.saturating_sub(kk);
                }
                if remaining == 0 {
                    break;
                }
            }
        }
        if read_from_sslcon {
            // init_ssl_connection handles the async events itself.
            if (!async_ || !con.waiting_for_async()) && !con.is_init_finished() {
                // Reads during the handshake tell configuration errors from the client's.
                st_mut(|s| s.read_counter = Some(0));
                let i = init_ssl_connection(con);
                let read_counter = st_mut(|s| s.read_counter.take()).unwrap_or(0);
                // A failure without reads is a configuration error.
                if i <= 0 && read_counter == 0 {
                    return sv_end(Some(con), -1);
                }
                if i < 0 {
                    return sv_end(Some(con), 0);
                } else if i == 0 {
                    return sv_end(Some(con), 1);
                }
            } else {
                loop {
                    let mut i = con.read(&mut buf);
                    while con.get_error(i) == SSL_ERROR_WANT_X509_LOOKUP {
                        sout("LOOKUP renego during read\n");
                        if let Some(o) = bio_s_out() {
                            s_cb::lookup_srp_user(&o);
                        }
                        i = con.read(&mut buf);
                    }
                    match con.get_error(i) {
                        SSL_ERROR_NONE => {
                            raw_write_stdout(
                                buf.get(..usize::try_from(i).unwrap_or(0))
                                    .unwrap_or_default(),
                            );
                            sflush();
                            if con.has_pending() {
                                continue;
                            }
                        }
                        SSL_ERROR_WANT_ASYNC => {
                            sout("Read BLOCK (Async)\n");
                            sflush();
                            s_cb::wait_for_async(con);
                        }
                        SSL_ERROR_WANT_WRITE | SSL_ERROR_WANT_READ => {
                            sout("Read BLOCK\n");
                            sflush();
                        }
                        SSL_ERROR_WANT_ASYNC_JOB | SSL_ERROR_SYSCALL | SSL_ERROR_SSL => {
                            sout("ERROR\n");
                            sflush();
                            io::print_errors();
                            return sv_end(Some(con), 1);
                        }
                        SSL_ERROR_ZERO_RETURN => {
                            sout("DONE\n");
                            sflush();
                            return sv_end(Some(con), 1);
                        }
                        _ => {}
                    }
                    break;
                }
            }
        }
        let _ = &mut ret;
    }
}

/// `sv_body`'s `err:` label.
fn sv_end(con: Option<SslRef<'_>>, ret: i32) -> i32 {
    if let Some(c) = con {
        sout("shutting down SSL\n");
        do_ssl_shutdown(c);
    }
    sout("CONNECTION CLOSED\n");
    ret
}

/// `www_body` (`-www`, `-WWW`, `-HTTP`).
#[allow(clippy::too_many_lines)]
fn www_body(s: i32, _stype: i32, _prot: i32) -> i32 {
    let mut ret = 1;
    let (s_nbio, s_quiet, s_nbio_test, ctx, context, early_data, www, s_debug, binmode, argv) =
        st(|st| {
            (
                st.s_nbio,
                st.s_quiet,
                st.s_nbio_test,
                st.ctx.clone(),
                st.context.clone(),
                st.early_data,
                st.www,
                st.s_debug,
                st.http_server_binmode,
                st.local_argv.clone(),
            )
        });
    // BIO_gets NUL-terminates: a byte more for a whole 2^14-byte record.
    let mut buf = vec![0u8; BUFSIZE + 1];
    let (Some(io_bio), Some(ssl_bio), Some(edio)) =
        (Bio::new_buffer(), Bio::new_ssl_filter(), Bio::new_mem())
    else {
        return ret;
    };
    if s_nbio {
        if !sock::socket_nbio(s, 1) {
            io::print_errors();
        } else if !s_quiet {
            eputs("Turned on non blocking io\n");
        }
    }
    // A reasonable output buffer.
    if io_bio.set_write_buffer_size(core::ffi::c_long::try_from(BUFSIZE).unwrap_or(0)) <= 0 {
        return ret;
    }
    let Some(ctx) = ctx else { return ret };
    let Some(con_owned) = Ssl::new(ctx.r()) else {
        return ret;
    };
    let con_ptr = con_owned.r().as_ptr();
    set_tlsext_debug(con_owned.r());
    if let Some(c) = &context
        && !con_owned.r().set_session_id_context(c.as_bytes())
    {
        return ret;
    }
    let Some(sbio) = Bio::new_socket(s) else {
        return ret;
    };
    let sbio = if s_nbio_test {
        let Some(test) = Bio::new_nbio_test() else {
            return ret;
        };
        test.push(sbio)
    } else {
        sbio
    };
    con_owned.r().set_bio(sbio);
    con_owned.r().set_accept_state();
    // The SSL BIO frees the connection.
    ssl_bio.set_ssl(con_owned);
    let io_bio = io_bio.push(ssl_bio);
    let Some(con) = io_bio.ssl() else {
        return ret;
    };
    debug_assert_eq!(con.as_ptr(), con_ptr);
    if s_debug
        && let Some(rb) = con.rbio()
        && let Some(out) = bio_s_out()
    {
        rb.set_callback_ex(s_cb::bio_dump_callback);
        rb.set_callback_arg_bio(Some(&out));
    }
    set_msg_and_tlsext(con);

    if early_data {
        let mut edret = SSL_READ_EARLY_DATA_ERROR;
        while edret != SSL_READ_EARLY_DATA_FINISH {
            let readbytes;
            loop {
                let (r, n) = con.read_early_data(buf.get_mut(..BUFSIZE).unwrap_or_default());
                edret = r;
                if edret != SSL_READ_EARLY_DATA_ERROR {
                    readbytes = n;
                    break;
                }
                match con.get_error(0) {
                    SSL_ERROR_WANT_WRITE | SSL_ERROR_WANT_ASYNC | SSL_ERROR_WANT_READ => continue,
                    _ => {
                        eputs("Error reading early data\n");
                        io::print_errors();
                        return ret;
                    }
                }
            }
            if readbytes > 0 {
                edio.write(buf.get(..readbytes).unwrap_or_default());
            }
        }
    }

    let w = |b: &Bio, t: &str| {
        let _ = b.write_all(t.as_bytes());
    };
    loop {
        let src: &Bio = if !edio.eof() { &edio } else { &io_bio };
        let i = src.gets_into(&mut buf);
        if i < 0 {
            if !io_bio.should_retry() && !con.waiting_for_async() {
                if !s_quiet {
                    io::print_errors();
                }
                return ret;
            }
            sout("read R BLOCK\n");
            if io_bio.should_io_special() && io_bio.retry_reason() == BIO_RR_SSL_X509_LOOKUP {
                sout("LOOKUP renego during read\n");
                if let Some(o) = bio_s_out() {
                    s_cb::lookup_srp_user(&o);
                }
                continue;
            }
            ssl::sleep_ms(1000);
            continue;
        } else if i == 0 {
            // End of input.
            ret = 1;
            do_ssl_shutdown(con);
            return ret;
        }
        let line_len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let line = buf.get(..line_len).unwrap_or_default().to_vec();
        if (www == 1 && line.starts_with(b"GET ")) || (www == 2 && line.starts_with(b"GET /stats "))
        {
            const SPACE: &str = "                          ";
            if www == 1 && line.starts_with(b"GET /reneg") {
                if line.starts_with(b"GET /renegcert") {
                    con.set_verify_mode(SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE);
                }
                let r = con.renegotiate();
                sout(&format!("SSL_renegotiate -> {r}\n"));
                // Send the HelloRequest.
                let r = con.do_handshake();
                if r <= 0 {
                    sout(&format!("SSL_do_handshake() Retval {}\n", con.get_error(r)));
                    io::print_errors();
                    return ret;
                }
                // Wait for a ClientHello to come back.
                let (n, ready, _) = sock::select(&[s], &[], None);
                if n <= 0 || ready.first() != Some(&true) {
                    sout("Error waiting for client response\n");
                    io::print_errors();
                    return ret;
                }
                // Data here is ignored: this only forces the client's handshake.
                io_bio.gets_into(&mut buf);
            }
            w(
                &io_bio,
                "HTTP/1.0 200 ok\r\nContent-type: text/html\r\n\r\n",
            );
            w(&io_bio, "<HTML><BODY BGCOLOR=\"#ffffff\">\n");
            w(&io_bio, "<pre>\n");
            w(&io_bio, "\n");
            for a in &argv {
                let mut t = String::new();
                for ch in a.chars() {
                    match ch {
                        '<' => t.push_str("&lt;"),
                        '>' => t.push_str("&gt;"),
                        '&' => t.push_str("&amp;"),
                        c => t.push(c),
                    }
                }
                t.push(' ');
                w(&io_bio, &t);
            }
            w(&io_bio, "\n");
            s_cb::ssl_print_secure_renegotiation_notes(&io_bio, con);
            // The following is evil and should not really be done.
            w(&io_bio, "Ciphers supported in s_server binary\n");
            let sk = con.ciphers();
            let j = sk.len();
            let mut t = String::new();
            for (i, c) in sk.iter().enumerate() {
                let v = c.version().unwrap_or_default();
                let n = c.name().unwrap_or_default();
                t.push_str(&format!("{v:<11}:{n:<25} "));
                if (i + 1) % 2 == 0 && i + 1 != j {
                    t.push('\n');
                }
            }
            t.push('\n');
            w(&io_bio, &t);
            if let Some(p) = con.shared_ciphers(BUFSIZE) {
                let mut t = String::from("---\nCiphers common between both SSL end points:\n");
                let (mut i, mut jj) = (0usize, 0usize);
                for ch in p.chars() {
                    if ch == ':' {
                        t.push_str(SPACE.get(..26usize.saturating_sub(jj)).unwrap_or_default());
                        i += 1;
                        jj = 0;
                        t.push(if i % 3 != 0 { ' ' } else { '\n' });
                    } else {
                        t.push(ch);
                        jj += 1;
                    }
                }
                t.push('\n');
                w(&io_bio, &t);
            }
            s_cb::ssl_print_sigalgs(&io_bio, con);
            s_cb::ssl_print_groups(&io_bio, con, false);
            s_cb::print_ca_names(&io_bio, con);
            w(
                &io_bio,
                if con.session_reused() {
                    "---\nReused, "
                } else {
                    "---\nNew, "
                },
            );
            let c = con.current_cipher();
            w(
                &io_bio,
                &format!(
                    "{}, Cipher is {}\n",
                    c.and_then(|c| c.version())
                        .unwrap_or_else(|| "(NONE)".to_owned()),
                    c.and_then(|c| c.name())
                        .unwrap_or_else(|| "(NONE)".to_owned())
                ),
            );
            if let Some(sess) = con.session() {
                sess.print(&io_bio);
            }
            w(&io_bio, "---\n");
            print_stats(&io_bio, con.ctx());
            w(&io_bio, "---\n");
            match con.peer_certificate() {
                Some(peer) => {
                    w(&io_bio, "Client certificate\n");
                    ssl::print_cert(&io_bio, &peer);
                    ssl::write_cert_pem(&io_bio, &peer);
                }
                None => w(&io_bio, "no client certificate available\n"),
            }
            w(&io_bio, "</pre></BODY></HTML>\r\n\r\n");
            break;
        } else if (www == 2 || www == 3) && line.starts_with(b"GET /") {
            const TEXT: &str = "HTTP/1.0 200 ok\r\nContent-type: text/plain\r\n\r\n";
            let p = line.get(5..).unwrap_or_default();
            let mut dot: i32 = 1;
            let mut e = 0usize;
            while e < p.len() {
                let c = p.get(e).copied().unwrap_or(0);
                if c == b' ' {
                    break;
                }
                if c == b':' {
                    // A Windows drive: treated as "..".
                    dot = -1;
                    break;
                }
                match dot {
                    1 => dot = if c == b'.' { 2 } else { 0 },
                    2 => dot = if c == b'.' { 3 } else { 0 },
                    3 => dot = if c == b'/' || c == b'\\' { -1 } else { 0 },
                    _ => {}
                }
                if dot == 0 {
                    dot = i32::from(c == b'/' || c == b'\\');
                }
                e += 1;
            }
            // The name contains a ".." component.
            let has_dots = dot == 3 || dot == -1;
            let pstr =
                |end: usize| String::from_utf8_lossy(p.get(..end).unwrap_or_default()).into_owned();
            if e >= p.len() {
                w(&io_bio, TEXT);
                w(
                    &io_bio,
                    &format!("'{}' is an invalid file name\r\n", pstr(p.len())),
                );
                break;
            }
            let name = pstr(e);
            if has_dots {
                w(&io_bio, TEXT);
                w(&io_bio, &format!("'{name}' contains '..' or ':'\r\n"));
                break;
            }
            if name.starts_with('/') || name.starts_with('\\') {
                w(&io_bio, TEXT);
                w(&io_bio, &format!("'{name}' is an invalid path\r\n"));
                break;
            }
            // A directory gets no index.
            if opt::isdir(&name) == Some(true) {
                w(&io_bio, TEXT);
                w(&io_bio, &format!("'{name}' is a directory\r\n"));
                break;
            }
            let opmode = if binmode { "rb" } else { "r" };
            let Some(file) = Bio::new_file(&name, opmode) else {
                w(&io_bio, TEXT);
                w(
                    &io_bio,
                    &format!("Error opening '{name}' mode='{opmode}'\r\n"),
                );
                rustyssl_ossl::err::print_errors(&io_bio);
                break;
            };
            if !s_quiet {
                eputs(&format!("FILE:{name}\n"));
            }
            if www == 2 {
                let html = name.len() > 5 && name.ends_with(".html")
                    || name.len() > 4 && (name.ends_with(".php") || name.ends_with(".htm"));
                if html {
                    w(
                        &io_bio,
                        "HTTP/1.0 200 ok\r\nContent-type: text/html\r\n\r\n",
                    );
                } else {
                    w(
                        &io_bio,
                        "HTTP/1.0 200 ok\r\nContent-type: text/plain\r\n\r\n",
                    );
                }
            }
            // Send the file.
            let mut fbuf = vec![0u8; BUFSIZE];
            'send: loop {
                let n = file.read(&mut fbuf);
                if n <= 0 {
                    break;
                }
                let n = usize::try_from(n).unwrap_or(0);
                let mut j = 0usize;
                while j < n {
                    let k = io_bio.write(fbuf.get(j..n).unwrap_or_default());
                    if k <= 0 {
                        if !io_bio.should_retry() && !con.waiting_for_async() {
                            break 'send;
                        }
                        sout("rwrite W BLOCK\n");
                    } else {
                        j += usize::try_from(k).unwrap_or(0);
                    }
                }
            }
            break;
        }
    }
    loop {
        let i = io_bio.ctrl_long(BIO_CTRL_FLUSH, 0);
        if i <= 0 && io_bio.should_retry() {
            continue;
        }
        break;
    }
    // Make sure sessions are reused.
    do_ssl_shutdown(con);
    ret
}

/// `rev_body` (`-rev`).
fn rev_body(s: i32, _stype: i32, _prot: i32) -> i32 {
    let mut ret = 1;
    let (ctx, context, s_debug, s_quiet, s_ign_eof) = st(|st| {
        (
            st.ctx.clone(),
            st.context.clone(),
            st.s_debug,
            st.s_quiet,
            st.s_ign_eof,
        )
    });
    let mut buf = vec![0u8; BUFSIZE + 1];
    let (Some(io_bio), Some(ssl_bio)) = (Bio::new_buffer(), Bio::new_ssl_filter()) else {
        return ret;
    };
    if io_bio.set_write_buffer_size(core::ffi::c_long::try_from(BUFSIZE).unwrap_or(0)) <= 0 {
        return ret;
    }
    let Some(ctx) = ctx else { return ret };
    let Some(con_owned) = Ssl::new(ctx.r()) else {
        return ret;
    };
    set_tlsext_debug(con_owned.r());
    if let Some(c) = &context
        && !con_owned.r().set_session_id_context(c.as_bytes())
    {
        io::print_errors();
        return ret;
    }
    let Some(sbio) = Bio::new_socket(s) else {
        io::print_errors();
        return ret;
    };
    con_owned.r().set_bio(sbio);
    con_owned.r().set_accept_state();
    ssl_bio.set_ssl(con_owned);
    let io_bio = io_bio.push(ssl_bio);
    let Some(con) = io_bio.ssl() else {
        return ret;
    };
    if s_debug
        && let Some(rb) = con.rbio()
        && let Some(out) = bio_s_out()
    {
        rb.set_callback_ex(s_cb::bio_dump_callback);
        rb.set_callback_arg_bio(Some(&out));
    }
    set_msg_and_tlsext(con);
    loop {
        if io_bio.do_handshake() > 0 {
            break;
        }
        if !io_bio.should_retry() {
            eputs("CONNECTION FAILURE\n");
            io::print_errors();
            do_ssl_shutdown(con);
            return ret;
        }
        if io_bio.should_io_special() && io_bio.retry_reason() == BIO_RR_SSL_X509_LOOKUP {
            sout("LOOKUP renego during accept\n");
            if let Some(o) = bio_s_out() {
                s_cb::lookup_srp_user(&o);
            }
            continue;
        }
    }
    eputs("CONNECTION ESTABLISHED\n");
    s_cb::print_ssl_summary(con);
    loop {
        let i = io_bio.gets_into(&mut buf);
        if i < 0 {
            if !io_bio.should_retry() {
                if !s_quiet {
                    io::print_errors();
                }
                return ret;
            }
            sout("read R BLOCK\n");
            if io_bio.should_io_special() && io_bio.retry_reason() == BIO_RR_SSL_X509_LOOKUP {
                sout("LOOKUP renego during read\n");
                if let Some(o) = bio_s_out() {
                    s_cb::lookup_srp_user(&o);
                }
                continue;
            }
            ssl::sleep_ms(1000);
            continue;
        } else if i == 0 {
            // End of input.
            ret = 1;
            eputs("CONNECTION CLOSED\n");
            break;
        }
        let mut n = usize::try_from(i).unwrap_or(0);
        while n > 0 && matches!(buf.get(n - 1), Some(b'\n' | b'\r')) {
            n -= 1;
        }
        if !s_ign_eof && n == 5 && buf.starts_with(b"CLOSE") {
            ret = 1;
            eputs("CONNECTION CLOSED\n");
            break;
        }
        let mut line: Vec<u8> = buf
            .get(..n)
            .unwrap_or_default()
            .iter()
            .rev()
            .copied()
            .collect();
        line.push(b'\n');
        io_bio.write(&line);
        let mut stop = false;
        loop {
            let r = io_bio.ctrl_long(BIO_CTRL_FLUSH, 0);
            if r > 0 {
                break;
            }
            if !io_bio.should_retry() {
                stop = true;
                break;
            }
        }
        if stop {
            break;
        }
    }
    // Make sure sessions are reused.
    do_ssl_shutdown(con);
    ret
}

pub fn main(argv: &[String]) -> i32 {
    let stdout = stdout_buffer();
    let ret = run(argv);
    // stdout is flushed at exit.
    if let Some(o) = &stdout {
        o.flush();
    }
    st_mut(|s| {
        s.bio_s_out = None;
        s.bio_s_msg = None;
        s.ctx = None;
        s.ctx2 = None;
        s.psksess = None;
    });
    ret
}

/// The `end:` label.
fn end(ret: i32) -> i32 {
    s_cb::set_keylog_file(None, None);
    ret
}

#[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
fn run(argv: &[String]) -> i32 {
    let ret = 1;
    st_mut(|s| s.local_argv = argv.to_vec());
    let mut port: Option<String> = Some(PORT.to_owned());
    let (Some(cctx), Some(vpm)) = (ConfCtx::new(), VerifyParam::new()) else {
        return end(ret);
    };
    cctx.set_flags((SSL_CONF_FLAG_SERVER | SSL_CONF_FLAG_CMDLINE).cast_unsigned());
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let mut meth = Method::tls_server();
    let mut exc: s_cb::ExcertList = None;
    let mut ssl_args: Vec<(String, Option<String>)> = Vec::new();
    let (mut ca_path, mut ca_file, mut ca_store): (Option<String>, Option<String>, Option<String>) =
        (None, None, None);
    let (mut ch_ca_path, mut ch_ca_file, mut ch_ca_store): (
        Option<String>,
        Option<String>,
        Option<String>,
    ) = (None, None, None);
    let (mut dpassarg, mut passarg): (Option<String>, Option<String>) = (None, None);
    let (mut vfy_ca_path, mut vfy_ca_file, mut vfy_ca_store): (
        Option<String>,
        Option<String>,
        Option<String>,
    ) = (None, None, None);
    let mut crl_file: Option<String> = None;
    let mut unlink_unix_path = false;
    let (mut vpmtouched, mut build_chain, mut no_cache, mut ext_cache) = (0, false, false, false);
    let mut dhfile: Option<String> = None;
    let mut no_dhe = false;
    let mut nocert = false;
    let (mut no_ca_path, mut no_ca_file, mut no_ca_store) = (false, false, false);
    let (mut s_cert_format, mut s_key_format) = (format::UNDEF, format::UNDEF);
    let (mut s_dcert_format, mut s_dkey_format) = (format::UNDEF, format::UNDEF);
    let mut rev = false;
    let mut naccept: i64 = -1;
    let mut sdebug = 0;
    let mut socket_family = AF_UNSPEC;
    let mut socket_type = SOCK_STREAM;
    let protocol = 0;
    let mut state = false;
    let mut crl_format = format::UNDEF;
    let mut crl_download = false;
    let mut host: Option<String> = None;
    let mut ssl_config: Option<String> = None;
    let mut read_buf_len = 0;
    let mut next_proto_neg_in: Option<String> = None;
    let mut alpn_in: Option<String> = None;
    let mut psk_identity_hint: Option<String> = None;
    let mut srpuserseed: Option<String> = None;
    let mut srp_verifier_file: Option<String> = None;
    let mut srtp_profiles: Option<String> = None;
    let (mut min_version, mut max_version, mut prot_opt, mut no_prot_opt) = (0, 0, 0, 0);
    let mut s_server_verify = SSL_VERIFY_NONE;
    let mut s_cert_file = Some(TEST_CERT.to_owned());
    let mut s_key_file: Option<String> = None;
    let mut s_chain_file: Option<String> = None;
    let mut s_cert_file2 = Some(TEST_CERT2.to_owned());
    let mut s_key_file2: Option<String> = None;
    let (mut s_dcert_file, mut s_dkey_file, mut s_dchain_file): (
        Option<String>,
        Option<String>,
        Option<String>,
    ) = (None, None, None);
    let mut s_tlsextstatus = false;
    let mut no_resume_ephemeral = false;
    let (mut max_send_fragment, mut split_send_fragment, mut max_pipelines) = (0u32, 0u32, 0u32);
    let mut s_serverinfo_file: Option<String> = None;
    let mut keylog_file: Option<String> = None;
    let (mut max_early_data, mut recv_max_early_data) = (-1i32, -1i32);
    let mut psksessf: Option<String> = None;
    let mut no_ca_names = false;
    let mut ignore_unexpected_eof = false;
    let mut tfo = false;
    let mut cert_comp = false;
    let mut enable_server_rpk = false;
    let mut engine_ = None;
    let mut tlscstatp = StatusCtx {
        timeout: -1,
        ..StatusCtx::default()
    };
    let mut servername: Option<String> = None;
    let mut extension_error = SSL_TLSEXT_ERR_ALERT_WARNING;
    // The globals, reset.
    let mut s_nbio = false;
    let mut s_nbio_test = false;
    let mut s_crlf = false;
    let mut www = 0;
    let mut s_debug = false;
    let mut s_tlsextdebug = false;
    let mut s_msg = 0;
    let mut s_quiet = false;
    let mut s_ign_eof = false;
    let mut s_brief = false;
    let mut keymatexportlabel: Option<String> = None;
    let mut keymatexportlen = 20;
    let mut async_ = false;
    let mut session_id_prefix: Option<String> = None;
    let mut enable_client_rpk = false;
    let mut enable_timeouts = false;
    let mut socket_mtu: i64 = 0;
    let mut dtlslisten = false;
    let mut stateless = false;
    let mut early_data = false;
    let mut psk_identity = "Client_identity".to_owned();
    let mut psk_key: Option<String> = None;
    let mut http_server_binmode = false;
    let mut context: Option<String> = None;
    let mut bio_s_msg: Option<Rc<Bio>> = None;

    let opthelp = |prog: &str| {
        eprintf!("{prog}: Use -help for summary.\n");
    };
    loop {
        let o = p.next();
        if o == Opt::EOF {
            break;
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
        );
        if is_prot {
            prot_opt += 1;
            if prot_opt > 1 {
                eprintf!("Cannot supply multiple protocol flags\n");
                return end(ret);
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
            return end(ret);
        }
        let arg = p.arg().to_owned();
        match o {
            Opt::EOF => break,
            Opt::ERR => {
                opthelp(&prog);
                return end(ret);
            }
            Opt::HELP => {
                opt::help(OPTIONS);
                return end(0);
            }
            Opt::_4 => {
                if socket_family == AF_UNIX {
                    host = None;
                    port = None;
                }
                socket_family = AF_INET;
            }
            Opt::_6 => {
                if socket_family == AF_UNIX {
                    host = None;
                    port = None;
                }
                socket_family = AF_INET6;
            }
            Opt::PORT => {
                if socket_family == AF_UNIX {
                    socket_family = AF_UNSPEC;
                }
                host = None;
                match sock::parse_hostserv(&arg, false, BIO_PARSE_PRIO_SERV) {
                    Some((r, _, s)) if r >= 1 => port = s,
                    _ => {
                        eprintf!("{prog}: -port argument malformed or ambiguous\n");
                        return end(ret);
                    }
                }
            }
            Opt::ACCEPT => {
                if socket_family == AF_UNIX {
                    socket_family = AF_UNSPEC;
                }
                match sock::parse_hostserv(&arg, true, BIO_PARSE_PRIO_SERV) {
                    Some((r, h, s)) if r >= 1 => {
                        host = h;
                        port = s;
                    }
                    _ => {
                        eprintf!("{prog}: -accept argument malformed or ambiguous\n");
                        return end(ret);
                    }
                }
            }
            Opt::UNIX => {
                socket_family = AF_UNIX;
                host = Some(arg);
                port = None;
            }
            Opt::UNLINK => unlink_unix_path = true,
            Opt::NACCEPT => naccept = atol(&arg),
            Opt::VERIFY => {
                s_server_verify = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE;
                let d = apps::atoi(&arg);
                s_cb::set_verify_args(|a| a.depth = d);
                if !s_quiet {
                    eprintf!("verify depth is {d}\n");
                }
            }
            Opt::UPPER_V_VERIFY => {
                s_server_verify =
                    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_CLIENT_ONCE;
                let d = apps::atoi(&arg);
                s_cb::set_verify_args(|a| a.depth = d);
                if !s_quiet {
                    eprintf!("verify depth is {d}, must return a certificate\n");
                }
            }
            Opt::CONTEXT => context = Some(arg),
            Opt::CERT => s_cert_file = Some(arg),
            Opt::NAMEOPT => {
                if !apps::set_nameopt(Some(&arg)) {
                    return end(ret);
                }
            }
            Opt::CRL => crl_file = Some(arg),
            Opt::CRL_DOWNLOAD => crl_download = true,
            Opt::SERVERINFO => s_serverinfo_file = Some(arg),
            Opt::CERTFORM | Opt::KEYFORM | Opt::DCERTFORM | Opt::DKEYFORM => {
                let Some(f) = opt::parse_format(&arg, fmt_flags::ANY) else {
                    opthelp(&prog);
                    return end(ret);
                };
                match o {
                    Opt::CERTFORM => s_cert_format = f,
                    Opt::KEYFORM => s_key_format = f,
                    Opt::DCERTFORM => s_dcert_format = f,
                    _ => s_dkey_format = f,
                }
            }
            Opt::KEY => s_key_file = Some(arg),
            Opt::PASS => passarg = Some(arg),
            Opt::CERT_CHAIN => s_chain_file = Some(arg),
            Opt::DHPARAM => dhfile = Some(arg),
            Opt::DCERT => s_dcert_file = Some(arg),
            Opt::DPASS => dpassarg = Some(arg),
            Opt::DKEY => s_dkey_file = Some(arg),
            Opt::DCERT_CHAIN => s_dchain_file = Some(arg),
            Opt::NOCERT => nocert = true,
            Opt::CAPATH => ca_path = Some(arg),
            Opt::NOCAPATH => no_ca_path = true,
            Opt::CHAINCAPATH => ch_ca_path = Some(arg),
            Opt::VERIFYCAPATH => vfy_ca_path = Some(arg),
            Opt::CASTORE => ca_store = Some(arg),
            Opt::NOCASTORE => no_ca_store = true,
            Opt::CHAINCASTORE => ch_ca_store = Some(arg),
            Opt::VERIFYCASTORE => vfy_ca_store = Some(arg),
            Opt::NO_CACHE => no_cache = true,
            Opt::EXT_CACHE => ext_cache = true,
            Opt::CRLFORM => match opt::parse_format(&arg, fmt_flags::PEMDER) {
                Some(f) => crl_format = f,
                None => {
                    opthelp(&prog);
                    return end(ret);
                }
            },
            Opt::OPT_S(_) | Opt::S_NUM_TICKETS | Opt::ANTI_REPLAY | Opt::NO_ANTI_REPLAY => {
                ssl_args.push((p.flag().to_owned(), p.arg_opt().map(str::to_owned)));
            }
            Opt::OPT_V(v) => {
                if !opt::verify(v, &arg, (&vpm).into()) {
                    return end(ret);
                }
                vpmtouched += 1;
            }
            Opt::OPT_X(x) => {
                if !s_cb::args_excert(x, &arg, &mut exc) {
                    return end(ret);
                }
            }
            Opt::VERIFY_RET_ERROR => s_cb::set_verify_args(|a| a.return_error = true),
            Opt::VERIFY_QUIET => s_cb::set_verify_args(|a| a.quiet = true),
            Opt::BUILD_CHAIN => build_chain = true,
            Opt::CAFILE => ca_file = Some(arg),
            Opt::NOCAFILE => no_ca_file = true,
            Opt::CHAINCAFILE => ch_ca_file = Some(arg),
            Opt::VERIFYCAFILE => vfy_ca_file = Some(arg),
            Opt::NBIO => s_nbio = true,
            Opt::NBIO_TEST => {
                s_nbio = true;
                s_nbio_test = true;
            }
            Opt::IGN_EOF => s_ign_eof = true,
            Opt::NO_IGN_EOF => s_ign_eof = false,
            Opt::DEBUG => s_debug = true,
            Opt::TLSEXTDEBUG => s_tlsextdebug = true,
            Opt::STATUS => {
                s_tlsextstatus = true;
                tlscstatp.status_all = false;
            }
            Opt::STATUS_ALL => {
                s_tlsextstatus = true;
                tlscstatp.status_all = true;
            }
            Opt::STATUS_VERBOSE => {
                s_tlsextstatus = true;
                tlscstatp.verbose = true;
            }
            Opt::STATUS_TIMEOUT => {
                s_tlsextstatus = true;
                tlscstatp.timeout = apps::atoi(&arg);
            }
            Opt::PROXY => tlscstatp.proxy = Some(arg),
            Opt::NO_PROXY => tlscstatp.no_proxy = Some(arg),
            Opt::STATUS_URL => {
                s_tlsextstatus = true;
                match ocsp_status::parse_url(&arg) {
                    Some((ssl_, h, pt, pa)) => {
                        tlscstatp.use_ssl = ssl_;
                        tlscstatp.host = Some(h);
                        tlscstatp.port = Some(pt);
                        tlscstatp.path = Some(pa);
                    }
                    None => {
                        eprintf!("Error parsing -status_url argument\n");
                        return end(ret);
                    }
                }
            }
            Opt::STATUS_FILE => {
                s_tlsextstatus = true;
                tlscstatp.sk_resp_in.get_or_insert_with(Vec::new).push(arg);
            }
            Opt::MSG => s_msg = 1,
            Opt::MSGFILE => match Bio::new_file(&arg, "w") {
                Some(b) => bio_s_msg = Some(Rc::new(b)),
                None => {
                    eprintf!("Error writing file {arg}\n");
                    return end(ret);
                }
            },
            Opt::TRACE => s_msg = 2,
            Opt::SECURITY_DEBUG => sdebug = 1,
            Opt::SECURITY_DEBUG_VERBOSE => sdebug = 2,
            Opt::STATE => state = true,
            Opt::CRLF => s_crlf = true,
            Opt::QUIET => s_quiet = true,
            Opt::BRIEF => {
                s_quiet = true;
                s_brief = true;
                s_cb::set_verify_args(|a| a.quiet = true);
            }
            Opt::NO_DHE => no_dhe = true,
            Opt::NO_RESUME_EPHEMERAL => no_resume_ephemeral = true,
            Opt::PSK_IDENTITY => psk_identity = arg,
            Opt::PSK_HINT => psk_identity_hint = Some(arg),
            Opt::PSK => {
                if !arg.bytes().all(|b| b.is_ascii_hexdigit()) {
                    eprintf!("Not a hex number '{arg}'\n");
                    return end(ret);
                }
                psk_key = Some(arg);
            }
            Opt::PSK_SESS => psksessf = Some(arg),
            Opt::SRPVFILE => {
                srp_verifier_file = Some(arg);
                min_version = min_version.max(TLS1_VERSION);
            }
            Opt::SRPUSERSEED => {
                srpuserseed = Some(arg);
                min_version = min_version.max(TLS1_VERSION);
            }
            Opt::REV => rev = true,
            Opt::WWW => www = 1,
            Opt::UPPER_WWW => www = 2,
            Opt::HTTP => www = 3,
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
            }
            Opt::DTLS => {
                meth = Method::dtls_server();
                socket_type = SOCK_DGRAM;
            }
            Opt::DTLS1 | Opt::DTLS1_2 => {
                meth = Method::dtls_server();
                let v = if o == Opt::DTLS1 {
                    DTLS1_VERSION
                } else {
                    DTLS1_2_VERSION
                };
                min_version = v;
                max_version = v;
                socket_type = SOCK_DGRAM;
            }
            Opt::SCTP | Opt::SCTP_LABEL_BUG | Opt::KTLS | Opt::SENDFILE | Opt::USE_ZC_SENDFILE => {}
            Opt::TIMEOUT => enable_timeouts = true,
            Opt::MTU => socket_mtu = atol(&arg),
            Opt::LISTEN => dtlslisten = true,
            Opt::STATELESS => stateless = true,
            Opt::ID_PREFIX => session_id_prefix = Some(arg),
            Opt::ENGINE => engine_ = engine::setup_engine(Some(&arg), s_debug),
            Opt::OPT_R(r) => {
                if !app_rand::opt_rand(r, &arg) {
                    return end(ret);
                }
            }
            Opt::OPT_PROV(pr) => {
                if !app_libctx::opt_provider(pr, &arg) {
                    return end(ret);
                }
            }
            Opt::SERVERNAME => servername = Some(arg),
            Opt::SERVERNAME_FATAL => extension_error = SSL_TLSEXT_ERR_ALERT_FATAL,
            Opt::CERT2 => s_cert_file2 = Some(arg),
            Opt::KEY2 => s_key_file2 = Some(arg),
            Opt::NEXTPROTONEG => next_proto_neg_in = Some(arg),
            Opt::ALPN => alpn_in = Some(arg),
            Opt::SRTP_PROFILES => srtp_profiles = Some(arg),
            Opt::KEYMATEXPORT => keymatexportlabel = Some(arg),
            Opt::KEYMATEXPORTLEN => keymatexportlen = apps::atoi(&arg),
            Opt::ASYNC => async_ = true,
            Opt::MAX_SEND_FRAG => max_send_fragment = apps::atoi(&arg).cast_unsigned(),
            Opt::SPLIT_SEND_FRAG => split_send_fragment = apps::atoi(&arg).cast_unsigned(),
            Opt::MAX_PIPELINES => max_pipelines = apps::atoi(&arg).cast_unsigned(),
            Opt::READ_BUF => read_buf_len = apps::atoi(&arg),
            Opt::KEYLOG_FILE => keylog_file = Some(arg),
            Opt::MAX_EARLY => {
                max_early_data = apps::atoi(&arg);
                if max_early_data < 0 {
                    eprintf!("Invalid value for max_early_data\n");
                    return end(ret);
                }
            }
            Opt::RECV_MAX_EARLY => {
                recv_max_early_data = apps::atoi(&arg);
                if recv_max_early_data < 0 {
                    eprintf!("Invalid value for recv_max_early_data\n");
                    return end(ret);
                }
            }
            Opt::EARLY_DATA => {
                early_data = true;
                if max_early_data == -1 {
                    max_early_data = SSL3_RT_MAX_PLAIN_LENGTH;
                }
            }
            Opt::HTTP_SERVER_BINMODE => http_server_binmode = true,
            Opt::NOCANAMES => no_ca_names = true,
            Opt::IGNORE_UNEXPECTED_EOF => ignore_unexpected_eof = true,
            Opt::TFO => tfo = true,
            Opt::CERT_COMP => cert_comp = true,
            Opt::ENABLE_SERVER_RPK => enable_server_rpk = true,
            Opt::ENABLE_CLIENT_RPK => enable_client_rpk = true,
        }
    }

    // No extra arguments.
    if !p.check_rest_arg(None) {
        opthelp(&prog);
        return end(ret);
    }
    if !app_rand::load() {
        return end(ret);
    }
    if min_version == TLS1_3_VERSION && next_proto_neg_in.is_some() {
        eprintf!("Cannot supply -nextprotoneg with TLSv1.3\n");
        opthelp(&prog);
        return end(ret);
    }
    if www != 0 && socket_type == SOCK_DGRAM {
        eprintf!("Can't use -HTTP, -www or -WWW with DTLS\n");
        return end(ret);
    }
    if dtlslisten && socket_type != SOCK_DGRAM {
        eprintf!("Can only use -listen with DTLS\n");
        return end(ret);
    }
    if rev && socket_type == SOCK_DGRAM {
        eprintf!("Can't use -rev with DTLS\n");
        return end(ret);
    }
    if tfo && socket_type != SOCK_STREAM {
        eprintf!("Can only use -tfo with TLS\n");
        return end(ret);
    }
    if stateless && socket_type != SOCK_STREAM {
        eprintf!("Can only use --stateless with TLS\n");
        return end(ret);
    }
    if socket_family == AF_UNIX && socket_type != SOCK_STREAM {
        eprintf!("Can't use unix sockets and datagrams together\n");
        return end(ret);
    }
    if early_data && rev {
        eprintf!("Can't use -early_data in combination with -rev\n");
        return end(ret);
    }
    let Some((pass, dpass)) = apps::app_passwd(passarg.as_deref(), dpassarg.as_deref()) else {
        eprintf!("Error getting password\n");
        return end(ret);
    };
    let pass = pass.map(|p| p.as_str().to_owned());
    let dpass = dpass.map(|p| p.as_str().to_owned());
    if s_key_file.is_none() {
        s_key_file = s_cert_file.clone();
    }
    if s_key_file2.is_none() {
        s_key_file2 = s_cert_file2.clone();
    }
    if !s_cb::load_excert(&mut exc) {
        return end(ret);
    }
    let (mut s_key, mut s_cert, mut s_chain) = (None, None, None);
    let (mut s_key2, mut s_cert2) = (None, None);
    if !nocert {
        s_key = apps::load_key(
            s_key_file.as_deref(),
            s_key_format,
            false,
            pass.as_deref(),
            engine_.as_ref(),
            Some("server certificate private key"),
        );
        if s_key.is_none() {
            return end(ret);
        }
        s_cert = apps::load_cert_pass(
            s_cert_file.as_deref(),
            s_cert_format,
            true,
            pass.as_deref(),
            Some("server certificate"),
        );
        if s_cert.is_none() {
            return end(ret);
        }
        if let Some(cf) = &s_chain_file {
            let (ok, c) = apps::load_certs(
                Some(cf),
                false,
                None,
                None,
                Some("server certificate chain"),
            );
            if !ok {
                return end(ret);
            }
            s_chain = c;
        }
        if servername.is_some() {
            s_key2 = apps::load_key(
                s_key_file2.as_deref(),
                s_key_format,
                false,
                pass.as_deref(),
                engine_.as_ref(),
                Some("second server certificate private key"),
            );
            if s_key2.is_none() {
                return end(ret);
            }
            s_cert2 = apps::load_cert_pass(
                s_cert_file2.as_deref(),
                s_cert_format,
                true,
                pass.as_deref(),
                Some("second server certificate"),
            );
            if s_cert2.is_none() {
                return end(ret);
            }
        }
    }
    let next_proto = match &next_proto_neg_in {
        Some(n) => match s_cb::next_protos_parse(n) {
            Some(v) => Some(v),
            None => return end(ret),
        },
        None => None,
    };
    let alpn = match &alpn_in {
        Some(a) => match s_cb::next_protos_parse(a) {
            Some(v) => Some(v),
            None => return end(ret),
        },
        None => None,
    };
    let mut crls: Option<CrlStack> = None;
    if let Some(cf) = &crl_file {
        let Some(crl) = apps::load_crl(Some(cf), crl_format, false, Some("CRL")) else {
            return end(ret);
        };
        let Some(stk) = CrlStack::new() else {
            return end(ret);
        };
        if !stk.push(crl) {
            eprintf!("Error adding CRL\n");
            io::print_errors();
            return end(ret);
        }
        crls = Some(stk);
    }
    let (mut s_dkey, mut s_dcert, mut s_dchain) = (None, None, None);
    if let Some(dcf) = &s_dcert_file {
        if s_dkey_file.is_none() {
            s_dkey_file = s_dcert_file.clone();
        }
        s_dkey = apps::load_key(
            s_dkey_file.as_deref(),
            s_dkey_format,
            false,
            dpass.as_deref(),
            engine_.as_ref(),
            Some("second certificate private key"),
        );
        if s_dkey.is_none() {
            return end(ret);
        }
        s_dcert = apps::load_cert_pass(
            Some(dcf),
            s_dcert_format,
            true,
            dpass.as_deref(),
            Some("second server certificate"),
        );
        if s_dcert.is_none() {
            io::print_errors();
            return end(ret);
        }
        if let Some(chf) = &s_dchain_file {
            let (ok, c) = apps::load_certs(
                Some(chf),
                false,
                None,
                None,
                Some("second server certificate chain"),
            );
            if !ok {
                return end(ret);
            }
            s_dchain = c;
        }
    }
    let stdout = stdout_buffer();
    let bio_s_out: Rc<Bio> = if s_quiet && !s_debug {
        let Some(null) = Bio::new_null() else {
            return end(ret);
        };
        if s_msg != 0 && bio_s_msg.is_none() {
            match &stdout {
                Some(o) => bio_s_msg = Some(o.clone()),
                None => {
                    eprintf!("Out of memory\n");
                    return end(ret);
                }
            }
        }
        Rc::new(null)
    } else {
        match &stdout {
            Some(o) => o.clone(),
            None => return end(ret),
        }
    };
    if nocert {
        s_cert_file = None;
        s_dcert_file = None;
        s_cert_file2 = None;
    }
    let _ = (&s_dcert_file, &s_key_file, &s_key_file2, &s_dkey_file);
    st_mut(|s| {
        s.s_nbio = s_nbio;
        s.s_nbio_test = s_nbio_test;
        s.s_crlf = s_crlf;
        s.www = www;
        s.bio_s_out = Some(bio_s_out.clone());
        s.bio_s_msg = bio_s_msg.clone();
        s.s_debug = s_debug;
        s.s_tlsextdebug = s_tlsextdebug;
        s.s_msg = s_msg;
        s.s_quiet = s_quiet;
        s.s_ign_eof = s_ign_eof;
        s.s_brief = s_brief;
        s.keymatexportlabel = keymatexportlabel.clone();
        s.keymatexportlen = keymatexportlen;
        s.async_ = async_;
        s.session_id_prefix = session_id_prefix.clone();
        s.enable_client_rpk = enable_client_rpk;
        s.enable_timeouts = enable_timeouts;
        s.socket_mtu = socket_mtu;
        s.dtlslisten = dtlslisten;
        s.stateless = stateless;
        s.early_data = early_data;
        s.psk_identity = psk_identity.clone();
        s.psk_key = psk_key.clone();
        s.http_server_binmode = http_server_binmode;
        s.tlscstatp = tlscstatp.clone();
        s.servername = servername.clone();
        s.extension_error = extension_error;
        s.context = context.clone();
    });

    let libctx = app_libctx::libctx();
    let Some(ctx) = SslCtx::new_ex(libctx.as_deref(), app_libctx::propq().as_deref(), meth) else {
        io::print_errors();
        return end(ret);
    };
    let ctx = Rc::new(ctx);
    st_mut(|s| s.ctx = Some(ctx.clone()));
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
        io::print_errors();
        return end(ret);
    }
    if min_version != 0 && !c.set_min_proto_version(min_version) {
        return end(ret);
    }
    if max_version != 0 && !c.set_max_proto_version(max_version) {
        return end(ret);
    }
    let set_id_prefix = |cx: rustyssl_ossl::ssl::CtxRef<'_>| -> bool {
        if let Some(pfx) = &session_id_prefix {
            if pfx.len() >= 32 {
                eprintf!("warning: id_prefix is too long, only one new session will be possible\n");
            }
            if !cx.set_generate_session_id(generate_session_id) {
                eprintf!("error setting 'id_prefix'\n");
                io::print_errors();
                return false;
            }
            eprintf!("id_prefix '{pfx}' set.\n");
        }
        true
    };
    if !set_id_prefix(c) {
        return end(ret);
    }
    let excerts = exc.take();
    let has_exc = excerts.is_some();
    if has_exc {
        s_cb::ssl_ctx_set_excert(c, excerts);
    }
    if state {
        c.set_info_callback(s_cb::apps_ssl_info_callback);
    }
    if no_cache {
        c.set_session_cache_mode(SSL_SESS_CACHE_OFF.into());
    } else if ext_cache {
        init_session_cache_ctx(c);
    } else {
        c.sess_set_cache_size(128);
    }
    if async_ {
        c.set_mode(SSL_MODE_ASYNC.into());
    }
    if no_ca_names {
        c.set_options(SSL_OP_DISABLE_TLSEXT_CA_NAMES);
    }
    if ignore_unexpected_eof {
        c.set_options(SSL_OP_IGNORE_UNEXPECTED_EOF);
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
    if let Some(sp) = &srtp_profiles
        && c.set_tlsext_use_srtp(sp) != 0
    {
        eprintf!("Error setting SRTP profile\n");
        io::print_errors();
        return end(ret);
    }
    if !s_cb::ctx_set_verify_locations(
        c,
        ca_file.as_deref(),
        no_ca_file,
        ca_path.as_deref(),
        no_ca_path,
        ca_store.as_deref(),
        no_ca_store,
    ) {
        io::print_errors();
        return end(ret);
    }
    if vpmtouched > 0 && !c.set1_param(&vpm) {
        eprintf!("Error setting verify params\n");
        io::print_errors();
        return end(ret);
    }
    s_cb::ssl_ctx_add_crls(c, crls.as_ref(), false);
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
        io::print_errors();
        return end(ret);
    }
    let mut ctx2: Option<Rc<SslCtx>> = None;
    if s_cert2.is_some() {
        let Some(c2) = SslCtx::new_ex(libctx.as_deref(), app_libctx::propq().as_deref(), meth)
        else {
            io::print_errors();
            return end(ret);
        };
        ctx2 = Some(Rc::new(c2));
    }
    if let Some(c2r) = &ctx2 {
        let c2 = c2r.r();
        let _ = bio_s_out.write_all(b"Setting secondary ctx parameters\n");
        if sdebug != 0 {
            s_cb::ssl_ctx_security_debug(c2, sdebug);
        }
        if !set_id_prefix(c2) {
            return end(ret);
        }
        if has_exc {
            s_cb::ssl_ctx_set_excert(c2, None);
        }
        if state {
            c2.set_info_callback(s_cb::apps_ssl_info_callback);
        }
        if no_cache {
            c2.set_session_cache_mode(SSL_SESS_CACHE_OFF.into());
        } else if ext_cache {
            init_session_cache_ctx(c2);
        } else {
            c2.sess_set_cache_size(128);
        }
        if async_ {
            c2.set_mode(SSL_MODE_ASYNC.into());
        }
        if !s_cb::ctx_set_verify_locations(
            c2,
            ca_file.as_deref(),
            no_ca_file,
            ca_path.as_deref(),
            no_ca_path,
            ca_store.as_deref(),
            no_ca_store,
        ) {
            io::print_errors();
            return end(ret);
        }
        if vpmtouched > 0 && !c2.set1_param(&vpm) {
            eprintf!("Error setting verify params\n");
            io::print_errors();
            return end(ret);
        }
        s_cb::ssl_ctx_add_crls(c2, crls.as_ref(), false);
        if !s_cb::config_ctx(&cctx, &ssl_args, c2) {
            return end(ret);
        }
    }
    st_mut(|s| s.ctx2 = ctx2.clone());
    if let Some(np) = next_proto {
        c.set_next_protos_advertised(np);
    }
    if let Some(a) = alpn {
        c.set_alpn_select_cb(a, alpn_cb);
    }
    if !no_dhe {
        let mut dhpkey = None;
        if let Some(df) = &dhfile {
            dhpkey = apps::load_keyparams(
                Some(df),
                format::UNDEF,
                false,
                Some("DH"),
                Some("DH parameters"),
            );
        } else if let Some(cf) = &s_cert_file {
            dhpkey = apps::load_keyparams_suppress(
                Some(cf),
                format::UNDEF,
                false,
                Some("DH"),
                Some("DH parameters"),
                true,
            );
        }
        if dhpkey.is_some() {
            let _ = bio_s_out.write_all(b"Setting temp DH parameters\n");
        } else {
            let _ = bio_s_out.write_all(b"Using default temp DH parameters\n");
        }
        bio_s_out.flush();
        match &dhpkey {
            None => {
                c.set_dh_auto(1);
            }
            Some(k) => {
                // One reference for ctx, one for ctx2.
                let Some(k1) = k.up_ref() else {
                    return end(ret);
                };
                if c.set0_tmp_dh_pkey(k1).is_err() {
                    eprintf!("Error setting temp DH parameters\n");
                    io::print_errors();
                    return end(ret);
                }
            }
        }
        if let Some(c2r) = &ctx2 {
            let c2 = c2r.r();
            if dhfile.is_some() {
                let dhpkey2 = apps::load_keyparams_suppress(
                    s_cert_file2.as_deref(),
                    format::UNDEF,
                    false,
                    Some("DH"),
                    Some("DH parameters"),
                    true,
                );
                if dhpkey2.is_some() {
                    let _ = bio_s_out.write_all(b"Setting temp DH parameters\n");
                    bio_s_out.flush();
                    dhpkey = dhpkey2;
                }
            }
            match dhpkey.take() {
                None => {
                    c2.set_dh_auto(1);
                }
                Some(k) => {
                    if c2.set0_tmp_dh_pkey(k).is_err() {
                        eprintf!("Error setting temp DH parameters\n");
                        io::print_errors();
                        return end(ret);
                    }
                }
            }
        }
        drop(dhpkey);
    }
    if !s_cb::set_cert_key_stuff(
        c,
        s_cert.as_ref(),
        s_key.as_ref(),
        s_chain.as_ref(),
        build_chain,
    ) {
        return end(ret);
    }
    if let Some(sf) = &s_serverinfo_file
        && !c.use_serverinfo_file(sf)
    {
        io::print_errors();
        return end(ret);
    }
    if let Some(c2r) = &ctx2
        && !s_cb::set_cert_key_stuff(
            c2r.r(),
            s_cert2.as_ref(),
            s_key2.as_ref(),
            None,
            build_chain,
        )
    {
        return end(ret);
    }
    if s_dcert.is_some()
        && !s_cb::set_cert_key_stuff(
            c,
            s_dcert.as_ref(),
            s_dkey.as_ref(),
            s_dchain.as_ref(),
            build_chain,
        )
    {
        return end(ret);
    }
    if no_resume_ephemeral {
        c.set_not_resumable_session_callback(not_resumable_sess_cb);
        if let Some(c2r) = &ctx2 {
            c2r.r()
                .set_not_resumable_session_callback(not_resumable_sess_cb);
        }
    }
    if psk_key.is_some() {
        if s_debug {
            let _ = bio_s_out.write_all(b"PSK key given, setting server callback\n");
        }
        c.set_psk_server_callback(psk_server_cb);
    }
    if let Some(h) = &psk_identity_hint {
        if min_version == TLS1_3_VERSION {
            let _ = bio_s_out.write_all(b"PSK warning: there is NO identity hint in TLSv1.3\n");
        } else if !c.use_psk_identity_hint(h) {
            eprintf!("error setting PSK identity hint to context\n");
            io::print_errors();
            return end(ret);
        }
    }
    if let Some(f) = &psksessf {
        let Some(b) = Bio::new_file(f, "r") else {
            eprintf!("Can't open PSK session file {f}\n");
            io::print_errors();
            return end(ret);
        };
        let Some(sess) = Session::read_pem(&b) else {
            eprintf!("Can't read PSK session file {f}\n");
            io::print_errors();
            return end(ret);
        };
        st_mut(|s| s.psksess = Some(sess));
    }
    if psk_key.is_some() || st(|s| s.psksess.is_some()) {
        c.set_psk_find_session_callback(psk_find_session_cb);
    }
    c.set_verify(s_server_verify, Some(s_cb::verify_callback));
    let sid_ctx = 1i32.to_ne_bytes();
    if !c.set_session_id_context(&sid_ctx) {
        eprintf!("error setting session id context\n");
        io::print_errors();
        return end(ret);
    }
    // DTLS and TLS 1.3 cookie callbacks.
    c.set_cookie_callbacks(s_cb::generate_cookie, s_cb::verify_cookie);
    if let Some(c2r) = &ctx2 {
        let c2 = c2r.r();
        c2.set_verify(s_server_verify, Some(s_cb::verify_callback));
        if !c2.set_session_id_context(&sid_ctx) {
            eprintf!("error setting session id context\n");
            io::print_errors();
            return end(ret);
        }
        st_mut(|s| s.servername_debug = true);
        c2.set_servername_callback(ssl_servername_cb);
        c.set_servername_callback(ssl_servername_cb);
    }
    if let Some(vf) = &srp_verifier_file {
        if !s_cb::set_up_srp_verifier_file(c, srpuserseed.as_deref(), vf) {
            return end(ret);
        }
    } else if let Some(cf) = &ca_file {
        c.set_client_ca_list_from_file(cf);
        if let Some(c2r) = &ctx2 {
            c2r.r().set_client_ca_list_from_file(cf);
        }
    }
    if s_tlsextstatus {
        c.set_tlsext_status_cb(cert_status_cb);
        if let Some(c2r) = &ctx2 {
            c2r.r().set_tlsext_status_cb(cert_status_cb);
        }
    }
    if s_cb::set_keylog_file(Some(c), keylog_file.as_deref()) {
        return end(ret);
    }
    if max_early_data >= 0 {
        c.set_max_early_data(max_early_data.cast_unsigned());
    }
    if recv_max_early_data >= 0 {
        c.set_recv_max_early_data(recv_max_early_data.cast_unsigned());
    }
    if cert_comp {
        let _ = bio_s_out.write_all(b"Compressing certificates\n");
        if !c.compress_certs(0) {
            let _ = bio_s_out.write_all(b"Error compressing certs on ctx\n");
        }
        if let Some(c2r) = &ctx2
            && !c2r.r().compress_certs(0)
        {
            let _ = bio_s_out.write_all(b"Error compressing certs on ctx2\n");
        }
    }
    if enable_server_rpk && !c.set1_server_cert_type(&CERT_TYPE_RPK) {
        let _ = bio_s_out.write_all(b"Error setting server certificate types\n");
        return end(ret);
    }
    if enable_client_rpk && !c.set1_client_cert_type(&CERT_TYPE_RPK) {
        let _ = bio_s_out.write_all(b"Error setting server certificate types\n");
        return end(ret);
    }
    let server_cb: fn(i32, i32, i32) -> i32 = if rev {
        rev_body
    } else if www != 0 {
        www_body
    } else {
        sv_body
    };
    if socket_family == AF_UNIX
        && unlink_unix_path
        && let Some(h) = &host
    {
        sock::unlink(h);
    }
    if tfo {
        let _ = bio_s_out.write_all(b"Listening for TFO\n");
    }
    let mut cb = |s: i32, t: i32, pr: i32| server_cb(s, t, pr);
    let mut on_listen = |asock: i32| st_mut(|s| s.accept_socket = asock);
    s_socket::do_server(
        host.as_deref(),
        port.as_deref(),
        socket_family,
        socket_type,
        protocol,
        &mut cb,
        naccept,
        &bio_s_out,
        tfo,
        &mut on_listen,
    );
    print_stats(&bio_s_out, c);
    let _ = err::peek_error();
    end(0)
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
