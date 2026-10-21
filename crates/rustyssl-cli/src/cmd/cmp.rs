//! `openssl cmp` (`apps/cmp.c`): a CMP client (RFC 9810, 9483), with the mock server of
//! `apps/lib/cmp_mock_srv.c` ([`crate::lib::cmp_mock_srv`]) in-process (`-use_mock_srv`) or
//! as a basic HTTP server (`-port`).
//!
//! Its own messages name upstream's function and line in `apps/cmp.c`, as upstream prints
//! them (`CMP_err` and friends); a test checks every one against the vendored source.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::io::Write;
use std::rc::Rc;

use rustyssl_ossl::abi::{
    CRL_REASON_AA_COMPROMISE, CRL_REASON_NONE, GEN_DNS, GEN_EMAIL, GEN_IPADD, GEN_URI,
    MBSTRING_UTF8, NID_id_it_caCerts, NID_id_it_certReqTemplate, NID_id_it_crlStatusList,
    NID_id_it_rootCaCert, NID_id_regCtrl_algId, NID_id_regCtrl_rsaKeyLen, NID_undef, OSSL_CMP_CR,
    OSSL_CMP_IR, OSSL_CMP_KUR, OSSL_CMP_LOG_DEBUG, OSSL_CMP_LOG_EMERG, OSSL_CMP_LOG_ERR,
    OSSL_CMP_LOG_INFO, OSSL_CMP_LOG_MAX, OSSL_CMP_LOG_WARNING, OSSL_CMP_OPT_DIGEST_ALGNID,
    OSSL_CMP_OPT_DISABLE_CONFIRM, OSSL_CMP_OPT_IGNORE_KEYUSAGE, OSSL_CMP_OPT_IMPLICIT_CONFIRM,
    OSSL_CMP_OPT_KEEP_ALIVE, OSSL_CMP_OPT_MAC_ALGNID, OSSL_CMP_OPT_MSG_TIMEOUT,
    OSSL_CMP_OPT_NO_CACHE_EXTRACERTS, OSSL_CMP_OPT_OWF_ALGNID, OSSL_CMP_OPT_POLICIES_CRITICAL,
    OSSL_CMP_OPT_POPO_METHOD, OSSL_CMP_OPT_REVOCATION_REASON, OSSL_CMP_OPT_SUBJECTALTNAME_CRITICAL,
    OSSL_CMP_OPT_SUBJECTALTNAME_NODEFAULT, OSSL_CMP_OPT_TOTAL_TIMEOUT,
    OSSL_CMP_OPT_UNPROTECTED_ERRORS, OSSL_CMP_OPT_UNPROTECTED_SEND, OSSL_CMP_OPT_USE_TLS,
    OSSL_CMP_OPT_VALIDITY_DAYS, OSSL_CMP_P10CR, OSSL_CMP_PKIFAILUREINFO_MAX,
    OSSL_CMP_PKIFAILUREINFO_MAX_BIT_PATTERN, OSSL_CMP_PKISTATUS_accepted,
    OSSL_CMP_PKISTATUS_rejection, OSSL_CMP_PKISTATUS_request, OSSL_CMP_PKISTATUS_trans,
    OSSL_CMP_PKISTATUS_waiting, OSSL_CRMF_POPO_KEYENC, OSSL_CRMF_POPO_NONE,
    OSSL_CRMF_POPO_RAVERIFIED, SSL_BUILD_CHAIN_FLAG_NO_ROOT, SSL_BUILD_CHAIN_FLAG_UNTRUSTED,
    X509_V_FLAG_NO_CHECK_TIME, X509_V_FLAG_PARTIAL_CHAIN, X509_V_FLAG_POLICY_CHECK,
    X509_V_FLAG_USE_CHECK_TIME, X509V3_CTX_REPLACE,
};
use rustyssl_ossl::cmp::{
    self, Atavs, CmpCtx, Ctx, ExtStack, GeneralName, Itav, ItavStack, LogTarget, Msg, MsgRef,
    NameField,
};
use rustyssl_ossl::conf::Conf;
use rustyssl_ossl::evp::Cipher;
use rustyssl_ossl::http::{self, SslCtx, TlsInfo};
use rustyssl_ossl::object::{self, Object};
use rustyssl_ossl::pkey::Pkey;
use rustyssl_ossl::verify::VerifyParam;
use rustyssl_ossl::x509::{Cert, CertStack, Crl, Store, V3Ctx};
use rustyssl_ossl::{Bio, err, pkcs12, ui};

use crate::generated::options::cmp::{OPTIONS, Opt};
use crate::lib::apps::{
    app_conf_try_string, app_load_config, atoi, bio_open_owner, default_config_file, get_passwd,
    load_cert_pass, load_crl, load_csr_autofmt, load_key, load_pubkey, parse_name,
};
use crate::lib::apps::{items, load_cert_certs, load_certs_multifile};
use crate::lib::cmp_mock_srv::{MockSrv, mock_srv_new};
use crate::lib::engine::{Engine, setup_engine_methods};
use crate::lib::http_server::{
    http_server_get_asn1_req, http_server_init, http_server_send_asn1_resp, http_server_send_status,
};
use crate::lib::opt::{self, Parser, eprintf, fmt_flags, format};
use crate::lib::{app_libctx, app_rand, io};

const CMP_SECTION: &str = "cmp";
/// The maximum length of a section name.
const SECTION_NAME_MAX: usize = 40;
const DEFAULT_SECTION: &str = "default";

thread_local! {
    /// `opt_verbosity`, which the message macros read.
    static VERBOSITY: Cell<i32> = const { Cell::new(OSSL_CMP_LOG_INFO) };
}

fn verbosity() -> i32 {
    VERBOSITY.with(Cell::get)
}

/// `CMP_print`: `func:apps/cmp.c:line:CMP prefix: msg` to standard error (`err`) or output,
/// if `level` is within the verbosity.
fn cmp_print(err: bool, level: i32, prefix: &str, func: &str, line: u32, msg: &str) {
    if level > verbosity() {
        return;
    }
    let text = format!("{func}:apps/cmp.c:{line}:CMP {prefix}: {msg}\n");
    if err {
        let _ = io::err().write_all(text.as_bytes());
    } else {
        let _ = io::out().write_all(text.as_bytes());
    }
}

macro_rules! cmp_err {
    ($func:literal, $line:literal, $($a:tt)*) => {
        cmp_print(true, OSSL_CMP_LOG_ERR, "error", $func, $line, &format!($($a)*))
    };
}
macro_rules! cmp_warn {
    ($func:literal, $line:literal, $($a:tt)*) => {
        cmp_print(false, OSSL_CMP_LOG_WARNING, "warning", $func, $line, &format!($($a)*))
    };
}
macro_rules! cmp_info {
    ($func:literal, $line:literal, $($a:tt)*) => {
        cmp_print(false, OSSL_CMP_LOG_INFO, "info", $func, $line, &format!($($a)*))
    };
}
macro_rules! cmp_debug {
    ($func:literal, $line:literal, $($a:tt)*) => {
        cmp_print(false, OSSL_CMP_LOG_DEBUG, "debug", $func, $line, &format!($($a)*))
    };
}

/// `%.Ns`: the first `n` bytes.
fn prec(s: &str, n: usize) -> String {
    let b = s.as_bytes();
    String::from_utf8_lossy(b.get(..n.min(b.len())).unwrap_or_default()).into_owned()
}

/// `isspace` of the C locale.
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// `strtol(s, &end, 10)`: the value (saturated, as C's) and the number of bytes used (0 if
/// there are no digits).
fn strtol10(s: &[u8]) -> (i64, usize) {
    let mut i = 0;
    while s.get(i).copied().is_some_and(is_space) {
        i += 1;
    }
    let neg = match s.get(i) {
        Some(b'-') => {
            i += 1;
            true
        }
        Some(b'+') => {
            i += 1;
            false
        }
        _ => false,
    };
    let start = i;
    let mut v: i128 = 0;
    while let Some(d) = s.get(i).filter(|c| c.is_ascii_digit()) {
        v = (v * 10 + i128::from(d - b'0')).min(i128::from(i64::MAX) + 1);
        i += 1;
    }
    if i == start {
        return (0, 0);
    }
    let v = if neg { -v } else { v };
    let v = i64::try_from(v).unwrap_or(if neg { i64::MIN } else { i64::MAX });
    (v, i)
}

/// The cmp command.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Cmd {
    Ir,
    Kur,
    Cr,
    P10cr,
    Rr,
    Genm,
}

/// The state of `read_write_req_resp`: the file lists, consumed one name per message.
#[derive(Default)]
struct Transfer {
    reqout_only: Option<String>,
    reqout_only_done: bool,
    reqout: VecDeque<String>,
    reqin: VecDeque<String>,
    reqin_new_tid: bool,
    rspin: VecDeque<String>,
    rspin_in_use: bool,
    rspout: VecDeque<String>,
    use_mock_srv: bool,
    server: bool,
}

/// The file names of a list (`next_item`), none for `None`.
fn list(s: Option<&str>) -> VecDeque<String> {
    s.map(|s| items(s).into_iter().collect())
        .unwrap_or_default()
}

/// `write_PKIMESSAGE`: `msg` to the next file of the list.
fn write_pkimessage(msg: &MsgRef, filenames: &mut VecDeque<String>) -> bool {
    let Some(file) = filenames.pop_front() else {
        cmp_err!(
            "write_PKIMESSAGE",
            887,
            "not enough file names provided for writing PKIMessage"
        );
        return false;
    };
    if msg.write(&file) < 0 {
        cmp_err!(
            "write_PKIMESSAGE",
            894,
            "cannot write PKIMessage to file '{file}'"
        );
        return false;
    }
    true
}

/// `read_PKIMESSAGE`: the message in the next file of the list.
fn read_pkimessage(desc: &str, filenames: &mut VecDeque<String>) -> Option<Msg> {
    let Some(file) = filenames.pop_front() else {
        cmp_err!(
            "read_PKIMESSAGE",
            911,
            "not enough file names provided for reading PKIMessage"
        );
        return None;
    };
    let lc = app_libctx::libctx();
    let ret = Msg::read(&file, lc.as_deref(), app_libctx::propq().as_deref());
    match &ret {
        None => cmp_err!(
            "read_PKIMESSAGE",
            920,
            "cannot read PKIMessage from file '{file}'"
        ),
        Some(_) => cmp_info!("read_PKIMESSAGE", 922, "{desc} {file}"),
    }
    ret
}

/// `read_write_req_resp`: sends the request `req` and returns the response, like
/// `OSSL_CMP_MSG_http_perform`, but also saving requests and responses to files and taking
/// them from files.
fn read_write_req_resp(t: &mut Transfer, ctx: &Ctx, req: &MsgRef) -> Option<Msg> {
    let prev_rspin = !t.rspin.is_empty();

    if let Some(f) = &t.reqout_only {
        if req.write(f) < 0 {
            cmp_err!(
                "read_write_req_resp",
                942,
                "cannot write request PKIMessage to file '{f}'"
            );
        } else {
            t.reqout_only_done = true;
        }
        return None; // stop at this point, not contacting any server
    }
    if !t.reqout.is_empty() && !write_pkimessage(req, &mut t.reqout) {
        return None;
    }
    let mut req_new = None;
    if !t.reqin.is_empty() && t.rspin.is_empty() {
        let r = read_pkimessage("actually sending", &mut t.reqin)?;
        // The transaction ID in the request read may not be fresh, so the server may
        // complain "Transaction id already in use." The workaround requires re-protection.
        if t.reqin_new_tid && !r.update_transaction_id(ctx) {
            return None;
        }
        // Except for the first request, the server's recipNonce check must be satisfied.
        if !r.update_recip_nonce(ctx) {
            return None;
        }
        req_new = Some(r);
    }

    let res = if !t.rspin.is_empty() {
        read_pkimessage("actually using", &mut t.rspin)
    } else {
        let actual_req: &MsgRef = req_new.as_deref().unwrap_or(req);
        let r = if t.use_mock_srv {
            if t.rspin_in_use {
                cmp_warn!(
                    "read_write_req_resp",
                    977,
                    "too few -rspin filename arguments; resorting to using mock server"
                );
            }
            ctx.server_perform(actual_req)
        } else {
            if !t.server {
                cmp_err!(
                    "read_write_req_resp",
                    982,
                    "missing -server or -use_mock_srv option, or too few -rspin filename arguments"
                );
                return None;
            }
            if t.rspin_in_use {
                cmp_warn!(
                    "read_write_req_resp",
                    986,
                    "too few -rspin filename arguments; resorting to contacting server"
                );
            }
            ctx.http_perform(actual_req)
        };
        t.rspin_in_use = false;
        r
    };
    let res = res?;

    if req_new.is_some() || prev_rspin {
        // need to satisfy nonce and transactionID checks by client
        let nonce = res.recip_nonce();
        let tid = res.transaction_id();
        if !ctx.set1_sender_nonce(nonce.as_deref()) || !ctx.set1_transaction_id(tid.as_deref()) {
            return None;
        }
    }

    if !t.rspout.is_empty() && !write_pkimessage(&res, &mut t.rspout) {
        return None;
    }
    Some(res)
}

/// `prev_item`: the item before `end` in a list of names separated by commas and/or
/// whitespace, and where the list before it ends.
fn prev_item(opt: &str, end: usize) -> Option<(String, usize)> {
    let b = opt.as_bytes();
    if end == 0 {
        return None;
    }
    let sep = |i: usize| b.get(i).is_some_and(|&c| c == b',' || is_space(c));
    let mut beg = end;
    while beg > 0 {
        beg -= 1;
        if sep(beg) {
            beg += 1;
            break;
        }
    }
    let mut len = end - beg;
    if len > SECTION_NAME_MAX {
        let start = String::from_utf8_lossy(b.get(beg..).unwrap_or_default()).into_owned();
        cmp_warn!(
            "prev_item",
            2665,
            "using only first {} characters of section name starting with \"{}\"",
            SECTION_NAME_MAX,
            prec(&start, SECTION_NAME_MAX)
        );
        len = SECTION_NAME_MAX;
    }
    let item = String::from_utf8_lossy(b.get(beg..beg + len).unwrap_or_default()).into_owned();
    while beg > 0 {
        beg -= 1;
        if !sep(beg) {
            beg += 1;
            break;
        }
    }
    Some((item, beg))
}

/// `conf_get_string`: the value of `name` in the first of the sections (comma-separated,
/// the last one first) that has it.
fn conf_get_string(conf: &Conf, groups: &str, name: &str) -> Option<String> {
    let mut end = groups.len();
    while let Some((item, e)) = prev_item(groups, end) {
        end = e;
        if let Some(res) = app_conf_try_string(conf, Some(&item), name) {
            return Some(res);
        }
    }
    None
}

/// `conf_get_number_e`.
fn conf_get_number_e(conf: &Conf, groups: &str, name: &str) -> Option<i64> {
    let s = conf_get_string(conf, groups, name)?;
    if s.is_empty() {
        return None;
    }
    let (res, used) = strtol10(s.as_bytes());
    if res == i64::MIN || res == i64::MAX || used != s.len() || used == 0 {
        return None;
    }
    Some(res)
}

/// `set_verbosity`.
fn set_verbosity(level: i32) -> bool {
    if !(OSSL_CMP_LOG_EMERG..=OSSL_CMP_LOG_MAX).contains(&level) {
        cmp_err!(
            "set_verbosity",
            834,
            "Logging verbosity level {level} out of range (0 .. 8)"
        );
        return false;
    }
    VERBOSITY.with(|v| v.set(level));
    true
}

/// A variable of `cmp_vars` that the configuration file sets.
enum Var<'a> {
    Txt(&'a mut Option<String>),
    Num(&'a mut i32),
}

/// The options, as `cmp.c`'s `opt_*` variables.
struct Cmp {
    prog: String,
    config: Option<String>,
    section: String,

    cmd_s: Option<String>,
    cmd: Option<Cmd>,
    geninfo: Option<String>,
    infotype_s: Option<String>,
    infotype: i32,
    profile: Option<String>,

    server: Option<String>,
    proxy: Option<String>,
    no_proxy: Option<String>,
    recipient: Option<String>,
    path: Option<String>,
    keep_alive: i32,
    msg_timeout: i32,
    total_timeout: i32,

    trusted: Option<String>,
    untrusted: Option<String>,
    srvcert: Option<String>,
    expect_sender: Option<String>,
    ignore_keyusage: i32,
    unprotected_errors: i32,
    no_cache_extracerts: i32,
    srvcertout: Option<String>,
    extracertsout: Option<String>,
    cacertsout: Option<String>,
    oldwithold: Option<String>,
    newwithnew: Option<String>,
    newwithold: Option<String>,
    oldwithnew: Option<String>,
    crlcert: Option<String>,
    oldcrl: Option<String>,
    crlout: Option<String>,
    template: Option<String>,
    keyspec: Option<String>,

    r#ref: Option<String>,
    secret: Option<String>,
    cert: Option<String>,
    own_trusted: Option<String>,
    key: Option<String>,
    keypass: Option<String>,
    digest: Option<String>,
    mac: Option<String>,
    extracerts: Option<String>,
    unprotected_requests: i32,

    newkey: Option<String>,
    newkeypass: Option<String>,
    centralkeygen: i32,
    newkeyout: Option<String>,
    subject: Option<String>,
    days: i32,
    reqexts: Option<String>,
    sans: Option<String>,
    san_nodefault: i32,
    policies: Option<String>,
    policy_oids: Option<String>,
    policy_oids_critical: i32,
    popo: i32,
    csr: Option<String>,
    out_trusted: Option<String>,
    implicit_confirm: i32,
    disable_confirm: i32,
    certout: Option<String>,
    chainout: Option<String>,

    oldcert: Option<String>,
    issuer: Option<String>,
    serial: Option<String>,
    revreason: i32,

    certform_s: Option<String>,
    certform: i32,
    crlform_s: Option<String>,
    crlform: i32,
    keyform_s: Option<String>,
    keyform: i32,
    otherpass: Option<String>,
    engine: Option<String>,

    tls_used: i32,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    tls_keypass: Option<String>,
    tls_extra: Option<String>,
    tls_trusted: Option<String>,
    tls_host: Option<String>,

    batch: i32,
    repeat: i32,
    reqin: Option<String>,
    reqin_new_tid: i32,
    reqout: Option<String>,
    reqout_only: Option<String>,
    rspin: Option<String>,
    rspout: Option<String>,
    use_mock_srv: i32,

    port: Option<String>,
    max_msgs: i32,
    srv_ref: Option<String>,
    srv_secret: Option<String>,
    srv_cert: Option<String>,
    srv_key: Option<String>,
    srv_keypass: Option<String>,
    srv_trusted: Option<String>,
    srv_untrusted: Option<String>,
    ref_cert: Option<String>,
    rsp_cert: Option<String>,
    rsp_key: Option<String>,
    rsp_keypass: Option<String>,
    rsp_crl: Option<String>,
    rsp_extracerts: Option<String>,
    rsp_capubs: Option<String>,
    rsp_newwithnew: Option<String>,
    rsp_newwithold: Option<String>,
    rsp_oldwithnew: Option<String>,
    poll_count: i32,
    check_after: i32,
    grant_implicitconf: i32,
    pkistatus: i32,
    failure: i32,
    failurebits: i32,
    statusstring: Option<String>,
    send_error: i32,
    send_unprotected: i32,
    send_unprot_err: i32,
    accept_unprotected: i32,
    accept_unprot_err: i32,
    accept_raverified: i32,

    vpm: Option<VerifyParam>,
    conf: Option<Conf>,
    transfer: Rc<RefCell<Transfer>>,
}

impl Default for Cmp {
    fn default() -> Self {
        Self {
            prog: String::new(),
            config: None,
            section: CMP_SECTION.to_owned(),
            cmd_s: None,
            cmd: None,
            geninfo: None,
            infotype_s: None,
            infotype: NID_undef,
            profile: None,
            server: None,
            proxy: None,
            no_proxy: None,
            recipient: None,
            path: None,
            keep_alive: 1,
            msg_timeout: -1,
            total_timeout: -1,
            trusted: None,
            untrusted: None,
            srvcert: None,
            expect_sender: None,
            ignore_keyusage: 0,
            unprotected_errors: 0,
            no_cache_extracerts: 0,
            srvcertout: None,
            extracertsout: None,
            cacertsout: None,
            oldwithold: None,
            newwithnew: None,
            newwithold: None,
            oldwithnew: None,
            crlcert: None,
            oldcrl: None,
            crlout: None,
            template: None,
            keyspec: None,
            r#ref: None,
            secret: None,
            cert: None,
            own_trusted: None,
            key: None,
            keypass: None,
            digest: None,
            mac: None,
            extracerts: None,
            unprotected_requests: 0,
            newkey: None,
            newkeypass: None,
            centralkeygen: 0,
            newkeyout: None,
            subject: None,
            days: 0,
            reqexts: None,
            sans: None,
            san_nodefault: 0,
            policies: None,
            policy_oids: None,
            policy_oids_critical: 0,
            popo: OSSL_CRMF_POPO_NONE - 1,
            csr: None,
            out_trusted: None,
            implicit_confirm: 0,
            disable_confirm: 0,
            certout: None,
            chainout: None,
            oldcert: None,
            issuer: None,
            serial: None,
            revreason: CRL_REASON_NONE,
            certform_s: Some("PEM".to_owned()),
            certform: format::PEM,
            // DER is the preferred format for CRLs: more efficient for large ones.
            crlform_s: Some("DER".to_owned()),
            crlform: format::ASN1,
            keyform_s: None,
            keyform: format::UNDEF,
            otherpass: None,
            engine: None,
            tls_used: 0,
            tls_cert: None,
            tls_key: None,
            tls_keypass: None,
            tls_extra: None,
            tls_trusted: None,
            tls_host: None,
            batch: 0,
            repeat: 1,
            reqin: None,
            reqin_new_tid: 0,
            reqout: None,
            reqout_only: None,
            rspin: None,
            rspout: None,
            use_mock_srv: 0,
            port: None,
            max_msgs: 0,
            srv_ref: None,
            srv_secret: None,
            srv_cert: None,
            srv_key: None,
            srv_keypass: None,
            srv_trusted: None,
            srv_untrusted: None,
            ref_cert: None,
            rsp_cert: None,
            rsp_key: None,
            rsp_keypass: None,
            rsp_crl: None,
            rsp_extracerts: None,
            rsp_capubs: None,
            rsp_newwithnew: None,
            rsp_newwithold: None,
            rsp_oldwithnew: None,
            poll_count: 0,
            check_after: 1,
            grant_implicitconf: 0,
            pkistatus: OSSL_CMP_PKISTATUS_accepted,
            failure: i32::MIN,
            failurebits: 0,
            statusstring: None,
            send_error: 0,
            send_unprotected: 0,
            send_unprot_err: 0,
            accept_unprotected: 0,
            accept_unprot_err: 0,
            accept_raverified: 0,
            vpm: None,
            conf: None,
            transfer: Rc::default(),
        }
    }
}

pub fn main(argv: &[String]) -> i32 {
    if let (Some(o), Some(e)) = (io::bio_out(), io::bio_err()) {
        cmp::set_log_bios(o, e);
    }
    let mut c = Cmp::default();
    let mut ctx: Option<CmpCtx> = None;
    let mut engine: Option<Engine> = None;
    let ret = c.run(argv, &mut ctx, &mut engine);
    if ret != 1 {
        cmp::print_errors(ctx.as_deref());
    }
    drop(ctx);
    drop(engine);
    c.conf = None;
    cmp::log_close();
    if ret == 0 { 1 } else { 0 } // ret == -1 for -help
}

impl Cmp {
    fn vpm(&self) -> Option<&VerifyParam> {
        self.vpm.as_ref()
    }

    /// The variable of `cmp_vars` for the option `name` (the variables follow the option
    /// table, so `ref_cert` is `opt_ref_cert` here although the option sets `opt_rsp_cert`).
    fn var(&mut self, name: &str) -> Option<Var<'_>> {
        use Var::{Num, Txt};
        Some(match name {
            "verbosity" => return None,
            "cmd" => Txt(&mut self.cmd_s),
            "infotype" => Txt(&mut self.infotype_s),
            "profile" => Txt(&mut self.profile),
            "geninfo" => Txt(&mut self.geninfo),
            "template" => Txt(&mut self.template),
            "keyspec" => Txt(&mut self.keyspec),
            "newkey" => Txt(&mut self.newkey),
            "newkeypass" => Txt(&mut self.newkeypass),
            "centralkeygen" => Num(&mut self.centralkeygen),
            "newkeyout" => Txt(&mut self.newkeyout),
            "subject" => Txt(&mut self.subject),
            "days" => Num(&mut self.days),
            "reqexts" => Txt(&mut self.reqexts),
            "sans" => Txt(&mut self.sans),
            "san_nodefault" => Num(&mut self.san_nodefault),
            "policies" => Txt(&mut self.policies),
            "policy_oids" => Txt(&mut self.policy_oids),
            "policy_oids_critical" => Num(&mut self.policy_oids_critical),
            "popo" => Num(&mut self.popo),
            "csr" => Txt(&mut self.csr),
            "out_trusted" => Txt(&mut self.out_trusted),
            "implicit_confirm" => Num(&mut self.implicit_confirm),
            "disable_confirm" => Num(&mut self.disable_confirm),
            "certout" => Txt(&mut self.certout),
            "chainout" => Txt(&mut self.chainout),
            "oldcert" => Txt(&mut self.oldcert),
            "issuer" => Txt(&mut self.issuer),
            "serial" => Txt(&mut self.serial),
            "revreason" => Num(&mut self.revreason),
            "server" => Txt(&mut self.server),
            "proxy" => Txt(&mut self.proxy),
            "no_proxy" => Txt(&mut self.no_proxy),
            "recipient" => Txt(&mut self.recipient),
            "path" => Txt(&mut self.path),
            "keep_alive" => Num(&mut self.keep_alive),
            "msg_timeout" => Num(&mut self.msg_timeout),
            "total_timeout" => Num(&mut self.total_timeout),
            "trusted" => Txt(&mut self.trusted),
            "untrusted" => Txt(&mut self.untrusted),
            "srvcert" => Txt(&mut self.srvcert),
            "expect_sender" => Txt(&mut self.expect_sender),
            "ignore_keyusage" => Num(&mut self.ignore_keyusage),
            "unprotected_errors" => Num(&mut self.unprotected_errors),
            "no_cache_extracerts" => Num(&mut self.no_cache_extracerts),
            "srvcertout" => Txt(&mut self.srvcertout),
            "extracertsout" => Txt(&mut self.extracertsout),
            "cacertsout" => Txt(&mut self.cacertsout),
            "oldwithold" => Txt(&mut self.oldwithold),
            "newwithnew" => Txt(&mut self.newwithnew),
            "newwithold" => Txt(&mut self.newwithold),
            "oldwithnew" => Txt(&mut self.oldwithnew),
            "crlcert" => Txt(&mut self.crlcert),
            "oldcrl" => Txt(&mut self.oldcrl),
            "crlout" => Txt(&mut self.crlout),
            "ref" => Txt(&mut self.r#ref),
            "secret" => Txt(&mut self.secret),
            "cert" => Txt(&mut self.cert),
            "own_trusted" => Txt(&mut self.own_trusted),
            "key" => Txt(&mut self.key),
            "keypass" => Txt(&mut self.keypass),
            "digest" => Txt(&mut self.digest),
            "mac" => Txt(&mut self.mac),
            "extracerts" => Txt(&mut self.extracerts),
            "unprotected_requests" => Num(&mut self.unprotected_requests),
            "certform" => Txt(&mut self.certform_s),
            "crlform" => Txt(&mut self.crlform_s),
            "keyform" => Txt(&mut self.keyform_s),
            "otherpass" => Txt(&mut self.otherpass),
            "engine" => Txt(&mut self.engine),
            "tls_used" => Num(&mut self.tls_used),
            "tls_cert" => Txt(&mut self.tls_cert),
            "tls_key" => Txt(&mut self.tls_key),
            "tls_keypass" => Txt(&mut self.tls_keypass),
            "tls_extra" => Txt(&mut self.tls_extra),
            "tls_trusted" => Txt(&mut self.tls_trusted),
            "tls_host" => Txt(&mut self.tls_host),
            "batch" => Num(&mut self.batch),
            "repeat" => Num(&mut self.repeat),
            "reqin" => Txt(&mut self.reqin),
            "reqin_new_tid" => Num(&mut self.reqin_new_tid),
            "reqout" => Txt(&mut self.reqout),
            "reqout_only" => Txt(&mut self.reqout_only),
            "rspin" => Txt(&mut self.rspin),
            "rspout" => Txt(&mut self.rspout),
            "use_mock_srv" => Num(&mut self.use_mock_srv),
            "port" => Txt(&mut self.port),
            "max_msgs" => Num(&mut self.max_msgs),
            "srv_ref" => Txt(&mut self.srv_ref),
            "srv_secret" => Txt(&mut self.srv_secret),
            "srv_cert" => Txt(&mut self.srv_cert),
            "srv_key" => Txt(&mut self.srv_key),
            "srv_keypass" => Txt(&mut self.srv_keypass),
            "srv_trusted" => Txt(&mut self.srv_trusted),
            "srv_untrusted" => Txt(&mut self.srv_untrusted),
            "ref_cert" => Txt(&mut self.ref_cert),
            "rsp_cert" => Txt(&mut self.rsp_cert),
            "rsp_key" => Txt(&mut self.rsp_key),
            "rsp_keypass" => Txt(&mut self.rsp_keypass),
            "rsp_crl" => Txt(&mut self.rsp_crl),
            "rsp_extracerts" => Txt(&mut self.rsp_extracerts),
            "rsp_capubs" => Txt(&mut self.rsp_capubs),
            "rsp_newwithnew" => Txt(&mut self.rsp_newwithnew),
            "rsp_newwithold" => Txt(&mut self.rsp_newwithold),
            "rsp_oldwithnew" => Txt(&mut self.rsp_oldwithnew),
            "poll_count" => Num(&mut self.poll_count),
            "check_after" => Num(&mut self.check_after),
            "grant_implicitconf" => Num(&mut self.grant_implicitconf),
            "pkistatus" => Num(&mut self.pkistatus),
            "failure" => Num(&mut self.failure),
            "failurebits" => Num(&mut self.failurebits),
            "statusstring" => Txt(&mut self.statusstring),
            "send_error" => Num(&mut self.send_error),
            "send_unprotected" => Num(&mut self.send_unprotected),
            "send_unprot_err" => Num(&mut self.send_unprot_err),
            "accept_unprotected" => Num(&mut self.accept_unprotected),
            "accept_unprot_err" => Num(&mut self.accept_unprot_err),
            "accept_raverified" => Num(&mut self.accept_raverified),
            _ => return None,
        })
    }

    /// `read_config`: the options' defaults from the configuration file's section(s).
    /// Returns 1 on success, 0 on error, -1 for a bad number.
    fn read_config(&mut self, conf: &Conf) -> i32 {
        let section = self.section.clone();
        let mut verbosity_num = None;
        let start = OPTIONS
            .iter()
            .position(|o| o.name == "verbosity")
            .unwrap_or(OPTIONS.len());
        for o in OPTIONS.iter().skip(start) {
            if o.marker.is_some() {
                continue;
            }
            let Some(ret) = o.ret else {
                continue;
            };
            let provider = matches!(ret, Opt::OPT_PROV(_));
            let rand = matches!(ret, Opt::OPT_R(_));
            let verification = matches!(ret, Opt::OPT_V(_));
            let mut num = 0i64;
            let mut txt = None;
            match o.valtype {
                b'-' | b'p' | b'n' | b'N' | b'l' => {
                    let Some(n) = conf_get_number_e(conf, &section, o.name) else {
                        err::clear();
                        continue; // option not provided
                    };
                    num = n;
                    if o.valtype == b'p' && num <= 0 {
                        opt::write_err(&format!(
                            "Non-positive number \"{num}\" for config option -{}\n",
                            o.name
                        ));
                        return -1;
                    }
                    if o.valtype == b'N' && num < 0 {
                        opt::write_err(&format!(
                            "Negative number \"{num}\" for config option -{}\n",
                            o.name
                        ));
                        return -1;
                    }
                }
                b's' | b'>' | b'M' => {
                    let Some(t) = conf_get_string(conf, &section, o.name) else {
                        err::clear();
                        continue; // option not provided
                    };
                    txt = Some(t);
                }
                v => {
                    cmp_err!(
                        "read_config",
                        2786,
                        "internal: unsupported type '{}' for option '{}'",
                        char::from(v),
                        o.name
                    );
                    return 0;
                }
            }
            if provider || verification {
                let mut conf_argv = vec![self.prog.clone(), format!("-{}", prec(o.name, 80))];
                if o.valtype == b'-' {
                    if num == 0 {
                        continue;
                    }
                } else {
                    conf_argv.push(conf_get_string(conf, &section, o.name).unwrap_or_default());
                }
                let mut p = Parser::new(&conf_argv, OPTIONS);
                let ok = match p.next() {
                    Opt::OPT_PROV(pr) => app_libctx::opt_provider(pr, p.arg()),
                    Opt::OPT_V(v) => match &self.vpm {
                        Some(vpm) => opt::verify(v, p.arg(), vpm.into()),
                        None => false,
                    },
                    _ => false,
                };
                if !ok {
                    cmp_err!(
                        "read_config",
                        2813,
                        "for option '{}' in config file section '{}'",
                        o.name,
                        section
                    );
                    return 0;
                }
            } else if rand {
                // Upstream writes these to the next variable's storage (opt_tls_used's), which
                // is undefined behavior; they are left out here.
            } else {
                match o.valtype {
                    b'-' | b'p' | b'n' | b'N' => {
                        let Ok(n) = i32::try_from(num) else {
                            eprintf!("integer value out of range for option '{}'\n", o.name);
                            return 0;
                        };
                        if o.name == "verbosity" {
                            verbosity_num = Some(n);
                        } else if let Some(Var::Num(v)) = self.var(o.name) {
                            *v = n;
                        }
                    }
                    _ => {
                        let txt = txt.filter(|t| !t.is_empty()); // reset option on empty string input
                        if let Some(Var::Txt(v)) = self.var(o.name) {
                            *v = txt;
                        }
                    }
                }
            }
        }
        if let Some(n) = verbosity_num {
            VERBOSITY.with(|v| v.set(n));
        }
        1
    }

    /// `opt_str`: the option's argument; `None` (with a warning) if it's empty.
    fn opt_str(p: &Parser<Opt>) -> Option<String> {
        let arg = p.arg();
        if arg.is_empty() {
            cmp_warn!(
                "opt_str",
                2852,
                "{} option argument is empty string, resetting option",
                p.flag()
            );
            return None;
        }
        if arg.starts_with('-') {
            cmp_warn!(
                "opt_str",
                2856,
                "{} option argument starts with hyphen",
                p.flag()
            );
        }
        Some(arg.to_owned())
    }

    /// `get_opts`: 1 on success, 0 on error, -1 for `-help`.
    fn get_opts(&mut self, argv: &[String]) -> i32 {
        let mut p = Parser::new(argv, OPTIONS);
        self.prog = p.prog();
        let opthelp = |prog: &str| {
            eprintf!("{prog}: Use -help for summary.\n");
            0
        };
        loop {
            let o = p.next();
            let s = || Self::opt_str(&p);
            match o {
                Opt::EOF => break,
                Opt::ERR => return opthelp(&self.prog),
                Opt::HELP => {
                    opt::help(OPTIONS);
                    return -1;
                }
                Opt::CONFIG | Opt::SECTION => {} // already handled
                Opt::VERBOSITY => {
                    if !set_verbosity(p.int_arg()) {
                        return opthelp(&self.prog);
                    }
                }
                Opt::SERVER => self.server = s(),
                Opt::PROXY => self.proxy = s(),
                Opt::NO_PROXY => self.no_proxy = s(),
                Opt::RECIPIENT => self.recipient = s(),
                Opt::PATH => self.path = s(),
                Opt::KEEP_ALIVE => {
                    self.keep_alive = p.int_arg();
                    if self.keep_alive > 2 {
                        cmp_err!("get_opts", 2905, "-keep_alive argument must be 0, 1, or 2");
                        return opthelp(&self.prog);
                    }
                }
                Opt::MSG_TIMEOUT => self.msg_timeout = p.int_arg(),
                Opt::TOTAL_TIMEOUT => self.total_timeout = p.int_arg(),
                Opt::TLS_USED => self.tls_used = 1,
                Opt::TLS_CERT => self.tls_cert = s(),
                Opt::TLS_KEY => self.tls_key = s(),
                Opt::TLS_KEYPASS => self.tls_keypass = s(),
                Opt::TLS_EXTRA => self.tls_extra = s(),
                Opt::TLS_TRUSTED => self.tls_trusted = s(),
                Opt::TLS_HOST => self.tls_host = s(),

                Opt::REF => self.r#ref = s(),
                Opt::SECRET => self.secret = s(),
                Opt::CERT => self.cert = s(),
                Opt::OWN_TRUSTED => self.own_trusted = s(),
                Opt::KEY => self.key = s(),
                Opt::KEYPASS => self.keypass = s(),
                Opt::DIGEST => self.digest = s(),
                Opt::MAC => self.mac = s(),
                Opt::EXTRACERTS => self.extracerts = s(),
                Opt::UNPROTECTED_REQUESTS => self.unprotected_requests = 1,

                Opt::TRUSTED => self.trusted = s(),
                Opt::UNTRUSTED => self.untrusted = s(),
                Opt::SRVCERT => self.srvcert = s(),
                Opt::EXPECT_SENDER => self.expect_sender = s(),
                Opt::IGNORE_KEYUSAGE => self.ignore_keyusage = 1,
                Opt::UNPROTECTED_ERRORS => self.unprotected_errors = 1,
                Opt::NO_CACHE_EXTRACERTS => self.no_cache_extracerts = 1,
                Opt::SRVCERTOUT => self.srvcertout = s(),
                Opt::EXTRACERTSOUT => self.extracertsout = s(),
                Opt::CACERTSOUT => self.cacertsout = s(),
                Opt::OLDWITHOLD => self.oldwithold = s(),
                Opt::NEWWITHNEW => self.newwithnew = s(),
                Opt::NEWWITHOLD => self.newwithold = s(),
                Opt::OLDWITHNEW => self.oldwithnew = s(),
                Opt::CRLCERT => self.crlcert = s(),
                Opt::OLDCRL => self.oldcrl = s(),
                Opt::CRLOUT => self.crlout = s(),

                Opt::OPT_V(v) => {
                    let ok = match &self.vpm {
                        Some(vpm) => opt::verify(v, p.arg(), vpm.into()),
                        None => false,
                    };
                    if !ok {
                        return opthelp(&self.prog);
                    }
                }
                Opt::CMD => self.cmd_s = s(),
                Opt::INFOTYPE => self.infotype_s = s(),
                Opt::PROFILE => self.profile = s(),
                Opt::GENINFO => self.geninfo = s(),
                Opt::TEMPLATE => self.template = s(),
                Opt::KEYSPEC => self.keyspec = s(),
                Opt::NEWKEY => self.newkey = s(),
                Opt::NEWKEYPASS => self.newkeypass = s(),
                Opt::CENTRALKEYGEN => self.centralkeygen = 1,
                Opt::NEWKEYOUT => self.newkeyout = s(),
                Opt::SUBJECT => self.subject = s(),
                Opt::DAYS => self.days = p.int_arg(),
                Opt::REQEXTS => self.reqexts = s(),
                Opt::SANS => self.sans = s(),
                Opt::SAN_NODEFAULT => self.san_nodefault = 1,
                Opt::POLICIES => self.policies = s(),
                Opt::POLICY_OIDS => self.policy_oids = s(),
                Opt::POLICY_OIDS_CRITICAL => self.policy_oids_critical = 1,
                Opt::POPO => {
                    self.popo = p.int_arg();
                    if self.popo < OSSL_CRMF_POPO_NONE || self.popo > OSSL_CRMF_POPO_KEYENC {
                        cmp_err!(
                            "get_opts",
                            3084,
                            "invalid popo spec. Valid values are -1 .. 2"
                        );
                        return opthelp(&self.prog);
                    }
                }
                Opt::CSR => self.csr = s(),
                Opt::OUT_TRUSTED => self.out_trusted = s(),
                Opt::IMPLICIT_CONFIRM => self.implicit_confirm = 1,
                Opt::DISABLE_CONFIRM => self.disable_confirm = 1,
                Opt::CERTOUT => self.certout = s(),
                Opt::CHAINOUT => self.chainout = s(),
                Opt::OLDCERT => self.oldcert = s(),
                Opt::REVREASON => {
                    self.revreason = p.int_arg();
                    if self.revreason < CRL_REASON_NONE
                        || self.revreason > CRL_REASON_AA_COMPROMISE
                        || self.revreason == 7
                    {
                        cmp_err!(
                            "get_opts",
                            3114,
                            "invalid revreason. Valid values are -1 .. 6, 8 .. 10"
                        );
                        return opthelp(&self.prog);
                    }
                }
                Opt::ISSUER => self.issuer = s(),
                Opt::SERIAL => self.serial = s(),
                Opt::CERTFORM => self.certform_s = s(),
                Opt::CRLFORM => self.crlform_s = s(),
                Opt::KEYFORM => self.keyform_s = s(),
                Opt::OTHERPASS => self.otherpass = s(),
                Opt::ENGINE => self.engine = s(),
                Opt::OPT_PROV(pr) => {
                    if !app_libctx::opt_provider(pr, p.arg()) {
                        return opthelp(&self.prog);
                    }
                }
                Opt::OPT_R(r) => {
                    if !app_rand::opt_rand(r, p.arg()) {
                        return opthelp(&self.prog);
                    }
                }

                Opt::BATCH => self.batch = 1,
                Opt::REPEAT => self.repeat = p.int_arg(),
                Opt::REQIN => self.reqin = s(),
                Opt::REQIN_NEW_TID => self.reqin_new_tid = 1,
                Opt::REQOUT => self.reqout = s(),
                Opt::REQOUT_ONLY => self.reqout_only = s(),
                Opt::RSPIN => self.rspin = s(),
                Opt::RSPOUT => self.rspout = s(),
                Opt::USE_MOCK_SRV => self.use_mock_srv = 1,

                Opt::PORT => self.port = s(),
                Opt::MAX_MSGS => self.max_msgs = p.int_arg(),
                Opt::SRV_REF => self.srv_ref = s(),
                Opt::SRV_SECRET => self.srv_secret = s(),
                Opt::SRV_CERT => self.srv_cert = s(),
                Opt::SRV_KEY => self.srv_key = s(),
                Opt::SRV_KEYPASS => self.srv_keypass = s(),
                Opt::SRV_TRUSTED => self.srv_trusted = s(),
                Opt::SRV_UNTRUSTED => self.srv_untrusted = s(),
                Opt::REF_CERT => self.ref_cert = s(),
                Opt::RSP_CERT => self.rsp_cert = s(),
                Opt::RSP_KEY => self.rsp_key = s(),
                Opt::RSP_KEYPASS => self.rsp_keypass = s(),
                Opt::RSP_CRL => self.rsp_crl = s(),
                Opt::RSP_EXTRACERTS => self.rsp_extracerts = s(),
                Opt::RSP_CAPUBS => self.rsp_capubs = s(),
                Opt::RSP_NEWWITHNEW => self.rsp_newwithnew = s(),
                Opt::RSP_NEWWITHOLD => self.rsp_newwithold = s(),
                Opt::RSP_OLDWITHNEW => self.rsp_oldwithnew = s(),
                Opt::POLL_COUNT => self.poll_count = p.int_arg(),
                Opt::CHECK_AFTER => self.check_after = p.int_arg(),
                Opt::GRANT_IMPLICITCONF => self.grant_implicitconf = 1,
                Opt::PKISTATUS => self.pkistatus = p.int_arg(),
                Opt::FAILURE => self.failure = p.int_arg(),
                Opt::FAILUREBITS => self.failurebits = p.int_arg(),
                Opt::STATUSSTRING => self.statusstring = s(),
                Opt::SEND_ERROR => self.send_error = 1,
                Opt::SEND_UNPROTECTED => self.send_unprotected = 1,
                Opt::SEND_UNPROT_ERR => self.send_unprot_err = 1,
                Opt::ACCEPT_UNPROTECTED => self.accept_unprotected = 1,
                Opt::ACCEPT_UNPROT_ERR => self.accept_unprot_err = 1,
                Opt::ACCEPT_RAVERIFIED => self.accept_raverified = 1,
            }
        }

        // No extra args.
        if !p.check_rest_arg(None) {
            return opthelp(&self.prog);
        }
        1
    }

    /// `handle_opts_upfront`: `-config`, `-section`, and `-verbosity`, which affect how the
    /// other options are read.
    fn handle_opts_upfront(&mut self, argv: &[String]) -> bool {
        self.prog = opt::appname(argv.first().map_or("", String::as_str));
        if argv.len() <= 1 {
            opt::help(OPTIONS);
            return false;
        }
        let mut i = 1;
        while i + 1 < argv.len() {
            if let Some(name) = argv.get(i).and_then(|a| a.strip_prefix('-')) {
                if name == "config" {
                    i += 1;
                    self.config = argv.get(i).cloned();
                } else if name == "section" {
                    i += 1;
                    self.section = argv.get(i).cloned().unwrap_or_default();
                } else if name == "verbosity" {
                    i += 1;
                    if !set_verbosity(atoi(argv.get(i).map_or("", String::as_str))) {
                        return false;
                    }
                }
            }
            i += 1;
        }
        if self.section.is_empty() {
            self.section = DEFAULT_SECTION.to_owned();
        }
        true
    }

    /// `cmp_main` up to its cleanup: 1 on success, 0 on failure, -1 for `-help`.
    fn run(
        &mut self,
        argv: &[String],
        ctx_slot: &mut Option<CmpCtx>,
        engine: &mut Option<Engine>,
    ) -> i32 {
        if !self.handle_opts_upfront(argv) {
            return 0;
        }

        self.vpm = VerifyParam::new();
        if self.vpm.is_none() {
            cmp_err!("cmp_main", 3686, "out of memory");
            return 0;
        }

        // read default values for options from config file
        let default_file = default_config_file();
        let (configfile, given) = match &self.config {
            Some(c) => (Some(c.clone()), true),
            None => (default_file, false),
        };
        if let Some(configfile) = configfile.filter(|c| !c.is_empty())
            && (given || std::path::Path::new(&configfile).exists())
        {
            cmp_info!(
                "cmp_main",
                3695,
                "using section(s) '{}' of OpenSSL configuration file '{}'",
                self.section,
                configfile
            );
            let Some(conf) = app_load_config(Some(&configfile)) else {
                return 0;
            };
            if self.section == CMP_SECTION {
                // default
                if conf.get_section(&self.section).is_none() {
                    cmp_info!(
                        "cmp_main",
                        3703,
                        "no [{}] section found in config file '{}'; will thus use just [default] and unnamed section if present",
                        self.section,
                        configfile
                    );
                }
            } else {
                let section = self.section.clone();
                let mut end = section.len();
                while let Some((item, e)) = prev_item(&section, end) {
                    end = e;
                    if conf.get_section(&item).is_none() {
                        cmp_err!(
                            "cmp_main",
                            3711,
                            "no [{}] section found in config file '{}'",
                            item,
                            configfile
                        );
                        self.conf = Some(conf);
                        return 0;
                    }
                }
            }
            let mut ret = self.read_config(&conf);
            self.conf = Some(conf);
            if !set_verbosity(verbosity()) {
                // just for checking range
                ret = -1;
            }
            if ret <= 0 {
                if ret == -1 {
                    eprintf!("Use -help for summary.\n");
                }
                return ret; // -1 ends with success, as upstream's does
            }
        }

        let lc = app_libctx::libctx();
        let Some(ctx) = CmpCtx::new(lc.as_deref(), app_libctx::propq().as_deref()) else {
            return 0;
        };
        let ctx = ctx_slot.insert(ctx);

        let ret = self.get_opts(argv);
        if ret <= 0 {
            return ret;
        }

        if !app_rand::load() {
            return 0;
        }

        if self.batch != 0 {
            ui::set_base_null();
        }

        if let Some(e) = &self.engine {
            *engine = setup_engine_methods(Some(e), 0, false);
            if engine.is_none() {
                cmp_err!("cmp_main", 3748, "cannot load engine {}", e);
                return 0;
            }
        }

        ctx.set_log_verbosity(verbosity());
        if !ctx.set_log_cb(LogTarget::Out) {
            cmp_err!(
                "cmp_main",
                3755,
                "cannot set up error reporting and logging for {}",
                self.prog
            );
            return 0;
        }

        if self.tls_cert.is_none()
            && self.tls_key.is_none()
            && self.tls_keypass.is_none()
            && self.tls_extra.is_none()
            && self.tls_trusted.is_none()
            && self.tls_host.is_none()
        {
            if self.tls_used != 0 {
                cmp_warn!(
                    "cmp_main",
                    3764,
                    "-tls_used given without any other TLS options"
                );
            }
        } else if self.tls_used == 0 {
            cmp_warn!(
                "cmp_main",
                3766,
                "ignoring TLS options(s) since -tls_used is not given"
            );
        }
        if self.port.is_some() {
            if self.tls_used != 0 {
                cmp_err!(
                    "cmp_main",
                    3770,
                    "-tls_used option not supported with -port option"
                );
                return 0;
            }
            if self.server.is_some() || self.use_mock_srv != 0 {
                cmp_err!(
                    "cmp_main",
                    3774,
                    "The -port option excludes -server and -use_mock_srv"
                );
                return 0;
            }
            if self.reqin.is_some() || self.reqout.is_some() {
                cmp_err!(
                    "cmp_main",
                    3778,
                    "The -port option does not support -reqin and -reqout"
                );
                return 0;
            }
            if self.rspin.is_some() || self.rspout.is_some() {
                cmp_err!(
                    "cmp_main",
                    3782,
                    "The -port option does not support -rspin and -rspout"
                );
                return 0;
            }
        }

        if self.server.is_some() && self.use_mock_srv != 0 {
            cmp_err!(
                "cmp_main",
                3788,
                "cannot use both -server and -use_mock_srv options"
            );
            return 0;
        }
        if (self.server.is_none() || self.use_mock_srv != 0) && self.tls_used != 0 {
            cmp_warn!(
                "cmp_main",
                3792,
                "ignoring -tls_used option since -server is not given or -use_mock_srv is given"
            );
            self.tls_used = 0;
        }

        if self.ignore_keyusage != 0 {
            ctx.set_option(OSSL_CMP_OPT_IGNORE_KEYUSAGE, 1);
        }
        if self.no_cache_extracerts != 0 {
            ctx.set_option(OSSL_CMP_OPT_NO_CACHE_EXTRACERTS, 1);
        }

        if self.reqout_only.is_none() && (self.use_mock_srv != 0 || self.port.is_some()) {
            let Some(srv) = self.setup_srv_ctx(ctx, engine.as_ref()) else {
                return 0;
            };
            ctx.set_mock_server(srv.into_srv());

            let Some(srv_cmp_ctx) = ctx.mock_server().and_then(|s| s.cmp_ctx()) else {
                return 0;
            };
            if !srv_cmp_ctx.set_log_cb(LogTarget::Err) {
                cmp_err!(
                    "cmp_main",
                    3817,
                    "Cannot set up server-side error reporting and logging for {}",
                    self.prog
                );
                return 0;
            }
            srv_cmp_ctx.set_log_verbosity(verbosity());
            if self.ignore_keyusage != 0 {
                srv_cmp_ctx.set_option(OSSL_CMP_OPT_IGNORE_KEYUSAGE, 1);
            }
            if self.no_cache_extracerts != 0 {
                srv_cmp_ctx.set_option(OSSL_CMP_OPT_NO_CACHE_EXTRACERTS, 1);
            }

            if let Some(port) = self.port.clone() {
                // act as very basic CMP HTTP server only
                return self.cmp_server(ctx, &port);
            }
        }

        // act as CMP client, possibly using internal mock server

        if self.reqout_only.is_some() {
            let msg = "option is ignored since -reqout_only option is given";
            if self.port.is_some() {
                cmp_err!(
                    "cmp_main",
                    3841,
                    "the -reqout_only client option does not combine with -port implying server behavior"
                );
                return 0;
            }
            if self.server.is_some() {
                cmp_warn!("cmp_main", 3845, "-server {msg}");
            }
            if self.use_mock_srv != 0 {
                cmp_warn!("cmp_main", 3848, "-use_mock_srv {msg}");
            }
            if self.reqout.is_some() {
                cmp_warn!("cmp_main", 3850, "-reqout {msg}");
            }
            if self.rspin.is_some() {
                cmp_warn!("cmp_main", 3852, "-rspin {msg}");
            }
            if self.rspout.is_some() {
                cmp_warn!("cmp_main", 3854, "-rspout {msg}");
            }
            self.reqout.clone_from(&self.reqout_only);
        }
        if self.rspin.is_some() {
            if self.server.is_some() {
                cmp_warn!(
                    "cmp_main",
                    3860,
                    "-server option is not used if enough filenames given for -rspin"
                );
            }
            if self.use_mock_srv != 0 {
                cmp_warn!(
                    "cmp_main",
                    3863,
                    "-use_mock_srv option is not used if enough filenames given for -rspin"
                );
            }
        }

        if !self.setup_client_ctx(ctx, engine.as_ref()) {
            cmp_err!("cmp_main", 3867, "cannot set up CMP context");
            return 0;
        }
        let mut newcert: Option<Cert> = None;
        for _ in 0..self.repeat {
            let mut ret = 0;
            // everything is ready, now connect and perform the command!
            match self.cmd {
                Some(Cmd::Ir) => {
                    newcert = ctx.exec_certreq(OSSL_CMP_IR);
                    ret = i32::from(newcert.is_some());
                }
                Some(Cmd::Kur) => {
                    newcert = ctx.exec_certreq(OSSL_CMP_KUR);
                    ret = i32::from(newcert.is_some());
                }
                Some(Cmd::Cr) => {
                    newcert = ctx.exec_certreq(OSSL_CMP_CR);
                    ret = i32::from(newcert.is_some());
                }
                Some(Cmd::P10cr) => {
                    newcert = ctx.exec_certreq(OSSL_CMP_P10CR);
                    ret = i32::from(newcert.is_some());
                }
                Some(Cmd::Rr) => ret = ctx.exec_rr(),
                Some(Cmd::Genm) => ret = i32::from(self.do_genm(ctx)),
                None => {}
            }
            if ctx.status() < OSSL_CMP_PKISTATUS_accepted {
                // we got no response, maybe even did not send request
                if self.transfer.borrow().reqout_only_done {
                    err::clear();
                    return 1;
                }
                return 0;
            }
            self.print_status(ctx);
            if !self.save_cert_or_delete(
                ctx.validated_srv_cert().as_ref(),
                self.srvcertout.as_deref(),
                "validated server",
            ) {
                ret = 0;
            }
            if ret == 0 {
                return 0;
            }
            if self.save_free_certs(ctx.extra_certs_in(), self.extracertsout.as_deref(), "extra")
                < 0
            {
                return 0;
            }
            if let Some(newcert) = &newcert
                && matches!(self.cmd, Some(Cmd::Ir | Cmd::Cr | Cmd::Kur | Cmd::P10cr))
            {
                let newchain = ctx.new_chain();
                match (&newchain, &self.certout, &self.chainout) {
                    (Some(chain), Some(co), Some(ch)) if co == ch => {
                        if !newcert.prepend_to(chain) {
                            return 0;
                        }
                        if self.save_free_certs(
                            newchain,
                            self.chainout.as_deref(),
                            "newly enrolled cert and chain",
                        ) == 0
                        {
                            return 0;
                        }
                    }
                    _ => {
                        if self.save_free_certs(newchain, self.chainout.as_deref(), "chain") < 0
                            || !self.save_cert_or_delete(
                                Some(newcert),
                                self.certout.as_deref(),
                                "newly enrolled",
                            )
                        {
                            return 0;
                        }
                    }
                }
                if self.save_free_certs(ctx.ca_pubs(), self.cacertsout.as_deref(), "CA") < 0 {
                    return 0;
                }
                if self.centralkeygen != 0 {
                    let Some(new_key) = ctx.new_pkey(true) else {
                        return 0;
                    };
                    let Some(out) = bio_open_owner(self.newkeyout.as_deref(), format::PEM, true)
                    else {
                        return 0;
                    };
                    let mut pass_string = None;
                    let mut cipher = None;
                    if let Some(np) = &self.newkeypass {
                        pass_string =
                            get_passwd(Some(np), Some("Centrally generated private key password"));
                        let lc = app_libctx::libctx();
                        cipher = Cipher::fetch(
                            lc.as_deref(),
                            "AES-256-CBC",
                            app_libctx::propq().as_deref(),
                        );
                    }

                    cmp_info!(
                        "cmp_main",
                        3959,
                        "saving centrally generated key to file '{}'",
                        self.newkeyout.as_deref().unwrap_or("<NULL>")
                    );
                    let pass = pass_string.as_ref().map(|p| p.as_str().as_bytes());
                    if pkcs12::write_private_key(&out, &new_key, cipher.as_ref(), pass) <= 0 {
                        return 0;
                    }
                }
            }
            if !ctx.reinit() {
                return 0;
            }
        }
        1
    }

    /// `load_key_pwd`.
    fn load_key_pwd(
        uri: Option<&str>,
        fmt: i32,
        pass: Option<&str>,
        eng: Option<&Engine>,
        desc: &str,
    ) -> Option<Pkey> {
        let pass_string = get_passwd(pass, Some(desc));
        load_key(
            uri,
            fmt,
            false,
            pass_string.as_ref().map(|p| p.as_str()),
            eng,
            Some(desc),
        )
    }

    /// `load_cert_pwd`.
    fn load_cert_pwd(uri: &str, pass: Option<&str>, desc: &str) -> Option<Cert> {
        let pass_string = get_passwd(pass, Some(desc));
        load_cert_pass(
            Some(uri),
            format::UNDEF,
            false,
            pass_string.as_ref().map(|p| p.as_str()),
            Some(desc),
        )
    }

    /// `load_certstore` of `apps.c`: a trust store with the certificates of each file of the
    /// list.
    fn load_certstore(&self, input: &str, pass: Option<&str>, desc: &str) -> Option<Store> {
        let mut store: Option<Store> = None;
        for f in items(input) {
            let (_, certs) = load_cert_certs(&f, false, true, true, pass, Some(desc), self.vpm())?;
            // sk_X509_to_store
            let st = match store.take() {
                Some(s) => s,
                None => Store::new()?,
            };
            for c in certs.map(|c| c.to_vec()).unwrap_or_default() {
                if !st.add_cert(&c) {
                    return None;
                }
            }
            store = Some(st);
        }
        store
    }

    /// `load_trusted`.
    fn load_trusted(
        &self,
        ctx: Option<&Ctx>,
        input: &str,
        for_new_cert: bool,
        desc: &str,
    ) -> Option<Store> {
        let ts = self.load_certstore(input, self.otherpass.as_deref(), desc)?;
        ts.set_print_verify_cb();

        // copy vpm to store
        let ok = match self.vpm() {
            Some(vpm) => ts.set1_param(vpm),
            None => true,
        };
        if ok && (for_new_cert || cmp::truststore_set_host_etc(&ts, None)) {
            return Some(ts);
        }
        eprintf!("error setting verification parameters for {desc}\n");
        cmp::print_errors(ctx);
        None
    }

    /// `setup_cert`: the certificate in `file` handed to `set1`.
    fn setup_cert(
        file: Option<&str>,
        pass: Option<&str>,
        desc: &str,
        set1: impl FnOnce(&Cert) -> bool,
    ) -> bool {
        let Some(file) = file else {
            return true;
        };
        let Some(cert) = Self::load_cert_pwd(file, pass, desc) else {
            return false;
        };
        set1(&cert)
    }

    /// `setup_certs`: the certificates in `files` handed to `set1`.
    fn setup_certs(
        &self,
        files: Option<&str>,
        desc: &str,
        set1: impl FnOnce(&CertStack) -> bool,
    ) -> bool {
        let Some(files) = files else {
            return true;
        };
        let Some(certs) =
            load_certs_multifile(files, self.otherpass.as_deref(), Some(desc), self.vpm())
        else {
            return false;
        };
        set1(&certs)
    }

    /// `set_name`.
    fn set_name(ctx: &Ctx, s: Option<&str>, field: NameField, desc: &str) -> bool {
        if let Some(s) = s {
            let Some(n) = parse_name(s, MBSTRING_UTF8, true, desc) else {
                return false;
            };
            if !ctx.set1_name(field, &n) {
                cmp_err!("set_name", 1034, "out of memory");
                return false;
            }
        }
        true
    }

    /// `set_gennames`.
    fn set_gennames(ctx: &Ctx, names: Option<&str>, desc: &str) -> bool {
        let Some(names) = names else {
            return true;
        };
        for name in items(names) {
            if name == "critical" {
                ctx.set_option(OSSL_CMP_OPT_SUBJECTALTNAME_CRITICAL, 1);
                continue;
            }

            // try IP address first, then email/URI/domain name
            err::set_mark();
            let mut n = GeneralName::from_text(GEN_IPADD, &name);
            if n.is_none() {
                let t = if name.contains('@') {
                    GEN_EMAIL
                } else if name.contains(':') {
                    GEN_URI
                } else {
                    GEN_DNS
                };
                n = GeneralName::from_text(t, &name);
            }
            err::pop_to_mark();

            let Some(n) = n else {
                cmp_err!("set_gennames", 1068, "bad syntax of {desc} '{name}'");
                return false;
            };
            if !ctx.push1_subject_alt_name(&n) {
                cmp_err!("set_gennames", 1073, "out of memory");
                return false;
            }
        }
        true
    }

    /// `transform_opts`: parses and checks some options.
    fn transform_opts(&mut self) -> bool {
        match self.cmd_s.as_deref() {
            Some(s) => {
                self.cmd = Some(match s {
                    "ir" => Cmd::Ir,
                    "kur" => Cmd::Kur,
                    "cr" => Cmd::Cr,
                    "p10cr" => Cmd::P10cr,
                    "rr" => Cmd::Rr,
                    "genm" => Cmd::Genm,
                    _ => {
                        cmp_err!("transform_opts", 1164, "unknown cmp command '{s}'");
                        return false;
                    }
                });
            }
            None => {
                cmp_err!("transform_opts", 1168, "no cmp command to execute");
                return false;
            }
        }

        if let Some(s) = &self.keyform_s {
            match opt::parse_format(s, fmt_flags::PEMDER | fmt_flags::PKCS12 | fmt_flags::ENGINE) {
                Some(f) => self.keyform = f,
                None => {
                    cmp_err!(
                        "transform_opts",
                        1180,
                        "unknown option given for key loading format"
                    );
                    return false;
                }
            }
        }
        if let Some(s) = &self.certform_s {
            match opt::parse_format(s, fmt_flags::PEMDER) {
                Some(f) => self.certform = f,
                None => {
                    cmp_err!(
                        "transform_opts",
                        1188,
                        "unknown option given for certificate storing format"
                    );
                    return false;
                }
            }
        }
        if let Some(s) = &self.crlform_s {
            match opt::parse_format(s, fmt_flags::PEMDER) {
                Some(f) => self.crlform = f,
                None => {
                    cmp_err!(
                        "transform_opts",
                        1193,
                        "unknown option given for CRL storing format"
                    );
                    return false;
                }
            }
        }
        true
    }

    /// `setup_srv_ctx`: the mock server.
    fn setup_srv_ctx(&mut self, client: &Ctx, engine: Option<&Engine>) -> Option<MockSrv> {
        let lc = app_libctx::libctx();
        let mock = mock_srv_new(lc.as_deref(), app_libctx::propq().as_deref())?;
        let ctx = mock.srv().cmp_ctx()?;

        match &self.srv_ref {
            None => {
                if self.srv_cert.is_none() {
                    // the server certificate should determine the sender
                    cmp_err!(
                        "setup_srv_ctx",
                        1213,
                        "must give -srv_ref for mock server if no -srv_cert given"
                    );
                    return None;
                }
            }
            Some(r) => {
                if !ctx.set1_reference_value(r.as_bytes()) {
                    return None;
                }
            }
        }

        if let Some(secret) = &self.srv_secret {
            if let Some(pass_str) = get_passwd(Some(secret), Some("PBMAC secret of mock server"))
                && !ctx.set1_secret_value(pass_str.as_str().as_bytes())
            {
                return None;
            }
        } else if self.srv_cert.is_none() {
            cmp_err!(
                "setup_srv_ctx",
                1235,
                "server credentials (-srv_secret or -srv_cert) must be given if -use_mock_srv or -port is used"
            );
            return None;
        } else {
            cmp_warn!(
                "setup_srv_ctx",
                1238,
                "server will not be able to handle PBM-protected requests since -srv_secret is not given"
            );
        }

        if self.srv_secret.is_none() && (self.srv_cert.is_none() != self.srv_key.is_none()) {
            cmp_err!(
                "setup_srv_ctx",
                1243,
                "must give both -srv_cert and -srv_key options or neither"
            );
            return None;
        }
        if !Self::setup_cert(
            self.srv_cert.as_deref(),
            self.srv_keypass.as_deref(),
            "signer certificate of the mock server",
            |c| ctx.set1_cert(c),
        ) {
            return None;
        }
        if self.srv_key.is_some() {
            let pkey = Self::load_key_pwd(
                self.srv_key.as_deref(),
                self.keyform,
                self.srv_keypass.as_deref(),
                engine,
                "private key for mock server cert",
            );
            if !pkey.is_some_and(|k| ctx.set1_pkey(&k)) {
                return None;
            }
        }

        if let Some(st) = &self.srv_trusted {
            let ts = self.load_trusted(Some(client), st, false, "certs trusted by mock server");
            if !ts.is_some_and(|t| ctx.set0_trusted(t)) {
                return None;
            }
        } else {
            cmp_warn!(
                "setup_srv_ctx",
                1271,
                "mock server will not be able to handle signature-protected requests since -srv_trusted is not given"
            );
        }
        if !self.setup_certs(
            self.srv_untrusted.as_deref(),
            "untrusted certificates for mock server",
            |c| ctx.set1_untrusted(c),
        ) {
            return None;
        }

        if !Self::setup_cert(
            self.ref_cert.as_deref(),
            self.otherpass.as_deref(),
            "reference cert to be expected by the mock server",
            |c| mock.set1_ref_cert(Some(c)),
        ) {
            return None;
        }
        if self.rsp_cert.is_none() {
            cmp_warn!("setup_srv_ctx", 1283, "no -rsp_cert given for mock server");
        } else if !Self::setup_cert(
            self.rsp_cert.as_deref(),
            self.rsp_keypass.as_deref(),
            "cert the mock server returns on certificate requests",
            |c| mock.set1_cert_out(Some(c)),
        ) {
            return None;
        }
        if self.rsp_key.is_some() {
            let pkey = Self::load_key_pwd(
                self.rsp_key.as_deref(),
                self.keyform,
                self.rsp_keypass.as_deref(),
                engine,
                "private key for enrollment cert",
            );
            if !pkey.is_some_and(|k| mock.set1_key_out(&k)) {
                return None;
            }
        }

        // setup_mock_crlout
        if let Some(f) = &self.rsp_crl {
            let crl = load_crl(
                Some(f),
                format::UNDEF,
                false,
                Some("CRL to be returned by the mock server"),
            )?;
            if !mock.set1_crl_out(&crl) {
                return None;
            }
        }
        if !self.setup_certs(
            self.rsp_extracerts.as_deref(),
            "CMP extra certificates for mock server",
            |c| mock.set1_chain_out(c),
        ) {
            return None;
        }
        if !self.setup_certs(self.rsp_capubs.as_deref(), "caPubs for mock server", |c| {
            mock.set1_ca_pubs_out(c)
        }) {
            return None;
        }
        if !Self::setup_cert(
            self.rsp_newwithnew.as_deref(),
            self.otherpass.as_deref(),
            "NewWithNew cert the mock server returns in rootCaKeyUpdate",
            |c| mock.set1_new_with_new(Some(c)),
        ) || !Self::setup_cert(
            self.rsp_newwithold.as_deref(),
            self.otherpass.as_deref(),
            "NewWithOld cert the mock server returns in rootCaKeyUpdate",
            |c| mock.set1_new_with_old(Some(c)),
        ) || !Self::setup_cert(
            self.rsp_oldwithnew.as_deref(),
            self.otherpass.as_deref(),
            "OldWithNew cert the mock server returns in rootCaKeyUpdate",
            |c| mock.set1_old_with_new(Some(c)),
        ) {
            return None;
        }
        mock.set_poll_count(self.poll_count);
        mock.set_check_after_time(self.check_after);
        if self.grant_implicitconf != 0 {
            mock.srv().set_grant_implicit_confirm(true);
        }

        if self.failure != i32::MIN {
            // option has been set explicitly
            if self.failure < 0 || OSSL_CMP_PKIFAILUREINFO_MAX < self.failure {
                cmp_err!(
                    "setup_srv_ctx",
                    1331,
                    "-failure out of range, should be >= 0 and <= {}",
                    OSSL_CMP_PKIFAILUREINFO_MAX
                );
                return None;
            }
            if self.failurebits != 0 {
                cmp_warn!("setup_srv_ctx", 1336, "-failurebits overrides -failure");
            } else {
                self.failurebits = 1 << self.failure;
            }
        }
        if self.failurebits.cast_unsigned()
            > OSSL_CMP_PKIFAILUREINFO_MAX_BIT_PATTERN.cast_unsigned()
        {
            cmp_err!("setup_srv_ctx", 1341, "-failurebits out of range");
            return None;
        }
        if !mock.set_status_info(
            self.pkistatus,
            self.failurebits,
            self.statusstring.as_deref(),
        ) {
            return None;
        }

        if self.send_error != 0 {
            mock.set_send_error(1);
        }

        if self.send_unprotected != 0 {
            ctx.set_option(OSSL_CMP_OPT_UNPROTECTED_SEND, 1);
        }
        if self.send_unprot_err != 0 {
            mock.srv().set_send_unprotected_errors(true);
        }
        if self.accept_unprotected != 0 {
            mock.srv().set_accept_unprotected(true);
        }
        if self.accept_unprot_err != 0 {
            ctx.set_option(OSSL_CMP_OPT_UNPROTECTED_ERRORS, 1);
        }
        if self.accept_raverified != 0 {
            mock.srv().set_accept_raverified(true);
        }

        Some(mock)
    }

    /// `setup_verification_ctx`.
    fn setup_verification_ctx(&mut self, ctx: &mut CmpCtx) -> bool {
        if !self.setup_certs(self.untrusted.as_deref(), "untrusted certificates", |c| {
            ctx.set1_untrusted(c)
        }) {
            return false;
        }

        if self.srvcert.is_some() || self.trusted.is_some() {
            if self.srvcert.is_some() {
                if self.trusted.is_some() {
                    cmp_warn!(
                        "setup_verification_ctx",
                        1382,
                        "-trusted option is ignored since -srvcert option is present"
                    );
                    self.trusted = None;
                }
                if self.recipient.is_some() {
                    cmp_warn!(
                        "setup_verification_ctx",
                        1386,
                        "-recipient option is ignored since -srvcert option is present"
                    );
                    self.recipient = None;
                }
                if !Self::setup_cert(
                    self.srvcert.as_deref(),
                    self.otherpass.as_deref(),
                    "directly trusted CMP server certificate",
                    |c| ctx.set1_srv_cert(c),
                ) {
                    return false;
                }
            }
            if let Some(t) = &self.trusted {
                // the false below clears any expected host/ip/email address; -expect_sender
                // is used instead
                let ts = self.load_trusted(Some(ctx), t, false, "certs trusted by client");
                if !ts.is_some_and(|t| ctx.set0_trusted(t)) {
                    return false;
                }
            }
        }

        if self.unprotected_errors != 0 {
            ctx.set_option(OSSL_CMP_OPT_UNPROTECTED_ERRORS, 1);
        }

        if let Some(ot) = &self.out_trusted {
            // for use in OSSL_CMP_certConf_cb()
            let Some(out_trusted) = self.load_trusted(
                Some(ctx),
                ot,
                true,
                "trusted certs for verifying newly enrolled cert",
            ) else {
                return false;
            };
            // ignore any -attime here, new certs are current anyway
            out_trusted.clear_param_flags(X509_V_FLAG_USE_CHECK_TIME.cast_unsigned().into());
            if !ctx.set_certconf_trusted(out_trusted) {
                return false;
            }
        }

        if self.disable_confirm != 0 {
            ctx.set_option(OSSL_CMP_OPT_DISABLE_CONFIRM, 1);
        }

        if self.implicit_confirm != 0 {
            ctx.set_option(OSSL_CMP_OPT_IMPLICIT_CONFIRM, 1);
        }

        true
    }

    /// `setup_ssl_ctx`: the `SSL_CTX` for the TLS connection.
    fn setup_ssl_ctx(
        &self,
        ctx: &Ctx,
        host: Option<&str>,
        engine: Option<&Engine>,
    ) -> Option<SslCtx> {
        let untrusted = ctx.untrusted();
        let ssl_ctx = SslCtx::new_client()?;

        let mut have_trust_store = false;
        if let Some(tt) = &self.tls_trusted {
            let trust_store = self.load_trusted(Some(ctx), tt, false, "trusted TLS certs")?;
            ssl_ctx.set_cert_store(trust_store, true);
            have_trust_store = true;
        } else {
            cmp_warn!(
                "setup_ssl_ctx",
                1464,
                "-tls_used given without -tls_trusted; will not authenticate the TLS server"
            );
        }

        if let (Some(tls_cert), Some(tls_key)) = (&self.tls_cert, &self.tls_key) {
            // tls_keypass is needed if tls_cert is an encrypted PKCS#12 file
            let (cert, certs) = load_cert_certs(
                tls_cert,
                true,
                true,
                false,
                self.tls_keypass.as_deref(),
                Some("TLS client certificate (optionally with chain)"),
                self.vpm(),
            )?;

            let ok = cert.as_ref().is_some_and(|c| ssl_ctx.use_certificate(c));
            drop(cert);

            // Any further certs and any untrusted certs are used for constructing the chain
            // to be provided with the TLS client cert to the TLS server.
            if !ok || ssl_ctx.set0_chain(certs).is_err() {
                cmp_err!(
                    "setup_ssl_ctx",
                    1486,
                    "unable to use client TLS certificate file '{tls_cert}'"
                );
                return None;
            }
            for c in &untrusted {
                if !ssl_ctx.add1_chain_cert(c) {
                    cmp_err!(
                        "setup_ssl_ctx",
                        1494,
                        "could not add untrusted cert to TLS client cert chain"
                    );
                    return None;
                }
            }

            {
                let mut bak_flags = 0;
                if have_trust_store {
                    bak_flags = ssl_ctx.store_flags().unwrap_or(0);
                    // disable any cert status/revocation checking etc.
                    let keep = X509_V_FLAG_USE_CHECK_TIME
                        | X509_V_FLAG_NO_CHECK_TIME
                        | X509_V_FLAG_PARTIAL_CHAIN
                        | X509_V_FLAG_POLICY_CHECK;
                    ssl_ctx.store_clear_flags(!core::ffi::c_ulong::from(keep.cast_unsigned()));
                }
                cmp_debug!(
                    "setup_ssl_ctx",
                    1513,
                    "trying to build cert chain for own TLS cert"
                );
                let flags = SSL_BUILD_CHAIN_FLAG_UNTRUSTED | SSL_BUILD_CHAIN_FLAG_NO_ROOT;
                if ssl_ctx.build_cert_chain(flags.into()) {
                    cmp_debug!(
                        "setup_ssl_ctx",
                        1516,
                        "success building cert chain for own TLS cert"
                    );
                } else {
                    ctx.print_errors();
                    cmp_warn!(
                        "setup_ssl_ctx",
                        1519,
                        "could not build cert chain for own TLS cert"
                    );
                }
                if have_trust_store {
                    ssl_ctx.store_set_flags(bak_flags);
                }
            }

            // If present we append to the list also the certs from tls_extra
            if let Some(te) = &self.tls_extra {
                let tls_extra = load_certs_multifile(
                    te,
                    self.otherpass.as_deref(),
                    Some("extra certificates for TLS"),
                    self.vpm(),
                )?;
                let mut res = true;
                for cert in tls_extra.to_vec() {
                    if res {
                        res = ssl_ctx.add_extra_chain_cert(cert);
                    }
                }
                if !res {
                    eprintf!("error: unable to add TLS extra certs\n");
                    return None;
                }
            }

            let pkey = Self::load_key_pwd(
                Some(tls_key),
                self.keyform,
                self.tls_keypass.as_deref(),
                engine,
                "TLS client private key",
            )?;
            // verify the key matches the cert, not using SSL_CTX_check_private_key(ssl_ctx)
            // because it gives poor and sometimes misleading diagnostics
            if !cmp::check_private_key(ssl_ctx.certificate().as_ref(), &pkey) {
                cmp_err!(
                    "setup_ssl_ctx",
                    1561,
                    "TLS private key '{tls_key}' does not match the TLS certificate '{tls_cert}'\n"
                );
                return None;
            }
            if !ssl_ctx.use_private_key(&pkey) {
                cmp_err!(
                    "setup_ssl_ctx",
                    1568,
                    "unable to use TLS client private key '{tls_key}'"
                );
                return None;
            }
        } else {
            cmp_warn!(
                "setup_ssl_ctx",
                1575,
                "-tls_used given without -tls_key; cannot authenticate to the TLS server"
            );
        }
        // Enable and parameterize server hostname/IP address check. If we did this before
        // checking our own TLS cert the expected hostname would mislead the check.
        if have_trust_store && !ssl_ctx.store_set_host_etc(self.tls_host.as_deref().or(host)) {
            return None;
        }
        Some(ssl_ctx)
    }

    /// `setup_protection_ctx`: the protection of the requests.
    fn setup_protection_ctx(&mut self, ctx: &Ctx, engine: Option<&Engine>) -> bool {
        if self.unprotected_requests == 0 && self.secret.is_none() && self.key.is_none() {
            cmp_err!(
                "setup_protection_ctx",
                1602,
                "must give -key or -secret unless -unprotected_requests is used"
            );
            return false;
        }

        if self.r#ref.is_none() && self.cert.is_none() && self.subject.is_none() {
            // cert or subject should determine the sender
            cmp_err!(
                "setup_protection_ctx",
                1608,
                "must give -ref if no -cert and no -subject given"
            );
            return false;
        }
        if self.secret.is_none() && (self.cert.is_none() != self.key.is_none()) {
            cmp_err!(
                "setup_protection_ctx",
                1612,
                "must give both -cert and -key options or neither"
            );
            return false;
        }
        if let Some(secret) = &self.secret {
            if let Some(pass_string) = get_passwd(Some(secret), Some("PBMAC"))
                && !ctx.set1_secret_value(pass_string.as_str().as_bytes())
            {
                return false;
            }
            if self.cert.is_some() || self.key.is_some() {
                cmp_warn!(
                    "setup_protection_ctx",
                    1629,
                    "-cert and -key not used for protection since -secret is given"
                );
            }
        }
        if let Some(r) = &self.r#ref
            && !ctx.set1_reference_value(r.as_bytes())
        {
            return false;
        }

        if self.key.is_some() {
            let pkey = Self::load_key_pwd(
                self.key.as_deref(),
                self.keyform,
                self.keypass.as_deref(),
                engine,
                "private key for CMP client certificate",
            );
            if !pkey.is_some_and(|k| ctx.set1_pkey(&k)) {
                return false;
            }
        }
        if self.secret.is_none() && self.srvcert.is_none() && self.trusted.is_none() {
            cmp_warn!(
                "setup_protection_ctx",
                1647,
                "will not authenticate server due to missing -secret, -trusted, or -srvcert"
            );
        }

        if let Some(cert_file) = &self.cert {
            // keypass is needed if cert is an encrypted PKCS#12 file
            let Some((cert, certs)) = load_cert_certs(
                cert_file,
                true,
                true,
                false,
                self.keypass.as_deref(),
                Some("CMP client certificate (optionally with chain)"),
                self.vpm(),
            ) else {
                return false;
            };
            let mut ok = cert.as_ref().is_some_and(|c| ctx.set1_cert(c));
            if !ok {
                cmp_err!("setup_protection_ctx", 1663, "out of memory");
            } else {
                let mut own_trusted = None;
                if let Some(ot) = &self.own_trusted {
                    own_trusted = self.load_trusted(
                        Some(ctx),
                        ot,
                        false,
                        "trusted certs for verifying own CMP signer cert",
                    );
                    ok = own_trusted.is_some();
                }
                ok = ok && ctx.build_cert_chain(own_trusted.as_ref(), certs.as_ref());
            }
            if !ok {
                return false;
            }
        } else if self.own_trusted.is_some() {
            cmp_warn!(
                "setup_protection_ctx",
                1677,
                "-own_trusted option is ignored without -cert"
            );
        }

        if !self.setup_certs(
            self.extracerts.as_deref(),
            "extra certificates for CMP",
            |c| ctx.set1_extra_certs_out(c),
        ) {
            return false;
        }

        if self.unprotected_requests != 0 {
            ctx.set_option(OSSL_CMP_OPT_UNPROTECTED_SEND, 1);
        }

        if let Some(d) = &self.digest {
            let digest = cmp::ln2nid(d);
            if digest == NID_undef {
                cmp_err!(
                    "setup_protection_ctx",
                    1692,
                    "digest algorithm name not recognized: '{d}'"
                );
                return false;
            }
            if !ctx.set_option(OSSL_CMP_OPT_DIGEST_ALGNID, digest)
                || !ctx.set_option(OSSL_CMP_OPT_OWF_ALGNID, digest)
            {
                cmp_err!(
                    "setup_protection_ctx",
                    1697,
                    "digest algorithm name not supported: '{d}'"
                );
                return false;
            }
        }

        if let Some(m) = &self.mac {
            let mac = cmp::ln2nid(m);
            if mac == NID_undef {
                cmp_err!(
                    "setup_protection_ctx",
                    1706,
                    "MAC algorithm name not recognized: '{m}'"
                );
                return false;
            }
            ctx.set_option(OSSL_CMP_OPT_MAC_ALGNID, mac);
        }
        true
    }

    /// `set_fallback_pubkey`: the public key of the first request in `-reqin`.
    fn set_fallback_pubkey(&self, ctx: &Ctx) -> bool {
        let reqin = self.reqin.as_deref().unwrap_or_default();
        // the first file name of the list
        let end = reqin
            .bytes()
            .position(|c| c == b',' || is_space(c))
            .unwrap_or(reqin.len());
        let file = reqin.get(..end).unwrap_or_default();
        let lc = app_libctx::libctx();
        let Some(req) = Msg::read(file, lc.as_deref(), app_libctx::propq().as_deref()) else {
            cmp_err!(
                "set_fallback_pubkey",
                1732,
                "failed to load ir/cr/kur file '{file}' attempting to get fallback public key"
            );
            return false;
        };
        let Some(pkey1) = req.certreq_public_key() else {
            cmp_err!(
                "set_fallback_pubkey",
                1738,
                "failed to get fallback public key from ir/cr/kur file '{file}'"
            );
            return false;
        };
        if !pkey1.is_some_and(|k| ctx.set0_new_pkey(false, k)) {
            cmp_err!(
                "set_fallback_pubkey",
                1745,
                "failed to get fallback public key obtained from ir/cr/kur file '{file}'"
            );
            return false;
        }
        true
    }

    /// `setup_request_ctx`: the parts of the requests.
    fn setup_request_ctx(&mut self, ctx: &Ctx, engine: Option<&Engine>) -> bool {
        let cmd = self.cmd;
        if self.subject.is_none()
            && self.csr.is_none()
            && self.oldcert.is_none()
            && self.cert.is_none()
            && cmd != Some(Cmd::Rr)
            && cmd != Some(Cmd::Genm)
        {
            cmp_warn!(
                "setup_request_ctx",
                1770,
                "no -subject given; no -csr or -oldcert or -cert available for fallback"
            );
        }

        if !Self::set_name(ctx, self.issuer.as_deref(), NameField::Issuer, "issuer") {
            return false;
        }
        if matches!(cmd, Some(Cmd::Ir | Cmd::Cr | Cmd::Kur)) {
            if self.reqin.is_none()
                && self.newkey.is_none()
                && self.centralkeygen == 0
                && self.key.is_none()
                && self.csr.is_none()
                && self.oldcert.is_none()
            {
                cmp_err!(
                    "setup_request_ctx",
                    1777,
                    "missing -newkey (or -key) to be certified and no -csr, -oldcert, -cert, or -reqin option given, which could provide fallback public key. Neither central key generation is requested."
                );
                return false;
            }
            if self.popo == OSSL_CRMF_POPO_NONE && self.centralkeygen == 0 {
                cmp_info!(
                    "setup_request_ctx",
                    1782,
                    "POPO is disabled, which implies -centralkeygen"
                );
                self.centralkeygen = 1;
            }
            if self.centralkeygen != 0 {
                if self.popo > OSSL_CRMF_POPO_NONE {
                    cmp_err!(
                        "setup_request_ctx",
                        1787,
                        "-popo value {} is inconsistent with -centralkeygen",
                        self.popo
                    );
                    return false;
                }
                if self.newkeyout.is_none() {
                    cmp_err!(
                        "setup_request_ctx",
                        1791,
                        "-newkeyout not given, nowhere to save centrally generated key"
                    );
                    return false;
                }
                self.popo = OSSL_CRMF_POPO_NONE;
            }
            if self.newkey.is_none()
                && self.popo != OSSL_CRMF_POPO_NONE
                && self.popo != OSSL_CRMF_POPO_RAVERIFIED
            {
                if self.csr.is_some() {
                    cmp_err!(
                        "setup_request_ctx",
                        1800,
                        "no -newkey option given with private key for POPO, -csr option provides just public key{}",
                        if self.key.is_none() {
                            ""
                        } else {
                            ", and -key option superseded by -csr"
                        }
                    );
                    if self.reqin.is_some() {
                        cmp_info!(
                            "setup_request_ctx",
                            1803,
                            "since -reqin is used, may use -popo -1 or -popo 0 to disable the needless generation of a POPO"
                        );
                    }
                    return false;
                }
                if self.key.is_none() {
                    cmp_err!(
                        "setup_request_ctx",
                        1807,
                        "missing -newkey (or -key) option for key to be certified and for POPO"
                    );
                    return false;
                }
            }
            if self.certout.is_none() && self.reqout_only.is_none() {
                cmp_err!(
                    "setup_request_ctx",
                    1812,
                    "-certout not given, nowhere to save newly enrolled certificate"
                );
                return false;
            }
            if !Self::set_name(ctx, self.subject.as_deref(), NameField::Subject, "subject") {
                return false;
            }
        } else {
            let msg = "option is ignored for commands other than 'ir', 'cr', and 'kur'";

            if self.subject.is_some() {
                if self.r#ref.is_none() && self.cert.is_none() {
                    // will use subject as sender unless oldcert subject is used
                    if !Self::set_name(ctx, self.subject.as_deref(), NameField::Subject, "subject")
                    {
                        return false;
                    }
                } else {
                    cmp_warn!(
                        "setup_request_ctx",
                        1826,
                        "-subject {msg} since sender is taken from -ref or -cert"
                    );
                }
            }
            if self.issuer.is_some() && cmd != Some(Cmd::Rr) {
                cmp_warn!("setup_request_ctx", 1831, "-issuer {msg} and 'rr'");
            }
            if self.reqexts.is_some() {
                cmp_warn!("setup_request_ctx", 1833, "-reqexts {msg}");
            }
            if self.san_nodefault != 0 {
                cmp_warn!("setup_request_ctx", 1835, "-san_nodefault {msg}");
            }
            if self.sans.is_some() {
                cmp_warn!("setup_request_ctx", 1837, "-sans {msg}");
            }
            if self.policies.is_some() {
                cmp_warn!("setup_request_ctx", 1839, "-policies {msg}");
            }
            if self.policy_oids.is_some() {
                cmp_warn!("setup_request_ctx", 1841, "-policy_oids {msg}");
            }
            if self.popo != OSSL_CRMF_POPO_NONE - 1 {
                cmp_warn!("setup_request_ctx", 1843, "-popo {msg}");
            }
            if self.centralkeygen != 0 {
                cmp_warn!(
                    "setup_request_ctx",
                    1845,
                    "-popo -1 or -centralkeygen {msg}"
                );
            }
            if self.newkeyout.is_some() {
                cmp_warn!("setup_request_ctx", 1847, "-newkeyout {msg}");
            }
            if cmd != Some(Cmd::P10cr) {
                if self.implicit_confirm != 0 {
                    cmp_warn!(
                        "setup_request_ctx",
                        1850,
                        "-implicit_confirm {msg}, and 'p10cr'"
                    );
                }
                if self.disable_confirm != 0 {
                    cmp_warn!(
                        "setup_request_ctx",
                        1852,
                        "-disable_confirm {msg}, and 'p10cr'"
                    );
                }
                if self.certout.is_some() {
                    cmp_warn!("setup_request_ctx", 1854, "-certout {msg}, and 'p10cr'");
                }
                if self.chainout.is_some() {
                    cmp_warn!("setup_request_ctx", 1856, "-chainout {msg}, and 'p10cr'");
                }
            }
        }
        if cmd == Some(Cmd::Kur) {
            let ref_cert = self.oldcert.as_deref().or(self.cert.as_deref());

            if ref_cert.is_none() && self.csr.is_none() {
                cmp_err!(
                    "setup_request_ctx",
                    1863,
                    "missing -oldcert for certificate to be updated and no -csr given"
                );
                return false;
            }
            if let Some(s) = &self.subject {
                cmp_warn!(
                    "setup_request_ctx",
                    1867,
                    "given -subject '{}' overrides the subject of '{}' for KUR",
                    s,
                    ref_cert.or(self.csr.as_deref()).unwrap_or("<NULL>")
                );
            }
        }
        if cmd == Some(Cmd::Rr) {
            if self.issuer.is_none() && self.serial.is_none() {
                if self.oldcert.is_none() && self.csr.is_none() {
                    cmp_err!(
                        "setup_request_ctx",
                        1873,
                        "missing -oldcert or -issuer and -serial for certificate to be revoked and no -csr given"
                    );
                    return false;
                }
                if self.oldcert.is_some() && self.csr.is_some() {
                    cmp_warn!(
                        "setup_request_ctx",
                        1877,
                        "ignoring -csr since certificate to be revoked is given"
                    );
                }
            } else {
                if self.issuer.is_none() || self.serial.is_none() {
                    cmp_err!(
                        "setup_request_ctx",
                        1881,
                        "Must give both -issuer and -serial options or neither"
                    );
                    return false;
                }
                if self.oldcert.is_some() {
                    cmp_warn!(
                        "setup_request_ctx",
                        1885,
                        "Ignoring -oldcert since -issuer and -serial is given for command 'rr'"
                    );
                }
                if self.csr.is_some() {
                    cmp_warn!(
                        "setup_request_ctx",
                        1887,
                        "Ignoring -csr since -issuer and -serial is given for command 'rr'"
                    );
                }
            }
            if let Some(serial) = &self.serial {
                match ctx.set1_serial_number(serial) {
                    None => {
                        cmp_err!(
                            "setup_request_ctx",
                            1893,
                            "cannot read serial number: '{serial}'"
                        );
                        return false;
                    }
                    Some(false) => {
                        cmp_err!("setup_request_ctx", 1898, "out of memory");
                        return false;
                    }
                    Some(true) => {}
                }
            }
            if self.revreason > CRL_REASON_NONE {
                ctx.set_option(OSSL_CMP_OPT_REVOCATION_REASON, self.revreason);
            }
        } else if self.serial.is_some() {
            cmp_warn!(
                "setup_request_ctx",
                1908,
                "Ignoring -serial for command other than 'rr'"
            );
        }
        if cmd == Some(Cmd::P10cr) && self.csr.is_none() {
            cmp_err!("setup_request_ctx", 1911, "missing PKCS#10 CSR for p10cr");
            return false;
        }

        if self.recipient.is_none()
            && self.srvcert.is_none()
            && self.issuer.is_none()
            && self.oldcert.is_none()
            && self.cert.is_none()
        {
            cmp_warn!(
                "setup_request_ctx",
                1917,
                "missing -recipient, -srvcert, -issuer, -oldcert or -cert; recipient for any requests not covered by -reqin will be set to \"NULL-DN\""
            );
        }

        if matches!(cmd, Some(Cmd::P10cr | Cmd::Rr | Cmd::Genm)) {
            let msg = "option is ignored for 'p10cr', 'rr', and 'genm' commands";

            if self.newkeypass.is_some() {
                cmp_warn!("setup_request_ctx", 1923, "-newkeypass {msg}");
            }
            if self.newkey.is_some() {
                cmp_warn!("setup_request_ctx", 1925, "-newkey {msg}");
            }
            if self.days != 0 {
                cmp_warn!("setup_request_ctx", 1927, "-days {msg}");
            }
            if self.popo != OSSL_CRMF_POPO_NONE - 1 {
                cmp_warn!("setup_request_ctx", 1929, "-popo {msg}");
            }
            if self.out_trusted.is_some() {
                cmp_warn!("setup_request_ctx", 1931, "-out_trusted {msg}");
            }
        } else if let Some(file) = self.newkey.clone() {
            let pass = self.newkeypass.clone();
            // suppress diagnostics on first try loading key
            let mut pkey = io::muted(|| {
                Self::load_key_pwd(
                    Some(&file),
                    self.keyform,
                    pass.as_deref(),
                    engine,
                    "new private key for cert to be enrolled",
                )
            });
            let mut private = true;
            if pkey.is_none() {
                err::clear();
                let desc = if self.csr.is_none() {
                    "fallback public key for cert to be enrolled"
                } else {
                    "public key for checking cert resulting from p10cr"
                };
                pkey = load_pubkey(
                    Some(&file),
                    self.keyform,
                    false,
                    pass.as_deref(),
                    engine,
                    Some(desc),
                );
                private = false;
            }

            if !pkey.is_some_and(|k| ctx.set0_new_pkey(private, k)) {
                return false;
            }
        } else if self.reqin.is_some()
            && self.key.is_none()
            && self.csr.is_none()
            && self.oldcert.is_none()
            && self.centralkeygen == 0
            && !self.set_fallback_pubkey(ctx)
        {
            return false;
        }

        if self.days > 0 && !ctx.set_option(OSSL_CMP_OPT_VALIDITY_DAYS, self.days) {
            cmp_err!(
                "setup_request_ctx",
                1967,
                "could not set requested cert validity period"
            );
            return false;
        }

        if self.policies.is_some() && self.policy_oids.is_some() {
            cmp_err!(
                "setup_request_ctx",
                1972,
                "cannot have policies both via -policies and via -policy_oids"
            );
            return false;
        }

        let mut csr = None;
        if let Some(csr_file) = &self.csr {
            if cmd == Some(Cmd::Genm) {
                cmp_warn!(
                    "setup_request_ctx",
                    1978,
                    "-csr option is ignored for 'genm' command"
                );
            } else {
                let Some(c) = load_csr_autofmt(Some(csr_file), format::UNDEF, &[], "PKCS#10 CSR")
                else {
                    return false;
                };
                if !ctx.set1_p10_csr(&c) {
                    cmp_err!("setup_request_ctx", 2074, "out of memory");
                    return false;
                }
                csr = Some(c);
            }
        }
        if self.reqexts.is_some() || self.policies.is_some() {
            let Some(mut exts) = ExtStack::new() else {
                cmp_err!("setup_request_ctx", 2074, "out of memory");
                return false;
            };
            let conf = self.conf.as_ref();
            let mut ext_ctx = V3Ctx::new(None, None, csr.as_ref(), None, X509V3_CTX_REPLACE);
            if let Some(c) = conf {
                ext_ctx.set_nconf(c);
            }
            if let Some(re) = &self.reqexts
                && !exts.add_nconf(conf, &mut ext_ctx, re)
            {
                cmp_err!(
                    "setup_request_ctx",
                    1994,
                    "cannot load certificate request extension section '{re}'"
                );
                return false;
            }
            if let Some(po) = &self.policies
                && !exts.add_nconf(conf, &mut ext_ctx, po)
            {
                cmp_err!(
                    "setup_request_ctx",
                    2000,
                    "cannot load policy cert request extension section '{po}'"
                );
                return false;
            }
            ctx.set0_req_extensions(exts);
        }
        drop(csr);

        if ctx.req_extensions_have_san() != 0 && self.sans.is_some() {
            cmp_err!(
                "setup_request_ctx",
                2010,
                "cannot have Subject Alternative Names both via -reqexts and via -sans"
            );
            return false;
        }
        if !Self::set_gennames(ctx, self.sans.as_deref(), "Subject Alternative Name") {
            return false;
        }

        if self.san_nodefault != 0 {
            if self.sans.is_some() {
                cmp_warn!(
                    "setup_request_ctx",
                    2018,
                    "-opt_san_nodefault has no effect when -sans is used"
                );
            }
            ctx.set_option(OSSL_CMP_OPT_SUBJECTALTNAME_NODEFAULT, 1);
        }

        if self.policy_oids_critical != 0 {
            if self.policy_oids.is_none() {
                cmp_warn!(
                    "setup_request_ctx",
                    2025,
                    "-opt_policy_oids_critical has no effect unless -policy_oids is given"
                );
            }
            ctx.set_option(OSSL_CMP_OPT_POLICIES_CRITICAL, 1);
        }

        if let Some(oids) = &self.policy_oids {
            for oid in items(oids) {
                let Some(policy) = Object::from_txt(&oid, true) else {
                    cmp_err!(
                        "setup_request_ctx",
                        2035,
                        "Invalid -policy_oids arg '{oid}'"
                    );
                    return false;
                };
                if policy.nid() == NID_undef {
                    cmp_warn!(
                        "setup_request_ctx",
                        2039,
                        "Unknown -policy_oids arg: {}",
                        prec(&oid, 40)
                    );
                }
                if !ctx.push0_policy(policy) {
                    cmp_err!(
                        "setup_request_ctx",
                        2048,
                        "cannot add policy with OID '{oid}'"
                    );
                    return false;
                }
            }
        }
        if self.popo >= OSSL_CRMF_POPO_NONE {
            ctx.set_option(OSSL_CMP_OPT_POPO_METHOD, self.popo);
        }

        if self.oldcert.is_some() {
            if cmd == Some(Cmd::Genm) {
                cmp_warn!(
                    "setup_request_ctx",
                    2059,
                    "-oldcert option is ignored for 'genm' command"
                );
            } else {
                let desc = match cmd {
                    Some(Cmd::Kur) => "certificate to be updated",
                    Some(Cmd::Rr) => "certificate to be revoked",
                    _ => "reference certificate (oldcert)",
                };
                // keypass is needed if oldcert is an encrypted PKCS#12 file
                if !Self::setup_cert(
                    self.oldcert.as_deref(),
                    self.keypass.as_deref(),
                    desc,
                    |c| ctx.set1_old_cert(c),
                ) {
                    return false;
                }
            }
        }
        true
    }

    /// `handle_opt_geninfo`: the `-geninfo` ITAVs.
    fn handle_opt_geninfo(&self, ctx: &Ctx) -> bool {
        // The list is parsed in place, as upstream does, so the messages show what it shows.
        let mut buf: Vec<u8> = self.geninfo.clone().unwrap_or_default().into_bytes();
        buf.push(0);
        let cstr = |buf: &[u8], at: usize| -> String {
            let rest = buf.get(at..).unwrap_or_default();
            let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
            String::from_utf8_lossy(rest.get(..end).unwrap_or_default()).into_owned()
        };
        let at = |buf: &[u8], i: usize| buf.get(i).copied().unwrap_or(0);
        let mut ptr = 0usize;
        loop {
            while is_space(at(&buf, ptr)) {
                ptr += 1;
            }
            let oid = ptr;
            let rest = buf.get(oid..).unwrap_or_default();
            let nul = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
            let Some(colon) = rest
                .get(..nul)
                .and_then(|r| r.iter().position(|&c| c == b':'))
            else {
                cmp_err!(
                    "handle_opt_geninfo",
                    2127,
                    "Missing ':' in -geninfo arg {}",
                    prec(&cstr(&buf, oid), 40)
                );
                return false;
            };
            ptr = oid + colon;
            if let Some(b) = buf.get_mut(ptr) {
                *b = 0;
            }
            ptr += 1;
            let oid_s = cstr(&buf, oid);
            let Some(obj) = Object::from_txt(&oid_s, false) else {
                cmp_err!(
                    "handle_opt_geninfo",
                    2132,
                    "Invalid OID in -geninfo arg {}",
                    prec(&oid_s, 40)
                );
                return false;
            };
            if obj.nid() == NID_undef {
                cmp_warn!(
                    "handle_opt_geninfo",
                    2136,
                    "Unknown OID in -geninfo arg: {}",
                    prec(&oid_s, 40)
                );
            }

            let prefix = |buf: &[u8], p: usize, pre: &[u8]| {
                buf.get(p..p + pre.len())
                    .is_some_and(|s| s.eq_ignore_ascii_case(pre))
            };
            let value;
            if prefix(&buf, ptr, b"int:") {
                ptr += 4;
                let rest = cstr(&buf, ptr);
                let (v, used) = strtol10(rest.as_bytes());
                if used == 0 {
                    cmp_err!(
                        "handle_opt_geninfo",
                        2143,
                        "Cannot parse int in -geninfo arg {}",
                        prec(&rest, 40)
                    );
                    return false;
                }
                ptr += used;
                if at(&buf, ptr) != 0 {
                    if at(&buf, ptr) != b',' {
                        cmp_err!(
                            "handle_opt_geninfo",
                            2149,
                            "Missing ',' or end of -geninfo arg after int at {}",
                            prec(&cstr(&buf, ptr), 40)
                        );
                        return false;
                    }
                    ptr += 1;
                }
                value = Ok(v);
            } else if prefix(&buf, ptr, b"str:") {
                ptr += 4;
                let rest = buf.get(ptr..).unwrap_or_default();
                let nul = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
                let end = match rest
                    .get(..nul)
                    .and_then(|r| r.iter().position(|&c| c == b','))
                {
                    None => ptr + nul,
                    Some(comma) => {
                        if let Some(b) = buf.get_mut(ptr + comma) {
                            *b = 0;
                        }
                        ptr + comma + 1
                    }
                };
                let text = cstr(&buf, ptr);
                ptr = end;
                value = Err(text);
            } else {
                cmp_err!(
                    "handle_opt_geninfo",
                    2176,
                    "Missing 'int:' or 'str:' in -geninfo arg {}",
                    prec(&cstr(&buf, ptr), 40)
                );
                return false;
            }

            let itav = match &value {
                Ok(v) => Itav::create(obj, Ok(*v)),
                Err(t) => Itav::create(obj, Err(t)),
            };
            let Some(itav) = itav else {
                cmp_err!(
                    "handle_opt_geninfo",
                    2181,
                    "Unable to create 'OSSL_CMP_ITAV' structure"
                );
                return false;
            };

            if !ctx.push0_geninfo_itav(itav) {
                cmp_err!(
                    "handle_opt_geninfo",
                    2188,
                    "Failed to add ITAV for geninfo of the PKI message header"
                );
                return false;
            }
            if at(&buf, ptr) == 0 {
                break;
            }
        }
        true
    }

    /// `setup_client_ctx`: the client context from the options.
    fn setup_client_ctx(&mut self, ctx: &mut CmpCtx, engine: Option<&Engine>) -> bool {
        let mut used_path = self.path.clone();
        let mut server_buf = "mock server".to_owned();
        let mut proxy_buf = String::new();
        let mut host = None;
        let mut server_port = String::new();
        let mut proxy_host = None;

        if self.use_mock_srv == 0 {
            server_buf = "no server".to_owned();
        }
        if self.use_mock_srv == 0
            && self.rspin.is_none()
            && self.server.is_none()
            && self.reqout_only.is_none()
        {
            // note: -port is not given
            cmp_err!(
                "setup_client_ctx",
                2228,
                "missing -server or -use_mock_srv or -rspin option"
            );
            return false;
        }
        match self.server.clone() {
            None => {
                if self.proxy.is_some() {
                    cmp_warn!(
                        "setup_client_ctx",
                        2239,
                        "ignoring -proxy option since -server is not given"
                    );
                }
                if self.no_proxy.is_some() {
                    cmp_warn!(
                        "setup_client_ctx",
                        2241,
                        "ignoring -no_proxy option since -server is not given"
                    );
                }
            }
            Some(server) => {
                let Some(u) = http::parse_url(&server) else {
                    cmp_err!(
                        "setup_client_ctx",
                        2247,
                        "cannot parse -server URL: {server}"
                    );
                    return false;
                };
                if u.use_ssl && self.tls_used == 0 {
                    cmp_warn!(
                        "setup_client_ctx",
                        2251,
                        "assuming -tls_used since -server URL indicates HTTPS"
                    );
                    self.tls_used = 1;
                }
                if !ctx.set_option(OSSL_CMP_OPT_USE_TLS, self.tls_used) {
                    return false;
                }

                server_port = prec(&u.port, 31);
                if self.path.is_none() {
                    used_path = Some(u.path.clone());
                }
                let portnum = u.port.parse::<i32>().unwrap_or(0);
                if !ctx.set1_server(&u.host) || !ctx.set_server_port(portnum) {
                    cmp_err!("setup_client_ctx", 2414, "out of memory");
                    return false;
                }
                if let Some(p) = &self.proxy
                    && !ctx.set1_proxy(p)
                {
                    cmp_err!("setup_client_ctx", 2414, "out of memory");
                    return false;
                }
                if let Some(np) = &self.no_proxy
                    && !ctx.set1_no_proxy(np)
                {
                    cmp_err!("setup_client_ctx", 2414, "out of memory");
                    return false;
                }
                let up = used_path.as_deref().unwrap_or_default();
                server_buf = prec(
                    &format!(
                        "http{}://{}:{}/{}",
                        if self.tls_used != 0 { "s" } else { "" },
                        u.host,
                        u.port,
                        up.strip_prefix('/').unwrap_or(up)
                    ),
                    199,
                );

                proxy_host = http::adapt_proxy_host(
                    self.proxy.as_deref(),
                    self.no_proxy.as_deref(),
                    &u.host,
                    u.use_ssl,
                );
                if let Some(ph) = &proxy_host {
                    proxy_buf = prec(&format!(" via {ph}"), 199);
                }
                host = Some(u.host);
            }
        }

        // set_path:
        if !ctx.set1_server_path(used_path.as_deref()) {
            cmp_err!("setup_client_ctx", 2414, "out of memory");
            return false;
        }
        if !self.transform_opts() {
            return false;
        }

        match &self.infotype_s {
            None => {
                if self.cmd == Some(Cmd::Genm) {
                    cmp_warn!(
                        "setup_client_ctx",
                        2285,
                        "no -infotype option given for genm"
                    );
                }
            }
            Some(_) if self.cmd != Some(Cmd::Genm) => {
                cmp_warn!(
                    "setup_client_ctx",
                    2287,
                    "-infotype option is ignored for commands other than 'genm'"
                );
            }
            Some(it) => {
                let id_buf = prec(&format!("id-it-{it}"), 99);
                self.infotype = object::sn2nid(&id_buf);
                if self.infotype == NID_undef {
                    cmp_err!(
                        "setup_client_ctx",
                        2293,
                        "unknown OID name in -infotype option"
                    );
                    return false;
                }
            }
        }
        if self.cmd != Some(Cmd::Genm) || self.infotype != NID_id_it_rootCaCert {
            let msg = "option is ignored unless -cmd 'genm' and -infotype rootCaCert is given";

            if self.oldwithold.is_some() {
                cmp_warn!("setup_client_ctx", 2301, "-oldwithold {msg}");
            }
            if self.newwithnew.is_some() {
                cmp_warn!("setup_client_ctx", 2303, "-newwithnew {msg}");
            }
            if self.newwithold.is_some() {
                cmp_warn!("setup_client_ctx", 2305, "-newwithold {msg}");
            }
            if self.oldwithnew.is_some() {
                cmp_warn!("setup_client_ctx", 2307, "-oldwithnew {msg}");
            }
        }
        if self.cmd != Some(Cmd::Genm) || self.infotype != NID_id_it_certReqTemplate {
            let msg =
                "option is ignored unless -cmd 'genm' and -infotype 'certReqTemplate' is given";

            if self.template.is_some() {
                cmp_warn!("setup_client_ctx", 2313, "-template {msg}");
            }
            if self.keyspec.is_some() {
                cmp_warn!("setup_client_ctx", 2315, "-keyspec {msg}");
            }
        } else if self.template.is_none() {
            cmp_err!(
                "setup_client_ctx",
                2318,
                "missing -template option for genm with infotype certReqTemplate"
            );
        }

        if !self.setup_verification_ctx(ctx) {
            return false;
        }

        if self.keep_alive != 1 {
            ctx.set_option(OSSL_CMP_OPT_KEEP_ALIVE, self.keep_alive);
        }
        if self.total_timeout > 0 && self.msg_timeout > 0 && self.total_timeout < self.msg_timeout {
            cmp_err!(
                "setup_client_ctx",
                2329,
                "-total_timeout argument = {} must not be < {} (-msg_timeout)",
                self.total_timeout,
                self.msg_timeout
            );
            return false;
        }
        if self.msg_timeout >= 0 {
            // must do this before setup_ssl_ctx()
            ctx.set_option(OSSL_CMP_OPT_MSG_TIMEOUT, self.msg_timeout);
        }
        if self.total_timeout >= 0 {
            ctx.set_option(OSSL_CMP_OPT_TOTAL_TIMEOUT, self.total_timeout);
        }

        {
            let mut t = self.transfer.borrow_mut();
            if self.rspin.is_some() {
                t.rspin_in_use = true;
                if self.reqin.is_some() {
                    cmp_warn!(
                        "setup_client_ctx",
                        2343,
                        "-reqin is ignored since -rspin is present"
                    );
                }
            }
            if self.reqin_new_tid != 0 && self.reqin.is_none() {
                cmp_warn!(
                    "setup_client_ctx",
                    2346,
                    "-reqin_new_tid is ignored since -reqin is not present"
                );
            }
            t.reqout_only.clone_from(&self.reqout_only);
            t.reqout = list(self.reqout.as_deref());
            t.reqin = list(self.reqin.as_deref());
            t.reqin_new_tid = self.reqin_new_tid != 0;
            t.rspin = list(self.rspin.as_deref());
            t.rspout = list(self.rspout.as_deref());
            t.use_mock_srv = self.use_mock_srv != 0;
            t.server = self.server.is_some();
        }
        if self.reqin.is_some()
            || self.reqout.is_some()
            || self.rspin.is_some()
            || self.rspout.is_some()
            || self.use_mock_srv != 0
        {
            let t = Rc::clone(&self.transfer);
            ctx.set_transfer_cb(Box::new(move |c: &Ctx, req: &MsgRef| {
                read_write_req_resp(&mut t.borrow_mut(), c, req)
            }));
        }

        if self.tls_used != 0 {
            if self.tls_cert.is_some() || self.tls_key.is_some() || self.tls_keypass.is_some() {
                if self.tls_key.is_none() {
                    cmp_err!("setup_client_ctx", 2358, "missing -tls_key option");
                    return false;
                } else if self.tls_cert.is_none() {
                    cmp_err!("setup_client_ctx", 2361, "missing -tls_cert option");
                    return false;
                }
            }

            let ssl_ctx = self.setup_ssl_ctx(ctx, host.as_deref(), engine);
            // workaround for callback design flaw, see #17088:
            let use_proxy = proxy_host.is_some();
            let timeout = ctx.get_option(OSSL_CMP_OPT_MSG_TIMEOUT);
            let Some(info) = TlsInfo::new(
                host.as_deref().unwrap_or_default(),
                &server_port,
                use_proxy,
                timeout.into(),
                ssl_ctx.as_ref(),
                &self.prog,
            ) else {
                return false;
            };
            ctx.set_tls_info(info);
            let Some(ssl_ctx) = ssl_ctx else {
                return false;
            };
            ctx.set_tls_ssl_ctx(ssl_ctx);
        }

        if !self.setup_protection_ctx(ctx, engine) {
            return false;
        }

        if !self.setup_request_ctx(ctx, engine) {
            return false;
        }

        if !Self::set_name(
            ctx,
            self.recipient.as_deref(),
            NameField::Recipient,
            "recipient",
        ) || !Self::set_name(
            ctx,
            self.expect_sender.as_deref(),
            NameField::ExpectedSender,
            "expected sender",
        ) {
            return false;
        }

        if self.geninfo.is_some() && !self.handle_opt_geninfo(ctx) {
            return false;
        }
        // add_certProfile
        if let Some(p) = &self.profile
            && !Itav::new_cert_profile(p).is_some_and(|i| ctx.push0_geninfo_itav(i))
        {
            return false;
        }

        // not printing earlier, to minimize confusion in case setup fails before
        if self.reqout_only.is_none() {
            cmp_info!(
                "setup_client_ctx",
                2403,
                "will contact {}{}{} ",
                server_buf,
                proxy_buf,
                if self.rspin.is_none() {
                    ""
                } else {
                    " only if -rspin argument gives too few filenames"
                }
            );
        }
        true
    }

    /// `write_cert`: in `-certform`'s format.
    fn write_cert(&self, bio: &Bio, cert: &Cert) -> bool {
        if (self.certform == format::PEM && cert.write_pem(bio) == 1)
            || (self.certform == format::ASN1 && cert.write_der(bio) == 1)
        {
            return true;
        }
        if self.certform != format::PEM && self.certform != format::ASN1 {
            eprintf!(
                "error: unsupported type '{}' for writing certificates\n",
                self.certform_s.as_deref().unwrap_or("<NULL>")
            );
        }
        false
    }

    /// `write_crl`: in `-crlform`'s format.
    fn write_crl(&self, bio: &Bio, crl: &Crl) -> bool {
        if self.crlform != format::PEM && self.crlform != format::ASN1 {
            eprintf!(
                "error: unsupported type '{}' for writing CRLs\n",
                self.crlform_s.as_deref().unwrap_or("<NULL>")
            );
            return false;
        }
        if self.crlform == format::PEM {
            crl.write_pem(bio) == 1
        } else {
            crl.write_der(bio) == 1
        }
    }

    /// `save_free_certs`: the certificates to `file` (emptied for none): their number, or -1
    /// on error.
    fn save_free_certs(&self, certs: Option<CertStack>, file: Option<&str>, desc: &str) -> i32 {
        let list = certs.as_ref().map(CertStack::to_vec).unwrap_or_default();
        let mut n = i32::try_from(list.len()).unwrap_or(i32::MAX);
        let Some(file) = file else {
            return n;
        };
        if certs.is_some() {
            cmp_info!(
                "save_free_certs",
                2467,
                "received {n} {desc} certificate(s), saving to file '{file}'"
            );
        }
        if n > 1 && self.certform != format::PEM {
            cmp_warn!(
                "save_free_certs",
                2470,
                "saving more than one certificate in non-PEM format"
            );
        }

        let Some(bio) = Bio::new_file(file, "w") else {
            cmp_err!(
                "save_free_certs",
                2474,
                "could not open file '{}' for {} {} certificate(s)",
                file,
                if certs.is_none() {
                    "deleting"
                } else {
                    "writing"
                },
                desc
            );
            return -1;
        };

        for c in &list {
            if !self.write_cert(&bio, c) {
                cmp_err!(
                    "save_free_certs",
                    2482,
                    "cannot write {desc} certificate to file '{file}'"
                );
                n = -1;
                break;
            }
        }
        n
    }

    /// `save_crl`.
    fn save_crl(&self, crl: &Crl, file: &str, desc: &str) -> bool {
        cmp_info!("save_crl", 2503, "received {desc}, saving to file '{file}'");
        let Some(bio) = Bio::new_file(file, "w") else {
            cmp_err!(
                "save_crl",
                2507,
                "could not open file '{file}' for writing {desc}"
            );
            return false;
        };
        if !self.write_crl(&bio, crl) {
            cmp_err!("save_crl", 2513, "cannot write {desc} to file '{file}'");
            return false;
        }
        true
    }

    /// `delete_file`.
    fn delete_file(file: Option<&str>, desc: &str) -> bool {
        let Some(file) = file else {
            return true;
        };
        if let Err(e) = std::fs::remove_file(file)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            cmp_err!(
                "delete_file",
                2529,
                "Failed to delete {file}, which should be done to indicate there is no {desc}"
            );
            return false;
        }
        true
    }

    /// `save_cert_or_delete`.
    fn save_cert_or_delete(&self, cert: Option<&Cert>, file: Option<&str>, desc: &str) -> bool {
        if file.is_none() {
            return true;
        }
        match cert {
            None => Self::delete_file(file, &prec(&format!("{desc} certificate"), 79)),
            Some(c) => {
                let Some(certs) = CertStack::new() else {
                    return false;
                };
                if !certs.push_ref(c) {
                    return false;
                }
                self.save_free_certs(Some(certs), file, desc) >= 0
            }
        }
    }

    /// `save_template`.
    fn save_template(file: &str, tmpl: &cmp::CertTemplateRef) -> bool {
        let Some(bio) = Bio::new_file(file, "wb") else {
            cmp_err!(
                "save_template",
                2568,
                "error saving certTemplate from genp: cannot open file {file}"
            );
            return false;
        };
        if !tmpl.to_der().is_some_and(|d| bio.write_der(&d)) {
            cmp_err!(
                "save_template",
                2574,
                "error saving certTemplate from genp: cannot write file {file}"
            );
            return false;
        }
        cmp_info!(
            "save_template",
            2579,
            "stored certTemplate from genp to file '{file}'"
        );
        true
    }

    /// `save_keyspec`.
    fn save_keyspec(file: &str, keyspec: &Atavs) -> bool {
        let Some(bio) = Bio::new_file(file, "wb") else {
            cmp_err!(
                "save_keyspec",
                2590,
                "error saving keySpec from genp: cannot open file {file}"
            );
            return false;
        };
        if !keyspec.to_der().is_some_and(|d| bio.write_der(&d)) {
            cmp_err!(
                "save_keyspec",
                2595,
                "error saving keySpec from genp: cannot write file {file}"
            );
            return false;
        }
        cmp_info!(
            "save_keyspec",
            2599,
            "stored keySpec from genp to file '{file}'"
        );
        true
    }

    /// `print_status`: the PKIStatusInfo received.
    fn print_status(&self, ctx: &Ctx) {
        let status = ctx.status();
        let string = ctx.snprint_pki_status();
        let (from, server) = match &self.server {
            Some(s) => (" from ", s.as_str()),
            None => ("", ""),
        };
        // Upstream's CMP_print takes the level unparenthesized, so the comparison binds to
        // its last alternative: only statuses other than accepted, rejection, and waiting
        // print, at the warning level.
        if status == OSSL_CMP_PKISTATUS_accepted
            || status == OSSL_CMP_PKISTATUS_rejection
            || status == OSSL_CMP_PKISTATUS_waiting
        {
            return;
        }
        cmp_print(
            true,
            OSSL_CMP_LOG_WARNING,
            "warning",
            "print_status",
            3447,
            &format!(
                "received{from}{server} {}",
                string.as_deref().unwrap_or("<unknown PKIStatus>")
            ),
        );
    }

    /// `print_itavs`.
    fn print_itavs(itavs: &ItavStack) -> bool {
        let mut ret = true;
        let items = itavs.items();
        if items.is_empty() {
            cmp_info!("print_itavs", 2622, "genp does not contain any ITAV");
            return ret;
        }
        for (i, itav) in items.iter().enumerate() {
            let i = i + 1;
            let Some(itav) = itav else {
                cmp_err!("print_itavs", 2632, "could not get ITAV #{i} from genp");
                ret = false;
                continue;
            };
            match itav.type_text(80) {
                None => {
                    cmp_err!(
                        "print_itavs",
                        2637,
                        "error parsing type of ITAV #{i} from genp"
                    );
                    ret = false;
                }
                Some(name) => cmp_info!("print_itavs", 2640, "ITAV #{i} from genp infoType={name}"),
            }
        }
        ret
    }

    /// `print_keyspec`.
    fn print_keyspec(keyspec: Option<&Atavs>) {
        let desc = "specifications contained in keySpec from genp";
        let Some(keyspec) = keyspec else {
            cmp_info!("print_keyspec", 3373, "No {desc}");
            return;
        };
        let Some(mem) = Bio::new_mem() else {
            cmp_err!(
                "print_keyspec",
                3379,
                "Out of memory - cannot dump key {desc}"
            );
            return;
        };
        let w = |s: &str| {
            let _ = mem.write_all(s.as_bytes());
        };
        w(&format!("Key {desc}:\n"));
        for atav in keyspec.items() {
            let nid = atav.map_or_else(cmp::absent_atav_nid, |a| a.type_nid());
            match (nid, atav) {
                (n, Some(a)) if n == NID_id_regCtrl_algId => match a.alg_id() {
                    None => w("Key algorithm: <absent>\n"),
                    Some(alg) => {
                        w("Key algorithm: ");
                        alg.print_oid(&mem);
                        if alg.has_parameter() {
                            w(" - ");
                            alg.item_print(&mem);
                        } else {
                            w("\n");
                        }
                    }
                },
                (n, Some(a)) if n == NID_id_regCtrl_rsaKeyLen => {
                    w(&format!("Key algorithm: RSA {}\n", a.rsa_key_len()));
                }
                _ => w(&format!("Invalid key spec: {}\n", nid_name(nid))),
            }
        }
        w(&format!("End of key {desc}"));

        let text = String::from_utf8_lossy(&mem.read_to_end()).into_owned();
        cmp_info!("print_keyspec", 3428, "{text}");
    }

    /// `do_genm`.
    fn do_genm(&self, ctx: &Ctx) -> bool {
        if self.infotype == NID_id_it_caCerts {
            let Some(cacertsout) = &self.cacertsout else {
                cmp_err!(
                    "do_genm",
                    3468,
                    "Missing -cacertsout option for -infotype caCerts"
                );
                return false;
            };

            let Some(cacerts) = ctx.get1_ca_certs() else {
                return false;
            };

            // could check authorization of sender/origin at this point
            match cacerts {
                None => cmp_warn!("do_genm", 3477, "no CA certificates provided by server"),
                Some(c) => {
                    if self.save_free_certs(Some(c), Some(cacertsout), "CA") < 0 {
                        cmp_err!(
                            "do_genm",
                            3479,
                            "Failed to store CA certificates from genp in {cacertsout}"
                        );
                        return false;
                    }
                }
            }
            true
        } else if self.infotype == NID_id_it_rootCaCert {
            if self.newwithnew.is_none() {
                cmp_err!(
                    "do_genm",
                    3492,
                    "Missing -newwithnew option for -infotype rootCaCert"
                );
                return false;
            }
            let mut oldwithold = None;
            match &self.oldwithold {
                None => cmp_warn!(
                    "do_genm",
                    3496,
                    "No -oldwithold given, will use all certs given with -trusted as trust anchors for verifying the newWithNew cert"
                ),
                Some(f) => {
                    oldwithold = Self::load_cert_pwd(
                        f,
                        self.otherpass.as_deref(),
                        "OldWithOld cert for genm with -infotype rootCaCert",
                    );
                    if oldwithold.is_none() {
                        return false;
                    }
                }
            }
            let Some(upd) = ctx.get1_root_ca_key_update(oldwithold.as_ref()) else {
                return false;
            };
            // At this point might check authorization of response sender/origin

            if upd.new_with_new.is_none() {
                cmp_info!("do_genm", 3509, "no root CA certificate update available");
            } else if oldwithold.is_none() && upd.old_with_new.is_some() {
                cmp_warn!(
                    "do_genm",
                    3511,
                    "oldWithNew certificate received in genp for verifying oldWithOld, but oldWithOld was not provided"
                );
            }

            self.save_cert_or_delete(
                upd.new_with_new.as_ref(),
                self.newwithnew.as_deref(),
                "NewWithNew cert from genp",
            ) && self.save_cert_or_delete(
                upd.new_with_old.as_ref(),
                self.newwithold.as_deref(),
                "NewWithOld cert from genp",
            ) && self.save_cert_or_delete(
                upd.old_with_new.as_ref(),
                self.oldwithnew.as_deref(),
                "OldWithNew cert from genp",
            )
        } else if self.infotype == NID_id_it_crlStatusList {
            let desc = "CRL from genp of type 'crls'";

            if self.oldcrl.is_none() && self.crlcert.is_none() {
                cmp_err!(
                    "do_genm",
                    3534,
                    "Missing -oldcrl and no -crlcert given for -infotype crlStatusList"
                );
                return false;
            }
            let Some(crlout) = &self.crlout else {
                cmp_err!(
                    "do_genm",
                    3538,
                    "Missing -crlout for -infotype crlStatusList"
                );
                return false;
            };

            let mut crlcert = None;
            if let Some(f) = &self.crlcert {
                crlcert = Self::load_cert_pwd(
                    f,
                    self.otherpass.as_deref(),
                    "Cert for genm with -infotype crlStatusList",
                );
                if crlcert.is_none() {
                    return false;
                }
            }

            let mut oldcrl = None;
            if let Some(f) = &self.oldcrl {
                oldcrl = load_crl(
                    Some(f),
                    format::UNDEF,
                    false,
                    Some("CRL for genm with -infotype crlStatusList"),
                );
                if oldcrl.is_none() {
                    return false;
                }
            }

            if let (Some(o), Some(c)) = (&oldcrl, &crlcert)
                && cmp::name_cmp(o.issuer_name(), c.issuer_name()) != 0
            {
                cmp_warn!(
                    "do_genm",
                    3560,
                    "-oldcrl and -crlcert have different issuer"
                );
            }

            let Some(crl) = ctx.get1_crl_update(crlcert.as_ref(), oldcrl.as_ref()) else {
                return false;
            };

            match &crl {
                None => {
                    cmp_info!("do_genm", 3567, "no CRL update available");
                    Self::delete_file(Some(crlout), desc)
                }
                Some(c) => self.save_crl(c, crlout, desc),
            }
        } else if self.infotype == NID_id_it_certReqTemplate {
            let Some((cert_template, keyspec)) = ctx.get1_cert_req_template() else {
                return false;
            };

            let Some(cert_template) = cert_template else {
                cmp_warn!("do_genm", 3588, "no certificate request template available");
                if !Self::delete_file(self.template.as_deref(), "certTemplate from genp") {
                    return false;
                }
                if self.keyspec.is_some()
                    && !Self::delete_file(self.keyspec.as_deref(), "keySpec from genp")
                {
                    return false;
                }
                return true;
            };
            if !Self::save_template(self.template.as_deref().unwrap_or_default(), &cert_template) {
                return false;
            }

            Self::print_keyspec(keyspec.as_ref());
            if let Some(ks) = &self.keyspec {
                match &keyspec {
                    None => {
                        cmp_warn!("do_genm", 3602, "no key specifications available");
                        if !Self::delete_file(Some(ks), "keySpec from genp") {
                            return false;
                        }
                    }
                    Some(k) => {
                        if !Self::save_keyspec(ks, k) {
                            return false;
                        }
                    }
                }
            }
            true
        } else {
            if self.infotype != NID_undef {
                let it = self.infotype_s.as_deref().unwrap_or("<NULL>");
                cmp_warn!(
                    "do_genm",
                    3620,
                    "No specific support for -infotype {it} available"
                );

                if !Itav::from_nid(self.infotype).is_some_and(|req| ctx.push0_genm_itav(req)) {
                    cmp_err!("do_genm", 3625, "Failed to create genm for -infotype {it}");
                    return false;
                }
            }

            if let Some(itavs) = ctx.exec_genm() {
                return Self::print_itavs(&itavs);
            }
            if ctx.status() != OSSL_CMP_PKISTATUS_request {
                cmp_err!(
                    "do_genm",
                    3638,
                    "Did not receive response on genm or genp is not valid"
                );
            }
            false
        }
    }

    /// `cmp_server`: a very basic HTTP server answering with the mock server.
    fn cmp_server(&self, ctx: &CmpCtx, port: &str) -> i32 {
        let Some(srv_cmp_ctx) = ctx.mock_server().and_then(|s| s.cmp_ctx()) else {
            return 0;
        };
        let prog = self.prog.as_str();
        let Some(acbio) = http_server_init(prog, port, verbosity()) else {
            return 0;
        };
        let mut cbio: Option<Bio> = None;
        let mut keep_alive = false;
        let mut msgs = 0;
        let mut retry = true;
        let mut ret = 1;

        'serve: while self.max_msgs <= 0 || msgs < self.max_msgs {
            let r = http_server_get_asn1_req(
                Msg::read_der,
                true,
                &mut cbio,
                &acbio,
                Some(&mut keep_alive),
                prog,
                false,
            );
            ret = r.ret;
            'next: {
                if ret == 0 {
                    // no request yet
                    if retry {
                        std::thread::sleep(std::time::Duration::from_secs(1));
                        retry = false;
                        continue 'serve;
                    }
                    ret = 0;
                    break 'next;
                }
                if ret == -1 {
                    // fatal error
                    return 0;
                }

                ret = 0;
                msgs += 1;
                if let Some(req) = r.req {
                    let path = r.path.unwrap_or_default();
                    let Some(cb) = &cbio else {
                        break 'next;
                    };
                    if !path.is_empty() && path != "pkix/" {
                        http_server_send_status(prog, cb, 404, "Not Found");
                        cmp_err!(
                            "cmp_server",
                            3323,
                            "expecting empty path or 'pkix/' but got '{path}'"
                        );
                        break 'next;
                    }
                    let Some(resp) = ctx.server_perform(&req) else {
                        http_server_send_status(prog, cb, 500, "Internal Server Error");
                        return 0; // treated as fatal error
                    };
                    let ok = http_server_send_asn1_resp(
                        prog,
                        cb,
                        keep_alive,
                        "application/pkixcmp",
                        resp.der_len(),
                        |b| resp.write_der(b),
                    );
                    ret = i32::from(ok);
                    if !ok {
                        return 0; // treated as fatal error
                    }
                }
            }
            // next:
            if ret == 0 {
                // on transmission error, cancel CMP transaction
                srv_cmp_ctx.set1_transaction_id(None);
                srv_cmp_ctx.set1_sender_nonce(None);
            }
            if ret == 0 || !keep_alive || srv_cmp_ctx.status() != OSSL_CMP_PKISTATUS_trans {
                // transaction closed by OSSL_CMP_CTX_server_perform()
                cbio = None;
            }
        }
        ret
    }
}

/// `nid_name`.
fn nid_name(nid: i32) -> String {
    object::nid2ln(nid)
        .or_else(|| object::nid2sn(nid))
        .unwrap_or_else(|| "<unknown OID>".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prev_items() {
        let all = |s: &str| {
            let mut v = Vec::new();
            let mut end = s.len();
            while let Some((item, e)) = prev_item(s, end) {
                v.push(item);
                end = e;
            }
            v
        };
        assert_eq!(all("a,b c"), ["c", "b", "a"]);
        assert_eq!(all(",a, "), ["", "a"]);
        assert_eq!(all("cmp"), ["cmp"]);
    }

    #[test]
    fn strtol_like_c() {
        assert_eq!(strtol10(b" 12x"), (12, 3));
        assert_eq!(strtol10(b"-5"), (-5, 2));
        assert_eq!(strtol10(b"x"), (0, 0));
        assert_eq!(strtol10(b"99999999999999999999"), (i64::MAX, 20));
    }

    /// Every message names the function and line of `apps/cmp.c` that prints it there.
    #[test]
    fn message_locations_match_upstream() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../abi/openssl-3.6/apps/cmp.c"
        );
        let Ok(c_src) = std::fs::read_to_string(path) else {
            return; // the vendored tree isn't there
        };
        let c_lines: Vec<&str> = c_src.lines().collect();
        let src = include_str!("cmp.rs");
        let mut checked = 0;
        for kind in ["cmp_err!(", "cmp_warn!(", "cmp_info!(", "cmp_debug!("] {
            let mut rest = src;
            while let Some(i) = rest.find(kind) {
                rest = rest.get(i + kind.len()..).unwrap_or_default();
                let args = rest.trim_start();
                if !args.starts_with('"') {
                    continue; // the macro definition
                }
                let func = args
                    .get(1..)
                    .and_then(|a| a.split('"').next())
                    .unwrap_or_default();
                if func.is_empty() || !func.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
                {
                    continue; // this test's own list
                }
                let after = args.get(func.len() + 2..).unwrap_or_default();
                let line: usize = after
                    .trim_start_matches([',', ' ', '\n'])
                    .split(|c: char| !c.is_ascii_digit())
                    .next()
                    .and_then(|n| n.parse().ok())
                    .unwrap_or(0);
                let c_line = c_lines
                    .get(line.saturating_sub(1))
                    .copied()
                    .unwrap_or_default();
                let macro_name = format!(
                    "CMP_{}",
                    kind.trim_start_matches("cmp_").trim_end_matches("!(")
                );
                assert!(
                    c_line.contains(&macro_name),
                    "{func}:{line}: no {macro_name} there: {c_line}"
                );
                let def = c_lines
                    .get(..line)
                    .unwrap_or_default()
                    .iter()
                    .rev()
                    .find(|l| {
                        l.starts_with(|c: char| c.is_ascii_alphabetic())
                            && l.contains('(')
                            && !l.contains(';')
                    })
                    .copied()
                    .unwrap_or_default();
                assert!(
                    def.contains(&format!("{func}(")),
                    "{func}:{line} is in: {def}"
                );
                checked += 1;
            }
        }
        assert!(checked > 200, "only {checked} messages found");
        assert!(
            c_lines
                .get(3446)
                .is_some_and(|l| l.contains("CMP_print(bio_err"))
        );
    }
}
