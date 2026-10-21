//! `openssl ocsp` (`apps/ocsp.c`).
//!
//! The responder reads the CA's index file with `lib::ca_db` (`load_index` and `index_index`
//! of `apps.c`). Its `unpack_revinfo` keeps what it parsed when it fails, as `ca.c`'s does
//! for `ocsp` (which ignores the failure); `ca`'s own copy returns nothing then.

use rustyssl_ossl::abi::{
    OCSP_NOCERTS, OCSP_NOCHAIN, OCSP_NOCHECKS, OCSP_NOEXPLICIT, OCSP_NOINTERN, OCSP_NOSIGS,
    OCSP_NOVERIFY, OCSP_RESPID_KEY, OCSP_RESPONSE_STATUS_INTERNALERROR,
    OCSP_RESPONSE_STATUS_MALFORMEDREQUEST, OCSP_RESPONSE_STATUS_SUCCESSFUL,
    OCSP_REVOKED_STATUS_CACOMPROMISE, OCSP_REVOKED_STATUS_CERTIFICATEHOLD,
    OCSP_REVOKED_STATUS_KEYCOMPROMISE, OCSP_REVOKED_STATUS_NOSTATUS,
    OCSP_REVOKED_STATUS_REMOVEFROMCRL, OCSP_TRUSTOTHER, V_OCSP_CERTSTATUS_GOOD,
    V_OCSP_CERTSTATUS_REVOKED, V_OCSP_CERTSTATUS_UNKNOWN,
};
use rustyssl_ossl::evp::Md;
use rustyssl_ossl::http::{self, Headers, Post, SslCtx};
use rustyssl_ossl::object::Object;
use rustyssl_ossl::ocsp::{self, BasicResp, CertId, OcspRequest, OcspResponse, Time};
use rustyssl_ossl::pkey::{MdCtx, Pkey};
use rustyssl_ossl::txt_db::TxtDb;
use rustyssl_ossl::verify::VerifyParam;
use rustyssl_ossl::x509::{Cert, CertStack};
use rustyssl_ossl::{Bio, err};

use crate::generated::options::ocsp::{OPTIONS, Opt};
use crate::lib::apps::{
    app_passwd, atoi, bio_open_default, load_cert, load_certs, load_key, setup_verify,
};
use crate::lib::apps_http::app_http_post_asn1;
use crate::lib::ca_db::{self, field};
use crate::lib::http_server::{
    http_server_get_asn1_req, http_server_init, http_server_send_asn1_resp, level, n_responders,
    set_n_responders, spawn_loop, trace_log_message,
};
use crate::lib::opt::{self, Parser, eprintf, format};
use crate::lib::{app_libctx, io};

/// `index_changed`: whether the index file's `stat` differs from when it was read.
fn index_changed(rdb: &ca_db::CaDb) -> bool {
    // A stat that fails now leaves the index as it is.
    let changed = matches!(
        (ca_db::file_stat(&rdb.dbfname), rdb.dbst),
        (Some(now), Some(then)) if now != then
    );
    if changed {
        rustyssl_ossl::os::syslog_info("index file changed, reloading");
    }
    changed
}

/// `MAX_VALIDITY_PERIOD`: the default `-validity_period`, in seconds.
const MAX_VALIDITY_PERIOD: i64 = 5 * 60;

/// The request being built from `-cert` and `-serial`, and its IDs.
#[derive(Default)]
struct Building {
    req: Option<OcspRequest>,
    ids: Vec<CertId>,
}

impl Building {
    /// `add_ocsp_cert`.
    fn add_cert(&mut self, cert: &Cert, md: &Md, issuer: Option<&Cert>) -> bool {
        let Some(issuer) = issuer else {
            eprintf!("No issuer certificate specified\n");
            return false;
        };
        let ok = (|| {
            if self.req.is_none() {
                self.req = OcspRequest::new();
            }
            let req = self.req.as_ref()?;
            let id = CertId::from_cert(Some(md), Some(cert), issuer)?;
            if !req.add_id(&id) {
                return None;
            }
            self.ids.push(id);
            Some(())
        })();
        if ok.is_none() {
            eprintf!("Error Creating OCSP request\n");
        }
        ok.is_some()
    }

    /// `add_ocsp_serial`.
    fn add_serial(&mut self, serial: &str, md: &Md, issuer: Option<&Cert>) -> bool {
        let Some(issuer) = issuer else {
            eprintf!("No issuer certificate specified\n");
            return false;
        };
        if self.req.is_none() {
            self.req = OcspRequest::new();
        }
        let Some(req) = self.req.as_ref() else {
            eprintf!("Error Creating OCSP request\n");
            return false;
        };
        let id = match CertId::from_serial(md, issuer, serial) {
            Ok(id) => id,
            Err(true) => {
                eprintf!("Error converting serial number {serial}\n");
                return false;
            }
            Err(false) => {
                eprintf!("Error Creating OCSP request\n");
                return false;
            }
        };
        if !req.add_id(&id) {
            eprintf!("Error Creating OCSP request\n");
            return false;
        }
        self.ids.push(id);
        true
    }
}

/// The responder's settings.
struct Responder<'a> {
    db: &'a TxtDb,
    ca: &'a [Cert],
    rcert: &'a Cert,
    rkey: &'a Pkey,
    rmd: Option<&'a Md>,
    sigopts: &'a [String],
    rother: Option<&'a CertStack>,
    flags: std::ffi::c_ulong,
    nmin: i32,
    ndays: i32,
    badsig: bool,
    resp_md: Option<&'a Md>,
}

pub fn main(argv: &[String]) -> i32 {
    let ret = run(argv);
    io::print_errors();
    ret
}

#[allow(clippy::too_many_lines)]
fn run(argv: &[String]) -> i32 {
    let Some(vpm) = VerifyParam::new() else {
        return 1;
    };
    let mut p = Parser::with_unknown(argv, OPTIONS, Some("digest"));
    let prog = p.prog();
    let opthelp = |prog: &str| {
        eprintf!("{prog}: Use -help for summary.\n");
        1
    };
    let mut cert_id_md: Option<Md> = None;
    let mut rsign_sigopts: Vec<String> = Vec::new();
    let mut trailing_md = false;
    let mut headers = Headers::default();
    let mut reqnames: Vec<String> = Vec::new();
    let mut issuers: Option<Vec<Cert>> = None;
    let mut issuer: Option<Cert> = None;
    let mut resp_certid_md: Option<Md> = None;
    let (mut ca_file, mut ca_path, mut ca_store) = (None::<String>, None::<String>, None::<String>);
    let mut respdigname: Option<String> = None;
    let (mut host, mut port, mut path) = (None::<String>, None::<String>, String::from("/"));
    let mut outfile: Option<String> = None;
    let (mut opt_proxy, mut opt_no_proxy) = (None::<String>, None::<String>);
    let (mut rca_filename, mut reqin, mut respin) =
        (None::<String>, None::<String>, None::<String>);
    let (mut reqout, mut respout, mut ridx_filename) =
        (None::<String>, None::<String>, None::<String>);
    let (mut rsignfile, mut rkeyfile) = (None::<String>, None::<String>);
    let mut passinarg: Option<String> = None;
    let (mut sign_certfile, mut verify_certfile, mut rcertfile) =
        (None::<String>, None::<String>, None::<String>);
    let (mut signfile, mut keyfile) = (None::<String>, None::<String>);
    let (mut no_ca_file, mut no_ca_path, mut no_ca_store) = (false, false, false);
    let (mut accept_count, mut add_nonce, mut noverify, mut use_ssl) = (-1i64, 1, false, -1);
    let (mut vpmtouched, mut badsig, mut ignore_err, mut nmin, mut ndays) =
        (false, false, false, 0, -1);
    let (mut req_text, mut resp_text) = (false, false);
    let mut req_timeout: i64 = -1;
    let (mut nsec, mut maxage) = (MAX_VALIDITY_PERIOD, -1i64);
    let (mut sign_flags, mut verify_flags, mut rflags) = (0u32, 0u32, 0u32);
    let mut b = Building::default();
    let flag = |f: i32| u32::try_from(f).unwrap_or(0);
    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::ERR => return opthelp(&prog),
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::OUTFILE => outfile = Some(p.arg().to_owned()),
            Opt::TIMEOUT => req_timeout = i64::from(atoi(p.arg())),
            Opt::URL => match http::parse_url(p.arg()) {
                Some(u) => {
                    use_ssl = i32::from(u.use_ssl);
                    host = Some(u.host);
                    port = Some(u.port);
                    path = u.path;
                }
                None => {
                    eprintf!("{prog} Error parsing -url argument\n");
                    return 1;
                }
            },
            Opt::HOST => host = Some(p.arg().to_owned()),
            Opt::PORT => port = Some(p.arg().to_owned()),
            Opt::PATH => path = p.arg().to_owned(),
            Opt::PROXY => opt_proxy = Some(p.arg().to_owned()),
            Opt::NO_PROXY => opt_no_proxy = Some(p.arg().to_owned()),
            Opt::IGNORE_ERR => ignore_err = true,
            Opt::NOVERIFY => noverify = true,
            Opt::NONCE => add_nonce = 2,
            Opt::NO_NONCE => add_nonce = 0,
            Opt::RESP_NO_CERTS => rflags |= flag(OCSP_NOCERTS),
            Opt::RESP_KEY_ID => rflags |= flag(OCSP_RESPID_KEY),
            Opt::NO_CERTS => sign_flags |= flag(OCSP_NOCERTS),
            Opt::NO_SIGNATURE_VERIFY => verify_flags |= flag(OCSP_NOSIGS),
            Opt::NO_CERT_VERIFY => verify_flags |= flag(OCSP_NOVERIFY),
            Opt::NO_CHAIN => verify_flags |= flag(OCSP_NOCHAIN),
            Opt::NO_CERT_CHECKS => verify_flags |= flag(OCSP_NOCHECKS),
            Opt::NO_EXPLICIT => verify_flags |= flag(OCSP_NOEXPLICIT),
            Opt::TRUST_OTHER => verify_flags |= flag(OCSP_TRUSTOTHER),
            Opt::NO_INTERN => verify_flags |= flag(OCSP_NOINTERN),
            Opt::BADSIG => badsig = true,
            Opt::TEXT => {
                req_text = true;
                resp_text = true;
            }
            Opt::REQ_TEXT => req_text = true,
            Opt::RESP_TEXT => resp_text = true,
            Opt::REQIN => reqin = Some(p.arg().to_owned()),
            Opt::RESPIN => respin = Some(p.arg().to_owned()),
            Opt::SIGNER => signfile = Some(p.arg().to_owned()),
            Opt::VAFILE => {
                verify_certfile = Some(p.arg().to_owned());
                verify_flags |= flag(OCSP_TRUSTOTHER);
            }
            Opt::SIGN_OTHER => sign_certfile = Some(p.arg().to_owned()),
            Opt::VERIFY_OTHER => verify_certfile = Some(p.arg().to_owned()),
            Opt::CAFILE => ca_file = Some(p.arg().to_owned()),
            Opt::CAPATH => ca_path = Some(p.arg().to_owned()),
            Opt::CASTORE => ca_store = Some(p.arg().to_owned()),
            Opt::NOCAFILE => no_ca_file = true,
            Opt::NOCAPATH => no_ca_path = true,
            Opt::NOCASTORE => no_ca_store = true,
            Opt::OPT_V(v) => {
                if !opt::verify(v, p.arg(), (&vpm).into()) {
                    return 1;
                }
                vpmtouched = true;
            }
            Opt::VALIDITY_PERIOD => {
                if let Some(v) = opt::long(p.arg()) {
                    nsec = v;
                }
            }
            Opt::STATUS_AGE => {
                if let Some(v) = opt::long(p.arg()) {
                    maxage = v;
                }
            }
            Opt::SIGNKEY => keyfile = Some(p.arg().to_owned()),
            Opt::REQOUT => reqout = Some(p.arg().to_owned()),
            Opt::RESPOUT => respout = Some(p.arg().to_owned()),
            Opt::ISSUER => {
                let Some(i) = load_cert(Some(p.arg()), format::UNDEF, Some("issuer certificate"))
                else {
                    return 1;
                };
                issuers.get_or_insert_with(Vec::new).push(i.clone_ref());
                issuer = Some(i);
            }
            Opt::CERT => {
                p.reset_unknown();
                let Some(cert) = load_cert(Some(p.arg()), format::UNDEF, Some("certificate"))
                else {
                    return 1;
                };
                if cert_id_md.is_none() {
                    cert_id_md = Md::by_name("SHA1");
                }
                let Some(md) = &cert_id_md else {
                    return 1;
                };
                if !b.add_cert(&cert, md, issuer.as_ref()) {
                    return 1;
                }
                reqnames.push(p.arg().to_owned());
                trailing_md = false;
            }
            Opt::SERIAL => {
                p.reset_unknown();
                if cert_id_md.is_none() {
                    cert_id_md = Md::by_name("SHA1");
                }
                let Some(md) = &cert_id_md else {
                    return 1;
                };
                if !b.add_serial(p.arg(), md, issuer.as_ref()) {
                    return 1;
                }
                reqnames.push(p.arg().to_owned());
                trailing_md = false;
            }
            Opt::INDEX => ridx_filename = Some(p.arg().to_owned()),
            Opt::CA => rca_filename = Some(p.arg().to_owned()),
            Opt::NMIN => {
                nmin = p.int_arg();
                if ndays == -1 {
                    ndays = 0;
                }
            }
            Opt::REQUEST => accept_count = i64::from(p.int_arg()),
            Opt::NDAYS => ndays = atoi(p.arg()),
            Opt::RSIGNER => rsignfile = Some(p.arg().to_owned()),
            Opt::RKEY => rkeyfile = Some(p.arg().to_owned()),
            Opt::PASSIN => passinarg = Some(p.arg().to_owned()),
            Opt::ROTHER => rcertfile = Some(p.arg().to_owned()),
            Opt::RMD => respdigname = Some(p.arg().to_owned()),
            Opt::RSIGOPT => rsign_sigopts.push(p.arg().to_owned()),
            Opt::HEADER => {
                let arg = p.arg().to_owned();
                let Some((k, v)) = arg.split_once('=') else {
                    eprintf!("Missing = in header key=value\n");
                    return opthelp(&prog);
                };
                if !headers.add(k, v) {
                    return 1;
                }
            }
            Opt::RCID => match opt::md(p.arg()) {
                Some(m) => resp_certid_md = Some(m),
                None => return opthelp(&prog),
            },
            Opt::MD => {
                if trailing_md {
                    eprintf!("{prog}: Digest must be before -cert or -serial\n");
                    return opthelp(&prog);
                }
                match opt::md(p.unknown().unwrap_or_default()) {
                    Some(m) => cert_id_md = Some(m),
                    None => return opthelp(&prog),
                }
                trailing_md = true;
            }
            Opt::MULTI => set_n_responders(usize::try_from(atoi(p.arg())).unwrap_or(0)),
            Opt::OPT_PROV(o) => {
                if !app_libctx::opt_provider(o, p.arg()) {
                    return 1;
                }
            }
        }
    }
    if !p.check_rest_arg(None) {
        return opthelp(&prog);
    }
    if trailing_md {
        eprintf!("{prog}: Digest must be before -cert or -serial\n");
        return opthelp(&prog);
    }
    let mut rsign_md = None;
    if let Some(r) = &respdigname {
        match opt::md(r) {
            Some(m) => rsign_md = Some(m),
            None => return 1,
        }
    }
    // Is there anything to do?
    let mut req = b.req.take();
    if req.is_none()
        && reqin.is_none()
        && respin.is_none()
        && !(port.is_some() && ridx_filename.is_some())
    {
        return opthelp(&prog);
    }
    if req.is_none() && add_nonce != 2 {
        add_nonce = 0;
    }
    if req.is_none()
        && let Some(r) = &reqin
    {
        let Some(derbio) = bio_open_default(Some(r), 'r', format::ASN1) else {
            return 1;
        };
        req = OcspRequest::read_der(Some(&derbio));
        if req.is_none() {
            eprintf!("Error reading OCSP request\n");
            return 1;
        }
    }
    let mut acbio = None;
    if req.is_none()
        && let Some(port) = &port
    {
        acbio = http_server_init(&prog, port, -1);
        if acbio.is_none() {
            return 1;
        }
    }
    let (mut rsigner, mut rkey) = (None, None);
    let (mut rca_certs, mut rother) = (None::<CertStack>, None::<CertStack>);
    if let Some(rs) = &rsignfile {
        if rkeyfile.is_none() {
            rkeyfile = Some(rs.clone());
        }
        rsigner = load_cert(Some(rs), format::UNDEF, Some("responder certificate"));
        if rsigner.is_none() {
            eprintf!("Error loading responder certificate\n");
            return 1;
        }
        let (ok, c) = load_certs(
            rca_filename.as_deref(),
            false,
            None,
            None,
            Some("CA certificates"),
        );
        if !ok {
            return 1;
        }
        rca_certs = c;
        if let Some(rc) = &rcertfile {
            let (ok, c) = load_certs(
                Some(rc),
                false,
                None,
                None,
                Some("responder other certificates"),
            );
            if !ok {
                return 1;
            }
            rother = c;
        }
        let passin = match app_passwd(passinarg.as_deref(), None) {
            Some((p, _)) => p,
            None => {
                eprintf!("Error getting password\n");
                return 1;
            }
        };
        rkey = load_key(
            rkeyfile.as_deref(),
            format::UNDEF,
            false,
            passin.as_ref().map(|p| p.as_str()),
            None,
            Some("responder private key"),
        );
        if rkey.is_none() {
            return 1;
        }
    }
    if ridx_filename.is_some() && (rkey.is_none() || rsigner.is_none() || rca_certs.is_none()) {
        eprintf!("Responder mode requires certificate, key, and CA.\n");
        return 1;
    }
    let mut rdb = None;
    if let Some(f) = &ridx_filename {
        match ca_db::load_index(f, true).filter(ca_db::index_index) {
            Some(db) => rdb = Some(db),
            None => {
                eprintf!("Problem with index file: {f} (could not load/parse file)\n");
                return 1;
            }
        }
    }
    if n_responders() != 0 && acbio.is_some() {
        spawn_loop(&prog);
    }
    if acbio.is_some() && req_timeout > 0 {
        rustyssl_ossl::os::catch_alarm_socket_timeout();
    }
    if acbio.is_some() {
        trace_log_message(&prog, level::INFO, "waiting for OCSP client connections...");
    }
    let rca_list = rca_certs
        .as_ref()
        .map(CertStack::to_vec)
        .unwrap_or_default();
    let mut cbio: Option<Bio> = None;
    let mut resp: Option<OcspResponse>;
    // Kept from one request to the next, as upstream's.
    let mut out: Option<Bio> = None;
    let mut store = None;

    loop {
        // redo_accept.
        resp = None;
        let mut skip_to_done = false;
        if let Some(ac) = &acbio {
            if let Some(db) = &rdb
                && index_changed(db)
            {
                match ca_db::load_index(&db.dbfname, true).filter(ca_db::index_index) {
                    Some(newdb) => rdb = Some(newdb),
                    None => {
                        let f = ridx_filename.as_deref().unwrap_or_default();
                        trace_log_message(
                            &prog,
                            level::ERR,
                            &format!("error reloading updated index: {f}"),
                        );
                    }
                }
            }
            req = None;
            let r = http_server_get_asn1_req(
                |b| OcspRequest::read_der(Some(b)),
                false,
                &mut cbio,
                ac,
                None,
                &prog,
                true,
                i32::try_from(req_timeout).unwrap_or(i32::MAX),
            );
            if r.ret == 0 {
                continue;
            }
            req = r.req;
            if req.is_none() {
                if r.ret == 1 {
                    resp = OcspResponse::create(OCSP_RESPONSE_STATUS_MALFORMEDREQUEST, None);
                    if let (Some(c), Some(rs)) = (&cbio, &resp) {
                        send_ocsp_response(&prog, c, rs);
                    }
                }
                skip_to_done = true;
            }
        }
        if !skip_to_done {
            if req.is_none()
                && (signfile.is_some()
                    || reqout.is_some()
                    || host.is_some()
                    || add_nonce != 0
                    || ridx_filename.is_some())
            {
                eprintf!("Need an OCSP request for this operation!\n");
                return 1;
            }
            if let Some(r) = &req
                && add_nonce != 0
                && !r.add1_nonce()
            {
                return 1;
            }
            if let Some(sf) = &signfile {
                if keyfile.is_none() {
                    keyfile = Some(sf.clone());
                }
                let Some(signer) = load_cert(Some(sf), format::UNDEF, Some("signer certificate"))
                else {
                    eprintf!("Error loading signer certificate\n");
                    return 1;
                };
                let mut sign_other = None;
                if let Some(sc) = &sign_certfile {
                    let (ok, c) =
                        load_certs(Some(sc), false, None, None, Some("signer certificates"));
                    if !ok {
                        return 1;
                    }
                    sign_other = c;
                }
                let Some(key) = load_key(
                    keyfile.as_deref(),
                    format::UNDEF,
                    false,
                    None,
                    None,
                    Some("signer private key"),
                ) else {
                    return 1;
                };
                let signed = req.as_ref().is_some_and(|r| {
                    r.sign(
                        &signer,
                        &key,
                        sign_other.as_ref(),
                        std::ffi::c_ulong::from(sign_flags),
                    )
                });
                if !signed {
                    eprintf!("Error signing OCSP request\n");
                    return 1;
                }
            }
            out = bio_open_default(outfile.as_deref(), 'w', format::TEXT);
            let Some(o) = &out else {
                return 1;
            };
            if req_text && let Some(r) = &req {
                r.print(o);
            }
            if let Some(ro) = &reqout {
                let Some(derbio) = bio_open_default(Some(ro), 'w', format::ASN1) else {
                    return 1;
                };
                if let Some(r) = &req {
                    r.write_der(&derbio);
                }
            }
            if let (Some(db), Some(r), Some(rc), Some(rk)) =
                (rdb.as_ref().map(|d| &d.db), &req, &rsigner, &rkey)
            {
                let rsp = Responder {
                    db,
                    ca: &rca_list,
                    rcert: rc,
                    rkey: rk,
                    rmd: rsign_md.as_ref(),
                    sigopts: &rsign_sigopts,
                    rother: rother.as_ref(),
                    flags: std::ffi::c_ulong::from(rflags),
                    nmin,
                    ndays,
                    badsig,
                    resp_md: resp_certid_md.as_ref(),
                };
                resp = make_ocsp_response(&rsp, r);
                if resp.is_none() {
                    return 1;
                }
                if let (Some(c), Some(rs)) = (&cbio, &resp) {
                    send_ocsp_response(&prog, c, rs);
                }
            } else if let Some(h) = &host {
                let ctx = if use_ssl == 1 {
                    let c = SslCtx::new_client();
                    if c.is_none() {
                        eprintf!("Error creating SSL context.\n");
                        return 1;
                    }
                    c
                } else {
                    None
                };
                let post = Post {
                    host: h,
                    port: port.as_deref(),
                    path: Some(&path),
                    proxy: opt_proxy.as_deref(),
                    no_proxy: opt_no_proxy.as_deref(),
                    ssl_ctx: ctx.as_ref(),
                    headers: &headers,
                    content_type: "application/ocsp-request",
                    expected_content_type: "application/ocsp-response",
                    timeout: req_timeout,
                    prog: &prog,
                };
                let body = req.as_ref().and_then(OcspRequest::to_mem_bio);
                resp = app_http_post_asn1(&post, body, OcspResponse::read_der);
                if resp.is_none() {
                    eprintf!("Error querying OCSP responder\n");
                    return 1;
                }
            } else if let Some(ri) = &respin {
                let Some(derbio) = bio_open_default(Some(ri), 'r', format::ASN1) else {
                    return 1;
                };
                resp = OcspResponse::read_der(Some(&derbio));
                if resp.is_none() {
                    eprintf!("Error reading OCSP response\n");
                    return 1;
                }
            } else {
                return 0;
            }
        }

        // done_resp.
        let Some(rs) = &resp else {
            return 1;
        };
        if let Some(ro) = &respout {
            let Some(derbio) = bio_open_default(Some(ro), 'w', format::ASN1) else {
                return 1;
            };
            rs.write_der(&derbio);
        }
        let i = rs.status();
        if i != OCSP_RESPONSE_STATUS_SUCCESSFUL {
            let text = ocsp::response_status_str(i.into());
            let line = format!("Responder Error: {text} ({i})\n");
            write_out(out.as_ref(), &line);
            if !ignore_err {
                return 1;
            }
        }
        if resp_text && let Some(o) = &out {
            rs.print(o);
        }
        // A responder doesn't verify its own response.
        if cbio.is_some() {
            if accept_count != -1 {
                accept_count -= 1;
                if accept_count <= 0 {
                    return 0;
                }
            }
            cbio = None;
            req = None;
            continue;
        }
        break;
    }
    let out = out;
    if ridx_filename.is_some() {
        return 0;
    }
    if store.is_none() {
        store = setup_verify(
            ca_file.as_deref(),
            no_ca_file,
            ca_path.as_deref(),
            no_ca_path,
            ca_store.as_deref(),
            no_ca_store,
        );
    }
    let Some(store) = store else {
        return 1;
    };
    if vpmtouched {
        store.set1_param(&vpm);
    }
    let mut verify_other = None;
    if let Some(vc) = &verify_certfile {
        let (ok, c) = load_certs(Some(vc), false, None, None, Some("validator certificates"));
        if !ok {
            return 1;
        }
        verify_other = c;
    }
    let Some(rs) = &resp else {
        return 1;
    };
    let Some(bs) = rs.basic() else {
        eprintf!("Error parsing response\n");
        return 1;
    };
    let mut ret = 0;
    if !noverify {
        if let Some(r) = &req {
            let i = r.check_nonce(&bs);
            if i <= 0 {
                if i == -1 {
                    eprintf!("WARNING: no nonce in response\n");
                } else {
                    eprintf!("Nonce Verify error\n");
                    return 1;
                }
            }
        }
        let vf = std::ffi::c_ulong::from(verify_flags);
        let mut i = bs.verify(verify_other.as_ref(), &store, vf);
        if i <= 0
            && let Some(iss) = &issuers
        {
            let stack = CertStack::new();
            if let Some(st) = &stack {
                for c in iss {
                    st.push_ref(c);
                }
            }
            i = bs.verify(stack.as_ref(), &store, vf);
            if i > 0 {
                err::clear();
            }
        }
        if i <= 0 {
            eprintf!("Response Verify Failure\n");
            io::print_errors();
            ret = 1;
        } else {
            eprintf!("Response verify OK\n");
        }
    }
    if !print_ocsp_summary(
        out.as_ref(),
        &bs,
        req.as_ref(),
        &reqnames,
        &b.ids,
        nsec,
        maxage,
    ) {
        ret = 1;
    }
    ret
}

/// `BIO_printf(out, ...)` (with no output `BIO`, nothing).
fn write_out(out: Option<&Bio>, text: &str) {
    if let Some(o) = out {
        let _ = o.write_all(text.as_bytes());
    }
}

/// `send_ocsp_response`.
fn send_ocsp_response(prog: &str, cbio: &Bio, resp: &OcspResponse) -> bool {
    http_server_send_asn1_resp(
        prog,
        cbio,
        false,
        "application/ocsp-response",
        resp.der_len(),
        |b| resp.write_der(b),
    )
}

/// `print_ocsp_summary`.
fn print_ocsp_summary(
    out: Option<&Bio>,
    bs: &BasicResp,
    req: Option<&OcspRequest>,
    names: &[String],
    ids: &[CertId],
    nsec: i64,
    maxage: i64,
) -> bool {
    if req.is_none() || names.is_empty() {
        return true;
    }
    if ids.is_empty() {
        return false;
    }
    let Some(out) = out else {
        return true;
    };
    let mut ret = true;
    for (id, name) in ids.iter().zip(names.iter()) {
        let _ = out.write_all(format!("{name}: ").as_bytes());
        let Some(st) = bs.find_status(id) else {
            let _ = out.write_all(b"ERROR: No Status found.\n");
            ret = false;
            continue;
        };
        // Invalid times are reported here, so it's clear which status they refer to.
        if !ocsp::check_validity(st.thisupd, st.nextupd, nsec, maxage) {
            let _ = out.write_all(b"WARNING: Status times invalid.\n");
            rustyssl_ossl::err::print_errors(out);
        }
        let _ = out.write_all(format!("{}\n", ocsp::cert_status_str(st.status.into())).as_bytes());
        let _ = out.write_all(b"\tThis Update: ");
        if let Some(t) = st.thisupd {
            t.print(out);
        }
        let _ = out.write_all(b"\n");
        if let Some(n) = st.nextupd {
            let _ = out.write_all(b"\tNext Update: ");
            n.print(out);
            let _ = out.write_all(b"\n");
        }
        if st.status != V_OCSP_CERTSTATUS_REVOKED {
            continue;
        }
        if st.reason != -1 {
            let r = ocsp::crl_reason_str(st.reason.into());
            let _ = out.write_all(format!("\tReason: {r}\n").as_bytes());
        }
        let _ = out.write_all(b"\tRevocation Time: ");
        if let Some(t) = st.revtime {
            t.print(out);
        }
        let _ = out.write_all(b"\n");
    }
    ret
}

/// `make_ocsp_response`: `None` only when even the error response can't be made.
fn make_ocsp_response(r: &Responder<'_>, req: &OcspRequest) -> Option<OcspResponse> {
    let error = || OcspResponse::create(OCSP_RESPONSE_STATUS_INTERNALERROR, None);
    if req.onereq_count() <= 0 {
        return OcspResponse::create(OCSP_RESPONSE_STATUS_MALFORMEDREQUEST, None);
    }
    let Some(bs) = BasicResp::new() else {
        return error();
    };
    let thisupd = Time::now();
    let nextupd = if r.ndays != -1 {
        Time::adj(r.ndays, std::ffi::c_long::from(r.nmin) * 60)
    } else {
        None
    };
    for cid in req.ids() {
        let Some(cert_id_md) = cid.md() else {
            return error();
        };
        let mut found = false;
        let mut cid_resp_md = None;
        for ca_cert in r.ca {
            if found {
                break;
            }
            let Some(ca_id) = CertId::from_cert(Some(&cert_id_md), None, ca_cert) else {
                return error();
            };
            if ca_id.same_issuer(&cid) {
                found = true;
                if let Some(m) = r.resp_md {
                    cid_resp_md = CertId::from_cert(Some(m), None, ca_cert);
                }
            }
        }
        let inf = cid.serial_hex().and_then(|h| row_by_serial(r.db, &h));
        let id = cid_resp_md.as_ref().unwrap_or(&cid);
        let (this, next) = (thisupd.as_ref(), nextupd.as_ref());
        let Some(inf) = inf.filter(|_| found) else {
            bs.add_status(id, V_OCSP_CERTSTATUS_UNKNOWN, 0, None, this, next);
            continue;
        };
        let t = inf.get(field::TYPE).and_then(|t| t.bytes().next());
        if t == Some(b'V') {
            bs.add_status(id, V_OCSP_CERTSTATUS_GOOD, 0, None, this, next);
        } else if t == Some(b'R') {
            let rev = unpack_revinfo(inf.get(field::REV_DATE).map_or("", String::as_str));
            let Some(single) = bs.add_status(
                id,
                V_OCSP_CERTSTATUS_REVOKED,
                rev.reason,
                rev.revtm.as_ref(),
                this,
                next,
            ) else {
                return error();
            };
            if let Some(inv) = &rev.invtm {
                single.add_invalidity_date(inv);
            } else if let Some(inst) = &rev.inst {
                single.add_hold_instruction(inst);
            }
        }
    }
    bs.copy_nonce(req);
    let Some(mctx) = MdCtx::new() else {
        return error();
    };
    match mctx.sign_init_with(r.rmd, r.rkey, r.sigopts) {
        Ok(()) => {}
        Err(None) => return error(),
        Err(Some(opt)) => {
            eprintf!("parameter error \"{opt}\"\n");
            io::print_errors();
            return error();
        }
    }
    if !bs.sign_ctx(r.rcert, &mctx, r.rother, r.flags) {
        return OcspResponse::create(OCSP_RESPONSE_STATUS_INTERNALERROR, Some(&bs));
    }
    if r.badsig {
        bs.corrupt_signature();
    }
    OcspResponse::create(OCSP_RESPONSE_STATUS_SUCCESSFUL, Some(&bs))
}

/// What `unpack_revinfo` of `ca.c` makes of a revocation field.
#[derive(Default)]
struct RevInfo {
    revtm: Option<Time>,
    reason: i32,
    inst: Option<Object>,
    invtm: Option<Time>,
}

/// `crl_reasons` of `ca.c`.
const CRL_REASONS: &[&str] = &[
    "unspecified",
    "keyCompromise",
    "CACompromise",
    "affiliationChanged",
    "superseded",
    "cessationOfOperation",
    "certificateHold",
    "removeFromCRL",
    "holdInstruction",
    "keyTime",
    "CAkeyTime",
];

/// `unpack_revinfo` of `ca.c` (whose failures `ocsp` ignores, keeping what was parsed).
fn unpack_revinfo(s: &str) -> RevInfo {
    let mut r = RevInfo {
        reason: -1,
        ..RevInfo::default()
    };
    let mut parts = s.splitn(2, ',');
    let rtime = parts.next().unwrap_or_default();
    let rest = parts.next();
    let (reason_str, arg_str) = match rest {
        Some(rest) => match rest.split_once(',') {
            Some((a, b)) => (Some(a), Some(b)),
            None => (Some(rest), None),
        },
        None => (None, None),
    };
    match Time::utc_from_string_kept(rtime) {
        Ok(t) => r.revtm = Some(t),
        Err(None) => {
            eprintf!("memory allocation failure\n");
            return r;
        }
        Err(Some(t)) => {
            eprintf!("invalid revocation date {rtime}\n");
            r.revtm = Some(t);
            return r;
        }
    }
    let Some(reason_str) = reason_str else {
        return r;
    };
    let mut code = CRL_REASONS
        .iter()
        .position(|c| c.eq_ignore_ascii_case(reason_str))
        .and_then(|i| i32::try_from(i).ok())
        .unwrap_or(-1);
    if code == OCSP_REVOKED_STATUS_NOSTATUS {
        eprintf!("invalid reason code {reason_str}\n");
        return r;
    }
    if code == 7 {
        code = OCSP_REVOKED_STATUS_REMOVEFROMCRL;
    } else if code == 8 {
        let Some(arg) = arg_str else {
            eprintf!("missing hold instruction\n");
            return r;
        };
        code = OCSP_REVOKED_STATUS_CERTIFICATEHOLD;
        match Object::from_txt(arg, false) {
            Some(o) => r.inst = Some(o),
            None => {
                eprintf!("invalid object identifier {arg}\n");
                return r;
            }
        }
    } else if code == 9 || code == 10 {
        let Some(arg) = arg_str else {
            eprintf!("missing compromised time\n");
            return r;
        };
        match Time::generalized_from_string(arg) {
            Ok(t) => r.invtm = Some(t),
            Err(true) => {
                eprintf!("memory allocation failure\n");
                return r;
            }
            Err(false) => {
                eprintf!("invalid compromised time {arg}\n");
                return r;
            }
        }
        code = if code == 9 {
            OCSP_REVOKED_STATUS_KEYCOMPROMISE
        } else {
            OCSP_REVOKED_STATUS_CACOMPROMISE
        };
    }
    r.reason = code;
    r
}

/// `TXT_DB_get_by_index(db, DB_serial, row)` with the serial `hex`: the row's fields.
fn row_by_serial(db: &TxtDb, hex: &str) -> Option<Vec<String>> {
    let mut key = [None; field::NUMBER];
    if let Some(k) = key.get_mut(field::SERIAL) {
        *k = Some(hex);
    }
    let r = db.get_by_index(field::SERIAL, &key)?;
    Some(
        (0..field::NUMBER)
            .map(|f| db.field_str(r, f).unwrap_or_default())
            .collect(),
    )
}
