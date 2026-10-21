//! `openssl ts` (`apps/ts.c`).
//!
//! It also holds two helpers of `apps.c` that F0 left out, `load_cert_certs` and
//! `load_certs_multifile` (with `warn_cert`), which `cmp` uses too.

use std::io::Write;

use rustyssl_ossl::abi::{
    TS_VFY_DATA, TS_VFY_IMPRINT, TS_VFY_SIGNATURE, TS_VFY_SIGNER, TS_VFY_VERSION,
};
use rustyssl_ossl::conf::Conf;
use rustyssl_ossl::evp::Md;
use rustyssl_ossl::object::Object;
use rustyssl_ossl::pkcs7::Pkcs7;
use rustyssl_ossl::ts::{self, ResponseInputs, TsReq, TsResp, TsVerifyCtx};
use rustyssl_ossl::verify::{FileType, LookupKind, VerifyParam};
use rustyssl_ossl::x509::Store;
use rustyssl_ossl::{Bio, crypto};

use crate::generated::options::ts::{OPTIONS, Opt};
use crate::lib::apps::load_certs_multifile;
use crate::lib::apps::{
    ConfigFile, add_oid_section, app_conf_try_string, app_load_config, app_load_modules,
    app_passwd, bio_open_default,
};
use crate::lib::opt::{self, Parser, eprintf, format};
use crate::lib::{app_libctx, app_rand, io};

/// The request nonce's length, in bits (a multiple of 8).
const NONCE_LENGTH: usize = 64;

/// The configuration entry naming the OID file.
const ENV_OID_FILE: &str = "oid_file";

/// `opt_helplist`: printed after the options by `-help`.
const OPT_HELPLIST: &[&str] = &[
    "",
    "Typical uses:",
    " openssl ts -query [-rand file...] [-config file] [-data file]",
    "    [-digest hexstring] [-tspolicy oid] [-no_nonce] [-cert]",
    "    [-in file] [-out file] [-text]",
    "",
    " openssl ts -reply [-config file] [-section tsa_section]",
    "    [-queryfile file] [-passin password]",
    "    [-signer tsa_cert.pem] [-inkey private_key.pem]",
    "    [-chain certs_file.pem] [-tspolicy oid]",
    "    [-in file] [-token_in] [-out file] [-token_out]",
    "    [-text] [-engine id]",
    "",
    " openssl ts -verify -CApath dir -CAfile root-cert.pem -CAstore uri",
    "   -untrusted extra-certs.pem [-data file] [-digest hexstring]",
    "    [-queryfile request.tsq] -in response.tsr [-token_in] ...",
];

/// `%s` of `BIO_printf`, which prints NULL as `<NULL>`.
fn s(v: Option<&str>) -> &str {
    v.unwrap_or("<NULL>")
}

/// The three modes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Query,
    Reply,
    Verify,
}

pub fn main(argv: &[String]) -> i32 {
    let Some(vpm) = VerifyParam::new() else {
        return 1;
    };
    let mut p = Parser::with_unknown(argv, OPTIONS, Some("digest"));
    let prog = p.prog();
    let opthelp = |prog: &str| {
        eprintf!("{prog}: Use -help for summary.\n");
        1
    };
    let (mut ca_file, mut untrusted) = (None::<String>, None::<String>);
    let mut configfile = ConfigFile::Default;
    let (mut engine, mut section, mut digestname) = (None::<String>, None::<String>, None);
    let (mut data, mut digest, mut policy) = (None::<String>, None::<String>, None::<String>);
    let (mut input, mut out, mut queryfile, mut passin) = (
        None::<String>,
        None::<String>,
        None::<String>,
        None::<String>,
    );
    let (mut inkey, mut signer, mut chain, mut ca_path) = (
        None::<String>,
        None::<String>,
        None::<String>,
        None::<String>,
    );
    let mut ca_store = None::<String>;
    let mut mode: Option<Mode> = None;
    let (mut no_nonce, mut cert, mut text, mut vpmtouched) = (false, false, false, false);
    let (mut token_in, mut token_out) = (false, false);
    loop {
        let o = p.next();
        match o {
            Opt::EOF => break,
            Opt::ERR => return opthelp(&prog),
            Opt::HELP => {
                opt::help(OPTIONS);
                for l in OPT_HELPLIST {
                    eprintf!("{l}\n");
                }
                return 0;
            }
            Opt::CONFIG => configfile = ConfigFile::Given(p.arg().to_owned()),
            Opt::SECTION => section = Some(p.arg().to_owned()),
            Opt::QUERY | Opt::REPLY | Opt::VERIFY => {
                if mode.is_some() {
                    eprintf!("{prog}: Must give only one of -query, -reply, or -verify\n");
                    return opthelp(&prog);
                }
                mode = Some(match o {
                    Opt::QUERY => Mode::Query,
                    Opt::REPLY => Mode::Reply,
                    _ => Mode::Verify,
                });
            }
            Opt::DATA => data = Some(p.arg().to_owned()),
            Opt::DIGEST => digest = Some(p.arg().to_owned()),
            Opt::OPT_R(r) => {
                if !app_rand::opt_rand(r, p.arg()) {
                    return 1;
                }
            }
            Opt::OPT_PROV(r) => {
                if !app_libctx::opt_provider(r, p.arg()) {
                    return 1;
                }
            }
            Opt::TSPOLICY => policy = Some(p.arg().to_owned()),
            Opt::NO_NONCE => no_nonce = true,
            Opt::CERT => cert = true,
            Opt::IN => input = Some(p.arg().to_owned()),
            Opt::TOKEN_IN => token_in = true,
            Opt::OUT => out = Some(p.arg().to_owned()),
            Opt::TOKEN_OUT => token_out = true,
            Opt::TEXT => text = true,
            Opt::QUERYFILE => queryfile = Some(p.arg().to_owned()),
            Opt::PASSIN => passin = Some(p.arg().to_owned()),
            Opt::INKEY => inkey = Some(p.arg().to_owned()),
            Opt::SIGNER => signer = Some(p.arg().to_owned()),
            Opt::CHAIN => chain = Some(p.arg().to_owned()),
            Opt::CAPATH => ca_path = Some(p.arg().to_owned()),
            Opt::CAFILE => ca_file = Some(p.arg().to_owned()),
            Opt::CASTORE => ca_store = Some(p.arg().to_owned()),
            Opt::UNTRUSTED => untrusted = Some(p.arg().to_owned()),
            Opt::ENGINE => engine = Some(p.arg().to_owned()),
            Opt::MD => digestname = p.unknown().map(str::to_owned),
            Opt::OPT_V(v) => {
                if !opt::verify(v, p.arg(), (&vpm).into()) {
                    return 1;
                }
                vpmtouched = true;
            }
        }
    }
    if !p.check_rest_arg(None) {
        return opthelp(&prog);
    }
    let Some(mode) = mode else {
        eprintf!("{prog}: Must give one of -query, -reply, or -verify\n");
        return opthelp(&prog);
    };
    if !app_rand::load() {
        return 1;
    }
    let mut md = None;
    if let Some(d) = &digestname {
        match opt::md(d) {
            Some(m) => md = Some(m),
            None => return opthelp(&prog),
        }
    }
    let mut password = None;
    if mode == Mode::Reply && passin.is_some() {
        match app_passwd(passin.as_deref(), None) {
            Some((p, _)) => password = p,
            None => {
                eprintf!("Error getting password.\n");
                return 1;
            }
        }
    }
    let Some(conf) = load_config_file(configfile.name().as_deref()) else {
        return 1;
    };
    if configfile != ConfigFile::Default && !app_load_modules(Some(&conf)) {
        return 1;
    }
    let ok = match mode {
        Mode::Query => {
            if vpmtouched || (data.is_some() && digest.is_some()) {
                return opthelp(&prog);
            }
            let q = Query {
                data: data.as_deref(),
                digest: digest.as_deref(),
                md: md.as_ref(),
                policy: policy.as_deref(),
                no_nonce,
                cert,
            };
            query_command(&q, input.as_deref(), out.as_deref(), text)
        }
        Mode::Reply => {
            if vpmtouched || (input.is_some() && queryfile.is_some()) {
                return opthelp(&prog);
            }
            if input.is_none() && (token_in || queryfile.is_none()) {
                return opthelp(&prog);
            }
            let r = ResponseInputs {
                section: section.as_deref(),
                engine: engine.as_deref(),
                queryfile: queryfile.as_deref(),
                passin: password.as_ref().map(|p| p.as_str()),
                inkey: inkey.as_deref(),
                md: md.as_ref(),
                signer: signer.as_deref(),
                chain: chain.as_deref(),
                policy: policy.as_deref(),
            };
            reply_command(
                &conf,
                &r,
                input.as_deref(),
                token_in,
                out.as_deref(),
                token_out,
                text,
            )
        }
        Mode::Verify => {
            let given = [queryfile.is_some(), data.is_some(), digest.is_some()];
            if input.is_none() || given.iter().filter(|&&g| g).count() != 1 {
                return opthelp(&prog);
            }
            let v = VerifyInputs {
                data: data.as_deref(),
                digest: digest.as_deref(),
                queryfile: queryfile.as_deref(),
                ca_path: ca_path.as_deref(),
                ca_file: ca_file.as_deref(),
                ca_store: ca_store.as_deref(),
                untrusted: untrusted.as_deref(),
                vpm: vpmtouched.then_some(&vpm),
            };
            verify_command(&v, input.as_deref().unwrap_or_default(), token_in)
        }
    };
    i32::from(!ok)
}

/// `txt2obj`.
fn txt2obj(oid: &str) -> Option<Object> {
    let o = Object::from_txt(oid, false);
    if o.is_none() {
        eprintf!("cannot convert {oid} to OID\n");
    }
    o
}

/// `load_config_file`: the configuration, its OID file, and its OID section.
fn load_config_file(configfile: Option<&str>) -> Option<Conf> {
    let conf = app_load_config(configfile)?;
    eprintf!("Using configuration from {}\n", s(configfile));
    if let Some(p) = app_conf_try_string(&conf, None, ENV_OID_FILE) {
        match Bio::new_file(&p, "r") {
            None => io::print_errors(),
            Some(b) => {
                ts::create_objects(&b);
            }
        }
    }
    if !add_oid_section(&conf) {
        io::print_errors();
    }
    Some(conf)
}

/// What `-query` makes a request of.
struct Query<'a> {
    data: Option<&'a str>,
    digest: Option<&'a str>,
    md: Option<&'a Md>,
    policy: Option<&'a str>,
    no_nonce: bool,
    cert: bool,
}

/// `query_command`.
fn query_command(q: &Query<'_>, input: Option<&str>, out: Option<&str>, text: bool) -> bool {
    let r = (|| {
        let query = if let Some(i) = input {
            let in_bio = bio_open_default(Some(i), 'r', format::ASN1)?;
            TsReq::read_der(&in_bio)
        } else {
            let data_bio = match q.digest {
                None => Some(bio_open_default(q.data, 'r', format::ASN1)?),
                Some(_) => None,
            };
            create_query(data_bio.as_ref(), q)
        };
        let query = query?;
        if text {
            let out_bio = bio_open_default(out, 'w', format::TEXT)?;
            query.print(&out_bio).then_some(())
        } else {
            let out_bio = bio_open_default(out, 'w', format::ASN1)?;
            query.write_der(&out_bio).then_some(())
        }
    })();
    io::print_errors();
    r.is_some()
}

/// `create_query`.
fn create_query(data_bio: Option<&Bio>, q: &Query<'_>) -> Option<TsReq> {
    let r = (|| {
        let default_md;
        let md = match q.md {
            Some(m) => m,
            None => {
                default_md = Md::by_name("sha256")?;
                &default_md
            }
        };
        let imprint = create_digest(data_bio, q.digest, md)?;
        let policy = match q.policy {
            Some(p) => Some(txt2obj(p)?),
            None => None,
        };
        let nonce = if q.no_nonce {
            None
        } else {
            Some(create_nonce(NONCE_LENGTH)?)
        };
        TsReq::create(md, &imprint, policy.as_ref(), nonce.as_deref(), q.cert)
    })();
    if r.is_none() {
        eprintf!("could not create query\n");
        io::print_errors();
    }
    r
}

/// `create_digest`: the data's digest, or the one given in hex (which must be the digest's
/// size).
fn create_digest(input: Option<&Bio>, digest: Option<&str>, md: &Md) -> Option<Vec<u8>> {
    let size = ts::md_size(md);
    if size <= 0 {
        return None;
    }
    match input {
        Some(i) => ts::digest_bio(md, i),
        None => {
            let d = crypto::hexstr2buf(digest.unwrap_or_default());
            match d {
                Some(d) if usize::try_from(size).is_ok_and(|n| n == d.len()) => Some(d),
                _ => {
                    eprintf!("bad digest, {size} bytes must be specified\n");
                    None
                }
            }
        }
    }
}

/// `create_nonce`: random content octets, with leading zeroes dropped.
fn create_nonce(bits: usize) -> Option<Vec<u8>> {
    let len = (bits - 1) / 8 + 1;
    let Some(buf) = (len <= 20).then(|| ts::rand_bytes(len)).flatten() else {
        eprintf!("could not create nonce\n");
        return None;
    };
    let first = buf.iter().position(|&b| b != 0).unwrap_or(len);
    Some(buf.get(first..).unwrap_or_default().to_vec())
}

/// `reply_command`.
fn reply_command(
    conf: &Conf,
    r: &ResponseInputs<'_>,
    input: Option<&str>,
    token_in: bool,
    out: Option<&str>,
    token_out: bool,
    text: bool,
) -> bool {
    let ok = (|| {
        let response = if let Some(i) = input {
            let in_bio = Bio::new_file(i, "rb")?;
            if token_in {
                TsResp::read_token(&in_bio)
            } else {
                TsResp::read_der(&in_bio)
            }
        } else {
            let resp = TsResp::create(conf, r);
            if resp.is_some() {
                eprintf!("Response has been generated.\n");
            } else {
                eprintf!("Response is not generated.\n");
            }
            resp
        };
        let response = response?;
        if text {
            let out_bio = bio_open_default(out, 'w', format::TEXT)?;
            let ok = if token_out {
                response.print_tst_info(&out_bio)
            } else {
                response.print(&out_bio)
            };
            ok.then_some(())
        } else {
            let out_bio = bio_open_default(out, 'w', format::ASN1)?;
            let ok = if token_out {
                response.write_token_der(&out_bio)
            } else {
                response.write_der(&out_bio)
            };
            ok.then_some(())
        }
    })();
    io::print_errors();
    ok.is_some()
}

/// What `-verify` checks against.
struct VerifyInputs<'a> {
    data: Option<&'a str>,
    digest: Option<&'a str>,
    queryfile: Option<&'a str>,
    ca_path: Option<&'a str>,
    ca_file: Option<&'a str>,
    ca_store: Option<&'a str>,
    untrusted: Option<&'a str>,
    vpm: Option<&'a VerifyParam>,
}

/// `verify_command`.
fn verify_command(v: &VerifyInputs<'_>, input: &str, token_in: bool) -> bool {
    let ret = (|| {
        let in_bio = Bio::new_file(input, "rb")?;
        let (token, response) = if token_in {
            (Some(Pkcs7::read_der(&in_bio)?), None)
        } else {
            (None, Some(TsResp::read_der(&in_bio)?))
        };
        let ctx = create_verify_ctx(v)?;
        Some(match (&token, &response) {
            (Some(t), _) => ctx.verify_token(t),
            (_, Some(r)) => ctx.verify_response(r),
            _ => false,
        })
    })()
    .unwrap_or(false);
    let _ = io::out().write_all(b"Verification: ");
    if ret {
        let _ = io::out().write_all(b"OK\n");
    } else {
        let _ = io::out().write_all(b"FAILED\n");
        io::print_errors();
    }
    ret
}

/// `create_verify_ctx`.
fn create_verify_ctx(v: &VerifyInputs<'_>) -> Option<TsVerifyCtx> {
    let flag = |f: u32| i32::try_from(f).unwrap_or(0);
    let mut f = 0;
    let ctx = if v.data.is_some() || v.digest.is_some() {
        let ctx = TsVerifyCtx::new()?;
        f = flag(TS_VFY_VERSION | TS_VFY_SIGNER);
        if let Some(d) = v.data {
            f |= flag(TS_VFY_DATA);
            let out = Bio::new_file(d, "rb")?;
            if !ctx.set0_data(out) {
                return None;
            }
        } else if let Some(d) = v.digest {
            f |= flag(TS_VFY_IMPRINT);
            if !ctx.set0_imprint_hex(d) {
                eprintf!("invalid digest string\n");
                return None;
            }
        }
        ctx
    } else {
        let input = Bio::new_file(v.queryfile?, "rb")?;
        let request = TsReq::read_der(&input)?;
        TsVerifyCtx::from_req(&request)?
    };
    // The signature verification flag and its arguments.
    ctx.add_flags(f | flag(TS_VFY_SIGNATURE));
    if !ctx.set0_store(create_cert_store(v.ca_path, v.ca_file, v.ca_store, v.vpm)) {
        return None;
    }
    if let Some(u) = v.untrusted {
        let certs = load_certs_multifile(u, None, Some("extra untrusted certs"), v.vpm)?;
        if !ctx.set0_certs(certs) {
            return None;
        }
    }
    Some(ctx)
}

/// `create_cert_store`.
fn create_cert_store(
    ca_path: Option<&str>,
    ca_file: Option<&str>,
    ca_store: Option<&str>,
    vpm: Option<&VerifyParam>,
) -> Option<Store> {
    let lc = app_libctx::libctx();
    let pq = app_libctx::propq();
    let Some(cert_ctx) = Store::new() else {
        eprintf!("memory allocation failure\n");
        return None;
    };
    cert_ctx.set_passthrough_verify_cb();
    if let Some(p) = ca_path {
        let Some(lookup) = cert_ctx.add_lookup(LookupKind::HashDir) else {
            eprintf!("memory allocation failure\n");
            return None;
        };
        if lookup.add_dir(Some(p), FileType::Pem) <= 0 {
            eprintf!("Error loading directory {p}\n");
            return None;
        }
    }
    if let Some(f) = ca_file {
        let Some(lookup) = cert_ctx.add_lookup(LookupKind::File) else {
            eprintf!("memory allocation failure\n");
            return None;
        };
        if lookup.load_file_ex(Some(f), FileType::Pem, lc.as_deref(), pq.as_deref()) <= 0 {
            eprintf!("Error loading file {f}\n");
            return None;
        }
    }
    if let Some(st) = ca_store {
        let Some(lookup) = cert_ctx.add_lookup(LookupKind::Store) else {
            eprintf!("memory allocation failure\n");
            return None;
        };
        if lookup.add_store_ex(Some(st), lc.as_deref(), pq.as_deref()) <= 0 {
            eprintf!("Error loading store URI {st}\n");
            return None;
        }
    }
    if let Some(v) = vpm {
        cert_ctx.set1_param(v);
    }
    Some(cert_ctx)
}
