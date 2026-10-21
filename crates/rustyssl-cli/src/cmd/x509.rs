//! `openssl x509` (`apps/x509.c`), with `apps.c`'s `set_cert_times` and
//! `check_cert_attributes`, which `req` and `ca` share.

use std::ffi::c_ulong;
use std::io::{IsTerminal, Write};

use rustyssl_ossl::Bio;
use rustyssl_ossl::abi::{
    ASN1_DTFLGS_RFC822, MBSTRING_ASC, NID_authority_key_identifier, NID_subject_key_identifier,
    X509_FLAG_COMPAT, X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, X509_V_FLAG_CHECK_SS_SIGNATURE,
    X509V3_CTX_REPLACE,
};
use rustyssl_ossl::evp::Md;
use rustyssl_ossl::pkey::Pkey;
use rustyssl_ossl::verify::{self, StoreCtxRef, VerifyCtx};
use rustyssl_ossl::x509::{self, Cert, CertStack, Integer, Name, Obj, Req, Store, V3Ctx};

use crate::generated::options::x509::{OPTIONS, Opt};
use crate::lib::app_libctx::{libctx, opt_provider, propq};
use crate::lib::app_rand;
use crate::lib::apps::{
    ExtCopy, app_conf_try_string, app_load_config, app_passwd, atoi, bio_open_default,
    cert_matches_key, copy_extensions, do_x509_req_sign, do_x509_req_verify, do_x509_sign,
    get_nameopt, load_cert_pass, load_certs, load_csr_autofmt, load_key, load_pubkey, parse_name,
    print_name, set_cert_ex, set_dateopt, set_ext_copy, set_nameopt,
};
use crate::lib::apps::{check_cert_attributes, set_cert_times};
use crate::lib::ca_db::{load_serial, rand_serial, save_serial};
use crate::lib::engine::setup_engine;
use crate::lib::io;
use crate::lib::opt::{self, Parser, eprintf, fmt_flags, format};

/// `POSTFIX`: the default serial file's suffix.
const POSTFIX: &str = ".srl";
/// `DEFAULT_DAYS`.
const DEFAULT_DAYS: i32 = 30;
/// `UNSET_DAYS`.
const UNSET_DAYS: i32 = -2;

/// The C `int` flag constants as `unsigned long`.
fn ul(v: core::ffi::c_int) -> c_ulong {
    c_ulong::try_from(v).unwrap_or(0)
}

/// A failure: `goto err` (the error queue printed, exit status 1).
struct Fail;

pub fn main(argv: &[String]) -> i32 {
    match run(argv) {
        Ok(ret) => ret,
        Err(Fail) => {
            io::print_errors();
            1
        }
    }
}

/// `-fingerprint`'s line.
fn fingerprint_line(name: &str, md: &[u8]) -> String {
    let mut s = format!("{name} Fingerprint=");
    for (j, b) in md.iter().enumerate() {
        let sep = if j + 1 == md.len() { '\n' } else { ':' };
        s.push_str(&format!("{b:02X}{sep}"));
    }
    s
}

/// `warn_copying`.
fn warn_copying(nid: core::ffi::c_int, names: Option<&str>) {
    let sn = x509::nid2sn(nid).unwrap_or_default();
    if names.is_some_and(|n| n.contains(&sn)) {
        eprintf!("Warning: -ext should not specify copying {sn} extension to CSR; ignoring this\n");
    }
}

/// `x509_to_req`: a request of the certificate, with its extensions but the key identifiers
/// (copied only when `ext_copy` says so).
fn x509_to_req(cert: &Cert, ext_copy: Option<ExtCopy>, names: Option<&str>) -> Option<Req> {
    let req = cert.to_req()?;
    warn_copying(NID_subject_key_identifier, names);
    warn_copying(NID_authority_key_identifier, names);
    let exts: Vec<_> = cert
        .extensions()
        .into_iter()
        .filter(|e| {
            let n = e.nid();
            n != NID_subject_key_identifier && n != NID_authority_key_identifier
        })
        .collect();
    if !exts.is_empty()
        && !matches!(ext_copy, None | Some(ExtCopy::None))
        && !req.add_extensions(&exts)
    {
        eprintf!("Error copying extensions from certificate\n");
        return None;
    }
    Some(req)
}

/// `self_signed`: whether the certificate verifies as self-signed with `store`.
fn self_signed(store: &Store, cert: &Cert) -> bool {
    match VerifyCtx::new(store, Some(cert), None) {
        Err(_) => {
            eprintf!("Error initialising X509 store\n");
            false
        }
        Ok(mut xsc) => {
            xsc.set_flags(ul(X509_V_FLAG_CHECK_SS_SIGNATURE));
            xsc.verify_cert() > 0
        }
    }
}

/// `callb`: a self-signed certificate is fine; other errors are reported, not fatal.
fn callb(ok: core::ffi::c_int, ctx: StoreCtxRef<'_>) -> core::ffi::c_int {
    let e = ctx.error();
    if e == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT {
        return 1;
    }
    if ok == 0 {
        if let Some(b) = io::bio_err() {
            let name = ctx.current_cert().map(|c| c.subject_name());
            if let Some(n) = name {
                print_name(b, Some("subject="), n);
            }
        }
        eprintf!(
            "Error with certificate - error {e} at depth {}\n{}\n",
            ctx.error_depth(),
            verify::verify_cert_error_string(e.into())
        );
    }
    1
}

/// `x509_load_serial`: the next serial number from the CA's serial file.
fn x509_load_serial(ca_file: &str, serialfile: Option<&str>, create: bool) -> Option<Integer> {
    let (serialfile, defaultfile) = match serialfile {
        Some(s) => (s.to_owned(), false),
        None => {
            let stem = match ca_file.rfind('.') {
                Some(i) => ca_file.get(..i).unwrap_or(ca_file),
                None => ca_file,
            };
            (format!("{stem}{POSTFIX}"), true)
        }
    };
    let (serial, file_exists) = load_serial(&serialfile, create || defaultfile);
    let (serial, _) = serial?;
    if !serial.add_word(1) {
        eprintf!("Serial number increment failure\n");
        return None;
    }
    if file_exists || create {
        save_serial(&serialfile, None, &serial)
    } else {
        Integer::from_bn(&serial)
    }
}

/// `purpose_print`.
fn purpose_print(out: &mut &Bio, cert: &Cert, id: core::ffi::c_int, pname: &str) {
    for i in 0..2 {
        let idret = cert.check_purpose(id, i);
        let ca = if i != 0 { " CA" } else { "" };
        let _ = write!(out, "{pname}{ca} : ");
        let _ = match idret {
            1 => writeln!(out, "Yes"),
            0 => writeln!(out, "No"),
            _ => writeln!(out, "Yes (WARNING code={idret})"),
        };
    }
}

/// `print_x509v3_exts`: the certificate's extensions named in the comma-separated `names`.
fn print_x509v3_exts(bio: &Bio, x: &Cert, ext_names: &str) -> bool {
    let mut out = bio;
    let exts = x.extensions();
    if exts.is_empty() {
        eprintf!("No extensions in certificate\n");
        return true;
    }
    let names: Vec<&str> = ext_names.split(',').filter(|n| !n.is_empty()).collect();
    if names.is_empty() {
        let _ = writeln!(out, "Invalid extension names: {ext_names}");
        return false;
    }
    let mut chosen = Vec::new();
    for ext in exts {
        let Some(sn) = ext.sn().filter(|s| s != "UNDEF") else {
            continue;
        };
        for n in &names {
            if sn == *n {
                chosen.push(ext);
            }
        }
    }
    if chosen.is_empty() {
        let _ = writeln!(out, "No extensions matched with {ext_names}");
        return true;
    }
    x509::extensions_print(bio, &chosen, 0, 0) == 1
}

#[allow(clippy::too_many_lines)]
fn run(argv: &[String]) -> Result<i32, Fail> {
    let ctx = Store::new().ok_or(Fail)?;
    ctx.set_verify_cb(callb);

    let mut p = Parser::with_unknown(argv, OPTIONS, Some("digest"));
    let prog = p.prog();
    let mut sno: Option<Integer> = None;
    let mut ext_copy: Option<ExtCopy> = None;
    let mut newcert = false;
    let (mut issu, mut subj, mut digest): (Option<String>, Option<String>, Option<String>) =
        (None, None, None);
    let mut trust: Vec<Obj> = Vec::new();
    let mut reject: Vec<Obj> = Vec::new();
    let (mut sigopts, mut vfyopts): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    let (mut ca_keyfile, mut ca_serial, mut pubkeyfile, mut alias): (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = (None, None, None, None);
    let (mut checkhost, mut checkemail, mut checkip): (
        Option<String>,
        Option<String>,
        Option<String>,
    ) = (None, None, None);
    let mut ext_names: Option<String> = None;
    let (mut extsect, mut extfile, mut passinarg): (
        Option<String>,
        Option<String>,
        Option<String>,
    ) = (None, None, None);
    let (mut infile, mut outfile, mut privkeyfile, mut ca_file): (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = (None, None, None, None);
    let (mut not_before, mut not_after): (Option<String>, Option<String>) = (None, None);
    let mut days = UNSET_DAYS;
    let (mut x509toreq, mut modulus, mut multi, mut print_pubkey, mut pprint) =
        (false, 0, false, 0, 0);
    let (mut ca_format, mut ca_keyformat) = (format::UNDEF, format::UNDEF);
    let mut dateopt: c_ulong = ASN1_DTFLGS_RFC822;
    let (mut fingerprint, mut reqfile, mut checkend) = (0, false, false);
    let (mut informat, mut outformat, mut keyformat) = (format::UNDEF, format::PEM, format::UNDEF);
    let (mut next_serial, mut subject_hash, mut issuer_hash, mut ocspid) = (0, 0, 0, 0);
    let (mut noout, mut ca_createserial, mut email) = (0, false, 0);
    let (mut ocsp_uri, mut trustout, mut clrtrust, mut clrreject, mut aliasout) =
        (0, false, 0, 0, 0);
    let (mut num, mut badsig, mut clrext, mut nocert) = (0, false, false, false);
    let (mut text, mut serial, mut subject, mut issuer, mut startdate, mut ext) =
        (0, 0, 0, 0, 0, 0);
    let mut enddate = 0;
    let mut checkoffset: i64 = 0;
    let mut certflag: c_ulong = 0;
    let mut preserve_dates = false;
    let mut engine = None;
    let (mut subject_hash_old, mut issuer_hash_old) = (0, 0);
    let opthelp = || {
        eprintf!("{prog}: Use -help for summary.\n");
        Fail
    };
    macro_rules! next {
        ($v:ident) => {{
            num += 1;
            $v = num;
        }};
    }
    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::ERR => return Err(opthelp()),
            Opt::HELP => {
                opt::help(OPTIONS);
                return Ok(0);
            }
            Opt::INFORM => match opt::parse_format(p.arg(), fmt_flags::PEMDER) {
                Some(f) => informat = f,
                None => return Err(opthelp()),
            },
            Opt::IN => infile = Some(p.arg().to_owned()),
            Opt::OUTFORM => match opt::parse_format(p.arg(), fmt_flags::ANY) {
                Some(f) => outformat = f,
                None => return Err(opthelp()),
            },
            Opt::KEYFORM => match opt::parse_format(p.arg(), fmt_flags::ANY) {
                Some(f) => keyformat = f,
                None => return Err(opthelp()),
            },
            Opt::CAFORM => match opt::parse_format(p.arg(), fmt_flags::ANY) {
                Some(f) => ca_format = f,
                None => return Err(opthelp()),
            },
            Opt::CAKEYFORM => match opt::parse_format(p.arg(), fmt_flags::ANY) {
                Some(f) => ca_keyformat = f,
                None => return Err(opthelp()),
            },
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::REQ => reqfile = true,
            Opt::DATEOPT => {
                if !set_dateopt(&mut dateopt, p.arg()) {
                    eprintf!("Invalid date format: {}\n", p.arg());
                    return Err(Fail);
                }
            }
            Opt::COPY_EXTENSIONS => match set_ext_copy(p.arg()) {
                Some(c) => ext_copy = Some(c),
                None => {
                    eprintf!("Invalid extension copy option: {}\n", p.arg());
                    return Err(Fail);
                }
            },
            Opt::SIGOPT => sigopts.push(p.arg().to_owned()),
            Opt::VFYOPT => vfyopts.push(p.arg().to_owned()),
            Opt::NOT_BEFORE => not_before = Some(p.arg().to_owned()),
            Opt::NOT_AFTER => not_after = Some(p.arg().to_owned()),
            Opt::DAYS => {
                days = atoi(p.arg());
                if days <= UNSET_DAYS {
                    eprintf!("{prog}: -days parameter arg must be >= -1\n");
                    return Err(Fail);
                }
            }
            Opt::PASSIN => passinarg = Some(p.arg().to_owned()),
            Opt::EXTFILE => extfile = Some(p.arg().to_owned()),
            Opt::OPT_R(o) => {
                if !app_rand::opt_rand(o, p.arg()) {
                    return Ok(1);
                }
            }
            Opt::OPT_PROV(o) => {
                if !opt_provider(o, p.arg()) {
                    return Ok(1);
                }
            }
            Opt::EXTENSIONS => extsect = Some(p.arg().to_owned()),
            Opt::KEY | Opt::SIGNKEY => privkeyfile = Some(p.arg().to_owned()),
            Opt::CA => ca_file = Some(p.arg().to_owned()),
            Opt::CAKEY => ca_keyfile = Some(p.arg().to_owned()),
            Opt::CASERIAL => ca_serial = Some(p.arg().to_owned()),
            Opt::SET_SERIAL => {
                if sno.is_some() {
                    eprintf!("Serial number supplied twice\n");
                    return Err(opthelp());
                }
                sno = Integer::from_dec_or_hex(p.arg());
                if sno.is_none() {
                    return Err(opthelp());
                }
            }
            Opt::NEW => newcert = true,
            Opt::FORCE_PUBKEY => pubkeyfile = Some(p.arg().to_owned()),
            Opt::ISSU => issu = Some(p.arg().to_owned()),
            Opt::SUBJ => subj = Some(p.arg().to_owned()),
            Opt::ADDTRUST => {
                let Some(o) = Obj::from_txt(p.arg(), false) else {
                    eprintf!("{prog}: Invalid trust object value {}\n", p.arg());
                    return Err(opthelp());
                };
                trust.push(o);
                trustout = true;
            }
            Opt::ADDREJECT => {
                let Some(o) = Obj::from_txt(p.arg(), false) else {
                    eprintf!("{prog}: Invalid reject object value {}\n", p.arg());
                    return Err(opthelp());
                };
                reject.push(o);
                trustout = true;
            }
            Opt::SETALIAS => {
                alias = Some(p.arg().to_owned());
                trustout = true;
            }
            Opt::CERTOPT => {
                if !set_cert_ex(&mut certflag, Some(p.arg())) {
                    return Err(opthelp());
                }
            }
            Opt::NAMEOPT => {
                if !set_nameopt(Some(p.arg())) {
                    return Err(opthelp());
                }
            }
            Opt::ENGINE => engine = setup_engine(Some(p.arg()), false),
            Opt::EMAIL => next!(email),
            Opt::OCSP_URI => next!(ocsp_uri),
            Opt::SERIAL => next!(serial),
            Opt::NEXT_SERIAL => next!(next_serial),
            Opt::MODULUS => next!(modulus),
            Opt::MULTI => multi = true,
            Opt::PUBKEY => next!(print_pubkey),
            Opt::X509TOREQ => x509toreq = true,
            Opt::TEXT => next!(text),
            Opt::SUBJECT => next!(subject),
            Opt::ISSUER => next!(issuer),
            Opt::FINGERPRINT => next!(fingerprint),
            Opt::HASH => next!(subject_hash),
            Opt::ISSUER_HASH => next!(issuer_hash),
            Opt::PURPOSE => next!(pprint),
            Opt::STARTDATE => next!(startdate),
            Opt::ENDDATE => next!(enddate),
            Opt::NOOUT => next!(noout),
            Opt::EXT => {
                next!(ext);
                ext_names = Some(p.arg().to_owned());
            }
            Opt::NOCERT => nocert = true,
            Opt::TRUSTOUT => trustout = true,
            Opt::CLRTRUST => next!(clrtrust),
            Opt::CLRREJECT => next!(clrreject),
            Opt::ALIAS => next!(aliasout),
            Opt::CACREATESERIAL => ca_createserial = true,
            Opt::CLREXT => clrext = true,
            Opt::OCSPID => next!(ocspid),
            Opt::BADSIG => badsig = true,
            Opt::SUBJECT_HASH_OLD => next!(subject_hash_old),
            Opt::ISSUER_HASH_OLD => next!(issuer_hash_old),
            Opt::DATES => {
                next!(startdate);
                next!(enddate);
            }
            Opt::CHECKEND => {
                checkend = true;
                match opt::intmax(p.arg()) {
                    Some(t) => checkoffset = t,
                    None => return Err(opthelp()),
                }
            }
            Opt::CHECKHOST => checkhost = Some(p.arg().to_owned()),
            Opt::CHECKEMAIL => checkemail = Some(p.arg().to_owned()),
            Opt::CHECKIP => checkip = Some(p.arg().to_owned()),
            Opt::PRESERVE_DATES => preserve_dates = true,
            Opt::MD => digest = p.unknown().map(str::to_owned),
        }
    }
    let _ = noout;
    let noout = noout != 0;
    if !p.check_rest_arg(None) {
        return Err(opthelp());
    }
    if !app_rand::load() {
        return Err(Fail);
    }
    if let Some(d) = &digest
        && !opt::check_md(d)
    {
        return Err(opthelp());
    }
    if preserve_dates && not_before.is_some() {
        eprintf!("Cannot use -preserve_dates with -not_before option\n");
        return Err(Fail);
    }
    if preserve_dates && not_after.is_some() {
        eprintf!("Cannot use -preserve_dates with -not_after option\n");
        return Err(Fail);
    }
    if preserve_dates && days != UNSET_DAYS {
        eprintf!("Cannot use -preserve_dates with -days option\n");
        return Err(Fail);
    }
    if days == UNSET_DAYS {
        days = DEFAULT_DAYS;
    } else if not_after.is_some() {
        eprintf!("Warning: -not_after option overriding -days option\n");
    }
    let Some((passin, _)) = app_passwd(passinarg.as_deref(), None) else {
        eprintf!("Error getting password\n");
        return Err(Fail);
    };
    let passin = passin.as_ref().map(|p| p.as_str().to_owned());
    let passin = passin.as_deref();
    let lc = libctx();
    let pq = propq();
    if !ctx.set_default_paths_ex(lc.as_deref(), pq.as_deref()) {
        return Err(Fail);
    }
    if newcert && infile.is_some() {
        eprintf!("The -in option cannot be used with -new\n");
        return Err(Fail);
    }
    if newcert && reqfile {
        eprintf!("The -req option cannot be used with -new\n");
        return Err(Fail);
    }
    let e = engine.as_ref();
    let mut privkey: Option<Pkey> = None;
    if let Some(f) = &privkeyfile {
        privkey = load_key(Some(f), keyformat, false, passin, e, Some("private key"));
        if privkey.is_none() {
            return Err(Fail);
        }
    }
    let mut pubkey: Option<Pkey> = None;
    if let Some(f) = &pubkeyfile {
        pubkey = load_pubkey(
            Some(f),
            keyformat,
            false,
            None,
            e,
            Some("explicitly set public key"),
        );
        if pubkey.is_none() {
            return Err(Fail);
        }
    }
    if newcert {
        if subj.is_none() {
            eprintf!("The -new option requires a subject to be set using -subj\n");
            return Err(Fail);
        }
        if privkeyfile.is_none() && pubkeyfile.is_none() {
            eprintf!("The -new option requires using the -key or -force_pubkey option\n");
            return Err(Fail);
        }
    }
    let mut fissu: Option<Name> = None;
    if let Some(i) = &issu {
        fissu = parse_name(i, MBSTRING_ASC, true, "issuer");
        if fissu.is_none() {
            return Err(Fail);
        }
    }
    let mut fsubj: Option<Name> = None;
    if let Some(s) = &subj {
        fsubj = parse_name(s, MBSTRING_ASC, true, "subject");
        if fsubj.is_none() {
            return Err(Fail);
        }
    }
    if ca_keyfile.is_none() {
        ca_keyfile.clone_from(&ca_file);
    }
    if ca_file.is_some() {
        if privkeyfile.is_some() {
            eprintf!("Cannot use both -key/-signkey and -CA option\n");
            return Err(Fail);
        }
    } else {
        let warn =
            |o: &str| eprintf!("Warning: ignoring {o} option since -CA option is not given\n");
        if ca_keyfile.is_some() {
            warn("-CAkey");
        }
        if ca_keyformat != format::UNDEF {
            warn("-CAkeyform");
        }
        if ca_format != format::UNDEF {
            warn("-CAform");
        }
        if ca_serial.is_some() {
            warn("-CAserial");
        }
        if ca_createserial {
            warn("-CAcreateserial");
        }
    }

    let mut extconf = None;
    match &extfile {
        None => {
            if extsect.is_some() {
                eprintf!("Warning: ignoring -extensions option without -extfile\n");
            }
        }
        Some(f) => {
            let conf = app_load_config(Some(f)).ok_or(Fail)?;
            if extsect.is_none() {
                extsect = Some(
                    app_conf_try_string(&conf, Some("default"), "extensions")
                        .unwrap_or_else(|| "default".to_owned()),
                );
            }
            let sect = extsect.clone().unwrap_or_default();
            let mut ctx2 = V3Ctx::test();
            ctx2.set_nconf(&conf);
            let ok = ctx2.add_nconf(&conf, &sect, None);
            drop(ctx2);
            if !ok {
                eprintf!("Error checking extension section {sect}\n");
                return Err(Fail);
            }
            extconf = Some(conf);
        }
    }
    let extsect = extsect.unwrap_or_default();

    if multi && (reqfile || newcert) {
        eprintf!("Error: -multi cannot be used with -req or -new\n");
        return Err(Fail);
    }

    let stdin_tty = std::io::stdin().is_terminal();
    let mut req: Option<Req> = None;
    if reqfile {
        if infile.is_none() && stdin_tty {
            eprintf!("Warning: Reading cert request from stdin since no -in option is given\n");
        }
        let r = load_csr_autofmt(
            infile.as_deref(),
            informat,
            &vfyopts,
            "certificate request input",
        )
        .ok_or(Fail)?;
        let Some(pkey) = r.pubkey() else {
            eprintf!("Error unpacking public key from CSR\n");
            return Err(Fail);
        };
        let i = do_x509_req_verify(&r, Some(&pkey), &vfyopts);
        if i <= 0 {
            if i < 0 {
                eprintf!("Error while verifying certificate request self-signature\n");
            } else {
                eprintf!("Certificate request self-signature did not match the contents\n");
            }
            return Err(Fail);
        }
        eprintf!("Certificate request self-signature ok\n");
        if let Some(b) = io::bio_err() {
            print_name(b, Some("subject="), r.subject_name());
        }
        req = Some(r);
    } else if !x509toreq && ext_copy.is_some() {
        eprintf!("Warning: ignoring -copy_extensions since neither -x509toreq nor -req is given\n");
    }

    let mut certs: Option<CertStack> = None;
    let mut single: Option<Cert> = None;
    if reqfile || newcert {
        if preserve_dates {
            eprintf!("Warning: ignoring -preserve_dates option with -req or -new\n");
        }
        preserve_dates = false;
        if privkeyfile.is_none() && ca_keyfile.is_none() {
            eprintf!(
                "We need a private key to sign with, use -key or -CAkey or -CA with private key\n"
            );
            return Err(Fail);
        }
        let x = Cert::new_ex(lc.as_deref(), pq.as_deref()).ok_or(Fail)?;
        if ca_file.is_none() && sno.is_none() {
            sno = Some(rand_serial().ok_or(Fail)?.1);
        }
        if let (Some(r), Some(copy)) = (&req, ext_copy) {
            if clrext && copy != ExtCopy::None {
                eprintf!("Must not use -clrext together with -copy_extensions\n");
                return Err(Fail);
            } else if !copy_extensions(&x, r, copy) {
                eprintf!("Error copying extensions from request\n");
                return Err(Fail);
            }
        }
        single = Some(x);
    } else {
        if infile.is_none() && stdin_tty {
            eprintf!(
                "Warning: Reading certificate(s) from stdin since no -in or -new option is given\n"
            );
        }
        if multi {
            let (ok, s) = load_certs(infile.as_deref(), true, CertStack::new(), passin, None);
            if !ok {
                return Err(Fail);
            }
            let s = s.ok_or(Fail)?;
            if s.is_empty() {
                return Err(Fail);
            }
            certs = Some(s);
        } else {
            single = Some(
                load_cert_pass(
                    infile.as_deref(),
                    informat,
                    true,
                    passin,
                    Some("certificate"),
                )
                .ok_or(Fail)?,
            );
        }
    }

    let out = bio_open_default(outfile.as_deref(), 'w', outformat).ok_or(Fail)?;
    let count = certs.as_ref().map_or(1, CertStack::len);
    let mut ret = 0;
    for k in 0..count {
        let x = match &certs {
            Some(s) => s.get(k).and_then(|c| c.to_owned()).ok_or(Fail)?,
            None => match single.take() {
                Some(x) => x,
                None => return Err(Fail),
            },
        };
        let mut o = &out;

        if let Some(nm) = fsubj
            .as_ref()
            .map(Name::as_name)
            .or_else(|| req.as_ref().map(Req::subject_name))
            && !x.set_subject_name(nm)
        {
            return Err(Fail);
        }
        let reqkey = req.as_ref().and_then(Req::pubkey);
        if let Some(k) = pubkey.as_ref().or(privkey.as_ref()).or(reqkey.as_ref())
            && !x.set_pubkey(k)
        {
            return Err(Fail);
        }
        let mut xca: Option<Cert> = None;
        if let Some(f) = &ca_file {
            xca = Some(
                load_cert_pass(Some(f), ca_format, true, passin, Some("CA certificate"))
                    .ok_or(Fail)?,
            );
        }
        if let Some(a) = &alias {
            x.alias_set1(a);
        }
        if clrtrust != 0 {
            x.trust_clear();
        }
        if clrreject != 0 {
            x.reject_clear();
        }
        for t in &trust {
            x.add1_trust_object(t);
        }
        for r in &reject {
            x.add1_reject_object(r);
        }
        if clrext && ext_names.is_some() {
            eprintf!("Warning: Ignoring -ext since -clrext is given\n");
        }
        for i in (0..x.ext_count()).rev() {
            let sn = x.ext(i).and_then(|e| e.sn()).unwrap_or_default();
            if clrext || ext_names.as_ref().is_some_and(|n| !n.contains(&sn)) {
                x.delete_ext(i);
            }
        }

        let issuer_cert = xca.as_ref().unwrap_or(&x);
        if let Some(f) = &ca_file {
            if sno.is_none() {
                sno = x509_load_serial(f, ca_serial.as_deref(), ca_createserial);
            }
            if sno.is_none() {
                return Err(Fail);
            }
            if !x509toreq && !reqfile && !newcert && !self_signed(&ctx, &x) {
                return Err(Fail);
            }
        } else if let Some(k) = &privkey
            && !cert_matches_key(&x, k)
        {
            eprintf!("Warning: Signature key and public key of cert do not match\n");
        }
        if let Some(s) = &sno
            && !x.set_serial(s)
        {
            return Err(Fail);
        }
        if reqfile || newcert || privkey.is_some() || ca_file.is_some() {
            if !preserve_dates
                && !set_cert_times(&x, not_before.as_deref(), not_after.as_deref(), days, true)
            {
                return Err(Fail);
            }
            let iname = match &fissu {
                Some(n) => n.as_name(),
                None => issuer_cert.subject_name(),
            };
            if !x.set_issuer_name(iname) {
                return Err(Fail);
            }
        }

        let mut ext_ctx = V3Ctx::new(Some(issuer_cert), Some(&x), None, None, X509V3_CTX_REPLACE);
        if ca_file.is_none() && !ext_ctx.set_issuer_pkey(privkey.as_ref()) {
            return Err(Fail);
        }
        if let Some(conf) = &extconf
            && !x509toreq
        {
            ext_ctx.set_nconf(conf);
            if !ext_ctx.add_nconf(conf, &extsect, Some(&x)) {
                eprintf!("Error adding extensions from section {extsect}\n");
                return Err(Fail);
            }
        }

        // The certificate's contents are now final.
        let pkey = x.pubkey();
        if (print_pubkey != 0 || modulus != 0) && pkey.is_none() {
            eprintf!("Error getting public key\n");
            return Err(Fail);
        }

        let mut noout = noout;
        let mut _rq = None;
        if x509toreq {
            let Some(k) = &privkey else {
                eprintf!("Must specify request signing key using -key\n");
                return Err(Fail);
            };
            if clrext && ext_copy != Some(ExtCopy::None) {
                eprintf!("Must not use -clrext together with -copy_extensions\n");
                return Err(Fail);
            }
            let rq = x509_to_req(&x, ext_copy, ext_names.as_deref()).ok_or(Fail)?;
            if let Some(conf) = &extconf {
                ext_ctx.set_nconf(conf);
                if !ext_ctx.req_add_nconf(conf, &extsect, Some(&rq)) {
                    eprintf!("Error adding request extensions from section {extsect}\n");
                    return Err(Fail);
                }
            }
            if !do_x509_req_sign(&rq, k, digest.as_deref(), &sigopts) {
                return Err(Fail);
            }
            if !noout {
                let i = if outformat == format::ASN1 {
                    rq.print_ex(&out, get_nameopt(), ul(X509_FLAG_COMPAT));
                    x.write_der(&out)
                } else {
                    rq.write_pem(&out)
                };
                if i == 0 {
                    eprintf!("Unable to write certificate request\n");
                    return Err(Fail);
                }
            }
            noout = true;
            _rq = Some(rq);
        } else if let (Some(_), Some(xca)) = (&ca_file, &xca) {
            let ca_key = load_key(
                ca_keyfile.as_deref(),
                ca_keyformat,
                false,
                passin,
                e,
                Some("CA private key"),
            )
            .ok_or(Fail)?;
            if !xca.check_private_key(&ca_key) {
                eprintf!("CA certificate and CA private key do not match\n");
                return Err(Fail);
            }
            if !do_x509_sign(
                &x,
                false,
                &ca_key,
                digest.as_deref(),
                &sigopts,
                &mut ext_ctx,
            ) {
                return Err(Fail);
            }
        } else if let Some(k) = &privkey
            && !do_x509_sign(&x, false, k, digest.as_deref(), &sigopts, &mut ext_ctx)
        {
            return Err(Fail);
        }
        drop(ext_ctx);
        if badsig {
            x.corrupt_signature();
        }

        // The printing options, in the order given.
        for i in 1..=num {
            if i == issuer {
                print_name(&out, Some("issuer="), x.issuer_name());
            } else if i == subject {
                print_name(&out, Some("subject="), x.subject_name());
            } else if i == serial {
                let _ = o.write_all(b"serial=");
                if let Some(s) = x.serial() {
                    s.i2a(&out);
                }
                let _ = o.write_all(b"\n");
            } else if i == next_serial {
                let bn = x.serial().and_then(|s| s.to_bn()).ok_or(Fail)?;
                if !bn.add_word(1) {
                    return Err(Fail);
                }
                let ser = Integer::from_bn(&bn).ok_or(Fail)?;
                ser.i2a(&out);
                let _ = o.write_all(b"\n");
            } else if i == email || i == ocsp_uri {
                let list = if i == email {
                    x.emails()
                } else {
                    x.ocsp_uris()
                };
                for s in list {
                    let _ = writeln!(o, "{s}");
                }
            } else if i == aliasout {
                match x.alias() {
                    Some(a) => {
                        let _ = o.write_all(&a);
                        let _ = o.write_all(b"\n");
                    }
                    None => {
                        let _ = o.write_all(b"<No Alias>\n");
                    }
                }
            } else if i == subject_hash {
                let _ = writeln!(o, "{:08x}", x.subject_name_hash());
            } else if i == subject_hash_old {
                let _ = writeln!(o, "{:08x}", x.subject_name_hash_old());
            } else if i == issuer_hash {
                let _ = writeln!(o, "{:08x}", x.issuer_name_hash());
            } else if i == issuer_hash_old {
                let _ = writeln!(o, "{:08x}", x.issuer_name_hash_old());
            } else if i == pprint {
                let _ = o.write_all(b"Certificate purposes:\n");
                for (id, name) in x509::purpose_ids() {
                    purpose_print(&mut o, &x, id, &name);
                }
            } else if i == modulus {
                let _ = o.write_all(b"Modulus=");
                if let Some(k) = &pkey {
                    if k.is_a("RSA") || k.is_a("RSA-PSS") {
                        x509::bn_print(&out, k.bn_param(c"n").as_ref());
                    } else if k.is_a("DSA") {
                        x509::bn_print(&out, k.bn_param(c"pub").as_ref());
                    } else {
                        let _ = o.write_all(b"No modulus for this public key type");
                    }
                }
                let _ = o.write_all(b"\n");
            } else if i == print_pubkey {
                if let Some(k) = &pkey {
                    k.write_pubkey_pem(&out);
                }
            } else if i == text {
                x.print_ex(&out, get_nameopt(), certflag);
            } else if i == startdate {
                let _ = o.write_all(b"notBefore=");
                if let Some(t) = x.not_before() {
                    t.print_ex(&out, dateopt);
                }
                let _ = o.write_all(b"\n");
            } else if i == enddate {
                let _ = o.write_all(b"notAfter=");
                if let Some(t) = x.not_after() {
                    t.print_ex(&out, dateopt);
                }
                let _ = o.write_all(b"\n");
            } else if i == fingerprint {
                let fdigname = digest.as_deref().unwrap_or("SHA1");
                let Some(fdig) = Md::fetch(lc.as_deref(), fdigname, pq.as_deref()) else {
                    eprintf!("Unknown digest\n");
                    return Err(Fail);
                };
                let Some(md) = x.digest(&fdig) else {
                    eprintf!("Out of memory\n");
                    return Err(Fail);
                };
                let _ = o.write_all(fingerprint_line(fdigname, &md).as_bytes());
            } else if i == ocspid {
                x.ocspid_print(&out);
            } else if i == ext {
                print_x509v3_exts(&out, &x, ext_names.as_deref().unwrap_or_default());
            }
        }

        if checkend {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
            let tcheck = now.saturating_add(checkoffset);
            let expired = x.not_after().is_some_and(|t| t.cmp_time(tcheck) < 0);
            if expired {
                let _ = o.write_all(b"Certificate will expire\n");
            } else {
                let _ = o.write_all(b"Certificate will not expire\n");
            }
            if multi && k > 0 {
                ret |= i32::from(expired);
            } else {
                ret = i32::from(expired);
            }
            if multi && k + 1 < count {
                continue;
            }
            return Ok(ret);
        }

        if !check_cert_attributes(
            &out,
            &x,
            checkhost.as_deref(),
            checkemail.as_deref(),
            checkip.as_deref(),
            true,
        ) {
            return Err(Fail);
        }
        if noout || nocert {
            continue;
        }
        let i = if outformat == format::ASN1 {
            x.write_der(&out)
        } else if outformat == format::PEM {
            if trustout {
                x.write_pem_aux(&out)
            } else {
                x.write_pem(&out)
            }
        } else {
            eprintf!("Bad output format specified for outfile\n");
            return Err(Fail);
        };
        if i == 0 {
            eprintf!("Unable to write certificate\n");
            return Err(Fail);
        }
    }
    Ok(0)
}
