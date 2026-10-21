//! `openssl ca` (`apps/ca.c`), with `apps.c`'s `set_crl_lastupdate` and
//! `set_crl_nextupdate`, and `unpack_revinfo` (which `ocsp` shares).

use std::ffi::c_ulong;
use std::io::{BufRead, Write};

use rustyssl_ossl::abi::{
    ASN1_DTFLGS_RFC822, MBSTRING_ASC, MBSTRING_UTF8, NID_crl_number, NID_crl_reason,
    NID_hold_instruction_code, NID_invalidity_date, NID_pkcs9_emailAddress,
    OCSP_REVOKED_STATUS_CACOMPROMISE, OCSP_REVOKED_STATUS_CERTIFICATEHOLD,
    OCSP_REVOKED_STATUS_KEYCOMPROMISE, OCSP_REVOKED_STATUS_NOSTATUS,
    OCSP_REVOKED_STATUS_REMOVEFROMCRL, V_ASN1_BMPSTRING, V_ASN1_IA5STRING, V_ASN1_PRINTABLESTRING,
    V_ASN1_T61STRING, V_ASN1_UNIVERSALSTRING, V_ASN1_UTF8STRING, X509_CRL_VERSION_2,
    X509_FLAG_COMPAT, X509_FLAG_NO_SIGDUMP, X509_FLAG_NO_SIGNAME, X509V3_CTX_REPLACE,
};
use rustyssl_ossl::conf::Conf;
use rustyssl_ossl::pkey::Pkey;
use rustyssl_ossl::txt_db::LegacyConf;
use rustyssl_ossl::x509::{
    self, Bn, Cert, CertStack, Crl, Integer, Name, Obj, Req, Revoked, Spki, Time, V3Ctx,
};
use rustyssl_ossl::{Bio, err};

use crate::cmd::x509::set_cert_times;
use crate::generated::options::ca::{OPTIONS, Opt};
use crate::lib::app_libctx::{libctx, opt_provider, propq};
use crate::lib::app_rand;
use crate::lib::apps::{
    ConfigFile, ExtCopy, add_oid_section, app_conf_try_number, app_conf_try_string,
    app_load_config, app_load_config_verbose, app_load_modules, app_passwd, atoi, bio_open_default,
    cert_matches_key, copy_extensions, do_x509_crl_sign, do_x509_req_verify, do_x509_sign,
    do_x509_verify, get_nameopt, load_cert_pass, load_csr_autofmt, load_key, parse_name,
    parse_yesno, set_cert_ex, set_dateopt, set_ext_copy, set_nameopt,
};
use crate::lib::ca_db::{
    CaDb, db_type, field, index_index, load_index, load_serial, perror, rand_serial, rotate_index,
    rotate_serial, save_index, save_serial,
};
use crate::lib::engine::setup_engine;
use crate::lib::io;
use crate::lib::opt::{self, Parser, eprintf, fmt_flags, format};

const BASE_SECTION: &str = "ca";
const ENV_DEFAULT_CA: &str = "default_ca";
const STRING_MASK: &str = "string_mask";
const UTF8_IN: &str = "utf8";
const ENV_NEW_CERTS_DIR: &str = "new_certs_dir";
const ENV_CERTIFICATE: &str = "certificate";
const ENV_SERIAL: &str = "serial";
const ENV_RAND_SERIAL: &str = "rand_serial";
const ENV_CRLNUMBER: &str = "crlnumber";
const ENV_PRIVATE_KEY: &str = "private_key";
const ENV_DEFAULT_DAYS: &str = "default_days";
const ENV_DEFAULT_STARTDATE: &str = "default_startdate";
const ENV_DEFAULT_ENDDATE: &str = "default_enddate";
const ENV_DEFAULT_CRL_DAYS: &str = "default_crl_days";
const ENV_DEFAULT_CRL_HOURS: &str = "default_crl_hours";
const ENV_DEFAULT_MD: &str = "default_md";
const ENV_DEFAULT_EMAIL_DN: &str = "email_in_dn";
const ENV_PRESERVE: &str = "preserve";
const ENV_POLICY: &str = "policy";
const ENV_EXTENSIONS: &str = "x509_extensions";
const ENV_CRLEXT: &str = "crl_extensions";
const ENV_MSIE_HACK: &str = "msie_hack";
const ENV_NAMEOPT: &str = "name_opt";
const ENV_CERTOPT: &str = "cert_opt";
const ENV_EXTCOPY: &str = "copy_extensions";
const ENV_UNIQUE_SUBJECT: &str = "unique_subject";
const ENV_DATABASE: &str = "database";
/// `PATH_MAX`.
const PATH_MAX: usize = 4096;

/// `REVINFO_TYPE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RevType {
    Valid,
    None,
    CrlReason,
    Hold,
    KeyCompromise,
    CaCompromise,
}

/// The CRL reason strings, then the pseudo reasons.
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

pub fn main(argv: &[String]) -> i32 {
    let ret = run(argv);
    if ret != 0 {
        io::print_errors();
    }
    ret
}

/// `lookup_conf`.
fn lookup_conf(conf: &Conf, section: Option<&str>, tag: &str) -> Option<String> {
    let entry = conf.get_string(section, tag);
    if entry.is_none() {
        let s = section.unwrap_or("(null)");
        eprintf!("variable lookup failed for {s}::{tag}\n");
    }
    entry
}

/// `fgets(buf, size, stdin)` (a prompt's answer): `None` at the end.
fn fgets(size: usize) -> Option<Vec<u8>> {
    let stdin = std::io::stdin();
    let mut lock = stdin.lock();
    let mut out = Vec::new();
    while out.len() + 1 < size {
        let Ok(buf) = lock.fill_buf() else {
            break;
        };
        let Some(&b) = buf.first() else {
            break;
        };
        lock.consume(1);
        out.push(b);
        if b == b'\n' {
            break;
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

/// `set_crl_lastupdate`.
pub fn set_crl_lastupdate(crl: &Crl, lastupdate: Option<&str>) -> bool {
    let Some(tm) = Time::new() else {
        return false;
    };
    let ok = match lastupdate {
        None => tm.set_adj(0, 0),
        Some(s) => tm.set_string_x509(s),
    };
    ok && crl.set1_last_update(&tm)
}

/// `set_crl_nextupdate`.
pub fn set_crl_nextupdate(
    crl: &Crl,
    nextupdate: Option<&str>,
    days: i64,
    hours: i64,
    secs: i64,
) -> bool {
    let Some(tm) = Time::new() else {
        return false;
    };
    let ok = match nextupdate {
        None => {
            // C passes long days to an int and hours * 3600 + secs as a long.
            let d = i32::try_from(days).unwrap_or(if days < 0 { i32::MIN } else { i32::MAX });
            let s = hours.saturating_mul(3600).saturating_add(secs);
            tm.set_adj(d, s)
        }
        Some(s) => tm.set_string_x509(s),
    };
    ok && crl.set1_next_update(&tm)
}

/// What `unpack_revinfo` makes of a database revocation field.
pub struct RevInfo {
    pub revtime: Option<Time>,
    pub reason: i32,
    pub hold: Option<Obj>,
    pub invtime: Option<Time>,
}

/// `unpack_revinfo(&revtm, &reason, &hold, &invtm, str)`: `revtime`, `hold` and `invtime`
/// are made only when asked for.
pub fn unpack_revinfo(s: &str, want_revtime: bool) -> Option<RevInfo> {
    let mut parts = s.splitn(2, ',');
    let rtime_str = parts.next().unwrap_or_default();
    let (reason_str, arg_str) = match parts.next() {
        Some(rest) => match rest.split_once(',') {
            Some((r, a)) => (Some(r), Some(a)),
            None => (Some(rest), None),
        },
        None => (None, None),
    };
    let mut info = RevInfo {
        revtime: None,
        reason: OCSP_REVOKED_STATUS_NOSTATUS,
        hold: None,
        invtime: None,
    };
    if want_revtime {
        match Time::utc_from_string(rtime_str) {
            Ok(t) => info.revtime = Some(t),
            Err(true) => {
                eprintf!("memory allocation failure\n");
                return None;
            }
            Err(false) => {
                eprintf!("invalid revocation date {rtime_str}\n");
                return None;
            }
        }
    }
    if let Some(r) = reason_str {
        let Some(i) = CRL_REASONS.iter().position(|c| c.eq_ignore_ascii_case(r)) else {
            eprintf!("invalid reason code {r}\n");
            return None;
        };
        let mut code = i32::try_from(i).unwrap_or(-1);
        match i {
            7 => code = OCSP_REVOKED_STATUS_REMOVEFROMCRL,
            8 => {
                let Some(a) = arg_str else {
                    eprintf!("missing hold instruction\n");
                    return None;
                };
                code = OCSP_REVOKED_STATUS_CERTIFICATEHOLD;
                let Some(h) = Obj::from_txt(a, false) else {
                    eprintf!("invalid object identifier {a}\n");
                    return None;
                };
                info.hold = Some(h);
            }
            9 | 10 => {
                let Some(a) = arg_str else {
                    eprintf!("missing compromised time\n");
                    return None;
                };
                match Time::generalized_from_string(a) {
                    Ok(t) => info.invtime = Some(t),
                    Err(true) => {
                        eprintf!("memory allocation failure\n");
                        return None;
                    }
                    Err(false) => {
                        eprintf!("invalid compromised time {a}\n");
                        return None;
                    }
                }
                code = if i == 9 {
                    OCSP_REVOKED_STATUS_KEYCOMPROMISE
                } else {
                    OCSP_REVOKED_STATUS_CACOMPROMISE
                };
            }
            _ => {}
        }
        info.reason = code;
    }
    Some(info)
}

/// `make_revoked(rev, str)`: 0 on error, 1 OK, 2 OK with extensions (a v2 CRL).
fn make_revoked(rev: Option<&Revoked>, s: &str) -> i32 {
    let Some(info) = unpack_revinfo(s, true) else {
        return 0;
    };
    if let Some(r) = rev {
        if !info
            .revtime
            .as_ref()
            .is_some_and(|t| r.set_revocation_date(t))
        {
            return 0;
        }
        if info.reason != OCSP_REVOKED_STATUS_NOSTATUS
            && r.add_reason(NID_crl_reason, info.reason.into()) <= 0
        {
            return 0;
        }
        if let Some(t) = &info.invtime
            && r.add_time_ext(NID_invalidity_date, t) <= 0
        {
            return 0;
        }
        if let Some(h) = &info.hold
            && r.add_obj_ext(NID_hold_instruction_code, h) <= 0
        {
            return 0;
        }
    }
    if info.reason != OCSP_REVOKED_STATUS_NOSTATUS {
        2
    } else {
        1
    }
}

/// `make_revocation_str`: `revtime[,reason[,extra]]`, the time now.
fn make_revocation_str(rev_type: RevType, rev_arg: Option<&str>) -> Option<String> {
    let arg = rev_arg.unwrap_or_default();
    let (reason, other): (Option<&str>, Option<&str>) = match rev_type {
        RevType::None | RevType::Valid => (None, None),
        RevType::CrlReason => {
            match CRL_REASONS
                .iter()
                .take(8)
                .find(|c| c.eq_ignore_ascii_case(arg))
            {
                Some(r) => (Some(*r), None),
                None => {
                    eprintf!("Unknown CRL reason {arg}\n");
                    return None;
                }
            }
        }
        RevType::Hold => {
            if Obj::from_txt(arg, false).is_none() {
                eprintf!("Invalid object identifier {arg}\n");
                return None;
            }
            (Some("holdInstruction"), Some(arg))
        }
        RevType::KeyCompromise | RevType::CaCompromise => {
            if !x509::generalized_time_check(arg) {
                eprintf!("Invalid time format {arg}. Need YYYYMMDDHHMMSSZ\n");
                return None;
            }
            let r = if rev_type == RevType::KeyCompromise {
                "keyTime"
            } else {
                "CAkeyTime"
            };
            (Some(r), Some(arg))
        }
    };
    let revtm = Time::now_utc()?;
    let (data, _) = revtm.as_ref().data();
    let mut s = String::from_utf8_lossy(&data).into_owned();
    if let Some(r) = reason {
        s.push(',');
        s.push_str(r);
    }
    if let Some(o) = other {
        s.push(',');
        s.push_str(o);
    }
    Some(s)
}

/// `old_entry_print`: one subject field, as `ca` lists the request's.
fn old_entry_print(e: x509::NameEntryRef<'_>) {
    let Some(berr) = io::bio_err() else {
        return;
    };
    let j = e.print_obj(berr);
    let pad = usize::try_from(22 - j).unwrap_or(0);
    let mut text = format!("{:pad$}:", "");
    let t = e.data_type();
    text.push_str(&match t {
        V_ASN1_PRINTABLESTRING => "PRINTABLE:'".to_owned(),
        V_ASN1_T61STRING => "T61STRING:'".to_owned(),
        V_ASN1_IA5STRING => "IA5STRING:'".to_owned(),
        V_ASN1_UNIVERSALSTRING => "UNIVERSALSTRING:'".to_owned(),
        _ => format!("ASN.1 {t:2}:'"),
    });
    for b in e.data() {
        // C's `char`: signed on some targets, which `%02X` then shows as an int.
        let c = c_char_value(b);
        if (i32::from(b' ')..=i32::from(b'~')).contains(&c) {
            text.push(char::from(b));
        } else if c & 0x80 != 0 {
            text.push_str(&format!("\\0x{:02X}", u32::from_ne_bytes(c.to_ne_bytes())));
        } else if b == 0xf7 {
            text.push_str("^?");
        } else {
            let at = u8::try_from(c + i32::from(b'@')).unwrap_or(b'?');
            text.push('^');
            text.push(char::from(at));
        }
    }
    text.push_str("'\n");
    let _ = io::err().write_all(text.as_bytes());
}

/// What `do_body` and its callers share.
struct Body<'a> {
    pkey: &'a Pkey,
    x509: Option<&'a Cert>,
    dgst: Option<&'a str>,
    sigopts: &'a [String],
    vfyopts: &'a [String],
    policy: &'a [(String, String)],
    db: &'a CaDb,
    subj: Option<&'a str>,
    chtype: i32,
    email_dn: bool,
    startdate: Option<&'a str>,
    enddate: Option<&'a str>,
    days: i64,
    batch: bool,
    ext_sect: Option<&'a str>,
    conf: &'a Conf,
    extfile_conf: Option<&'a Conf>,
    verbose: bool,
    certopt: c_ulong,
    default_op: bool,
    ext_copy: ExtCopy,
    dateopt: c_ulong,
    preserve: bool,
    msie_hack: bool,
}

/// A byte as C's `char` promotes it to an `int`: sign-extended where `char` is signed.
fn c_char_value(b: u8) -> i32 {
    if core::ffi::c_char::MIN == 0 {
        i32::from(b)
    } else {
        i32::from(b.cast_signed())
    }
}

/// The C string of an `ASN1_STRING`'s data (up to a NUL), for messages.
fn c_text(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(b.get(..end).unwrap_or_default()).into_owned()
}

/// `do_body`: -1 a bad error, 0 not certified, 1 certified (the certificate).
#[allow(clippy::too_many_lines)]
fn do_body(
    b: &Body<'_>,
    serial: &Bn,
    req: &Req,
    selfsign: bool,
    batch: bool,
) -> (i32, Option<Cert>) {
    if let Some(s) = b.subj {
        let Some(n) = parse_name(s, b.chtype, true, "subject") else {
            return (-1, None);
        };
        req.set_subject_name(n.as_name());
    }
    if b.default_op {
        eprintf!("The Subject's Distinguished Name is as follows\n");
    }
    let name = req.subject_name();
    for i in 0..name.entry_count() {
        let Some(ne) = name.entry(i) else {
            continue;
        };
        let nid = ne.nid();
        if b.msie_hack {
            if ne.data_type() == V_ASN1_UNIVERSALSTRING {
                ne.universal_to_string();
            }
            if ne.data_type() == V_ASN1_IA5STRING && nid != NID_pkcs9_emailAddress {
                ne.set_data_type(V_ASN1_T61STRING);
            }
            if nid == NID_pkcs9_emailAddress && ne.data_type() == V_ASN1_PRINTABLESTRING {
                ne.set_data_type(V_ASN1_IA5STRING);
            }
        }
        if nid == NID_pkcs9_emailAddress && !b.email_dn {
            continue;
        }
        let t = ne.data_type();
        if nid == NID_pkcs9_emailAddress && t != V_ASN1_IA5STRING {
            eprintf!("\nemailAddress type needs to be of type IA5STRING\n");
            return (-1, None);
        }
        if t != V_ASN1_BMPSTRING && t != V_ASN1_UTF8STRING {
            let j = x509::printable_type(&ne.data());
            if (j == V_ASN1_T61STRING && t != V_ASN1_T61STRING)
                || (j == V_ASN1_IA5STRING && t == V_ASN1_PRINTABLESTRING)
            {
                eprintf!("\nThe string contains characters that are illegal for the ASN.1 type\n");
                return (-1, None);
            }
        }
        if b.default_op {
            old_entry_print(ne);
        }
    }

    // The policy.
    let Some(mut subject) = Name::new() else {
        eprintf!("Memory allocation failure\n");
        return (-1, None);
    };
    let ca_name = if selfsign {
        name.to_owned()
    } else {
        b.x509.and_then(|x| x.subject_name().to_owned())
    };
    let Some(ca_name) = ca_name else {
        return (-1, None);
    };
    for (pname, pvalue) in b.policy {
        let nid = x509::txt2nid(pname);
        if nid == 0 {
            eprintf!("{pname}:unknown object type in 'policy' configuration\n");
            return (-1, None);
        }
        let mut last = -1;
        loop {
            let j = name.index_by_nid(nid, last);
            let tne = if j < 0 {
                if last != -1 {
                    break;
                }
                None
            } else {
                name.entry(j)
            };
            last = j;
            let mut push = None;
            let mut jj = j;
            match pvalue.as_str() {
                "optional" => push = tne,
                "supplied" => {
                    if tne.is_none() {
                        eprintf!("The {pname} field needed to be supplied and was missing\n");
                        return (-1, None);
                    }
                    push = tne;
                }
                "match" => {
                    let Some(t) = tne else {
                        eprintf!("The mandatory {pname} field was missing\n");
                        return (-1, None);
                    };
                    let ca = ca_name.as_name();
                    let mut last2 = -1;
                    let mut strs: (Option<Vec<u8>>, Option<Vec<u8>>) = (None, None);
                    loop {
                        jj = ca.index_by_nid(nid, last2);
                        if jj < 0 && last2 == -1 {
                            eprintf!(
                                "The {pname} field does not exist in the CA certificate,\nthe 'policy' is misconfigured\n"
                            );
                            return (-1, None);
                        }
                        if jj >= 0 {
                            let p = ca.entry(jj);
                            strs = (Some(t.data()), p.map(|p| p.data()));
                            last2 = jj;
                            if p.is_some_and(|p| t.data_cmp(p) != 0) {
                                continue;
                            }
                            push = p;
                        }
                        break;
                    }
                    if jj < 0 {
                        let s2 = strs.1.as_deref().map_or_else(|| "NULL".to_owned(), c_text);
                        let s1 = strs.0.as_deref().map_or_else(|| "NULL".to_owned(), c_text);
                        eprintf!(
                            "The {pname} field is different between\nCA certificate ({s2}) and the request ({s1})\n"
                        );
                        return (-1, None);
                    }
                }
                _ => {
                    eprintf!("{pvalue}:invalid type in 'policy' configuration\n");
                    return (-1, None);
                }
            }
            if let Some(p) = push
                && !subject.add_entry(p)
            {
                eprintf!("Memory allocation failure\n");
                return (-1, None);
            }
            if jj < 0 || j < 0 {
                break;
            }
        }
    }
    if b.preserve {
        match name.to_owned() {
            Some(n) => subject = n,
            None => return (-1, None),
        }
    }

    if b.verbose {
        eprintf!("Everything appears to be ok, creating and signing the certificate\n");
    }
    let lc = libctx();
    let pq = propq();
    let Some(ret) = Cert::new_ex(lc.as_deref(), pq.as_deref()) else {
        return (-1, None);
    };
    if !Integer::from_bn(serial).is_some_and(|s| ret.set_serial(&s)) {
        return (-1, None);
    }
    let issuer_ok = if selfsign {
        ret.set_issuer_name(subject.as_name())
    } else {
        b.x509
            .is_some_and(|x| ret.set_issuer_name(x.subject_name()))
    };
    if !issuer_ok {
        return (-1, None);
    }
    let mut days = b.days;
    let ndays = i32::try_from(days).unwrap_or(i32::MAX);
    if !set_cert_times(&ret, b.startdate, b.enddate, ndays, false) {
        return (-1, None);
    }
    if b.enddate.is_some() {
        match ret.not_after().and_then(x509::days_until) {
            Some(d) => days = i64::from(d),
            None => return (-1, None),
        }
    }
    if !ret.set_subject_name(subject.as_name()) {
        return (-1, None);
    }
    if !req.pubkey().is_some_and(|k| ret.set_pubkey(&k)) {
        return (-1, None);
    }

    let issuer_cert = if selfsign { Some(&ret) } else { b.x509 };
    let mut ext_ctx = V3Ctx::new(issuer_cert, Some(&ret), None, None, X509V3_CTX_REPLACE);
    if selfsign {
        if !ext_ctx.set_issuer_pkey(Some(b.pkey)) {
            return (-1, None);
        }
        if !cert_matches_key(&ret, b.pkey) {
            eprintf!("Warning: Signature key and public key of cert do not match\n");
        }
    }
    if let Some(sect) = b.ext_sect {
        if let Some(ec) = b.extfile_conf {
            if b.verbose {
                eprintf!("Extra configuration file found\n");
            }
            ext_ctx.set_nconf(ec);
            if !ext_ctx.add_nconf(ec, sect, Some(&ret)) {
                eprintf!("Error adding certificate extensions from extfile section {sect}\n");
                return (-1, None);
            }
            if b.verbose {
                eprintf!("Successfully added extensions from file.\n");
            }
        } else {
            ext_ctx.set_nconf(b.conf);
            if !ext_ctx.add_nconf(b.conf, sect, Some(&ret)) {
                eprintf!("Error adding certificate extensions from config section {sect}\n");
                return (-1, None);
            }
            if b.verbose {
                eprintf!("Successfully added extensions from config\n");
            }
        }
    }
    if !copy_extensions(&ret, req, b.ext_copy) {
        eprintf!("ERROR: adding extensions from request\n");
        return (-1, None);
    }
    if b.verbose {
        eprintf!("The subject name appears to be ok, checking database for clashes\n");
    }
    if !b.email_dn {
        let Some(dn_subject) = subject.as_name().to_owned() else {
            eprintf!("Memory allocation failure\n");
            return (-1, None);
        };
        let mut i = -1;
        loop {
            i = dn_subject.as_name().index_by_nid(NID_pkcs9_emailAddress, i);
            if i < 0 {
                break;
            }
            dn_subject.delete_entry(i);
            i -= 1;
        }
        if !ret.set_subject_name(dn_subject.as_name()) {
            return (-1, None);
        }
    }

    let Some(mut row_name) = x509::name_oneline(ret.subject_name()) else {
        eprintf!("Memory allocation failure\n");
        return (-1, None);
    };
    let row_serial = if serial.is_zero() {
        "00".to_owned()
    } else {
        match serial.to_hex() {
            Some(h) => h,
            None => {
                eprintf!("Memory allocation failure\n");
                return (-1, None);
            }
        }
    };
    if row_name.is_empty() {
        row_name.clone_from(&row_serial);
    }
    let key = row(None, None, None, Some(&row_serial), None, Some(&row_name));
    let mut rrow = None;
    if b.db.unique_subject {
        rrow = b.db.db.get_by_index(field::NAME, &key);
        if rrow.is_some() {
            eprintf!("ERROR:There is already a certificate for {row_name}\n");
        }
    }
    if rrow.is_none() {
        rrow = b.db.db.get_by_index(field::SERIAL, &key);
        if rrow.is_some() {
            eprintf!("ERROR:Serial number {row_serial} has already been issued,\n");
            eprintf!("      check the database/serial_file for corruption\n");
        }
    }
    if let Some(r) = rrow {
        let get = |f| b.db.db.field_str(r, f);
        eprintf!("The matching entry has the following details\n");
        let t = get(field::TYPE).and_then(|t| t.bytes().next());
        let p = match t {
            Some(db_type::EXP) => "Expired",
            Some(db_type::REV) => "Revoked",
            Some(db_type::VAL) => "Valid",
            _ => "\ninvalid type, Database error\n",
        };
        eprintf!("Type          :{p}\n");
        let undef = |v: Option<String>| v.unwrap_or_else(|| "undef".to_owned());
        if t == Some(db_type::REV) {
            eprintf!("Was revoked on:{}\n", undef(get(field::EXP_DATE)));
        }
        eprintf!("Expires on    :{}\n", undef(get(field::EXP_DATE)));
        eprintf!("Serial Number :{}\n", undef(get(field::SERIAL)));
        eprintf!("File name     :{}\n", undef(get(field::FILE)));
        eprintf!("Subject Name  :{}\n", undef(get(field::NAME)));
        return (-1, None);
    }

    if !b.default_op {
        eprintf!("Certificate Details:\n");
        let flags =
            b.certopt | c_ulong::try_from(X509_FLAG_NO_SIGDUMP | X509_FLAG_NO_SIGNAME).unwrap_or(0);
        if let Some(berr) = io::bio_err() {
            ret.print_ex(berr, get_nameopt(), flags);
        }
    }
    eprintf!("Certificate is to be certified until ");
    if let (Some(t), Some(berr)) = (ret.not_after(), io::bio_err()) {
        t.print_ex(berr, b.dateopt);
    }
    if days != 0 {
        eprintf!(" ({days} days)");
    }
    eprintf!("\n");

    if !batch {
        eprintf!("Sign the certificate? [y/n]:");
        let Some(buf) = fgets(25) else {
            eprintf!("CERTIFICATE WILL NOT BE CERTIFIED: I/O error\n");
            return (0, None);
        };
        if !matches!(buf.first(), Some(b'y' | b'Y')) {
            eprintf!("CERTIFICATE WILL NOT BE CERTIFIED\n");
            return (0, None);
        }
    }

    if let Some(k) = ret.pubkey()
        && k.missing_parameters()
        && !b.pkey.missing_parameters()
    {
        k.copy_parameters(b.pkey);
    }
    if !do_x509_sign(&ret, false, b.pkey, b.dgst, b.sigopts, &mut ext_ctx) {
        return (-1, None);
    }
    drop(ext_ctx);

    // Into the database, as valid.
    let exp = ret
        .not_after()
        .map(|t| c_text(&t.data().0))
        .unwrap_or_default();
    let new = row(
        Some("V"),
        Some(&exp),
        None,
        Some(&row_serial),
        Some("unknown"),
        Some(&row_name),
    );
    if !b.db.db.insert(&new) {
        eprintf!("failed to update database\n");
        eprintf!("TXT_DB error number {}\n", b.db.db.error().0);
        return (-1, None);
    }
    (1, Some(ret))
}

/// A database row of its six fields.
fn row<'a>(
    t: Option<&'a str>,
    exp: Option<&'a str>,
    rev: Option<&'a str>,
    serial: Option<&'a str>,
    file: Option<&'a str>,
    name: Option<&'a str>,
) -> [Option<&'a str>; field::NUMBER] {
    [t, exp, rev, serial, file, name]
}

/// `certify`: a request from a file.
fn certify(
    b: &Body<'_>,
    infile: &str,
    informat: i32,
    serial: &Bn,
    selfsign: bool,
) -> (i32, Option<Cert>) {
    let r = (|| {
        let Some(req) = load_csr_autofmt(Some(infile), informat, b.vfyopts, "certificate request")
        else {
            return (-1, None);
        };
        let Some(pktmp) = req.pubkey() else {
            eprintf!("Error unpacking public key\n");
            return (-1, None);
        };
        if b.verbose
            && let Some(berr) = io::bio_err()
        {
            req.print_ex(
                berr,
                get_nameopt(),
                c_ulong::try_from(X509_FLAG_COMPAT).unwrap_or(0),
            );
        }
        eprintf!("Check that the request matches the signature\n");
        if selfsign && !req.check_private_key(b.pkey) {
            eprintf!("Certificate request and CA private key do not match\n");
            return (0, None);
        }
        let i = do_x509_req_verify(&req, Some(&pktmp), b.vfyopts);
        if i < 0 {
            eprintf!("Signature verification problems...\n");
            return (0, None);
        }
        if i == 0 {
            eprintf!("Signature did not match the certificate request\n");
            return (0, None);
        }
        eprintf!("Signature ok\n");
        do_body(b, serial, &req, selfsign, b.batch)
    })();
    io::print_errors();
    r
}

/// `certify_cert`: a self-signed certificate's contents, as a request.
fn certify_cert(
    b: &Body<'_>,
    infile: &str,
    certformat: i32,
    passin: Option<&str>,
    serial: &Bn,
) -> (i32, Option<Cert>) {
    let Some(template) = load_cert_pass(
        Some(infile),
        certformat,
        true,
        passin,
        Some("template certificate"),
    ) else {
        return (-1, None);
    };
    if b.verbose
        && let Some(berr) = io::bio_err()
    {
        template.print(berr);
    }
    eprintf!("Check that the request matches the signature\n");
    let Some(pktmp) = template.pubkey() else {
        eprintf!("error unpacking public key\n");
        return (-1, None);
    };
    let i = do_x509_verify(&template, &pktmp, b.vfyopts);
    if i < 0 {
        eprintf!("Signature verification problems....\n");
        return (0, None);
    }
    if i == 0 {
        eprintf!("Signature did not match the certificate\n");
        return (0, None);
    }
    eprintf!("Signature ok\n");
    let Some(rreq) = template.to_req() else {
        return (-1, None);
    };
    do_body(b, serial, &rreq, false, b.batch)
}

/// `certify_spkac`: an SPKAC and its DN fields from a file.
fn certify_spkac(b: &Body<'_>, infile: &str, serial: &Bn) -> (i32, Option<Cert>) {
    let parms = match LegacyConf::load(infile) {
        Ok(p) => p,
        Err(errline) => {
            eprintf!("error on line {errline} of {infile}\n");
            return (-1, None);
        }
    };
    let sk = parms.get_section("default");
    if sk.is_empty() {
        eprintf!("no name/value pairs found in {infile}\n");
        return (-1, None);
    }
    let Some(req) = Req::new() else {
        return (-1, None);
    };
    let mut spki: Option<Spki> = None;
    for (name, value) in &sk {
        let mut ty = name.as_str();
        if let Some(i) = name.find([':', ',', '.']) {
            let after = name.get(i + 1..).unwrap_or_default();
            if !after.is_empty() {
                ty = after;
            }
        }
        let nid = x509::txt2nid(ty);
        if nid == 0 {
            if ty == "SPKAC" {
                spki = Spki::b64_decode(value);
                if spki.is_none() {
                    eprintf!("unable to load Netscape SPKAC structure\n");
                    return (-1, None);
                }
            }
            continue;
        }
        if !req.add_subject_entry_by_nid(nid, b.chtype, value.as_bytes(), 0) {
            return (-1, None);
        }
    }
    let Some(spki) = spki else {
        eprintf!("Netscape SPKAC structure not found in {infile}\n");
        return (-1, None);
    };
    eprintf!("Check that the SPKAC request matches the signature\n");
    let Some(pktmp) = spki.pubkey() else {
        eprintf!("error unpacking SPKAC public key\n");
        return (-1, None);
    };
    if spki.verify(Some(&pktmp)) <= 0 {
        eprintf!("signature verification failed on SPKAC public key\n");
        return (-1, None);
    }
    eprintf!("Signature ok\n");
    req.set_pubkey(Some(&pktmp));
    do_body(b, serial, &req, false, true)
}

/// `write_new_certificate`.
fn write_new_certificate(bp: &Bio, x: &Cert, output_der: bool, notext: bool) {
    if output_der {
        x.write_der(bp);
        return;
    }
    if !notext {
        x.print(bp);
    }
    x.write_pem(bp);
}

/// `do_revoke`: -1 on error, 1 done.
fn do_revoke(x509: &Cert, db: &CaDb, rev_type: RevType, value: Option<&str>) -> i32 {
    let name = x509::name_oneline(x509.subject_name());
    let Some(bn) = x509.serial().and_then(|s| s.to_bn()) else {
        return -1;
    };
    let serial = if bn.is_zero() {
        Some("00".to_owned())
    } else {
        bn.to_hex()
    };
    let name = match (&name, &serial) {
        (Some(n), Some(s)) if n.is_empty() => Some(s.clone()),
        _ => name,
    };
    let (Some(name), Some(serial)) = (name, serial) else {
        eprintf!("Memory allocation failure\n");
        return -1;
    };
    let key = row(None, None, None, Some(&serial), None, Some(&name));
    let Some(r) = db.db.get_by_index(field::SERIAL, &key) else {
        eprintf!("Adding Entry with serial number {serial} to DB for {name}\n");
        let exp = x509
            .not_after()
            .map(|t| c_text(&t.data().0))
            .unwrap_or_default();
        let new = row(
            Some("V"),
            Some(&exp),
            None,
            Some(&serial),
            Some("unknown"),
            Some(&name),
        );
        if !db.db.insert(&new) {
            eprintf!("failed to update database\n");
            eprintf!("TXT_DB error number {}\n", db.db.error().0);
            return -1;
        }
        return if rev_type == RevType::Valid {
            1
        } else {
            do_revoke(x509, db, rev_type, value)
        };
    };
    if db.db.field_str(r, field::NAME).as_deref() != Some(name.as_str()) {
        eprintf!("ERROR:name does not match {name}\n");
        return -1;
    }
    if rev_type == RevType::Valid {
        eprintf!("ERROR:Already present, serial number {serial}\n");
        return -1;
    }
    if db.db.field(r, field::TYPE).and_then(|t| t.first().copied()) == Some(db_type::REV) {
        eprintf!("ERROR:Already revoked, serial number {serial}\n");
        return -1;
    }
    eprintf!(
        "Revoking Certificate {}.\n",
        db.db.field_str(r, field::SERIAL).unwrap_or_default()
    );
    let Some(rev_str) = make_revocation_str(rev_type, value) else {
        eprintf!("Error in revocation arguments\n");
        return -1;
    };
    if !db.db.set_field(r, field::TYPE, Some("R"))
        || !db.db.set_field(r, field::REV_DATE, Some(&rev_str))
    {
        return -1;
    }
    1
}

/// `get_certificate_status`: 1 if found (and known), -1 if not.
fn get_certificate_status(serial: &str, db: &CaDb) -> i32 {
    let mut s = if serial.len() % 2 == 1 {
        format!("0{serial}")
    } else {
        serial.to_owned()
    };
    s.make_ascii_uppercase();
    let key = row(None, None, None, Some(&s), None, None);
    let Some(r) = db.db.get_by_index(field::SERIAL, &key) else {
        eprintf!("Serial {s} not present in db.\n");
        return -1;
    };
    let t = db
        .db
        .field(r, field::TYPE)
        .and_then(|t| t.first().copied())
        .unwrap_or(0);
    let c = char::from(t);
    match t {
        db_type::VAL => eprintf!("{s}=Valid ({c})\n"),
        db_type::REV => eprintf!("{s}=Revoked ({c})\n"),
        db_type::EXP => eprintf!("{s}=Expired ({c})\n"),
        db_type::SUSP => eprintf!("{s}=Suspended ({c})\n"),
        _ => {
            eprintf!("{s}=Unknown ({c}).\n");
            return -1;
        }
    };
    1
}

/// `do_updatedb`: marks the valid entries that have expired; their number, or -1.
fn do_updatedb(db: &CaDb) -> i32 {
    let Some(a_tm) = Time::new() else {
        return -1;
    };
    if !a_tm.set_now() {
        return -1;
    }
    let mut cnt = 0;
    for i in 0..db.db.len() {
        if db.db.field(i, field::TYPE).and_then(|t| t.first().copied()) != Some(db_type::VAL) {
            continue;
        }
        let Some(exp_date) = Time::new() else {
            return -1;
        };
        let exp = db.db.field_str(i, field::EXP_DATE).unwrap_or_default();
        if !exp_date.set_string(&exp) {
            return -1;
        }
        if x509::time_compare(exp_date.as_ref(), a_tm.as_ref()) <= 0 {
            db.db.set_field(i, field::TYPE, Some("E"));
            cnt += 1;
            eprintf!(
                "{}=Expired\n",
                db.db.field_str(i, field::SERIAL).unwrap_or_default()
            );
        }
    }
    cnt
}

/// C's `atol`.
fn atol(s: &str) -> i64 {
    let t = s.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, t.get(1..).unwrap_or_default()),
        Some(b'+') => (false, t.get(1..).unwrap_or_default()),
        _ => (false, t),
    };
    let mut v: i64 = 0;
    for d in digits.bytes().take_while(u8::is_ascii_digit) {
        v = v.saturating_mul(10).saturating_add(i64::from(d - b'0'));
    }
    if neg { -v } else { v }
}

/// The checks `ca` makes of each database row; the message's row, if one fails.
fn check_db(db: &CaDb) -> bool {
    for i in 0..db.db.len() {
        let n = i + 1;
        let f = |k| db.db.field(i, k).unwrap_or_default();
        let t = f(field::TYPE).first().copied().unwrap_or(0);
        let rev = f(field::REV_DATE);
        if t != db_type::REV && rev.first().is_some_and(|&c| c != 0) {
            eprintf!("entry {n}: not revoked yet, but has a revocation date\n");
            return false;
        }
        if t == db_type::REV && make_revoked(None, &String::from_utf8_lossy(&rev)) == 0 {
            eprintf!(" in entry {n}\n");
            return false;
        }
        if !x509::time_set_string_check(&String::from_utf8_lossy(&f(field::EXP_DATE))) {
            eprintf!("entry {n}: invalid expiry date\n");
            return false;
        }
        let serial = f(field::SERIAL);
        let digits = serial.strip_prefix(b"-").unwrap_or(&serial);
        let j = digits.len();
        if j % 2 == 1 || j < 2 {
            eprintf!("entry {n}: bad serial number length ({j})\n");
            return false;
        }
        if let Some(&c) = digits.iter().find(|c| !c.is_ascii_hexdigit()) {
            // `%o` and `%c` of a C `char`.
            let v = c_char_value(c);
            let oct = format!("{:o}", u32::from_ne_bytes(v.to_ne_bytes()));
            eprintf!(
                "entry {n}: bad char 0{oct} '{}' in serial number\n",
                char::from(c)
            );
            return false;
        }
    }
    true
}

#[allow(clippy::too_many_lines)]
fn run(argv: &[String]) -> i32 {
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let mut configfile = ConfigFile::Default;
    let mut section: Option<String> = None;
    let (mut dgst, mut policy, mut keyfile): (Option<String>, Option<String>, Option<String>) =
        (None, None, None);
    let (mut certfile, mut crl_ext): (Option<String>, Option<String>) = (None, None);
    let (mut certformat, mut informat) = (format::UNDEF, format::UNDEF);
    let mut dateopt: c_ulong = ASN1_DTFLGS_RFC822;
    let (mut infile, mut spkac_file, mut ss_cert_file): (
        Option<String>,
        Option<String>,
        Option<String>,
    ) = (None, None, None);
    let (mut extensions, mut extfile, mut passinarg): (
        Option<String>,
        Option<String>,
        Option<String>,
    ) = (None, None, None);
    let mut passin: Option<String> = None;
    let (mut outdir, mut outfile, mut rev_arg, mut ser_status): (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = (None, None, None, None);
    let mut subj: Option<String> = None;
    let (mut startdate, mut enddate): (Option<String>, Option<String>) = (None, None);
    let (mut create_ser, mut batch, mut default_op, mut doupdatedb) = (false, false, true, false);
    let mut ext_copy = ExtCopy::None;
    let (mut keyformat, mut notext, mut output_der) = (format::UNDEF, false, false);
    let (mut email_dn, mut req, mut verbose, mut gencrl, mut dorevoke) =
        (true, false, false, false, 0);
    let (mut rand_ser, mut selfsign) = (false, false);
    let (mut crl_lastupdate, mut crl_nextupdate): (Option<String>, Option<String>) = (None, None);
    let (mut crldays, mut crlhours, mut crlsec, mut days): (i64, i64, i64, i64) = (0, 0, 0, 0);
    let (mut chtype, mut certopt) = (MBSTRING_ASC, 0 as c_ulong);
    let mut rev_type = RevType::None;
    let (mut sigopts, mut vfyopts): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    let mut preserve = false;
    let mut msie_hack = false;
    let mut engine = None;
    let opthelp = || {
        eprintf!("{prog}: Use -help for summary.\n");
        1
    };
    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::ERR => return opthelp(),
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::IN => {
                req = true;
                infile = Some(p.arg().to_owned());
            }
            Opt::INFORM => match opt::parse_format(p.arg(), fmt_flags::PEMDER) {
                Some(f) => informat = f,
                None => return opthelp(),
            },
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::DATEOPT => {
                if !set_dateopt(&mut dateopt, p.arg()) {
                    return opthelp();
                }
            }
            Opt::VERBOSE => verbose = true,
            Opt::QUIET => verbose = false,
            Opt::CONFIG => configfile = ConfigFile::Given(p.arg().to_owned()),
            Opt::NAME => section = Some(p.arg().to_owned()),
            Opt::SUBJ => subj = Some(p.arg().to_owned()),
            Opt::UTF8 => chtype = MBSTRING_UTF8,
            Opt::RAND_SERIAL => rand_ser = true,
            Opt::CREATE_SERIAL => create_ser = true,
            Opt::MULTIVALUE_RDN => {}
            Opt::STARTDATE | Opt::NOT_BEFORE => startdate = Some(p.arg().to_owned()),
            Opt::ENDDATE | Opt::NOT_AFTER => enddate = Some(p.arg().to_owned()),
            Opt::DAYS => days = i64::from(atoi(p.arg())),
            Opt::MD => dgst = Some(p.arg().to_owned()),
            Opt::POLICY => policy = Some(p.arg().to_owned()),
            Opt::KEYFILE => keyfile = Some(p.arg().to_owned()),
            Opt::KEYFORM => match opt::parse_format(p.arg(), fmt_flags::ANY) {
                Some(f) => keyformat = f,
                None => return opthelp(),
            },
            Opt::PASSIN => passinarg = Some(p.arg().to_owned()),
            Opt::OPT_R(o) => {
                if !app_rand::opt_rand(o, p.arg()) {
                    return 1;
                }
            }
            Opt::OPT_PROV(o) => {
                if !opt_provider(o, p.arg()) {
                    return 1;
                }
            }
            Opt::KEY => passin = Some(p.arg().to_owned()),
            Opt::CERT => certfile = Some(p.arg().to_owned()),
            Opt::CERTFORM => match opt::parse_format(p.arg(), fmt_flags::ANY) {
                Some(f) => certformat = f,
                None => return opthelp(),
            },
            Opt::SELFSIGN => selfsign = true,
            Opt::OUTDIR => outdir = Some(p.arg().to_owned()),
            Opt::SIGOPT => sigopts.push(p.arg().to_owned()),
            Opt::VFYOPT => vfyopts.push(p.arg().to_owned()),
            Opt::NOTEXT => notext = true,
            Opt::BATCH => batch = true,
            Opt::PRESERVEDN => preserve = true,
            Opt::NOEMAILDN => email_dn = false,
            Opt::GENCRL => gencrl = true,
            Opt::MSIE_HACK => msie_hack = true,
            Opt::CRL_LASTUPDATE => crl_lastupdate = Some(p.arg().to_owned()),
            Opt::CRL_NEXTUPDATE => crl_nextupdate = Some(p.arg().to_owned()),
            Opt::CRLDAYS => crldays = atol(p.arg()),
            Opt::CRLHOURS => crlhours = atol(p.arg()),
            Opt::CRLSEC => crlsec = atol(p.arg()),
            Opt::INFILES => {
                req = true;
                break;
            }
            Opt::SS_CERT => {
                ss_cert_file = Some(p.arg().to_owned());
                req = true;
            }
            Opt::SPKAC => {
                spkac_file = Some(p.arg().to_owned());
                req = true;
            }
            Opt::REVOKE => {
                infile = Some(p.arg().to_owned());
                dorevoke = 1;
            }
            Opt::VALID => {
                infile = Some(p.arg().to_owned());
                dorevoke = 2;
            }
            Opt::EXTENSIONS => extensions = Some(p.arg().to_owned()),
            Opt::EXTFILE => extfile = Some(p.arg().to_owned()),
            Opt::STATUS => ser_status = Some(p.arg().to_owned()),
            Opt::UPDATEDB => doupdatedb = true,
            Opt::CRLEXTS => crl_ext = Some(p.arg().to_owned()),
            Opt::CRL_REASON => {
                rev_arg = Some(p.arg().to_owned());
                rev_type = RevType::CrlReason;
            }
            Opt::CRL_HOLD => {
                rev_arg = Some(p.arg().to_owned());
                rev_type = RevType::Hold;
            }
            Opt::CRL_COMPROMISE => {
                rev_arg = Some(p.arg().to_owned());
                rev_type = RevType::KeyCompromise;
            }
            Opt::CRL_CA_COMPROMISE => {
                rev_arg = Some(p.arg().to_owned());
                rev_type = RevType::CaCompromise;
            }
            Opt::ENGINE => engine = setup_engine(Some(p.arg()), false),
        }
    }
    // The remaining arguments are requests to certify.
    let files: Vec<String> = p.rest().to_vec();

    let cfname = configfile.name().unwrap_or_default();
    let Some(conf) = app_load_config_verbose(&cfname, true) else {
        return 1;
    };
    if configfile != ConfigFile::Default && !app_load_modules(Some(&conf)) {
        return 1;
    }
    if section.is_none() {
        section = lookup_conf(&conf, Some(BASE_SECTION), ENV_DEFAULT_CA);
        if section.is_none() {
            return 1;
        }
    }
    let section = section.unwrap_or_default();
    let sect = Some(section.as_str());
    if let Some(f) = app_conf_try_string(&conf, None, "oid_file") {
        match Bio::new_file(&f, "r") {
            None => err::clear(),
            Some(b) => {
                x509::obj_create_objects(&b);
            }
        }
    }
    if !add_oid_section(&conf) {
        return 1;
    }
    app_rand::load_conf(&conf, Some(BASE_SECTION));
    if !app_rand::load() {
        return 1;
    }
    if let Some(m) = app_conf_try_string(&conf, sect, STRING_MASK)
        && !x509::set_default_mask_asc(&m)
    {
        eprintf!("Invalid global string mask setting {m}\n");
        return 1;
    }
    if chtype != MBSTRING_UTF8
        && app_conf_try_string(&conf, sect, UTF8_IN).is_some_and(|v| v == "yes")
    {
        chtype = MBSTRING_UTF8;
    }
    let mut unique_subject = true;
    if let Some(v) = app_conf_try_string(&conf, sect, ENV_UNIQUE_SUBJECT) {
        unique_subject = parse_yesno(Some(&v), true);
    }

    // The status of the certificate with the serial number given.
    if let Some(s) = &ser_status {
        let Some(dbfile) = lookup_conf(&conf, sect, ENV_DATABASE) else {
            return 1;
        };
        let Some(db) = load_index(&dbfile, unique_subject) else {
            eprintf!("Problem with index file: {dbfile} (could not load/parse file)\n");
            return 1;
        };
        if !index_index(&db) {
            return 1;
        }
        if get_certificate_status(s, &db) != 1 {
            eprintf!("Error verifying serial {s}!\n");
        }
        return 1;
    }

    // The private key.
    if keyfile.is_none() {
        keyfile = lookup_conf(&conf, sect, ENV_PRIVATE_KEY);
        if keyfile.is_none() {
            return 1;
        }
    }
    if passin.is_none() {
        let Some((pw, _)) = app_passwd(passinarg.as_deref(), None) else {
            eprintf!("Error getting password\n");
            return 1;
        };
        passin = pw.map(|p| p.as_str().to_owned());
    }
    let e = engine.as_ref();
    let pkey = load_key(
        keyfile.as_deref(),
        keyformat,
        false,
        passin.as_deref(),
        e,
        Some("CA private key"),
    );
    // `cleanse(passin)`: the password is all NULs from here on, an empty C string.
    if passin.is_some() {
        passin = Some(String::new());
    }
    let Some(pkey) = pkey else {
        return 1;
    };

    // The certificate.
    let mut x509: Option<Cert> = None;
    if !selfsign || spkac_file.is_some() || ss_cert_file.is_some() || gencrl {
        if certfile.is_none() {
            certfile = lookup_conf(&conf, sect, ENV_CERTIFICATE);
            if certfile.is_none() {
                return 1;
            }
        }
        x509 = load_cert_pass(
            certfile.as_deref(),
            certformat,
            true,
            passin.as_deref(),
            Some("CA certificate"),
        );
        let Some(x) = &x509 else {
            return 1;
        };
        if !x.check_private_key(&pkey) {
            eprintf!("CA certificate and CA private key do not match\n");
            return 1;
        }
    }
    let x509p = if selfsign { None } else { x509.as_ref() };

    if app_conf_try_string(&conf, Some(BASE_SECTION), ENV_PRESERVE)
        .is_some_and(|f| f.starts_with(['y', 'Y']))
    {
        preserve = true;
    }
    if app_conf_try_string(&conf, Some(BASE_SECTION), ENV_MSIE_HACK)
        .is_some_and(|f| f.starts_with(['y', 'Y']))
    {
        msie_hack = true;
    }
    if let Some(f) = app_conf_try_string(&conf, sect, ENV_NAMEOPT) {
        if !set_nameopt(Some(&f)) {
            eprintf!("Invalid name options: \"{f}\"\n");
            return 1;
        }
        default_op = false;
    }
    if let Some(f) = app_conf_try_string(&conf, sect, ENV_CERTOPT) {
        if !set_cert_ex(&mut certopt, Some(&f)) {
            eprintf!("Invalid certificate options: \"{f}\"\n");
            return 1;
        }
        default_op = false;
    }
    if let Some(f) = app_conf_try_string(&conf, sect, ENV_EXTCOPY) {
        match set_ext_copy(&f) {
            Some(c) => ext_copy = c,
            None => {
                eprintf!("Invalid extension copy option: \"{f}\"\n");
                return 1;
            }
        }
    }

    // Where the new certificates go.
    if outdir.is_none() && req {
        outdir = conf.get_string(sect, ENV_NEW_CERTS_DIR);
        let Some(d) = &outdir else {
            eprintf!("there needs to be defined a directory for new certificate to be placed in\n");
            return 1;
        };
        if opt::isdir(d) != Some(true) {
            eprintf!("{prog}: {d} is not a directory\n");
            perror(d);
            return 1;
        }
    }

    // The database.
    let Some(dbfile) = lookup_conf(&conf, sect, ENV_DATABASE) else {
        return 1;
    };
    let Some(db) = load_index(&dbfile, unique_subject) else {
        eprintf!("Problem with index file: {dbfile} (could not load/parse file)\n");
        return 1;
    };
    if !check_db(&db) {
        return 1;
    }
    if verbose {
        if let Some(b) = io::bio_out() {
            db.db.write(b);
        }
        eprintf!("{} entries loaded from the database\n", db.db.len());
        eprintf!("generating index\n");
    }
    if !index_index(&db) {
        return 1;
    }

    // Mark the expired certificates.
    if doupdatedb {
        if verbose {
            eprintf!("Updating {dbfile} ...\n");
        }
        let i = do_updatedb(&db);
        if i == -1 {
            eprintf!("Malloc failure\n");
            return 1;
        } else if i == 0 {
            if verbose {
                eprintf!("No entries found to mark expired\n");
            }
        } else {
            if !save_index(&dbfile, "new", &db) || !rotate_index(&dbfile, "new", "old") {
                return 1;
            }
            if verbose {
                eprintf!("Done. {i} entries marked as expired\n");
            }
        }
    }

    // The extensions file.
    let mut extfile_conf: Option<Conf> = None;
    if let Some(f) = &extfile {
        let Some(c) = app_load_config(Some(f)) else {
            return 1;
        };
        if verbose {
            eprintf!("Successfully loaded extensions file {f}\n");
        }
        if extensions.is_none() {
            extensions = Some(
                app_conf_try_string(&c, Some("default"), "extensions")
                    .unwrap_or_else(|| "default".to_owned()),
            );
        }
        extfile_conf = Some(c);
    }

    if (req || gencrl) && spkac_file.is_some() && outfile.is_some() {
        output_der = true;
        batch = true;
    }

    let (def_ret, def_dgst) = pkey.default_digest_name();
    if def_ret == 2 && def_dgst == "UNDEF" {
        dgst = None;
    } else {
        if dgst.is_none() {
            dgst = lookup_conf(&conf, sect, ENV_DEFAULT_MD);
            if dgst.is_none() && def_dgst != "UNDEF" {
                return 1;
            }
        }
        // C compares the NULL digest name too; with no name, the default digest is used.
        if dgst.as_deref().is_none_or(|d| d == "default") || def_dgst == "UNDEF" {
            if def_ret <= 0 {
                eprintf!("no default digest\n");
                return 1;
            }
            dgst = Some(def_dgst.clone());
        }
    }

    if req {
        if email_dn
            && app_conf_try_string(&conf, sect, ENV_DEFAULT_EMAIL_DN).is_some_and(|v| v == "no")
        {
            email_dn = false;
        }
        if verbose {
            eprintf!(
                "message digest is {}\n",
                dgst.as_deref().unwrap_or("(null)")
            );
        }
        if policy.is_none() {
            policy = lookup_conf(&conf, sect, ENV_POLICY);
            if policy.is_none() {
                return 1;
            }
        }
        let policy_name = policy.clone().unwrap_or_default();
        if verbose {
            eprintf!("policy is {policy_name}\n");
        }
        let mut serialfile: Option<String> = None;
        if app_conf_try_string(&conf, sect, ENV_RAND_SERIAL).is_some() {
            rand_ser = true;
        } else {
            serialfile = lookup_conf(&conf, sect, ENV_SERIAL);
            if serialfile.is_none() {
                return 1;
            }
        }
        if let Some(ec) = &extfile_conf {
            let ext = extensions.clone().unwrap_or_default();
            let mut ctx = V3Ctx::test();
            ctx.set_nconf(ec);
            if !ctx.add_nconf(ec, &ext, None) {
                eprintf!("Error checking certificate extensions from extfile section {ext}\n");
                return 1;
            }
        } else {
            if extensions.is_none() {
                extensions = app_conf_try_string(&conf, sect, ENV_EXTENSIONS);
            }
            if let Some(ext) = &extensions {
                let mut ctx = V3Ctx::test();
                ctx.set_nconf(&conf);
                if !ctx.add_nconf(&conf, ext, None) {
                    eprintf!("Error checking certificate extension config section {ext}\n");
                    return 1;
                }
            }
        }
        if startdate.is_none() {
            startdate = app_conf_try_string(&conf, sect, ENV_DEFAULT_STARTDATE);
        }
        if enddate.is_none() {
            enddate = app_conf_try_string(&conf, sect, ENV_DEFAULT_ENDDATE);
        }
        if days == 0 {
            days = app_conf_try_number(&conf, sect, ENV_DEFAULT_DAYS).unwrap_or(0);
        }
        if enddate.is_none() && days == 0 {
            eprintf!("cannot lookup how many days to certify for\n");
            return 1;
        }
        if days != 0 && enddate.is_some() {
            eprintf!("Warning: -enddate or -not_after option overriding -days option\n");
        }

        let serial: Bn = if rand_ser {
            match rand_serial() {
                Some((b, _)) => b,
                None => {
                    eprintf!("error generating serial number\n");
                    return 1;
                }
            }
        } else {
            let (s, _) = load_serial(serialfile.as_deref().unwrap_or_default(), create_ser);
            let Some((b, _)) = s else {
                eprintf!("error while loading serial number\n");
                return 1;
            };
            if verbose {
                if b.is_zero() {
                    eprintf!("next serial number is 00\n");
                } else {
                    let Some(h) = b.to_hex() else {
                        return 1;
                    };
                    eprintf!("next serial number is {h}\n");
                }
            }
            b
        };
        let Some(attribs) = conf.get_section(&policy_name) else {
            eprintf!("unable to find 'section' for {policy_name}\n");
            return 1;
        };
        let Some(cert_sk) = CertStack::new() else {
            eprintf!("Memory allocation failure\n");
            return 1;
        };
        let body = Body {
            pkey: &pkey,
            x509: x509.as_ref(),
            dgst: dgst.as_deref(),
            sigopts: &sigopts,
            vfyopts: &vfyopts,
            policy: &attribs,
            db: &db,
            subj: subj.as_deref(),
            chtype,
            email_dn,
            startdate: startdate.as_deref(),
            enddate: enddate.as_deref(),
            days,
            batch,
            ext_sect: extensions.as_deref(),
            conf: &conf,
            extfile_conf: extfile_conf.as_ref(),
            verbose,
            certopt,
            default_op,
            ext_copy,
            dateopt,
            preserve,
            msie_hack,
        };
        let (mut total, mut total_done) = (0, 0);
        let done = |j: i32, x: Option<Cert>, total_done: &mut i32| -> bool {
            if j < 0 {
                return false;
            }
            if j > 0 {
                *total_done += 1;
                eprintf!("\n");
                if !serial.add_word(1) {
                    return false;
                }
                if !x.is_some_and(|x| cert_sk.push(x)) {
                    eprintf!("Memory allocation failure\n");
                    return false;
                }
            }
            true
        };
        if let Some(f) = &spkac_file {
            total += 1;
            let (j, x) = certify_spkac(&body, f, &serial);
            if !done(j, x, &mut total_done) {
                return 1;
            }
        }
        if let Some(f) = &ss_cert_file {
            total += 1;
            let (j, x) = certify_cert(&body, f, certformat, passin.as_deref(), &serial);
            if !done(j, x, &mut total_done) {
                return 1;
            }
        }
        let with_ca = Body {
            x509: x509p,
            ..body
        };
        if let Some(f) = &infile {
            total += 1;
            let (j, x) = certify(&with_ca, f, informat, &serial, selfsign);
            if !done(j, x, &mut total_done) {
                return 1;
            }
        }
        for f in &files {
            total += 1;
            let (j, x) = certify(&with_ca, f, informat, &serial, selfsign);
            if !done(j, x, &mut total_done) {
                return 1;
            }
        }

        // The new certificates, and the database and serial number to update.
        if !cert_sk.is_empty() {
            if !batch {
                eprintf!(
                    "\n{total_done} out of {total} certificate requests certified, commit? [y/n]"
                );
                let Some(tmp) = fgets(11) else {
                    eprintf!("CERTIFICATION CANCELED: I/O error\n");
                    return 0;
                };
                if !matches!(tmp.first(), Some(b'y' | b'Y')) {
                    eprintf!("CERTIFICATION CANCELED\n");
                    return 0;
                }
            }
            eprintf!("Write out database with {} new entries\n", cert_sk.len());
            if let Some(sf) = &serialfile
                && save_serial(sf, Some("new"), &serial).is_none()
            {
                return 1;
            }
            if !save_index(&dbfile, "new", &db) {
                return 1;
            }
        }
        let outdir = outdir.clone().unwrap_or_default();
        if verbose {
            eprintf!("writing new certificates\n");
        }
        for i in 0..cert_sk.len() {
            let Some(xi) = cert_sk.get(i).and_then(|c| c.to_owned()) else {
                return 1;
            };
            let sn = xi.serial().map(|s| s.bytes()).unwrap_or_default();
            let name_len = 2 * sn.len().max(1) + ".pem".len() + 1;
            if outdir.len() + 1 + name_len > PATH_MAX {
                eprintf!("certificate file name too long\n");
                return 1;
            }
            let hex: String = if sn.is_empty() {
                "00".to_owned()
            } else {
                sn.iter().map(|b| format!("{b:02X}")).collect()
            };
            let new_cert = format!("{outdir}/{hex}.pem");
            if verbose {
                eprintf!("writing {new_cert}\n");
            }
            let fmt = if output_der {
                format::ASN1
            } else {
                format::TEXT
            };
            let Some(sout) = bio_open_default(outfile.as_deref(), 'w', fmt) else {
                return 1;
            };
            let Some(cout) = Bio::new_file(&new_cert, "w") else {
                perror(&new_cert);
                return 1;
            };
            write_new_certificate(&cout, &xi, false, notext);
            write_new_certificate(&sout, &xi, output_der, notext);
        }
        if !cert_sk.is_empty() {
            if let Some(sf) = &serialfile
                && !rotate_serial(sf, "new", "old")
            {
                return 1;
            }
            if !rotate_index(&dbfile, "new", "old") {
                return 1;
            }
            eprintf!("Database updated\n");
        }
    }

    if gencrl {
        let mut crl_v2 = false;
        if crl_ext.is_none() {
            crl_ext = app_conf_try_string(&conf, sect, ENV_CRLEXT);
        }
        if let Some(ce) = &crl_ext {
            let mut ctx = V3Ctx::test();
            ctx.set_nconf(&conf);
            if !ctx.add_nconf(&conf, ce, None) {
                eprintf!("Error checking CRL extension section {ce}\n");
                return 1;
            }
        }
        let crlnumberfile = app_conf_try_string(&conf, sect, ENV_CRLNUMBER);
        let mut crlnumber: Option<Bn> = None;
        if let Some(f) = &crlnumberfile {
            let (n, _) = load_serial(f, false);
            let Some((b, _)) = n else {
                eprintf!("error while loading CRL number\n");
                return 1;
            };
            crlnumber = Some(b);
        }
        if crldays == 0 && crlhours == 0 && crlsec == 0 {
            crldays = app_conf_try_number(&conf, sect, ENV_DEFAULT_CRL_DAYS).unwrap_or(0);
            crlhours = app_conf_try_number(&conf, sect, ENV_DEFAULT_CRL_HOURS).unwrap_or(0);
        }
        if crl_nextupdate.is_none() && crldays == 0 && crlhours == 0 && crlsec == 0 {
            eprintf!("cannot lookup how long until the next CRL is issued\n");
            return 1;
        }
        if verbose {
            eprintf!("making CRL\n");
        }
        let lc = libctx();
        let pq = propq();
        let Some(crl) = Crl::new_ex(lc.as_deref(), pq.as_deref()) else {
            return 1;
        };
        let Some(x) = &x509 else {
            return 1;
        };
        if !crl.set_issuer_name(x.subject_name()) {
            return 1;
        }
        if !set_crl_lastupdate(&crl, crl_lastupdate.as_deref()) {
            eprintf!("error setting CRL lastUpdate\n");
            return 1;
        }
        if !set_crl_nextupdate(&crl, crl_nextupdate.as_deref(), crldays, crlhours, crlsec) {
            eprintf!("error setting CRL nextUpdate\n");
            return 1;
        }
        for i in 0..db.db.len() {
            if db.db.field(i, field::TYPE).and_then(|t| t.first().copied()) != Some(db_type::REV) {
                continue;
            }
            let Some(r) = Revoked::new() else {
                return 1;
            };
            let rev = db.db.field_str(i, field::REV_DATE).unwrap_or_default();
            let j = make_revoked(Some(&r), &rev);
            if j == 0 {
                return 1;
            }
            if j == 2 {
                crl_v2 = true;
            }
            let ser = db.db.field_str(i, field::SERIAL).unwrap_or_default();
            let (bn, n) = Bn::hex2bn(&ser);
            let Some(bn) = bn.filter(|_| n != 0) else {
                return 1;
            };
            let Some(tmpser) = Integer::from_bn(&bn) else {
                return 1;
            };
            r.set_serial(&tmpser);
            crl.add0_revoked(r);
        }
        crl.sort();
        if verbose {
            eprintf!("signing CRL\n");
        }
        if crl_ext.is_some() || crlnumberfile.is_some() {
            let mut crlctx = V3Ctx::new(Some(x), None, None, Some(&crl), 0);
            crlctx.set_nconf(&conf);
            if let Some(ce) = &crl_ext
                && !crlctx.crl_add_nconf(&conf, ce, Some(&crl))
            {
                eprintf!("Error adding CRL extensions from section {ce}\n");
                return 1;
            }
            if let Some(n) = &crlnumber {
                let Some(tmpser) = Integer::from_bn(n) else {
                    return 1;
                };
                crl.add1_ext_integer(NID_crl_number, &tmpser, 0, 0);
                crl_v2 = true;
                if !n.add_word(1) {
                    return 1;
                }
            }
        }
        if (crl_ext.is_some() || crl_v2) && !crl.set_version(X509_CRL_VERSION_2.into()) {
            return 1;
        }
        if let (Some(f), Some(n)) = (&crlnumberfile, &crlnumber)
            && save_serial(f, Some("new"), n).is_none()
        {
            return 1;
        }
        if !do_x509_crl_sign(&crl, &pkey, dgst.as_deref(), &sigopts) {
            return 1;
        }
        let fmt = if output_der {
            format::ASN1
        } else {
            format::TEXT
        };
        let Some(sout) = bio_open_default(outfile.as_deref(), 'w', fmt) else {
            return 1;
        };
        crl.write_pem(&sout);
        if let Some(f) = &crlnumberfile
            && !rotate_serial(f, "new", "old")
        {
            return 1;
        }
    }

    if dorevoke != 0 {
        let Some(f) = &infile else {
            eprintf!("no input files\n");
            return 1;
        };
        let Some(revcert) = load_cert_pass(
            Some(f),
            informat,
            true,
            passin.as_deref(),
            Some("certificate to be revoked"),
        ) else {
            return 1;
        };
        if dorevoke == 2 {
            rev_type = RevType::Valid;
        }
        if do_revoke(&revcert, &db, rev_type, rev_arg.as_deref()) <= 0 {
            return 1;
        }
        if !save_index(&dbfile, "new", &db) || !rotate_index(&dbfile, "new", "old") {
            return 1;
        }
        eprintf!("Database updated\n");
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reference's source tree, when the live tests are on (`cargo xtask test-apps`).
    fn live() -> bool {
        std::env::var_os("RUSTYSSL_CLI_LIVE").is_some()
    }

    #[test]
    fn c_chars() {
        assert_eq!(c_char_value(b'A'), 65);
        let high = c_char_value(0xC3);
        assert!(high == 0xC3 || high == -61);
        assert_eq!(atol("12 "), 12);
        assert_eq!(c_text(b"ab\0cd"), "ab");
    }

    #[test]
    fn live_revinfo() {
        if !live() {
            return;
        }
        let i = unpack_revinfo("260101000000Z", true).unwrap();
        assert!(i.revtime.is_some());
        assert_eq!(i.reason, OCSP_REVOKED_STATUS_NOSTATUS);
        let i = unpack_revinfo("260101000000Z,keyTime,20250601000000Z", false).unwrap();
        assert_eq!(i.reason, OCSP_REVOKED_STATUS_KEYCOMPROMISE);
        assert!(i.revtime.is_none() && i.invtime.is_some());
        let i = unpack_revinfo("260101000000Z,holdInstruction,1.2.840.10040.2.2", true).unwrap();
        assert_eq!(i.reason, OCSP_REVOKED_STATUS_CERTIFICATEHOLD);
        assert!(i.hold.is_some());
        assert_eq!(
            unpack_revinfo("260101000000Z,removeFromCRL", true).map(|i| i.reason),
            Some(OCSP_REVOKED_STATUS_REMOVEFROMCRL)
        );
        let (r, err) = crate::lib::io::capture_err(|| {
            (
                unpack_revinfo("bad", true).is_none(),
                unpack_revinfo("260101000000Z,nope", true).is_none(),
                unpack_revinfo("260101000000Z,holdInstruction", true).is_none(),
                unpack_revinfo("260101000000Z,CAkeyTime,bad", true).is_none(),
            )
        });
        assert_eq!(r, (true, true, true, true));
        assert_eq!(
            String::from_utf8_lossy(&err),
            "invalid revocation date bad\ninvalid reason code nope\nmissing hold instruction\ninvalid compromised time bad\n"
        );
    }

    #[test]
    fn live_ca_database() {
        if !live() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("rustyssl-cli-ca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let index = dir.join("index.txt");
        let rows = "R\t350101000000Z\t260101000000Z,superseded\t10\tunknown\t/CN=a\nV\t210101000000Z\t\t0B\tunknown\t/CN=b\n";
        std::fs::write(&index, rows).unwrap();
        let file = index.display().to_string();
        let db = load_index(&file, true).unwrap();
        assert!(db.unique_subject);
        assert_eq!(db.db.len(), 2);
        assert!(check_db(&db));
        assert!(index_index(&db));
        // The serial index ignores leading zeros; the name index counts valid rows only.
        let key = |s: &'static str, n: &'static str| row(None, None, None, Some(s), None, Some(n));
        assert_eq!(
            db.db.get_by_index(field::SERIAL, &key("000B", "x")),
            Some(1)
        );
        assert_eq!(db.db.get_by_index(field::NAME, &key("", "/CN=b")), Some(1));
        assert_eq!(db.db.get_by_index(field::NAME, &key("", "/CN=a")), None);
        assert_eq!(get_certificate_status_quiet("B", &db), 1);
        assert!(db.db.insert(&row(
            Some("V"),
            Some("350101000000Z"),
            None,
            Some("0C"),
            Some("unknown"),
            Some("/CN=c")
        )));
        assert!(db.db.set_field(1, field::TYPE, Some("E")));
        assert!(save_index(&file, "new", &db));
        assert!(rotate_index(&file, "new", "old"));
        assert_eq!(
            std::fs::read_to_string(&index).unwrap(),
            "R\t350101000000Z\t260101000000Z,superseded\t10\tunknown\t/CN=a\nE\t210101000000Z\t\t0B\tunknown\t/CN=b\nV\t350101000000Z\t\t0C\tunknown\t/CN=c\n"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("index.txt.old")).unwrap(),
            rows
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("index.txt.attr")).unwrap(),
            "unique_subject = yes\n"
        );
        // The attributes file now says what a reload uses.
        std::fs::write(dir.join("index.txt.attr"), "unique_subject = no\n").unwrap();
        assert!(!load_index(&file, true).unwrap().unique_subject);
        // Serial files.
        let serial = dir.join("serial").display().to_string();
        std::fs::write(&serial, "0F\n").unwrap();
        let (s, exists) = load_serial(&serial, false);
        let (bn, _) = s.unwrap();
        assert!(exists);
        assert!(bn.add_word(1));
        assert!(save_serial(&serial, Some("new"), &bn).is_some());
        assert!(rotate_serial(&serial, "new", "old"));
        assert_eq!(std::fs::read_to_string(&serial).unwrap(), "10\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `get_certificate_status` without its message.
    fn get_certificate_status_quiet(s: &str, db: &CaDb) -> i32 {
        crate::lib::io::capture_err(|| get_certificate_status(s, db)).0
    }
}
