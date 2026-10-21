//! `openssl storeutl` (`apps/storeutl.c`).

use std::io::Write;

use rustyssl_ossl::abi::{
    MBSTRING_UTF8, OSSL_STORE_INFO_CERT, OSSL_STORE_INFO_CRL, OSSL_STORE_INFO_NAME,
    OSSL_STORE_INFO_PARAMS, OSSL_STORE_INFO_PKEY, OSSL_STORE_INFO_PUBKEY,
    OSSL_STORE_SEARCH_BY_ALIAS, OSSL_STORE_SEARCH_BY_ISSUER_SERIAL,
    OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT, OSSL_STORE_SEARCH_BY_NAME,
};
use rustyssl_ossl::store::{self, Search, Store};
use rustyssl_ossl::ui::Passphrase;
use rustyssl_ossl::x509::{Integer, Name};
use rustyssl_ossl::{Bio, err};

use crate::generated::options::storeutl::{OPTIONS, Opt};
use crate::lib::app_libctx::{libctx, opt_provider, propq};
use crate::lib::apps::{app_passwd, bio_open_default, parse_name};
use crate::lib::engine::setup_engine;
use crate::lib::io;
use crate::lib::opt::{self, Parser, eprintf, format};

/// What `process` is asked to do, the same for every level of the recursion.
struct Job<'a> {
    uidata: &'a Passphrase,
    expected: i32,
    criterion: i32,
    search: Option<&'a Search>,
    text: bool,
    noout: bool,
    recursive: bool,
    outfile: Option<&'a str>,
    prog: &'a str,
}

pub fn main(argv: &[String]) -> i32 {
    let mut p = Parser::with_unknown(argv, OPTIONS, Some("digest"));
    let prog = p.prog();
    let (mut noout, mut text, mut recursive) = (false, false, false);
    let (mut outfile, mut passinarg): (Option<String>, Option<String>) = (None, None);
    let (mut expected, mut criterion) = (0, 0);
    let (mut subject, mut issuer): (Option<Name>, Option<Name>) = (None, None);
    let mut serial: Option<Integer> = None;
    let mut fingerprint: Option<Vec<u8>> = None;
    let mut alias: Option<std::ffi::CString> = None;
    let mut digestname: Option<String> = None;
    let mut _engine = None;
    let opthelp = || {
        eprintf!("{prog}: Use -help for summary.\n");
        1
    };
    loop {
        let o = p.next();
        match o {
            Opt::EOF => break,
            Opt::ERR => return opthelp(),
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::PASSIN => passinarg = Some(p.arg().to_owned()),
            Opt::NOOUT => noout = true,
            Opt::TEXT => text = true,
            Opt::RECURSIVE => recursive = true,
            Opt::SEARCHFOR_CERTS | Opt::SEARCHFOR_KEYS | Opt::SEARCHFOR_CRLS => {
                if expected != 0 {
                    eprintf!("{prog}: only one search type can be given.\n");
                    return 1;
                }
                expected = match o {
                    Opt::SEARCHFOR_CERTS => OSSL_STORE_INFO_CERT,
                    Opt::SEARCHFOR_KEYS => OSSL_STORE_INFO_PKEY,
                    _ => OSSL_STORE_INFO_CRL,
                };
            }
            Opt::CRITERION_SUBJECT => {
                if criterion != 0 {
                    eprintf!("{prog}: criterion already given.\n");
                    return 1;
                }
                criterion = OSSL_STORE_SEARCH_BY_NAME;
                if subject.is_some() {
                    eprintf!("{prog}: subject already given.\n");
                    return 1;
                }
                subject = parse_name(p.arg(), MBSTRING_UTF8, true, "subject");
                if subject.is_none() {
                    return 1;
                }
            }
            Opt::CRITERION_ISSUER => {
                if criterion != 0 && criterion != OSSL_STORE_SEARCH_BY_ISSUER_SERIAL {
                    eprintf!("{prog}: criterion already given.\n");
                    return 1;
                }
                criterion = OSSL_STORE_SEARCH_BY_ISSUER_SERIAL;
                if issuer.is_some() {
                    eprintf!("{prog}: issuer already given.\n");
                    return 1;
                }
                issuer = parse_name(p.arg(), MBSTRING_UTF8, true, "issuer");
                if issuer.is_none() {
                    return 1;
                }
            }
            Opt::CRITERION_SERIAL => {
                if criterion != 0 && criterion != OSSL_STORE_SEARCH_BY_ISSUER_SERIAL {
                    eprintf!("{prog}: criterion already given.\n");
                    return 1;
                }
                criterion = OSSL_STORE_SEARCH_BY_ISSUER_SERIAL;
                if serial.is_some() {
                    eprintf!("{prog}: serial number already given.\n");
                    return 1;
                }
                serial = Integer::from_dec_or_hex(p.arg());
                if serial.is_none() {
                    eprintf!("{prog}: can't parse serial number argument.\n");
                    return 1;
                }
            }
            Opt::CRITERION_FINGERPRINT => {
                if criterion != 0 {
                    eprintf!("{prog}: criterion already given.\n");
                    return 1;
                }
                criterion = OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT;
                if fingerprint.is_some() {
                    eprintf!("{prog}: fingerprint already given.\n");
                    return 1;
                }
                fingerprint = rustyssl_ossl::crypto::hexstr2buf(p.arg());
                if fingerprint.is_none() {
                    eprintf!("{prog}: can't parse fingerprint argument.\n");
                    return 1;
                }
            }
            Opt::CRITERION_ALIAS => {
                if criterion != 0 {
                    eprintf!("{prog}: criterion already given.\n");
                    return 1;
                }
                criterion = OSSL_STORE_SEARCH_BY_ALIAS;
                if alias.is_some() {
                    eprintf!("{prog}: alias already given.\n");
                    return 1;
                }
                alias = std::ffi::CString::new(p.arg()).ok();
                if alias.is_none() {
                    eprintf!("{prog}: can't parse alias argument.\n");
                    return 1;
                }
            }
            Opt::ENGINE => _engine = setup_engine(Some(p.arg()), false),
            Opt::MD => digestname = p.unknown().map(str::to_owned),
            Opt::OPT_PROV(o) => {
                if !opt_provider(o, p.arg()) {
                    return 1;
                }
            }
        }
    }
    if !p.check_rest_arg(Some("URI")) {
        return opthelp();
    }
    let uri = p.rest().first().cloned().unwrap_or_default();
    let digest = match &digestname {
        None => None,
        Some(n) => match opt::md(n) {
            Some(m) => Some(m),
            None => return opthelp(),
        },
    };

    let search = match criterion {
        0 => None,
        OSSL_STORE_SEARCH_BY_NAME => subject.as_ref().and_then(Search::by_name),
        OSSL_STORE_SEARCH_BY_ISSUER_SERIAL => {
            let (Some(i), Some(s)) = (&issuer, &serial) else {
                eprintf!("{prog}: both -issuer and -serial must be given.\n");
                return 1;
            };
            Search::by_issuer_serial(i, s)
        }
        OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT => {
            Search::by_key_fingerprint(digest.as_ref(), fingerprint.as_deref().unwrap_or_default())
        }
        _ => alias.as_deref().and_then(Search::by_alias),
    };
    if criterion != 0 && search.is_none() {
        io::print_errors();
        return 1;
    }

    let Some((passin, _)) = app_passwd(passinarg.as_deref(), None) else {
        eprintf!("Error getting passwords\n");
        return 1;
    };
    let uidata = Passphrase::new(passin.as_ref().map(|p| p.as_str()), Some(&uri));
    let job = Job {
        uidata: &uidata,
        expected,
        criterion,
        search: search.as_ref(),
        text,
        noout,
        recursive,
        outfile: outfile.as_deref(),
        prog: &prog,
    };
    let mut out = None;
    process(&uri, &job, 0, &mut out)
}

/// `indent_printf`, to `bio` (nothing for `None`, as `BIO_printf(NULL, ...)`).
fn indent_printf(indent: usize, bio: Option<&Bio>, text: &str) {
    if let Some(b) = bio {
        let _ = b.write_all(format!("{:indent$}{text}", "").as_bytes());
    }
}

/// `process`: the number of errors.
fn process(uri: &str, job: &Job<'_>, indent: usize, out: &mut Option<Bio>) -> i32 {
    let lc = libctx();
    let pq = propq();
    let Some(store_ctx) = Store::open_plain(uri, lc.as_deref(), pq.as_deref(), job.uidata) else {
        eprintf!("Couldn't open file or uri {uri}\n");
        io::print_errors();
        return 1;
    };
    let mut ret = 1;
    let body = |ret: &mut i32, out: &mut Option<Bio>| {
        if job.expected != 0 && !store_ctx.expect(job.expected) {
            io::print_errors();
            return;
        }
        if job.criterion != 0 {
            if !store_ctx.supports_search(job.criterion) {
                eprintf!(
                    "{}: the store scheme doesn't support the given search criteria.\n",
                    job.prog
                );
                return;
            }
            if !job.search.is_some_and(|s| store_ctx.find(s)) {
                io::print_errors();
                return;
            }
        }
        // From here on, the errors are counted.
        *ret = 0;
        let mut items = 0;
        loop {
            let Some(info) = store_ctx.load() else {
                if store_ctx.error() {
                    if job.recursive {
                        err::clear();
                    } else {
                        io::print_errors();
                    }
                    if store_ctx.eof() {
                        break;
                    }
                    *ret += 1;
                    continue;
                }
                if store_ctx.eof() {
                    break;
                }
                eprintf!(
                    "ERROR: OSSL_STORE_load() returned NULL without eof or error indications\n"
                );
                eprintf!("       This is an error in the loader\n");
                io::print_errors();
                *ret += 1;
                break;
            };
            let kind = info.kind();
            let infostr = store::type_string(kind).unwrap_or_else(|| "(null)".to_owned());
            if kind == OSSL_STORE_INFO_NAME {
                let name = info.name().unwrap_or_else(|| "(null)".to_owned());
                indent_printf(
                    indent,
                    io::bio_out(),
                    &format!("{items}: {infostr}: {name}\n"),
                );
                if let Some(desc) = info.name_description() {
                    indent_printf(indent, io::bio_out(), &format!("{desc}\n"));
                }
            } else {
                indent_printf(indent, io::bio_out(), &format!("{items}: {infostr}\n"));
            }
            if out.is_none() {
                *out = bio_open_default(job.outfile, 'w', format::TEXT);
                if out.is_none() {
                    *ret += 1;
                    return;
                }
            }
            let Some(o) = out.as_ref() else {
                return;
            };
            match kind {
                OSSL_STORE_INFO_NAME => {
                    if job.recursive
                        && let Some(suburi) = info.name()
                    {
                        *ret += process(&suburi, job, indent + 2, out);
                    }
                }
                OSSL_STORE_INFO_PARAMS => {
                    if let Some(k) = info.params() {
                        if job.text {
                            k.print_params(o, 0);
                        }
                        if !job.noout {
                            k.write_params_pem(o);
                        }
                    }
                }
                OSSL_STORE_INFO_PUBKEY => {
                    if let Some(k) = info.pubkey() {
                        if job.text {
                            k.print_public(o, 0);
                        }
                        if !job.noout {
                            k.write_pubkey_pem(o);
                        }
                    }
                }
                OSSL_STORE_INFO_PKEY => {
                    if let Some(k) = info.pkey() {
                        if job.text {
                            k.print_private(o, 0);
                        }
                        if !job.noout {
                            k.write_private_pem(o);
                        }
                    }
                }
                OSSL_STORE_INFO_CERT => {
                    if let Some(c) = info.cert() {
                        if job.text {
                            c.print(o);
                        }
                        if !job.noout {
                            c.write_pem(o);
                        }
                    }
                }
                OSSL_STORE_INFO_CRL => {
                    if let Some(c) = info.crl() {
                        if job.text {
                            c.print(o);
                        }
                        if !job.noout {
                            c.write_pem(o);
                        }
                    }
                }
                _ => {
                    eprintf!("!!! Unknown code\n");
                    *ret += 1;
                }
            }
            items += 1;
        }
        indent_printf(indent, out.as_ref(), &format!("Total found: {items}\n"));
    };
    body(&mut ret, out);
    if !store_ctx.close() {
        io::print_errors();
        ret += 1;
    }
    let _ = io::out().flush();
    ret
}
