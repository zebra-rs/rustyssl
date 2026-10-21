//! `openssl verify` (`apps/verify.c`), with `apps.c`'s `policies_print` and
//! `store_setup_crl_download` and `app_x509.c`'s `x509_ctrl_string`.

use std::cell::Cell;
use std::io::Write;

use rustyssl_ossl::abi as a;
use rustyssl_ossl::verify::{self, CtxError, StoreCtxRef, VerifyCtx, VerifyParam};
use rustyssl_ossl::x509::{Cert, CertStack, CrlStack, Store};

use crate::generated::options::verify::{OPTIONS, Opt};
use crate::lib::app_libctx::opt_provider;
use crate::lib::apps::{
    get_nameopt, load_cert, load_certs, load_crl, load_crls, set_nameopt, setup_verify,
};
use crate::lib::engine::setup_engine;
use crate::lib::io;
use crate::lib::opt::{self, Parser, eprintf, format};

thread_local! {
    /// `v_verbose`.
    static VERBOSE: Cell<bool> = const { Cell::new(false) };
}

pub fn main(argv: &[String]) -> i32 {
    let ret = run(argv);
    if ret < 0 { 2 } else { ret }
}

fn run(argv: &[String]) -> i32 {
    let Some(vpm) = VerifyParam::new() else {
        return 1;
    };
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let (mut ca_path, mut ca_file, mut ca_store): (Option<String>, Option<String>, Option<String>) =
        (None, None, None);
    let (mut no_ca_path, mut no_ca_file, mut no_ca_store) = (false, false, false);
    let (mut vpmtouched, mut crl_download, mut show_chain) = (false, false, false);
    let mut untrusted: Option<CertStack> = None;
    let mut trusted: Option<CertStack> = None;
    let mut crls: Option<CrlStack> = None;
    let mut vfyopts: Vec<String> = Vec::new();
    let mut _engine = None;
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
                let mut e = io::err();
                let _ = e.write_all(b"\nRecognized certificate chain purposes:\n");
                for (sname, name) in verify::purposes() {
                    let _ = writeln!(e, "  {sname:<15}  {name}");
                }
                let _ = e.write_all(b"Recognized certificate policy names:\n");
                for name in verify::param_names() {
                    let _ = writeln!(e, "  {name}");
                }
                return 0;
            }
            Opt::OPT_V(o) => {
                if !opt::verify(o, p.arg(), (&vpm).into()) {
                    return 1;
                }
                vpmtouched = true;
            }
            Opt::CAPATH => ca_path = Some(p.arg().to_owned()),
            Opt::CAFILE => ca_file = Some(p.arg().to_owned()),
            Opt::CASTORE => ca_store = Some(p.arg().to_owned()),
            Opt::NOCAPATH => no_ca_path = true,
            Opt::NOCAFILE => no_ca_file = true,
            Opt::NOCASTORE => no_ca_store = true,
            Opt::UNTRUSTED => {
                let (ok, s) = load_certs(
                    Some(p.arg()),
                    false,
                    untrusted.take(),
                    None,
                    Some("untrusted certificates"),
                );
                untrusted = s;
                if !ok {
                    return 1;
                }
            }
            Opt::TRUSTED => {
                (no_ca_file, no_ca_path, no_ca_store) = (true, true, true);
                let (ok, s) = load_certs(
                    Some(p.arg()),
                    false,
                    trusted.take(),
                    None,
                    Some("trusted certificates"),
                );
                trusted = s;
                if !ok {
                    return 1;
                }
            }
            Opt::CRLFILE => {
                let (ok, s) = load_crls(Some(p.arg()), crls.take(), None, Some("other CRLs"));
                crls = s;
                if !ok {
                    return 1;
                }
            }
            Opt::CRL_DOWNLOAD => crl_download = true,
            Opt::ENGINE => match setup_engine(Some(p.arg()), false) {
                Some(e) => _engine = Some(e),
                None => return 1,
            },
            Opt::SHOW_CHAIN => show_chain = true,
            Opt::NAMEOPT => {
                if !set_nameopt(Some(p.arg())) {
                    return 1;
                }
            }
            Opt::VFYOPT => vfyopts.push(p.arg().to_owned()),
            Opt::VERBOSE => VERBOSE.with(|v| v.set(true)),
            Opt::OPT_PROV(o) => {
                if !opt_provider(o, p.arg()) {
                    return 1;
                }
            }
        }
    }
    let files: Vec<String> = p.rest().to_vec();

    if trusted.is_some() && (ca_file.is_some() || ca_path.is_some() || ca_store.is_some()) {
        eprintf!("{prog}: Cannot use -trusted with -CAfile, -CApath or -CAstore\n");
        return 1;
    }
    let Some(store) = setup_verify(
        ca_file.as_deref(),
        no_ca_file,
        ca_path.as_deref(),
        no_ca_path,
        ca_store.as_deref(),
        no_ca_store,
    ) else {
        return 1;
    };
    store.set_verify_cb(cb);
    if vpmtouched {
        store.set1_param(&vpm);
    }
    rustyssl_ossl::err::clear();
    if crl_download {
        store_setup_crl_download(&store);
    }

    let mut ret = 0;
    let lists = (untrusted.as_ref(), trusted.as_ref(), crls.as_ref());
    if files.is_empty() {
        if !check(&store, None, lists, show_chain, &vfyopts) {
            ret = -1;
        }
    } else {
        for f in &files {
            if !check(&store, Some(f), lists, show_chain, &vfyopts) {
                ret = -1;
            }
        }
    }
    ret
}

/// `check`: verifies one certificate (standard input for `None`); whether it is OK.
fn check(
    store: &Store,
    file: Option<&str>,
    (uchain, tchain, crls): (Option<&CertStack>, Option<&CertStack>, Option<&CrlStack>),
    show_chain: bool,
    opts: &[String],
) -> bool {
    let name = file.unwrap_or("stdin");
    let mut i = 0;
    let mut ret = false;
    if let Some(x) = load_cert(file, format::UNDEF, Some("certificate file")) {
        for opt in opts {
            if x509_ctrl_string(&x, opt) <= 0 {
                eprintf!("parameter error \"{opt}\"\n");
                io::print_errors();
                return false;
            }
        }
        store.set_flags(0);
        match VerifyCtx::new(store, Some(&x), uchain) {
            Err(CtxError::Alloc) => {
                eprintf!("error {name}: X.509 store context allocation failed\n");
            }
            Err(CtxError::Init) => {
                eprintf!("error {name}: X.509 store context initialization failed\n");
            }
            Ok(mut csc) => {
                if let Some(t) = tchain {
                    csc.set0_trusted_stack(t);
                }
                if let Some(c) = crls {
                    csc.set0_crls(c);
                }
                i = csc.verify_cert();
                let ctx = csc.as_ref();
                if i > 0 && ctx.error() == a::X509_V_OK {
                    let mut out = io::out();
                    let _ = writeln!(out, "{name}: OK");
                    ret = true;
                    if show_chain {
                        print_chain(ctx);
                    }
                } else {
                    eprintf!("error {name}: verification failed\n");
                }
            }
        }
    }
    if i <= 0 {
        io::print_errors();
    }
    ret
}

/// `-show_chain`'s lines.
fn print_chain(ctx: StoreCtxRef<'_>) {
    let mut out = io::out();
    let Some(bout) = io::bio_out() else {
        return;
    };
    let num_untrusted = usize::try_from(ctx.num_untrusted()).unwrap_or(0);
    let _ = out.write_all(b"Chain:\n");
    if let Some(chain) = ctx.chain() {
        for j in 0..chain.len() {
            let Some(cert) = chain.get(j) else {
                continue;
            };
            let _ = write!(out, "depth={j}: ");
            rustyssl_ossl::x509::name_print_ex(bout, cert.subject_name(), 0, get_nameopt());
            if j < num_untrusted {
                let _ = out.write_all(b" (untrusted)");
            }
            let _ = out.write_all(b"\n");
        }
    }
}

/// The errors `cb` lets the verification go on after.
const TOLERATED: &[core::ffi::c_int] = &[
    a::X509_V_ERR_NO_EXPLICIT_POLICY,
    a::X509_V_ERR_CERT_HAS_EXPIRED,
    a::X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
    a::X509_V_ERR_INVALID_CA,
    a::X509_V_ERR_INVALID_NON_CA,
    a::X509_V_ERR_PATH_LENGTH_EXCEEDED,
    a::X509_V_ERR_CRL_HAS_EXPIRED,
    a::X509_V_ERR_CRL_NOT_YET_VALID,
    a::X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION,
    a::X509_V_ERR_INVALID_PURPOSE,
    a::X509_V_ERR_PATHLEN_INVALID_FOR_NON_CA,
    a::X509_V_ERR_PATHLEN_WITHOUT_KU_KEY_CERT_SIGN,
    a::X509_V_ERR_CA_BCONS_NOT_CRITICAL,
    a::X509_V_ERR_CA_CERT_MISSING_KEY_USAGE,
    a::X509_V_ERR_KU_KEY_CERT_SIGN_INVALID_FOR_NON_CA,
    a::X509_V_ERR_ISSUER_NAME_EMPTY,
    a::X509_V_ERR_SUBJECT_NAME_EMPTY,
    a::X509_V_ERR_EMPTY_SUBJECT_SAN_NOT_CRITICAL,
    a::X509_V_ERR_EMPTY_SUBJECT_ALT_NAME,
    a::X509_V_ERR_SIGNATURE_ALGORITHM_INCONSISTENCY,
    a::X509_V_ERR_AUTHORITY_KEY_IDENTIFIER_CRITICAL,
    a::X509_V_ERR_SUBJECT_KEY_IDENTIFIER_CRITICAL,
    a::X509_V_ERR_MISSING_AUTHORITY_KEY_IDENTIFIER,
    a::X509_V_ERR_MISSING_SUBJECT_KEY_IDENTIFIER,
    a::X509_V_ERR_EXTENSIONS_REQUIRE_VERSION_3,
];

/// `cb`, the verification callback.
fn cb(ok: core::ffi::c_int, ctx: StoreCtxRef<'_>) -> core::ffi::c_int {
    let cert_error = ctx.error();
    if ok == 0 {
        if let Some(cur) = ctx.current_cert()
            && let Some(berr) = io::bio_err()
        {
            rustyssl_ossl::x509::name_print_ex(berr, cur.subject_name(), 0, get_nameopt());
            eprintf!("\n");
        }
        eprintf!(
            "{}error {cert_error} at {} depth lookup: {}\n",
            if ctx.has_parent() { "[CRL path] " } else { "" },
            ctx.error_depth(),
            verify::verify_cert_error_string(cert_error.into())
        );
        if cert_error == a::X509_V_ERR_NO_EXPLICIT_POLICY {
            policies_print(ctx);
        }
        return i32::from(TOLERATED.contains(&cert_error));
    }
    if cert_error == a::X509_V_OK && ok == 2 {
        policies_print(ctx);
    }
    if !VERBOSE.with(Cell::get) {
        rustyssl_ossl::err::clear();
    }
    ok
}

/// `policies_print` of `apps.c`, to standard error.
pub fn policies_print(ctx: StoreCtxRef<'_>) {
    let explicit = if ctx.explicit_policy() {
        "True"
    } else {
        "False"
    };
    eprintf!("Require explicit Policy: {explicit}\n");
    for (name, user) in [("Authority", false), ("User", true)] {
        eprintf!("{name} Policies:");
        let printed = io::bio_err().and_then(|b| ctx.print_policy_nodes(user, b, 2));
        if printed.is_none() {
            eprintf!(" <empty>\n");
        }
    }
}

/// `store_setup_crl_download` of `apps.c`: CRLs fetched from the certificates' distribution
/// points (`http://` only).
pub fn store_setup_crl_download(store: &Store) {
    store.set_lookup_crls_cb(crls_http_cb);
}

/// `load_crl_crldp`: the CRL at the first distribution point with an HTTP URL.
fn load_crl_crldp(urls: &[Option<String>]) -> Option<rustyssl_ossl::x509::Crl> {
    let url = urls.iter().flatten().next()?;
    load_crl(Some(url), format::UNDEF, false, Some("CRL via CDP"))
}

/// `crls_http_cb`.
fn crls_http_cb(ctx: StoreCtxRef<'_>) -> Option<CrlStack> {
    let crls = CrlStack::new()?;
    let x = ctx.current_cert()?;
    let crl = load_crl_crldp(&x.dp_http_urls(a::NID_crl_distribution_points))?;
    if !crls.push(crl) {
        return None;
    }
    // A delta CRL, if there is one.
    if let Some(crl) = load_crl_crldp(&x.dp_http_urls(a::NID_freshest_crl))
        && !crls.push(crl)
    {
        return None;
    }
    Some(crls)
}

/// `x509_ctrl_string` of `app_x509.c`: `distid:` or `hexdistid:` for the certificate.
fn x509_ctrl_string(x: &Cert, value: &str) -> i32 {
    let (name, v) = match value.split_once(':') {
        Some((n, v)) => (n, Some(v)),
        None => (value, None),
    };
    let id: Vec<u8> = match name {
        "distid" => v.unwrap_or_default().as_bytes().to_vec(),
        // A failed conversion sets an empty ID, as upstream's NULL value does.
        "hexdistid" => v
            .map(|h| rustyssl_ossl::crypto::hexstr2buf(h).unwrap_or_default())
            .unwrap_or_default(),
        _ => return -2,
    };
    if x.set_distinguishing_id(&id) {
        1
    } else {
        eprintf!("error: setting distinguishing ID in certificate failed\n");
        0
    }
}
