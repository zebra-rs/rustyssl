//! The shared helpers on a real library: these run only when `RUSTYSSL_CLI_LIVE` names the
//! reference's source tree (for its test files), with the library path pointing at a build
//! of the libraries. `cargo xtask test-apps` runs them on the reference's and on rustyssl's.
//! The expected texts are upstream's (`apps/lib/apps.c`), as its commands print them.

use std::io::Write as _;
use std::path::PathBuf;

use rustyssl_ossl::verify::{ParamRef, VerifyParam};

use super::apps::{self, Wanted};
use super::io;
use super::opt::{self, format, progname};
use crate::generated::options::V;

/// The reference's `test/` directory, when the live tests are on.
fn live() -> Option<PathBuf> {
    let src = std::env::var_os("RUSTYSSL_CLI_LIVE")?;
    let _ = rustyssl_ossl::ui::setup();
    Some(PathBuf::from(src).join("test"))
}

fn path(dir: &std::path::Path, file: &str) -> String {
    dir.join(file).display().to_string()
}

/// The text with error-queue lines reduced to their reason (`lib:func:reason`).
fn reasons(text: &[u8]) -> String {
    String::from_utf8_lossy(text)
        .lines()
        .map(|l| match l.split_once(":error:") {
            Some((_, rest)) => {
                let parts: Vec<&str> = rest.split(':').collect();
                format!(
                    "error:{}",
                    parts.get(1..4).map(|p| p.join(":")).unwrap_or_default()
                )
            }
            None => l.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn live_passwords() {
    let Some(_) = live() else { return };
    progname("x");
    let (p, _) = apps::app_passwd(Some("pass:secret"), None).unwrap();
    assert_eq!(p.unwrap().as_str(), "secret");
    let dir = std::env::temp_dir().join(format!("rustyssl-cli-live-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("pw.txt");
    std::fs::write(&file, "first\nsecond\n").unwrap();
    let arg = format!("file:{}", file.display());
    // The same source for both: two lines of one file.
    let (a, b) = apps::app_passwd(Some(&arg), Some(&arg)).unwrap();
    assert_eq!(
        (a.unwrap().as_str(), b.unwrap().as_str()),
        ("first", "second")
    );
    // Different sources: each from its first line.
    let (a, b) = apps::app_passwd(Some(&arg), Some("pass:x")).unwrap();
    assert_eq!((a.unwrap().as_str(), b.unwrap().as_str()), ("first", "x"));
    let (r, e) = io::capture_err(|| apps::app_passwd(Some("bogus"), None).is_none());
    assert!(r);
    assert_eq!(
        String::from_utf8(e).unwrap(),
        "Invalid password argument, missing ':' within the first 5 chars\n"
    );
    let (r, e) = io::capture_err(|| apps::app_passwd(Some("nope:x"), None).is_none());
    assert!(r);
    assert_eq!(
        String::from_utf8(e).unwrap(),
        "Invalid password argument, starting with \"nope:\"\n"
    );
    let (r, e) = io::capture_err(|| apps::app_passwd(Some("toolong:x"), None).is_none());
    assert!(r);
    assert!(
        String::from_utf8(e)
            .unwrap()
            .contains("missing ':' within the first 5 chars")
    );
    let (r, e) =
        io::capture_err(|| apps::app_passwd(Some("env:RUSTYSSL_CLI_NO_SUCH_VAR"), None).is_none());
    assert!(r);
    assert_eq!(
        String::from_utf8(e).unwrap(),
        "No environment variable RUSTYSSL_CLI_NO_SUCH_VAR\n"
    );
    let (r, e) = io::capture_err(|| apps::app_passwd(Some("file:/nonexistent/pw"), None).is_none());
    assert!(r);
    assert_eq!(
        String::from_utf8(e).unwrap(),
        "Can't open file /nonexistent/pw\n"
    );
    let (r, e) = io::capture_err(|| apps::app_passwd(Some("fd:-1"), None).is_none());
    assert!(r);
    assert_eq!(
        String::from_utf8(e).unwrap(),
        "Can't access file descriptor -1\n"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn live_load_key_messages() {
    let Some(test) = live() else { return };
    progname("pkey");
    let (k, e) = io::capture_err(|| {
        apps::load_key(
            Some("/nonexistent/k"),
            format::UNDEF,
            false,
            None,
            None,
            Some("key"),
        )
    });
    assert!(k.is_none());
    assert_eq!(
        reasons(&e).lines().next().unwrap(),
        "Could not open file or uri for loading private key of key from /nonexistent/k: No such file or directory"
    );
    let enc = path(&test, "certs/key-pass-12345.pem");
    let (k, e) = io::capture_err(|| {
        apps::load_key(
            Some(&enc),
            format::UNDEF,
            false,
            Some("bad"),
            None,
            Some("key"),
        )
    });
    assert!(k.is_none());
    let e = reasons(&e);
    assert!(
        e.starts_with(&format!("Could not find private key of key from {enc}\n")),
        "{e}"
    );
    assert!(e.contains("bad decrypt"), "{e}");
    let (k, _) = io::capture_err(|| {
        apps::load_key(
            Some(&enc),
            format::UNDEF,
            false,
            Some("12345"),
            None,
            Some("key"),
        )
    });
    assert!(k.is_some());
    let cert = path(&test, "testx509.pem");
    let (k, e) = io::capture_err(|| {
        apps::load_key(Some(&cert), format::PEM, false, None, None, Some("key"))
    });
    assert!(k.is_none());
    assert_eq!(
        reasons(&e),
        format!("Could not find private key of key from {cert}")
    );
    // A private key's public half.
    let (k, e) = io::capture_err(|| {
        apps::load_pubkey(
            Some(&path(&test, "testrsa.pem")),
            format::PEM,
            false,
            None,
            None,
            None,
        )
    });
    assert!(k.is_some(), "{}", reasons(&e));
}

#[test]
fn live_certs_and_crls() {
    let Some(test) = live() else { return };
    progname("x509");
    let c = apps::load_cert(Some(&path(&test, "testx509.pem")), format::UNDEF, None);
    assert!(c.is_some());
    let (ok, certs) = apps::load_certs(
        Some(&path(&test, "certs/ee-cert.pem")),
        false,
        None,
        None,
        None,
    );
    assert!(ok);
    assert_eq!(certs.unwrap().len(), 1);
    let crl = apps::load_crl(
        Some(&path(&test, "testcrl.pem")),
        format::UNDEF,
        false,
        None,
    );
    assert!(crl.is_some());
    let (ok, crls) = apps::load_crls(Some(&path(&test, "testcrl.pem")), None, None, None);
    assert!(ok);
    assert_eq!(crls.unwrap().len(), 1);
    let (r, e) = io::capture_err(|| {
        apps::load_certs(Some(&path(&test, "testrsa.pem")), false, None, None, None)
    });
    assert!(!r.0);
    assert_eq!(
        reasons(&e),
        format!(
            "Could not find certificates from {}\nerror:STORE routines:ossl_store_handle_load_result:unsupported",
            path(&test, "testrsa.pem")
        )
    );
    let (r, e) = io::capture_err(|| {
        apps::load_key_certs_crls(None, 0, false, None, None, false, Wanted::default())
    });
    assert!(!r.0);
    assert_eq!(
        String::from_utf8(e).unwrap(),
        "Internal error: nothing was requested to load from <stdin>\n"
    );
    let req = apps::load_csr(
        Some(&path(&test, "testreq2.pem")),
        format::UNDEF,
        Some("request"),
    );
    assert!(req.is_some());
    let (req, e) = io::capture_err(|| {
        apps::load_csr_autofmt(
            Some(&path(&test, "testreq2.pem")),
            format::UNDEF,
            &[],
            "request",
        )
    });
    assert!(req.is_some(), "{}", reasons(&e));
}

#[test]
fn live_names() {
    let Some(test) = live() else { return };
    progname("req");
    let n = apps::parse_name(
        "/CN=a/O=b\\/c+OU=d",
        rustyssl_ossl::abi::MBSTRING_ASC,
        true,
        "subject",
    )
    .unwrap();
    assert_eq!(
        rustyssl_ossl::x509::name_oneline(n.as_name()).unwrap(),
        "/CN=a/O=b\\/c+OU=d"
    );
    let (n, e) = io::capture_err(|| {
        apps::parse_name(
            "/CN=a/XX=1/C=",
            rustyssl_ossl::abi::MBSTRING_ASC,
            false,
            "subject",
        )
    });
    assert_eq!(
        rustyssl_ossl::x509::name_oneline(n.unwrap().as_name()).unwrap(),
        "/CN=a"
    );
    assert_eq!(
        String::from_utf8(e).unwrap(),
        "req warning: Skipping unknown subject name attribute \"XX\"\n\
         req warning: No value provided for subject name attribute \"C\", skipped\n"
    );
    let (n, e) = io::capture_err(|| {
        apps::parse_name("CN=a", rustyssl_ossl::abi::MBSTRING_ASC, false, "subject")
    });
    assert!(n.is_none());
    assert!(
        String::from_utf8(e)
            .unwrap()
            .ends_with("This name is not in that format: 'CN=a'\n")
    );
    let (n, e) = io::capture_err(|| {
        apps::parse_name("/CN", rustyssl_ossl::abi::MBSTRING_ASC, false, "subject")
    });
    assert!(n.is_none());
    assert_eq!(
        String::from_utf8(e).unwrap(),
        "req: Missing '=' after RDN type string 'CN' in subject name string\n"
    );
    let (n, e) = io::capture_err(|| {
        apps::parse_name(
            "/CN=a\\",
            rustyssl_ossl::abi::MBSTRING_ASC,
            false,
            "subject",
        )
    });
    assert!(n.is_none());
    assert_eq!(
        String::from_utf8(e).unwrap(),
        "req: Escape character at end of subject name string\n"
    );

    // print_name with -nameopt multiline, and the default.
    let cert = apps::load_cert(Some(&path(&test, "testx509.pem")), format::UNDEF, None).unwrap();
    let out = rustyssl_ossl::Bio::new_mem().unwrap();
    apps::print_name(&out, Some("subject="), cert.subject_name());
    assert_eq!(
        String::from_utf8(out.read_to_end()).unwrap(),
        "subject=C=AU, ST=QLD, CN=SSLeay rsa test cert\n"
    );
    assert!(apps::set_nameopt(Some("multiline")));
    apps::print_name(&out, Some("subject="), cert.subject_name());
    assert_eq!(
        String::from_utf8(out.read_to_end()).unwrap(),
        "subject=\n    countryName               = AU\n    stateOrProvinceName       = QLD\n    commonName                = SSLeay rsa test cert\n"
    );
    let mut flags = 0;
    assert!(!apps::set_name_ex(&mut flags, Some("nosuch")));
    let mut flags = 0;
    assert!(apps::set_cert_ex(&mut flags, Some("no_header, no_version")));
    assert_eq!(flags, 3);
}

#[test]
fn live_ciphers_digests_and_verify_options() {
    let Some(test) = live() else { return };
    progname("enc");
    assert!(opt::cipher("aes-128-cbc").is_some());
    let (c, e) = io::capture_err(|| opt::cipher("aes-128-gcm"));
    assert!(c.is_none());
    assert_eq!(
        String::from_utf8(e).unwrap(),
        "enc: AEAD ciphers not supported\n"
    );
    let (c, e) = io::capture_err(|| opt::cipher("aes-128-xts"));
    assert!(c.is_none());
    assert_eq!(
        String::from_utf8(e).unwrap(),
        "enc XTS ciphers not supported\n"
    );
    let (c, e) = io::capture_err(|| opt::cipher("nosuch"));
    assert!(c.is_none());
    assert_eq!(
        String::from_utf8(e).unwrap(),
        "enc: Unknown option or cipher: nosuch\n"
    );
    assert!(opt::md("SHA256").is_some());
    let (m, e) = io::capture_err(|| opt::md("nosuch"));
    assert!(m.is_none());
    assert_eq!(
        String::from_utf8(e).unwrap(),
        "enc: Unknown option or message digest: nosuch\n"
    );

    progname("verify");
    let vpm = VerifyParam::new().unwrap();
    let p = ParamRef::from(&vpm);
    assert!(opt::verify(V::PURPOSE, "sslserver", p));
    let (ok, e) = io::capture_err(|| opt::verify(V::PURPOSE, "nosuch", p));
    assert!(!ok);
    assert_eq!(
        String::from_utf8(e).unwrap(),
        "verify: Invalid purpose nosuch\n"
    );
    let (ok, e) = io::capture_err(|| opt::verify(V::POLICY, "not an oid", p));
    assert!(!ok);
    assert_eq!(
        String::from_utf8(e).unwrap(),
        "verify: Invalid Policy not an oid\n"
    );
    let (ok, e) = io::capture_err(|| opt::verify(V::VERIFY_NAME, "nosuch", p));
    assert!(!ok);
    assert_eq!(
        String::from_utf8(e).unwrap(),
        "verify: Invalid verify name nosuch\n"
    );
    assert!(opt::verify(V::VERIFY_NAME, "ssl_server", p));
    assert!(opt::verify(V::ATTIME, "0", p));
    assert!(opt::verify(V::PARTIAL_CHAIN, "", p));

    let store = apps::setup_verify(
        Some(&path(&test, "certs/root-cert.pem")),
        false,
        None,
        true,
        None,
        true,
    );
    assert!(store.is_some());
    let (s, e) = io::capture_err(|| {
        apps::setup_verify(Some("/nonexistent/ca"), false, None, true, None, true)
    });
    assert!(s.is_none());
    assert!(reasons(&e).starts_with("Error loading file /nonexistent/ca\n"));
}

#[test]
fn live_files_and_config() {
    let Some(_) = live() else { return };
    progname("x509");
    let (b, e) =
        io::capture_err(|| apps::bio_open_default(Some("/nonexistent/f"), 'r', format::PEM));
    assert!(b.is_none());
    assert!(
        reasons(&e)
            .starts_with("Can't open \"/nonexistent/f\" for reading, No such file or directory\n"),
        "{}",
        reasons(&e)
    );
    let (b, e) =
        io::capture_err(|| apps::bio_open_owner(Some("/nonexistent/f"), format::PEM, true));
    assert!(b.is_none());
    assert!(
        reasons(&e).starts_with(
            "x509: Can't open \"/nonexistent/f\" for writing, No such file or directory"
        )
    );
    let dir = std::env::temp_dir().join(format!("rustyssl-cli-conf-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let conf = dir.join("a.cnf");
    std::fs::write(
        &conf,
        "oid_section = oids\nRANDFILE = x\n[oids]\nmyoid = 1.2.3.4.5\n[s]\nn = 42\n",
    )
    .unwrap();
    let c = conf.display().to_string();
    let given = apps::ConfigFile::Given(c.clone());
    let (cf, e) = io::capture_err(|| apps::app_load_config_modules(Some(&given)));
    let cf = cf.unwrap();
    assert_eq!(
        String::from_utf8(e).unwrap(),
        format!("Using configuration from {c}\n")
    );
    assert!(apps::add_oid_section(&cf));
    assert!(rustyssl_ossl::x509::txt2nid("myoid") > 0);
    assert_eq!(apps::app_conf_try_number(&cf, Some("s"), "n"), Some(42));
    assert_eq!(apps::app_conf_try_string(&cf, Some("s"), "missing"), None);
    assert_eq!(rustyssl_ossl::err::peek_error(), 0);
    std::fs::write(&conf, "[unterminated\n").unwrap();
    let (cf, e) = io::capture_err(|| apps::app_load_config(Some(&c)));
    assert!(cf.is_none());
    assert_eq!(
        String::from_utf8(e).unwrap(),
        format!("x509: Error on line 1 of config file \"{c}\"\n")
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = io::err().flush();
}
