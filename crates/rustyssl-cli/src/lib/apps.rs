//! `apps/lib/apps.c` and `app_x509.c`: the helpers the commands share, with upstream's exact
//! messages. Passwords (`app_passwd`), configuration files (`app_load_config*`), opening
//! files (`bio_open_*`), loading keys, certificates, CRLs and requests (`load_*`, through
//! `OSSL_STORE` as upstream does), the name and certificate printing flags (`set_name_ex`,
//! `set_cert_ex`, ...), `print_name`, `parse_name`, trust stores (`setup_verify`), and
//! signing and verifying (`do_X509_sign` and friends).

use std::cell::RefCell;
use std::ffi::c_ulong;
use std::io::Write;

use rustyssl_ossl::abi as a;
use rustyssl_ossl::abi::{
    ASN1_DTFLGS_ISO8601, ASN1_DTFLGS_RFC822, ASN1_STRFLGS_DUMP_ALL, ASN1_STRFLGS_DUMP_DER,
    ASN1_STRFLGS_DUMP_UNKNOWN, ASN1_STRFLGS_ESC_2253, ASN1_STRFLGS_ESC_2254, ASN1_STRFLGS_ESC_CTRL,
    ASN1_STRFLGS_ESC_MSB, ASN1_STRFLGS_ESC_QUOTE, ASN1_STRFLGS_IGNORE_TYPE, ASN1_STRFLGS_SHOW_TYPE,
    ASN1_STRFLGS_UTF8_CONVERT, OSSL_STORE_INFO_CERT, OSSL_STORE_INFO_CRL, OSSL_STORE_INFO_PARAMS,
    OSSL_STORE_INFO_PKEY, OSSL_STORE_INFO_PUBKEY, X509_FLAG_COMPAT, X509_FLAG_NO_ATTRIBUTES,
    X509_FLAG_NO_AUX, X509_FLAG_NO_EXTENSIONS, X509_FLAG_NO_HEADER, X509_FLAG_NO_ISSUER,
    X509_FLAG_NO_PUBKEY, X509_FLAG_NO_SERIAL, X509_FLAG_NO_SIGDUMP, X509_FLAG_NO_SIGNAME,
    X509_FLAG_NO_SUBJECT, X509_FLAG_NO_VALIDITY, X509_FLAG_NO_VERSION, X509_VERSION_3,
    X509V3_EXT_DEFAULT, X509V3_EXT_DUMP_UNKNOWN, X509V3_EXT_ERROR_UNKNOWN,
    X509V3_EXT_PARSE_UNKNOWN, X509V3_EXT_UNKNOWN_MASK, XN_FLAG_COMPAT, XN_FLAG_DN_REV,
    XN_FLAG_DUMP_UNKNOWN_FIELDS, XN_FLAG_FN_ALIGN, XN_FLAG_FN_LN, XN_FLAG_FN_MASK, XN_FLAG_FN_NONE,
    XN_FLAG_FN_OID, XN_FLAG_FN_SN, XN_FLAG_MULTILINE, XN_FLAG_ONELINE, XN_FLAG_RFC2253,
    XN_FLAG_SEP_COMMA_PLUS, XN_FLAG_SEP_CPLUS_SPC, XN_FLAG_SEP_MASK, XN_FLAG_SEP_MULTILINE,
    XN_FLAG_SEP_SPLUS_SPC, XN_FLAG_SPC_EQ,
};
use rustyssl_ossl::conf::Conf;
use rustyssl_ossl::pkey::{MdCtx, Pkey, PkeyCtxRef};
use rustyssl_ossl::store::{self, Store};
use rustyssl_ossl::ui::Passphrase;
use rustyssl_ossl::verify::{FileType, LookupKind, StoreCtxRef, VerifyParam};
use rustyssl_ossl::x509::{self, Cert, CertStack, Crl, CrlStack, Name, NameRef, Req, Time, V3Ctx};
use rustyssl_ossl::{Bio, err};

use super::app_libctx::{libctx, propq};
use super::io;
use super::opt::{eprintf, fmt_flags, format, print_format_error, prog};

/// `APP_PASS_LEN` of `apps.h`.
const APP_PASS_LEN: usize = 1024;

/// `PASS_SOURCE_SIZE_MAX` of `apps.c`: the longest password source name before its `:`.
const PASS_SOURCE_SIZE_MAX: usize = 4;

/// A password, zeroed when dropped (upstream's `clear_free`).
pub struct Password(Vec<u8>);

impl Password {
    fn new(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    /// The password, as the C string it would be (up to its first NUL).
    pub fn as_str(&self) -> &str {
        let end = self.0.iter().position(|&b| b == 0).unwrap_or(self.0.len());
        std::str::from_utf8(self.0.get(..end).unwrap_or_default()).unwrap_or_default()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Password {
    fn drop(&mut self) {
        self.0.fill(0);
        std::hint::black_box(&self.0);
    }
}

thread_local! {
    /// `app_get_pass`'s `pwdbio`: kept open between the two reads of `app_passwd` when both
    /// passwords come from the same source.
    static PWDBIO: RefCell<Option<Bio>> = const { RefCell::new(None) };
    /// `nmflag` and `nmflag_set` (`set_nameopt`).
    static NAMEOPT: RefCell<(c_ulong, bool)> = const { RefCell::new((0, false)) };
    /// `default_config_file` of `openssl.c`.
    static DEFAULT_CONFIG_FILE: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Records the default configuration file (`CONF_get1_default_config_file`, at start-up).
pub fn set_default_config_file(file: Option<String>) {
    DEFAULT_CONFIG_FILE.with(|d| *d.borrow_mut() = file);
}

/// `default_config_file`.
pub fn default_config_file() -> Option<String> {
    DEFAULT_CONFIG_FILE.with(|d| d.borrow().clone())
}

/// A command's configuration file: upstream's commands start from the `default_config_file`
/// pointer and `-config` replaces it, and `app_load_config_modules` tells the two apart by
/// address, not by name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigFile {
    /// `default_config_file`.
    Default,
    /// A `-config` value.
    Given(String),
}

impl ConfigFile {
    /// The file name (`None` if there is no default).
    pub fn name(&self) -> Option<String> {
        match self {
            ConfigFile::Default => default_config_file(),
            ConfigFile::Given(f) => Some(f.clone()),
        }
    }
}

/// `app_get_pass`: one password from `pass:`, `env:`, `file:`, `fd:`, or `stdin`. `keepbio`
/// 1 keeps the source open for a second read, 2 reads from the kept one and closes it.
fn app_get_pass(arg: &str, keepbio: u8) -> Option<Password> {
    if let Some(p) = arg.strip_prefix("pass:") {
        return Some(Password::new(p.as_bytes()));
    }
    if let Some(var) = arg.strip_prefix("env:") {
        return match std::env::var_os(var) {
            Some(v) => Some(Password::new(v.as_encoded_bytes())),
            None => {
                eprintf!("No environment variable {var}\n");
                None
            }
        };
    }
    let have = PWDBIO.with(|p| p.borrow().is_some());
    if keepbio == 0 || !have {
        let bio = if let Some(file) = arg.strip_prefix("file:") {
            match Bio::new_file(file, "r") {
                Some(b) => b,
                None => {
                    eprintf!("Can't open file {file}\n");
                    return None;
                }
            }
        } else if let Some(fd) = arg.strip_prefix("fd:") {
            let i = atoi(fd);
            let b = if i >= 0 { Bio::new_fd(i, false) } else { None };
            let Some(b) = b else {
                eprintf!("Can't access file descriptor {fd}\n");
                return None;
            };
            // Can't BIO_gets on an fd BIO, so add a buffering BIO.
            let Some(buffer) = Bio::new_buffer() else {
                eprintf!("Out of memory\n");
                return None;
            };
            buffer.push(b)
        } else if arg == "stdin" {
            match dup_bio_in(format::TEXT) {
                Some(b) => b,
                None => {
                    eprintf!("Can't open BIO for stdin\n");
                    return None;
                }
            }
        } else {
            // A syntax error: don't reveal too much of the argument.
            match arg.find(':') {
                Some(i) if i <= PASS_SOURCE_SIZE_MAX => {
                    let shown = arg.get(..=i).unwrap_or(arg);
                    eprintf!("Invalid password argument, starting with \"{shown}\"\n");
                }
                _ => {
                    eprintf!(
                        "Invalid password argument, missing ':' within the first {} chars\n",
                        PASS_SOURCE_SIZE_MAX + 1
                    );
                }
            }
            return None;
        };
        PWDBIO.with(|p| *p.borrow_mut() = Some(bio));
    }
    let (n, line) = PWDBIO.with(|p| {
        p.borrow()
            .as_ref()
            .map_or((0, Vec::new()), |b| b.gets(APP_PASS_LEN))
    });
    if keepbio != 1 {
        PWDBIO.with(|p| *p.borrow_mut() = None);
    }
    if n <= 0 {
        eprintf!("Error reading password from BIO\n");
        return None;
    }
    let end = line.iter().position(|&b| b == b'\n').unwrap_or(line.len());
    Some(Password::new(line.get(..end).unwrap_or_default()))
}

/// C's `atoi`: leading whitespace, a sign, digits; 0 when there are none.
pub fn atoi(s: &str) -> i32 {
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
    let v = if neg { -v } else { v };
    i32::try_from(v).unwrap_or(if neg { i32::MIN } else { i32::MAX })
}

/// `app_passwd(arg1, arg2, &pass1, &pass2)`: `None` (the message printed) on failure.
pub fn app_passwd(
    arg1: Option<&str>,
    arg2: Option<&str>,
) -> Option<(Option<Password>, Option<Password>)> {
    let same = matches!((arg1, arg2), (Some(a), Some(b)) if a == b);
    let p1 = match arg1 {
        Some(a) => Some(app_get_pass(a, u8::from(same))?),
        None => None,
    };
    let p2 = match arg2 {
        Some(a) => Some(app_get_pass(a, if same { 2 } else { 0 })?),
        None => None,
    };
    Some((p1, p2))
}

/// `get_passwd(pass, desc)`.
pub fn get_passwd(pass: Option<&str>, desc: Option<&str>) -> Option<Password> {
    let desc = desc.unwrap_or("<unknown>");
    let result = match app_passwd(pass, None) {
        Some((p, _)) => p,
        None => {
            eprintf!("Error getting password for {desc}\n");
            None
        }
    };
    if let (Some(p), None) = (pass, &result) {
        eprintf!("Trying plain input string (better precede with 'pass:')\n");
        return Some(Password::new(p.as_bytes()));
    }
    result
}

/// `app_conf_try_string`: the value, with no error left behind when there is none.
pub fn app_conf_try_string(conf: &Conf, group: Option<&str>, name: &str) -> Option<String> {
    err::set_mark();
    let r = conf.get_string(group, name);
    if r.is_none() {
        err::pop_to_mark();
    } else {
        err::clear_last_mark();
    }
    r
}

/// `app_conf_try_number`.
pub fn app_conf_try_number(conf: &Conf, group: Option<&str>, name: &str) -> Option<i64> {
    err::set_mark();
    let r = conf.get_number(group, name);
    if r.is_none() {
        err::pop_to_mark();
    } else {
        err::clear_last_mark();
    }
    r
}

/// `app_load_config_bio`.
pub fn app_load_config_bio(input: &Bio, filename: Option<&str>) -> Option<Conf> {
    let lc = libctx();
    let conf = Conf::new(lc.as_deref())?;
    let (i, errorline) = conf.load_bio(input);
    if i > 0 {
        return Some(conf);
    }
    let prog = prog();
    if errorline <= 0 {
        eprintf!("{prog}: Can't load ");
    } else {
        eprintf!("{prog}: Error on line {errorline} of ");
    }
    match filename {
        Some(f) => eprintf!("config file \"{f}\"\n"),
        None => eprintf!("config input"),
    };
    None
}

/// `app_load_config_verbose`.
pub fn app_load_config_verbose(filename: &str, verbose: bool) -> Option<Conf> {
    if verbose {
        if filename.is_empty() {
            eprintf!("No configuration used\n");
        } else {
            eprintf!("Using configuration from {filename}\n");
        }
    }
    app_load_config_internal(Some(filename), false)
}

/// `app_load_config_internal`: an empty name is an empty configuration.
pub fn app_load_config_internal(filename: Option<&str>, quiet: bool) -> Option<Conf> {
    if filename.is_some_and(str::is_empty) {
        let lc = libctx();
        return Conf::new(lc.as_deref());
    }
    let input = bio_open_default_(filename, 'r', format::TEXT, quiet)?;
    app_load_config_bio(&input, filename)
}

/// `app_load_config`.
pub fn app_load_config(filename: Option<&str>) -> Option<Conf> {
    app_load_config_internal(filename, false)
}

/// `app_load_config_quiet`.
pub fn app_load_config_quiet(filename: Option<&str>) -> Option<Conf> {
    app_load_config_internal(filename, true)
}

/// `app_load_modules`: the configuration's modules (the default file's when `None`).
pub fn app_load_modules(config: Option<&Conf>) -> bool {
    let owned;
    let config = match config {
        Some(c) => c,
        None => {
            let file = default_config_file();
            match app_load_config_quiet(file.as_deref()) {
                Some(c) => {
                    owned = c;
                    &owned
                }
                None => return true,
            }
        }
    };
    if config.modules_load(0) <= 0 {
        eprintf!("Error configuring OpenSSL modules\n");
        io::print_errors();
        return false;
    }
    true
}

/// `add_oid_section`: the objects the configuration's `oid_section` names.
pub fn add_oid_section(conf: &Conf) -> bool {
    let Some(section) = app_conf_try_string(conf, None, "oid_section") else {
        return true;
    };
    let Some(values) = conf.get_section(&section) else {
        eprintf!("problem loading oid section {section}\n");
        return false;
    };
    for (name, value) in values {
        if x509::obj_create(&value, &name, &name) == 0 {
            eprintf!("problem creating object {name}={value}\n");
            return false;
        }
    }
    true
}

/// `app_load_config_modules`: loads the file (verbosely) and, unless it is the default one
/// (whose modules start-up loaded), its modules.
pub fn app_load_config_modules(configfile: Option<&ConfigFile>) -> Option<Conf> {
    let file = configfile?.name()?;
    let conf = app_load_config_verbose(&file, true)?;
    if configfile != Some(&ConfigFile::Default) && !app_load_modules(Some(&conf)) {
        return None;
    }
    Some(conf)
}

/// `dup_bio_in`: standard input (descriptor 0).
pub fn dup_bio_in(_format: i32) -> Option<Bio> {
    Bio::new_fd(0, false)
}

/// `dup_bio_out`: standard output (descriptor 1).
pub fn dup_bio_out(_format: i32) -> Option<Bio> {
    Bio::new_fd(1, false)
}

/// `dup_bio_err`: standard error (descriptor 2).
pub fn dup_bio_err(_format: i32) -> Option<Bio> {
    Bio::new_fd(2, false)
}

/// `modestr`.
fn modestr(mode: char, fmt: i32) -> &'static str {
    let text = format::is_text(fmt);
    match (mode, text) {
        ('a', true) => "a",
        ('a', false) => "ab",
        ('r', true) => "r",
        ('r', false) => "rb",
        (_, true) => "w",
        (_, false) => "wb",
    }
}

/// `modeverb`.
fn modeverb(mode: char) -> &'static str {
    match mode {
        'a' => "appending",
        'r' => "reading",
        'w' => "writing",
        _ => "(doing something)",
    }
}

/// `strerror(errno)` of the last system call.
fn last_os_error() -> String {
    let e = std::io::Error::last_os_error();
    strerror(e.raw_os_error().unwrap_or(0))
}

/// C's `perror(s)`: `s: ` (when given and not empty) and `strerror(errno)`.
pub fn perror(s: Option<&str>) {
    let reason = strerror(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
    match s {
        Some(s) if !s.is_empty() => eprintf!("{s}: {reason}\n"),
        _ => eprintf!("{reason}\n"),
    };
}

/// `strerror(code)`, as the C library words it.
pub fn strerror(code: i32) -> String {
    let text = std::io::Error::from_raw_os_error(code).to_string();
    // Rust appends " (os error N)".
    match text.rfind(" (os error ") {
        Some(i) => text.get(..i).unwrap_or(&text).to_owned(),
        None => text,
    }
}

fn bio_open_default_(filename: Option<&str>, mode: char, fmt: i32, quiet: bool) -> Option<Bio> {
    let stdio = filename.is_none_or(|f| f == "-");
    let ret = if stdio {
        if mode == 'r' {
            dup_bio_in(fmt)
        } else {
            dup_bio_out(fmt)
        }
    } else {
        Bio::new_file(filename.unwrap_or_default(), modestr(mode, fmt))
    };
    if quiet {
        err::clear();
        return ret;
    }
    if ret.is_some() {
        return ret;
    }
    let reason = last_os_error();
    if stdio {
        let which = if mode == 'r' { "stdin" } else { "stdout" };
        eprintf!("Can't open {which}, {reason}\n");
    } else {
        let f = filename.unwrap_or_default();
        eprintf!("Can't open \"{f}\" for {}, {reason}\n", modeverb(mode));
    }
    io::print_errors();
    None
}

/// `bio_open_default`: `-` or `None` is standard input or output.
pub fn bio_open_default(filename: Option<&str>, mode: char, fmt: i32) -> Option<Bio> {
    bio_open_default_(filename, mode, fmt, false)
}

/// `bio_open_default_quiet`.
pub fn bio_open_default_quiet(filename: Option<&str>, mode: char, fmt: i32) -> Option<Bio> {
    bio_open_default_(filename, mode, fmt, true)
}

/// `bio_open_owner`: for writing, readable by the owner only when `private`.
pub fn bio_open_owner(filename: Option<&str>, fmt: i32, private: bool) -> Option<Bio> {
    let Some(file) = filename.filter(|f| private && *f != "-") else {
        return bio_open_default(filename, 'w', fmt);
    };
    let opened = {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        o.open(file)
    };
    let bio = match opened {
        Ok(f) => {
            // The descriptor passes to the BIO, which closes it.
            #[cfg(unix)]
            let fd = std::os::unix::io::IntoRawFd::into_raw_fd(f);
            #[cfg(not(unix))]
            let fd = {
                drop(f);
                -1
            };
            Bio::new_fd(fd, true)
        }
        Err(e) => {
            let prog = prog();
            let reason = strerror(e.raw_os_error().unwrap_or(0));
            eprintf!("{prog}: Can't open \"{file}\" for writing, {reason}\n");
            io::print_errors();
            return None;
        }
    };
    if bio.is_none() {
        let prog = prog();
        let reason = last_os_error();
        eprintf!("{prog}: Can't open \"{file}\" for writing, {reason}\n");
        io::print_errors();
    }
    bio
}

/// `bio_to_mem`: everything `input` holds, at most `maxlen` bytes (0: no limit).
pub fn bio_to_mem(maxlen: usize, input: &Bio) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = input.read(&mut buf);
        if n == 0 {
            break;
        }
        let n = usize::try_from(n).ok()?;
        out.extend_from_slice(buf.get(..n)?);
        if maxlen != 0 && out.len() > maxlen {
            return None;
        }
    }
    Some(out)
}

/// `app_bail_out`: the message, the error queue, and exit status 1.
pub fn app_bail_out(message: &str) -> ! {
    eprintf!("{message}");
    io::print_errors();
    crate::exit(1)
}

/// What [`load_key_certs_crls`] is asked to load; `Some` for each kind wanted.
#[derive(Default)]
pub struct Wanted {
    pub pkey: bool,
    pub pubkey: bool,
    pub params: bool,
    pub cert: bool,
    /// Certificates are appended here.
    pub certs: Option<CertStack>,
    pub crl: bool,
    /// CRLs are appended here.
    pub crls: Option<CrlStack>,
}

/// What [`load_key_certs_crls`] loaded.
#[derive(Default)]
pub struct Loaded {
    pub pkey: Option<Pkey>,
    pub pubkey: Option<Pkey>,
    pub params: Option<Pkey>,
    pub cert: Option<Cert>,
    pub certs: Option<CertStack>,
    pub crl: Option<Crl>,
    pub crls: Option<CrlStack>,
}

/// `format2string`.
fn format2string(fmt: i32) -> Option<&'static str> {
    match fmt {
        format::PEM => Some("PEM"),
        format::ASN1 => Some("DER"),
        format::PVK => Some("PVK"),
        format::MSBLOB => Some("MSBLOB"),
        _ => None,
    }
}

/// `load_key_certs_crls`: loads, from `uri` (or standard input when `None` and
/// `maybe_stdin`), the first key, certificate, CRL, ... of each kind `wanted` asks for, and
/// all certificates or CRLs for the stacks. Returns whether everything asked for was found,
/// and what was loaded; messages as upstream's unless `quiet`.
#[allow(clippy::too_many_arguments)]
pub fn load_key_certs_crls(
    uri: Option<&str>,
    fmt: i32,
    maybe_stdin: bool,
    pass: Option<&str>,
    desc: Option<&str>,
    quiet: bool,
    mut wanted: Wanted,
) -> (bool, Loaded) {
    let mut got = Loaded::default();
    let mut want_pkey = wanted.pkey;
    let mut want_pubkey = wanted.pubkey;
    let mut want_params = wanted.params;
    let mut want_cert = wanted.cert;
    let mut want_crl = wanted.crl;
    let mut certs = wanted.certs.take();
    let mut crls = wanted.crls.take();
    let mut want_certs = certs.is_some();
    let mut want_crls = crls.is_some();
    // The stacks are made if the caller passed none but asked for them.
    let fail_name = |pk: bool, pubk: bool, pa: bool, c: bool, cs: bool, cr: bool, crs: bool| {
        let name = if pk {
            "private key"
        } else if pubk {
            "public key"
        } else if pa {
            "key parameters"
        } else if c {
            "certificate"
        } else if cs {
            "certificates"
        } else if cr {
            "CRL"
        } else if crs {
            "CRLs"
        } else {
            return None;
        };
        Some(name.to_owned())
    };
    let mut failed = fail_name(
        want_pkey,
        want_pubkey,
        want_params,
        want_cert,
        want_certs,
        want_crl,
        want_crls,
    );
    if failed.is_none() {
        if !quiet {
            let from = uri.unwrap_or("<stdin>");
            eprintf!("Internal error: nothing was requested to load from {from}\n");
        }
        return (false, got);
    }
    // Suppress extraneous errors left over from failed parse attempts.
    err::set_mark();

    // SET_EXPECT: the one kind expected, or 0 when several are.
    let mut expect: i32 = -1;
    let set_expect = |expect: &mut i32, v: i32| {
        *expect = if *expect < 0 || *expect == v { v } else { 0 };
    };
    if want_pkey {
        set_expect(&mut expect, OSSL_STORE_INFO_PKEY);
    }
    if want_pubkey {
        set_expect(&mut expect, OSSL_STORE_INFO_PUBKEY);
    }
    if want_params {
        set_expect(&mut expect, OSSL_STORE_INFO_PARAMS);
    }
    if want_cert {
        set_expect(&mut expect, OSSL_STORE_INFO_CERT);
    }
    let mut ncerts = 0;
    let mut ncrls = 0;
    let mut uri_shown = uri.map(str::to_owned);
    let result: Result<(), ()> = (|| {
        if want_certs {
            if certs.is_none() {
                certs = CertStack::new();
            }
            if certs.is_none() {
                if !quiet {
                    eprintf!("Out of memory loading");
                }
                return Err(());
            }
            set_expect(&mut expect, OSSL_STORE_INFO_CERT);
        }
        if want_crl {
            set_expect(&mut expect, OSSL_STORE_INFO_CRL);
        }
        if want_crls {
            if crls.is_none() {
                crls = CrlStack::new();
            }
            if crls.is_none() {
                if !quiet {
                    eprintf!("Out of memory loading");
                }
                return Err(());
            }
            set_expect(&mut expect, OSSL_STORE_INFO_CRL);
        }
        let uidata = Passphrase::new(pass, uri);
        let input_type = format2string(fmt);
        let lc = libctx();
        let pq = propq();
        let ctx = match uri {
            None => {
                if !maybe_stdin {
                    if !quiet {
                        eprintf!("No filename or uri specified for loading\n");
                    }
                    return Err(());
                }
                uri_shown = Some("<stdin>".to_owned());
                dup_bio_in(format::TEXT).and_then(|bio| {
                    Store::attach(&bio, lc.as_deref(), pq.as_deref(), &uidata, input_type)
                })
            }
            Some(u) => Store::open(u, lc.as_deref(), pq.as_deref(), &uidata, input_type),
        };
        let Some(ctx) = ctx else {
            if !quiet {
                eprintf!("Could not open file or uri for loading");
            }
            return Err(());
        };
        if expect > 0 && !ctx.expect(expect) {
            if !quiet {
                eprintf!("Internal error trying to load");
            }
            return Err(());
        }
        failed = None;
        while (want_pkey
            || want_pubkey
            || want_params
            || want_cert
            || want_certs
            || want_crl
            || want_crls)
            && !ctx.eof()
        {
            let Some(info) = ctx.load() else {
                continue;
            };
            let kind = info.kind();
            let mut ok = true;
            match kind {
                k if k == OSSL_STORE_INFO_PKEY && want_pkey => {
                    got.pkey = info.pkey();
                    ok = got.pkey.is_some();
                    if ok {
                        want_pkey = false;
                    }
                }
                // A private key also holds the public parts.
                k if k == OSSL_STORE_INFO_PKEY || k == OSSL_STORE_INFO_PUBKEY => {
                    if want_pubkey {
                        got.pubkey = info.pubkey();
                        ok = got.pubkey.is_some();
                        if ok {
                            want_pubkey = false;
                        }
                    }
                }
                k if k == OSSL_STORE_INFO_PARAMS => {
                    if want_params {
                        got.params = info.params();
                        ok = got.params.is_some();
                        if ok {
                            want_params = false;
                        }
                    }
                }
                k if k == OSSL_STORE_INFO_CERT => {
                    if want_cert {
                        got.cert = info.cert();
                        ok = got.cert.is_some();
                        if ok {
                            want_cert = false;
                        }
                    } else if let Some(stack) = &certs {
                        ok = info.cert().is_some_and(|c| stack.add_cert(c));
                    }
                    if ok {
                        ncerts += 1;
                    }
                }
                k if k == OSSL_STORE_INFO_CRL => {
                    if want_crl {
                        got.crl = info.crl();
                        ok = got.crl.is_some();
                        if ok {
                            want_crl = false;
                        }
                    } else if let Some(stack) = &crls {
                        ok = info.crl().is_some_and(|c| stack.push(c));
                    }
                    if ok {
                        ncrls += 1;
                    }
                }
                _ => {} // any other type is skipped
            }
            drop(info);
            if !ok {
                failed = Some(store::type_string(kind).unwrap_or_else(|| "(null)".to_owned()));
                if !quiet {
                    eprintf!("Error reading");
                }
                break;
            }
        }
        Ok(())
    })();
    let _ = result;

    // Were any of the requested kinds not found?
    if failed.is_none() {
        if ncerts > 0 {
            want_certs = false;
        }
        if ncrls > 0 {
            want_crls = false;
        }
        failed = fail_name(
            want_pkey,
            want_pubkey,
            want_params,
            want_cert,
            want_certs,
            want_crl,
            want_crls,
        );
        if failed.is_some() && !quiet {
            eprintf!("Could not find");
        }
    }
    if let Some(f) = failed.as_deref()
        && !quiet
    {
        let e = err::peek_last_error();
        let mut text = match desc {
            Some(d) if d.contains(f) => format!(" {d}"),
            Some(d) => format!(" {f} of {d}"),
            None => format!(" {f}"),
        };
        if let Some(u) = &uri_shown {
            text.push_str(&format!(" from {u}"));
        }
        // A system error: a more readable reason.
        if err::is_system_error(e) {
            text.push_str(&format!(": {}", strerror(err::reason(e))));
            err::pop_to_mark();
            err::set_mark();
        }
        text.push('\n');
        eprintf!("{text}");
        io::print_errors();
    }
    if quiet || failed.is_none() {
        err::pop_to_mark();
    } else {
        err::clear_last_mark();
    }
    got.certs = certs;
    got.crls = crls;
    (failed.is_none(), got)
}

fn is_https(uri: Option<&str>) -> bool {
    uri.is_some_and(|u| u.starts_with("https://"))
}

fn is_http(uri: Option<&str>) -> bool {
    uri.is_some_and(|u| u.starts_with("http://"))
}

/// `load_cert_pass`.
pub fn load_cert_pass(
    uri: Option<&str>,
    fmt: i32,
    maybe_stdin: bool,
    pass: Option<&str>,
    desc: Option<&str>,
) -> Option<Cert> {
    let desc = desc.unwrap_or("certificate");
    if is_https(uri) {
        eprintf!("Loading {desc} over HTTPS is unsupported\n");
        return None;
    }
    if is_http(uri) {
        let u = uri.unwrap_or_default();
        let cert = x509::load_http_cert(u);
        if cert.is_none() {
            io::print_errors();
            eprintf!("Unable to load {desc} from {u}\n");
        }
        return cert;
    }
    let wanted = Wanted {
        cert: true,
        ..Wanted::default()
    };
    load_key_certs_crls(uri, fmt, maybe_stdin, pass, Some(desc), false, wanted)
        .1
        .cert
}

/// `load_cert`.
pub fn load_cert(uri: Option<&str>, fmt: i32, desc: Option<&str>) -> Option<Cert> {
    load_cert_pass(uri, fmt, true, None, desc)
}

/// `load_crl`.
pub fn load_crl(uri: Option<&str>, fmt: i32, maybe_stdin: bool, desc: Option<&str>) -> Option<Crl> {
    let desc = desc.unwrap_or("CRL");
    if is_https(uri) {
        eprintf!("Loading {desc} over HTTPS is unsupported\n");
        return None;
    }
    if is_http(uri) {
        let u = uri.unwrap_or_default();
        let crl = x509::load_http_crl(u);
        if crl.is_none() {
            io::print_errors();
            eprintf!("Unable to load {desc} from {u}\n");
        }
        return crl;
    }
    let wanted = Wanted {
        crl: true,
        ..Wanted::default()
    };
    load_key_certs_crls(uri, fmt, maybe_stdin, None, Some(desc), false, wanted)
        .1
        .crl
}

/// `load_csr`: a request in PEM (the default) or DER.
pub fn load_csr(file: Option<&str>, fmt: i32, desc: Option<&str>) -> Option<Req> {
    let fmt = if fmt == format::UNDEF {
        format::PEM
    } else {
        fmt
    };
    let req = bio_open_default(file, 'r', fmt).and_then(|input| {
        if fmt == format::ASN1 {
            Req::read_der(&input)
        } else if fmt == format::PEM {
            Req::read_pem(&input)
        } else {
            print_format_error(fmt, fmt_flags::PEMDER);
            None
        }
    });
    if req.is_none() {
        io::print_errors();
        if let Some(d) = desc {
            eprintf!("Unable to load {d}\n");
        }
    }
    req
}

/// `load_csr_autofmt`: with no format, PEM then DER; then checks the self-signature.
pub fn load_csr_autofmt(
    infile: Option<&str>,
    fmt: i32,
    vfyopts: &[String],
    desc: &str,
) -> Option<Req> {
    let csr = if fmt != format::UNDEF {
        load_csr(infile, fmt, Some(desc))
    } else {
        let first = io::muted(|| load_csr(infile, format::PEM, None));
        let csr = match first {
            Some(c) => Some(c),
            None => {
                err::clear();
                load_csr(infile, format::ASN1, None)
            }
        };
        if csr.is_none() {
            let f = infile.unwrap_or("(null)");
            eprintf!("error: unable to load {desc} from file '{f}'\n");
        }
        csr
    };
    let csr = csr?;
    let pkey = csr.pubkey();
    let ret = do_x509_req_verify(&csr, pkey.as_ref(), vfyopts);
    let mut e = io::err();
    if pkey.is_none() || ret < 0 {
        let _ = e.write_all(b"Warning: error while verifying CSR self-signature\n");
    } else if ret == 0 {
        let _ = e.write_all(b"Warning: CSR self-signature does not match the contents\n");
    }
    Some(csr)
}

/// `load_key`.
pub fn load_key(
    uri: Option<&str>,
    fmt: i32,
    may_stdin: bool,
    pass: Option<&str>,
    engine: Option<&super::engine::Engine>,
    desc: Option<&str>,
) -> Option<Pkey> {
    let desc = desc.unwrap_or("private key");
    let allocated;
    let uri = if fmt == format::ENGINE {
        allocated = super::engine::make_engine_uri(engine, uri, desc);
        allocated.as_deref()
    } else {
        uri
    };
    let wanted = Wanted {
        pkey: true,
        ..Wanted::default()
    };
    load_key_certs_crls(uri, fmt, may_stdin, pass, Some(desc), false, wanted)
        .1
        .pkey
}

/// `load_pubkey`: a public key, else the public part of a private key.
pub fn load_pubkey(
    uri: Option<&str>,
    fmt: i32,
    maybe_stdin: bool,
    pass: Option<&str>,
    engine: Option<&super::engine::Engine>,
    desc: Option<&str>,
) -> Option<Pkey> {
    let desc = desc.unwrap_or("public key");
    let allocated;
    let uri = if fmt == format::ENGINE {
        allocated = super::engine::make_engine_uri(engine, uri, desc);
        allocated.as_deref()
    } else {
        uri
    };
    let wanted = Wanted {
        pubkey: true,
        ..Wanted::default()
    };
    let (_, got) = load_key_certs_crls(uri, fmt, maybe_stdin, pass, Some(desc), true, wanted);
    if got.pubkey.is_some() {
        return got.pubkey;
    }
    let wanted = Wanted {
        pkey: true,
        ..Wanted::default()
    };
    load_key_certs_crls(uri, fmt, maybe_stdin, pass, Some(desc), false, wanted)
        .1
        .pkey
}

/// `load_keyparams_suppress`.
pub fn load_keyparams_suppress(
    uri: Option<&str>,
    fmt: i32,
    maybe_stdin: bool,
    keytype: Option<&str>,
    desc: Option<&str>,
    suppress_decode_errors: bool,
) -> Option<Pkey> {
    let desc = desc.unwrap_or("key parameters");
    let wanted = Wanted {
        params: true,
        ..Wanted::default()
    };
    let params = load_key_certs_crls(
        uri,
        fmt,
        maybe_stdin,
        None,
        Some(desc),
        suppress_decode_errors,
        wanted,
    )
    .1
    .params;
    if let (Some(p), Some(t)) = (&params, keytype)
        && !p.is_a(t)
    {
        io::print_errors();
        let u = uri.unwrap_or("(null)");
        eprintf!("Unable to load {desc} from {u} (unexpected parameters type)\n");
        return None;
    }
    params
}

/// `load_keyparams`.
pub fn load_keyparams(
    uri: Option<&str>,
    fmt: i32,
    maybe_stdin: bool,
    keytype: Option<&str>,
    desc: Option<&str>,
) -> Option<Pkey> {
    load_keyparams_suppress(uri, fmt, maybe_stdin, keytype, desc, false)
}

/// `load_certs`: appends every certificate of `uri` to `certs` (made if `None`); on failure
/// a stack this made is dropped.
pub fn load_certs(
    uri: Option<&str>,
    maybe_stdin: bool,
    certs: Option<CertStack>,
    pass: Option<&str>,
    desc: Option<&str>,
) -> (bool, Option<CertStack>) {
    let was_none = certs.is_none();
    let desc = desc.unwrap_or("certificates");
    let wanted = Wanted {
        certs: Some(match certs {
            Some(c) => c,
            None => match CertStack::new() {
                Some(c) => c,
                None => return (false, None),
            },
        }),
        ..Wanted::default()
    };
    let (ok, got) = load_key_certs_crls(
        uri,
        format::UNDEF,
        maybe_stdin,
        pass,
        Some(desc),
        false,
        wanted,
    );
    if !ok && was_none {
        return (false, None);
    }
    (ok, got.certs)
}

/// `load_crls`: as [`load_certs`], for CRLs.
pub fn load_crls(
    uri: Option<&str>,
    crls: Option<CrlStack>,
    pass: Option<&str>,
    desc: Option<&str>,
) -> (bool, Option<CrlStack>) {
    let was_none = crls.is_none();
    let desc = desc.unwrap_or("CRLs");
    let wanted = Wanted {
        crls: Some(match crls {
            Some(c) => c,
            None => match CrlStack::new() {
                Some(c) => c,
                None => return (false, None),
            },
        }),
        ..Wanted::default()
    };
    let (ok, got) = load_key_certs_crls(uri, format::UNDEF, false, pass, Some(desc), false, wanted);
    if !ok && was_none {
        return (false, None);
    }
    (ok, got.crls)
}

/// A flag constant (an `int`, `long`, or `unsigned long` macro) as the `unsigned long` C
/// converts it to; every one is non-negative.
fn ul(v: impl Into<i128>) -> c_ulong {
    c_ulong::try_from(v.into()).unwrap_or(0)
}

/// `X509_FLAG_CA` of `apps.c`.
fn x509_flag_ca() -> c_ulong {
    ul(X509_FLAG_NO_ISSUER)
        | ul(X509_FLAG_NO_PUBKEY)
        | ul(X509_FLAG_NO_HEADER)
        | ul(X509_FLAG_NO_VERSION)
}

/// One `NAME_EX_TBL` entry: a name, its flag, and the mask it clears first.
type NameExTbl = (&'static str, c_ulong, c_ulong);

/// `set_table_opts`: one `[+-]name`.
fn set_table_opts(flags: &mut c_ulong, arg: &str, table: &[NameExTbl]) -> bool {
    let (on, name) = match arg.as_bytes().first() {
        Some(b'-') => (false, arg.get(1..).unwrap_or_default()),
        Some(b'+') => (true, arg.get(1..).unwrap_or_default()),
        _ => (true, arg),
    };
    for (n, flag, mask) in table {
        if n.eq_ignore_ascii_case(name) {
            *flags &= !mask;
            if on {
                *flags |= flag;
            } else {
                *flags &= !flag;
            }
            return true;
        }
    }
    false
}

/// `set_multi_opts`: a comma-separated list (`X509V3_parse_list`).
fn set_multi_opts(flags: &mut c_ulong, arg: Option<&str>, table: &[NameExTbl]) -> bool {
    let Some(arg) = arg else {
        return false;
    };
    let mut ret = true;
    for (name, _) in x509::parse_list(arg).unwrap_or_default() {
        if !set_table_opts(flags, name.as_deref().unwrap_or_default(), table) {
            ret = false;
        }
    }
    ret
}

/// `set_cert_ex`: `-certopt`.
pub fn set_cert_ex(flags: &mut c_ulong, arg: Option<&str>) -> bool {
    let unknown = ul(X509V3_EXT_UNKNOWN_MASK);
    let table: &[NameExTbl] = &[
        ("compatible", ul(X509_FLAG_COMPAT), 0xffff_ffff),
        ("ca_default", x509_flag_ca(), 0xffff_ffff),
        ("no_header", ul(X509_FLAG_NO_HEADER), 0),
        ("no_version", ul(X509_FLAG_NO_VERSION), 0),
        ("no_serial", ul(X509_FLAG_NO_SERIAL), 0),
        ("no_signame", ul(X509_FLAG_NO_SIGNAME), 0),
        ("no_validity", ul(X509_FLAG_NO_VALIDITY), 0),
        ("no_subject", ul(X509_FLAG_NO_SUBJECT), 0),
        ("no_issuer", ul(X509_FLAG_NO_ISSUER), 0),
        ("no_pubkey", ul(X509_FLAG_NO_PUBKEY), 0),
        ("no_extensions", ul(X509_FLAG_NO_EXTENSIONS), 0),
        ("no_sigdump", ul(X509_FLAG_NO_SIGDUMP), 0),
        ("no_aux", ul(X509_FLAG_NO_AUX), 0),
        ("no_attributes", ul(X509_FLAG_NO_ATTRIBUTES), 0),
        ("ext_default", ul(X509V3_EXT_DEFAULT), unknown),
        ("ext_error", ul(X509V3_EXT_ERROR_UNKNOWN), unknown),
        ("ext_parse", ul(X509V3_EXT_PARSE_UNKNOWN), unknown),
        ("ext_dump", ul(X509V3_EXT_DUMP_UNKNOWN), unknown),
    ];
    set_multi_opts(flags, arg, table)
}

/// `set_name_ex`: `-nameopt`.
pub fn set_name_ex(flags: &mut c_ulong, arg: Option<&str>) -> bool {
    let table: &[NameExTbl] = &[
        ("esc_2253", ul(ASN1_STRFLGS_ESC_2253), 0),
        ("esc_2254", ul(ASN1_STRFLGS_ESC_2254), 0),
        ("esc_ctrl", ul(ASN1_STRFLGS_ESC_CTRL), 0),
        ("esc_msb", ul(ASN1_STRFLGS_ESC_MSB), 0),
        ("use_quote", ul(ASN1_STRFLGS_ESC_QUOTE), 0),
        ("utf8", ul(ASN1_STRFLGS_UTF8_CONVERT), 0),
        ("ignore_type", ul(ASN1_STRFLGS_IGNORE_TYPE), 0),
        ("show_type", ul(ASN1_STRFLGS_SHOW_TYPE), 0),
        ("dump_all", ul(ASN1_STRFLGS_DUMP_ALL), 0),
        ("dump_nostr", ul(ASN1_STRFLGS_DUMP_UNKNOWN), 0),
        ("dump_der", ul(ASN1_STRFLGS_DUMP_DER), 0),
        ("compat", ul(XN_FLAG_COMPAT), 0xffff_ffff),
        (
            "sep_comma_plus",
            ul(XN_FLAG_SEP_COMMA_PLUS),
            ul(XN_FLAG_SEP_MASK),
        ),
        (
            "sep_comma_plus_space",
            ul(XN_FLAG_SEP_CPLUS_SPC),
            ul(XN_FLAG_SEP_MASK),
        ),
        (
            "sep_semi_plus_space",
            ul(XN_FLAG_SEP_SPLUS_SPC),
            ul(XN_FLAG_SEP_MASK),
        ),
        (
            "sep_multiline",
            ul(XN_FLAG_SEP_MULTILINE),
            ul(XN_FLAG_SEP_MASK),
        ),
        ("dn_rev", ul(XN_FLAG_DN_REV), 0),
        ("nofname", ul(XN_FLAG_FN_NONE), ul(XN_FLAG_FN_MASK)),
        ("sname", ul(XN_FLAG_FN_SN), ul(XN_FLAG_FN_MASK)),
        ("lname", ul(XN_FLAG_FN_LN), ul(XN_FLAG_FN_MASK)),
        ("align", ul(XN_FLAG_FN_ALIGN), 0),
        ("oid", ul(XN_FLAG_FN_OID), ul(XN_FLAG_FN_MASK)),
        ("space_eq", ul(XN_FLAG_SPC_EQ), 0),
        ("dump_unknown", ul(XN_FLAG_DUMP_UNKNOWN_FIELDS), 0),
        ("RFC2253", ul(XN_FLAG_RFC2253), 0xffff_ffff),
        ("oneline", ul(XN_FLAG_ONELINE), 0xffff_ffff),
        ("multiline", ul(XN_FLAG_MULTILINE), 0xffff_ffff),
        ("ca_default", ul(XN_FLAG_MULTILINE), 0xffff_ffff),
    ];
    if !set_multi_opts(flags, arg, table) {
        return false;
    }
    if *flags != ul(XN_FLAG_COMPAT) && *flags & ul(XN_FLAG_SEP_MASK) == 0 {
        *flags |= ul(XN_FLAG_SEP_CPLUS_SPC);
    }
    true
}

/// `set_nameopt`: like upstream, a failed list still changes the flags (`nmflag`), but only
/// a successful one makes them used.
pub fn set_nameopt(arg: Option<&str>) -> bool {
    NAMEOPT.with(|n| {
        let mut n = n.borrow_mut();
        let ret = set_name_ex(&mut n.0, arg);
        if ret {
            n.1 = true;
        }
        ret
    })
}

/// `get_nameopt`.
pub fn get_nameopt() -> c_ulong {
    NAMEOPT.with(|n| {
        let (flags, set) = *n.borrow();
        if set {
            flags
        } else {
            ul(XN_FLAG_SEP_CPLUS_SPC)
                | ul(XN_FLAG_FN_SN)
                | ul(ASN1_STRFLGS_ESC_CTRL)
                | ul(ASN1_STRFLGS_UTF8_CONVERT)
                | ul(ASN1_STRFLGS_DUMP_UNKNOWN)
                | ul(ASN1_STRFLGS_DUMP_DER)
        }
    })
}

/// `set_dateopt`.
pub fn set_dateopt(dateopt: &mut c_ulong, arg: &str) -> bool {
    if arg.eq_ignore_ascii_case("rfc_822") {
        *dateopt = ul(ASN1_DTFLGS_RFC822);
    } else if arg.eq_ignore_ascii_case("iso_8601") {
        *dateopt = ul(ASN1_DTFLGS_ISO8601);
    } else {
        return false;
    }
    true
}

/// `EXT_COPY_*` of `apps.h`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExtCopy {
    None,
    Add,
    All,
}

/// `set_ext_copy`.
pub fn set_ext_copy(arg: &str) -> Option<ExtCopy> {
    if arg.eq_ignore_ascii_case("none") {
        Some(ExtCopy::None)
    } else if arg.eq_ignore_ascii_case("copy") {
        Some(ExtCopy::Add)
    } else if arg.eq_ignore_ascii_case("copyall") {
        Some(ExtCopy::All)
    } else {
        None
    }
}

/// `copy_extensions`: the request's extensions into the certificate.
pub fn copy_extensions(x: &Cert, req: &Req, copy: ExtCopy) -> bool {
    if copy == ExtCopy::None {
        return true;
    }
    for ext in req.extensions() {
        let mut idx = x.ext_index_like(&ext, -1);
        if idx != -1 {
            if copy == ExtCopy::Add {
                continue;
            }
            while idx != -1 {
                x.delete_ext(idx);
                idx = x.ext_index_like(&ext, -1);
            }
        }
        if !x.add_ext(&ext) {
            return false;
        }
    }
    true
}

/// `print_name(out, title, nm)`, with the `-nameopt` flags.
pub fn print_name(out: &Bio, title: Option<&str>, nm: NameRef<'_>) {
    let lflags = get_nameopt();
    if let Some(t) = title {
        let _ = out.write_all(t.as_bytes());
    }
    let mline = lflags & ul(XN_FLAG_SEP_MASK) == ul(XN_FLAG_SEP_MULTILINE);
    if lflags == ul(XN_FLAG_COMPAT) {
        let line = x509::name_oneline(nm).unwrap_or_default();
        let _ = out.write_all(line.as_bytes());
        let _ = out.write_all(b"\n");
    } else {
        if mline {
            let _ = out.write_all(b"\n");
        }
        x509::name_print_ex(out, nm, if mline { 4 } else { 0 }, lflags);
        let _ = out.write_all(b"\n");
    }
}

/// `dump_cert_text`.
pub fn dump_cert_text(out: &Bio, x: &Cert) {
    print_name(out, Some("subject="), x.subject_name());
    print_name(out, Some("issuer="), x.issuer_name());
}

/// `setup_verify`: a trust store of the CA file, directory, and store URI (each, unless
/// turned off, the default one when not given).
pub fn setup_verify(
    ca_file: Option<&str>,
    no_ca_file: bool,
    ca_path: Option<&str>,
    no_ca_path: bool,
    ca_store: Option<&str>,
    no_ca_store: bool,
) -> Option<x509::Store> {
    let store = x509::Store::new();
    let lc = libctx();
    let pq = propq();
    let ok = (|| {
        let store = store.as_ref()?;
        if ca_file.is_some() || !no_ca_file {
            let lookup = store.add_lookup(LookupKind::File)?;
            if let Some(f) = ca_file {
                if lookup.load_file_ex(Some(f), FileType::Pem, lc.as_deref(), pq.as_deref()) <= 0 {
                    err::clear();
                    if lookup.load_file_ex(Some(f), FileType::Asn1, lc.as_deref(), pq.as_deref())
                        <= 0
                    {
                        eprintf!("Error loading file {f}\n");
                        return None;
                    }
                }
            } else {
                lookup.load_file_ex(None, FileType::Default, lc.as_deref(), pq.as_deref());
            }
        }
        if ca_path.is_some() || !no_ca_path {
            let lookup = store.add_lookup(LookupKind::HashDir)?;
            if let Some(p) = ca_path {
                if lookup.add_dir(Some(p), FileType::Pem) <= 0 {
                    eprintf!("Error loading directory {p}\n");
                    return None;
                }
            } else {
                lookup.add_dir(None, FileType::Default);
            }
        }
        if ca_store.is_some() || !no_ca_store {
            let lookup = store.add_lookup(LookupKind::Store)?;
            if lookup.add_store_ex(ca_store, lc.as_deref(), pq.as_deref()) == 0 {
                if let Some(s) = ca_store {
                    eprintf!("Error loading store URI {s}\n");
                }
                return None;
            }
        }
        Some(())
    })();
    if ok.is_none() {
        io::print_errors();
        return None;
    }
    err::clear();
    store
}

/// `parse_yesno`.
pub fn parse_yesno(s: Option<&str>, def: bool) -> bool {
    match s.and_then(|s| s.bytes().next()) {
        Some(b'f' | b'F' | b'n' | b'N' | b'0') => false,
        Some(b't' | b'T' | b'y' | b'Y' | b'1') => true,
        _ => def,
    }
}

/// `parse_name`: `/type0=value0/type1=value1...`, `+` joining multi-valued RDNs when
/// `canmulti`, `\` escaping.
pub fn parse_name(cp: &str, chtype: i32, canmulti: bool, desc: &str) -> Option<Name> {
    let prog = prog();
    let Some(rest) = cp.strip_prefix('/') else {
        eprintf!(
            "{prog}: {desc} name is expected to be in the format /type0=value0/type1=value1/type2=... \
             where characters may be escaped by \\. This name is not in that format: '{cp}'\n"
        );
        return None;
    };
    let Some(n) = Name::new() else {
        eprintf!("{prog}: Out of memory\n");
        return None;
    };
    let b = rest.as_bytes();
    let mut i = 0;
    let mut nextismulti = false;
    while i < b.len() {
        let ismulti = nextismulti;
        nextismulti = false;
        let start = i;
        while i < b.len() && b.get(i) != Some(&b'=') {
            i += 1;
        }
        let typestr = String::from_utf8_lossy(b.get(start..i).unwrap_or_default()).into_owned();
        if i >= b.len() {
            eprintf!(
                "{prog}: Missing '=' after RDN type string '{typestr}' in {desc} name string\n"
            );
            return None;
        }
        i += 1;
        let mut value: Vec<u8> = Vec::new();
        while let Some(&c) = b.get(i) {
            if c == b'/' {
                break;
            }
            if canmulti && c == b'+' {
                nextismulti = true;
                break;
            }
            let mut c = c;
            if c == b'\\' {
                i += 1;
                match b.get(i) {
                    Some(&e) => c = e,
                    None => {
                        eprintf!("{prog}: Escape character at end of {desc} name string\n");
                        return None;
                    }
                }
            }
            value.push(c);
            i += 1;
        }
        // Past the '/' or '+'.
        if i < b.len() {
            i += 1;
        }
        let nid = x509::txt2nid(&typestr);
        if nid == 0 {
            eprintf!("{prog} warning: Skipping unknown {desc} name attribute \"{typestr}\"\n");
            if ismulti {
                eprintf!(
                    "{prog} hint: a '+' in a value string needs be escaped using '\\' else a new member of a multi-valued RDN is expected\n"
                );
            }
            continue;
        }
        if value.is_empty() {
            eprintf!(
                "{prog} warning: No value provided for {desc} name attribute \"{typestr}\", skipped\n"
            );
            continue;
        }
        if !n.add_entry_by_nid(nid, chtype, &value, if ismulti { -1 } else { 0 }) {
            io::print_errors();
            let v = String::from_utf8_lossy(&value);
            eprintf!("{prog}: Error adding {desc} name attribute \"/{typestr}={v}\"\n");
            return None;
        }
    }
    Some(n)
}

/// `pkey_ctrl_string`: `name:value` for `EVP_PKEY_CTX_ctrl_str`.
pub fn pkey_ctrl_string(ctx: PkeyCtxRef<'_>, value: &str) -> i32 {
    match value.split_once(':') {
        Some((k, v)) => ctx.ctrl_str(k, v),
        None => 0,
    }
}

/// `do_x509_ctrl_string` of `app_x509.c`: `distid:` or `hexdistid:`, for a certificate or a
/// request.
fn do_x509_ctrl_string(set: &dyn Fn(&[u8]) -> bool, what: &str, value: &str) -> i32 {
    let (name, v) = match value.split_once(':') {
        Some((n, v)) => (n, Some(v)),
        None => (value, None),
    };
    let id: Option<Vec<u8>> = match name {
        "distid" => Some(v.unwrap_or_default().as_bytes().to_vec()),
        // A failed conversion sets an empty ID, as upstream's NULL value does.
        "hexdistid" => Some(
            v.map(|h| rustyssl_ossl::crypto::hexstr2buf(h).unwrap_or_default())
                .unwrap_or_default(),
        ),
        _ => None,
    };
    // Every other name is the "unsupported" command 0.
    let Some(id) = id else {
        return -2;
    };
    if set(&id) {
        1
    } else {
        eprintf!("error: setting distinguishing ID in {what} failed\n");
        0
    }
}

/// `do_pkey_ctx_init`.
fn do_pkey_ctx_init(ctx: PkeyCtxRef<'_>, opts: &[String]) -> bool {
    for opt in opts {
        if pkey_ctrl_string(ctx, opt) <= 0 {
            eprintf!("parameter error \"{opt}\"\n");
            io::print_errors();
            return false;
        }
    }
    true
}

/// `do_sign_init`.
fn do_sign_init(ctx: &MdCtx, pkey: &Pkey, md: Option<&str>, sigopts: &[String]) -> bool {
    // A mandatory "UNDEF" default digest: the algorithm signs with no digest.
    let (r, def) = pkey.default_digest_name();
    let md = if r == 2 && def == "UNDEF" { None } else { md };
    let lc = libctx();
    let pq = propq();
    let (ok, pctx) = ctx.digest_sign_init(md, lc.as_deref(), pq.as_deref(), pkey);
    ok && do_pkey_ctx_init(pctx, sigopts)
}

/// `adapt_keyid_ext`.
fn adapt_keyid_ext(
    cert: &Cert,
    ext_ctx: &mut V3Ctx,
    name: &str,
    value: &str,
    add_default: bool,
) -> bool {
    let Some(new_ext) = ext_ctx.ext_nconf(name, value) else {
        return false;
    };
    match cert.existing_ext(&new_ext) {
        Some((idx, disabled)) => {
            if disabled {
                cert.delete_ext(idx);
            }
            true
        }
        None => !add_default || cert.add_ext(&new_ext),
    }
}

/// `cert_matches_key`.
pub fn cert_matches_key(cert: &Cert, pkey: &Pkey) -> bool {
    err::set_mark();
    let m = cert.check_private_key(pkey);
    err::pop_to_mark();
    m
}

/// `do_X509_sign`: RFC 5280 compliance (version 3, key identifiers), then the signature.
pub fn do_x509_sign(
    cert: &Cert,
    force_v1: bool,
    pkey: &Pkey,
    md: Option<&str>,
    sigopts: &[String],
    ext_ctx: &mut V3Ctx<'_>,
) -> bool {
    let mctx = MdCtx::new();
    if !force_v1 {
        if !cert.set_version(core::ffi::c_long::from(X509_VERSION_3)) {
            return false;
        }
        // The subject key identifier first, so the authority key identifier can use it.
        if !adapt_keyid_ext(cert, ext_ctx, "subjectKeyIdentifier", "hash", true) {
            return false;
        }
        let self_sign = cert_matches_key(cert, pkey);
        if !adapt_keyid_ext(
            cert,
            ext_ctx,
            "authorityKeyIdentifier",
            "keyid, issuer",
            !self_sign,
        ) {
            return false;
        }
    }
    match mctx {
        Some(m) if do_sign_init(&m, pkey, md, sigopts) => cert.sign_ctx(&m) > 0,
        _ => false,
    }
}

/// `do_X509_REQ_sign`.
pub fn do_x509_req_sign(x: &Req, pkey: &Pkey, md: Option<&str>, sigopts: &[String]) -> bool {
    match MdCtx::new() {
        Some(m) if do_sign_init(&m, pkey, md, sigopts) => x.sign_ctx(&m) > 0,
        _ => false,
    }
}

/// `do_X509_CRL_sign`.
pub fn do_x509_crl_sign(x: &Crl, pkey: &Pkey, md: Option<&str>, sigopts: &[String]) -> bool {
    match MdCtx::new() {
        Some(m) if do_sign_init(&m, pkey, md, sigopts) => x.sign_ctx(&m) > 0,
        _ => false,
    }
}

/// `do_X509_verify`: 1 valid, 0 not, -1 error.
pub fn do_x509_verify(x: &Cert, pkey: &Pkey, vfyopts: &[String]) -> i32 {
    for opt in vfyopts {
        if do_x509_ctrl_string(&|id| x.set_distinguishing_id(id), "certificate", opt) <= 0 {
            eprintf!("parameter error \"{opt}\"\n");
            io::print_errors();
            return -1;
        }
    }
    x.verify(pkey)
}

/// `do_X509_REQ_verify`: 1 valid, 0 not, -1 error.
pub fn do_x509_req_verify(x: &Req, pkey: Option<&Pkey>, vfyopts: &[String]) -> i32 {
    for opt in vfyopts {
        let set = |id: &[u8]| x.set_distinguishing_id(id);
        if do_x509_ctrl_string(&set, "certificate signing request", opt) <= 0 {
            eprintf!("parameter error \"{opt}\"\n");
            io::print_errors();
            return -1;
        }
    }
    let lc = libctx();
    let pq = propq();
    x.verify_ex(pkey, lc.as_deref(), pq.as_deref())
}

/// `set_cert_times(x, startdate, enddate, days, strict_compare_times)`.
pub fn set_cert_times(
    x: &Cert,
    startdate: Option<&str>,
    enddate: Option<&str>,
    days: i32,
    strict_compare_times: bool,
) -> bool {
    if !check_cert_time_string(startdate, "start date")
        || !check_cert_time_string(enddate, "end date")
    {
        return false;
    }
    let start = startdate.filter(|s| *s != "today");
    if !x.set_not_before(start) {
        eprintf!("Error setting notBefore certificate field\n");
        return false;
    }
    let (enddate, days) = match enddate {
        Some("today") => (None, 0),
        e => (e, days),
    };
    if !x.set_not_after(enddate, days) {
        eprintf!("Error setting notAfter certificate field\n");
        return false;
    }
    if let (Some(a), Some(b)) = (x.not_after(), x.not_before())
        && x509::time_compare(a, b) < 0
    {
        let what = if strict_compare_times {
            "Error"
        } else {
            "Warning"
        };
        eprintf!("{what}: end date before start date\n");
        if strict_compare_times {
            return false;
        }
    }
    true
}

/// `check_cert_time_string`.
pub fn check_cert_time_string(time: Option<&str>, desc: &str) -> bool {
    match time {
        None => true,
        Some("today") => true,
        Some(t) if x509::time_string_ok(t) => true,
        Some(_) => {
            eprintf!(
                "{desc} is invalid, it should be \"today\" or have format [CC]YYMMDDHHMMSSZ\n"
            );
            false
        }
    }
}

/// `check_cert_attributes(bio, x, checkhost, checkemail, checkip, print)`.
pub fn check_cert_attributes(
    bio: &Bio,
    x: &Cert,
    checkhost: Option<&str>,
    checkemail: Option<&str>,
    checkip: Option<&str>,
    print: bool,
) -> bool {
    let mut ret = true;
    let mut out = bio;
    if let Some(h) = checkhost {
        let valid = x.check_host(h);
        if print {
            let not = if valid == 1 { "" } else { " NOT" };
            let _ = writeln!(out, "Hostname {h} does{not} match certificate");
        }
        ret = ret && valid > 0;
    }
    if let Some(e) = checkemail {
        let valid = x.check_email(e);
        if print {
            let not = if valid != 0 { "" } else { " NOT" };
            let _ = writeln!(out, "Email {e} does{not} match certificate");
        }
        ret = ret && valid > 0;
    }
    if let Some(ip) = checkip {
        let valid = x.check_ip_asc(ip);
        if print {
            let not = if valid != 0 { "" } else { " NOT" };
            let _ = writeln!(out, "IP {ip} does{not} match certificate");
        }
        ret = ret && valid > 0;
    }
    ret
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
pub fn store_setup_crl_download(store: &x509::Store) {
    store.set_lookup_crls_cb(crls_http_cb);
}

/// `load_cert_certs` of `apps.c`: the first certificate (`want_cert`) and the others (all
/// of them without `want_cert`) when `want_certs`, with the validity warnings.
pub fn load_cert_certs(
    uri: &str,
    want_cert: bool,
    want_certs: bool,
    exclude_http: bool,
    pass: Option<&str>,
    desc: Option<&str>,
    vpm: Option<&VerifyParam>,
) -> Option<(Option<Cert>, Option<CertStack>)> {
    let desc = desc.unwrap_or(if want_certs {
        "certificates"
    } else {
        "certificate"
    });
    let lower = uri.to_ascii_lowercase();
    if exclude_http && (lower.starts_with("http://") || lower.starts_with("https://")) {
        eprintf!("error: HTTP retrieval not allowed for {desc}\n");
        return None;
    }
    let pass_string = get_passwd(pass, Some(desc));
    let wanted = Wanted {
        cert: want_cert,
        certs: if want_certs {
            Some(CertStack::new()?)
        } else {
            None
        },
        ..Wanted::default()
    };
    let (ok, got) = load_key_certs_crls(
        Some(uri),
        format::UNDEF,
        false,
        pass_string.as_ref().map(|p| p.as_str()),
        Some(desc),
        false,
        wanted,
    );
    if !ok {
        return None;
    }
    if let Some(c) = &got.cert {
        warn_cert(uri, c, false, vpm);
    }
    if let Some(cs) = &got.certs {
        for c in cs.to_vec() {
            warn_cert(uri, &c, true, vpm);
        }
    }
    Some((got.cert, got.certs))
}

/// `load_certs_multifile` of `apps.c`: every certificate of each file of the list, without
/// duplicates.
pub fn load_certs_multifile(
    files: &str,
    pass: Option<&str>,
    desc: Option<&str>,
    vpm: Option<&VerifyParam>,
) -> Option<CertStack> {
    let Some(result) = CertStack::new() else {
        eprintf!("out of memory\n");
        return None;
    };
    for f in items(files) {
        let (_, certs) = load_cert_certs(&f, false, true, false, pass, desc, vpm)?;
        let certs = certs?;
        if !result.add_certs(&certs, a::X509_ADD_FLAG_UP_REF | a::X509_ADD_FLAG_NO_DUP) {
            eprintf!("out of memory\n");
            return None;
        }
    }
    Some(result)
}

/// `warn_cert` of `apps.c`.
pub fn warn_cert(uri: &str, cert: &Cert, warn_ee: bool, vpm: Option<&VerifyParam>) {
    let ex_flags = cert.extension_flags();
    let res = cert.cmp_timeframe(vpm);
    if res != 0 {
        let msg = if res > 0 {
            "has expired"
        } else {
            "not yet valid"
        };
        warn_cert_msg(uri, cert, msg);
    }
    let flag = |f: i32| u32::try_from(f).unwrap_or(0);
    if warn_ee && ex_flags & flag(a::EXFLAG_V1) == 0 && ex_flags & flag(a::EXFLAG_CA) == 0 {
        warn_cert_msg(uri, cert, "is not a CA cert");
    }
}

/// `next_item` of `apps.c`: the items of a list separated by commas and/or whitespace.
pub fn items(list: &str) -> Vec<String> {
    let mut out = Vec::new();
    let b = list.as_bytes();
    let mut i = 0;
    loop {
        let start = i;
        while i < b.len()
            && b.get(i) != Some(&b',')
            && !b.get(i).is_some_and(u8::is_ascii_whitespace)
        {
            i += 1;
        }
        out.push(String::from_utf8_lossy(b.get(start..i).unwrap_or_default()).into_owned());
        if i >= b.len() {
            break;
        }
        i += 1;
        while b.get(i).is_some_and(u8::is_ascii_whitespace) {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
    }
    out
}

/// `crls_http_cb`.
pub fn crls_http_cb(ctx: StoreCtxRef<'_>) -> Option<CrlStack> {
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

/// `warn_cert_msg` of `apps.c`.
pub fn warn_cert_msg(uri: &str, cert: &Cert, msg: &str) {
    let subj = x509::name_oneline(cert.subject_name()).unwrap_or_default();
    eprintf!("Warning: certificate from '{uri}' with subject '{subj}' {msg}\n");
}

/// `load_crl_crldp`: the CRL at the first distribution point with an HTTP URL.
pub fn load_crl_crldp(urls: &[Option<String>]) -> Option<rustyssl_ossl::x509::Crl> {
    let url = urls.iter().flatten().next()?;
    load_crl(Some(url), format::UNDEF, false, Some("CRL via CDP"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_item_lists() {
        assert_eq!(items("a,b c"), ["a", "b", "c"]);
        assert_eq!(items("a, b"), ["a", "b"]);
        assert_eq!(items("a,"), ["a"]);
        assert_eq!(items("a"), ["a"]);
        assert_eq!(items(""), [""]);
    }

    #[test]
    fn c_atoi() {
        assert_eq!(atoi(" 12x"), 12);
        assert_eq!(atoi("-3"), -3);
        assert_eq!(atoi("x"), 0);
        assert_eq!(atoi("99999999999"), i32::MAX);
    }

    #[test]
    fn yes_no() {
        assert!(parse_yesno(Some("Yes"), false));
        assert!(!parse_yesno(Some("0"), true));
        assert!(parse_yesno(Some("maybe"), true));
        assert!(!parse_yesno(None, false));
    }

    #[test]
    fn table_options() {
        let table: &[NameExTbl] = &[("a", 1, 0), ("b", 2, 0), ("c", 4, 0xff)];
        let mut f = 0x10;
        assert!(set_table_opts(&mut f, "A", table));
        assert_eq!(f, 0x11);
        assert!(set_table_opts(&mut f, "-a", table));
        assert_eq!(f, 0x10);
        assert!(set_table_opts(&mut f, "+c", table));
        assert_eq!(f, 4);
        assert!(!set_table_opts(&mut f, "d", table));
    }

    #[test]
    fn ext_copy_and_dates() {
        assert_eq!(set_ext_copy("CopyAll"), Some(ExtCopy::All));
        assert_eq!(set_ext_copy("x"), None);
        let mut d = 0;
        assert!(set_dateopt(&mut d, "ISO_8601"));
        assert_eq!(d, ul(ASN1_DTFLGS_ISO8601));
        assert!(!set_dateopt(&mut d, "x"));
    }

    #[test]
    fn errno_texts() {
        assert_eq!(strerror(2), "No such file or directory");
    }
}
