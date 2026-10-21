//! `openssl req` (`apps/req.c`), with `apps.c`'s `app_keygen` and `s_cb.c`'s `progress_cb`.

use std::collections::HashSet;
use std::io::{BufRead, IsTerminal, Write};

use rustyssl_ossl::abi::{
    MBSTRING_ASC, MBSTRING_UTF8, NID_ct_precert_poison, OPENSSL_DSA_MAX_MODULUS_BITS,
    OPENSSL_RSA_MAX_MODULUS_BITS, PEM_R_PROBLEMS_GETTING_PASSWORD, X509_REQ_VERSION_1,
    X509V3_CTX_REPLACE,
};
use rustyssl_ossl::conf::Conf;
use rustyssl_ossl::engine::{self, Engine};
use rustyssl_ossl::evp::Cipher;
use rustyssl_ossl::pkey::{self, KeygenCtx, Pkey};
use rustyssl_ossl::x509::{self, Cert, Integer, Name, Req, V3Ctx};
use rustyssl_ossl::{Bio, err};

use crate::cmd::x509::set_cert_times;
use crate::generated::options::req::{OPTIONS, Opt};
use crate::lib::app_libctx::{libctx, opt_provider, propq};
use crate::lib::app_rand;
use crate::lib::apps::{
    ConfigFile, ExtCopy, add_oid_section, app_conf_try_number, app_conf_try_string,
    app_load_config_bio, app_load_config_verbose, app_load_modules, app_passwd, atoi,
    bio_open_default, bio_open_owner, cert_matches_key, copy_extensions, do_x509_req_sign,
    do_x509_req_verify, do_x509_sign, get_nameopt, load_cert_pass, load_csr_autofmt, load_key,
    parse_name, pkey_ctrl_string, print_name, set_cert_ex, set_ext_copy, set_nameopt,
};
use crate::lib::ca_db::rand_serial;
use crate::lib::engine::setup_engine;
use crate::lib::io;
use crate::lib::opt::{self, Parser, eprintf, fmt_flags, format};

const BITS: &str = "default_bits";
const KEYFILE: &str = "default_keyfile";
const PROMPT: &str = "prompt";
const DISTINGUISHED_NAME: &str = "distinguished_name";
const ATTRIBUTES: &str = "attributes";
const V3_EXTENSIONS: &str = "x509_extensions";
const REQ_EXTENSIONS: &str = "req_extensions";
const STRING_MASK: &str = "string_mask";
const UTF8_IN: &str = "utf8";
const DEFAULT_KEY_LENGTH: i64 = 2048;
const MIN_KEY_LENGTH: i64 = 512;
const DEFAULT_DAYS: i32 = 30;
const UNSET_DAYS: i32 = -2;

/// What the prompting functions share (`section`, `req_conf`, `batch` of `req.c`).
struct Ctx<'a> {
    conf: &'a Conf,
    section: &'a str,
    batch: bool,
}

pub fn main(argv: &[String]) -> i32 {
    let ret = run(argv);
    if ret != 0 {
        io::print_errors();
    }
    ret
}

/// `progress_cb` of `s_cb.c`: one character per keygen step, to standard error.
fn progress_cb(p: core::ffi::c_int) {
    const SYMBOLS: &[u8] = b".+*\n";
    let c = usize::try_from(p)
        .ok()
        .and_then(|i| SYMBOLS.get(i))
        .copied()
        .unwrap_or(b'?');
    if let Some(b) = io::bio_err() {
        let _ = b.write_all(&[c]);
        b.flush();
    }
}

/// `app_keygen`.
fn app_keygen(ctx: &KeygenCtx, alg: Option<&str>, bits: i32, verbose: bool) -> Option<Pkey> {
    if verbose && let Some(a) = alg {
        eprintf!("Generating {a} key");
        if bits > 0 {
            eprintf!(" with {bits} bits\n");
        } else {
            eprintf!("\n");
        }
    }
    if !pkey::rand_status() {
        eprintf!(
            "Warning: generating random key material may take a long time\nif the system has a poor entropy source\n"
        );
    }
    let k = ctx.keygen();
    if k.is_none() {
        eprintf!(
            "{}: Error generating {} key\n",
            opt::prog(),
            alg.unwrap_or("asymmetric")
        );
    }
    k
}

/// `duplicated`: whether the `-addext` key is already given: `Ok(false)` if unique,
/// `Ok(true)` if found (reported), `Err(())` on a syntax error (reported).
fn duplicated(addexts: &mut HashSet<Vec<u8>>, kv: &str) -> Result<bool, ()> {
    let kv = kv.trim_start_matches(|c: char| c.is_ascii_whitespace() || c == '\x0b');
    let Some(off) = kv.find('=') else {
        eprintf!("Parse error on -addext: missing '='\n");
        return Err(());
    };
    let key = kv
        .get(..off)
        .unwrap_or_default()
        .trim_end_matches(|c: char| c.is_ascii_whitespace() || c == '\x0b');
    if key.is_empty() {
        eprintf!("Parse error on -addext: missing key\n");
        return Err(());
    }
    if !addexts.insert(key.as_bytes().to_vec()) {
        eprintf!("Duplicate extension name: {key}\n");
        return Ok(true);
    }
    Ok(false)
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

/// `set_keygen_ctx`: the keygen context for `-newkey` (`None`: the default RSA), its key
/// type, and the key length (`pkeylen` updated).
fn set_keygen_ctx(
    gstr: Option<&str>,
    pkeylen: &mut i64,
    keygen_engine: Option<&Engine>,
) -> Option<(KeygenCtx, String)> {
    let mut keylen: i64 = -1;
    let mut keytype: Option<String> = None;
    let mut expect_paramfile = false;
    let mut paramfile: Option<&str> = None;
    let mut rest = gstr;
    match gstr {
        None => {
            keytype = Some("RSA".to_owned());
            keylen = *pkeylen;
        }
        Some(g) if g.as_bytes().first().is_some_and(u8::is_ascii_digit) => {
            keytype = Some("RSA".to_owned());
        }
        Some(g) => {
            let (first, second) = match g.split_once(':') {
                Some((a, b)) => (a, Some(b)),
                None => (g, None),
            };
            if b"param".starts_with(first.as_bytes()) {
                expect_paramfile = true;
                if second.is_none() {
                    eprintf!("Parameter file requested but no path given: {g}\n");
                    return None;
                }
            } else {
                keytype = Some(first.to_owned());
            }
            rest = second;
        }
    }
    if let Some(g) = rest {
        if !expect_paramfile && g.as_bytes().first().is_some_and(u8::is_ascii_digit) {
            keylen = atol(g);
        } else {
            paramfile = Some(g);
        }
    }
    let lc = libctx();
    let pq = propq();
    let mut param: Option<Pkey> = None;
    if let Some(pf) = paramfile {
        let Some(pbio) = Bio::new_file(pf, "r") else {
            eprintf!("Cannot open parameter file {pf}\n");
            return None;
        };
        param = Pkey::read_params_pem(&pbio);
        if param.is_none() {
            pbio.reset();
            param = Cert::read_pem_bio(&pbio).and_then(|x| x.pubkey());
        }
        let Some(p) = &param else {
            eprintf!("Error reading parameter file {pf}\n");
            return None;
        };
        if keytype.is_none() {
            match p.type_name() {
                Some(t) => keytype = Some(t),
                None => {
                    eprintf!("Unable to determine key type\n");
                    return None;
                }
            }
        }
    }
    let keytype = keytype.unwrap_or_default();
    if keylen >= 0 {
        *pkeylen = keylen;
    }
    let gctx = if let Some(p) = &param {
        if !p.is_a(&keytype) {
            eprintf!("Key type does not match parameters\n");
            return None;
        }
        let g = match keygen_engine {
            Some(e) => KeygenCtx::with_engine(p, e),
            None => KeygenCtx::from_pkey(lc.as_deref(), p, pq.as_deref()),
        };
        *pkeylen = i64::from(p.bits());
        g
    } else {
        match keygen_engine {
            Some(e) => {
                let id = engine::legacy_pkey_id(&keytype, Some(e));
                if id != 0 {
                    KeygenCtx::from_id(id, e)
                } else {
                    None
                }
            }
            None => KeygenCtx::from_name(lc.as_deref(), &keytype, pq.as_deref()),
        }
    };
    let Some(gctx) = gctx else {
        eprintf!("Error allocating keygen context\n");
        return None;
    };
    if gctx.keygen_init() <= 0 {
        eprintf!("Error initializing keygen context\n");
        return None;
    }
    if keylen == -1 && (gctx.is_a("RSA") || gctx.is_a("RSA-PSS")) {
        keylen = *pkeylen;
    }
    if keylen != -1 {
        let bits = usize::try_from(keylen).unwrap_or(usize::MAX);
        if gctx.set_bits(bits) <= 0 {
            eprintf!("Error setting keysize\n");
            return None;
        }
    }
    Some((gctx, keytype))
}

/// `check_end`: whether `s` ends with `end`.
fn ends_with(s: &str, end: &str) -> bool {
    s.len() >= end.len() && s.ends_with(end)
}

/// `join`: `name` + `tail`, if it fits a buffer of `buf_size`.
fn join(buf_size: usize, name: &str, tail: &str, desc: &str) -> Option<String> {
    if name.len() + tail.len() + 1 > buf_size {
        eprintf!("{desc} '{name}' too long\n");
        return None;
    }
    Some(format!("{name}{tail}"))
}

/// `fgets(buf, size, stdin)`: up to `size - 1` bytes, through a newline; `None` at the end.
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

/// `req_check_len`.
fn req_check_len(len: usize, n_min: i64, n_max: i64) -> bool {
    let len = i64::try_from(len).unwrap_or(i64::MAX);
    if n_min > 0 && len < n_min {
        eprintf!("String too short, must be at least {n_min} bytes long\n");
        return false;
    }
    if n_max >= 0 && len > n_max {
        eprintf!("String too long, must be at most {n_max} bytes long\n");
        return false;
    }
    true
}

/// `build_data`: 0 on error, 1 to skip the field, else the value to add.
#[allow(clippy::too_many_arguments)]
fn build_data(
    c: &Ctx<'_>,
    text: &str,
    def: &str,
    value: Option<&str>,
    n_min: i64,
    n_max: i64,
    desc1: &str,
    desc2: &str,
) -> Result<Option<Vec<u8>>, ()> {
    const BUF_SIZE: usize = 1024;
    loop {
        if !c.batch {
            eprintf!("{text} [{def}]:");
        }
        let mut buf: Vec<u8> = match value {
            Some(v) => {
                let b = join(BUF_SIZE, v, "\n", desc1).ok_or(())?;
                eprintf!("{v}\n");
                b.into_bytes()
            }
            None => {
                if !c.batch {
                    fgets(BUF_SIZE).ok_or(())?
                } else {
                    b"\n".to_vec()
                }
            }
        };
        match buf.first() {
            None | Some(0) => return Err(()),
            Some(b'\n') => {
                if def.is_empty() {
                    return Ok(None);
                }
                buf = join(BUF_SIZE, def, "\n", desc2).ok_or(())?.into_bytes();
            }
            Some(b'.') if buf.get(1) == Some(&b'\n') => return Ok(None),
            _ => {}
        }
        // The C string ends at its first NUL.
        if let Some(n) = buf.iter().position(|&b| b == 0) {
            buf.truncate(n);
        }
        if buf.last() != Some(&b'\n') {
            eprintf!("Missing newline at end of input\n");
            return Err(());
        }
        buf.pop();
        if !req_check_len(buf.len(), n_min, n_max) {
            if c.batch || value.is_some() {
                return Err(());
            }
            continue;
        }
        return Ok(Some(buf));
    }
}

/// The field of a `distinguished_name` entry's name: past a leading `X.`, `X:` or `X,`, and
/// whether it starts with `+` (a multi-valued RDN's next part).
fn dn_field(name: &str) -> (&str, bool) {
    let mut ty = name;
    if let Some(i) = name.find([':', ',', '.']) {
        let after = name.get(i + 1..).unwrap_or_default();
        if !after.is_empty() {
            ty = after;
        }
    }
    match ty.strip_prefix('+') {
        Some(t) => (t, true),
        None => (ty, false),
    }
}

/// `prompt_info`.
#[allow(clippy::too_many_arguments)]
fn prompt_info(
    c: &Ctx<'_>,
    req: &Req,
    dn_sk: Option<&[(String, String)]>,
    dn_sect: Option<&str>,
    attr_sk: Option<&[(String, String)]>,
    attr_sect: Option<&str>,
    attribs: bool,
    chtype: i32,
) -> bool {
    if !c.batch {
        eprintf!("You are about to be asked to enter information that will be incorporated\n");
        eprintf!("into your certificate request.\n");
        eprintf!("What you are about to enter is what is called a Distinguished Name or a DN.\n");
        eprintf!("There are quite a few fields but you can leave some blank\n");
        eprintf!("For some fields there will be a default value,\n");
        eprintf!("If you enter '.', the field will be left blank.\n");
        eprintf!("-----\n");
    }
    let dn = dn_sk.unwrap_or_default();
    // `sk_CONF_VALUE_num` of a NULL stack is -1, which counts as a template.
    if dn_sk.is_some() && dn.is_empty() {
        eprintf!("No template, please set one up.\n");
        return false;
    }
    let try_str = |sect: Option<&str>, k: &str| app_conf_try_string(c.conf, sect, k);
    let try_num = |sect: Option<&str>, k: &str| app_conf_try_number(c.conf, sect, k);
    for (name, value) in dn {
        if ["_min", "_max", "_default", "_value"]
            .iter()
            .any(|e| ends_with(name, e))
        {
            continue;
        }
        let (ty, multi) = dn_field(name);
        let nid = x509::txt2nid(ty);
        if nid == 0 {
            continue;
        }
        let Some(k) = join(100, name, "_default", "Name") else {
            return false;
        };
        let def = try_str(dn_sect, &k).unwrap_or_default();
        let Some(k) = join(100, name, "_value", "Name") else {
            return false;
        };
        let val = try_str(dn_sect, &k);
        let Some(k) = join(100, name, "_min", "Name") else {
            return false;
        };
        let n_min = try_num(dn_sect, &k).unwrap_or(-1);
        let Some(k) = join(100, name, "_max", "Name") else {
            return false;
        };
        let n_max = try_num(dn_sect, &k).unwrap_or(-1);
        match build_data(
            c,
            value,
            &def,
            val.as_deref(),
            n_min,
            n_max,
            "DN value",
            "DN default",
        ) {
            Err(()) => return false,
            Ok(None) => {}
            Ok(Some(buf)) => {
                if !req.add_subject_entry_by_nid(nid, chtype, &buf, if multi { -1 } else { 0 }) {
                    return false;
                }
            }
        }
    }
    if req.subject_name().entry_count() == 0 {
        eprintf!("Error: No objects specified in config file\n");
        return false;
    }
    if attribs {
        let attrs = attr_sk.unwrap_or_default();
        if attr_sk.is_some() && !attrs.is_empty() && !c.batch {
            eprintf!("\nPlease enter the following 'extra' attributes\n");
            eprintf!("to be sent with your certificate request\n");
        }
        for (ty, value) in attrs {
            let nid = x509::txt2nid(ty);
            if nid == 0 {
                continue;
            }
            let Some(k) = join(100, ty, "_default", "Name") else {
                return false;
            };
            let def = try_str(attr_sect, &k).unwrap_or_default();
            let Some(k) = join(100, ty, "_value", "Name") else {
                return false;
            };
            let val = try_str(attr_sect, &k);
            let Some(k) = join(100, ty, "_min", "Name") else {
                return false;
            };
            let n_min = try_num(attr_sect, &k).unwrap_or(-1);
            let Some(k) = join(100, ty, "_max", "Name") else {
                return false;
            };
            let n_max = try_num(attr_sect, &k).unwrap_or(-1);
            match build_data(
                c,
                value,
                &def,
                val.as_deref(),
                n_min,
                n_max,
                "Attribute value",
                "Attribute default",
            ) {
                Err(()) => return false,
                Ok(None) => {}
                Ok(Some(buf)) => {
                    if !req.add1_attr_by_nid(nid, chtype, &buf) {
                        eprintf!("Error adding attribute\n");
                        return false;
                    }
                }
            }
        }
    }
    true
}

/// `auto_info`.
fn auto_info(
    req: &Req,
    dn_sk: Option<&[(String, String)]>,
    attr_sk: Option<&[(String, String)]>,
    attribs: bool,
    chtype: i32,
) -> bool {
    for (name, value) in dn_sk.unwrap_or_default() {
        let (ty, multi) = dn_field(name);
        if !req.add_subject_entry_by_txt(ty, chtype, value, if multi { -1 } else { 0 }) {
            return false;
        }
    }
    if req.subject_name().entry_count() == 0 {
        eprintf!("Error: No objects specified in config file\n");
        return false;
    }
    if attribs {
        for (name, value) in attr_sk.unwrap_or_default() {
            if !req.add1_attr_by_txt(name, chtype, value) {
                return false;
            }
        }
    }
    true
}

/// `make_REQ`.
fn make_req(
    c: &Ctx<'_>,
    req: &Req,
    pkey: Option<&Pkey>,
    fsubj: Option<&Name>,
    attribs: bool,
    chtype: i32,
) -> bool {
    let no_prompt = app_conf_try_string(c.conf, Some(c.section), PROMPT).is_some_and(|t| t == "no");
    let dn_sect = app_conf_try_string(c.conf, Some(c.section), DISTINGUISHED_NAME);
    let mut dn_sk = None;
    if let Some(s) = &dn_sect {
        match c.conf.get_section(s) {
            Some(v) => dn_sk = Some(v),
            None => {
                eprintf!("Unable to get '{s}' section\n");
                return false;
            }
        }
    }
    let attr_sect = app_conf_try_string(c.conf, Some(c.section), ATTRIBUTES);
    let mut attr_sk = None;
    if let Some(s) = &attr_sect {
        match c.conf.get_section(s) {
            Some(v) => attr_sk = Some(v),
            None => {
                eprintf!("Unable to get '{s}' section\n");
                return false;
            }
        }
    }
    if !req.set_version(X509_REQ_VERSION_1.into()) {
        return false;
    }
    let ok = if let Some(n) = fsubj {
        req.set_subject_name(n.as_name())
    } else if no_prompt {
        auto_info(req, dn_sk.as_deref(), attr_sk.as_deref(), attribs, chtype)
    } else {
        prompt_info(
            c,
            req,
            dn_sk.as_deref(),
            dn_sect.as_deref(),
            attr_sk.as_deref(),
            attr_sect.as_deref(),
            attribs,
            chtype,
        )
    };
    ok && req.set_pubkey(pkey)
}

#[allow(clippy::too_many_lines)]
fn run(argv: &[String]) -> i32 {
    let mut serial: Option<Integer> = None;
    let mut e: Option<Engine> = None;
    let mut gen_eng: Option<Engine> = None;
    let mut pkeyopts: Vec<String> = Vec::new();
    let mut sigopts: Vec<String> = Vec::new();
    let mut vfyopts: Vec<String> = Vec::new();
    let mut addexts: Option<(HashSet<Vec<u8>>, String)> = None;
    let mut cipher = Cipher::aes_256_cbc();
    let mut ext_copy: Option<ExtCopy> = None;
    let mut extsect: Option<String> = None;
    let (mut infile, mut ca_file, mut ca_keyfile): (
        Option<String>,
        Option<String>,
        Option<String>,
    ) = (None, None, None);
    let (mut outfile, mut keyfile, mut digest): (Option<String>, Option<String>, Option<String>) =
        (None, None, None);
    let (mut passargin, mut passargout): (Option<String>, Option<String>) = (None, None);
    let mut subj: Option<String> = None;
    let mut template = ConfigFile::Default;
    let mut keyout: Option<String> = None;
    let mut keyalg: Option<String> = None;
    let (mut not_before, mut not_after): (Option<String>, Option<String>) = (None, None);
    let mut section = "req".to_owned();
    let mut batch = false;
    let mut days = UNSET_DAYS;
    let (mut gen_x509, mut newreq, mut verbose, mut progress) = (false, false, false, true);
    let (mut informat, mut outformat, mut keyform) = (format::UNDEF, format::PEM, format::UNDEF);
    let (mut modulus, mut verify, mut noout, mut text) = (false, false, false, false);
    let (mut noenc, mut newhdr, mut subject, mut pubkey, mut precert, mut x509v1) =
        (false, false, false, false, false, false);

    let mut chtype = MBSTRING_ASC;
    let mut reqflag: core::ffi::c_ulong = 0;

    let mut p = Parser::with_unknown(argv, OPTIONS, Some("digest"));
    let prog = p.prog();
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
            Opt::INFORM => match opt::parse_format(p.arg(), fmt_flags::PEMDER) {
                Some(f) => informat = f,
                None => return opthelp(),
            },
            Opt::OUTFORM => match opt::parse_format(p.arg(), fmt_flags::PEMDER) {
                Some(f) => outformat = f,
                None => return opthelp(),
            },
            Opt::ENGINE => e = setup_engine(Some(p.arg()), false),
            Opt::KEYGEN_ENGINE => {
                gen_eng = setup_engine(Some(p.arg()), false);
                if gen_eng.is_none() {
                    let argv0 = argv.first().map_or("", String::as_str);
                    eprintf!("Can't find keygen engine {argv0}\n");
                    return opthelp();
                }
            }
            Opt::KEY => keyfile = Some(p.arg().to_owned()),
            Opt::PUBKEY => pubkey = true,
            Opt::NEW => newreq = true,
            Opt::CONFIG => template = ConfigFile::Given(p.arg().to_owned()),
            Opt::SECTION => section = p.arg().to_owned(),
            Opt::KEYFORM => match opt::parse_format(p.arg(), fmt_flags::ANY) {
                Some(f) => keyform = f,
                None => return opthelp(),
            },
            Opt::IN => infile = Some(p.arg().to_owned()),
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::KEYOUT => keyout = Some(p.arg().to_owned()),
            Opt::PASSIN => passargin = Some(p.arg().to_owned()),
            Opt::PASSOUT => passargout = Some(p.arg().to_owned()),
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
            Opt::NEWKEY => {
                keyalg = Some(p.arg().to_owned());
                newreq = true;
            }
            Opt::PKEYOPT => pkeyopts.push(p.arg().to_owned()),
            Opt::SIGOPT => sigopts.push(p.arg().to_owned()),
            Opt::VFYOPT => vfyopts.push(p.arg().to_owned()),
            Opt::BATCH => batch = true,
            Opt::NEWHDR => newhdr = true,
            Opt::MODULUS => modulus = true,
            Opt::VERIFY => verify = true,
            Opt::NODES | Opt::NOENC => noenc = true,
            Opt::NOOUT => noout = true,
            Opt::VERBOSE => (verbose, progress) = (true, true),
            Opt::QUIET => (verbose, progress) = (false, false),
            Opt::UTF8 => chtype = MBSTRING_UTF8,
            Opt::NAMEOPT => {
                if !set_nameopt(Some(p.arg())) {
                    return opthelp();
                }
            }
            Opt::REQOPT => {
                if !set_cert_ex(&mut reqflag, Some(p.arg())) {
                    return opthelp();
                }
            }
            Opt::TEXT => text = true,
            Opt::X509V1 => (x509v1, gen_x509) = (true, true),
            Opt::X509 => gen_x509 = true,
            Opt::CA => {
                ca_file = Some(p.arg().to_owned());
                gen_x509 = true;
            }
            Opt::CAKEY => ca_keyfile = Some(p.arg().to_owned()),
            Opt::NOT_BEFORE => not_before = Some(p.arg().to_owned()),
            Opt::NOT_AFTER => not_after = Some(p.arg().to_owned()),
            Opt::DAYS => {
                days = atoi(p.arg());
                if days <= UNSET_DAYS {
                    eprintf!("{prog}: -days parameter arg must be >= -1\n");
                    return 1;
                }
            }
            Opt::SET_SERIAL => {
                if serial.is_some() {
                    eprintf!("Serial number supplied twice\n");
                    return opthelp();
                }
                serial = Integer::from_dec_or_hex(p.arg());
                if serial.is_none() {
                    return opthelp();
                }
            }
            Opt::SUBJECT => subject = true,
            Opt::SUBJ => subj = Some(p.arg().to_owned()),
            Opt::MULTIVALUE_RDN => {}
            Opt::COPY_EXTENSIONS => match set_ext_copy(p.arg()) {
                Some(c) => ext_copy = Some(c),
                None => {
                    eprintf!("Invalid extension copy option: \"{}\"\n", p.arg());
                    return 1;
                }
            },
            Opt::EXTENSIONS | Opt::REQEXTS => extsect = Some(p.arg().to_owned()),
            Opt::ADDEXT => {
                let (set, text) = addexts.get_or_insert_with(|| (HashSet::new(), String::new()));
                match duplicated(set, p.arg()) {
                    Ok(true) | Err(()) => return 1,
                    Ok(false) => {
                        text.push_str(p.arg());
                        text.push('\n');
                    }
                }
            }
            Opt::PRECERT => (newreq, precert) = (true, true),
            Opt::CIPHER => match Cipher::by_name(p.arg()) {
                Some(c) => cipher = Some(c),
                None => {
                    eprintf!("Unknown cipher: {}\n", p.arg());
                    return opthelp();
                }
            },
            Opt::MD => digest = p.unknown().map(str::to_owned),
        }
    }
    if !p.check_rest_arg(None) {
        return opthelp();
    }
    if !app_rand::load() {
        return 1;
    }
    if !gen_x509 {
        if days != UNSET_DAYS {
            eprintf!("Warning: Ignoring -days without -x509; not generating a certificate\n");
        }
        if not_before.is_some() {
            eprintf!("Warning: Ignoring -not_before without -x509; not generating a certificate\n");
        }
        if not_after.is_some() {
            eprintf!("Warning: Ignoring -not_after without -x509; not generating a certificate\n");
        }
        if ext_copy == Some(ExtCopy::None) {
            eprintf!("Warning: Ignoring -copy_extensions 'none' when -x509 is not given\n");
        }
    }
    if infile.is_none() {
        if gen_x509 {
            newreq = true;
        } else if !newreq && std::io::stdin().is_terminal() {
            eprintf!("Warning: Will read cert request from stdin since no -in option is given\n");
        }
    }
    let Some((passin, passout)) = app_passwd(passargin.as_deref(), passargout.as_deref()) else {
        eprintf!("Error getting passwords\n");
        return 1;
    };
    let mut passin = passin.map(|p| p.as_str().to_owned());
    let mut passout = passout.map(|p| p.as_str().to_owned());

    let template_name = template.name().unwrap_or_default();
    let Some(req_conf) = app_load_config_verbose(&template_name, verbose) else {
        return 1;
    };
    let mut addext_conf = None;
    if let Some((_, text)) = &addexts {
        if verbose {
            eprintf!("Using additional configuration from -addext options\n");
        }
        let Some(bio) = Bio::from_bytes(text.as_bytes()) else {
            return 1;
        };
        match app_load_config_bio(&bio, None) {
            Some(c) => addext_conf = Some(c),
            None => return 1,
        }
    }
    if template != ConfigFile::Default && !app_load_modules(Some(&req_conf)) {
        return 1;
    }
    if let Some(f) = app_conf_try_string(&req_conf, None, "oid_file") {
        match Bio::new_file(&f, "r") {
            None => {
                if verbose {
                    eprintf!("Problems opening '{f}' for extra OIDs\n");
                }
            }
            Some(b) => {
                x509::obj_create_objects(&b);
            }
        }
    }
    if !add_oid_section(&req_conf) {
        return 1;
    }
    let sect = Some(section.as_str());
    match &digest {
        Some(d) => {
            if !opt::check_md(d) {
                return opthelp();
            }
        }
        None => digest = app_conf_try_string(&req_conf, sect, "default_md"),
    }
    if extsect.is_none() {
        let which = if gen_x509 {
            V3_EXTENSIONS
        } else {
            REQ_EXTENSIONS
        };
        extsect = app_conf_try_string(&req_conf, sect, which);
    }
    if let Some(s) = &extsect {
        let mut ctx = V3Ctx::test();
        ctx.set_nconf(&req_conf);
        if !ctx.add_nconf(&req_conf, s, None) {
            let what = if gen_x509 { "x509" } else { "request" };
            eprintf!("Error checking {what} extension section {s}\n");
            return 1;
        }
    }
    if let Some(ac) = &addext_conf {
        let mut ctx = V3Ctx::test();
        ctx.set_nconf(&req_conf);
        if !ctx.add_nconf(ac, "default", None) {
            eprintf!("Error checking extensions defined using -addext\n");
            return 1;
        }
    }
    if passin.is_none() {
        passin = app_conf_try_string(&req_conf, sect, "input_password");
    }
    if passout.is_none() {
        passout = app_conf_try_string(&req_conf, sect, "output_password");
    }
    if let Some(m) = app_conf_try_string(&req_conf, sect, STRING_MASK)
        && !x509::set_default_mask_asc(&m)
    {
        eprintf!("Invalid global string mask setting {m}\n");
        return 1;
    }
    if chtype != MBSTRING_UTF8
        && app_conf_try_string(&req_conf, sect, UTF8_IN).is_some_and(|v| v == "yes")
    {
        chtype = MBSTRING_UTF8;
    }

    let mut pkey: Option<Pkey> = None;
    if let Some(k) = &keyfile {
        pkey = load_key(
            Some(k),
            keyform,
            false,
            passin.as_deref(),
            e.as_ref(),
            Some("private key"),
        );
        if pkey.is_none() {
            return 1;
        }
        app_rand::load_conf(&req_conf, sect);
    }
    if keyalg.is_some() && pkey.is_some() {
        eprintf!("Warning: Not generating key via given -newkey option since -key is given\n");
    }
    if newreq && pkey.is_none() {
        app_rand::load_conf(&req_conf, sect);
        let mut newkey_len =
            app_conf_try_number(&req_conf, sect, BITS).unwrap_or(DEFAULT_KEY_LENGTH);
        let Some((genctx, keyalgstr)) =
            set_keygen_ctx(keyalg.as_deref(), &mut newkey_len, gen_eng.as_ref())
        else {
            return 1;
        };
        let rsa = genctx.is_a("RSA") || genctx.is_a("RSA-PSS");
        if newkey_len < MIN_KEY_LENGTH && (rsa || genctx.is_a("DSA")) {
            eprintf!(
                "Private key length too short, needs to be at least {MIN_KEY_LENGTH} bits, not {newkey_len}.\n"
            );
            return 1;
        }
        if newkey_len > i64::from(OPENSSL_RSA_MAX_MODULUS_BITS) && rsa {
            eprintf!(
                "Warning: It is not recommended to use more than {OPENSSL_RSA_MAX_MODULUS_BITS} bit for RSA keys.\n         Your key size is {newkey_len}! Larger key size may behave not as expected.\n"
            );
        }
        if genctx.is_a("DSA") && newkey_len > i64::from(OPENSSL_DSA_MAX_MODULUS_BITS) {
            eprintf!(
                "Warning: It is not recommended to use more than {OPENSSL_DSA_MAX_MODULUS_BITS} bit for DSA keys.\n         Your key size is {newkey_len}! Larger key size may behave not as expected.\n"
            );
        }
        for genopt in &pkeyopts {
            if pkey_ctrl_string(genctx.as_ref(), genopt) <= 0 {
                eprintf!("Key parameter error \"{genopt}\"\n");
                return 1;
            }
        }
        if progress {
            genctx.set_progress_cb(progress_cb);
        }
        // C passes the long to an int.
        let bits = i32::try_from(newkey_len).unwrap_or(i32::MAX);
        pkey = app_keygen(&genctx, Some(&keyalgstr), bits, verbose);
        if pkey.is_none() {
            return 1;
        }
    }
    if keyout.is_none() && keyfile.is_none() {
        keyout = app_conf_try_string(&req_conf, sect, KEYFILE);
    }
    if let Some(k) = &pkey
        && (keyfile.is_none() || keyout.is_some())
    {
        if verbose {
            eprintf!("Writing private key to ");
            match &keyout {
                None => eprintf!("stdout\n"),
                Some(f) => eprintf!("'{f}'\n"),
            };
        }
        let Some(out) = bio_open_owner(keyout.as_deref(), outformat, true) else {
            return 1;
        };
        let enc = app_conf_try_string(&req_conf, sect, "encrypt_rsa_key")
            .or_else(|| app_conf_try_string(&req_conf, sect, "encrypt_key"));
        if enc.is_some_and(|v| v == "no") || noenc {
            cipher = None;
        }
        let mut tries = 0;
        loop {
            if k.write_private_pem_enc(&out, cipher.as_ref(), passout.as_deref()) != 0 {
                break;
            }
            if err::reason(err::peek_error()) == PEM_R_PROBLEMS_GETTING_PASSWORD && tries < 3 {
                err::clear();
                tries += 1;
                continue;
            }
            return 1;
        }
        drop(out);
        eprintf!("-----\n");
    }

    let mut fsubj: Option<Name> = None;
    if let Some(s) = &subj {
        fsubj = parse_name(s, chtype, true, "subject");
        if fsubj.is_none() {
            return 1;
        }
    }
    let mut req: Option<Req> = None;
    if !newreq {
        if keyfile.is_some() {
            eprintf!("Warning: Not placing -key in cert or request since request is used\n");
        }
        req = load_csr_autofmt(infile.as_deref(), informat, &vfyopts, "X509 request");
        if req.is_none() {
            return 1;
        }
    } else if infile.is_some() {
        eprintf!("Warning: Ignoring -in option since -new or -newkey or -precert is given\n");
    }

    let ca_key_given = ca_keyfile.is_some();
    if ca_keyfile.is_none() {
        ca_keyfile.clone_from(&ca_file);
    }
    let mut ca_key: Option<Pkey> = None;
    if let Some(k) = &ca_keyfile {
        if ca_file.is_none() {
            eprintf!("Warning: Ignoring -CAkey option since no -CA option is given\n");
        } else {
            let desc = if ca_key_given {
                "issuer private key from -CAkey arg"
            } else {
                "issuer private key from -CA arg"
            };
            ca_key = load_key(
                Some(k),
                format::UNDEF,
                false,
                passin.as_deref(),
                e.as_ref(),
                Some(desc),
            );
            if ca_key.is_none() {
                return 1;
            }
        }
    }
    let mut ca_cert: Option<Cert> = None;
    if let Some(f) = &ca_file {
        ca_cert = load_cert_pass(
            Some(f),
            format::UNDEF,
            true,
            passin.as_deref(),
            Some("issuer cert from -CA arg"),
        );
        let Some(c) = &ca_cert else {
            return 1;
        };
        if !ca_key.as_ref().is_some_and(|k| c.check_private_key(k)) {
            eprintf!("Issuer CA certificate and key do not match\n");
            return 1;
        }
    }

    let lc = libctx();
    let pq = propq();
    let c = Ctx {
        conf: &req_conf,
        section: &section,
        batch,
    };
    let mut new_x509: Option<Cert> = None;
    if newreq || gen_x509 {
        if ca_cert.is_none() && pkey.is_none() {
            eprintf!("Must provide a signature key using -key or provide -CA / -CAkey\n");
            return 1;
        }
        if req.is_none() {
            let Some(r) = Req::new_ex(lc.as_deref(), pq.as_deref()) else {
                return 1;
            };
            if !make_req(&c, &r, pkey.as_ref(), fsubj.as_ref(), !gen_x509, chtype) {
                eprintf!("Error making certificate request\n");
                return 1;
            }
            req = Some(r);
        }
        let Some(r) = &req else {
            return 1;
        };
        if gen_x509 {
            let pub_key = r.pubkey();
            let issuer_key = if ca_cert.is_some() {
                ca_key.as_ref()
            } else {
                pkey.as_ref()
            };
            let Some(issuer_key) = issuer_key else {
                return 1;
            };
            if ca_cert.is_some() && keyfile.is_some() {
                eprintf!(
                    "Warning: Not using -key or -newkey for signing since -CA option is given\n"
                );
            }
            let Some(x) = Cert::new_ex(lc.as_deref(), pq.as_deref()) else {
                return 1;
            };
            match &serial {
                Some(s) => {
                    if !x.set_serial(s) {
                        return 1;
                    }
                }
                None => match rand_serial() {
                    Some((_, s)) if x.set_serial(&s) => {}
                    _ => return 1,
                },
            }
            let issuer = match &ca_cert {
                Some(ca) => ca.subject_name(),
                None => r.subject_name(),
            };
            if !x.set_issuer_name(issuer) {
                return 1;
            }
            if days == UNSET_DAYS {
                days = DEFAULT_DAYS;
            } else if not_after.is_some() {
                eprintf!("Warning: -not_after option overriding -days option\n");
            }
            if !set_cert_times(&x, not_before.as_deref(), not_after.as_deref(), days, true) {
                return 1;
            }
            let n_subj = match &fsubj {
                Some(n) => n.as_name(),
                None => r.subject_name(),
            };
            if !x.set_subject_name(n_subj) {
                return 1;
            }
            if !pub_key.as_ref().is_some_and(|k| x.set_pubkey(k)) {
                return 1;
            }
            match ext_copy {
                None => {
                    if infile.is_some() {
                        eprintf!(
                            "Warning: No -copy_extensions given; ignoring any extensions in the request\n"
                        );
                    }
                }
                Some(copy) => {
                    if !copy_extensions(&x, r, copy) {
                        eprintf!("Error copying extensions from request\n");
                        return 1;
                    }
                }
            }
            {
                let issuer_cert = ca_cert.as_ref().unwrap_or(&x);
                let mut ext_ctx =
                    V3Ctx::new(Some(issuer_cert), Some(&x), None, None, X509V3_CTX_REPLACE);
                if ca_cert.is_none() {
                    if !ext_ctx.set_issuer_pkey(Some(issuer_key)) {
                        return 1;
                    }
                    if !cert_matches_key(&x, issuer_key) {
                        eprintf!("Warning: Signature key and public key of cert do not match\n");
                    }
                }
                ext_ctx.set_nconf(&req_conf);
                if let Some(s) = &extsect
                    && !ext_ctx.add_nconf(&req_conf, s, Some(&x))
                {
                    eprintf!("Error adding x509 extensions from section {s}\n");
                    return 1;
                }
                if let Some(ac) = &addext_conf
                    && !ext_ctx.add_nconf(ac, "default", Some(&x))
                {
                    eprintf!("Error adding x509 extensions defined via -addext\n");
                    return 1;
                }
                if precert && x.add1_ext_null(NID_ct_precert_poison, 1) != 1 {
                    eprintf!("Error adding poison extension\n");
                    return 1;
                }
                if !do_x509_sign(
                    &x,
                    x509v1,
                    issuer_key,
                    digest.as_deref(),
                    &sigopts,
                    &mut ext_ctx,
                ) {
                    return 1;
                }
            }
            new_x509 = Some(x);
        } else {
            if precert {
                eprintf!("Warning: Ignoring -precert flag since no cert is produced\n");
            }
            let mut ext_ctx = V3Ctx::new(None, None, Some(r), None, X509V3_CTX_REPLACE);
            ext_ctx.set_nconf(&req_conf);
            if let Some(s) = &extsect
                && !ext_ctx.req_add_nconf(&req_conf, s, Some(r))
            {
                eprintf!("Error adding request extensions from section {s}\n");
                return 1;
            }
            if let Some(ac) = &addext_conf
                && !ext_ctx.req_add_nconf(ac, "default", Some(r))
            {
                eprintf!("Error adding request extensions defined via -addext\n");
                return 1;
            }
            drop(ext_ctx);
            let Some(k) = &pkey else {
                return 1;
            };
            if !do_x509_req_sign(r, k, digest.as_deref(), &sigopts) {
                return 1;
            }
        }
    }
    let Some(req) = req else {
        return 1;
    };

    if let Some(n) = &fsubj
        && !newreq
        && !gen_x509
    {
        // With -verbose, upstream prints the old and new subjects to its output BIO, which
        // isn't open here (NULL), so nothing is printed.
        if !req.set_subject_name(n.as_name()) {
            eprintf!("Error modifying subject of certificate request\n");
            return 1;
        }
    }

    if verify {
        let owned;
        let tpubkey = match &pkey {
            Some(k) => k,
            None => match req.pubkey() {
                Some(k) => {
                    owned = k;
                    &owned
                }
                None => return 1,
            },
        };
        let i = do_x509_req_verify(&req, Some(tpubkey), &vfyopts);
        if i < 0 {
            return 1;
        }
        if i == 0 {
            eprintf!("Certificate request self-signature verify failure\n");
            return 1;
        }
        let _ = io::out().write_all(b"Certificate request self-signature verify OK\n");
    }

    if noout && !text && !modulus && !subject && !pubkey {
        return 0;
    }
    let mode = if keyout.is_some() && keyout == outfile {
        'a'
    } else {
        'w'
    };
    let Some(out) = bio_open_default(outfile.as_deref(), mode, outformat) else {
        return 1;
    };
    let o = &out;
    if pubkey {
        let Some(k) = req.pubkey() else {
            eprintf!("Error getting public key\n");
            return 1;
        };
        k.write_pubkey_pem(&out);
    }
    if text {
        let r = match &new_x509 {
            Some(x) if gen_x509 => x.print_ex(&out, get_nameopt(), reqflag),
            _ => req.print_ex(&out, get_nameopt(), reqflag),
        };
        if r == 0 {
            if gen_x509 {
                eprintf!("Error printing certificate\n");
            } else {
                eprintf!("Error printing certificate request\n");
            }
            return 1;
        }
    }
    if subject {
        let nm = match &new_x509 {
            Some(x) if gen_x509 => x.subject_name(),
            _ => req.subject_name(),
        };
        print_name(&out, Some("subject="), nm);
    }
    if modulus {
        let tpubkey = match &new_x509 {
            Some(x) if gen_x509 => x.pubkey(),
            _ => req.pubkey(),
        };
        let Some(tpubkey) = tpubkey else {
            eprintf!("Modulus is unavailable\n");
            return 1;
        };
        let _ = o.write_all(b"Modulus=");
        if tpubkey.is_a("RSA") || tpubkey.is_a("RSA-PSS") {
            let Some(n) = tpubkey.bn_param(c"n") else {
                return 1;
            };
            x509::bn_print(&out, Some(&n));
        } else {
            let _ = o.write_all(b"Wrong Algorithm type");
        }
        let _ = o.write_all(b"\n");
    }
    if !noout && !gen_x509 {
        let i = if outformat == format::ASN1 {
            req.write_der(&out)
        } else if newhdr {
            req.write_pem_new(&out)
        } else {
            req.write_pem(&out)
        };
        if i == 0 {
            eprintf!("Unable to write certificate request\n");
            return 1;
        }
    }
    if !noout
        && gen_x509
        && let Some(x) = &new_x509
    {
        let i = if outformat == format::ASN1 {
            x.write_der(&out)
        } else {
            x.write_pem(&out)
        };
        if i == 0 {
            eprintf!("Unable to write X509 certificate\n");
            return 1;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dn_fields() {
        assert_eq!(dn_field("CN"), ("CN", false));
        assert_eq!(dn_field("1.OU"), ("OU", false));
        assert_eq!(dn_field("x:+CN"), ("CN", true));
        assert_eq!(dn_field("+CN"), ("CN", true));
        // A separator at the end leaves the name as it is.
        assert_eq!(dn_field("CN."), ("CN.", false));
    }

    #[test]
    fn c_helpers() {
        assert_eq!(atol(" 42x"), 42);
        assert_eq!(atol("-7"), -7);
        assert_eq!(atol("x"), 0);
        assert!(ends_with("CN_default", "_default"));
        assert!(!ends_with("_min", "x_min"));
        assert_eq!(join(10, "abc", "_d", "Name").as_deref(), Some("abc_d"));
        crate::lib::io::capture_err(|| assert_eq!(join(5, "abc", "_d", "Name"), None));
    }

    #[test]
    fn addext_keys() {
        let mut set = HashSet::new();
        let (r, err) = crate::lib::io::capture_err(|| {
            (
                duplicated(&mut set, " keyUsage = x"),
                duplicated(&mut set, "keyUsage=y"),
                duplicated(&mut set, "novalue"),
                duplicated(&mut set, " = x"),
            )
        });
        assert_eq!(r, (Ok(false), Ok(true), Err(()), Err(())));
        assert_eq!(
            String::from_utf8_lossy(&err),
            "Duplicate extension name: keyUsage\nParse error on -addext: missing '='\nParse error on -addext: missing key\n"
        );
    }
}
