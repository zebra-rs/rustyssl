//! `openssl pkcs12` (`apps/pkcs12.c`).

use std::io::Write;

use rustyssl_ossl::abi::{
    ERR_LIB_MASK, ERR_LIB_OFFSET, ERR_LIB_PKCS12, KEY_EX, KEY_SIG, MBSTRING_ASC, NID_LocalKeySet,
    NID_certBag, NID_keyBag, NID_localKeyID, NID_ms_csp_name,
    NID_pbe_WithSHA1And3_Key_TripleDES_CBC, NID_pbe_WithSHA1And40BitRC2_CBC, NID_pbmac1,
    NID_pkcs7_data, NID_pkcs7_encrypted, NID_pkcs8ShroudedKeyBag, NID_safeContentsBag,
    NID_secretBag, NID_undef, NID_x509Certificate, PKCS12_R_MAC_ABSENT, PKCS12_SALT_LEN,
    X509_ADD_FLAG_NO_DUP, X509_ADD_FLAG_UP_REF, X509_V_ERR_UNSPECIFIED,
};
use rustyssl_ossl::evp::Cipher;
use rustyssl_ossl::object::{self, Attribute, Object, Value};
use rustyssl_ossl::pkcs12::{
    self, AlgDetail, AlgInfo, Kdf, Pkcs12, SafeBag, read_pw_string, write_private_key,
};
use rustyssl_ossl::x509::CertStack;
use rustyssl_ossl::{Bio, err};

use crate::generated::options::pkcs12::{OPTIONS, Opt};
use crate::lib::apps::{
    Password, app_passwd, bio_open_default, bio_open_owner, cert_matches_key, dump_cert_text,
    load_certs, load_key, setup_verify,
};
use crate::lib::opt::{self, Parser, eprintf, format};
use crate::lib::{app_libctx, app_rand, engine, io};

const NOKEYS: u32 = 0x1;
const NOCERTS: u32 = 0x2;
const INFO: u32 = 0x4;
const CLCERTS: u32 = 0x8;
const CACERTS: u32 = 0x10;

/// `PASSWD_BUF_SIZE`.
const PASSWD_BUF_SIZE: usize = 2048;

/// The output encryption: the default (`EVP_aes_256_cbc()`), none, or one named.
enum Enc {
    Default,
    None,
    Named(Cipher),
    Legacy,
}

/// `%s` of `BIO_printf`, which prints NULL as `<NULL>`.
fn s(v: Option<&str>) -> &str {
    v.unwrap_or("<NULL>")
}

pub fn main(argv: &[String]) -> i32 {
    let mut p = Parser::with_unknown(argv, OPTIONS, Some("cipher"));
    let prog = p.prog();
    let usage = |prog: &str| {
        eprintf!("{prog}: Use -help for summary.\n");
        1
    };
    let (mut infile, mut outfile, mut keyname, mut certfile) = (None, None, None, None);
    let (mut untrusted, mut ciphername, mut enc_name) = (None, None::<String>, None::<String>);
    let (mut passcertsarg, mut name, mut csp_name) = (None, None, None);
    let (mut export_pkcs12, mut options, mut chain, mut twopass, mut keytype) =
        (false, 0u32, false, false, 0);
    let mut jdktrust: Option<String> = None;
    let mut use_legacy = false;
    let (mut iter, mut maciter, mut pbmac1_pbkdf2) = (0, 0, false);
    let mut macsaltlen = PKCS12_SALT_LEN;
    let (mut cert_pbe, mut key_pbe) = (NID_undef, NID_undef);
    let (mut macver, mut add_lmk) = (true, false);
    let (mut passinarg, mut passoutarg, mut passarg) = (None, None, None);
    let (mut macalg, mut pbmac1_pbkdf2_md) = (None::<String>, None::<String>);
    let (mut ca_path, mut ca_file, mut ca_store) = (None, None, None);
    let (mut no_ca_path, mut no_ca_file, mut no_ca_store) = (false, false, false);
    let mut _e = None;
    let mut canames: Vec<String> = Vec::new();
    let mut enc = Enc::Default;
    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::ERR => return usage(&prog),
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::NOKEYS => options |= NOKEYS,
            Opt::KEYEX => keytype = KEY_EX,
            Opt::KEYSIG => keytype = KEY_SIG,
            Opt::NOCERTS => options |= NOCERTS,
            Opt::CLCERTS => options |= CLCERTS,
            Opt::CACERTS => options |= CACERTS,
            Opt::NOOUT => options |= NOKEYS | NOCERTS,
            Opt::JDKTRUST => {
                jdktrust = Some(p.arg().to_owned());
                options |= NOKEYS;
            }
            Opt::INFO => options |= INFO,
            Opt::CHAIN => chain = true,
            Opt::TWOPASS => twopass = true,
            Opt::NOMACVER => macver = false,
            Opt::DESCERT => cert_pbe = NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
            Opt::EXPORT => export_pkcs12 = true,
            Opt::NODES | Opt::NOENC => {
                enc_name = Some(p.flag().get(1..).unwrap_or_default().to_owned());
                enc = Enc::None;
                ciphername = None;
            }
            Opt::CIPHER => {
                ciphername = p.unknown().map(str::to_owned);
                enc_name.clone_from(&ciphername);
            }
            Opt::ITER => {
                iter = p.int_arg();
                maciter = iter;
            }
            Opt::NOITER => iter = 1,
            Opt::MACITER => {}
            Opt::NOMACITER => maciter = 1,
            Opt::MACSALTLEN => macsaltlen = p.int_arg(),
            Opt::NOMAC => {
                cert_pbe = -1;
                maciter = -1;
            }
            Opt::MACALG => macalg = Some(p.arg().to_owned()),
            Opt::PBMAC1_PBKDF2 => pbmac1_pbkdf2 = true,
            Opt::PBMAC1_PBKDF2_MD => pbmac1_pbkdf2_md = Some(p.arg().to_owned()),
            Opt::CERTPBE => match set_pbe(p.arg()) {
                Some(n) => cert_pbe = n,
                None => return usage(&prog),
            },
            Opt::KEYPBE => match set_pbe(p.arg()) {
                Some(n) => key_pbe = n,
                None => return usage(&prog),
            },
            Opt::OPT_R(o) => {
                if !app_rand::opt_rand(o, p.arg()) {
                    return 1;
                }
            }
            Opt::INKEY => keyname = Some(p.arg().to_owned()),
            Opt::CERTFILE => certfile = Some(p.arg().to_owned()),
            Opt::UNTRUSTED => untrusted = Some(p.arg().to_owned()),
            Opt::PASSCERTS => passcertsarg = Some(p.arg().to_owned()),
            Opt::NAME => name = Some(p.arg().to_owned()),
            Opt::LMK => add_lmk = true,
            Opt::CSP => csp_name = Some(p.arg().to_owned()),
            Opt::CANAME => canames.push(p.arg().to_owned()),
            Opt::IN => infile = Some(p.arg().to_owned()),
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::PASSIN => passinarg = Some(p.arg().to_owned()),
            Opt::PASSOUT => passoutarg = Some(p.arg().to_owned()),
            Opt::PASSWORD => passarg = Some(p.arg().to_owned()),
            Opt::CAPATH => ca_path = Some(p.arg().to_owned()),
            Opt::CASTORE => ca_store = Some(p.arg().to_owned()),
            Opt::CAFILE => ca_file = Some(p.arg().to_owned()),
            Opt::NOCAPATH => no_ca_path = true,
            Opt::NOCASTORE => no_ca_store = true,
            Opt::NOCAFILE => no_ca_file = true,
            Opt::ENGINE => _e = engine::setup_engine(Some(p.arg()), false),
            Opt::LEGACY_ALG => use_legacy = true,
            Opt::OPT_PROV(o) => {
                if !app_libctx::opt_provider(o, p.arg()) {
                    return 1;
                }
            }
        }
    }
    if !p.check_rest_arg(None) {
        return usage(&prog);
    }
    if !app_rand::load() {
        return 1;
    }
    if let Some(c) = &ciphername {
        match opt::cipher_any(c) {
            Some(c) => enc = Enc::Named(c),
            None => return usage(&prog),
        }
    }
    let enc_name = enc_name.unwrap_or_default();
    let warn_export = |o: &str| eprintf!("Warning: -{o} option ignored with -export\n");
    let warn_no_export = |o: &str| eprintf!("Warning: -{o} option ignored without -export\n");
    if export_pkcs12 {
        if options & INFO != 0 {
            warn_export("info");
        }
        if !macver {
            warn_export("nomacver");
        }
        if options & CLCERTS != 0 {
            warn_export("clcerts");
        }
        if options & CACERTS != 0 {
            warn_export("cacerts");
        }
        if !matches!(enc, Enc::Default) {
            eprintf!("Warning: output encryption option -{enc_name} ignored with -export\n");
        }
    } else {
        let checks: [(bool, &str); 24] = [
            (keyname.is_some(), "inkey"),
            (certfile.is_some(), "certfile"),
            (passcertsarg.is_some(), "passcerts"),
            (chain, "chain"),
            (untrusted.is_some(), "untrusted"),
            (ca_file.is_some(), "CAfile"),
            (ca_path.is_some(), "CApath"),
            (ca_store.is_some(), "CAstore"),
            (no_ca_file, "no-CAfile"),
            (no_ca_path, "no-CApath"),
            (no_ca_store, "no-CAstore"),
            (name.is_some(), "name"),
            (!canames.is_empty(), "caname"),
            (csp_name.is_some(), "CSP"),
            (add_lmk, "LMK"),
            (keytype == KEY_EX, "keyex"),
            (keytype == KEY_SIG, "keysig"),
            (key_pbe != NID_undef, "keypbe"),
            (
                cert_pbe != NID_undef && cert_pbe != -1,
                "certpbe and -descert",
            ),
            (macalg.is_some(), "macalg"),
            (iter != 0, "iter and -noiter"),
            (maciter == 1, "nomaciter"),
            (cert_pbe == -1 && maciter == -1, "nomac"),
            (macsaltlen != PKCS12_SALT_LEN, "macsaltlen"),
        ];
        for (given, o) in checks {
            if given {
                warn_no_export(o);
            }
        }
    }
    let lc = app_libctx::libctx();
    let pq = app_libctx::propq();
    if use_legacy {
        // Load the legacy provider, and the default one explicitly, if not loaded already.
        if !pkcs12::provider_available(lc.as_deref(), "legacy") {
            if !app_libctx::provider_load(lc.as_deref(), "legacy") {
                return 1;
            }
            if !app_libctx::provider_load(lc.as_deref(), "default") {
                return 1;
            }
        }
        if cert_pbe == NID_undef {
            // The default build has RC2 (no OPENSSL_NO_RC2).
            cert_pbe = NID_pbe_WithSHA1And40BitRC2_CBC;
        }
        if key_pbe == NID_undef {
            key_pbe = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
        }
        if matches!(enc, Enc::Default) {
            enc = Enc::Legacy;
        }
        if macalg.is_none() {
            macalg = Some("sha1".to_owned());
        }
    }

    let passcerts = match app_passwd(passcertsarg.as_deref(), None) {
        Some((p, _)) => p,
        None => {
            eprintf!("Error getting certificate file password\n");
            return 1;
        }
    };
    if let Some(a) = &passarg {
        if export_pkcs12 {
            passoutarg = Some(a.clone());
        } else {
            passinarg = Some(a.clone());
        }
    }
    let Some((passin, passout)) = app_passwd(passinarg.as_deref(), passoutarg.as_deref()) else {
        eprintf!("Error getting passwords\n");
        return 1;
    };
    let given = if export_pkcs12 { &passout } else { &passin };
    // cpass and mpass: the encryption and MAC passwords; `pass` and `macpass` the buffers
    // read at the prompts, used when neither -passin/-passout nor -password gave one.
    let noprompt = given.is_some();
    let mut pass: Vec<u8> = Vec::new();
    let mut macpass: Vec<u8> = Vec::new();
    if noprompt && twopass {
        if export_pkcs12 {
            eprintf!("Option -twopass cannot be used with -passout or -password\n");
        } else {
            eprintf!("Option -twopass cannot be used with -passin or -password\n");
        }
        return 1;
    }
    if twopass {
        match read_pw_string(PASSWD_BUF_SIZE, "Enter MAC Password:", export_pkcs12) {
            Some(p) => macpass = p,
            None => {
                eprintf!("Can't read Password\n");
                return 1;
            }
        }
    }

    if export_pkcs12 {
        let ctx = Export {
            infile: infile.as_deref(),
            outfile: outfile.as_deref(),
            keyname: keyname.as_deref(),
            certfile: certfile.as_deref(),
            untrusted: untrusted.as_deref(),
            name: name.as_deref(),
            csp_name: csp_name.as_deref(),
            jdktrust: jdktrust.as_deref(),
            macalg: macalg.as_deref(),
            pbmac1_pbkdf2_md: pbmac1_pbkdf2_md.as_deref(),
            ca: (
                ca_file.as_deref(),
                no_ca_file,
                ca_path.as_deref(),
                no_ca_path,
            ),
            ca_store: (ca_store.as_deref(), no_ca_store),
            canames: &canames,
            options,
            chain,
            twopass,
            keytype,
            iter,
            maciter,
            pbmac1_pbkdf2,
            macsaltlen,
            key_pbe,
            cert_pbe,
            add_lmk,
            no_enc: matches!(enc, Enc::None),
            passin: passin.as_ref(),
            passcerts: passcerts.as_ref(),
            given: passout.as_ref(),
        };
        let r = export(&ctx, &mut pass, &mut macpass, &prog);
        return match r {
            Exit::Usage => usage(&prog),
            Exit::Code(c) => c,
        };
    }

    let Some(input) = bio_open_default(infile.as_deref(), 'r', format::PKCS12) else {
        return 1;
    };
    let Some(p12) = Pkcs12::init_ex(NID_pkcs7_data, lc.as_deref(), pq.as_deref()) else {
        io::print_errors();
        return 1;
    };
    let Some(p12) = p12.read_der_into(&input) else {
        io::print_errors();
        return 1;
    };
    if !noprompt {
        match read_pw_string(PASSWD_BUF_SIZE, "Enter Import Password:", false) {
            Some(p) => pass = p,
            None => {
                eprintf!("Can't read Password\n");
                return 1;
            }
        }
    }
    if !twopass {
        macpass.clone_from(&pass);
    }
    // cpass: None is C's NULL.
    let mut cpass: Option<Vec<u8>> = Some(match &passin {
        Some(p) => p.as_bytes().to_vec(),
        None => pass.clone(),
    });
    let mpass: Vec<u8> = match &passin {
        Some(p) => p.as_bytes().to_vec(),
        None => macpass.clone(),
    };
    // The C strings stop at their first NUL.
    let cstr = |v: &[u8]| v.split(|&b| b == 0).next().unwrap_or_default().to_vec();
    let mpass = cstr(&mpass);
    cpass = cpass.map(|c| cstr(&c));

    if options & INFO != 0 && p12.mac_present() {
        print_mac_info(&p12);
    }
    let mut dump_now = false;
    if macver {
        match p12.mac_alg() {
            None => {
                eprintf!("Warning: MAC is absent!\n");
                dump_now = true;
            }
            Some(obj) => {
                if obj.as_ref().map_or(NID_undef, Object::nid) != NID_pbmac1
                    && !pkcs12::kdf_available(lc.as_deref(), "PKCS12KDF", pq.as_deref())
                {
                    eprintf!("Error verifying PKCS12 MAC; no PKCS12KDF support.\n");
                    eprintf!("Use -nomacver if MAC verification is not required.\n");
                    return 1;
                }
            }
        }
        if !dump_now {
            if mpass.is_empty() && p12.verify_mac(None) {
                if !twopass {
                    cpass = None;
                }
            } else if !p12.verify_mac(Some(&mpass)) {
                // May be UTF-8 from a previous version of OpenSSL: convert to a UTF-8 form
                // which will translate to the same Unicode password.
                let e = err::peek_error();
                let lib = (e >> ERR_LIB_OFFSET) & std::ffi::c_ulong::from(ERR_LIB_MASK as u8);
                let lib_is_pkcs12 = !err::is_system_error(e)
                    && lib == std::ffi::c_ulong::from(ERR_LIB_PKCS12 as u8);
                if lib_is_pkcs12 && err::reason(e) == PKCS12_R_MAC_ABSENT {
                    eprintf!("Warning: MAC is absent!\n");
                } else {
                    let badpass = match pkcs12::asc2uni_utf8(&mpass) {
                        Ok(b) => b,
                        Err(true) => return 1,
                        Err(false) => {
                            eprintf!(
                                "Verbatim password did not match, and fallback conversion to UTF-8 failed\n\
                                 The password entered or the input encoding may be wrong\n"
                            );
                            return 1;
                        }
                    };
                    if !p12.verify_mac(Some(&badpass)) {
                        eprintf!("Mac verify error: invalid password?\n");
                        io::print_errors();
                        return 1;
                    }
                    eprintf!("Warning: using broken algorithm\n");
                    if !twopass {
                        cpass = Some(badpass);
                    }
                }
            }
        }
    }

    let Some(out) = bio_open_owner(outfile.as_deref(), format::PEM, true) else {
        return 1;
    };
    let cipher = match enc {
        Enc::Default => Cipher::by_name("AES-256-CBC"),
        Enc::Legacy => Cipher::by_name("DES-EDE3-CBC"),
        Enc::None => None,
        Enc::Named(c) => Some(c),
    };
    let dump = Dump {
        out: &out,
        pass: cpass.as_deref(),
        options,
        pempass: passout.as_ref().map(Password::as_bytes),
        enc: cipher.as_ref(),
    };
    if !dump.p12(&p12) {
        eprintf!("Error outputting keys and certificates\n");
        io::print_errors();
        return 1;
    }
    0
}

/// How the export ends: with a status, or at `opthelp`.
enum Exit {
    Code(i32),
    Usage,
}

/// The export's inputs.
struct Export<'a> {
    infile: Option<&'a str>,
    outfile: Option<&'a str>,
    keyname: Option<&'a str>,
    certfile: Option<&'a str>,
    untrusted: Option<&'a str>,
    name: Option<&'a str>,
    csp_name: Option<&'a str>,
    jdktrust: Option<&'a str>,
    macalg: Option<&'a str>,
    pbmac1_pbkdf2_md: Option<&'a str>,
    ca: (Option<&'a str>, bool, Option<&'a str>, bool),
    ca_store: (Option<&'a str>, bool),
    canames: &'a [String],
    options: u32,
    chain: bool,
    twopass: bool,
    keytype: i32,
    iter: i32,
    maciter: i32,
    pbmac1_pbkdf2: bool,
    macsaltlen: i32,
    key_pbe: i32,
    cert_pbe: i32,
    add_lmk: bool,
    no_enc: bool,
    passin: Option<&'a Password>,
    passcerts: Option<&'a Password>,
    /// The password -passout or -password gave.
    given: Option<&'a Password>,
}

/// The `-export` branch, up to `export_end` (which prints the errors queued).
fn export(x: &Export<'_>, pass: &mut Vec<u8>, macpass: &mut Vec<u8>, prog: &str) -> Exit {
    // Errors are printed at export_end on every path that reaches it.
    match export_inner(x, pass, macpass, prog) {
        Some(Exit::Usage) => Exit::Usage,
        // Opening the output failed: `goto end`, past export_end.
        Some(Exit::Code(2)) => Exit::Code(1),
        Some(Exit::Code(c)) => {
            io::print_errors();
            Exit::Code(c)
        }
        None => {
            io::print_errors();
            Exit::Code(1)
        }
    }
}

/// The export itself: `None` for `goto export_end` with status 1, `Some(Exit::Code(2))` for
/// the output that couldn't be opened (`goto end`).
fn export_inner(
    x: &Export<'_>,
    pass: &mut Vec<u8>,
    macpass: &mut Vec<u8>,
    prog: &str,
) -> Option<Exit> {
    let _ = prog;
    let lc = app_libctx::libctx();
    let pq = app_libctx::propq();
    let mut chain = x.chain;
    let passin = x.passin.map(Password::as_str);
    let passcerts = x.passcerts.map(Password::as_str);
    if x.options & (NOCERTS | NOKEYS) == NOCERTS | NOKEYS {
        eprintf!("Nothing to export due to -noout or -nocerts and -nokeys\n");
        return None;
    }
    if x.options & NOCERTS != 0 {
        chain = false;
        eprintf!("Warning: -chain option ignored with -nocerts\n");
    }
    let mut key = None;
    if x.options & NOKEYS == 0 {
        let desc = if x.keyname.is_some() {
            "private key from -inkey file"
        } else {
            "private key from -in file"
        };
        key = Some(load_key(
            x.keyname.or(x.infile),
            format::PEM,
            true,
            passin,
            None,
            Some(desc),
        )?);
    }
    let mut certs: Option<CertStack> = None;
    let mut ee_cert = None;
    if x.options & NOCERTS == 0 {
        let (ok, c) = load_certs(
            x.infile,
            true,
            None,
            passin,
            Some("certificates from -in file"),
        );
        if !ok {
            return None;
        }
        let c = c?;
        if c.is_empty() {
            eprintf!("No certificate in -in file {}\n", s(x.infile));
            return None;
        }
        if let Some(k) = &key {
            for (i, cert) in c.to_vec().iter().enumerate() {
                if cert_matches_key(cert, k) {
                    cert.clear_keyid_alias();
                    ee_cert = c.delete(i);
                    break;
                }
            }
            if ee_cert.is_none() {
                eprintf!(
                    "No cert in -in file '{}' matches private key\n",
                    s(x.infile)
                );
                return None;
            }
        }
        certs = Some(c);
    }
    let mut untrusted_certs = None;
    if let Some(u) = x.untrusted {
        let (ok, c) = load_certs(
            Some(u),
            false,
            None,
            passcerts,
            Some("untrusted certificates"),
        );
        if !ok {
            return None;
        }
        untrusted_certs = c;
    }
    if chain {
        let first = certs.as_ref().and_then(|c| c.to_vec().into_iter().next());
        let Some(ee_tmp) = ee_cert.as_ref().or(first.as_ref()) else {
            eprintf!("No end entity certificate to check with -chain\n");
            return None;
        };
        let (ca_file, no_ca_file, ca_path, no_ca_path) = x.ca;
        let store = setup_verify(
            ca_file,
            no_ca_file,
            ca_path,
            no_ca_path,
            x.ca_store.0,
            x.ca_store.1,
        )?;
        let vret = pkcs12::get_cert_chain(
            ee_tmp,
            &store,
            untrusted_certs.as_ref(),
            lc.as_deref(),
            pq.as_deref(),
        );
        drop(store);
        match vret {
            Ok(chain2) => {
                // Remove the end entity certificate; add the rest but duplicates.
                chain2.shift_free();
                if let Some(c) = &certs
                    && !c.add_certs(&chain2, X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_NO_DUP)
                {
                    return None;
                }
            }
            Err(vret) => {
                if vret != X509_V_ERR_UNSPECIFIED {
                    let msg = pkcs12::verify_cert_error_string(vret);
                    eprintf!("Error getting chain: {msg}\n");
                }
                return None;
            }
        }
    }
    if let Some(f) = x.certfile {
        let (ok, c) = load_certs(
            Some(f),
            false,
            certs.take(),
            passcerts,
            Some("extra certificates from -certfile"),
        );
        certs = c;
        if !ok {
            return None;
        }
    }
    if let Some(c) = &certs {
        let list = c.to_vec();
        for (name, cert) in x.canames.iter().zip(list.iter()) {
            cert.set_alias(name);
        }
    }
    if let (Some(csp), Some(k)) = (x.csp_name, &key) {
        k.add1_attr_by_nid(NID_ms_csp_name, MBSTRING_ASC, Some(csp));
    }
    if x.add_lmk
        && let Some(k) = &key
    {
        k.add1_attr_by_nid(NID_LocalKeySet, 0, None);
    }
    let noprompt = x.given.is_some();
    if !noprompt && !(x.no_enc && x.maciter == -1) {
        match read_pw_string(PASSWD_BUF_SIZE, "Enter Export Password:", true) {
            Some(p) => *pass = p,
            None => {
                eprintf!("Can't read Password\n");
                return None;
            }
        }
    }
    if !x.twopass {
        macpass.clone_from(pass);
    }
    let cpass: Vec<u8> = match x.given {
        Some(p) => p.as_str().as_bytes().to_vec(),
        None => pass.clone(),
    };
    let mpass: Vec<u8> = match x.given {
        Some(p) => p.as_str().as_bytes().to_vec(),
        None => macpass.clone(),
    };
    let obj = x.jdktrust.and_then(|j| Object::from_txt(j, false));
    let Some(p12) = Pkcs12::create(
        Some(&cpass),
        x.name,
        key.as_ref(),
        ee_cert.as_ref(),
        certs.as_ref(),
        x.key_pbe,
        x.cert_pbe,
        x.iter,
        x.keytype,
        lc.as_deref(),
        pq.as_deref(),
        obj.as_ref(),
    ) else {
        eprintf!("Error creating PKCS12 structure for {}\n", s(x.outfile));
        return None;
    };
    let mut macmd = None;
    if let Some(m) = x.macalg {
        match opt::md(m) {
            Some(md) => macmd = Some(md),
            None => return Some(Exit::Usage),
        }
    }
    if x.maciter != -1 {
        if x.pbmac1_pbkdf2 {
            if !p12.set_pbmac1_pbkdf2(
                Some(&mpass),
                x.macsaltlen,
                x.maciter,
                macmd.as_ref(),
                x.pbmac1_pbkdf2_md,
            ) {
                eprintf!("Error creating PBMAC1\n");
                return None;
            }
        } else if !p12.set_mac(Some(&mpass), x.macsaltlen, x.maciter, macmd.as_ref()) {
            eprintf!("Error creating PKCS12 MAC; no PKCS12KDF support?\n");
            eprintf!("Use -nomac or -pbmac1_pbkdf2 if PKCS12KDF support not available\n");
            return None;
        }
    }
    let Some(out) = bio_open_owner(x.outfile, format::PKCS12, true) else {
        return Some(Exit::Code(2));
    };
    p12.write_der(&out);
    Some(Exit::Code(0))
}

/// `set_pbe`: `NONE` is -1; an unknown name prints a message.
fn set_pbe(s: &str) -> Option<i32> {
    if s == "NONE" {
        return Some(-1);
    }
    let nid = rustyssl_ossl::x509::txt2nid(s);
    if nid == NID_undef {
        eprintf!("Unknown PBE algorithm {s}\n");
        return None;
    }
    Some(nid)
}

/// `-info`'s MAC lines.
fn print_mac_info(p12: &Pkcs12) {
    let info = p12.mac_info();
    let mut e = io::err();
    let _ = e.write_all(b"MAC: ");
    if let (Some(o), Some(b)) = (&info.alg, io::bio_err()) {
        o.i2a(b);
    }
    if info.alg.as_ref().map_or(NID_undef, Object::nid) == NID_pbmac1 {
        match info.pbmac1 {
            None => {
                eprintf!(", Unsupported KDF or params for PBMAC1\n");
            }
            Some((iter, keylen, saltlen, prf)) => {
                eprintf!(" using PBKDF2, Iteration {iter}\n");
                eprintf!("Key length: {keylen}, Salt length: {saltlen}\n");
                eprintf!("PBKDF2 PRF: {}\n", s(object::nid2sn(prf).as_deref()));
            }
        }
    } else {
        eprintf!(", Iteration {}\n", info.iter.unwrap_or(1));
        eprintf!(
            "MAC length: {}, salt length: {}\n",
            info.mac_len,
            info.salt_len
        );
    }
}

/// `alg_print`, to standard error.
fn alg_print(alg: &AlgInfo) {
    let ln = |n| object::nid2ln(n);
    let sn = |n| object::nid2sn(n);
    let mut text = s(ln(alg.nid).as_deref()).to_owned();
    match &alg.detail {
        AlgDetail::Pbes2(None) | AlgDetail::Pbe(None) => {
            text.push_str(", <unsupported parameters>")
        }
        AlgDetail::Pbes2(Some((kdf_nid, enc_nid, kdf))) => {
            text.push_str(&format!(
                ", {}, {}",
                s(ln(*kdf_nid).as_deref()),
                s(sn(*enc_nid).as_deref())
            ));
            match kdf {
                Kdf::Pbkdf2(None) | Kdf::Scrypt(None) => {
                    text.push_str(", <unsupported parameters>");
                }
                Kdf::Pbkdf2(Some((iter, prf))) => {
                    text.push_str(&format!(
                        ", Iteration {iter}, PRF {}",
                        s(sn(*prf).as_deref())
                    ));
                }
                Kdf::Scrypt(Some((salt, n, r, p))) => {
                    text.push_str(&format!(
                        ", Salt length: {salt}, Cost(N): {n}, Block size(r): {r}, Parallelism(p): {p}"
                    ));
                }
                Kdf::Other => {}
            }
        }
        AlgDetail::Pbe(Some(iter)) => text.push_str(&format!(", Iteration {iter}")),
    }
    text.push('\n');
    let _ = io::err().write_all(text.as_bytes());
}

/// `hex_prin`.
fn hex_prin(out: &mut Vec<u8>, buf: &[u8]) {
    for b in buf {
        out.extend_from_slice(format!("{b:02X} ").as_bytes());
    }
}

/// `print_attribute`.
fn print_attribute(out: &Bio, av: Option<&Value>) {
    let mut t: Vec<u8> = Vec::new();
    match av {
        Some(Value::Bmp(b)) => {
            match object::uni2asc(b) {
                Some(v) => t.extend_from_slice(&v),
                None => t.extend_from_slice(b"<NULL>"),
            }
            t.push(b'\n');
        }
        Some(Value::Utf8(b)) => {
            // "%.*s": up to the first NUL.
            t.extend(b.iter().take_while(|&&c| c != 0));
            t.push(b'\n');
        }
        Some(Value::Octet(b) | Value::Bit(b)) => {
            hex_prin(&mut t, b);
            t.push(b'\n');
        }
        Some(Value::Object(o)) => {
            let ln = o
                .as_ref()
                .and_then(|o| object::nid2ln(o.nid()))
                .unwrap_or_default();
            let txt = o.as_ref().map(|o| o.txt(80, true)).unwrap_or_default();
            t.extend_from_slice(format!("{ln} ({txt})\n").as_bytes());
        }
        Some(Value::Other(tag)) => {
            t.extend_from_slice(format!("<Unsupported tag {tag}>\n").as_bytes())
        }
        None => {}
    }
    let _ = out.write_all(&t);
}

/// `print_attribs`.
fn print_attribs(out: &Bio, attrs: Option<&[Attribute]>, name: &str) {
    let Some(attrs) = attrs else {
        let _ = out.write_all(format!("{name}: <No Attributes>\n").as_bytes());
        return;
    };
    if attrs.is_empty() {
        let _ = out.write_all(format!("{name}: <Empty Attributes>\n").as_bytes());
        return;
    }
    let _ = out.write_all(format!("{name}\n").as_bytes());
    for a in attrs {
        let _ = out.write_all(b"    ");
        let nid = a.object.as_ref().map_or(NID_undef, Object::nid);
        if nid == NID_undef {
            if let Some(o) = &a.object {
                o.i2a(out);
            }
            let _ = out.write_all(b": ");
        } else {
            let ln = object::nid2ln(nid);
            let _ = out.write_all(format!("{}: ", s(ln.as_deref())).as_bytes());
        }
        if a.values.is_empty() {
            let _ = out.write_all(b"<No Values>\n");
        } else {
            for v in &a.values {
                print_attribute(out, v.as_ref());
            }
        }
    }
}

/// `dump_certs_keys_p12` and its helpers.
struct Dump<'a> {
    out: &'a Bio,
    pass: Option<&'a [u8]>,
    options: u32,
    pempass: Option<&'a [u8]>,
    enc: Option<&'a Cipher>,
}

impl Dump<'_> {
    /// `dump_certs_keys_p12`.
    fn p12(&self, p12: &Pkcs12) -> bool {
        let Some(asafes) = p12.authsafes() else {
            return false;
        };
        for p7 in &asafes {
            let bagnid = p7.type_nid();
            let bags = if bagnid == NID_pkcs7_data {
                let b = pkcs12::unpack_p7data(p7);
                if self.options & INFO != 0 {
                    eprintf!("PKCS7 Data\n");
                }
                b
            } else if bagnid == NID_pkcs7_encrypted {
                if self.options & INFO != 0 {
                    eprintf!("PKCS7 Encrypted data: ");
                    match pkcs12::encrypted_alg(p7) {
                        None => {
                            eprintf!("<no data>\n");
                        }
                        Some(a) => alg_print(&a),
                    }
                }
                pkcs12::unpack_p7encdata(p7, self.pass)
            } else {
                continue;
            };
            let Some(bags) = bags else {
                return false;
            };
            if !self.bags(&bags.bags()) {
                return false;
            }
        }
        true
    }

    /// `dump_certs_pkeys_bags`.
    fn bags(&self, bags: &[SafeBag<'_>]) -> bool {
        bags.iter().all(|b| self.bag(b))
    }

    /// `dump_certs_pkeys_bag`.
    #[allow(non_upper_case_globals)] // The NIDs, as the C headers name them.
    fn bag(&self, bag: &SafeBag<'_>) -> bool {
        let out = self.out;
        let info = self.options & INFO != 0;
        let attrs = bag.attrs();
        let write_key = |pkey: &rustyssl_ossl::pkey::Pkey| {
            write_private_key(out, pkey, self.enc, self.pempass) == 1
        };
        match bag.nid() {
            NID_keyBag => {
                if info {
                    eprintf!("Key bag\n");
                }
                if self.options & NOKEYS != 0 {
                    return true;
                }
                print_attribs(out, attrs.as_deref(), "Bag Attributes");
                let Some((pkey, kattrs)) = bag.key() else {
                    return false;
                };
                print_attribs(out, kattrs.as_deref(), "Key Attributes");
                write_key(&pkey)
            }
            NID_pkcs8ShroudedKeyBag => {
                if info {
                    eprintf!("Shrouded Keybag: ");
                    alg_print(&bag.pkcs8_alg());
                }
                if self.options & NOKEYS != 0 {
                    return true;
                }
                print_attribs(out, attrs.as_deref(), "Bag Attributes");
                let Some((pkey, kattrs)) = bag.decrypt_key(self.pass) else {
                    return false;
                };
                print_attribs(out, kattrs.as_deref(), "Key Attributes");
                write_key(&pkey)
            }
            NID_certBag => {
                if info {
                    eprintf!("Certificate bag\n");
                }
                if self.options & NOCERTS != 0 {
                    return true;
                }
                if bag.has_attr(NID_localKeyID) {
                    if self.options & CACERTS != 0 {
                        return true;
                    }
                } else if self.options & CLCERTS != 0 {
                    return true;
                }
                print_attribs(out, attrs.as_deref(), "Bag Attributes");
                if bag.bag_nid() != NID_x509Certificate {
                    return true;
                }
                let Some(x509) = bag.cert() else {
                    return false;
                };
                dump_cert_text(out, &x509);
                x509.write_pem(out)
            }
            NID_secretBag => {
                if info {
                    eprintf!("Secret bag\n");
                }
                print_attribs(out, attrs.as_deref(), "Bag Attributes");
                eprintf!("Bag Type: ");
                if let (Some(t), Some(b)) = (bag.bag_type(), io::bio_err()) {
                    t.i2a(b);
                }
                eprintf!("\nBag Value: ");
                print_attribute(out, bag.bag_obj().as_ref());
                true
            }
            NID_safeContentsBag => {
                if info {
                    eprintf!("Safe Contents bag\n");
                }
                print_attribs(out, attrs.as_deref(), "Bag Attributes");
                self.bags(&bag.safes())
            }
            _ => {
                eprintf!("Warning unsupported bag type: ");
                if let (Some(t), Some(b)) = (bag.type_obj(), io::bio_err()) {
                    t.i2a(b);
                }
                eprintf!("\n");
                true
            }
        }
    }
}
