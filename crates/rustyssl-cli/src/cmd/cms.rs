//! `openssl cms` (`apps/cms.c`).

use std::io::Write;

use rustyssl_ossl::abi::{
    CMS_ASCIICRLF, CMS_BINARY, CMS_CADES, CMS_CRLFEOL, CMS_DEBUG_DECRYPT, CMS_DETACHED,
    CMS_KEY_PARAM, CMS_NO_ATTR_VERIFY, CMS_NO_CONTENT_VERIFY, CMS_NO_SIGNER_CERT_VERIFY,
    CMS_NO_SIGNING_TIME, CMS_NOATTR, CMS_NOCERTS, CMS_NOINTERN, CMS_NOSIGS, CMS_NOSMIMECAP,
    CMS_PARTIAL, CMS_R_ERROR_UNSUPPORTED_STATIC_KEY_AGREEMENT, CMS_REUSE_DIGEST, CMS_STREAM,
    CMS_TEXT, CMS_USE_KEYID, XN_FLAG_ONELINE,
};
use rustyssl_ossl::cms::{self, Cms, ReceiptRequest, RecipientError, RecipientOptions, Rr};
use rustyssl_ossl::evp::Cipher;
use rustyssl_ossl::object::Object;
use rustyssl_ossl::pkcs7::last_verify_error;
use rustyssl_ossl::verify::VerifyParam;
use rustyssl_ossl::x509::{Cert, CertStack};
use rustyssl_ossl::{Bio, crypto, err};

use crate::generated::options::cms::{OPTIONS, Opt};
use crate::lib::apps::{
    ConfigFile, app_load_config_modules, app_passwd, bio_open_default, get_nameopt, load_cert,
    load_certs, load_key, set_nameopt, setup_verify,
};
use crate::lib::opt::{self, Parser, eprintf, fmt_flags, format};
use crate::lib::{app_libctx, app_rand, engine, io};

const SMIME_OP: i32 = 0x100;
const SMIME_IP: i32 = 0x200;
const SMIME_SIGNERS: i32 = 0x400;
const SMIME_ENCRYPT: i32 = 1 | SMIME_OP;
const SMIME_DECRYPT: i32 = 2 | SMIME_IP;
const SMIME_SIGN: i32 = 3 | SMIME_OP | SMIME_SIGNERS;
const SMIME_VERIFY: i32 = 4 | SMIME_IP;
const SMIME_RESIGN: i32 = 5 | SMIME_IP | SMIME_OP | SMIME_SIGNERS;
const SMIME_SIGN_RECEIPT: i32 = 6 | SMIME_IP | SMIME_OP;
const SMIME_VERIFY_RECEIPT: i32 = 7 | SMIME_IP;
const SMIME_DIGEST_CREATE: i32 = 8 | SMIME_OP;
const SMIME_DIGEST_VERIFY: i32 = 9 | SMIME_IP;
const SMIME_COMPRESS: i32 = 10 | SMIME_OP;
const SMIME_UNCOMPRESS: i32 = 11 | SMIME_IP;
const SMIME_ENCRYPTED_ENCRYPT: i32 = 12 | SMIME_OP;
const SMIME_ENCRYPTED_DECRYPT: i32 = 13 | SMIME_IP;
const SMIME_DATA_CREATE: i32 = 14 | SMIME_OP;
const SMIME_DATA_OUT: i32 = 15 | SMIME_IP;
const SMIME_CMSOUT: i32 = 16 | SMIME_IP | SMIME_OP;

/// The flags as the library takes them (every flag is non-negative).
fn fl(flags: i32) -> u32 {
    u32::try_from(flags).unwrap_or(0)
}

/// `cms_main`'s end: the error queue for any status but 0.
fn end(ret: i32) -> i32 {
    if ret != 0 {
        io::print_errors();
    }
    ret
}

/// `cms_key_param`: a signer's or recipient's `-keyopt` values.
struct KeyParam {
    idx: usize,
    param: Vec<String>,
}

/// `cms_recip_opt`: a KEM recipient's `-recip_kdf` and `-recip_ukm`.
struct RecipOpt {
    idx: usize,
    kdf: Option<String>,
    ukm: Option<Vec<u8>>,
}

/// `load_content_info`.
fn load_content_info(
    informat: i32,
    input: &Bio,
    flags: i32,
    want_indata: bool,
    name: &str,
) -> (Option<Cms>, Option<Bio>) {
    let lc = app_libctx::libctx();
    let pq = app_libctx::propq();
    let Some(ret) = Cms::new_ex(lc.as_deref(), pq.as_deref()) else {
        eprintf!("Error allocating CMS_contentinfo\n");
        return (None, None);
    };
    let (ci, indata) = match informat {
        format::SMIME => ret.read_smime_into(input, fl(flags), want_indata),
        format::PEM => (ret.read_pem_into(input), None),
        format::ASN1 => (ret.read_der_into(input), None),
        _ => {
            eprintf!("Bad input format for {name}\n");
            return (None, None);
        }
    };
    if ci.is_none() {
        eprintf!("Error reading {name} Content Info\n");
    }
    (ci, indata)
}

pub fn main(argv: &[String]) -> i32 {
    let encerts = CertStack::new();
    let vpm = VerifyParam::new();
    let (Some(encerts), Some(vpm)) = (encerts, vpm) else {
        return end(1);
    };
    let mut p = Parser::with_unknown(argv, OPTIONS, Some("cipher"));
    let prog = p.prog();
    let opthelp = |prog: &str| {
        eprintf!("{prog}: Use -help for summary.\n");
        end(1)
    };
    let mut _conf = None;
    let mut econtent_type: Option<Object> = None;
    let mut rr_to: Option<Vec<String>> = None;
    let mut rr_from: Option<Vec<String>> = None;
    let mut sksigners: Option<Vec<String>> = None;
    let mut skkeys: Option<Vec<String>> = None;
    let (mut certfile, mut keyfile, mut contfile) = (None, None::<String>, None::<String>);
    let (mut ca_file, mut ca_path, mut ca_store) = (None, None, None);
    let (mut certsoutfile, mut digestname, mut wrapname) =
        (None::<String>, None::<String>, None::<String>);
    let (mut no_ca_file, mut no_ca_path, mut no_ca_store) = (false, false, false);
    let mut digesthex: Option<String> = None;
    let (mut infile, mut outfile, mut rctfile) = (None::<String>, None::<String>, None::<String>);
    let (mut passinarg, mut signerfile) = (None::<String>, None::<String>);
    let (mut originatorfile, mut recipfile) = (None::<String>, None::<String>);
    let (mut ciphername, mut kekciphername) = (None::<String>, None::<String>);
    let (mut to, mut from, mut subject) = (None::<String>, None::<String>, None::<String>);
    let mut key_params: Vec<KeyParam> = Vec::new();
    let mut flags = CMS_DETACHED;
    let (mut noout, mut print, mut vpmtouched) = (false, false, false);
    let (mut informat, mut outformat) = (format::SMIME, format::SMIME);
    let (mut operation, mut rr_print, mut rr_allorfirst) = (0, false, -1);
    let (mut verify_retcode, mut rctformat, mut keyform) = (false, format::SMIME, format::UNDEF);
    let (mut secret_key, mut secret_keyid) = (None::<Vec<u8>>, None::<Vec<u8>>);
    let mut pwri_pass: Option<String> = None;
    let mut recip_opts: Vec<RecipOpt> = Vec::new();
    let mut mime_eol = "\n";
    let mut e = None;
    loop {
        let o = p.next();
        match o {
            Opt::EOF => break,
            Opt::ERR => return opthelp(&prog),
            Opt::HELP => {
                opt::help(OPTIONS);
                return end(0);
            }
            Opt::INFORM | Opt::OUTFORM => {
                let Some(f) = opt::parse_format(p.arg(), fmt_flags::PDS) else {
                    return opthelp(&prog);
                };
                if o == Opt::INFORM {
                    informat = f;
                } else {
                    outformat = f;
                }
            }
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::ENCRYPT => operation = SMIME_ENCRYPT,
            Opt::DECRYPT => operation = SMIME_DECRYPT,
            Opt::SIGN => operation = SMIME_SIGN,
            Opt::VERIFY => operation = SMIME_VERIFY,
            Opt::RESIGN => operation = SMIME_RESIGN,
            Opt::SIGN_RECEIPT => operation = SMIME_SIGN_RECEIPT,
            Opt::VERIFY_RECEIPT => {
                operation = SMIME_VERIFY_RECEIPT;
                rctfile = Some(p.arg().to_owned());
            }
            Opt::VERIFY_RETCODE => verify_retcode = true,
            Opt::DIGEST_CREATE => operation = SMIME_DIGEST_CREATE,
            Opt::DIGEST => digesthex = Some(p.arg().to_owned()),
            Opt::DIGEST_VERIFY => operation = SMIME_DIGEST_VERIFY,
            Opt::COMPRESS => operation = SMIME_COMPRESS,
            Opt::UNCOMPRESS => operation = SMIME_UNCOMPRESS,
            Opt::ED_ENCRYPT => operation = SMIME_ENCRYPTED_ENCRYPT,
            Opt::ED_DECRYPT => operation = SMIME_ENCRYPTED_DECRYPT,
            Opt::DATA_CREATE => operation = SMIME_DATA_CREATE,
            Opt::DATA_OUT => operation = SMIME_DATA_OUT,
            Opt::CMSOUT => operation = SMIME_CMSOUT,
            Opt::DEBUG_DECRYPT => flags |= CMS_DEBUG_DECRYPT,
            Opt::TEXT => flags |= CMS_TEXT,
            Opt::ASCIICRLF => flags |= CMS_ASCIICRLF,
            Opt::NOINTERN => flags |= CMS_NOINTERN,
            Opt::NOVERIFY => flags |= CMS_NO_SIGNER_CERT_VERIFY,
            Opt::NOCERTS => flags |= CMS_NOCERTS,
            Opt::NOATTR => flags |= CMS_NOATTR,
            Opt::NODETACH => flags &= !CMS_DETACHED,
            Opt::NOSMIMECAP => flags |= CMS_NOSMIMECAP,
            Opt::NO_SIGNING_TIME => flags |= CMS_NO_SIGNING_TIME,
            Opt::BINARY => flags |= CMS_BINARY,
            Opt::CADES => flags |= CMS_CADES,
            Opt::KEYID => flags |= CMS_USE_KEYID,
            Opt::NOSIGS => flags |= CMS_NOSIGS,
            Opt::NO_CONTENT_VERIFY => flags |= CMS_NO_CONTENT_VERIFY,
            Opt::NO_ATTR_VERIFY => flags |= CMS_NO_ATTR_VERIFY,
            Opt::INDEF => flags |= CMS_STREAM,
            Opt::NOINDEF => flags &= !CMS_STREAM,
            Opt::CRLFEOL => {
                mime_eol = "\r\n";
                flags |= CMS_CRLFEOL;
            }
            Opt::NOOUT => noout = true,
            Opt::RR_PRINT => rr_print = true,
            Opt::RR_ALL => rr_allorfirst = 0,
            Opt::RR_FIRST => rr_allorfirst = 1,
            Opt::RCTFORM => {
                match opt::parse_format(p.arg(), fmt_flags::PEMDER | fmt_flags::SMIME) {
                    Some(f) => rctformat = f,
                    None => return opthelp(&prog),
                }
            }
            Opt::CERTFILE => certfile = Some(p.arg().to_owned()),
            Opt::CAFILE => ca_file = Some(p.arg().to_owned()),
            Opt::CAPATH => ca_path = Some(p.arg().to_owned()),
            Opt::CASTORE => ca_store = Some(p.arg().to_owned()),
            Opt::NOCAFILE => no_ca_file = true,
            Opt::NOCAPATH => no_ca_path = true,
            Opt::NOCASTORE => no_ca_store = true,
            Opt::IN => infile = Some(p.arg().to_owned()),
            Opt::CONTENT => contfile = Some(p.arg().to_owned()),
            Opt::RR_FROM => rr_from
                .get_or_insert_with(Vec::new)
                .push(p.arg().to_owned()),
            Opt::RR_TO => rr_to.get_or_insert_with(Vec::new).push(p.arg().to_owned()),
            Opt::PRINT => {
                noout = true;
                print = true;
            }
            Opt::NAMEOPT => {
                if !set_nameopt(Some(p.arg())) {
                    return opthelp(&prog);
                }
            }
            Opt::SECRETKEY => {
                if secret_key.is_some() {
                    eprintf!("Invalid key (supplied twice) {}\n", p.arg());
                    return opthelp(&prog);
                }
                match crypto::hexstr2buf(p.arg()) {
                    Some(k) => secret_key = Some(k),
                    None => {
                        eprintf!("Invalid key {}\n", p.arg());
                        return end(1);
                    }
                }
            }
            Opt::SECRETKEYID => {
                if secret_keyid.is_some() {
                    eprintf!("Invalid id (supplied twice) {}\n", p.arg());
                    return opthelp(&prog);
                }
                match crypto::hexstr2buf(p.arg()) {
                    Some(k) => secret_keyid = Some(k),
                    None => {
                        eprintf!("Invalid id {}\n", p.arg());
                        return opthelp(&prog);
                    }
                }
            }
            Opt::PWRI_PASSWORD => pwri_pass = Some(p.arg().to_owned()),
            Opt::ECONTENT_TYPE => {
                if econtent_type.is_some() {
                    eprintf!("Invalid OID (supplied twice) {}\n", p.arg());
                    return opthelp(&prog);
                }
                match Object::from_txt(p.arg(), false) {
                    Some(obj) => econtent_type = Some(obj),
                    None => {
                        eprintf!("Invalid OID {}\n", p.arg());
                        return opthelp(&prog);
                    }
                }
            }
            Opt::ENGINE => e = engine::setup_engine(Some(p.arg()), false),
            Opt::PASSIN => passinarg = Some(p.arg().to_owned()),
            Opt::TO => to = Some(p.arg().to_owned()),
            Opt::FROM => from = Some(p.arg().to_owned()),
            Opt::SUBJECT => subject = Some(p.arg().to_owned()),
            Opt::CERTSOUT => certsoutfile = Some(p.arg().to_owned()),
            Opt::MD => digestname = Some(p.arg().to_owned()),
            Opt::SIGNER => {
                // A previous -signer argument: add it to the list.
                if let Some(s) = signerfile.take() {
                    let k = keyfile.take().unwrap_or_else(|| s.clone());
                    sksigners.get_or_insert_with(Vec::new).push(s);
                    skkeys.get_or_insert_with(Vec::new).push(k);
                }
                signerfile = Some(p.arg().to_owned());
            }
            Opt::ORIGINATOR => originatorfile = Some(p.arg().to_owned()),
            Opt::INKEY => {
                // A previous -inkey argument: add the signer to the list.
                if let Some(k) = keyfile.take() {
                    let Some(s) = signerfile.take() else {
                        eprintf!("Illegal -inkey without -signer\n");
                        return end(1);
                    };
                    sksigners.get_or_insert_with(Vec::new).push(s);
                    skkeys.get_or_insert_with(Vec::new).push(k);
                }
                keyfile = Some(p.arg().to_owned());
            }
            Opt::KEYFORM => match opt::parse_format(p.arg(), fmt_flags::ANY) {
                Some(f) => keyform = f,
                None => return opthelp(&prog),
            },
            Opt::RECIP => {
                if operation == SMIME_ENCRYPT {
                    let Some(cert) = load_cert(
                        Some(p.arg()),
                        format::UNDEF,
                        Some("recipient certificate file"),
                    ) else {
                        return end(1);
                    };
                    if !encerts.push(cert) {
                        return end(1);
                    }
                } else {
                    recipfile = Some(p.arg().to_owned());
                }
            }
            Opt::RECIP_KDF | Opt::RECIP_UKM => {
                let n = if operation == SMIME_ENCRYPT {
                    encerts.len()
                } else {
                    0
                };
                if n == 0 {
                    eprintf!("No recipient specified\n");
                    return opthelp(&prog);
                }
                let recipidx = n - 1;
                if recip_opts.last().is_none_or(|r| r.idx != recipidx) {
                    recip_opts.push(RecipOpt {
                        idx: recipidx,
                        kdf: None,
                        ukm: None,
                    });
                }
                let Some(ropt) = recip_opts.last_mut() else {
                    return end(1);
                };
                if o == Opt::RECIP_KDF {
                    if ropt.kdf.is_some() {
                        eprintf!("Illegal multiple -recip_kdf for one -recip\n");
                        return end(1);
                    }
                    ropt.kdf = Some(p.arg().to_owned());
                } else {
                    if ropt.ukm.is_some() {
                        eprintf!("Illegal multiple -recip_ukm for one -recip\n");
                        return end(1);
                    }
                    match crypto::hexstr2buf(p.arg()) {
                        Some(u) => ropt.ukm = Some(u),
                        None => {
                            eprintf!("Invalid hex value after -recip_ukm\n");
                            return end(1);
                        }
                    }
                }
            }
            Opt::CIPHER => ciphername = p.unknown().map(str::to_owned),
            Opt::KEKCIPHER => kekciphername = Some(p.arg().to_owned()),
            Opt::KEYOPT => {
                let mut keyidx: i64 = -1;
                if operation == SMIME_ENCRYPT {
                    keyidx += i64::try_from(encerts.len()).unwrap_or(0);
                } else {
                    if keyfile.is_some() || signerfile.is_some() {
                        keyidx += 1;
                    }
                    if let Some(k) = &skkeys {
                        keyidx += i64::try_from(k.len()).unwrap_or(0);
                    }
                }
                let Ok(keyidx) = usize::try_from(keyidx) else {
                    eprintf!("No key specified\n");
                    return opthelp(&prog);
                };
                if key_params.last().is_none_or(|k| k.idx != keyidx) {
                    key_params.push(KeyParam {
                        idx: keyidx,
                        param: Vec::new(),
                    });
                }
                if let Some(k) = key_params.last_mut() {
                    k.param.push(p.arg().to_owned());
                }
            }
            Opt::OPT_V(v) => {
                if !opt::verify(v, p.arg(), (&vpm).into()) {
                    return end(1);
                }
                vpmtouched = true;
            }
            Opt::OPT_R(r) => {
                if !app_rand::opt_rand(r, p.arg()) {
                    return end(1);
                }
            }
            Opt::OPT_PROV(r) => {
                if !app_libctx::opt_provider(r, p.arg()) {
                    return end(1);
                }
            }
            Opt::CONFIG => {
                _conf = app_load_config_modules(Some(&ConfigFile::Given(p.arg().to_owned())));
                if _conf.is_none() {
                    return end(1);
                }
            }
            Opt::WRAP => wrapname = Some(p.arg().to_owned()),
            Opt::AES128_WRAP | Opt::AES192_WRAP | Opt::AES256_WRAP | Opt::_3DES_WRAP => {
                wrapname = Some(p.flag().get(1..).unwrap_or_default().to_owned());
            }
        }
    }
    if !app_rand::load() {
        return end(1);
    }
    let mut sign_md = None;
    if let Some(d) = &digestname {
        match opt::md(d) {
            Some(m) => sign_md = Some(m),
            None => return end(1),
        }
    }
    let mut cipher: Option<Cipher> = None;
    if let Some(c) = &ciphername {
        match opt::cipher_any(c) {
            Some(c) => cipher = Some(c),
            None => return end(1),
        }
    }
    let mut kekcipher = None;
    if let Some(c) = &kekciphername {
        match opt::cipher_any(c) {
            Some(c) => kekcipher = Some(c),
            None => return end(1),
        }
    }
    let mut wrap_cipher = None;
    if let Some(w) = &wrapname {
        match opt::cipher_any(w) {
            Some(c) => wrap_cipher = Some(c),
            None => return end(1),
        }
    }
    // The remaining arguments are files to process.
    let rest: Vec<String> = p.rest().to_vec();

    if (rr_allorfirst != -1 || rr_from.is_some()) && rr_to.is_none() {
        eprintf!("No Signed Receipts Recipients\n");
        return opthelp(&prog);
    }
    if operation & SMIME_SIGNERS == 0 && (rr_to.is_some() || rr_from.is_some()) {
        eprintf!("Signed receipts only allowed with -sign\n");
        return opthelp(&prog);
    }
    if operation & SMIME_SIGNERS == 0 && (skkeys.is_some() || sksigners.is_some()) {
        eprintf!("Multiple signers or keys not allowed\n");
        return opthelp(&prog);
    }
    if flags & CMS_CADES != 0 {
        if flags & CMS_NOATTR != 0 {
            eprintf!("Incompatible options: CAdES requires signed attributes\n");
            return opthelp(&prog);
        }
        if operation == SMIME_VERIFY
            && flags & (CMS_NO_SIGNER_CERT_VERIFY | CMS_NO_ATTR_VERIFY) != 0
        {
            eprintf!(
                "Incompatible options: CAdES validation requires certs and signed attributes validations\n"
            );
            return opthelp(&prog);
        }
    }
    if operation & SMIME_SIGNERS != 0 {
        if keyfile.is_some() && signerfile.is_none() {
            eprintf!("Illegal -inkey without -signer\n");
            return opthelp(&prog);
        }
        // A final signer to append.
        if let Some(s) = signerfile.take() {
            let k = keyfile.take().unwrap_or_else(|| s.clone());
            sksigners.get_or_insert_with(Vec::new).push(s);
            skkeys.get_or_insert_with(Vec::new).push(k);
        }
        if sksigners.is_none() {
            eprintf!("No signer certificate specified\n");
            return opthelp(&prog);
        }
        keyfile = None;
    } else if operation == SMIME_DECRYPT {
        if recipfile.is_none() && keyfile.is_none() && secret_key.is_none() && pwri_pass.is_none() {
            eprintf!("No recipient certificate or key specified\n");
            return opthelp(&prog);
        }
    } else if operation == SMIME_ENCRYPT {
        if rest.is_empty() && secret_key.is_none() && pwri_pass.is_none() && encerts.is_empty() {
            eprintf!("No recipient(s) certificate(s) specified\n");
            return opthelp(&prog);
        }
    } else if operation == 0 {
        eprintf!("No operation option (-encrypt|-decrypt|-sign|-verify|...) specified.\n");
        return opthelp(&prog);
    }
    let passin = match app_passwd(passinarg.as_deref(), None) {
        Some((p, _)) => p,
        None => {
            eprintf!("Error getting password\n");
            return end(1);
        }
    };
    let passin = passin.as_ref().map(|p| p.as_str());

    let mut ret = 2;
    if operation & SMIME_SIGNERS == 0 {
        if flags & CMS_DETACHED == 0 {
            eprintf!("Warning: -nodetach option is ignored for non-signing operation\n");
        }
        flags &= !CMS_DETACHED;
    }
    if operation & SMIME_IP == 0 && contfile.is_some() {
        eprintf!("Warning: -contfile option is ignored for the given operation\n");
    }
    if operation != SMIME_ENCRYPT && !rest.is_empty() {
        eprintf!(
            "Warning: recipient certificate file parameters ignored for operation other than -encrypt\n"
        );
    }
    if operation != SMIME_ENCRYPT && !recip_opts.is_empty() {
        eprintf!(
            "Warning: -recip_kdf and -recip_ukm parameters ignored for operation other than -encrypt\n"
        );
    }
    let mut binary_files = false;
    if flags & CMS_BINARY != 0 {
        if operation & SMIME_OP == 0 {
            outformat = format::BINARY;
        }
        if operation & SMIME_IP == 0 {
            informat = format::BINARY;
        }
        if operation & SMIME_SIGNERS != 0 && flags & CMS_DETACHED != 0 {
            binary_files = true;
        }
        if operation & SMIME_IP != 0 && contfile.is_none() {
            binary_files = true;
        }
    }
    if operation == SMIME_ENCRYPT {
        if cipher.is_none() {
            cipher = Cipher::by_name("AES-256-CBC");
        }
        if secret_key.is_some() && secret_keyid.is_none() {
            eprintf!("No secret key id\n");
            return end(ret);
        }
        for a in &rest {
            let Some(cert) = load_cert(Some(a), format::UNDEF, Some("recipient certificate file"))
            else {
                return end(ret);
            };
            if !encerts.push(cert) {
                return end(ret);
            }
        }
    }
    let mut other = None;
    if let Some(f) = &certfile {
        let (ok, c) = load_certs(Some(f), false, None, None, Some("certificate file"));
        if !ok {
            return end(ret);
        }
        other = c;
    }
    let mut recip: Option<Cert> = None;
    if let (Some(r), SMIME_DECRYPT) = (&recipfile, operation) {
        recip = load_cert(Some(r), format::UNDEF, Some("recipient certificate file"));
        if recip.is_none() {
            return end(ret);
        }
    }
    let mut originator = None;
    if let Some(o) = &originatorfile {
        originator = load_cert(Some(o), format::UNDEF, Some("originator certificate file"));
        if originator.is_none() {
            return end(ret);
        }
    }
    let mut signer = None;
    if operation == SMIME_SIGN_RECEIPT {
        signer = load_cert(
            signerfile.as_deref(),
            format::UNDEF,
            Some("receipt signer certificate file"),
        );
        if signer.is_none() {
            return end(ret);
        }
    }
    if operation == SMIME_DECRYPT || operation == SMIME_ENCRYPT {
        if keyfile.is_none() {
            keyfile.clone_from(&recipfile);
        }
    } else if operation == SMIME_SIGN || operation == SMIME_SIGN_RECEIPT {
        if keyfile.is_none() {
            keyfile.clone_from(&signerfile);
        }
    } else {
        keyfile = None;
    }
    let mut key = None;
    if let Some(k) = &keyfile {
        key = load_key(
            Some(k),
            keyform,
            false,
            passin,
            e.as_ref(),
            Some("signing key"),
        );
        if key.is_none() {
            return end(ret);
        }
    }
    let mut digestbin = None;
    let mut input = None;
    if let Some(h) = &digesthex {
        if operation != SMIME_SIGN {
            eprintf!("Cannot use -digest for non-signing operation\n");
            return end(ret);
        }
        if infile.is_some() || flags & CMS_DETACHED == 0 || flags & CMS_STREAM != 0 {
            eprintf!("Cannot use -digest when -in, -nodetach or streaming is used\n");
            return end(ret);
        }
        match crypto::hexstr2buf(h) {
            Some(d) => digestbin = Some(d),
            None => {
                eprintf!("Invalid hex value after -digest\n");
                return end(ret);
            }
        }
    } else {
        let fmt = if binary_files {
            format::BINARY
        } else {
            informat
        };
        input = bio_open_default(infile.as_deref(), 'r', fmt);
        if input.is_none() {
            return end(ret);
        }
    }
    let mut cms: Option<Cms> = None;
    let mut indata: Option<Bio> = None;
    if operation & SMIME_IP != 0 {
        let Some(inp) = &input else {
            return end(ret);
        };
        let (c, d) = load_content_info(informat, inp, flags, true, "SMIME");
        let Some(c) = c else {
            return end(ret);
        };
        indata = d;
        if let Some(cf) = &contfile {
            indata = Bio::new_file(cf, "rb");
            if indata.is_none() {
                eprintf!("Can't read content file {cf}\n");
                return end(ret);
            }
        }
        if let Some(f) = &certsoutfile {
            let allcerts = c.certs();
            if !save_certs(Some(f), &allcerts.map(|s| s.to_vec()).unwrap_or_default()) {
                eprintf!("Error writing certs to {f}\n");
                return end(5);
            }
        }
        cms = Some(c);
    }
    let mut rcms = None;
    if let Some(rf) = &rctfile {
        let mode = if rctformat == format::ASN1 { "rb" } else { "r" };
        let Some(rctin) = Bio::new_file(rf, mode) else {
            eprintf!("Can't open receipt file {rf}\n");
            return end(ret);
        };
        let (r, _) = load_content_info(rctformat, &rctin, 0, false, "receipt");
        if r.is_none() {
            return end(ret);
        }
        rcms = r;
    }
    let fmt = if binary_files {
        format::BINARY
    } else {
        outformat
    };
    let Some(out) = bio_open_default(outfile.as_deref(), 'w', fmt) else {
        return end(ret);
    };
    let mut store = None;
    if operation == SMIME_VERIFY || operation == SMIME_VERIFY_RECEIPT {
        let Some(s) = setup_verify(
            ca_file.as_deref(),
            no_ca_file,
            ca_path.as_deref(),
            no_ca_path,
            ca_store.as_deref(),
            no_ca_store,
        ) else {
            return end(ret);
        };
        s.set_policy_print_cb();
        if vpmtouched {
            s.set1_param(&vpm);
        }
        store = Some(s);
    }

    ret = 3;
    let lc = app_libctx::libctx();
    let pq = app_libctx::propq();
    let key_params_of = |i: usize| {
        key_params
            .iter()
            .find(|k| k.idx == i)
            .map(|k| k.param.as_slice())
    };
    if operation == SMIME_DATA_CREATE {
        if let Some(inp) = &input {
            cms = Cms::data_create(inp, fl(flags), lc.as_deref(), pq.as_deref());
        }
    } else if operation == SMIME_DIGEST_CREATE {
        if let Some(inp) = &input {
            cms = Cms::digest_create(
                inp,
                sign_md.as_ref(),
                fl(flags),
                lc.as_deref(),
                pq.as_deref(),
            );
        }
    } else if operation == SMIME_COMPRESS {
        if let Some(inp) = &input {
            cms = Cms::compress(inp, fl(flags));
        }
    } else if operation == SMIME_ENCRYPT {
        flags |= CMS_PARTIAL;
        let (Some(inp), Some(c)) = (&input, &cipher) else {
            return end(ret);
        };
        let Some(new) = Cms::encrypt_partial(inp, c, fl(flags), lc.as_deref(), pq.as_deref())
        else {
            return end(ret);
        };
        for (i, x) in encerts.to_vec().iter().enumerate() {
            let tflags = flags | CMS_KEY_PARAM;
            let ropt = recip_opts.iter().find(|r| r.idx == i);
            let o = RecipientOptions {
                key_params: key_params_of(i),
                cipher: c,
                wrap: wrap_cipher.as_ref(),
                ukm: ropt.and_then(|r| r.ukm.as_deref()),
                kdf: ropt.and_then(|r| r.kdf.as_deref()),
            };
            match new.add_recipient(x, key.as_ref(), originator.as_ref(), fl(tflags), &o) {
                Ok(()) => {}
                Err(RecipientError::KeyParam(p)) => {
                    eprintf!("Error setting CMS key parameter \"{p}\"\n");
                    return end(ret);
                }
                Err(RecipientError::UnknownKdf(k)) => {
                    eprintf!("Unknown KDF {k}\n");
                    return end(ret);
                }
                Err(RecipientError::Other) => return end(ret),
            }
        }
        if let (Some(k), Some(id)) = (&secret_key, &secret_keyid)
            && !new.add_recipient_key(k, id)
        {
            return end(ret);
        }
        if let Some(pw) = &pwri_pass
            && !new.add_recipient_password(pw, kekcipher.as_ref())
        {
            return end(ret);
        }
        if flags & CMS_STREAM == 0 && !new.finalize(Some(inp), fl(flags)) {
            if originator.is_some()
                && err::reason(err::peek_error()) == CMS_R_ERROR_UNSUPPORTED_STATIC_KEY_AGREEMENT
            {
                eprintf!("Cannot use originator for encryption\n");
            }
            return end(ret);
        }
        cms = Some(new);
    } else if operation == SMIME_ENCRYPTED_ENCRYPT {
        if let Some(inp) = &input {
            cms = Cms::encrypted_data_encrypt(
                inp,
                cipher.as_ref(),
                secret_key.as_deref(),
                fl(flags),
                lc.as_deref(),
                pq.as_deref(),
            );
        }
    } else if operation == SMIME_SIGN_RECEIPT {
        let (Some(c), Some(s)) = (&cms, &signer) else {
            return end(ret);
        };
        let Some(srcms) = c.sign_receipt(s, key.as_ref(), other.as_ref(), fl(flags)) else {
            return end(ret);
        };
        cms = Some(srcms);
    } else if operation & SMIME_SIGNERS != 0 {
        let mut rr = None;
        // With detached content and no precomputed digest, stream S/MIME output.
        if operation == SMIME_SIGN {
            if flags & CMS_DETACHED != 0 && digestbin.is_none() && outformat == format::SMIME {
                flags |= CMS_STREAM;
            }
            flags |= CMS_PARTIAL;
            let Some(new) = Cms::sign_partial(
                other.as_ref(),
                input.as_ref(),
                fl(flags),
                lc.as_deref(),
                pq.as_deref(),
            ) else {
                eprintf!("CMS SignedData Creation Error\n");
                return end(ret);
            };
            if let Some(ct) = &econtent_type {
                new.set1_econtent_type(ct);
            }
            if let Some(t) = &rr_to {
                rr = Rr::new(t, rr_allorfirst, rr_from.as_deref(), lc.as_deref());
                if rr.is_none() {
                    eprintf!("Signed Receipt Request Creation Error\n");
                    return end(ret);
                }
            }
            cms = Some(new);
        } else {
            flags |= CMS_REUSE_DIGEST;
        }
        let Some(c) = &cms else {
            eprintf!("Error creating CMS structure\n");
            return end(ret);
        };
        let signers = sksigners.clone().unwrap_or_default();
        let keys = skkeys.clone().unwrap_or_default();
        for (i, (s, k)) in signers.iter().zip(keys.iter()).enumerate() {
            let Some(signer) = load_cert(Some(s), format::UNDEF, Some("signer certificate")) else {
                return end(2);
            };
            let Some(skey) = load_key(
                Some(k),
                keyform,
                false,
                passin,
                e.as_ref(),
                Some("signing key"),
            ) else {
                return end(2);
            };
            let kp = key_params_of(i);
            let tflags = if kp.is_some() {
                flags | CMS_KEY_PARAM
            } else {
                flags
            };
            match c.add_signer(
                &signer,
                &skey,
                sign_md.as_ref(),
                fl(tflags),
                kp,
                rr.as_ref(),
            ) {
                Ok(true) => {}
                Ok(false) => {
                    eprintf!("Error adding CMS ReceiptRequest\n");
                    return end(ret);
                }
                Err(None) => {
                    eprintf!("Error adding SignerInfo with key from {k}\n");
                    return end(ret);
                }
                Err(Some(p)) => {
                    eprintf!("Error setting CMS key parameter \"{p}\"\n");
                    return end(ret);
                }
            }
        }
        // Unless streaming or resigning, finalize the structure.
        if operation == SMIME_SIGN && flags & CMS_STREAM == 0 {
            let res = match &digestbin {
                Some(d) => c.finalize_digest(d, fl(flags)),
                None => c.finalize(input.as_ref(), fl(flags)),
            };
            if !res {
                eprintf!("Error finalizing CMS structure\n");
                return end(ret);
            }
        }
    }
    let Some(cms) = cms else {
        eprintf!("Error creating CMS structure\n");
        return end(ret);
    };

    ret = 4;
    match operation {
        SMIME_DECRYPT => {
            if flags & CMS_DEBUG_DECRYPT != 0 {
                cms.decrypt(None, None, None, None, fl(flags));
            }
            if let Some(k) = &secret_key
                && !cms.decrypt_set1_key(k, secret_keyid.as_deref())
            {
                eprintf!("Error decrypting CMS using secret key\n");
                return end(ret);
            }
            if let Some(k) = &key
                && !cms.decrypt_set1_pkey_and_peer(k, recip.as_ref(), originator.as_ref())
            {
                eprintf!("Error decrypting CMS using private key\n");
                return end(ret);
            }
            if let Some(pw) = &pwri_pass
                && !cms.decrypt_set1_password(pw)
            {
                eprintf!("Error decrypting CMS using password\n");
                return end(ret);
            }
            if !cms.decrypt(None, None, indata.as_ref(), Some(&out), fl(flags)) {
                eprintf!("Error decrypting CMS structure\n");
                return end(ret);
            }
        }
        SMIME_DATA_OUT => {
            if !cms.data(&out, fl(flags)) {
                return end(ret);
            }
        }
        SMIME_UNCOMPRESS => {
            if !cms.uncompress(indata.as_ref(), &out, fl(flags)) {
                return end(ret);
            }
        }
        SMIME_DIGEST_VERIFY => {
            if cms.digest_verify(indata.as_ref(), &out, fl(flags)) {
                eprintf!("Verification successful\n");
            } else {
                eprintf!("Verification failure\n");
                return end(ret);
            }
        }
        SMIME_ENCRYPTED_DECRYPT => {
            if !cms.encrypted_data_decrypt(secret_key.as_deref(), indata.as_ref(), &out, fl(flags))
            {
                return end(ret);
            }
        }
        SMIME_VERIFY => {
            let what = if flags & CMS_CADES != 0 {
                "CAdES"
            } else {
                "CMS"
            };
            if cms.verify(
                other.as_ref(),
                store.as_ref(),
                indata.as_ref(),
                Some(&out),
                fl(flags),
            ) {
                eprintf!("{what} Verification successful\n");
            } else {
                eprintf!("{what} Verification failure\n");
                if verify_retcode {
                    ret = last_verify_error() + 32;
                }
                return end(ret);
            }
            if let Some(sf) = &signerfile
                && !save_certs(Some(sf), &cms.signers())
            {
                eprintf!("Error writing signers to {sf}\n");
                return end(5);
            }
            if rr_print {
                receipt_request_print(&cms);
            }
        }
        SMIME_VERIFY_RECEIPT => {
            let Some(r) = &rcms else {
                return end(ret);
            };
            if r.verify_receipt(&cms, other.as_ref(), store.as_ref(), fl(flags)) {
                eprintf!("Verification successful\n");
            } else {
                eprintf!("Verification failure\n");
                return end(ret);
            }
        }
        _ => {
            // Within this block, a positive result means success.
            let r = if noout {
                if print {
                    let nm = get_nameopt();
                    let oneline = std::ffi::c_ulong::try_from(XN_FLAG_ONELINE).unwrap_or(0);
                    cms.print(&out, (nm != oneline).then_some(nm));
                }
                1
            } else if outformat == format::SMIME {
                let mut head = String::new();
                if let Some(t) = &to {
                    head.push_str(&format!("To: {t}{mime_eol}"));
                }
                if let Some(f) = &from {
                    head.push_str(&format!("From: {f}{mime_eol}"));
                }
                if let Some(s) = &subject {
                    head.push_str(&format!("Subject: {s}{mime_eol}"));
                }
                let _ = out.write_all(head.as_bytes());
                if operation == SMIME_RESIGN {
                    cms.write_smime(&out, indata.as_ref(), fl(flags))
                } else {
                    cms.write_smime(&out, input.as_ref(), fl(flags))
                }
            } else if outformat == format::PEM {
                cms.write_pem_stream(&out, input.as_ref(), fl(flags))
            } else if outformat == format::ASN1 {
                cms.write_der_stream(&out, input.as_ref(), fl(flags))
            } else {
                eprintf!("Bad output format for CMS file\n");
                return end(ret);
            };
            if r <= 0 {
                eprintf!("Error writing CMS output\n");
                return end(6);
            }
        }
    }
    end(0)
}

/// `save_certs`.
fn save_certs(file: Option<&str>, certs: &[Cert]) -> bool {
    let Some(f) = file else {
        return true;
    };
    let Some(tmp) = Bio::new_file(f, "w") else {
        return false;
    };
    for x in certs {
        x.write_pem(&tmp);
    }
    true
}

/// `receipt_request_print`, to standard error.
fn receipt_request_print(c: &Cms) {
    for (i, r) in c.receipt_requests().iter().enumerate() {
        eprintf!("Signer {}:\n", i + 1);
        match r {
            ReceiptRequest::None => {
                eprintf!("  No Receipt Request\n");
            }
            ReceiptRequest::ParseError => {
                eprintf!("  Receipt Request Parse Error\n");
                io::print_errors();
            }
            ReceiptRequest::Request {
                content_id,
                all_or_first,
                from,
                to,
            } => {
                eprintf!("  Signed Content ID:\n");
                if let Some(b) = io::bio_err() {
                    cms::dump_indent(b, content_id, 4);
                }
                let mut t = String::from("  Receipts From");
                if let Some(list) = from {
                    t.push_str(" List:\n");
                    for n in list {
                        t.push_str(&format!("    {n}\n"));
                    }
                } else if *all_or_first == 1 {
                    t.push_str(": First Tier\n");
                } else if *all_or_first == 0 {
                    t.push_str(": All\n");
                } else {
                    t.push_str(&format!(" Unknown ({all_or_first})\n"));
                }
                t.push_str("  Receipts To:\n");
                for n in to {
                    t.push_str(&format!("    {n}\n"));
                }
                let _ = io::err().write_all(t.as_bytes());
            }
        }
    }
}
