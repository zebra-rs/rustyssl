//! `openssl smime` (`apps/smime.c`).

use rustyssl_ossl::Bio;
use rustyssl_ossl::abi::{
    PKCS7_BINARY, PKCS7_CRLFEOL, PKCS7_DETACHED, PKCS7_NOATTR, PKCS7_NOCERTS, PKCS7_NOCHAIN,
    PKCS7_NOINTERN, PKCS7_NOSIGS, PKCS7_NOSMIMECAP, PKCS7_NOVERIFY, PKCS7_PARTIAL,
    PKCS7_REUSE_DIGEST, PKCS7_STREAM, PKCS7_TEXT,
};
use rustyssl_ossl::evp::Cipher;
use rustyssl_ossl::pkcs7::Pkcs7;
use rustyssl_ossl::verify::VerifyParam;
use rustyssl_ossl::x509::{Cert, CertStack};

use crate::generated::options::smime::{OPTIONS, Opt};
use crate::lib::apps::{
    ConfigFile, app_load_config_modules, app_passwd, bio_open_default, load_cert, load_certs,
    load_key, setup_verify,
};
use crate::lib::opt::{self, Parser, eprintf, fmt_flags, format};
use crate::lib::{app_libctx, app_rand, engine, io};

const SMIME_OP: i32 = 0x10;
const SMIME_IP: i32 = 0x20;
const SMIME_SIGNERS: i32 = 0x40;
const SMIME_ENCRYPT: i32 = 1 | SMIME_OP;
const SMIME_DECRYPT: i32 = 2 | SMIME_IP;
const SMIME_SIGN: i32 = 3 | SMIME_OP | SMIME_SIGNERS;
const SMIME_RESIGN: i32 = 6 | SMIME_IP | SMIME_OP | SMIME_SIGNERS;
const SMIME_VERIFY: i32 = 4 | SMIME_IP;
const SMIME_PK7OUT: i32 = 5 | SMIME_IP | SMIME_OP;

/// `operation_name`.
fn operation_name(operation: i32) -> &'static str {
    match operation {
        SMIME_ENCRYPT => "encrypt",
        SMIME_DECRYPT => "decrypt",
        SMIME_SIGN => "sign",
        SMIME_RESIGN => "resign",
        SMIME_VERIFY => "verify",
        SMIME_PK7OUT => "pk7out",
        _ => "(invalid operation)",
    }
}

/// How `smime_main` ends: its status, and whether it prints the error queue (any status
/// but 0).
fn end(ret: i32) -> i32 {
    if ret != 0 {
        io::print_errors();
    }
    ret
}

pub fn main(argv: &[String]) -> i32 {
    let Some(vpm) = VerifyParam::new() else {
        return 1;
    };
    let mut p = Parser::with_unknown(argv, OPTIONS, Some("cipher"));
    let prog = p.prog();
    // Upstream's status starts at 0, so errors before the operation starts exit with 0.
    let opthelp = |prog: &str| {
        eprintf!("{prog}: Use -help for summary.\n");
        end(0)
    };
    let mut _conf = None;
    let mut sksigners: Vec<String> = Vec::new();
    let mut skkeys: Vec<String> = Vec::new();
    let (mut ca_file, mut ca_path, mut ca_store) = (None, None, None);
    let (mut certfile, mut keyfile, mut contfile) = (None::<String>, None::<String>, None);
    let (mut infile, mut outfile, mut signerfile, mut recipfile) =
        (None, None, None::<String>, None::<String>);
    let (mut passinarg, mut to, mut from, mut subject) = (None, None, None, None);
    let (mut digestname, mut ciphername) = (None::<String>, None::<String>);
    let (mut no_ca_path, mut no_ca_file, mut no_ca_store) = (false, false, false);
    let mut flags = PKCS7_DETACHED;
    let mut operation = 0;
    let mut indef = false;
    let (mut informat, mut outformat, mut keyform) = (format::SMIME, format::SMIME, format::UNDEF);
    let mut vpmtouched = false;
    let mut e = None;
    let mut mime_eol = "\n";
    loop {
        let o = p.next();
        let mut set_operation = |op: i32| {
            if operation != 0 && operation != op {
                eprintf!(
                    "{prog}: Cannot use -{} together with -{}\n",
                    operation_name(op),
                    operation_name(operation)
                );
                false
            } else {
                operation = op;
                true
            }
        };
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
            Opt::IN => infile = Some(p.arg().to_owned()),
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::ENCRYPT | Opt::DECRYPT | Opt::SIGN | Opt::RESIGN | Opt::VERIFY | Opt::PK7OUT => {
                let op = match o {
                    Opt::ENCRYPT => SMIME_ENCRYPT,
                    Opt::DECRYPT => SMIME_DECRYPT,
                    Opt::SIGN => SMIME_SIGN,
                    Opt::RESIGN => SMIME_RESIGN,
                    Opt::VERIFY => SMIME_VERIFY,
                    _ => SMIME_PK7OUT,
                };
                if !set_operation(op) {
                    return end(0);
                }
            }
            Opt::TEXT => flags |= PKCS7_TEXT,
            Opt::NOINTERN => flags |= PKCS7_NOINTERN,
            Opt::NOVERIFY => flags |= PKCS7_NOVERIFY,
            Opt::NOCHAIN => flags |= PKCS7_NOCHAIN,
            Opt::NOCERTS => flags |= PKCS7_NOCERTS,
            Opt::NOATTR => flags |= PKCS7_NOATTR,
            Opt::NODETACH => flags &= !PKCS7_DETACHED,
            Opt::NOSMIMECAP => flags |= PKCS7_NOSMIMECAP,
            Opt::BINARY => flags |= PKCS7_BINARY,
            Opt::NOSIGS => flags |= PKCS7_NOSIGS,
            Opt::STREAM | Opt::INDEF => indef = true,
            Opt::NOINDEF => indef = false,
            Opt::CRLFEOL => {
                flags |= PKCS7_CRLFEOL;
                mime_eol = "\r\n";
            }
            Opt::OPT_R(r) => {
                if !app_rand::opt_rand(r, p.arg()) {
                    return end(0);
                }
            }
            Opt::OPT_PROV(r) => {
                if !app_libctx::opt_provider(r, p.arg()) {
                    return end(0);
                }
            }
            Opt::CONFIG => {
                _conf = app_load_config_modules(Some(&ConfigFile::Given(p.arg().to_owned())));
                if _conf.is_none() {
                    return end(0);
                }
            }
            Opt::ENGINE => e = engine::setup_engine(Some(p.arg()), false),
            Opt::PASSIN => passinarg = Some(p.arg().to_owned()),
            Opt::TO => to = Some(p.arg().to_owned()),
            Opt::FROM => from = Some(p.arg().to_owned()),
            Opt::SUBJECT => subject = Some(p.arg().to_owned()),
            Opt::SIGNER => {
                // A previous -signer argument: add it to the list.
                if let Some(s) = signerfile.take() {
                    let k = keyfile.take().unwrap_or_else(|| s.clone());
                    sksigners.push(s);
                    skkeys.push(k);
                }
                signerfile = Some(p.arg().to_owned());
            }
            Opt::RECIP => recipfile = Some(p.arg().to_owned()),
            Opt::MD => digestname = Some(p.arg().to_owned()),
            Opt::CIPHER => ciphername = p.unknown().map(str::to_owned),
            Opt::INKEY => {
                // A previous -inkey argument: add the signer to the list.
                if let Some(k) = keyfile.take() {
                    let Some(s) = signerfile.take() else {
                        eprintf!("{prog}: Must have -signer before -inkey\n");
                        return opthelp(&prog);
                    };
                    sksigners.push(s);
                    skkeys.push(k);
                }
                keyfile = Some(p.arg().to_owned());
            }
            Opt::KEYFORM => match opt::parse_format(p.arg(), fmt_flags::ANY) {
                Some(f) => keyform = f,
                None => return opthelp(&prog),
            },
            Opt::CERTFILE => certfile = Some(p.arg().to_owned()),
            Opt::CAFILE => ca_file = Some(p.arg().to_owned()),
            Opt::CAPATH => ca_path = Some(p.arg().to_owned()),
            Opt::CASTORE => ca_store = Some(p.arg().to_owned()),
            Opt::NOCAFILE => no_ca_file = true,
            Opt::NOCAPATH => no_ca_path = true,
            Opt::NOCASTORE => no_ca_store = true,
            Opt::CONTENT => contfile = Some(p.arg().to_owned()),
            Opt::OPT_V(v) => {
                if !opt::verify(v, p.arg(), (&vpm).into()) {
                    return opthelp(&prog);
                }
                vpmtouched = true;
            }
        }
    }
    // Extra arguments are files with recipient keys.
    let rest: Vec<String> = p.rest().to_vec();
    if !app_rand::load() {
        return end(0);
    }
    let mut sign_md = None;
    if let Some(d) = &digestname {
        match opt::md(d) {
            Some(m) => sign_md = Some(m),
            None => return opthelp(&prog),
        }
    }
    let mut cipher: Option<Cipher> = None;
    if let Some(c) = &ciphername {
        match opt::cipher_any(c) {
            Some(c) => cipher = Some(c),
            None => return opthelp(&prog),
        }
    }
    if operation & SMIME_SIGNERS == 0 && (!skkeys.is_empty() || !sksigners.is_empty()) {
        eprintf!("Multiple signers or keys not allowed\n");
        return opthelp(&prog);
    }
    if operation == 0 {
        eprintf!("No operation (-encrypt|-sign|...) specified\n");
        return opthelp(&prog);
    }
    if operation & SMIME_SIGNERS != 0 {
        // A final signer to append.
        if keyfile.is_some() && signerfile.is_none() {
            eprintf!("Illegal -inkey without -signer\n");
            return opthelp(&prog);
        }
        if let Some(s) = signerfile.take() {
            let k = keyfile.take().unwrap_or_else(|| s.clone());
            sksigners.push(s);
            skkeys.push(k);
        }
        if sksigners.is_empty() {
            eprintf!("No signer certificate specified\n");
            return opthelp(&prog);
        }
        keyfile = None;
    } else if operation == SMIME_DECRYPT {
        if recipfile.is_none() && keyfile.is_none() {
            eprintf!("No recipient certificate or key specified\n");
            return opthelp(&prog);
        }
    } else if operation == SMIME_ENCRYPT && rest.is_empty() {
        eprintf!("No recipient(s) certificate(s) specified\n");
        return opthelp(&prog);
    }
    let passin = match app_passwd(passinarg.as_deref(), None) {
        Some((p, _)) => p,
        None => {
            eprintf!("Error getting password\n");
            return end(0);
        }
    };
    let passin = passin.as_ref().map(|p| p.as_str());

    let mut ret = 2;
    if operation & SMIME_SIGNERS == 0 {
        flags &= !PKCS7_DETACHED;
    }
    if operation & SMIME_OP == 0 && flags & PKCS7_BINARY != 0 {
        outformat = format::BINARY;
    }
    if operation & SMIME_IP == 0 && flags & PKCS7_BINARY != 0 {
        informat = format::BINARY;
    }
    let lc = app_libctx::libctx();
    let pq = app_libctx::propq();

    let mut encerts = None;
    if operation == SMIME_ENCRYPT {
        if cipher.is_none() {
            cipher = Cipher::by_name("AES-256-CBC");
        }
        let Some(certs) = CertStack::new() else {
            return end(ret);
        };
        for a in &rest {
            let Some(cert) = load_cert(Some(a), format::UNDEF, Some("recipient certificate file"))
            else {
                return end(ret);
            };
            if !certs.push(cert) {
                return end(ret);
            }
        }
        encerts = Some(certs);
    }
    let mut other = None;
    if let Some(f) = &certfile {
        let (ok, c) = load_certs(Some(f), false, None, None, Some("certificates"));
        if !ok {
            io::print_errors();
            return end(ret);
        }
        other = c;
    }
    let mut recip: Option<Cert> = None;
    if let (Some(r), SMIME_DECRYPT) = (&recipfile, operation) {
        recip = load_cert(Some(r), format::UNDEF, Some("recipient certificate file"));
        if recip.is_none() {
            io::print_errors();
            return end(ret);
        }
    }
    if operation == SMIME_DECRYPT {
        if keyfile.is_none() {
            keyfile.clone_from(&recipfile);
        }
    } else if operation != SMIME_SIGN {
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
    let Some(input) = bio_open_default(infile.as_deref(), 'r', informat) else {
        return end(ret);
    };
    let mut indata: Option<Bio> = None;
    let mut p7: Option<Pkcs7> = None;
    if operation & SMIME_IP != 0 {
        let Some(new) = Pkcs7::new_ex(lc.as_deref(), pq.as_deref()) else {
            eprintf!("Error allocating PKCS7 object\n");
            return end(ret);
        };
        let read = match informat {
            format::SMIME => {
                let (r, d) = new.read_smime_into(&input);
                indata = d;
                r
            }
            format::PEM => new.read_pem_into(&input),
            format::ASN1 => new.read_der_into(&input),
            _ => {
                eprintf!("Bad input format for PKCS#7 file\n");
                return end(ret);
            }
        };
        let Some(read) = read else {
            eprintf!("Error reading S/MIME message\n");
            return end(ret);
        };
        p7 = Some(read);
        if let Some(c) = &contfile {
            indata = Bio::new_file(c, "rb");
            if indata.is_none() {
                eprintf!("Can't read content file {c}\n");
                return end(ret);
            }
        }
    }
    let Some(out) = bio_open_default(outfile.as_deref(), 'w', outformat) else {
        return end(ret);
    };
    let mut store = None;
    if operation == SMIME_VERIFY {
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
    if operation == SMIME_ENCRYPT {
        if indef {
            flags |= PKCS7_STREAM;
        }
        if let (Some(certs), Some(c)) = (&encerts, &cipher) {
            p7 = Pkcs7::encrypt(certs, &input, c, flags, lc.as_deref(), pq.as_deref());
        }
    } else if operation & SMIME_SIGNERS != 0 {
        // With detached content, stream only for S/MIME output.
        if operation == SMIME_SIGN {
            if flags & PKCS7_DETACHED != 0 {
                if outformat == format::SMIME {
                    flags |= PKCS7_STREAM;
                }
            } else if indef {
                flags |= PKCS7_STREAM;
            }
            flags |= PKCS7_PARTIAL;
            let Some(new) =
                Pkcs7::sign_partial(other.as_ref(), &input, flags, lc.as_deref(), pq.as_deref())
            else {
                return end(ret);
            };
            if flags & PKCS7_NOCERTS != 0
                && let Some(o) = &other
            {
                for x in o.to_vec() {
                    new.add_certificate(&x);
                }
            }
            p7 = Some(new);
        } else {
            flags |= PKCS7_REUSE_DIGEST;
        }
        let Some(p7s) = &p7 else {
            eprintf!("Error creating PKCS#7 structure\n");
            return end(ret);
        };
        for (s, k) in sksigners.iter().zip(skkeys.iter()) {
            let Some(signer) = load_cert(Some(s), format::UNDEF, Some("signer certificate")) else {
                return end(ret);
            };
            let Some(key) = load_key(
                Some(k),
                keyform,
                false,
                passin,
                e.as_ref(),
                Some("signing key"),
            ) else {
                return end(ret);
            };
            if !p7s.sign_add_signer(&signer, &key, sign_md.as_ref(), flags) {
                return end(ret);
            }
        }
        // Unless streaming or resigning, finalize the structure.
        if operation == SMIME_SIGN && flags & PKCS7_STREAM == 0 && !p7s.finalize(&input, flags) {
            return end(ret);
        }
    }
    let Some(p7) = p7 else {
        eprintf!("Error creating PKCS#7 structure\n");
        return end(ret);
    };

    ret = 4;
    if operation == SMIME_DECRYPT {
        if !p7.decrypt(key.as_ref(), recip.as_ref(), &out, flags) {
            eprintf!("Error decrypting PKCS#7 structure\n");
            return end(ret);
        }
    } else if operation == SMIME_VERIFY {
        if p7.verify(
            other.as_ref(),
            store.as_ref(),
            indata.as_ref(),
            Some(&out),
            flags,
        ) {
            eprintf!("Verification successful\n");
        } else {
            eprintf!("Verification failure\n");
            return end(ret);
        }
        let signers = p7.signers(other.as_ref(), flags);
        if !save_certs(signerfile.as_deref(), signers.as_deref()) {
            eprintf!(
                "Error writing signers to {}\n",
                signerfile.as_deref().unwrap_or("<NULL>")
            );
            return end(5);
        }
    } else if operation == SMIME_PK7OUT {
        p7.write_pem(&out);
    } else {
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
        let rv = match outformat {
            format::SMIME => {
                if operation == SMIME_RESIGN {
                    p7.write_smime(&out, indata.as_ref(), flags)
                } else {
                    p7.write_smime(&out, Some(&input), flags)
                }
            }
            format::PEM => p7.write_pem_stream(&out, Some(&input), flags),
            format::ASN1 => p7.write_der_stream(&out, Some(&input), flags),
            _ => {
                eprintf!("Bad output format for PKCS#7 file\n");
                return end(ret);
            }
        };
        if rv == 0 {
            eprintf!("Error writing output\n");
            return end(3);
        }
    }
    end(0)
}

/// `save_certs`: the signers, to `signerfile` if given.
fn save_certs(signerfile: Option<&str>, signers: Option<&[Cert]>) -> bool {
    let Some(f) = signerfile else {
        return true;
    };
    let Some(tmp) = Bio::new_file(f, "w") else {
        return false;
    };
    for x in signers.unwrap_or_default() {
        x.write_pem(&tmp);
    }
    true
}
