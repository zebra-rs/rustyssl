//! `openssl rsautl` (`apps/rsautl.c`).

use rustyssl_ossl::abi::{
    RSA_NO_PADDING, RSA_PKCS1_OAEP_PADDING, RSA_PKCS1_PADDING, RSA_X931_PADDING,
};
use rustyssl_ossl::pkey::PkeyCtx;

use crate::generated::options::rsautl::{OPTIONS, Opt};
use crate::lib::apps::{app_passwd, bio_open_default, load_cert, load_key, load_pubkey};
use crate::lib::opt::{self, Parser, eprintf, fmt_flags, format};
use crate::lib::{app_libctx, app_rand, engine, io};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Verify,
    Sign,
    Encrypt,
    Decrypt,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyType {
    Private,
    Public,
    Cert,
}

pub fn main(argv: &[String]) -> i32 {
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let usage = || {
        eprintf!("{prog}: Use -help for summary.\n");
        1
    };
    let mut e = None;
    let (mut infile, mut outfile, mut keyfile, mut passinarg) = (None, None, None, None);
    let (mut mode, mut key_type, mut pad) = (Mode::Verify, KeyType::Private, RSA_PKCS1_PADDING);
    let mut keyformat = format::UNDEF;
    let (mut hexdump, mut asn1parse, mut need_priv, mut rev) = (false, false, false, false);
    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::ERR => return usage(),
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::KEYFORM => match opt::parse_format(p.arg(), fmt_flags::ANY) {
                Some(f) => keyformat = f,
                None => return usage(),
            },
            Opt::IN => infile = Some(p.arg().to_owned()),
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::ENGINE => e = engine::setup_engine(Some(p.arg()), false),
            Opt::ASN1PARSE => asn1parse = true,
            Opt::HEXDUMP => hexdump = true,
            Opt::RSA_RAW => pad = RSA_NO_PADDING,
            Opt::OAEP => pad = RSA_PKCS1_OAEP_PADDING,
            Opt::PKCS => pad = RSA_PKCS1_PADDING,
            Opt::X931 => pad = RSA_X931_PADDING,
            Opt::SIGN => (mode, need_priv) = (Mode::Sign, true),
            Opt::VERIFY => mode = Mode::Verify,
            Opt::REV => rev = true,
            Opt::ENCRYPT => mode = Mode::Encrypt,
            Opt::DECRYPT => (mode, need_priv) = (Mode::Decrypt, true),
            Opt::PUBIN => key_type = KeyType::Public,
            Opt::CERTIN => key_type = KeyType::Cert,
            Opt::INKEY => keyfile = Some(p.arg().to_owned()),
            Opt::PASSIN => passinarg = Some(p.arg().to_owned()),
            Opt::OPT_R(o) => {
                if !app_rand::opt_rand(o, p.arg()) {
                    return 1;
                }
            }
            Opt::OPT_PROV(o) => {
                if !app_libctx::opt_provider(o, p.arg()) {
                    return 1;
                }
            }
        }
    }
    if !p.check_rest_arg(None) {
        return usage();
    }
    if !app_rand::load() {
        return 1;
    }
    if need_priv && key_type != KeyType::Private {
        eprintf!("A private key is needed for this operation\n");
        return 1;
    }
    let Some((passin, _)) = app_passwd(passinarg.as_deref(), None) else {
        eprintf!("Error getting password\n");
        return 1;
    };
    let kf = keyfile.as_deref();
    let pkey = match key_type {
        KeyType::Private => load_key(
            kf,
            keyformat,
            false,
            passin.as_ref().map(|p| p.as_str()),
            e.as_ref(),
            Some("private key"),
        ),
        KeyType::Public => load_pubkey(kf, keyformat, false, None, e.as_ref(), Some("public key")),
        KeyType::Cert => load_cert(kf, format::UNDEF, Some("Certificate")).and_then(|x| x.pubkey()),
    };
    let Some(pkey) = pkey else {
        return 1;
    };
    let Some(input) = bio_open_default(infile.as_deref(), 'r', format::BINARY) else {
        return 1;
    };
    let Some(out) = bio_open_default(outfile.as_deref(), 'w', format::BINARY) else {
        return 1;
    };
    let keysize = usize::try_from(pkey.size()).unwrap_or(0);
    let mut rsa_in = vec![0u8; keysize * 2];
    let mut rsa_out = vec![0u8; keysize];
    let rv = input.read(&mut rsa_in);
    let Ok(inlen) = usize::try_from(rv) else {
        eprintf!("Error reading input Data\n");
        return 1;
    };
    rsa_in.truncate(inlen);
    if rev {
        rsa_in.reverse();
    }
    let Some(ctx) = PkeyCtx::from_pkey(None, Some(&pkey), None) else {
        return 1;
    };
    let mut outlen = keysize;
    let ok = match mode {
        Mode::Verify => {
            ctx.verify_recover_init() > 0
                && ctx.set_rsa_padding(pad) > 0
                && ctx.verify_recover(Some(&mut rsa_out), &mut outlen, &rsa_in) > 0
        }
        Mode::Sign => {
            ctx.sign_init() > 0
                && ctx.set_rsa_padding(pad) > 0
                && ctx.sign(Some(&mut rsa_out), &mut outlen, &rsa_in) > 0
        }
        Mode::Encrypt => {
            ctx.encrypt_init() > 0
                && ctx.set_rsa_padding(pad) > 0
                && ctx.encrypt(Some(&mut rsa_out), &mut outlen, &rsa_in) > 0
        }
        Mode::Decrypt => {
            ctx.decrypt_init() > 0
                && ctx.set_rsa_padding(pad) > 0
                && ctx.decrypt(Some(&mut rsa_out), &mut outlen, &rsa_in) > 0
        }
    };
    if !ok {
        eprintf!("RSA operation error\n");
        io::print_errors();
        return 1;
    }
    let result = rsa_out.get(..outlen).unwrap_or_default();
    if asn1parse {
        if out.asn1_parse_dump(result, 1, -1) == 0 {
            io::print_errors();
        }
    } else if hexdump {
        out.dump(result);
    } else {
        out.write(result);
    }
    0
}
