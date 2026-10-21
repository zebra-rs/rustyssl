//! `openssl ec` (`apps/ec.c`).

use rustyssl_ossl::abi::{
    OSSL_KEYMGMT_SELECT_ALL, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
    OSSL_PKEY_PARAM_EC_ENCODING, OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC,
    OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
};
use rustyssl_ossl::encoder::Encoder;
use rustyssl_ossl::pkey::PkeyCtx;

use super::pkey::{ASN1_ENCODING_OPTIONS, POINT_FORMAT_OPTIONS, opt_cipher};
use crate::generated::options::ec::{OPTIONS, Opt};
use crate::lib::apps::{app_passwd, bio_open_owner, load_key, load_pubkey};
use crate::lib::opt::{self, Parser, eprintf, fmt_flags, format};
use crate::lib::{app_libctx, engine, io};

pub fn main(argv: &[String]) -> i32 {
    let ret = run(argv);
    if ret != 0 {
        io::print_errors();
    }
    ret
}

fn run(argv: &[String]) -> i32 {
    let mut p = Parser::with_unknown(argv, OPTIONS, Some("cipher"));
    let prog = p.prog();
    let usage = || {
        eprintf!("{prog}: Use -help for summary.\n");
        1
    };
    let mut e = None;
    let (mut infile, mut outfile, mut ciphername) = (None, None, None);
    let (mut passinarg, mut passoutarg) = (None, None);
    let (mut informat, mut outformat) = (format::UNDEF, format::PEM);
    let (mut text, mut noout, mut pubin, mut pubout, mut param_out) =
        (false, false, false, false, false);
    let (mut check, mut no_public) = (false, false);
    let (mut asn1_encoding, mut point_format): (Option<String>, Option<String>) = (None, None);
    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::ERR => return usage(),
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::INFORM => match opt::parse_format(p.arg(), fmt_flags::ANY) {
                Some(f) => informat = f,
                None => return usage(),
            },
            Opt::IN => infile = Some(p.arg().to_owned()),
            Opt::OUTFORM => match opt::parse_format(p.arg(), fmt_flags::PEMDER) {
                Some(f) => outformat = f,
                None => return usage(),
            },
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::NOOUT => noout = true,
            Opt::TEXT => text = true,
            Opt::PARAM_OUT => param_out = true,
            Opt::PUBIN => pubin = true,
            Opt::PUBOUT => pubout = true,
            Opt::PASSIN => passinarg = Some(p.arg().to_owned()),
            Opt::PASSOUT => passoutarg = Some(p.arg().to_owned()),
            Opt::ENGINE => e = engine::setup_engine(Some(p.arg()), false),
            Opt::CIPHER => ciphername = p.unknown().map(str::to_owned),
            Opt::CONV_FORM => {
                point_format = Some(p.arg().to_owned());
                if !opt::string(p.arg(), POINT_FORMAT_OPTIONS) {
                    return usage();
                }
            }
            Opt::PARAM_ENC => {
                asn1_encoding = Some(p.arg().to_owned());
                if !opt::string(p.arg(), ASN1_ENCODING_OPTIONS) {
                    return usage();
                }
            }
            Opt::NO_PUBLIC => no_public = true,
            Opt::CHECK => check = true,
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
    let Ok(enc) = opt_cipher(ciphername.as_deref()) else {
        return usage();
    };
    let private = !pubin && (text || (!param_out && !pubout));
    let Some((passin, passout)) = app_passwd(passinarg.as_deref(), passoutarg.as_deref()) else {
        eprintf!("Error getting passwords\n");
        return 1;
    };
    let passin = passin.as_ref().map(|p| p.as_str());
    let eckey = if pubin {
        load_pubkey(
            infile.as_deref(),
            informat,
            true,
            passin,
            e.as_ref(),
            Some("public key"),
        )
    } else {
        load_key(
            infile.as_deref(),
            informat,
            true,
            passin,
            e.as_ref(),
            Some("private key"),
        )
    };
    let Some(eckey) = eckey else {
        eprintf!("unable to load Key\n");
        return 1;
    };
    let Some(out) = bio_open_owner(outfile.as_deref(), outformat, private) else {
        return 1;
    };
    if let Some(f) = &point_format
        && !eckey.set_utf8_string_param(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, f)
    {
        eprintf!("unable to set point conversion format\n");
        return 1;
    }
    if let Some(a) = &asn1_encoding
        && !eckey.set_utf8_string_param(OSSL_PKEY_PARAM_EC_ENCODING, a)
    {
        eprintf!("unable to set asn1 encoding format\n");
        return 1;
    }
    if no_public {
        if !eckey.set_int_param(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, 0) {
            eprintf!("unable to disable public key encoding\n");
            return 1;
        }
    } else if !eckey.set_int_param(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, 1) {
        eprintf!("unable to enable public key encoding\n");
        return 1;
    }
    if text {
        let r = if pubin {
            eckey.print_public(&out, 0)
        } else {
            eckey.print_private(&out, 0)
        };
        if r <= 0 {
            eprintf!("unable to print EC key\n");
            return 1;
        }
    }
    if check {
        let Some(pctx) = PkeyCtx::from_pkey(None, Some(&eckey), None) else {
            eprintf!("unable to check EC key\n");
            return 1;
        };
        if pctx.check() <= 0 {
            eprintf!("EC Key Invalid!\n");
        } else {
            eprintf!("EC Key valid.\n");
        }
        io::print_errors();
    }
    if !noout {
        let output_type = if outformat == format::ASN1 {
            "DER"
        } else {
            "PEM"
        };
        let mut output_structure = "type-specific";
        let selection = if param_out {
            OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
        } else if pubin || pubout {
            output_structure = "SubjectPublicKeyInfo";
            OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS | OSSL_KEYMGMT_SELECT_PUBLIC_KEY
        } else {
            OSSL_KEYMGMT_SELECT_ALL
        };
        let ectx =
            Encoder::new_for_pkey(&eckey, selection, Some(output_type), Some(output_structure));
        if let Some(c) = &enc {
            ectx.set_cipher(c.name().as_deref());
            ectx.set_passphrase_ui();
            if let Some(pw) = &passout {
                ectx.set_passphrase(pw.as_str().as_bytes());
            }
        }
        if ectx.to_bio(&out) == 0 {
            eprintf!("unable to write EC key\n");
            return 1;
        }
    }
    0
}
