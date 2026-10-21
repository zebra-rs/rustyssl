//! `openssl pkey` (`apps/pkey.c`).

use rustyssl_ossl::abi::{OSSL_PKEY_PARAM_EC_ENCODING, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT};
use rustyssl_ossl::params::ParamList;
use rustyssl_ossl::pkey::PkeyCtx;

use crate::generated::options::pkey::{OPTIONS, Opt};
use crate::lib::apps::{app_passwd, bio_open_owner, load_key, load_pubkey};
use crate::lib::ec_common::{ASN1_ENCODING_OPTIONS, POINT_FORMAT_OPTIONS};
use crate::lib::opt::opt_cipher;
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
    let (mut infile, mut outfile, mut passinarg, mut passoutarg) = (None, None, None, None);
    let mut ciphername: Option<String> = None;
    let (mut informat, mut outformat) = (format::UNDEF, format::PEM);
    let (mut pubin, mut pubout, mut text_pub, mut text, mut noout) =
        (false, false, false, false, false);
    let (mut traditional, mut check, mut pub_check) = (false, false, false);
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
            Opt::OUTFORM => match opt::parse_format(p.arg(), fmt_flags::PEMDER) {
                Some(f) => outformat = f,
                None => return usage(),
            },
            Opt::PASSIN => passinarg = Some(p.arg().to_owned()),
            Opt::PASSOUT => passoutarg = Some(p.arg().to_owned()),
            Opt::ENGINE => e = engine::setup_engine(Some(p.arg()), false),
            Opt::IN => infile = Some(p.arg().to_owned()),
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::PUBIN => (pubin, pubout) = (true, true),
            Opt::PUBOUT => pubout = true,
            Opt::TEXT_PUB => text_pub = true,
            Opt::TEXT => text = true,
            Opt::NOOUT => noout = true,
            Opt::TRADITIONAL => traditional = true,
            Opt::CHECK => check = true,
            Opt::PUB_CHECK => pub_check = true,
            Opt::CIPHER => ciphername = p.unknown().map(str::to_owned),
            Opt::EC_CONV_FORM => {
                if !opt::string(p.arg(), POINT_FORMAT_OPTIONS) {
                    return usage();
                }
                point_format = Some(p.arg().to_owned());
            }
            Opt::EC_PARAM_ENC => {
                if !opt::string(p.arg(), ASN1_ENCODING_OPTIONS) {
                    return usage();
                }
                asn1_encoding = Some(p.arg().to_owned());
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

    if text && text_pub {
        eprintf!("Warning: The -text option is ignored with -text_pub\n");
    }
    if traditional && (noout || pubout) {
        eprintf!("Warning: -traditional is ignored with no private key output\n");
    }
    if !text_pub && pubout && text {
        text = false;
        text_pub = true;
    }
    let private = (!noout && !pubout) || (text && !text_pub);

    let Ok(cipher) = opt_cipher(ciphername.as_deref()) else {
        return usage();
    };
    if cipher.is_none() {
        if passoutarg.is_some() {
            eprintf!("Warning: The -passout option is ignored without a cipher option\n");
        }
    } else if noout || outformat != format::PEM {
        eprintf!("Error: Cipher options are supported only for PEM output\n");
        return 1;
    }
    let Some((passin, passout)) = app_passwd(passinarg.as_deref(), passoutarg.as_deref()) else {
        eprintf!("Error getting passwords\n");
        return 1;
    };
    let passin = passin.as_ref().map(|p| p.as_str());
    let passout = passout.as_ref().map(|p| p.as_str());

    let pkey = if pubin {
        load_pubkey(
            infile.as_deref(),
            informat,
            true,
            passin,
            e.as_ref(),
            Some("Public Key"),
        )
    } else {
        load_key(
            infile.as_deref(),
            informat,
            true,
            passin,
            e.as_ref(),
            Some("key"),
        )
    };
    let Some(pkey) = pkey else {
        return 1;
    };
    let Some(out) = bio_open_owner(outfile.as_deref(), outformat, private) else {
        return 1;
    };

    if asn1_encoding.is_some() || point_format.is_some() {
        if !pkey.is_a("EC") {
            return 1;
        }
        let mut params = ParamList::new();
        if let Some(a) = &asn1_encoding {
            params.utf8(OSSL_PKEY_PARAM_EC_ENCODING, a);
        }
        if let Some(f) = &point_format {
            params.utf8(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, f);
        }
        if pkey.set_params(&mut params) <= 0 {
            return 1;
        }
    }

    if check || pub_check {
        let Some(ctx) = PkeyCtx::new(&pkey, e.as_ref()) else {
            io::print_errors();
            return 1;
        };
        let r = if check && !pubin {
            ctx.check()
        } else {
            ctx.public_check()
        };
        if r == 1 {
            let _ = out.write_all(b"Key is valid\n");
        } else {
            eprintf!("Key is invalid\n");
            io::print_errors();
            return 1;
        }
    }

    if !noout {
        if outformat == format::PEM {
            let ok = if pubout {
                pkey.write_pem_pubkey(&out)
            } else {
                pkey.write_pem_private(&out, cipher.as_ref(), passout, traditional)
            };
            if ok == 0 {
                return 1;
            }
        } else if outformat == format::ASN1 {
            if text || text_pub {
                eprintf!("Error: Text output cannot be combined with DER output\n");
                return 1;
            }
            let ok = if pubout {
                pkey.write_der_pubkey(&out)
            } else if traditional {
                pkey.write_der_private(&out)
            } else {
                pkey.write_der_pkcs8(&out)
            };
            if ok == 0 {
                return 1;
            }
        } else {
            eprintf!("Bad format specified for key\n");
            return 1;
        }
    }

    if text_pub {
        if pkey.print_public(&out, 0) <= 0 {
            return 1;
        }
    } else if text && pkey.print_private(&out, 0) <= 0 {
        return 1;
    }
    0
}
