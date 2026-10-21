//! `openssl rsa` (`apps/rsa.c`).
//!
//! Also the key commands' shared [`perror`] (C's), and [`PVK_ENCRYPT_LEVEL`].

use rustyssl_ossl::abi::{
    OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, OSSL_KEYMGMT_SELECT_KEYPAIR, OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
};
use rustyssl_ossl::encoder::Encoder;
use rustyssl_ossl::params::ParamList;
use rustyssl_ossl::pkey::{Pkey, PkeyCtx};

use super::pkey::opt_cipher;
use crate::generated::options::rsa::{OPTIONS, Opt};
use crate::lib::apps::perror;
use crate::lib::apps::{app_passwd, bio_open_owner, load_key, load_pubkey};
use crate::lib::opt::{self, Parser, eprintf, fmt_flags, format};
use crate::lib::{app_libctx, engine, io};

/// `DEFAULT_PVK_ENCR_STRENGTH` (RC4 is in the default build).
const DEFAULT_PVK_ENCR_STRENGTH: i32 = 2;

/// The PVK encoder's parameter.
pub const PVK_ENCRYPT_LEVEL: &std::ffi::CStr = c"encrypt-level";

/// `try_legacy_encoding`.
fn try_legacy_encoding(pkey: &Pkey, outformat: i32, pubout: u8, out: &rustyssl_ossl::Bio) -> bool {
    if !pkey.has_legacy_rsa() {
        return false;
    }
    if outformat == format::ASN1 || outformat == format::PEM {
        pkey.write_legacy_rsa_public(out, outformat == format::ASN1, pubout == 2)
            .unwrap_or(false)
    } else if outformat == format::MSBLOB || outformat == format::PVK {
        pkey.write_msblob_public(out) > 0
    } else {
        false
    }
}

pub fn main(argv: &[String]) -> i32 {
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
    let (mut text, mut check, mut noout, mut modulus) = (false, false, false, false);
    let (mut pubin, mut pubout) = (0u8, 0u8);
    let mut pvk_encr = DEFAULT_PVK_ENCR_STRENGTH;
    let mut traditional = false;
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
            Opt::OUTFORM => match opt::parse_format(p.arg(), fmt_flags::ANY) {
                Some(f) => outformat = f,
                None => return usage(),
            },
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::PASSIN => passinarg = Some(p.arg().to_owned()),
            Opt::PASSOUT => passoutarg = Some(p.arg().to_owned()),
            Opt::ENGINE => e = engine::setup_engine(Some(p.arg()), false),
            Opt::PUBIN => pubin = 1,
            Opt::PUBOUT => pubout = 1,
            Opt::RSAPUBKEY_IN => pubin = 2,
            Opt::RSAPUBKEY_OUT => pubout = 2,
            Opt::PVK_STRONG => pvk_encr = 2,
            Opt::PVK_WEAK => pvk_encr = 1,
            Opt::PVK_NONE => pvk_encr = 0,
            Opt::NOOUT => noout = true,
            Opt::TEXT => text = true,
            Opt::MODULUS => modulus = true,
            Opt::CHECK => check = true,
            Opt::CIPHER => ciphername = p.unknown().map(str::to_owned),
            Opt::OPT_PROV(o) => {
                if !app_libctx::opt_provider(o, p.arg()) {
                    return 1;
                }
            }
            Opt::TRADITIONAL => traditional = true,
        }
    }
    if !p.check_rest_arg(None) {
        return usage();
    }
    let Ok(enc) = opt_cipher(ciphername.as_deref()) else {
        return usage();
    };
    let private = (text && pubin == 0) || (pubout == 0 && !noout);
    let Some((passin, passout)) = app_passwd(passinarg.as_deref(), passoutarg.as_deref()) else {
        eprintf!("Error getting passwords\n");
        return 1;
    };
    if check && pubin != 0 {
        eprintf!("Only private keys can be checked\n");
        return 1;
    }
    let passin = passin.as_ref().map(|p| p.as_str());
    let pkey = if pubin != 0 {
        let tmpformat = if pubin == 2 {
            match informat {
                format::PEM => format::PEMRSA,
                format::ASN1 => format::ASN1RSA,
                _ => format::UNDEF,
            }
        } else {
            informat
        };
        load_pubkey(
            infile.as_deref(),
            tmpformat,
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
    let Some(pkey) = pkey else {
        io::print_errors();
        return 1;
    };
    if !pkey.is_a("RSA") && !pkey.is_a("RSA-PSS") {
        eprintf!("Not an RSA key\n");
        return 1;
    }
    let Some(out) = bio_open_owner(outfile.as_deref(), outformat, private) else {
        return 1;
    };
    if text {
        let r = if pubin != 0 {
            pkey.print_public(&out, 0)
        } else {
            pkey.print_private(&out, 0)
        };
        if r <= 0 {
            perror(outfile.as_deref());
            io::print_errors();
            return 1;
        }
    }
    if modulus {
        let n = pkey.bn_param(c"n");
        let _ = out.write_all(b"Modulus=");
        if let Some(n) = &n {
            n.print(&out);
        }
        let _ = out.write_all(b"\n");
    }
    if check {
        let Some(pctx) = PkeyCtx::from_pkey(None, Some(&pkey), None) else {
            eprintf!("RSA unable to create PKEY context\n");
            io::print_errors();
            return 1;
        };
        let r = pctx.check();
        drop(pctx);
        if r == 1 {
            let _ = out.write_all(b"RSA key ok\n");
        } else if r == 0 {
            eprintf!("RSA key not ok\n");
            io::print_errors();
        } else {
            io::print_errors();
            return 1;
        }
    }
    if noout {
        return 0;
    }
    eprintf!("writing RSA key\n");
    let output_type = match outformat {
        format::ASN1 => "DER",
        format::PEM => "PEM",
        format::MSBLOB => "MSBLOB",
        format::PVK => {
            if pubin != 0 {
                eprintf!("PVK form impossible with public key input\n");
                return 1;
            }
            "PVK"
        }
        _ => {
            eprintf!("bad output format specified for outfile\n");
            return 1;
        }
    };
    let public = pubout != 0 || pubin != 0;
    let selection = if public {
        OSSL_KEYMGMT_SELECT_PUBLIC_KEY
    } else {
        OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS
    };
    let output_structure = if outformat == format::ASN1 || outformat == format::PEM {
        Some(if public {
            if pubout == 2 {
                "pkcs1"
            } else {
                "SubjectPublicKeyInfo"
            }
        } else if traditional {
            "pkcs1"
        } else {
            "PrivateKeyInfo"
        })
    } else {
        None
    };
    let ectx = Encoder::new_for_pkey(&pkey, selection, Some(output_type), output_structure);
    if ectx.num_encoders() == 0 {
        if !public || !try_legacy_encoding(&pkey, outformat, pubout, &out) {
            eprintf!("{output_type} format not supported\n");
            return 1;
        }
        return 0;
    }
    if let Some(c) = &enc {
        ectx.set_cipher(c.name().as_deref());
    }
    if enc.is_some() || outformat == format::PVK {
        ectx.set_passphrase_ui();
        if let Some(pw) = &passout {
            ectx.set_passphrase(pw.as_str().as_bytes());
        }
    }
    if outformat == format::PVK {
        let mut params = ParamList::new();
        params.int(PVK_ENCRYPT_LEVEL, pvk_encr);
        if ectx.set_params(&params) == 0 {
            eprintf!("invalid PVK encryption level\n");
            return 1;
        }
    }
    if ectx.to_bio(&out) == 0 {
        eprintf!("unable to write key\n");
        io::print_errors();
        return 1;
    }
    0
}
