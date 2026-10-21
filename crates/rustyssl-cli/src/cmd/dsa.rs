//! `openssl dsa` (`apps/dsa.c`).

use rustyssl_ossl::abi::{
    OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, OSSL_KEYMGMT_SELECT_KEYPAIR, OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
};
use rustyssl_ossl::encoder::Encoder;
use rustyssl_ossl::params::ParamList;

use super::pkey::opt_cipher;
use super::rsa::PVK_ENCRYPT_LEVEL;
use crate::generated::options::dsa::{OPTIONS, Opt};
use crate::lib::apps::perror;
use crate::lib::apps::{app_passwd, bio_open_owner, load_key, load_pubkey};
use crate::lib::opt::{self, Parser, eprintf, fmt_flags, format};
use crate::lib::{app_libctx, engine, io};

/// `DEFAULT_PVK_ENCR_STRENGTH` (RC4 is in the default build).
const DEFAULT_PVK_ENCR_STRENGTH: i32 = 2;

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
    // Upstream's usage path sets ret = 0: option errors exit with success.
    let usage = || {
        eprintf!("{prog}: Use -help for summary.\n");
        0
    };
    let mut e = None;
    let (mut infile, mut outfile, mut ciphername) = (None, None, None);
    let (mut passinarg, mut passoutarg) = (None, None);
    let (mut informat, mut outformat) = (format::UNDEF, format::PEM);
    let (mut text, mut noout, mut modulus, mut pubin, mut pubout) =
        (false, false, false, false, false);
    let mut pvk_encr = DEFAULT_PVK_ENCR_STRENGTH;
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
            Opt::ENGINE => e = engine::setup_engine(Some(p.arg()), false),
            Opt::PASSIN => passinarg = Some(p.arg().to_owned()),
            Opt::PASSOUT => passoutarg = Some(p.arg().to_owned()),
            Opt::PVK_STRONG => pvk_encr = 2,
            Opt::PVK_WEAK => pvk_encr = 1,
            Opt::PVK_NONE => pvk_encr = 0,
            Opt::NOOUT => noout = true,
            Opt::TEXT => text = true,
            Opt::MODULUS => modulus = true,
            Opt::PUBIN => pubin = true,
            Opt::PUBOUT => pubout = true,
            Opt::CIPHER => ciphername = p.unknown().map(str::to_owned),
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
        return 1;
    };
    let private = !pubin && (!pubout || text);
    let Some((passin, passout)) = app_passwd(passinarg.as_deref(), passoutarg.as_deref()) else {
        eprintf!("Error getting passwords\n");
        return 1;
    };
    eprintf!("read DSA key\n");
    let passin = passin.as_ref().map(|p| p.as_str());
    let pkey = if pubin {
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
    let Some(pkey) = pkey else {
        eprintf!("unable to load Key\n");
        io::print_errors();
        return 1;
    };
    if !pkey.is_a("DSA") {
        eprintf!("Not a DSA key\n");
        return 1;
    }
    let Some(out) = bio_open_owner(outfile.as_deref(), outformat, private) else {
        return 1;
    };
    if text {
        let r = if pubin {
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
        let Some(pub_key) = pkey.bn_param(c"pub") else {
            io::print_errors();
            return 1;
        };
        let _ = out.write_all(b"Public Key=");
        pub_key.print(&out);
        let _ = out.write_all(b"\n");
    }
    if noout {
        return 0;
    }
    eprintf!("writing DSA key\n");
    let output_type = match outformat {
        format::ASN1 => "DER",
        format::PEM => "PEM",
        format::MSBLOB => "MSBLOB",
        format::PVK => {
            if pubin {
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
    let public = pubout || pubin;
    let output_structure = if outformat == format::ASN1 || outformat == format::PEM {
        Some(if public {
            "SubjectPublicKeyInfo"
        } else {
            "type-specific"
        })
    } else {
        None
    };
    let selection = if public {
        OSSL_KEYMGMT_SELECT_PUBLIC_KEY
    } else {
        OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS
    };
    let ectx = Encoder::new_for_pkey(&pkey, selection, Some(output_type), output_structure);
    if ectx.num_encoders() == 0 {
        eprintf!("{output_type} format not supported\n");
        return 1;
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
        return 1;
    }
    0
}
