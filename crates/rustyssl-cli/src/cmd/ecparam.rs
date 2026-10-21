//! `openssl ecparam` (`apps/ecparam.c`).

use rustyssl_ossl::abi::{
    OSSL_KEYMGMT_SELECT_ALL, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, OSSL_PKEY_EC_GROUP_CHECK_NAMED,
    OSSL_PKEY_PARAM_EC_ENCODING, OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE,
    OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, OSSL_PKEY_PARAM_EC_SEED,
    OSSL_PKEY_PARAM_GROUP_NAME, SN_X9_62_prime192v1, SN_X9_62_prime256v1,
};
use rustyssl_ossl::encoder::Encoder;
use rustyssl_ossl::params::ParamList;
use rustyssl_ossl::pkey::{self, PkeyCtx};
use rustyssl_ossl::{Bio, obj};

use super::pkey::{ASN1_ENCODING_OPTIONS, POINT_FORMAT_OPTIONS};
use crate::generated::options::ecparam::{OPTIONS, Opt};
use crate::lib::apps::{bio_open_owner, load_keyparams_suppress};
use crate::lib::opt::{self, Parser, eprintf, fmt_flags, format};
use crate::lib::{app_libctx, app_rand, engine, io};

/// `list_builtin_curves`.
fn list_builtin_curves(out: &Bio) -> bool {
    let mut text = String::new();
    for (nid, comment) in pkey::builtin_curves() {
        let comment = comment.unwrap_or_else(|| "CURVE DESCRIPTION NOT AVAILABLE".to_owned());
        let sname = obj::nid2sn(nid).unwrap_or_default();
        text.push_str(&format!("  {sname:<10}: {comment}\n"));
    }
    let _ = out.write_all(text.as_bytes());
    true
}

pub fn main(argv: &[String]) -> i32 {
    let ret = run(argv);
    if ret != 0 {
        io::print_errors();
    }
    ret
}

fn run(argv: &[String]) -> i32 {
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let usage = || {
        eprintf!("{prog}: Use -help for summary.\n");
        1
    };
    let mut _e = None;
    let (mut curve_name, mut asn1_encoding, mut point_format): (
        Option<String>,
        Option<String>,
        Option<String>,
    ) = (None, None, None);
    let (mut infile, mut outfile) = (None, None);
    let (mut informat, mut outformat) = (format::PEM, format::PEM);
    let (mut noout, mut no_seed, mut check, mut check_named) = (false, false, false, false);
    let (mut text, mut genkey, mut list_curves) = (false, false, false);
    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::ERR => return usage(),
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::INFORM => match opt::parse_format(p.arg(), fmt_flags::PEMDER) {
                Some(f) => informat = f,
                None => return usage(),
            },
            Opt::IN => infile = Some(p.arg().to_owned()),
            Opt::OUTFORM => match opt::parse_format(p.arg(), fmt_flags::PEMDER) {
                Some(f) => outformat = f,
                None => return usage(),
            },
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::TEXT => text = true,
            Opt::CHECK => check = true,
            Opt::CHECK_NAMED => check_named = true,
            Opt::LIST_CURVES => list_curves = true,
            Opt::NO_SEED => no_seed = true,
            Opt::NOOUT => noout = true,
            Opt::NAME => curve_name = Some(p.arg().to_owned()),
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
            Opt::GENKEY => genkey = true,
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
            Opt::ENGINE => _e = engine::setup_engine(Some(p.arg()), false),
        }
    }
    if !p.check_rest_arg(None) {
        return usage();
    }
    if !app_rand::load() {
        return 1;
    }
    if list_curves {
        let Some(out) = bio_open_owner(outfile.as_deref(), outformat, false) else {
            return 1;
        };
        return if list_builtin_curves(&out) { 0 } else { 1 };
    }
    let private = genkey;
    let lc = app_libctx::libctx();
    let pq = app_libctx::propq();
    let params_key = if let Some(mut curve) = curve_name.clone() {
        if curve == "secp192r1" {
            eprintf!("using curve name prime192v1 instead of secp192r1\n");
            curve = SN_X9_62_prime192v1.to_string_lossy().into_owned();
        } else if curve == "secp256r1" {
            eprintf!("using curve name prime256v1 instead of secp256r1\n");
            curve = SN_X9_62_prime256v1.to_string_lossy().into_owned();
        }
        let mut params = ParamList::new();
        let mut ok = params.utf8(OSSL_PKEY_PARAM_GROUP_NAME, &curve);
        if let Some(a) = &asn1_encoding {
            ok &= params.utf8(OSSL_PKEY_PARAM_EC_ENCODING, a);
        }
        if let Some(f) = &point_format {
            ok &= params.utf8(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, f);
        }
        let alg = if curve.eq_ignore_ascii_case("SM2") {
            "sm2"
        } else {
            "ec"
        };
        let gctx = PkeyCtx::from_name(lc.as_deref(), alg, pq.as_deref());
        let key = gctx.as_ref().filter(|_| ok).and_then(|g| {
            if g.keygen_init() <= 0 || g.set_params(&params) <= 0 {
                return None;
            }
            match g.keygen() {
                (r, k) if r > 0 => k,
                _ => None,
            }
        });
        let Some(key) = key else {
            eprintf!("unable to generate key\n");
            return 1;
        };
        key
    } else {
        let mut k = load_keyparams_suppress(
            infile.as_deref(),
            informat,
            true,
            Some("EC"),
            Some("EC parameters"),
            true,
        );
        if k.is_none() {
            k = load_keyparams_suppress(
                infile.as_deref(),
                informat,
                true,
                Some("SM2"),
                Some("SM2 parameters"),
                true,
            );
        }
        let Some(k) = k else {
            eprintf!(
                "Unable to load parameters from {}\n",
                infile.as_deref().unwrap_or("<NULL>")
            );
            return 1;
        };
        if let Some(f) = &point_format
            && !k.set_utf8_string_param(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, f)
        {
            eprintf!("unable to set point conversion format\n");
            return 1;
        }
        if let Some(a) = &asn1_encoding
            && !k.set_utf8_string_param(OSSL_PKEY_PARAM_EC_ENCODING, a)
        {
            eprintf!("unable to set asn1 encoding format\n");
            return 1;
        }
        k
    };
    if no_seed && !params_key.set_octet_string_param(OSSL_PKEY_PARAM_EC_SEED, &[]) {
        eprintf!("unable to clear seed\n");
        return 1;
    }
    let Some(out) = bio_open_owner(outfile.as_deref(), outformat, private) else {
        return 1;
    };
    if text && params_key.print_params(&out, 0) <= 0 {
        eprintf!("unable to print params\n");
        return 1;
    }
    if check || check_named {
        eprintf!("checking elliptic curve parameters: ");
        if check_named
            && !params_key.set_utf8_string_param(
                OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE,
                &OSSL_PKEY_EC_GROUP_CHECK_NAMED.to_string_lossy(),
            )
        {
            eprintf!("unable to set check_type\n");
            return 1;
        }
        let pctx = PkeyCtx::from_pkey(lc.as_deref(), Some(&params_key), pq.as_deref());
        if !pctx.is_some_and(|c| c.param_check() > 0) {
            eprintf!("failed\n");
            return 1;
        }
        eprintf!("ok\n");
    }
    if outformat == format::ASN1 && genkey {
        noout = true;
    }
    let output_type = if outformat == format::ASN1 {
        "DER"
    } else {
        "PEM"
    };
    if !noout {
        let ectx = Encoder::new_for_pkey(
            &params_key,
            OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
            Some(output_type),
            None,
        );
        if ectx.to_bio(&out) == 0 {
            eprintf!("unable to write elliptic curve parameters\n");
            return 1;
        }
    }
    if genkey {
        let gctx = PkeyCtx::from_pkey(lc.as_deref(), Some(&params_key), pq.as_deref());
        let key = gctx.as_ref().and_then(|g| {
            if g.keygen_init() <= 0 {
                return None;
            }
            match g.keygen() {
                (r, k) if r > 0 => k,
                _ => None,
            }
        });
        let Some(key) = key else {
            eprintf!("unable to generate key\n");
            return 1;
        };
        let ectx = Encoder::new_for_pkey(&key, OSSL_KEYMGMT_SELECT_ALL, Some(output_type), None);
        if ectx.to_bio(&out) == 0 {
            eprintf!("unable to write elliptic curve parameters\n");
            return 1;
        }
    }
    0
}
