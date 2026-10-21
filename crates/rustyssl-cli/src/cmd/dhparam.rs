//! `openssl dhparam` (`apps/dhparam.c`).

use rustyssl_ossl::abi::{
    EVP_PKEY_KEY_PARAMETERS, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, OSSL_PKEY_PARAM_FFC_G,
    OSSL_PKEY_PARAM_FFC_P, OSSL_PKEY_PARAM_FFC_Q,
};
use rustyssl_ossl::encoder::{Decoder, Encoder};
use rustyssl_ossl::params::ParamBld;
use rustyssl_ossl::pkey::{Pkey, PkeyCtx};

use super::genpkey::app_paramgen;
use crate::generated::options::dhparam::{OPTIONS, Opt};
use crate::lib::apps::bio_open_default;
use crate::lib::opt::{self, Parser, eprintf, fmt_flags, format};
use crate::lib::{app_libctx, app_rand, engine, io};

/// `DEFBITS`.
const DEFBITS: i32 = 2048;

/// `dsa_to_dh`: DSA parameters as DHX ones.
fn dsa_to_dh(dh: &Pkey) -> Option<Pkey> {
    let fail = || {
        eprintf!("Error, failed to set DH parameters\n");
        None
    };
    let (Some(p), Some(q), Some(g)) = (
        dh.bn_param(OSSL_PKEY_PARAM_FFC_P),
        dh.bn_param(OSSL_PKEY_PARAM_FFC_Q),
        dh.bn_param(OSSL_PKEY_PARAM_FFC_G),
    ) else {
        return fail();
    };
    let Some(tmpl) = ParamBld::new() else {
        return fail();
    };
    if !tmpl.push_bn(OSSL_PKEY_PARAM_FFC_P, &p)
        || !tmpl.push_bn(OSSL_PKEY_PARAM_FFC_Q, &q)
        || !tmpl.push_bn(OSSL_PKEY_PARAM_FFC_G, &g)
    {
        return fail();
    }
    let Some(mut params) = tmpl.to_param() else {
        return fail();
    };
    let lc = app_libctx::libctx();
    let pq = app_libctx::propq();
    let ctx = PkeyCtx::from_name(lc.as_deref(), "DHX", pq.as_deref());
    let pkey = ctx.as_ref().and_then(|c| {
        if c.fromdata_init() <= 0 {
            return None;
        }
        match c.fromdata_built(EVP_PKEY_KEY_PARAMETERS, &mut params) {
            (r, k) if r > 0 => k,
            _ => None,
        }
    });
    if pkey.is_none() {
        return fail();
    }
    pkey
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
    let (mut infile, mut outfile) = (None, None);
    let (mut informat, mut outformat) = (format::PEM, format::PEM);
    let (mut dsaparam, mut text, mut check, mut noout) = (false, false, false, false);
    let mut verbose = true;
    let (mut num, mut g) = (0, 0);
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
            Opt::OUTFORM => match opt::parse_format(p.arg(), fmt_flags::PEMDER) {
                Some(f) => outformat = f,
                None => return usage(),
            },
            Opt::IN => infile = Some(p.arg().to_owned()),
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::ENGINE => _e = engine::setup_engine(Some(p.arg()), false),
            Opt::CHECK => check = true,
            Opt::TEXT => text = true,
            Opt::DSAPARAM => dsaparam = true,
            Opt::_2 => g = 2,
            Opt::_3 => g = 3,
            Opt::_5 => g = 5,
            Opt::NOOUT => noout = true,
            Opt::VERBOSE => verbose = true,
            Opt::QUIET => verbose = false,
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
    if let [arg] = p.rest() {
        match opt::int(arg) {
            Some(n) if n > 0 => num = n,
            _ => return usage(),
        }
    } else if !p.check_rest_arg(None) {
        return usage();
    }
    if !app_rand::load() {
        return 1;
    }
    if g != 0 && num == 0 {
        num = DEFBITS;
    }
    if dsaparam && g != 0 {
        eprintf!("Error, generator may not be chosen for DSA parameters\n");
        return 1;
    }
    if num != 0 && g == 0 {
        g = 2;
    }
    let lc = app_libctx::libctx();
    let pq = app_libctx::propq();
    let pkey = if num != 0 {
        let alg = if dsaparam { "DSA" } else { "DH" };
        if let Some(f) = &infile {
            eprintf!("Warning, input file {f} ignored\n");
        }
        let Some(ctx) = PkeyCtx::from_name(lc.as_deref(), alg, pq.as_deref()) else {
            eprintf!("Error, {alg} param generation context allocation failed\n");
            return 1;
        };
        if let Some(b) = io::bio_err() {
            ctx.set_app_bio(b);
        }
        if verbose {
            ctx.set_progress_cb();
            eprintf!(
                "Generating {alg} parameters, {num} bit long {}prime\n",
                if dsaparam { "" } else { "safe " }
            );
        }
        if ctx.paramgen_init() <= 0 {
            eprintf!("Error, unable to initialise {alg} parameters\n");
            return 1;
        }
        if dsaparam {
            if ctx.set_dsa_paramgen_bits(num) <= 0 {
                eprintf!("Error, unable to set DSA prime length\n");
                return 1;
            }
        } else {
            if ctx.set_dh_paramgen_prime_len(num) <= 0 {
                eprintf!("Error, unable to set DH prime length\n");
                return 1;
            }
            if ctx.set_dh_paramgen_generator(g) <= 0 {
                eprintf!("Error, unable to set generator\n");
                return 1;
            }
        }
        let Some(tmppkey) = app_paramgen(&ctx, Some(alg)) else {
            return 1;
        };
        drop(ctx);
        if dsaparam {
            let Some(k) = dsa_to_dh(&tmppkey) else {
                return 1;
            };
            k
        } else {
            tmppkey
        }
    } else {
        let Some(input) = bio_open_default(infile.as_deref(), 'r', informat) else {
            return 1;
        };
        let der = informat == format::ASN1;
        let mut keytype = "DH";
        let mut tmppkey;
        loop {
            let mut done = true;
            let mut dctx = Decoder::new_for_pkey(
                Some(if der { "DER" } else { "PEM" }),
                None,
                der.then_some(keytype),
                OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                None,
                None,
            );
            if !dctx.is_null() && dctx.from_bio(&input) == 0 && der && keytype == "DH" {
                keytype = "DHX";
                if input.reset_ret() == 0 {
                    done = false;
                }
            }
            tmppkey = dctx.take();
            drop(dctx);
            if done {
                break;
            }
        }
        let Some(tmppkey) = tmppkey else {
            eprintf!("Error, unable to load parameters\n");
            return 1;
        };
        if dsaparam {
            if !tmppkey.is_a("DSA") {
                eprintf!("Error, unable to load DSA parameters\n");
                return 1;
            }
            let Some(k) = dsa_to_dh(&tmppkey) else {
                return 1;
            };
            k
        } else {
            if !tmppkey.is_a("DH") && !tmppkey.is_a("DHX") {
                eprintf!("Error, unable to load DH parameters\n");
                return 1;
            }
            tmppkey
        }
    };
    let Some(out) = bio_open_default(outfile.as_deref(), 'w', outformat) else {
        return 1;
    };
    if text {
        pkey.print_params(&out, 4);
    }
    if check {
        let Some(ctx) = PkeyCtx::from_pkey(lc.as_deref(), Some(&pkey), pq.as_deref()) else {
            eprintf!("Error, failed to check DH parameters\n");
            return 1;
        };
        if ctx.param_check() <= 0 {
            eprintf!("Error, invalid parameters generated\n");
            return 1;
        }
        eprintf!("DH parameters appear to be ok.\n");
    }
    if !noout {
        let ectx = Encoder::new_for_pkey(
            &pkey,
            OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
            Some(if outformat == format::ASN1 {
                "DER"
            } else {
                "PEM"
            }),
            None,
        );
        if ectx.is_null() || ectx.to_bio(&out) == 0 {
            eprintf!("Error, unable to write DH parameters\n");
            return 1;
        }
    }
    0
}
