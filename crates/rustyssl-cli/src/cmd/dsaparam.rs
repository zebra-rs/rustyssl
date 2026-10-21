//! `openssl dsaparam` (`apps/dsaparam.c`).

use rustyssl_ossl::abi::OPENSSL_DSA_MAX_MODULUS_BITS;
use rustyssl_ossl::pkey::PkeyCtx;

use crate::generated::options::dsaparam::{OPTIONS, Opt};
use crate::lib::apps::{bio_open_owner, load_keyparams};
use crate::lib::keygen;
use crate::lib::opt::{self, Parser, eprintf, fmt_flags, format};
use crate::lib::{app_libctx, app_rand, engine, io};

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
    let (mut informat, mut outformat) = (format::UNDEF, format::PEM);
    let (mut noout, mut text, mut genkey, mut verbose) = (false, false, false, false);
    let (mut num, mut numqbits) = (0, -1);
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
            Opt::ENGINE => _e = engine::setup_engine(Some(p.arg()), false),
            Opt::TEXT => text = true,
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
            Opt::NOOUT => noout = true,
            Opt::VERBOSE => verbose = true,
            Opt::QUIET => verbose = false,
        }
    }
    let rest = p.rest().to_vec();
    match rest.as_slice() {
        [a, b] => {
            match opt::int(a) {
                Some(n) if n >= 0 => num = n,
                _ => return usage(),
            }
            match opt::int(b) {
                Some(n) if n >= 0 => numqbits = n,
                _ => return usage(),
            }
        }
        [a] => match opt::int(a) {
            Some(n) if n >= 0 => num = n,
            _ => return usage(),
        },
        _ => {
            if !p.check_rest_arg(None) {
                return usage();
            }
        }
    }
    if !app_rand::load() {
        return 1;
    }
    let numbits = num;
    let private = genkey;
    let lc = app_libctx::libctx();
    let pq = app_libctx::propq();
    let Some(ctx) = PkeyCtx::from_name(lc.as_deref(), "DSA", pq.as_deref()) else {
        eprintf!("Error, DSA parameter generation context allocation failed\n");
        return 1;
    };
    let params = if numbits > 0 {
        if numbits > OPENSSL_DSA_MAX_MODULUS_BITS {
            eprintf!(
                "Warning: It is not recommended to use more than {OPENSSL_DSA_MAX_MODULUS_BITS} bit for DSA keys.\n         Your key size is {numbits}! Larger key size may behave not as expected.\n"
            );
        }
        if let Some(b) = io::bio_err() {
            ctx.set_app_bio(b);
        }
        if verbose {
            ctx.set_progress_cb();
            eprintf!("Generating DSA parameters, {num} bit long prime\n");
            eprintf!("This could take some time\n");
        }
        if ctx.paramgen_init() <= 0 {
            eprintf!("Error, DSA key generation paramgen init failed\n");
            return 1;
        }
        if ctx.set_dsa_paramgen_bits(num) <= 0 {
            eprintf!("Error, DSA key generation setting bit length failed\n");
            return 1;
        }
        if numqbits > 0 && ctx.set_dsa_paramgen_q_bits(numqbits) <= 0 {
            eprintf!("Error, DSA key generation setting subprime bit length failed\n");
            return 1;
        }
        keygen::app_paramgen(&ctx, Some("DSA"))
    } else {
        load_keyparams(
            infile.as_deref(),
            informat,
            true,
            Some("DSA"),
            Some("DSA parameters"),
        )
    };
    drop(ctx);
    let Some(params) = params else {
        return 1;
    };
    let Some(out) = bio_open_owner(outfile.as_deref(), outformat, private) else {
        return 1;
    };
    if text {
        params.print_params(&out, 0);
    }
    if outformat == format::ASN1 && genkey {
        noout = true;
    }
    if !noout {
        let i = if outformat == format::ASN1 {
            params.write_der_params(&out)
        } else {
            params.write_pem_params(&out)
        };
        if i == 0 {
            eprintf!("Error, unable to write DSA parameters\n");
            return 1;
        }
    }
    if genkey {
        let Some(ctx) = PkeyCtx::from_pkey(lc.as_deref(), Some(&params), pq.as_deref()) else {
            eprintf!("Error, DSA key generation context allocation failed\n");
            return 1;
        };
        if ctx.keygen_init() <= 0 {
            eprintf!("Error, unable to initialise for key generation\n");
            return 1;
        }
        let Some(pkey) = keygen::app_keygen(&ctx, Some("DSA"), numbits, verbose) else {
            return 1;
        };
        if outformat == format::ASN1 {
            pkey.write_der_private(&out);
        } else {
            pkey.write_pem_private(&out, None, None, false);
        }
    }
    0
}
