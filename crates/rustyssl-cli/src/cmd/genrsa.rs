//! `openssl genrsa` (`apps/genrsa.c`).

use rustyssl_ossl::abi::{OPENSSL_RSA_MAX_MODULUS_BITS, RSA_3, RSA_F4};
use rustyssl_ossl::bn::Bn;

use super::pkey::opt_cipher;
use crate::generated::options::genrsa::{OPTIONS, Opt};
use crate::lib::apps::{app_passwd, bio_open_owner};
use crate::lib::keygen;
use crate::lib::opt::{self, Parser, eprintf, format};
use crate::lib::{app_libctx, app_rand, engine, io};

/// `DEFBITS` and `DEFPRIMES`.
const DEFBITS: i32 = 2048;
const DEFPRIMES: i32 = 2;

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
    let mut eng = None;
    let (mut num, mut primes, mut f4) = (DEFBITS, DEFPRIMES, RSA_F4);
    let (mut outfile, mut passoutarg, mut ciphername) = (None, None, None);
    let (mut verbose, mut traditional) = (false, false);
    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::ERR => return usage(),
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::_3 => f4 = RSA_3,
            Opt::F4 => f4 = RSA_F4,
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::ENGINE => eng = engine::setup_engine(Some(p.arg()), false),
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
            Opt::PASSOUT => passoutarg = Some(p.arg().to_owned()),
            Opt::CIPHER => ciphername = p.unknown().map(str::to_owned),
            Opt::PRIMES => primes = p.int_arg(),
            Opt::VERBOSE => verbose = true,
            Opt::QUIET => verbose = false,
            Opt::TRADITIONAL => traditional = true,
        }
    }
    if let [arg] = p.rest() {
        match opt::int(arg) {
            Some(n) if n > 0 => num = n,
            _ => return 1,
        }
        if num > OPENSSL_RSA_MAX_MODULUS_BITS {
            eprintf!(
                "Warning: It is not recommended to use more than {OPENSSL_RSA_MAX_MODULUS_BITS} bit for RSA keys.\n         Your key size is {num}! Larger key size may behave not as expected.\n"
            );
        }
    } else if !p.check_rest_arg(None) {
        return usage();
    }
    if !app_rand::load() {
        return 1;
    }
    let Ok(enc) = opt_cipher(ciphername.as_deref()) else {
        return 1;
    };
    let Some((_, passout)) = app_passwd(None, passoutarg.as_deref()) else {
        eprintf!("Error getting password\n");
        return 1;
    };
    let Some(out) = bio_open_owner(outfile.as_deref(), format::PEM, true) else {
        return 1;
    };
    let mut ctx = None;
    if !keygen::init_gen_str(
        &mut ctx,
        "RSA",
        eng.as_ref(),
        false,
        app_libctx::libctx().as_deref(),
        app_libctx::propq().as_deref(),
    ) {
        return 1;
    }
    let Some(ctx) = ctx else {
        return 1;
    };
    if verbose {
        ctx.set_progress_cb();
    }
    if let Some(b) = io::bio_err() {
        ctx.set_app_bio(b);
    }
    if ctx.set_rsa_keygen_bits(num) <= 0 {
        eprintf!("Error setting RSA length\n");
        return 1;
    }
    let bn = Bn::new();
    let Some(bn) = bn.filter(|b| b.set_word(u64::try_from(f4).unwrap_or(0))) else {
        eprintf!("Error allocating RSA public exponent\n");
        return 1;
    };
    if ctx.set1_rsa_keygen_pubexp(&bn) <= 0 {
        eprintf!("Error setting RSA public exponent\n");
        return 1;
    }
    if ctx.set_rsa_keygen_primes(primes) <= 0 {
        eprintf!("Error setting number of primes\n");
        return 1;
    }
    let Some(pkey) = keygen::app_keygen(&ctx, Some("RSA"), num, verbose) else {
        return 1;
    };
    if verbose {
        let Some(e) = pkey.bn_param(c"e") else {
            eprintf!("Error cannot access RSA e\n");
            return 1;
        };
        if let (Some(hexe), Some(dece)) = (e.to_hex(), e.to_dec()) {
            eprintf!("e is {dece} (0x{hexe})\n");
        }
    }
    let pass = passout.as_ref().map(|p| p.as_str());
    if pkey.write_pem_private(&out, enc.as_ref(), pass, traditional) == 0 {
        return 1;
    }
    0
}
