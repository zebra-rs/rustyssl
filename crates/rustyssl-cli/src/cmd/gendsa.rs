//! `openssl gendsa` (`apps/gendsa.c`).

use rustyssl_ossl::abi::OPENSSL_DSA_MAX_MODULUS_BITS;
use rustyssl_ossl::pkey::{self, PkeyCtx};

use super::pkey::opt_cipher;
use crate::generated::options::gendsa::{OPTIONS, Opt};
use crate::lib::apps::{app_passwd, bio_open_owner, load_keyparams};
use crate::lib::keygen;
use crate::lib::opt::{self, Parser, eprintf, format};
use crate::lib::{app_libctx, app_rand, engine, io};

pub fn main(argv: &[String]) -> i32 {
    let mut p = Parser::with_unknown(argv, OPTIONS, Some("cipher"));
    let prog = p.prog();
    let fail = || {
        io::print_errors();
        1
    };
    let usage = || {
        eprintf!("{prog}: Use -help for summary.\n");
        fail()
    };
    let mut _e = None;
    let (mut outfile, mut passoutarg, mut ciphername) = (None, None, None);
    let mut verbose = false;
    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::ERR => return usage(),
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::PASSOUT => passoutarg = Some(p.arg().to_owned()),
            Opt::ENGINE => _e = engine::setup_engine(Some(p.arg()), false),
            Opt::OPT_R(o) => {
                if !app_rand::opt_rand(o, p.arg()) {
                    return fail();
                }
            }
            Opt::OPT_PROV(o) => {
                if !app_libctx::opt_provider(o, p.arg()) {
                    return fail();
                }
            }
            Opt::CIPHER => ciphername = p.unknown().map(str::to_owned),
            Opt::VERBOSE => verbose = true,
            Opt::QUIET => verbose = false,
        }
    }
    if !p.check_rest_arg(Some("params file")) {
        return usage();
    }
    let dsaparams = p.rest().first().cloned();
    if !app_rand::load() {
        return fail();
    }
    let Ok(enc) = opt_cipher(ciphername.as_deref()) else {
        return fail();
    };
    let Some((_, passout)) = app_passwd(None, passoutarg.as_deref()) else {
        eprintf!("Error getting password\n");
        return fail();
    };
    let params = load_keyparams(
        dsaparams.as_deref(),
        format::UNDEF,
        true,
        Some("DSA"),
        Some("DSA parameters"),
    );
    // A failure to open the output skips the error queue (upstream's `end2`).
    let Some(out) = bio_open_owner(outfile.as_deref(), format::PEM, true) else {
        return 1;
    };
    let nbits = pkey::bits_of(params.as_ref());
    if nbits > OPENSSL_DSA_MAX_MODULUS_BITS {
        eprintf!(
            "Warning: It is not recommended to use more than {OPENSSL_DSA_MAX_MODULUS_BITS} bit for DSA keys.\n         Your key size is {}! Larger key size may behave not as expected.\n",
            pkey::bits_of(params.as_ref())
        );
    }
    let lc = app_libctx::libctx();
    let pq = app_libctx::propq();
    let Some(ctx) = PkeyCtx::from_pkey(lc.as_deref(), params.as_ref(), pq.as_deref()) else {
        eprintf!("unable to create PKEY context\n");
        return fail();
    };
    drop(params);
    if ctx.keygen_init() <= 0 {
        eprintf!("unable to set up for key generation\n");
        return fail();
    }
    let Some(pkey) = keygen::app_keygen(&ctx, Some("DSA"), nbits, verbose) else {
        return fail();
    };
    let pass = passout.as_ref().map(|p| p.as_str());
    if pkey.write_pem_private(&out, enc.as_ref(), pass, false) == 0 {
        eprintf!("unable to output generated key\n");
        return fail();
    }
    0
}
