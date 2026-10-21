//! Key and parameter generation shared by the commands: `genpkey.c`'s `init_gen_str`, and
//! `apps.c`'s `app_keygen` and `app_paramgen`.

use core::ffi::c_int;

use rustyssl_ossl::pkey::{self, Pkey, PkeyCtx};
use rustyssl_ossl::provider::LibCtx;
use rustyssl_ossl::rand;

use crate::lib::engine::Engine;
use crate::lib::io;
use crate::lib::opt::{eprintf, prog};

/// `init_gen_str(pctx, algname, e, do_param, libctx, propq)`: a context for generating
/// `algname` keys (or parameters, with `do_param`) into `pctx`, from an ENGINE's key method if
/// one has it. False (with its message) if `pctx` is already set or the context can't be made.
pub fn init_gen_str(
    pctx: &mut Option<PkeyCtx>,
    algname: &str,
    e: Option<&Engine>,
    do_param: bool,
    libctx: Option<&LibCtx>,
    propq: Option<&str>,
) -> bool {
    if pctx.is_some() {
        eprintf!("Algorithm already set!\n");
        return false;
    }
    let pkey_id = pkey::legacy_pkey_id(algname, e);
    let ctx = if pkey_id != 0 {
        PkeyCtx::new_id(pkey_id, e)
    } else {
        PkeyCtx::from_name(libctx, algname, propq)
    };
    let ok = ctx.as_ref().is_some_and(|c| {
        if do_param {
            c.paramgen_init() > 0
        } else {
            c.keygen_init() > 0
        }
    });
    if !ok {
        eprintf!("Error initializing {algname} context\n");
        io::print_errors();
        return false;
    }
    *pctx = ctx;
    true
}

/// `app_keygen`.
pub fn app_keygen(ctx: &PkeyCtx, alg: Option<&str>, bits: c_int, verbose: bool) -> Option<Pkey> {
    if verbose && let Some(a) = alg {
        eprintf!("Generating {a} key");
        if bits > 0 {
            eprintf!(" with {bits} bits\n");
        } else {
            eprintf!("\n");
        }
    }
    if !rand::status() {
        eprintf!(
            "Warning: generating random key material may take a long time\nif the system has a poor entropy source\n"
        );
    }
    let (r, k) = ctx.keygen();
    if r <= 0 {
        eprintf!(
            "{}: Error generating {} key\n",
            prog(),
            alg.unwrap_or("asymmetric")
        );
    }
    k
}

/// `app_paramgen`.
pub fn app_paramgen(ctx: &PkeyCtx, alg: Option<&str>) -> Option<Pkey> {
    if !rand::status() {
        eprintf!(
            "Warning: generating random key parameters may take a long time\nif the system has a poor entropy source\n"
        );
    }
    let (r, k) = ctx.paramgen();
    if r <= 0 {
        eprintf!(
            "{}: Generating {} key parameters failed\n",
            prog(),
            alg.unwrap_or("asymmetric")
        );
    }
    k
}
