//! `openssl skeyutl` (`apps/skeyutl.c`).
//!
//! Also a private copy of `apps.c`'s [`app_params_new_from_opts`] (fork G2; G1 ports
//! `app_params.c`).

use std::io::Write;

use rustyssl_ossl::params::{Params, ParamsRef};
use rustyssl_ossl::skey::{Skey, SkeyMgmt};

use crate::generated::options::skeyutl::{OPTIONS, Opt};
use crate::lib::opt::{self, Parser, eprintf};
use crate::lib::{app_libctx, io};

/// `app_params_new_from_opts`: `None` without options, or (the message printed) on an
/// option the descriptions don't accept.
pub fn app_params_new_from_opts(opts: Option<&[String]>, defs: ParamsRef<'_>) -> Option<Params> {
    let opts = opts?;
    match Params::from_text(defs, opts) {
        Ok(p) => Some(p),
        Err(e) => {
            eprintf!(
                "Parameter {} '{}'\n",
                if e.found { "error" } else { "unknown" },
                e.opt
            );
            io::print_errors();
            None
        }
    }
}

pub fn main(argv: &[String]) -> i32 {
    let ret = run(argv);
    io::print_errors();
    ret
}

fn run(argv: &[String]) -> i32 {
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let usage = || {
        eprintf!("{prog}: Use -help for summary.\n");
        1
    };
    let mut genkey = false;
    let (mut ciphername, mut skeymgmt): (Option<String>, Option<String>) = (None, None);
    let mut skeyopts: Option<Vec<String>> = None;
    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::ERR => return usage(),
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::GENKEY => genkey = true,
            Opt::CIPHER => ciphername = Some(p.arg().to_owned()),
            Opt::SKEYOPT => skeyopts
                .get_or_insert_with(Vec::new)
                .push(p.arg().to_owned()),
            Opt::SKEYMGMT => skeymgmt = Some(p.arg().to_owned()),
            Opt::OPT_PROV(o) => {
                if !app_libctx::opt_provider(o, p.arg()) {
                    return 1;
                }
            }
        }
    }
    let cipher = match &ciphername {
        Some(n) => match opt::cipher_any(n) {
            Some(c) => Some(c),
            None => return usage(),
        },
        None => None,
    };
    if cipher.is_none() && skeymgmt.is_none() {
        eprintf!("Either -skeymgmt -or -cipher option should be specified\n");
        return 1;
    }
    if !genkey {
        eprintf!("Key generation is the only supported operation as of now\n");
        return 1;
    }
    let name = match (&skeymgmt, &cipher) {
        (Some(m), _) => m.clone(),
        (None, Some(c)) => c.name().unwrap_or_default(),
        (None, None) => String::new(),
    };
    let lc = app_libctx::libctx();
    let pq = app_libctx::propq();
    let Some(mgmt) = SkeyMgmt::fetch(lc.as_deref(), &name, pq.as_deref()) else {
        return 1;
    };
    let params = app_params_new_from_opts(skeyopts.as_deref(), mgmt.gen_settable_params());
    let skey = Skey::generate(lc.as_deref(), &name, pq.as_deref(), params.as_ref());
    drop(params);
    let Some(skey) = skey else {
        eprintf!("Error creating opaque key for skeymgmt {name}\n");
        io::print_errors();
        return 1;
    };
    let text = format!(
        "An opaque key identified by {} is created\nProvider: {}\nKey management: {}\n",
        skey.key_id().as_deref().unwrap_or("<unknown>"),
        skey.provider_name().as_deref().unwrap_or("<NULL>"),
        skey.skeymgmt_name().as_deref().unwrap_or("<NULL>")
    );
    let _ = io::out().write_all(text.as_bytes());
    0
}
