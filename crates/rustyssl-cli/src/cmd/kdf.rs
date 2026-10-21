//! `openssl kdf` (`apps/kdf.c`).

use rustyssl_ossl::crypto;
use rustyssl_ossl::evp::{Kdf, KdfCtx};

use crate::generated::options::kdf::{OPTIONS, Opt};
use crate::lib::app_params::app_params_new_from_opts;
use crate::lib::apps::{atoi, bio_open_default};
use crate::lib::opt::{self, Parser, eprintf, format};
use crate::lib::{app_libctx, io};

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
    let mut out_bin = false;
    let mut dkm_len = 0;
    let mut outfile: Option<String> = None;
    let mut opts: Option<Vec<String>> = None;
    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::ERR => return usage(),
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::BIN => out_bin = true,
            Opt::KEYLEN => dkm_len = atoi(p.arg()),
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::KDFOPT => opts.get_or_insert_with(Vec::new).push(p.arg().to_owned()),
            Opt::CIPHER => opts
                .get_or_insert_with(Vec::new)
                .push(format!("cipher:{}", p.arg())),
            Opt::DIGEST => opts
                .get_or_insert_with(Vec::new)
                .push(format!("digest:{}", p.arg())),
            Opt::MAC => opts
                .get_or_insert_with(Vec::new)
                .push(format!("mac:{}", p.arg())),
            Opt::OPT_PROV(o) => {
                if !app_libctx::opt_provider(o, p.arg()) {
                    return 1;
                }
            }
        }
    }
    // One argument, the KDF's name.
    let [name] = p.rest() else {
        return usage();
    };
    let libctx = app_libctx::libctx();
    let propq = app_libctx::propq();
    let Some(kdf) = Kdf::fetch(libctx.as_deref(), name, propq.as_deref()) else {
        eprintf!("Invalid KDF name {name}\n");
        return usage();
    };
    let Some(ctx) = KdfCtx::new(&kdf) else {
        return 1;
    };
    if let Some(opts) = &opts {
        let Some(params) = app_params_new_from_opts(opts, kdf.settable_ctx_params()) else {
            return 1;
        };
        if !ctx.set_params(&params) {
            eprintf!("KDF parameter error\n");
            io::print_errors();
            return 1;
        }
    }
    let fmt = if out_bin {
        format::BINARY
    } else {
        format::TEXT
    };
    let Some(out) = bio_open_default(outfile.as_deref(), 'w', fmt) else {
        return 1;
    };
    let Some(len) = usize::try_from(dkm_len).ok().filter(|n| *n > 0) else {
        eprintf!("Invalid derived key length.\n");
        return 1;
    };
    let mut dkm = vec![0u8; len];
    if !ctx.derive(&mut dkm) {
        eprintf!("EVP_KDF_derive failed\n");
        return 1;
    }
    if out_bin {
        out.write(&dkm);
    } else {
        let Some(hex) = crypto::buf2hexstr(&dkm) else {
            eprintf!("Memory allocation failure\n");
            return 1;
        };
        let _ = out.write_all(format!("{hex}\n\n").as_bytes());
    }
    dkm.fill(0);
    0
}
