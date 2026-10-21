//! `openssl pkeyparam` (`apps/pkeyparam.c`).

use rustyssl_ossl::pkey::{Pkey, PkeyCtx};

use crate::generated::options::pkeyparam::{OPTIONS, Opt};
use crate::lib::apps::bio_open_default;
use crate::lib::opt::{self, Parser, eprintf, format};
use crate::lib::{app_libctx, engine, io};

pub fn main(argv: &[String]) -> i32 {
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let usage = || {
        eprintf!("{prog}: Use -help for summary.\n");
        1
    };
    let mut e = None;
    let (mut infile, mut outfile) = (None, None);
    let (mut text, mut noout, mut check) = (false, false, false);
    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::ERR => return usage(),
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::IN => infile = Some(p.arg().to_owned()),
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::ENGINE => e = engine::setup_engine(Some(p.arg()), false),
            Opt::TEXT => text = true,
            Opt::NOOUT => noout = true,
            Opt::CHECK => check = true,
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
    let Some(input) = bio_open_default(infile.as_deref(), 'r', format::PEM) else {
        return 1;
    };
    let lc = app_libctx::libctx();
    let pq = app_libctx::propq();
    let Some(pkey) = Pkey::read_pem_params(&input, lc.as_deref(), pq.as_deref()) else {
        eprintf!("Error reading parameters\n");
        io::print_errors();
        return 1;
    };
    let Some(out) = bio_open_default(outfile.as_deref(), 'w', format::PEM) else {
        return 1;
    };
    if check {
        let ctx = match &e {
            None => PkeyCtx::from_pkey(lc.as_deref(), Some(&pkey), pq.as_deref()),
            Some(_) => PkeyCtx::new(&pkey, e.as_ref()),
        };
        let Some(ctx) = ctx else {
            io::print_errors();
            return 1;
        };
        if ctx.param_check() == 1 {
            let _ = out.write_all(b"Parameters are valid\n");
        } else {
            eprintf!("Parameters are invalid\n");
            io::print_errors();
            return 1;
        }
    }
    if !noout {
        pkey.write_pem_params(&out);
    }
    if text {
        pkey.print_params(&out, 0);
    }
    0
}
