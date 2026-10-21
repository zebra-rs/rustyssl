//! `openssl mac` (`apps/mac.c`).

use rustyssl_ossl::evp::{Mac, MacCtx};

use crate::generated::options::mac::{OPTIONS, Opt};
use crate::lib::app_params::app_params_new_from_opts;
use crate::lib::apps::bio_open_default;
use crate::lib::opt::{self, Parser, eprintf, format};
use crate::lib::{app_libctx, io};

/// `BUFSIZE`: the I/O buffer, and the longest MAC printed.
const BUFSIZE: usize = 1024 * 8;

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
    let (mut infile, mut outfile): (Option<String>, Option<String>) = (None, None);
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
            Opt::IN => infile = Some(p.arg().to_owned()),
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::MACOPT => opts.get_or_insert_with(Vec::new).push(p.arg().to_owned()),
            Opt::CIPHER => opts
                .get_or_insert_with(Vec::new)
                .push(format!("cipher:{}", p.arg())),
            Opt::DIGEST => opts
                .get_or_insert_with(Vec::new)
                .push(format!("digest:{}", p.arg())),
            Opt::OPT_PROV(o) => {
                if !app_libctx::opt_provider(o, p.arg()) {
                    return 1;
                }
            }
        }
    }
    // One argument, the MAC's name.
    if !p.check_rest_arg(Some("MAC name")) {
        return usage();
    }
    let name = p.rest().first().cloned().unwrap_or_default();
    let libctx = app_libctx::libctx();
    let propq = app_libctx::propq();
    let Some(mac) = Mac::fetch(libctx.as_deref(), &name, propq.as_deref()) else {
        eprintf!("Invalid MAC name {name}\n");
        return usage();
    };
    let Some(ctx) = MacCtx::new(&mac) else {
        return 1;
    };
    if let Some(opts) = &opts {
        let Some(params) = app_params_new_from_opts(opts, mac.settable_ctx_params()) else {
            return 1;
        };
        if !ctx.set_params(&params) {
            eprintf!("MAC parameter error\n");
            io::print_errors();
            return 1;
        }
    }
    let Some(input) = bio_open_default(infile.as_deref(), 'r', format::BINARY) else {
        return 1;
    };
    let fmt = if out_bin {
        format::BINARY
    } else {
        format::TEXT
    };
    let Some(out) = bio_open_default(outfile.as_deref(), 'w', fmt) else {
        return 1;
    };
    if !ctx.init() {
        eprintf!("EVP_MAC_Init failed\n");
        return 1;
    }
    let mut buf = vec![0u8; BUFSIZE];
    while input.pending() > 0 || !input.eof() {
        let i = input.read(&mut buf);
        let Ok(n) = usize::try_from(i) else {
            eprintf!(
                "Read Error in '{}'\n",
                infile.as_deref().unwrap_or("<NULL>")
            );
            io::print_errors();
            return 1;
        };
        if n == 0 {
            break;
        }
        if !ctx.update(buf.get(..n).unwrap_or_default()) {
            eprintf!("EVP_MAC_update failed\n");
            return 1;
        }
    }
    let Some(len) = ctx.final_len() else {
        eprintf!("EVP_MAC_final failed\n");
        return 1;
    };
    if len > BUFSIZE {
        eprintf!("output len is too large\n");
        return 1;
    }
    let Some(len) = ctx.finish(&mut buf) else {
        eprintf!("EVP_MAC_final failed\n");
        return 1;
    };
    let result = buf.get(..len).unwrap_or_default();
    if out_bin {
        out.write(result);
    } else {
        let mut text: String = result.iter().map(|b| format!("{b:02X}")).collect();
        if outfile.is_none() {
            text.push('\n');
        }
        let _ = out.write_all(text.as_bytes());
    }
    buf.fill(0);
    0
}
