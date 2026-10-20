//! `openssl version` (`apps/version.c`).

use std::io::Write;

use rustyssl_ossl::abi::{
    OPENSSL_BUILT_ON, OPENSSL_CFLAGS, OPENSSL_CPU_INFO, OPENSSL_DIR, OPENSSL_ENGINES_DIR,
    OPENSSL_INFO_SEED_SOURCE, OPENSSL_MODULES_DIR, OPENSSL_PLATFORM, OPENSSL_VERSION,
    OPENSSL_VERSION_TEXT,
};
use rustyssl_ossl::crypto;

use crate::generated::options::version::{OPTIONS, Opt};
use crate::lib::io;
use crate::lib::opt::{self, Parser, eprintf};

pub fn main(argv: &[String]) -> i32 {
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let (mut dirty, mut seed, mut cflags, mut version, mut date) =
        (false, false, false, false, false);
    let (mut options, mut platform, mut dir, mut engdir, mut moddir) =
        (false, false, false, false, false);
    let mut cpuinfo = false;
    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::ERR => {
                eprintf!("{prog}: Use -help for summary.\n");
                return 1;
            }
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::B => (dirty, date) = (true, true),
            Opt::D => (dirty, dir) = (true, true),
            Opt::E => (dirty, engdir) = (true, true),
            Opt::M => (dirty, moddir) = (true, true),
            Opt::F => (dirty, cflags) = (true, true),
            Opt::O => (dirty, options) = (true, true),
            Opt::P => (dirty, platform) = (true, true),
            Opt::R => (dirty, seed) = (true, true),
            Opt::V => (dirty, version) = (true, true),
            Opt::C => (dirty, cpuinfo) = (true, true),
            Opt::A => {
                (seed, options, cflags, version, date) = (true, true, true, true, true);
                (platform, dir, engdir, moddir, cpuinfo) = (true, true, true, true, true);
            }
        }
    }
    if !p.check_rest_arg(None) {
        eprintf!("{prog}: Use -help for summary.\n");
        return 1;
    }
    if !dirty {
        version = true;
    }
    let mut out = String::new();
    if version {
        out.push_str(&format!(
            "{} (Library: {})\n",
            OPENSSL_VERSION_TEXT.to_string_lossy(),
            crypto::version(OPENSSL_VERSION)
        ));
    }
    let line = |out: &mut String, t| out.push_str(&format!("{}\n", crypto::version(t)));
    if date {
        line(&mut out, OPENSSL_BUILT_ON);
    }
    if platform {
        line(&mut out, OPENSSL_PLATFORM);
    }
    if options {
        out.push_str(&format!("options:  {}\n", crypto::bn_options()));
    }
    if cflags {
        line(&mut out, OPENSSL_CFLAGS);
    }
    if dir {
        line(&mut out, OPENSSL_DIR);
    }
    if engdir {
        line(&mut out, OPENSSL_ENGINES_DIR);
    }
    if moddir {
        line(&mut out, OPENSSL_MODULES_DIR);
    }
    if seed {
        let src = crypto::info(OPENSSL_INFO_SEED_SOURCE);
        out.push_str(&format!(
            "Seeding source: {}\n",
            src.as_deref().unwrap_or("N/A")
        ));
    }
    if cpuinfo {
        line(&mut out, OPENSSL_CPU_INFO);
    }
    let _ = io::out().write_all(out.as_bytes());
    0
}
