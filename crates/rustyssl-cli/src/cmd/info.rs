//! `openssl info` (`apps/info.c`).

use std::io::Write;

use rustyssl_ossl::abi::{
    OPENSSL_INFO_CONFIG_DIR, OPENSSL_INFO_CPU_SETTINGS, OPENSSL_INFO_DIR_FILENAME_SEPARATOR,
    OPENSSL_INFO_DSO_EXTENSION, OPENSSL_INFO_ENGINES_DIR, OPENSSL_INFO_LIST_SEPARATOR,
    OPENSSL_INFO_MODULES_DIR, OPENSSL_INFO_SEED_SOURCE, OPENSSL_INFO_WINDOWS_CONTEXT,
};
use rustyssl_ossl::crypto;

use crate::generated::options::info::{OPTIONS, Opt};
use crate::lib::io;
use crate::lib::opt::{self, Parser, eprintf};

pub fn main(argv: &[String]) -> i32 {
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let usage = || {
        eprintf!("{prog}: Use -help for summary.\n");
        1
    };
    let (mut dirty, mut kind) = (0, 0);
    loop {
        let t = match p.next() {
            Opt::EOF => break,
            Opt::ERR => return usage(),
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::CONFIGDIR => OPENSSL_INFO_CONFIG_DIR,
            Opt::ENGINESDIR => OPENSSL_INFO_ENGINES_DIR,
            Opt::MODULESDIR => OPENSSL_INFO_MODULES_DIR,
            Opt::DSOEXT => OPENSSL_INFO_DSO_EXTENSION,
            Opt::DIRNAMESEP => OPENSSL_INFO_DIR_FILENAME_SEPARATOR,
            Opt::LISTSEP => OPENSSL_INFO_LIST_SEPARATOR,
            Opt::SEEDS => OPENSSL_INFO_SEED_SOURCE,
            Opt::CPUSETTINGS => OPENSSL_INFO_CPU_SETTINGS,
            Opt::WINDOWSCONTEXT => OPENSSL_INFO_WINDOWS_CONTEXT,
        };
        kind = t;
        dirty += 1;
    }
    if !p.check_rest_arg(None) {
        return usage();
    }
    if dirty > 1 {
        eprintf!("{prog}: Only one item allowed\n");
        return usage();
    }
    if dirty == 0 {
        eprintf!("{prog}: No items chosen\n");
        return usage();
    }
    let data = crypto::info(kind);
    let _ = writeln!(io::out(), "{}", data.as_deref().unwrap_or("Undefined"));
    0
}
