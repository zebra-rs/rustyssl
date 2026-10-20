//! The `openssl` command-line tool in Rust (ADR 0007): the same commands, options, help and
//! error texts, exit codes, and output as upstream's, on the public C API (`rustyssl-ossl`).
//!
//! This file is `apps/openssl.c`: start-up, the command table and its dispatch (a command by
//! its name, a digest or cipher name as `dgst` or `enc`, `no-<command>`), `help`, and the end.

#![forbid(unsafe_code)]
// `mod lib` is `src/lib/`, as ADR 0007 names it: the shared code of upstream's `apps/lib`.
#![allow(special_module_name)]

mod cmd;
mod generated;
mod lib;

use std::io::Write;

use rustyssl_ossl::abi::{OPENSSL_INIT_ENGINE_ALL_BUILTIN, OPENSSL_INIT_LOAD_CONFIG};
use rustyssl_ossl::{crypto, evp};

use generated::options::{FUNCTIONS, FuncType, Function};
use lib::opt::{self, Parser, eprintf};
use lib::{app_libctx, app_rand, io};

/// `DEPRECATED_NO_ALTERNATIVE`.
const DEPRECATED_NO_ALTERNATIVE: &str = "unknown";

fn main() {
    // Fail closed: without both libraries, nothing runs.
    rustyssl_ossl::load::init();
    let argv: Vec<String> = std::env::args_os()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let code = run(argv);
    exit(code);
}

#[allow(clippy::exit)] // The program's exit status.
fn exit(code: i32) -> ! {
    let _ = std::io::stderr().flush();
    std::process::exit(code)
}

/// `main` of `openssl.c`, up to its exit status.
fn run(mut argv: Vec<String>) -> i32 {
    if !io::init() {
        let _ = writeln!(
            std::io::stderr(),
            "FATAL: cannot set up the standard streams"
        );
        return 1;
    }
    let mut ret = startup_and_dispatch(&mut argv);
    if !app_rand::write() {
        ret = 1;
    }
    app_libctx::cleanup();
    crypto::secure_malloc_done();
    ret
}

fn startup_and_dispatch(argv: &mut Vec<String>) -> i32 {
    if let Some(sec_mem) = std::env::var_os("OPENSSL_SEC_MEM") {
        let sec_mem = sec_mem.to_string_lossy().into_owned();
        let Some(size) = opt::strtol(&sec_mem) else {
            eprintf!("FATAL: could not convert OPENSSL_SEC_MEM ({sec_mem}) to number\n");
            return 1;
        };
        let mut minsize = 0;
        if let Some(m) = std::env::var_os("OPENSSL_SEC_MEM_MINSIZE") {
            let m = m.to_string_lossy().into_owned();
            let Some(v) = opt::strtol(&m) else {
                eprintf!("FATAL: could not convert OPENSSL_SEC_MEM_MINSIZE ({m}) to number\n");
                return 1;
            };
            minsize = v;
        }
        // C converts the longs to size_t, wrapping.
        let as_size = |v: i64| usize::try_from(u64::from_ne_bytes(v.to_ne_bytes())).unwrap_or(0);
        if crypto::secure_malloc_init(as_size(size), as_size(minsize)) != 1 {
            eprintf!("FATAL: could not initialize secure memory\n");
            io::print_errors();
            return 1;
        }
    }

    let argv0 = argv.first().cloned().unwrap_or_default();
    if !apps_startup() {
        eprintf!("FATAL: Startup failure (dev note: apps_startup()) for {argv0}\n");
        io::print_errors();
        return 1;
    }
    let pname = opt::progname(&argv0);
    if crypto::default_config_file().is_none() {
        bail_out(&format!("{pname}: could not get default config file\n"));
    }

    // Called by a command's name (a link), or as `openssl <command> ...`.
    if find_function(&pname).is_some() {
        if let Some(a) = argv.first_mut() {
            *a = pname;
        }
        return do_cmd(argv);
    }
    let first = argv.get(1).map(String::as_str);
    let global_help = matches!(first, Some("-help" | "--help" | "-h" | "--h"));
    let global_version = matches!(first, Some("-version" | "--version" | "-v" | "--v"));
    argv.remove(0);
    let name = if argv.len() == 1 || global_help {
        Some("help")
    } else if global_version {
        Some("version")
    } else {
        argv.first().map(String::as_str)
    };
    if let Some(name) = name {
        opt::appname(name);
    }
    if argv.is_empty() || global_help {
        do_cmd(&["help".to_owned()])
    } else if global_version {
        do_cmd(&["version".to_owned()])
    } else {
        do_cmd(argv)
    }
}

/// `apps_startup`.
fn apps_startup() -> bool {
    if !crypto::init_ssl(
        u64::try_from(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG).unwrap_or(0),
    ) {
        return false;
    }
    // An undocumented testing feature of upstream's: a global library context.
    if std::env::var("OPENSSL_TEST_LIBCTX").is_ok_and(|v| v == "1")
        && app_libctx::create_libctx().is_none()
    {
        return false;
    }
    true
}

/// `app_bail_out`.
fn bail_out(message: &str) -> ! {
    eprintf!("{message}");
    io::print_errors();
    exit(1)
}

/// The table's entry named `name` (`lh_FUNCTION_retrieve`).
fn find_function(name: &str) -> Option<&'static Function> {
    FUNCTIONS.iter().find(|f| f.name == name)
}

/// `warn_deprecated`.
fn warn_deprecated(f: &Function) {
    let mut text = match f.deprecated_version {
        Some(v) => format!("The command {} was deprecated in version {v}.", f.name),
        None => format!("The command {} is deprecated.", f.name),
    };
    if let Some(alt) = f.deprecated_alternative
        && alt != DEPRECATED_NO_ALTERNATIVE
    {
        text.push_str(&format!(" Use '{alt}' instead."));
    }
    eprintf!("{text}\n");
}

/// `do_cmd`: runs `argv[0]`.
fn do_cmd(argv: &[String]) -> i32 {
    let Some(name) = argv.first() else {
        return 0;
    };
    let entry = find_function(name);
    let (kind, implementation) = match entry {
        Some(f) => (f.kind, f.name),
        None if evp::digest_exists(name) => (FuncType::Md, "dgst"),
        None if evp::cipher_exists(name) => (FuncType::Cipher, "enc"),
        None => {
            if let Some(rest) = name.strip_prefix("no-") {
                // "Is foo unsupported?", asked by running no-foo.
                let mut out = io::out();
                if find_function(rest).is_none() {
                    let _ = writeln!(out, "{name}");
                    return 0;
                }
                let _ = writeln!(out, "{rest}");
                return 1;
            }
            eprintf!("Invalid command '{name}'; type \"help\" for a list.\n");
            return 1;
        }
    };
    let implementation = match kind {
        FuncType::Md => "dgst",
        FuncType::Cipher => "enc",
        _ => implementation,
    };
    if let Some(f) = entry
        && f.deprecated_alternative.is_some()
    {
        warn_deprecated(f);
    }
    match cmd::find(implementation) {
        Some(main) => main(argv),
        None => unported(implementation, argv),
    }
}

/// A command not ported yet fails closed (ADR 0007, section 3): its `-help` works (it is
/// generated), and anything else prints that it isn't implemented and exits 1.
fn unported(implementation: &str, argv: &[String]) -> i32 {
    if generated::options::help_only(implementation, argv) == Some(true) {
        return 0;
    }
    let name = argv.first().map_or(implementation, String::as_str);
    eprintf!("openssl: {name} is not implemented in rustyssl's CLI yet\n");
    1
}

/// `calculate_columns` of `columns.c`: (columns, width).
fn calculate_columns() -> (usize, usize) {
    let maxlen = FUNCTIONS
        .iter()
        .filter(|f| matches!(f.kind, FuncType::General | FuncType::Md | FuncType::Cipher))
        .map(|f| f.name.len())
        .max()
        .unwrap_or(0);
    let width = maxlen + 2;
    ((80 - 1) / width, width)
}

/// The command table as `prog_init` sorts it: by type, then by name.
fn sorted_functions() -> Vec<&'static Function> {
    let mut f: Vec<&Function> = FUNCTIONS.iter().collect();
    f.sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.name.cmp(b.name)));
    f
}

/// `help_main`: `openssl help [command]`.
pub fn help_main(argv: &[String]) -> i32 {
    use generated::options::help::{OPTIONS, Opt};
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    match p.next() {
        Opt::hEOF => {}
        Opt::hERR => {
            eprintf!("{prog}: Use -help for summary.\n");
            return 1;
        }
        Opt::hHELP => {
            opt::help(OPTIONS);
            return 0;
        }
    }
    if let [command] = p.rest() {
        return do_cmd(&[command.clone(), "--help".to_owned()]);
    }
    if !p.check_rest_arg(None) {
        eprintf!("Usage: {prog}\n");
        return 1;
    }
    let (columns, width) = calculate_columns();
    let mut text = format!("{prog}:\n\nStandard commands");
    let mut i = 0usize;
    let mut tp = FuncType::None;
    for f in sorted_functions() {
        let mut nl = false;
        if i.is_multiple_of(columns) {
            text.push('\n');
            nl = true;
        }
        i += 1;
        if f.kind != tp {
            tp = f.kind;
            if !nl {
                text.push('\n');
            }
            if tp == FuncType::Md {
                i = 1;
                text.push_str(
                    "\nMessage Digest commands (see the `dgst' command for more details)\n",
                );
            } else if tp == FuncType::Cipher {
                i = 1;
                text.push_str("\nCipher commands (see the `enc' command for more details)\n");
            }
        }
        text.push_str(&format!("{:<width$}", f.name));
    }
    text.push_str("\n\n");
    eprintf!("{text}");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns_fit_eighty() {
        let (columns, width) = calculate_columns();
        assert!(columns * width < 80);
        assert!(columns > 0);
    }

    #[test]
    fn the_table_is_upstreams() {
        assert!(find_function("x509").is_some());
        assert!(find_function("sha256").is_some_and(|f| f.kind == FuncType::Md));
        assert!(find_function("aes-128-cbc").is_some_and(|f| f.kind == FuncType::Cipher));
        let rsautl = find_function("rsautl").unwrap();
        assert_eq!(rsautl.deprecated_alternative, Some("pkeyutl"));
        assert_eq!(rsautl.deprecated_version, Some("3.0"));
        // The default build has no MD2, RC5, or zlib.
        assert!(find_function("md2").is_none());
        assert!(find_function("rc5").is_none());
        assert!(find_function("zlib").is_none());
    }

    /// Golden tests: each command's `-help`, from the generated table, is upstream's text
    /// byte for byte (`tests/help/<command>.txt`, written by `cargo xtask test-apps --bless
    /// help` from the reference build).
    #[test]
    fn help_is_upstreams() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/help");
        let mut checked = 0;
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let command = path.file_stem().unwrap().to_str().unwrap().to_owned();
            let golden = std::fs::read(&path).unwrap();
            let argv = [command.clone(), "-help".to_owned()];
            let ((), text) = io::capture_err(|| {
                if command == "help" {
                    assert_eq!(help_main(&argv), 0);
                } else {
                    let f = find_function(&command).unwrap();
                    if f.deprecated_alternative.is_some() {
                        warn_deprecated(f);
                    }
                    let module = match f.kind {
                        FuncType::Md => "dgst",
                        FuncType::Cipher => "enc",
                        _ => f.options.unwrap(),
                    };
                    assert_eq!(generated::options::help_only(module, &argv), Some(true));
                }
            });
            assert!(
                text == golden,
                "{command}: the -help text differs from {}",
                path.display()
            );
            checked += 1;
        }
        // Every command but `ts` and `verify`, which print more than their tables, and some
        // digest and cipher commands.
        assert!(checked >= 53);
    }

    #[test]
    fn every_table_has_help() {
        for f in FUNCTIONS.iter().filter(|f| f.kind == FuncType::General) {
            let module = f.options.unwrap();
            let argv = [f.name.to_owned(), "-help".to_owned()];
            let (shown, text) = io::capture_err(|| generated::options::help_only(module, &argv));
            assert_eq!(shown, Some(true), "{}", f.name);
            assert!(!text.is_empty());
        }
    }
}
