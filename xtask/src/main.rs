//! Developer task runner, invoked as `cargo xtask <command>` (alias in `.cargo/config.toml`).
//!
//! Commands are implemented step by step during Phase 0 of `docs/IMPLEMENTATION_PLAN.md`.
//! Until then they fail with a clear message instead of doing nothing.

#![forbid(unsafe_code)]
// This is a command-line tool: printing to the terminal is its interface.
#![allow(clippy::print_stdout, clippy::print_stderr)]

mod abi_check;
mod codegen;
mod coverage;
mod dist;
mod elf;
mod json;
mod reference;
mod targets;
mod test_apps;
mod test_c;
mod test_differential;
mod test_openssl_suite;
mod test_wycheproof;
mod usage_scan;
mod util;
mod vendor;

use std::process::ExitCode;

/// Every command named in README.md and the plans, with a one-line summary.
#[rustfmt::skip]
const COMMANDS: &[(&str, &str)] = &[
    ("vendor", "fetch and verify a pinned OpenSSL release into abi/openssl-<ver>/"),
    ("codegen", "regenerate ABI bindings, NID/error tables, stubs, and version scripts"),
    ("dist", "build lib{crypto,ssl} with soname and symbol versions into target/dist/"),
    ("ref-openssl", "build the pinned reference OpenSSL into target/ref/"),
    ("abi-check", "check symbols, versions, signatures, and struct layouts against abi/"),
    ("coverage", "report implemented exports per library and header into docs/coverage.md"),
    ("usage-scan", "rank exported functions by how many distro packages import them"),
    ("test-c", "run the C conformance tests against the reference and target/dist"),
    ("test-apps", "run the reference's openssl tool on rustyssl and compare its output"),
    ("test-differential", "compare results against the reference OpenSSL"),
    ("test-openssl-suite", "run the upstream OpenSSL test suite against our libraries"),
    ("test-wycheproof", "run Wycheproof's test vectors on the reference and rustyssl"),
    ("test-consumers", "run consumer test suites (curl, nginx, openssh, ...) on our libraries"),
    ("regen-golden", "regenerate golden files from the reference OpenSSL"),
    ("bench", "benchmark against the reference OpenSSL"),
];

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let command = args.next();
    let rest: Vec<String> = args.collect();
    match command.as_deref() {
        None | Some("help" | "-h" | "--help") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some("abi-check") => report("abi-check", abi_check::run(&rest)),
        Some("codegen") => report("codegen", codegen::run(&rest)),
        Some("coverage") => report("coverage", coverage::run(&rest)),
        Some("dist") => report("dist", dist::run(&rest)),
        Some("ref-openssl") => report("ref-openssl", reference::run(&rest)),
        Some("test-apps") => report("test-apps", test_apps::run(&rest)),
        Some("test-c") => report("test-c", test_c::run(&rest)),
        Some("test-differential") => report("test-differential", test_differential::run(&rest)),
        Some("test-openssl-suite") => report("test-openssl-suite", test_openssl_suite::run(&rest)),
        Some("test-wycheproof") => report("test-wycheproof", test_wycheproof::run(&rest)),
        Some("usage-scan") => report("usage-scan", usage_scan::run(&rest)),
        Some("vendor") => report("vendor", vendor::run(&rest)),
        Some(name) if COMMANDS.iter().any(|(known, _)| *known == name) => {
            eprintln!(
                "xtask: `{name}` is not implemented yet; see Phase 0 in docs/IMPLEMENTATION_PLAN.md"
            );
            ExitCode::FAILURE
        }
        Some(name) => {
            eprintln!("xtask: unknown command `{name}`\n");
            print_help();
            ExitCode::from(2)
        }
    }
}

fn report(command: &str, result: util::Result) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask {command}: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!("Usage: cargo xtask <command> [args]\n\nCommands:");
    for (name, summary) in COMMANDS {
        println!("  {name:<20} {summary}");
    }
}
