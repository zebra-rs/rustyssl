//! Developer task runner, invoked as `cargo xtask <command>` (alias in `.cargo/config.toml`).
//!
//! Commands are implemented step by step during Phase 0 of `docs/IMPLEMENTATION_PLAN.md`.
//! Until then they fail with a clear message instead of doing nothing.

#![forbid(unsafe_code)]
// This is a command-line tool: printing to the terminal is its interface.
#![allow(clippy::print_stdout, clippy::print_stderr)]

mod util;
mod vendor;

use std::process::ExitCode;

/// Every command named in AGENTS.md and the plans, with a one-line summary.
#[rustfmt::skip]
const COMMANDS: &[(&str, &str)] = &[
    ("vendor", "fetch and verify a pinned OpenSSL release into abi/openssl-<ver>/"),
    ("codegen", "regenerate ABI bindings, NID/error tables, stubs, and version scripts"),
    ("dist", "build lib{crypto,ssl} with soname and symbol versions into target/dist/"),
    ("ref-openssl", "build the pinned reference OpenSSL into target/ref/"),
    ("abi-check", "check symbols, versions, signatures, and struct layouts against abi/"),
    ("coverage", "report implemented / stubbed exports per API family"),
    ("usage-scan", "rank exported functions by how many distro packages import them"),
    ("test-c", "run the C conformance tests against the reference and target/dist"),
    ("test-differential", "compare results against the reference OpenSSL"),
    ("test-openssl-suite", "run the upstream OpenSSL test suite against our libraries"),
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
