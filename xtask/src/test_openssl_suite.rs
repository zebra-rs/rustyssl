//! `cargo xtask test-openssl-suite`: upstream OpenSSL's own tests on rustyssl (TEST_PLAN.md,
//! layer L6). So far:
//!
//! - `evp_test`, the data-driven test of the EVP algorithms, over the data files listed in
//!   `tests/openssl-suite/evp_test.txt` (milestone M1: "upstream `evp_test` passes for the
//!   implemented algorithms").
//! - `bntest` (on each of its data files, then alone), `ectest`, and `rsa_test` (phase 4's
//!   exit). Upstream links `ectest` and `rsa_test` with the static `libcrypto.a`; they use only
//!   exported functions, so they're built against the shared one here, as `bntest` is.
//!
//! The test programs are built from the reference's verified source, configured as the
//! reference is, into `target/ref-suite/openssl-<version>/`, and reused until their inputs
//! change. They link the reference's shared libraries, so instead of relinking them, each data
//! file runs twice, on the reference libraries and on rustyssl's, by pointing the dynamic loader
//! at each. Both runs must succeed, with the same "Completed N tests with E errors and S skipped"
//! lines and the same number of `ERROR` lines: `evp_test` counts some tests that fail to start
//! (a key generation whose algorithm can't be fetched) as passed, saying so only in one. The
//! other programs must succeed on both with the same numbers of `ok` and `not ok` lines.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::reference;
use crate::targets::host;
use crate::test_c::{LOADER_PATH, prepare};
use crate::util::{Result, fresh_dir, run_logged, target_dir, workspace_root};
use crate::vendor::CONFIGURE_OPTIONS;

/// The test programs built, as `make` targets.
const PROGRAMS: &[&str] = &[
    "test/evp_test",
    "test/bntest",
    "test/ectest",
    "test/rsa_test",
];

/// The programs upstream links with the static `libcrypto.a`, relinked with the shared one (a
/// change to `test/build.info` before configuring).
const DYNAMIC: &[&str] = &["ectest", "rsa_test"];

/// The other programs' runs: each program with the arguments of one run, a data file of
/// `test/recipes/` or none.
const RUNS: &[(&str, &[&str])] = &[
    ("bntest", &["10-test_bn_data/bnexp.txt"]),
    ("bntest", &["10-test_bn_data/bngcd.txt"]),
    ("bntest", &["10-test_bn_data/bnmod.txt"]),
    ("bntest", &["10-test_bn_data/bnmul.txt"]),
    ("bntest", &["10-test_bn_data/bnshift.txt"]),
    ("bntest", &["10-test_bn_data/bnsum.txt"]),
    ("bntest", &[]),
    ("ectest", &[]),
    ("rsa_test", &[]),
];

/// Marks a finished build; holds the inputs it was built from.
const STAMP: &str = ".rustyssl-build";

/// The configuration file both runs are pointed at by `OPENSSL_CONF`, one that doesn't exist;
/// `evp_test` loads its own (`-config`).
const MISSING_CONFIG: &str = "/nonexistent/rustyssl-tests/openssl.cnf";

/// Builds the test programs for reference OpenSSL `version` (whose install prefix is
/// `reference`) unless an up-to-date build exists, and returns the directory holding them.
fn ensure(root: &Path, version: &str, reference: &Path) -> Result<PathBuf> {
    let (_, target) = host()?;
    let suite = target_dir(root)
        .join("ref-suite")
        .join(format!("openssl-{version}"));
    // Configured as `reference::ensure` configures the reference.
    let mut options: Vec<&str> = CONFIGURE_OPTIONS.to_vec();
    options.push("-g");
    let inputs = format!(
        "version = {version}\ntarget = {}\noptions = {}\nprograms = {}\ndynamic = {}\n",
        target.configure,
        options.join(" "),
        PROGRAMS.join(" "),
        DYNAMIC.join(" ")
    );
    if fs::read_to_string(suite.join(STAMP)).is_ok_and(|built| built == inputs) {
        return Ok(suite);
    }

    let work = target_dir(root).join("xtask/ref-suite");
    fresh_dir(&work)?;
    let log = work.join("build.log");
    let src = work.join(format!("openssl-{version}"));
    let mut copy = Command::new("cp");
    copy.arg("-R").arg(reference.join("src")).arg(&src);
    run_logged(&mut copy, &log)?;
    let build_info = src.join("test/build.info");
    let mut rules = fs::read_to_string(&build_info)?;
    for program in DYNAMIC {
        let from = format!("DEPEND[{program}]=../libcrypto.a libtestutil.a");
        if !rules.contains(&from) {
            return Err(format!("test/build.info has no rule {from}").into());
        }
        rules = rules.replace(
            &from,
            &format!("DEPEND[{program}]=../libcrypto libtestutil.a"),
        );
    }
    fs::write(&build_info, rules)?;
    println!(
        "Building upstream OpenSSL {version}'s test programs for {} (log: {})...",
        target.configure,
        log.display()
    );
    // A cleared environment keeps CC, CFLAGS, and the like from changing the build.
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut configure = Command::new("perl");
    configure
        .arg("Configure")
        .arg(target.configure)
        .args(&options)
        .arg(format!("--prefix={}", reference.display()))
        .arg("--libdir=lib")
        .current_dir(&src)
        .env_clear()
        .env("PATH", &path);
    run_logged(&mut configure, &log)?;
    let jobs = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);
    let mut make = Command::new("make");
    make.arg(format!("-j{jobs}"))
        .arg("build_generated")
        .current_dir(&src)
        .env_clear()
        .env("PATH", &path);
    run_logged(&mut make, &log)?;
    let mut make = Command::new("make");
    make.arg(format!("-j{jobs}"))
        .args(PROGRAMS)
        .current_dir(&src)
        .env_clear()
        .env("PATH", &path);
    run_logged(&mut make, &log)?;

    fresh_dir(&suite)?;
    for program in PROGRAMS {
        let name = Path::new(program)
            .file_name()
            .ok_or("a program without a name")?;
        fs::copy(src.join(program), suite.join(name))?;
    }
    fs::write(suite.join(STAMP), inputs)?;
    fs::remove_dir_all(&work)?;
    Ok(suite)
}

/// One run of `evp_test` on `file` with the libraries in `lib`: whether it succeeded, its
/// "Completed ..." lines with the number of `ERROR` lines, and its output.
fn run_evp_test(
    program: &Path,
    config: &Path,
    file: &Path,
    lib: &Path,
) -> Result<(bool, Vec<String>, String)> {
    let out = Command::new(program)
        .arg("-config")
        .arg(config)
        .arg(file)
        .env(LOADER_PATH, lib)
        .env("OPENSSL_CONF", MISSING_CONFIG)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run {}: {e}", program.display()))?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    let mut completed: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("# Completed "))
        .map(str::to_owned)
        .collect();
    let errors = text.lines().filter(|l| l.contains("ERROR")).count();
    completed.push(format!("{errors} ERROR line(s)"));
    Ok((out.status.success(), completed, text))
}

/// One run of a test program with the files as arguments and the libraries in `lib`: whether it
/// succeeded, its numbers of `ok` and `not ok` lines (subtests' included), and its output.
fn run_program(
    program: &Path,
    files: &[PathBuf],
    lib: &Path,
) -> Result<(bool, (usize, usize), String)> {
    let out = Command::new(program)
        .args(files)
        .env(LOADER_PATH, lib)
        .env("OPENSSL_CONF", MISSING_CONFIG)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run {}: {e}", program.display()))?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    let ok = text
        .lines()
        .filter(|l| l.trim_start().starts_with("ok "))
        .count();
    let not_ok = text
        .lines()
        .filter(|l| l.trim_start().starts_with("not ok "))
        .count();
    Ok((out.status.success(), (ok, not_ok), text))
}

/// The first lines of `text` that report a failure, for a short diagnosis.
fn failure_lines(text: &str) -> String {
    text.lines()
        .filter(|l| l.contains("ERROR") || l.contains("not ok") || l.contains("aborting"))
        .take(5)
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn run(args: &[String]) -> Result {
    let root = workspace_root();
    let (reference, dist) = prepare(&root)?;
    let version = reference::vendored_version(&root)?;
    let suite = ensure(&root, &version, &reference)?;
    let evp_test = suite.join("evp_test");
    let src = reference.join("src");
    let config = src.join("test/default.cnf");
    let data = src.join("test/recipes/30-test_evp_data");

    // Guard: a missing library falls back to the one the program was linked with.
    let ours = dist.join("lib");
    if !fs::read_dir(&ours)?
        .any(|e| e.is_ok_and(|e| e.file_name().to_string_lossy().starts_with("libcrypto.")))
    {
        return Err(format!("no libcrypto in {}", ours.display()).into());
    }

    let list = fs::read_to_string(root.join("tests/openssl-suite/evp_test.txt"))?;
    let files: Vec<&str> = list
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| args.is_empty() || args.iter().any(|a| a == l))
        .collect();
    let runs: Vec<&(&str, &[&str])> = RUNS
        .iter()
        .filter(|(p, _)| args.is_empty() || args.iter().any(|a| a == p))
        .collect();
    if files.is_empty() && runs.is_empty() {
        return Err("no data files or programs selected".into());
    }
    let mut failures = Vec::new();
    for name in &files {
        let file = data.join(name);
        let (theirs_ok, theirs, theirs_text) =
            run_evp_test(&evp_test, &config, &file, &reference.join("lib"))?;
        let (ours_ok, ours, ours_text) = run_evp_test(&evp_test, &config, &file, &ours)?;
        let verdict = if !theirs_ok {
            Err(format!(
                "fails on the reference:\n{}",
                failure_lines(&theirs_text)
            ))
        } else if !ours_ok {
            Err(format!("fails on rustyssl:\n{}", failure_lines(&ours_text)))
        } else if theirs != ours {
            Err(format!(
                "counts differ:\n  reference: {}\n  rustyssl:  {}",
                theirs.join("; "),
                ours.join("; ")
            ))
        } else if ours.len() < 2 {
            Err("no tests completed".to_owned())
        } else {
            Ok(ours.join("; "))
        };
        match verdict {
            Ok(counts) => println!("PASS evp_test {name}: {counts}"),
            Err(e) => {
                println!("FAIL evp_test {name}: {e}");
                failures.push(*name);
            }
        }
    }
    let recipes = src.join("test/recipes");
    let mut failed_runs = 0;
    for (program, run_args) in &runs {
        let exe = suite.join(program);
        let files: Vec<PathBuf> = run_args.iter().map(|a| recipes.join(a)).collect();
        let label = format!("{program} {}", run_args.join(" "));
        let (theirs_ok, theirs, theirs_text) = run_program(&exe, &files, &reference.join("lib"))?;
        let (ours_ok, ours, ours_text) = run_program(&exe, &files, &ours)?;
        let verdict = if !theirs_ok {
            Err(format!(
                "fails on the reference:\n{}",
                failure_lines(&theirs_text)
            ))
        } else if !ours_ok {
            Err(format!("fails on rustyssl:\n{}", failure_lines(&ours_text)))
        } else if theirs != ours {
            Err(format!(
                "counts differ: reference {theirs:?}, rustyssl {ours:?}"
            ))
        } else {
            Ok(format!("{} ok, {} not ok", ours.0, ours.1))
        };
        match verdict {
            Ok(counts) => println!("PASS {}: {counts}", label.trim_end()),
            Err(e) => {
                println!("FAIL {}: {e}", label.trim_end());
                failed_runs += 1;
            }
        }
    }
    if failures.is_empty() && failed_runs == 0 {
        println!(
            "{} data files of upstream evp_test and {} runs of its other programs pass on rustyssl as on the reference",
            files.len(),
            runs.len()
        );
        Ok(())
    } else {
        Err(format!(
            "{} data file(s) and {failed_runs} program run(s) failed",
            failures.len()
        )
        .into())
    }
}
