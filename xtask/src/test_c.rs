//! `cargo xtask test-c [name...]`: the C conformance tests (TEST_PLAN.md, layer L4).
//!
//! Each `tests/c/<name>.c` prints TAP. It is compiled once against the vendored headers and
//! linked against the reference OpenSSL (`cargo xtask ref-openssl`), then run twice: on the
//! reference libraries, and on rustyssl's (`cargo xtask dist`), by pointing the dynamic loader
//! at each in turn. A test passes when both runs pass every check and print exactly the same
//! output: the reference run validates the test, the rustyssl run the implementation.
//!
//! `tests/c/modules/*.c` are providers and other loadable modules the tests use: each is built
//! into a module of its own (`<name>.so`, or `.dylib` on macOS) in one directory, which the
//! tests find through `RUSTYSSL_TEST_MODULES`. They link against the reference libcrypto, as the
//! tests do, so each run's loader gives them the libraries under test.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::reference;
use crate::util::{Result, fresh_dir, run_output, target_dir, workspace_root};

/// How every C test is compiled. `-Werror` turns a call to an undeclared function into an error.
pub const CFLAGS: &[&str] = &["-std=c99", "-Wall", "-Wextra", "-Werror", "-g"];

/// How long one run of one test may take.
const TIMEOUT: Duration = Duration::from_secs(120);

/// The variable that makes the dynamic loader look in a directory first.
pub const LOADER_PATH: &str = if cfg!(target_os = "macos") {
    "DYLD_LIBRARY_PATH"
} else {
    "LD_LIBRARY_PATH"
};

pub fn run(args: &[String]) -> Result {
    let root = workspace_root();
    let (reference, dist) = prepare(&root)?;
    let tests = select(&root.join("tests/c"), args)?;
    let work = target_dir(&root).join("xtask/test-c");
    fresh_dir(&work)?;
    compile_modules(
        &root.join("tests/c/modules"),
        &work.join("modules"),
        &dist,
        &reference,
    )?;

    let mut failures = Vec::new();
    for (name, source) in &tests {
        let exe = work.join(name);
        compile(source, &exe, &dist, &reference)?;
        let theirs = execute(&exe, &reference.join("lib"), &work)?;
        let ours = execute(&exe, &dist.join("lib"), &work)?;
        match verdict(&theirs, &ours) {
            Ok(checks) => println!("PASS {name}: {checks} checks, identical on both"),
            Err(problem) => {
                println!("FAIL {name}: {problem}");
                failures.push(name.clone());
            }
        }
    }
    if failures.is_empty() {
        println!("{} C conformance tests passed", tests.len());
        Ok(())
    } else {
        Err(format!("failed: {}", failures.join(", ")).into())
    }
}

/// Builds the reference OpenSSL and rustyssl's libraries, returning both install prefixes.
pub fn prepare(root: &Path) -> Result<(PathBuf, PathBuf)> {
    let reference = reference::ensure(root, &reference::vendored_version(root)?)?;
    crate::dist::run(&[])?;
    Ok((reference, target_dir(root).join("dist")))
}

/// The `.c` files in `dir` as (name, path), all of them or only those named in `only`.
pub fn select(dir: &Path, only: &[String]) -> Result<Vec<(String, PathBuf)>> {
    let mut tests = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "c")
            && let Some(name) = path.file_stem().and_then(|n| n.to_str())
            && (only.is_empty() || only.iter().any(|o| o == name))
        {
            tests.push((name.to_owned(), path));
        }
    }
    tests.sort();
    if tests.is_empty() {
        return Err(format!("no tests matched in {}", dir.display()).into());
    }
    Ok(tests)
}

/// The C compiler: `$CC`, or `cc`.
pub fn cc() -> Command {
    Command::new(std::env::var_os("CC").unwrap_or_else(|| "cc".into()))
}

/// Compiles a C program against the vendored headers and links it against the reference.
pub fn compile(source: &Path, exe: &Path, dist: &Path, reference: &Path) -> Result {
    run_output(
        cc().args(CFLAGS)
            .arg("-I")
            .arg(dist.join("include"))
            .arg(source)
            .arg("-L")
            .arg(reference.join("lib"))
            .args(["-lssl", "-lcrypto", "-o"])
            .arg(exe),
    )?;
    Ok(())
}

/// The platform's extension for a loadable module (`DSO_EXTENSION`).
pub const MODULE_EXTENSION: &str = if cfg!(target_os = "macos") {
    "dylib"
} else {
    "so"
};

/// The directory of the built test modules, once built: given to every test run.
static MODULES: OnceLock<PathBuf> = OnceLock::new();

/// Builds each `<dir>/*.c` into the module `<out>/<name>.<ext>`, linked against the reference.
pub fn compile_modules(dir: &Path, out: &Path, dist: &Path, reference: &Path) -> Result {
    if !dir.is_dir() {
        return Ok(());
    }
    fresh_dir(out)?;
    for (name, source) in select(dir, &[])? {
        let module = out.join(format!("{name}.{MODULE_EXTENSION}"));
        let mut cmd = cc();
        cmd.args(CFLAGS);
        if cfg!(target_os = "macos") {
            cmd.arg("-dynamiclib");
        } else {
            cmd.args(["-shared", "-fPIC"]);
        }
        run_output(
            cmd.arg("-I")
                .arg(dist.join("include"))
                .arg(&source)
                .arg("-L")
                .arg(reference.join("lib"))
                .args(["-lcrypto", "-o"])
                .arg(&module),
        )?;
    }
    let _ = MODULES.set(out.to_path_buf());
    Ok(())
}

/// What one run produced.
pub struct Outcome {
    pub status: String,
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// The configuration file test programs are pointed at, on both libraries: one that doesn't
/// exist, so loading it fails the same way on each. (By default each would look in its own
/// build's directory, and the error OpenSSL keeps names the path.)
const MISSING_CONFIG: &str = "/nonexistent/rustyssl-tests/openssl.cnf";

/// Runs `exe` with the dynamic loader pointed at `lib_dir`.
pub fn execute(exe: &Path, lib_dir: &Path, work: &Path) -> Result<Outcome> {
    execute_with_input(exe, lib_dir, work, None)
}

/// Like [`execute`], feeding `input` (a file) to the program's stdin.
pub fn execute_with_input(
    exe: &Path,
    lib_dir: &Path,
    work: &Path,
    input: Option<&Path>,
) -> Result<Outcome> {
    // Files rather than pipes, so a chatty program can't block on a full pipe.
    let stdout_path = work.join("stdout");
    let stderr_path = work.join("stderr");
    let stdin = match input {
        Some(path) => Stdio::from(fs::File::open(path)?),
        None => Stdio::null(),
    };
    let mut command = Command::new(exe);
    if let Some(modules) = MODULES.get() {
        command.env("RUSTYSSL_TEST_MODULES", modules);
    }
    let mut child = command
        .env(LOADER_PATH, lib_dir)
        .env("OPENSSL_CONF", MISSING_CONFIG)
        .stdin(stdin)
        .stdout(fs::File::create(&stdout_path)?)
        .stderr(fs::File::create(&stderr_path)?)
        .spawn()
        .map_err(|e| format!("cannot run {}: {e}", exe.display()))?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > TIMEOUT {
            child.kill()?;
            child.wait()?;
            return Err(format!("{} timed out after {TIMEOUT:?}", exe.display()).into());
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    Ok(Outcome {
        status: status.to_string(),
        success: status.success(),
        stdout: fs::read_to_string(&stdout_path)?,
        stderr: fs::read_to_string(&stderr_path)?,
    })
}

/// Both runs must pass every TAP check and print the same output. Returns the check count.
fn verdict(theirs: &Outcome, ours: &Outcome) -> std::result::Result<usize, String> {
    let checks = tap_checks(&theirs.stdout)
        .map_err(|e| format!("the reference run fails ({}): {e}", theirs.status))?;
    if !theirs.success {
        return Err(format!("the reference run exits with {}", theirs.status));
    }
    if let Err(e) = tap_checks(&ours.stdout) {
        return Err(format!(
            "{e} ({}){}",
            ours.status,
            stderr_tail(&ours.stderr)
        ));
    }
    if !ours.success {
        return Err(format!(
            "exits with {}{}",
            ours.status,
            stderr_tail(&ours.stderr)
        ));
    }
    if ours.stdout != theirs.stdout {
        let first = ours
            .stdout
            .lines()
            .zip(theirs.stdout.lines())
            .position(|(a, b)| a != b);
        let Some(i) = first else {
            return Err("output differs from the reference in length".to_owned());
        };
        // The differing line of each, cut short, so a failure elsewhere (CI) can be read.
        let show = |s: &str| -> String {
            let l = s.lines().nth(i).unwrap_or("");
            l.chars().take(300).collect()
        };
        return Err(format!(
            "output differs from the reference at line {}:\n  reference: {}\n  rustyssl:  {}",
            i + 1,
            show(&theirs.stdout),
            show(&ours.stdout)
        ));
    }
    Ok(checks)
}

/// Checks TAP output: every test line is `ok`, and the plan `1..N` matches. Returns `N`.
fn tap_checks(output: &str) -> std::result::Result<usize, String> {
    let mut passed = 0;
    let mut failed = Vec::new();
    let mut planned = None;
    for line in output.lines() {
        if line.starts_with("ok ") {
            passed += 1;
        } else if line.starts_with("not ok ") {
            failed.push(line.to_owned());
        } else if let Some(count) = line.strip_prefix("1..") {
            planned = count.trim().parse::<usize>().ok();
        }
    }
    if let Some(first) = failed.first() {
        return Err(format!("{} failing check(s), first: {first}", failed.len()));
    }
    match planned {
        Some(count) if count == passed => Ok(count),
        Some(count) => Err(format!("planned {count} checks, {passed} passed")),
        None => Err("no TAP plan line (did it crash?)".to_owned()),
    }
}

fn stderr_tail(stderr: &str) -> String {
    let lines: Vec<&str> = stderr.lines().rev().take(3).collect();
    if lines.is_empty() {
        String::new()
    } else {
        let tail: Vec<&str> = lines.into_iter().rev().collect();
        format!("; stderr: {}", tail.join(" | "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(stdout: &str, success: bool) -> Outcome {
        Outcome {
            status: if success {
                "exit status: 0"
            } else {
                "signal: 6"
            }
            .to_owned(),
            success,
            stdout: stdout.to_owned(),
            stderr: if success {
                ""
            } else {
                "rustyssl: X is not implemented yet; aborting"
            }
            .to_owned(),
        }
    }

    #[test]
    fn tap_plans_and_failures() {
        assert_eq!(tap_checks("ok 1 - a\nok 2 - b\n1..2\n"), Ok(2));
        assert!(tap_checks("ok 1 - a\nnot ok 2 - b\n1..2\n").is_err());
        assert!(tap_checks("ok 1 - a\n1..2\n").is_err());
        assert!(tap_checks("ok 1 - a\n").is_err());
    }

    #[test]
    fn verdicts() {
        let good = "ok 1 - a\n1..1\n";
        assert_eq!(verdict(&outcome(good, true), &outcome(good, true)), Ok(1));
        let other = "ok 1 - different text\n1..1\n";
        assert!(verdict(&outcome(good, true), &outcome(other, true)).is_err());
        let aborted = verdict(&outcome(good, true), &outcome("", false)).unwrap_err();
        assert!(aborted.contains("not implemented"), "{aborted}");
        assert!(
            verdict(
                &outcome("not ok 1 - a\n1..1\n", false),
                &outcome(good, true)
            )
            .is_err()
        );
    }
}
