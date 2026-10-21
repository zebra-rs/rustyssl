//! `cargo xtask test-apps [--bless] [corpus...]`: the `openssl` tool on rustyssl, upstream's and
//! ours (milestone M1, and Phase 11's golden tests; ADR 0007, section 4).
//!
//! - **The smoke list, `tests/apps/commands.txt`:** each line runs with upstream's tool (the
//!   reference build's) on the reference libraries and on rustyssl's, by pointing the dynamic
//!   loader at each.
//! - **The per-command corpora, `tests/apps/<command>.txt`:** each line runs three times: (1)
//!   upstream's tool on the reference libraries, the expectation; (2) our tool
//!   (`target/dist/bin/openssl-rs`) on rustyssl's libraries; (3) our tool on the reference
//!   libraries, which tells a CLI bug from a library bug. Lines of the smoke list whose command
//!   is ported (`crates/rustyssl-cli/src/cmd/<command>.rs` exists) also run (2) and (3).
//!
//! Every run must print the same and exit the same as (1), after masking what differs by
//! design: the library's version metadata (`+rustyssl...`), the directories it was built with,
//! and errors' thread id and file and line. A line starting with `~` (timings) must only
//! succeed on every run.
//!
//! In a line, `{bin}` is 100,000 octets of fixed data, `{txt}` a line of text, `{dir}` the work
//! directory, `{src}` the reference's source tree (its `test/certs/`, ...), and `{tests}`
//! `tests/apps/`; a final `< file` gives the command its standard input (otherwise empty).
//! `{fresh:NAME}` is `fresh/NAME` in the work directory, a pristine copy of `tests/apps/NAME`
//! made again before each run, for commands that change the files they're given.
//!
//! Run whole (no list named), it also runs the CLI's library-backed unit tests (`live_*`, the
//! shared helpers) on each library.
//!
//! `crates/rustyssl-cli/tests/help/<command>.txt` holds upstream's `<command> -help` for each
//! `<command> -help` line of `tests/apps/help.txt`, which the CLI's unit tests compare its
//! generated help with; this checks them against the reference and fails when one is stale,
//! and `--bless` rewrites them.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::dist::CLI_NAME;
use crate::test_c::{LOADER_PATH, prepare};
use crate::util::{Result, fresh_dir, target_dir, workspace_root};

/// The configuration file every run is pointed at, one that doesn't exist.
const MISSING_CONFIG: &str = "/nonexistent/rustyssl-tests/openssl.cnf";

/// Where the golden `-help` texts live.
const HELP_GOLDENS: &str = "crates/rustyssl-cli/tests/help";

/// One run's output: stdout, stderr, and the exit status, as one text; and whether it
/// succeeded.
struct Output {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    text: String,
    ok: bool,
}

fn run_tool(
    tool: &Path,
    lib: &Path,
    args: &[String],
    stdin: Option<&Path>,
    work: &Path,
) -> Result<Output> {
    let input = match stdin {
        Some(f) => {
            Stdio::from(fs::File::open(f).map_err(|e| format!("cannot open {}: {e}", f.display()))?)
        }
        None => Stdio::null(),
    };
    let out = Command::new(tool)
        .args(args)
        .current_dir(work)
        .env(LOADER_PATH, lib)
        .env("OPENSSL_MODULES", crate::test_c::modules_of(lib))
        .env("OPENSSL_CONF", MISSING_CONFIG)
        .stdin(input)
        .output()
        .map_err(|e| format!("cannot run {}: {e}", tool.display()))?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    text.push_str(&format!("[{}]\n", out.status));
    Ok(Output {
        stdout: out.stdout,
        stderr: out.stderr,
        text,
        ok: out.status.success(),
    })
}

/// The output with the expected differences masked: the version's build metadata, the
/// directories the libraries were built with, and errors' `file:line:`.
fn masked(text: &str) -> String {
    text.lines()
        .map(|line| {
            let mut l = line.to_owned();
            if let Some(at) = l.find("+rustyssl") {
                let end = l[at..].find(' ').map_or(l.len(), |e| at + e);
                l.replace_range(at..end, "");
            }
            for dir in ["OPENSSLDIR: ", "ENGINESDIR: ", "MODULESDIR: "] {
                if l.starts_with(dir) {
                    l = format!("{dir}DIR");
                }
            }
            if let Some(at) = l.find(":error:") {
                // The thread's id comes first, which differs from run to run on Linux.
                if l[..at].chars().all(|c| c.is_ascii_hexdigit()) {
                    l.replace_range(..at, "THREAD");
                }
                l = mask_location(&l);
            }
            l
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// An error line's `:<file>.c:<line>:` (or `.rs`) as `:FILE:LINE:`.
fn mask_location(line: &str) -> String {
    let parts: Vec<&str> = line.split(':').collect();
    let at = parts.windows(2).position(|w| {
        matches!(w, [file, number] if (file.ends_with(".c") || file.ends_with(".rs"))
            && !number.is_empty()
            && number.chars().all(|c| c.is_ascii_digit()))
    });
    match at {
        Some(i) => {
            let mut out: Vec<&str> = parts.iter().take(i).copied().collect();
            out.push("FILE");
            out.push("LINE");
            out.extend(parts.iter().skip(i + 2));
            out.join(":")
        }
        None => line.to_owned(),
    }
}

/// The first difference between two outputs, after masking.
fn compare(expected: &Output, got: &Output, label: &str) -> std::result::Result<(), String> {
    let (t, o) = (masked(&expected.text), masked(&got.text));
    if t == o {
        return Ok(());
    }
    let at = t
        .lines()
        .zip(o.lines())
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| t.lines().count().min(o.lines().count()));
    let a = t.lines().nth(at).unwrap_or("(end)");
    let b = o.lines().nth(at).unwrap_or("(end)");
    Err(format!(
        "{label}, line {}:\n  expected: {a}\n  got:      {b}",
        at + 1
    ))
}

/// The tools and libraries of a run.
struct Setup {
    upstream: PathBuf,
    ours: PathBuf,
    ref_lib: PathBuf,
    our_lib: PathBuf,
    work: PathBuf,
    /// `tests/apps/`.
    tests: PathBuf,
    subst: Vec<(&'static str, String)>,
}

/// One line of a list: its arguments, its standard input, and whether it is compared.
struct Line {
    text: String,
    compare: bool,
    args: Vec<String>,
    stdin: Option<PathBuf>,
    /// The `{fresh:NAME}` files.
    fresh: Vec<String>,
}

/// Replaces each `{fresh:NAME}` of `arg` with its path, recording the names.
fn fresh_files(arg: &str, work: &Path, names: &mut Vec<String>) -> String {
    let mut out = String::new();
    let mut rest = arg;
    while let Some(at) = rest.find("{fresh:") {
        let Some(end) = rest[at..].find('}') else {
            break;
        };
        let name = &rest[at + 7..at + end];
        out.push_str(&rest[..at]);
        out.push_str(&work.join("fresh").join(name).display().to_string());
        names.push(name.to_owned());
        rest = &rest[at + end + 1..];
    }
    out.push_str(rest);
    out
}

/// Makes the `{fresh:NAME}` copies again (`tests/apps/NAME` when it exists).
fn refresh(setup: &Setup, line: &Line) -> Result {
    if line.fresh.is_empty() {
        return Ok(());
    }
    let dir = setup.work.join("fresh");
    fresh_dir(&dir)?;
    for name in &line.fresh {
        let src = setup.tests.join(name);
        let dst = dir.join(name);
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        if src.is_file() {
            fs::copy(&src, &dst)?;
        }
    }
    Ok(())
}

fn parse_list(text: &str, setup: &Setup) -> Vec<Line> {
    let mut out = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (compare, rest) = match line.strip_prefix('~') {
            Some(rest) => (false, rest),
            None => (true, line),
        };
        let mut fresh = Vec::new();
        let mut args: Vec<String> = rest
            .split_whitespace()
            .map(|a| {
                let mut a = fresh_files(a, &setup.work, &mut fresh);
                for (key, value) in &setup.subst {
                    a = a.replace(key, value);
                }
                a
            })
            .collect();
        let mut stdin = None;
        if args.len() >= 2 && args.get(args.len() - 2).is_some_and(|a| a == "<") {
            stdin = args.pop().map(PathBuf::from);
            args.pop();
        }
        out.push(Line {
            text: rest.to_owned(),
            compare,
            args,
            stdin,
            fresh,
        });
    }
    out
}

/// Whether our tool implements `command` (its module exists).
fn ported(root: &Path, command: &str) -> bool {
    !command.is_empty()
        && command
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && root
            .join("crates/rustyssl-cli/src/cmd")
            .join(format!("{command}.rs"))
            .is_file()
}

/// Runs one line: upstream's tool on the reference (the expectation), then the runs `ours`
/// lists, each as (tool, libraries, label).
fn check(
    setup: &Setup,
    line: &Line,
    runs: &[(&Path, &Path, &str)],
) -> Result<std::result::Result<(), String>> {
    let w = &setup.work;
    refresh(setup, line)?;
    let expected = run_tool(
        &setup.upstream,
        &setup.ref_lib,
        &line.args,
        line.stdin.as_deref(),
        w,
    )?;
    for (tool, lib, label) in runs {
        refresh(setup, line)?;
        let got = run_tool(tool, lib, &line.args, line.stdin.as_deref(), w)?;
        let verdict = if line.compare {
            compare(&expected, &got, label)
        } else if expected.ok && got.ok {
            Ok(())
        } else {
            Err(format!(
                "{label}: exit: expected success {}, got {}\n{}",
                expected.ok,
                got.ok,
                got.text
                    .lines()
                    .rev()
                    .take(3)
                    .collect::<Vec<_>>()
                    .join("\n")
            ))
        };
        if verdict.is_err() {
            return Ok(verdict);
        }
    }
    Ok(Ok(()))
}

pub fn run(args: &[String]) -> Result {
    let bless = args.iter().any(|a| a == "--bless");
    let only: Vec<&String> = args.iter().filter(|a| *a != "--bless").collect();
    let root = workspace_root();
    let (reference, dist) = prepare(&root)?;
    let work = target_dir(&root).join("xtask/test-apps");
    fresh_dir(&work)?;
    let bin = work.join("data.bin");
    let txt = work.join("data.txt");
    // Fixed data: the same octets everywhere.
    let data: Vec<u8> = (0..100_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    fs::write(&bin, data)?;
    fs::write(&txt, "hello, rustyssl\n")?;
    let setup = Setup {
        upstream: reference.join("bin/openssl"),
        ours: dist.join("bin").join(CLI_NAME),
        ref_lib: reference.join("lib"),
        our_lib: dist.join("lib"),
        work: work.clone(),
        tests: root.join("tests/apps"),
        subst: vec![
            ("{bin}", bin.display().to_string()),
            ("{txt}", txt.display().to_string()),
            ("{dir}", work.display().to_string()),
            ("{src}", reference.join("src").display().to_string()),
            ("{tests}", root.join("tests/apps").display().to_string()),
        ],
    };

    // Guards: a missing library falls back to the one a tool was linked with (upstream's), or
    // isn't the one asked for (ours).
    let version = ["version".to_owned()];
    for (tool, lib, rustyssl) in [
        (&setup.upstream, &setup.our_lib, true),
        (&setup.ours, &setup.our_lib, true),
        (&setup.ours, &setup.ref_lib, false),
    ] {
        let out = run_tool(tool, lib, &version, None, &work)?;
        if out.text.contains("+rustyssl") != rustyssl {
            return Err(format!(
                "{} didn't load the libraries in {}: {}",
                tool.display(),
                lib.display(),
                out.text
            )
            .into());
        }
    }

    let mut lists: Vec<(String, PathBuf)> = Vec::new();
    for entry in fs::read_dir(root.join("tests/apps"))? {
        let path = entry?.path();
        if let Some(stem) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .filter(|_| path.extension().is_some_and(|e| e == "txt"))
            && (only.is_empty() || only.iter().any(|o| *o == stem))
        {
            lists.push((stem.to_owned(), path));
        }
    }
    lists.sort();
    if lists.is_empty() {
        return Err("no lists selected".into());
    }

    let mut failures = 0;
    let mut count = 0;
    for (name, path) in &lists {
        let text = fs::read_to_string(path)?;
        for line in parse_list(&text, &setup) {
            let command = line.args.first().map_or("", String::as_str);
            let mut runs: Vec<(&Path, &Path, &str)> = Vec::new();
            if name == "commands" {
                runs.push((
                    &setup.upstream,
                    &setup.our_lib,
                    "upstream's tool on rustyssl",
                ));
            }
            if name != "commands" || ported(&root, command) {
                runs.push((&setup.ours, &setup.our_lib, "our tool on rustyssl"));
                runs.push((&setup.ours, &setup.ref_lib, "our tool on the reference"));
            }
            count += 1;
            match check(&setup, &line, &runs)? {
                Ok(()) => println!("PASS {name}: openssl {}", line.text),
                Err(e) => {
                    println!("FAIL {name}: openssl {}: {e}", line.text);
                    failures += 1;
                }
            }
        }
        if name == "help" {
            failures += check_help_goldens(&root, &setup, &text, bless)?;
        }
    }
    if only.is_empty() {
        failures += run_live_tests(&root, &reference, &dist)?;
    }
    if failures == 0 {
        println!(
            "{count} command lines behave the same on rustyssl, and with our tool, as upstream's tool on the reference"
        );
        Ok(())
    } else {
        Err(format!("{failures} check(s) failed").into())
    }
}

/// The CLI's library-backed unit tests (`live_*`, the shared helpers of `src/lib/`) on each
/// library: the number of runs that failed.
fn run_live_tests(root: &Path, reference: &Path, dist: &Path) -> Result<usize> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut failed = 0;
    for (label, lib) in [
        ("the reference", reference.join("lib")),
        ("rustyssl", dist.join("lib")),
    ] {
        let out = Command::new(&cargo)
            .args([
                "test",
                "--quiet",
                "--color",
                "never",
                "-p",
                "rustyssl-cli",
                "live_",
            ])
            .current_dir(root)
            .env(LOADER_PATH, &lib)
            .env("OPENSSL_MODULES", crate::test_c::modules_of(&lib))
            .env("OPENSSL_CONF", MISSING_CONFIG)
            .env("RUSTYSSL_CLI_LIVE", reference.join("src"))
            .output()
            .map_err(|e| format!("cannot run cargo: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout);
        let summary = text
            .lines()
            .find(|l| l.starts_with("test result:"))
            .unwrap_or("no result")
            .to_owned();
        if out.status.success() && !summary.contains(" 0 passed") {
            println!("PASS the CLI's shared helpers on {label}: {summary}");
        } else {
            let details: Vec<&str> = text
                .lines()
                .filter(|l| l.contains("panicked") || l.contains("left:") || l.contains("right:"))
                .take(9)
                .collect();
            println!(
                "FAIL the CLI's shared helpers on {label}: {summary}\n{}\n{}",
                details.join("\n"),
                String::from_utf8_lossy(&out.stderr)
                    .lines()
                    .rev()
                    .take(3)
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            failed += 1;
        }
    }
    Ok(failed)
}

/// Checks (or with `bless`, writes) the golden `-help` texts against upstream's tool.
fn check_help_goldens(root: &Path, setup: &Setup, list: &str, bless: bool) -> Result<usize> {
    let dir = root.join(HELP_GOLDENS);
    fs::create_dir_all(&dir)?;
    let mut stale = 0;
    for line in list.lines().map(str::trim) {
        let Some(command) = line.strip_suffix(" -help") else {
            continue;
        };
        // Only the table's own names: others (`SHA256`) are looked up by the library.
        if !command
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        {
            continue;
        }
        let args = [command.to_owned(), "-help".to_owned()];
        let out = run_tool(&setup.upstream, &setup.ref_lib, &args, None, &setup.work)?;
        if !out.ok || !out.stdout.is_empty() {
            println!("FAIL help golden {command}: upstream's -help printed to stdout or failed");
            stale += 1;
            continue;
        }
        let golden = dir.join(format!("{command}.txt"));
        if bless {
            fs::write(&golden, &out.stderr)?;
        } else if fs::read(&golden).ok().as_deref() != Some(out.stderr.as_slice()) {
            println!(
                "FAIL help golden {command}: {} is stale (run `cargo xtask test-apps --bless help`)",
                golden.display()
            );
            stale += 1;
        }
    }
    Ok(stale)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masking() {
        assert_eq!(
            masked("OpenSSL 3.5.9 (Library: OpenSSL 3.5.9+rustyssl.0.1.0 29 Sep)"),
            "OpenSSL 3.5.9 (Library: OpenSSL 3.5.9 29 Sep)"
        );
        assert_eq!(
            masked("80:error:1C80006B:Provider routines:f:wrong final block length:a/b.c:467:"),
            "THREAD:error:1C80006B:Provider routines:f:wrong final block length:FILE:LINE:"
        );
        assert_eq!(masked("plain: 12:"), "plain: 12:");
        assert_eq!(
            masked(
                "80:error:0308010C:x:f:unsupported:crypto/evp/f.c:376:Global, Algorithm (a : 0)"
            ),
            "THREAD:error:0308010C:x:f:unsupported:FILE:LINE:Global, Algorithm (a : 0)"
        );
        assert_eq!(masked("OPENSSLDIR: \"/usr/local/ssl\""), "OPENSSLDIR: DIR");
    }

    #[test]
    fn lines_parse() {
        let setup = Setup {
            upstream: PathBuf::new(),
            ours: PathBuf::new(),
            ref_lib: PathBuf::new(),
            our_lib: PathBuf::new(),
            work: PathBuf::from("/w"),
            tests: PathBuf::new(),
            subst: vec![("{txt}", "/w/t".to_owned())],
        };
        let lines = parse_list(
            "# c\n\n~speed -seconds 1\nenc -base64 -in {txt}\nx509 -noout < {txt}\n",
            &setup,
        );
        assert_eq!(lines.len(), 3);
        assert!(!lines[0].compare);
        assert_eq!(lines[1].args, ["enc", "-base64", "-in", "/w/t"]);
        assert_eq!(lines[2].args, ["x509", "-noout"]);
        assert_eq!(lines[2].stdin.as_deref(), Some(Path::new("/w/t")));
        let lines = parse_list("srp -srpvfile {fresh:srp/v.txt} -list\n", &setup);
        assert_eq!(
            lines[0].args,
            ["srp", "-srpvfile", "/w/fresh/srp/v.txt", "-list"]
        );
        assert_eq!(lines[0].fresh, ["srp/v.txt"]);
    }
}
