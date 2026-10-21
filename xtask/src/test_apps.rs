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
//! succeed on every run; one starting with `%` (`speed`'s) is compared with its numbers masked,
//! and the lines naming the library's build (`built on:`, `compiler:`, `CPUINFO:`).
//!
//! In a line, `{bin}` is 100,000 octets of fixed data, `{txt}` a line of text, `{dir}` the work
//! directory, `{src}` the reference's source tree (its `test/certs/`, ...), and `{tests}`
//! `tests/apps/`; a final `< file` gives the command its standard input (otherwise empty).
//! A line starting with `@<fixture> ` (after any `~`) is stateful: before each of its runs, the
//! directory `tests/apps/<fixture>` is copied afresh to `{dir}/<its last component>` (a CA's
//! database and serial files, which the command changes), so every run starts the same.
//!
//! Output that is random by design (key and parameter generation, randomized signatures) is
//! compared structurally: in `command ... | check ...`, each run of `command` is followed by
//! `check` with upstream's tool on the reference libraries, reading the command's standard
//! output (further `| check` stages chain the same way). What is compared is the command's
//! exit status and the last check's output, with runs of hex-dump lines (`    01:ab:...`)
//! collapsed to one and `asn1parse`'s `[HEX DUMP]:` values masked; a `< file` comes before
//! the first `|`.
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
                l = mask_libdir(&l);
            }
            for dir in OPENSSLDIRS.get().into_iter().flatten() {
                l = l.replace(dir.as_str(), "OPENSSLDIR/");
            }
            l
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Both libraries' OPENSSLDIRs (with a trailing `/`), set once the libraries are found: a
/// default file's path (`cert.pem`, `openssl.cnf`, ...) is `OPENSSLDIR/<file>` in the output.
static OPENSSLDIRS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();

/// The libraries' own directory as `LIBDIR/`: macOS's `dlopen` errors list the paths dyld
/// tried, the library's directory first (`target/ref/openssl-<version>/lib/` on the reference,
/// `target/dist/lib/` on ours).
fn mask_libdir(line: &str) -> String {
    let mut l = line.replace("target/dist/lib/", "LIBDIR/");
    while let Some(at) = l.find("target/ref/openssl-") {
        let Some(end) = l[at..].find("/lib/") else {
            break;
        };
        l.replace_range(at..at + end + "/lib/".len(), "LIBDIR/");
    }
    l
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

/// The output with what varies from run to run masked too: each number (`12`, `0.25s`,
/// `1234.50k`, `inf`, `-nan`) as `N`, runs of spaces as one, and the lines that name how the
/// library was built.
fn masked_timings(text: &str) -> String {
    let mut out = Vec::new();
    for line in masked(text).lines() {
        if let Some(p) = ["built on:", "compiler:", "CPUINFO:"]
            .iter()
            .find(|p| line.starts_with(**p))
        {
            out.push((*p).to_owned());
            continue;
        }
        let c: Vec<char> = line.chars().collect();
        let mut l = String::new();
        let mut i = 0;
        while let Some(&here) = c.get(i) {
            let word_start = i == 0 || !c.get(i - 1).is_some_and(char::is_ascii_alphabetic);
            let sign = usize::from(here == '-');
            let rest = c.get(i + sign..).unwrap_or_default();
            let num = rest
                .iter()
                .take_while(|c| c.is_ascii_digit() || **c == '.')
                .count();
            // `inf` or `nan` as a word (or with `k`), not the start of one.
            let alpha = |j: usize| rest.get(j).is_some_and(char::is_ascii_alphabetic);
            let ends = !alpha(3) || (rest.get(3) == Some(&'k') && !alpha(4));
            let starts = |w: &str| ends && rest.iter().take(3).copied().eq(w.chars());
            let len = if rest.iter().take(num).any(char::is_ascii_digit) {
                num
            } else if word_start && (starts("inf") || starts("nan")) {
                3
            } else {
                0
            };
            if len == 0 {
                l.push(here);
                i += 1;
                continue;
            }
            l.push('N');
            i += sign + len;
            if c.get(i) == Some(&'k') {
                i += 1;
            }
        }
        let mut collapsed = String::new();
        for c in l.chars() {
            if !(c == ' ' && collapsed.ends_with(' ')) {
                collapsed.push(c);
            }
        }
        out.push(collapsed);
    }
    out.join("\n")
}

/// The first difference between two outputs, after masking (and with `timings`, after
/// [`masked_timings`]).
fn compare(
    expected: &Output,
    got: &Output,
    label: &str,
    timings: bool,
) -> std::result::Result<(), String> {
    let mask = if timings { masked_timings } else { masked };
    let (t, o) = (mask(&expected.text), mask(&got.text));
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

/// One line of a list: its arguments, its standard input, whether it is compared, and the
/// checks its output is piped through (each one's arguments).
struct Line {
    text: String,
    compare: bool,
    /// Compared with its timings masked (`%` lines).
    timings: bool,
    args: Vec<String>,
    stdin: Option<PathBuf>,
    checks: Vec<Vec<String>>,
    /// The fixture directory copied afresh before each run, and where it goes.
    reset: Option<(PathBuf, PathBuf)>,
}

/// Copies the directory `from` to `to`, replacing what was there.
fn copy_fresh(from: &Path, to: &Path) -> Result {
    if to.exists() {
        fs::remove_dir_all(to)?;
    }
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let path = entry.path();
        let dest = to.join(entry.file_name());
        if path.is_dir() {
            copy_fresh(&path, &dest)?;
        } else {
            fs::copy(&path, &dest)?;
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
        let (compare, timings, rest) = match (line.strip_prefix('~'), line.strip_prefix('%')) {
            (Some(rest), _) => (false, false, rest),
            (None, Some(rest)) => (true, true, rest),
            (None, None) => (true, false, line),
        };
        let mut reset = None;
        let rest = match rest.strip_prefix('@').and_then(|r| r.split_once(' ')) {
            Some((fixture, r)) => {
                let from = setup.tests.join(fixture);
                let name = from.file_name().map(PathBuf::from).unwrap_or_default();
                reset = Some((from, setup.work.join(name)));
                r
            }
            None => rest,
        };
        let mut args: Vec<String> = rest
            .split_whitespace()
            .map(|a| {
                let mut a = a.to_owned();
                for (key, value) in &setup.subst {
                    a = a.replace(key, value);
                }
                a
            })
            .collect();
        let mut checks: Vec<Vec<String>> = Vec::new();
        while let Some(at) = args.iter().rposition(|a| a == "|") {
            checks.insert(0, args.split_off(at + 1));
            args.pop();
        }
        let mut stdin = None;
        if args.len() >= 2 && args.get(args.len() - 2).is_some_and(|a| a == "<") {
            stdin = args.pop().map(PathBuf::from);
            args.pop();
        }
        out.push(Line {
            text: rest.to_owned(),
            compare,
            timings,
            args,
            stdin,
            checks,
            reset,
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

/// Runs a line's command with `tool` on `lib`, then its checks (if any) with upstream's tool on
/// the reference, each reading the previous one's standard output. With checks, the result is
/// the command's exit status and the last check's output, hex dumps collapsed.
fn run_line(setup: &Setup, line: &Line, tool: &Path, lib: &Path) -> Result<Output> {
    let w = &setup.work;
    if let Some((from, to)) = &line.reset {
        copy_fresh(from, to)?;
    }
    let first = run_tool(tool, lib, &line.args, line.stdin.as_deref(), w)?;
    if line.checks.is_empty() {
        return Ok(first);
    }
    let mut prev = first.stdout.clone();
    let mut last = None;
    for check in &line.checks {
        let piped = w.join("pipe.in");
        fs::write(&piped, &prev)?;
        let out = run_tool(&setup.upstream, &setup.ref_lib, check, Some(&piped), w)?;
        prev = out.stdout.clone();
        last = Some(out);
    }
    let last = last.ok_or("no check")?;
    let text = format!(
        "[command: {}]\n{}",
        if first.ok { "success" } else { "failure" },
        collapse_hex(&last.text)
    );
    Ok(Output {
        stdout: last.stdout,
        stderr: last.stderr,
        text,
        ok: first.ok && last.ok,
    })
}

/// Collapses each run of hex-dump lines (`    00:c3:...`, the random parts of a printed key)
/// into one `HEX` line, and masks `asn1parse`'s `[HEX DUMP]:` values.
fn collapse_hex(text: &str) -> String {
    let is_hex = |l: &str| {
        let t = l.trim();
        l.starts_with(' ')
            && !t.is_empty()
            && t.split(':')
                .filter(|p| !p.is_empty())
                .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
    };
    let mut out: Vec<String> = Vec::new();
    for l in text.lines() {
        if is_hex(l) {
            if out.last().map(String::as_str) != Some("HEX") {
                out.push("HEX".to_owned());
            }
        } else if let Some(at) = l.find("[HEX DUMP]:") {
            // asn1parse's dump of a primitive's (random) octets.
            out.push(format!("{}[HEX DUMP]:HEX", &l[..at]));
        } else {
            out.push(l.to_owned());
        }
    }
    let mut s = out.join("\n");
    s.push('\n');
    s
}

/// Runs one line: upstream's tool on the reference (the expectation), then the runs `ours`
/// lists, each as (tool, libraries, label).
fn check(
    setup: &Setup,
    line: &Line,
    runs: &[(&Path, &Path, &str)],
) -> Result<std::result::Result<(), String>> {
    let expected = run_line(setup, line, &setup.upstream, &setup.ref_lib)?;
    for (tool, lib, label) in runs {
        let got = run_line(setup, line, tool, lib)?;
        let verdict = if line.compare {
            compare(&expected, &got, label, line.timings)
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
    // Each library's OPENSSLDIR (the reference's is under its prefix, ours the target's
    // default), masked wherever an output names a file in it.
    let mut dirs = Vec::new();
    for lib in [&setup.ref_lib, &setup.our_lib] {
        let out = run_tool(
            &setup.upstream,
            lib,
            &["version".to_owned(), "-d".to_owned()],
            None,
            &work,
        )?;
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        if let Some(dir) = text
            .trim()
            .strip_prefix("OPENSSLDIR: \"")
            .and_then(|d| d.strip_suffix('"'))
        {
            dirs.push(format!("{dir}/"));
        }
    }
    let _ = OPENSSLDIRS.set(dirs);

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
        assert_eq!(
            mask_libdir("tried: '/r/target/ref/openssl-3.6.5/lib/p.dylib' (no such file)"),
            "tried: '/r/LIBDIR/p.dylib' (no such file)"
        );
        assert_eq!(
            mask_libdir("tried: '/r/target/dist/lib/p.dylib' (no such file)"),
            "tried: '/r/LIBDIR/p.dylib' (no such file)"
        );
    }

    #[test]
    fn timings_masking() {
        assert_eq!(
            masked_timings("Doing sha256 ops for 1s on 16 size blocks: 12 sha256 ops in 0.99s"),
            "Doing shaN ops for Ns on N size blocks: N shaN ops in Ns"
        );
        assert_eq!(
            masked_timings("sha256           1234.50k        infk     -nan       12.00 "),
            "shaN N N N N "
        );
        assert_eq!(masked_timings("+F:6:sha256:inf:0.50"), "+F:N:shaN:N:N");
        assert_eq!(
            masked_timings("built on: Tue Oct 20 2026\ncompiler: gcc"),
            "built on:\ncompiler:"
        );
        assert_eq!(masked_timings("information: é 3"), "information: é N");
    }

    #[test]
    fn lines_parse() {
        let setup = Setup {
            upstream: PathBuf::new(),
            ours: PathBuf::new(),
            ref_lib: PathBuf::new(),
            our_lib: PathBuf::new(),
            work: PathBuf::from("/w"),
            tests: PathBuf::from("/t"),
            subst: vec![("{txt}", "/w/t".to_owned())],
        };
        let lines = parse_list(
            "# c\n\n~speed -seconds 1\nenc -base64 -in {txt}\nx509 -noout < {txt}\n~@pki/db ca -x\n",
            &setup,
        );
        assert_eq!(lines.len(), 4);
        assert!(!lines[3].compare);
        assert_eq!(lines[3].args, ["ca", "-x"]);
        assert_eq!(
            lines[3].reset,
            Some((PathBuf::from("/t/pki/db"), PathBuf::from("/w/db")))
        );
        assert!(!lines[0].compare);
        assert_eq!(lines[1].args, ["enc", "-base64", "-in", "/w/t"]);
        assert_eq!(lines[2].args, ["x509", "-noout"]);
        assert_eq!(lines[2].stdin.as_deref(), Some(Path::new("/w/t")));
        let piped = parse_list("genrsa 512 < {txt} | rsa -check | pkey -noout\n", &setup);
        assert_eq!(piped[0].args, ["genrsa", "512"]);
        assert_eq!(piped[0].stdin.as_deref(), Some(Path::new("/w/t")));
        assert_eq!(
            piped[0].checks,
            [vec!["rsa", "-check"], vec!["pkey", "-noout"]]
        );
    }

    #[test]
    fn hex_collapses() {
        assert_eq!(
            collapse_hex("modulus:\n    00:c3:\n    ab:01\nexponent: 3\n    12\n"),
            "modulus:\nHEX\nexponent: 3\nHEX\n"
        );
        assert_eq!(collapse_hex("a: 1:\n"), "a: 1:\n");
        assert_eq!(
            collapse_hex("  34:d=5  hl=2 l=  16 prim: OCTET STRING [HEX DUMP]:A1EA\n"),
            "  34:d=5  hl=2 l=  16 prim: OCTET STRING [HEX DUMP]:HEX\n"
        );
    }
}
