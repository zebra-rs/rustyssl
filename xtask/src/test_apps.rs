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
//! errors' thread id and file and line, and our tool's name (`openssl-rs`). A line starting with `~` (timings) must only
//! succeed on every run.
//!
//! In a line, `{bin}` is 100,000 octets of fixed data, `{txt}` a line of text, `{dir}` the work
//! directory, `{src}` the reference's source tree (its `test/certs/`, ...), and `{tests}`
//! `tests/apps/`; a final `< file` gives the command its standard input (otherwise empty).
//! Prefixes, in any order: `~` (only success is compared, as above); `&`, a server (`ocsp
//! -port`, `cmp -port`): it starts in the background, the next line runs once it has printed
//! its `ACCEPT` line, and then both outputs are compared (the server must exit by itself, as
//! with `-nrequest 1`); `@`, the times within a few days of now (a reply made now) are masked.
//! Every output's `PID=n` is masked.
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
/// directories the libraries were built with, errors' `file:line:`, and process ids.
fn masked(text: &str) -> String {
    text.lines()
        .map(|line| {
            // Our tool's own name, which commands show through `opt_appname` ("openssl cmp").
            let mut l = mask_pid(line).replace(&format!("{CLI_NAME} "), "openssl ");
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

/// `PID=<digits>` as `PID=PID` (a server's `ACCEPT` line).
fn mask_pid(line: &str) -> String {
    let mut out = String::new();
    let mut rest = line;
    while let Some((before, after)) = rest.split_once("PID=") {
        out.push_str(before);
        out.push_str("PID=");
        let n = after.bytes().take_while(u8::is_ascii_digit).count();
        if n > 0 {
            out.push_str("PID");
        }
        rest = after.get(n..).unwrap_or_default();
    }
    out.push_str(rest);
    out
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Days since 1970-01-01 of a civil date (Howard Hinnant's `days_from_civil`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The length of the time `ASN1_TIME_print` writes (`Mmm dd hh:mm:ss[.fff] yyyy GMT`) at the
/// start of `s`, if it is within three days of `today` (days since the epoch).
fn time_near(s: &str, today: i64) -> Option<usize> {
    let m = MONTHS.iter().position(|m| s.starts_with(m))?;
    let rest = s.get(3..)?;
    let rb = rest.as_bytes();
    if rb.first() != Some(&b' ') {
        return None;
    }
    let day: i64 = rest.get(1..3)?.trim().parse().ok()?;
    let time = rest.get(4..12)?.as_bytes();
    if time.get(2) != Some(&b':') || time.get(5) != Some(&b':') {
        return None;
    }
    let mut j = 12;
    if rb.get(j) == Some(&b'.') {
        j += 1;
        while rb.get(j).is_some_and(u8::is_ascii_digit) {
            j += 1;
        }
    }
    if rb.get(j) != Some(&b' ') {
        return None;
    }
    let year: i64 = rest.get(j + 1..j + 5)?.parse().ok()?;
    if rest.get(j + 5..j + 9) != Some(" GMT") {
        return None;
    }
    let days = days_from_civil(year, i64::try_from(m).ok()? + 1, day);
    ((days - today).abs() <= 3).then_some(3 + j + 9)
}

/// The times near `today` ([`time_near`]) of a line, as `TIME`.
fn mask_times_near(line: &str, today: i64) -> String {
    let mut out = String::new();
    let mut rest = line;
    while let Some(c) = rest.chars().next() {
        if let Some(len) = time_near(rest, today) {
            out.push_str("TIME");
            rest = rest.get(len..).unwrap_or_default();
        } else {
            out.push(c);
            rest = rest.get(c.len_utf8()..).unwrap_or_default();
        }
    }
    out
}

/// [`mask_times_near`] for every line, around the current day.
fn mask_now_times(text: &str) -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let today = i64::try_from(secs / 86_400).unwrap_or(0);
    text.lines()
        .map(|l| mask_times_near(l, today))
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

/// The first difference between two outputs, after masking (also of the current times, with
/// `times`).
fn compare(
    expected: &Output,
    got: &Output,
    label: &str,
    times: bool,
) -> std::result::Result<(), String> {
    let (mut t, mut o) = (masked(&expected.text), masked(&got.text));
    if times {
        (t, o) = (mask_now_times(&t), mask_now_times(&o));
    }
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
    subst: Vec<(&'static str, String)>,
}

/// One line of a list: its arguments, its standard input, whether it is compared, whether
/// it is a server for the next line, and whether the current times are masked.
struct Line {
    text: String,
    compare: bool,
    args: Vec<String>,
    stdin: Option<PathBuf>,
    background: bool,
    times: bool,
}

fn parse_list(text: &str, setup: &Setup) -> Vec<Line> {
    let mut out = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (mut compare, mut background, mut times) = (true, false, false);
        let mut rest = line;
        loop {
            match rest.as_bytes().first() {
                Some(b'~') => compare = false,
                Some(b'&') => background = true,
                Some(b'@') => times = true,
                _ => break,
            }
            rest = rest[1..].trim_start();
        }
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
            background,
            times,
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
    let expected = run_tool(
        &setup.upstream,
        &setup.ref_lib,
        &line.args,
        line.stdin.as_deref(),
        w,
    )?;
    for (tool, lib, label) in runs {
        let got = run_tool(tool, lib, &line.args, line.stdin.as_deref(), w)?;
        let verdict = if line.compare {
            compare(&expected, &got, label, line.times)
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

/// A server line's run: started in the background, then (once it has printed its `ACCEPT`
/// line) the client's run, then the server's end. Both outputs, as (server, client).
fn run_pair(
    tool: &Path,
    lib: &Path,
    server: &Line,
    client: &Line,
    work: &Path,
) -> Result<(Output, Output)> {
    use std::io::{BufRead, BufReader, Read};
    use std::time::{Duration, Instant};
    let mut child = Command::new(tool)
        .args(&server.args)
        .current_dir(work)
        .env(LOADER_PATH, lib)
        .env("OPENSSL_MODULES", crate::test_c::modules_of(lib))
        .env("OPENSSL_CONF", MISSING_CONFIG)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run {}: {e}", tool.display()))?;
    let stdout = child.stdout.take().ok_or("no server stdout")?;
    let mut stderr = child.stderr.take().ok_or("no server stderr")?;
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let out_thread = std::thread::spawn(move || {
        let mut all = Vec::new();
        let mut r = BufReader::new(stdout);
        let mut line = Vec::new();
        while r.read_until(b'\n', &mut line).unwrap_or(0) > 0 {
            all.extend_from_slice(&line);
            let _ = tx.send(line.clone());
            line.clear();
        }
        all
    });
    let err_thread = std::thread::spawn(move || {
        let mut all = Vec::new();
        let _ = stderr.read_to_end(&mut all);
        all
    });
    // The server is ready once it reports where it accepts (or gone, if it failed).
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(l) if l.starts_with(b"ACCEPT") => break,
            Ok(_) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
    let got = run_tool(tool, lib, &client.args, client.stdin.as_deref(), work)?;
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            break child.wait()?;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let stdout = out_thread.join().unwrap_or_default();
    let stderr = err_thread.join().unwrap_or_default();
    let mut text = String::from_utf8_lossy(&stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&stderr));
    text.push_str(&format!("[{status}]\n"));
    let server_out = Output {
        stdout,
        stderr,
        text,
        ok: status.success(),
    };
    Ok((server_out, got))
}

/// [`check`] for a server line and its client line.
fn check_pair(
    setup: &Setup,
    server: &Line,
    client: &Line,
    runs: &[(&Path, &Path, &str)],
) -> Result<std::result::Result<(), String>> {
    let w = &setup.work;
    let (es, ec) = run_pair(&setup.upstream, &setup.ref_lib, server, client, w)?;
    for (tool, lib, label) in runs {
        let (gs, gc) = run_pair(tool, lib, server, client, w)?;
        let both = [(&es, &gs, server, "server"), (&ec, &gc, client, "client")];
        for (expected, got, line, which) in both {
            let label = format!("{label} ({which})");
            let verdict = if line.compare {
                compare(expected, got, &label, line.times || server.times)
            } else if expected.ok == got.ok {
                Ok(())
            } else {
                Err(format!(
                    "{label}: exit: expected success {}, got {}",
                    expected.ok, got.ok
                ))
            };
            if verdict.is_err() {
                return Ok(verdict);
            }
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
        let mut lines = parse_list(&text, &setup).into_iter();
        while let Some(line) = lines.next() {
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
            if line.background {
                let Some(client) = lines.next() else {
                    println!(
                        "FAIL {name}: openssl {}: no client line after it",
                        line.text
                    );
                    failures += 1;
                    continue;
                };
                count += 1;
                let text = format!("{} & {}", line.text, client.text);
                match check_pair(&setup, &line, &client, &runs)? {
                    Ok(()) => println!("PASS {name}: openssl {text}"),
                    Err(e) => {
                        println!("FAIL {name}: openssl {text}: {e}");
                        failures += 1;
                    }
                }
                continue;
            }
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
            masked("ACCEPT [::]:8888 PID=4242"),
            "ACCEPT [::]:8888 PID=PID"
        );
    }

    #[test]
    fn current_times() {
        let today = days_from_civil(2026, 10, 21);
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(
            mask_times_near("This Update: Oct 21 01:02:03 2026 GMT", today),
            "This Update: TIME"
        );
        assert_eq!(
            mask_times_near(
                "a Oct 23 01:02:03.123 2026 GMT b Nov  2 00:00:00 2026 GMT",
                today
            ),
            "a TIME b Nov  2 00:00:00 2026 GMT"
        );
        assert_eq!(
            mask_times_near("Not After : Jan  1 00:00:00 2030 GMT", today),
            "Not After : Jan  1 00:00:00 2030 GMT"
        );
    }

    #[test]
    fn lines_parse() {
        let setup = Setup {
            upstream: PathBuf::new(),
            ours: PathBuf::new(),
            ref_lib: PathBuf::new(),
            our_lib: PathBuf::new(),
            work: PathBuf::new(),
            subst: vec![("{txt}", "/w/t".to_owned())],
        };
        let lines = parse_list(
            "# c\n\n~speed -seconds 1\nenc -base64 -in {txt}\nx509 -noout < {txt}\n&@ ocsp -port 1\n",
            &setup,
        );
        assert_eq!(lines.len(), 4);
        assert!(lines[3].background && lines[3].times && lines[3].compare);
        assert_eq!(lines[3].args, ["ocsp", "-port", "1"]);
        assert!(!lines[0].compare);
        assert_eq!(lines[1].args, ["enc", "-base64", "-in", "/w/t"]);
        assert_eq!(lines[2].args, ["x509", "-noout"]);
        assert_eq!(lines[2].stdin.as_deref(), Some(Path::new("/w/t")));
    }
}
