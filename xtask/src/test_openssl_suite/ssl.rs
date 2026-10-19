//! libssl's upstream test programs, and the provider programs (`cargo xtask test-openssl-suite
//! --ssl`, or by name).
//!
//! `tests/openssl-suite/ssl.txt` lists the programs with the arguments and environment their
//! recipes give them, and the test modules (`p_test`) built with them.
//! They're built from the reference's source as the others are; the ones upstream links with
//! the static libraries are relinked with the shared ones, which needs `sslapitest`'s test
//! providers to carry their own copies of three internal libcrypto helpers. The `dasync`
//! engine (`sslapitest`'s pipelining tests) is built too, and both runs find it through
//! `OPENSSL_ENGINES`.
//!
//! A program's tests are listed on the reference (`-list`), and each test runs in a process of
//! its own, each iteration of an iterated test too (`-test N -iter I`), so that an abort in one
//! of rustyssl's stubs, a crash, or a hang (a timeout) costs only that subtest. Each runs on the
//! reference first: what fails there alone isn't counted. What then fails on rustyssl is
//! classified (a stub's abort, a missing export, a crash, a timeout, a failed check, a skip the
//! reference didn't make) and grouped by root cause into `target/ssl-suite-report.md`: the
//! stub, the symbol, or the test's first `ERROR` line. Tests that read libssl's private
//! structures (`internal` lines) are reported apart: they can't pass on another layout.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::{Build, MISSING_CONFIG};
use crate::test_c::LOADER_PATH;
use crate::util::{Result, fresh_dir, target_dir};

/// How long one subtest may run before it counts as a hang.
const TIMEOUT: Duration = Duration::from_secs(30);

/// The engine module `sslapitest` loads (`load_dasync`).
const DASYNC: &str = if cfg!(target_os = "macos") {
    "engines/dasync.dylib"
} else {
    "engines/dasync.so"
};

/// One program's line of `ssl.txt`: the program, its arguments and its environment, the
/// placeholders unexpanded.
struct Line {
    program: String,
    args: Vec<String>,
    /// `VAR=value` words before the program: its environment, over the run's.
    env: Vec<(String, String)>,
    /// Whether it runs as one subtest (a `whole` line): its program reads its arguments in a
    /// way that options before them break.
    whole: bool,
}

impl Line {
    /// The name its results go by: the program, with `ssl_test`'s file, or with the options it
    /// was given (`provider_test -loaded`).
    fn label(&self) -> String {
        match self.args.first().and_then(|a| a.rsplit('/').next()) {
            Some(file) if self.program == "ssl_test" => {
                format!("ssl_test {}", file.trim_end_matches(".cnf"))
            }
            _ => {
                // Each option, with its value's file name when it has one.
                let mut options: Vec<&str> = Vec::new();
                let mut args = self.args.iter().map(String::as_str).peekable();
                while let Some(a) = args.next() {
                    if !a.starts_with('-') {
                        continue;
                    }
                    options.push(a);
                    if let Some(v) = args.next_if(|v| !v.starts_with('-')) {
                        options.push(v.rsplit('/').next().unwrap_or(v));
                    }
                }
                if options.is_empty() {
                    self.program.clone()
                } else {
                    format!("{} {}", self.program, options.join(" "))
                }
            }
        }
    }

    /// Whether `name` selects it: its program, or `ssl_test`'s file (with or without `.cnf`).
    fn named(&self, name: &str) -> bool {
        self.program == name
            || (self.program == "ssl_test"
                && self
                    .args
                    .first()
                    .and_then(|a| a.rsplit('/').next())
                    .is_some_and(|f| {
                        f == name || f.trim_end_matches(".cnf") == name.trim_end_matches(".cnf")
                    }))
    }
}

impl Line {
    /// A line's words: `VAR=value` words, the program, its arguments. `None` without a program.
    fn parse(words: &[&str], whole: bool) -> Option<Line> {
        let mut env = Vec::new();
        let mut rest = words.iter();
        let program = loop {
            let w = rest.next()?;
            match w.split_once('=') {
                Some((var, value))
                    if !var.is_empty()
                        && var.bytes().all(|b| b.is_ascii_uppercase() || b == b'_') =>
                {
                    env.push((var.to_owned(), value.to_owned()));
                }
                _ => break (*w).to_owned(),
            }
        };
        Some(Line {
            program,
            args: rest.map(|a| (*a).to_owned()).collect(),
            env,
            whole,
        })
    }
}

/// A `build` line's module as a make target: `test/p_test` with the platform's module
/// extension.
fn module_target(name: &str) -> String {
    if cfg!(target_os = "macos") {
        format!("{name}.dylib")
    } else {
        format!("{name}.so")
    }
}

/// `tests/openssl-suite/ssl.txt`.
pub struct List {
    lines: Vec<Line>,
    /// Programs not run, and why.
    skips: Vec<(String, String)>,
    /// Each program's tests that read libssl's private structures: a program (or an `ssl_test`
    /// file, as `ssl_test/<file>`) and a test, or one iteration of it (`<test>#<iteration>`).
    internal: Vec<(String, String)>,
    /// What else the build makes (`build` lines): modules the programs load.
    extra: Vec<String>,
}

impl List {
    pub fn load(root: &Path) -> Result<List> {
        let path = root.join("tests/openssl-suite/ssl.txt");
        let text = fs::read_to_string(&path)?;
        let mut list = List {
            lines: Vec::new(),
            skips: Vec::new(),
            internal: Vec::new(),
            extra: Vec::new(),
        };
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut words = line.split_whitespace();
            let first = words.next().ok_or("an empty line")?;
            match first {
                "skip" => {
                    let program = words
                        .next()
                        .ok_or(format!("{}: `{line}`", path.display()))?;
                    let reason = words.collect::<Vec<_>>().join(" ");
                    list.skips.push((program.to_owned(), reason));
                }
                "internal" => {
                    let program = words
                        .next()
                        .ok_or(format!("{}: `{line}`", path.display()))?;
                    for test in words {
                        list.internal.push((program.to_owned(), test.to_owned()));
                    }
                }
                "build" => list.extra.extend(words.map(module_target)),
                "whole" => {
                    let rest: Vec<&str> = words.collect();
                    list.lines.push(
                        Line::parse(&rest, true).ok_or(format!("{}: `{line}`", path.display()))?,
                    );
                }
                _ => {
                    let all: Vec<&str> = line.split_whitespace().collect();
                    list.lines.push(
                        Line::parse(&all, false).ok_or(format!("{}: `{line}`", path.display()))?,
                    );
                }
            }
        }
        Ok(list)
    }

    /// Whether `name` names one of the programs (or `ssl_test` files).
    pub fn names(&self, name: &str) -> bool {
        self.lines.iter().any(|l| l.named(name))
    }

    fn is_internal(&self, line: &Line, test: &str, iteration: Option<usize>) -> bool {
        let label = line.label();
        let one = iteration.map(|i| format!("{test}#{i}"));
        self.internal.iter().any(|(p, t)| {
            (*p == line.program || p.replace('/', " ") == label)
                && (t == test || one.as_deref() == Some(t.as_str()))
        })
    }
}

/// The build of `list`'s programs and the `dasync` engine.
pub fn build(list: &List) -> Build {
    let mut targets: Vec<String> = Vec::new();
    for line in &list.lines {
        let target = format!("test/{}", line.program);
        if !targets.contains(&target) {
            targets.push(target);
        }
    }
    targets.push(DASYNC.to_owned());
    for extra in &list.extra {
        if !targets.contains(extra) {
            targets.push(extra.clone());
        }
    }
    let mut patches = vec![
            // Upstream links `sslapitest` with the static libraries, from which its test
            // providers (`filterprov.c`, `tls-provider.c`) take a few internal helpers that no
            // shared library exports (except the reference's on macOS, which exports
            // everything); they get their own copies, and the program the shared libraries.
            (
                "test/build.info",
                "DEPEND[sslapitest]=../libcrypto.a ../libssl.a libtestutil.a".to_owned(),
                "DEPEND[sslapitest]=../libcrypto ../libssl libtestutil.a".to_owned(),
            ),
            (
                "test/build.info",
                "SOURCE[sslapitest]=sslapitest.c helpers/ssltestlib.c filterprov.c tls-provider.c\n".to_owned(),
                "SOURCE[sslapitest]=sslapitest.c helpers/ssltestlib.c filterprov.c tls-provider.c \
                 ../providers/common/provider_ctx.c ../providers/common/bio_prov.c ../crypto/time.c\n".to_owned(),
        ),
    ];
    // The provider programs upstream links statically, relinked with the shared libraries (they
    // use only the public API).
    for program in RELINKED {
        if list.lines.iter().any(|l| l.program == *program) {
            patches.push((
                "test/build.info",
                format!("DEPEND[{program}]=../libcrypto.a libtestutil.a"),
                format!("DEPEND[{program}]=../libcrypto libtestutil.a"),
            ));
        }
    }
    Build {
        suffix: "-ssl",
        targets,
        patches,
    }
}

/// Programs upstream links with the static libcrypto that the list's runs relink with the shared
/// one.
const RELINKED: &[&str] = &[
    "provider_test",
    "provfetchtest",
    "prov_config_test",
    "provider_status_test",
];

/// One subtest: a test of a line's program, or one iteration of it.
struct Unit {
    line: usize,
    id: usize,
    test: String,
    iteration: Option<usize>,
}

/// How one run of a subtest ended.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    Pass,
    Skip,
    /// A rustyssl stub aborted: the function.
    Stub(String),
    /// The dynamic loader found no such symbol.
    MissingSymbol(String),
    /// Killed by a signal, with the first `ERROR` line if any.
    Signal(i32, String),
    Timeout,
    /// Exited with failure: the first `ERROR` line (or what stands for it).
    Failed(String),
}

/// The paths a run's arguments and environment refer to.
struct Setting<'a> {
    suite: &'a Path,
    src: PathBuf,
    work: PathBuf,
}

impl Setting<'_> {
    /// `text` with its placeholders expanded: `{src}`, `{tmp}`, and `{suite}` (the built
    /// programs and modules).
    fn expand(&self, text: &str, tmp: &Path) -> String {
        text.replace("{src}", &self.src.to_string_lossy())
            .replace("{tmp}", &tmp.to_string_lossy())
            .replace("{suite}", &self.suite.to_string_lossy())
    }

    fn args(&self, line: &Line, tmp: &Path) -> Vec<String> {
        line.args.iter().map(|a| self.expand(a, tmp)).collect()
    }

    /// `line`'s own environment, expanded.
    fn env(&self, line: &Line, tmp: &Path) -> Vec<(String, String)> {
        line.env
            .iter()
            .map(|(k, v)| (k.clone(), self.expand(v, tmp)))
            .collect()
    }

    /// Runs `program` with `args` on the libraries in `lib`, for at most `TIMEOUT`: its exit
    /// status (`None` if it timed out) and output. `name` keeps its files apart from others':
    /// its output, and the directory it runs in, where programs write their own files
    /// (`sslapitest`'s pluggable tests write a key and a certificate per iteration, which
    /// subtests running at the same time would otherwise share).
    fn run(
        &self,
        program: &str,
        args: &[String],
        env: &[(String, String)],
        lib: &Path,
        name: &str,
    ) -> Result<(Option<ExitStatus>, String)> {
        let out_path = self.work.join(format!("{name}.out"));
        let out = File::create(&out_path)?;
        let cwd = self.work.join(format!("{name}.d"));
        fs::create_dir_all(&cwd)?;
        let exe = self.suite.join(program);
        let mut child = Command::new(&exe)
            .args(args)
            .current_dir(&cwd)
            .env(LOADER_PATH, lib)
            .env("OPENSSL_CONF", MISSING_CONFIG)
            .env("OPENSSL_ENGINES", self.suite)
            .env("TEST_CERTS_DIR", self.src.join("test/certs"))
            .env("CTLOG_FILE", self.src.join("test/ct/log_list.cnf"))
            .envs(env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::null())
            .stdout(out.try_clone()?)
            .stderr(out)
            .spawn()
            .map_err(|e| format!("cannot run {}: {e}", exe.display()))?;
        let start = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break Some(status);
            }
            if start.elapsed() > TIMEOUT {
                // The process may have exited meanwhile; either way it's gone after `wait`.
                let _ = child.kill();
                child.wait()?;
                break None;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let text = String::from_utf8_lossy(&fs::read(&out_path)?).into_owned();
        fs::remove_file(&out_path)?;
        fs::remove_dir_all(&cwd)?;
        Ok((status, text))
    }
}

/// The first `ERROR` line of `text`, or the first `not ok` line.
fn first_error(text: &str) -> Option<String> {
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    for (i, line) in lines.iter().enumerate() {
        if let Some(error) = line.strip_prefix("# ERROR:") {
            let error = error.trim();
            // `ERROR:  @ file:line` carries its message on the next line.
            if error.starts_with('@')
                && let Some(next) = lines.get(i + 1).and_then(|l| l.strip_prefix('#'))
            {
                return Some(format!("{} {error}", next.trim()));
            }
            return Some(error.to_owned());
        }
    }
    lines
        .iter()
        .find(|l| l.starts_with("not ok"))
        .map(|l| (*l).to_owned())
}

/// The first error the library queued in `text` (testutil prints the queue after a failed
/// check), as `function: reason`: the first that isn't an alert received from the peer (the
/// peer's own error, when there is one, says why it sent it), else the first.
fn first_queued_error(text: &str) -> Option<String> {
    let mut errors = text.lines().filter_map(|line| {
        // `THREAD:error:CODE:LIBRARY:FUNCTION:REASON:FILE:LINE:DATA`
        let fields: Vec<&str> = line
            .trim()
            .trim_start_matches('#')
            .trim()
            .split(':')
            .collect();
        match fields.as_slice() {
            [_, "error", code, _, function, reason, ..]
                if code.len() == 8 && code.chars().all(|c| c.is_ascii_hexdigit()) =>
            {
                Some((reason.contains("alert"), format!("{function}: {reason}")))
            }
            _ => None,
        }
    });
    let first = errors.next()?;
    if !first.0 {
        return Some(first.1);
    }
    Some(errors.find(|(alert, _)| !alert).unwrap_or(first).1)
}

/// What a failed run is grouped by: the library's first queued error, or else the test's
/// first `ERROR` line; `ssl_test`'s, which is always the same comparison, gives way to the
/// message after it (`ExpectedResult mismatch: expected Success, got ServerFail.`).
fn failure_cause(text: &str, status: ExitStatus) -> String {
    if let Some(error) = first_queued_error(text) {
        return error;
    }
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    let checked = lines
        .iter()
        .position(|l| l.starts_with("# ERROR:") && l.contains("@ test/ssl_test.c"));
    if let Some(at) = checked {
        let message = lines
            .iter()
            .skip(at)
            .skip_while(|l| !l.starts_with("# INFO:"))
            .nth(1)
            .and_then(|l| l.strip_prefix('#'))
            .map(str::trim);
        if let Some(message) = message.filter(|m| !m.is_empty()) {
            return message.to_owned();
        }
    }
    first_error(text).unwrap_or_else(|| format!("{status} without an ERROR line"))
}

fn classify(status: Option<ExitStatus>, text: &str) -> Outcome {
    if let Some(at) = text.find(" is not implemented yet; aborting") {
        let before = text.get(..at).unwrap_or_default();
        let name = before.rsplit("rustyssl: ").next().unwrap_or(before);
        return Outcome::Stub(name.trim().to_owned());
    }
    for marker in ["Symbol not found: ", "undefined symbol: "] {
        if let Some(at) = text.find(marker) {
            let rest = text.get(at + marker.len()..).unwrap_or_default();
            let symbol = rest.split_whitespace().next().unwrap_or_default();
            return Outcome::MissingSymbol(symbol.trim_start_matches('_').to_owned());
        }
    }
    let Some(status) = status else {
        return Outcome::Timeout;
    };
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return Outcome::Signal(signal, first_error(text).unwrap_or_default());
        }
    }
    if !status.success() {
        return Outcome::Failed(failure_cause(text, status));
    }
    if text
        .lines()
        .any(|l| l.trim_start().starts_with("ok ") && l.trim_end().ends_with("# skipped"))
    {
        Outcome::Skip
    } else {
        Outcome::Pass
    }
}

fn signal_name(signal: i32) -> String {
    match signal {
        4 => "SIGILL".to_owned(),
        5 => "SIGTRAP".to_owned(),
        6 => "SIGABRT".to_owned(),
        7 if cfg!(target_os = "linux") => "SIGBUS".to_owned(),
        10 if cfg!(target_os = "macos") => "SIGBUS".to_owned(),
        8 => "SIGFPE".to_owned(),
        11 => "SIGSEGV".to_owned(),
        n => format!("signal {n}"),
    }
}

/// The tests of `line`'s program, as the reference lists them: id, name, and iterations.
fn list_tests(setting: &Setting, line: &Line, lib: &Path, n: usize) -> Result<Vec<Unit>> {
    let tmp = setting.work.join(format!("list{n}.tmp"));
    let mut args = vec!["-list".to_owned()];
    args.extend(setting.args(line, &tmp));
    let env = setting.env(line, &tmp);
    let (status, text) = setting.run(&line.program, &args, &env, lib, &format!("list{n}"))?;
    if !status.is_some_and(|s| s.success()) {
        return Err(format!(
            "{} -list fails on the reference:\n{}",
            line.label(),
            text.lines().take(5).collect::<Vec<_>>().join("\n")
        )
        .into());
    }
    let mut units = Vec::new();
    for entry in text.lines() {
        // `N - name` or `N - name (1..I)`.
        let Some((id, rest)) = entry.trim().split_once(" - ") else {
            continue;
        };
        let Ok(id) = id.parse::<usize>() else {
            continue;
        };
        let mut words = rest.split_whitespace();
        let Some(test) = words.next() else {
            continue;
        };
        let iterations = words
            .next()
            .and_then(|w| w.strip_prefix("(1.."))
            .and_then(|w| w.strip_suffix(')'))
            .and_then(|w| w.parse::<usize>().ok());
        match iterations {
            Some(count) => units.extend((1..=count).map(|i| Unit {
                line: n,
                id,
                test: test.to_owned(),
                iteration: Some(i),
            })),
            None => units.push(Unit {
                line: n,
                id,
                test: test.to_owned(),
                iteration: None,
            }),
        }
    }
    if units.is_empty() {
        return Err(format!("{} lists no tests", line.label()).into());
    }
    Ok(units)
}

/// A subtest's results on both libraries.
struct Done {
    theirs: Outcome,
    ours: Outcome,
    /// The start of rustyssl's output when it didn't pass.
    excerpt: String,
}

/// A failure's category, in the order the report lists them.
fn category(outcome: &Outcome, internal: bool) -> &'static str {
    if internal {
        return "reads libssl internals";
    }
    match outcome {
        Outcome::Stub(_) => "stub abort",
        Outcome::MissingSymbol(_) => "missing export",
        Outcome::Signal(..) => "crash",
        Outcome::Timeout => "hang (timeout)",
        Outcome::Failed(_) => "wrong result",
        Outcome::Skip => "skipped on rustyssl only",
        Outcome::Pass => "pass",
    }
}

/// What a failure is grouped by.
fn cause(outcome: &Outcome, label: &str, test: &str) -> String {
    match outcome {
        Outcome::Stub(name) => format!("`{name}` is not implemented yet"),
        Outcome::MissingSymbol(symbol) => format!("`{symbol}` isn't exported"),
        Outcome::Signal(signal, error) if error.is_empty() => {
            format!("{} in {label} {test}", signal_name(*signal))
        }
        Outcome::Signal(signal, error) => format!("{}: {error}", signal_name(*signal)),
        Outcome::Timeout | Outcome::Skip | Outcome::Pass => format!("{label} {test}"),
        Outcome::Failed(error) => error.clone(),
    }
}

/// Per line: subtests, then the reference's passes, skips, and failures, then rustyssl's passes,
/// skips, and failures (of those the reference passed or skipped).
#[derive(Default)]
struct Row {
    units: usize,
    theirs: [usize; 3],
    ours: [usize; 3],
}

pub fn run(
    root: &Path,
    suite: &Path,
    reference: &Path,
    ours: &Path,
    list: &List,
    names: &[String],
) -> Result {
    let theirs = reference.join("lib");
    let work = target_dir(root).join("xtask/ssl-suite");
    fresh_dir(&work)?;
    let setting = Setting {
        suite,
        src: reference.join("src"),
        work,
    };
    let selected: Vec<usize> = (0..list.lines.len())
        .filter(|&n| {
            names.is_empty()
                || list
                    .lines
                    .get(n)
                    .is_some_and(|l| names.iter().any(|a| l.named(a)))
        })
        .collect();

    let mut units = Vec::new();
    let mut unlisted = Vec::new();
    for &n in &selected {
        let Some(line) = list.lines.get(n) else {
            continue;
        };
        if line.whole {
            units.push(Unit {
                line: n,
                id: 0,
                test: line.program.clone(),
                iteration: None,
            });
            continue;
        }
        match list_tests(&setting, line, &theirs, n) {
            Ok(found) => units.extend(found),
            Err(e) => {
                println!("SKIP {}: {e}", line.label());
                unlisted.push((line.label(), e.to_string()));
            }
        }
    }
    println!(
        "Running {} subtests of {} libssl test programs, each on the reference and then on rustyssl...",
        units.len(),
        selected.len()
    );

    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<Option<Done>>> = Mutex::new((0..units.len()).map(|_| None).collect());
    let errors: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let jobs = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);
    std::thread::scope(|scope| {
        for _ in 0..jobs {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(unit) = units.get(i) else {
                        break;
                    };
                    match run_unit(&setting, list, unit, i, &theirs, ours) {
                        Ok(done) => {
                            if let Ok(mut results) = results.lock()
                                && let Some(slot) = results.get_mut(i)
                            {
                                *slot = Some(done);
                            }
                        }
                        Err(e) => {
                            if let Ok(mut errors) = errors.lock() {
                                errors.push(e.to_string());
                            }
                        }
                    }
                    if (i + 1).is_multiple_of(200) {
                        println!("  {} of {} subtests started", i + 1, units.len());
                    }
                }
            });
        }
    });
    let errors = errors.into_inner().map_err(|_| "a worker panicked")?;
    if let Some(e) = errors.first() {
        return Err(format!("{} subtest(s) couldn't run; the first: {e}", errors.len()).into());
    }
    let results = results.into_inner().map_err(|_| "a worker panicked")?;

    // Tally.
    let mut rows: BTreeMap<usize, Row> = BTreeMap::new();
    let mut theirs_failed: Vec<String> = Vec::new();
    let mut groups: BTreeMap<(&'static str, String), Vec<(String, String)>> = BTreeMap::new();
    for (unit, done) in units.iter().zip(&results) {
        let (Some(line), Some(done)) = (list.lines.get(unit.line), done) else {
            continue;
        };
        let label = line.label();
        let name = match unit.iteration {
            Some(i) => format!("{} #{i}", unit.test),
            None => unit.test.clone(),
        };
        let row = rows.entry(unit.line).or_default();
        row.units += 1;
        let ([pass, skip, fail], [our_pass, our_skip, our_fail]) = (&mut row.theirs, &mut row.ours);
        match &done.theirs {
            Outcome::Pass => *pass += 1,
            Outcome::Skip => *skip += 1,
            other => {
                *fail += 1;
                theirs_failed.push(format!(
                    "{label} {name}: {}",
                    cause(other, &label, &unit.test)
                ));
                continue;
            }
        }
        match &done.ours {
            Outcome::Pass => *our_pass += 1,
            Outcome::Skip if done.theirs == Outcome::Skip => *our_skip += 1,
            other => {
                *our_fail += 1;
                let internal = list.is_internal(line, &unit.test, unit.iteration);
                let key = (
                    category(other, internal),
                    if internal {
                        format!("{label} {}", unit.test)
                    } else {
                        cause(other, &label, &unit.test)
                    },
                );
                groups
                    .entry(key)
                    .or_default()
                    .push((format!("{label} {name}"), done.excerpt.clone()));
            }
        }
    }

    let report = write_report(root, list, &rows, &theirs_failed, &groups, &unlisted)?;
    let total: usize = rows.values().map(|r| r.units).sum();
    let counted: usize = rows.values().map(|r| r.units - r.theirs[2]).sum();
    let passed: usize = rows.values().map(|r| r.ours[0] + r.ours[1]).sum();
    let failed: usize = rows.values().map(|r| r.ours[2]).sum();
    println!(
        "{:<40} {:>6} {:>18} {:>18}",
        "program", "tests", "reference p/s/f", "rustyssl p/s/f"
    );
    for (n, row) in &rows {
        let label = list.lines.get(*n).map(Line::label).unwrap_or_default();
        println!(
            "{label:<40} {:>6} {:>18} {:>18}",
            row.units,
            format!("{}/{}/{}", row.theirs[0], row.theirs[1], row.theirs[2]),
            format!("{}/{}/{}", row.ours[0], row.ours[1], row.ours[2])
        );
    }
    let mut ranked: Vec<_> = groups.iter().collect();
    ranked.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(b.0)));
    println!("Root causes (subtests blocked):");
    for ((category, cause), units) in ranked.iter().take(20) {
        println!("  {:>5}  [{category}] {cause}", units.len());
    }
    println!(
        "{total} subtests, {} failing on the reference alone; of the other {counted}, {passed} pass on rustyssl and {failed} fail (report: {})",
        total - counted,
        report.display()
    );
    if failed == 0 && unlisted.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{failed} of {counted} libssl subtests fail on rustyssl; see {}",
            report.display()
        )
        .into())
    }
}

/// Runs one subtest on the reference, then on rustyssl.
fn run_unit(
    setting: &Setting,
    list: &List,
    unit: &Unit,
    i: usize,
    theirs: &Path,
    ours: &Path,
) -> Result<Done> {
    let line = list.lines.get(unit.line).ok_or("no such line")?;
    let mut outcomes = Vec::new();
    let mut excerpt = String::new();
    for (lib, side) in [(theirs, "ref"), (ours, "ours")] {
        let tmp = setting.work.join(format!("{i}.{side}.tmp"));
        let mut args = Vec::new();
        if !line.whole {
            args.push("-test".to_owned());
            args.push(unit.id.to_string());
        }
        if let Some(iteration) = unit.iteration {
            args.push("-iter".to_owned());
            args.push(iteration.to_string());
        }
        args.extend(setting.args(line, &tmp));
        let env = setting.env(line, &tmp);
        let (status, text) =
            setting.run(&line.program, &args, &env, lib, &format!("{i}.{side}"))?;
        if tmp.exists() {
            fs::remove_file(&tmp)?;
        }
        let outcome = classify(status, &text);
        if side == "ours" && outcome != Outcome::Pass {
            excerpt = text
                .lines()
                .filter(|l| !l.trim().is_empty())
                .take(12)
                .collect::<Vec<_>>()
                .join("\n");
        }
        outcomes.push(outcome);
    }
    let mut outcomes = outcomes.into_iter();
    Ok(Done {
        theirs: outcomes.next().ok_or("no reference run")?,
        ours: outcomes.next().ok_or("no rustyssl run")?,
        excerpt,
    })
}

/// Writes `target/ssl-suite-report.md` and returns its path.
fn write_report(
    root: &Path,
    list: &List,
    rows: &BTreeMap<usize, Row>,
    theirs_failed: &[String],
    groups: &BTreeMap<(&'static str, String), Vec<(String, String)>>,
    unlisted: &[(String, String)],
) -> Result<PathBuf> {
    let mut md = String::new();
    writeln!(md, "# libssl's upstream tests on rustyssl\n")?;
    writeln!(
        md,
        "Written by `cargo xtask test-openssl-suite --ssl` (`tests/openssl-suite/ssl.txt`). Each \
         subtest (a test, or one iteration of an iterated test) runs in its own process on the \
         reference, then on rustyssl, with a {}-second timeout. Subtests that fail on the \
         reference alone aren't counted against rustyssl.\n",
        TIMEOUT.as_secs()
    )?;
    writeln!(md, "## Results per program\n")?;
    writeln!(
        md,
        "| program | subtests | reference pass | skip | fail | rustyssl pass | skip | fail |"
    )?;
    writeln!(md, "|---|---:|---:|---:|---:|---:|---:|---:|")?;
    let mut sums = Row::default();
    for (n, row) in rows {
        let label = list.lines.get(*n).map(Line::label).unwrap_or_default();
        writeln!(
            md,
            "| {label} | {} | {} | {} | {} | {} | {} | {} |",
            row.units,
            row.theirs[0],
            row.theirs[1],
            row.theirs[2],
            row.ours[0],
            row.ours[1],
            row.ours[2]
        )?;
        sums.units += row.units;
        for k in 0..3 {
            if let (Some(t), Some(o), Some(rt), Some(ro)) = (
                sums.theirs.get_mut(k),
                sums.ours.get_mut(k),
                row.theirs.get(k),
                row.ours.get(k),
            ) {
                *t += rt;
                *o += ro;
            }
        }
    }
    writeln!(
        md,
        "| **all** | {} | {} | {} | {} | {} | {} | {} |\n",
        sums.units,
        sums.theirs[0],
        sums.theirs[1],
        sums.theirs[2],
        sums.ours[0],
        sums.ours[1],
        sums.ours[2]
    )?;

    let mut by_category: BTreeMap<&str, usize> = BTreeMap::new();
    for ((category, _), units) in groups {
        *by_category.entry(category).or_default() += units.len();
    }
    writeln!(md, "## Failures on rustyssl by category\n")?;
    writeln!(md, "| category | subtests | root causes |")?;
    writeln!(md, "|---|---:|---:|")?;
    for (category, count) in &by_category {
        let causes = groups.keys().filter(|(c, _)| c == category).count();
        writeln!(md, "| {category} | {count} | {causes} |")?;
    }
    writeln!(md)?;

    let mut ranked: Vec<_> = groups.iter().collect();
    ranked.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(b.0)));
    writeln!(md, "## Root causes, by subtests blocked\n")?;
    writeln!(
        md,
        "| # | subtests | tests | category | root cause | examples |"
    )?;
    writeln!(md, "|---:|---:|---:|---|---|---|")?;
    for (rank, ((category, cause), units)) in ranked.iter().enumerate() {
        let examples: Vec<&str> = units.iter().take(3).map(|(u, _)| u.as_str()).collect();
        // The tests, iterations aside.
        let mut tests: Vec<&str> = units
            .iter()
            .map(|(u, _)| u.rsplit_once(" #").map_or(u.as_str(), |(t, _)| t))
            .collect();
        tests.sort_unstable();
        tests.dedup();
        writeln!(
            md,
            "| {} | {} | {} | {category} | {} | {} |",
            rank + 1,
            units.len(),
            tests.len(),
            cause.replace('|', "\\|"),
            examples.join("; ").replace('|', "\\|")
        )?;
    }
    writeln!(md)?;

    writeln!(md, "## Details\n")?;
    for ((category, cause), units) in &ranked {
        writeln!(md, "### [{category}] {cause}\n")?;
        let names: Vec<&str> = units.iter().take(40).map(|(u, _)| u.as_str()).collect();
        let more = units.len().saturating_sub(names.len());
        let more = if more > 0 {
            format!(", and {more} more")
        } else {
            String::new()
        };
        writeln!(
            md,
            "{} subtest(s): {}{more}\n",
            units.len(),
            names.join(", ")
        )?;
        if let Some((unit, excerpt)) = units.first() {
            writeln!(md, "rustyssl's output for {unit}:\n\n```\n{excerpt}\n```\n")?;
        }
    }

    writeln!(md, "## Not counted\n")?;
    for (program, reason) in &list.skips {
        writeln!(md, "- {program}: not run; {reason}.")?;
    }
    for (label, error) in unlisted {
        writeln!(md, "- {label}: not run; {}", error.replace('\n', " "))?;
    }
    for failure in theirs_failed {
        writeln!(md, "- fails on the reference when run alone: {failure}")?;
    }
    let path = target_dir(root).join("ssl-suite-report.md");
    fs::write(&path, md)?;
    Ok(path)
}
