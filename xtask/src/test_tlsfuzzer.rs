//! `cargo xtask test-tlsfuzzer [--timing [--interface IF]] [--reference-only] [--jobs N] [script...]`:
//! tlsfuzzer's scripts (TEST_PLAN.md, layer L7) against the reference's `openssl s_server`,
//! once on the reference's libraries and once on rustyssl's.
//!
//! `tests/tlsfuzzer/scripts.txt` pins tlsfuzzer and its Python dependencies (tlslite-ng,
//! python-ecdsa, six) to commits, fetched as GitHub tarballs into `target/tlsfuzzer/` and
//! checked against their SHA-256 sums, and lists the scripts with the `s_server` each one
//! runs against. The downloads are untrusted data: they are unpacked into their own
//! directories, the scripts are passed to `python3 -I` by path (no `PYTHONPATH`, no current
//! directory on the path), and a launcher of ours puts the trees on `sys.path`.
//!
//! Each script prints a `FAILED:` list of the conversations that failed. A conversation that
//! fails on rustyssl but not on the reference is a failure, as is a script that ends abnormally
//! on rustyssl only; conversations both libraries fail are reported, not counted. The report
//! goes to `target/tlsfuzzer-report.md`, each run's output to
//! `target/xtask/test-tlsfuzzer/<script>.<library>.log`.
//!
//! The timing scripts (`timing` lines: Lucky13, Bleichenbacher/Marvin) run only with
//! `--timing`. They measure many thousands of connections, capturing them with `tcpdump` on
//! the loopback interface (`--interface`, `lo0` on macOS and `lo` elsewhere by default; the
//! capture needs the privileges tcpdump does), write their samples under the work directory,
//! and need tlsfuzzer's analysis dependencies (NumPy, SciPy, pandas, ...) in the Python that
//! runs them. Run them with `--jobs 1`: concurrent connections disturb the timings.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use crate::test_c::{LOADER_PATH, prepare};
use crate::util::{Result, fresh_dir, run_output, sha256_file, target_dir, workspace_root};

/// The configuration file every server is pointed at, one that doesn't exist.
const MISSING_CONFIG: &str = "/nonexistent/rustyssl-tests/openssl.cnf";

/// How long a server may take to start.
const START_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a script may run (a timing script: `TIMING_TIMEOUT`).
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(900);
const TIMING_TIMEOUT: Duration = Duration::from_secs(6 * 3600);

/// Puts the trees named by the first arguments on `sys.path` and runs the script after them
/// as `__main__` with the rest as its arguments.
const LAUNCHER: &str = "import sys, runpy\n\
n = int(sys.argv[1])\n\
sys.path[:0] = sys.argv[2:2 + n]\n\
script = sys.argv[2 + n]\n\
sys.argv = [script] + sys.argv[3 + n:]\n\
runpy.run_path(script, run_name='__main__')\n";

/// A pinned dependency.
struct Pin {
    name: String,
    repository: String,
    commit: String,
    sum: String,
}

/// A script line.
#[derive(Clone)]
struct Script {
    /// Its position in `scripts.txt` (a script may run more than once, with other options).
    index: usize,
    file: String,
    args: Vec<String>,
    server: Vec<String>,
    timing: bool,
}

/// What one run of a script gave.
struct Outcome {
    /// The conversations that ran (`<name> ...` lines: a script may run a random sample of
    /// them), those that failed (`FAILED:`), and whether the script finished its summary.
    ran: BTreeSet<String>,
    failed: BTreeSet<String>,
    finished: bool,
    total: Option<u64>,
    error: Option<String>,
}

/// Splits a line at spaces, keeping "double-quoted" arguments whole.
fn split(line: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut any = false;
    for ch in line.chars() {
        match ch {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            ' ' | '\t' if !quoted => {
                if any {
                    out.push(core::mem::take(&mut cur));
                    any = false;
                }
            }
            c => {
                cur.push(c);
                any = true;
            }
        }
    }
    if quoted {
        return Err(format!("unbalanced quote: {line}").into());
    }
    if any {
        out.push(cur);
    }
    Ok(out)
}

/// The pins and the scripts of `scripts.txt`, `{tf}` substituted.
fn parse(text: &str, tf: &dyn Fn(&str) -> String) -> Result<(Vec<Pin>, Vec<Script>)> {
    let mut pins = Vec::new();
    let mut scripts = Vec::new();
    let mut server: Option<Vec<String>> = None;
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let words = split(line)?;
        let Some((kind, rest)) = words.split_first() else {
            continue;
        };
        match kind.as_str() {
            "pin" => {
                let [name, repository, commit, sum] = rest else {
                    return Err(format!("malformed pin: {line}").into());
                };
                pins.push(Pin {
                    name: name.clone(),
                    repository: repository.clone(),
                    commit: commit.clone(),
                    sum: sum.clone(),
                });
            }
            "server" => server = Some(rest.iter().map(|a| tf(a)).collect()),
            "script" | "timing" => {
                let Some((file, args)) = rest.split_first() else {
                    return Err(format!("a script line without a script: {line}").into());
                };
                let Some(server) = &server else {
                    return Err(format!("a script before any server line: {line}").into());
                };
                scripts.push(Script {
                    index: scripts.len(),
                    file: file.clone(),
                    args: args.iter().map(|a| tf(a)).collect(),
                    server: server.clone(),
                    timing: kind == "timing",
                });
            }
            _ => return Err(format!("unknown line: {line}").into()),
        }
    }
    Ok((pins, scripts))
}

/// Fetches a pinned tarball (if it isn't there with its sum) and unpacks it afresh; returns the
/// tree.
fn fetch(dir: &Path, pin: &Pin) -> Result<PathBuf> {
    let downloads = dir.join("downloads");
    fs::create_dir_all(&downloads)?;
    let tarball = downloads.join(format!("{}-{}.tar.gz", pin.name, pin.commit));
    if !(tarball.exists() && sha256_file(&tarball)? == pin.sum) {
        let url = format!(
            "https://codeload.github.com/{}/tar.gz/{}",
            pin.repository, pin.commit
        );
        let partial = tarball.with_extension("part");
        run_output(
            Command::new("curl")
                .args(["-sSfL", "--retry", "3", "-o"])
                .arg(&partial)
                .arg(&url),
        )?;
        let got = sha256_file(&partial)?;
        if got != pin.sum {
            fs::remove_file(&partial)?;
            return Err(format!("{url}: SHA-256 {got}, expected {}", pin.sum).into());
        }
        fs::rename(&partial, &tarball)?;
    }
    // Each tree in a directory of its own, unpacked from the verified tarball every run.
    let tree_dir = dir.join("trees").join(&pin.name);
    fresh_dir(&tree_dir)?;
    run_output(
        Command::new("tar")
            .arg("-xzf")
            .arg(&tarball)
            .arg("-C")
            .arg(&tree_dir),
    )?;
    let repo = pin
        .repository
        .rsplit('/')
        .next()
        .ok_or("a pin without a repository name")?;
    let tree = tree_dir.join(format!("{repo}-{}", pin.commit));
    if !tree.is_dir() {
        return Err(format!("{}: the tarball has no {}", pin.name, tree.display()).into());
    }
    Ok(tree)
}

/// A free local port (the listener is closed again; the server binds it next).
fn free_port() -> Result<u16> {
    let l = TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

/// The libraries and tools a run needs.
struct Env {
    openssl: PathBuf,
    reference: PathBuf,
    ours: PathBuf,
    python: String,
    /// The directories the launcher puts on `sys.path`.
    paths: Vec<PathBuf>,
    tf: PathBuf,
    work: PathBuf,
    /// The interface timing scripts capture on.
    interface: String,
}

/// Starts `s_server` on a free port and waits for it to accept.
fn start_server(env: &Env, ours: bool, args: &[String]) -> Result<(Child, u16)> {
    let mut last = String::new();
    // A port picked free can be taken before the server binds it: a few tries.
    for _ in 0..5 {
        let port = free_port()?;
        let mut child = Command::new(&env.openssl)
            .arg("s_server")
            .arg("-accept")
            .arg(format!("127.0.0.1:{port}"))
            .args(args)
            .current_dir(&env.work)
            .env(LOADER_PATH, if ours { &env.ours } else { &env.reference })
            .env("OPENSSL_CONF", MISSING_CONFIG)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot start s_server: {e}"))?;
        let (tx, rx) = mpsc::channel();
        let stdout = child.stdout.take().ok_or("no server stdout")?;
        let tx2 = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout)
                .lines()
                .map_while(std::io::Result::ok)
            {
                if tx2.send(line).is_err() {
                    break;
                }
            }
        });
        let mut stderr = child.stderr.take().ok_or("no server stderr")?;
        std::thread::spawn(move || {
            // Drained so the server never blocks writing its errors.
            let mut s = String::new();
            let _ = stderr.read_to_string(&mut s);
            let _ = tx.send(format!("stderr: {s}"));
        });
        let deadline = Instant::now() + START_TIMEOUT;
        last.clear();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok(line) if line.starts_with("ACCEPT") => {
                    // The rest of its output is dropped from here on.
                    std::thread::spawn(move || while rx.recv().is_ok() {});
                    return Ok((child, port));
                }
                Ok(line) => {
                    last.push_str(&line);
                    last.push('\n');
                }
                Err(_) => break,
            }
        }
        let _ = child.kill();
        let _ = child.wait();
    }
    Err(format!("s_server didn't start:\n{last}").into())
}

/// Runs one script against a fresh server on one library.
fn run_script(env: &Env, s: &Script, ours: bool) -> Result<Outcome> {
    let (mut server, port) = start_server(env, ours, &s.server)?;
    let script = env.tf.join("scripts").join(&s.file);
    let log = env.work.join(format!(
        "{:03}-{}.{}.log",
        s.index,
        s.file,
        if ours { "rustyssl" } else { "reference" }
    ));
    let out = fs::File::create(&log)?;
    let err = out.try_clone()?;
    // A timing script captures its connections and writes its samples here.
    let mut timing = Vec::new();
    if s.timing {
        let dir = log.with_extension("timing");
        fs::create_dir_all(&dir)?;
        timing.extend(["-i".to_owned(), env.interface.clone(), "-o".to_owned()]);
        timing.push(dir.display().to_string());
    }
    let mut child = Command::new(&env.python)
        .arg("-I")
        .arg("-c")
        .arg(LAUNCHER)
        .arg(env.paths.len().to_string())
        .args(&env.paths)
        .arg(&script)
        .args(["-h", "127.0.0.1", "-p", &port.to_string()])
        .args(&s.args)
        .args(&timing)
        .current_dir(&env.work)
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err)
        .spawn()
        .map_err(|e| format!("cannot run {}: {e}", env.python))?;
    let limit = if s.timing {
        TIMING_TIMEOUT
    } else {
        SCRIPT_TIMEOUT
    };
    let start = Instant::now();
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break Some(st);
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let _ = server.kill();
    let _ = server.wait();
    let text = String::from_utf8_lossy(&fs::read(&log)?).into_owned();
    let mut outcome = summary(&text);
    match status {
        None => outcome.error = Some(format!("timed out after {}s", limit.as_secs())),
        Some(st) if !outcome.finished => {
            outcome.error = Some(format!("ended without a summary ({st})"));
        }
        Some(_) => {}
    }
    Ok(outcome)
}

/// The failed conversations and the total from a script's output.
fn summary(text: &str) -> Outcome {
    let mut ran = BTreeSet::new();
    let mut failed = BTreeSet::new();
    let mut finished = false;
    let mut total = None;
    let mut in_failed = false;
    for line in text.lines() {
        if line == "Test end" {
            finished = true;
        }
        if !finished && let Some(name) = line.strip_suffix(" ...") {
            ran.insert(name.to_owned());
        }
        if let Some(n) = line.strip_prefix("TOTAL: ") {
            total = n.trim().parse().ok();
        }
        if line == "FAILED:" {
            in_failed = true;
            continue;
        }
        if in_failed {
            match line.strip_prefix('\t') {
                Some(name) => {
                    let name = name.trim();
                    let name = name
                        .strip_prefix('\'')
                        .and_then(|n| n.strip_suffix('\''))
                        .or_else(|| name.strip_prefix('"').and_then(|n| n.strip_suffix('"')))
                        .unwrap_or(name);
                    failed.insert(name.to_owned());
                }
                None => in_failed = false,
            }
        }
    }
    Outcome {
        ran,
        failed,
        finished,
        total,
        error: None,
    }
}

/// A run's outcome, or why it couldn't run (sent between threads, so as text).
type Ran = core::result::Result<Outcome, String>;

/// A script's row: what each library gave.
struct Row {
    script: Script,
    reference: Ran,
    ours: Option<Ran>,
}

impl Script {
    /// The script with its options, as the report names it (paths shortened).
    fn label(&self) -> String {
        let mut l = self.file.clone();
        for a in &self.args {
            l.push(' ');
            l.push_str(a.rsplit('/').next().unwrap_or(a));
        }
        l
    }
}

impl Row {
    /// What rustyssl fails that the reference doesn't.
    fn regressions(&self) -> Vec<String> {
        let Some(ours) = &self.ours else {
            return Vec::new();
        };
        let (r, o) = match (&self.reference, ours) {
            (_, Err(e)) => return vec![format!("rustyssl run failed: {e}")],
            (Err(_), Ok(_)) => return Vec::new(),
            (Ok(r), Ok(o)) => (r, o),
        };
        let mut out = Vec::new();
        if let Some(e) = &o.error
            && r.error.is_none()
        {
            out.push(format!("rustyssl: {e}"));
        }
        // Only what the reference ran too: a sampled script may run others on each library.
        for name in o.failed.difference(&r.failed) {
            if r.ran.contains(name) || !r.finished {
                out.push(name.clone());
            }
        }
        out
    }

    /// What rustyssl failed that the reference didn't run (a sample's difference).
    fn unmatched(&self) -> Vec<String> {
        match (&self.reference, &self.ours) {
            (Ok(r), Some(Ok(o))) if r.finished => o
                .failed
                .iter()
                .filter(|n| !r.ran.contains(*n) && !r.failed.contains(*n))
                .cloned()
                .collect(),
            _ => Vec::new(),
        }
    }
}

fn describe(o: &Ran) -> String {
    match o {
        Err(e) => format!("error: {e}"),
        Ok(o) => {
            let mut s = match o.total {
                Some(t) => format!("{} of {t} fail", o.failed.len()),
                None => format!("{} fail", o.failed.len()),
            };
            if let Some(e) = &o.error {
                let _ = write!(s, "; {e}");
            }
            s
        }
    }
}

fn write_report(path: &Path, rows: &[Row]) -> Result {
    let mut md = String::from(
        "# tlsfuzzer on rustyssl\n\nWritten by `cargo xtask test-tlsfuzzer` \
         (`tests/tlsfuzzer/scripts.txt`). Each script runs against the reference's `s_server`, \
         on the reference's libraries and on rustyssl's; a conversation failing on rustyssl \
         only is a regression.\n\n\
         | script | reference | rustyssl | regressions |\n|---|---|---|---:|\n",
    );
    for r in rows {
        let ours = r.ours.as_ref().map_or("not run".to_owned(), describe);
        let _ = writeln!(
            md,
            "| {}{} | {} | {} | {} |",
            r.script.label(),
            if r.script.timing { " (timing)" } else { "" },
            describe(&r.reference),
            ours,
            r.regressions().len()
        );
    }
    for r in rows {
        let reg = r.regressions();
        let shared: Vec<&String> = match (&r.reference, &r.ours) {
            (Ok(a), Some(Ok(b))) => a.failed.intersection(&b.failed).collect(),
            _ => Vec::new(),
        };
        let unmatched = r.unmatched();
        if reg.is_empty() && shared.is_empty() && unmatched.is_empty() {
            continue;
        }
        let _ = writeln!(md, "\n## {}\n", r.script.label());
        for name in &reg {
            let _ = writeln!(md, "- **rustyssl only:** `{name}`");
        }
        for name in &unmatched {
            let _ = writeln!(md, "- rustyssl, not run on the reference: `{name}`");
        }
        for name in shared {
            let _ = writeln!(md, "- both: `{name}`");
        }
    }
    fs::write(path, md)?;
    Ok(())
}

pub fn run(args: &[String]) -> Result {
    let root = workspace_root();
    let timing = args.iter().any(|a| a == "--timing");
    let reference_only = args.iter().any(|a| a == "--reference-only");
    let mut jobs = std::thread::available_parallelism().map_or(4, |n| n.get().div_ceil(2));
    let mut interface = if cfg!(target_os = "macos") {
        "lo0"
    } else {
        "lo"
    }
    .to_owned();
    let mut only = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--timing" | "--reference-only" => {}
            "--interface" => {
                interface = it
                    .next()
                    .cloned()
                    .ok_or("--interface takes an interface name")?;
            }
            "--jobs" => {
                jobs = it
                    .next()
                    .and_then(|n| n.parse().ok())
                    .filter(|&n| n > 0)
                    .ok_or("--jobs takes a positive number")?;
            }
            s if s.starts_with("--") => return Err(format!("unknown option {s}").into()),
            s => only.push(s.to_owned()),
        }
    }
    let (reference, dist) = prepare(&root)?;
    let dir = target_dir(&root).join("tlsfuzzer");
    let text = fs::read_to_string(root.join("tests/tlsfuzzer/scripts.txt"))?;
    // The pins first (`{tf}` isn't known until tlsfuzzer is fetched).
    let (pins, _) = parse(&text, &|a| a.to_owned())?;
    let mut trees = Vec::new();
    for pin in &pins {
        trees.push((pin.name.clone(), fetch(&dir, pin)?));
    }
    let tree = |name: &str| {
        trees
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, t)| t.clone())
            .ok_or_else(|| format!("scripts.txt pins no {name}"))
    };
    let tf = tree("tlsfuzzer")?;
    let paths = vec![
        tf.clone(),
        tree("tlslite-ng")?,
        tree("python-ecdsa")?.join("src"),
        tree("six")?,
    ];
    let tf_text = tf.display().to_string();
    let (_, scripts) = parse(&text, &|a| a.replace("{tf}", &tf_text))?;
    let selected: Vec<Script> = scripts
        .into_iter()
        .filter(|s| (timing || !s.timing) && (only.is_empty() || only.contains(&s.file)))
        .collect();
    if selected.is_empty() {
        return Err("no tlsfuzzer scripts selected".into());
    }
    let work = target_dir(&root).join("xtask/test-tlsfuzzer");
    fresh_dir(&work)?;
    let env = Arc::new(Env {
        openssl: reference.join("bin/openssl"),
        reference: reference.join("lib"),
        ours: dist.join("lib"),
        python: std::env::var("PYTHON").unwrap_or_else(|_| "python3".to_owned()),
        paths,
        tf,
        work,
        interface,
    });

    // A pool of workers, each taking the next script and running it on both libraries.
    let queue = Arc::new(Mutex::new(selected.into_iter().enumerate()));
    let (tx, rx) = mpsc::channel();
    let mut workers = Vec::new();
    for _ in 0..jobs {
        let (queue, env, tx) = (Arc::clone(&queue), Arc::clone(&env), tx.clone());
        workers.push(std::thread::spawn(move || {
            loop {
                let next = queue.lock().ok().and_then(|mut q| q.next());
                let Some((i, s)) = next else { break };
                let reference = run_script(&env, &s, false).map_err(|e| e.to_string());
                let ours = (!reference_only)
                    .then(|| run_script(&env, &s, true).map_err(|e| e.to_string()));
                let row = Row {
                    script: s,
                    reference,
                    ours,
                };
                if tx.send((i, row)).is_err() {
                    break;
                }
            }
        }));
    }
    drop(tx);
    let mut rows = Vec::new();
    for (i, row) in rx {
        let reg = row.regressions();
        let ours = row
            .ours
            .as_ref()
            .map_or(String::new(), |o| format!(", rustyssl: {}", describe(o)));
        let verdict = if reg.is_empty() { "PASS" } else { "FAIL" };
        println!(
            "{verdict} {} (reference: {}{ours})",
            row.script.label(),
            describe(&row.reference)
        );
        for r in &reg {
            println!("    rustyssl only: {r}");
        }
        rows.push((i, row));
    }
    for w in workers {
        let _ = w.join();
    }
    rows.sort_by_key(|(i, _)| *i);
    let rows: Vec<Row> = rows.into_iter().map(|(_, r)| r).collect();
    let report = target_dir(&root).join("tlsfuzzer-report.md");
    write_report(&report, &rows)?;
    let failing: Vec<&str> = rows
        .iter()
        .filter(|r| !r.regressions().is_empty())
        .map(|r| r.script.file.as_str())
        .collect();
    let conversations: usize = rows
        .iter()
        .filter_map(|r| r.reference.as_ref().ok().and_then(|o| o.total))
        .map(|t| usize::try_from(t).unwrap_or(usize::MAX))
        .sum();
    if reference_only {
        println!(
            "{} tlsfuzzer scripts ({conversations} conversations) run on the reference \
             (report: {})",
            rows.len(),
            report.display()
        );
        Ok(())
    } else if failing.is_empty() {
        println!(
            "{} tlsfuzzer scripts ({conversations} conversations) pass on rustyssl wherever they \
             pass on the reference (report: {})",
            rows.len(),
            report.display()
        );
        Ok(())
    } else {
        Err(format!(
            "{} of {} scripts fail on rustyssl only: {} (report: {})",
            failing.len(),
            rows.len(),
            failing.join(", "),
            report.display()
        )
        .into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_quoted_arguments() {
        assert_eq!(
            split(r#"script a.py -n 0 --ems "session ID len fuzz""#).unwrap(),
            ["script", "a.py", "-n", "0", "--ems", "session ID len fuzz"]
        );
        assert!(split(r#"a "b"#).is_err());
    }

    #[test]
    fn reads_the_failed_conversations() {
        let out = "one ...\nError\nthree ...\nOK\n\
                   Test end\n====\nTOTAL: 5\nPASS: 3\n====\nFAILED:\n\t'one'\n\t\"two's\"\n";
        let o = summary(out);
        assert!(o.finished);
        assert_eq!(
            o.ran.into_iter().collect::<Vec<_>>(),
            ["one".to_owned(), "three".to_owned()]
        );
        assert_eq!(o.total, Some(5));
        assert_eq!(
            o.failed.into_iter().collect::<Vec<_>>(),
            ["one".to_owned(), "two's".to_owned()]
        );
    }

    #[test]
    fn parses_servers_and_scripts() {
        let text = "pin a o/a c s\nserver -www -cert {tf}/x\nscript t.py -x \"a b\"\ntiming u.py\n";
        let (pins, scripts) = parse(text, &|s| s.replace("{tf}", "/t")).unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(scripts.len(), 2);
        assert_eq!(scripts[0].server, ["-www", "-cert", "/t/x"]);
        assert_eq!(scripts[0].args, ["-x", "a b"]);
        assert!(scripts[1].timing);
        assert!(parse("script t.py\n", &|s| s.to_owned()).is_err());
    }
}
