//! `cargo xtask test-bogo [pattern...]`: BoringSSL's TLS test runner, BoGo (TEST_PLAN.md,
//! layer L7), on the reference and on rustyssl.
//!
//! The runner (`ssl/test/runner` in BoringSSL) is fetched from the commit pinned in
//! `tests/bogo/pin.txt`, checked against its SHA-256, and built with Go into
//! `target/xtask/test-bogo/`. It drives `tests/bogo/shim.c`, a shim written against the
//! OpenSSL API (compiled against the vendored headers), through every test: once with the
//! dynamic loader pointed at the reference libraries, once at rustyssl's. Tests needing what
//! the shim doesn't implement (BoringSSL-only features, DTLS for now) are reported
//! unimplemented, and `tests/bogo/config.json` disables the BoringSSL-only behaviors no flag
//! announces. Errors are matched loosely (`-loose-errors`): BoringSSL's error names aren't
//! OpenSSL's, so a test that must fail passes on any failure; the shim's failure log
//! (`BOGO_SHIM_LOG`) then compares the two libraries' first error entries instead.
//!
//! The reference run is the expectation: a test the reference passes must pass on rustyssl.
//! `target/bogo-report.md` lists the counts per library, the tests that pass on the reference
//! but not on rustyssl (grouped by rustyssl's first error), those rustyssl passes alone, the
//! tests whose expected failures differ in their first error, and what the shim leaves
//! unimplemented. With patterns, only the tests they match run (`*` globs, as the runner's
//! `-test` takes them); `--workers N` runs N tests at a time (the runner's `-num-workers`;
//! by default one per CPU). Under full load the runner itself loses some alerts (it sees a
//! closed connection or a broken pipe before it reads the shim's alert), on either library and
//! never on the same tests twice, so the tests whose verdicts differ are run again one at a
//! time on both libraries, and those verdicts count. The command fails while any test passes
//! on the reference alone.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::json::{self, Value};
use crate::test_c::{LOADER_PATH, compile, prepare};
use crate::util::{Result, fresh_dir, run_output, sha256_file, target_dir, workspace_root};

/// Where the pinned commit's archive comes from.
const ARCHIVE_URL: &str = "https://codeload.github.com/google/boringssl/tar.gz";

/// The configuration file every run is pointed at, one that doesn't exist.
const MISSING_CONFIG: &str = "/nonexistent/rustyssl-tests/openssl.cnf";

/// One library's results: each test's verdict (`PASS`, `FAIL`, `SKIP`) and the runner's
/// message for a failure.
struct Run {
    verdicts: BTreeMap<String, (String, String)>,
    /// The shim's failure log: per argument hash, its first error entries.
    log: BTreeMap<String, String>,
    unimplemented: BTreeMap<String, usize>,
}

/// What the command line chose: the tests' patterns, and the runner's parallelism.
struct Options {
    patterns: Vec<String>,
    workers: Option<usize>,
}

fn options(args: &[String]) -> Result<Options> {
    let mut patterns = Vec::new();
    let mut workers = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--workers" {
            let n = it.next().ok_or("--workers needs a count")?;
            workers = Some(
                n.parse::<usize>()
                    .ok()
                    .filter(|&n| n > 0)
                    .ok_or_else(|| format!("--workers: bad count `{n}`"))?,
            );
        } else {
            patterns.push(a.clone());
        }
    }
    Ok(Options { patterns, workers })
}

pub fn run(args: &[String]) -> Result {
    let opts = options(args)?;
    let root = workspace_root();
    let (commit, sum) = pin(&root)?;
    let source = fetch(&root, &commit, &sum)?;
    let work = target_dir(&root).join("xtask/test-bogo");
    fs::create_dir_all(&work)?;
    let runner = build_runner(&source, &work, &commit)?;
    let (reference, dist) = prepare(&root)?;
    let shim = work.join("shim");
    compile(&root.join("tests/bogo/shim.c"), &shim, &dist, &reference)?;

    let config = root.join("tests/bogo/config.json");
    let runner_dir = source.join("ssl/test/runner");
    let theirs = execute(
        &runner,
        &runner_dir,
        &shim,
        &config,
        &reference.join("lib"),
        &work,
        "reference",
        &opts,
    )?;
    let ours = execute(
        &runner,
        &runner_dir,
        &shim,
        &config,
        &dist.join("lib"),
        &work,
        "rustyssl",
        &opts,
    )?;

    let (mut theirs, mut ours) = (theirs, ours);
    let differing: Vec<String> = theirs
        .verdicts
        .iter()
        .filter(|(test, (v, _))| {
            ours.verdicts
                .get(*test)
                .is_some_and(|(o, _)| (v == "PASS") != (o == "PASS"))
        })
        .map(|(test, _)| test.clone())
        .collect();
    if !differing.is_empty() && opts.workers != Some(1) {
        println!(
            "{} tests differ under load; running them again one at a time...",
            differing.len()
        );
        let serial = Options {
            patterns: differing.clone(),
            workers: Some(1),
        };
        let lib = |dir: &Path| dir.join("lib");
        for (run, dir, name) in [
            (&mut theirs, &reference, "reference-serial"),
            (&mut ours, &dist, "rustyssl-serial"),
        ] {
            let again = execute(
                &runner,
                &runner_dir,
                &shim,
                &config,
                &lib(dir),
                &work,
                name,
                &serial,
            )?;
            for test in &differing {
                if let Some(v) = again.verdicts.get(test) {
                    run.verdicts.insert(test.clone(), v.clone());
                }
            }
            run.log.extend(again.log);
        }
    }

    let report = target_dir(&root).join("bogo-report.md");
    let regressions = write_report(&report, &commit, &theirs, &ours)?;
    let passed = |r: &Run| r.verdicts.values().filter(|(v, _)| v == "PASS").count();
    println!(
        "BoGo: {} tests; the reference passes {}, rustyssl {}; {} pass on the reference alone (report: {})",
        theirs.verdicts.len(),
        passed(&theirs),
        passed(&ours),
        regressions,
        report.display()
    );
    if regressions > 0 {
        return Err(format!(
            "{regressions} BoGo tests pass on the reference but not on rustyssl; see {}",
            report.display()
        )
        .into());
    }
    Ok(())
}

/// The pinned commit and its archive's checksum, from `tests/bogo/pin.txt`.
fn pin(root: &Path) -> Result<(String, String)> {
    let text = fs::read_to_string(root.join("tests/bogo/pin.txt"))?;
    let (mut commit, mut sum) = (None, None);
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match line.split_once(' ') {
            Some(("commit", c)) => commit = Some(c.trim().to_owned()),
            Some(("sha256", s)) => sum = Some(s.trim().to_owned()),
            _ => return Err(format!("pin.txt: bad line `{line}`").into()),
        }
    }
    Ok((
        commit.ok_or("pin.txt has no commit")?,
        sum.ok_or("pin.txt has no sha256")?,
    ))
}

/// The pinned source tree, fetched, checked and unpacked unless it already is.
fn fetch(root: &Path, commit: &str, sum: &str) -> Result<PathBuf> {
    let data = target_dir(root).join("testdata");
    fs::create_dir_all(&data)?;
    let archive = data.join(format!("boringssl-{commit}.tar.gz"));
    let tree = data.join(format!("boringssl-{commit}"));
    let done = tree.join(".rustyssl-verified");
    if done.exists() {
        return Ok(tree);
    }
    if !archive.exists() || sha256_file(&archive)? != sum {
        println!("Fetching BoringSSL {commit}...");
        run_output(
            Command::new("curl")
                .args(["-fsSL", "--retry", "3", "-o"])
                .arg(&archive)
                .arg(format!("{ARCHIVE_URL}/{commit}")),
        )?;
    }
    let got = sha256_file(&archive)?;
    if got != sum {
        return Err(format!(
            "{}: SHA-256 {got}, but tests/bogo/pin.txt pins {sum}",
            archive.display()
        )
        .into());
    }
    // The archive's single top-level directory is `boringssl-<commit>`.
    if tree.exists() {
        fs::remove_dir_all(&tree)?;
    }
    run_output(
        Command::new("tar")
            .arg("-xzf")
            .arg(&archive)
            .arg("-C")
            .arg(&data),
    )?;
    if !tree.join("ssl/test/runner").is_dir() {
        return Err(format!("{} has no ssl/test/runner", tree.display()).into());
    }
    fs::write(&done, sum)?;
    Ok(tree)
}

/// The runner's test binary, built once per commit (Go checks the modules against go.sum).
fn build_runner(source: &Path, work: &Path, commit: &str) -> Result<PathBuf> {
    let runner = work.join(format!("runner-{commit}.test"));
    if runner.exists() {
        return Ok(runner);
    }
    println!("Building BoGo's runner...");
    run_output(
        Command::new("go")
            .current_dir(source)
            .env("GOTOOLCHAIN", "local")
            .env("GOFLAGS", "-mod=readonly")
            .args(["test", "-c", "-o"])
            .arg(&runner)
            .arg("./ssl/test/runner"),
    )?;
    Ok(runner)
}

/// Runs every test (or those `patterns` match) with the shim on the libraries in `lib_dir`.
#[expect(clippy::too_many_arguments, reason = "the runner's inputs, each named")]
fn execute(
    runner: &Path,
    runner_dir: &Path,
    shim: &Path,
    config: &Path,
    lib_dir: &Path,
    work: &Path,
    name: &str,
    opts: &Options,
) -> Result<Run> {
    println!("Running BoGo on {name}...");
    let json_path = work.join(format!("{name}.json"));
    let log_dir = work.join(format!("{name}-log"));
    fresh_dir(&log_dir)?;
    let _ = fs::remove_file(&json_path);
    let mut cmd = Command::new(runner);
    cmd.current_dir(runner_dir)
        .env(LOADER_PATH, lib_dir)
        .env("OPENSSL_MODULES", crate::test_c::modules_of(lib_dir))
        .env("OPENSSL_CONF", MISSING_CONFIG)
        .env("BOGO_SHIM_LOG", &log_dir)
        .arg("-shim-path")
        .arg(shim)
        .arg("-shim-config")
        .arg(config)
        .args([
            "-allow-unimplemented",
            "-loose-errors",
            "-pipe",
            "-json-output",
        ])
        .arg(&json_path);
    if !opts.patterns.is_empty() {
        cmd.arg("-test").arg(opts.patterns.join(";"));
    }
    if let Some(n) = opts.workers {
        cmd.arg("-num-workers").arg(n.to_string());
    }
    // The runner exits non-zero when a test fails; the JSON output is what counts.
    let output = cmd
        .output()
        .map_err(|e| format!("cannot run {}: {e}", runner.display()))?;
    fs::write(work.join(format!("{name}.out")), &output.stdout)?;
    let text = fs::read_to_string(&json_path).map_err(|e| {
        format!(
            "the runner wrote no results ({e}); it said:\n{}",
            String::from_utf8_lossy(&output.stderr)
        )
    })?;
    let results = json::parse(&text)?;
    let mut verdicts = BTreeMap::new();
    if let Some(Value::Object(tests)) = results.get("tests") {
        for (test, result) in tests {
            let verdict = result.get("actual").and_then(Value::as_str).unwrap_or("?");
            let error = result.get("error").and_then(Value::as_str).unwrap_or("");
            verdicts.insert(test.clone(), (verdict.to_owned(), error.to_owned()));
        }
    } else {
        return Err(format!("{}: no `tests` object", json_path.display()).into());
    }
    let mut log = BTreeMap::new();
    let mut unimplemented = BTreeMap::new();
    for entry in fs::read_dir(&log_dir)? {
        let path = entry?.path();
        let Some(file) = path.file_name().and_then(|n| n.to_str()).map(str::to_owned) else {
            continue;
        };
        let content = fs::read_to_string(&path)?;
        if file == "unimplemented" {
            for line in content.lines() {
                *unimplemented.entry(line.to_owned()).or_insert(0) += 1;
            }
        } else {
            log.insert(file, content);
        }
    }
    Ok(Run {
        verdicts,
        log,
        unimplemented,
    })
}

/// What a failure is grouped by: the first error-queue entry the shim printed (its code,
/// library, function and reason, without the source location), else its first message, else
/// the runner's own complaint.
fn first_error(message: &str) -> String {
    let mut stderr = false;
    let mut first_line = None;
    for line in message.lines().map(str::trim) {
        if line.starts_with("stderr:") {
            stderr = true;
            continue;
        }
        if line.starts_with("local:") {
            if first_line.is_none() {
                first_line = Some(line.to_owned());
            }
            break;
        }
        if !stderr || line.is_empty() {
            continue;
        }
        if let Some(at) = line.find(":error:") {
            let entry = line.get(at.saturating_add(7)..).unwrap_or(line);
            // `code:library:function:reason:file:line:data`
            let fields: Vec<&str> = entry.splitn(5, ':').collect();
            return fields.get(..4).map_or(entry.to_owned(), |f| f.join(":"));
        }
        if first_line.is_none()
            && !line.starts_with("SSL error:")
            && !line.starts_with("Connection ")
        {
            first_line = Some(line.to_owned());
        }
    }
    first_line.unwrap_or_else(|| message.lines().next().unwrap_or("").trim().to_owned())
}

/// A failure log's entries (without its argument lines), sorted.
fn log_entries(log: &str) -> Vec<&str> {
    let mut v: Vec<&str> = log
        .lines()
        .skip(1)
        .filter(|l| !l.starts_with("args:"))
        .collect();
    v.sort_unstable();
    v
}

/// Writes the report; returns how many tests pass on the reference but not on rustyssl.
fn write_report(path: &Path, commit: &str, theirs: &Run, ours: &Run) -> Result<usize> {
    let count = |r: &Run, v: &str| r.verdicts.values().filter(|(x, _)| x == v).count();
    let mut regressions: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    let mut only_ours = Vec::new();
    let mut total = 0;
    for (test, (verdict, _)) in &theirs.verdicts {
        let (our_verdict, our_error) = ours
            .verdicts
            .get(test)
            .map_or(("missing", ""), |(v, e)| (v.as_str(), e.as_str()));
        if verdict == "PASS" && our_verdict != "PASS" {
            total += 1;
            let cause = if our_verdict == "FAIL" {
                first_error(our_error)
            } else {
                format!("({our_verdict})")
            };
            regressions.entry(cause).or_default().push(test);
        } else if verdict != "PASS" && our_verdict == "PASS" {
            only_ours.push(test.as_str());
        }
    }
    // Expected failures (passing on both) whose first error entries differ. Tests with the
    // same arguments share a log file and append to it in whatever order they finish, so the
    // entries are compared as a sorted multiset.
    let differing: BTreeSet<&String> = theirs
        .log
        .iter()
        .filter(|(hash, entry)| {
            ours.log
                .get(*hash)
                .is_some_and(|o| log_entries(o) != log_entries(entry))
        })
        .map(|(hash, _)| hash)
        .collect();

    let mut out = String::new();
    out.push_str("# BoGo on rustyssl\n\n");
    out.push_str(&format!(
        "Written by `cargo xtask test-bogo`: BoringSSL's runner at {commit}, driving `tests/bogo/shim.c` on the reference and on rustyssl. A test the reference passes must pass on rustyssl.\n\n"
    ));
    out.push_str(
        "| library | tests | pass | fail | skip (unimplemented) |\n|---|---:|---:|---:|---:|\n",
    );
    for (name, r) in [("reference", theirs), ("rustyssl", ours)] {
        out.push_str(&format!(
            "| {name} | {} | {} | {} | {} |\n",
            r.verdicts.len(),
            count(r, "PASS"),
            count(r, "FAIL"),
            count(r, "SKIP")
        ));
    }
    out.push_str(&format!(
        "\n## Passing on the reference, not on rustyssl: {total}\n\n"
    ));
    let mut causes: Vec<(&String, &Vec<&str>)> = regressions.iter().collect();
    causes.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(b.0)));
    for (cause, tests) in causes {
        out.push_str(&format!("### {} × `{cause}`\n\n", tests.len()));
        for test in tests {
            out.push_str(&format!("- {test}\n"));
        }
        out.push('\n');
    }
    out.push_str(&format!(
        "## Passing on rustyssl, not on the reference: {}\n\n",
        only_ours.len()
    ));
    for test in &only_ours {
        out.push_str(&format!("- {test}\n"));
    }
    out.push_str(&format!(
        "\n## Failed connections whose first error differs: {}\n\n",
        differing.len()
    ));
    out.push_str("The shim's arguments (paths reduced to file names), then the reference's first entry per failed connection and rustyssl's.\n\n");
    for hash in &differing {
        let a = theirs.log.get(*hash).map_or("", String::as_str);
        let b = ours.log.get(*hash).map_or("", String::as_str);
        let args = a
            .lines()
            .next()
            .unwrap_or("")
            .trim_start_matches("args:")
            .trim();
        let entries = |log: &str| log.lines().skip(1).collect::<Vec<_>>().join("; ");
        out.push_str(&format!(
            "- `{args}`\n  - reference: {}\n  - rustyssl: {}\n",
            entries(a),
            entries(b)
        ));
    }
    out.push_str("\n## Unimplemented in the shim (reference run), by test count\n\n");
    let mut flags: Vec<(&String, &usize)> = theirs.unimplemented.iter().collect();
    flags.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    for (flag, n) in flags {
        out.push_str(&format!("- {n} {flag}\n"));
    }
    fs::write(path, out)?;
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::first_error;

    #[test]
    fn groups_by_the_first_error_entry() {
        let message = "unexpected error\ngot:\n\tstderr:\n\t\tSSL error: 1\nConnection 1 failed.\n803F51E601000000:error:0A000119:SSL routines:tls_get_more_records:decryption failed or bad record mac:crates/x.rs:973:\n\tlocal: \"EOF\"\n";
        assert_eq!(
            first_error(message),
            "0A000119:SSL routines:tls_get_more_records:decryption failed or bad record mac"
        );
        let message = "unexpected failure\ngot:\n\tstderr:\n\t\tWrong certificate verification result\nSSL error: 5\n\tlocal: \"EOF\"\n";
        assert_eq!(
            first_error(message),
            "Wrong certificate verification result"
        );
        let message = "unexpected failure\ngot:\n\tstderr:\n\t\t\n\tlocal: \"bad reply\"\n";
        assert_eq!(first_error(message), "local: \"bad reply\"");
    }
}
