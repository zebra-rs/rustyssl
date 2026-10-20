//! `cargo xtask test-consumers [--jobs N] [--reference-only] [consumer...]`: applications'
//! and bindings' own test suites (TEST_PLAN.md, layer L8), built once against the reference
//! OpenSSL and run twice, with the reference's libraries and with rustyssl's (`target/dist`)
//! swapped in through the loader path, as a binary built against OpenSSL would load rustyssl.
//!
//! `tests/consumers/pins.txt` pins each project's sources to a release commit, fetched as a
//! GitHub tarball into `target/consumers/` and checked against its SHA-256 sum. Each test runs
//! in a process of its own (one that aborts can't hide the rest), both sides in the same
//! configuration (`OPENSSL_CONF` naming a file that doesn't exist, as the other harnesses do).
//! A test that passes on the reference and fails (or is missing) on rustyssl is a failure; one
//! that fails on both (an expired test certificate, say) is reported but isn't counted.
//! Results go to `target/consumers-report.md`, each failing run's output under
//! `target/xtask/test-consumers/<consumer>/`.
//!
//! **rust** (rust-openssl): the `openssl` crate's tests, built with `OPENSSL_DIR` naming the
//! reference (openssl-sys links its shared libraries), each run as `<test> --exact` from the
//! crate's directory.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::test_c::prepare;
use crate::test_providers::{Pin, Results, Side, fetch, parse_pins, pool, wait};
use crate::util::{Result, fresh_dir, run_logged, target_dir, workspace_root};

/// The consumers the command knows, as named on its command line.
const CONSUMERS: &[&str] = &["rust"];

/// How long one test may run.
const TEST_TIMEOUT: Duration = Duration::from_secs(300);

/// The configuration file both runs are pointed at (one that doesn't exist).
const MISSING_CONFIG: &str = "/nonexistent/rustyssl-tests/openssl.cnf";

/// What a consumer's run needs: the reference, the sides, the work and output directories.
struct Ctx<'a> {
    reference: &'a Path,
    sides: &'a [Side],
    jobs: usize,
    /// `target/consumers`: downloads, trees and builds.
    dir: PathBuf,
    /// `target/xtask/test-consumers`: logs and failing runs' output.
    work: PathBuf,
}

impl Ctx<'_> {
    fn pin<'p>(&self, pins: &'p [Pin], name: &str) -> Result<&'p Pin> {
        pins.iter()
            .find(|p| p.name == name)
            .ok_or_else(|| format!("tests/consumers/pins.txt pins no {name}").into())
    }
}

/// One test's outcome on one side, with its output when it failed.
struct Outcome {
    name: String,
    passed: bool,
    output: Option<String>,
}

/// A consumer's results on every side.
struct Report {
    consumer: &'static str,
    per_side: Vec<Results>,
}

/// Runs `cmd` per test (`argv(test)` its arguments) on every side, in a pool.
fn run_tests(
    ctx: &Ctx<'_>,
    tests: &[String],
    make: impl Fn(&str) -> Command + Send + Sync + Clone + 'static,
    passed: fn(bool, &str) -> bool,
) -> Result<Vec<Vec<Outcome>>> {
    let mut all = Vec::new();
    for side in ctx.sides {
        let side = side.clone();
        let make = make.clone();
        let outcomes = pool(tests.to_vec(), ctx.jobs, move |test| {
            let mut cmd = make(test);
            side.env(&mut cmd)
                .env("OPENSSL_CONF", MISSING_CONFIG)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let (ok, out) = match cmd.spawn() {
                Ok(child) => wait_both(child).unwrap_or((false, String::new())),
                Err(e) => (false, format!("spawn: {e}")),
            };
            let p = passed(ok, &out);
            Outcome {
                name: test.clone(),
                passed: p,
                output: (!p).then_some(out),
            }
        });
        all.push(outcomes);
    }
    Ok(all)
}

/// [`wait`] with standard error folded into the output.
fn wait_both(mut child: std::process::Child) -> Result<(bool, String)> {
    let mut err = child.stderr.take().ok_or("no stderr")?;
    let reader = std::thread::spawn(move || {
        let mut s = Vec::new();
        let _ = std::io::Read::read_to_end(&mut err, &mut s);
        String::from_utf8_lossy(&s).into_owned()
    });
    let (ok, mut out) = wait(child, TEST_TIMEOUT)?;
    out.push_str(&reader.join().map_err(|_| "reader panicked")?);
    Ok((ok, out))
}

/// Keeps failing runs' output under `dir/<side>/`, and returns the per-side results.
fn keep(ctx: &Ctx<'_>, consumer: &str, all: Vec<Vec<Outcome>>) -> Result<Vec<Results>> {
    let mut per_side = Vec::new();
    for (side, outcomes) in ctx.sides.iter().zip(all) {
        let dir = ctx.work.join(consumer).join(side.name);
        fs::create_dir_all(&dir)?;
        let mut results = Results::new();
        for o in outcomes {
            if let Some(out) = &o.output {
                let file: String = o
                    .name
                    .chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                            c
                        } else {
                            '_'
                        }
                    })
                    .collect();
                fs::write(dir.join(format!("{file}.log")), out)?;
            }
            results.insert(o.name, o.passed);
        }
        per_side.push(results);
    }
    Ok(per_side)
}

/// rust-openssl: the `openssl` crate's test binary, built against the reference.
fn run_rust(ctx: &Ctx<'_>, pins: &[Pin]) -> Result<Vec<Results>> {
    let tree = fetch(&ctx.dir, ctx.pin(pins, "rust-openssl")?)?;
    let build = ctx.dir.join("build/rust-openssl");
    let log = ctx.work.join("rust-build.log");
    println!("Building rust-openssl's tests (log: {})...", log.display());
    // The log gets cargo's JSON messages (standard output) among its diagnostics.
    run_logged(
        Command::new("cargo")
            .args(["test", "-p", "openssl", "--no-run", "--message-format=json"])
            .current_dir(&tree)
            .env("OPENSSL_DIR", ctx.reference)
            .env("CARGO_TARGET_DIR", &build),
        &log,
    )?;
    let exe = fs::read_to_string(&log)?
        .lines()
        .filter(|l| l.contains("\"reason\":\"compiler-artifact\"") && l.contains("\"test\":true"))
        .filter(|l| l.contains("\"name\":\"openssl\""))
        .find_map(executable)
        .ok_or("cargo built no test executable for the openssl crate")?;
    let crate_dir = tree.join("openssl");
    let list = Command::new(&exe)
        .args(["--list", "--format", "terse"])
        .current_dir(&crate_dir)
        .env(crate::test_c::LOADER_PATH, ctx.reference.join("lib"))
        .output()?;
    let tests: Vec<String> = String::from_utf8_lossy(&list.stdout)
        .lines()
        .filter_map(|l| l.strip_suffix(": test"))
        .map(str::to_owned)
        .collect();
    if tests.is_empty() {
        return Err("rust-openssl's test binary lists no tests".into());
    }
    let make = move |test: &str| {
        let mut cmd = Command::new(&exe);
        cmd.args([test, "--exact", "--test-threads=1"])
            .current_dir(&crate_dir);
        cmd
    };
    let all = run_tests(ctx, &tests, make, |ok, out| {
        ok && out.contains("test result: ok. 1 passed")
    })?;
    keep(ctx, "rust", all)
}

/// The `"executable"` of a cargo JSON artifact line.
fn executable(line: &str) -> Option<PathBuf> {
    let rest = line.split("\"executable\":\"").nth(1)?;
    let path = rest.split('"').next()?;
    (!path.is_empty()).then(|| PathBuf::from(path.replace("\\\\", "\\")))
}

/// Tallies each side's results and lists the failures that are rustyssl's alone.
fn compare(report: &Report, sides: &[Side]) -> Vec<String> {
    for (side, results) in sides.iter().zip(&report.per_side) {
        let passed = results.values().filter(|&&p| p).count();
        println!(
            "{} on {}: {passed} of {} tests pass",
            report.consumer,
            side.name,
            results.len()
        );
    }
    let [reference, ours] = report.per_side.as_slice() else {
        return Vec::new();
    };
    let mut regressions = Vec::new();
    for (test, ok) in reference {
        match ours.get(test) {
            _ if !ok => {}
            Some(true) => {}
            Some(false) => regressions.push(format!("{}: {test}", report.consumer)),
            None => regressions.push(format!("{}: {test} (missing on rustyssl)", report.consumer)),
        }
    }
    regressions
}

/// `target/consumers-report.md`: each consumer's counts and rustyssl's own failures.
fn write_report(
    root: &Path,
    reports: &[Report],
    sides: &[Side],
    regressions: &[String],
) -> Result<PathBuf> {
    let mut md = String::from(
        "# Consumer test suites on rustyssl\n\nWritten by `cargo xtask test-consumers` \
         (`tests/consumers/pins.txt`): each suite built against the reference, run with the \
         reference's libraries and with rustyssl's.\n\n| consumer |",
    );
    for side in sides {
        write!(md, " {} |", side.name)?;
    }
    md.push_str(" fail on rustyssl only |\n|---|");
    for _ in sides {
        md.push_str("---:|");
    }
    md.push_str("---:|\n");
    for r in reports {
        write!(md, "| {} |", r.consumer)?;
        for results in &r.per_side {
            let p = results.values().filter(|&&ok| ok).count();
            write!(md, " {p} of {} |", results.len())?;
        }
        let own = regressions
            .iter()
            .filter(|x| x.starts_with(&format!("{}:", r.consumer)))
            .count();
        writeln!(md, " {own} |")?;
    }
    if !regressions.is_empty() {
        md.push_str("\n## Failing on rustyssl only\n\n");
        for x in regressions {
            writeln!(md, "- {x}")?;
        }
    }
    let path = target_dir(root).join("consumers-report.md");
    fs::write(&path, md)?;
    Ok(path)
}

pub fn run(args: &[String]) -> Result {
    let root = workspace_root();
    let mut reference_only = false;
    let mut jobs = std::thread::available_parallelism().map_or(4, |n| n.get());
    let mut only = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--reference-only" => reference_only = true,
            "--jobs" => {
                jobs = it
                    .next()
                    .and_then(|n| n.parse().ok())
                    .filter(|&n| n > 0)
                    .ok_or("--jobs takes a positive number")?;
            }
            s if s.starts_with("--") => return Err(format!("unknown option {s}").into()),
            s if CONSUMERS.contains(&s) => only.push(s.to_owned()),
            s => {
                return Err(format!(
                    "unknown consumer {s}; the consumers are: {}",
                    CONSUMERS.join(", ")
                )
                .into());
            }
        }
    }
    let (reference, dist) = prepare(&root)?;
    let mut sides = vec![Side {
        name: "reference",
        lib: reference.join("lib"),
    }];
    if !reference_only {
        sides.push(Side {
            name: "rustyssl",
            lib: dist.join("lib"),
        });
    }
    let pins = parse_pins(&fs::read_to_string(root.join("tests/consumers/pins.txt"))?)?;
    let work = target_dir(&root).join("xtask/test-consumers");
    fresh_dir(&work)?;
    let ctx = Ctx {
        reference: &reference,
        sides: &sides,
        jobs,
        dir: target_dir(&root).join("consumers"),
        work,
    };
    let mut reports = Vec::new();
    let mut regressions = Vec::new();
    for c in CONSUMERS
        .iter()
        .filter(|c| only.is_empty() || only.iter().any(|o| o == *c))
    {
        let per_side = match *c {
            "rust" => run_rust(&ctx, &pins)?,
            _ => unreachable!(),
        };
        let report = Report {
            consumer: c,
            per_side,
        };
        regressions.extend(compare(&report, &sides));
        reports.push(report);
    }
    let path = write_report(&root, &reports, &sides, &regressions)?;
    if regressions.is_empty() {
        println!(
            "The consumers pass on rustyssl wherever they pass on the reference (report: {})",
            path.display()
        );
        Ok(())
    } else {
        for r in &regressions {
            println!("FAIL {r}");
        }
        Err(format!(
            "{} tests fail on rustyssl only (report: {})",
            regressions.len(),
            path.display()
        )
        .into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_cargo_executables() {
        let line = r#"{"reason":"compiler-artifact","executable":"/t/debug/deps/openssl-ab","fresh":false}"#;
        assert_eq!(
            executable(line),
            Some(PathBuf::from("/t/debug/deps/openssl-ab"))
        );
        assert_eq!(executable(r#"{"executable":null}"#), None);
    }

    #[test]
    fn regressions_are_rustyssl_failures_where_the_reference_passes() {
        let sides = [
            Side {
                name: "reference",
                lib: PathBuf::new(),
            },
            Side {
                name: "rustyssl",
                lib: PathBuf::new(),
            },
        ];
        let reference: Results = [
            ("a".to_owned(), true),
            ("b".to_owned(), false),
            ("c".to_owned(), true),
            ("d".to_owned(), true),
        ]
        .into();
        let ours: Results = [
            ("a".to_owned(), true),
            ("b".to_owned(), true),
            ("c".to_owned(), false),
        ]
        .into();
        let report = Report {
            consumer: "x",
            per_side: vec![reference, ours],
        };
        assert_eq!(
            compare(&report, &sides),
            ["x: c", "x: d (missing on rustyssl)"]
        );
    }
}
