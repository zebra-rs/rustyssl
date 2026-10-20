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
//!
//! **ruby** (the openssl gem): its extension built against the reference (`extconf.rb
//! --with-openssl-dir`), each `test/openssl/test_*.rb` file run by Ruby's bundled test-unit
//! with `core_assertions` from the pinned test-unit-ruby-core; each test's mark in the verbose
//! output is its result. Needs `ruby` (skipped without it).
//!
//! **pyca** (pyca/cryptography): built against the reference (`OPENSSL_DIR`) into a virtualenv
//! under `target/consumers/build/` with the build requirements its CI pins by hash and the test
//! requirements at its CI's versions; its `tests` run by pytest over every core, each test's
//! `-rA` line its result. Needs Python 3 with `venv` (3.13 or 3.12 preferred, for wheels) and
//! network access to PyPI for those requirements (skipped without Python).
//!
//! **node** (Node.js): built once with `--shared-openssl` against the reference (long; kept under
//! `target/consumers/build/` until the pin changes), its `test/parallel/test-crypto*` and
//! `test-tls*` run by `tools/test.py` with TAP output, each `ok`/`not ok` line a result.
//!
//! **ngtcp2**: its `ossl` crypto backend (OpenSSL 3.5's third-party QUIC API,
//! `SSL_set_quic_tls_cbs`) and its `osslclient`/`osslserver` examples, built by cmake against the
//! reference with nghttp3 (pinned too) and libev (the system's); the submodules they build with
//! are pinned as trees of their own. Its examples' pytest suite (`examples/tests`: handshake,
//! resumption, early data, client certificates, ciphers; the client against the server over
//! loopback) runs in a virtualenv with pytest and cryptography. Needs cmake, libev (Debian
//! `libev-dev`, Homebrew `libev`) and Python 3 with `venv`; skipped without them.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::test_c::prepare;
use crate::test_providers::{Pin, Results, Side, cmake, fetch, parse_pins, pool, wait};
use crate::util::{Result, fresh_dir, run_logged, target_dir, workspace_root};

/// The consumers the command knows, as named on its command line.
const CONSUMERS: &[&str] = &["rust", "ruby", "pyca", "node", "ngtcp2"];

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

/// Runs `make(item)` per item on every side, in a pool; `results` makes the item's tests'
/// outcomes of its exit status and output (one test per item, or a file's tests).
fn run_tests(
    ctx: &Ctx<'_>,
    items: &[String],
    make: impl Fn(&str) -> Command + Send + Sync + Clone + 'static,
    results: fn(&str, bool, &str) -> Vec<(String, bool)>,
) -> Result<Vec<Vec<Outcome>>> {
    let mut all = Vec::new();
    for side in ctx.sides {
        let side = side.clone();
        let make = make.clone();
        let per_item = pool(items.to_vec(), ctx.jobs, move |item| {
            let mut cmd = make(item);
            side.env(&mut cmd)
                .env("OPENSSL_CONF", MISSING_CONFIG)
                .env("OPENSSL_MODULES", crate::test_c::modules_of(&side.lib))
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let (ok, out) = match cmd.spawn() {
                Ok(child) => wait_both(child).unwrap_or((false, String::new())),
                Err(e) => (false, format!("spawn: {e}")),
            };
            let mut outcomes: Vec<Outcome> = results(item, ok, &out)
                .into_iter()
                .map(|(name, passed)| Outcome {
                    name,
                    passed,
                    output: None,
                })
                .collect();
            // The run's output, once, with its first failing test (or the item when it
            // reported none: a crash before any test).
            if outcomes.is_empty() {
                outcomes.push(Outcome {
                    name: format!("{item} (no results)"),
                    passed: false,
                    output: Some(out),
                });
            } else if let Some(o) = outcomes.iter_mut().find(|o| !o.passed) {
                o.output = Some(out);
            }
            outcomes
        });
        all.push(per_item.into_iter().flatten().collect());
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
    let all = run_tests(ctx, &tests, make, |test, ok, out| {
        vec![(
            test.to_owned(),
            ok && out.contains("test result: ok. 1 passed"),
        )]
    })?;
    keep(ctx, "rust", all)
}

/// ruby/openssl: the gem's extension built against the reference, each `test/openssl/test_*.rb`
/// file run by Ruby's test-unit (`core_assertions` from the pinned test-unit-ruby-core).
fn run_ruby(ctx: &Ctx<'_>, pins: &[Pin]) -> Result<Vec<Results>> {
    if Command::new("ruby").arg("--version").output().is_err() {
        println!("ruby: skipped (no ruby on PATH)");
        return Ok(Vec::new());
    }
    let tree = fetch(&ctx.dir, ctx.pin(pins, "ruby-openssl")?)?;
    let core = fetch(&ctx.dir, ctx.pin(pins, "test-unit-ruby-core")?)?;
    let build = ctx.dir.join("build/ruby-openssl");
    let log = ctx.work.join("ruby-build.log");
    let ext = ["openssl.bundle", "openssl.so"];
    if !ext.iter().any(|e| build.join(e).exists()) {
        println!(
            "Building ruby/openssl's extension (log: {})...",
            log.display()
        );
        fresh_dir(&build)?;
        run_logged(
            Command::new("ruby")
                .arg(tree.join("ext/openssl/extconf.rb"))
                .arg(format!("--with-openssl-dir={}", ctx.reference.display()))
                .current_dir(&build),
            &log,
        )?;
        run_logged(
            Command::new("make")
                .arg(format!("-j{}", ctx.jobs))
                .current_dir(&build),
            &log,
        )?;
    }
    let mut files: Vec<String> = fs::read_dir(tree.join("test/openssl"))?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("test_") && n.ends_with(".rb"))
        .collect();
    files.sort();
    let load = [
        tree.join("lib"),
        build,
        core.join("lib"),
        tree.join("test/openssl"),
    ];
    let make = move |file: &str| {
        let mut cmd = Command::new("ruby");
        for dir in &load {
            cmd.arg("-I").arg(dir);
        }
        cmd.arg(format!("test/openssl/{file}"))
            .args(["-v", "--no-use-color"])
            .current_dir(&tree);
        cmd
    };
    let all = run_tests(ctx, &files, make, |_, _, out| test_unit_results(out))?;
    keep(ctx, "ruby", all)
}

/// pyca/cryptography: the package built against the reference in a virtualenv of its own
/// (the build requirements its CI pins with hashes, the test requirements at its CI's
/// versions), its `tests` run by pytest with `cryptography_vectors` from the same tree.
fn run_pyca(ctx: &Ctx<'_>, pins: &[Pin]) -> Result<Vec<Results>> {
    let Some(python) = ["python3.13", "python3.12", "python3"]
        .into_iter()
        .find(|p| Command::new(p).arg("--version").output().is_ok())
    else {
        println!("pyca: skipped (no python3 on PATH)");
        return Ok(Vec::new());
    };
    let pin = ctx.pin(pins, "cryptography")?;
    let tree = fetch(&ctx.dir, pin)?;
    let venv = ctx.dir.join("build/cryptography-venv");
    let stamp = venv.join(format!("built-{}", pin.commit));
    let py = venv.join("bin/python");
    if !stamp.exists() {
        let log = ctx.work.join("pyca-build.log");
        println!("Building pyca/cryptography (log: {})...", log.display());
        fresh_dir(&venv)?;
        run_logged(Command::new(python).args(["-m", "venv"]).arg(&venv), &log)?;
        let pip = || {
            let mut cmd = Command::new(&py);
            cmd.args(["-m", "pip", "install", "-q"]);
            cmd
        };
        run_logged(
            pip()
                .arg("--require-hashes")
                .arg("-r")
                .arg(tree.join(".github/requirements/build-requirements.txt")),
            &log,
        )?;
        run_logged(
            pip()
                .arg("-c")
                .arg(tree.join("ci-constraints-requirements.txt"))
                .args([
                    "pytest",
                    "pytest-benchmark",
                    "pytest-xdist",
                    "pretend",
                    "certifi",
                ]),
            &log,
        )?;
        // maturin's backend runs `maturin` from PATH.
        let path = std::env::join_paths(std::iter::once(venv.join("bin")).chain(
            std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()),
        ))?;
        run_logged(
            pip()
                .arg("--no-build-isolation")
                .arg(&tree)
                .env("PATH", path)
                .env("OPENSSL_DIR", ctx.reference),
            &log,
        )?;
        fs::write(&stamp, "")?;
    }
    let jobs = ctx.jobs.to_string();
    let make = move |_: &str| {
        let mut cmd = Command::new(&py);
        cmd.args([
            "-m",
            "pytest",
            "tests",
            "-n",
            &jobs,
            "-q",
            "-rA",
            "-p",
            "no:cacheprovider",
        ])
        .arg("--benchmark-disable")
        .current_dir(&tree)
        .env("PYTHONPATH", "vectors");
        cmd
    };
    // One run per side (pytest-xdist spreads it over the cores).
    let all = run_tests(ctx, &["tests".to_owned()], make, |_, _, out| {
        pytest_results(out)
    })?;
    keep(ctx, "pyca", all)
}

/// Node.js: built once with `--shared-openssl` against the reference (a long build, kept under
/// `target/consumers/build/`), its `test/parallel/test-crypto*` and `test-tls*` run by
/// `tools/test.py` with TAP output.
fn run_node(ctx: &Ctx<'_>, pins: &[Pin]) -> Result<Vec<Results>> {
    let Some(python) = ["python3.13", "python3.12", "python3"]
        .into_iter()
        .find(|p| Command::new(p).arg("--version").output().is_ok())
    else {
        println!("node: skipped (no python3 on PATH)");
        return Ok(Vec::new());
    };
    let pin = ctx.pin(pins, "node")?;
    let tree = fetch(&ctx.dir, pin)?;
    let node = tree.join("out/Release/node");
    if !node.exists() {
        let log = ctx.work.join("node-build.log");
        println!(
            "Building Node.js (log: {}; this takes a while)...",
            log.display()
        );
        run_logged(
            Command::new(python)
                .arg("configure.py")
                .arg("--shared-openssl")
                .arg(format!(
                    "--shared-openssl-includes={}",
                    ctx.reference.join("include").display()
                ))
                .arg(format!(
                    "--shared-openssl-libpath={}",
                    ctx.reference.join("lib").display()
                ))
                .current_dir(&tree),
            &log,
        )?;
        run_logged(
            Command::new("make")
                .arg(format!("-j{}", ctx.jobs))
                .current_dir(&tree),
            &log,
        )?;
    }
    let jobs = ctx.jobs.to_string();
    let make = move |_: &str| {
        let mut cmd = Command::new(python);
        cmd.args([
            "tools/test.py",
            "-p",
            "tap",
            "-j",
            &jobs,
            "--timeout",
            "240",
        ])
        .arg("--shell")
        .arg(&node)
        .args(["parallel/test-crypto*", "parallel/test-tls*"])
        .current_dir(&tree);
        cmd
    };
    let all = run_tests(ctx, &["tests".to_owned()], make, |_, _, out| {
        tap_results(out)
    })?;
    keep(ctx, "node", all)
}

/// The examples' test requirements (`examples/tests/README.rst`: pytest and cryptography).
const NGTCP2_TEST_REQUIREMENTS: &[&str] = &["pytest==8.3.5", "cryptography==44.0.2"];

/// Copies a pinned submodule's tree into its place in its parent's tree (once: a GitHub
/// tarball leaves the directory empty).
fn submodule(ctx: &Ctx<'_>, pins: &[Pin], name: &str, place: &Path) -> Result {
    let tree = fetch(&ctx.dir, ctx.pin(pins, name)?)?;
    if fs::read_dir(place).is_ok_and(|mut d| d.next().is_some()) {
        return Ok(());
    }
    fs::create_dir_all(place)?;
    crate::util::run_output(Command::new("cp").arg("-R").arg(tree.join(".")).arg(place))?;
    Ok(())
}

/// ngtcp2: nghttp3 and ngtcp2 (its `ossl` backend and examples) built against the reference,
/// the examples' pytest suite run over loopback.
fn run_ngtcp2(ctx: &Ctx<'_>, pins: &[Pin]) -> Result<Vec<Results>> {
    if Command::new("cmake").arg("--version").output().is_err() {
        println!("ngtcp2: skipped (no cmake on PATH)");
        return Ok(Vec::new());
    }
    let Some(python) = ["python3.13", "python3.12", "python3"]
        .into_iter()
        .find(|p| Command::new(p).arg("--version").output().is_ok())
    else {
        println!("ngtcp2: skipped (no python3 on PATH)");
        return Ok(Vec::new());
    };
    let nghttp3 = fetch(&ctx.dir, ctx.pin(pins, "nghttp3")?)?;
    submodule(ctx, pins, "nghttp3-sfparse", &nghttp3.join("lib/sfparse"))?;
    let tree = fetch(&ctx.dir, ctx.pin(pins, "ngtcp2")?)?;
    submodule(
        ctx,
        pins,
        "ngtcp2-urlparse",
        &tree.join("third-party/urlparse"),
    )?;
    let build = ctx.dir.join("build/ngtcp2");
    let prefix = build.join("prefix");
    let log = ctx.work.join("ngtcp2-build.log");
    cmake(
        &nghttp3,
        &build.join("nghttp3"),
        &[
            "-DENABLE_LIB_ONLY=ON".to_owned(),
            "-DBUILD_TESTING=OFF".to_owned(),
            "-DENABLE_SHARED_LIB=OFF".to_owned(),
            "-DENABLE_STATIC_LIB=ON".to_owned(),
            "-DCMAKE_BUILD_TYPE=RelWithDebInfo".to_owned(),
            format!("-DCMAKE_INSTALL_PREFIX={}", prefix.display()),
        ],
        true,
        &log,
    )?;
    // libev where Homebrew keeps it (it isn't on the default search path there).
    let mut search = vec![prefix.display().to_string()];
    for p in ["/opt/homebrew/opt/libev", "/usr/local/opt/libev"] {
        if Path::new(p).is_dir() {
            search.push(p.to_owned());
        }
    }
    let ngbuild = build.join("ngtcp2");
    cmake(
        &tree,
        &ngbuild,
        &[
            "-DENABLE_OPENSSL=ON".to_owned(),
            "-DBUILD_TESTING=OFF".to_owned(),
            "-DCMAKE_BUILD_TYPE=RelWithDebInfo".to_owned(),
            format!("-DOPENSSL_ROOT_DIR={}", ctx.reference.display()),
            format!("-DCMAKE_PREFIX_PATH={}", search.join(";")),
        ],
        false,
        &log,
    )?;
    let examples = tree.join("examples");
    for program in ["osslclient", "osslserver"] {
        let built = ngbuild.join("examples").join(program);
        if !built.exists() {
            println!(
                "ngtcp2: skipped (no {program}: its examples need libev; log: {})",
                log.display()
            );
            return Ok(Vec::new());
        }
        fs::copy(&built, examples.join(program))?;
    }
    // What its configure would write (cmake doesn't): the ossl examples only.
    fs::write(
        examples.join("tests/config.ini"),
        "[ngtcp2]\nversion = rustyssl\nexamples = yes\n\n[crypto]\nossl = yes\n\n\
         [examples]\nport = 4433\nossl = yes\n\n[clients]\nossl = osslclient\n\n\
         [servers]\nossl = osslserver\n",
    )?;
    let venv = build.join("venv");
    let py = venv.join("bin/python");
    let stamp = venv.join("rustyssl-requirements");
    let wanted = NGTCP2_TEST_REQUIREMENTS.join("\n");
    if fs::read_to_string(&stamp).ok().as_deref() != Some(wanted.as_str()) {
        fresh_dir(&venv)?;
        run_logged(Command::new(python).args(["-m", "venv"]).arg(&venv), &log)?;
        run_logged(
            Command::new(&py)
                .args(["-m", "pip", "install", "-q"])
                .args(NGTCP2_TEST_REQUIREMENTS),
            &log,
        )?;
        fs::write(&stamp, &wanted)?;
    }
    let dir = examples.join("tests");
    let make = move |_: &str| {
        let mut cmd = Command::new(&py);
        cmd.args(["-m", "pytest", "-q", "-rA", "-p", "no:cacheprovider"])
            .current_dir(&dir);
        cmd
    };
    // One run per side: the server listens on a fixed port.
    let all = run_tests(ctx, &["examples".to_owned()], make, |_, _, out| {
        pytest_results(out)
    })?;
    keep(ctx, "ngtcp2", all)
}

/// Each test's outcome in TAP: `ok N name` passes (a `# skip` isn't a result), `not ok N
/// name` fails.
fn tap_results(out: &str) -> Vec<(String, bool)> {
    out.lines()
        .filter_map(|l| {
            let (passed, rest) = match l.strip_prefix("not ok ") {
                Some(r) => (false, r),
                None => (true, l.strip_prefix("ok ")?),
            };
            let (_, rest) = rest.split_once(' ')?;
            let (name, directive) = rest.split_once(" # ").unwrap_or((rest, ""));
            let skip = directive.to_ascii_lowercase().starts_with("skip");
            (!skip).then(|| (name.trim().to_owned(), passed))
        })
        .collect()
}

/// Each test's outcome in pytest's `-rA` summary: `PASSED <id>`, `FAILED <id> - ...`,
/// `ERROR <id> - ...`, `XFAIL`/`XPASS <id>` (skips are listed by place, not by test, and so
/// aren't results; a test skipped on one side only is missing there).
fn pytest_results(out: &str) -> Vec<(String, bool)> {
    out.lines()
        .filter_map(|l| {
            let (kind, rest) = l.split_once(' ')?;
            let id = rest.split(" - ").next()?.trim();
            let passed = match kind {
                "PASSED" | "XFAIL" => true,
                "FAILED" | "ERROR" | "XPASS" => false,
                _ => return None,
            };
            id.contains("::").then(|| (id.to_owned(), passed))
        })
        .collect()
}

/// Each test's outcome in test-unit's verbose output: `Class::Name:` lines name the case,
/// `  test_name:<tabs><mark>: (time)` its tests, `.` a pass (failures, errors, omissions and
/// pendings are not).
fn test_unit_results(out: &str) -> Vec<(String, bool)> {
    let mut case = String::new();
    let mut results = Vec::new();
    for line in out.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("test") {
            let Some((name, rest)) = trimmed.split_once(':') else {
                continue;
            };
            let mark = rest.trim_start_matches(['\t', ' ']).chars().next();
            if !name.contains(' ')
                && let Some(mark) = mark.filter(|c| ".FEOPN".contains(*c))
            {
                results.push((format!("{case}#{name}"), mark == '.'));
            }
        } else if let Some(name) = trimmed.strip_suffix(':')
            && !name.is_empty()
            && !name.contains([' ', '\t'])
        {
            case = name.to_owned();
        }
    }
    results
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
            "ruby" => run_ruby(&ctx, &pins)?,
            "pyca" => run_pyca(&ctx, &pins)?,
            "node" => run_node(&ctx, &pins)?,
            "ngtcp2" => run_ngtcp2(&ctx, &pins)?,
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
    fn reads_tap_results() {
        let out = "TAP version 13\n1..4\nok 1 parallel/test-crypto-a\n  ---\n  duration_ms: 5\n\
                   not ok 2 parallel/test-tls-b\nok 3 parallel/test-crypto-c # skip no ICU\n\
                   ok 4 parallel/test-tls-d # TODO later\n";
        assert_eq!(
            tap_results(out),
            [
                ("parallel/test-crypto-a".to_owned(), true),
                ("parallel/test-tls-b".to_owned(), false),
                ("parallel/test-tls-d".to_owned(), true),
            ]
        );
    }

    #[test]
    fn reads_pytest_results() {
        let out = "....\n=== short test summary info ===\nPASSED tests/a.py::test_x[p1]\n\
                   FAILED tests/b.py::TestB::test_y - assert 1 == 2\nERROR tests/c.py::test_z\n\
                   SKIPPED [3] tests/d.py:12: no wycheproof\n4 passed, 1 failed in 1s\n";
        assert_eq!(
            pytest_results(out),
            [
                ("tests/a.py::test_x[p1]".to_owned(), true),
                ("tests/b.py::TestB::test_y".to_owned(), false),
                ("tests/c.py::test_z".to_owned(), false),
            ]
        );
    }

    #[test]
    fn reads_test_unit_results() {
        let out = "Loaded suite test/openssl/test_hmac\nStarted\nOpenSSL::TestCase: \n  \
                   OpenSSL::TestHMAC: \n    test_dup:\t\t\t\t\t\t.: (0.000032)\n    \
                   test_eq:\t\t\t\t\t\tF\n===\nFailure: test_eq(OpenSSL::TestHMAC)\n    \
                   test_x:\t\t\t\t\t\tO: (0.1)\n\nFinished in 0.0009 seconds.\n";
        assert_eq!(
            test_unit_results(out),
            [
                ("OpenSSL::TestHMAC#test_dup".to_owned(), true),
                ("OpenSSL::TestHMAC#test_eq".to_owned(), false),
                ("OpenSSL::TestHMAC#test_x".to_owned(), false),
            ]
        );
    }

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
