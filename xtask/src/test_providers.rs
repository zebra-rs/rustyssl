//! `cargo xtask test-providers [--jobs N] [provider...]`: real third-party providers
//! (TEST_PLAN.md, layer L8), built against the reference OpenSSL and run on both libraries.
//!
//! `tests/providers/pins.txt` pins each project's sources to a commit, fetched as GitHub
//! tarballs into `target/providers/` and checked against their SHA-256 sums. Each is unpacked
//! into a directory of its own and built there once per pin (cmake, out of tree). The provider
//! module is the same file on both runs: only the libraries change, through the loader path,
//! as an application that loads it would see them.
//!
//! **oqs** (liboqs and oqs-provider): the provider's own suite (`ctest`: its signature, KEM,
//! library-context, TLS-group, TLS-signature, encoder/decoder and key-parameter programs),
//! its local algorithm scripts (`scripts/oqsprovider-{certgen,certverify,cmssign,ca,pkcs12gen}.sh`
//! for every signature algorithm, which `scripts/runtests.sh` runs), and the TLS handshakes of
//! `scripts/test_tls_full.py` (every signature algorithm's server against a client of each of
//! its groups) with the reference's `openssl` program. A program, script or handshake that fails
//! on rustyssl but not on the reference is a failure. Each run's output goes under
//! `target/xtask/test-providers/`.
//!
//! **pkcs11** (pkcs11-provider): its meson suite on the SoftHSM and NSS softokn tokens
//! (`meson test --suite softhsm|softokn`), each test's outcome from `testlog.json`. It needs
//! meson, ninja, SoftHSM (`softhsm2-util`), NSS's tools and softokn (`certutil`), OpenSC's
//! `pkcs11-tool`, GnuTLS's `p11tool`, `expect` and `xxd`, as the suite does, and skips with a
//! message without them (Linux CI has them; see AGENTS.md). The tools run on the side's
//! libraries too, through the loader path; the reference's `openssl` program comes first on
//! `PATH`.
//!
//! **tpm2** (tpm2-openssl): its `make check` against a software TPM, as its
//! `test/run-with-simulator` runs it: `swtpm` behind `tpm2-abrmd` on a private D-Bus session
//! bus, started afresh for each side (on the system's libraries), each test's outcome from its
//! `.trs` file. It needs autotools, `libtss2-dev`, `tpm2-abrmd`, `tpm2-tools`, `swtpm` and
//! `dbus-daemon`, and skips with a message without them. Both sides read the reference's
//! `apps/openssl.cnf` (the tests run `openssl req`, which needs one).

use std::collections::BTreeMap;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::test_c::{LOADER_PATH, prepare};
use crate::util::{
    Result, fresh_dir, run_logged, run_output, sha256_file, target_dir, workspace_root,
};

/// The providers the command knows.
const PROVIDERS: &[&str] = &["oqs", "pkcs11", "tpm2"];

/// The programs tpm2-openssl's tests need.
const TPM2_TOOLS: &[&str] = &[
    "autoreconf",
    "make",
    "pkg-config",
    "swtpm",
    "tpm2-abrmd",
    "tpm2_getcap",
    "dbus-daemon",
];

/// pkcs11-provider's token suites, and the programs they need.
const PKCS11_SUITES: &[&str] = &["softhsm", "softokn"];
const PKCS11_TOOLS: &[&str] = &[
    "meson",
    "ninja",
    "softhsm2-util",
    "certutil",
    "pkcs11-tool",
    "p11tool",
    "expect",
    "xxd",
];

/// How long a server may take to start, and a client to finish.
const START_TIMEOUT: Duration = Duration::from_secs(30);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(120);

/// oqs-provider's local algorithm scripts, in `runtests.sh`'s order.
const OQS_SCRIPTS: &[&str] = &["certgen", "certverify", "cmssign", "ca", "pkcs12gen"];

/// A pinned source tree.
pub(crate) struct Pin {
    pub(crate) name: String,
    pub(crate) repository: String,
    pub(crate) commit: String,
    pub(crate) sum: String,
}

pub(crate) fn parse_pins(text: &str) -> Result<Vec<Pin>> {
    let mut pins = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        let ["pin", name, repository, commit, sum] = words.as_slice() else {
            return Err(format!("malformed line: {line}").into());
        };
        pins.push(Pin {
            name: (*name).to_owned(),
            repository: (*repository).to_owned(),
            commit: (*commit).to_owned(),
            sum: (*sum).to_owned(),
        });
    }
    Ok(pins)
}

/// Fetches a pinned tarball (if it isn't there with its sum) and unpacks it, once per pin;
/// returns the tree.
pub(crate) fn fetch(dir: &Path, pin: &Pin) -> Result<PathBuf> {
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
    let repo = pin
        .repository
        .rsplit('/')
        .next()
        .ok_or("a pin without a repository name")?;
    let tree_dir = dir.join("trees").join(&pin.name);
    let tree = tree_dir.join(format!("{repo}-{}", pin.commit));
    let stamp = tree_dir.join("unpacked");
    if fs::read_to_string(&stamp).ok().as_deref() != Some(pin.sum.as_str()) {
        fresh_dir(&tree_dir)?;
        run_output(
            Command::new("tar")
                .arg("-xzf")
                .arg(&tarball)
                .arg("-C")
                .arg(&tree_dir),
        )?;
        if !tree.is_dir() {
            return Err(format!("{}: the tarball has no {}", pin.name, tree.display()).into());
        }
        fs::write(&stamp, &pin.sum)?;
    }
    Ok(tree)
}

/// Builds a cmake project once per pin (the stamp names its sources and options).
fn cmake(source: &Path, build: &Path, options: &[String], install: bool, log: &Path) -> Result {
    let stamp = build.join("rustyssl-built");
    let key = format!("{}\n{}", source.display(), options.join("\n"));
    if fs::read_to_string(&stamp).ok().as_deref() == Some(key.as_str()) {
        return Ok(());
    }
    fresh_dir(build)?;
    println!("Building {} (log: {})...", source.display(), log.display());
    run_logged(
        Command::new("cmake")
            .arg("-S")
            .arg(source)
            .arg("-B")
            .arg(build)
            .args(options),
        log,
    )?;
    let jobs = std::thread::available_parallelism().map_or(4, |n| n.get());
    let mut cmd = Command::new("cmake");
    cmd.arg("--build")
        .arg(build)
        .arg("-j")
        .arg(jobs.to_string());
    if install {
        cmd.args(["--target", "install"]);
    }
    run_logged(&mut cmd, log)?;
    fs::write(&stamp, key)?;
    Ok(())
}

/// One library a run uses.
#[derive(Clone)]
pub(crate) struct Side {
    pub(crate) name: &'static str,
    pub(crate) lib: PathBuf,
}

impl Side {
    /// `cmd` with this side's libraries first on the loader path (both variables: oqs-provider's
    /// scripts copy `LD_LIBRARY_PATH` into `DYLD_LIBRARY_PATH`, which macOS drops for `/bin/bash`).
    pub(crate) fn env<'a>(&self, cmd: &'a mut Command) -> &'a mut Command {
        cmd.env(LOADER_PATH, &self.lib)
            .env("LD_LIBRARY_PATH", &self.lib)
    }
}

/// Waits for `child` up to `timeout`, killing it after; its output and whether it exited 0.
pub(crate) fn wait(mut child: Child, timeout: Duration) -> Result<(bool, String)> {
    let mut out = child.stdout.take().ok_or("no stdout")?;
    let reader = std::thread::spawn(move || {
        let mut s = Vec::new();
        let _ = out.read_to_end(&mut s);
        String::from_utf8_lossy(&s).into_owned()
    });
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let text = reader.join().map_err(|_| "reader panicked")?;
    Ok((status.is_some_and(|s| s.success()), text))
}

/// Runs `work` over `items` on `jobs` threads, keeping their order.
pub(crate) fn pool<T: Send + Sync + 'static, R: Send + 'static>(
    items: Vec<T>,
    jobs: usize,
    work: impl Fn(&T) -> R + Send + Sync + 'static,
) -> Vec<R> {
    let items = Arc::new(items);
    let next = Arc::new(Mutex::new(0usize));
    let results = Arc::new(Mutex::new(BTreeMap::new()));
    let work = Arc::new(work);
    let threads: Vec<_> = (0..jobs.max(1))
        .map(|_| {
            let (items, next, results, work) = (
                Arc::clone(&items),
                Arc::clone(&next),
                Arc::clone(&results),
                Arc::clone(&work),
            );
            std::thread::spawn(move || {
                loop {
                    let i = {
                        let Ok(mut n) = next.lock() else { break };
                        let i = *n;
                        *n += 1;
                        i
                    };
                    let Some(item) = items.get(i) else { break };
                    let r = work(item);
                    if let Ok(mut m) = results.lock() {
                        m.insert(i, r);
                    }
                }
            })
        })
        .collect();
    for t in threads {
        let _ = t.join();
    }
    Arc::try_unwrap(results)
        .ok()
        .and_then(|m| m.into_inner().ok())
        .map(|m| m.into_values().collect())
        .unwrap_or_default()
}

/// A result per check (`program`, `script alg`, `tls sig group`): passed or not, per side.
pub(crate) type Results = BTreeMap<String, bool>;

/// oqs-provider's built tree and what its runs need.
struct Oqs {
    source: PathBuf,
    build: PathBuf,
    openssl: PathBuf,
    work: PathBuf,
    jobs: usize,
}

impl Oqs {
    fn modules(&self) -> PathBuf {
        self.build.join("lib")
    }

    /// `openssl` with oqs-provider configured, on `side`.
    fn openssl(&self, side: &Side) -> Command {
        let mut cmd = Command::new(&self.openssl);
        side.env(&mut cmd)
            .env("OPENSSL_MODULES", self.modules())
            .env("OPENSSL_CONF", self.source.join("scripts/openssl-ca.cnf"));
        cmd
    }

    /// The suite's programs (`ctest`), each one's outcome by name.
    fn programs(&self, side: &Side) -> Result<Results> {
        let list = run_output(
            Command::new("ctest")
                .arg("--test-dir")
                .arg(&self.build)
                .arg("-N"),
        )?;
        let names: Vec<&str> = list
            .lines()
            .filter_map(|l| l.split_once("Test #"))
            .filter_map(|(_, rest)| rest.split_once(": "))
            .filter_map(|(_, name)| name.split_whitespace().next())
            .collect();
        if names.is_empty() {
            return Err("ctest lists no tests".into());
        }
        let log = self.work.join(format!("{}.ctest.log", side.name));
        let mut cmd = Command::new("ctest");
        cmd.arg("--test-dir")
            .arg(&self.build)
            .args(["--output-on-failure", "-j"])
            .arg(self.jobs.to_string());
        side.env(&mut cmd);
        // Failing programs make it fail; their lines say which.
        let _ = run_logged(&mut cmd, &log);
        let passed = ctest_passed(&fs::read_to_string(&log)?);
        Ok(names
            .into_iter()
            .map(|n| (format!("program {n}"), passed.contains(n)))
            .collect())
    }

    /// The signature algorithms oqs-provider offers (`list -signature-algorithms`).
    fn signature_algorithms(&self, side: &Side) -> Result<Vec<String>> {
        let out = run_output(self.openssl(side).args(["list", "-signature-algorithms"]))?;
        Ok(out
            .lines()
            .filter(|l| l.contains("@ oqsprovider"))
            .filter_map(|l| l.split(" @ ").next())
            .map(|a| a.trim().to_owned())
            .collect())
    }

    /// The local algorithm scripts for each signature algorithm, each in its own directory.
    fn scripts(&self, side: &Side, algorithms: &[String]) -> Result<Results> {
        let root = self.work.join(side.name).join("scripts");
        fresh_dir(&root)?;
        let (source, openssl, modules) =
            (self.source.clone(), self.openssl.clone(), self.modules());
        let side2 = side.clone();
        let outcomes = pool(algorithms.to_vec(), self.jobs, move |alg| {
            let dir = root.join(alg);
            let mut results = Vec::new();
            if fs::create_dir_all(&dir).is_err() {
                return results;
            }
            for script in OQS_SCRIPTS {
                let mut cmd = Command::new("bash");
                cmd.arg(source.join(format!("scripts/oqsprovider-{script}.sh")))
                    .arg(alg)
                    .current_dir(&dir)
                    .env("OPENSSL_APP", &openssl)
                    .env("OPENSSL_MODULES", &modules)
                    .env("OPENSSL_CONF", source.join("scripts/openssl-ca.cnf"));
                side2.env(&mut cmd);
                let ok = run_logged(&mut cmd, &dir.join(format!("{script}.log"))).is_ok();
                results.push((format!("script {script} {alg}"), ok));
            }
            results
        });
        Ok(outcomes.into_iter().flatten().collect())
    }

    /// The signature algorithms TLS 1.3 offers with oqs-provider (`list
    /// -tls-signature-algorithms`): those of `algorithms` that it lists.
    fn tls_algorithms(&self, side: &Side, algorithms: &[String]) -> Result<Vec<String>> {
        let out = run_output(
            self.openssl(side)
                .args(["list", "-tls-signature-algorithms"]),
        )?;
        let listed: Vec<&str> = out.trim().split(':').collect();
        Ok(algorithms
            .iter()
            .filter(|a| listed.contains(&a.as_str()))
            .cloned()
            .collect())
    }

    /// oqs-provider's TLS groups: those `list -tls-groups` gives with it and not without.
    fn groups(&self, side: &Side) -> Result<Vec<String>> {
        let with = run_output(self.openssl(side).args(["list", "-tls1_3", "-tls-groups"]))?;
        let mut plain = Command::new(&self.openssl);
        side.env(&mut plain)
            .env("OPENSSL_CONF", "/nonexistent/rustyssl-tests/openssl.cnf");
        let without = run_output(plain.args(["list", "-tls1_3", "-tls-groups"]))?;
        let builtin: Vec<&str> = without.trim().split(':').collect();
        Ok(with
            .trim()
            .split(':')
            .filter(|g| !builtin.contains(g))
            .map(str::to_owned)
            .collect())
    }

    /// `test_tls_full.py`: each signature algorithm's server (TLS 1.3, X25519 and half the
    /// groups each, as the script splits them), and a client of each group.
    fn tls(&self, side: &Side, algorithms: &[String], groups: &[String]) -> Result<Results> {
        let root = self.work.join(side.name).join("tls");
        fresh_dir(&root)?;
        let half = groups.len() / 2;
        let halves = [
            groups.get(..half).unwrap_or(&[]),
            groups.get(half..).unwrap_or(&[]),
        ];
        let mut jobs = Vec::new();
        for alg in algorithms {
            for (i, h) in halves.iter().enumerate() {
                if !h.is_empty() {
                    jobs.push((alg.clone(), i, h.to_vec()));
                }
            }
        }
        let me = Arc::new(Oqs {
            source: self.source.clone(),
            build: self.build.clone(),
            openssl: self.openssl.clone(),
            work: root,
            jobs: 1,
        });
        let side2 = side.clone();
        let outcomes = pool(jobs, self.jobs, move |(alg, i, groups)| {
            me.server_and_clients(&side2, alg, *i, groups)
                .unwrap_or_else(|e| {
                    groups
                        .iter()
                        .map(|g| (format!("tls {alg} {g} ({e})"), false))
                        .collect()
                })
        });
        let mut results = Results::new();
        for r in outcomes.into_iter().flatten() {
            // A setup failure names itself; keep the check's own name for comparison.
            let name = r.0.split(" (").next().unwrap_or(&r.0).to_owned();
            results.insert(name, r.1);
        }
        Ok(results)
    }

    fn server_and_clients(
        &self,
        side: &Side,
        alg: &str,
        half: usize,
        groups: &[String],
    ) -> Result<Vec<(String, bool)>> {
        let dir = self.work.join(format!("{alg}-{half}"));
        fs::create_dir_all(&dir)?;
        let p = |s: &str| dir.join(s);
        let newkey = if alg == "rsa3072" { "rsa:3072" } else { alg };
        let log = p("setup.log");
        run_logged(
            self.openssl(side)
                .args(["req", "-x509", "-new", "-newkey", newkey, "-keyout"])
                .arg(p("CA.key"))
                .arg("-out")
                .arg(p("CA.crt"))
                .args(["-nodes", "-subj", "/CN=oqstest_CA", "-days", "365"]),
            &log,
        )?;
        run_logged(
            self.openssl(side)
                .args(["req", "-new", "-newkey", newkey, "-keyout"])
                .arg(p("srv.key"))
                .arg("-out")
                .arg(p("srv.csr"))
                .args(["-nodes", "-subj", "/CN=oqstest_server"]),
            &log,
        )?;
        run_logged(
            self.openssl(side)
                .args(["x509", "-req", "-in"])
                .arg(p("srv.csr"))
                .arg("-out")
                .arg(p("srv.crt"))
                .arg("-CA")
                .arg(p("CA.crt"))
                .arg("-CAkey")
                .arg(p("CA.key"))
                .args(["-CAcreateserial", "-days", "365"]),
            &log,
        )?;
        let (mut server, port) = self.start_server(side, &dir, groups)?;
        let mut results = Vec::new();
        for g in groups {
            let child = self
                .openssl(side)
                .args(["s_client", "-groups", g, "-CAfile"])
                .arg(p("CA.crt"))
                .args(["-verify_return_error", "-connect"])
                .arg(format!("127.0.0.1:{port}"))
                .current_dir(&dir)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn();
            let ok = match child {
                Ok(mut c) => {
                    if let Some(mut stdin) = c.stdin.take() {
                        use std::io::Write as _;
                        let _ = stdin.write_all(b"Q");
                    }
                    let (_, out) = wait(c, CLIENT_TIMEOUT)?;
                    let ok = out.contains("SSL handshake has read");
                    fs::write(dir.join(format!("client-{g}.log")), out)?;
                    ok
                }
                Err(_) => false,
            };
            results.push((format!("tls {alg} {g}"), ok));
        }
        let _ = server.kill();
        let _ = server.wait();
        Ok(results)
    }

    /// `s_server` on a free port, once it accepts.
    fn start_server(&self, side: &Side, dir: &Path, groups: &[String]) -> Result<(Child, u16)> {
        let mut last = String::new();
        for _ in 0..5 {
            let port = std::net::TcpListener::bind("127.0.0.1:0")?
                .local_addr()?
                .port();
            let mut child = self
                .openssl(side)
                .arg("s_server")
                .arg("-cert")
                .arg(dir.join("srv.crt"))
                .arg("-key")
                .arg(dir.join("srv.key"))
                .arg("-CAfile")
                .arg(dir.join("CA.crt"))
                .args(["-tls1_3", "-quiet", "-groups"])
                .arg(format!("x25519:{}", groups.join(":")))
                .arg("-accept")
                .arg(format!("127.0.0.1:{port}"))
                .current_dir(dir)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(fs::File::create(dir.join("server.log"))?)
                .spawn()?;
            let start = Instant::now();
            while start.elapsed() < START_TIMEOUT {
                if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                    return Ok((child, port));
                }
                if let Some(status) = child.try_wait()? {
                    last = format!("s_server exited ({status})");
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        Err(format!("cannot start s_server: {last}").into())
    }
}

/// The programs a ctest log reports as passed (`  1/7 Test #2: oqs_kems ....   Passed`).
fn ctest_passed(log: &str) -> std::collections::BTreeSet<String> {
    log.lines()
        .filter_map(|l| l.split_once("Test #"))
        .filter_map(|(_, rest)| rest.split_once(": "))
        .filter_map(|(_, rest)| {
            let mut words = rest.split_whitespace();
            let name = words.next()?;
            words.any(|w| w == "Passed").then(|| name.to_owned())
        })
        .collect()
}

/// Fetches and builds liboqs and oqs-provider; runs each side; compares.
fn run_oqs(root: &Path, reference: &Path, sides: &[Side], jobs: usize) -> Result<Vec<String>> {
    let dir = target_dir(root).join("providers");
    let pins = parse_pins(&fs::read_to_string(root.join("tests/providers/pins.txt"))?)?;
    let pin = |name: &str| {
        pins.iter()
            .find(|p| p.name == name)
            .ok_or_else(|| format!("pins.txt pins no {name}"))
    };
    let liboqs = fetch(&dir, pin("liboqs")?)?;
    let provider = fetch(&dir, pin("oqs-provider")?)?;
    let logs = dir.join("logs");
    fs::create_dir_all(&logs)?;
    let install = dir.join("install/liboqs");
    cmake(
        &liboqs,
        &dir.join("build/liboqs"),
        &[
            "-DOQS_BUILD_ONLY_LIB=ON".to_owned(),
            "-DBUILD_SHARED_LIBS=OFF".to_owned(),
            "-DCMAKE_POSITION_INDEPENDENT_CODE=ON".to_owned(),
            // liboqs's own primitives: nothing of it links OpenSSL.
            "-DOQS_USE_OPENSSL=OFF".to_owned(),
            "-DCMAKE_BUILD_TYPE=Release".to_owned(),
            format!("-DCMAKE_INSTALL_PREFIX={}", install.display()),
        ],
        true,
        &logs.join("liboqs.log"),
    )?;
    let build = dir.join("build/oqs-provider");
    cmake(
        &provider,
        &build,
        &[
            "-DCMAKE_BUILD_TYPE=Release".to_owned(),
            "-DBUILD_TESTING=ON".to_owned(),
            format!("-DOPENSSL_ROOT_DIR={}", reference.display()),
            format!(
                "-Dliboqs_DIR={}",
                install.join("lib/cmake/liboqs").display()
            ),
        ],
        false,
        &logs.join("oqs-provider.log"),
    )?;
    let work = target_dir(root).join("xtask/test-providers/oqs");
    fresh_dir(&work)?;
    let oqs = Oqs {
        source: provider,
        build,
        openssl: reference.join("bin/openssl"),
        work,
        jobs,
    };
    let mut all: Vec<Results> = Vec::new();
    for side in sides {
        let algorithms = oqs.signature_algorithms(side)?;
        let tls = oqs.tls_algorithms(side, &algorithms)?;
        let groups = oqs.groups(side)?;
        println!(
            "oqs on {}: {} signature algorithms ({} in TLS), {} TLS groups",
            side.name,
            algorithms.len(),
            tls.len(),
            groups.len()
        );
        let mut results = oqs.programs(side)?;
        results.extend(oqs.scripts(side, &algorithms)?);
        results.extend(oqs.tls(side, &tls, &groups)?);
        all.push(results);
    }
    compare("oqs", sides, &all)
}

/// Whether `program` is on `PATH`.
fn have(program: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|d| d.join(program).is_file()))
}

/// The tests a meson `testlog.json` reports as passed, and all it reports (one JSON object a
/// line).
fn meson_outcomes(log: &str) -> Result<Vec<(String, bool)>> {
    let mut out = Vec::new();
    for line in log.lines().filter(|l| !l.trim().is_empty()) {
        let v = crate::json::parse(line)?;
        let name = v
            .get("name")
            .and_then(crate::json::Value::as_str)
            .ok_or("a test without a name")?;
        let result = v.get("result").and_then(crate::json::Value::as_str);
        // `pkcs11-provider:softhsm / basic`: the suite is the check's already.
        let name = name.rsplit(" / ").next().unwrap_or(name);
        out.push((name.to_owned(), result == Some("OK")));
    }
    Ok(out)
}

/// Fetches and builds pkcs11-provider; runs its token suites on each side; compares.
fn run_pkcs11(root: &Path, reference: &Path, sides: &[Side], jobs: usize) -> Result<Vec<String>> {
    let missing: Vec<&str> = PKCS11_TOOLS.iter().copied().filter(|t| !have(t)).collect();
    if !missing.is_empty() {
        println!("pkcs11: skipped, without {}", missing.join(", "));
        return Ok(Vec::new());
    }
    let dir = target_dir(root).join("providers");
    let pins = parse_pins(&fs::read_to_string(root.join("tests/providers/pins.txt"))?)?;
    let pin = pins
        .iter()
        .find(|p| p.name == "pkcs11-provider")
        .ok_or("pins.txt pins no pkcs11-provider")?;
    let source = fetch(&dir, pin)?;
    let build = dir.join("build/pkcs11-provider");
    let logs = dir.join("logs");
    fs::create_dir_all(&logs)?;
    let log = logs.join("pkcs11-provider.log");
    let stamp = build.join("rustyssl-built");
    let key = format!("{}\n{}", source.display(), reference.display());
    if fs::read_to_string(&stamp).ok().as_deref() != Some(key.as_str()) {
        if build.exists() {
            fs::remove_dir_all(&build)?;
        }
        println!("Building {} (log: {})...", source.display(), log.display());
        run_logged(
            Command::new("meson")
                .arg("setup")
                .arg(&build)
                .arg(&source)
                .env("PKG_CONFIG_PATH", reference.join("lib/pkgconfig")),
            &log,
        )?;
        run_logged(
            Command::new("meson").arg("compile").arg("-C").arg(&build),
            &log,
        )?;
        fs::write(&stamp, key)?;
    }
    let work = target_dir(root).join("xtask/test-providers/pkcs11");
    fresh_dir(&work)?;
    let path = std::env::join_paths(
        std::iter::once(reference.join("bin")).chain(
            std::env::var_os("PATH")
                .iter()
                .flat_map(std::env::split_paths),
        ),
    )?;
    let mut all = Vec::new();
    for side in sides {
        let mut results = Results::new();
        for suite in PKCS11_SUITES {
            let mut cmd = Command::new("meson");
            cmd.args(["test", "-C"])
                .arg(&build)
                .args(["--suite", suite, "--num-processes"])
                .arg(jobs.to_string())
                .env("PATH", &path);
            side.env(&mut cmd);
            // Failing tests make it fail; the log says which.
            let _ = run_logged(&mut cmd, &work.join(format!("{}.{suite}.log", side.name)));
            let meson_logs = build.join("meson-logs");
            let text = fs::read_to_string(meson_logs.join("testlog.json"))?;
            fs::copy(
                meson_logs.join("testlog.txt"),
                work.join(format!("{}.{suite}.testlog.txt", side.name)),
            )?;
            for (name, ok) in meson_outcomes(&text)? {
                results.insert(format!("{suite} {name}"), ok);
            }
        }
        all.push(results);
    }
    compare("pkcs11", sides, &all)
}

/// Kills its child when dropped.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A software TPM behind a resource manager on a private session bus: the TCTI string and
/// the bus address, and the daemons.
fn start_tpm(state: &Path, log: &Path) -> Result<(String, String, Vec<Daemon>)> {
    fresh_dir(state)?;
    let mut bus = Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--print-address"])
        .stdout(Stdio::piped())
        .stderr(fs::File::create(log.with_extension("dbus.log"))?)
        .spawn()?;
    let mut line = String::new();
    {
        use std::io::BufRead as _;
        let out = bus.stdout.take().ok_or("no dbus-daemon stdout")?;
        std::io::BufReader::new(out).read_line(&mut line)?;
    }
    let address = line.trim().to_owned();
    let mut daemons = vec![Daemon(bus)];
    if address.is_empty() {
        return Err("dbus-daemon printed no address".into());
    }
    // A port picked free can be taken before swtpm binds it (or the one after it): a few tries.
    let mut port = 0;
    for _ in 0..5 {
        let p = std::net::TcpListener::bind("127.0.0.1:0")?
            .local_addr()?
            .port();
        let ctrl = p.checked_add(1).ok_or("no port after the TPM's")?;
        let mut child = Command::new("swtpm")
            .args(["socket", "--tpm2", "--server"])
            .arg(format!("port={p}"))
            .arg("--ctrl")
            .arg(format!("type=tcp,port={ctrl}"))
            .args(["--flags", "not-need-init", "--tpmstate"])
            .arg(format!("dir={}", state.display()))
            .args(["--seccomp", "action=none"])
            .stdout(Stdio::null())
            .stderr(fs::File::create(log.with_extension("swtpm.log"))?)
            .spawn()?;
        let start = Instant::now();
        let up = loop {
            if std::net::TcpStream::connect(("127.0.0.1", p)).is_ok() {
                break true;
            }
            if child.try_wait()?.is_some() || start.elapsed() > START_TIMEOUT {
                break false;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        daemons.push(Daemon(child));
        if up {
            port = p;
            break;
        }
    }
    if port == 0 {
        return Err("swtpm didn't start".into());
    }
    let name = format!("com.intel.tss2.Tabrmd{port}");
    daemons.push(Daemon(
        Command::new("tpm2-abrmd")
            .args(["--allow-root", "--session"])
            .arg(format!("--dbus-name={name}"))
            .arg("--tcti")
            .arg(format!("swtpm:host=127.0.0.1,port={port}"))
            .env("DBUS_SESSION_BUS_ADDRESS", &address)
            .stdout(Stdio::null())
            .stderr(fs::File::create(log.with_extension("abrmd.log"))?)
            .spawn()?,
    ));
    let tcti = format!("tabrmd:bus_name={name},bus_type=session");
    // Ready once a tool reaches the TPM through it.
    let start = Instant::now();
    loop {
        let ok = Command::new("tpm2_getcap")
            .arg("properties-fixed")
            .env("DBUS_SESSION_BUS_ADDRESS", &address)
            .env("TPM2TOOLS_TCTI", &tcti)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if ok {
            break;
        }
        if start.elapsed() > START_TIMEOUT {
            return Err("tpm2-abrmd didn't start".into());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok((tcti, address, daemons))
}

/// The automake test results under `dir` (`<test>.trs`: `:test-result: PASS`), by test path.
fn trs_outcomes(dir: &Path, base: &Path, out: &mut Results) -> Result {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            trs_outcomes(&path, base, out)?;
        } else if path.extension().is_some_and(|e| e == "trs") {
            let text = fs::read_to_string(&path)?;
            let name = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .with_extension("")
                .display()
                .to_string();
            out.insert(
                format!("check {name}"),
                text.lines().any(|l| l.trim() == ":test-result: PASS"),
            );
        }
    }
    Ok(())
}

/// Fetches and builds tpm2-openssl; runs its `make check` on each side; compares.
fn run_tpm2(root: &Path, reference: &Path, sides: &[Side]) -> Result<Vec<String>> {
    let mut missing: Vec<&str> = TPM2_TOOLS.iter().copied().filter(|t| !have(t)).collect();
    let tss = Command::new("pkg-config")
        .args(["--exists", "tss2-esys"])
        .status()
        .is_ok_and(|s| s.success());
    if !tss {
        missing.push("libtss2-dev (tss2-esys)");
    }
    if !missing.is_empty() {
        println!("tpm2: skipped, without {}", missing.join(", "));
        return Ok(Vec::new());
    }
    let dir = target_dir(root).join("providers");
    let pins = parse_pins(&fs::read_to_string(root.join("tests/providers/pins.txt"))?)?;
    let pin = pins
        .iter()
        .find(|p| p.name == "tpm2-openssl")
        .ok_or("pins.txt pins no tpm2-openssl")?;
    let source = fetch(&dir, pin)?;
    let logs = dir.join("logs");
    fs::create_dir_all(&logs)?;
    let log = logs.join("tpm2-openssl.log");
    let stamp = source.join("rustyssl-built");
    let key = reference.display().to_string();
    let pkg_config = std::env::join_paths(
        std::iter::once(reference.join("lib/pkgconfig")).chain(
            std::env::var_os("PKG_CONFIG_PATH")
                .iter()
                .flat_map(std::env::split_paths),
        ),
    )?;
    if fs::read_to_string(&stamp).ok().as_deref() != Some(key.as_str()) {
        println!("Building {} (log: {})...", source.display(), log.display());
        // `bootstrap` takes the version from git; the tarball has none.
        fs::write(source.join("VERSION"), &pin.commit)?;
        fs::create_dir_all(source.join("m4"))?;
        run_logged(
            Command::new("autoreconf")
                .args(["--install", "--sym"])
                .current_dir(&source),
            &log,
        )?;
        run_logged(
            Command::new("./configure")
                .args(["--enable-op-digest", "--enable-op-cipher"])
                .env("PKG_CONFIG_PATH", &pkg_config)
                .current_dir(&source),
            &log,
        )?;
        let jobs = std::thread::available_parallelism().map_or(4, |n| n.get());
        run_logged(
            Command::new("make")
                .arg(format!("-j{jobs}"))
                .current_dir(&source),
            &log,
        )?;
        fs::write(&stamp, key)?;
    }
    let work = target_dir(root).join("xtask/test-providers/tpm2");
    fresh_dir(&work)?;
    let path = std::env::join_paths(
        std::iter::once(reference.join("bin")).chain(
            std::env::var_os("PATH")
                .iter()
                .flat_map(std::env::split_paths),
        ),
    )?;
    let conf = reference.join("src/apps/openssl.cnf");
    let mut all = Vec::new();
    for side in sides {
        let side_log = work.join(format!("{}.log", side.name));
        let (tcti, address, daemons) =
            start_tpm(&work.join(format!("{}.tpm", side.name)), &side_log)?;
        let mut cmd = Command::new("make");
        cmd.args(["check", "-j1"])
            .current_dir(&source)
            .env("PATH", &path)
            .env("OPENSSL_CONF", &conf)
            .env("DBUS_SESSION_BUS_ADDRESS", &address)
            .env("TPM2OPENSSL_TCTI", &tcti)
            .env("TPM2TOOLS_TCTI", &tcti);
        side.env(&mut cmd);
        // Failing tests make it fail; the .trs files say which.
        let _ = run_logged(&mut cmd, &side_log);
        drop(daemons);
        let mut results = Results::new();
        trs_outcomes(&source.join("test"), &source, &mut results)?;
        if let Err(e) = fs::copy(
            source.join("test-suite.log"),
            work.join(format!("{}.test-suite.log", side.name)),
        ) {
            println!("tpm2: no test-suite.log on {}: {e}", side.name);
        }
        all.push(results);
    }
    compare("tpm2", sides, &all)
}

/// Prints each side's tally and returns the checks rustyssl fails where the reference passes.
fn compare(provider: &str, sides: &[Side], all: &[Results]) -> Result<Vec<String>> {
    for (side, results) in sides.iter().zip(all) {
        let mut kinds: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
        for (check, ok) in results {
            let kind = check.split(' ').next().unwrap_or(check);
            let e = kinds.entry(kind).or_default();
            e.0 += usize::from(*ok);
            e.1 += 1;
        }
        let tally: Vec<String> = kinds
            .iter()
            .map(|(k, (p, n))| format!("{k} {p}/{n}"))
            .collect();
        println!("{provider} on {}: {} pass", side.name, tally.join(", "));
    }
    let [reference, ours] = all else {
        return Ok(Vec::new());
    };
    let mut regressions = Vec::new();
    for (check, ok) in reference {
        if *ok && ours.get(check) != Some(&true) {
            regressions.push(format!("{provider}: {check}"));
        }
    }
    for check in ours.keys().filter(|c| !reference.contains_key(*c)) {
        regressions.push(format!("{provider}: {check} (rustyssl only)"));
    }
    for check in reference.keys().filter(|c| !ours.contains_key(*c)) {
        regressions.push(format!("{provider}: {check} (missing on rustyssl)"));
    }
    Ok(regressions)
}

pub fn run(args: &[String]) -> Result {
    let root = workspace_root();
    let reference_only = args.iter().any(|a| a == "--reference-only");
    let mut jobs = std::thread::available_parallelism().map_or(4, |n| n.get());
    let mut only = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--reference-only" => {}
            "--jobs" => {
                jobs = it
                    .next()
                    .and_then(|n| n.parse().ok())
                    .filter(|&n| n > 0)
                    .ok_or("--jobs takes a positive number")?;
            }
            s if s.starts_with("--") => return Err(format!("unknown option {s}").into()),
            s if PROVIDERS.contains(&s) => only.push(s.to_owned()),
            s => {
                return Err(format!(
                    "unknown provider {s}; the providers are: {}",
                    PROVIDERS.join(", ")
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
    let mut regressions = Vec::new();
    for p in PROVIDERS
        .iter()
        .filter(|p| only.is_empty() || only.iter().any(|o| o == *p))
    {
        match *p {
            "oqs" => regressions.extend(run_oqs(&root, &reference, &sides, jobs)?),
            "pkcs11" => regressions.extend(run_pkcs11(&root, &reference, &sides, jobs)?),
            "tpm2" => regressions.extend(run_tpm2(&root, &reference, &sides)?),
            _ => unreachable!(),
        }
    }
    if regressions.is_empty() {
        println!("The providers pass on rustyssl wherever they pass on the reference");
        Ok(())
    } else {
        for r in &regressions {
            println!("FAIL {r}");
        }
        Err(format!("{} checks fail on rustyssl only", regressions.len()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_ctest_outcomes() {
        let log = "    Start 1: a\n1/2 Test #1: a ..........   Passed    0.84 sec\n\
                   2/2 Test #2: b ..........***Failed    1.00 sec\n";
        assert_eq!(ctest_passed(log).into_iter().collect::<Vec<_>>(), ["a"]);
    }

    #[test]
    fn reads_meson_outcomes() {
        let log = "{\"name\": \"setup\", \"result\": \"OK\"}\n\
                   {\"name\": \"tls\", \"result\": \"FAIL\"}\n";
        let o = meson_outcomes(log).unwrap();
        assert_eq!(o, [("setup".to_owned(), true), ("tls".to_owned(), false)]);
    }

    #[test]
    fn parses_pins() {
        let pins = parse_pins("# c\npin a o/a c s\n\n").unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].repository, "o/a");
        assert!(parse_pins("pin a b\n").is_err());
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
        ]
        .into();
        let ours: Results = [
            ("a".to_owned(), true),
            ("b".to_owned(), true),
            ("c".to_owned(), false),
        ]
        .into();
        let r = compare("p", &sides, &[reference, ours]).unwrap();
        assert_eq!(r, ["p: c"]);
    }
}
