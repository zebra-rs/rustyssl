//! `cargo xtask test-quic-interop [--peer P]... [--reference-only] [case...]`: the core cases of
//! quic-interop-runner, run locally between OpenSSL's QUIC API (on the reference's libraries and
//! on rustyssl's) and other QUIC stacks (ADR 0006, section 4; TEST_PLAN.md, layer L7).
//!
//! The runner itself needs Docker images of several GB each; this driver runs the same cases on
//! the loopback interface instead (the user's decision, 2026-10-20: Phase 10's interop exit is
//! this local driver, the Docker runner a follow-up). It follows the runner's definitions
//! (`testcases_quic.py` at `RUNNER_COMMIT`): each case's files (sizes and counts, random names
//! and contents), the test name each endpoint is given (a multiplexing run is a "transfer" to
//! both, a key update a "keyupdate" to the client and a "transfer" to the server), and each
//! implementation's `run_endpoint.sh`, translated: what it supports in each role and the
//! arguments it runs with. An endpoint that doesn't support a case's test name is "unsupported"
//! (exit 127 in the runner).
//!
//! **Our endpoint** is OpenSSL's own interop endpoint, the one its runner image uses
//! (`test/quic-openssl-docker/`): `quic-hq-interop` and `quic-hq-interop-server` for the HTTP/0.9
//! cases, curl (with OpenSSL's QUIC backend and nghttp3) as the HTTP/3 client and
//! `ossl-nghttp3-demo-server` as the HTTP/3 server. They're compiled from the reference's source
//! (curl from its pin, 8.18.0, the last release with that backend) against the reference's
//! headers, and each run loads either the reference's libraries or rustyssl's. Two changes to
//! their source: the hq client's download directory is `$DOWNLOADS`, not `/downloads`, and the
//! demo server's connection state starts zeroed (it frees an uninitialized pointer otherwise).
//! curl is given the CA with `--cacert`, as its own default bundle would take precedence.
//!
//! **The peers** are built from sources pinned by commit and SHA-256 (`tests/quic-interop/
//! pins.txt`), each on a TLS stack of its own:
//! - `quiche`: quiche's `quiche-client` and `quiche-server` apps (BoringSSL, through the `boring`
//!   crate), built with the lockfile `tests/quic-interop/quiche.Cargo.lock` (quiche commits
//!   none).
//! - `ngtcp2`: ngtcp2's example client and server on its `ossl` backend (OpenSSL's third-party
//!   QUIC API) with nghttp3, built against the reference and always run on its libraries (only
//!   our endpoint changes libraries). Its interop image runs `*hqclient`/`*hqserver`, the
//!   examples with the HTTP/0.9 codec, which only its autotools build defines, and only for
//!   wolfSSL; the driver adds `osslhqclient` and `osslhqserver` to its cmake build from the same
//!   sources.
//! - `quic-go`: quic-go's interop client and server (`interop/`, on Go's crypto/tls), built in
//!   its own module (they use its internal packages) with its `go.sum`. Their fixed paths (the
//!   log, the certificate and key, `/www`, `/downloads`, port 443) become environment variables.
//!
//! **Checks.** A run passes when the client exits 0 and every requested file arrived with its
//! contents. The runner's packet-trace checks (one handshake, a Retry sent, no certificate on
//! resumption, the key phase changing, the stream limit) need a packet capture and its TLS keys,
//! which this driver doesn't take; the cases still exercise each feature, and a failure in it
//! fails the transfer.
//!
//! A case passes on rustyssl when it passes on the reference: a case the reference fails (or
//! doesn't support) is reported but not counted. Results go to `target/quic-interop-report.md`,
//! each run's logs to `target/xtask/test-quic-interop/<peer>/<case>/<run>/`.

use std::fmt::Write as _;
use std::fs;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::test_c::{LOADER_PATH, modules_of, prepare};
use crate::test_providers::{Pin, Side, cmake, fetch, parse_pins};
use crate::util::{Result, fresh_dir, run_logged, target_dir, workspace_root};

/// quic-interop-runner's commit whose `testcases_quic.py` the cases follow.
pub(crate) const RUNNER_COMMIT: &str = "a1004d4b60a6894ea33736a555f294c663e54b22";

const KB: usize = 1 << 10;
const MB: usize = 1 << 20;

/// A runner test case: its files, and the test name each role is given.
struct Case {
    name: &'static str,
    /// The files to transfer: (count, size in octets, length of the random name).
    files: &'static [(usize, usize, usize)],
    client: &'static str,
    server: &'static str,
}

/// The core cases (ADR 0006, section 4), as `testcases_quic.py` defines them.
const CASES: &[Case] = &[
    Case {
        name: "handshake",
        files: &[(1, KB, 10)],
        client: "handshake",
        server: "handshake",
    },
    Case {
        name: "transfer",
        files: &[(1, 2 * MB, 10), (1, 3 * MB, 10), (1, 5 * MB, 10)],
        client: "transfer",
        server: "transfer",
    },
    Case {
        name: "retry",
        files: &[(1, 10 * KB, 10)],
        client: "retry",
        server: "retry",
    },
    Case {
        name: "resumption",
        files: &[(1, 5 * KB, 10), (1, 10 * KB, 10)],
        client: "resumption",
        server: "resumption",
    },
    Case {
        name: "zerortt",
        files: &[(40, 32, 250)],
        client: "zerortt",
        server: "zerortt",
    },
    Case {
        name: "chacha20",
        files: &[(1, 3 * MB, 10)],
        client: "chacha20",
        server: "chacha20",
    },
    Case {
        name: "keyupdate",
        files: &[(1, 3 * MB, 10)],
        client: "keyupdate",
        server: "transfer",
    },
    Case {
        name: "multiplexing",
        files: &[(1999, 32, 10)],
        client: "transfer",
        server: "transfer",
    },
    Case {
        name: "http3",
        files: &[(1, 5 * KB, 10), (1, 10 * KB, 10), (1, 500 * KB, 10)],
        client: "http3",
        server: "http3",
    },
];

/// The peers the command knows, as `--peer` names them.
const PEERS: &[&str] = &["quiche", "ngtcp2", "quic-go"];

/// How long a client may run.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(120);

/// How long a server is given to bind its port before a client is started.
const SERVER_START: Duration = Duration::from_millis(500);

/// The configuration file every run is pointed at (one that doesn't exist).
const MISSING_CONFIG: &str = "/nonexistent/rustyssl-tests/openssl.cnf";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Role {
    Client,
    Server,
}

/// One run's outcome.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Outcome {
    Pass,
    Fail(String),
    Unsupported,
}

impl Outcome {
    fn label(&self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail(_) => "FAIL",
            Self::Unsupported => "unsupported",
        }
    }
}

/// What a run gives its endpoints: the server's address, the files, the directories.
struct Run<'a> {
    port: u16,
    /// The files the client requests, by name.
    files: &'a [String],
    www: &'a Path,
    downloads: &'a Path,
    pki: &'a Path,
    /// This run's directory (logs, session files).
    dir: &'a Path,
    /// The reference's libraries (for peers that link OpenSSL).
    reference_lib: &'a Path,
}

impl Run<'_> {
    fn urls(&self) -> Vec<String> {
        self.files
            .iter()
            .map(|f| format!("https://127.0.0.1:{}/{f}", self.port))
            .collect()
    }
}

/// A QUIC endpoint: what it supports, and the commands that run it.
trait Endpoint {
    fn name(&self) -> String;
    /// Whether it supports `testcase` (the role's test name) in `role`.
    fn supports(&self, role: Role, testcase: &str) -> bool;
    fn server(&self, run: &Run<'_>, testcase: &str) -> Command;
    /// The client's invocations, run in order (a resumption's second connection is a second
    /// process).
    fn client(&self, run: &Run<'_>, testcase: &str) -> Vec<Command>;
}

/// `cmd` loading `lib`'s libraries, with the missing configuration file and its modules.
fn with_lib<'a>(cmd: &'a mut Command, lib: &Path) -> &'a mut Command {
    cmd.env(LOADER_PATH, lib)
        .env("LD_LIBRARY_PATH", lib)
        .env("OPENSSL_MODULES", modules_of(lib))
        .env("OPENSSL_CONF", MISSING_CONFIG)
}

/// OpenSSL's interop endpoint (`test/quic-openssl-docker/run_endpoint.sh`) on one side's
/// libraries.
struct Ours {
    side: Side,
    hq: PathBuf,
    /// curl and `ossl-nghttp3-demo-server`, for http3.
    h3: H3,
}

/// Our HTTP/3 endpoints: curl's binary and OpenSSL's nghttp3 demo server.
#[derive(Clone)]
pub(crate) struct H3 {
    pub(crate) curl: PathBuf,
    pub(crate) server: PathBuf,
}

/// curl's command fetching `urls` into `downloads` over HTTP/3 in parallel, as OpenSSL's
/// `run_endpoint.sh` runs it (a config file of `--http3-only -o FILE --url URL` per request),
/// trusting `ca`.
pub(crate) fn curl_command(
    curl: &Path,
    dir: &Path,
    ca: &Path,
    urls: &[String],
    downloads: &Path,
) -> Command {
    let mut config = String::from("--verbose\n--parallel\n");
    for (i, url) in urls.iter().enumerate() {
        if i > 0 {
            config.push_str("--next\n");
        }
        let name = url.rsplit('/').next().unwrap_or_default();
        let _ = writeln!(
            config,
            "--http3-only\n-o \"{}\"\n--url {url}",
            downloads.join(name).display()
        );
    }
    let curlrc = dir.join("curlrc");
    // Written here; a failure shows as curl failing to read it.
    let _ = fs::write(&curlrc, config);
    let mut c = Command::new(curl);
    // The CA explicitly: curl's own default bundle takes precedence over SSL_CERT_FILE.
    c.arg("--cacert")
        .arg(ca)
        .arg("--config")
        .arg(&curlrc)
        .env("SSL_CERT_FILE", ca)
        .current_dir(dir);
    c
}

impl Endpoint for Ours {
    fn name(&self) -> String {
        format!("openssl({})", self.side.name)
    }

    fn supports(&self, role: Role, testcase: &str) -> bool {
        match role {
            Role::Client => matches!(
                testcase,
                "handshake" | "transfer" | "retry" | "resumption" | "chacha20" | "http3"
            ),
            Role::Server => matches!(
                testcase,
                "handshake" | "transfer" | "retry" | "resumption" | "chacha20" | "http3"
            ),
        }
    }

    fn server(&self, run: &Run<'_>, testcase: &str) -> Command {
        if testcase == "http3" {
            let mut c = Command::new(&self.h3.server);
            with_lib(&mut c, &self.side.lib);
            c.arg(run.port.to_string())
                .arg(run.pki.join("cert.pem"))
                .arg(run.pki.join("priv.key"))
                .env("FILEPREFIX", format!("{}/", run.www.display()))
                .current_dir(run.dir);
            return c;
        }
        let mut c = Command::new(self.hq.join("quic-hq-interop-server"));
        with_lib(&mut c, &self.side.lib);
        c.arg(run.port.to_string())
            .arg(run.pki.join("cert.pem"))
            .arg(run.pki.join("priv.key"))
            .env("FILEPREFIX", run.www)
            .current_dir(run.dir);
        match testcase {
            "retry" => {}
            "chacha20" => {
                c.env("SSL_CIPHER_SUITES", "TLS_CHACHA20_POLY1305_SHA256");
            }
            _ => {
                c.env("NO_ADDR_VALIDATE", "yes");
            }
        }
        c
    }

    fn client(&self, run: &Run<'_>, testcase: &str) -> Vec<Command> {
        if testcase == "http3" {
            let mut c = curl_command(
                &self.h3.curl,
                run.dir,
                &run.pki.join("ca.pem"),
                &run.urls(),
                run.downloads,
            );
            with_lib(&mut c, &self.side.lib);
            return vec![c];
        }
        // A request file per invocation: all the files, or (resumption) one per connection.
        let batches: Vec<Vec<String>> = if testcase == "resumption" {
            run.files.iter().map(|f| vec![f.clone()]).collect()
        } else {
            vec![run.files.to_vec()]
        };
        batches
            .into_iter()
            .enumerate()
            .map(|(i, batch)| {
                let reqfile = run.dir.join(format!("reqfile-{i}.txt"));
                let mut text = String::new();
                for f in &batch {
                    let _ = write!(text, "{f} ");
                }
                // Written here; a failure shows as the client failing to read it.
                let _ = fs::write(&reqfile, text);
                let mut c = Command::new(self.hq.join("quic-hq-interop"));
                with_lib(&mut c, &self.side.lib);
                c.arg("127.0.0.1")
                    .arg(run.port.to_string())
                    .arg(&reqfile)
                    .env("SSL_CERT_FILE", run.pki.join("ca.pem"))
                    .env("SSL_CERT_DIR", run.pki)
                    .env("DOWNLOADS", run.downloads)
                    .current_dir(run.dir);
                if testcase == "resumption" || testcase == "chacha20" {
                    c.env("SSL_SESSION_FILE", run.dir.join("session.db"));
                }
                if testcase == "chacha20" {
                    c.env("SSL_CIPHER_SUITES", "TLS_CHACHA20_POLY1305_SHA256");
                }
                c
            })
            .collect()
    }
}

/// quiche's apps (`apps/run_endpoint.sh`).
struct Quiche {
    bin: PathBuf,
}

impl Endpoint for Quiche {
    fn name(&self) -> String {
        "quiche".to_owned()
    }

    fn supports(&self, role: Role, testcase: &str) -> bool {
        match testcase {
            "handshake" | "multiconnect" | "http3" | "transfer" | "resumption" | "zerortt"
            | "retry" => true,
            // "We don't support selecting a cipher on the client-side."
            "chacha20" => role == Role::Server,
            _ => false,
        }
    }

    fn server(&self, run: &Run<'_>, testcase: &str) -> Command {
        let mut c = Command::new(self.bin.join("quiche-server"));
        c.arg("--listen")
            .arg(format!("127.0.0.1:{}", run.port))
            .arg("--root")
            .arg(run.www)
            .arg("--cert")
            .arg(run.pki.join("cert.pem"))
            .arg("--key")
            .arg(run.pki.join("priv.key"))
            .args([
                "--enable-active-migration",
                "--max-active-cids",
                "8",
                "--disable-gso",
                "--disable-pacing",
            ])
            .current_dir(run.dir);
        if testcase != "retry" {
            c.arg("--no-retry");
        }
        if testcase == "zerortt" {
            c.arg("--early-data");
        }
        c
    }

    fn client(&self, run: &Run<'_>, testcase: &str) -> Vec<Command> {
        let make = |urls: &[String]| {
            let mut c = Command::new(self.bin.join("quiche-client"));
            c.arg("--no-verify")
                .arg("--dump-responses")
                .arg(run.downloads)
                .args(["--wire-version", "1", "--max-active-cids", "8"])
                .current_dir(run.dir);
            if testcase == "resumption" || testcase == "zerortt" {
                c.arg(format!(
                    "--session-file={}",
                    run.dir.join("session.bin").display()
                ));
            }
            if testcase == "zerortt" {
                c.arg("--early-data");
            }
            c.args(urls);
            c
        };
        let urls = run.urls();
        match testcase {
            // The first request in 1-RTT, to establish the session; the rest resumed.
            "resumption" | "zerortt" => match urls.split_first() {
                Some((first, rest)) => vec![make(std::slice::from_ref(first)), make(rest)],
                None => Vec::new(),
            },
            _ => vec![make(&urls)],
        }
    }
}

/// ngtcp2's examples (`interop/run_endpoint.sh`), on the reference's libraries.
struct Ngtcp2 {
    bin: PathBuf,
}

impl Ngtcp2 {
    fn program(&self, run: &Run<'_>, name: &str) -> Command {
        let mut c = Command::new(self.bin.join(name));
        with_lib(&mut c, run.reference_lib);
        c.current_dir(run.dir);
        c
    }
}

impl Endpoint for Ngtcp2 {
    fn name(&self) -> String {
        "ngtcp2".to_owned()
    }

    fn supports(&self, _: Role, testcase: &str) -> bool {
        matches!(
            testcase,
            "versionnegotiation"
                | "handshake"
                | "transfer"
                | "retry"
                | "resumption"
                | "http3"
                | "multiconnect"
                | "zerortt"
                | "chacha20"
                | "keyupdate"
                | "ecn"
                | "v2"
                | "connectionmigration"
        )
    }

    fn server(&self, run: &Run<'_>, testcase: &str) -> Command {
        let name = if testcase == "http3" {
            "osslserver"
        } else {
            "osslhqserver"
        };
        let mut c = self.program(run, name);
        c.arg("127.0.0.1")
            .arg(run.port.to_string())
            .arg(run.pki.join("priv.key"))
            .arg(run.pki.join("cert.pem"))
            .args(["-s", "-d"])
            .arg(run.www)
            .args(["--cc", "bbr", "--initial-rtt", "100ms", "--show-stat"]);
        if testcase == "retry" {
            c.arg("-V");
        }
        c
    }

    fn client(&self, run: &Run<'_>, testcase: &str) -> Vec<Command> {
        let name = if testcase == "http3" {
            "osslclient"
        } else {
            "osslhqclient"
        };
        let make = |urls: &[String]| {
            let mut c = self.program(run, name);
            c.arg("127.0.0.1")
                .arg(run.port.to_string())
                .arg("--download")
                .arg(run.downloads)
                .args([
                    "-s",
                    "--no-quic-dump",
                    "--no-http-dump",
                    "--exit-on-all-streams-close",
                    "--cc",
                    "bbr",
                    "--initial-rtt",
                    "100ms",
                    "--show-stat",
                    "-v",
                    "0x1",
                ]);
            match testcase {
                "chacha20" => {
                    c.arg("--ciphers=TLS_CHACHA20_POLY1305_SHA256");
                }
                "keyupdate" => {
                    c.args(["--delay-stream", "10ms", "--key-update", "1ms"]);
                }
                "zerortt" => {
                    c.arg("--no-pmtud");
                }
                _ => {}
            }
            if testcase == "resumption" || testcase == "zerortt" {
                c.args(["--session-file", "session.txt", "--tp-file", "tp.txt"])
                    .arg("--wait-for-ticket");
                if testcase == "resumption" {
                    c.arg("--disable-early-data");
                }
            }
            c.args(urls);
            c
        };
        let urls = run.urls();
        match testcase {
            "resumption" | "zerortt" => match urls.split_first() {
                Some((first, rest)) => vec![make(std::slice::from_ref(first)), make(rest)],
                None => Vec::new(),
            },
            _ => vec![make(&urls)],
        }
    }
}

/// quic-go's interop programs (`interop/{client,server}/main.go`, driven by `TESTCASE`).
struct QuicGo {
    bin: PathBuf,
}

impl QuicGo {
    fn program(&self, run: &Run<'_>, name: &str, testcase: &str) -> Command {
        let mut c = Command::new(self.bin.join(name));
        c.env("TESTCASE", testcase)
            .env("QUIC_GO_LOG_LEVEL", "debug")
            .env("INTEROP_LOG", run.dir.join(format!("quic-go-{name}.log")))
            .current_dir(run.dir);
        c
    }
}

impl Endpoint for QuicGo {
    fn name(&self) -> String {
        "quic-go".to_owned()
    }

    fn supports(&self, role: Role, testcase: &str) -> bool {
        match role {
            Role::Client => matches!(
                testcase,
                "handshake"
                    | "transfer"
                    | "retry"
                    | "keyupdate"
                    | "chacha20"
                    | "multiconnect"
                    | "versionnegotiation"
                    | "resumption"
                    | "zerortt"
                    | "http3"
            ),
            Role::Server => matches!(
                testcase,
                "versionnegotiation"
                    | "handshake"
                    | "retry"
                    | "transfer"
                    | "resumption"
                    | "multiconnect"
                    | "zerortt"
                    | "chacha20"
                    | "http3"
            ),
        }
    }

    fn server(&self, run: &Run<'_>, testcase: &str) -> Command {
        let mut c = self.program(run, "server", testcase);
        c.env("INTEROP_CERT", run.pki.join("cert.pem"))
            .env("INTEROP_KEY", run.pki.join("priv.key"))
            .env("INTEROP_WWW", run.www)
            .env("INTEROP_LISTEN", format!("127.0.0.1:{}", run.port));
        c
    }

    fn client(&self, run: &Run<'_>, testcase: &str) -> Vec<Command> {
        let mut c = self.program(run, "client", testcase);
        c.env("INTEROP_DOWNLOADS", run.downloads).args(run.urls());
        vec![c]
    }
}

/// quic-go's interop programs' fixed paths, and the variables that replace them.
const QUIC_GO_PATCHES: &[(&str, &str, &str)] = &[
    ("client", "\"/logs/log.txt\"", "os.Getenv(\"INTEROP_LOG\")"),
    (
        "client",
        "\"/downloads\"",
        "os.Getenv(\"INTEROP_DOWNLOADS\")",
    ),
    ("server", "\"/logs/log.txt\"", "os.Getenv(\"INTEROP_LOG\")"),
    (
        "server",
        "\"/certs/cert.pem\"",
        "os.Getenv(\"INTEROP_CERT\")",
    ),
    (
        "server",
        "\"/certs/priv.key\"",
        "os.Getenv(\"INTEROP_KEY\")",
    ),
    ("server", "\"/www\"", "os.Getenv(\"INTEROP_WWW\")"),
    ("server", "\":443\"", "os.Getenv(\"INTEROP_LISTEN\")"),
];

/// quic-go's interop client and server from the pinned tree (its fixed paths patched); the
/// directory holding `client` and `server`.
fn build_quic_go(dir: &Path, pins: &[Pin], log: &Path) -> Result<PathBuf> {
    let tree = fetch(dir, pin(pins, "quic-go")?)?;
    let build = dir.join("build/quic-go");
    fs::create_dir_all(&build)?;
    for program in ["client", "server"] {
        let path = tree.join("interop").join(program).join("main.go");
        let mut text = fs::read_to_string(&path)?;
        for &(_, old, new) in QUIC_GO_PATCHES.iter().filter(|p| p.0 == program) {
            // Already patched when the tree is reused.
            if !text.contains(old) && !text.contains(new) {
                return Err(format!("quic-go's interop/{program}: no {old} to patch").into());
            }
            text = text.replace(old, new);
        }
        fs::write(&path, text)?;
        println!(
            "Building quic-go's interop {program} (log: {})...",
            log.display()
        );
        run_logged(
            Command::new("go")
                .args(["build", "-mod=readonly", "-o"])
                .arg(build.join(program))
                .arg(format!("./interop/{program}"))
                .env("GOTOOLCHAIN", "local")
                .env("GOFLAGS", "-modcacherw")
                .env("GOMODCACHE", dir.join("build/go-mod"))
                .env("GOCACHE", dir.join("build/go-cache"))
                .current_dir(&tree),
            log,
        )?;
    }
    Ok(build)
}

/// A seeded generator for the files' names and contents (xorshift64*).
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n.saturating_add(8));
        while out.len() < n {
            out.extend_from_slice(&self.next().to_le_bytes());
        }
        out.truncate(n);
        out
    }

    /// A name of `n` lowercase letters and digits, as the runner's `random_string`.
    fn name(&mut self, n: usize) -> String {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        (0..n)
            .map(|_| {
                let i = usize::try_from(self.next() % 36).unwrap_or(0);
                ALPHABET.get(i).map_or('a', |&b| char::from(b))
            })
            .collect()
    }
}

/// Writes `case`'s files into `www`; returns their names.
fn make_files(case: &Case, www: &Path, seed: u64) -> Result<Vec<String>> {
    fresh_dir(www)?;
    let mut random = Random(seed | 1);
    let mut names = Vec::new();
    for &(count, size, name_len) in case.files {
        for _ in 0..count {
            let name = random.name(name_len);
            fs::write(www.join(&name), random.bytes(size))?;
            names.push(name);
        }
    }
    Ok(names)
}

/// A test PKI: a root and a server certificate for `localhost` and 127.0.0.1 (P-256), made with
/// the reference's `openssl`.
fn make_pki(reference: &Path, dir: &Path) -> Result {
    fresh_dir(dir)?;
    let cnf = dir.join("req.cnf");
    fs::write(&cnf, "[req]\ndistinguished_name = dn\n[dn]\n")?;
    let openssl = |args: &[&str]| -> Result {
        let mut c = Command::new(reference.join("bin/openssl"));
        with_lib(&mut c, &reference.join("lib"));
        let out = c
            .args(args)
            .env("OPENSSL_CONF", &cnf)
            .current_dir(dir)
            .stdin(Stdio::null())
            .output()?;
        if !out.status.success() {
            return Err(format!(
                "openssl {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr)
            )
            .into());
        }
        Ok(())
    };
    let ec = [
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
    ];
    let mut ca = vec!["req", "-x509"];
    ca.extend(ec);
    ca.extend([
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
        "-days",
        "3650",
        "-subj",
        "/O=rustyssl quic-interop/CN=Interop Root",
        "-addext",
        "basicConstraints=critical,CA:true",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    ]);
    openssl(&ca)?;
    let mut req = vec!["req", "-new"];
    req.extend(ec);
    req.extend([
        "-keyout",
        "priv.key",
        "-out",
        "server.csr",
        "-subj",
        "/O=rustyssl quic-interop/CN=localhost",
    ]);
    openssl(&req)?;
    fs::write(
        dir.join("ext.cnf"),
        "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:false\n",
    )?;
    openssl(&[
        "x509",
        "-req",
        "-in",
        "server.csr",
        "-CA",
        "ca.pem",
        "-CAkey",
        "ca.key",
        "-CAcreateserial",
        "-days",
        "3650",
        "-extfile",
        "ext.cnf",
        "-out",
        "cert.pem",
    ])?;
    Ok(())
}

/// A free local UDP port (the socket is closed again; the server binds it next).
fn free_udp_port() -> Result<u16> {
    let s = UdpSocket::bind("127.0.0.1:0")?;
    Ok(s.local_addr()?.port())
}

/// Spawns `cmd` with its output in `log`.
fn spawn_logged(cmd: &mut Command, log: &Path) -> Result<Child> {
    let out = fs::File::create(log)?;
    let err = out.try_clone()?;
    Ok(cmd
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()?)
}

/// Waits for `child` up to `timeout` (killing it after): whether it exited 0, and how.
fn wait_for(child: &mut Child, timeout: Duration) -> Result<std::result::Result<(), String>> {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(if status.success() {
                Ok(())
            } else {
                Err(format!("exited with {status}"))
            });
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(Err(format!("timed out after {}s", timeout.as_secs())));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The last lines of a log, for a failure's reason.
fn tail(log: &Path, lines: usize) -> String {
    let text = fs::read_to_string(log).unwrap_or_default();
    let all: Vec<&str> = text.lines().collect();
    all.get(all.len().saturating_sub(lines)..)
        .unwrap_or_default()
        .join(" / ")
}

/// Runs `case` with `server` serving `client`; the outcome, with the logs in `dir`.
fn run_case(
    case: &Case,
    server: &dyn Endpoint,
    client: &dyn Endpoint,
    dir: &Path,
    pki: &Path,
    reference_lib: &Path,
    seed: u64,
) -> Result<Outcome> {
    if !server.supports(Role::Server, case.server) || !client.supports(Role::Client, case.client) {
        return Ok(Outcome::Unsupported);
    }
    fresh_dir(dir)?;
    let www = dir.join("www");
    let downloads = dir.join("downloads");
    let files = make_files(case, &www, seed)?;
    fs::create_dir_all(&downloads)?;
    let run = Run {
        port: free_udp_port()?,
        files: &files,
        www: &www,
        downloads: &downloads,
        pki,
        dir,
        reference_lib,
    };
    let server_log = dir.join("server.log");
    let mut srv = spawn_logged(&mut server.server(&run, case.server), &server_log)?;
    std::thread::sleep(SERVER_START);
    let result = (|| -> Result<Outcome> {
        if let Some(status) = srv.try_wait()? {
            return Ok(Outcome::Fail(format!(
                "the server exited ({status}): {}",
                tail(&server_log, 3)
            )));
        }
        for (i, mut cmd) in client.client(&run, case.client).into_iter().enumerate() {
            let log = dir.join(format!("client-{i}.log"));
            let mut child = spawn_logged(&mut cmd, &log)?;
            if let Err(why) = wait_for(&mut child, CLIENT_TIMEOUT)? {
                return Ok(Outcome::Fail(format!(
                    "the client {why}: {}",
                    tail(&log, 3)
                )));
            }
        }
        for f in &files {
            let want = fs::read(www.join(f))?;
            match fs::read(downloads.join(f)) {
                Ok(got) if got == want => {}
                Ok(got) => {
                    return Ok(Outcome::Fail(format!(
                        "{f}: {} octets, expected {}",
                        got.len(),
                        want.len()
                    )));
                }
                Err(_) => return Ok(Outcome::Fail(format!("{f} wasn't downloaded"))),
            }
        }
        Ok(Outcome::Pass)
    })();
    let _ = srv.kill();
    let _ = srv.wait();
    let outcome = result?;
    if outcome == Outcome::Pass {
        // The files are large and the run passed: keep only the logs.
        let _ = fs::remove_dir_all(&www);
        let _ = fs::remove_dir_all(&downloads);
    }
    Ok(outcome)
}

/// OpenSSL's interop endpoint compiled against the reference's headers and libraries; the
/// directory holding `quic-hq-interop` and `quic-hq-interop-server`.
fn build_hq(reference: &Path, build: &Path, log: &Path) -> Result<PathBuf> {
    let src = reference.join("src/test/quic-openssl-docker/hq-interop");
    let dir = build.join("hq");
    fs::create_dir_all(&dir)?;
    let client = fs::read_to_string(src.join("quic-hq-interop.c"))?;
    let old = r#"BIO_snprintf(outfilename, REQ_STRING_SZ, "/downloads/%s", req);"#;
    if !client.contains(old) {
        return Err("quic-hq-interop.c: its download path has changed".into());
    }
    let patched = client.replace(
        old,
        r#"BIO_snprintf(outfilename, REQ_STRING_SZ, "%s/%s", getenv("DOWNLOADS") != NULL ? getenv("DOWNLOADS") : "/downloads", req);"#,
    );
    fs::write(dir.join("quic-hq-interop.c"), patched)?;
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_owned());
    for (program, source) in [
        ("quic-hq-interop", dir.join("quic-hq-interop.c")),
        (
            "quic-hq-interop-server",
            src.join("quic-hq-interop-server.c"),
        ),
    ] {
        run_logged(
            Command::new(&cc)
                .args(["-O1", "-w", "-I"])
                .arg(reference.join("include"))
                .arg(&source)
                .arg("-L")
                .arg(reference.join("lib"))
                .args(["-lssl", "-lcrypto", "-o"])
                .arg(dir.join(program)),
            log,
        )?;
    }
    Ok(dir)
}

/// quiche's apps from the pinned tree, with the committed lockfile; the directory holding
/// `quiche-client` and `quiche-server`.
fn build_quiche(root: &Path, dir: &Path, pins: &[Pin], log: &Path) -> Result<PathBuf> {
    let tree = fetch(dir, pin(pins, "quiche")?)?;
    fs::copy(
        root.join("tests/quic-interop/quiche.Cargo.lock"),
        tree.join("Cargo.lock"),
    )?;
    let target = dir.join("build/quiche");
    println!("Building quiche's apps (log: {})...", log.display());
    run_logged(
        Command::new("cargo")
            .args(["build", "--locked", "--release", "-p", "quiche_apps"])
            .env("CARGO_TARGET_DIR", &target)
            .current_dir(&tree),
        log,
    )?;
    Ok(target.join("release"))
}

/// nghttp3, a static library installed into a prefix; returns the prefix.
fn build_nghttp3(dir: &Path, pins: &[Pin], log: &Path) -> Result<PathBuf> {
    let nghttp3 = fetch(dir, pin(pins, "nghttp3")?)?;
    submodule(dir, pins, "nghttp3-sfparse", &nghttp3.join("lib/sfparse"))?;
    let prefix = dir.join("build/nghttp3/prefix");
    cmake(
        &nghttp3,
        &dir.join("build/nghttp3/build"),
        &[
            "-DENABLE_LIB_ONLY=ON".to_owned(),
            "-DBUILD_TESTING=OFF".to_owned(),
            "-DENABLE_SHARED_LIB=OFF".to_owned(),
            "-DENABLE_STATIC_LIB=ON".to_owned(),
            "-DCMAKE_BUILD_TYPE=RelWithDebInfo".to_owned(),
            format!("-DCMAKE_INSTALL_PREFIX={}", prefix.display()),
        ],
        true,
        log,
    )?;
    Ok(prefix)
}

/// Our HTTP/3 endpoints, built against the reference: OpenSSL's `ossl-nghttp3-demo-server`
/// (`demos/http3/`) and curl (`--with-openssl-quic`, nghttp3), both with nghttp3 static.
pub(crate) fn build_h3(reference: &Path, dir: &Path, pins: &[Pin], log: &Path) -> Result<H3> {
    let prefix = build_nghttp3(dir, pins, log)?;
    let out = dir.join("build/h3");
    fs::create_dir_all(&out)?;
    let demos = reference.join("src/demos/http3");
    let server = out.join("ossl-nghttp3-demo-server");
    // Its connection state starts uninitialized, and the first reset frees whatever pointer the
    // stack held there (on macOS, an abort before it serves anything): start it zeroed.
    let source = fs::read_to_string(demos.join("ossl-nghttp3-demo-server.c"))?;
    let old = "    struct h3ssl h3ssl;\n";
    if !source.contains(old) {
        return Err("ossl-nghttp3-demo-server.c: its connection state has changed".into());
    }
    let patched = out.join("ossl-nghttp3-demo-server.c");
    fs::write(
        &patched,
        source.replace(old, "    struct h3ssl h3ssl = { 0 };\n"),
    )?;
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_owned());
    run_logged(
        Command::new(&cc)
            .args(["-O1", "-w", "-I"])
            .arg(reference.join("include"))
            .arg("-I")
            .arg(demos.clone())
            .arg("-I")
            .arg(prefix.join("include"))
            .arg(&patched)
            .arg(demos.join("ossl-nghttp3.c"))
            .arg(prefix.join("lib/libnghttp3.a"))
            .arg("-L")
            .arg(reference.join("lib"))
            .args(["-lssl", "-lcrypto", "-o"])
            .arg(&server),
        log,
    )?;
    Ok(H3 {
        curl: build_curl(reference, dir, pins, &prefix, log)?,
        server,
    })
}

/// curl from the pinned tree, configured with OpenSSL's QUIC stack against the reference
/// (`--with-openssl-quic`) and nghttp3, without the optional libraries; once per pin.
fn build_curl(
    reference: &Path,
    dir: &Path,
    pins: &[Pin],
    nghttp3: &Path,
    log: &Path,
) -> Result<PathBuf> {
    let tree = fetch(dir, pin(pins, "curl")?)?;
    let build = dir.join("build/curl");
    let curl = build.join("src/curl");
    let options = [
        format!("--with-openssl={}", reference.display()),
        "--with-openssl-quic".to_owned(),
        format!("--with-nghttp3={}", nghttp3.display()),
        "--disable-shared".to_owned(),
        "--disable-ldap".to_owned(),
        "--disable-docs".to_owned(),
        "--without-libpsl".to_owned(),
        "--without-brotli".to_owned(),
        "--without-zstd".to_owned(),
        "--without-libidn2".to_owned(),
        "--without-nghttp2".to_owned(),
        "--without-librtmp".to_owned(),
    ];
    let stamp = build.join("rustyssl-built");
    let key = format!("{}\n{}", tree.display(), options.join("\n"));
    if fs::read_to_string(&stamp).ok().as_deref() == Some(key.as_str()) && curl.exists() {
        return Ok(curl);
    }
    println!("Building curl (log: {})...", log.display());
    // A release tarball ships configure; a commit's tree is generated first.
    if !tree.join("configure").exists() {
        let mut autoreconf = Command::new("autoreconf");
        autoreconf.arg("-fi").current_dir(&tree);
        // Homebrew installs libtoolize as glibtoolize.
        if Command::new("libtoolize")
            .arg("--version")
            .output()
            .is_err()
        {
            autoreconf.env("LIBTOOLIZE", "glibtoolize");
        }
        run_logged(&mut autoreconf, log)?;
    }
    fresh_dir(&build)?;
    run_logged(
        Command::new(tree.join("configure"))
            .args(&options)
            .env("PKG_CONFIG_PATH", nghttp3.join("lib/pkgconfig"))
            .current_dir(&build),
        log,
    )?;
    let jobs = std::thread::available_parallelism().map_or(4, |n| n.get());
    run_logged(
        Command::new("make")
            .arg(format!("-j{jobs}"))
            .current_dir(&build),
        log,
    )?;
    fs::write(&stamp, key)?;
    Ok(curl)
}

/// The line that starts what the driver appends to ngtcp2's `examples/CMakeLists.txt`.
const NGTCP2_HQ_MARKER: &str = "\n# rustyssl test-quic-interop:";

/// The HTTP/0.9 variants of ngtcp2's `ossl` examples, appended to `examples/CMakeLists.txt` (as
/// its autotools build defines them for wolfSSL, the backend of its interop image).
const NGTCP2_HQ_TARGETS: &str = "
# rustyssl test-quic-interop: the HTTP/0.9 (hq-interop) ossl examples.
if(LIBEV_FOUND AND HAVE_OSSL AND LIBNGHTTP3_FOUND)
  string(REPLACE http3_client_proto_codec.cc hq_client_proto_codec.cc osslhqclient_SOURCES \"${osslclient_SOURCES}\")
  string(REPLACE http3_server_proto_codec.cc hq_server_proto_codec.cc osslhqserver_SOURCES \"${osslserver_SOURCES}\")
  foreach(t osslhqclient osslhqserver)
    add_executable(${t} ${${t}_SOURCES} $<TARGET_OBJECTS:urlparse> $<TARGET_OBJECTS:http-parser>)
    set_target_properties(${t} PROPERTIES
      COMPILE_FLAGS \"${WARNCXXFLAGS} -DWITH_EXAMPLE_OSSL -DWITH_EXAMPLE_HQ_PROTO_CODEC\"
      CXX_STANDARD 23
      CXX_STANDARD_REQUIRED ON
    )
    target_include_directories(${t} PUBLIC ${ossl_INCLUDE_DIRS})
    target_link_libraries(${t} ${ossl_LIBS})
  endforeach()
endif()
";

/// Copies a pinned submodule's tree into `place` (once).
fn submodule(dir: &Path, pins: &[Pin], name: &str, place: &Path) -> Result {
    let tree = fetch(dir, pin(pins, name)?)?;
    if fs::read_dir(place).is_ok_and(|mut d| d.next().is_some()) {
        return Ok(());
    }
    fs::create_dir_all(place)?;
    run_logged(
        Command::new("cp").arg("-R").arg(tree.join(".")).arg(place),
        &dir.join("cp.log"),
    )
}

/// nghttp3 and ngtcp2's `ossl` examples (with the HTTP/0.9 ones) built against the reference;
/// the directory holding them.
fn build_ngtcp2(reference: &Path, dir: &Path, pins: &[Pin], log: &Path) -> Result<PathBuf> {
    let prefix = build_nghttp3(dir, pins, log)?;
    let tree = fetch(dir, pin(pins, "ngtcp2")?)?;
    submodule(
        dir,
        pins,
        "ngtcp2-urlparse",
        &tree.join("third-party/urlparse"),
    )?;
    let lists = tree.join("examples/CMakeLists.txt");
    let text = fs::read_to_string(&lists)?;
    if !text.contains("set(osslclient_SOURCES") {
        return Err("ngtcp2's examples/CMakeLists.txt no longer defines osslclient".into());
    }
    if !text.ends_with(NGTCP2_HQ_TARGETS) {
        let upstream = text.split(NGTCP2_HQ_MARKER).next().unwrap_or_default();
        fs::write(&lists, format!("{upstream}{NGTCP2_HQ_TARGETS}"))?;
    }
    let build = dir.join("build/ngtcp2");
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
            format!("-DOPENSSL_ROOT_DIR={}", reference.display()),
            format!("-DCMAKE_PREFIX_PATH={}", search.join(";")),
        ],
        false,
        log,
    )?;
    let examples = ngbuild.join("examples");
    for program in ["osslclient", "osslserver", "osslhqclient", "osslhqserver"] {
        if !examples.join(program).exists() {
            return Err(format!(
                "ngtcp2 built no {program} (its examples need libev; log: {})",
                log.display()
            )
            .into());
        }
    }
    Ok(examples)
}

fn pin<'p>(pins: &'p [Pin], name: &str) -> Result<&'p Pin> {
    pins.iter()
        .find(|p| p.name == name)
        .ok_or_else(|| format!("tests/quic-interop/pins.txt pins no {name}").into())
}

/// One case between one peer and our endpoint, both ways, on each side.
struct Row {
    peer: String,
    case: &'static str,
    /// Our server, the peer's client: an outcome per side.
    ours_server: Vec<Outcome>,
    /// The peer's server, our client: an outcome per side.
    ours_client: Vec<Outcome>,
}

/// The rows' regressions: runs that pass on the reference and not on rustyssl.
fn regressions(rows: &[Row], sides: &[Side]) -> Vec<String> {
    let mut out = Vec::new();
    for r in rows {
        for (direction, outcomes) in [
            ("openssl server", &r.ours_server),
            ("openssl client", &r.ours_client),
        ] {
            let Some(reference) = outcomes.first() else {
                continue;
            };
            for (side, o) in sides.iter().zip(outcomes).skip(1) {
                if *reference == Outcome::Pass && *o != Outcome::Pass {
                    let why = match o {
                        Outcome::Fail(why) => why.clone(),
                        _ => o.label().to_owned(),
                    };
                    out.push(format!(
                        "{} {} ({direction}) on {}: {why}",
                        r.peer, r.case, side.name
                    ));
                }
            }
        }
    }
    out
}

fn write_report(root: &Path, rows: &[Row], sides: &[Side], bad: &[String]) -> Result<PathBuf> {
    let mut md = String::from("# QUIC interop: OpenSSL's QUIC API against other stacks\n\n");
    let _ = writeln!(
        md,
        "Written by `cargo xtask test-quic-interop`: quic-interop-runner's core cases \
         (`testcases_quic.py` at {RUNNER_COMMIT}) on the loopback interface, OpenSSL's interop \
         endpoint on each library against each peer, both ways. A run passes when the client \
         exits 0 and every file arrived intact.\n"
    );
    let names: Vec<&str> = sides.iter().map(|s| s.name).collect();
    let _ = writeln!(
        md,
        "| peer | case | openssl server ({}) | openssl client ({}) |",
        names.join(" / "),
        names.join(" / ")
    );
    md.push_str("|---|---|---|---|\n");
    for r in rows {
        let cell = |o: &[Outcome]| o.iter().map(Outcome::label).collect::<Vec<_>>().join(" / ");
        let _ = writeln!(
            md,
            "| {} | {} | {} | {} |",
            r.peer,
            r.case,
            cell(&r.ours_server),
            cell(&r.ours_client)
        );
    }
    let mut failures = String::new();
    for r in rows {
        for (direction, outcomes) in [
            ("openssl server", &r.ours_server),
            ("openssl client", &r.ours_client),
        ] {
            for (side, o) in sides.iter().zip(outcomes) {
                if let Outcome::Fail(why) = o {
                    let _ = writeln!(
                        failures,
                        "- {} {} ({direction}, {}): {why}",
                        r.peer, r.case, side.name
                    );
                }
            }
        }
    }
    if !failures.is_empty() {
        md.push_str("\n## Failures\n\n");
        md.push_str(&failures);
    }
    if !bad.is_empty() {
        md.push_str("\n## Passing on the reference only\n\n");
        for b in bad {
            let _ = writeln!(md, "- {b}");
        }
    }
    let path = target_dir(root).join("quic-interop-report.md");
    fs::write(&path, md)?;
    Ok(path)
}

pub fn run(args: &[String]) -> Result {
    let root = workspace_root();
    let mut reference_only = false;
    let mut peers: Vec<String> = Vec::new();
    let mut only: Vec<String> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--reference-only" => reference_only = true,
            "--peer" => {
                let p = it.next().ok_or("--peer takes a peer's name")?;
                if !PEERS.contains(&p.as_str()) {
                    return Err(
                        format!("unknown peer {p}; the peers are: {}", PEERS.join(", ")).into(),
                    );
                }
                peers.push(p.clone());
            }
            s if s.starts_with("--") => return Err(format!("unknown option {s}").into()),
            s if CASES.iter().any(|c| c.name == s) => only.push(s.to_owned()),
            s => {
                let names: Vec<&str> = CASES.iter().map(|c| c.name).collect();
                return Err(
                    format!("unknown case {s}; the cases are: {}", names.join(", ")).into(),
                );
            }
        }
    }
    if peers.is_empty() {
        peers = PEERS.iter().map(|p| (*p).to_owned()).collect();
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
    let pins = parse_pins(&fs::read_to_string(
        root.join("tests/quic-interop/pins.txt"),
    )?)?;
    let dir = target_dir(&root).join("quic-interop");
    let work = target_dir(&root).join("xtask/test-quic-interop");
    fresh_dir(&work)?;
    let log = work.join("build.log");
    let hq = build_hq(&reference, &dir.join("build"), &log)?;
    let pki = work.join("pki");
    make_pki(&reference, &pki)?;
    let h3 = build_h3(&reference, &dir, &pins, &log)?;
    let ours: Vec<Ours> = sides
        .iter()
        .map(|s| Ours {
            side: s.clone(),
            hq: hq.clone(),
            h3: h3.clone(),
        })
        .collect();
    let reference_lib = reference.join("lib");
    let mut rows = Vec::new();
    for peer_name in &peers {
        let peer: Box<dyn Endpoint> = match peer_name.as_str() {
            "quiche" => Box::new(Quiche {
                bin: build_quiche(&root, &dir, &pins, &log)?,
            }),
            "ngtcp2" => Box::new(Ngtcp2 {
                bin: build_ngtcp2(&reference, &dir, &pins, &log)?,
            }),
            "quic-go" => Box::new(QuicGo {
                bin: build_quic_go(&dir, &pins, &log)?,
            }),
            _ => return Err(format!("unknown peer {peer_name}").into()),
        };
        for (n, case) in CASES.iter().enumerate() {
            if !only.is_empty() && !only.iter().any(|o| o == case.name) {
                continue;
            }
            let seed = 0x5155_4943_0000_0000 ^ u64::try_from(n).unwrap_or(0);
            let mut row = Row {
                peer: peer.name(),
                case: case.name,
                ours_server: Vec::new(),
                ours_client: Vec::new(),
            };
            for o in &ours {
                let base = work.join(peer.name()).join(case.name).join(o.side.name);
                let a = run_case(
                    case,
                    o,
                    peer.as_ref(),
                    &base.join("openssl-server"),
                    &pki,
                    &reference_lib,
                    seed,
                )?;
                let b = run_case(
                    case,
                    peer.as_ref(),
                    o,
                    &base.join("openssl-client"),
                    &pki,
                    &reference_lib,
                    seed,
                )?;
                println!(
                    "{:<8} {:<13} {:<9} openssl server: {:<11} openssl client: {}",
                    peer.name(),
                    case.name,
                    o.side.name,
                    a.label(),
                    b.label()
                );
                row.ours_server.push(a);
                row.ours_client.push(b);
            }
            rows.push(row);
        }
    }
    let bad = regressions(&rows, &sides);
    let path = write_report(&root, &rows, &sides, &bad)?;
    if reference_only {
        // Validating the cases themselves: every supported run must pass on the reference.
        let failed = rows
            .iter()
            .flat_map(|r| r.ours_server.iter().chain(&r.ours_client))
            .filter(|o| matches!(o, Outcome::Fail(_)))
            .count();
        if failed > 0 {
            return Err(format!(
                "{failed} runs fail on the reference (report: {})",
                path.display()
            )
            .into());
        }
        println!(
            "Every supported run passes on the reference (report: {})",
            path.display()
        );
        Ok(())
    } else if bad.is_empty() {
        println!(
            "Every case passes on rustyssl wherever it passes on the reference (report: {})",
            path.display()
        );
        Ok(())
    } else {
        for b in &bad {
            println!("FAIL {b}");
        }
        Err(format!(
            "{} runs pass on the reference only (report: {})",
            bad.len(),
            path.display()
        )
        .into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cases_follow_the_runner() {
        let files = |name: &str| -> usize {
            CASES
                .iter()
                .find(|c| c.name == name)
                .map_or(0, |c| c.files.iter().map(|f| f.0).sum())
        };
        assert_eq!(files("multiplexing"), 1999);
        assert_eq!(files("zerortt"), 40);
        assert_eq!(files("transfer"), 3);
        let keyupdate = CASES.iter().find(|c| c.name == "keyupdate");
        assert_eq!(
            keyupdate.map(|c| (c.client, c.server)),
            Some(("keyupdate", "transfer"))
        );
    }

    #[test]
    fn files_are_reproducible() {
        let mut a = Random(7);
        let mut b = Random(7);
        assert_eq!(a.bytes(100), b.bytes(100));
        let name = a.name(250);
        assert_eq!(name.len(), 250);
        assert!(
            name.bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
    }

    #[test]
    fn regressions_are_reference_passes_only() {
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
        let rows = [
            Row {
                peer: "p".to_owned(),
                case: "handshake",
                ours_server: vec![Outcome::Pass, Outcome::Fail("x".to_owned())],
                ours_client: vec![Outcome::Fail("y".to_owned()), Outcome::Fail("z".to_owned())],
            },
            Row {
                peer: "p".to_owned(),
                case: "zerortt",
                ours_server: vec![Outcome::Unsupported, Outcome::Unsupported],
                ours_client: vec![Outcome::Pass, Outcome::Pass],
            },
        ];
        assert_eq!(
            regressions(&rows, &sides),
            ["p handshake (openssl server) on rustyssl: x"]
        );
    }
}
