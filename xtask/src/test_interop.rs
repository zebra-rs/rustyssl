//! `cargo xtask test-interop`: TLS between the reference OpenSSL and rustyssl (milestone M2's
//! "interop with reference `s_client`/`s_server`").
//!
//! Each line of `tests/interop/cases.txt` runs the reference's `openssl s_server` (echoing
//! lines reversed, `-rev`) and `openssl s_client -brief` against each other in four pairings:
//! reference/reference, rustyssl server, rustyssl client, rustyssl/rustyssl, by pointing the
//! dynamic loader at each library. The reference/reference run is the expectation: every
//! other pairing must connect, echo, and report the same handshake summary (protocol, cipher,
//! peer certificate, signature, temporary key).
//!
//! A case line is `name | server arguments | client arguments`, with `{rsa}`, `{ec}`,
//! `{p521}`, `{ed25519}`, `{mldsa65}` (a server's `-cert`/`-key` pair), `{client}` (a client's), `{ca}` (the
//! root to verify with), `{srpvfile}` (an SRP verifier file with the user `user`, password
//! `password`), and `{dir}` substituted. Lines starting with `#` are comments. Client
//! arguments starting with `+` direct the harness:
//!
//! - `+full`: the client runs without `-brief`, and the summary takes its session lines
//!   (`New,`/`Reused,`, ALPN, secure renegotiation) from its standard output.
//! - `+resume`: two connections, the first saving its session (`-sess_out`) and the second, a
//!   `+full` one, resuming it (`-sess_in`); the summary says whether it was reused.
//! - `+trace`: the client also runs with `-trace`, and the summary takes the trace (its random
//!   octets masked) from its standard output.
//! - `+early`: with `+resume`, the second connection sends a line as TLS 1.3 early data
//!   (`-early_data`).
//! - `+cmd=X`: the client first sends the command line `X` (`R` renegotiates, `k`/`K` update
//!   the keys), then the data a second later; commands need it to run without `-ign_eof`, so
//!   its input stays open until it exits.
//! - `+faults`: for a DTLS case, the client talks to the server through a relay that drops,
//!   duplicates and reorders handshake datagrams by a schedule from `--seed` (see [`relay`]).
//!   The client runs with `-nbio`, as a stale datagram after the handshake would leave a
//!   blocking one waiting in `recvfrom`.
//!
//! A DTLS case runs without `-rev` (which `s_server` refuses with DTLS): the server printing
//! the line the client sent stands for the echo.
//!
//! `--peer gnutls` runs `tests/interop/gnutls.txt` instead, against GnuTLS (see [`gnutls`]);
//! `--peer quic` runs `tests/interop/quic.txt`, QUIC with OpenSSL's QUIC demos and `s_client
//! -quic` (see [`quic`]).
//!
//! The server's report of the client (its certificate, the ALPN list and the host name it
//! sent) joins the summary.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

mod gnutls;
mod quic;
mod relay;

use crate::test_c::{LOADER_PATH, prepare};
use crate::util::{Result, fresh_dir, target_dir, workspace_root};

/// The configuration file every run is pointed at, one that doesn't exist.
const MISSING_CONFIG: &str = "/nonexistent/rustyssl-tests/openssl.cnf";

/// How long a server may take to start, and a connection to finish.
const TIMEOUT: Duration = Duration::from_secs(30);

/// The client's handshake summary lines on standard error (`-brief`); the rest (verify depth
/// lines, DONE) is the same or timing-dependent.
const CLIENT_SUMMARY: [&str; 12] = [
    "CONNECTION ESTABLISHED",
    "Protocol version",
    "Ciphersuite",
    "Peer certificate",
    "Hash used",
    "Signature type",
    "Verification",
    "Peer Temp Key",
    "Negotiated TLS1.3 group",
    "Peer signature",
    "Supported",
    "Shared",
];

/// The client's session lines on standard output without `-brief` (`print_stuff`).
const CLIENT_SESSION: [&str; 6] = [
    "New, ",
    "Reused, ",
    "ALPN protocol",
    "No ALPN",
    "Secure Renegotiation",
    "Server public key",
];

/// The client's lines for a command (`user_data_execute`).
const CLIENT_COMMAND: [&str; 3] = ["RENEGOTIATING", "KEYUPDATE", "ERROR"];

/// The server's lines about the client.
/// The lines of an `-early_data` server (no `-rev`) that say what it received.
const SERVER_EARLY: [&str; 4] = [
    "Early data received:",
    "early data",
    "End of early data",
    "hello rustyssl",
];

const SERVER_SUMMARY: [&str; 6] = [
    "SSL_accept:",
    "Peer certificate",
    "No peer certificate",
    "ALPN protocols advertised",
    "Hostname in TLS extension",
    "Switching server context",
];

/// Which library each side uses.
#[derive(Clone, Copy)]
struct Pairing {
    name: &'static str,
    server_ours: bool,
    client_ours: bool,
}

const PAIRINGS: [Pairing; 4] = [
    Pairing {
        name: "reference/reference",
        server_ours: false,
        client_ours: false,
    },
    Pairing {
        name: "rustyssl server",
        server_ours: true,
        client_ours: false,
    },
    Pairing {
        name: "rustyssl client",
        server_ours: false,
        client_ours: true,
    },
    Pairing {
        name: "rustyssl/rustyssl",
        server_ours: true,
        client_ours: true,
    },
];

/// The reference tool with a library directory.
struct Tool<'a> {
    bin: &'a Path,
    reference: &'a Path,
    ours: &'a Path,
    work: &'a Path,
}

impl Tool<'_> {
    fn command(&self, ours: bool, args: &[String]) -> Command {
        let mut c = Command::new(self.bin);
        c.args(args)
            .current_dir(self.work)
            .env(LOADER_PATH, if ours { self.ours } else { self.reference })
            .env(
                "OPENSSL_MODULES",
                crate::test_c::modules_of(if ours { self.ours } else { self.reference }),
            )
            .env("OPENSSL_CONF", MISSING_CONFIG);
        c
    }

    /// Runs a command to completion on the reference library (setting up the PKI).
    fn setup(&self, args: &[&str]) -> Result {
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        let cnf = self.work.join("setup.cnf");
        fs::write(&cnf, "[req]\ndistinguished_name = dn\n[dn]\n")?;
        let out = self
            .command(false, &args)
            .env("OPENSSL_CONF", &cnf)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("cannot run the reference openssl: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "openssl {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr)
            )
            .into());
        }
        Ok(())
    }
}

/// A test PKI: a root, five servers (RSA, ECDSA P-256 and P-521, Ed25519, ML-DSA-65), and an
/// RSA client it issued.
fn make_pki(t: &Tool<'_>, dir: &Path) -> Result {
    let d = |f: &str| dir.join(f).display().to_string();
    t.setup(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        &d("ca.key"),
        "-out",
        &d("ca.pem"),
        "-days",
        "3650",
        "-subj",
        "/O=rustyssl interop/CN=Interop Root",
        "-addext",
        "basicConstraints=critical,CA:true",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    ])?;
    for (name, alg) in [
        ("rsa", "rsa:2048"),
        ("ec", "P-256"),
        ("p521", "P-521"),
        ("ed25519", "ed25519"),
        ("mldsa65", "ML-DSA-65"),
        ("client", "rsa:2048"),
    ] {
        let mut req = vec![
            "req".to_owned(),
            "-new".to_owned(),
            "-nodes".to_owned(),
            "-keyout".to_owned(),
            d(&format!("{name}.key")),
            "-out".to_owned(),
            d(&format!("{name}.csr")),
            "-subj".to_owned(),
            format!("/O=rustyssl interop/CN=localhost-{name}"),
        ];
        if let Some(curve) = alg.strip_prefix("P-") {
            req.extend([
                "-newkey".to_owned(),
                "ec".to_owned(),
                "-pkeyopt".to_owned(),
                format!("ec_paramgen_curve:P-{curve}"),
            ]);
        } else {
            req.extend(["-newkey".to_owned(), alg.to_owned()]);
        }
        let args: Vec<&str> = req.iter().map(String::as_str).collect();
        t.setup(&args)?;
        let ext = if name == "client" {
            "basicConstraints=CA:false\nextendedKeyUsage=clientAuth\n"
        } else {
            "subjectAltName=DNS:localhost\nbasicConstraints=CA:false\n"
        };
        fs::write(dir.join("ext.cnf"), ext)?;
        t.setup(&[
            "x509",
            "-req",
            "-in",
            &d(&format!("{name}.csr")),
            "-CA",
            &d("ca.pem"),
            "-CAkey",
            &d("ca.key"),
            "-CAcreateserial",
            "-days",
            "3650",
            "-extfile",
            &d("ext.cnf"),
            "-out",
            &d(&format!("{name}.pem")),
        ])?;
    }
    // An SRP verifier file with the user "user", password "password", in the 1024-bit group.
    fs::write(dir.join("srp.txt"), "")?;
    t.setup(&[
        "srp",
        "-srpvfile",
        &d("srp.txt"),
        "-add",
        "-gn",
        "1024",
        "-passout",
        "pass:password",
        "user",
    ])?;
    Ok(())
}

/// The case's arguments with the placeholders substituted.
fn substitute(args: &str, dir: &Path) -> Vec<String> {
    let d = |f: &str| dir.join(f).display().to_string();
    let mut out = Vec::new();
    for a in args.split_whitespace() {
        match a {
            "{rsa}" | "{ec}" | "{p521}" | "{ed25519}" | "{mldsa65}" | "{client}" => {
                let n = a.trim_matches(|c| c == '{' || c == '}');
                out.extend([
                    "-cert".to_owned(),
                    d(&format!("{n}.pem")),
                    "-key".to_owned(),
                    d(&format!("{n}.key")),
                ]);
            }
            "{ca}" => out.extend(["-CAfile".to_owned(), d("ca.pem")]),
            "{srpvfile}" => out.extend(["-srpvfile".to_owned(), d("srp.txt")]),
            _ => out.push(a.replace("{dir}", &dir.display().to_string())),
        }
    }
    out
}

/// A free local port, TCP's or (for a DTLS server) UDP's: the socket is closed again and the
/// server binds the port next.
fn free_port(udp: bool) -> Result<u16> {
    if udp {
        let s = std::net::UdpSocket::bind("127.0.0.1:0")?;
        return Ok(s.local_addr()?.port());
    }
    let l = TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

/// How many times `s_server` is started on a new port when another process took the one
/// [`free_port`] found before the server could bind it.
const BIND_ATTEMPTS: usize = 3;

/// Starts `s_server` and waits for it to accept; returns it with its output so far.
fn start_server(
    t: &Tool<'_>,
    ours: bool,
    port: u16,
    naccept: usize,
    args: &[String],
    rev: bool,
) -> Result<(Child, mpsc::Receiver<String>)> {
    let mut all = vec![
        "s_server".to_owned(),
        "-accept".to_owned(),
        format!("127.0.0.1:{port}"),
        "-naccept".to_owned(),
        naccept.to_string(),
    ];
    // `-rev` echoes; it can't be combined with `-early_data`, whose server prints what it got.
    if rev {
        all.push("-rev".to_owned());
    }
    if !args.iter().any(|a| a == "-cert") {
        all.extend(substitute("{rsa}", t.work));
    }
    all.extend(args.iter().cloned());
    // Without `-rev` the server quits at the end of its input: it stays open (in the child).
    let stdin = if rev { Stdio::null() } else { Stdio::piped() };
    let mut child = t
        .command(ours, &all)
        .stdin(stdin)
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
        let mut s = String::new();
        let _ = stderr.read_to_string(&mut s);
        for line in s.lines() {
            let _ = tx.send(format!("stderr: {line}"));
        }
    });
    let mut seen = String::new();
    loop {
        match rx.recv_timeout(TIMEOUT) {
            Ok(line) => {
                let accepting = line.starts_with("ACCEPT");
                seen.push_str(&line);
                seen.push('\n');
                if accepting {
                    return Ok((child, rx));
                }
            }
            Err(_) => {
                let _ = child.kill();
                return Err(format!("s_server didn't start:\n{seen}").into());
            }
        }
    }
}

/// How a case's client runs (its `+` directives).
#[derive(Default)]
struct Mode {
    full: bool,
    resume: bool,
    early: bool,
    cmd: Option<String>,
    trace: bool,
    faults: bool,
}

/// The client arguments without the directives, and the directives.
fn mode(args: &[String]) -> (Vec<String>, Mode) {
    let mut m = Mode::default();
    let mut rest = Vec::new();
    for a in args {
        match a.as_str() {
            "+full" => m.full = true,
            "+resume" => m.resume = true,
            "+trace" => m.trace = true,
            "+early" => m.early = true,
            "+faults" => m.faults = true,
            _ => match a.strip_prefix("+cmd=") {
                Some(c) => m.cmd = Some(c.to_owned()),
                None => rest.push(a.clone()),
            },
        }
    }
    (rest, m)
}

/// One `s_client` run: its summary, or why it failed.
#[expect(
    clippy::too_many_arguments,
    reason = "one per s_client mode the cases combine"
)]
fn client(
    t: &Tool<'_>,
    ours: bool,
    port: u16,
    args: &[String],
    full: bool,
    no_echo: Option<Duration>,
    cmd: Option<&str>,
    trace: bool,
) -> Result<String> {
    let mut all = vec![
        "s_client".to_owned(),
        "-connect".to_owned(),
        format!("127.0.0.1:{port}"),
    ];
    if !full {
        all.push("-brief".to_owned());
    }
    if trace {
        all.push("-trace".to_owned());
    }
    // `-ign_eof` turns the commands off (`USER_DATA_MODE_NONE`). With no echo coming, the end of
    // the input ends the client.
    if cmd.is_none() && no_echo.is_none() {
        all.push("-ign_eof".to_owned());
    }
    all.extend(args.iter().cloned());
    let mut child = t
        .command(ours, &all)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot start s_client: {e}"))?;
    let pid = child.id();
    let mut stdin = child.stdin.take();
    if let Some(input) = stdin.as_mut() {
        if let Some(c) = cmd {
            // A command takes the whole read: the data follows once it has run.
            let _ = writeln!(input, "{c}");
            let _ = input.flush();
            std::thread::sleep(Duration::from_secs(1));
        }
        // `-rev` reverses each line and ends the connection on CLOSE.
        let _ = input.write_all(b"hello rustyssl\nCLOSE\n");
        let _ = input.flush();
        if let Some(wait) = no_echo {
            // No echo ends the connection: the session's tickets (and, with faults, the
            // retransmitted flights) arrive first.
            std::thread::sleep(wait);
        }
    }
    if cmd.is_none() {
        drop(stdin.take());
    }
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    let got = rx.recv_timeout(TIMEOUT);
    drop(stdin);
    let out = match got {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return Err(format!("s_client failed: {e}").into()),
        Err(_) => {
            let _ = Command::new("kill").arg(pid.to_string()).status();
            // What it said before it was stopped.
            let said = match rx.recv_timeout(Duration::from_secs(5)) {
                Ok(Ok(o)) => format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                ),
                _ => String::new(),
            };
            let said: Vec<String> = said.lines().map(mask_err_location).collect();
            return Err(
                format!("s_client timed out; it said:\n{}", indent(&said.join("\n"))).into(),
            );
        }
    };
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut summary = String::new();
    let mut lines = if full {
        stdout
            .lines()
            .filter(|l| CLIENT_SESSION.iter().any(|k| l.starts_with(k)))
            .collect::<Vec<_>>()
    } else {
        stderr
            .lines()
            .filter(|l| CLIENT_SUMMARY.iter().any(|k| l.starts_with(k)))
            .collect()
    };
    // What a command did (`ERROR` when it failed).
    lines.extend(stderr.lines().filter(|l| CLIENT_COMMAND.contains(l)));
    for line in lines {
        summary.push_str(line);
        summary.push('\n');
    }
    if no_echo.is_some() {
        summary.push_str("echo: none\n");
        return Ok(summary);
    }
    // `-trace`'s lines (on standard output), with the random octets masked. The echo is written
    // to the descriptor directly while the trace is buffered, so it lands anywhere in it.
    let echo = "lssytsur olleh\n";
    let echoed = if trace {
        for line in stdout.replacen(echo, "", 1).lines() {
            summary.push_str("trace: ");
            summary.push_str(&mask_trace(line));
            summary.push('\n');
        }
        stdout.contains(echo)
    } else {
        stdout.lines().any(|l| l == "lssytsur olleh")
    };
    summary.push_str(if echoed {
        "echo: ok\n"
    } else {
        "echo: MISSING\n"
    });
    if !echoed {
        let stderr: Vec<String> = stderr.lines().map(mask_err_location).collect();
        summary.push_str(&format!("client stderr: {}\n", stderr.join("\n")));
    }
    Ok(summary)
}

/// Whether the server's arguments make it a DTLS server.
fn is_dtls(server_args: &[String]) -> bool {
    server_args.iter().any(|a| a.starts_with("-dtls"))
}

/// One case in one pairing: the clients' summaries and what the server said of them.
fn connect(
    t: &Tool<'_>,
    p: Pairing,
    server_args: &[String],
    client_args: &[String],
) -> Result<String> {
    let (mut args, m) = mode(client_args);
    let naccept = if m.resume { 2 } else { 1 };
    // `-rev` can't be used with DTLS: no echo then (the summaries and the server's output are
    // compared).
    let dtls = is_dtls(server_args);
    let mut attempt = 0;
    let (port, mut server, lines) = loop {
        let port = free_port(dtls)?;
        match start_server(
            t,
            p.server_ours,
            port,
            naccept,
            server_args,
            !m.early && !dtls,
        ) {
            Ok((server, lines)) => break (port, server, lines),
            Err(e) if attempt + 1 < BIND_ATTEMPTS && e.to_string().contains("already in use") => {
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    };
    // With faults, the client talks to the relay; its schedule is the case's.
    let relay = if m.faults && dtls {
        Some(relay::Relay::start(port, &client_args.join(" "))?)
    } else {
        None
    };
    let client_port = relay.as_ref().map_or(port, |r| r.port);
    if relay.is_some() {
        // Non-blocking: a duplicated or held-back flight that arrives after the handshake is
        // read and discarded, and a blocking `s_client` (`dtls1_read_bytes` reading again)
        // would then wait in `recvfrom` for a datagram that never comes, on either library.
        args.push("-nbio".to_owned());
    }
    // How long a client with no echo to wait for keeps its input open: with faults, past the
    // longest retransmission run the relay allows (three drops: 1 + 2 + 4 seconds) with room
    // for a loaded machine.
    let wait = Duration::from_secs(if relay.is_some() { 15 } else { 1 });
    let sess = t.work.join("session.pem").display().to_string();
    let mut runs = Vec::new();
    if m.resume {
        let _ = fs::remove_file(&sess);
        let mut first = args.clone();
        first.extend(["-sess_out".to_owned(), sess.clone()]);
        runs.push((first, m.full, false));
        let mut second = args.clone();
        second.extend(["-sess_in".to_owned(), sess.clone()]);
        if m.early {
            let early = t.work.join("early.txt");
            fs::write(&early, "early data\n")?;
            second.extend(["-early_data".to_owned(), early.display().to_string()]);
        }
        runs.push((second, true, m.early));
    } else {
        runs.push((args, m.full, false));
    }
    let mut summary = String::new();
    for (args, full, early) in &runs {
        let no_echo = (*early || m.early || dtls).then_some(wait);
        match client(
            t,
            p.client_ours,
            client_port,
            args,
            *full,
            no_echo,
            m.cmd.as_deref(),
            m.trace,
        ) {
            Ok(s) => summary.push_str(&s),
            Err(e) => {
                let _ = server.kill();
                let _ = server.wait();
                return Err(e);
            }
        }
    }
    // The server exits after its connections (`-naccept`); its output is complete then.
    let spid = server.id();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(server.wait());
    });
    let exited = rx.recv_timeout(Duration::from_secs(5)).is_ok();
    if !exited {
        let _ = Command::new("kill").arg(spid.to_string()).status();
    }
    let server_out: Vec<String> = if exited {
        lines.iter().collect()
    } else {
        lines.try_iter().collect()
    };
    // Standard output, then standard error: the two streams arrive in no fixed order.
    let (errs, outs): (Vec<&String>, Vec<&String>) =
        server_out.iter().partition(|l| l.starts_with("stderr: "));
    for line in outs.into_iter().chain(errs) {
        let line = line.strip_prefix("stderr: ").unwrap_or(line);
        if SERVER_SUMMARY.iter().any(|k| line.starts_with(k))
            || (m.early && SERVER_EARLY.contains(&line))
            || (dtls && line == "hello rustyssl")
        {
            summary.push_str("server: ");
            summary.push_str(line);
            summary.push('\n');
        }
    }
    if let Some(r) = &relay {
        // The relay's work, for the log (the counts vary with retransmission timing).
        let [up, down] = r.counts();
        println!(
            "  relay ({}): client->server {up:?}, server->client {down:?}",
            p.name
        );
    }
    let data_missing = dtls && !summary.lines().any(|l| l == "server: hello rustyssl");
    if summary.contains("echo: MISSING") || data_missing {
        let lines: Vec<String> = server_out.iter().map(|l| mask_err_location(l)).collect();
        summary.push_str(&format!("server: {}\n", lines.join(" / ")));
    }
    Ok(summary)
}

pub fn run(args: &[String]) -> Result {
    let root = workspace_root();
    let (reference, dist) = prepare(&root)?;
    let bin = reference.join("bin/openssl");
    let work = target_dir(&root).join("xtask/test-interop");
    fresh_dir(&work)?;
    let ref_lib = reference.join("lib");
    let our_lib = dist.join("lib");
    let t = Tool {
        bin: &bin,
        reference: &ref_lib,
        ours: &our_lib,
        work: &work,
    };
    let mut only: Vec<&String> = Vec::new();
    let mut peer = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--seed" => {
                let s = it.next().ok_or("--seed needs a number")?;
                relay::set_seed(s.parse().map_err(|_| format!("bad --seed {s}"))?);
            }
            "--peer" => peer = Some(it.next().ok_or("--peer needs a name")?.as_str()),
            "--reference-only" => {}
            _ if a.starts_with("--") => return Err(format!("unknown option {a}").into()),
            _ => only.push(a),
        }
    }
    let reference_only = args.iter().any(|a| a == "--reference-only");
    make_pki(&t, &work)?;
    println!("fault schedule seed: {}", relay::seed());
    match peer {
        None => {}
        Some("gnutls") => return gnutls::run(&t, &root, &only, reference_only),
        Some("quic") => return quic::run(&t, &root, &only),
        Some(p) => return Err(format!("unknown peer {p} (known: gnutls, quic)").into()),
    }

    let list = fs::read_to_string(root.join("tests/interop/cases.txt"))?;
    let mut failures = Vec::new();
    let mut count = 0;
    for line in list.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(3, '|').map(str::trim);
        let (Some(name), Some(sargs), Some(cargs)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(format!("malformed case: {line}").into());
        };
        if !only.is_empty() && !only.iter().any(|o| o.as_str() == name) {
            continue;
        }
        count += 1;
        let (sargs, cargs) = (substitute(sargs, &work), substitute(cargs, &work));
        let expected = match connect(&t, PAIRINGS[0], &sargs, &cargs) {
            Ok(s) => s,
            Err(e) => {
                println!("FAIL {name}: the reference/reference run failed: {e}");
                failures.push(name.to_owned());
                continue;
            }
        };
        let mut ok = true;
        if reference_only {
            println!(
                "PASS {name} (reference/reference only)\n{}",
                indent(&expected)
            );
            continue;
        }
        for p in PAIRINGS.iter().skip(1) {
            match connect(&t, *p, &sargs, &cargs) {
                Ok(got) if got == expected => {}
                Ok(got) => {
                    ok = false;
                    // Both whole, for a diff (the summaries with traces are long).
                    let base = work.join(format!("{name}-{}", p.name.replace(['/', ' '], "-")));
                    let _ = fs::write(base.with_extension("expected"), &expected);
                    let _ = fs::write(base.with_extension("got"), &got);
                    println!(
                        "FAIL {name} ({}):\n  expected:\n{}\n  got:\n{}",
                        p.name,
                        indent(&expected),
                        indent(&got)
                    );
                }
                Err(e) => {
                    ok = false;
                    println!("FAIL {name} ({}): {e}", p.name);
                }
            }
        }
        if ok {
            println!("PASS {name}");
        } else {
            failures.push(name.to_owned());
        }
    }
    if failures.is_empty() {
        if reference_only {
            println!("{count} interop cases pass on the reference");
        } else {
            println!("{count} interop cases pass in all four pairings");
        }
        Ok(())
    } else {
        Err(format!("failed: {}", failures.join(", ")).into())
    }
}

/// A trace line with what varies between runs masked: hex octets (`name (len=N): …`), the time
/// in a random, and `ticket_age_add`.
fn mask_trace(line: &str) -> String {
    if let Some(i) = line.find("): ") {
        return format!("{}): *", &line[..i]);
    }
    for label in ["gmt_unix_time=", "ticket_age_add="] {
        if let Some(i) = line.find(label) {
            return format!("{}{label}*", &line[..i]);
        }
    }
    line.to_owned()
}

/// An `ERR_print_errors` line with its source location masked (`…:reason:FILE:LINE:data`): the
/// file and line are the implementation's, not behavior. The thread id before `:error:` is
/// masked too: on Linux it's the thread's address, which differs from run to run.
fn mask_err_location(line: &str) -> String {
    let Some(at) = line.find(":error:") else {
        return line.to_owned();
    };
    let id_start = line[..at]
        .rfind(|c: char| !c.is_ascii_hexdigit())
        .map_or(0, |i| i + 1);
    let masked = format!("{}*{}", &line[..id_start], &line[at..]);
    let line = masked.as_str();
    let at = id_start + 1;
    // thread id, "error", code, library, function, reason, file, line, data
    let fields: Vec<&str> = line[at + 1..].splitn(8, ':').collect();
    match fields.as_slice() {
        [e, code, lib, func, reason, _file, rest @ ..] => {
            let data = rest
                .first()
                .and_then(|r| r.split_once(':'))
                .map_or("", |(_, d)| d);
            format!(
                "{}:{e}:{code}:{lib}:{func}:{reason}:*:*:{data}",
                &line[..at]
            )
        }
        _ => line.to_owned(),
    }
}

fn indent(s: &str) -> String {
    s.lines()
        .map(|l| format!("    {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::mask_err_location;

    #[test]
    fn error_lines_lose_their_thread_and_location() {
        assert_eq!(
            mask_err_location(
                "807BE6FEFF7F0000:error:0A0000BF:SSL routines:tls_setup_handshake:no protocols available:ssl/statem/statem_lib.c:155:"
            ),
            "*:error:0A0000BF:SSL routines:tls_setup_handshake:no protocols available:*:*:"
        );
        assert_eq!(mask_err_location("no error here"), "no error here");
    }
}
