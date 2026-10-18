//! `cargo xtask test-interop --peer gnutls`: the reference's `s_server` and `s_client`, on
//! each library, against GnuTLS's `gnutls-cli` and `gnutls-serv` (`tests/interop/gnutls.txt`).
//!
//! A case line is `name | role | openssl arguments | gnutls arguments`. The role says which
//! side GnuTLS takes: `gnutls-client` (`gnutls-cli` connects to `s_server`, which echoes lines
//! reversed with `-rev`, or for DTLS prints what it got) or `gnutls-server` (`s_client`
//! connects to `gnutls-serv --echo`). A `-dtls*` OpenSSL argument makes the case DTLS, and
//! GnuTLS gets `--udp`. The OpenSSL arguments take the placeholders of `cases.txt` and `+faults`
//! (the fault relay between the two, see [`super::relay`]); the GnuTLS arguments take `{rsa}`,
//! `{ec}`, ... (as `--x509certfile`/`--x509keyfile`), `{ca}` (`--x509cafile`) and `{dir}`.
//!
//! Each case runs twice, with OpenSSL's side on the reference and on rustyssl; the reference's
//! summary is the expectation.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::relay::Relay;
use super::{
    CLIENT_SUMMARY, SERVER_SUMMARY, TIMEOUT, Tool, free_port, indent, is_dtls, mask_err_location,
    start_server, substitute,
};
use crate::util::Result;

/// The line each client sends; `s_server -rev` answers it reversed, `gnutls-serv --echo` as is.
const LINE: &str = "hello rustyssl";

/// `gnutls-cli`'s lines about the session (the rest is certificate details, random IDs, or
/// timing).
const GNUTLS_CLIENT_SUMMARY: [&str; 8] = [
    "- Description:",
    "- Handshake was completed",
    "- Status:",
    "- Server has requested a certificate",
    "- Successfully sent",
    "*** Fatal error",
    "*** Handshake has failed",
    "*** Received alert",
];

/// `s_server`'s lines beyond the shared summary when it runs without `-rev`.
const SERVER_SESSION: [&str; 2] = ["CIPHER is", "Secure Renegotiation"];

/// A process with its output lines (`true` for standard error) arriving on a channel.
struct Proc {
    child: Child,
    stdin: Option<ChildStdin>,
    rx: mpsc::Receiver<(bool, String)>,
    lines: Vec<(bool, String)>,
}

impl Proc {
    fn spawn(mut c: Command, what: &str) -> Result<Self> {
        let mut child = c
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot start {what}: {e}"))?;
        let (tx, rx) = mpsc::channel();
        let out = child.stdout.take().ok_or("no stdout")?;
        let err = child.stderr.take().ok_or("no stderr")?;
        let tx2 = tx.clone();
        std::thread::spawn(move || {
            for l in BufReader::new(out).lines().map_while(std::io::Result::ok) {
                if tx2.send((false, l)).is_err() {
                    break;
                }
            }
        });
        std::thread::spawn(move || {
            for l in BufReader::new(err).lines().map_while(std::io::Result::ok) {
                if tx.send((true, l)).is_err() {
                    break;
                }
            }
        });
        let stdin = child.stdin.take();
        Ok(Self {
            child,
            stdin,
            rx,
            lines: Vec::new(),
        })
    }

    fn send(&mut self, line: &str) {
        if let Some(i) = self.stdin.as_mut() {
            let _ = writeln!(i, "{line}");
            let _ = i.flush();
        }
    }

    /// Takes output until a line satisfies `pred` or the time is up; whether one did.
    fn wait_for(&mut self, until: Instant, pred: impl Fn(bool, &str) -> bool) -> bool {
        if self.lines.iter().any(|(e, l)| pred(*e, l)) {
            return true;
        }
        while let Some(left) = until.checked_duration_since(Instant::now()) {
            match self.rx.recv_timeout(left.min(Duration::from_millis(50))) {
                Ok((e, l)) => {
                    let hit = pred(e, &l);
                    self.lines.push((e, l));
                    if hit {
                        return true;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return false,
            }
        }
        false
    }

    /// Closes its input and waits for it to exit (killing it after `within`); all its output.
    fn finish(mut self, within: Duration) -> Vec<(bool, String)> {
        drop(self.stdin.take());
        let until = Instant::now() + within;
        loop {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                break;
            }
            if Instant::now() >= until {
                let _ = self.child.kill();
                let _ = self.child.wait();
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        // The reader threads end with the pipes.
        let drain_until = Instant::now() + Duration::from_secs(2);
        while let Some(left) = drain_until.checked_duration_since(Instant::now()) {
            match self.rx.recv_timeout(left) {
                Ok(l) => self.lines.push(l),
                Err(_) => break,
            }
        }
        self.lines
    }
}

/// The GnuTLS arguments with the placeholders substituted.
fn gnutls_args(args: &str, dir: &Path) -> Vec<String> {
    let d = |f: &str| dir.join(f).display().to_string();
    let mut out = Vec::new();
    for a in args.split_whitespace() {
        match a {
            "{rsa}" | "{ec}" | "{p521}" | "{ed25519}" | "{mldsa65}" | "{client}" => {
                let n = a.trim_matches(|c| c == '{' || c == '}');
                out.push(format!("--x509certfile={}", d(&format!("{n}.pem"))));
                out.push(format!("--x509keyfile={}", d(&format!("{n}.key"))));
            }
            "{ca}" => out.push(format!("--x509cafile={}", d("ca.pem"))),
            _ => out.push(a.replace("{dir}", &dir.display().to_string())),
        }
    }
    out
}

/// One case's run with OpenSSL's side on one library: the summary.
fn run_case(
    t: &Tool<'_>,
    ours: bool,
    name: &str,
    role: &str,
    oargs: &[String],
    gargs: &[String],
) -> Result<String> {
    let faults = oargs.iter().any(|a| a == "+faults");
    let oargs: Vec<String> = oargs.iter().filter(|a| *a != "+faults").cloned().collect();
    let dtls = is_dtls(&oargs);
    let mut gargs = gargs.to_vec();
    if dtls {
        gargs.push("--udp".to_owned());
    }
    match role {
        "gnutls-client" => gnutls_client(t, ours, name, &oargs, &gargs, dtls, faults),
        "gnutls-server" => gnutls_server(t, ours, name, &oargs, &gargs, dtls, faults),
        _ => Err(format!("unknown role {role} (gnutls-client or gnutls-server)").into()),
    }
}

/// `gnutls-cli` against `s_server` on the library.
fn gnutls_client(
    t: &Tool<'_>,
    ours: bool,
    name: &str,
    oargs: &[String],
    gargs: &[String],
    dtls: bool,
    faults: bool,
) -> Result<String> {
    let port = free_port()?;
    let (mut server, srx) = start_server(t, ours, port, 1, oargs, !dtls)?;
    let relay = if faults {
        Some(Relay::start(port, name)?)
    } else {
        None
    };
    let cport = relay.as_ref().map_or(port, |r| r.port);
    let mut c = Command::new("gnutls-cli");
    c.args(["127.0.0.1", "-p", &cport.to_string()])
        .args(["--sni-hostname=localhost", "--verify-hostname=localhost"])
        .arg(format!("--x509cafile={}", t.work.join("ca.pem").display()))
        .args(gargs)
        .current_dir(t.work);
    let mut client = Proc::spawn(c, "gnutls-cli")?;
    client.send(LINE);
    let until = Instant::now() + TIMEOUT;
    let reversed: String = LINE.chars().rev().collect();
    let mut server_lines = Vec::new();
    let delivered = if dtls {
        // The server prints the line it got.
        let mut got = false;
        while Instant::now() < until && !got {
            match srx.recv_timeout(Duration::from_millis(50)) {
                Ok(l) => {
                    got = l == LINE;
                    server_lines.push(l);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            // Keep the client's output moving.
            let _ = client.wait_for(Instant::now(), |_, _| false);
        }
        got
    } else {
        client.wait_for(until, |e, l| !e && l == reversed)
    };
    let client_lines = client.finish(Duration::from_secs(5));
    // The server exits after its connection (`-naccept 1`).
    let spid = server.id();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(server.wait());
    });
    if rx.recv_timeout(Duration::from_secs(5)).is_err() {
        let _ = Command::new("kill").arg(spid.to_string()).status();
    }
    server_lines.extend(srx.try_iter());
    while let Ok(l) = srx.recv_timeout(Duration::from_millis(200)) {
        server_lines.push(l);
    }
    if let Some(r) = &relay {
        let [up, down] = r.counts();
        println!(
            "  relay ({}): client->server {up:?}, server->client {down:?}",
            lib(ours)
        );
    }
    let mut summary = String::new();
    for (_, l) in &client_lines {
        if GNUTLS_CLIENT_SUMMARY.iter().any(|k| l.starts_with(k)) {
            summary.push_str(&format!("gnutls-cli: {l}\n"));
        }
    }
    summary.push_str(if delivered {
        "data: ok\n"
    } else {
        "data: MISSING\n"
    });
    let (errs, outs): (Vec<&String>, Vec<&String>) =
        server_lines.iter().partition(|l| l.starts_with("stderr: "));
    for line in outs.into_iter().chain(errs) {
        let line = line.strip_prefix("stderr: ").unwrap_or(line);
        if SERVER_SUMMARY.iter().any(|k| line.starts_with(k))
            || SERVER_SESSION.iter().any(|k| line.starts_with(k))
        {
            summary.push_str(&format!("server: {line}\n"));
        }
    }
    if !delivered {
        for (_, l) in &client_lines {
            summary.push_str(&format!("gnutls-cli said: {l}\n"));
        }
        let lines: Vec<String> = server_lines.iter().map(|l| mask_err_location(l)).collect();
        summary.push_str(&format!("server: {}\n", lines.join(" / ")));
    }
    Ok(summary)
}

/// `s_client` on the library against `gnutls-serv --echo`.
fn gnutls_server(
    t: &Tool<'_>,
    ours: bool,
    name: &str,
    oargs: &[String],
    gargs: &[String],
    dtls: bool,
    faults: bool,
) -> Result<String> {
    // It binds the port on every address, and for DTLS over UDP: a port can be taken there
    // though it's free for TCP on 127.0.0.1, so a failed bind tries another.
    let mut started = None;
    for _ in 0..5 {
        let port = if dtls { free_udp_port()? } else { free_port()? };
        let mut c = Command::new("gnutls-serv");
        c.args(["--echo", "-p", &port.to_string()]);
        if !gargs.iter().any(|a| a.starts_with("--x509certfile")) {
            c.args(gnutls_args("{rsa}", t.work));
        }
        c.args(gargs).current_dir(t.work);
        let mut server = Proc::spawn(c, "gnutls-serv")?;
        let ready = server.wait_for(Instant::now() + TIMEOUT, |_, l| {
            l.contains("IPv4") && (l.ends_with("done") || l.contains("failed"))
        });
        let bound = server
            .lines
            .iter()
            .any(|(_, l)| l.contains("IPv4") && l.ends_with("done"));
        if ready && bound {
            started = Some((server, port));
            break;
        }
        let _ = server.finish(Duration::from_millis(200));
    }
    let Some((server, port)) = started else {
        return Err("gnutls-serv didn't start (no port it could bind)".into());
    };
    let relay = if faults {
        Some(Relay::start(port, name)?)
    } else {
        None
    };
    let cport = relay.as_ref().map_or(port, |r| r.port);
    let mut all = vec![
        "s_client".to_owned(),
        "-connect".to_owned(),
        format!("127.0.0.1:{cport}"),
        "-brief".to_owned(),
        "-servername".to_owned(),
        "localhost".to_owned(),
    ];
    all.extend(oargs.iter().cloned());
    let mut client = Proc::spawn(t.command(ours, &all), "s_client")?;
    client.send(LINE);
    let echoed = client.wait_for(Instant::now() + TIMEOUT, |e, l| !e && l == LINE);
    let client_lines = client.finish(Duration::from_secs(5));
    let _server_lines = server.finish(Duration::from_millis(200));
    if let Some(r) = &relay {
        let [up, down] = r.counts();
        println!(
            "  relay ({}): client->server {up:?}, server->client {down:?}",
            lib(ours)
        );
    }
    let mut summary = String::new();
    for (e, l) in &client_lines {
        if *e && CLIENT_SUMMARY.iter().any(|k| l.starts_with(k)) {
            summary.push_str(l);
            summary.push('\n');
        }
    }
    summary.push_str(if echoed {
        "echo: ok\n"
    } else {
        "echo: MISSING\n"
    });
    if !echoed {
        for (_, l) in &client_lines {
            summary.push_str(&format!("s_client said: {}\n", mask_err_location(l)));
        }
    }
    Ok(summary)
}

/// A UDP port free on every IPv4 address (the socket is closed again).
fn free_udp_port() -> Result<u16> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0")?;
    Ok(s.local_addr()?.port())
}

fn lib(ours: bool) -> &'static str {
    if ours { "rustyssl" } else { "reference" }
}

pub(super) fn run(t: &Tool<'_>, root: &Path, only: &[&String], reference_only: bool) -> Result {
    for tool in ["gnutls-cli", "gnutls-serv"] {
        if Command::new(tool).arg("--version").output().is_err() {
            println!("test-interop --peer gnutls: {tool} isn't installed; skipped");
            return Ok(());
        }
    }
    let list = fs::read_to_string(root.join("tests/interop/gnutls.txt"))?;
    let mut failures = Vec::new();
    let mut count = 0;
    for line in list.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(4, '|').map(str::trim);
        let (Some(name), Some(role), Some(oargs), Some(gargs)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(format!("malformed case: {line}").into());
        };
        if !only.is_empty() && !only.iter().any(|o| o.as_str() == name) {
            continue;
        }
        count += 1;
        let oargs = substitute(oargs, t.work);
        let gargs = gnutls_args(gargs, t.work);
        let expected = match run_case(t, false, name, role, &oargs, &gargs) {
            Ok(s) if s.contains("MISSING") => {
                println!("FAIL {name}: the reference run failed:\n{}", indent(&s));
                failures.push(name.to_owned());
                continue;
            }
            Ok(s) => s,
            Err(e) => {
                println!("FAIL {name}: the reference run failed: {e}");
                failures.push(name.to_owned());
                continue;
            }
        };
        if reference_only {
            println!("PASS {name} (reference only)\n{}", indent(&expected));
            continue;
        }
        match run_case(t, true, name, role, &oargs, &gargs) {
            Ok(got) if got == expected => println!("PASS {name}"),
            Ok(got) => {
                println!(
                    "FAIL {name}:\n  expected:\n{}\n  got:\n{}",
                    indent(&expected),
                    indent(&got)
                );
                failures.push(name.to_owned());
            }
            Err(e) => {
                println!("FAIL {name} (rustyssl): {e}");
                failures.push(name.to_owned());
            }
        }
    }
    if failures.is_empty() {
        println!("{count} GnuTLS interop cases pass on both libraries");
        Ok(())
    } else {
        Err(format!("failed: {}", failures.join(", ")).into())
    }
}
