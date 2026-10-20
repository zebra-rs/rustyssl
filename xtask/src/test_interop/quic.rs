//! `cargo xtask test-interop --peer quic`: QUIC between the reference OpenSSL and rustyssl
//! (`tests/interop/quic.txt`).
//!
//! The reference's `s_server` has no QUIC mode, so the servers are OpenSSL's own QUIC demos
//! (`demos/guide/quic-server-block.c` and `quic-server-non-block.c`, built from the reference's
//! source against the vendored headers); the clients are the guide's QUIC clients and the
//! reference's `s_client -quic`. A case line is `name | server | client`, the client being a
//! demo's name or `s_client` with its arguments (`{port}` substituted). Each case runs in four
//! pairings by pointing the dynamic loader at each library; the reference/reference run is the
//! expectation for the client's output and exit status.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::{Tool, free_port, mask_err_location};
use crate::test_c::{LOADER_PATH, cc};
use crate::util::{Result, run_output};

/// The demos built: the servers and the clients.
const DEMOS: [&str; 4] = [
    "quic-server-block",
    "quic-server-non-block",
    "quic-client-block",
    "quic-client-non-block",
];

/// How long a client may take.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(30);

/// Builds the demos into `work`.
fn build(t: &Tool<'_>, src: &Path, work: &Path) -> Result {
    let include = t.ours.parent().ok_or("no dist directory")?.join("include");
    for demo in DEMOS {
        run_output(
            cc().arg("-g")
                .arg("-I")
                .arg(&include)
                .arg(src.join(format!("demos/guide/{demo}.c")))
                .arg("-L")
                .arg(t.reference)
                .args(["-lssl", "-lcrypto", "-o"])
                .arg(work.join(demo)),
        )?;
    }
    Ok(())
}

/// What a client run produced: its output (error locations masked) and exit status.
fn run_client(cmd: &mut Command) -> Result<String> {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot start the client: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write as _;
        let _ = stdin.write_all(b"hello over quic\n");
    }
    let start = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if start.elapsed() > CLIENT_TIMEOUT {
            let _ = child.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let out = child.wait_with_output()?;
    let mut text = String::new();
    for l in String::from_utf8_lossy(&out.stdout)
        .lines()
        .chain(String::from_utf8_lossy(&out.stderr).lines())
    {
        text.push_str(&mask_err_location(l));
        text.push('\n');
    }
    text.push_str(&format!("exit: {:?}\n", out.status.code()));
    Ok(text)
}

/// One pairing of one case: the client's report.
fn pairing(
    t: &Tool<'_>,
    work: &Path,
    guide: &Path,
    server: &str,
    client: &str,
    server_lib: &Path,
    client_lib: &Path,
) -> Result<String> {
    let port = free_port(true)?;
    // `none`: no server (the network refuses the client's datagrams).
    let mut srv = if server == "none" {
        None
    } else {
        Some(
            Command::new(work.join(server))
                .arg(port.to_string())
                .arg(guide.join("servercert.pem"))
                .arg(guide.join("serverkey.pem"))
                .env(LOADER_PATH, server_lib)
                .env("OPENSSL_CONF", super::MISSING_CONFIG)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| format!("cannot start {server}: {e}"))?,
        )
    };
    // Wait until the server has bound its port (a client sending before then gets an ICMP
    // refusal, which ends its connection).
    let start = Instant::now();
    while srv.is_some()
        && start.elapsed() < Duration::from_secs(5)
        && std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok()
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut words = client.split_whitespace();
    let program = words.next().ok_or("an empty client")?;
    let mut cmd = if program == "s_client" {
        let mut c = Command::new(t.bin);
        c.arg("s_client")
            .arg("-quic")
            .arg("-connect")
            .arg(format!("127.0.0.1:{port}"))
            .args(words.map(|w| w.replace("{port}", &port.to_string())));
        c
    } else {
        let mut c = Command::new(work.join(program));
        c.arg("localhost").arg(port.to_string());
        c
    };
    cmd.env(LOADER_PATH, client_lib)
        .env("OPENSSL_CONF", super::MISSING_CONFIG)
        .env("SSL_CERT_FILE", guide.join("rootcert.pem"));
    let r = run_client(&mut cmd);
    if let Some(srv) = srv.as_mut() {
        let _ = srv.kill();
        let _ = srv.wait();
    }
    r
}

pub fn run(t: &Tool<'_>, root: &Path, only: &[&String]) -> Result {
    let src: PathBuf = t
        .reference
        .parent()
        .ok_or("no reference directory")?
        .join("src");
    let guide = src.join("demos/guide");
    let work = t.work.join("quic");
    crate::util::fresh_dir(&work)?;
    build(t, &src, &work)?;
    let list = fs::read_to_string(root.join("tests/interop/quic.txt"))?;
    let mut failures = Vec::new();
    let mut count = 0;
    for line in list.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(3, '|').map(str::trim);
        let (Some(name), Some(server), Some(client)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(format!("malformed case: {line}").into());
        };
        if !only.is_empty() && !only.iter().any(|o| o.as_str() == name) {
            continue;
        }
        count += 1;
        let expected = pairing(t, &work, &guide, server, client, t.reference, t.reference)?;
        let mut bad = Vec::new();
        for (label, s, c) in [
            ("rustyssl server", t.ours, t.reference),
            ("rustyssl client", t.reference, t.ours),
            ("rustyssl both", t.ours, t.ours),
        ] {
            let got = pairing(t, &work, &guide, server, client, s, c)?;
            if got != expected {
                bad.push(format!(
                    "  {label}:\n    expected:\n{}    got:\n{}",
                    super::indent(&expected),
                    super::indent(&got)
                ));
            }
        }
        if bad.is_empty() {
            println!("ok   {name}");
        } else {
            println!("FAIL {name}");
            for b in &bad {
                println!("{b}");
            }
            failures.push(name.to_owned());
        }
    }
    println!(
        "{} of {count} QUIC cases pass in all four pairings",
        count - failures.len()
    );
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("failing QUIC cases: {}", failures.join(", ")).into())
    }
}
