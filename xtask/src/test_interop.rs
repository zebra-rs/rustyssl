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
//! `{ed25519}` (a server's `-cert`/`-key` pair), `{ca}` (the root to verify with), and
//! `{dir}` substituted. Lines starting with `#` are comments.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use crate::test_c::{LOADER_PATH, prepare};
use crate::util::{Result, fresh_dir, target_dir, workspace_root};

/// The configuration file every run is pointed at, one that doesn't exist.
const MISSING_CONFIG: &str = "/nonexistent/rustyssl-tests/openssl.cnf";

/// How long a server may take to start, and a connection to finish.
const TIMEOUT: Duration = Duration::from_secs(30);

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

/// A test PKI: a root and three servers (RSA, ECDSA P-256, Ed25519) it issued.
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
    for (name, alg) in [("rsa", "rsa:2048"), ("ec", "ec"), ("ed25519", "ed25519")] {
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
        if alg == "ec" {
            req.extend([
                "-newkey".to_owned(),
                "ec".to_owned(),
                "-pkeyopt".to_owned(),
                "ec_paramgen_curve:P-256".to_owned(),
            ]);
        } else {
            req.extend(["-newkey".to_owned(), alg.to_owned()]);
        }
        let args: Vec<&str> = req.iter().map(String::as_str).collect();
        t.setup(&args)?;
        fs::write(
            dir.join("ext.cnf"),
            "subjectAltName=DNS:localhost\nbasicConstraints=CA:false\n",
        )?;
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
    Ok(())
}

/// The case's arguments with the placeholders substituted.
fn substitute(args: &str, dir: &Path) -> Vec<String> {
    let d = |f: &str| dir.join(f).display().to_string();
    let mut out = Vec::new();
    for a in args.split_whitespace() {
        match a {
            "{rsa}" | "{ec}" | "{ed25519}" => {
                let n = a.trim_matches(|c| c == '{' || c == '}');
                out.extend([
                    "-cert".to_owned(),
                    d(&format!("{n}.pem")),
                    "-key".to_owned(),
                    d(&format!("{n}.key")),
                ]);
            }
            "{ca}" => out.extend(["-CAfile".to_owned(), d("ca.pem")]),
            _ => out.push(a.replace("{dir}", &dir.display().to_string())),
        }
    }
    out
}

/// A free local port (the listener is closed again; the server binds it next).
fn free_port() -> Result<u16> {
    let l = TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

/// Starts `s_server` and waits for it to accept; returns it with its output so far.
fn start_server(
    t: &Tool<'_>,
    ours: bool,
    port: u16,
    args: &[String],
) -> Result<(Child, mpsc::Receiver<String>)> {
    let mut all = vec![
        "s_server".to_owned(),
        "-accept".to_owned(),
        format!("127.0.0.1:{port}"),
        "-naccept".to_owned(),
        "1".to_owned(),
        "-rev".to_owned(),
    ];
    if !args.iter().any(|a| a == "-cert") {
        all.extend(substitute("{rsa}", t.work));
    }
    all.extend(args.iter().cloned());
    let mut child = t
        .command(ours, &all)
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

/// One connection: the client's summary (stderr's handshake lines) and the echo it got.
fn connect(
    t: &Tool<'_>,
    p: Pairing,
    server_args: &[String],
    client_args: &[String],
) -> Result<String> {
    let port = free_port()?;
    let (mut server, lines) = start_server(t, p.server_ours, port, server_args)?;
    let mut all = vec![
        "s_client".to_owned(),
        "-connect".to_owned(),
        format!("127.0.0.1:{port}"),
        "-brief".to_owned(),
        "-ign_eof".to_owned(),
    ];
    all.extend(client_args.iter().cloned());
    let mut client = t
        .command(p.client_ours, &all)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot start s_client: {e}"))?;
    if let Some(mut stdin) = client.stdin.take() {
        // `-rev` reverses each line and ends the connection on CLOSE.
        let _ = stdin.write_all(b"hello rustyssl\nCLOSE\n");
    }
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(client.wait_with_output());
    });
    let out = match rx.recv_timeout(TIMEOUT) {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return Err(format!("s_client failed: {e}").into()),
        Err(_) => {
            let _ = server.kill();
            return Err("s_client timed out".into());
        }
    };
    let _ = server.kill();
    let _ = server.wait();
    let server_out: Vec<String> = lines.try_iter().collect();
    let mut summary = String::new();
    for line in String::from_utf8_lossy(&out.stderr).lines() {
        // Only the handshake's summary: the rest (verify depth lines, DONE) is the same or
        // timing-dependent.
        if [
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
        ]
        .iter()
        .any(|k| line.starts_with(k))
        {
            summary.push_str(line);
            summary.push('\n');
        }
    }
    let echo = String::from_utf8_lossy(&out.stdout);
    let echoed = echo.lines().any(|l| l == "lssytsur olleh");
    summary.push_str(if echoed {
        "echo: ok\n"
    } else {
        "echo: MISSING\n"
    });
    if !echoed {
        summary.push_str(&format!(
            "client stderr: {}\nserver: {}\n",
            String::from_utf8_lossy(&out.stderr),
            server_out.join(" / ")
        ));
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
    make_pki(&t, &work)?;

    let list = fs::read_to_string(root.join("tests/interop/cases.txt"))?;
    let reference_only = args.iter().any(|a| a == "--reference-only");
    let only: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
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

fn indent(s: &str) -> String {
    s.lines()
        .map(|l| format!("    {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}
