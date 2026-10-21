//! Paired lines of the TLS commands' corpora: `SERVER ARGS || CLIENT ARGS`.
//!
//! The server (`s_server`, which must report its port with `-accept 127.0.0.1:0` or the
//! like) starts first; once it prints its `ACCEPT` line, the client runs with `{port}` in
//! its arguments replaced by the server's port. Either side may end with `< file`, its
//! standard input; without one the client's is empty and the server's an open pipe that
//! stays silent (an interactive server's terminal). The server must then finish on its own
//! (`-naccept 1`); a `~` line's server is stopped once the client is done, and only whether
//! its client succeeds is compared (with the reference pairing's).
//!
//! Each line runs in five pairings: upstream's tool on the reference for both sides (the
//! expectation); ours on rustyssl, and ours on the reference, for both; and ours (on
//! rustyssl) against upstream's (on the reference) in each direction. Every run's two
//! outputs must match the expectation's after [`mask`], which hides what is random by design
//! (the port, session IDs, master keys, tickets, random octets in dumps, pointers, times).

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::{LOADER_PATH, MISSING_CONFIG, Setup};
use crate::util::Result;

/// How long a server may take to start, and a client to finish.
const TIMEOUT: Duration = Duration::from_secs(30);

/// How long a server may take to finish after its client.
const SERVER_GRACE: Duration = Duration::from_secs(10);

/// One side of a paired line.
#[derive(Clone, Debug, Default)]
pub struct Side {
    pub args: Vec<String>,
    pub stdin: Option<PathBuf>,
}

/// A paired line's two sides.
#[derive(Clone, Debug, Default)]
pub struct Pair {
    pub server: Side,
    pub client: Side,
}

/// Splits a line's arguments at a lone `||`; `None` if there is none.
pub fn split(args: &[String]) -> Option<Pair> {
    let at = args.iter().position(|a| a == "||")?;
    let side = |a: &[String]| {
        let mut args = a.to_vec();
        let mut stdin = None;
        if args.len() >= 2 && args.get(args.len() - 2).is_some_and(|a| a == "<") {
            stdin = args.pop().map(PathBuf::from);
            args.pop();
        }
        Side { args, stdin }
    };
    Some(Pair {
        server: side(args.get(..at).unwrap_or_default()),
        client: side(args.get(at + 1..).unwrap_or_default()),
    })
}

/// A run's outputs: each side's stdout, stderr and exit status as one text, and whether the
/// client (the side `~` lines need) succeeded.
struct Outcome {
    server: String,
    client: String,
    port: String,
    client_ok: bool,
    server_ok: bool,
}

fn command(tool: &Path, lib: &Path, work: &Path, args: &[String]) -> Command {
    let mut c = Command::new(tool);
    c.args(args)
        .current_dir(work)
        .env(LOADER_PATH, lib)
        .env("OPENSSL_MODULES", crate::test_c::modules_of(lib))
        .env("OPENSSL_CONF", MISSING_CONFIG);
    c
}

fn stdin_of(f: Option<&Path>, default: Stdio) -> Result<Stdio> {
    Ok(match f {
        Some(f) => {
            Stdio::from(fs::File::open(f).map_err(|e| format!("cannot open {}: {e}", f.display()))?)
        }
        None => default,
    })
}

/// Waits for `child` up to `limit`, killing it after; whether it exited by itself, and how.
fn wait(child: &mut Child, limit: Duration) -> (bool, String) {
    let deadline = Instant::now() + limit;
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return (true, format!("[{st}]")),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let st = child.wait().map(|s| s.to_string()).unwrap_or_default();
                return (false, format!("[killed: {st}]"));
            }
        }
    }
}

/// Reads a pipe to the end on a thread.
fn reader(mut r: impl Read + Send + 'static) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = r.read_to_end(&mut v);
        let _ = tx.send(v);
    });
    rx
}

/// Runs one pairing.
fn run(
    setup: &Setup,
    pair: &Pair,
    server: (&Path, &Path),
    client: (&Path, &Path),
    lenient: bool,
) -> Result<Outcome> {
    let w = &setup.work;
    let mut srv = command(server.0, server.1, w, &pair.server.args)
        .stdin(stdin_of(pair.server.stdin.as_deref(), Stdio::piped())?)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot start the server: {e}"))?;
    // The silent terminal: kept open until the server is done.
    let silent = srv.stdin.take();
    let mut out = srv.stdout.take().ok_or("no server stdout")?;
    let err_rx = reader(srv.stderr.take().ok_or("no server stderr")?);
    // Read standard output up to the ACCEPT line, then the rest on a thread.
    let (line_tx, line_rx) = mpsc::channel();
    let out_rx = {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut seen = Vec::new();
            let mut buf = [0u8; 4096];
            let mut reported = false;
            loop {
                match out.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        seen.extend_from_slice(buf.get(..n).unwrap_or_default());
                        if !reported {
                            let text = String::from_utf8_lossy(&seen);
                            if let Some(l) = text.lines().find(|l| l.starts_with("ACCEPT"))
                                && text.contains(&format!("{l}\n"))
                            {
                                let _ = line_tx.send(Some(l.to_owned()));
                                reported = true;
                            }
                        }
                    }
                }
            }
            if !reported {
                let _ = line_tx.send(None);
            }
            let _ = tx.send(seen);
        });
        rx
    };
    let accept = line_rx.recv_timeout(TIMEOUT).ok().flatten();
    let Some(accept) = accept else {
        let _ = wait(&mut srv, Duration::from_secs(1));
        let o = out_rx.recv().unwrap_or_default();
        let e = err_rx.recv().unwrap_or_default();
        return Ok(Outcome {
            server: format!(
                "{}{}",
                String::from_utf8_lossy(&o),
                String::from_utf8_lossy(&e)
            ),
            client: String::new(),
            port: String::new(),
            client_ok: false,
            server_ok: false,
        });
    };
    // `ACCEPT 127.0.0.1:PORT`; a Unix socket's is `ACCEPTunknown:error`, with no port.
    let port = accept
        .rsplit(':')
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned();
    let port = if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
        port
    } else {
        String::new()
    };
    let cargs: Vec<String> = pair
        .client
        .args
        .iter()
        .map(|a| a.replace("{port}", &port))
        .collect();
    let mut cl = command(client.0, client.1, w, &cargs)
        .stdin(stdin_of(pair.client.stdin.as_deref(), Stdio::null())?)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot start the client: {e}"))?;
    let c_out = reader(cl.stdout.take().ok_or("no client stdout")?);
    let c_err = reader(cl.stderr.take().ok_or("no client stderr")?);
    let (c_done, c_status) = wait(&mut cl, TIMEOUT);
    let grace = if lenient {
        Duration::from_secs(2)
    } else {
        SERVER_GRACE
    };
    let (s_done, s_status) = wait(&mut srv, grace);
    drop(silent);
    let text = |o: Vec<u8>, e: Vec<u8>, st: &str| {
        format!(
            "{}{}{st}\n",
            String::from_utf8_lossy(&o),
            String::from_utf8_lossy(&e)
        )
    };
    let client_text = text(
        c_out.recv().unwrap_or_default(),
        c_err.recv().unwrap_or_default(),
        &c_status,
    );
    let server_text = text(
        out_rx.recv().unwrap_or_default(),
        err_rx.recv().unwrap_or_default(),
        &s_status,
    );
    Ok(Outcome {
        client_ok: c_done && c_status == "[exit status: 0]",
        server_ok: s_done,
        server: server_text,
        client: client_text,
        port,
    })
}

/// Marks a line [`mask`] took out of a ticket's dump; [`tickets_last`] keeps it where the
/// ticket's block was.
const STRAY: &str = "\u{1}stray:";

/// The peer's data in a `BIO_dump` line the stdio buffer cut short, where a raw write of
/// it landed: whatever doesn't fit the dump's layout (indent, `0050 - `, 16 three-character
/// byte slots, two spaces, one character per byte). In the hex, the first character out of
/// place starts it (`    0530 - 95 f6 5aolleh`); the peer's leading hex digits can't be told
/// from the dump's, and the corpora's peer data (`olleh`) has none. In the text column, `next`
/// (the line after, the rest of the cut one) says how many of the dump's characters came
/// before the cut (`    0050 - dc ... 49   ...=...olleh`, then `.....I`). `None` for a
/// whole line.
fn stray_text<'a>(line: &'a str, next: Option<&str>) -> Option<&'a str> {
    let t = line.trim_start();
    let (offset, rest) = t.split_once(" - ")?;
    if offset.len() != 4 || !offset.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let b = rest.as_bytes();
    // The first byte that doesn't fit the layout starts the peer's text.
    let stray_at = |at: usize| rest.get(at..).filter(|s| !s.is_empty());
    let mut n = 0;
    while n < 16 {
        let at = n * 3;
        if b.get(at..at + 3) == Some(b"   ") {
            break;
        }
        let sep = if n == 7 { b'-' } else { b' ' };
        for i in 0..3 {
            let &c = b.get(at + i)?;
            if !(if i < 2 {
                c.is_ascii_hexdigit()
            } else {
                c == sep
            }) {
                return stray_at(at + i);
            }
        }
        n += 1;
    }
    // The padding of a short last line, two spaces, and the text column.
    let text = 48 + 2;
    let pad = b.get(n * 3..text.min(b.len())).unwrap_or_default();
    if let Some(i) = pad.iter().position(|&c| c != b' ') {
        return stray_at(n * 3 + i);
    }
    let next = next.filter(|l| !is_dump_line(l))?;
    let printed = n.checked_sub(next.len())?;
    stray_at(text + printed)
}

/// A client's text with each TLS 1.3 session ticket's block (`---`, `Post-Handshake New
/// Session Ticket arrived:` ... `---`, and a following `read R BLOCK`) moved to the end, in
/// order: the server's tickets and its reply race to the client, so where the reply's line
/// falls among them depends on scheduling, on the reference as on rustyssl (measured on macOS).
fn tickets_last(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let (mut rest, mut tickets): (Vec<&str>, Vec<&str>) = (Vec::new(), Vec::new());
    let mut i = 0;
    while let Some(&l) = lines.get(i) {
        let starts =
            l == "---" && lines.get(i + 1) == Some(&"Post-Handshake New Session Ticket arrived:");
        if !starts {
            rest.push(l);
            i += 1;
            continue;
        }
        // The block ends at its own closing `---` (the first after its header).
        let mut j = i + 2;
        while lines.get(j).is_some_and(|l| *l != "---") {
            j += 1;
        }
        let mut end = (j + 1).min(lines.len());
        if lines.get(end) == Some(&"read R BLOCK") {
            end += 1;
        }
        for l in lines.get(i..end).unwrap_or_default() {
            match l.strip_prefix(STRAY) {
                Some(stray) => rest.push(stray),
                None => tickets.push(l),
            }
        }
        i = end;
    }
    rest.extend(tickets);
    // A stray line outside a ticket's block (the reply cut a dump that isn't a ticket's).
    let rest: Vec<&str> = rest
        .into_iter()
        .map(|l| l.strip_prefix(STRAY).unwrap_or(l))
        .collect();
    let mut out = rest.join("\n");
    if text.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// A run's text with what is random by design masked.
pub fn mask(text: &str, port: &str) -> String {
    let mut out = Vec::new();
    let mut in_pem = false;
    let mut in_ticket = false;
    let mut cut = false;
    let lines: Vec<&str> = text.lines().collect();
    for (i, &line) in lines.iter().enumerate() {
        let mut l = if port.is_empty() {
            line.to_owned()
        } else {
            replace_number(line, port, "{port}")
        };
        // A session's ticket (random), up to the blank line after it: a raw write of
        // the peer's data may split one of its lines where the stdio buffer filled.
        if in_ticket {
            if l.is_empty() && !cut {
                in_ticket = false;
            } else {
                let hex = out.iter().rev().find(|p: &&String| !p.starts_with(STRAY));
                if hex.is_none_or(|p| p != "HEX") {
                    out.push("HEX".to_owned());
                }
                if cut {
                    // The rest of the line the buffer cut (maybe just its newline).
                    cut = false;
                } else if let Some(stray) = stray_text(line, lines.get(i + 1).copied()) {
                    // The peer's data written into a dump line the buffer cut short.
                    out.push(format!("{STRAY}{stray}"));
                    cut = true;
                } else if !is_dump_line(&l) {
                    // Or between two lines.
                    out.push(format!("{STRAY}{l}"));
                }
                continue;
            }
        }
        if l.trim_start() == "TLS session ticket:" {
            in_ticket = true;
        }
        if l.starts_with("-----BEGIN SSL SESSION PARAMETERS-----") {
            in_pem = true;
            out.push(l);
            continue;
        }
        if in_pem {
            if l.starts_with("-----END SSL SESSION PARAMETERS-----") {
                in_pem = false;
                out.push(l);
            } else if out.last().is_none_or(|p: &String| p != "SESSION") {
                out.push("SESSION".to_owned());
            }
            continue;
        }
        for key in [
            "Session-ID: ",
            "Master-Key: ",
            "Resumption PSK: ",
            "Start Time: ",
            "    Keying material: ",
            "TLS session ticket lifetime hint: ",
        ] {
            if let Some(at) = l.find(key) {
                l.truncate(at + key.len());
                l.push_str("MASKED");
            }
        }
        if is_dump_line(&l) || is_msg_hex_line(&l) {
            l = "HEX".to_owned();
        }
        mask_trace_hex(&mut l);
        l = mask_pointers(&l);
        l = super::masked(&l);
        // Consecutive masked hex lines count as one (their number varies with lengths).
        if l == "HEX" && out.last().is_some_and(|p: &String| p == "HEX") {
            continue;
        }
        out.push(l);
    }
    out.join("\n")
}

/// `s` with each occurrence of the number `n` that isn't part of a longer number replaced.
fn replace_number(s: &str, n: &str, with: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(at) = rest.find(n) {
        let before = rest[..at].chars().next_back();
        let after = rest[at + n.len()..].chars().next();
        out.push_str(&rest[..at]);
        if before.is_some_and(|c| c.is_ascii_digit()) || after.is_some_and(|c| c.is_ascii_digit()) {
            out.push_str(n);
        } else {
            out.push_str(with);
        }
        rest = &rest[at + n.len()..];
    }
    out.push_str(rest);
    out
}

/// A `BIO_dump` line: `0000 - 16 03 01 ...   ....`, maybe indented.
fn is_dump_line(l: &str) -> bool {
    let t = l.trim_start();
    let mut parts = t.splitn(2, " - ");
    let (Some(off), Some(rest)) = (parts.next(), parts.next()) else {
        return false;
    };
    off.len() == 4
        && off.chars().all(|c| c.is_ascii_hexdigit())
        && rest.len() >= 2
        && rest.chars().take(2).all(|c| c.is_ascii_hexdigit())
}

/// A `msg_cb` dump line: four spaces then ` xx` octets.
fn is_msg_hex_line(l: &str) -> bool {
    let Some(rest) = l.strip_prefix("   ") else {
        return false;
    };
    !rest.is_empty()
        && rest
            .split(' ')
            .skip(1)
            .all(|b| b.len() == 2 && b.chars().all(|c| c.is_ascii_hexdigit()))
        && rest.starts_with(' ')
}

/// A `-trace` field's octets (`random_bytes (len=28): 1046A9...`) as `HEX`.
fn mask_trace_hex(l: &mut String) {
    let Some(at) = l.find("): ") else {
        return;
    };
    let (head, hex) = l.split_at(at + 3);
    if head.contains("(len=") && hex.len() >= 8 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        l.truncate(at + 3);
        l.push_str("HEX");
    }
}

/// `0x...` addresses as `0xPTR`.
fn mask_pointers(l: &str) -> String {
    let mut out = String::new();
    let mut rest = l;
    while let Some(at) = rest.find("0x") {
        out.push_str(&rest[..at]);
        let tail = &rest[at + 2..];
        let n = tail.chars().take_while(char::is_ascii_hexdigit).count();
        if n >= 8 {
            out.push_str("0xPTR");
        } else {
            out.push_str(&rest[at..at + 2 + n]);
        }
        rest = &tail[n..];
    }
    out.push_str(rest);
    out
}

/// The first differing line of two masked texts.
fn first_diff(expected: &str, got: &str) -> String {
    let at = expected
        .lines()
        .zip(got.lines())
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| expected.lines().count().min(got.lines().count()));
    format!(
        "line {}:\n  expected: {}\n  got:      {}",
        at + 1,
        expected.lines().nth(at).unwrap_or("(end)"),
        got.lines().nth(at).unwrap_or("(end)")
    )
}

/// Runs a paired line in its five pairings.
pub fn check(
    setup: &Setup,
    pair: &Pair,
    compare: bool,
    label: &str,
) -> Result<std::result::Result<(), String>> {
    let up = (setup.upstream.as_path(), setup.ref_lib.as_path());
    let ours_rs = (setup.ours.as_path(), setup.our_lib.as_path());
    let ours_ref = (setup.ours.as_path(), setup.ref_lib.as_path());
    let expected = run(setup, pair, up, up, !compare)?;
    let runs = [
        ("our server and client on rustyssl", ours_rs, ours_rs),
        ("our server and client on the reference", ours_ref, ours_ref),
        ("upstream's server, our client on rustyssl", up, ours_rs),
        ("our server on rustyssl, upstream's client", ours_rs, up),
    ];
    let (es, ec) = (
        mask(&expected.server, &expected.port),
        tickets_last(&mask(&expected.client, &expected.port)),
    );
    for (name, server, client) in runs {
        let got = run(setup, pair, server, client, !compare)?;
        if !compare {
            if got.client_ok != expected.client_ok {
                let how = if got.client_ok { "succeeded" } else { "failed" };
                return Ok(Err(format!(
                    "{name}: the client {how}, unlike the reference pairing's:\n{}",
                    got.client
                )));
            }
            continue;
        }
        let (gs, gc) = (
            mask(&got.server, &got.port),
            tickets_last(&mask(&got.client, &got.port)),
        );
        if gc != ec {
            save(setup, label, name, "client", &ec, &gc);
            return Ok(Err(format!("{name}: client {}", first_diff(&ec, &gc))));
        }
        if gs != es {
            save(setup, label, name, "server", &es, &gs);
            return Ok(Err(format!("{name}: server {}", first_diff(&es, &gs))));
        }
        if expected.server_ok != got.server_ok {
            return Ok(Err(format!(
                "{name}: the server didn't finish as the reference's did"
            )));
        }
    }
    Ok(Ok(()))
}

/// Keeps both texts of a failure, for a diff.
fn save(setup: &Setup, label: &str, name: &str, side: &str, expected: &str, got: &str) {
    let dir = setup.work.join("failures");
    let _ = fs::create_dir_all(&dir);
    let base: String = format!("{label}-{name}-{side}")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .take(150)
        .collect();
    let _ = fs::write(dir.join(format!("{base}.expected")), expected);
    let _ = fs::write(dir.join(format!("{base}.got")), got);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitting() {
        let a: Vec<String> = "s_server -accept 0 < in || s_client -connect h:{port} < x"
            .split(' ')
            .map(str::to_owned)
            .collect();
        let p = split(&a).unwrap();
        assert_eq!(p.server.args, ["s_server", "-accept", "0"]);
        assert_eq!(p.server.stdin.as_deref(), Some(Path::new("in")));
        assert_eq!(p.client.args, ["s_client", "-connect", "h:{port}"]);
        assert!(split(&a[..3]).is_none());
    }

    #[test]
    fn masking() {
        assert_eq!(
            mask("ACCEPT 127.0.0.1:4321", "4321"),
            "ACCEPT 127.0.0.1:{port}"
        );
        assert_eq!(mask("x 43210", "4321"), "x 43210");
        assert_eq!(mask("    Session-ID: ABCD", ""), "    Session-ID: MASKED");
        let full = "    0050 - dc e2 c2 3d 04 d9 0f dd-d6 77 45 46 96 a0 01 49   ...=....wEF....I";
        assert_eq!(stray_text(full, Some("    0060 - 00")), None);
        assert_eq!(stray_text(full, Some("")), None);
        assert_eq!(
            stray_text(
                "    0050 - dc e2 c2 3d 04 d9 0f dd-d6 77 45 46 96 a0 01 49   ...=...olleh",
                Some(".wEF....I")
            ),
            Some("olleh")
        );
        assert_eq!(
            stray_text(
                "    0050 - dc e2 c2 3d 04 d9 0f dd-d6 77 45 46 96 a0 01 49  olleh",
                None
            ),
            Some("olleh")
        );
        assert_eq!(
            stray_text("    0530 - 95 f6 5a ba 2b 7e 07 olleh", None),
            Some("olleh")
        );
        assert_eq!(
            stray_text("    01a0 - e1 9c fb 69 38 7a dolleh", None),
            Some("olleh")
        );
        assert_eq!(
            stray_text("    01a0 - e1 9c fb 69 38 7aolleh", None),
            Some("olleh")
        );
        assert_eq!(stray_text("    01a0 - e1 9c fb", Some("")), None);
        let short = format!("    01a0 - e1 9c fb {}...", " ".repeat(41));
        assert_eq!(stray_text(&short, Some("")), None);
        assert_eq!(
            stray_text(&format!("{short}olleh"), Some("")),
            Some("olleh")
        );
        // The reply cut into a ticket's dump comes out where an uncut run has it.
        let ticket = |dump: &str, reply: &str| {
            format!(
                "x\n---\nPost-Handshake New Session Ticket arrived:\n    TLS session ticket:\n\
                 {dump}\n\n---\nread R BLOCK\n{reply}closed\n"
            )
        };
        let uncut = ticket(&format!("{full}\n{short}"), "olleh\n");
        let uncut = tickets_last(&mask(&uncut, ""));
        let cut = ticket(
            &format!(
                "    0050 - dc e2 c2 3d 04 d9 0f dd-d6 77 45 46 96 a0 01 49   ...=...olleh\n\
             .wEF....I\n{short}",
            ),
            "",
        );
        assert_eq!(tickets_last(&mask(&cut, "")), uncut);
        assert_eq!(
            tickets_last(
                "a\n---\nPost-Handshake New Session Ticket arrived:\nt\n---\nread R BLOCK\nolleh\nz\n"
            ),
            "a\nolleh\nz\n---\nPost-Handshake New Session Ticket arrived:\nt\n---\nread R BLOCK\n"
        );
        assert_eq!(mask("0000 - 16 03 01 00 2a   ....\n0010 - 01", ""), "HEX");
        assert_eq!(mask("    16 03 01\n    0a", ""), "HEX");
        assert_eq!(
            mask(
                "read from 0x55d0c0a1b2c0 [0x7ffd0a1b2c3d] (5 bytes => 5 (0x5))",
                ""
            ),
            "read from 0xPTR [0xPTR] (5 bytes => 5 (0x5))"
        );
        assert_eq!(
            mask(
                "-----BEGIN SSL SESSION PARAMETERS-----\nAAA\nBBB\n-----END SSL SESSION PARAMETERS-----",
                ""
            ),
            "-----BEGIN SSL SESSION PARAMETERS-----\nSESSION\n-----END SSL SESSION PARAMETERS-----"
        );
    }
}
