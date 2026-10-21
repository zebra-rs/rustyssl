//! The server side of `s_client -starttls`'s plaintext exchanges, for paired lines.
//!
//! A paired line whose server side starts with `{starttls:NAME}` runs that s_server behind a
//! front: a listener on loopback that, for the one connection it takes, plays the server's
//! part of protocol NAME as `apps/s_client.c` expects it (greeting, capabilities, the go-ahead),
//! then relays octets both ways between the client and the s_server, which does the TLS. The
//! client's `{port}` is the front's. A NAME with a suffix (`smtp-nocap`, `irc-421`, ...) is a
//! variant: a server without the capability (the client tries anyway), or one that refuses
//! (the client gives up; the front then connects to the s_server and closes, so it ends too).

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use crate::util::Result;

/// How long the front waits for the client, and for each of its messages.
const WAIT: Duration = Duration::from_secs(20);

/// One step of a script.
enum Step {
    /// Send these octets.
    Send(&'static [u8]),
    /// Read one line (to `\n`).
    Line,
    /// Read until these octets have arrived.
    Until(&'static [u8]),
    /// Read exactly this many octets.
    Exactly(usize),
    /// Read one DER element (a short- or long-form length).
    Der,
}

use Step::{Der, Exactly, Line, Send, Until};

/// MySQL's initial handshake packet (protocol 10, server version "5.7.0", connection id,
/// salt, filler, and capability flags with `CLIENT_SSL`, 0x800, set or not).
const MYSQL_SSL: &[u8] =
    b"\x19\x00\x00\x00\x0a5.7.0\x00\x01\x00\x00\x00abcdefgh\x00\xff\xff\x21\x02\x00";
const MYSQL_NO_SSL: &[u8] =
    b"\x19\x00\x00\x00\x0a5.7.0\x00\x01\x00\x00\x00abcdefgh\x00\xff\xf7\x21\x02\x00";

/// LDAP's ExtendedResponse to message 1: success, or `unavailable` (52).
const LDAP_OK: &[u8] = b"\x30\x0c\x02\x01\x01\x78\x07\x0a\x01\x00\x04\x00\x04\x00";
const LDAP_UNAVAILABLE: &[u8] = b"\x30\x0c\x02\x01\x01\x78\x07\x0a\x01\x34\x04\x00\x04\x00";

const XMPP_FEATURES: &[u8] = b"<?xml version='1.0'?><stream:stream xmlns='jabber:client' \
xmlns:stream='http://etherx.jabber.org/streams' id='1' from='example.com' version='1.0'>\
<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>\
</stream:features>";

/// A script's steps, and whether the TLS session follows (false: the client gives up).
fn script(name: &str) -> Option<(Vec<Step>, bool)> {
    let smtp = |caps: &'static [u8]| {
        vec![
            Send(b"220-mail.example.com ESMTP\r\n220 ready\r\n"),
            Line,
            Send(caps),
            Line,
            Send(b"220 2.0.0 Ready to start TLS\r\n"),
        ]
    };
    let imap = |caps: &'static [u8]| {
        vec![
            Send(b"* OK IMAP4rev1 ready\r\n"),
            Line,
            Send(caps),
            Line,
            Send(b". OK Begin TLS negotiation now\r\n"),
        ]
    };
    let nntp = |caps: &'static [u8], go: &'static [u8]| {
        vec![
            Send(b"200 news.example.com ready\r\n"),
            Line,
            Send(caps),
            Line,
            Send(go),
        ]
    };
    let sieve = |caps: &'static [u8], go: &'static [u8]| vec![Send(caps), Line, Send(go)];
    Some(match name {
        "smtp" | "lmtp" => (
            smtp(b"250-mail.example.com\r\n250-PIPELINING\r\n250 STARTTLS\r\n"),
            true,
        ),
        "smtp-nocap" => (smtp(b"250-mail.example.com\r\n250 PIPELINING\r\n"), true),
        "pop3" => (
            vec![
                // s_client prints the greeting cut to the reply's length (and reads past it
                // when the reply is the longer): the reply is the shorter here.
                Send(b"+OK POP3 server ready <1896.697170952@example.com>\r\n"),
                Line,
                Send(b"+OK Begin TLS\r\n"),
            ],
            true,
        ),
        "imap" => (
            imap(b"* CAPABILITY IMAP4rev1 STARTTLS\r\n. OK CAPABILITY completed\r\n"),
            true,
        ),
        "imap-nocap" => (
            imap(b"* CAPABILITY IMAP4rev1\r\n. OK CAPABILITY completed\r\n"),
            true,
        ),
        "ftp" => (
            vec![
                Send(b"220-Welcome\r\n220 FTP ready\r\n"),
                Line,
                Send(b"234 AUTH TLS successful\r\n"),
            ],
            true,
        ),
        "xmpp" => (
            vec![
                Until(b"version='1.0'>"),
                Send(XMPP_FEATURES),
                Until(b"/>"),
                Send(b"<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"),
            ],
            true,
        ),
        "xmpp-failure" => (
            vec![
                Until(b"version='1.0'>"),
                Send(XMPP_FEATURES),
                Until(b"/>"),
                Send(b"<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"),
            ],
            false,
        ),
        "telnet" => (
            vec![
                Send(b"\xff\xfd\x2e"),
                Exactly(9),
                Send(b"\xff\xfa\x2e\x01\xff\xf0"),
            ],
            true,
        ),
        "irc" => (
            vec![
                Line,
                Send(b":irc.example.net 670 * :STARTTLS successful, go ahead with TLS handshake\r\n"),
            ],
            true,
        ),
        "irc-421" => (
            vec![
                Line,
                Send(b":irc.example.net 421 * STARTTLS :Unknown command\r\n"),
            ],
            false,
        ),
        "mysql" => (vec![Send(MYSQL_SSL), Exactly(36)], true),
        "mysql-nossl" => (vec![Send(MYSQL_NO_SSL)], false),
        "postgres" => (vec![Exactly(8), Send(b"S")], true),
        "postgres-n" => (vec![Exactly(8), Send(b"N")], false),
        "nntp" => (
            nntp(
                b"101 Capability list:\r\nVERSION 2\r\nSTARTTLS\r\n.\r\n",
                b"382 Continue with TLS negotiation\r\n",
            ),
            true,
        ),
        "nntp-nocap" => (
            nntp(
                b"101 Capability list:\r\nVERSION 2\r\n.\r\n",
                b"382 Continue with TLS negotiation\r\n",
            ),
            true,
        ),
        "nntp-580" => (
            nntp(
                b"101 Capability list:\r\nVERSION 2\r\nSTARTTLS\r\n.\r\n",
                b"580 Can not initiate TLS negotiation\r\n",
            ),
            false,
        ),
        "sieve" => (
            sieve(
                b"\"IMPLEMENTATION\" \"Example\"\r\n\"SIEVE\" \"fileinto\"\r\n\"starttls\"\r\nOK\r\n",
                b"OK \"Begin TLS negotiation now\"\r\n",
            ),
            true,
        ),
        "sieve-no" => (
            sieve(
                b"\"IMPLEMENTATION\" \"Example\"\r\n\"STARTTLS\"\r\nOK\r\n",
                b"NO \"TLS is not available\"\r\n",
            ),
            false,
        ),
        "ldap" => (vec![Der, Send(LDAP_OK)], true),
        "ldap-unavailable" => (vec![Der, Send(LDAP_UNAVAILABLE)], false),
        _ => return None,
    })
}

/// A started front: its port. Its thread ends with its connection (once both ends have
/// closed, which the s_server's end makes sure of) or when no client came.
pub struct Front {
    pub port: u16,
}

/// Starts a front for script `name` before the s_server on `backend`.
pub fn start(name: &str, backend: u16) -> Result<Front> {
    let (steps, relay) = script(name).ok_or_else(|| format!("no STARTTLS script {name}"))?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    listener.set_nonblocking(true)?;
    std::thread::spawn(move || {
        let deadline = Instant::now() + WAIT;
        let client = loop {
            match listener.accept() {
                Ok((s, _)) => break Some(s),
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break None,
            }
        };
        // Without a client (it failed before connecting), the s_server still ends.
        let Some(client) = client else {
            let _ = TcpStream::connect(("127.0.0.1", backend));
            return;
        };
        let _ = client.set_nonblocking(false);
        let _ = client.set_read_timeout(Some(WAIT));
        let played = play(&client, &steps);
        let Ok(server) = TcpStream::connect(("127.0.0.1", backend)) else {
            return;
        };
        if !(played && relay) {
            // The client gave up (or the script broke off): close both sides.
            let _ = server.shutdown(Shutdown::Both);
            let _ = drain_then_close(client);
            return;
        }
        relay_both(client, server);
    });
    Ok(Front { port })
}

/// Plays the script on `s`; false if the client went away or didn't say what was expected.
fn play(mut s: &TcpStream, steps: &[Step]) -> bool {
    for step in steps {
        let ok = match step {
            Send(b) => s.write_all(b).is_ok(),
            Line => read_until(s, b"\n"),
            Until(end) => read_until(s, end),
            Exactly(n) => {
                let mut buf = vec![0u8; *n];
                s.read_exact(&mut buf).is_ok()
            }
            Der => read_der(s),
        };
        if !ok {
            return false;
        }
    }
    true
}

/// Reads octets one at a time until the last ones read are `end`.
fn read_until(mut s: &TcpStream, end: &[u8]) -> bool {
    let mut seen = Vec::new();
    let mut b = [0u8; 1];
    while !seen.ends_with(end) {
        match s.read(&mut b) {
            Ok(1) => seen.push(b[0]),
            _ => return false,
        }
        if seen.len() > 65536 {
            return false;
        }
    }
    true
}

/// Reads one DER element: its tag, its length, and that many octets.
fn read_der(mut s: &TcpStream) -> bool {
    let mut head = [0u8; 2];
    if s.read_exact(&mut head).is_err() {
        return false;
    }
    let len = if head[1] & 0x80 == 0 {
        usize::from(head[1])
    } else {
        let n = usize::from(head[1] & 0x7f);
        if n == 0 || n > 4 {
            return false;
        }
        let mut l = vec![0u8; n];
        if s.read_exact(&mut l).is_err() {
            return false;
        }
        l.iter().fold(0usize, |acc, &b| (acc << 8) | usize::from(b))
    };
    let mut body = vec![0u8; len.min(65536)];
    s.read_exact(&mut body).is_ok()
}

/// Lets the client read what was sent, then closes.
fn drain_then_close(client: TcpStream) -> std::io::Result<()> {
    client.shutdown(Shutdown::Write)?;
    let mut sink = Vec::new();
    let _ = (&client).take(1 << 20).read_to_end(&mut sink);
    Ok(())
}

/// Copies octets both ways until each side has closed its half.
fn relay_both(client: TcpStream, server: TcpStream) {
    let _ = client.set_read_timeout(None);
    let (Ok(c2), Ok(s2)) = (client.try_clone(), server.try_clone()) else {
        return;
    };
    let up = std::thread::spawn(move || copy_half(c2, s2));
    copy_half(server, client);
    let _ = up.join();
}

/// Copies from `from` to `to` until `from` ends, then ends `to`'s writing half.
fn copy_half(mut from: TcpStream, mut to: TcpStream) {
    let mut buf = [0u8; 16384];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if to.write_all(buf.get(..n).unwrap_or_default()).is_err() {
                    break;
                }
            }
        }
    }
    let _ = to.shutdown(Shutdown::Write);
}
