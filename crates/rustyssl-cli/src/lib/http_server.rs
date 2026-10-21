//! `apps/lib/http_server.c`, the very basic HTTP server of `ocsp` and `cmp`, with the part of
//! `apps/lib/log.c` it logs through (`log_set_verbosity`, `trace_log_message`).
//!
//! With `HTTP_DAEMON`, as upstream builds it on Unix: forked responders (`ocsp -multi`,
//! [`spawn_loop`]) and the alarm-based read timeout. Its log messages go to standard error even
//! then: `log.c` doesn't include `http_server.h`, so its syslog branch is never compiled.

use std::cell::Cell;
use std::io::Write;

use rustyssl_ossl::Bio;
use rustyssl_ossl::http;
use rustyssl_ossl::os;

use super::io;

/// `syslog.h`'s levels, as `log.h` uses them.
pub mod level {
    pub const EMERG: i32 = 0;
    pub const ALERT: i32 = 1;
    pub const CRIT: i32 = 2;
    pub const ERR: i32 = 3;
    pub const WARNING: i32 = 4;
    pub const NOTICE: i32 = 5;
    pub const INFO: i32 = 6;
    pub const DEBUG: i32 = 7;
    pub const TRACE: i32 = 8;
}

thread_local! {
    /// `verbosity` of `log.c`.
    static VERBOSITY: Cell<i32> = const { Cell::new(level::INFO) };
    /// `n_responders` of `http_server.c`: the responder processes to run (set by `ocsp`).
    static N_RESPONDERS: Cell<usize> = const { Cell::new(0) };
}

/// Sets `n_responders` (`ocsp -multi`).
pub fn set_n_responders(n: usize) {
    N_RESPONDERS.with(|c| c.set(n));
}

/// `n_responders`.
pub fn n_responders() -> usize {
    N_RESPONDERS.with(Cell::get)
}

/// `killall`: SIGTERM to each child left, a second's pause, and the process's exit.
fn killall(ret: i32, kidpids: &[i32]) -> ! {
    for &pid in kidpids {
        if pid != 0 {
            os::terminate(pid);
        }
    }
    rustyssl_ossl::ssl::sleep_ms(1000);
    crate::exit(ret)
}

/// `spawn_loop`: keeps up to `n_responders` child processes running, each returning from here
/// to serve; the parent loops until a termination signal, then ends the children and exits.
pub fn spawn_loop(prog: &str) {
    let n = n_responders();
    if let Err(e) = os::setpgid_self() {
        let e = os::strerror(e);
        trace_log_message(
            prog,
            level::CRIT,
            &format!("error detaching from parent process group: {e}"),
        );
        crate::exit(1);
    }
    let mut kidpids = vec![0i32; n];
    let mut procs = 0usize;
    os::catch_termination();
    while os::termination_signal() == 0 {
        // Wait for a child to replace when at the limit; slow down if one exited abnormally
        // or waitpid failed.
        while os::termination_signal() == 0 && procs >= n {
            match os::waitpid_any() {
                Ok(w) => {
                    match kidpids.iter_mut().take(procs).find(|p| **p == w.pid) {
                        Some(slot) => {
                            *slot = 0;
                            procs -= 1;
                        }
                        None => {
                            trace_log_message(
                                prog,
                                level::CRIT,
                                &format!(
                                    "internal error: no matching child slot for pid: {}",
                                    w.pid
                                ),
                            );
                            killall(1, &kidpids);
                        }
                    }
                    if w.status != 0 {
                        match w.how {
                            os::ChildStatus::Exited(code) => trace_log_message(
                                prog,
                                level::WARNING,
                                &format!("child process: {}, exit status: {code}", w.pid),
                            ),
                            os::ChildStatus::Signaled(sig) => {
                                let dumped = if w.core_dumped { " (core dumped)" } else { "" };
                                trace_log_message(
                                    prog,
                                    level::WARNING,
                                    &format!("child process: {}, term signal {sig}{dumped}", w.pid),
                                );
                            }
                            os::ChildStatus::Other => {}
                        }
                        rustyssl_ossl::ssl::sleep_ms(1000);
                    }
                    break;
                }
                Err(os::EINTR) => {}
                Err(e) => {
                    let e = os::strerror(e);
                    trace_log_message(prog, level::CRIT, &format!("waitpid() failed: {e}"));
                    killall(1, &kidpids);
                }
            }
        }
        if os::termination_signal() != 0 {
            break;
        }
        if let Some(b) = io::bio_out() {
            b.flush();
        }
        match os::fork() {
            // System critically low on memory: pause and try again later.
            Err(_) => rustyssl_ossl::ssl::sleep_ms(30000),
            Ok(os::Fork::Child) => {
                os::default_termination();
                if os::termination_signal() != 0 {
                    crate::exit(0);
                }
                if !rustyssl_ossl::rand::poll() {
                    trace_log_message(prog, level::CRIT, "RAND_poll() failed");
                    crate::exit(1);
                }
                return;
            }
            Ok(os::Fork::Parent(pid)) => match kidpids.iter_mut().find(|p| **p == 0) {
                Some(slot) => {
                    *slot = pid;
                    procs += 1;
                }
                None => {
                    trace_log_message(prog, level::CRIT, "internal error: no free child slots");
                    killall(1, &kidpids);
                }
            },
        }
    }
    // The loop above only ends on a termination signal.
    let sig = os::termination_signal();
    trace_log_message(prog, level::INFO, &format!("terminating on signal: {sig}"));
    killall(0, &kidpids);
}

/// `log_set_verbosity`.
pub fn log_set_verbosity(prog: &str, l: i32) -> bool {
    if !(level::EMERG..=level::TRACE).contains(&l) {
        trace_log_message(prog, level::ERR, &format!("Invalid verbosity level {l}"));
        return false;
    }
    VERBOSITY.with(|v| v.set(l));
    true
}

/// `log_get_verbosity`.
pub fn log_get_verbosity() -> i32 {
    VERBOSITY.with(Cell::get)
}

/// `trace_log_message` without a trace category (tracing isn't in the default build): the
/// message, prefixed with `prog: ` on each line (`log_with_prefix`), if the verbosity
/// allows it.
pub fn trace_log_message(prog: &str, l: i32, msg: &str) {
    if log_get_verbosity() < l {
        return;
    }
    let mut text = String::new();
    for line in format!("{msg}\n").split_inclusive('\n') {
        text.push_str(&format!("{prog}: {line}"));
    }
    let _ = io::err().write_all(text.as_bytes());
}

/// `report_server_accept(bio_out, asock, 1, 1)` of `s_socket.c`: `ACCEPT host:port PID=n`.
fn report_server_accept(asock: i32) -> bool {
    let mut line = String::from("ACCEPT");
    let (host, service) = http::sock_info_address(asock);
    let success = match (host, service) {
        (Some(h), Some(s)) => {
            if h.contains(':') {
                line.push_str(&format!(" [{h}]:{s}"));
            } else {
                line.push_str(&format!(" {h}:{s}"));
            }
            true
        }
        _ => {
            line.push_str("unknown:error\n");
            false
        }
    };
    line.push_str(&format!(" PID={}\n", http::getpid()));
    let _ = io::out().write_all(line.as_bytes());
    success
}

/// `http_server_init`: the accept `BIO` on `port` ("0" picks one), reported on standard
/// output; `None` (the errors printed) on failure.
pub fn http_server_init(prog: &str, port: &str, verb: i32) -> Option<Bio> {
    if verb >= 0 && !log_set_verbosity(prog, verb) {
        return None;
    }
    match http::accept_bio(port) {
        Ok(acbio) => {
            let fd = http::bio_fd(&acbio);
            if !report_server_accept(fd) {
                trace_log_message(prog, level::ERR, "error printing ACCEPT string");
                io::print_errors();
                return None;
            }
            Some(acbio)
        }
        Err(http::AcceptError::Alloc) => {
            io::print_errors();
            None
        }
        Err(http::AcceptError::Setup) => {
            trace_log_message(prog, level::ERR, "error setting up accept BIO");
            io::print_errors();
            None
        }
        Err(http::AcceptError::Accept(acbio)) => {
            trace_log_message(
                prog,
                level::ERR,
                &format!("error setting accept on port {port}"),
            );
            io::print_errors();
            drop(acbio);
            None
        }
    }
}

/// `urldecode`: `%xx` decoded in place; `None` for a malformed escape.
fn urldecode(p: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(p.len());
    let mut i = 0;
    while let Some(&c) = p.get(i) {
        if c != b'%' {
            out.push(c);
            i += 1;
            continue;
        }
        let (h, l) = (p.get(i + 1).copied(), p.get(i + 2).copied());
        match (h.and_then(hexval), l.and_then(hexval)) {
            (Some(h), Some(l)) => {
                out.push((h << 4) | l);
                i += 3;
            }
            _ => return None,
        }
    }
    Some(out)
}

fn hexval(c: u8) -> Option<u8> {
    (c as char).to_digit(16).and_then(|d| u8::try_from(d).ok())
}

/// Strips a line's end at its first `\r\n` (or first `\n`): `None` if it has neither.
fn chop_eol(line: &[u8]) -> Option<&[u8]> {
    if let Some(r) = line.iter().position(|&b| b == b'\r')
        && line.get(r + 1) == Some(&b'\n')
    {
        return line.get(..r);
    }
    line.iter()
        .position(|&b| b == b'\n')
        .and_then(|n| line.get(..n))
}

/// What [`http_server_get_asn1_req`] returns: upstream's status (0 to accept again, 1 for a
/// request, -1 on a fatal error), the request (if one parsed), and its path.
pub struct Request<T> {
    pub ret: i32,
    pub req: Option<T>,
    pub path: Option<String>,
}

/// `http_server_get_asn1_req`: the next request on `cbio` (a new connection when `None`),
/// its DER parsed by `parse`. A request that fails gets a 400 (or 500) response here. With a
/// `timeout` (seconds; the caller has set [`os::catch_alarm_socket_timeout`]), an alarm shuts
/// the connection down for reading if its request line and headers take longer.
#[allow(clippy::too_many_arguments)]
pub fn http_server_get_asn1_req<T>(
    parse: impl FnOnce(&Bio) -> Option<T>,
    want_path: bool,
    pcbio: &mut Option<Bio>,
    acbio: &Bio,
    found_keep_alive: Option<&mut bool>,
    prog: &str,
    accept_get: bool,
    timeout: i32,
) -> Request<T> {
    let mut armed = false;
    let r = get_asn1_req(
        parse,
        want_path,
        pcbio,
        acbio,
        found_keep_alive,
        prog,
        accept_get,
        timeout,
        &mut armed,
    );
    if armed {
        os::alarm(0);
    }
    os::set_alarm_socket(-1);
    r
}

/// [`http_server_get_asn1_req`]'s work; `armed` says whether the alarm is still pending.
#[allow(clippy::too_many_arguments)]
fn get_asn1_req<T>(
    parse: impl FnOnce(&Bio) -> Option<T>,
    want_path: bool,
    pcbio: &mut Option<Bio>,
    acbio: &Bio,
    found_keep_alive: Option<&mut bool>,
    prog: &str,
    accept_get: bool,
    timeout: i32,
    armed: &mut bool,
) -> Request<T> {
    let mut out = Request {
        ret: 0,
        req: None,
        path: None,
    };
    if pcbio.is_none() {
        let (_, port) = http::sock_info_address(http::bio_fd(acbio));
        let Some(port) = port else {
            trace_log_message(prog, level::ERR, "cannot get port listening on");
            out.ret = -1;
            return out;
        };
        trace_log_message(
            prog,
            level::DEBUG,
            &format!("awaiting new connection on port {port} ..."),
        );
        if !http::do_accept(acbio) {
            // Connection loss before accept() is routine: ignore it.
            return out;
        }
        *pcbio = http::pop(acbio);
    } else {
        trace_log_message(prog, level::DEBUG, "awaiting next request ...");
    }
    let Some(cbio) = pcbio.as_ref() else {
        out.ret = -1;
        return out;
    };
    if let Ok(secs) = u32::try_from(timeout)
        && secs > 0
    {
        os::set_alarm_socket(http::bio_fd(cbio));
        os::alarm(secs);
        *armed = true;
    }
    let bad = |cbio: &Bio| {
        let _ = http_server_send_status(prog, cbio, 400, "Bad Request");
    };

    // The request line.
    let (len, reqbuf) = cbio.gets(2048);
    if len == 0 {
        // A connection closed (or timed out) before its request line is dropped here, where
        // upstream keeps it: its `ocsp` would then read the dead connection again and again,
        // spinning without ever accepting another (docs/DEVIATIONS.md). `cmp` drops it itself.
        *pcbio = None;
        return out;
    }
    out.ret = 1;
    if len < 0 {
        trace_log_message(prog, level::WARNING, "request line read error");
        bad(cbio);
        return out;
    }
    let line = chop_eol(&reqbuf);
    let shown = String::from_utf8_lossy(line.unwrap_or(&reqbuf)).into_owned();
    if log_get_verbosity() < level::TRACE {
        trace_log_message(
            prog,
            level::INFO,
            &format!("received request, 1st line: {shown}"),
        );
    }
    trace_log_message(prog, level::TRACE, "received request header:");
    trace_log_message(prog, level::TRACE, &shown);
    let Some(line) = line else {
        trace_log_message(
            prog,
            level::WARNING,
            "cannot parse HTTP header: missing end of line",
        );
        bad(cbio);
        return out;
    };
    let (meth, rest) = if accept_get && line.starts_with(b"GET ") {
        ("GET", line.get(4..).unwrap_or_default())
    } else if line.starts_with(b"POST ") {
        ("POST", line.get(5..).unwrap_or_default())
    } else {
        let get_or = if accept_get { "GET or " } else { "" };
        trace_log_message(
            prog,
            level::WARNING,
            &format!("HTTP request does not begin with {get_or}POST: {shown}"),
        );
        bad(cbio);
        return out;
    };
    // Expecting (GET|POST) {sp} /URL {sp} HTTP/1.x
    let mut url = rest;
    while url.first() == Some(&b' ') {
        url = url.get(1..).unwrap_or_default();
    }
    if url.first() != Some(&b'/') {
        let u = String::from_utf8_lossy(url);
        trace_log_message(
            prog,
            level::WARNING,
            &format!("invalid {meth} -- URL does not begin with '/': {u}"),
        );
        bad(cbio);
        return out;
    }
    url = url.get(1..).unwrap_or_default();
    // Splice off the HTTP version identifier.
    let end = url.iter().position(|&b| b == b' ').unwrap_or(url.len());
    let version = url.get(end..).unwrap_or_default();
    if !version.starts_with(b" HTTP/1.") {
        let v = String::from_utf8_lossy(version.get(1..).unwrap_or_default());
        trace_log_message(
            prog,
            level::WARNING,
            &format!("invalid {meth} -- bad HTTP/version string: {v}"),
        );
        bad(cbio);
        return out;
    }
    let mut keep_alive = version.get(8).is_some_and(|&c| c > b'0');
    url = url.get(..end).unwrap_or_default();
    // "GET / HTTP..." (load balancers): just OK.
    if meth == "GET" && url.is_empty() {
        let _ = http_server_send_status(prog, cbio, 200, "OK");
        return out;
    }
    let Some(decoded) = urldecode(url) else {
        let u = String::from_utf8_lossy(url);
        trace_log_message(
            prog,
            level::WARNING,
            &format!("invalid {meth} request -- bad URL encoding: {u}"),
        );
        bad(cbio);
        return out;
    };
    let mut getbio = None;
    if meth == "GET" {
        getbio = http::base64_reader(&decoded);
        if getbio.is_none() {
            let n = decoded.len();
            trace_log_message(
                prog,
                level::ERR,
                &format!("could not allocate base64 bio with size = {n}"),
            );
            let _ = http_server_send_status(prog, cbio, 500, "Internal Server Error");
            *pcbio = None;
            out.ret = -1;
            return out;
        }
    }
    // Further or duplicate leading, and trailing, '/', of the URL as C sees it (up to its
    // first NUL).
    let mut path: &[u8] = decoded.split(|&b| b == 0).next().unwrap_or_default();
    while path.first() == Some(&b'/') {
        path = path.get(1..).unwrap_or_default();
    }
    while path.len() >= 2 && path.ends_with(b"//") {
        path = path.get(..path.len() - 1).unwrap_or_default();
    }
    let path = String::from_utf8_lossy(path).into_owned();

    // The headers.
    loop {
        let (len, inbuf) = cbio.gets(2048);
        if len <= 0 {
            trace_log_message(prog, level::WARNING, "error reading HTTP header");
            bad(cbio);
            return out;
        }
        let hline = chop_eol(&inbuf);
        let shown = String::from_utf8_lossy(hline.unwrap_or(&inbuf)).into_owned();
        trace_log_message(
            prog,
            level::TRACE,
            if shown.is_empty() { " " } else { &shown },
        );
        let Some(hline) = hline else {
            trace_log_message(
                prog,
                level::WARNING,
                "error parsing HTTP header: missing end of line",
            );
            bad(cbio);
            return out;
        };
        let hline = hline.split(|&b| b == 0).next().unwrap_or_default();
        if hline.is_empty() {
            break;
        }
        let Some(colon) = hline.iter().position(|&b| b == b':') else {
            trace_log_message(
                prog,
                level::WARNING,
                "error parsing HTTP header: missing ':'",
            );
            bad(cbio);
            return out;
        };
        let key = hline.get(..colon).unwrap_or_default();
        let mut value = hline.get(colon + 1..).unwrap_or_default();
        while value.first() == Some(&b' ') {
            value = value.get(1..).unwrap_or_default();
        }
        if key.eq_ignore_ascii_case(b"Connection") {
            if value.eq_ignore_ascii_case(b"keep-alive") {
                keep_alive = true;
            } else if value.eq_ignore_ascii_case(b"close") {
                keep_alive = false;
            }
        }
    }
    if let Some(k) = found_keep_alive {
        *k = keep_alive;
    }
    // The alarm is cleared before the client socket is closed.
    if *armed {
        os::alarm(0);
        *armed = false;
    }

    // The request's content.
    let req = parse(getbio.as_ref().unwrap_or(cbio));
    if req.is_none() {
        trace_log_message(
            prog,
            level::WARNING,
            "error parsing DER-encoded request content",
        );
        bad(cbio);
    } else if want_path {
        out.path = Some(path);
    }
    out.req = req;
    out
}

/// `http_server_send_asn1_resp`: the 200 response header, then the DER `write` writes (of
/// length `len`).
pub fn http_server_send_asn1_resp(
    prog: &str,
    cbio: &Bio,
    keep_alive: bool,
    content_type: &str,
    len: i32,
    write: impl FnOnce(&Bio) -> i32,
) -> bool {
    let ka = if keep_alive {
        "Connection: keep-alive\r\n"
    } else {
        ""
    };
    let buf =
        format!("HTTP/1.0 200 OK\r\n{ka}Content-type: {content_type}\r\nContent-Length: {len}\r\n");
    if buf.len() >= 200 {
        return false;
    }
    if log_get_verbosity() < level::TRACE
        && let Some(p) = buf.find('\r')
    {
        let first = buf.get(..p).unwrap_or_default();
        trace_log_message(
            prog,
            level::INFO,
            &format!("sending response, 1st line: {first}"),
        );
    }
    trace_log_message(
        prog,
        level::TRACE,
        &format!("sending response header:\n{buf}"),
    );
    let ret = cbio.write_all(format!("{buf}\r\n").as_bytes()).is_ok() && write(cbio) > 0;
    cbio.flush();
    ret
}

/// `http_server_send_status`.
pub fn http_server_send_status(prog: &str, cbio: &Bio, status: i32, reason: &str) -> bool {
    let buf = format!("HTTP/1.0 {status} {reason}\r\n\r\n");
    if buf.len() >= 200 {
        return false;
    }
    trace_log_message(
        prog,
        level::TRACE,
        &format!("sending response header:\n{buf}"),
    );
    let ret = cbio.write_all(format!("{buf}\r\n").as_bytes()).is_ok();
    cbio.flush();
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_decoding() {
        assert_eq!(urldecode(b"a%2Fb%2b").as_deref(), Some(&b"a/b+"[..]));
        assert_eq!(urldecode(b"a%2"), None);
        assert_eq!(urldecode(b"%zz"), None);
    }

    #[test]
    fn line_ends() {
        assert_eq!(
            chop_eol(b"GET / HTTP/1.0\r\n"),
            Some(&b"GET / HTTP/1.0"[..])
        );
        assert_eq!(chop_eol(b"x\ny"), Some(&b"x"[..]));
        assert_eq!(chop_eol(b"x\r"), None);
    }

    /// A connection that closes before its request line is dropped, and the next one is
    /// served (upstream's `ocsp` spins on the dead one instead).
    #[test]
    fn live_closed_connection_dropped() {
        if std::env::var_os("RUSTYSSL_CLI_LIVE").is_none() {
            return;
        }
        let acbio = http::accept_bio("0").ok().unwrap();
        let (_, port) = http::sock_info_address(http::bio_fd(&acbio));
        let port: u16 = port.unwrap().parse().unwrap();
        drop(std::net::TcpStream::connect(("127.0.0.1", port)).unwrap());
        let mut cbio = None;
        let parse = |_: &Bio| Some(());
        let r = http_server_get_asn1_req(parse, false, &mut cbio, &acbio, None, "t", true, 0);
        assert_eq!(r.ret, 0);
        assert!(cbio.is_none());
        // The next connection's request is read.
        let mut client = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        client.write_all(b"POST / HTTP/1.0\r\n\r\n").unwrap();
        let r = io::muted(|| {
            http_server_get_asn1_req(parse, false, &mut cbio, &acbio, None, "t", true, 0)
        });
        assert_eq!((r.ret, r.req), (1, Some(())));
    }

    #[test]
    fn verbosity_range() {
        assert!(!log_set_verbosity("t", 9));
        assert!(log_set_verbosity("t", level::INFO));
    }
}
