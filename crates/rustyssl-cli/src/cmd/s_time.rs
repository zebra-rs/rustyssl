//! `openssl s_time` (`apps/s_time.c`).

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use rustyssl_ossl::abi::{
    BIO_C_SET_CONNECT_MODE, BIO_SOCK_NODELAY, SSL_OP_ALL, SSL_RECEIVED_SHUTDOWN, SSL_SENT_SHUTDOWN,
    SSL3_VERSION, TLS1_1_VERSION, TLS1_2_VERSION, TLS1_3_VERSION, TLS1_VERSION, X509_V_OK,
};
use rustyssl_ossl::ssl::{self, CtxRef, Method, Ssl, SslCtx};
use rustyssl_ossl::{Bio, sock};

use crate::generated::options::s_time::{OPTIONS, Opt};
use crate::lib::opt::{self, Parser, eprintf};
use crate::lib::s_cb;
use crate::lib::{app_libctx, apps, io};

const SSL_CONNECT_NAME: &str = "localhost:4433";
const SECONDS: i32 = 30;

/// `fmt_http_get_cmd`'s length less its `%s`.
const FMT_HTTP_GET_CMD_SIZE: usize = "GET %s HTTP/1.0\r\n\r\n".len() - 1;

/// Upstream's `buf`.
const BUFSIZE: usize = 1024 * 8;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn out(s: &str) {
    let mut o = io::out();
    let _ = o.write_all(s.as_bytes());
    let _ = o.flush();
}

/// `tm_Time_F`: the user time since the last `START`.
struct Timer(f64);

impl Timer {
    fn start() -> Self {
        Self(sock::user_seconds())
    }
    fn stop(&self) -> f64 {
        sock::user_seconds() - self.0
    }
}

/// `doConnection`: connects `scon` (reset) or a new `SSL`; `None` on failure.
fn do_connection(scon: Option<Ssl>, host: &str, ctx: CtxRef<'_>) -> Option<Ssl> {
    let conn = Bio::new_connect()?;
    if conn.set_conn_hostname(host) <= 0
        || conn.ctrl_long(BIO_C_SET_CONNECT_MODE, BIO_SOCK_NODELAY.into()) <= 0
    {
        return None;
    }
    let server_con = match scon {
        None => Ssl::new(ctx)?,
        Some(s) => {
            // Reset the SSL object before reusing it for a new connection.
            if !s.r().clear() {
                io::print_errors();
                return None;
            }
            s.r().set_connect_state();
            s
        }
    };
    server_con.r().set_bio(conn);
    if server_con.r().connect() <= 0 {
        eprintf!("ERROR\n");
        let error = s_cb::verify_args().error;
        if error != X509_V_OK {
            eprintf!(
                "verify error:{}\n",
                ssl::verify_cert_error_string(error.into())
            );
        } else {
            io::print_errors();
        }
        return None;
    }
    let fd = server_con.r().fd();
    if fd >= 0 {
        sock::set_no_linger(fd);
    }
    Some(server_con)
}

/// The connection's mark: `r` reused, `t` TLS 1.0, `3` SSLv3, `*` otherwise.
fn mark(s: &Ssl) -> char {
    if s.r().session_reused() {
        return 'r';
    }
    match s.r().version() {
        TLS1_VERSION => 't',
        SSL3_VERSION => '3',
        _ => '*',
    }
}

/// Sends the GET and reads the reply; the octets read, `None` on a write failure.
fn fetch(s: &Ssl, path: &str) -> Option<i64> {
    let cmd = format!("GET {path} HTTP/1.0\r\n\r\n");
    // BIO_snprintf truncates to the buffer (the length was checked with the option).
    let cmd = cmd.as_bytes().get(..BUFSIZE - 1).unwrap_or(cmd.as_bytes());
    if cmd.is_empty() || s.r().write(cmd) <= 0 {
        return None;
    }
    let mut buf = vec![0u8; BUFSIZE];
    let mut n = 0i64;
    loop {
        let i = s.r().read(&mut buf);
        if i <= 0 {
            break;
        }
        n += i64::from(i);
    }
    Some(n)
}

fn close(s: &Ssl) {
    s.r()
        .set_shutdown(SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    let fd = s.r().fd();
    if fd >= 0 {
        sock::closesocket(fd);
    }
}

/// `%.2f` of a ratio as C prints it (`inf`, `nan` and `-nan` included).
fn ratio(n: i32, t: f64) -> String {
    let r = f64::from(n) / t;
    if r.is_nan() {
        return if r.is_sign_negative() {
            "-nan".into()
        } else {
            "nan".into()
        };
    }
    format!("{r:.2}")
}

pub fn main(argv: &[String]) -> i32 {
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let (mut ca_path, mut ca_file, mut ca_store) = (None::<String>, None::<String>, None::<String>);
    let (mut cipher, mut ciphersuites, mut www_path) =
        (None::<String>, None::<String>, None::<String>);
    let mut host = SSL_CONNECT_NAME.to_owned();
    let (mut certfile, mut keyfile) = (None::<String>, None::<String>);
    let (mut no_ca_path, mut no_ca_file, mut no_ca_store) = (false, false, false);
    let (mut maxtime, mut perform, mut st_bugs) = (SECONDS, 3, false);
    let (mut min_version, mut max_version) = (0, 0);
    let opthelp = |prog: &str| {
        eprintf!("{prog}: Use -help for summary.\n");
        1
    };
    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::ERR => return opthelp(&prog),
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::CONNECT => host = p.arg().to_owned(),
            Opt::REUSE => perform = 2,
            Opt::NEW => perform = 1,
            Opt::VERIFY => {
                let depth = p.int_arg();
                s_cb::set_verify_args(|a| a.depth = depth);
                eprintf!("{prog}: verify depth is {depth}\n");
            }
            Opt::CERT => certfile = Some(p.arg().to_owned()),
            Opt::NAMEOPT => {
                if !apps::set_nameopt(Some(p.arg())) {
                    return 1;
                }
            }
            Opt::KEY => keyfile = Some(p.arg().to_owned()),
            Opt::CAPATH => ca_path = Some(p.arg().to_owned()),
            Opt::CAFILE => ca_file = Some(p.arg().to_owned()),
            Opt::NOCAPATH => no_ca_path = true,
            Opt::NOCAFILE => no_ca_file = true,
            Opt::CASTORE => ca_store = Some(p.arg().to_owned()),
            Opt::NOCASTORE => no_ca_store = true,
            Opt::CIPHER => cipher = Some(p.arg().to_owned()),
            Opt::CIPHERSUITES => ciphersuites = Some(p.arg().to_owned()),
            Opt::BUGS => st_bugs = true,
            Opt::TIME => maxtime = p.int_arg(),
            Opt::WWW => {
                let w = p.arg().to_owned();
                if w.len() + FMT_HTTP_GET_CMD_SIZE > BUFSIZE {
                    eprintf!("{prog}: -www option is too long\n");
                    return 1;
                }
                www_path = Some(w);
            }
            Opt::SSL3 => (min_version, max_version) = (SSL3_VERSION, SSL3_VERSION),
            Opt::TLS1 => (min_version, max_version) = (TLS1_VERSION, TLS1_VERSION),
            Opt::TLS1_1 => (min_version, max_version) = (TLS1_1_VERSION, TLS1_1_VERSION),
            Opt::TLS1_2 => (min_version, max_version) = (TLS1_2_VERSION, TLS1_2_VERSION),
            Opt::TLS1_3 => (min_version, max_version) = (TLS1_3_VERSION, TLS1_3_VERSION),
            Opt::OPT_PROV(o) => {
                if !app_libctx::opt_provider(o, p.arg()) {
                    return 1;
                }
            }
        }
    }

    // No extra arguments.
    if !p.check_rest_arg(None) {
        return opthelp(&prog);
    }

    if cipher.is_none() {
        cipher = std::env::var("SSL_CIPHER").ok();
    }

    let Some(ctx) = SslCtx::new(Method::tls_client()) else {
        return 1;
    };
    let c = ctx.r();
    c.set_quiet_shutdown(1);
    if !c.set_min_proto_version(min_version) || !c.set_max_proto_version(max_version) {
        return 1;
    }
    if st_bugs {
        c.set_options(SSL_OP_ALL);
    }
    if cipher.as_deref().is_some_and(|s| !c.set_cipher_list(s)) {
        return 1;
    }
    if ciphersuites
        .as_deref()
        .is_some_and(|s| !c.set_ciphersuites(s))
    {
        return 1;
    }
    if !s_cb::set_cert_stuff(c, certfile.as_deref(), keyfile.as_deref()) {
        return 1;
    }
    if !s_cb::ctx_set_verify_locations(
        c,
        ca_file.as_deref(),
        no_ca_file,
        ca_path.as_deref(),
        no_ca_path,
        ca_store.as_deref(),
        no_ca_store,
    ) {
        io::print_errors();
        return 1;
    }

    if perform & 1 != 0 {
        out(&format!(
            "Collecting connection statistics for {maxtime} seconds\n"
        ));
        // Loop and time how long it takes to make connections.
        let mut bytes_read = 0i64;
        let mut n_conn = 0i32;
        let finishtime = now() + i64::from(maxtime);
        let timer = Timer::start();
        loop {
            if finishtime < now() {
                break;
            }
            let Some(scon) = do_connection(None, &host, c) else {
                return 1;
            };
            if let Some(w) = &www_path {
                let Some(n) = fetch(&scon, w) else {
                    return 1;
                };
                bytes_read += n;
            }
            close(&scon);
            n_conn += 1;
            out(&mark(&scon).to_string());
        }
        let total = timer.stop();
        out(&format!(
            "\n\n{n_conn} connections in {total:.2}s; {} connections/user sec, bytes read {bytes_read}\n",
            ratio(n_conn, total)
        ));
        out(&format!(
            "{n_conn} connections in {} real seconds, {} bytes read per connection\n",
            now() - finishtime + i64::from(maxtime),
            if n_conn > 0 {
                bytes_read / i64::from(n_conn)
            } else {
                0
            }
        ));
    }

    // Now loop and time connections using the same session id over and over.
    if perform & 2 == 0 {
        return 0;
    }
    out("\n\nNow timing with session id reuse.\n");

    // Get an SSL object so we can reuse the session id.
    let Some(mut scon) = do_connection(None, &host, c) else {
        eprintf!("Unable to get connection\n");
        return 1;
    };
    if let Some(w) = &www_path
        && fetch(&scon, w).is_none()
    {
        return 1;
    }
    close(&scon);

    let mut n_conn = 0i32;
    let finishtime = now() + i64::from(maxtime);
    out("starting\n");
    let mut bytes_read = 0i64;
    let timer = Timer::start();
    loop {
        if finishtime < now() {
            break;
        }
        let Some(s) = do_connection(Some(scon), &host, c) else {
            return 1;
        };
        scon = s;
        if let Some(w) = &www_path {
            let Some(n) = fetch(&scon, w) else {
                return 1;
            };
            bytes_read += n;
        }
        close(&scon);
        n_conn += 1;
        out(&mark(&scon).to_string());
    }
    let total = timer.stop();
    out(&format!(
        "\n\n{n_conn} connections in {total:.2}s; {} connections/user sec, bytes read {bytes_read}\n",
        ratio(n_conn, total)
    ));
    let real = now() - finishtime + i64::from(maxtime);
    if n_conn > 0 {
        out(&format!(
            "{n_conn} connections in {real} real seconds, {} bytes read per connection\n",
            bytes_read / i64::from(n_conn)
        ));
    } else {
        out(&format!("0 connections in {real} real seconds\n"));
    }
    0
}
