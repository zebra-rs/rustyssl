//! The TLS commands' sockets: a port of `apps/lib/s_socket.c` (`init_client`, `do_server`,
//! `report_server_accept`, `do_ssl_shutdown`).

use std::cell::RefCell;

use rustyssl_ossl::abi::{
    BIO_LOOKUP_CLIENT, BIO_LOOKUP_SERVER, BIO_SOCK_NODELAY, BIO_SOCK_REUSEADDR, BIO_SOCK_TFO,
    BIO_SOCK_V6_ONLY, SSL_ERROR_WANT_ASYNC, SSL_ERROR_WANT_ASYNC_JOB, SSL_ERROR_WANT_READ,
    SSL_ERROR_WANT_WRITE,
};
use rustyssl_ossl::sock::consts::{
    AF_INET, AF_INET6, AF_UNIX, AF_UNSPEC, IPPROTO_TCP, SOCK_STREAM,
};
use rustyssl_ossl::sock::{self, Addr, AddrInfo};
use rustyssl_ossl::ssl::SslRef;
use rustyssl_ossl::{Bio, err};

use super::io;
use super::opt::eprintf;

thread_local! {
    /// `ourpeer`: the peer of the connection being served, for the cookie callback.
    static OURPEER: RefCell<Option<Addr>> = const { RefCell::new(None) };
}

/// Runs `f` with the current peer's address (`ourpeer`), if there is one.
pub fn with_ourpeer<T>(f: impl FnOnce(Option<&Addr>) -> T) -> T {
    OURPEER.with(|p| f(p.borrow().as_ref()))
}

/// What `init_client` made: the socket and, for TFO or an unconnected socket, the peer's
/// address.
pub struct Client {
    pub sock: i32,
    pub peer: Option<Addr>,
}

/// `init_client(&sock, host, port, bindhost, bindport, family, type, protocol, tfo,
/// doconn, &ba_ret)`: `Err(sock)` (`INVALID_SOCKET` or a socket that failed) on failure.
#[allow(clippy::too_many_arguments)]
pub fn init_client(
    host: Option<&str>,
    port: Option<&str>,
    bindhost: Option<&str>,
    bindport: Option<&str>,
    family: i32,
    socktype: i32,
    protocol: i32,
    tfo: bool,
    doconn: bool,
    want_addr: bool,
) -> Result<Client, i32> {
    let mut sockfd = -1;
    if !sock::sock_init() {
        return Err(sockfd);
    }
    let Some(res) = AddrInfo::lookup_ex(host, port, BIO_LOOKUP_CLIENT, family, socktype, protocol)
    else {
        io::print_errors();
        return Err(sockfd);
    };
    let bindaddr = if bindhost.is_some() || bindport.is_some() {
        match AddrInfo::lookup_ex(
            bindhost,
            bindport,
            BIO_LOOKUP_CLIENT,
            family,
            socktype,
            protocol,
        ) {
            Some(b) => Some(b),
            None => {
                io::print_errors();
                return Err(sockfd);
            }
        }
    } else {
        None
    };
    let mut found = 0;
    let mut chosen = None;
    let mut peer = None;
    let entries = res.iter();
    let binds = bindaddr.as_ref().map(AddrInfo::iter);
    for ai in &entries {
        let mut bi = None;
        if let Some(binds) = &binds {
            bi = binds.iter().find(|b| b.family() == ai.family()).copied();
            if bi.is_none() {
                continue;
            }
            found += 1;
        }
        sockfd = sock::socket(ai.family(), ai.socktype(), ai.protocol());
        if sockfd == -1 {
            // Maybe the kernel doesn't support the socket family.
            continue;
        }
        if let Some(b) = bi
            && !b.bind(sockfd, BIO_SOCK_REUSEADDR)
        {
            sock::closesocket(sockfd);
            sockfd = -1;
            break;
        }
        let mut options = 0;
        if ai.protocol() == IPPROTO_TCP {
            options |= BIO_SOCK_NODELAY;
            if tfo {
                options |= BIO_SOCK_TFO;
            }
        }
        if doconn && !ai.connect(sockfd, options) {
            sock::closesocket(sockfd);
            sockfd = -1;
            continue;
        }
        // Save the address.
        if tfo || !doconn {
            if !want_addr {
                eprintf!("Internal error\n");
                sock::closesocket(sockfd);
                return Err(-1);
            }
            peer = ai.address_dup();
        }
        // Success, don't try any more addresses.
        chosen = Some(*ai);
        break;
    }
    if sockfd == -1 {
        if bindaddr.is_some() && found == 0 {
            let fam = entries.first().map_or(AF_UNSPEC, |e| e.family());
            let which = match fam {
                f if f == AF_INET6 => "IPv6 ",
                f if f == AF_INET => "IPv4 ",
                f if f == AF_UNIX => "unix ",
                _ => "",
            };
            eprintf!(
                "Can't bind {which}address for {}{}{}\n",
                bindhost.unwrap_or(""),
                if bindport.is_some() { ":" } else { "" },
                bindport.unwrap_or("")
            );
            err::clear();
        }
        io::print_errors();
        return Err(sockfd);
    }
    if let Some(hostname) = chosen.and_then(|ai| ai.hostname_string()) {
        eprintf!("Connecting to {hostname}\n");
    }
    // Remove any stale errors from previous connection attempts.
    err::clear();
    Ok(Client { sock: sockfd, peer })
}

/// `report_server_accept(out, asock, with_address, with_pid)`.
pub fn report_server_accept(out: &Bio, asock: i32, with_address: bool, with_pid: bool) -> bool {
    let mut text = String::from("ACCEPT");
    let mut success = true;
    if with_address {
        let a = sock::sock_address(asock);
        let host = a.as_ref().and_then(Addr::hostname_string);
        let service = a.as_ref().and_then(Addr::service_string);
        match (host, service) {
            (Some(h), Some(s)) => {
                if h.contains(':') {
                    text.push_str(&format!(" [{h}]:{s}"));
                } else {
                    text.push_str(&format!(" {h}:{s}"));
                }
            }
            _ => {
                success = false;
                text.push_str("unknown:error\n");
            }
        }
    }
    if with_pid {
        text.push_str(&format!(" PID={}", sock::getpid()));
    }
    text.push('\n');
    let ok = out.write_all(text.as_bytes()).is_ok();
    out.flush();
    success && ok
}

/// The connection handler of [`do_server`]: the socket, its type and protocol; negative
/// stops the server.
pub type ServerCb<'a> = dyn FnMut(i32, i32, i32) -> i32 + 'a;

/// `do_server(&accept_sock, host, port, family, type, protocol, cb, context, naccept,
/// bio_s_out, tfo)`: 0 on failure. The accepting socket is reported through `on_listen`.
#[allow(clippy::too_many_arguments)]
pub fn do_server(
    host: Option<&str>,
    port: Option<&str>,
    family: i32,
    socktype: i32,
    protocol: i32,
    cb: &mut ServerCb<'_>,
    mut naccept: i64,
    bio_s_out: &Bio,
    tfo: bool,
    on_listen: &mut dyn FnMut(i32),
) -> i32 {
    let ret = do_server_inner(
        host,
        port,
        family,
        socktype,
        protocol,
        cb,
        &mut naccept,
        bio_s_out,
        tfo,
        on_listen,
    );
    if family == AF_UNIX
        && let Some(h) = host
    {
        sock::unlink(h);
    }
    OURPEER.with(|p| *p.borrow_mut() = None);
    ret
}

#[allow(clippy::too_many_arguments)]
fn do_server_inner(
    host: Option<&str>,
    port: Option<&str>,
    family: i32,
    socktype: i32,
    protocol: i32,
    cb: &mut ServerCb<'_>,
    naccept: &mut i64,
    bio_s_out: &Bio,
    tfo: bool,
    on_listen: &mut dyn FnMut(i32),
) -> i32 {
    if !sock::sock_init() {
        return 0;
    }
    let Some(res) = AddrInfo::lookup_ex(host, port, BIO_LOOKUP_SERVER, family, socktype, protocol)
    else {
        io::print_errors();
        return 0;
    };
    let entries = res.iter();
    let Some(&first) = entries.first() else {
        return 0;
    };
    let mut sock_family = first.family();
    let sock_type = first.socktype();
    let sock_protocol = first.protocol();
    let mut sock_address = first;
    let next = entries.get(1).copied();
    let mut fallback: Option<(i32, rustyssl_ossl::sock::AddrInfoRef<'_>)> = None;
    let mut sock_options = BIO_SOCK_REUSEADDR;
    if tfo && sock_type == SOCK_STREAM {
        sock_options |= BIO_SOCK_TFO;
    }
    if sock_family == AF_INET6 {
        sock_options |= BIO_SOCK_V6_ONLY;
    }
    if let Some(n) = next
        && n.socktype() == sock_type
        && n.protocol() == sock_protocol
    {
        if sock_family == AF_INET && n.family() == AF_INET6 {
            // In case AF_INET6 is returned but not supported by the kernel, retry with the
            // first detected address family.
            fallback = Some((sock_family, sock_address));
            sock_family = AF_INET6;
            sock_address = n;
        } else if sock_family == AF_INET6 && n.family() == AF_INET {
            sock_options &= !BIO_SOCK_V6_ONLY;
        }
    }
    let mut asock = sock::socket(sock_family, sock_type, sock_protocol);
    if asock == -1
        && let Some((f, a)) = fallback
    {
        asock = sock::socket(f, sock_type, sock_protocol);
        sock_address = a;
    }
    if asock == -1 || !sock_address.listen(asock, sock_options) {
        io::print_errors();
        if asock != -1 {
            sock::closesocket(asock);
        }
        return 0;
    }
    let sock_port = sock_address.rawport();
    drop(entries);
    drop(res);
    if !report_server_accept(bio_s_out, asock, sock_port == 0, false) {
        sock::closesocket(asock);
        io::print_errors();
        return 0;
    }
    on_listen(asock);
    loop {
        let i;
        if socktype == SOCK_STREAM {
            let Some(peer) = Addr::new() else {
                sock::closesocket(asock);
                io::print_errors();
                return 0;
            };
            OURPEER.with(|p| *p.borrow_mut() = Some(peer));
            let mut s;
            loop {
                s = OURPEER.with(|p| sock::accept_ex(asock, p.borrow().as_ref()));
                if !(s < 0 && sock::sock_should_retry(s)) {
                    break;
                }
            }
            if s < 0 {
                io::print_errors();
                sock::closesocket(asock);
                return 0;
            }
            if *naccept != -1 {
                *naccept -= 1;
            }
            sock::set_tcp_ndelay(s, 1);
            i = cb(s, socktype, protocol);
            // Shut down the sending side first, then drain what the peer still sends (so
            // that an alert reaches it), then close.
            sock::shutdown_wr(s);
            let mut sink = [0u8; 64];
            // One timeout for the whole drain, as Linux's select counts it down.
            let deadline = std::time::Instant::now() + std::time::Duration::from_micros(500_000);
            loop {
                let left = deadline.saturating_duration_since(std::time::Instant::now());
                let (r, ready, _) = sock::select(&[s], &[], Some(left));
                if !(r > 0 && ready.first() == Some(&true) && sock::read_fd(s, &mut sink) > 0) {
                    break;
                }
            }
            sock::closesocket(s);
        } else {
            if *naccept != -1 {
                *naccept -= 1;
            }
            i = cb(asock, socktype, protocol);
        }
        if i < 0 || *naccept == 0 {
            sock::closesocket(asock);
            return i;
        }
    }
}

/// `do_ssl_shutdown`: a unidirectional shutdown, retried while it would block.
pub fn do_ssl_shutdown(ssl: SslRef<'_>) {
    loop {
        let ret = ssl.shutdown();
        if ret >= 0 {
            return;
        }
        match ssl.get_error(ret) {
            SSL_ERROR_WANT_READ
            | SSL_ERROR_WANT_WRITE
            | SSL_ERROR_WANT_ASYNC
            | SSL_ERROR_WANT_ASYNC_JOB => continue,
            _ => return,
        }
    }
}
