//! `openssl ciphers` (`apps/ciphers.c`).

use std::io::Write;

use rustyssl_ossl::abi::{
    SSL3_VERSION, TLS1_1_VERSION, TLS1_2_VERSION, TLS1_3_VERSION, TLS1_VERSION,
};
use rustyssl_ossl::ssl::{self, Method, Ssl, SslCtx, SslRef};

use crate::generated::options::ciphers::{OPTIONS, Opt};
use crate::lib::opt::{self, Parser, eprintf};
use crate::lib::{app_libctx, io};

fn dummy_psk(_: SslRef<'_>, _: Option<&str>, _: &mut [u8], _: &mut [u8]) -> u32 {
    0
}

fn dummy_srp(_: SslRef<'_>) -> Option<String> {
    Some(String::new())
}

pub fn main(argv: &[String]) -> i32 {
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let (mut verbose, mut upper_v, mut use_supported, mut stdname) = (false, false, false, false);
    let (mut psk, mut srp) = (false, false);
    let (mut convert, mut ciphersuites): (Option<String>, Option<String>) = (None, None);
    let (mut min_version, mut max_version) = (0, 0);
    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::ERR => {
                eprintf!("{prog}: Use -help for summary.\n");
                return 1;
            }
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::V => verbose = true,
            Opt::UPPER_V => (verbose, upper_v) = (true, true),
            Opt::S => use_supported = true,
            Opt::STDNAME => (stdname, verbose) = (true, true),
            Opt::CONVERT => convert = Some(p.arg().to_owned()),
            Opt::SSL3 => (min_version, max_version) = (SSL3_VERSION, SSL3_VERSION),
            Opt::TLS1 => (min_version, max_version) = (TLS1_VERSION, TLS1_VERSION),
            Opt::TLS1_1 => (min_version, max_version) = (TLS1_1_VERSION, TLS1_1_VERSION),
            Opt::TLS1_2 => (min_version, max_version) = (TLS1_2_VERSION, TLS1_2_VERSION),
            Opt::TLS1_3 => (min_version, max_version) = (TLS1_3_VERSION, TLS1_3_VERSION),
            Opt::PSK => psk = true,
            Opt::SRP => srp = true,
            Opt::CIPHERSUITES => ciphersuites = Some(p.arg().to_owned()),
            Opt::OPT_PROV(o) => {
                if !app_libctx::opt_provider(o, p.arg()) {
                    return 1;
                }
            }
        }
    }

    // Optional arg is cipher name.
    let mut ciphers = None;
    if p.num_rest() == 1 {
        ciphers = p.rest().first().cloned();
    } else if !p.check_rest_arg(None) {
        eprintf!("{prog}: Use -help for summary.\n");
        return 1;
    }

    if let Some(c) = convert {
        let _ = io::out().write_all(
            format!("OpenSSL cipher name: {}\n", ssl::openssl_cipher_name(&c)).as_bytes(),
        );
        return 0;
    }

    let fail = || {
        io::print_errors();
        1
    };
    let libctx = app_libctx::libctx();
    let Some(ctx) = SslCtx::new_ex(
        libctx.as_deref(),
        app_libctx::propq().as_deref(),
        Method::tls_server(),
    ) else {
        return fail();
    };
    let c = ctx.r();
    if !c.set_min_proto_version(min_version) || !c.set_max_proto_version(max_version) {
        return fail();
    }
    if psk {
        c.set_psk_client_callback(dummy_psk);
    }
    if srp {
        c.set_srp_client_pwd_callback(dummy_srp);
    }
    if let Some(cs) = &ciphersuites
        && !c.set_ciphersuites(cs)
    {
        eprintf!("Error setting TLSv1.3 ciphersuites\n");
        return fail();
    }
    if let Some(cl) = &ciphers
        && !c.set_cipher_list(cl)
    {
        eprintf!("Error in cipher list\n");
        return fail();
    }
    let Some(con) = Ssl::new(c) else {
        return fail();
    };
    let sk = if use_supported {
        con.r().supported_ciphers()
    } else {
        con.r().ciphers()
    };

    let mut out = String::new();
    if !verbose {
        for (i, c) in sk.iter().enumerate() {
            let Some(name) = c.name() else { break };
            if i != 0 {
                out.push(':');
            }
            out.push_str(&name);
        }
        out.push('\n');
    } else {
        for c in &sk {
            if upper_v {
                let id = c.id();
                let (id0, id1, id2, id3) =
                    (id >> 24, (id >> 16) & 0xff, (id >> 8) & 0xff, id & 0xff);
                if id & 0xff00_0000 == 0x0300_0000 {
                    out.push_str(&format!("          0x{id2:02X},0x{id3:02X} - "));
                } else {
                    out.push_str(&format!(
                        "0x{id0:02X},0x{id1:02X},0x{id2:02X},0x{id3:02X} - "
                    ));
                }
            }
            if stdname {
                let nm = c.standard_name().unwrap_or_else(|| "UNKNOWN".to_owned());
                out.push_str(&format!("{nm:<45} - "));
            }
            out.push_str(&c.description().unwrap_or_default());
        }
    }
    let _ = io::out().write_all(out.as_bytes());
    0
}
