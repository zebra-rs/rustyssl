//! `openssl sess_id` (`apps/sess_id.c`).

use rustyssl_ossl::abi::SSL_MAX_SID_CTX_LENGTH;
use rustyssl_ossl::session::Session;

use crate::generated::options::sess_id::{OPTIONS, Opt};
use crate::lib::apps::bio_open_default;
use crate::lib::io;
use crate::lib::opt::{self, Parser, eprintf, fmt_flags, format};

pub fn main(argv: &[String]) -> i32 {
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let (mut informat, mut outformat) = (format::PEM, format::PEM);
    let (mut infile, mut outfile, mut context) = (None, None, None);
    let (mut cert, mut noout, mut text, mut num) = (0, 0, 0, 0);
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
            Opt::INFORM => match opt::parse_format(p.arg(), fmt_flags::PEMDER) {
                Some(f) => informat = f,
                None => {
                    eprintf!("{prog}: Use -help for summary.\n");
                    return 1;
                }
            },
            Opt::OUTFORM => {
                let flags = fmt_flags::PEMDER | fmt_flags::NSS;
                match opt::parse_format(p.arg(), flags) {
                    Some(f) => outformat = f,
                    None => {
                        eprintf!("{prog}: Use -help for summary.\n");
                        return 1;
                    }
                }
            }
            Opt::IN => infile = Some(p.arg().to_owned()),
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::TEXT => {
                num += 1;
                text = num;
            }
            Opt::CERT => {
                num += 1;
                cert = num;
            }
            Opt::NOOUT => {
                num += 1;
                noout = num;
            }
            Opt::CONTEXT => context = Some(p.arg().to_owned()),
        }
    }
    if !p.check_rest_arg(None) {
        eprintf!("{prog}: Use -help for summary.\n");
        return 1;
    }

    let Some(x) = load_sess_id(infile.as_deref(), informat) else {
        return 1;
    };
    let peer = x.peer();
    if let Some(c) = &context {
        if c.len() > SSL_MAX_SID_CTX_LENGTH as usize {
            eprintf!("Context too long\n");
            return 1;
        }
        if !x.set1_id_context(c.as_bytes()) {
            eprintf!("Error setting id context\n");
            return 1;
        }
    }
    let out = if noout == 0 || text != 0 {
        match bio_open_default(outfile.as_deref(), 'w', outformat) {
            Some(b) => Some(b),
            None => return 1,
        }
    } else {
        None
    };
    if let (Some(out), true) = (&out, text != 0) {
        x.print(out);
        if cert != 0 {
            match &peer {
                None => {
                    let _ = out.write_all(b"No certificate present\n");
                }
                Some(c) => {
                    c.print(out);
                }
            }
        }
    }
    let Some(out) = &out else {
        return 0;
    };
    if noout == 0 && cert == 0 {
        let i = match outformat {
            format::ASN1 => x.write_der(out),
            format::PEM => x.write_pem(out),
            format::NSS => x.print_keylog(out),
            _ => {
                eprintf!("bad output format specified for outfile\n");
                return 1;
            }
        };
        if i == 0 {
            eprintf!("unable to write SSL_SESSION\n");
            return 1;
        }
    } else if noout == 0
        && let Some(peer) = &peer
    {
        let ok = match outformat {
            format::ASN1 => peer.write_der(out) == 1,
            format::PEM => peer.write_pem(out) == 1,
            _ => {
                eprintf!("bad output format specified for outfile\n");
                return 1;
            }
        };
        if !ok {
            eprintf!("unable to write X509\n");
            return 1;
        }
    }
    0
}

/// `load_sess_id`.
fn load_sess_id(infile: Option<&str>, format: i32) -> Option<Session> {
    let input = bio_open_default(infile, 'r', format)?;
    let x = if format == format::ASN1 {
        Session::read_der(&input)
    } else {
        Session::read_pem(&input)
    };
    if x.is_none() {
        eprintf!("unable to load SSL_SESSION\n");
        io::print_errors();
    }
    x
}
