//! `openssl crl2pkcs7` (`apps/crl2pkcs7.c`).

use rustyssl_ossl::Bio;
use rustyssl_ossl::x509::{self, CertStack, Crl, Pkcs7};

use crate::generated::options::crl2pkcs7::{OPTIONS, Opt};
use crate::lib::app_libctx::opt_provider;
use crate::lib::apps::bio_open_default;
use crate::lib::io;
use crate::lib::opt::{self, Parser, eprintf, fmt_flags, format};

pub fn main(argv: &[String]) -> i32 {
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let (mut infile, mut outfile): (Option<String>, Option<String>) = (None, None);
    let (mut informat, mut outformat) = (format::PEM, format::PEM);
    let mut nocrl = false;
    let mut certflst: Vec<String> = Vec::new();
    let opthelp = || {
        eprintf!("{prog}: Use -help for summary.\n");
        1
    };
    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::ERR => return opthelp(),
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::INFORM => match opt::parse_format(p.arg(), fmt_flags::PEMDER) {
                Some(f) => informat = f,
                None => return opthelp(),
            },
            Opt::OUTFORM => match opt::parse_format(p.arg(), fmt_flags::PEMDER) {
                Some(f) => outformat = f,
                None => return opthelp(),
            },
            Opt::IN => infile = Some(p.arg().to_owned()),
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::NOCRL => nocrl = true,
            Opt::CERTFILE => certflst.push(p.arg().to_owned()),
            Opt::OPT_PROV(o) => {
                if !opt_provider(o, p.arg()) {
                    return 1;
                }
            }
        }
    }
    if !p.check_rest_arg(None) {
        return opthelp();
    }

    let mut crl = None;
    if !nocrl {
        let Some(input) = bio_open_default(infile.as_deref(), 'r', informat) else {
            return 1;
        };
        crl = if informat == format::ASN1 {
            Crl::read_der_bio(&input)
        } else if informat == format::PEM {
            Crl::read_pem_bio(&input)
        } else {
            None
        };
        if crl.is_none() {
            eprintf!("unable to load CRL\n");
            io::print_errors();
            return 1;
        }
    }

    let mut certs = None;
    if !certflst.is_empty() {
        let Some(stack) = CertStack::new() else {
            return 1;
        };
        for certfile in &certflst {
            if add_certs_from_file(&stack, certfile).is_none() {
                eprintf!("error loading certificates\n");
                io::print_errors();
                return 1;
            }
        }
        certs = Some(stack);
    }
    let Some(p7) = Pkcs7::degenerate_signed(crl, certs) else {
        return 1;
    };

    let Some(out) = bio_open_default(outfile.as_deref(), 'w', outformat) else {
        return 1;
    };
    let i = if outformat == format::ASN1 {
        p7.write_der(&out)
    } else if outformat == format::PEM {
        p7.write_pem(&out)
    } else {
        0
    };
    if i == 0 {
        eprintf!("unable to write pkcs7 object\n");
        io::print_errors();
        return 1;
    }
    0
}

/// `add_certs_from_file`: the certificates of a PEM file, onto `stack`.
fn add_certs_from_file(stack: &CertStack, certfile: &str) -> Option<usize> {
    let Some(input) = Bio::new_file(certfile, "r") else {
        eprintf!("error opening the file, {certfile}\n");
        return None;
    };
    let Some(certs) = x509::pem_x509_info_certs(&input) else {
        eprintf!("error reading the file, {certfile}\n");
        return None;
    };
    let mut count = 0;
    for c in certs {
        if !stack.push(c) {
            return None;
        }
        count += 1;
    }
    Some(count)
}
