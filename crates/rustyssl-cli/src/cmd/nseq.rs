//! `openssl nseq` (`apps/nseq.c`).

use rustyssl_ossl::x509::{Cert, CertSeq};

use crate::generated::options::nseq::{OPTIONS, Opt};
use crate::lib::apps::{bio_open_default, dump_cert_text};
use crate::lib::opt::{self, Parser, eprintf, format};
use crate::lib::{app_libctx, io};

/// `BIO_printf`'s `%s` of a NULL string.
pub(crate) fn or_null(s: Option<&str>) -> &str {
    s.unwrap_or("<NULL>")
}

pub fn main(argv: &[String]) -> i32 {
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let usage = || {
        eprintf!("{prog}: Use -help for summary.\n");
        1
    };
    let mut toseq = false;
    let (mut infile, mut outfile) = (None, None);
    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::ERR => return usage(),
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::TOSEQ => toseq = true,
            Opt::IN => infile = Some(p.arg().to_owned()),
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::OPT_PROV(o) => {
                if !app_libctx::opt_provider(o, p.arg()) {
                    return 1;
                }
            }
        }
    }
    if !p.check_rest_arg(None) {
        return usage();
    }
    let Some(input) = bio_open_default(infile.as_deref(), 'r', format::PEM) else {
        return 1;
    };
    let Some(out) = bio_open_default(outfile.as_deref(), 'w', format::PEM) else {
        return 1;
    };
    if toseq {
        let Some(seq) = CertSeq::new() else {
            return 1;
        };
        while let Some(x) = Cert::read_pem(&input) {
            if !seq.push(x) {
                return 1;
            }
        }
        if seq.is_empty() {
            eprintf!(
                "{prog}: Error reading certs file {}\n",
                or_null(infile.as_deref())
            );
            io::print_errors();
            return 1;
        }
        seq.write_pem(&out);
        return 0;
    }
    let Some(seq) = CertSeq::read_pem(&input) else {
        eprintf!(
            "{prog}: Error reading sequence file {}\n",
            or_null(infile.as_deref())
        );
        io::print_errors();
        return 1;
    };
    for i in 0..seq.len() {
        if let Some(x) = seq.get(i) {
            dump_cert_text(&out, &x);
            x.write_pem(&out);
        }
    }
    0
}
