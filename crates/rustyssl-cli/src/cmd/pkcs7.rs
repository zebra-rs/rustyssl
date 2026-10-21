//! `openssl pkcs7` (`apps/pkcs7.c`).

use rustyssl_ossl::pkcs7::Pkcs7;

use crate::generated::options::pkcs7::{OPTIONS, Opt};
use crate::lib::apps::{bio_open_default, dump_cert_text, get_nameopt};
use crate::lib::opt::{self, Parser, eprintf, fmt_flags, format};
use crate::lib::{app_libctx, engine, io};

pub fn main(argv: &[String]) -> i32 {
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let (mut informat, mut outformat) = (format::PEM, format::PEM);
    let (mut infile, mut outfile) = (None, None);
    let (mut print_certs, mut text, mut noout, mut p7_print, mut quiet) =
        (false, false, false, false, false);
    let mut _e = None;
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
            Opt::INFORM | Opt::OUTFORM => {
                let Some(f) = opt::parse_format(p.arg(), fmt_flags::PEMDER) else {
                    eprintf!("{prog}: Use -help for summary.\n");
                    return 1;
                };
                if p.flag() == "-inform" {
                    informat = f;
                } else {
                    outformat = f;
                }
            }
            Opt::IN => infile = Some(p.arg().to_owned()),
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::NOOUT => noout = true,
            Opt::TEXT => text = true,
            Opt::PRINT => p7_print = true,
            Opt::PRINT_CERTS => print_certs = true,
            Opt::QUIET => quiet = true,
            Opt::ENGINE => _e = engine::setup_engine(Some(p.arg()), false),
            Opt::OPT_PROV(o) => {
                if !app_libctx::opt_provider(o, p.arg()) {
                    return 1;
                }
            }
        }
    }
    if !p.check_rest_arg(None) {
        eprintf!("{prog}: Use -help for summary.\n");
        return 1;
    }

    let Some(input) = bio_open_default(infile.as_deref(), 'r', informat) else {
        return 1;
    };
    let lc = app_libctx::libctx();
    let pq = app_libctx::propq();
    let Some(p7) = Pkcs7::new_ex(lc.as_deref(), pq.as_deref()) else {
        eprintf!("unable to allocate PKCS7 object\n");
        io::print_errors();
        return 1;
    };
    let p7 = if informat == format::ASN1 {
        p7.read_der_into(&input)
    } else {
        p7.read_pem_into(&input)
    };
    let Some(p7) = p7 else {
        eprintf!("unable to load PKCS7 object\n");
        io::print_errors();
        return 1;
    };
    let Some(out) = bio_open_default(outfile.as_deref(), 'w', outformat) else {
        return 1;
    };
    if p7_print {
        p7.print_ctx(&out, 0);
    }
    if print_certs {
        let (certs, crls) = p7.certs_and_crls();
        for x in certs.unwrap_or_default() {
            if text {
                x.print(&out);
            } else if !quiet {
                dump_cert_text(&out, &x);
            }
            if !noout {
                x.write_pem(&out);
            }
            let _ = out.write_all(b"\n");
        }
        for crl in crls.unwrap_or_default() {
            crl.print_ex(&out, get_nameopt());
            if !noout {
                crl.write_pem(&out);
            }
            let _ = out.write_all(b"\n");
        }
        return 0;
    }
    if !noout {
        let i = if outformat == format::ASN1 {
            p7.write_der(&out)
        } else {
            p7.write_pem(&out)
        };
        if i == 0 {
            eprintf!("unable to write pkcs7 object\n");
            io::print_errors();
            return 1;
        }
    }
    0
}
