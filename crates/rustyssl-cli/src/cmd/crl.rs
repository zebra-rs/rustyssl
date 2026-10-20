//! `openssl crl` (`apps/crl.c`).

use std::io::Write;

use rustyssl_ossl::abi::{ASN1_DTFLGS_RFC822, NID_crl_number};
use rustyssl_ossl::evp::Md;
use rustyssl_ossl::verify::{LookupKind, StoreCtx};

use crate::generated::options::crl::{OPTIONS, Opt};
use crate::lib::app_libctx::{libctx, opt_provider, propq};
use crate::lib::apps::{
    bio_open_default, get_nameopt, load_crl, load_key, print_name, set_dateopt, set_nameopt,
    setup_verify,
};
use crate::lib::io;
use crate::lib::opt::{self, Parser, eprintf, fmt_flags, format};

pub fn main(argv: &[String]) -> i32 {
    let ret = run(argv);
    if ret != 0 {
        io::print_errors();
    }
    ret
}

/// `-fingerprint`'s line: `<digest> Fingerprint=AA:BB:...`.
pub fn fingerprint_line(md: &Md, digest: &[u8]) -> String {
    let mut s = format!("{} Fingerprint=", md.name());
    for (j, b) in digest.iter().enumerate() {
        let sep = if j + 1 == digest.len() { '\n' } else { ':' };
        s.push_str(&format!("{b:02X}{sep}"));
    }
    s
}

fn run(argv: &[String]) -> i32 {
    let mut p = Parser::with_unknown(argv, OPTIONS, Some("digest"));
    let prog = p.prog();
    let (mut infile, mut outfile, mut crldiff, mut keyfile): (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = (None, None, None, None);
    let mut digestname: Option<String> = None;
    let (mut ca_file, mut ca_path, mut ca_store): (Option<String>, Option<String>, Option<String>) =
        (None, None, None);
    let (mut hash, mut issuer, mut lastupdate, mut nextupdate, mut noout) = (0, 0, 0, 0, false);
    let (mut informat, mut outformat, mut keyformat) = (format::UNDEF, format::PEM, format::UNDEF);
    let (mut num, mut badsig, mut fingerprint, mut crlnumber) = (0, false, 0, 0);
    let (mut text, mut do_ver) = (false, false);
    let (mut no_ca_file, mut no_ca_path, mut no_ca_store) = (false, false, false);
    let mut dateopt = core::ffi::c_ulong::try_from(ASN1_DTFLGS_RFC822).unwrap_or(0);
    let mut hash_old = 0;
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
            Opt::IN => infile = Some(p.arg().to_owned()),
            Opt::OUTFORM => match opt::parse_format(p.arg(), fmt_flags::PEMDER) {
                Some(f) => outformat = f,
                None => return opthelp(),
            },
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::KEYFORM => match opt::parse_format(p.arg(), fmt_flags::ANY) {
                Some(f) => keyformat = f,
                None => return opthelp(),
            },
            Opt::KEY => keyfile = Some(p.arg().to_owned()),
            Opt::GENDELTA => crldiff = Some(p.arg().to_owned()),
            Opt::CAPATH => {
                ca_path = Some(p.arg().to_owned());
                do_ver = true;
            }
            Opt::CAFILE => {
                ca_file = Some(p.arg().to_owned());
                do_ver = true;
            }
            Opt::CASTORE => {
                ca_store = Some(p.arg().to_owned());
                do_ver = true;
            }
            Opt::NOCAPATH => no_ca_path = true,
            Opt::NOCAFILE => no_ca_file = true,
            Opt::NOCASTORE => no_ca_store = true,
            Opt::HASH_OLD => {
                num += 1;
                hash_old = num;
            }
            Opt::VERIFY => do_ver = true,
            Opt::DATEOPT => {
                if !set_dateopt(&mut dateopt, p.arg()) {
                    return opthelp();
                }
            }
            Opt::TEXT => text = true,
            Opt::HASH => {
                num += 1;
                hash = num;
            }
            Opt::ISSUER => {
                num += 1;
                issuer = num;
            }
            Opt::LASTUPDATE => {
                num += 1;
                lastupdate = num;
            }
            Opt::NEXTUPDATE => {
                num += 1;
                nextupdate = num;
            }
            Opt::NOOUT => noout = true,
            Opt::FINGERPRINT => {
                num += 1;
                fingerprint = num;
            }
            Opt::CRLNUMBER => {
                num += 1;
                crlnumber = num;
            }
            Opt::BADSIG => badsig = true,
            Opt::NAMEOPT => {
                if !set_nameopt(Some(p.arg())) {
                    return opthelp();
                }
            }
            Opt::MD => digestname = p.unknown().map(str::to_owned),
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
    let digest = match &digestname {
        None => Md::sha1(),
        Some(n) => match opt::md(n) {
            Some(m) => Some(m),
            None => return opthelp(),
        },
    };
    let Some(digest) = digest else {
        return 1;
    };
    let Some(mut x) = load_crl(infile.as_deref(), informat, true, Some("CRL")) else {
        return 1;
    };

    if do_ver {
        let Some(store) = setup_verify(
            ca_file.as_deref(),
            no_ca_file,
            ca_path.as_deref(),
            no_ca_path,
            ca_store.as_deref(),
            no_ca_store,
        ) else {
            return 1;
        };
        if store.add_lookup(LookupKind::File).is_none() {
            return 1;
        }
        let ctx = StoreCtx::new();
        let Some(ctx) = ctx.filter(|c| c.init(&store, None, None)) else {
            eprintf!("Error initialising X509 store\n");
            return 1;
        };
        let Some(xobj) = ctx.get_cert_by_subject(x.issuer_name()) else {
            eprintf!("Error getting CRL issuer certificate\n");
            return 1;
        };
        let pkey = xobj.cert_pubkey();
        drop(xobj);
        let Some(pkey) = pkey else {
            eprintf!("Error getting CRL issuer public key\n");
            return 1;
        };
        let i = x.verify(&pkey);
        if i < 0 {
            return 1;
        }
        if i == 0 {
            eprintf!("verify failure\n");
            return 1;
        }
        eprintf!("verify OK\n");
    }

    if let Some(crldiff) = &crldiff {
        let Some(keyfile) = &keyfile else {
            eprintf!("Missing CRL signing key\n");
            return 1;
        };
        let Some(newcrl) = load_crl(Some(crldiff), informat, false, Some("other CRL")) else {
            return 1;
        };
        let Some(pkey) = load_key(
            Some(keyfile),
            keyformat,
            false,
            None,
            None,
            Some("CRL signing key"),
        ) else {
            return 1;
        };
        match x.diff(&newcrl, &pkey, &digest, 0) {
            Some(delta) => x = delta,
            None => {
                eprintf!("Error creating delta CRL\n");
                return 1;
            }
        }
    }

    if badsig {
        x.corrupt_signature();
    }

    let Some(bout) = io::bio_out() else {
        return 1;
    };
    let mut o = io::out();
    for i in 1..=num {
        if issuer == i {
            print_name(bout, Some("issuer="), x.issuer_name());
        }
        if crlnumber == i {
            let _ = o.write_all(b"crlNumber=");
            match x.ext_integer(NID_crl_number) {
                Some(n) => {
                    let _ = o.write_all(b"0x");
                    n.i2a(bout);
                }
                None => {
                    let _ = o.write_all(b"<NONE>");
                }
            }
            let _ = o.write_all(b"\n");
        }
        if hash == i {
            let lc = libctx();
            let pq = propq();
            let (h, ok) = x.issuer_name().hash_ex(lc.as_deref(), pq.as_deref());
            if num > 1 {
                let _ = o.write_all(b"issuer name hash=");
            }
            if ok {
                let _ = writeln!(o, "{h:08x}");
            } else {
                let _ = o.write_all(b"<ERROR>");
                return 1;
            }
        }
        if hash_old == i {
            if num > 1 {
                let _ = o.write_all(b"issuer name old hash=");
            }
            let _ = writeln!(o, "{:08x}", x.issuer_name().hash_old());
        }
        if lastupdate == i {
            let _ = o.write_all(b"lastUpdate=");
            if let Some(t) = x.last_update() {
                t.print_ex(bout, dateopt);
            }
            let _ = o.write_all(b"\n");
        }
        if nextupdate == i {
            let _ = o.write_all(b"nextUpdate=");
            match x.next_update() {
                Some(t) => {
                    t.print_ex(bout, dateopt);
                }
                None => {
                    let _ = o.write_all(b"NONE");
                }
            }
            let _ = o.write_all(b"\n");
        }
        if fingerprint == i {
            let Some(md) = x.digest(&digest) else {
                eprintf!("out of memory\n");
                return 1;
            };
            let _ = o.write_all(fingerprint_line(&digest, &md).as_bytes());
        }
    }

    let Some(out) = bio_open_default(outfile.as_deref(), 'w', outformat) else {
        return 1;
    };
    if text {
        x.print_ex(&out, get_nameopt());
    }
    if noout {
        return 0;
    }
    let i = if outformat == format::ASN1 {
        x.write_der(&out)
    } else {
        x.write_pem(&out)
    };
    if i == 0 {
        eprintf!("unable to write CRL\n");
        return 1;
    }
    0
}
