//! `openssl spkac` (`apps/spkac.c`).

use rustyssl_ossl::x509::Spki;

use crate::generated::options::spkac::{OPTIONS, Opt};
use crate::lib::app_libctx::opt_provider;
use crate::lib::apps::{app_load_config, app_passwd, bio_open_default, load_key};
use crate::lib::engine::setup_engine;
use crate::lib::io;
use crate::lib::opt::{self, Parser, eprintf, fmt_flags, format};

pub fn main(argv: &[String]) -> i32 {
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let (mut infile, mut outfile, mut passinarg) = (None, None, None);
    let (mut keyfile, mut challenge): (Option<String>, Option<String>) = (None, None);
    let mut spkac = "SPKAC".to_owned();
    let mut spksect = "default".to_owned();
    let mut digest = "MD5".to_owned();
    let (mut verify, mut noout, mut pubkey) = (false, false, false);
    let mut keyformat = format::UNDEF;
    let mut e = None;
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
            Opt::IN => infile = Some(p.arg().to_owned()),
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::NOOUT => noout = true,
            Opt::PUBKEY => pubkey = true,
            Opt::VERIFY => verify = true,
            Opt::PASSIN => passinarg = Some(p.arg().to_owned()),
            Opt::KEY => keyfile = Some(p.arg().to_owned()),
            Opt::KEYFORM => match opt::parse_format(p.arg(), fmt_flags::ANY) {
                Some(f) => keyformat = f,
                None => return opthelp(),
            },
            Opt::CHALLENGE => challenge = Some(p.arg().to_owned()),
            Opt::SPKAC => spkac = p.arg().to_owned(),
            Opt::SPKSECT => spksect = p.arg().to_owned(),
            Opt::DIGEST => digest = p.arg().to_owned(),
            Opt::ENGINE => e = setup_engine(Some(p.arg()), false),
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
    let Some((passin, _)) = app_passwd(passinarg.as_deref(), None) else {
        eprintf!("Error getting password\n");
        return 1;
    };

    if let Some(keyfile) = keyfile {
        let Some(md) = opt::md(&digest) else {
            return 1;
        };
        let uri = (keyfile != "-").then_some(keyfile.as_str());
        let pass = passin.as_ref().map(|p| p.as_str());
        let Some(pkey) = load_key(uri, keyformat, true, pass, e.as_ref(), Some("private key"))
        else {
            return 1;
        };
        let Some(spki) = Spki::new() else {
            return 1;
        };
        if let Some(c) = &challenge
            && !spki.set_challenge(c.as_bytes())
        {
            return 1;
        }
        if !spki.set_pubkey(&pkey) {
            eprintf!("Error setting public key\n");
            return 1;
        }
        if spki.sign(&pkey, &md) <= 0 {
            eprintf!("Error signing SPKAC\n");
            return 1;
        }
        let Some(spkstr) = spki.b64_encode() else {
            return 1;
        };
        let Some(out) = bio_open_default(outfile.as_deref(), 'w', format::TEXT) else {
            return 1;
        };
        let _ = out.write_all(format!("SPKAC={spkstr}\n").as_bytes());
        return 0;
    }

    let Some(conf) = app_load_config(infile.as_deref()) else {
        return 1;
    };
    let Some(spkstr) = conf.get_string(Some(&spksect), &spkac) else {
        eprintf!("Can't find SPKAC called \"{spkac}\"\n");
        io::print_errors();
        return 1;
    };
    let Some(spki) = Spki::b64_decode(&spkstr) else {
        eprintf!("Error loading SPKAC\n");
        io::print_errors();
        return 1;
    };
    let Some(out) = bio_open_default(outfile.as_deref(), 'w', format::TEXT) else {
        return 1;
    };
    if !noout {
        spki.print(&out);
    }
    let pkey = spki.pubkey();
    if verify {
        if spki.verify(pkey.as_ref()) > 0 {
            eprintf!("Signature OK\n");
        } else {
            eprintf!("Signature Failure\n");
            io::print_errors();
            return 1;
        }
    }
    if pubkey && let Some(k) = &pkey {
        k.write_pubkey_pem(&out);
    }
    0
}
