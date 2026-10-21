//! `openssl genpkey` (`apps/genpkey.c`).
//!
//! Also `genpkey.c`'s [`mem_bio_to_file`], which `pkey`, `pkeyparam` and others share
//! (`init_gen_str`, `app_keygen` and `app_paramgen` are in `lib::keygen`).

use std::ffi::c_int;

use rustyssl_ossl::Bio;
use rustyssl_ossl::abi::{
    OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_STRING, OSSL_PARAM_REAL, OSSL_PARAM_UNSIGNED_INTEGER,
    OSSL_PARAM_UTF8_STRING,
};
use rustyssl_ossl::pkey::{Pkey, PkeyCtx};

use crate::generated::options::genpkey::{OPTIONS, Opt};
use crate::lib::apps::{
    ConfigFile, app_load_config_modules, app_passwd, bio_open_owner, pkey_ctrl_string, strerror,
};
use crate::lib::engine::Engine;
use crate::lib::keygen;
use crate::lib::opt::opt_cipher;
use crate::lib::opt::{self, Parser, eprintf, fmt_flags, format};
use crate::lib::{app_libctx, app_rand, engine, io};

/// `mem_bio_to_file`: what the memory `BIO` holds, to `filename`.
pub fn mem_bio_to_file(input: &Bio, filename: Option<&str>, fmt: i32, private: bool) -> bool {
    let data = input.read_to_end();
    let mut ret = false;
    if let Some(out) = bio_open_owner(filename, fmt, private) {
        let rv = out.write(&data);
        if usize::try_from(rv).ok() != Some(data.len()) {
            eprintf!(
                "Error writing to output file: '{}'\n",
                filename.unwrap_or("<NULL>")
            );
        } else {
            ret = true;
        }
    }
    if !ret {
        io::print_errors();
    }
    ret
}

/// `strerror(errno)`.
fn errno_text() -> String {
    strerror(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
}

/// `param_datatype_2name`: the type's name, and whether it is given in hex.
fn param_datatype_2name(t: u32) -> Option<(&'static str, bool)> {
    let t = c_int::try_from(t).ok()?;
    match t {
        OSSL_PARAM_INTEGER => Some(("int", false)),
        OSSL_PARAM_UNSIGNED_INTEGER => Some(("uint", false)),
        OSSL_PARAM_REAL => Some(("float", false)),
        OSSL_PARAM_OCTET_STRING => Some(("string", true)),
        OSSL_PARAM_UTF8_STRING => Some(("string", false)),
        _ => None,
    }
}

/// `show_gen_pkeyopt`.
fn show_gen_pkeyopt(algname: Option<&str>) {
    let Some(algname) = algname else {
        return;
    };
    let lc = app_libctx::libctx();
    let pq = app_libctx::propq();
    let Some(ctx) = PkeyCtx::from_name(lc.as_deref(), algname, pq.as_deref()) else {
        return;
    };
    if ctx.keygen_init() <= 0 {
        return;
    }
    let params = ctx.settable_params();
    if params.is_null() {
        return;
    }
    eprintf!("\nThe possible -pkeyopt arguments are:\n");
    for (key, t) in params.iter().map(|p| (p.key(), p.data_type())) {
        if let Some((name, ishex)) = param_datatype_2name(t) {
            eprintf!("    {}{key}:{name}\n", if ishex { "hex" } else { "" });
        }
    }
}

/// `init_keygen_file`.
fn init_keygen_file(pctx: &mut Option<PkeyCtx>, file: &str, e: Option<&Engine>) -> bool {
    if pctx.is_some() {
        eprintf!("Parameters already set!\n");
        return false;
    }
    let Some(pbio) = Bio::new_file(file, "r") else {
        eprintf!("Can't open parameter file {file}\n");
        return false;
    };
    let lc = app_libctx::libctx();
    let pq = app_libctx::propq();
    let pkey = Pkey::read_pem_params(&pbio, lc.as_deref(), pq.as_deref());
    drop(pbio);
    let Some(pkey) = pkey else {
        eprintf!("Error reading parameter file {file}\n");
        return false;
    };
    let ctx = if e.is_some() {
        PkeyCtx::new(&pkey, e)
    } else {
        PkeyCtx::from_pkey(lc.as_deref(), Some(&pkey), pq.as_deref())
    };
    match ctx {
        Some(c) if c.keygen_init() > 0 => {
            *pctx = Some(c);
            true
        }
        _ => {
            eprintf!("Error initializing context\n");
            io::print_errors();
            false
        }
    }
}

pub fn main(argv: &[String]) -> i32 {
    let mut p = Parser::with_unknown(argv, OPTIONS, Some("cipher"));
    let prog = p.prog();
    let usage = || {
        eprintf!("{prog}: Use -help for summary.\n");
        io::print_errors();
        1
    };
    let fail = || {
        io::print_errors();
        1
    };
    let mut verbose = true;
    let mut e = None;
    let (mut outfile, mut outpubkeyfile, mut passarg) = (None, None, None);
    let (mut ciphername, mut paramfile, mut algname): (
        Option<String>,
        Option<String>,
        Option<String>,
    ) = (None, None, None);
    let (mut outformat, mut text, mut do_param) = (format::PEM, false, false);
    let mut keyopt: Vec<String> = Vec::new();
    let mut _conf = None;
    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::ERR => return usage(),
            Opt::HELP => {
                opt::help(OPTIONS);
                show_gen_pkeyopt(algname.as_deref());
                return 0;
            }
            Opt::OUTFORM => match opt::parse_format(p.arg(), fmt_flags::PEMDER) {
                Some(f) => outformat = f,
                None => return usage(),
            },
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::OUTPUBKEY => outpubkeyfile = Some(p.arg().to_owned()),
            Opt::PASS => passarg = Some(p.arg().to_owned()),
            Opt::ENGINE => e = engine::setup_engine(Some(p.arg()), false),
            Opt::PARAMFILE => {
                if do_param {
                    return usage();
                }
                paramfile = Some(p.arg().to_owned());
            }
            Opt::ALGORITHM => algname = Some(p.arg().to_owned()),
            Opt::PKEYOPT => keyopt.push(p.arg().to_owned()),
            Opt::QUIET => verbose = false,
            Opt::VERBOSE => verbose = true,
            Opt::GENPARAM => do_param = true,
            Opt::TEXT => text = true,
            Opt::CIPHER => ciphername = p.unknown().map(str::to_owned),
            Opt::CONFIG => {
                _conf = app_load_config_modules(Some(&ConfigFile::Given(p.arg().to_owned())));
                if _conf.is_none() {
                    return fail();
                }
            }
            Opt::OPT_PROV(o) => {
                if !app_libctx::opt_provider(o, p.arg()) {
                    return fail();
                }
            }
            Opt::OPT_R(o) => {
                if !app_rand::opt_rand(o, p.arg()) {
                    return fail();
                }
            }
        }
    }
    if !p.check_rest_arg(None) {
        return usage();
    }
    if !app_rand::load() {
        return fail();
    }

    let mut ctx = None;
    if let Some(f) = &paramfile
        && !init_keygen_file(&mut ctx, f, e.as_ref())
    {
        return fail();
    }
    if let Some(a) = &algname
        && !keygen::init_gen_str(
            &mut ctx,
            a,
            e.as_ref(),
            do_param,
            app_libctx::libctx().as_deref(),
            app_libctx::propq().as_deref(),
        )
    {
        return fail();
    }
    let Some(ctx) = ctx else {
        return usage();
    };
    for o in &keyopt {
        if pkey_ctrl_string(ctx.borrow(), o) <= 0 {
            eprintf!("{prog}: Error setting {o} parameter:\n");
            io::print_errors();
            return fail();
        }
    }
    let Ok(cipher) = opt_cipher(ciphername.as_deref()) else {
        return usage();
    };
    if ciphername.is_some() && do_param {
        eprintf!("Cannot use cipher with -genparam option\n");
        return usage();
    }
    let private = !do_param;
    let Some((pass, _)) = app_passwd(passarg.as_deref(), None) else {
        eprintf!("Error getting password\n");
        return fail();
    };
    let Some(mem_out) = Bio::new_mem() else {
        return fail();
    };
    mem_out.set_mem_eof_return(0);
    let mem_outpubkey = match &outpubkeyfile {
        Some(_) => {
            let Some(m) = Bio::new_mem() else {
                return fail();
            };
            m.set_mem_eof_return(0);
            Some(m)
        }
        None => None,
    };
    if verbose {
        ctx.set_progress_cb();
    }
    if let Some(b) = io::bio_err() {
        ctx.set_app_bio(b);
    }
    let pkey = if do_param {
        keygen::app_paramgen(&ctx, algname.as_deref())
    } else {
        keygen::app_keygen(&ctx, algname.as_deref(), 0, false)
    };
    let Some(pkey) = pkey else {
        return fail();
    };
    let mut rv;
    if do_param {
        rv = pkey.write_pem_params(&mem_out);
    } else if outformat == format::PEM {
        rv = pkey.write_pem_private(
            &mem_out,
            cipher.as_ref(),
            pass.as_ref().map(|p| p.as_str()),
            false,
        );
        if let (true, Some(m)) = (rv > 0, &mem_outpubkey) {
            rv = pkey.write_pem_pubkey(m);
        }
    } else if outformat == format::ASN1 {
        rv = pkey.write_der_private(&mem_out);
        if let (true, Some(m)) = (rv > 0, &mem_outpubkey) {
            rv = pkey.write_der_pubkey(m);
        }
    } else {
        eprintf!("Bad format specified for key\n");
        return fail();
    }
    let mut ret = 0;
    if rv <= 0 {
        eprintf!("Error writing key(s)\n");
        ret = 1;
    }
    if text {
        let r = if do_param {
            pkey.print_params(&mem_out, 0)
        } else {
            pkey.print_private(&mem_out, 0)
        };
        if r <= 0 {
            eprintf!("Error printing key\n");
            ret = 1;
        }
    }
    if ret != 0 {
        io::print_errors();
        return ret;
    }
    if let Some(m) = &mem_outpubkey
        && !mem_bio_to_file(m, outpubkeyfile.as_deref(), outformat, private)
    {
        eprintf!(
            "Error writing to outpubkey: '{}'. Error: {}\n",
            outpubkeyfile.as_deref().unwrap_or("<NULL>"),
            errno_text()
        );
    }
    if !mem_bio_to_file(&mem_out, outfile.as_deref(), outformat, private) {
        eprintf!(
            "Error writing to outfile: '{}'. Error: {}\n",
            outfile.as_deref().unwrap_or("<NULL>"),
            errno_text()
        );
    }
    0
}
