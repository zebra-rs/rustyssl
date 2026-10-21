//! `openssl dgst` (`apps/dgst.c`), and every digest's name as a command (`openssl sha256`).

use std::io::Write;

use rustyssl_ossl::Bio;
use rustyssl_ossl::abi::{EVP_PKEY_HMAC, OBJ_NAME_TYPE_MD_METH, SN_sha256};
use rustyssl_ossl::evp::{self, Md, MdCtxRef};
use rustyssl_ossl::pkey::{MdCtx, Pkey};

use crate::generated::options::dgst::{OPTIONS, Opt};
use crate::lib::apps::{
    app_passwd, bio_open_default, bio_to_mem, load_key, load_pubkey, pkey_ctrl_string, strerror,
};
use crate::lib::engine::{Engine, setup_engine};
use crate::lib::keygen;
use crate::lib::opt::{self, Parser, eprintf, fmt_flags, format};
use crate::lib::{app_libctx, app_rand, io};

/// `BUFSIZE`: the I/O buffer.
const BUFSIZE: usize = 1024 * 8;

/// The key of the OpenSSL-FIPS fingerprint (`-fips-fingerprint`).
const FIPS_FINGERPRINT_KEY: &str = "etaonrishdlcupfm";

/// `show_digests`: one `-list` entry per usable digest, three to a line.
fn show_digests(out: &mut String, n: &mut i32) {
    let libctx = app_libctx::libctx();
    let propq = app_libctx::propq();
    for name in evp::names_sorted(OBJ_NAME_TYPE_MD_METH) {
        let name = name.name;
        // Not the signature algorithms.
        if name.contains("rsa") || name.contains("RSA") {
            continue;
        }
        if !name.bytes().next().is_some_and(|c| c.is_ascii_lowercase()) {
            continue;
        }
        // Not the digests that can't be used.
        let md = Md::fetch(libctx.as_deref(), &name, propq.as_deref());
        if md.is_none() && !evp::digest_exists(&name) {
            continue;
        }
        out.push_str(&format!("-{name:<25}"));
        *n += 1;
        if *n == 3 {
            out.push('\n');
            *n = 0;
        } else {
            out.push(' ');
        }
    }
}

struct Settings<'a> {
    sep: u8,
    binout: bool,
    xoflen: usize,
    key: Option<&'a Pkey>,
    sigin: Option<&'a [u8]>,
    sig_name: Option<&'a str>,
}

pub fn main(argv: &[String]) -> i32 {
    let ret = run(argv);
    if ret != 0 {
        io::print_errors();
    }
    ret
}

fn run(argv: &[String]) -> i32 {
    let argv0 = argv.first().map_or("", String::as_str);
    let mut md = evp::Md::by_name(argv0);
    let mut digestname = md.is_some().then(|| argv0.to_owned());

    let mut p = Parser::with_unknown(argv, OPTIONS, Some("digest"));
    let prog = p.prog();
    let usage = || {
        eprintf!("{prog}: Use -help for summary.\n");
        1
    };
    let mut separator = 0u8;
    let mut debug = false;
    let mut keyform = format::UNDEF;
    let mut out_bin: Option<bool> = None;
    let (mut want_pub, mut do_verify, mut engine_impl) = (false, false, false);
    let mut xoflen = 0;
    let mut outfile = None;
    let mut keyfile: Option<String> = None;
    let mut passinarg = None;
    let mut sigfile = None;
    let mut hmac_key: Option<String> = None;
    let mut mac_name: Option<String> = None;
    let mut sigopts: Vec<String> = Vec::new();
    let mut macopts: Vec<String> = Vec::new();
    let mut e: Option<Engine> = None;
    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::ERR => return usage(),
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::LIST => {
                let mut text = String::from("Supported digests:\n");
                let mut n = 0;
                show_digests(&mut text, &mut n);
                text.push('\n');
                let _ = io::out().write_all(text.as_bytes());
                return 0;
            }
            Opt::C => separator = 1,
            Opt::R => separator = 2,
            Opt::OPT_R(o) => {
                if !app_rand::opt_rand(o, p.arg()) {
                    return 1;
                }
            }
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::SIGN => keyfile = Some(p.arg().to_owned()),
            Opt::PASSIN => passinarg = Some(p.arg().to_owned()),
            Opt::VERIFY => {
                keyfile = Some(p.arg().to_owned());
                (want_pub, do_verify) = (true, true);
            }
            Opt::PRVERIFY => {
                keyfile = Some(p.arg().to_owned());
                do_verify = true;
            }
            Opt::SIGNATURE => sigfile = Some(p.arg().to_owned()),
            Opt::KEYFORM => match opt::parse_format(p.arg(), fmt_flags::ANY) {
                Some(f) => keyform = f,
                None => return usage(),
            },
            Opt::ENGINE => e = setup_engine(Some(p.arg()), false),
            Opt::ENGINE_IMPL => engine_impl = true,
            Opt::HEX => out_bin = Some(false),
            Opt::BINARY => out_bin = Some(true),
            Opt::XOFLEN => xoflen = crate::lib::apps::atoi(p.arg()),
            Opt::DEBUG => debug = true,
            Opt::FIPS_FINGERPRINT => hmac_key = Some(FIPS_FINGERPRINT_KEY.to_owned()),
            Opt::HMAC => hmac_key = Some(p.arg().to_owned()),
            Opt::MAC => mac_name = Some(p.arg().to_owned()),
            Opt::SIGOPT => sigopts.push(p.arg().to_owned()),
            Opt::MACOPT => macopts.push(p.arg().to_owned()),
            Opt::DIGEST => digestname = p.unknown().map(str::to_owned),
            Opt::OPT_PROV(o) => {
                if !app_libctx::opt_provider(o, p.arg()) {
                    return 1;
                }
            }
        }
    }

    let files = p.rest().to_vec();
    if keyfile.is_some() && files.len() > 1 {
        eprintf!("{prog}: Can only sign or verify one file.\n");
        return fail();
    }
    if !app_rand::load() {
        return fail();
    }
    if let Some(name) = &digestname {
        match opt::md(name) {
            Some(m) => md = Some(m),
            None => {
                usage();
                return fail();
            }
        }
    }
    if do_verify && sigfile.is_none() {
        eprintf!("No signature to verify: use the -signature option\n");
        return fail();
    }
    let impl_ = if engine_impl { e.as_ref() } else { None };

    let (Some(input), Some(bmd)) = (Bio::new_file_unset(), Bio::new_md()) else {
        return fail();
    };
    if debug && let Some(b) = io::bio_err() {
        input.set_debug_callback(b);
    }
    let Some((passin, _)) = app_passwd(passinarg.as_deref(), None) else {
        eprintf!("Error getting password\n");
        return fail();
    };
    let out_bin = out_bin.unwrap_or(keyfile.is_some());
    let fmt = if out_bin {
        format::BINARY
    } else {
        format::TEXT
    };
    let Some(out) = bio_open_default(outfile.as_deref(), 'w', fmt) else {
        return fail();
    };
    let given = [mac_name.is_some(), keyfile.is_some(), hmac_key.is_some()];
    if given.iter().filter(|g| **g).count() > 1 {
        eprintf!("MAC and signing key cannot both be specified\n");
        return fail();
    }

    let mut sigkey = None;
    let mut signctx = None;
    let mut oneshot_sign = false;
    if let Some(keyfile) = &keyfile {
        sigkey = if want_pub {
            load_pubkey(
                Some(keyfile),
                keyform,
                false,
                None,
                e.as_ref(),
                Some("public key"),
            )
        } else {
            load_key(
                Some(keyfile),
                keyform,
                false,
                passin.as_ref().map(|p| p.as_str()),
                e.as_ref(),
                Some("private key"),
            )
        };
        let Some(key) = &sigkey else {
            return fail();
        };
        let (r, def_md) = key.default_digest_name();
        if r == 2 && def_md == "UNDEF" {
            oneshot_sign = true;
        }
        signctx = MdCtx::new();
        if signctx.is_none() {
            return fail();
        }
    }

    if let Some(mac_name) = &mac_name {
        let mut mac_ctx = None;
        if !keygen::init_gen_str(&mut mac_ctx, mac_name, impl_, false, None, None) {
            return fail();
        }
        let Some(mac_ctx) = mac_ctx else {
            return fail();
        };
        for macopt in &macopts {
            if pkey_ctrl_string(mac_ctx.borrow(), macopt) <= 0 {
                drop(mac_ctx);
                eprintf!("MAC parameter error \"{macopt}\"\n");
                return fail();
            }
        }
        // Not verbose: the output would break gost-engine's external tests.
        sigkey = keygen::app_keygen(&mac_ctx, Some(mac_name), 0, false);
        drop(mac_ctx);
        if sigkey.is_none() {
            return fail();
        }
    }

    if let Some(hmac_key) = &hmac_key {
        if md.is_none() {
            md = Md::sha256();
            digestname = Some(SN_sha256.to_string_lossy().into_owned());
        }
        sigkey = Pkey::new_raw_private_key(EVP_PKEY_HMAC, impl_, hmac_key.as_bytes());
        if sigkey.is_none() {
            return fail();
        }
    }

    if let Some(key) = &sigkey {
        let mctx = if oneshot_sign {
            signctx.as_ref().map(MdCtx::borrow)
        } else {
            bmd.md_ctx()
        };
        let Some(mctx) = mctx else {
            eprintf!("Error getting context\n");
            return fail();
        };
        let (res, pctx) = match impl_ {
            None => {
                let libctx = app_libctx::libctx();
                let propq = app_libctx::propq();
                mctx.sign_verify_init_ex(
                    do_verify,
                    digestname.as_deref(),
                    libctx.as_deref(),
                    propq.as_deref(),
                    key,
                )
            }
            Some(eng) => mctx.sign_verify_init(do_verify, md.as_ref(), Some(eng), key),
        };
        if res == 0 {
            eprintf!("Error setting context\n");
            return fail();
        }
        for sigopt in &sigopts {
            if pkey_ctrl_string(pctx, sigopt) <= 0 {
                eprintf!("Signature parameter error \"{sigopt}\"\n");
                return fail();
            }
        }
    } else {
        // The digest BIO is the filter the input is read through.
        if oneshot_sign {
            eprintf!("Oneshot algorithms don't use a digest\n");
            return fail();
        }
        let Some(mctx) = bmd.md_ctx() else {
            eprintf!("Error getting context\n");
            return fail();
        };
        if md.is_none() {
            md = Md::sha256();
        }
        if !md.as_ref().is_some_and(|m| mctx.digest_init(m, impl_)) {
            eprintf!("Error setting digest\n");
            return fail();
        }
    }

    let mut sigbuf = None;
    if let (Some(sigfile), Some(key)) = (&sigfile, &sigkey) {
        let Some(sigbio) = Bio::new_file(sigfile, "rb") else {
            eprintf!("Error opening signature file {sigfile}\n");
            return fail();
        };
        let mut buf = vec![0u8; usize::try_from(key.size()).unwrap_or(0)];
        let n = sigbio.read(&mut buf);
        drop(sigbio);
        let Ok(n) = usize::try_from(n) else {
            eprintf!("Error reading signature file {sigfile}\n");
            return fail();
        };
        if n == 0 {
            eprintf!("Error reading signature file {sigfile}\n");
            return fail();
        }
        buf.truncate(n);
        sigbuf = Some(buf);
    }

    // The input: through the digest BIO, unless the algorithm signs in one shot.
    let mut md_name = None;
    let (chain, apart) = if oneshot_sign {
        (None, Some((input, bmd)))
    } else {
        let chain = bmd.push(input);
        if md.is_none() {
            md = chain.md_ctx().and_then(MdCtxRef::get1_md);
        }
        md_name = md.as_ref().and_then(Md::name);
        (Some(chain), None)
    };
    if xoflen > 0 {
        if !md.as_ref().is_some_and(Md::xof) {
            eprintf!("Length can only be specified for XOF\n");
            return fail();
        }
        // No algorithm signs with an XOF (their final steps call EVP_DigestFinal_ex).
        if sigkey.is_some() {
            eprintf!("Signing key cannot be specified for XOF\n");
            return fail();
        }
    }
    let xoflen = usize::try_from(xoflen).unwrap_or(0);

    let next;
    let (in_bio, bmd_bio): (&Bio, &Bio) = match (&chain, &apart) {
        (Some(c), _) => {
            let Some(n) = c.next_bio() else {
                return fail();
            };
            next = n;
            (&next, c)
        }
        (None, Some((i, b))) => (i, b),
        (None, None) => return fail(),
    };
    let signctx_ref = signctx.as_ref().map(MdCtx::borrow);
    let mut s = Settings {
        sep: separator,
        binout: out_bin,
        xoflen,
        key: sigkey.as_ref(),
        sigin: sigbuf.as_deref(),
        sig_name: None,
    };
    if files.is_empty() {
        if !in_bio.set_fp_stdin() {
            return fail();
        }
        match signctx_ref.filter(|_| oneshot_sign) {
            Some(ctx) => do_fp_oneshot_sign(&out, ctx, in_bio, &s, "stdin"),
            None => do_fp(&out, bmd_bio, &s, md_name.as_deref(), "stdin"),
        }
    } else {
        let sig_name = if out_bin {
            None
        } else {
            sigkey.as_ref().and_then(Pkey::type_name)
        };
        s.sig_name = sig_name.as_deref();
        let mut ret = 0;
        for file in &files {
            if in_bio.read_filename(file) <= 0 {
                let reason = strerror(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
                eprintf!("{file}: {reason}\n");
                ret = 1;
                continue;
            }
            let r = match signctx_ref.filter(|_| oneshot_sign) {
                Some(ctx) => do_fp_oneshot_sign(&out, ctx, in_bio, &s, file),
                None => do_fp(&out, bmd_bio, &s, md_name.as_deref(), file),
            };
            if r != 0 {
                ret = 1;
            }
            bmd_bio.reset();
        }
        ret
    }
}

/// The failure exit (the error queue is printed on the way out).
fn fail() -> i32 {
    1
}

/// `newline_escape_filename`: each newline as `\n`, and whether there was one.
fn newline_escape_filename(file: &str) -> (String, bool) {
    (file.replace('\n', "\\n"), file.contains('\n'))
}

/// `print_out`.
fn print_out(out: &Bio, buf: &[u8], s: &Settings<'_>, md_name: Option<&str>, file: &str) {
    if s.binout {
        out.write(buf);
        return;
    }
    let mut text = String::new();
    if s.sep == 2 {
        let (file, backslash) = newline_escape_filename(file);
        if backslash {
            text.push('\\');
        }
        for b in buf {
            text.push_str(&format!("{b:02x}"));
        }
        text.push_str(&format!(" *{file}\n"));
    } else {
        if let Some(sig_name) = s.sig_name {
            text.push_str(sig_name);
            if let Some(md_name) = md_name {
                text.push_str(&format!("-{md_name}"));
            }
            text.push_str(&format!("({file})= "));
        } else if let Some(md_name) = md_name {
            text.push_str(&format!("{md_name}({file})= "));
        } else {
            text.push_str(&format!("({file})= "));
        }
        for (i, b) in buf.iter().enumerate() {
            if s.sep != 0 && i != 0 {
                text.push(':');
            }
            text.push_str(&format!("{b:02x}"));
        }
        text.push('\n');
    }
    let _ = out.write_all(text.as_bytes());
}

/// `print_verify_result`.
fn print_verify_result(out: &Bio, i: i32) {
    if i > 0 {
        let _ = out.write_all(b"Verified OK\n");
    } else if i == 0 {
        let _ = out.write_all(b"Verification failure\n");
    } else {
        eprintf!("Error verifying data\n");
    }
}

/// `do_fp`: reads `bp` (the digest BIO and its input) to the end, then prints the digest,
/// signature, or verification result. Returns the exit status.
fn do_fp(out: &Bio, bp: &Bio, s: &Settings<'_>, md_name: Option<&str>, file: &str) -> i32 {
    let mut buf = vec![0u8; BUFSIZE];
    while bp.pending() > 0 || !bp.eof() {
        let i = bp.read(&mut buf);
        if i < 0 {
            eprintf!("Read error in {file}\n");
            return 1;
        }
        if i == 0 {
            break;
        }
    }
    let Some(ctx) = bp.md_ctx() else {
        return 1;
    };
    if let Some(sigin) = s.sigin {
        let i = ctx.verify_final(sigin);
        print_verify_result(out, i);
        return if i > 0 { 0 } else { 1 };
    }
    let result = if s.key.is_some() {
        let Some(tmplen) = ctx.sign_final_len() else {
            eprintf!("Error getting maximum length of signed data\n");
            return 1;
        };
        let mut sig = vec![0u8; tmplen.max(BUFSIZE)];
        let Some(len) = ctx.sign_final(&mut sig) else {
            eprintf!("Error signing data\n");
            return 1;
        };
        sig.truncate(len);
        sig
    } else if s.xoflen > 0 {
        let mut d = vec![0u8; s.xoflen];
        if !ctx.final_xof(&mut d) {
            eprintf!("Error Digesting Data\n");
            return 1;
        }
        d
    } else {
        let (r, d) = bp.gets_bytes(BUFSIZE);
        if r < 0 {
            return 1;
        }
        d
    };
    print_out(out, &result, s, md_name, file);
    0
}

/// `do_fp_oneshot_sign`: for algorithms that sign only in one shot, the whole input (at
/// most 16 MiB) at once.
fn do_fp_oneshot_sign(
    out: &Bio,
    ctx: MdCtxRef<'_>,
    input: &Bio,
    s: &Settings<'_>,
    file: &str,
) -> i32 {
    let Some(data) = bio_to_mem(16 * 1024 * 1024, input) else {
        eprintf!("Read error in {file}\n");
        return 1;
    };
    if let Some(sigin) = s.sigin {
        let res = ctx.verify_oneshot(sigin, &data);
        print_verify_result(out, res);
        return if res > 0 { 0 } else { 1 };
    }
    if s.key.is_none() {
        eprintf!("key must be set for one-shot algorithms\n");
        return 1;
    }
    let Some(len) = ctx.sign_oneshot_len(&data) else {
        eprintf!("Error getting maximum length of signed data\n");
        return 1;
    };
    let mut sig = vec![0u8; len];
    let Some(len) = ctx.sign_oneshot(&mut sig, &data) else {
        eprintf!("Error signing data\n");
        return 1;
    };
    sig.truncate(len);
    print_out(out, &sig, s, None, file);
    0
}
