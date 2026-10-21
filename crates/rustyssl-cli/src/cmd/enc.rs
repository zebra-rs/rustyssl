//! `openssl enc` (`apps/enc.c`), `base64`, and every cipher's name as a command
//! (`openssl aes-128-cbc`).

use std::io::Write;

use rustyssl_ossl::abi::{
    BIO_FLAGS_BASE64_NO_NL, EVP_CIPH_FLAG_AEAD_CIPHER, EVP_CIPH_FLAG_ENC_THEN_MAC,
    EVP_CIPH_WRAP_MODE, EVP_CIPH_XTS_MODE, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW,
    OBJ_NAME_TYPE_CIPHER_METH, OSSL_SKEYMGMT_SELECT_ALL, PKCS5_SALT_LEN,
};
use rustyssl_ossl::evp::{self, Cipher, Md, Skey, SkeyMgmt};
use rustyssl_ossl::{Bio, rand};

use crate::generated::options::enc::{OPTIONS, Opt};
use crate::lib::app_params::app_params_new_from_opts;
use crate::lib::apps::{app_passwd, bio_open_default};
use crate::lib::engine::{Engine, setup_engine};
use crate::lib::opt::{self, Parser, eprintf, format};
use crate::lib::{app_libctx, app_rand, io};

/// `SIZE`: the password buffer.
const SIZE: usize = 512;
/// `BSIZE`: the default I/O buffer size.
const BSIZE: i32 = 8 * 1024;
/// `PBKDF2_ITER_DEFAULT`.
const PBKDF2_ITER_DEFAULT: i32 = 10000;
/// The salted file's magic.
const MAGIC: &[u8; 8] = b"Salted__";
/// `sizeof(salt)` (`EVP_MAX_IV_LENGTH`).
const SALT_MAX: i32 = 16;

/// `show_ciphers`: one `-list` entry per usable cipher, three to a line.
fn show_ciphers(out: &mut String) {
    let mut n = 0;
    for name in evp::names_sorted(OBJ_NAME_TYPE_CIPHER_METH) {
        let name = name.name;
        if !name.bytes().next().is_some_and(|c| c.is_ascii_lowercase()) {
            continue;
        }
        // Not the ciphers that can't be used.
        let Some(c) = Cipher::by_name(&name) else {
            continue;
        };
        let has = |f: i32| u64::try_from(f).is_ok_and(|f| c.flags() & f != 0);
        if has(EVP_CIPH_FLAG_AEAD_CIPHER)
            || has(EVP_CIPH_FLAG_ENC_THEN_MAC)
            || c.mode() == EVP_CIPH_XTS_MODE
        {
            continue;
        }
        out.push_str(&format!("-{name:<25}"));
        n += 1;
        if n == 3 {
            out.push('\n');
            n = 0;
        } else {
            out.push(' ');
        }
    }
}

/// `set_hex`: `input`'s hex digits into the first `size` bytes of `out`, zero-padded, with
/// upstream's warnings; false on a non-hex digit.
fn set_hex(input: &str, out: &mut [u8], size: usize) -> bool {
    let i = size * 2;
    let mut n = input.len();
    if n > i {
        eprintf!("hex string is too long, ignoring excess\n");
        n = i;
    } else if n < i {
        eprintf!("hex string is too short, padding with zero bytes to length\n");
    }
    let Some(out) = out.get_mut(..size) else {
        return false;
    };
    out.fill(0);
    for (i, c) in input.bytes().take(n).enumerate() {
        let Some(j) = char::from(c).to_digit(16) else {
            eprintf!("non-hex digit\n");
            return false;
        };
        let j = u8::try_from(j).unwrap_or(0);
        if let Some(b) = out.get_mut(i / 2) {
            if i & 1 == 1 {
                *b |= j;
            } else {
                *b = j << 4;
            }
        }
    }
    true
}

/// `dup_bio_in`: standard input as a file `BIO` (whose end of file is seen as soon as a read
/// comes up short, which the unstreamable wrap ciphers rely on).
fn stdin_bio() -> Option<Bio> {
    let b = Bio::new_file_unset()?;
    b.set_fp_stdin().then_some(b)
}

/// Upper-case hex, as `printf("%02X")` prints each byte.
fn upper_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// A C `int` from a C `long` the way a cast truncates (the low 32 bits).
fn truncate_to_int(n: i64) -> i32 {
    let low = n.to_ne_bytes();
    let bytes = if cfg!(target_endian = "little") {
        [low[0], low[1], low[2], low[3]]
    } else {
        [low[4], low[5], low[6], low[7]]
    };
    i32::from_ne_bytes(bytes)
}

pub fn main(argv: &[String]) -> i32 {
    let ret = run(argv);
    // Upstream prints the error queue on every way out.
    io::print_errors();
    ret
}

fn run(argv: &[String]) -> i32 {
    let argv0 = argv.first().map_or("", String::as_str);
    let mut base64 = argv0 == "base64";
    let mut ciphername = (!base64 && argv0 != "enc").then(|| argv0.to_owned());

    let mut p = Parser::with_unknown(argv, OPTIONS, Some("cipher"));
    let prog = p.prog();
    let usage = || {
        eprintf!("{prog}: Use -help for summary.\n");
        1
    };
    let mut bsize = BSIZE;
    let (mut verbose, mut debug, mut olb64, mut nosalt, mut nopad) =
        (false, false, false, false, false);
    let mut enc = true;
    let mut printkey = 0;
    let mut saltlen = 0;
    let mut pbkdf2 = false;
    let mut iter = 0;
    let (mut infile, mut outfile, mut passarg) = (None, None, None);
    let mut str_: Option<Vec<u8>> = None;
    let (mut hkey, mut hiv, mut hsalt, mut digestname) = (None, None, None, None);
    let mut skeyopts: Option<Vec<String>> = None;
    let mut skeymgmt: Option<String> = None;
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
                let mut text = String::from("Supported ciphers:\n");
                show_ciphers(&mut text);
                text.push('\n');
                let _ = io::out().write_all(text.as_bytes());
                return 0;
            }
            Opt::E => enc = true,
            Opt::IN => infile = Some(p.arg().to_owned()),
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::PASS => passarg = Some(p.arg().to_owned()),
            Opt::ENGINE => e = setup_engine(Some(p.arg()), false),
            Opt::D => enc = false,
            Opt::P => printkey = 1,
            Opt::V => verbose = true,
            Opt::NOPAD => nopad = true,
            Opt::SALT => nosalt = false,
            Opt::NOSALT => nosalt = true,
            Opt::DEBUG => debug = true,
            Opt::UPPER_P => printkey = 2,
            Opt::UPPER_A => olb64 = true,
            Opt::A => base64 = true,
            Opt::Z => {} // no zlib in the default build
            Opt::BUFSIZE => {
                let arg = p.arg();
                let k = arg.len() >= 2 && arg.ends_with('k');
                let digits = if k {
                    arg.get(..arg.len() - 1).unwrap_or_default()
                } else {
                    arg
                };
                let Some(n) = opt::long(digits) else {
                    return usage();
                };
                if n < 0 || (k && n >= i64::MAX / 1024) {
                    return usage();
                }
                bsize = truncate_to_int(if k { n * 1024 } else { n });
            }
            Opt::K => str_ = Some(p.arg().as_bytes().to_vec()),
            Opt::KFILE => {
                let file = p.arg().to_owned();
                let Some(input) = bio_open_default(Some(&file), 'r', format::TEXT) else {
                    return usage();
                };
                let (got, mut buf) = input.gets_bytes(128);
                drop(input);
                if got <= 0 {
                    eprintf!("{prog} Can't read key from {file}\n");
                    return usage();
                }
                // Upstream's loop: it strips trailing CR and LF, and stops at index 1.
                let mut i = buf.len();
                loop {
                    i = i.saturating_sub(1);
                    if i == 0 || !matches!(buf.get(i), Some(b'\r' | b'\n')) {
                        break;
                    }
                    if let Some(b) = buf.get_mut(i) {
                        *b = 0;
                    }
                }
                if i == 0 {
                    eprintf!("{prog}: zero length password\n");
                    return usage();
                }
                let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                buf.truncate(end);
                str_ = Some(buf);
            }
            Opt::UPPER_K => hkey = Some(p.arg().to_owned()),
            Opt::UPPER_S => hsalt = Some(p.arg().to_owned()),
            Opt::IV => hiv = Some(p.arg().to_owned()),
            Opt::MD => digestname = Some(p.arg().to_owned()),
            Opt::CIPHER => ciphername = p.unknown().map(str::to_owned),
            Opt::ITER => {
                iter = p.int_arg();
                pbkdf2 = true;
            }
            Opt::SALTLEN => {
                let Some(n) = opt::int(p.arg()) else {
                    return usage();
                };
                saltlen = n.min(SALT_MAX);
            }
            Opt::PBKDF2 => {
                pbkdf2 = true;
                if iter == 0 {
                    // A chosen value stays.
                    iter = PBKDF2_ITER_DEFAULT;
                }
            }
            Opt::NONE => {} // the cipher is set after the options
            Opt::SKEYOPT => skeyopts
                .get_or_insert_with(Vec::new)
                .push(p.arg().to_owned()),
            Opt::SKEYMGMT => skeymgmt = Some(p.arg().to_owned()),
            Opt::OPT_R(o) => {
                if !app_rand::opt_rand(o, p.arg()) {
                    return 1;
                }
            }
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
    if !app_rand::load() {
        return 1;
    }
    if saltlen == 0 || !pbkdf2 {
        saltlen = PKCS5_SALT_LEN;
    }
    let saltlen = usize::try_from(saltlen).unwrap_or(0);

    let cipher = match &ciphername {
        Some(name) => match opt::cipher(name) {
            Some(c) => Some(c),
            None => return usage(),
        },
        None => None,
    };
    let wrap = cipher
        .as_ref()
        .is_some_and(|c| c.mode() == EVP_CIPH_WRAP_MODE);
    let streamable = !wrap;
    let dgst = match &digestname {
        Some(name) => match opt::md(name) {
            Some(m) => m,
            None => return usage(),
        },
        None => match Md::sha256() {
            Some(m) => m,
            None => return 1,
        },
    };
    if iter == 0 {
        iter = 1;
    }
    // Large enough for a base64 line.
    if base64 && bsize < 80 {
        bsize = 80;
    }
    if verbose {
        eprintf!("bufsize={bsize}\n");
    }
    let (mut informat, mut outformat) = (format::BINARY, format::BINARY);
    if base64 {
        if enc {
            outformat = format::BASE64;
        } else {
            informat = format::BASE64;
        }
    }

    let input = match infile.as_deref() {
        None => {
            // Printing the key and exiting is fine.
            if !streamable && printkey != 2 {
                eprintf!("Unstreamable cipher mode\n");
                return 1;
            }
            stdin_bio()
        }
        Some("-") => stdin_bio(),
        Some(f) => bio_open_default(Some(f), 'r', informat),
    };
    let Some(input) = input else {
        return 1;
    };

    if str_.is_none()
        && let Some(passarg) = &passarg
    {
        let Some((pass, _)) = app_passwd(Some(passarg), None) else {
            eprintf!("Error getting password\n");
            return 1;
        };
        str_ = pass.map(|p| p.as_str().as_bytes().to_vec());
    }

    if let Some(c) = &cipher
        && str_.is_none()
        && hkey.is_none()
        && skeyopts.is_none()
    {
        let prompt = format!(
            "enter {} {} password:",
            c.name().unwrap_or_default(),
            if enc { "encryption" } else { "decryption" }
        );
        let mut prompt = prompt;
        prompt.truncate(199);
        loop {
            let (i, pw) = evp::read_pw_string(SIZE, &prompt, enc);
            if i == 0 {
                if pw.is_empty() {
                    return 1;
                }
                str_ = Some(pw);
                break;
            }
            if i < 0 {
                eprintf!("bad password read\n");
                return 1;
            }
        }
    }

    let Some(out) = bio_open_default(outfile.as_deref(), 'w', outformat) else {
        return 1;
    };
    let bio_err = io::bio_err();
    if debug && let Some(b) = bio_err {
        input.set_debug_callback(b);
        out.set_debug_callback(b);
    }

    // The chains: rbio reads through base64 decoding, wbio writes through encryption and
    // base64 encoding.
    let mut rbio = input;
    let mut wbio = out;
    if base64 {
        let Some(b64) = Bio::new_base64() else {
            return 1;
        };
        if debug && let Some(b) = bio_err {
            b64.set_debug_callback(b);
        }
        if olb64 {
            b64.set_flags(BIO_FLAGS_BASE64_NO_NL);
        }
        if enc {
            wbio = b64.push(wbio);
        } else {
            rbio = b64.push(rbio);
        }
    }

    let mut benc = None;
    if let Some(cipher) = &cipher {
        let mut key = [0u8; 64];
        let mut iv = [0u8; 16];
        let mut salt = [0u8; 16];
        let mut rawkey_set = false;
        if let Some(pass) = &str_ {
            // A salt: when encrypting, a new one (unless given), written to the output;
            // when decrypting, the input's (unless given).
            let sptr = if nosalt {
                None
            } else {
                if let Some(h) = &hsalt
                    && !set_hex(h, &mut salt, saltlen)
                {
                    eprintf!("invalid hex salt value\n");
                    return 1;
                }
                let s = salt.get_mut(..saltlen).unwrap_or_default();
                if enc {
                    if hsalt.is_none() {
                        if rand::bytes(s) <= 0 {
                            eprintf!("RAND_bytes failed\n");
                            return 1;
                        }
                        // Not written with -P.
                        if printkey != 2
                            && (usize::try_from(wbio.write(MAGIC)) != Ok(MAGIC.len())
                                || usize::try_from(wbio.write(s)) != Ok(saltlen))
                        {
                            eprintf!("error writing output file\n");
                            return 1;
                        }
                    }
                } else if hsalt.is_none() {
                    let mut mbuf = [0u8; 8];
                    if usize::try_from(rbio.read(&mut mbuf)) != Ok(mbuf.len()) {
                        eprintf!("error reading input file\n");
                        return 1;
                    }
                    if &mbuf != MAGIC {
                        // Not salted, and no salt given.
                        eprintf!("bad magic number\n");
                        return 1;
                    }
                    if usize::try_from(rbio.read(s)) != Ok(saltlen) {
                        eprintf!("error reading input file\n");
                        return 1;
                    }
                }
                Some(salt)
            };
            if pbkdf2 {
                // The key and the default IV, derived together.
                let iklen = usize::try_from(cipher.key_length()).unwrap_or(0).min(64);
                let ivlen = usize::try_from(cipher.iv_length()).unwrap_or(0).min(16);
                let mut tmpkeyiv = [0u8; 80];
                let salt_used = sptr.as_ref().and_then(|s| s.get(..saltlen));
                if !evp::pbkdf2_hmac(
                    pass,
                    salt_used,
                    iter,
                    &dgst,
                    tmpkeyiv.get_mut(..iklen + ivlen).unwrap_or_default(),
                ) {
                    eprintf!("PKCS5_PBKDF2_HMAC failed\n");
                    return 1;
                }
                if let (Some(k), Some(t)) = (key.get_mut(..iklen), tmpkeyiv.get(..iklen)) {
                    k.copy_from_slice(t);
                }
                if let (Some(v), Some(t)) =
                    (iv.get_mut(..ivlen), tmpkeyiv.get(iklen..iklen + ivlen))
                {
                    v.copy_from_slice(t);
                }
                tmpkeyiv.fill(0);
            } else {
                eprintf!(
                    "*** WARNING : deprecated key derivation used.\n\
                     Using -iter or -pbkdf2 would be better.\n"
                );
                let salt8 = sptr.as_ref().and_then(|s| s.first_chunk::<8>());
                if cipher.bytes_to_key(&dgst, salt8, pass, 1, &mut key, &mut iv) == 0 {
                    eprintf!("EVP_BytesToKey failed\n");
                    return 1;
                }
            }
            rawkey_set = true;
        }
        if let Some(pw) = &mut str_ {
            pw.fill(0);
        }
        if let Some(h) = &hiv {
            let siz = usize::try_from(cipher.iv_length()).unwrap_or(0);
            if siz == 0 {
                eprintf!("warning: iv not used by this cipher\n");
            } else if !set_hex(h, &mut iv, siz.min(16)) {
                eprintf!("invalid hex iv value\n");
                return 1;
            }
        }
        if hiv.is_none() && str_.is_none() && cipher.iv_length() != 0 && !wrap {
            // No IV was set or derived: decryption would be impossible.
            eprintf!("iv undefined\n");
            return 1;
        }
        if let Some(h) = &hkey {
            let n = usize::try_from(cipher.key_length()).unwrap_or(0);
            if !set_hex(h, &mut key, n.min(64)) {
                eprintf!("invalid hex key value\n");
                return 1;
            }
            rawkey_set = true;
        }
        // A raw key or an opaque one, not both.
        if rawkey_set && skeyopts.is_some() {
            eprintf!("Either a raw key or the 'skeyopt' args must be used.\n");
            return 1;
        }
        let Some(b) = Bio::new_cipher() else {
            return 1;
        };
        // The parameters may change: work on the context rather than BIO_set_cipher().
        let Some(ctx) = b.cipher_ctx() else {
            return 1;
        };
        if wrap {
            ctx.set_flags(EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
        }
        let ivp = if hiv.is_none() && wrap {
            None
        } else {
            Some(&iv)
        };
        let cname = cipher.name().unwrap_or_default();
        if rawkey_set {
            if !ctx.init(cipher, e.as_ref(), &key, ivp, enc) {
                eprintf!("Error setting cipher {cname}\n");
                io::print_errors();
                return 1;
            }
        } else {
            let libctx = app_libctx::libctx();
            let propq = app_libctx::propq();
            let mgmt_name = skeymgmt.clone().unwrap_or_else(|| cname.clone());
            let Some(mgmt) = SkeyMgmt::fetch(libctx.as_deref(), &mgmt_name, propq.as_deref())
            else {
                return 1;
            };
            let Some(opts) = &skeyopts else {
                return 1;
            };
            let Some(params) = app_params_new_from_opts(opts, mgmt.imp_settable_params()) else {
                return 1;
            };
            let skey = Skey::import(
                libctx.as_deref(),
                &mgmt.name().unwrap_or_default(),
                propq.as_deref(),
                OSSL_SKEYMGMT_SELECT_ALL,
                &params,
            );
            drop(params);
            let Some(skey) = skey else {
                eprintf!("Error creating opaque key object for skeymgmt {mgmt_name}\n");
                io::print_errors();
                return 1;
            };
            let ivlen = usize::try_from(cipher.iv_length()).unwrap_or(0);
            if !ctx.init_skey(cipher, &skey, ivp, ivlen, enc) {
                eprintf!("Error setting an opaque key for cipher {cname}\n");
                io::print_errors();
                return 1;
            }
        }
        if nopad {
            ctx.set_padding(false);
        }
        if debug && let Some(be) = bio_err {
            b.set_debug_callback(be);
        }
        if printkey != 0 {
            let mut text = String::new();
            if !nosalt {
                text.push_str(&format!(
                    "salt={}\n",
                    upper_hex(salt.get(..saltlen).unwrap_or_default())
                ));
            }
            let klen = usize::try_from(cipher.key_length()).unwrap_or(0).min(64);
            if klen > 0 {
                text.push_str(&format!(
                    "key={}\n",
                    upper_hex(key.get(..klen).unwrap_or_default())
                ));
            }
            let ivlen = usize::try_from(cipher.iv_length()).unwrap_or(0).min(16);
            if ivlen > 0 {
                text.push_str(&format!(
                    "iv ={}\n",
                    upper_hex(iv.get(..ivlen).unwrap_or_default())
                ));
            }
            let _ = io::out().write_all(text.as_bytes());
            if printkey == 2 {
                return 0;
            }
        }
        key.fill(0);
        benc = Some(b);
    }

    // Encrypt or decrypt while writing.
    if let Some(b) = benc {
        wbio = b.push(wbio);
    }
    let mut buff = vec![0u8; usize::try_from(bsize).unwrap_or(0)];
    while rbio.pending() > 0 || !rbio.eof() {
        let inl = rbio.read(&mut buff);
        let Ok(n) = usize::try_from(inl) else {
            break;
        };
        if n == 0 {
            break;
        }
        if !streamable && !rbio.eof() {
            // No output.
            eprintf!("Unstreamable cipher mode\n");
            return 1;
        }
        if wbio.write(buff.get(..n).unwrap_or_default()) != inl {
            eprintf!("error writing output file\n");
            return 1;
        }
        if !streamable {
            break;
        }
    }
    if !wbio.flush() {
        eprintf!(
            "{}",
            if enc {
                "bad encrypt\n"
            } else {
                "bad decrypt\n"
            }
        );
        return 1;
    }
    if verbose {
        eprintf!("bytes read   : {:8}\n", rbio.bottom().number_read());
        eprintf!("bytes written: {:8}\n", wbio.bottom().number_written());
    }
    0
}
