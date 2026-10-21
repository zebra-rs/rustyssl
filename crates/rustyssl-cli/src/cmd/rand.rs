//! `openssl rand` (`apps/rand.c`).

use rustyssl_ossl::{Bio, rand};

use crate::generated::options::rand::{OPTIONS, Opt};
use crate::lib::apps::bio_open_default;
use crate::lib::engine::setup_engine;
use crate::lib::opt::{self, Parser, eprintf, format};
use crate::lib::{app_libctx, app_rand, io};

/// The largest chunk asked of the generator at once (2^16 bytes).
const BUFLEN: u64 = 1 << 16;

/// The most a request may ask for: 2^61 bytes, the limit per DRBG instantiation.
const MAX: u64 = u64::MAX >> 3;

/// The number of bytes `arg` asks for (`num[K|M|G|T]`, or `max`), with upstream's messages;
/// `None` means show the usage hint.
fn scaled(arg: &str) -> Option<u64> {
    if arg == "max" {
        return Some(MAX);
    }
    let mut digits = arg;
    let mut shift = 0;
    if let Some(i) = arg.bytes().position(|c| !c.is_ascii_digit()) {
        let suffix = arg.get(i..).unwrap_or_default();
        shift = match suffix.bytes().next() {
            Some(b'K') => 10,
            Some(b'M') => 20,
            Some(b'G') => 30,
            Some(b'T') => 40,
            _ => {
                eprintf!("Invalid size suffix {suffix}\n");
                return None;
            }
        };
        if suffix.len() != 1 {
            eprintf!("Invalid size suffix {suffix}\n");
            return None;
        }
        digits = arg.get(..i).unwrap_or_default();
    }
    let num = opt::long(digits)?;
    let num = u64::try_from(num).ok().filter(|n| *n > 0)?;
    if shift == 0 {
        return Some(num);
    }
    if (u64::MAX >> shift) < num {
        eprintf!("{num} bytes with suffix overflows\n");
        return None;
    }
    let n = num << shift;
    if n > MAX {
        eprintf!("Request exceeds max allowed output\n");
        return None;
    }
    Some(n)
}

pub fn main(argv: &[String]) -> i32 {
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let usage = || {
        eprintf!("{prog}: Use -help for summary.\n");
        1
    };
    let mut outfile = None;
    let mut fmt = format::BINARY;
    let mut _engine = None;
    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::ERR => return usage(),
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::OUT => outfile = Some(p.arg().to_owned()),
            Opt::ENGINE => _engine = setup_engine(Some(p.arg()), false),
            Opt::OPT_R(o) => {
                if !app_rand::opt_rand(o, p.arg()) {
                    return 1;
                }
            }
            Opt::BASE64 => fmt = format::BASE64,
            Opt::HEX => fmt = format::TEXT,
            Opt::OPT_PROV(o) => {
                if !app_libctx::opt_provider(o, p.arg()) {
                    return 1;
                }
            }
        }
    }
    let mut num = 0;
    match p.rest() {
        [arg] => match scaled(arg) {
            Some(n) => num = n,
            None => return usage(),
        },
        _ => {
            if !p.check_rest_arg(None) {
                return usage();
            }
        }
    }
    let ret = generate(outfile.as_deref(), fmt, num);
    if ret != 0 {
        io::print_errors();
    }
    ret
}

/// The output part, which prints the error queue when it fails.
fn generate(outfile: Option<&str>, fmt: i32, mut num: u64) -> i32 {
    if !app_rand::load() {
        return 1;
    }
    let Some(mut out) = bio_open_default(outfile, 'w', fmt) else {
        return 1;
    };
    if fmt == format::BASE64 {
        let Some(b64) = Bio::new_base64() else {
            return 1;
        };
        out = b64.push(out);
    }
    let libctx = app_libctx::libctx();
    let mut buf = vec![0u8; 1 << 16];
    while num > 0 {
        let chunk = usize::try_from(num.min(BUFLEN)).unwrap_or(0);
        let Some(b) = buf.get_mut(..chunk) else {
            return 1;
        };
        if rand::bytes_ex(libctx.as_deref(), b) <= 0 {
            return 1;
        }
        if fmt != format::TEXT {
            if usize::try_from(out.write(b)) != Ok(chunk) {
                return 1;
            }
        } else {
            let mut hex = String::with_capacity(chunk * 2);
            for byte in b.iter() {
                hex.push_str(&format!("{byte:02x}"));
            }
            if out.write_all(hex.as_bytes()).is_err() {
                return 1;
            }
        }
        num -= chunk as u64;
    }
    if fmt == format::TEXT && out.write_all(b"\n").is_err() {
        return 1;
    }
    if !out.flush() {
        return 1;
    }
    0
}
