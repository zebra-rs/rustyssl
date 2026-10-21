//! `openssl passwd` (`apps/passwd.c`): the MD5-based (`-1`, `-apr1`, `-aixmd5`) and SHA-based
//! (`-5`, `-6`) crypt(3) password hashes.

use std::io::Write;

use rustyssl_ossl::evp::Md;
use rustyssl_ossl::pkey::MdCtx;
use rustyssl_ossl::rand;

use crate::generated::options::passwd::{OPTIONS, Opt};
use crate::lib::apps::bio_open_default;
use crate::lib::opt::{self, Parser, eprintf, format};
use crate::lib::{app_libctx, app_rand, io};

/// `cov_2char` (from `crypto/des/fcrypt.c`): the crypt(3) base-64 alphabet.
const COV_2CHAR: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// The longest password hashed (longer ones are truncated, with a warning).
const PW_MAXLEN: usize = 256;

/// glibc's `BUFSIZ`, the buffer the rest of an over-long input line is read into.
const BUFSIZ: usize = 8192;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Unset,
    Md5,
    Apr1,
    Sha256,
    Sha512,
    AixMd5,
}

fn cov(b: u8) -> u8 {
    COV_2CHAR
        .get(usize::from(b & 0x3f))
        .copied()
        .unwrap_or(b'.')
}

/// A digest context the crypt functions update and finish; every step can fail.
struct Hash(MdCtx);

impl Hash {
    fn new() -> Option<Self> {
        MdCtx::new().map(Hash)
    }

    fn init(&self, md: &Md) -> Option<()> {
        self.0.borrow().digest_init(md, None).then_some(())
    }

    fn update(&self, data: &[u8]) -> Option<()> {
        self.0.borrow().update(data).then_some(())
    }

    fn finish(&self) -> Option<Vec<u8>> {
        self.0.borrow().finish()
    }
}

fn at(b: &[u8], i: usize) -> u8 {
    b.get(i).copied().unwrap_or(0)
}

/// `md5crypt`: magic `1` (BSD), `apr1` (Apache), or empty (AIX).
fn md5crypt(passwd: &[u8], magic: &str, salt: &[u8]) -> Option<String> {
    let md5 = Md::md5()?;
    // The salt is truncated to 8 characters.
    let salt = salt.get(..salt.len().min(8)).unwrap_or_default();
    let mut out: Vec<u8> = Vec::new();
    if !magic.is_empty() {
        if magic.len() > 4 {
            return None;
        }
        out.push(b'$');
        out.extend_from_slice(magic.as_bytes());
        out.push(b'$');
    }
    out.extend_from_slice(salt);
    if out.len() > 6 + 8 {
        return None;
    }

    let md = Hash::new()?;
    md.init(&md5)?;
    md.update(passwd)?;
    if !magic.is_empty() {
        md.update(b"$")?;
        md.update(magic.as_bytes())?;
        md.update(b"$")?;
    }
    md.update(salt)?;

    let md2 = Hash::new()?;
    md2.init(&md5)?;
    md2.update(passwd)?;
    md2.update(salt)?;
    md2.update(passwd)?;
    let mut buf = md2.finish()?;

    let mut i = passwd.len();
    while i > buf.len() {
        md.update(&buf)?;
        i -= buf.len();
    }
    md.update(buf.get(..i).unwrap_or_default())?;
    let mut n = passwd.len();
    while n != 0 {
        if n & 1 == 1 {
            md.update(b"\0")?;
        } else {
            md.update(passwd.get(..1).unwrap_or_default())?;
        }
        n >>= 1;
    }
    buf = md.finish()?;

    for i in 0..1000 {
        md2.init(&md5)?;
        md2.update(if i & 1 == 1 { passwd } else { &buf })?;
        if i % 3 != 0 {
            md2.update(salt)?;
        }
        if i % 7 != 0 {
            md2.update(passwd)?;
        }
        md2.update(if i & 1 == 1 { &buf } else { passwd })?;
        buf = md2.finish()?;
    }

    // The output permutation.
    let mut perm = [0u8; 16];
    let mut source = 0;
    for slot in perm.iter_mut().take(14) {
        *slot = at(&buf, source);
        source = (source + 6) % 17;
    }
    if let Some(tail) = perm.get_mut(14..) {
        tail.copy_from_slice(&[at(&buf, 5), at(&buf, 11)]);
    }
    out.push(b'$');
    for i in (0..15).step_by(3) {
        let (a, b, c) = (at(&perm, i), at(&perm, i + 1), at(&perm, i + 2));
        out.push(cov(c));
        out.push(cov(((b & 0xf) << 2) | (c >> 6)));
        out.push(cov(((a & 3) << 4) | (b >> 4)));
        out.push(cov(a >> 2));
    }
    out.push(cov(at(&perm, 15)));
    out.push(cov(at(&perm, 15) >> 6));
    String::from_utf8(out).ok()
}

/// The result of `strtoul(num, &endp, 10)`: the value (saturated), and what follows the
/// number (all of `num` when there are no digits).
fn strtoul10(num: &[u8]) -> (u64, &[u8]) {
    let mut i = 0;
    while num
        .get(i)
        .is_some_and(|c| matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r'))
    {
        i += 1;
    }
    let mut neg = false;
    if let Some(&c @ (b'+' | b'-')) = num.get(i) {
        neg = c == b'-';
        i += 1;
    }
    let start = i;
    let mut v: u64 = 0;
    let mut overflow = false;
    while let Some(d) = num.get(i).filter(|c| c.is_ascii_digit()) {
        match v
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(d - b'0')))
        {
            Some(n) => v = n,
            None => overflow = true,
        }
        i += 1;
    }
    if i == start {
        return (0, num);
    }
    let v = if overflow {
        u64::MAX
    } else if neg {
        v.wrapping_neg()
    } else {
        v
    };
    (v, num.get(i..).unwrap_or_default())
}

/// `shacrypt` (Ulrich Drepper's SHA-crypt): magic `5` (SHA-256) or `6` (SHA-512).
fn shacrypt(passwd: &[u8], magic: &str, salt: &[u8]) -> Option<String> {
    const ROUNDS_DEFAULT: u64 = 5000;
    const ROUNDS_MIN: u64 = 1000;
    const ROUNDS_MAX: u64 = 999_999_999;
    let (sha, buf_size) = match magic {
        "5" => (Md::sha256()?, 32),
        "6" => (Md::sha512()?, 64),
        _ => return None,
    };
    let mut salt = salt;
    let mut rounds = ROUNDS_DEFAULT;
    let mut rounds_custom = false;
    if let Some(num) = salt.strip_prefix(b"rounds=") {
        let (srounds, rest) = strtoul10(num);
        salt = rest.strip_prefix(b"$")?;
        rounds = srounds.clamp(ROUNDS_MIN, ROUNDS_MAX);
        rounds_custom = true;
    }
    // The salt is truncated to 16 characters.
    let salt = salt.get(..salt.len().min(16)).unwrap_or_default();
    let mut out: Vec<u8> = format!("${magic}$").into_bytes();
    if rounds_custom {
        out.extend_from_slice(format!("rounds={rounds}$").as_bytes());
    }
    out.extend_from_slice(salt);

    let md = Hash::new()?;
    md.init(&sha)?;
    md.update(passwd)?;
    md.update(salt)?;

    let md2 = Hash::new()?;
    md2.init(&sha)?;
    md2.update(passwd)?;
    md2.update(salt)?;
    md2.update(passwd)?;
    let mut buf = md2.finish()?;

    let mut n = passwd.len();
    while n > buf_size {
        md.update(&buf)?;
        n -= buf_size;
    }
    md.update(buf.get(..n).unwrap_or_default())?;
    let mut n = passwd.len();
    while n != 0 {
        md.update(if n & 1 == 1 { &buf } else { passwd })?;
        n >>= 1;
    }
    buf = md.finish()?;

    // The P sequence.
    md2.init(&sha)?;
    for _ in 0..passwd.len() {
        md2.update(passwd)?;
    }
    let temp = md2.finish()?;
    // OPENSSL_zalloc(0) fails, so an empty password has no hash.
    if passwd.is_empty() {
        return None;
    }
    let p_bytes: Vec<u8> = temp.iter().copied().cycle().take(passwd.len()).collect();

    // The S sequence.
    md2.init(&sha)?;
    for _ in 0..16 + usize::from(at(&buf, 0)) {
        md2.update(salt)?;
    }
    let temp = md2.finish()?;
    // As above, for an empty salt.
    if salt.is_empty() {
        return None;
    }
    let s_bytes: Vec<u8> = temp.iter().copied().cycle().take(salt.len()).collect();

    for n in 0..rounds {
        md2.init(&sha)?;
        md2.update(if n & 1 == 1 { &p_bytes } else { &buf })?;
        if n % 3 != 0 {
            md2.update(&s_bytes)?;
        }
        if n % 7 != 0 {
            md2.update(&p_bytes)?;
        }
        md2.update(if n & 1 == 1 { &buf } else { &p_bytes })?;
        buf = md2.finish()?;
    }

    out.push(b'$');
    let mut b64 = |b2: u8, b1: u8, b0: u8, n: usize| {
        let mut w = (u32::from(b2) << 16) | (u32::from(b1) << 8) | u32::from(b0);
        for _ in 0..n {
            out.push(cov(u8::try_from(w & 0x3f).unwrap_or(0)));
            w >>= 6;
        }
    };
    let b = |i| at(&buf, i);
    if magic == "5" {
        for &(x, y, z) in &[
            (0, 10, 20),
            (21, 1, 11),
            (12, 22, 2),
            (3, 13, 23),
            (24, 4, 14),
            (15, 25, 5),
            (6, 16, 26),
            (27, 7, 17),
            (18, 28, 8),
            (9, 19, 29),
        ] {
            b64(b(x), b(y), b(z), 4);
        }
        b64(0, b(31), b(30), 3);
    } else {
        for &(x, y, z) in &[
            (0, 21, 42),
            (22, 43, 1),
            (44, 2, 23),
            (3, 24, 45),
            (25, 46, 4),
            (47, 5, 26),
            (6, 27, 48),
            (28, 49, 7),
            (50, 8, 29),
            (9, 30, 51),
            (31, 52, 10),
            (53, 11, 32),
            (12, 33, 54),
            (34, 55, 13),
            (56, 14, 35),
            (15, 36, 57),
            (37, 58, 16),
            (59, 17, 38),
            (18, 39, 60),
            (40, 61, 19),
            (62, 20, 41),
        ] {
            b64(b(x), b(y), b(z), 4);
        }
        b64(0, 0, b(63), 2);
    }
    String::from_utf8(out).ok()
}

struct Settings {
    passed_salt: bool,
    quiet: bool,
    table: bool,
    reverse: bool,
    mode: Mode,
}

/// `do_passwd`: hashes one password (with a new random salt unless one was given) and prints
/// it; false if no salt could be made.
fn do_passwd(s: &Settings, salt: &mut Vec<u8>, passwd: &[u8]) -> bool {
    if !s.passed_salt {
        let saltlen = match s.mode {
            Mode::Sha256 | Mode::Sha512 => 16,
            _ => 8,
        };
        let mut raw = vec![0u8; saltlen];
        if rand::bytes(&mut raw) <= 0 {
            return false;
        }
        *salt = raw.into_iter().map(cov).collect();
    }
    let mut passwd = passwd;
    if passwd.len() > PW_MAXLEN {
        if !s.quiet {
            eprintf!("Warning: truncating password to {PW_MAXLEN} characters\n");
        }
        passwd = passwd.get(..PW_MAXLEN).unwrap_or_default();
    }
    let hash = match s.mode {
        Mode::Md5 => md5crypt(passwd, "1", salt),
        Mode::Apr1 => md5crypt(passwd, "apr1", salt),
        Mode::AixMd5 => md5crypt(passwd, "", salt),
        Mode::Sha256 => shacrypt(passwd, "5", salt),
        Mode::Sha512 => shacrypt(passwd, "6", salt),
        Mode::Unset => None,
    };
    // A failed hash prints as BIO_printf's NULL.
    let hash = hash.unwrap_or_else(|| "<NULL>".to_owned());
    let mut line = Vec::new();
    if s.table && !s.reverse {
        line.extend_from_slice(passwd);
        line.push(b'\t');
        line.extend_from_slice(hash.as_bytes());
    } else if s.table {
        line.extend_from_slice(hash.as_bytes());
        line.push(b'\t');
        line.extend_from_slice(passwd);
    } else {
        line.extend_from_slice(hash.as_bytes());
    }
    line.push(b'\n');
    let _ = io::out().write_all(&line);
    true
}

pub fn main(argv: &[String]) -> i32 {
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let usage = || {
        eprintf!("{prog}: Use -help for summary.\n");
        1
    };
    let mut infile = None;
    let (mut in_stdin, mut pw_source_defined, mut in_noverify) = (false, false, false);
    let mut s = Settings {
        passed_salt: false,
        quiet: false,
        table: false,
        reverse: false,
        mode: Mode::Unset,
    };
    let mut salt: Vec<u8> = Vec::new();
    loop {
        let mode = match p.next() {
            Opt::EOF => break,
            Opt::ERR => return usage(),
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::IN => {
                if pw_source_defined {
                    return usage();
                }
                infile = Some(p.arg().to_owned());
                pw_source_defined = true;
                continue;
            }
            Opt::NOVERIFY => {
                in_noverify = true;
                continue;
            }
            Opt::QUIET => {
                s.quiet = true;
                continue;
            }
            Opt::TABLE => {
                s.table = true;
                continue;
            }
            Opt::REVERSE => {
                s.reverse = true;
                continue;
            }
            Opt::SALT => {
                s.passed_salt = true;
                salt = p.arg().as_bytes().to_vec();
                continue;
            }
            Opt::STDIN => {
                if pw_source_defined {
                    return usage();
                }
                in_stdin = true;
                pw_source_defined = true;
                continue;
            }
            Opt::OPT_R(o) => {
                if !app_rand::opt_rand(o, p.arg()) {
                    return 1;
                }
                continue;
            }
            Opt::OPT_PROV(o) => {
                if !app_libctx::opt_provider(o, p.arg()) {
                    return 1;
                }
                continue;
            }
            Opt::_1 => Mode::Md5,
            Opt::_5 => Mode::Sha256,
            Opt::_6 => Mode::Sha512,
            Opt::APR1 => Mode::Apr1,
            Opt::AIXMD5 => Mode::AixMd5,
        };
        if s.mode != Mode::Unset {
            return usage();
        }
        s.mode = mode;
    }

    // The arguments left are the passwords.
    let passwds: Vec<Vec<u8>> = p.rest().iter().map(|a| a.as_bytes().to_vec()).collect();
    if !passwds.is_empty() {
        if pw_source_defined {
            return usage();
        }
        pw_source_defined = true;
    }
    let _ = pw_source_defined;
    if !app_rand::load() {
        return 1;
    }
    if s.mode == Mode::Unset {
        s.mode = Mode::Md5;
    }
    if infile.is_some() && in_stdin {
        eprintf!("{prog}: Can't combine -in and -stdin\n");
        return 1;
    }
    let input = if infile.is_some() || in_stdin {
        match bio_open_default(infile.as_deref(), 'r', format::TEXT) {
            Some(b) => Some(b),
            None => return 1,
        }
    } else {
        None
    };

    let Some(input) = input else {
        let passwds = if passwds.is_empty() {
            // No password given: prompt for one.
            let verify = !(s.passed_salt || in_noverify);
            let (r, pw) = rustyssl_ossl::evp::read_pw_string(PW_MAXLEN + 2, "Password: ", verify);
            if r != 0 {
                return 1;
            }
            vec![pw]
        } else {
            passwds
        };
        for pw in &passwds {
            if !do_passwd(&s, &mut salt, pw) {
                return 1;
            }
        }
        return 0;
    };

    loop {
        let (mut r, line) = input.gets(PW_MAXLEN + 1);
        if r > 0 {
            let passwd = match line.iter().position(|&b| b == b'\n') {
                Some(nl) => line.get(..nl).unwrap_or_default(),
                None => {
                    // The rest of the line is ignored.
                    loop {
                        let (r2, trash) = input.gets(BUFSIZ);
                        r = r2;
                        if r <= 0 || trash.contains(&b'\n') {
                            break;
                        }
                    }
                    &line
                }
            };
            if !do_passwd(&s, &mut salt, passwd) {
                return 1;
            }
        }
        if r <= 0 {
            return 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::strtoul10;

    #[test]
    fn strtoul_like_c() {
        assert_eq!(strtoul10(b"1500$x"), (1500, &b"$x"[..]));
        assert_eq!(strtoul10(b" 7$"), (7, &b"$"[..]));
        assert_eq!(strtoul10(b"$x"), (0, &b"$x"[..]));
        assert_eq!(strtoul10(b" $x"), (0, &b" $x"[..]));
        assert_eq!(strtoul10(b"-1$"), (u64::MAX, &b"$"[..]));
        assert_eq!(
            strtoul10(b"99999999999999999999999$"),
            (u64::MAX, &b"$"[..])
        );
    }
}
