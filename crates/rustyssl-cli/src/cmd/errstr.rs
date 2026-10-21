//! `openssl errstr` (`apps/errstr.c`).

use std::io::Write;

use rustyssl_ossl::abi::{OPENSSL_INIT_LOAD_CRYPTO_STRINGS, OPENSSL_INIT_LOAD_SSL_STRINGS};
use rustyssl_ossl::{crypto, err};

use crate::generated::options::errstr::{OPTIONS, Opt};
use crate::lib::io;
use crate::lib::opt::{self, Parser, eprintf};

pub fn main(argv: &[String]) -> i32 {
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    // The only option is -help.
    match p.next() {
        Opt::EOF => {}
        Opt::ERR => {
            eprintf!("{prog}: Use -help for summary.\n");
            return 1;
        }
        Opt::HELP => {
            opt::help(OPTIONS);
            return 0;
        }
    }
    // Not an SSL application, but interested in libssl's error strings too.
    let _ = crypto::init_ssl(
        u64::try_from(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS)
            .unwrap_or(0),
    );
    let mut ret = 0;
    for arg in p.rest() {
        match scan_hex(arg) {
            Some(l) => {
                let _ = writeln!(io::out(), "{}", err::error_string_n(l));
            }
            None => ret += 1,
        }
    }
    ret
}

/// `sscanf(s, "%lx", &l)` as glibc does it: `None` when it converts nothing. Leading white
/// space, a sign (`-` negates, wrapping), and a `0x` prefix are allowed; trailing bytes are
/// ignored; a value too large for an `unsigned long` saturates, as `strtoul` does.
pub(crate) fn scan_hex(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    let mut i = 0;
    while b
        .get(i)
        .is_some_and(|c| c.is_ascii_whitespace() || *c == 0x0b)
    {
        i += 1;
    }
    let mut neg = false;
    if let Some(&c @ (b'+' | b'-')) = b.get(i) {
        neg = c == b'-';
        i += 1;
    }
    let mut digits = 0usize;
    if b.get(i) == Some(&b'0') && matches!(b.get(i + 1), Some(b'x' | b'X')) {
        // "0x" counts as the digit 0 even with no hex digit after it.
        i += 2;
        digits = 1;
    }
    let mut value: u64 = 0;
    let mut overflow = false;
    while let Some(d) = b.get(i).and_then(|c| char::from(*c).to_digit(16)) {
        match value
            .checked_mul(16)
            .and_then(|v| v.checked_add(u64::from(d)))
        {
            Some(v) => value = v,
            None => overflow = true,
        }
        digits += 1;
        i += 1;
    }
    if digits == 0 {
        return None;
    }
    if overflow {
        return Some(u64::MAX);
    }
    Some(if neg { value.wrapping_neg() } else { value })
}

#[cfg(test)]
mod tests {
    use super::scan_hex;

    #[test]
    fn scans_like_sscanf() {
        assert_eq!(scan_hex("1C80006B"), Some(0x1C80_006B));
        assert_eq!(scan_hex(" 0x10zz"), Some(0x10));
        assert_eq!(scan_hex("-1"), Some(u64::MAX));
        assert_eq!(scan_hex("zz"), None);
        assert_eq!(scan_hex(""), None);
        assert_eq!(scan_hex("11112222333344445555"), Some(u64::MAX));
    }
}
