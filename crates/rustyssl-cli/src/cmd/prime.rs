//! `openssl prime` (`apps/prime.c`).

use std::io::Write;

use rustyssl_ossl::bn::Bn;

use crate::generated::options::prime::{OPTIONS, Opt};
use crate::lib::apps::{atoi, bio_open_default_quiet};
use crate::lib::opt::{self, Parser, eprintf};
use crate::lib::{app_libctx, io};

/// `BUFSIZE`: consistent with the RSA modulus size limit and plausible primes.
const BUFSIZE: usize = 4098;

/// `check_num`: only (hex) digits.
fn check_num(s: &str, hex: bool) -> bool {
    s.bytes().all(|c| {
        if hex {
            c.is_ascii_hexdigit()
        } else {
            c.is_ascii_digit()
        }
    })
}

/// `process_num`.
fn process_num(s: &str, hex: bool) {
    let bn = if !check_num(s, hex) {
        None
    } else if hex {
        Bn::from_hex(s)
    } else {
        Bn::from_dec(s)
    };
    let Some(bn) = bn else {
        eprintf!("Failed to process value ({s})\n");
        return;
    };
    let Some(out) = io::bio_out() else {
        return;
    };
    bn.print(out);
    let r = bn.check_prime();
    drop(bn);
    if r < 0 {
        eprintf!("Error checking prime\n");
        return;
    }
    let verdict = if r == 1 { "is" } else { "is not" };
    let _ = writeln!(io::out(), " ({s}) {verdict} prime");
}

pub fn main(argv: &[String]) -> i32 {
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let usage = || {
        eprintf!("{prog}: Use -help for summary.\n");
        1
    };
    let (mut hex, mut generate, mut safe, mut in_file) = (false, false, false, false);
    let mut bits = 0;
    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::ERR => return usage(),
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::HEX => hex = true,
            Opt::GENERATE => generate = true,
            Opt::BITS => bits = atoi(p.arg()),
            Opt::SAFE => safe = true,
            Opt::CHECKS => {} // the value is ignored
            Opt::OPT_PROV(o) => {
                if !app_libctx::opt_provider(o, p.arg()) {
                    return 1;
                }
            }
            Opt::IN_FILE => in_file = true,
        }
    }
    if generate && !p.check_rest_arg(None) {
        return usage();
    }
    let rest = p.rest().to_vec();
    if !generate && rest.is_empty() {
        eprintf!("Missing number (s) to check\n");
        return usage();
    }
    if generate {
        if bits == 0 {
            eprintf!("Specify the number of bits.\n");
            return 1;
        }
        let Some(bn) = Bn::new() else {
            eprintf!("Out of memory.\n");
            return 1;
        };
        if !bn.generate_prime(bits, safe) {
            eprintf!("Failed to generate prime.\n");
            return 1;
        }
        let Some(s) = (if hex { bn.to_hex() } else { bn.to_dec() }) else {
            eprintf!("Out of memory.\n");
            return 1;
        };
        let _ = writeln!(io::out(), "{s}");
        return 0;
    }
    for arg in &rest {
        if !in_file {
            process_num(arg, hex);
            continue;
        }
        let Some(input) = bio_open_default_quiet(Some(arg), 'r', 0) else {
            eprintf!("Error opening file {arg}\n");
            continue;
        };
        let bytes_read = loop {
            let (n, line) = input.get_line(BUFSIZE);
            if n <= 0 {
                break n;
            }
            // Too long: discard the rest of the line.
            if line.len() == BUFSIZE - 1 && line.get(BUFSIZE - 2) != Some(&b'\n') {
                eprintf!(
                    "Value in {arg} is over the maximum size ({} digits)\n",
                    BUFSIZE - 2
                );
                while usize::try_from(input.get_line(BUFSIZE).0) == Ok(BUFSIZE - 1) {}
                continue;
            }
            let valid = line.iter().take_while(|c| c.is_ascii_hexdigit()).count();
            let digits = std::str::from_utf8(line.get(..valid).unwrap_or_default()).unwrap_or("");
            process_num(digits, hex);
        };
        if bytes_read < 0 {
            eprintf!("Read error in {arg}\n");
        }
    }
    0
}
