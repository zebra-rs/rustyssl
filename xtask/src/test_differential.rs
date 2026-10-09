//! `cargo xtask test-differential [--random N] [--seed S]`: differential testing
//! (TEST_PLAN.md, layer L5).
//!
//! The probe (`tests/differential/probe.c`) reads commands on stdin and prints what the library
//! did. It is compiled once and linked against the reference OpenSSL, then fed the same input on
//! the reference and on rustyssl, and the outputs must match line for line. Unlike the C
//! conformance tests, nothing states the expected result: the reference is the oracle.
//!
//! Inputs are the files in `tests/differential/corpus/` plus `N` (default 200) random command
//! sessions. The random seed is printed, and `--seed` replays a run.

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::test_c::{compile, execute_with_input, prepare};
use crate::util::{Result, fresh_dir, target_dir, workspace_root};

pub fn run(args: &[String]) -> Result {
    let (sessions, seed) = parse_args(args)?;
    let root = workspace_root();
    let (reference, dist) = prepare(&root)?;
    let work = target_dir(&root).join("xtask/test-differential");
    fresh_dir(&work)?;
    let probe = work.join("probe");
    compile(
        &root.join("tests/differential/probe.c"),
        &probe,
        &dist,
        &reference,
    )?;

    let mut inputs: Vec<PathBuf> = fs::read_dir(root.join("tests/differential/corpus"))?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<std::io::Result<_>>()?;
    inputs.sort();
    let random = work.join(format!("random-seed-{seed}.txt"));
    fs::write(&random, random_sessions(seed, sessions)?)?;
    inputs.push(random);
    println!("Random sessions: {sessions}, seed {seed} (replay with --seed {seed})");

    let mut failures = 0;
    for input in &inputs {
        let theirs = execute_with_input(&probe, &reference.join("lib"), &work, Some(input))?;
        let ours = execute_with_input(&probe, &dist.join("lib"), &work, Some(input))?;
        let name = input
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        let lines = theirs.stdout.lines().count();
        if !theirs.success {
            failures += 1;
            println!(
                "FAIL {name}: the reference probe exits with {}",
                theirs.status
            );
        } else if ours.stdout == theirs.stdout && ours.success {
            println!("PASS {name}: {lines} lines identical");
        } else {
            failures += 1;
            let mismatch = ours
                .stdout
                .lines()
                .zip(theirs.stdout.lines())
                .enumerate()
                .find(|(_, (a, b))| a != b);
            match mismatch {
                Some((i, (a, b))) => println!(
                    "FAIL {name}: line {}: reference `{b}`, rustyssl `{a}`",
                    i + 1
                ),
                None => println!(
                    "FAIL {name}: rustyssl stopped after {} of {lines} lines ({}): {}",
                    ours.stdout.lines().count(),
                    ours.status,
                    ours.stderr.trim()
                ),
            }
        }
    }
    if failures == 0 {
        Ok(())
    } else {
        Err(format!("{failures} differential input(s) differ").into())
    }
}

fn parse_args(args: &[String]) -> Result<(usize, u64)> {
    let mut sessions = 200;
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |d| d.as_secs());
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let value = args.next().ok_or_else(|| format!("{arg} needs a value"))?;
        match arg.as_str() {
            "--random" => sessions = value.parse()?,
            "--seed" => seed = value.parse()?,
            _ => {
                return Err("usage: cargo xtask test-differential [--random N] [--seed S]".into());
            }
        }
    }
    Ok((sessions, seed))
}

/// A small deterministic generator (xorshift64*), so a seed always replays the same input.
struct Random(u64);

impl Random {
    /// Mixes the seed (SplitMix64), so nearby seeds start far apart and the state is never
    /// the zero that xorshift can't leave.
    fn new(seed: u64) -> Self {
        let mut z = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        Self((z ^ (z >> 31)).max(1))
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A number in `0..bound`.
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound.max(1)
    }

    /// A number in `low..low + span`.
    fn offset(&mut self, low: i64, span: u64) -> i64 {
        low.saturating_add(i64::try_from(self.below(span)).unwrap_or(0))
    }

    /// One of `items`.
    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        let i = self.below(u64::try_from(items.len()).unwrap_or(1));
        let i = usize::try_from(i).unwrap_or(0);
        items.get(i).copied().unwrap_or_default()
    }
}

/// Random command sessions in the probe's language, for `BUF_MEM` and the error queue.
fn random_sessions(seed: u64, count: usize) -> Result<String> {
    let mut random = Random::new(seed);
    let mut out = String::new();
    for session in 0..count {
        writeln!(out, "# session {session}")?;
        match random.below(8) {
            0 => err_session(&mut random, &mut out)?,
            1 => buf_mem_session(&mut random, &mut out)?,
            2 => stack_session(&mut random, &mut out)?,
            3 => lhash_session(&mut random, &mut out)?,
            4 => bio_session(&mut random, &mut out)?,
            5 => printf_session(&mut random, &mut out)?,
            6 => addr_session(&mut random, &mut out)?,
            _ => string_session(&mut random, &mut out)?,
        }
    }
    Ok(out)
}

/// A random session of `printf` and `bioprintf` commands.
fn printf_session(random: &mut Random, out: &mut String) -> Result {
    for _ in 0..1 + random.below(20) {
        let (format, args) = printf_format(random);
        let args: String = args.iter().map(|a| format!(" {a}")).collect();
        if random.below(4) == 0 {
            writeln!(out, "bioprintf {format}{args}")?;
        } else {
            let n = random.pick(&["0", "1", "2", "3", "8", "16", "40", "100"]);
            writeln!(out, "printf {n} {format}{args}")?;
        }
    }
    Ok(())
}

/// A random format of up to four conversions, with typed arguments for what they consume (at
/// most the probe's three). `_` is a space. The arguments follow OpenSSL's parsing exactly, or
/// a conversion would read an argument of the wrong type.
fn printf_format(random: &mut Random) -> (String, Vec<String>) {
    let mut format = String::new();
    let mut args = Vec::new();
    for _ in 0..1 + random.below(4) {
        if random.below(2) == 0 {
            let text = random_text(random, b"ab_-.:", 4);
            format.push_str(if text == "-" { "" } else { &text });
        }
        let mut spec = String::from("%");
        let mut needed = Vec::new();
        for flag in ['-', '+', '_', '#', '0'] {
            if random.below(5) == 0 {
                spec.push(flag);
            }
        }
        match random.below(5) {
            0 | 1 => {}
            2 => spec.push_str(&random.below(25).to_string()),
            3 => spec.push_str(&random.below(120).to_string()),
            _ => {
                spec.push('*');
                needed.push(format!("i:{}", random.offset(-10, 40)));
            }
        }
        match random.below(5) {
            0 | 1 => {}
            2 => spec.push('.'),
            3 => spec.push_str(&format!(".{}", random.below(15))),
            _ => {
                spec.push_str(".*");
                needed.push(format!("i:{}", random.offset(-5, 20)));
            }
        }
        let modifier = random.pick(&["", "", "", "", "h", "l", "ll", "z", "j", "q", "L", "hh"]);
        spec.push_str(modifier);
        let mut conversion = random.pick(&[
            "d", "i", "u", "x", "X", "o", "c", "s", "s", "p", "f", "f", "e", "E", "g", "G", "%",
            "k", "w",
        ]);
        if modifier == "hh" && conversion == "%" {
            // After `%hh` the conversion character is text; a `%` would start a conversion.
            conversion = "d";
        }
        spec.push_str(conversion);
        let wide = ["l", "ll", "z", "j", "q"].contains(&modifier);
        // `%hh` is `%h` and the unknown conversion `h`: the conversion character is just text.
        let argument = if modifier == "hh" {
            None
        } else {
            match conversion {
                "d" | "i" | "u" | "x" | "X" | "o" if wide => Some(printf_long(random)),
                "d" | "i" | "u" | "x" | "X" | "o" => Some(printf_int(random)),
                "c" => Some(format!("i:{}", random.below(128))),
                "s" => Some(format!(
                    "s:{}",
                    random.pick(&["-", "x", "hello", "abcdefghijklmnopqrstuvwxyz0123456789"])
                )),
                "p" => Some(printf_long(random)),
                "f" | "e" | "E" | "g" | "G" => Some(printf_double(random)),
                _ => None,
            }
        };
        needed.extend(argument);
        if args.len() + needed.len() > 3 {
            break;
        }
        format.push_str(&spec);
        if conversion == "w" {
            // `%w` skips the next character; make it text, not the next conversion's `%`.
            format.push('x');
        }
        args.extend(needed);
    }
    if format.is_empty() {
        format.push('-');
    }
    (format, args)
}

fn printf_int(random: &mut Random) -> String {
    let value = match random.below(4) {
        0 => random
            .pick(&[
                "0",
                "1",
                "-1",
                "255",
                "65535",
                "70000",
                "-2147483648",
                "2147483647",
            ])
            .to_owned(),
        _ => random.offset(-100_000, 200_000).to_string(),
    };
    format!("i:{value}")
}

fn printf_long(random: &mut Random) -> String {
    let value = match random.below(3) {
        0 => random
            .pick(&[
                "0",
                "-1",
                "-9223372036854775808",
                "9223372036854775807",
                "4294967296",
            ])
            .to_owned(),
        1 => random.next().cast_signed().to_string(),
        _ => random.offset(-1_000_000, 2_000_000).to_string(),
    };
    format!("j:{value}")
}

fn printf_double(random: &mut Random) -> String {
    let value = match random.below(4) {
        0 => random
            .pick(&[
                "0",
                "-0",
                "1.5",
                "2.675",
                "10",
                "1e-5",
                "0.0001",
                "100000",
                "1e19",
                "1e20",
                "inf",
                "-inf",
                "nan",
                "5e-324",
                "1e-300",
                "9.9999999995",
                "0.5",
            ])
            .to_owned(),
        1 => format!("{:e}", f64::from_bits(random.next())),
        _ => {
            let scaled = random.offset(-1_000_000_000, 2_000_000_000);
            #[expect(clippy::cast_precision_loss, reason = "any double will do")]
            let value = scaled as f64 / 10f64.powi(i32::try_from(random.below(12)).unwrap_or(0));
            format!("{value:e}")
        }
    };
    format!("d:{value}")
}

/// A random session of `hostserv` and `addr` commands.
fn addr_session(random: &mut Random, out: &mut String) -> Result {
    for _ in 0..1 + random.below(20) {
        if random.below(2) == 0 {
            let spec = random_text(random, b"[]:*ab1_", 10);
            writeln!(out, "hostserv {spec} {}", random.below(2))?;
            continue;
        }
        let (family, len) = match random.below(5) {
            0 | 1 => ("4", 4),
            2 | 3 => ("6", 16),
            _ => ("u", 1 + random.below(20)),
        };
        // Sometimes a wrong length.
        let len = if random.below(8) == 0 {
            random.below(20)
        } else {
            len
        };
        let hex: String = (0..len.max(1))
            .map(|_| {
                let byte = if family == "u" {
                    0x61 + random.below(26)
                } else {
                    random.below(256)
                };
                format!("{byte:02x}")
            })
            .collect();
        writeln!(out, "addr {family} {hex} {}", random.below(65536))?;
    }
    Ok(())
}

/// A random `BUF_MEM` session.
fn buf_mem_session(random: &mut Random, out: &mut String) -> Result {
    writeln!(out, "new {}", random.below(2))?;
    for _ in 0..1 + random.below(40) {
        match random.below(10) {
            0..=3 => writeln!(out, "grow {}", length(random))?,
            4..=6 => writeln!(out, "grow_clean {}", length(random))?,
            7 => writeln!(out, "fill {}", random.below(256))?,
            8 => writeln!(out, "dump")?,
            _ => {
                let bytes: Vec<String> = (0..1 + random.below(32))
                    .map(|_| format!("{:02x}", random.below(256)))
                    .collect();
                writeln!(out, "reverse {}", bytes.concat())?;
            }
        }
    }
    if random.below(4) != 0 {
        writeln!(out, "free")?;
    }
    Ok(())
}

/// A random error-queue session: errors raised, marked, read, saved, and restored, ending
/// with the whole ring.
fn err_session(random: &mut Random, out: &mut String) -> Result {
    writeln!(out, "clear")?;
    for _ in 0..1 + random.below(40) {
        match random.below(20) {
            0..=6 => {
                let library = match random.below(4) {
                    0 => 2, // ERR_LIB_SYS: the reason is an errno value
                    1 => 128 + random.below(4),
                    _ => 1 + random.below(64),
                };
                writeln!(out, "raise {library} {}", reason(random))?;
            }
            7 => {
                let word: String = (0..1 + random.below(20))
                    .map(|_| char::from(b'a' + u8::try_from(random.below(26)).unwrap_or(0)))
                    .collect();
                writeln!(out, "data {word}")?;
            }
            8 => {
                // Pieces between separators stay shorter than an error holds: OpenSSL loops
                // forever on longer ones (docs/DEVIATIONS.md).
                let separator = random.pick(&["-", ";", ",", ":", "::"]);
                let every = if separator == "-" {
                    0
                } else {
                    1 + random.below(3000)
                };
                writeln!(out, "txt {separator} {} {every}", random.below(9000))?;
            }
            9 => writeln!(out, "mark")?,
            10 => writeln!(out, "pop")?,
            11 => writeln!(out, "poptomark")?,
            12 => writeln!(out, "clearmark")?,
            13 => writeln!(out, "count")?,
            14 => writeln!(out, "{}", random.pick(&["get", "peek", "last"]))?,
            15 => writeln!(out, "{}", random.pick(&["save", "savemark", "restore"]))?,
            16 => writeln!(out, "errstr {:x} {}", error_code(random), random.below(300))?,
            17 => writeln!(out, "state")?,
            _ => writeln!(out, "get")?,
        }
    }
    writeln!(out, "state")?;
    Ok(())
}

/// A random stack session: elements pushed, inserted, removed, replaced, sorted, and found,
/// with comparators changing along the way.
fn stack_session(random: &mut Random, out: &mut String) -> Result {
    writeln!(out, "sknew {}", random.below(3))?;
    for _ in 0..1 + random.below(60) {
        let element = random.below(64);
        match random.below(24) {
            0..=5 => writeln!(out, "skpush {element}")?,
            6 => writeln!(out, "skunshift {element}")?,
            7 | 8 => writeln!(out, "skinsert {element} {}", random.offset(-3, 20))?,
            9 => writeln!(out, "skset {} {element}", random.offset(-2, 20))?,
            10 => writeln!(out, "skdelptr {element}")?,
            11 => writeln!(out, "skdelete {}", random.offset(-2, 20))?,
            12 => writeln!(out, "{}", random.pick(&["skshift", "skpop"]))?,
            13 => writeln!(out, "skcmp {}", random.below(3))?,
            14 | 15 => writeln!(out, "sksort")?,
            16..=19 => writeln!(
                out,
                "{} {}",
                random.pick(&["skfind", "skfindex", "skfindall"]),
                random.offset(-1, 12)
            )?,
            20 => writeln!(out, "skdup")?,
            21 => writeln!(out, "skreserve {}", random.offset(-2, 10))?,
            22 => writeln!(out, "skzero")?,
            _ => writeln!(out, "skdump")?,
        }
    }
    writeln!(out, "skdump")?;
    Ok(())
}

/// A random hash table session: items inserted, replaced, deleted, and looked up while the
/// table grows and shrinks, with its doall order printed along the way.
fn lhash_session(random: &mut Random, out: &mut String) -> Result {
    writeln!(out, "lhnew {}", random.below(2))?;
    let keys = 1 + random.below(64);
    for _ in 0..1 + random.below(150) {
        let key = random.below(keys);
        match random.below(20) {
            0..=8 => writeln!(out, "lhinsert {key}")?,
            9..=13 => writeln!(out, "lhdelete {key}")?,
            14..=16 => writeln!(out, "lhget {key}")?,
            17 => writeln!(out, "lhdown {}", random.pick(&["0", "128", "256", "512"]))?,
            _ => writeln!(out, "lhdump")?,
        }
    }
    writeln!(out, "lhdump")?;
    Ok(())
}

/// A random memory BIO session: writes and reads of every kind, seeks, resets, and the EOF
/// return, on a writable, secure, read-only, or filtered memory BIO.
fn bio_session(random: &mut Random, out: &mut String) -> Result {
    let kind = random.below(11);
    writeln!(out, "bionew {kind}")?;
    for _ in 0..1 + random.below(50) {
        match random.below(19) {
            0..=3 => writeln!(out, "biowrite {}", random_text(random, b"abcxyz__", 30))?,
            4 => writeln!(out, "bioputs {}", random_text(random, b"abc__", 12))?,
            5..=7 => writeln!(out, "bioread {}", random.below(40))?,
            // A size of 0 makes OpenSSL's buffer filter loop forever once it holds data.
            8 if kind == 4 => writeln!(out, "biogets {}", 1 + random.below(40))?,
            8 => writeln!(out, "biogets {}", random.below(40))?,
            9 => writeln!(out, "bioline {}", random.below(20))?,
            10 | 11 => {
                let name = random.pick(&[
                    "reset",
                    "eof",
                    "pending",
                    "wpending",
                    "seek",
                    "tell",
                    "eofret",
                    "getclose",
                    "flush",
                    "info",
                    "shutdown",
                    "guarantee",
                    "request",
                    "lines",
                    "bufsize",
                    "wbufsize",
                    "notrunc",
                    "mtu",
                ]);
                let arg = if name == "bufsize" || name == "wbufsize" {
                    random.offset(-2, 9000)
                } else if name == "eofret" && (4..=7).contains(&kind) {
                    // A positive EOF return reads bytes nobody wrote; behind a filter, those
                    // are the filter's uninitialized buffer in OpenSSL.
                    random.offset(-2, 3)
                } else {
                    random.offset(-2, 40)
                };
                writeln!(out, "bioctrl {name} {arg}")?;
            }
            12 => writeln!(out, "biomem")?,
            13 | 14 if kind == 8 || kind == 10 => writeln!(out, "biopeer")?,
            15 if kind == 8 => writeln!(out, "bionread {}", random.below(20))?,
            16 if kind == 8 => writeln!(out, "bionwrite {}", random_text(random, b"pqr", 20))?,
            _ => writeln!(out, "biostate")?,
        }
    }
    writeln!(out, "biostate")?;
    Ok(())
}

/// A random session of hex decoding and `OPENSSL_strtoul`, on text mixing digits, letters,
/// separators, signs, and spaces.
fn string_session(random: &mut Random, out: &mut String) -> Result {
    const HEX: &[u8] = b"0123456789abcdefABCDEF::--xg";
    const NUMBER: &[u8] = b"0123456789abcdefxX+-";
    for _ in 0..1 + random.below(20) {
        let choice = random.below(4);
        if choice == 0 {
            let text = random_text(random, HEX, 16);
            let separator = random.pick(&["0", "58", "45", "120"]);
            writeln!(out, "hexdecode {text} {separator}")?;
        } else if choice == 1 {
            let name = random.pick(&[
                "ALL",
                "tls",
                "Tls_Cipher",
                "x509v3_policy",
                "QUERY",
                "query_",
                "TLS-CIPHER",
                "-",
                "PKCS5v2",
                "ref_count",
                "engine",
            ]);
            let num = random.below(25).cast_signed() - 2;
            writeln!(out, "tracecat {name} {num}")?;
        } else if choice == 2 {
            writeln!(out, "tracestr {}", trace_string_args(random))?;
        } else {
            let text = random_text(random, NUMBER, 24);
            let base = random.pick(&["0", "8", "10", "16", "36", "1", "99"]);
            writeln!(out, "strtoul {text} {base}")?;
        }
    }
    Ok(())
}

/// `OSSL_trace_string`'s text and full flags and data in hex: up to 120 bytes, around the
/// 80-byte limit, mixing printable text with newlines, control characters, NULs, and high bytes.
fn trace_string_args(random: &mut Random) -> String {
    let len = match random.below(4) {
        0 => random.below(4),
        1 => 78 + random.below(5),
        _ => random.below(121),
    };
    let hex: String = (0..len)
        .map(|_| {
            let byte = match random.below(8) {
                0 => b'\n',
                1 => [0u8, 9, 13, 27, 0x7f]
                    .get(usize::try_from(random.below(5)).unwrap_or(0))
                    .copied()
                    .unwrap_or(0),
                2 => u8::try_from(0x80 + random.below(0x80)).unwrap_or(0x80),
                _ => u8::try_from(0x20 + random.below(0x5f)).unwrap_or(b'a'),
            };
            format!("{byte:02x}")
        })
        .collect();
    let text = random.below(2);
    let full = random.below(2);
    format!("{text} {full} {}", if hex.is_empty() { "-" } else { &hex })
}

/// Up to `max` characters from `alphabet`, or `-` for none.
fn random_text(random: &mut Random, alphabet: &[u8], max: u64) -> String {
    let len = random.below(max + 1);
    let text: String = (0..len)
        .map(|_| {
            let i = usize::try_from(random.below(u64::try_from(alphabet.len()).unwrap_or(1)))
                .unwrap_or(0);
            char::from(alphabet.get(i).copied().unwrap_or(b'0'))
        })
        .collect();
    if text.is_empty() {
        "-".to_owned()
    } else {
        text
    }
}

/// A reason for `raise`: small codes, with the common and fatal flags, or anything.
fn reason(random: &mut Random) -> u64 {
    match random.below(4) {
        0 => random.below(300),
        1 => 0x8_0000 | random.below(300),
        2 => 0xc_0000 | random.below(300),
        _ => random.below(0x80_0000),
    }
}

/// An error code for `errstr`: packed from a library and reason, a system error, or any bits.
fn error_code(random: &mut Random) -> u64 {
    match random.below(5) {
        0 | 1 => (random.below(70) << 23) | reason(random),
        2 => 0x8000_0000 | random.below(200),
        3 => random.below(1 << 32),
        _ => random.next(),
    }
}

/// Mostly small lengths, where growth, shrinking, and reuse of `max` interact, plus a few
/// past `BUF_MEM`'s limit.
fn length(random: &mut Random) -> u64 {
    match random.below(20) {
        0..=11 => random.below(65),
        12..=16 => random.below(1025),
        17..=18 => random.below(8193),
        _ => 0x5fff_fffd,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_replays_the_same_sessions() {
        let first = random_sessions(42, 100).unwrap();
        assert_eq!(first, random_sessions(42, 100).unwrap());
        assert_ne!(first, random_sessions(43, 100).unwrap());
        // Every kind of session.
        for start in [
            "\nnew ",
            "\nclear\n",
            "\nsknew ",
            "\nlhnew ",
            "\nbionew ",
            "\nhexdecode ",
            "printf ",
            "\nhostserv ",
        ] {
            assert!(first.contains(start), "no session starting {start:?}");
        }
    }

    #[test]
    fn arguments() {
        let args = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            parse_args(&args(&["--random", "5", "--seed", "9"])).unwrap(),
            (5, 9)
        );
        assert!(parse_args(&args(&["--seed"])).is_err());
        assert!(parse_args(&args(&["--bogus", "1"])).is_err());
    }
}
