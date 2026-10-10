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
        match random.below(24) {
            0 => err_session(&mut random, &mut out)?,
            1 => buf_mem_session(&mut random, &mut out)?,
            2 => stack_session(&mut random, &mut out)?,
            3 => lhash_session(&mut random, &mut out)?,
            4 => bio_session(&mut random, &mut out)?,
            5 => printf_session(&mut random, &mut out)?,
            6 => addr_session(&mut random, &mut out)?,
            7 => obj_session(&mut random, &mut out)?,
            8 => asn_session(&mut random, &mut out)?,
            9 => int_session(&mut random, &mut out)?,
            10 => text_session(&mut random, &mut out)?,
            11 => time_session(&mut random, &mut out)?,
            12 => any_session(&mut random, &mut out)?,
            14 => s2i_session(&mut random, &mut out)?,
            15 => base64_session(&mut random, &mut out)?,
            16 => pem_session(&mut random, &mut out)?,
            13 => d2i_session(&mut random, &mut out)?,
            17 => params_session(&mut random, &mut out)?,
            18 => ctx_session(&mut random, &mut out)?,
            19 => prop_session(&mut random, &mut out)?,
            20 => prov_session(&mut random, &mut out)?,
            21 => fetch_session(&mut random, &mut out)?,
            22 => digest_session(&mut random, &mut out)?,
            _ => string_session(&mut random, &mut out)?,
        }
    }
    Ok(out)
}

/// A random session of object commands: dotted texts (mostly well formed, around known OIDs,
/// with large arcs, odd separators, and stray characters), names, and content octets.
fn obj_session(random: &mut Random, out: &mut String) -> Result {
    let hex = |bytes: &[u8]| -> String {
        if bytes.is_empty() {
            "-".to_owned()
        } else {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }
    };
    for _ in 0..1 + random.below(20) {
        match random.below(3) {
            0 => {
                let mut text = random
                    .pick(&[
                        "",
                        "0",
                        "1",
                        "2",
                        "3",
                        "2.5.4",
                        "1.2.840.113549.1.1",
                        "1.3.6.1.5.5.7",
                        "x",
                    ])
                    .to_owned();
                for _ in 0..random.below(6) {
                    text.push_str(random.pick(&[".", ".", ".", " ", "..", "-"]));
                    let arc = match random.below(6) {
                        0 => random.below(40).to_string(),
                        1 => random.below(200).to_string(),
                        2 => random.next().to_string(),
                        3 => format!(
                            "{}{:019}",
                            random.below(1000),
                            random.next() % 10_000_000_000_000_000_000
                        ),
                        4 => random
                            .pick(&["", "a", "007", "18446744073709551616"])
                            .to_owned(),
                        _ => random.below(20).to_string(),
                    };
                    text.push_str(&arc);
                }
                writeln!(out, "objtxt {} {}", hex(text.as_bytes()), random.below(2))?;
            }
            1 => {
                let name = random.pick(&[
                    "CN",
                    "commonName",
                    "SHA256",
                    "sha256",
                    "NULL",
                    "UNDEF",
                    "undefined",
                    "rsaEncryption",
                    "ORG",
                    "org",
                    "2.5.4.3",
                    "1.3",
                    "x",
                    "ISO",
                    "iso",
                ]);
                writeln!(out, "objname {name}")?;
            }
            _ => {
                let len = match random.below(4) {
                    0 => random.below(4),
                    1 => random.below(12),
                    2 => random.below(40),
                    _ => 200 + random.below(57),
                };
                let mut bytes: Vec<u8> = (0..len)
                    .map(|_| {
                        let byte = match random.below(4) {
                            0 => 0x80 | random.below(0x80),
                            1 => random.below(0x80),
                            2 => random
                                .pick(&["0", "42", "85", "96", "128", "134"])
                                .parse()
                                .unwrap_or(0),
                            _ => random.below(256),
                        };
                        u8::try_from(byte).unwrap_or(0)
                    })
                    .collect();
                if random.below(3) == 0
                    && let Some(last) = bytes.last_mut()
                {
                    *last &= 0x7f;
                }
                writeln!(out, "objder {}", hex(&bytes))?;
            }
        }
    }
    Ok(())
}

/// A random session of ASN.1 header commands: headers in every form OpenSSL reads (high tag
/// numbers with leading 0x80 octets, long and zero-padded lengths, indefinite lengths), cut
/// short and claimed long; header writes; and OBJECT IDENTIFIER elements, well formed or not.
fn asn_session(random: &mut Random, out: &mut String) -> Result {
    let hex = |bytes: &[u8]| -> String {
        if bytes.is_empty() {
            "-".to_owned()
        } else {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }
    };
    let byte = |random: &mut Random, limit: u64| u8::try_from(random.below(limit)).unwrap_or(0);
    for _ in 0..1 + random.below(20) {
        match random.below(3) {
            0 => {
                let first = byte(random, 256);
                let high = random.below(3) == 0;
                let mut bytes = vec![if high { first | 0x1f } else { first }];
                if high {
                    for _ in 0..random.below(6) {
                        bytes.push(if random.below(3) == 0 {
                            0x80
                        } else {
                            0x80 | byte(random, 128)
                        });
                    }
                    bytes.push(byte(random, 128));
                }
                match random.below(4) {
                    0 => bytes.push(byte(random, 128)),
                    1 => bytes.push(0x80),
                    2 => {
                        let count = random.below(11);
                        bytes.push(0x80 | u8::try_from(count).unwrap_or(0));
                        for _ in 0..count {
                            bytes.push(if random.below(3) == 0 {
                                0
                            } else {
                                byte(random, 256)
                            });
                        }
                    }
                    _ => bytes.push(byte(random, 256)),
                }
                for _ in 0..random.below(8) {
                    bytes.push(byte(random, 256));
                }
                let cut = random.below(4) == 0;
                if cut {
                    bytes.truncate(
                        usize::try_from(random.below(u64::try_from(bytes.len()).unwrap_or(1)))
                            .unwrap_or(0),
                    );
                }
                let delta = match random.below(4) {
                    0 => -i64::try_from(random.below(3)).unwrap_or(0),
                    1 => i64::try_from(random.below(1000)).unwrap_or(0),
                    _ => 0,
                };
                writeln!(out, "asnhdr {} {delta}", hex(&bytes))?;
            }
            1 => {
                let constructed = random.below(4);
                let length = match random.below(4) {
                    0 => random.below(128).to_string(),
                    1 => random.below(70_000).to_string(),
                    2 => random
                        .pick(&["-1", "-128", "2147483647", "2147483640", "16777216"])
                        .to_owned(),
                    _ => random.below(256).to_string(),
                };
                let tag = match random.below(3) {
                    0 => random.below(31).to_string(),
                    1 => random.below(1 << 21).to_string(),
                    _ => random
                        .pick(&["31", "-1", "-31", "2147483647", "127", "128"])
                        .to_owned(),
                };
                writeln!(
                    out,
                    "asnput {constructed} {length} {tag} {}",
                    random.below(512)
                )?;
            }
            _ => {
                let content_len = random.below(12);
                let mut content: Vec<u8> = (0..content_len)
                    .map(|_| match random.below(3) {
                        0 => 0x80 | byte(random, 128),
                        1 => random
                            .pick(&["42", "85", "43", "128", "0"])
                            .parse()
                            .unwrap_or(0),
                        _ => byte(random, 128),
                    })
                    .collect();
                if random.below(2) == 0
                    && let Some(last) = content.last_mut()
                {
                    *last &= 0x7f;
                }
                let identifier = match random.below(5) {
                    0 => 0x86,
                    1 => 0x26,
                    2 => byte(random, 256),
                    _ => 0x06,
                };
                let mut bytes = vec![identifier];
                match random.below(5) {
                    0 => bytes.extend([0x81, u8::try_from(content.len()).unwrap_or(0)]),
                    1 => bytes.push(
                        u8::try_from(content.len() + usize::try_from(random.below(3)).unwrap_or(0))
                            .unwrap_or(0),
                    ),
                    2 => bytes.push(0x80),
                    _ => bytes.push(u8::try_from(content.len()).unwrap_or(0)),
                }
                bytes.extend(content);
                writeln!(out, "d2iobj {}", hex(&bytes))?;
            }
        }
    }
    Ok(())
}

/// A random session of INTEGER commands: octet strings of every length around 8 under the
/// integer types (and others), int64 values at the edges, and hex text with the endings,
/// junk, and continuations `a2i_ASN1_INTEGER` handles; and BIT STRING bit changes and checks.
fn int_session(random: &mut Random, out: &mut String) -> Result {
    let hex = |bytes: &[u8]| -> String {
        if bytes.is_empty() {
            "-".to_owned()
        } else {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }
    };
    for _ in 0..1 + random.below(20) {
        match random.below(4) {
            0 => {
                let kind = random.pick(&["2", "258", "10", "266", "4", "0"]);
                let len = random.below(11);
                let bytes: Vec<u8> = (0..len)
                    .map(|_| match random.below(4) {
                        0 => 0,
                        1 => 0xff,
                        2 => 0x80,
                        _ => u8::try_from(random.below(256)).unwrap_or(0),
                    })
                    .collect();
                writeln!(out, "asnint {kind} {}", hex(&bytes))?;
            }
            1 => {
                let value = match random.below(4) {
                    0 => random
                        .pick(&[
                            "0",
                            "-1",
                            "9223372036854775807",
                            "-9223372036854775808",
                            "128",
                            "-128",
                            "-129",
                        ])
                        .to_owned(),
                    1 => (random.next() >> random.below(64)).to_string(),
                    2 => format!("-{}", random.next() >> (1 + random.below(63))),
                    _ => random.below(70_000).to_string(),
                };
                writeln!(out, "asnset {value}")?;
            }
            3 => {
                let bytes: Vec<u8> = (0..random.below(6))
                    .map(|_| match random.below(3) {
                        0 => 0,
                        _ => u8::try_from(random.below(256)).unwrap_or(0),
                    })
                    .collect();
                let flags: Vec<u8> = (0..random.below(5))
                    .map(|_| u8::try_from(random.below(256)).unwrap_or(0))
                    .collect();
                let n = i64::try_from(random.below(60)).unwrap_or(0) - 2;
                writeln!(
                    out,
                    "asnbit {} {n} {} {}",
                    hex(&bytes),
                    random.below(3),
                    hex(&flags)
                )?;
            }
            _ => {
                let mut text = String::new();
                for line in 0..1 + random.below(3) {
                    if line == 0 && random.below(3) == 0 {
                        text.push_str("00");
                    }
                    let digits = random.below(14);
                    for _ in 0..digits {
                        text.push(char::from(
                            b"0123456789abcdefABCDEF"
                                .get(usize::try_from(random.below(22)).unwrap_or(0))
                                .copied()
                                .unwrap_or(b'0'),
                        ));
                    }
                    text.push_str(random.pick(&["", " junk", "z", "\\", "\\"]));
                    text.push_str(random.pick(&["\n", "\r\n", "", "\n"]));
                }
                let size = random.pick(&["300", "300", "8", "3", "1", "0"]);
                let command = random.pick(&["a2iint", "a2istr"]);
                writeln!(out, "{command} {size} {}", hex(text.as_bytes()))?;
            }
        }
    }
    Ok(())
}

/// A random session of character-string commands: strings of every universal type (and some
/// others) holding text in every form, valid and not, printed with random combinations of the
/// `ASN1_STRFLGS_*` flags; and conversions between forms with random masks and size limits.
fn text_session(random: &mut Random, out: &mut String) -> Result {
    let hex = |bytes: &[u8]| -> String {
        if bytes.is_empty() {
            "-".to_owned()
        } else {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }
    };
    let pieces: &[&[u8]] = &[
        b"a",
        b"Z",
        b"0",
        b" ",
        b",",
        b"+",
        b"\"",
        b"\\",
        b"<",
        b">",
        b";",
        b"#",
        b"=",
        b"(",
        b"*",
        b"@",
        b"\x00",
        b"\x01",
        b"\x7f",
        b"\x80",
        b"\xe9",
        b"\xc3\xa9",
        b"\xe2\x82\xac",
        b"\xf0\x9f\x98\x80",
        b"\xc3",
        b"\xed\xa0\x80",
        b"\xff",
        b"\x00\x00",
        b"\x00h",
    ];
    for _ in 0..1 + random.below(20) {
        let mut bytes = Vec::new();
        for _ in 0..random.below(8) {
            let i = usize::try_from(random.below(u64::try_from(pieces.len()).unwrap_or(1)))
                .unwrap_or(0);
            bytes.extend_from_slice(pieces.get(i).copied().unwrap_or(b"a"));
        }
        if random.below(2) == 0 {
            // Not BOOLEAN or OBJECT: dumping their DER, OpenSSL reads the string as another
            // structure and prints part of a heap address (docs/DEVIATIONS.md).
            let kind = random.pick(&[
                "12", "12", "19", "20", "22", "30", "30", "28", "28", "4", "2", "258", "3", "16",
                "5", "26", "21", "99", "-1", "-3", "0",
            ]);
            let flag_bits = [
                0x1u64, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400,
            ];
            let flags = if random.below(4) == 0 {
                random.pick(&["317", "2", "0", "10317"]).to_owned()
            } else {
                let mut f = 0u64;
                for bit in flag_bits {
                    if random.below(3) == 0 {
                        f |= bit;
                    }
                }
                format!("{f:x}")
            };
            writeln!(out, "asntext {kind} {flags} {}", hex(&bytes))?;
        } else {
            let inform = random.pick(&["1000", "1001", "1002", "1004", "1003", "0"]);
            let masks = [
                0x1u64, 0x2, 0x4, 0x10, 0x100, 0x200, 0x800, 0x2000, 0x2_0000, 0x4,
            ];
            let mut mask = 0u64;
            for m in masks {
                if random.below(3) == 0 {
                    mask |= m;
                }
            }
            let min = random.pick(&["0", "0", "1", "3", "-1"]);
            let max = random.pick(&["0", "0", "2", "5", "-1"]);
            writeln!(out, "asnmb {inform} {mask:x} {min} {max} {}", hex(&bytes))?;
        }
    }
    Ok(())
}

/// A random session of `asnany` commands: SEQUENCE OF and SET OF ANY over values of the
/// universal types (and a few odd ones: none, high tag numbers, a SEQUENCE's raw octets), many
/// sharing prefixes, so the SET's DER ordering compares lengths and contents.
fn any_session(random: &mut Random, out: &mut String) -> Result {
    for _ in 0..random.below(6) + 1 {
        let mut line = String::from("asnany");
        for _ in 0..random.below(9) {
            let kind = random.pick(&[
                "1", "2", "-2", "3", "4", "4", "5", "6", "10", "12", "16", "17", "19", "22", "23",
                "24", "30", "-1", "31", "99", "200",
            ]);
            let len = match random.below(4) {
                0 => 0,
                1 => random.below(3),
                2 => random.below(8),
                _ => random.below(140),
            };
            let shared = random.below(2) == 0;
            let octets: Vec<u8> = (0..len)
                .map(|i| {
                    if shared && i < 2 {
                        0x01
                    } else {
                        u8::try_from(random.below(256)).unwrap_or(0)
                    }
                })
                .collect();
            let octets = if kind == "6" && !octets.is_empty() {
                // Mostly valid OID content: the last octet without the continuation bit.
                let mut o = octets;
                if let Some(last) = o.last_mut() {
                    *last &= 0x7f;
                }
                o
            } else {
                octets
            };
            let hex: String = if octets.is_empty() {
                "-".to_owned()
            } else {
                octets.iter().map(|b| format!("{b:02x}")).collect()
            };
            write!(line, " {kind}:{hex}")?;
        }
        writeln!(out, "{line}")?;
    }
    Ok(())
}

/// A random session of `asnd2i`, `asnbio`, and `asnparse` commands: BER near what each item takes (nested TLVs of its
/// types and others, indefinite lengths, constructed strings, end-of-contents octets, lengths a
/// little off, and cut short), decoded with one of the probe's items.
fn d2i_session(random: &mut Random, out: &mut String) -> Result {
    for _ in 0..random.below(8) + 1 {
        let item = random.below(14);
        let mut der = Vec::new();
        ber_value(random, &mut der, item, 0);
        if random.below(10) == 0 {
            let cut = usize::try_from(random.below(u64::try_from(der.len()).unwrap_or(1) + 1))
                .unwrap_or(0);
            der.truncate(cut);
        } else if random.below(10) == 0 {
            der.push(u8::try_from(random.below(256)).unwrap_or(0));
        }
        // Sometimes a stream of elements for a BIO to read.
        let stream = random.below(4) == 0;
        if stream {
            for _ in 0..random.below(3) {
                ber_value(random, &mut der, 0, 1);
            }
        }
        der.truncate(256);
        let hex: String = if der.is_empty() {
            "-".to_owned()
        } else {
            der.iter().map(|b| format!("{b:02x}")).collect()
        };
        if random.below(4) == 0 {
            let indent = random.below(2);
            let dump = random.pick(&["-2", "-1", "0", "4", "16"]);
            writeln!(out, "asnparse {indent} {dump} {hex}")?;
        } else if stream {
            writeln!(out, "asnbio {hex}")?;
        } else {
            writeln!(out, "asnd2i {item} {hex}")?;
        }
    }
    Ok(())
}

/// One of `octets`, at random.
fn pick_octet(random: &mut Random, octets: &[u8]) -> u8 {
    let i = usize::try_from(random.below(u64::try_from(octets.len()).unwrap_or(1))).unwrap_or(0);
    octets.get(i).copied().unwrap_or(0)
}

/// Appends a random BER value, mostly of a type `item` takes, nested at most a few deep.
fn ber_value(random: &mut Random, out: &mut Vec<u8>, item: u64, depth: u32) {
    // Identifier octets: the item's usual tags, others, context tags, and the high form.
    let identifier: Vec<u8> = match random.below(12) {
        0 => vec![0x30],
        1 => vec![0x31],
        2 => vec![0x04],
        3 => vec![0x24],
        4 => vec![0x02],
        5 => vec![0x03],
        6 => vec![pick_octet(
            random,
            &[0x01, 0x05, 0x06, 0x0c, 0x13, 0x16, 0x17, 0x18, 0x1e, 0x00],
        )],
        7 => vec![pick_octet(random, &[0xa0, 0xa2, 0xa3, 0x81, 0x84, 0x80])],
        8 => vec![0x1f, u8::try_from(random.below(0x80)).unwrap_or(0)],
        9 if item == 11 => vec![0x06],
        _ => vec![u8::try_from(random.below(256)).unwrap_or(0)],
    };
    let constructed = identifier.first().is_some_and(|b| b & 0x20 != 0);
    let mut content = Vec::new();
    if constructed && depth < 4 {
        for _ in 0..random.below(4) {
            ber_value(random, &mut content, item, depth + 1);
        }
    } else {
        let len = match random.below(4) {
            0 => 0,
            1 => 1,
            2 => random.below(4),
            _ => random.below(20),
        };
        for _ in 0..len {
            content.push(u8::try_from(random.below(256)).unwrap_or(0));
        }
        if identifier == [0x06] && item == 11 {
            let oids: [&[u8]; 3] = [
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
                &[0x2b, 0x0e, 0x03, 0x02, 0x1a],
                &[0x2a, 0x03],
            ];
            let which = usize::try_from(random.below(3)).unwrap_or(0);
            content = oids.get(which).copied().unwrap_or(&[]).to_vec();
        }
    }
    out.extend(&identifier);
    let indefinite = constructed && random.below(4) == 0;
    if indefinite {
        out.push(0x80);
        out.extend(&content);
        if random.below(8) != 0 {
            out.extend([0, 0]);
        }
    } else {
        let mut len = content.len();
        match random.below(12) {
            0 => len = len.saturating_add(1),
            1 => len = len.saturating_sub(1),
            _ => {}
        }
        if len < 0x80 && random.below(8) != 0 {
            out.push(u8::try_from(len).unwrap_or(0));
        } else {
            out.push(0x81);
            out.push(u8::try_from(len.min(255)).unwrap_or(0));
        }
        out.extend(&content);
    }
}

/// A random session of `asns2i` commands: numbers in decimal and hex around 128 bits (where
/// printing turns to hex), with signs in both places `s2i_ASN1_INTEGER` takes them, leading
/// zeros, and stray characters.
fn s2i_session(random: &mut Random, out: &mut String) -> Result {
    for _ in 0..random.below(6) + 1 {
        let mut text = String::new();
        if random.below(3) == 0 {
            text.push('-');
        }
        let hex = random.below(2) == 0;
        if hex {
            text.push_str(random.pick(&["0x", "0X"]));
        }
        if random.below(6) == 0 {
            text.push('-');
        }
        let digits = match random.below(4) {
            0 => random.below(4),
            1 => random.below(20),
            2 => {
                if hex {
                    30 + random.below(5)
                } else {
                    37 + random.below(4)
                }
            }
            _ => random.below(80),
        };
        if random.below(4) == 0 {
            text.push_str("000");
        }
        for _ in 0..digits {
            let d = random.below(if hex { 16 } else { 10 });
            text.push(char::from_digit(u32::try_from(d).unwrap_or(0), 16).unwrap_or('0'));
        }
        if random.below(10) == 0 {
            text.push_str(random.pick(&["g", "_", "-", "x"]));
        }
        if text.is_empty() {
            text.push('-');
        }
        writeln!(out, "asns2i {text}")?;
    }
    Ok(())
}

/// A random property query over the probe's fetch providers' properties (`provider`, `fips`,
/// `x.n`, `x.s`, `x.flag`, and ones they don't have), each optional, negated, or compared.
fn fetch_query(random: &mut Random) -> String {
    let mut q = String::new();
    for i in 0..random.below(4) {
        if i > 0 {
            q.push(',');
        }
        q.push_str(random.pick(&["", "", "?", "?", "-"]));
        q.push_str(random.pick(&[
            "provider", "fips", "x.n", "x.n", "x.s", "x.flag", "x.other", "unknown",
        ]));
        match random.below(4) {
            0 => {}
            _ => {
                q.push_str(random.pick(&["=", "=", "!="]));
                q.push_str(random.pick(&[
                    "fp", "fq", "yes", "no", "1", "2", "3", "-1", "0x2", "a", "b", "'Q'", "q", "",
                ]));
            }
        }
    }
    q
}

/// A random session of fetches from the probe's two providers: random names and property
/// queries, default properties set and cleared, providers unloaded and reloaded, listings,
/// and sometimes a fresh context.
fn fetch_session(random: &mut Random, out: &mut String) -> Result {
    let hex = |q: &str| -> String {
        if q.is_empty() {
            "-".to_owned()
        } else {
            q.bytes().map(|b| format!("{b:02x}")).collect()
        }
    };
    for _ in 0..random.below(12) + 1 {
        match random.below(14) {
            0 => writeln!(out, "fnew")?,
            1 => writeln!(out, "fdefault {}", hex(&fetch_query(random)))?,
            2 => writeln!(out, "fdefault -")?,
            3 => writeln!(out, "fall")?,
            4 => writeln!(out, "funload {}", random.pick(&["p", "q"]))?,
            5 => writeln!(out, "fload {}", random.pick(&["p", "q"]))?,
            _ => {
                let name = random.pick(&[
                    "ALG-1", "alg-1", "A1", "ALG-2", "A2", "ALG-3", "ALG-4", "a4", "NOPE",
                ]);
                let q = if random.below(5) == 0 {
                    String::new()
                } else {
                    fetch_query(random)
                };
                writeln!(out, "ffetch {name} {}", hex(&q))?;
            }
        }
    }
    writeln!(out, "fdefault -")?;
    Ok(())
}

/// A random session of digest commands on the probe's two contexts: initializations with
/// the default provider's digests (with and without an XOF length or BLAKE2 size), updates of
/// random lengths around block sizes, finals, XOF finals, and squeezes in random pieces (also
/// after finals and before updates), parameters, copies, and resets.
fn digest_session(random: &mut Random, out: &mut String) -> Result {
    const DIGESTS: &[&str] = &[
        "SHA1",
        "SHA224",
        "SHA256",
        "SHA2-256/192",
        "SHA384",
        "SHA512",
        "SHA512-224",
        "SHA512-256",
        "SHA3-224",
        "SHA3-256",
        "SHA3-384",
        "SHA3-512",
        "KECCAK-224",
        "KECCAK-256",
        "KECCAK-384",
        "KECCAK-512",
        "KECCAK-KMAC-128",
        "KECCAK-KMAC-256",
        "SHAKE128",
        "SHAKE256",
        "BLAKE2s256",
        "BLAKE2b512",
        "SM3",
        "MD5",
        "MD5-SHA1",
        "RIPEMD160",
        "NULL",
        "nonesuch",
    ];
    let length = |random: &mut Random| -> u64 {
        match random.below(4) {
            0 => random.below(4),
            1 => random
                .pick(&[
                    "63", "64", "65", "71", "72", "104", "135", "136", "137", "167", "168", "169",
                ])
                .parse()
                .unwrap_or(0),
            _ => random.below(400),
        }
    };
    for _ in 0..random.below(20) + 1 {
        match random.below(17) {
            0 | 1 => writeln!(out, "dinit {}", random.pick(DIGESTS))?,
            2 => writeln!(out, "dinit -")?,
            3 => {
                let key = random.pick(&["xoflen", "size"]);
                let n = random.below(70);
                writeln!(out, "dinitp {} {key} {n}", random.pick(DIGESTS))?;
            }
            4 => {
                let key = random.pick(&["xoflen", "size"]);
                let n = random.below(300);
                writeln!(out, "dset {key} {n}")?;
            }
            5..=8 => writeln!(out, "dupdate {}", length(random))?,
            9 => writeln!(out, "dfinal")?,
            10 => writeln!(out, "dxof {}", random.below(257))?,
            11 | 12 => writeln!(out, "dsqueeze {}", length(random).min(256))?,
            13 => writeln!(out, "dcopy")?,
            14 => writeln!(out, "dctx {}", random.below(2))?,
            15 if random.below(2) == 0 => {
                let name = random.pick(&[
                    "SHA256",
                    "sha256",
                    "SHA2-256",
                    "sha-256",
                    "2.16.840.1.101.3.4.2.1",
                    "RSA-SHA256",
                    "rsa-sha1-2",
                    "ssl3-md5",
                    "ripemd",
                    "RMD160",
                    "SHAKE-128",
                    "shake256",
                    "KECCAK-512",
                    "SHA2-256/192",
                    "blake2s256",
                    "BLAKE2B-512",
                    "MD4",
                    "whirlpool",
                    "mdc2",
                    "NULL",
                    "UNDEF",
                    "md5-sha1",
                    "SM3",
                    "nonesuch",
                ]);
                // Mixed case, as the names compare without it.
                let name: String = name
                    .chars()
                    .map(|c| {
                        if random.below(4) == 0 {
                            c.to_ascii_lowercase()
                        } else {
                            c
                        }
                    })
                    .collect();
                writeln!(out, "dname {name}")?;
            }
            // Digest, signature, and non-algorithm NIDs: a cipher's or key type's name is in
            // the reference's name map (its pre-filling adds them), so looking one up doesn't
            // fetch there; until 3.4 and Phase 4 it does here.
            15 => writeln!(
                out,
                "dnid {}",
                random.pick(&[
                    "4", "64", "672", "673", "674", "675", "1094", "1095", "1096", "1097", "1100",
                    "1101", "117", "95", "257", "804", "1143", "1056", "1057", "114", "668", "65",
                    "13", "0", "99999", "-1",
                ])
            )?,
            _ => writeln!(
                out,
                "{}",
                random.pick(&["dsize", "dflags", "dreset", "dfinal"])
            )?,
        }
    }
    writeln!(out, "dctx 0")?;
    Ok(())
}

/// A random session of provider commands in the probe's context: loads (keeping the fallback
/// or not) of the built-in providers and of modules that don't exist, into eight slots;
/// unloads; availability, the store's order, and parameters; sometimes a fresh context.
fn prov_session(random: &mut Random, out: &mut String) -> Result {
    for _ in 0..random.below(14) + 1 {
        let slot = random.below(8);
        let name = random.pick(&[
            "default", "default", "base", "base", "null", "null", "nosuch", "a/b",
        ]);
        match random.below(12) {
            0 => writeln!(out, "pnew")?,
            1..=3 => writeln!(out, "pload {slot} {name}")?,
            4 | 5 => writeln!(out, "ptry {slot} {name} {}", random.below(2))?,
            6..=8 => writeln!(out, "punload {slot}")?,
            9 => writeln!(out, "pavail {name}")?,
            10 => writeln!(out, "pparams {slot}")?,
            _ => writeln!(out, "pall")?,
        }
    }
    writeln!(out, "pall")?;
    Ok(())
}

/// A random property query: known, unknown, and dotted names in any case, each alone, negated,
/// optional, or compared with `=` or `!=` to a word, a quoted string, or a number in any base,
/// with stray spaces, separators, and characters.
fn property_query(random: &mut Random) -> String {
    let mut q = String::new();
    for i in 0..random.below(5) {
        if i > 0 {
            q.push_str(random.pick(&[",", ",", ", ", " ,", ",,", " "]));
        }
        if random.below(8) == 0 {
            q.push(' ');
        }
        q.push_str(random.pick(&["", "", "", "?", "-", "?"]));
        q.push_str(random.pick(&[
            "provider",
            "fips",
            "FIPS",
            "version",
            "output",
            "input",
            "structure",
            "x.y",
            "X.Y",
            "a.b",
            "a.b.c",
            "my_name.v2",
            "unknown",
            "other",
            "a..b",
            "1x",
            "",
            "_x",
            "a.",
        ]));
        match random.below(4) {
            0 => {}
            1 => q.push_str(random.pick(&["=", " = ", "!=", " != ", "==", "=!"])),
            _ => {
                q.push_str(random.pick(&["=", "!=", " = "]));
                let value = match random.below(7) {
                    0 => random
                        .pick(&["yes", "no", "YES", "default", "legacy", "der", "Mixed"])
                        .to_owned(),
                    1 => format!("{}", random.below(1000)),
                    2 => random
                        .pick(&[
                            "0x1f",
                            "0X1F",
                            "0xg",
                            "017",
                            "08",
                            "+5",
                            "-5",
                            "+",
                            "-",
                            "0x",
                            "9223372036854775808",
                        ])
                        .to_owned(),
                    3 => random
                        .pick(&["'a b'", "\"it's\"", "'a\"b'", "'open", "\"x'", "''", "\"\""])
                        .to_owned(),
                    4 => random
                        .pick(&["a\u{1}", "a~b", "a/b", "a=b", "a\u{7f}"])
                        .to_owned(),
                    5 => String::new(),
                    _ => format!("v{}", random.below(5)),
                };
                q.push_str(&value);
            }
        }
        if random.below(10) == 0 {
            q.push_str(random.pick(&[" ", "  ", " junk", "!", "\t"]));
        }
    }
    q
}

/// A random session of default-property commands: random queries set in the probe's context
/// (sometimes a new one, numbering names afresh), NULL, and the FIPS switch.
fn prop_session(random: &mut Random, out: &mut String) -> Result {
    for _ in 0..random.below(10) + 1 {
        match random.below(10) {
            0 => writeln!(out, "propnew")?,
            1 => writeln!(out, "propfips {}", random.below(3))?,
            2 => writeln!(out, "propset")?,
            _ => {
                let q = property_query(random);
                let hex: String = if q.is_empty() {
                    "-".to_owned()
                } else {
                    q.bytes().map(|b| format!("{b:02x}")).collect()
                };
                writeln!(out, "propset {hex}")?;
            }
        }
    }
    Ok(())
}

/// A random session of library-context commands: contexts made and freed in four slots,
/// defaults switched among them and the global one, thread limits and diagnostics flags set
/// through a context or NULL, and indexes registered under whichever is the default. The
/// session ends on the global default with its settings cleared, so later sessions start as
/// the first did.
fn ctx_session(random: &mut Random, out: &mut String) -> Result {
    for _ in 0..random.below(12) + 1 {
        let slot = random.below(4);
        let name = match random.below(6) {
            0 => "g".to_owned(),
            1 => "-".to_owned(),
            _ => slot.to_string(),
        };
        match random.below(8) {
            0 | 1 => writeln!(out, "ctxnew {slot}")?,
            2 => writeln!(out, "ctxfree {slot}")?,
            3 => writeln!(out, "ctxdefault {name}")?,
            4 => writeln!(out, "ctxmax {name} {}", random.below(20))?,
            5 => writeln!(out, "ctxdiag {name} {}", random.below(3))?,
            6 => writeln!(out, "ctxexidx {}", random.below(18))?,
            _ => writeln!(out, "ctxfreeglobal")?,
        }
    }
    writeln!(out, "ctxdefault g")?;
    writeln!(out, "ctxmax g 0")?;
    writeln!(out, "ctxdiag g 0")?;
    Ok(())
}

/// A random session of `OSSL_PARAM` commands: setters of values near the type limits into
/// parameters of every type and many sizes, getters over native octets, string copies around
/// the buffer sizes, and merges of keys that differ in case.
fn params_session(random: &mut Random, out: &mut String) -> Result {
    const SIGNED: &[i64] = &[
        0,
        1,
        -1,
        127,
        128,
        -128,
        -129,
        255,
        256,
        32767,
        -32769,
        2_147_483_647,
        2_147_483_648,
        -2_147_483_648,
        -2_147_483_649,
        4_294_967_295,
        4_294_967_296,
        9_007_199_254_740_992,
        9_007_199_254_740_993,
        -9_007_199_254_740_993,
        i64::MAX,
        i64::MIN,
    ];
    let hex = |bytes: &[u8]| -> String {
        if bytes.is_empty() {
            "-".to_owned()
        } else {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }
    };
    for _ in 0..random.below(8) + 1 {
        match random.below(5) {
            0 | 1 => {
                let function = random.pick(&[
                    "int32", "uint32", "int64", "uint64", "double", "int", "uint", "long", "ulong",
                    "size_t", "time_t",
                ]);
                let i = usize::try_from(random.below(SIGNED.len() as u64)).unwrap_or(0);
                let base = SIGNED.get(i).copied().unwrap_or(0);
                let delta = i64::try_from(random.below(3)).unwrap_or(0) - 1;
                let v = base.wrapping_add(delta);
                let value = match function {
                    "uint32" | "uint64" | "uint" | "ulong" | "size_t" => {
                        if random.below(4) == 0 {
                            format!("{}", u64::MAX - random.below(3))
                        } else {
                            format!("{}", v.unsigned_abs())
                        }
                    }
                    "double" => match random.below(4) {
                        0 => random
                            .pick(&["nan", "inf", "-inf", "0.5", "-0.5", "1e300", "-0"])
                            .to_owned(),
                        1 => format!("{}.25", v / 4),
                        _ => format!("{v}"),
                    },
                    _ => format!("{v}"),
                };
                let data_type = random.pick(&["1", "1", "2", "2", "3", "4", "5", "6"]);
                let size = match random.below(3) {
                    0 => random.pick(&["4", "8"]).to_owned(),
                    _ => format!("{}", random.below(18)),
                };
                writeln!(
                    out,
                    "paramset {function} {data_type} {size} {} {value}",
                    u8::from(random.below(6) == 0)
                )?;
            }
            2 => {
                let data_type = random.pick(&["1", "2", "3", "4", "5"]);
                let len = match random.below(3) {
                    0 => *[4usize, 8]
                        .get(usize::try_from(random.below(2)).unwrap_or(0))
                        .unwrap_or(&4),
                    _ => usize::try_from(random.below(18)).unwrap_or(0),
                };
                let mut data = Vec::new();
                for _ in 0..len {
                    data.push(pick_octet(
                        random,
                        &[0x00, 0xff, 0x7f, 0x80, 0x01, 0x3f, 0xf0, 0x43, 0xc3],
                    ));
                }
                writeln!(out, "paramget {data_type} {}", hex(&data))?;
            }
            3 => {
                let len = usize::try_from(random.below(12)).unwrap_or(0);
                let mut data = Vec::new();
                for _ in 0..len {
                    data.push(pick_octet(random, &[0x00, b'a', b'b', 0xff]));
                }
                let op = random.below(4);
                let size = random.below(14);
                let max = random.below(14);
                writeln!(out, "paramstr {op} {size} {max} {}", hex(&data))?;
            }
            _ => {
                let keys = |random: &mut Random| -> String {
                    let n = random.below(5);
                    let mut used: Vec<String> = Vec::new();
                    for _ in 0..n {
                        let key = random
                            .pick(&["a", "A", "b", "B", "key", "KEY", "kez", "a_b", "a-b", "z"]);
                        if !used.iter().any(|k| k.eq_ignore_ascii_case(key)) {
                            used.push(key.to_owned());
                        }
                    }
                    if used.is_empty() {
                        "-".to_owned()
                    } else {
                        used.join(",")
                    }
                };
                let a = keys(random);
                let b = keys(random);
                writeln!(out, "parammerge {a} {b}")?;
            }
        }
    }
    Ok(())
}

/// A random session of `b64enc` and `b64dec` commands: octets of every length near the
/// 48-octet line, and base64 text with whitespace, CR LF, `-`, padding in and out of place, and
/// stray characters, fed in chunks of every size.
fn base64_session(random: &mut Random, out: &mut String) -> Result {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for _ in 0..random.below(6) + 1 {
        let chunk = match random.below(4) {
            0 => 1,
            1 => random.below(8) + 1,
            2 => random.below(70) + 1,
            _ => 1000,
        };
        let mut data: Vec<u8> = Vec::new();
        if random.below(2) == 0 {
            let len = match random.below(3) {
                0 => random.below(5),
                1 => 44 + random.below(10),
                _ => random.below(200),
            };
            for _ in 0..len {
                data.push(u8::try_from(random.below(256)).unwrap_or(0));
            }
            let hex: String = if data.is_empty() {
                "-".to_owned()
            } else {
                data.iter().map(|b| format!("{b:02x}")).collect()
            };
            if random.below(2) == 0 {
                writeln!(out, "b64bio 1 {} {chunk} {hex}", random.below(2))?;
            } else {
                writeln!(out, "b64enc {chunk} {hex}")?;
            }
            continue;
        }
        if random.below(4) == 0 {
            data.extend_from_slice(
                random
                    .pick(&["-----BEGIN X-----\n", "junk\n", "a b\n", "QUJD\n"])
                    .as_bytes(),
            );
        }
        for _ in 0..random.below(120) {
            let c = match random.below(40) {
                0 => *random
                    .pick(&["\n", "\r", " ", "\t", "=", "-", "*", "\u{e9}"])
                    .as_bytes()
                    .first()
                    .unwrap_or(&b' '),
                1 => b'=',
                _ => ALPHABET
                    .get(usize::try_from(random.below(64)).unwrap_or(0))
                    .copied()
                    .unwrap_or(b'A'),
            };
            data.push(c);
        }
        if random.below(3) == 0 {
            data.extend_from_slice(random.pick(&["=", "==", "\n", "-", "===", "=A"]).as_bytes());
        }
        data.truncate(300);
        let hex: String = if data.is_empty() {
            "-".to_owned()
        } else {
            data.iter().map(|b| format!("{b:02x}")).collect()
        };
        if random.below(2) == 0 {
            writeln!(out, "b64bio 0 {} {chunk} {hex}", random.below(2))?;
        } else {
            writeln!(out, "b64dec {chunk} {hex}")?;
        }
    }
    Ok(())
}

/// A random session of `pemread` commands: PEM-like text from pieces (lines before the BEGIN
/// line, a BOM, names matching or not, headers with and without the blank line, base64 lines of
/// every length, CR LF, trailing spaces and controls, high octets, NULs, truncation), read with
/// each flag.
fn pem_session(random: &mut Random, out: &mut String) -> Result {
    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for _ in 0..random.below(5) + 1 {
        let mut text: Vec<u8> = Vec::new();
        let eol = |random: &mut Random| -> &'static str {
            random.pick(&["\n", "\n", "\r\n", "  \n", "\t\n", "\x01\n"])
        };
        if random.below(4) == 0 {
            text.extend_from_slice(
                random
                    .pick(&["junk\n", "-----BEGIN-----\n", "\u{feff}", "\n"])
                    .as_bytes(),
            );
        }
        let name = random.pick(&["X", "CERTIFICATE", "A B", "", "Y"]);
        text.extend_from_slice(format!("-----BEGIN {name}-----").as_bytes());
        let e = eol(random);
        text.extend_from_slice(e.as_bytes());
        if random.below(3) == 0 {
            text.extend_from_slice(
                random
                    .pick(&["Proc-Type: 4,ENCRYPTED\n", "K: v\n", "Key:value\n"])
                    .as_bytes(),
            );
            if random.below(4) != 0 {
                text.push(b'\n');
            }
        }
        for _ in 0..random.below(4) {
            let len = match random.below(4) {
                0 => 64,
                1 => random.below(8) * 4,
                2 => random.below(70),
                _ => random.below(120),
            };
            for _ in 0..len {
                let c = match random.below(60) {
                    0 => b'=',
                    1 => *random
                        .pick(&["\u{0}", "*", " ", "\u{a0}"])
                        .as_bytes()
                        .first()
                        .unwrap_or(&b' '),
                    _ => B64
                        .get(usize::try_from(random.below(64)).unwrap_or(0))
                        .copied()
                        .unwrap_or(b'A'),
                };
                text.push(c);
            }
            let e = eol(random);
            text.extend_from_slice(e.as_bytes());
        }
        let end = if random.below(5) == 0 {
            random.pick(&["X", "Z", "CERTIFICATE"])
        } else {
            name
        };
        if random.below(8) != 0 {
            text.extend_from_slice(format!("-----END {end}-----").as_bytes());
            let e = eol(random);
            text.extend_from_slice(e.as_bytes());
        }
        if random.below(8) == 0 {
            let cut =
                usize::try_from(random.below(u64::try_from(text.len()).unwrap_or(1))).unwrap_or(0);
            text.truncate(cut);
        }
        text.truncate(256);
        let flags = random.pick(&["0", "2", "2", "4", "6"]);
        let hex: String = if text.is_empty() {
            "-".to_owned()
        } else {
            text.iter().map(|b| format!("{b:02x}")).collect()
        };
        writeln!(out, "pemread {flags} {hex}")?;
    }
    Ok(())
}

/// A random session of time commands: UTCTime and GeneralizedTime text near the valid forms
/// (field values at their limits, leap days, fractions, offsets, cut short, stray characters),
/// strict or not; and times and offsets around the edges of both types and of 9999.
fn time_session(random: &mut Random, out: &mut String) -> Result {
    let hex = |bytes: &[u8]| -> String {
        if bytes.is_empty() {
            "-".to_owned()
        } else {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }
    };
    for _ in 0..1 + random.below(20) {
        if random.below(3) == 0 {
            let when = match random.below(4) {
                0 => random
                    .pick(&[
                        "0",
                        "-1",
                        "2524607999",
                        "2524608000",
                        "-631152000",
                        "-631152001",
                        "253402300799",
                        "253402300800",
                    ])
                    .to_owned(),
                1 => (random.next() % 5_000_000_000).to_string(),
                2 => format!("-{}", random.next() % 3_000_000_000),
                _ => (random.next() % 300_000_000_000).to_string(),
            };
            let days = i64::try_from(random.below(80_000)).unwrap_or(0) - 40_000;
            let secs = match random.below(3) {
                0 => 0,
                1 => i64::try_from(random.below(200_000)).unwrap_or(0) - 100_000,
                _ => i64::try_from(random.below(2_000_000_000)).unwrap_or(0) - 1_000_000_000,
            };
            writeln!(out, "asntimet {when} {days} {secs}")?;
            continue;
        }
        let generalized = random.below(2) == 0;
        let two = |random: &mut Random, max: u64| format!("{:02}", random.below(max + 2));
        let mut text = String::new();
        if generalized {
            text.push_str(random.pick(&["19", "20", "99", "00", "16", "17", "24"]));
        }
        text.push_str(random.pick(&["24", "49", "50", "99", "00", "23"]));
        text.push_str(&two(random, 12));
        text.push_str(random.pick(&["01", "28", "29", "30", "31", "00", "32"]));
        text.push_str(&two(random, 23));
        text.push_str(&two(random, 59));
        if random.below(5) != 0 {
            text.push_str(&two(random, 59));
        }
        if generalized && random.below(4) == 0 {
            text.push('.');
            for _ in 0..random.below(4) {
                text.push(char::from(
                    b'0' + u8::try_from(random.below(10)).unwrap_or(0),
                ));
            }
        }
        text.push_str(random.pick(&[
            "Z", "Z", "Z", "+0000", "-0130", "+1200", "+1300", "-0060", "+01", "", "ZZ", "z",
        ]));
        if random.below(8) == 0 {
            let cut =
                usize::try_from(random.below(u64::try_from(text.len()).unwrap_or(1))).unwrap_or(0);
            text.truncate(cut);
        }
        let kind = random.pick(&["23", "24", "23", "24", "4"]);
        let flags = random.pick(&["0", "0", "100"]);
        writeln!(out, "asntime {kind} {flags} {}", hex(text.as_bytes()))?;
    }
    Ok(())
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
        match random.below(13) {
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
        let first = random_sessions(42, 300).unwrap();
        assert_eq!(first, random_sessions(42, 300).unwrap());
        assert_ne!(first, random_sessions(43, 300).unwrap());
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
            "\nobjtxt ",
            "\nasnhdr ",
            "\nasnint ",
            "\nasntext ",
            "\nasntime",
            "\nasnany",
            "\nasnd2i",
            "\nasnbio",
            "\nasnparse",
            "\nasns2i",
            "\nb64enc",
            "\nb64dec",
            "\nb64bio",
            "\npemread",
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
