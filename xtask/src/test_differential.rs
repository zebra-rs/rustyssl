//! `cargo xtask test-differential [--random N] [--seed S] [--only ...] [--duration T]`:
//! differential testing
//! (TEST_PLAN.md, layer L5).
//!
//! The probe (`tests/differential/probe.c`) reads commands on stdin and prints what the library
//! did. It is compiled once and linked against the reference OpenSSL, then fed the same input on
//! the reference and on rustyssl, and the outputs must match line for line. Unlike the C
//! conformance tests, nothing states the expected result: the reference is the oracle.
//!
//! Inputs are the files in `tests/differential/corpus/` plus `N` (default 200) random command
//! sessions. The random seed is printed, and `--seed` replays a run. `--only` draws the
//! sessions from some generators (`evp`: the EVP family). `--duration` runs a campaign instead
//! (milestone M1's long EVP run): rounds of `N` sessions from successive seeds on `--jobs`
//! workers until the time is up or a round differs, whose input is kept and replay printed.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::test_c::{compile, execute_with_input, prepare};
use crate::util::{Result, fresh_dir, target_dir, workspace_root};

pub fn run(args: &[String]) -> Result {
    let options = parse_args(args)?;
    let only = resolve(&options.only)?;
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
    let libs = Libraries {
        probe,
        reference: reference.join("lib"),
        ours: dist.join("lib"),
    };
    if let Some(duration) = options.duration {
        return campaign(&libs, &work, &options, &only, duration);
    }

    let mut inputs: Vec<PathBuf> = fs::read_dir(root.join("tests/differential/corpus"))?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<std::io::Result<_>>()?;
    inputs.sort();
    let random = work.join(format!("random-seed-{}.txt", options.seed));
    fs::write(
        &random,
        random_sessions(options.seed, options.sessions, &only)?,
    )?;
    inputs.push(random);
    println!(
        "Random sessions: {}, seed {} (replay with --seed {})",
        options.sessions, options.seed, options.seed
    );

    let mut failures = 0;
    for input in &inputs {
        let name = input
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        match compare(&libs, input, &work)? {
            Ok(lines) => println!("PASS {name}: {lines} lines identical"),
            Err(problem) => {
                failures += 1;
                println!("FAIL {name}: {problem}");
            }
        }
    }
    if failures == 0 {
        Ok(())
    } else {
        Err(format!("{failures} differential input(s) differ").into())
    }
}

/// The probe and the two library directories it runs with.
struct Libraries {
    probe: PathBuf,
    reference: PathBuf,
    ours: PathBuf,
}

/// Runs `input` on both libraries (in `work`): the number of identical lines, or what differs.
fn compare(
    libs: &Libraries,
    input: &Path,
    work: &Path,
) -> Result<std::result::Result<usize, String>> {
    let theirs = execute_with_input(&libs.probe, &libs.reference, work, Some(input))?;
    let ours = execute_with_input(&libs.probe, &libs.ours, work, Some(input))?;
    let lines = theirs.stdout.lines().count();
    if !theirs.success {
        return Ok(Err(format!(
            "the reference probe exits with {}",
            theirs.status
        )));
    }
    if ours.stdout == theirs.stdout && ours.success {
        return Ok(Ok(lines));
    }
    let mismatch = ours
        .stdout
        .lines()
        .zip(theirs.stdout.lines())
        .enumerate()
        .find(|(_, (a, b))| a != b);
    Ok(Err(match mismatch {
        Some((i, (a, b))) => format!("line {}: reference `{b}`, rustyssl `{a}`", i + 1),
        None => format!(
            "rustyssl stopped after {} of {lines} lines ({}): {}",
            ours.stdout.lines().count(),
            ours.status,
            ours.stderr.trim()
        ),
    }))
}

/// `--duration`: rounds of `--random` sessions, each from the next seed, on every core until
/// the time is up or an input differs. A differing input is kept, and its replay printed.
fn campaign(
    libs: &Libraries,
    work: &Path,
    options: &Options,
    only: &[usize],
    duration: Duration,
) -> Result {
    let started = Instant::now();
    let deadline = started + duration;
    let next = AtomicU64::new(0);
    let rounds = AtomicU64::new(0);
    let failure: Mutex<Option<String>> = Mutex::new(None);
    let only_arg = if options.only.is_empty() {
        String::new()
    } else {
        format!(" --only {}", options.only.join(","))
    };
    println!(
        "Differential campaign: {duration:?} on {} worker(s), {} sessions a round from seed {}{only_arg}",
        options.jobs, options.sessions, options.seed
    );
    let failed = || {
        failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    };
    let fail = |message: String| {
        let mut slot = failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        slot.get_or_insert(message);
    };
    std::thread::scope(|scope| {
        for worker in 0..options.jobs {
            let (next, rounds, failed, fail, only_arg) =
                (&next, &rounds, &failed, &fail, &only_arg);
            scope.spawn(move || {
                let dir = work.join(format!("worker-{worker}"));
                if let Err(e) = fs::create_dir_all(&dir) {
                    fail(format!("{}: {e}", dir.display()));
                    return;
                }
                while Instant::now() < deadline && !failed() {
                    let seed = options
                        .seed
                        .wrapping_add(next.fetch_add(1, Ordering::Relaxed));
                    let input = dir.join(format!("random-seed-{seed}.txt"));
                    let outcome = random_sessions(seed, options.sessions, only)
                        .and_then(|text| Ok(fs::write(&input, text)?))
                        .and_then(|()| compare(libs, &input, &dir));
                    match outcome {
                        Ok(Ok(_)) => {
                            rounds.fetch_add(1, Ordering::Relaxed);
                            let _ = fs::remove_file(&input);
                        }
                        Ok(Err(problem)) => fail(format!(
                            "seed {seed}: {problem}\n  input kept: {}\n  replay: cargo xtask \
                             test-differential --random {} --seed {seed}{only_arg}",
                            input.display(),
                            options.sessions
                        )),
                        Err(e) => fail(format!("seed {seed}: {e}")),
                    }
                }
            });
        }
        // Progress, every ten minutes.
        let mut reported = Instant::now();
        while Instant::now() < deadline && !failed() {
            std::thread::sleep(Duration::from_secs(1));
            if reported.elapsed() >= Duration::from_secs(600) {
                reported = Instant::now();
                println!(
                    "  {:?}: {} rounds identical",
                    Duration::from_secs(started.elapsed().as_secs()),
                    rounds.load(Ordering::Relaxed)
                );
            }
        }
    });
    let rounds = rounds.load(Ordering::Relaxed);
    let elapsed = Duration::from_secs(started.elapsed().as_secs());
    match failure
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
    {
        Some(message) => {
            Err(format!("after {elapsed:?} and {rounds} identical rounds, {message}").into())
        }
        None => {
            println!(
                "{rounds} rounds ({} sessions) identical on both libraries in {elapsed:?}",
                rounds.saturating_mul(u64::try_from(options.sessions).unwrap_or(0))
            );
            Ok(())
        }
    }
}

/// The command line's settings.
#[derive(Debug, PartialEq)]
struct Options {
    /// Random sessions in a run (in each round, with `--duration`).
    sessions: usize,
    seed: u64,
    /// Session generators to draw from (`evp` for [`EVP_SESSIONS`]); all when empty.
    only: Vec<String>,
    duration: Option<Duration>,
    jobs: usize,
}

const USAGE: &str = "usage: cargo xtask test-differential [--random N] [--seed S] \
                     [--only NAME,...|evp] [--duration 90s|30m|24h] [--jobs N]";

fn parse_args(args: &[String]) -> Result<Options> {
    let mut options = Options {
        sessions: 200,
        seed: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(1, |d| d.as_secs()),
        only: Vec::new(),
        duration: None,
        jobs: std::thread::available_parallelism().map_or(4, std::num::NonZero::get),
    };
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let value = args.next().ok_or_else(|| format!("{arg} needs a value"))?;
        match arg.as_str() {
            "--random" => options.sessions = value.parse()?,
            "--seed" => options.seed = value.parse()?,
            "--only" => options.only = value.split(',').map(str::to_owned).collect(),
            "--duration" => options.duration = Some(parse_duration(value)?),
            "--jobs" => options.jobs = value.parse::<usize>()?.max(1),
            _ => return Err(USAGE.into()),
        }
    }
    Ok(options)
}

/// `90s`, `30m`, `24h`, or seconds.
fn parse_duration(text: &str) -> Result<Duration> {
    let (number, unit) = match text.char_indices().last() {
        Some((at, 's')) => (text.get(..at), 1),
        Some((at, 'm')) => (text.get(..at), 60),
        Some((at, 'h')) => (text.get(..at), 3600),
        _ => (Some(text), 1),
    };
    let n: u64 = number.unwrap_or_default().parse()?;
    Ok(Duration::from_secs(
        n.checked_mul(unit).ok_or("duration too long")?,
    ))
}

/// The indexes in [`SESSIONS`] of the generators `names` picks.
fn resolve(names: &[String]) -> Result<Vec<usize>> {
    let mut indexes = Vec::new();
    for name in names {
        let wanted: Vec<&str> = if name == "evp" {
            EVP_SESSIONS.to_vec()
        } else {
            vec![name.as_str()]
        };
        for w in wanted {
            let i = SESSIONS
                .iter()
                .position(|(n, _)| *n == w)
                .ok_or_else(|| format!("no session generator `{w}`"))?;
            if !indexes.contains(&i) {
                indexes.push(i);
            }
        }
    }
    Ok(indexes)
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

/// A session generator: appends one session's commands.
type Session = fn(&mut Random, &mut String) -> Result;

/// The session generators by name, in the order a seed picks them from (keep it: a seed
/// replays only with the same table).
const SESSIONS: &[(&str, Session)] = &[
    ("err", err_session),
    ("buf_mem", buf_mem_session),
    ("stack", stack_session),
    ("lhash", lhash_session),
    ("bio", bio_session),
    ("printf", printf_session),
    ("addr", addr_session),
    ("obj", obj_session),
    ("asn", asn_session),
    ("int", int_session),
    ("text", text_session),
    ("time", time_session),
    ("any", any_session),
    ("d2i", d2i_session),
    ("s2i", s2i_session),
    ("base64", base64_session),
    ("pem", pem_session),
    ("params", params_session),
    ("ctx", ctx_session),
    ("prop", prop_session),
    ("prov", prov_session),
    ("fetch", fetch_session),
    ("digest", digest_session),
    ("cipher", cipher_session),
    ("mac", mac_session),
    ("kdf", kdf_session),
    ("rand", rand_session),
    ("bn", bn_session),
    ("pkey", pkey_session),
    ("meth", meth_session),
    ("lowlevel_hash", lowlevel_hash_session),
    ("lowlevel_aes", lowlevel_aes_session),
    ("lowlevel_aead", lowlevel_aead_session),
    ("lowlevel_des", lowlevel_des_session),
    ("lowlevel_legacy", lowlevel_legacy_session),
    ("lowlevel_ciphers", lowlevel_ciphers_session),
    ("bio_evp", bio_evp_session),
    ("skey", skey_session),
    ("md_meth", md_meth_session),
    ("cipher_meth", cipher_meth_session),
    ("conf", conf_session),
    ("conf_modules", conf_modules_session),
    ("ec", ec_session),
    ("ecpk", ecpk_session),
    ("eckey", eckey_session),
    ("ecdsa", ecdsa_session),
    ("eckm", eckm_session),
    ("ecsig", ecsig_session),
    ("ecdhx", ecdhx_session),
    ("sm2sig", sm2sig_session),
    ("sm2enc", sm2enc_session),
    ("ecxkm", ecxkm_session),
    ("ecxop", ecxop_session),
    ("mlkemkm", mlkemkm_session),
    ("mlkem", mlkem_session),
    ("mldsakm", mldsakm_session),
    ("mldsa", mldsa_session),
    ("slhdsakm", slhdsakm_session),
    ("string", string_session),
];

/// The sessions `--only evp` stands for: the EVP API, its methods, and the low-level
/// functions over the same algorithms (TEST_PLAN.md, milestone M1).
const EVP_SESSIONS: &[&str] = &[
    "fetch",
    "digest",
    "cipher",
    "mac",
    "kdf",
    "rand",
    "pkey",
    "meth",
    "lowlevel_hash",
    "lowlevel_aes",
    "lowlevel_aead",
    "lowlevel_des",
    "lowlevel_legacy",
    "lowlevel_ciphers",
    "bio_evp",
    "skey",
    "md_meth",
    "cipher_meth",
];

/// Random command sessions in the probe's language: `count` of them, from every generator,
/// or only from those at the indexes in `only`.
fn random_sessions(seed: u64, count: usize, only: &[usize]) -> Result<String> {
    let mut random = Random::new(seed);
    let mut out = String::new();
    let all = u64::try_from(SESSIONS.len()).unwrap_or(1);
    for session in 0..count {
        writeln!(out, "# session {session}")?;
        let index = if only.is_empty() {
            usize::try_from(random.below(all)).unwrap_or(0)
        } else {
            let i = random.below(u64::try_from(only.len()).unwrap_or(1));
            only.get(usize::try_from(i).unwrap_or(0))
                .copied()
                .unwrap_or(0)
        };
        let (_, generate) = SESSIONS.get(index).ok_or("no such session")?;
        generate(&mut random, &mut out)?;
    }
    Ok(out)
}

/// A random session of the deprecated low-level hashes: one or two algorithms' contexts
/// initialized, updated around their block sizes, transformed, given other digest lengths,
/// paddings, and bit counts near a carry, and finalized (also twice, and before an init);
/// Whirlpool also by bits; and the one-shots.
fn lowlevel_hash_session(random: &mut Random, out: &mut String) -> Result {
    const ALGS: &[&str] = &[
        "sha1", "sha224", "sha256", "sha384", "sha512", "md4", "md5", "rmd160", "mdc2", "wp",
    ];
    let algs = [random.pick(ALGS), random.pick(ALGS)];
    let length = |random: &mut Random| -> u64 {
        match random.below(4) {
            0 => random.below(9),
            1 => random
                .pick(&[
                    "55", "56", "63", "64", "65", "111", "112", "119", "120", "127", "128",
                ])
                .parse()
                .unwrap_or(0),
            _ => random.below(400),
        }
    };
    for alg in algs {
        if random.below(8) != 0 {
            writeln!(out, "llinit {alg}")?;
        }
    }
    for _ in 0..random.below(20) + 1 {
        let [first, second] = algs;
        let alg = if random.below(2) == 0 { first } else { second };
        match random.below(14) {
            0..=4 => writeln!(out, "llupdate {alg} {}", length(random))?,
            5 => {
                let bits = match random.below(3) {
                    0 => random.below(17),
                    1 => random.below(1100),
                    _ => 8 * random.below(70),
                };
                writeln!(out, "llbits {bits}")?;
            }
            6 => writeln!(out, "lltransform {alg} {}", random.below(1024))?,
            7 => {
                let len = random.pick(&["0", "3", "20", "23", "28", "32", "33", "48", "64", "65"]);
                writeln!(out, "llset {alg} md_len {len}")?;
            }
            8 => writeln!(out, "llset {alg} pad_type {}", random.below(4))?,
            9 => writeln!(out, "llset {alg} Nl {}", 1 + random.below(2000))?,
            10 => writeln!(out, "llone {alg} {}", length(random))?,
            11 => writeln!(out, "llinit {alg}")?,
            _ => writeln!(out, "llfinal {alg}")?,
        }
    }
    for alg in algs {
        writeln!(out, "llfinal {alg}")?;
    }
    Ok(())
}

/// A random session of the deprecated AES functions and the block-mode helpers: keys of each
/// size (and refused ones), IVs (some a few blocks before the 32-bit counter wraps), positions,
/// single blocks, the modes in pieces around the block size, the key wraps, ciphertext
/// stealing, and CTR both ways.
fn lowlevel_aes_session(random: &mut Random, out: &mut String) -> Result {
    let length = |random: &mut Random| -> u64 {
        match random.below(4) {
            0 => random.below(4),
            1 => random
                .pick(&["15", "16", "17", "31", "32", "33", "48"])
                .parse()
                .unwrap_or(0),
            _ => random.below(200),
        }
    };
    let bits = random.pick(&["128", "192", "256"]);
    writeln!(out, "aeskey {bits}")?;
    writeln!(out, "aesiv")?;
    for _ in 0..random.below(20) + 1 {
        match random.below(12) {
            0 => writeln!(
                out,
                "aeskey {}",
                random.pick(&["128", "192", "256", "0", "64", "255"])
            )?,
            1 => {
                if random.below(2) == 0 {
                    writeln!(out, "aesiv")?;
                } else {
                    writeln!(out, "aesiv {}", 1 + random.below(4))?;
                }
            }
            2 => writeln!(out, "aesnum {}", random.offset(-3, 19))?,
            3 => writeln!(
                out,
                "aesblock {}",
                random.pick(&["enc", "dec", "ecb0", "ecb1", "ecb9"])
            )?,
            4..=6 => {
                let mode = random.pick(&["cbc", "cfb128", "cfb8", "cfb1", "ofb", "ige", "biige"]);
                let enc = random.below(2);
                let len = if mode == "cfb1" {
                    random.below(70)
                } else {
                    length(random)
                };
                writeln!(out, "aesmode {mode} {enc} {len}")?;
            }
            7 => {
                let form = random.pick(&["wrap", "wrap_pad", "aes"]);
                let len = match random.below(3) {
                    0 => random.below(30),
                    1 => 8 * random.below(8),
                    _ => random.below(120),
                };
                writeln!(out, "aeswrap {form} {} {len}", random.below(2))?;
            }
            8 | 9 => writeln!(
                out,
                "cts {} {}",
                random.pick(&["cts", "nistcts"]),
                length(random)
            )?,
            _ => writeln!(
                out,
                "ctr {} {}",
                random.pick(&["block", "ctr32"]),
                length(random)
            )?,
        }
    }
    Ok(())
}

/// A random session of the AEAD helpers: GCM (IVs of any length, AAD and data in pieces
/// through the block and the CTR function, AAD after data, tags read and checked, finishes
/// repeated), CCM (tag and length field sizes, nonces, matching and mismatched lengths, both
/// functions), OCB (with and without a bulk function, copies, bad nonce and tag lengths), and
/// XTS.
fn lowlevel_aead_session(random: &mut Random, out: &mut String) -> Result {
    let length = |random: &mut Random| -> u64 {
        match random.below(4) {
            0 => random.below(4),
            1 => random
                .pick(&["15", "16", "17", "31", "32", "33", "48"])
                .parse()
                .unwrap_or(0),
            _ => random.below(200),
        }
    };
    match random.below(4) {
        0 => {
            writeln!(out, "gcminit")?;
            writeln!(
                out,
                "gcmiv {}",
                random.pick(&["12", "12", "1", "16", "60", "0"])
            )?;
            for _ in 0..random.below(15) + 1 {
                let ctr = if random.below(2) == 0 { "" } else { " ctr" };
                match random.below(9) {
                    0 | 1 => writeln!(out, "gcmaad {}", length(random))?,
                    2..=4 => writeln!(out, "gcmenc {}{ctr}", length(random))?,
                    5 => writeln!(out, "gcmdec {}{ctr}", length(random))?,
                    6 => writeln!(out, "gcmtag {}", random.below(18))?,
                    7 => writeln!(out, "gcmfinish {}", random.below(18))?,
                    _ => writeln!(out, "gcmiv {}", random.below(40))?,
                }
            }
            writeln!(out, "gcmtag 16")?;
        }
        1 => {
            let m = random.pick(&["4", "6", "8", "10", "12", "14", "16", "3", "0"]);
            let l = random.pick(&["2", "3", "4", "8", "1", "0"]);
            writeln!(out, "ccminit {m} {l}")?;
            for _ in 0..random.below(4) + 1 {
                let len = length(random);
                let mlen = if random.below(5) == 0 {
                    length(random)
                } else {
                    len
                };
                writeln!(out, "ccmiv {} {mlen}", 6 + random.below(11))?;
                if random.below(2) == 0 {
                    writeln!(out, "ccmaad {}", random.below(300))?;
                }
                let stream = if random.below(2) == 0 { "" } else { " stream" };
                writeln!(out, "ccm{} {len}{stream}", random.pick(&["enc", "dec"]))?;
                writeln!(out, "ccmtag {}", random.below(18))?;
            }
        }
        2 => {
            writeln!(out, "ocbinit {}", random.below(2))?;
            writeln!(out, "ocbiv {} {}", random.below(17), random.below(18))?;
            for _ in 0..random.below(10) + 1 {
                // Whole blocks until the last call.
                let len = 16 * random.below(12);
                match random.below(7) {
                    0 => writeln!(out, "ocbaad {len}")?,
                    1 | 2 => writeln!(out, "ocbenc {len}")?,
                    3 => writeln!(out, "ocbdec {len}")?,
                    4 => writeln!(out, "ocbcopy")?,
                    5 => writeln!(out, "ocbtag {}", random.below(18))?,
                    _ => writeln!(out, "ocbfinish {}", random.below(18))?,
                }
            }
            writeln!(
                out,
                "ocb{} {}",
                random.pick(&["enc", "dec", "aad"]),
                random.below(20)
            )?;
            writeln!(out, "ocbtag 16")?;
        }
        _ => {
            for _ in 0..random.below(5) + 1 {
                writeln!(out, "xts {} {}", random.below(2), length(random))?;
            }
        }
    }
    Ok(())
}

/// A random session of the deprecated DES functions: keys (checked, unchecked, weak and with
/// parity errors as they come), IVs, positions, every mode around the block size and bit
/// widths (CFB widths out of range included; triple-DES CFB and OFB only in range, since
/// OpenSSL loops without end or shifts by too much otherwise), the checksums, the string to
/// key functions, and crypt(3) with salts good and bad.
fn lowlevel_des_session(random: &mut Random, out: &mut String) -> Result {
    let length = |random: &mut Random| -> u64 {
        match random.below(4) {
            0 => random.below(4),
            1 => random
                .pick(&["7", "8", "9", "15", "16", "17", "24"])
                .parse()
                .unwrap_or(0),
            _ => random.below(120),
        }
    };
    writeln!(out, "deskey")?;
    writeln!(out, "desiv")?;
    for _ in 0..random.below(15) + 1 {
        match random.below(12) {
            0 => writeln!(out, "deskey")?,
            1 => writeln!(out, "desiv")?,
            2 => writeln!(out, "desnum {}", random.offset(-20, 40))?,
            3..=6 => {
                let mode = random.pick(&[
                    "ecb",
                    "ecb3",
                    "cbc",
                    "ncbc",
                    "xcbc",
                    "pcbc",
                    "ede3cbc",
                    "cfb",
                    "ede3cfb",
                    "ofb",
                    "cfb64",
                    "ede3cfb64",
                    "ofb64",
                    "ede3ofb64",
                ]);
                let bits = match mode {
                    "cfb" => random.offset(-2, 70),
                    "ede3cfb" | "ofb" => random.offset(1, 64),
                    _ => 0,
                };
                let len = if mode == "ofb" {
                    random.below(12)
                } else {
                    length(random)
                };
                writeln!(out, "desmode {mode} {} {len} {bits}", random.below(2))?;
            }
            7 => writeln!(out, "descksum {} {}", length(random), random.offset(-1, 7))?,
            8 => writeln!(out, "desstr {}", random.below(50))?,
            _ => {
                let salt = |random: &mut Random| match random.below(5) {
                    0 => random.below(256),
                    _ => random
                        .pick(&["97", "122", "65", "90", "48", "57", "46", "47"])
                        .parse()
                        .unwrap_or(97),
                };
                writeln!(
                    out,
                    "descrypt {} {} {}",
                    random.below(12),
                    salt(random),
                    salt(random)
                )?;
            }
        }
    }
    Ok(())
}

/// A random session of the deprecated Blowfish, CAST, RC2, and RC4 functions: keys of every
/// length the setters cap or treat specially (RC2 with any effective bit count), IVs,
/// positions, the four block modes around the block size, and RC4 in pieces.
fn lowlevel_legacy_session(random: &mut Random, out: &mut String) -> Result {
    let length = |random: &mut Random| -> u64 {
        match random.below(4) {
            0 => random.below(4),
            1 => random
                .pick(&["7", "8", "9", "15", "16", "17"])
                .parse()
                .unwrap_or(0),
            _ => random.below(100),
        }
    };
    writeln!(out, "lgkey bf {}", 1 + random.below(80))?;
    writeln!(out, "lgkey cast {}", random.below(20))?;
    writeln!(
        out,
        "lgkey rc2 {} {}",
        1 + random.below(140),
        random.offset(-10, 1100)
    )?;
    writeln!(out, "lgiv")?;
    writeln!(out, "rc4key {}", 1 + random.below(300))?;
    for _ in 0..random.below(15) + 1 {
        let cipher = random.pick(&["bf", "cast", "rc2"]);
        match random.below(10) {
            0 => writeln!(
                out,
                "lgkey {cipher} {} {}",
                random.offset(-2, 140),
                random.offset(-10, 1100)
            )?,
            1 => writeln!(out, "lgiv")?,
            2 => writeln!(out, "lgnum {}", random.offset(-20, 40))?,
            3..=6 => {
                let mode = random.pick(&["ecb", "cbc", "cfb64", "ofb64"]);
                writeln!(
                    out,
                    "lgmode {cipher} {mode} {} {}",
                    random.below(2),
                    length(random)
                )?;
            }
            7 => writeln!(out, "rc4key {}", 1 + random.below(300))?,
            _ => writeln!(out, "rc4 {}", length(random))?,
        }
    }
    Ok(())
}

/// A random session of the deprecated IDEA, SEED, and Camellia functions: keys of each size
/// (Camellia's refused ones too), IDEA decryption schedules from arbitrary words and in place,
/// IVs, positions, and every mode around the block sizes.
fn lowlevel_ciphers_session(random: &mut Random, out: &mut String) -> Result {
    let length = |random: &mut Random| -> u64 {
        match random.below(4) {
            0 => random.below(4),
            1 => random
                .pick(&["7", "8", "9", "15", "16", "17", "31", "32", "33"])
                .parse()
                .unwrap_or(0),
            _ => random.below(100),
        }
    };
    let bits = |random: &mut Random| -> String {
        if random.below(8) == 0 {
            random.offset(-10, 300).to_string()
        } else {
            random.pick(&["128", "192", "256"]).to_string()
        }
    };
    writeln!(out, "ckey idea")?;
    writeln!(out, "ckey seed")?;
    writeln!(out, "ckey camellia {}", random.pick(&["128", "192", "256"]))?;
    writeln!(out, "civ")?;
    for _ in 0..random.below(15) + 1 {
        match random.below(12) {
            0 => {
                let which = random.pick(&["idea", "idea-odd", "idea-inplace", "seed"]);
                writeln!(out, "ckey {which}")?;
            }
            1 => writeln!(out, "ckey camellia {}", bits(random))?,
            2 => writeln!(out, "civ")?,
            3 => writeln!(out, "cnum {}", random.offset(-5, 21))?,
            4 => writeln!(out, "cwords")?,
            _ => {
                let (cipher, mode) = match random.below(3) {
                    0 => ("idea", random.pick(&["ecb", "cbc", "cfb64", "ofb64"])),
                    1 => ("seed", random.pick(&["ecb", "cbc", "cfb128", "ofb128"])),
                    _ => (
                        "camellia",
                        random.pick(&["ecb", "cbc", "cfb128", "ofb128", "cfb1", "cfb8", "ctr"]),
                    ),
                };
                writeln!(
                    out,
                    "cmode {cipher} {mode} {} {}",
                    random.below(2),
                    length(random)
                )?;
            }
        }
    }
    Ok(())
}

/// A random session of the EVP filter BIOs: digests and ciphers (block, stream, and AEAD) over
/// lengths around their blocks, written and read in pieces of every size, some ciphertexts
/// corrupted.
fn bio_evp_session(random: &mut Random, out: &mut String) -> Result {
    let length = |random: &mut Random| -> u64 {
        match random.below(4) {
            0 => random.below(4),
            1 => random
                .pick(&[
                    "15", "16", "17", "31", "32", "33", "255", "256", "257", "1024",
                ])
                .parse()
                .unwrap_or(0),
            _ => random.below(2001),
        }
    };
    let piece = |random: &mut Random| -> u64 {
        match random.below(3) {
            0 => 1 + random.below(16),
            1 => random
                .pick(&["255", "256", "257", "288", "300", "4096", "4097", "4999"])
                .parse()
                .unwrap_or(1),
            _ => 1 + random.below(2000),
        }
    };
    for _ in 0..random.below(8) + 1 {
        match random.below(4) {
            0 | 1 => {
                let digest = random.pick(&[
                    "sha256",
                    "sha1",
                    "md5",
                    "sha512",
                    "sha3-256",
                    "sha224",
                    "sha512-256",
                    "blake2b512",
                    "sm3",
                    "shake128",
                ]);
                let command = if random.below(2) == 0 {
                    "bmd"
                } else {
                    "bmdread"
                };
                writeln!(
                    out,
                    "{command} {digest} {} {}",
                    length(random),
                    piece(random)
                )?;
            }
            _ => {
                let cipher = random.pick(&[
                    "aes-128-cbc",
                    "aes-256-cbc",
                    "aes-128-ecb",
                    "aes-256-ctr",
                    "aes-128-cfb8",
                    "aes-192-ofb",
                    "des-ede3-cbc",
                    "chacha20",
                    "camellia-128-cbc",
                    "aes-128-gcm",
                    "aria-256-cbc",
                ]);
                if random.below(2) == 0 {
                    writeln!(out, "benc {cipher} {} {}", length(random), piece(random))?;
                } else {
                    writeln!(
                        out,
                        "bdec {cipher} {} {} {}",
                        length(random),
                        piece(random),
                        u64::from(random.below(5) == 0)
                    )?;
                }
            }
        }
    }
    Ok(())
}

/// A random session of opaque symmetric keys: each key type (and unknown ones) at lengths
/// around AES's, imported and used with ciphers that take key objects or raw keys, with IVs of
/// right and wrong lengths.
fn skey_session(random: &mut Random, out: &mut String) -> Result {
    let types = ["AES", "GENERIC-SECRET", "aes", "HMAC", "NO-SUCH"];
    let ciphers = [
        "AES-128-CBC",
        "AES-256-CBC",
        "AES-192-ECB",
        "AES-128-CTR",
        "AES-128-GCM",
        "AES-256-OFB",
        "ARIA-128-CBC",
        "CAMELLIA-256-CFB",
        "CHACHA20",
        "DES-EDE3-CBC",
        "NO-SUCH",
    ];
    let length = |random: &mut Random| -> u64 {
        match random.below(3) {
            0 => random.pick(&["16", "24", "32"]).parse().unwrap_or(16),
            1 => random.below(65),
            _ => random
                .pick(&["0", "1", "15", "17", "31", "33", "64"])
                .parse()
                .unwrap_or(0),
        }
    };
    for _ in 0..random.below(8) + 1 {
        let kind = random.pick(&types);
        if random.below(3) == 0 {
            writeln!(out, "symkey {kind} {}", length(random))?;
        } else {
            let cipher = random.pick(&ciphers);
            let ivlen = random.pick(&["0", "8", "12", "16", "16", "16", "7"]);
            writeln!(
                out,
                "symkeyenc {cipher} {kind} {} {ivlen} {}",
                length(random),
                random.below(2)
            )?;
        }
    }
    Ok(())
}

/// A random session of application-defined digests: copies of the static digests given their
/// state's size, over lengths around their blocks, in pieces of every size.
fn md_meth_session(random: &mut Random, out: &mut String) -> Result {
    let names = [
        "MD4",
        "MD5",
        "SHA1",
        "SHA224",
        "SHA256",
        "SHA384",
        "SHA512",
        "SHA512-224",
        "SHA512-256",
        "RIPEMD160",
        "MDC2",
        "WHIRLPOOL",
        "MD5-SHA1",
    ];
    for _ in 0..random.below(8) + 1 {
        let len = match random.below(3) {
            0 => random
                .pick(&[
                    "0", "1", "55", "56", "63", "64", "65", "111", "112", "127", "128", "129",
                ])
                .parse()
                .unwrap_or(0),
            _ => random.below(1001),
        };
        writeln!(
            out,
            "mdcopy {} {len} {}",
            random.pick(&names),
            1 + random.below(200)
        )?;
    }
    Ok(())
}

/// A random session of application-defined ciphers: a toy cipher of each mode, block size,
/// and combination of the flags it takes, over lengths around its blocks, in pieces of every
/// size, padded or not, its ciphertext tampered with or not.
fn cipher_meth_session(random: &mut Random, out: &mut String) -> Result {
    let flags = [0x8u32, 0x10, 0x20, 0x40, 0x80, 0x400, 0x800];
    for _ in 0..random.below(8) + 1 {
        let mut f = 0;
        for bit in flags {
            if random.below(4) == 0 {
                f |= bit;
            }
        }
        let bs = random.pick(&["1", "8", "16"]);
        let len = match random.below(3) {
            0 => random
                .pick(&["0", "1", "7", "8", "9", "15", "16", "17", "31", "32", "33"])
                .parse()
                .unwrap_or(0),
            _ => random.below(513),
        };
        let tamper = if random.below(3) == 0 {
            random.below(600).to_string()
        } else {
            "-1".to_owned()
        };
        writeln!(
            out,
            "cmeth {} {bs} {f:x} {len} {} {} {tamper}",
            random.pick(&["stream", "ecb", "cbc", "cfb", "ofb", "ctr"]),
            1 + random.below(40),
            random.below(2),
        )?;
    }
    Ok(())
}

/// A random session of configuration files: texts of lines picked from the grammar's pieces
/// (sections, names, quotes, escapes, references, pragmas, includes of missing files, and
/// malformed lines), joined with LF, CR LF, or continuations, with stray octets, read with
/// either method.
fn conf_session(random: &mut Random, out: &mut String) -> Result {
    const NAMES: &[&str] = &["a", "b", "x_1", "s.t", "c$", "k-v", "ENV", "default", ""];
    const VALUES: &[&str] = &[
        "1",
        "v w",
        "'q # q'",
        "\"d\"\"e\"",
        "\\n\\t\\x\\\\",
        "$a",
        "${a}",
        "$(b)",
        "$s::a",
        "${s::x_1}",
        "$ENV::RUSTYSSL_PROBE_NONE",
        "${a",
        "$",
        "$a$b",
        "# comment",
        "; semi",
        "'open",
        "\"open",
        "tail\\",
        "\u{e9}",
    ];
    for _ in 0..random.below(6) + 1 {
        let mut text: Vec<u8> = Vec::new();
        if random.below(10) == 0 {
            text.extend_from_slice(b"\xef\xbb\xbf");
        }
        for _ in 0..random.below(10) + 1 {
            let name = random.pick(NAMES);
            let line = match random.below(14) {
                0 => format!(
                    "[{}]",
                    random.pick(&["s", " s ", "a b", "", "t", "s", "ENV"])
                ),
                1 => format!("[{}", random.pick(&["s", "a b c", ""])),
                2 => format!("# {}", random.pick(VALUES)),
                3 => format!(
                    ".pragma {}",
                    random.pick(&[
                        "dollarid:on",
                        "dollarid:off",
                        "= dollarid : TRUE",
                        "abspath:on",
                        "includedir:/nonexistent",
                        "dollarid",
                        ":on",
                        "unknown:1",
                    ])
                ),
                4 => format!(
                    ".include {}",
                    random.pick(&["/nonexistent/x.cnf", "missing.cnf", "= $a", ""])
                ),
                5 => format!("s::{name} = {}", random.pick(VALUES)),
                6 => format!("{name} {}", random.pick(VALUES)),
                7 => String::new(),
                _ => format!(
                    "{}{name}{}={}{}",
                    random.pick(&["", " ", "\t"]),
                    random.pick(&["", " "]),
                    random.pick(&["", " "]),
                    random.pick(VALUES)
                ),
            };
            text.extend_from_slice(line.as_bytes());
            if random.below(20) == 0 {
                text.push(pick_octet(random, &[0, 0x80, b'\r', b'\\']));
            }
            text.extend_from_slice(
                random
                    .pick(&["\n", "\n", "\n", "\r\n", "\\\n", ""])
                    .as_bytes(),
            );
        }
        text.truncate(500);
        let hex: String = if text.is_empty() {
            "-".to_owned()
        } else {
            text.iter().map(|b| format!("{b:02x}")).collect()
        };
        writeln!(
            out,
            "cnf {} {hex}",
            if random.below(5) == 0 { "w" } else { "d" }
        )?;
    }
    Ok(())
}

/// A random session of configuration modules: an `openssl_conf` section of modules picked
/// from the built-in ones (and unknown ones), each with a section of settings, good and bad,
/// loaded into a new library context with random `CONF_MFLAGS_*`.
fn conf_modules_session(random: &mut Random, out: &mut String) -> Result {
    for _ in 0..random.below(4) + 1 {
        let mut text = String::new();
        if random.below(6) == 0 {
            writeln!(text, "config_diagnostics = {}", random.below(2))?;
        }
        text.push_str("openssl_conf = init\n");
        let mut modules = String::from("[init]\n");
        let mut sections = String::new();
        for i in 0..random.below(4) + 1 {
            let section = format!("s{i}");
            match random.below(9) {
                0 | 1 => {
                    writeln!(modules, "providers = {section}")?;
                    writeln!(sections, "[{section}]")?;
                    for j in 0..random.below(3) + 1 {
                        let name = random.pick(&["default", "base", "null", "nope", "x.base"]);
                        writeln!(sections, "{name} = {section}p{j}")?;
                        writeln!(sections, "[{section}p{j}]")?;
                        writeln!(
                            sections,
                            "activate = {}",
                            random.pick(&["1", "0", "yes", "maybe", "TRUE", "off"])
                        )?;
                        if random.below(3) == 0 {
                            writeln!(sections, "soft_load = {}", random.pick(&["1", "no"]))?;
                        }
                        if random.below(4) == 0 {
                            writeln!(
                                sections,
                                "identity = {}",
                                random.pick(&["base", "null", "nope"])
                            )?;
                        }
                        if random.below(4) == 0 {
                            writeln!(sections, "param = value")?;
                        }
                        writeln!(sections, "[{section}]")?;
                    }
                }
                2 => {
                    writeln!(modules, "alg_section = {section}")?;
                    writeln!(sections, "[{section}]")?;
                    writeln!(
                        sections,
                        "{}",
                        random.pick(&[
                            "default_properties = ?provider=base",
                            "default_properties = provider=default",
                            "default_properties = ?",
                            "default_properties = -fips",
                            "fips_mode = yes",
                            "fips_mode = n",
                            "fips_mode = maybe",
                            "foo = bar",
                        ])
                    )?;
                }
                3 => {
                    writeln!(modules, "ssl_conf = {section}")?;
                    writeln!(sections, "[{section}]")?;
                    if random.below(4) != 0 {
                        writeln!(sections, "sys = {section}c")?;
                        writeln!(sections, "[{section}c]")?;
                        if random.below(4) != 0 {
                            writeln!(sections, "CipherString = DEFAULT\n.MinProtocol = TLSv1.2")?;
                        }
                    }
                }
                4 => {
                    writeln!(modules, "random = {section}")?;
                    writeln!(sections, "[{section}]")?;
                    writeln!(
                        sections,
                        "{}",
                        random.pick(&[
                            "random = CTR-DRBG",
                            "cipher = AES-128-CTR",
                            "digest = SHA256",
                            "seed = SEED-SRC",
                            "SEED_PROPERTIES = x",
                            "random_provider = nosuch",
                            "foo = bar",
                        ])
                    )?;
                }
                5 => {
                    writeln!(modules, "stbl_section = {section}")?;
                    writeln!(sections, "[{section}]")?;
                    writeln!(
                        sections,
                        "{} = {}",
                        random.pick(&["commonName", "CN", "nosuchobject"]),
                        random.pick(&[
                            "min:1, max:64",
                            "mask:UTF8|PRINTABLE",
                            "flags:nomask",
                            "flags:none, min:0x2",
                            "max: 8 ",
                            "size:1",
                            "mask:foo",
                        ])
                    )?;
                }
                6 => {
                    writeln!(modules, "engines = {section}")?;
                    writeln!(sections, "[{section}]")?;
                    writeln!(sections, "e = {section}e")?;
                    writeln!(sections, "[{section}e]")?;
                    writeln!(
                        sections,
                        "{}",
                        random.pick(&[
                            "engine_id = foo",
                            "engine_id = foo\ninit = 0",
                            "soft_load = 1\nx = y",
                            "x = y",
                        ])
                    )?;
                }
                7 => writeln!(
                    modules,
                    "{} = {section}",
                    random.pick(&["nosuch", "providers", "random"])
                )?,
                _ => writeln!(modules, "alg_section = nosuch")?,
            }
        }
        text.push_str(&modules);
        text.push_str(&sections);
        let hex: String = text.bytes().take(500).map(|b| format!("{b:02x}")).collect();
        let flags = random.pick(&["0", "1", "4", "8", "9", "c", "2", "20"]);
        writeln!(out, "cmod {flags} {hex}")?;
    }
    Ok(())
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
        let item = random.below(19);
        let mut der = Vec::new();
        if item >= 14 && random.below(4) != 0 {
            rsa_ber(random, &mut der, item);
        } else {
            ber_value(random, &mut der, item, 0);
        }
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

/// Appends a TLV with a definite length (the short form, or the long one when it must be).
fn tlv(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else if len < 0x100 {
        out.extend([0x81, u8::try_from(len).unwrap_or(0)]);
    } else {
        out.extend([
            0x82,
            u8::try_from(len >> 8).unwrap_or(0),
            u8::try_from(len & 0xff).unwrap_or(0),
        ]);
    }
    out.extend(content);
}

/// Appends a random INTEGER: mostly short, sometimes empty, negative, or with leading zeros;
/// a version (`small`) is mostly 0, 1, or 2.
fn rsa_integer(random: &mut Random, out: &mut Vec<u8>, small: bool) {
    let content: Vec<u8> = if small && random.below(4) != 0 {
        vec![pick_octet(random, &[0, 1, 1, 2, 5, 0xff])]
    } else {
        let len = match random.below(6) {
            0 => 0,
            1 => 1,
            2 => 5,
            _ => random.below(14),
        };
        (0..len)
            .map(|_| u8::try_from(random.below(256)).unwrap_or(0))
            .collect()
    };
    tlv(out, 0x02, &content);
}

/// Appends a random AlgorithmIdentifier: a digest's, MGF1's, or pSpecified's OID, with NULL,
/// nothing, another AlgorithmIdentifier, or an OCTET STRING.
fn rsa_algor(random: &mut Random, out: &mut Vec<u8>, depth: u32) {
    let oids: [&[u8]; 4] = [
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08],
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x09],
        &[0x2b, 0x0e, 0x03, 0x02, 0x1a],
    ];
    let mut body = Vec::new();
    let which = usize::try_from(random.below(4)).unwrap_or(0);
    tlv(&mut body, 0x06, oids.get(which).copied().unwrap_or(&[]));
    match random.below(5) {
        0 => {}
        1 if depth == 0 => rsa_algor(random, &mut body, 1),
        2 => tlv(&mut body, 0x04, b"label"),
        _ => tlv(&mut body, 0x05, &[]),
    }
    tlv(out, 0x30, &body);
}

/// Appends BER near what RSA's items take (14 RSAPublicKey, 15 RSAPrivateKey, 16
/// RSA_PSS_PARAMS, 17 RSA_OAEP_PARAMS, 18 BIGNUM): their fields mostly in place, some missing,
/// replaced by other values, or followed by more, and a multi-prime key's list of other primes.
fn rsa_ber(random: &mut Random, out: &mut Vec<u8>, item: u64) {
    let mut body = Vec::new();
    match item {
        14 | 15 => {
            let count = if item == 14 { 2 } else { 9 };
            for i in 0..count {
                match random.below(20) {
                    0 => {}
                    1 => ber_value(random, &mut body, item, 2),
                    _ => rsa_integer(random, &mut body, item == 15 && i == 0),
                }
            }
            if item == 15 && random.below(3) == 0 {
                let mut list = Vec::new();
                for _ in 0..random.below(4) {
                    let mut info = Vec::new();
                    for _ in 0..3 - u32::from(random.below(8) == 0) {
                        rsa_integer(random, &mut info, false);
                    }
                    tlv(&mut list, 0x30, &info);
                }
                tlv(&mut body, 0x30, &list);
            }
            if random.below(10) == 0 {
                ber_value(random, &mut body, item, 2);
            }
        }
        16 | 17 => {
            let fields = if item == 16 { 4 } else { 3 };
            for tag in 0..fields {
                if random.below(3) == 0 {
                    continue;
                }
                let mut inner = Vec::new();
                if item == 16 && tag >= 2 {
                    rsa_integer(random, &mut inner, true);
                } else {
                    rsa_algor(random, &mut inner, 0);
                }
                let tag = if random.below(12) == 0 {
                    0xa5
                } else {
                    0xa0 | tag
                };
                tlv(&mut body, tag, &inner);
            }
        }
        _ => {
            rsa_integer(random, out, false);
            return;
        }
    }
    tlv(out, 0x30, &body);
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
            // Digest, signature, cipher, and non-algorithm NIDs. (A key type's name is in the
            // reference's name map, which pre-fills it, so looking one up doesn't fetch there;
            // until Phase 4 it does here.)
            15 => writeln!(
                out,
                "dnid {}",
                random.pick(&[
                    "4", "64", "672", "673", "674", "675", "1094", "1095", "1096", "1097", "1100",
                    "1101", "117", "95", "257", "804", "1143", "1056", "1057", "114", "668", "65",
                    "13", "0", "99999", "-1", "419", "421", "650", "904", "44", "1019", "895",
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

/// A random session of MAC commands on the probe's two contexts: HMAC, CMAC, and GMAC made by
/// name, initialized and set with random digests, ciphers (of every mode, so the wrong ones
/// too), properties, keys and IVs of lengths around the right ones, and the other parameters;
/// updates of lengths around the block sizes, finals into buffers of sizes around the MAC's,
/// XOF finals, sizes, copies, and one-shot MACs. (HMAC's TLS data size comes with step 3.5b.)
fn mac_session(random: &mut Random, out: &mut String) -> Result {
    const MACS: &[&str] = &[
        "HMAC",
        "CMAC",
        "GMAC",
        "hmac",
        "1.0.9797.3.4",
        "KMAC-128",
        "KMAC256",
        "2.16.840.1.101.3.4.2.19",
        "POLY1305",
        "SIPHASH",
        "BLAKE2BMAC",
        "BLAKE2SMAC",
        "KMAC-128x",
    ];
    const DIGESTS: &[&str] = &[
        "SHA1",
        "SHA224",
        "SHA256",
        "SHA384",
        "SHA512",
        "SHA512-224",
        "SHA3-256",
        "SHA3-512",
        "KECCAK-256",
        "SHAKE128",
        "BLAKE2s256",
        "BLAKE2b512",
        "SM3",
        "MD5",
        "MD5-SHA1",
        "RIPEMD160",
        "NULL",
        "nonesuch",
    ];
    const CIPHERS: &[&str] = &[
        "AES-128-CBC",
        "AES-192-CBC",
        "AES-256-CBC",
        "DES-EDE3-CBC",
        "ARIA-128-CBC",
        "CAMELLIA-256-CBC",
        "SM4-CBC",
        "AES-128-CBC-CTS",
        "AES-128-ECB",
        "AES-128-CTR",
        "AES-128-GCM",
        "AES-192-GCM",
        "AES-256-GCM",
        "ARIA-128-GCM",
        "AES-128-CCM",
        "ChaCha20-Poly1305",
        "nonesuch",
    ];
    let key_length = |random: &mut Random| -> u64 {
        match random.below(3) {
            0 => random.pick(&["16", "24", "32", "64"]).parse().unwrap_or(16),
            1 => {
                random.below(4)
                    + random
                        .pick(&["2", "14", "22", "30", "62"])
                        .parse()
                        .unwrap_or(14)
            }
            _ => random.below(200),
        }
    };
    let params = |random: &mut Random| -> String {
        let mut text = String::new();
        for _ in 0..random.below(3) {
            let param = match random.below(13) {
                0 | 1 => format!("digest={}", random.pick(DIGESTS)),
                2 | 3 => format!("cipher={}", random.pick(CIPHERS)),
                4 => format!("key={}", key_length(random)),
                5 | 6 => format!(
                    "iv={}",
                    random.pick(&["12", "12", "16", "1", "0", "13", "64"])
                ),
                7 => format!(
                    "properties={}",
                    random.pick(&["provider=default", "provider=nonesuch", "-fips", "?x"])
                ),
                // KMAC's, SipHash's, and the BLAKE2 MACs' (rounds kept small: OpenSSL runs
                // as many as asked for).
                9 => format!(
                    "{}={}",
                    random.pick(&["custom", "salt"]),
                    random.pick(&["0", "1", "8", "9", "16", "17", "21"])
                ),
                10 => format!(
                    "{}={}",
                    random.pick(&["c-rounds", "d-rounds"]),
                    random.below(6)
                ),
                11 => format!(
                    "size={}",
                    random.pick(&[
                        "0", "1", "8", "12", "16", "20", "32", "33", "64", "65", "100"
                    ])
                ),
                // HMAC's TLS mode: the record's whole length (data, MAC, padding).
                12 => format!(
                    "tls-data-size={}",
                    random.pick(&["0", "48", "64", "100", "300", "1000"])
                ),
                _ => random
                    .pick(&[
                        "tls-data-size=0",
                        "digest-noinit=1",
                        "digest-oneshot=0",
                        "xof=1",
                        "size=20",
                    ])
                    .to_owned(),
            };
            text.push(' ');
            text.push_str(&param);
        }
        text
    };
    let length = |random: &mut Random| -> u64 {
        match random.below(4) {
            0 => random.below(4),
            1 => random
                .pick(&[
                    "7", "8", "9", "13", "15", "16", "17", "63", "64", "65", "127", "128", "129",
                ])
                .parse()
                .unwrap_or(0),
            _ => random.below(600),
        }
    };
    for _ in 0..random.below(25) + 1 {
        match random.below(16) {
            0 | 1 => writeln!(out, "mnew {}", random.pick(MACS))?,
            2..=4 => {
                let key = if random.below(4) == 0 {
                    "-".to_owned()
                } else {
                    key_length(random).to_string()
                };
                writeln!(out, "minit {key}{}", params(random))?;
            }
            5 => writeln!(out, "mset{}", params(random))?,
            6..=8 => writeln!(out, "mupdate {}", length(random))?,
            9 | 10 => {
                let size =
                    random.pick(&["", " 64", " 0", " 7", " 15", " 16", " 19", " 31", " 300"]);
                writeln!(out, "mfinal{size}")?;
            }
            11 => writeln!(out, "mxof {}", random.below(70))?,
            12 => writeln!(out, "mdup")?,
            13 => writeln!(out, "mctx {}", random.below(2))?,
            14 => {
                let (mac, sub) = match random.below(4) {
                    0 => ("HMAC", random.pick(DIGESTS)),
                    1 => ("CMAC", random.pick(CIPHERS)),
                    2 => ("GMAC", random.pick(CIPHERS)),
                    _ => (
                        random.pick(MACS),
                        random.pick(&["-", "SHA256", "AES-128-CBC"]),
                    ),
                };
                let outsize = random.pick(&["0", "64", "16", "15", "31", "20"]);
                writeln!(
                    out,
                    "mq {mac} {sub} {} {} {outsize}{}",
                    key_length(random),
                    length(random),
                    params(random)
                )?;
            }
            _ => writeln!(
                out,
                "{}",
                random.pick(&["msize", "mget", "mfree", "mfinal"])
            )?,
        }
    }
    writeln!(out, "mfree")?;
    writeln!(out, "mctx 1")?;
    writeln!(out, "mfree")?;
    writeln!(out, "mctx 0")?;
    Ok(())
}

/// A random session of KDF commands on the probe's two contexts: each of the default
/// provider's KDFs made by name, given random digests, MACs, ciphers, modes, keys, salts,
/// secrets, seeds, info, labels, constants, entropy, nonces, iterations and costs (kept small),
/// and sizes, and derived from into lengths around the digests' sizes; sizes, copies, resets,
/// and `PKCS5_PBKDF2_HMAC`.
fn kdf_session(random: &mut Random, out: &mut String) -> Result {
    const KDFS: &[&str] = &[
        "HKDF",
        "TLS13-KDF",
        "PBKDF2",
        "1.2.840.113549.1.5.12",
        "TLS1-PRF",
        "SSKDF",
        "X963KDF",
        "X942KDF-CONCAT",
        "hkdf",
        "SCRYPT",
        "id-scrypt",
        "SSHKDF",
        "KBKDF",
        "X942KDF-ASN1",
        "X942KDF",
        "PKCS12KDF",
        "KRB5KDF",
        "HMAC-DRBG-KDF",
        "ARGON2I",
        "ARGON2D",
        "ARGON2ID",
        "argon2id",
        "NO-SUCH-KDF",
    ];
    const DIGESTS: &[&str] = &[
        "SHA1",
        "SHA224",
        "SHA256",
        "SHA384",
        "SHA512",
        "SHA512-256",
        "SHA3-256",
        "MD5",
        "MD5-SHA1",
        "md5-sha1",
        "SM3",
        "BLAKE2s256",
        "RIPEMD160",
        "SHAKE128",
        "NULL",
        "nonesuch",
    ];
    let octets = |random: &mut Random| -> String {
        random
            .pick(&[
                "0", "1", "4", "8", "13", "16", "20", "32", "48", "64", "100", "199",
            ])
            .to_owned()
    };
    let params = |random: &mut Random| -> String {
        let mut text = String::new();
        for _ in 0..random.below(4) {
            let param = match random.below(21) {
                0 | 1 => format!("digest={}", random.pick(DIGESTS)),
                2 => format!(
                    "mac={}",
                    random.pick(&["HMAC", "KMAC128", "KMAC-256", "CMAC", "nonesuch"])
                ),
                3 => format!(
                    "mode={}",
                    random.pick(&[
                        "0",
                        "1",
                        "2",
                        "3",
                        "EXTRACT_ONLY",
                        "expand_only",
                        "EXTRACT_AND_EXPAND",
                        "both"
                    ])
                ),
                4..=8 => format!(
                    "{}={}",
                    random.pick(&[
                        "key", "salt", "info", "secret", "seed", "pass", "prefix", "label", "data"
                    ]),
                    octets(random)
                ),
                9 => format!(
                    "iter={}",
                    random.pick(&["0", "1", "2", "999", "1000", "2048", "3"])
                ),
                10 => format!("pkcs5={}", random.below(2)),
                // scrypt's (small: the probe caps memory), KBKDF's, SSHKDF's, X9.42's.
                12 => format!(
                    "{}={}",
                    random.pick(&["n", "r", "p"]),
                    random.pick(&["0", "1", "2", "8", "15", "16", "64", "1024"])
                ),
                13 => format!(
                    "{}={}",
                    random.pick(&["use-l", "use-separator", "use-keybits", "r"]),
                    random.pick(&["0", "1", "8", "12", "16", "24", "32"])
                ),
                14 => format!(
                    "{}={}",
                    random.pick(&[
                        "xcghash",
                        "session_id",
                        "ukm",
                        "acvp-info",
                        "partyu-info",
                        "partyv-info",
                        "supp-pubinfo",
                        "supp-privinfo"
                    ]),
                    octets(random)
                ),
                15 => format!("type={}", random.pick(&["A", "C", "F", "G", "AB", "a"])),
                16 => random
                    .pick(&[
                        "cekalg=AES-128-WRAP",
                        "cekalg=AES-256-WRAP",
                        "cekalg=DES3-WRAP",
                        "cekalg=AES-128-CBC",
                        "mode=counter",
                        "mode=FEEDBACK",
                        "mode=co",
                        "mode=pipeline",
                        "mac=CMAC cipher=AES-128-CBC",
                        "mac=HMAC digest=SHA256",
                        "maxmem_bytes=1024",
                    ])
                    .to_owned(),
                // PKCS12KDF's, KRB5KDF's, HMAC-DRBG-KDF's (the probe skips ciphers it doesn't
                // know to finish), and Argon2's (small costs).
                17 => format!(
                    "{}={}",
                    random.pick(&["constant", "entropy", "nonce", "ad", "secret", "salt"]),
                    octets(random)
                ),
                18 => format!(
                    "cipher={}",
                    random.pick(&[
                        "AES-128-CBC",
                        "AES-256-CBC",
                        "AES-192-ECB",
                        "DES-EDE3-CBC",
                        "CAMELLIA-256-CBC",
                        "AES-128-CTR",
                        "ARIA-128-CBC",
                        "SM4-CBC",
                        "AES-128-WRAP",
                        "nonesuch"
                    ])
                ),
                19 => format!(
                    "{}={}",
                    random.pick(&["lanes", "memcost", "threads", "version", "size"]),
                    random.pick(&["0", "1", "2", "3", "4", "7", "8", "16", "19", "21", "64"])
                ),
                20 => format!(
                    "{}={}",
                    random.pick(&["pkcs12-id", "early_clean"]),
                    random.pick(&["0", "1", "2", "3", "255", "256"])
                ),
                _ => format!(
                    "{}={}",
                    random.pick(&["mac-size", "properties"]),
                    random.pick(&["0", "20", "21", "32", "64"])
                ),
            };
            let param = param.replace("properties=0", "properties=provider=default");
            text.push(' ');
            text.push_str(&param);
        }
        text
    };
    let length = |random: &mut Random| -> u64 {
        match random.below(3) {
            0 => random
                .pick(&[
                    "0", "1", "13", "14", "16", "20", "28", "31", "32", "33", "48", "64",
                ])
                .parse()
                .unwrap_or(0),
            _ => random.below(300),
        }
    };
    for _ in 0..random.below(25) + 1 {
        match random.below(14) {
            0 | 1 => writeln!(out, "knew {}", random.pick(KDFS))?,
            2..=4 => writeln!(out, "kset{}", params(random))?,
            5..=8 => writeln!(out, "kderive {}{}", length(random), params(random))?,
            9 => writeln!(out, "kdup")?,
            10 => writeln!(out, "kctx {}", random.below(2))?,
            11 => {
                let passlen = random.pick(&["-1", "0", "1", "8", "199"]);
                writeln!(
                    out,
                    "kpbkdf2 {} {passlen} {} {} {}",
                    random.pick(DIGESTS),
                    random.below(30),
                    random.pick(&["0", "1", "2", "100"]),
                    length(random)
                )?;
            }
            _ => writeln!(
                out,
                "{}",
                random.pick(&["ksize", "kget", "kreset", "kfree"])
            )?,
        }
    }
    writeln!(out, "kfree")?;
    writeln!(out, "kctx 1")?;
    writeln!(out, "kfree")?;
    writeln!(out, "kctx 0")?;
    Ok(())
}

/// A random session of random-generator commands on the probe's two contexts: each of the
/// default provider's generators made by name (a context often under the other), given
/// TEST-RAND's entropy, nonce, strength, request limit, and mode, the DRBGs' ciphers, digests,
/// MACs, derivation function, and reseed requests (the reseed interval kept at its hour, so
/// timing never decides), instantiated, generated from, reseeded, asked for nonces, states,
/// and parameters; and the RAND layer over them (a context made the thread's public or private
/// DRBG, `RAND_bytes`, `RAND_priv_bytes`, `RAND_status`, `RAND_poll`).
fn rand_session(random: &mut Random, out: &mut String) -> Result {
    const RANDS: &[&str] = &[
        "TEST-RAND",
        "TEST-RAND",
        "CTR-DRBG",
        "HASH-DRBG",
        "HMAC-DRBG",
        "SEED-SRC",
        "hash-drbg",
        "NO-SUCH-RAND",
    ];
    let params = |random: &mut Random| -> String {
        let mut text = String::new();
        for _ in 0..random.below(3) + 1 {
            let param = match random.below(10) {
                0 | 1 => format!(
                    "{}={}",
                    random.pick(&["test_entropy", "test_nonce"]),
                    random.pick(&["0", "8", "16", "24", "32", "40", "48", "64", "100", "199"])
                ),
                2 => format!(
                    "strength={}",
                    random.pick(&["0", "112", "128", "192", "256", "257"])
                ),
                3 => format!("generate={}", random.below(2)),
                4 => format!(
                    "max_request={}",
                    random.pick(&["0", "1", "5", "16", "1000", "65536"])
                ),
                5 => format!(
                    "cipher={}",
                    random.pick(&[
                        "AES-128-CTR",
                        "AES-192-CTR",
                        "AES-256-CTR",
                        "aria-128-ctr",
                        "CAMELLIA-256-CTR",
                        "SM4-CTR",
                        "AES-128-CBC",
                        "NOPE-CTR"
                    ])
                ),
                6 => format!(
                    "digest={}",
                    random.pick(&[
                        "SHA1",
                        "SHA256",
                        "SHA512",
                        "SHA3-256",
                        "SHA512-224",
                        "SM3",
                        "MD5",
                        "SHAKE128",
                        "NULL",
                        "nonesuch"
                    ])
                ),
                7 => random
                    .pick(&[
                        "mac=HMAC",
                        "mac=KMAC128",
                        "mac=CMAC",
                        "mac=nonesuch",
                        "properties=provider=default",
                        "properties=provider=nonesuch",
                    ])
                    .to_owned(),
                8 => format!("use_derivation_function={}", random.below(2)),
                _ if random.below(2) == 0 => format!(
                    "reseed_requests={}",
                    random.pick(&["0", "1", "2", "3", "256"])
                ),
                // Never a short interval: whether time reseeds would decide the output.
                _ => format!(
                    "reseed_time_interval={}",
                    random.pick(&["0", "3600", "86400"])
                ),
            };
            text.push(' ');
            text.push_str(&param);
        }
        text
    };
    let strength = |random: &mut Random| random.pick(&["0", "0", "112", "128", "256", "257"]);
    let length = |random: &mut Random| -> u64 {
        match random.below(3) {
            0 => random
                .pick(&["0", "1", "15", "16", "17", "32", "64", "128", "129"])
                .parse()
                .unwrap_or(0),
            _ => random.below(400),
        }
    };
    for _ in 0..random.below(30) + 1 {
        match random.below(18) {
            0 | 1 => {
                let child = if random.below(3) == 0 { "" } else { " child" };
                writeln!(out, "rnew {}{child}", random.pick(RANDS))?;
            }
            2..=4 => writeln!(out, "rset{}", params(random))?,
            5 | 6 => writeln!(
                out,
                "rinst {} {} {}",
                strength(random),
                random.below(2),
                random.pick(&["0", "0", "8", "48", "49", "199"])
            )?,
            7..=9 => writeln!(
                out,
                "rgen {} {} {} {}",
                length(random),
                strength(random),
                u64::from(random.below(4) == 0),
                random.pick(&["0", "0", "1", "16", "48", "49", "299"])
            )?,
            10 => writeln!(
                out,
                "rreseed {} {} {}",
                u64::from(random.below(3) == 0),
                random.pick(&["0", "0", "5", "16", "32", "48", "100"]),
                random.pick(&["0", "7", "49"])
            )?,
            11 => writeln!(out, "rnonce {}", length(random))?,
            12 => writeln!(out, "rctx {}", random.below(2))?,
            13 | 14 => writeln!(
                out,
                "{}",
                random.pick(&[
                    "rsetpub",
                    "rsetpriv",
                    "rbytes 32 0",
                    "rbytes 48 256",
                    "rprivbytes 16 0",
                    "rprivbytes 100 128",
                    "rbytes 8 257",
                    "rstatus",
                    "rpoll",
                    "rreset"
                ])
            )?,
            _ => writeln!(
                out,
                "{}",
                random.pick(&["rget", "runinst", "rzero", "rlock", "rfree"])
            )?,
        }
    }
    writeln!(out, "rreset")?;
    writeln!(out, "rctx 0")?;
    writeln!(out, "rfree")?;
    writeln!(out, "rctx 1")?;
    writeln!(out, "rfree")?;
    writeln!(out, "rctx 0")?;
    Ok(())
}

/// A hex number for the big-number commands: zero, values around octet and word boundaries, or
/// random digits with runs of 0 and F, of either sign.
/// The curves `ec_session` uses, with their field elements' sizes in octets: NIST, Koblitz,
/// brainpool, small SECG, SM2, and binary trinomial, pentanomial, and even-degree ones.
const EC_CURVES: &[(&str, usize)] = &[
    ("prime256v1", 32),
    ("secp224r1", 28),
    ("secp384r1", 48),
    ("secp521r1", 66),
    ("secp256k1", 32),
    ("brainpoolP256r1", 32),
    ("brainpoolP384t1", 48),
    ("secp112r1", 14),
    ("secp160r2", 20),
    ("SM2", 32),
    ("sect113r1", 15),
    ("sect163k1", 21),
    ("sect233r1", 30),
    ("c2pnb176v1", 22),
    ("c2tnb191v1", 24),
    ("Oakley-EC2N-3", 20),
];

/// Random octets, as hex.
fn random_hex(random: &mut Random, len: usize) -> String {
    (0..len)
        .map(|_| format!("{:02x}", random.below(256)))
        .collect()
}

/// Encodings of EC parameters for `ecpk` sessions to start from: explicit secp112r1 (with and
/// without its seed, with a compressed base), sect113r1 with its trinomial and with a
/// pentanomial, and prime256v1's name.
const ECPK_SEEDS: &[&str] = &[
    "3074020101301a06072a8648ce3d0101020f00db7c2abf62e35e668076bead208b3020040edb7c2abf62e35e668076bead2088040e659ef8ba043916eede8911702b22041d0409487239995a5ee76b55f9c2f098a89ce5af8724c0a23e0e0ff77500020f00db7c2abf62e35e7628dfac6561c5020101",
    "3079020101301a06072a8648ce3d0101020f00db7c2abf62e35e668076bead208b3033040edb7c2abf62e35e668076bead2088040e659ef8ba043916eede8911702b2203110000f50b028e4d696e6768756151752904040f0209487239995a5ee76b55f9c2f098020f00db7c2abf62e35e7628dfac6561c5020101",
    "307a020101301c06072a8648ce3d0102301102017106092a8648ce3d010203020201093022040f003088250ca6e7c7fe649ce85820f7040f00e8bee4d3e2260744188be0e9c723041f04009d73616f35f4ab1407d73562c10f00a52830277958ee84d1315ed31886020f0100000000000000d9ccec8a39e56f020102",
    "308182020101302406072a8648ce3d0102301902017106092a8648ce3d0102030330090201020201040201093022040f003088250ca6e7c7fe649ce85820f7040f00e8bee4d3e2260744188be0e9c723041f04009d73616f35f4ab1407d73562c10f00a52830277958ee84d1315ed31886020f0100000000000000d9ccec8a39e56f020102",
    "06082a8648ce3d030107",
    "308187020101301a06072a8648ce3d0101020f00db7c2abf62e35e668076bead208b3033040edb7c2abf62e35e668076bead2088040e659ef8ba043916eede8911702b2203110000f50b028e4d696e6768756151752904041d0409487239995a5ee76b55f9c2f098a89ce5af8724c0a23e0e0ff77500020f00db7c2abf62e35e7628dfac6561c5020101",
];

/// A random session of `ecpk` commands: the seed encodings with octets changed, removed, or
/// added, cut short, or whole.
fn ecpk_session(random: &mut Random, out: &mut String) -> Result {
    mutated_sessions(random, out, "ecpk", ECPK_SEEDS)
}

/// Commands `command <hex>` on `seeds` with octets changed, removed, or added, cut short, or
/// whole.
fn mutated_sessions(
    random: &mut Random,
    out: &mut String,
    command: &str,
    seeds: &[&str],
) -> Result {
    for _ in 0..random.below(6) + 1 {
        let seed = random.pick(seeds);
        let mut der: Vec<u8> = (0..seed.len() / 2)
            .filter_map(|i| seed.get(2 * i..2 * i + 2))
            .filter_map(|h| u8::from_str_radix(h, 16).ok())
            .collect();
        for _ in 0..random.below(4) {
            let len = der.len() as u64;
            if len == 0 {
                break;
            }
            let at = usize::try_from(random.below(len)).unwrap_or(0);
            let v = u8::try_from(random.below(256)).unwrap_or(0);
            match random.below(5) {
                0 => {
                    der.remove(at);
                }
                1 => der.insert(at, v),
                2 => der.truncate(at),
                _ => {
                    if let Some(b) = der.get_mut(at) {
                        *b = if random.below(2) == 0 {
                            v
                        } else {
                            *b ^ (1 << random.below(8))
                        };
                    }
                }
            }
        }
        der.truncate(250);
        let hex: String = der.iter().map(|b| format!("{b:02x}")).collect();
        writeln!(out, "{command} {hex}")?;
    }
    Ok(())
}

/// Encodings of EC private keys for `eckey` sessions to start from: prime256v1 with private key
/// 1 (named, then with no parameters), with a public key off the curve, and with a private key
/// longer than the order.
const ECKEY_SEEDS: &[&str] = &[
    "3012020101040101a00a06082a8648ce3d030107",
    "3006020101040101",
    "3058020101040101a00a06082a8648ce3d030107a144034200040102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
    "30350201010424ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa00a06082a8648ce3d030107",
];

/// A random session of `eckey` commands: the seed encodings mutated as `ecpk`'s are.
fn eckey_session(random: &mut Random, out: &mut String) -> Result {
    mutated_sessions(random, out, "eckey", ECKEY_SEEDS)
}

/// The lines that make the probe's private and public generators deterministic, so random
/// nonces and keys come out the same on both libraries.
const DETERMINISTIC_RAND: [&str; 10] = [
    "rctx 0",
    "rnew TEST-RAND",
    "rset strength=256 test_entropy=64 test_nonce=32",
    "rinst 0 0",
    "rctx 1",
    "rnew HASH-DRBG child",
    "rset digest=SHA256",
    "rinst 0 0",
    "rsetpub",
    "rsetpriv",
];

/// A random session of ECDSA and ECDH on one curve, from deterministic generators: key
/// generation, signatures (whose nonces come from the generator), setups, verification of a
/// signature's mutations and of random octets, and shared secrets with and without the
/// cofactor; private keys of every size, digests of every length up to 70 octets.
fn ecdsa_session(random: &mut Random, out: &mut String) -> Result {
    for line in DETERMINISTIC_RAND {
        writeln!(out, "{line}")?;
    }
    let i = usize::try_from(random.below(EC_CURVES.len() as u64)).unwrap_or(0);
    let (curve, fl) = EC_CURVES.get(i).copied().unwrap_or(("prime256v1", 32));
    let privkey = |random: &mut Random| match random.below(5) {
        0 => format!("{:x}", random.below(1000).saturating_add(1)),
        1 => "F".repeat(fl.saturating_mul(2)),
        _ => random_hex(random, fl),
    };
    for _ in 0..random.below(8).saturating_add(1) {
        let d = privkey(random);
        let dlen = usize::try_from(random.below(71)).unwrap_or(32);
        match random.below(6) {
            0 => writeln!(out, "ecgen {curve}")?,
            1 | 2 => writeln!(out, "ecsign {curve} {d} {}", random_hex(random, dlen))?,
            3 => writeln!(out, "ecsetup {curve} {d}")?,
            4 => {
                let siglen = usize::try_from(random.below(16))
                    .unwrap_or(0)
                    .saturating_add(fl.saturating_mul(2));
                writeln!(
                    out,
                    "ecverify {curve} {d} {} 30{}",
                    random_hex(random, dlen),
                    random_hex(random, siglen)
                )?;
            }
            _ => {
                let peer = privkey(random);
                writeln!(out, "ecdh {curve} {d} {peer} {}", random.below(2))?;
            }
        }
    }
    Ok(())
}

/// A random session of the ECDSA signature provider on one curve, from deterministic
/// generators: messages of every length signed with each nonce type (through a digest context,
/// as a digest, and with a composite algorithm), with digests good and bad, by keys of every
/// size; and signatures near valid ones verified.
fn ecsig_session(random: &mut Random, out: &mut String) -> Result {
    for line in DETERMINISTIC_RAND {
        writeln!(out, "{line}")?;
    }
    let i = usize::try_from(random.below(EC_CURVES.len() as u64)).unwrap_or(0);
    let (curve, fl) = EC_CURVES.get(i).copied().unwrap_or(("prime256v1", 32));
    for _ in 0..random.below(6).saturating_add(1) {
        let d = match random.below(6) {
            0 => format!("{:x}", random.below(1000)),
            1 => "F".repeat(fl.saturating_mul(2)),
            _ => random_hex(random, fl),
        };
        let md = random.pick(&[
            "SHA256",
            "SHA256",
            "SHA1",
            "SHA224",
            "SHA384",
            "SHA512",
            "SHA3-256",
            "SHA3-512",
            "SHA512-256",
            "MD5",
            "SM3",
            "SHAKE128",
            "-",
        ]);
        let nonce = random.pick(&["1", "1", "0", "2"]);
        let alg = random.pick(&[
            "-",
            "ECDSA-SHA256",
            "ECDSA-SHA1",
            "ECDSA-SHA384",
            "ECDSA-SHA3-224",
            "ECDSA-SHA2-512",
        ]);
        let msg = if random.below(4) == 0 {
            // A digest's length, for signing as a digest.
            let len = random.pick(&["20", "28", "32", "48", "64"]);
            random_hex(random, len.parse().unwrap_or(32))
        } else {
            let len = usize::try_from(random.below(100)).unwrap_or(0);
            random_hex(random, len)
        };
        let sig = match random.below(3) {
            0 => {
                let len = usize::try_from(random.below(8))
                    .unwrap_or(0)
                    .saturating_add(fl.saturating_mul(2));
                format!("30{}", random_hex(random, len))
            }
            _ => "-".to_owned(),
        };
        writeln!(out, "ecsig {curve} {d} {md} {nonce} {alg} {msg} {sig}")?;
    }
    Ok(())
}

/// A random session of the ECDH provider on one curve: keys of every size (some not below the
/// order), cofactor modes valid and not, plain secrets into buffers of every size, and X9.63's
/// KDF with digests good and bad, output lengths of every size, and keying material.
fn ecdhx_session(random: &mut Random, out: &mut String) -> Result {
    let i = usize::try_from(random.below(EC_CURVES.len() as u64)).unwrap_or(0);
    let (curve, fl) = EC_CURVES.get(i).copied().unwrap_or(("prime256v1", 32));
    let privkey = |random: &mut Random| match random.below(6) {
        0 => format!("{:x}", random.below(1000)),
        1 => "F".repeat(fl.saturating_mul(2)),
        _ => random_hex(random, fl),
    };
    for _ in 0..random.below(6).saturating_add(1) {
        let (a, b) = (privkey(random), privkey(random));
        let mode = random.pick(&["-1", "-1", "0", "1", "2"]);
        let md = random.pick(&[
            "-", "-", "SHA256", "SHA1", "SHA3-512", "MD5", "SHAKE256", "nosuch",
        ]);
        let outlen = random.below(80);
        let ukm = match random.below(3) {
            0 => "-".to_owned(),
            _ => {
                let len = usize::try_from(random.below(40)).unwrap_or(0);
                random_hex(random, len)
            }
        };
        let room = random.pick(&["0", "1", "16", "32", "66", "80", "100"]);
        writeln!(
            out,
            "ecdhx {curve} {a} {b} {mode} {md} {outlen} {ukm} {room}"
        )?;
    }
    Ok(())
}

/// A random session of the ECX key managers (X25519, ED25519, X448, ED448): keys from data of
/// every selection, with private and public keys of every length (the right one most often), matching or not, and keys
/// generated from DHKEM input of every length.
fn ecxkm_session(random: &mut Random, out: &mut String) -> Result {
    for _ in 0..random.below(6).saturating_add(1) {
        const KINDS: [(&str, usize); 4] =
            [("X25519", 32), ("ED25519", 32), ("X448", 56), ("ED448", 57)];
        let i = usize::try_from(random.below(4)).unwrap_or(0);
        let (kind, keylen) = KINDS.get(i).copied().unwrap_or(("X25519", 32));
        if random.below(5) == 0 {
            let len = usize::try_from(random.below(72)).unwrap_or(32);
            writeln!(out, "ecxkm {kind} 87 - - {}", random_hex(random, len))?;
            continue;
        }
        let selection = random.pick(&["87", "87", "86", "85", "84", "83", "81", "80", "7", "4"]);
        let part = |random: &mut Random| match random.below(5) {
            0 => "-".to_owned(),
            1 => {
                let len = usize::try_from(random.below(64)).unwrap_or(0);
                random_hex(random, len)
            }
            _ => random_hex(random, keylen),
        };
        let privkey = part(random);
        let pubkey = part(random);
        writeln!(out, "ecxkm {kind} {selection} {privkey} {pubkey} -")?;
    }
    Ok(())
}

/// A random session of the ML-KEM key managers: keys from a seed (of every length, the right
/// one most often) and the private and public keys of keys generated from a few seeds, so that
/// they match or not, by every selection, sometimes edited (octets changed, set, or the length
/// changed).
fn mlkemkm_session(random: &mut Random, out: &mut String) -> Result {
    const ALGS: [(&str, usize, usize); 3] = [
        ("ML-KEM-512", 1632, 800),
        ("ML-KEM-768", 2400, 1184),
        ("ML-KEM-1024", 3168, 1568),
    ];
    let pool: Vec<String> = (0..3).map(|_| random_hex(random, 64)).collect();
    for _ in 0..random.below(4).saturating_add(1) {
        let i = usize::try_from(random.below(3)).unwrap_or(0);
        let (alg, privlen, publen) = ALGS.get(i).copied().unwrap_or(ALGS[0]);
        let selection = random.pick(&[
            "87", "87", "87", "86", "85", "84", "83", "81", "80", "7", "4",
        ]);
        let from_pool = |random: &mut Random| {
            let j = usize::try_from(random.below(3)).unwrap_or(0);
            pool.get(j).cloned().unwrap_or_default()
        };
        let seed = match random.below(6) {
            0 | 1 => "-".to_owned(),
            2 => {
                let len = usize::try_from(random.below(70)).unwrap_or(0);
                random_hex(random, len)
            }
            _ => from_pool(random),
        };
        let privfrom = if random.below(2) == 0 {
            "-".to_owned()
        } else {
            from_pool(random)
        };
        let pubfrom = if random.below(2) == 0 {
            "-".to_owned()
        } else {
            from_pool(random)
        };
        let mut edits = Vec::new();
        if random.below(4) == 0 {
            for _ in 0..random.below(2).saturating_add(1) {
                let (target, len) = match (privfrom.as_str(), pubfrom.as_str()) {
                    ("-", "-") => break,
                    ("-", _) => ("q", publen),
                    (_, "-") => ("p", privlen),
                    _ if random.below(2) == 0 => ("p", privlen),
                    _ => ("q", publen),
                };
                let len = u64::try_from(len).unwrap_or(1);
                edits.push(match random.below(4) {
                    0 => {
                        let n = random.pick(&["-1", "+1", "0", "short"]);
                        let n = match n {
                            "-1" => len.saturating_sub(1),
                            "+1" => len.saturating_add(1),
                            "0" => 0,
                            _ => random.below(len),
                        };
                        format!("{target}#{n}")
                    }
                    1 => format!("{target}@{}={:02x}", random.below(len), random.below(256)),
                    _ => format!(
                        "{target}@{}^{:02x}",
                        random.below(len),
                        random.below(255).saturating_add(1)
                    ),
                });
            }
        }
        let edits = if edits.is_empty() {
            "-".to_owned()
        } else {
            edits.join(",")
        };
        writeln!(
            out,
            "mlkemkm {alg} {selection} {seed} {privfrom} {pubfrom} {edits}"
        )?;
    }
    Ok(())
}

/// A random session of the ML-KEM KEM: encapsulations (with an ikmE of every length, the right
/// one most often, or random) into rooms around the right sizes, and decapsulations of the
/// ciphertext as is, with octets changed, or of another length.
fn mlkem_session(random: &mut Random, out: &mut String) -> Result {
    const ALGS: [(&str, u64); 3] = [
        ("ML-KEM-512", 768),
        ("ML-KEM-768", 1088),
        ("ML-KEM-1024", 1568),
    ];
    for _ in 0..random.below(4).saturating_add(1) {
        let i = usize::try_from(random.below(3)).unwrap_or(0);
        let (alg, clen) = ALGS.get(i).copied().unwrap_or(ALGS[0]);
        let seed = random_hex(random, 64);
        let ikme = match random.below(6) {
            0 => "-".to_owned(),
            1 => {
                let len = usize::try_from(random.below(40)).unwrap_or(0);
                random_hex(random, len)
            }
            _ => random_hex(random, 32),
        };
        let croom = match random.below(6) {
            0 => clen.saturating_sub(random.below(3).saturating_add(1)),
            1 => clen.saturating_add(random.below(100)),
            _ => clen,
        };
        let sroom = match random.below(6) {
            0 => random.below(32),
            1 => 32u64.saturating_add(random.below(64)),
            _ => 32,
        };
        let mut edits = Vec::new();
        for _ in 0..random.below(3) {
            edits.push(match random.below(4) {
                0 => format!(
                    "c#{}",
                    clen.saturating_add(random.below(3)).saturating_sub(1)
                ),
                _ => format!(
                    "c@{}^{:02x}",
                    random.below(clen),
                    random.below(255).saturating_add(1)
                ),
            });
        }
        let edits = if edits.is_empty() {
            "-".to_owned()
        } else {
            edits.join(",")
        };
        writeln!(out, "mlkem {alg} {seed} {ikme} {edits} {croom} {sroom}")?;
    }
    Ok(())
}

/// A random session of the ML-DSA key managers, as `mlkemkm_session` (with 32-octet seeds).
fn mldsakm_session(random: &mut Random, out: &mut String) -> Result {
    const ALGS: [(&str, usize, usize); 3] = [
        ("ML-DSA-44", 2560, 1312),
        ("ML-DSA-65", 4032, 1952),
        ("ML-DSA-87", 4896, 2592),
    ];
    let pool: Vec<String> = (0..3).map(|_| random_hex(random, 32)).collect();
    for _ in 0..random.below(4).saturating_add(1) {
        let i = usize::try_from(random.below(3)).unwrap_or(0);
        let (alg, privlen, publen) = ALGS.get(i).copied().unwrap_or(ALGS[0]);
        let selection = random.pick(&[
            "87", "87", "87", "86", "85", "84", "83", "81", "80", "7", "4",
        ]);
        let from_pool = |random: &mut Random| {
            let j = usize::try_from(random.below(3)).unwrap_or(0);
            pool.get(j).cloned().unwrap_or_default()
        };
        let seed = match random.below(6) {
            0 | 1 => "-".to_owned(),
            2 => {
                let len = usize::try_from(random.below(40)).unwrap_or(0);
                random_hex(random, len)
            }
            _ => from_pool(random),
        };
        let privfrom = if random.below(2) == 0 {
            "-".to_owned()
        } else {
            from_pool(random)
        };
        let pubfrom = if random.below(2) == 0 {
            "-".to_owned()
        } else {
            from_pool(random)
        };
        let mut edits = Vec::new();
        if random.below(4) == 0 {
            for _ in 0..random.below(2).saturating_add(1) {
                let (target, len) = match (privfrom.as_str(), pubfrom.as_str()) {
                    ("-", "-") => break,
                    ("-", _) => ("q", publen),
                    (_, "-") => ("p", privlen),
                    _ if random.below(2) == 0 => ("p", privlen),
                    _ => ("q", publen),
                };
                let len = u64::try_from(len).unwrap_or(1);
                edits.push(match random.below(4) {
                    0 => {
                        let n = random.pick(&["-1", "+1", "0", "short"]);
                        let n = match n {
                            "-1" => len.saturating_sub(1),
                            "+1" => len.saturating_add(1),
                            "0" => 0,
                            _ => random.below(len),
                        };
                        format!("{target}#{n}")
                    }
                    1 => format!("{target}@{}={:02x}", random.below(len), random.below(256)),
                    _ => format!(
                        "{target}@{}^{:02x}",
                        random.below(len),
                        random.below(255).saturating_add(1)
                    ),
                });
            }
        }
        let edits = if edits.is_empty() {
            "-".to_owned()
        } else {
            edits.join(",")
        };
        writeln!(
            out,
            "mldsakm {alg} {selection} {seed} {privfrom} {pubfrom} {edits}"
        )?;
    }
    Ok(())
}

/// A random session of the SLH-DSA key managers, as `mldsakm_session` (with seeds of `3n`
/// octets, the fast parameter sets most often, and edits that halve the private key or change
/// its root).
fn slhdsakm_session(random: &mut Random, out: &mut String) -> Result {
    const FAST: [(&str, usize); 6] = [
        ("SLH-DSA-SHA2-128f", 16),
        ("SLH-DSA-SHA2-192f", 24),
        ("SLH-DSA-SHA2-256f", 32),
        ("SLH-DSA-SHAKE-128f", 16),
        ("SLH-DSA-SHAKE-192f", 24),
        ("SLH-DSA-SHAKE-256f", 32),
    ];
    const SMALL: [(&str, usize); 6] = [
        ("SLH-DSA-SHA2-128s", 16),
        ("SLH-DSA-SHA2-192s", 24),
        ("SLH-DSA-SHA2-256s", 32),
        ("SLH-DSA-SHAKE-128s", 16),
        ("SLH-DSA-SHAKE-192s", 24),
        ("SLH-DSA-SHAKE-256s", 32),
    ];
    for _ in 0..random.below(3).saturating_add(1) {
        let set = if random.below(6) == 0 { &SMALL } else { &FAST };
        let i = usize::try_from(random.below(6)).unwrap_or(0);
        let (alg, n) = set.get(i).copied().unwrap_or(FAST[0]);
        let pool: Vec<String> = (0..2)
            .map(|_| random_hex(random, n.saturating_mul(3)))
            .collect();
        let selection = random.pick(&["87", "87", "87", "86", "85", "84", "83", "81", "7", "4"]);
        let from_pool = |random: &mut Random| {
            let j = usize::try_from(random.below(2)).unwrap_or(0);
            pool.get(j).cloned().unwrap_or_default()
        };
        let privfrom = if random.below(3) == 0 {
            "-".to_owned()
        } else {
            from_pool(random)
        };
        let pubfrom = if random.below(2) == 0 {
            "-".to_owned()
        } else {
            from_pool(random)
        };
        let (privlen, publen) = (n.saturating_mul(4), n.saturating_mul(2));
        let mut edits = Vec::new();
        if random.below(3) == 0 {
            for _ in 0..random.below(2).saturating_add(1) {
                let (target, len) = match (privfrom.as_str(), pubfrom.as_str()) {
                    ("-", "-") => break,
                    ("-", _) => ("q", publen),
                    (_, "-") => ("p", privlen),
                    _ if random.below(2) == 0 => ("p", privlen),
                    _ => ("q", publen),
                };
                let len = u64::try_from(len).unwrap_or(1);
                edits.push(match random.below(5) {
                    0 => {
                        let n = match random.pick(&["half", "-1", "+1", "0", "short"]) {
                            "half" => len / 2,
                            "-1" => len.saturating_sub(1),
                            "+1" => len.saturating_add(1),
                            "0" => 0,
                            _ => random.below(len),
                        };
                        format!("{target}#{n}")
                    }
                    1 => format!("{target}#{}", len / 2),
                    _ => format!(
                        "{target}@{}^{:02x}",
                        random.below(len),
                        random.below(255).saturating_add(1)
                    ),
                });
            }
        }
        let edits = if edits.is_empty() {
            "-".to_owned()
        } else {
            edits.join(",")
        };
        writeln!(
            out,
            "slhdsakm {alg} {selection} - {privfrom} {pubfrom} {edits}"
        )?;
    }
    Ok(())
}

/// A random session of the ML-DSA signatures: messages and context strings of every length up
/// to past the limit (often none), each option now and then (deterministic, an encoding, mu
/// with a message of 64 octets or another length, test entropy of 32 octets or another
/// length, the public key alone for the verification), rooms around the signature's size (or
/// a size query), and the verification of the signature as is, with octets of it or the
/// message changed, or of another length.
fn mldsa_session(random: &mut Random, out: &mut String) -> Result {
    const ALGS: [(&str, u64); 3] = [
        ("ML-DSA-44", 2420),
        ("ML-DSA-65", 3309),
        ("ML-DSA-87", 4627),
    ];
    for _ in 0..random.below(4).saturating_add(1) {
        let i = usize::try_from(random.below(3)).unwrap_or(0);
        let (alg, slen) = ALGS.get(i).copied().unwrap_or(ALGS[0]);
        let seed = random_hex(random, 32);
        let mut opts = Vec::new();
        if random.below(3) != 0 {
            opts.push(format!("det={}", random.below(3)));
        }
        if random.below(5) == 0 {
            opts.push(format!("enc={}", random.below(3)));
        }
        let mu = random.below(5) == 0;
        if mu {
            opts.push(format!("mu={}", random.below(2)));
        }
        if random.below(4) == 0 {
            let len = match random.below(4) {
                0 => usize::try_from(random.below(40)).unwrap_or(0),
                _ => 32,
            };
            opts.push(format!("ent={}", random_hex(random, len)));
        }
        if random.below(4) == 0 {
            opts.push("pub".to_owned());
        }
        let opts = if opts.is_empty() {
            "-".to_owned()
        } else {
            opts.join(",")
        };
        let mlen = match random.below(4) {
            0 if mu => 64,
            0 => 0,
            1 => usize::try_from(random.below(257)).unwrap_or(0),
            _ => usize::try_from(random.below(70)).unwrap_or(0),
        };
        let msg = if mlen == 0 {
            "-".to_owned()
        } else {
            random_hex(random, mlen)
        };
        let ctx = match random.below(6) {
            0 => "e".to_owned(),
            1 => {
                let len = usize::try_from(random.below(3).saturating_add(254)).unwrap_or(0);
                random_hex(random, len)
            }
            2 | 3 => {
                let len = usize::try_from(random.below(20).saturating_add(1)).unwrap_or(1);
                random_hex(random, len)
            }
            _ => "-".to_owned(),
        };
        let room = match random.below(8) {
            0 => 0,
            1 => slen.saturating_sub(random.below(3).saturating_add(1)),
            2 => slen.saturating_add(random.below(100)),
            _ => slen,
        };
        let mut edits = Vec::new();
        for _ in 0..random.below(3) {
            edits.push(match random.below(5) {
                0 => format!(
                    "s#{}",
                    slen.saturating_add(random.below(3)).saturating_sub(1)
                ),
                1 if mlen > 0 => format!(
                    "m@{}^{:02x}",
                    random.below(u64::try_from(mlen).unwrap_or(1)),
                    random.below(255).saturating_add(1)
                ),
                _ => format!(
                    "s@{}^{:02x}",
                    random.below(slen),
                    random.below(255).saturating_add(1)
                ),
            });
        }
        let edits = if edits.is_empty() {
            "-".to_owned()
        } else {
            edits.join(",")
        };
        writeln!(out, "mldsa {alg} {seed} {msg} {ctx} {opts} {room} {edits}")?;
    }
    Ok(())
}

/// A random session of the X25519 and X448 exchanges and the Ed25519 and Ed448 signatures: secrets with peers
/// random and low-order into buffers of every size, and messages signed and verified by every
/// algorithm and instance, with contexts of every length, and signatures changed or not.
fn ecxop_session(random: &mut Random, out: &mut String) -> Result {
    const LOW_ORDER: [&str; 3] = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    ];
    // X448's: 0, 1, and p - 1 (which the ladder takes as -1).
    const LOW_ORDER_448: [&str; 3] = [
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ];
    for _ in 0..random.below(8).saturating_add(1) {
        let wide = random.below(2) == 0;
        if random.below(3) == 0 {
            let (cmd, len, low) = if wide {
                ("x448x", 56, &LOW_ORDER_448)
            } else {
                ("x25519x", 32, &LOW_ORDER)
            };
            let peer = if random.below(4) == 0 {
                random.pick(low).to_owned()
            } else {
                random_hex(random, len)
            };
            let room = if wide {
                random.pick(&["56", "56", "64", "55", "0"])
            } else {
                random.pick(&["32", "32", "64", "31", "0"])
            };
            writeln!(out, "{cmd} {} {peer} {room}", random_hex(random, len))?;
            continue;
        }
        let (cmd, keylen, siglen) = if wide {
            ("ed448", 57, 114)
        } else {
            ("ed25519", 32, 64)
        };
        let alg = if wide {
            random.pick(&["-", "-", "ED448", "ED448ph"])
        } else {
            random.pick(&["-", "-", "ED25519", "ED25519ph", "ED25519ctx"])
        };
        let instance = random.pick(&[
            "-",
            "-",
            "-",
            "Ed25519",
            "Ed25519ctx",
            "Ed25519ph",
            "ed25519PH",
            "Ed448",
            "Ed448ph",
            "bogus",
        ]);
        let context = match random.below(4) {
            0 | 1 => "-".to_owned(),
            2 => {
                let n = usize::try_from(random.below(8)).unwrap_or(0);
                random_hex(random, n)
            }
            _ => {
                let n = usize::try_from(random.below(260)).unwrap_or(0);
                random_hex(random, n)
            }
        };
        let context = if context.is_empty() {
            "-".to_owned()
        } else {
            context
        };
        let msg = {
            let n = usize::try_from(random.below(100)).unwrap_or(0);
            random_hex(random, n)
        };
        let msg = if msg.is_empty() { "-".to_owned() } else { msg };
        let sig = match random.below(4) {
            0 => random_hex(random, siglen),
            1 => {
                let n = usize::try_from(random.below(120)).unwrap_or(0);
                random_hex(random, n)
            }
            _ => "-".to_owned(),
        };
        let sig = if sig.is_empty() { "-".to_owned() } else { sig };
        writeln!(
            out,
            "{cmd} {alg} {instance} {context} {} {msg} {sig}",
            random_hex(random, keylen)
        )?;
    }
    Ok(())
}

/// A random session of the SM2 asymmetric cipher, from deterministic generators: messages of
/// every length encrypted with digests good and bad into buffers of every size and decrypted
/// again, and ciphertexts near valid ones decrypted.
fn sm2enc_session(random: &mut Random, out: &mut String) -> Result {
    for line in DETERMINISTIC_RAND {
        writeln!(out, "{line}")?;
    }
    for _ in 0..random.below(5).saturating_add(1) {
        let d = match random.below(5) {
            0 => format!("{:x}", random.below(1000).saturating_add(1)),
            _ => random_hex(random, 32),
        };
        let md = random.pick(&["-", "-", "SM3", "SHA256", "SHA1", "SHAKE256", "nosuch"]);
        let len = usize::try_from(random.below(60)).unwrap_or(0);
        let msg = random_hex(random, len);
        let room = random.pick(&["300", "300", "120", "100", "20", "0"]);
        let ct = match random.below(4) {
            0 => {
                let n = usize::try_from(random.below(120)).unwrap_or(0);
                format!("30{}", random_hex(random, n))
            }
            _ => "-".to_owned(),
        };
        writeln!(out, "sm2enc {d} {md} {msg} {ct} {room}")?;
    }
    Ok(())
}

/// A random session of the SM2 signature provider, from deterministic generators: messages and
/// digest-sized numbers signed by keys of every size, with IDs of every length (or none), with
/// SM3 or another digest; and signatures near valid ones verified.
fn sm2sig_session(random: &mut Random, out: &mut String) -> Result {
    for line in DETERMINISTIC_RAND {
        writeln!(out, "{line}")?;
    }
    for _ in 0..random.below(6).saturating_add(1) {
        let d = match random.below(6) {
            0 => format!("{:x}", random.below(1000)),
            1 => "F".repeat(64),
            _ => random_hex(random, 32),
        };
        let id = match random.below(3) {
            0 => "-".to_owned(),
            _ => {
                let len = usize::try_from(random.below(40)).unwrap_or(0);
                if len == 0 {
                    "-".to_owned()
                } else {
                    random_hex(random, len)
                }
            }
        };
        let md = random.pick(&["-", "-", "SM3", "SHA256"]);
        let msg = if random.below(3) == 0 {
            random_hex(random, 32)
        } else {
            let len = usize::try_from(random.below(100)).unwrap_or(0);
            random_hex(random, len)
        };
        let sig = match random.below(3) {
            0 => {
                let len = usize::try_from(random.below(8))
                    .unwrap_or(0)
                    .saturating_add(64);
                format!("30{}", random_hex(random, len))
            }
            _ => "-".to_owned(),
        };
        writeln!(out, "sm2sig {d} {id} {md} {msg} {sig}")?;
    }
    Ok(())
}

/// A random session of the EC key manager on one curve: keys from data of every selection,
/// with private keys of every size, public keys near valid encodings (a random compressed x
/// decompresses about half the time), and the other parameters with good and bad values; and
/// DHKEM key generation on the NIST curves and others, from inputs of every length.
fn eckm_session(random: &mut Random, out: &mut String) -> Result {
    let i = usize::try_from(random.below(EC_CURVES.len() as u64)).unwrap_or(0);
    let (curve, fl) = EC_CURVES.get(i).copied().unwrap_or(("prime256v1", 32));
    for _ in 0..random.below(6).saturating_add(1) {
        if random.below(5) == 0 {
            let group = random.pick(&["P-256", "P-384", "P-521", "P-224", curve]);
            let len = usize::try_from(random.below(80)).unwrap_or(32);
            writeln!(out, "ecdhkem {group} {}", random_hex(random, len))?;
            continue;
        }
        let selection = random.pick(&[
            "87", "87", "86", "85", "84", "83", "81", "80", "7", "6", "4", "1", "0",
        ]);
        let group = if random.below(12) == 0 {
            random.pick(&["-", "nosuchcurve", "SM2", "P-256"])
        } else {
            curve
        };
        let privkey = match random.below(6) {
            0 => "-".to_owned(),
            1 => format!("{:x}", random.below(4)),
            2 => "F".repeat(fl.saturating_mul(2)),
            _ => random_hex(random, fl),
        };
        let pubkey = match random.below(4) {
            0 => "-".to_owned(),
            _ => {
                let first = random.pick(&["02", "03", "04", "06", "07", "00", "05"]);
                let mut len = match first {
                    "02" | "03" => fl,
                    "00" => 0,
                    _ => fl.saturating_mul(2),
                };
                if random.below(8) == 0 {
                    len = len.saturating_add(1);
                }
                format!("{first}{}", random_hex(random, len))
            }
        };
        let mut other = Vec::new();
        for (key, values) in [
            (
                "point-format",
                &["compressed", "uncompressed", "hybrid", "bogus"][..],
            ),
            ("encoding", &["named_curve", "explicit", "bogus"][..]),
            (
                "group-check",
                &["default", "named", "named-nist", "bogus"][..],
            ),
            ("use-cofactor-flag", &["#0", "#1", "#2", "#-1"][..]),
            ("include-public", &["#0", "#1"][..]),
        ] {
            if random.below(4) == 0 {
                other.push(format!("{key}={}", random.pick(values)));
            }
        }
        let other = if other.is_empty() {
            "-".to_owned()
        } else {
            other.join(",")
        };
        // The SM2 key manager takes only SM2's curve; it gets that and others.
        let command = if curve == "SM2" || random.below(8) == 0 {
            "sm2km"
        } else {
            "eckm"
        };
        writeln!(
            out,
            "{command} {selection} {group} {privkey} {pubkey} {other}"
        )?;
    }
    Ok(())
}

/// A random session of EC commands on one curve: encodings near valid ones (random x, which a
/// compressed form decompresses about half the time; uncompressed and hybrid ones, mostly off
/// the curve; lengths a little off; bad first octets), decompression, multiplication by scalars
/// of every size and sign, and addition, sometimes from a known generator.
fn ec_session(random: &mut Random, out: &mut String) -> Result {
    if random.below(2) == 0 {
        for line in [
            "rctx 0",
            "rnew TEST-RAND",
            "rset strength=256 test_entropy=64 test_nonce=32",
            "rinst 0 0",
            "rctx 1",
            "rnew HASH-DRBG child",
            "rset digest=SHA256",
            "rinst 0 0",
            "rsetpub",
            "rsetpriv",
        ] {
            writeln!(out, "{line}")?;
        }
    }
    let i = usize::try_from(random.below(EC_CURVES.len() as u64)).unwrap_or(0);
    let (curve, fl) = EC_CURVES.get(i).copied().unwrap_or(("prime256v1", 32));
    writeln!(out, "ecgrp {curve}")?;
    // Start with a known point: the generator times a small scalar.
    writeln!(out, "ecmul 0 {:x} - -", random.below(1000) + 1)?;
    for _ in 0..random.below(12) + 1 {
        let r = random.below(2);
        match random.below(6) {
            0 | 1 => {
                let first = random.pick(&["02", "03", "04", "06", "07", "00", "05", "08"]);
                let mut len = match first {
                    "02" | "03" => fl,
                    "00" => 0,
                    _ => fl * 2,
                };
                if random.below(8) == 0 {
                    len = len.saturating_add(1);
                } else if random.below(8) == 0 {
                    len = len.saturating_sub(1);
                }
                writeln!(out, "ecpt {r} {first}{}", random_hex(random, len))?;
            }
            2 => {
                let x = if random.below(6) == 0 {
                    random.pick(&["0", "1", "2"]).to_owned()
                } else {
                    random_hex(random, fl)
                };
                writeln!(out, "eccomp {r} {x} {}", random.below(2))?;
            }
            3 | 4 => {
                let scalar = |random: &mut Random| -> String {
                    match random.below(6) {
                        0 => "-".to_owned(),
                        1 => format!("{:x}", random.below(100)),
                        2 => format!("-{}", random_hex(random, fl)),
                        3 => "F".repeat(fl * 2),
                        _ => {
                            let extra = usize::try_from(random.below(3)).unwrap_or(0);
                            random_hex(random, fl + extra)
                        }
                    }
                };
                let k = scalar(random);
                let mut p = random.pick(&["-", "0", "1"]);
                let k2 = scalar(random);
                // OpenSSL's binary curves crash on a point's scalar without a point or the
                // generator's, and its sm2p256 (aarch64) returns uninitialized memory
                // (docs/DEVIATIONS.md).
                let odd = ["sect", "c2", "Oakley", "SM2"]
                    .iter()
                    .any(|b| curve.starts_with(b));
                if odd && k == "-" && p == "-" && k2 != "-" {
                    p = "0";
                }
                writeln!(out, "ecmul {r} {k} {p} {k2}")?;
            }
            _ => writeln!(out, "ecadd {r} {} {}", random.below(2), random.below(2))?,
        }
    }
    Ok(())
}

fn bn_hex(random: &mut Random) -> String {
    let digits = if random.below(4) == 0 {
        random
            .pick(&[
                "0",
                "1",
                "7F",
                "80",
                "FF",
                "100",
                "7FFFFFFFFFFFFFFF",
                "FFFFFFFFFFFFFFFF",
                "10000000000000000",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                "100000000000000000000000000000000",
            ])
            .to_owned()
    } else {
        let len = random.below(96) + 1;
        (0..len)
            .map(|_| match random.below(8) {
                0 | 1 => '0',
                2 | 3 => 'F',
                _ => char::from_digit(u32::try_from(random.below(16)).unwrap_or(0), 16)
                    .unwrap_or('0')
                    .to_ascii_uppercase(),
            })
            .collect()
    };
    if random.below(3) == 0 {
        format!("-{digits}")
    } else {
        digits
    }
}

/// A random session of big-number commands on the probe's four registers: text in and out,
/// the arithmetic (aliasing results with operands), words, bits, octets either way round and
/// signed, MPIs, ASN.1 integers, parameters, random numbers (from a known generator in a third
/// of the sessions), and the modular arithmetic: each exponentiation, inverses, gcds, square
/// roots, the Montgomery and reciprocal contexts, the NIST and RFC primes, primality tests,
/// prime generation, and binary fields.
fn bn_session(random: &mut Random, out: &mut String) -> Result {
    const OPS: &[&str] = &[
        "add", "sub", "uadd", "usub", "mul", "sqr", "nnmod", "exp", "cmp", "copy", "swap",
    ];
    const KINDS: &[&str] = &["bin", "lebin", "native", "sbin", "slebin", "snative"];
    let known = random.below(3) == 0;
    if known {
        for line in [
            "rctx 0",
            "rnew TEST-RAND",
            "rset strength=256 test_entropy=64 test_nonce=32",
            "rinst 0 0",
            "rctx 1",
            "rnew HASH-DRBG child",
            "rset digest=SHA256",
            "rinst 0 0",
            "rsetpub",
            "rsetpriv",
        ] {
            writeln!(out, "{line}")?;
        }
    }
    for r in 0..4 {
        writeln!(out, "bnset {r} {}", bn_hex(random))?;
    }
    let reg = |random: &mut Random| random.below(4);
    for _ in 0..random.below(30) + 1 {
        match random.below(44) {
            0 => writeln!(out, "bnset {} {}", reg(random), bn_hex(random))?,
            1 => {
                let kind = random.pick(&["dec", "hex", "asc"]);
                let text = match random.below(4) {
                    0 => format!("0x{}", bn_hex(random)),
                    1 => format!("{}z{}", random.below(1_000_000_000), random.below(10)),
                    2 => random
                        .pick(&[
                            "-",
                            "",
                            "--1",
                            "-0x-1",
                            "0x",
                            "-0",
                            "00000000000000000000001",
                        ])
                        .to_owned(),
                    _ => bn_hex(random),
                };
                let text = if text.is_empty() {
                    "-".to_owned()
                } else {
                    text
                };
                writeln!(out, "bntext {} {kind} {text}", reg(random))?;
            }
            2..=6 => writeln!(
                out,
                "bnop {} {} {} {}",
                random.pick(OPS),
                reg(random),
                reg(random),
                reg(random)
            )?,
            7 | 8 => {
                let q = if random.below(4) == 0 {
                    "-".to_owned()
                } else {
                    reg(random).to_string()
                };
                let rem = if random.below(4) == 0 {
                    "-".to_owned()
                } else {
                    reg(random).to_string()
                };
                writeln!(out, "bndiv {q} {rem} {} {}", reg(random), reg(random))?;
            }
            9 => writeln!(
                out,
                "bnshift {} {} {} {}",
                random.pick(&["lshift", "rshift", "lshift1", "rshift1"]),
                reg(random),
                reg(random),
                random.offset(-2, 300)
            )?,
            10 => writeln!(
                out,
                "bnword {} {} {}",
                random.pick(&["add", "sub", "mul", "div", "mod"]),
                reg(random),
                random.pick(&[
                    "0",
                    "1",
                    "2",
                    "7",
                    "10",
                    "1000000007",
                    "4294967296",
                    "9223372036854775808",
                    "18446744073709551615"
                ])
            )?,
            11 => writeln!(
                out,
                "bnbit {} {} {}",
                random.pick(&["set", "clear", "isset", "mask"]),
                reg(random),
                random.offset(-1, 400)
            )?,
            12 => {
                if random.below(4) == 0 {
                    writeln!(out, "bnflag {}", reg(random))?;
                } else {
                    writeln!(out, "bnshow {}", reg(random))?;
                }
            }
            13 | 14 => writeln!(
                out,
                "bnto {} {} {}",
                reg(random),
                random.pick(&[
                    "bin", "binpad", "lebin", "native", "sbin", "slebin", "snative", "mpi"
                ]),
                random.offset(-2, 70)
            )?,
            15 => {
                let len = random.below(40);
                let hex: String = (0..len)
                    .map(|_| match random.below(5) {
                        0 => "00".to_owned(),
                        1 => "ff".to_owned(),
                        _ => format!("{:02x}", random.below(256)),
                    })
                    .collect();
                let hex = if hex.is_empty() { "-".to_owned() } else { hex };
                writeln!(out, "bnfrom {} {} {hex}", reg(random), random.pick(KINDS))?;
            }
            16 => {
                let body = random.below(20);
                let len = if random.below(4) == 0 {
                    random.below(30)
                } else {
                    body
                };
                let hex: String = (0..body)
                    .map(|_| format!("{:02x}", random.below(256)))
                    .collect();
                writeln!(out, "bnfrom {} mpi {len:08x}{hex}", reg(random))?;
            }
            17 => writeln!(
                out,
                "bnrand {} {} {} {} {}",
                reg(random),
                random.offset(-1, 300),
                random.offset(-1, 3),
                random.below(2),
                random.below(3)
            )?,
            18 => writeln!(
                out,
                "bnrange {} {} {}",
                reg(random),
                reg(random),
                random.below(2)
            )?,
            19 => writeln!(out, "bnasn1 {}", reg(random))?,
            20 => writeln!(
                out,
                "bnparam {} {} {}",
                reg(random),
                random.pick(&["u", "s"]),
                random.below(40)
            )?,
            21..=24 => writeln!(
                out,
                "bnmod {} {} {} {} {}",
                random.pick(&[
                    "add", "sub", "mul", "sqr", "lshift1", "addq", "subq", "lshift1q"
                ]),
                reg(random),
                reg(random),
                reg(random),
                reg(random)
            )?,
            25 => writeln!(
                out,
                "bnmshift {} {} {} {} {}",
                random.pick(&["q", "n"]),
                reg(random),
                reg(random),
                random.offset(-2, 200),
                reg(random)
            )?,
            26..=29 => writeln!(
                out,
                "bnexp {} {} {} {} {}",
                random.pick(&["exp", "mont", "ct", "recp", "simple", "word"]),
                reg(random),
                reg(random),
                reg(random),
                reg(random)
            )?,
            30 => writeln!(
                out,
                "bnexp2 {} {} {} {} {} {}",
                reg(random),
                reg(random),
                reg(random),
                reg(random),
                reg(random),
                reg(random)
            )?,
            31 | 32 => {
                let target = if random.below(3) == 0 {
                    "-".to_owned()
                } else {
                    reg(random).to_string()
                };
                writeln!(out, "bninv {target} {} {}", reg(random), reg(random))?;
            }
            33 => writeln!(
                out,
                "{} {} {}",
                random.pick(&["bngcd 0", "bngcd 3", "bnkron", "bncoprime"]),
                reg(random),
                reg(random)
            )?,
            34 => {
                let target = if random.below(2) == 0 {
                    "-".to_owned()
                } else {
                    reg(random).to_string()
                };
                writeln!(out, "bnsqrt {target} {} {}", reg(random), reg(random))?;
            }
            35 | 36 => writeln!(
                out,
                "{} {} {} {} {} {}",
                random.pick(&["bnmont", "bnrecp"]),
                random.pick(&["mul", "to", "from", "div", "recip"]),
                reg(random),
                reg(random),
                reg(random),
                reg(random)
            )?,
            37 => writeln!(
                out,
                "bnnist {} {} {}",
                random.pick(&["192", "224", "256", "384", "521"]),
                reg(random),
                reg(random)
            )?,
            38 => writeln!(out, "bnprime {} {}", random.below(8), reg(random))?,
            39 => writeln!(
                out,
                "bnisprime {} {} {}",
                reg(random),
                random.pick(&["check", "ex", "fast"]),
                random.offset(-1, 80)
            )?,
            40 => {
                // Only combinations that end: a safe prime with add needs rem 11 mod 12.
                let (safe, add, rem) = match random.below(5) {
                    0 => (1, 0, 0),
                    1 => (0, 12, 7),
                    2 => (0, 12, 0),
                    3 => (1, 12, 11),
                    _ => (0, 0, 0),
                };
                let bits = if safe == 1 {
                    6 + random.below(40)
                } else {
                    random.below(120)
                };
                let bits = if add != 0 { bits.max(8) } else { bits };
                writeln!(out, "bngen {} {bits} {safe} {add} {rem}", reg(random))?;
            }
            _ => writeln!(
                out,
                "bngf2m {} {} {} {} {}",
                random.pick(&[
                    "mod", "add", "mul", "sqr", "inv", "div", "exp", "sqrt", "solve", "modarr",
                    "mularr", "sqrarr", "invarr", "divarr", "exparr", "sqrtarr", "solvearr"
                ]),
                reg(random),
                reg(random),
                reg(random),
                random.below(6)
            )?,
        }
    }
    if known {
        for line in ["rreset", "rctx 0", "rfree", "rctx 1", "rfree", "rctx 0"] {
            writeln!(out, "{line}")?;
        }
    }
    Ok(())
}

/// A random session of cipher commands on the probe's two contexts: inits by name (or with
/// none, keeping the cipher, with and without a key and IV, in either direction), updates of
/// lengths around the block sizes, finals, `EVP_Cipher`, padding, key lengths, `num`, flags
/// (CFB1 counting bits), ctrls, init parameters, copies, resets, and name lookups.
fn cipher_session(random: &mut Random, out: &mut String) -> Result {
    const CIPHERS: &[&str] = &[
        "AES-128-ECB",
        "AES-192-ECB",
        "AES-256-ECB",
        "AES-128-CBC",
        "AES-192-CBC",
        "AES-256-CBC",
        "AES-128-OFB",
        "AES-256-OFB",
        "AES-128-CFB",
        "AES-192-CFB",
        "AES-128-CFB1",
        "AES-256-CFB1",
        "AES-128-CFB8",
        "AES-192-CFB8",
        "AES-128-CTR",
        "AES-256-CTR",
        "ARIA-128-ECB",
        "ARIA-192-CBC",
        "ARIA-256-OFB",
        "ARIA-128-CFB",
        "ARIA-192-CFB1",
        "ARIA-256-CFB8",
        "ARIA-128-CTR",
        "CAMELLIA-256-ECB",
        "CAMELLIA-128-CBC",
        "CAMELLIA-192-OFB",
        "CAMELLIA-256-CFB",
        "CAMELLIA-128-CFB1",
        "CAMELLIA-192-CFB8",
        "CAMELLIA-256-CTR",
        "DES-EDE3-ECB",
        "DES-EDE3-CBC",
        "DES-EDE3-OFB",
        "DES-EDE3-CFB",
        "DES-EDE3-CFB8",
        "DES-EDE3-CFB1",
        "DES-EDE-ECB",
        "DES-EDE-CBC",
        "DES-EDE-OFB",
        "DES-EDE-CFB",
        "SM4-ECB",
        "SM4-CBC",
        "SM4-CTR",
        "SM4-OFB",
        "SM4-CFB",
        "ChaCha20",
        "NULL",
        "AES-128-GCM",
        "AES-256-GCM",
        "ARIA-192-GCM",
        "SM4-GCM",
        "AES-128-CCM",
        "AES-192-CCM",
        "ARIA-256-CCM",
        "SM4-CCM",
        "AES-128-OCB",
        "AES-256-OCB",
        "ChaCha20-Poly1305",
        "AES-128-CBC-CTS",
        "CAMELLIA-256-CBC-CTS",
        "AES-128-XTS",
        "AES-256-XTS",
        "SM4-XTS",
        "AES-128-WRAP",
        "AES-192-WRAP-PAD",
        "AES-256-WRAP-INV",
        "AES-128-WRAP-PAD-INV",
        "DES3-WRAP",
        "AES-128-SIV",
        "AES-256-SIV",
        "AES-128-GCM-SIV",
        "AES-256-GCM-SIV",
        "AES-128-CBC-HMAC-SHA1",
        "AES-256-CBC-HMAC-SHA256",
        "nonesuch",
    ];
    let length = |random: &mut Random| -> u64 {
        match random.below(4) {
            0 => random.below(4),
            1 => random
                .pick(&[
                    "7", "8", "9", "15", "16", "17", "31", "32", "33", "63", "64", "65",
                ])
                .parse()
                .unwrap_or(0),
            _ => random.below(300),
        }
    };
    let bit = |random: &mut Random| random.below(2);
    for _ in 0..random.below(25) + 1 {
        match random.below(27) {
            0..=2 => {
                let enc = random.pick(&["1", "0"]);
                writeln!(out, "cinit {} {enc} 1 1", random.pick(CIPHERS))?;
            }
            3 => {
                let enc = random.pick(&["1", "0", "-1"]);
                writeln!(
                    out,
                    "cinit {} {enc} {} {}",
                    random.pick(CIPHERS),
                    bit(random),
                    bit(random)
                )?;
            }
            4 => {
                let enc = random.pick(&["1", "0", "-1"]);
                writeln!(out, "cinit - {enc} {} {}", bit(random), bit(random))?;
            }
            5 => {
                let key = random.pick(&["keylen", "ivlen", "padding", "num", "use-bits"]);
                let n = random.pick(&["0", "1", "3", "8", "12", "16", "24", "32", "4294967295"]);
                writeln!(out, "cinitp {} {key} {n}", random.pick(CIPHERS))?;
            }
            6..=9 => writeln!(out, "cupdate {}", length(random))?,
            20 | 21 => writeln!(
                out,
                "{} {}",
                random.pick(&["caad", "caad", "cmsglen"]),
                length(random)
            )?,
            22 | 23 => {
                let n = random.pick(&["0", "1", "4", "6", "8", "12", "13", "16"]);
                let c = random.pick(&["ctagget", "ctagget", "ctagset", "ctaglen"]);
                writeln!(out, "{c} {n}")?;
            }
            10 | 11 => writeln!(out, "cfinal")?,
            24 => {
                let (name, value) = match random.below(3) {
                    0 => (
                        "cts_mode",
                        random.pick(&["CS1", "CS2", "CS3", "cs2", "CS4"]),
                    ),
                    1 => ("xts_standard", random.pick(&["GB", "IEEE", "ieee", "ISO"])),
                    _ => ("speed", random.pick(&["0", "1", "2"])),
                };
                writeln!(out, "cparam {name} {value}")?;
            }
            25 | 26 => {
                let version = random.pick(&["301", "302", "303", "304", "fefd"]);
                let len = random.pick(&["0", "15", "16", "17", "32", "33", "50", "100"]);
                writeln!(out, "ctlsaad {version} {len}")?;
            }
            12 => writeln!(out, "ccipher {}", length(random))?,
            13 => writeln!(out, "cpad {}", bit(random))?,
            14 => {
                let n = random.pick(&["0", "1", "8", "15", "16", "24", "32", "-1"]);
                writeln!(out, "{} {n}", random.pick(&["ckeylen", "cnum"]))?;
            }
            15 => {
                let f = random.pick(&["2000", "100", "1", "2100", "ffff"]);
                writeln!(out, "cflags {} {f}", random.pick(&["set", "clear"]))?;
            }
            16 => {
                // SET_KEY_LENGTH, INIT, AEAD_SET_IVLEN, GET_TAG, SET_TAG, CCM_SET_L,
                // AEAD_SET_IV_FIXED, GCM_IV_GEN, GCM_SET_IV_INV, TLS1_AAD, the RC2 and RC5
                // ones, SET_SPEED, AEAD_SET_MAC_KEY, MULTIBLOCK_MAX_BUFSIZE, an unknown one.
                let t = random.pick(&[
                    "9", "1", "9", "16", "17", "20", "18", "19", "24", "22", "2", "3", "4", "5",
                    "11", "23", "28", "30583",
                ]);
                // A fixed IV past the IV (or an inverted one past it) writes outside the
                // reference's context (docs/DEVIATIONS.md): not drawn.
                let a = match t {
                    "18" => random.pick(&["-1", "4", "8", "12"]),
                    "24" => random.pick(&["0", "4", "8"]),
                    _ => random.pick(&["-1", "0", "1", "4", "12", "13", "16", "24", "32"]),
                };
                writeln!(out, "cctrl {t} {a}")?;
            }
            17 => writeln!(
                out,
                "{}",
                random.pick(&["cstate", "ccopy", "creset", "cctx 1", "cctx 0", "casn1"])
            )?,
            18 => {
                let name = random.pick(&[
                    "AES-128-CBC",
                    "aes128",
                    "AES256",
                    "des3",
                    "DES-EDE3",
                    "des-ede3-ecb",
                    "2.16.840.1.101.3.4.1.2",
                    "AES-128-CFB1",
                    "aes-128-ctr",
                    "id-aes128-GCM",
                    "AES-128-GCM",
                    "ChaCha20",
                    "chacha20-poly1305",
                    "SHA256",
                    "sm4-ofb128",
                    "camellia256",
                    "ARIA128",
                    "rc2-40",
                    "blowfish",
                    "desx",
                    "NULL",
                    "UNDEF",
                    "nonesuch",
                ]);
                let name: String = name
                    .chars()
                    .map(|c| {
                        if random.below(4) == 0 {
                            c.to_ascii_uppercase()
                        } else {
                            c
                        }
                    })
                    .collect();
                writeln!(out, "cname {name}")?;
            }
            _ => writeln!(
                out,
                "cnid {}",
                random.pick(&[
                    "419", "421", "650", "653", "904", "44", "33", "32", "1019", "1018", "895",
                    "31", "5", "0", "64", "99999", "-1",
                ])
            )?,
        }
    }
    writeln!(out, "cctx 0")?;
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
            if random.below(2) == 0 {
                // A DEK-Info line, right or wrong in each part.
                let cipher = random.pick(&[
                    "AES-128-CBC",
                    "aes-256-cbc",
                    "DES-EDE3-CBC",
                    "AES-128-ECB",
                    "NOSUCH",
                    "",
                ]);
                let sep = random.pick(&[",", ",", " ,", " ", ""]);
                let digits: usize = random
                    .pick(&["32", "32", "16", "0", "3", "40"])
                    .parse()
                    .unwrap_or(0);
                let mut iv = String::new();
                for _ in 0..digits {
                    iv.push_str(random.pick(&["0", "7", "a", "F", "c", "z"]));
                }
                let tag = random.pick(&["DEK-Info: ", "DEK-Info:", "Dek-Info: "]);
                text.extend_from_slice(format!("{tag}{cipher}{sep}{iv}\n").as_bytes());
            }
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

/// Random octets as the probe's hex (`-` for none).
fn pkey_hex(random: &mut Random, max: u64) -> String {
    let len = if random.below(8) == 0 {
        0
    } else {
        random.below(max) + 1
    };
    if len == 0 {
        return "-".to_owned();
    }
    (0..len)
        .map(|_| format!("{:02x}", random.below(256)))
        .collect()
}

/// A random session of key commands (`EVP_PKEY`) on the probe's eight slots: raw keys by name
/// and id, MAC and CMAC keys, generation and parameter generation (with and without a key),
/// keys from parameters (with every selection, wrong types, and ciphers), parameters, copies,
/// comparisons, typing, checks, and signing (through digest contexts and the `EVP_PKEY_sign`
/// family), over the MAC and KDF key types and some that don't exist.
/// The digests the derivation commands name.
const KDF_DIGESTS: &[&str] = &[
    "SHA256", "SHA1", "SHA512", "SHA3-256", "MD5", "MD5-SHA1", "SHAKE128", "NOPE",
];

/// The named ctrls of `pkctrl`.
const PK_CTRLS: &[&str] = &[
    "tls_md",
    "tls_secret",
    "tls_seed",
    "hkdf_md",
    "hkdf_salt",
    "hkdf_key",
    "hkdf_info",
    "hkdf_mode",
    "pass",
    "scrypt_salt",
    "scrypt_n",
    "scrypt_r",
    "scrypt_p",
    "scrypt_maxmem",
    "mac_key",
    "digest_size",
    "set1_id",
    "cipher",
    "md",
    "dh_pad",
    "unknown",
];

/// The key types the `meth*` commands add a method for.
const METH_TYPES: &[&str] = &[
    "RSA", "RSA-PSS", "EC", "SM2", "DH", "DHX", "DSA", "X25519", "X448", "ED25519", "HMAC", "toy",
];

/// The operations a `meth*` command's context is initialized for.
const METH_OPS: &[&str] = &[
    "sign",
    "verify",
    "verifyrecover",
    "encrypt",
    "decrypt",
    "derive",
    "keygen",
    "paramgen",
    "none",
    "custom",
];

/// The parameter keys of the ctrl translations, and some that aren't.
const METH_KEYS: &[&str] = &[
    "distid",
    "kdf-type",
    "kdf-digest",
    "kdf-digest-props",
    "kdf-outlen",
    "kdf-ukm",
    "cekalg",
    "type",
    "pbits",
    "qbits",
    "group",
    "safeprime-generator",
    "pad",
    "digest",
    "encoding",
    "ecdh-cofactor-mode",
    "pad-mode",
    "mgf1-digest",
    "saltlen",
    "oaep-label",
    "implicit-rejection",
    "bits",
    "e",
    "primes",
    "size",
    "secret",
    "seed",
    "salt",
    "key",
    "info",
    "mode",
    "pass",
    "n",
    "r",
    "p",
    "maxmem_bytes",
    "cipher",
    "priv",
    "nope",
];

/// A session of applications' methods: lookups in the method tables, and contexts with a
/// logging method taking parameters (as ctrls), ctrls, and ctrl strings.
fn meth_session(random: &mut Random, out: &mut String) -> Result {
    let ret = |random: &mut Random| random.pick(&["1", "1", "0", "-1", "-2", "2", "3", "16"]);
    for _ in 0..1 + random.below(12) {
        match random.below(6) {
            0 => {
                let id = match random.below(3) {
                    0 => random.below(1200).to_string(),
                    _ => random
                        .pick(&[
                            "6", "19", "28", "67", "116", "408", "912", "920", "1034", "1087",
                            "1172", "855", "0", "-1",
                        ])
                        .to_owned(),
                };
                writeln!(out, "methfind {id}")?;
            }
            1 => {
                let name = random.pick(&[
                    "RSA", "rsa", "RSA-PSS", "x9.42", "X9.42 DH", "DHX", "EC", "ec", "ED448", "x",
                    "-",
                ]);
                let len = random.pick(&["-1", "-1", "0", "1", "2", "3", "7", "-2"]);
                writeln!(out, "methstr {name} {len}")?;
            }
            2 | 3 => {
                let op = random.pick(METH_OPS);
                let dir = random.pick(&["set", "get"]);
                let key = random.pick(METH_KEYS);
                // Setting the HKDF mode makes the reference compare a NULL name
                // (docs/DEVIATIONS.md).
                if dir == "set" && key == "mode" && op == "derive" {
                    continue;
                }
                let ptype = random.pick(&["int", "uint", "utf8", "octets", "octptr"]);
                let value = match ptype {
                    "int" | "uint" => random
                        .pick(&["0", "1", "2", "3", "6", "16", "-1", "-2", "65537"])
                        .to_owned(),
                    "utf8" => random
                        .pick(&[
                            "SHA256",
                            "NOPE",
                            "pkcs1",
                            "pss",
                            "oaep",
                            "none",
                            "x931",
                            "auto",
                            "max",
                            "digest",
                            "20",
                            "X942KDF-ASN1",
                            "X963KDF",
                            "P-256",
                            "prime256v1",
                            "explicit",
                            "named_curve",
                            "X25519",
                            "x448",
                            "EXTRACT_ONLY",
                            "1.2.3.4",
                            "ffdhe2048",
                            "-",
                        ])
                        .to_owned(),
                    "octets" => pkey_hex(random, 12),
                    _ => "-".to_owned(),
                };
                let ret = ret(random);
                writeln!(
                    out,
                    "methparam {} {op} {dir} {key} {ptype} {value} {ret}",
                    random.pick(METH_TYPES)
                )?;
            }
            4 => {
                let cmd = random
                    .pick(&[
                        "1", "2", "3", "7", "13", "14", "15", "16", "17", "4097", "4098", "4099",
                        "4100", "4101", "4102", "4103", "4104", "4105", "4106", "4107", "4108",
                        "4109", "4110", "9999",
                    ])
                    .to_owned();
                // A distinguishing ID with a length but no pointer is copied from NULL by the
                // reference.
                let p1 = if cmd == "15" {
                    "0".to_owned()
                } else {
                    random.pick(&["0", "1", "-1", "-2", "8", "2048"]).to_owned()
                };
                let ret = ret(random);
                writeln!(
                    out,
                    "methctrl {} {} {} {} {cmd} {p1} {ret}",
                    random.pick(METH_TYPES),
                    random.pick(METH_OPS),
                    random.pick(&["-1", "-1", "6", "408", "28", "920", "1034", "855"]),
                    random.pick(&["-1", "-1", "0", "8", "16", "248", "1024", "4", "2048"]),
                )?;
            }
            _ => {
                let name = random.pick(&[
                    "digest",
                    "md",
                    "distid",
                    "hexdistid",
                    "key",
                    "hexkey",
                    "salt",
                    "hexsalt",
                    "dh_pad",
                    "nope",
                ]);
                let value = match name {
                    "digest" | "md" => random.pick(&["SHA256", "sha1", "NOPE"]).to_owned(),
                    _ => pkey_hex(random, 8),
                };
                let ret = ret(random);
                writeln!(
                    out,
                    "methctrlstr {} {} {name} {value} {ret}",
                    random.pick(METH_TYPES),
                    random.pick(METH_OPS)
                )?;
            }
        }
    }
    Ok(())
}

/// A `pkderive` line: a KDF context (scrypt's with small costs first: its defaults take a
/// GiB) and ctrl strings, known and not.
fn derive_line(random: &mut Random, out: &mut String) -> Result {
    let kdf = random.pick(&[
        "HKDF", "TLS1-PRF", "SCRYPT", "1036", "1021", "973", "HMAC", "NOPE",
    ]);
    let len = random.pick(&["0", "16", "20", "32", "42", "64", "100"]);
    let mut line = format!("pkderive {kdf} {len}");
    if matches!(kdf, "SCRYPT" | "973") {
        line.push_str(" N=16 r=1 p=1");
    }
    for _ in 0..random.below(7) {
        let name = random.pick(&[
            "md",
            "digest",
            "salt",
            "hexsalt",
            "key",
            "hexkey",
            "info",
            "hexinfo",
            "mode",
            "secret",
            "hexsecret",
            "seed",
            "hexseed",
            "pass",
            "hexpass",
            "N",
            "r",
            "p",
            "maxmem_bytes",
            "properties",
            "distid",
            "hexdistid",
            "foo",
            "MD",
            "n",
            "size",
        ]);
        let value = match name {
            "md" | "digest" | "MD" => random.pick(KDF_DIGESTS).to_owned(),
            "mode" => random
                .pick(&[
                    "EXTRACT_AND_EXPAND",
                    "EXTRACT_ONLY",
                    "EXPAND_ONLY",
                    "x",
                    "1",
                ])
                .to_owned(),
            "N" | "n" => random
                .pick(&["1", "2", "4", "8", "16", "3", "0", "x"])
                .to_owned(),
            "r" | "p" => random.pick(&["1", "2", "0", "x"]).to_owned(),
            "maxmem_bytes" => random.pick(&["1048576", "0", "1", "x"]).to_owned(),
            "properties" => random.pick(&["", "provider=default", "x"]).to_owned(),
            n if n.starts_with("hex") => {
                if random.below(5) == 0 {
                    random.pick(&["z", "abc", "0g"]).to_owned()
                } else {
                    let h = pkey_hex(random, 20);
                    if h == "-" { String::new() } else { h }
                }
            }
            _ => random
                .pick(&["", "abc", "secret", "0123456789abcdef", "x=y"])
                .to_owned(),
        };
        line.push_str(&format!(" {name}={value}"));
    }
    writeln!(out, "{line}")?;
    Ok(())
}

fn pkey_session(random: &mut Random, out: &mut String) -> Result {
    const NAMES: &[&str] = &[
        "HMAC",
        "SIPHASH",
        "POLY1305",
        "CMAC",
        "HKDF",
        "TLS1-PRF",
        "SCRYPT",
        "id-scrypt",
        "hmac",
        "NOPE",
        "855",
        "1062",
        "1061",
        "894",
        "1036",
        "99999",
    ];
    const IDS: &[&str] = &[
        "855", "1062", "1061", "894", "1036", "1021", "973", "0", "-1", "99999",
    ];
    const CIPHERS: &[&str] = &[
        "AES-128-CBC",
        "AES-192-CBC",
        "AES-256-CBC",
        "DES-EDE3-CBC",
        "AES-128-GCM",
        "RC4",
        "NOPE",
    ];
    const SELECTIONS: &[&str] = &["keypair", "public", "private", "params", "all"];
    const TYPES: &[&str] = &[
        "6", "19", "28", "116", "67", "66", "408", "912", "920", "1034", "1087", "1172", "855", "0",
    ];
    const TYPE_NAMES: &[&str] = &[
        "RSA", "rsa", "DH", "DSA", "EC", "X25519", "ED448", "RSA-PSS", "nope", "SM2",
    ];
    let slot = |random: &mut Random| random.below(8);
    for _ in 0..random.below(25) + 1 {
        let s = slot(random);
        match random.below(26) {
            0 | 1 => writeln!(
                out,
                "pkraw {s} {} {}",
                random.pick(NAMES),
                pkey_hex(random, 40)
            )?,
            2 => writeln!(
                out,
                "pkrawid {s} {} {}",
                random.pick(IDS),
                pkey_hex(random, 40)
            )?,
            3 => writeln!(
                out,
                "pkpub {s} {} {}",
                random.pick(NAMES),
                pkey_hex(random, 40)
            )?,
            4 => {
                let len = random.pick(&["16", "24", "32", "8", "0"]);
                let n: u64 = len.parse().unwrap_or(16);
                let key = if n == 0 {
                    "-".to_owned()
                } else {
                    (0..n)
                        .map(|_| format!("{:02x}", random.below(256)))
                        .collect()
                };
                writeln!(out, "pkcmac {s} {} {key}", random.pick(CIPHERS))?;
            }
            5 => writeln!(
                out,
                "pkmac {s} {} {}",
                random.pick(IDS),
                pkey_hex(random, 40)
            )?,
            6 => {
                let key = if random.below(4) == 0 {
                    "none".to_owned()
                } else {
                    pkey_hex(random, 40)
                };
                let cmd = if random.below(4) == 0 {
                    "pkparamgen"
                } else {
                    "pkgen"
                };
                writeln!(out, "{cmd} {s} {} {key}", random.pick(NAMES))?;
            }
            7 | 8 => {
                let mut line = format!(
                    "pkfrom {s} {} {}",
                    random.pick(NAMES),
                    random.pick(SELECTIONS)
                );
                for _ in 0..random.below(4) {
                    match random.below(5) {
                        0 | 1 => line.push_str(&format!(" priv={}", pkey_hex(random, 40))),
                        2 => line.push_str(&format!(" cipher={}", random.pick(CIPHERS))),
                        3 => line.push_str(&format!(
                            " properties={}",
                            random.pick(&["provider=default", "provider=base", "x", "?fips=yes"])
                        )),
                        _ => line.push_str(" privstr=abc"),
                    }
                }
                writeln!(out, "{line}")?;
            }
            9 => {
                let key = random.pick(&["priv", "bits", "cipher", "encoded-pub-key"]);
                writeln!(out, "pkset {s} {key} {}", pkey_hex(random, 40))?;
            }
            10 => {
                let key = random.pick(&["priv", "cipher", "properties"]);
                writeln!(out, "pksetstr {s} {key} {}", random.pick(CIPHERS))?;
            }
            11 => writeln!(out, "pkeq {s} {}", slot(random))?,
            12 => {
                let cmd = random.pick(&["pkcopy", "pkdup"]);
                writeln!(out, "{cmd} {s} {}", slot(random))?;
            }
            13 => {
                if random.below(2) == 0 {
                    writeln!(out, "pktype {s} {}", random.pick(TYPES))?;
                } else {
                    let len = random.pick(&["-1", "1", "2", "3"]);
                    writeln!(out, "pktypestr {s} {} {len}", random.pick(TYPE_NAMES))?;
                }
            }
            14 => writeln!(out, "pkcheck {s}")?,
            15 | 16 => {
                const DIGESTS: &[&str] = &[
                    "-",
                    "SHA256",
                    "SHA2-512",
                    "SHA1",
                    "MD5",
                    "SHA3-256",
                    "SHAKE128",
                    "NOPE",
                    "SM3",
                    "BLAKE2B-512",
                ];
                let cmd = random.pick(&["pkdsign", "pkdsign", "pkdsignone"]);
                let mut line = format!("{cmd} {s} {} {}", random.pick(DIGESTS), random.below(2));
                for _ in 0..random.below(4) {
                    line.push(' ');
                    line.push_str(&pkey_hex(random, 60));
                }
                writeln!(out, "{line}")?;
            }
            17 => {
                // The message operations aren't run after an init with an algorithm of
                // another key type: the reference crashes there (docs/DEVIATIONS.md).
                let op = random.pick(&["sign", "verify", "recover", "signmsg", "verifymsg"]);
                let alg = random.pick(&["-", "HMAC", "SIPHASH", "POLY1305", "CMAC", "NOPE"]);
                writeln!(out, "pksiginit {s} {op} {alg}")?;
            }
            18 => writeln!(out, "pkcansign {s}")?,
            19 | 20 => derive_line(random, out)?,
            21 => {
                let cmd = random.pick(PK_CTRLS);
                let arg = match cmd {
                    "tls_md" | "hkdf_md" | "md" => random.pick(KDF_DIGESTS).to_owned(),
                    "cipher" => random.pick(CIPHERS).to_owned(),
                    "hkdf_mode" | "scrypt_n" | "scrypt_r" | "scrypt_p" | "scrypt_maxmem"
                    | "digest_size" | "dh_pad" | "unknown" => random
                        .pick(&["0", "1", "2", "3", "8", "16", "-1", "1048576"])
                        .to_owned(),
                    _ => pkey_hex(random, 20),
                };
                writeln!(
                    out,
                    "pkctrl {} {} {} {cmd} {arg}",
                    random.pick(&[
                        "HKDF", "TLS1-PRF", "SCRYPT", "HMAC", "CMAC", "SIPHASH", "1036"
                    ]),
                    random.pick(&["derive", "keygen", "paramgen", "none"]),
                    random.pick(&["-1", "2048", "4", "2", "16", "0", "6"]),
                )?;
            }
            22 => writeln!(
                out,
                "pkcrypt {s} {}",
                random.pick(&["encrypt", "decrypt", "encap", "decap", "derive"])
            )?,
            23 => {
                let part = random.pick(&["public", "private", "params", "public+", "params+"]);
                let indent = random.pick(&["0", "1", "4", "-3", "130"]);
                writeln!(out, "pkprint {s} {part} {indent}")?;
            }
            24 => {
                const PEM_NAMES: &[&str] = &[
                    "RSA_PRIVATE_KEY",
                    "rsa_PRIVATE_KEY",
                    "DSA_PRIVATE_KEY",
                    "EC_PRIVATE_KEY",
                    "DH_PRIVATE_KEY",
                    "PRIVATE_KEY",
                    "ENCRYPTED_PRIVATE_KEY",
                    "_PRIVATE_KEY",
                    "DH_PARAMETERS",
                    "X9.42_DH_PARAMETERS",
                    "x9.42_dh_PARAMETERS",
                    "EC_PARAMETERS",
                    "RSA_PARAMETERS",
                    "PARAMETERS",
                    "CERTIFICATE",
                    "X509_CERTIFICATE",
                    "TRUSTED_CERTIFICATE",
                    "NEW_CERTIFICATE_REQUEST",
                    "CERTIFICATE_REQUEST",
                    "PKCS7",
                    "PKCS_#7_SIGNED_DATA",
                    "CMS",
                    "X",
                ];
                let wanted = random.pick(&[
                    "ANY_PRIVATE_KEY",
                    "PARAMETERS",
                    "DH_PARAMETERS",
                    "CERTIFICATE",
                    "TRUSTED_CERTIFICATE",
                    "CERTIFICATE_REQUEST",
                    "PKCS7",
                    "CMS",
                    "X",
                ]);
                let names: Vec<&str> = (0..1 + random.below(6))
                    .map(|_| random.pick(PEM_NAMES))
                    .collect();
                writeln!(out, "pembytes {wanted} {}", names.join(","))?;
            }
            _ => writeln!(out, "pkshow {s}")?,
        }
        if random.below(10) == 0 {
            writeln!(out, "pkfree {}", slot(random))?;
        }
    }
    for s in 0..8 {
        writeln!(out, "pkfree {s}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_replays_the_same_sessions() {
        let first = random_sessions(42, 500, &[]).unwrap();
        assert_eq!(first, random_sessions(42, 500, &[]).unwrap());
        assert_ne!(first, random_sessions(43, 500, &[]).unwrap());
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
        let o = parse_args(&args(&["--random", "5", "--seed", "9"])).unwrap();
        assert_eq!((o.sessions, o.seed, o.duration), (5, 9, None));
        let o = parse_args(&args(&[
            "--only",
            "evp,bn",
            "--duration",
            "24h",
            "--jobs",
            "3",
        ]))
        .unwrap();
        assert_eq!(o.only, ["evp", "bn"]);
        assert_eq!(o.duration, Some(Duration::from_secs(86_400)));
        assert_eq!(o.jobs, 3);
        assert_eq!(parse_duration("90").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("30m").unwrap(), Duration::from_secs(1800));
        assert!(parse_duration("h").is_err());
        assert!(parse_args(&args(&["--seed"])).is_err());
        assert!(parse_args(&args(&["--bogus", "1"])).is_err());
    }

    #[test]
    fn only_draws_from_the_named_generators() {
        let evp = resolve(&["evp".to_owned()]).unwrap();
        assert_eq!(evp.len(), EVP_SESSIONS.len());
        assert!(resolve(&["nosuch".to_owned()]).is_err());
        let digest = resolve(&["digest".to_owned()]).unwrap();
        let text = random_sessions(7, 50, &digest).unwrap();
        let mut only = String::new();
        let mut random = Random::new(7);
        for session in 0..50 {
            writeln!(only, "# session {session}").unwrap();
            let _ = random.below(1);
            digest_session(&mut random, &mut only).unwrap();
        }
        assert_eq!(text, only);
    }
}
