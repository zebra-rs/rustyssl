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
    ("slhdsa", slhdsa_session),
    ("mlx", mlx_session),
    ("dhcheck", dhcheck_session),
    ("dhder", dhder_session),
    ("dhkey", dhkey_session),
    ("dhexch", dhexch_session),
    ("dsaverify", dsaverify_session),
    ("dsader", dsader_session),
    ("dsakey", dsakey_session),
    ("dsasig", dsasig_session),
    ("p8der", p8der_session),
    ("spkider", spkider_session),
    ("d2ikey", d2ikey_session),
    ("pemkey", pemkey_session),
    ("enckey", enckey_session),
    ("pemwrite", pemwrite_session),
    ("pbe", pbe_session),
    ("msblob", msblob_session),
    ("hpke", hpke_session),
    ("x509name", x509name_session),
    ("v3print", v3print_session),
    ("decode", decode_session),
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
        if random.below(5) == 0 {
            cert_line(random, out)?;
            continue;
        }
        if random.below(10) == 0 {
            crl_line(random, out)?;
            continue;
        }
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

/// Seeds for the certificate items of `d2i_session` (21 X509, 22 X509_CINF, 23 X509_CERT_AUX,
/// 24 X509_VAL, 25 X509_REQ, 26 X509_REQ_INFO), in hex: an Ed25519 and an EC certificate and a
/// leaf, their TBSCertificates, the auxiliary data of a trusted certificate, a validity, and
/// requests (Ed25519, and EC with attributes and extensions) with a CertificationRequestInfo.
const CERT_SEEDS: [(u64, &str); 10] = [
    (
        21,
        "3081f33081a6a003020102020104300506032b657030123110300e06035504030c0745643235353139301e170d3236313031373131353733395a170d3236313131363131353733395a30123110300e06035504030c0745643235353139302a300506032b6570032100b8d871412bfad65be1ccec3d8daf6f52becec77ce652348b758f6e112f5c127aa321301f301d0603551d0e0416041405f57291cf24c75713a59301ed78aae6b60c8602300506032b65700341002a3bfc3e3e5b9d1ba6f881a4413c4dc5abb4d9a4d5f294b2984c14d796c76f92b80951445f57c6d066574990dc53c47ca4eadb277336b5a7b1973ad436e5c104",
    ),
    (
        21,
        "308201993082013fa00302010202081234567890abcdef300a06082a8648ce3d0403023032310b3009060355040613024a503111300f060355040a0c08727573747973736c3110300e06035504030c0754657374204341301e170d3236313031373131353732395a170d3336313031343131353732395a3032310b3009060355040613024a503111300f060355040a0c08727573747973736c3110300e06035504030c07546573742043413059301306072a8648ce3d020106082a8648ce3d030107034200041bc401a85547f58d771f4b3d0a8a6ca7cb145d93d8750ddac405676ea2d2454e3f11ee66778d10c2aab207fd011451deb32eb58d60cfe85016b812a6fc789bbba33f303d300f0603551d130101ff040530030101ff300b0603551d0f040403020106301d0603551d0e0416041454ffa67b8d3e6d5207ec8981c3096390b0e6e2b7300a06082a8648ce3d0403020348003045022077153741ad39fec8ef20585bdc305c4a8166154c74956eb48d8fc0aa218f57e1022100ff27b38303f211e2106192c5d32930d2a91cd5dc5181d03a0a50fc58600b28e3",
    ),
    (
        21,
        "308201e230820187a003020102020102300a06082a8648ce3d0403023032310b3009060355040613024a503111300f060355040a0c08727573747973736c3110300e06035504030c0754657374204341301e170d3236313031373131353733395a170d3237313031373131353733395a3037310b3009060355040613024a503111300f060355040a0c08727573747973736c3115301306035504030c0c6c6561662e6578616d706c6530819f300d06092a864886f70d010101050003818d0030818902818100c8b896cc3757ea747f2343c57ea40c8e6cce68fde4d9c84b97a6e09f0ff9eae45bbad7659471a26585b55b35f9a05be08c6c3e64140bd3cbfff9264445ecdd0678a712401f272db2936b6e1095153e9392f60eafeb42ebf76c21136a62f94d25367082c3c5146798ccbccc64dc4b3072f167d2a1cec69ff8f519eef0b69fb3010203010001a3423040301d0603551d0e04160414a08c9471777058179933eb11a8a109894bc241d4301f0603551d2304183016801454ffa67b8d3e6d5207ec8981c3096390b0e6e2b7300a06082a8648ce3d0403020349003046022100a11270c8d299a5ce7c8c62e8f9bad0cb4c4510ca277eaafb5b3f0a1672fb2bcc022100dc2cae1261b824edd258781f3ec9b72e9c1c097c7ecc27f83af90cbf4338557c",
    ),
    (
        22,
        "3081a6a003020102020104300506032b657030123110300e06035504030c0745643235353139301e170d3236313031373131353733395a170d3236313131363131353733395a30123110300e06035504030c0745643235353139302a300506032b6570032100b8d871412bfad65be1ccec3d8daf6f52becec77ce652348b758f6e112f5c127aa321301f301d0603551d0e0416041405f57291cf24c75713a59301ed78aae6b60c8602",
    ),
    (
        22,
        "3082013fa00302010202081234567890abcdef300a06082a8648ce3d0403023032310b3009060355040613024a503111300f060355040a0c08727573747973736c3110300e06035504030c0754657374204341301e170d3236313031373131353732395a170d3336313031343131353732395a3032310b3009060355040613024a503111300f060355040a0c08727573747973736c3110300e06035504030c07546573742043413059301306072a8648ce3d020106082a8648ce3d030107034200041bc401a85547f58d771f4b3d0a8a6ca7cb145d93d8750ddac405676ea2d2454e3f11ee66778d10c2aab207fd011451deb32eb58d60cfe85016b812a6fc789bbba33f303d300f0603551d130101ff040530030101ff300b0603551d0f040403020106301d0603551d0e0416041454ffa67b8d3e6d5207ec8981c3096390b0e6e2b7",
    ),
    (23, "3013300a06082b060105050703010c056d79204341"),
    (
        24,
        "301e170d3236313031373131353733395a170d3236313131363131353733395a",
    ),
    (
        25,
        "30819030440201003011310f300d06035504030c06656420726571302a300506032b6570032100b8d871412bfad65be1ccec3d8daf6f52becec77ce652348b758f6e112f5c127aa000300506032b6570034100aa65f0f825fd850643692069a9008ae562ff7ec3182d157dd0f15a326e3bb7cbe21b17ccea80dd6a5721a919a18b8a33da555758b907773585ff46a10faf0f05",
    ),
    (
        25,
        "308201493081f102010030163114301206035504030c0b7265712e6578616d706c653059301306072a8648ce3d020106082a8648ce3d030107034200041bc401a85547f58d771f4b3d0a8a6ca7cb145d93d8750ddac405676ea2d2454e3f11ee66778d10c2aab207fd011451deb32eb58d60cfe85016b812a6fc789bbba079301606092a864886f70d01090231090c076d7920756e6974301806092a864886f70d010907310b0c09736563726574313233304506092a864886f70d01090e3138303630270603551d110420301e820b7265712e6578616d706c65820f7777772e7265712e6578616d706c65300b0603551d0f040403020780300a06082a8648ce3d040302034700304402203ffe778bdeaf44b2e395c300d6d255c6df2534c6a5e6bdd3001d44df8d53d57c022036e80606390d1d4681073db2ad41d12a3a473437cf8f0cfb3237299ad1e76fa5",
    ),
    (
        26,
        "30440201003011310f300d06035504030c06656420726571302a300506032b6570032100b8d871412bfad65be1ccec3d8daf6f52becec77ce652348b758f6e112f5c127aa000",
    ),
];

/// Changes up to three octets, cuts a range out, or cuts the octets short.
fn mutate(random: &mut Random, der: &mut Vec<u8>) {
    for _ in 0..random.below(4) {
        let len = u64::try_from(der.len()).unwrap_or(0);
        if len == 0 {
            break;
        }
        let at = usize::try_from(random.below(len)).unwrap_or(0);
        match random.below(4) {
            0 => {
                if let Some(b) = der.get_mut(at) {
                    *b ^= 1 << random.below(8);
                }
            }
            1 => {
                if let Some(b) = der.get_mut(at) {
                    *b = u8::try_from(random.below(256)).unwrap_or(0);
                }
            }
            2 => {
                let end = (at + usize::try_from(random.below(16)).unwrap_or(0) + 1).min(der.len());
                der.drain(at..end);
            }
            _ => der.truncate(at),
        }
    }
}

/// Seeds for `x509crl`, in hex: the reference tool's CRL (with an issuing distribution point)
/// and a CRL built with entries out of order, reasons, a certificate issuer, and a removal.
const CRL_SEEDS: [&str; 2] = [
    "308201233081ca020101300a06082a8648ce3d04030230153113301106035504030c0a507572706f7365204341170d3236313031373135313531315a170d3236313131363135313531315a30223020020107170d3236313031373135313531315a300c300a0603551d1504030a0101a060305e301f0603551d230418301680143496cc3c74ec4ff75918857cdd9c71f79a92e135302f0603551d1c0101ff04253023a01da01b8619687474703a2f2f63726c2e6578616d706c652f63612e63726c83020348300a0603551d140403020111300a06082a8648ce3d04030203480030450221008efa92bece57a14c32aa525c81297b0dfcfe413e08cc72198c1e8e355b8e1c88022047f63f2888fda2df8e7474a562d0c8afc3bdee21d3ea393e0cd6d7aa0865e95c",
    "3082016130820113020101300506032b657030153113301106035504030c0a43524c20497373756572180f32303236303130313030303030305a180f32303236303230313030303030305a3081bd302202011e180f32303236303130323033303430355a300c300a0603551d1504030a0101301402010a180f32303236303130323033303430355a3022020114180f32303236303130323033303430355a300c300a0603551d1504030a01083047020128180f32303236303130323033303430355a3031300a0603551d1504030a010230230603551d1d0101ff04193017a41530133111300f06035504030c084f746865722043413014020132180f32303236303130323033303430355aa00e300c300a0603551d140403020105300506032b6570034100cb7c40fe9ca4ba63b69a0ea573d1c748b12755b26547b8905a1516eb5620866d63a0c195ae966f9096a9ec7aab782862d7a144294cb841b118f234027181870e",
];

/// An `x509crl` of one of [`CRL_SEEDS`] as it is, or with octets changed, a range cut out, or
/// cut short.
fn crl_line(random: &mut Random, out: &mut String) -> Result {
    let i = usize::try_from(random.below(2)).unwrap_or(0);
    let hex = CRL_SEEDS.get(i).copied().unwrap_or("");
    let mut der: Vec<u8> = (0..hex.len() / 2)
        .filter_map(|i| u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok())
        .collect();
    mutate(random, &mut der);
    let hex: String = if der.is_empty() {
        "-".to_owned()
    } else {
        der.iter().map(|b| format!("{b:02x}")).collect()
    };
    writeln!(out, "x509crl {hex}")?;
    Ok(())
}

/// An `asnd2i` of a certificate item: one of [`CERT_SEEDS`] as it is, or with octets changed, a
/// range cut out, or cut short.
fn cert_line(random: &mut Random, out: &mut String) -> Result {
    let i = usize::try_from(random.below(10)).unwrap_or(0);
    let (item, hex) = CERT_SEEDS.get(i).copied().unwrap_or((21, ""));
    let mut der: Vec<u8> = (0..hex.len() / 2)
        .filter_map(|i| u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok())
        .collect();
    mutate(random, &mut der);
    let hex: String = if der.is_empty() {
        "-".to_owned()
    } else {
        der.iter().map(|b| format!("{b:02x}")).collect()
    };
    writeln!(out, "asnd2i {item} {hex}")?;
    if item == 21 {
        writeln!(out, "x509cache {hex}")?;
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
    mutated_sessions_upto(random, out, command, seeds, 250)
}

/// `mutated_sessions` with the octets cut to `max`.
fn mutated_sessions_upto(
    random: &mut Random,
    out: &mut String,
    command: &str,
    seeds: &[&str],
    max: usize,
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
        der.truncate(max);
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

/// A random session of the SLH-DSA signatures, as `mldsa_session` (keys from `3n` octets of
/// seeds, test entropy of `n` octets or another length, no `mu`), on the fast parameter sets
/// (the small ones, slow to sign, rarely).
fn slhdsa_session(random: &mut Random, out: &mut String) -> Result {
    const ALGS: [(&str, usize, u64); 12] = [
        ("SLH-DSA-SHA2-128f", 16, 17088),
        ("SLH-DSA-SHA2-192f", 24, 35664),
        ("SLH-DSA-SHA2-256f", 32, 49856),
        ("SLH-DSA-SHAKE-128f", 16, 17088),
        ("SLH-DSA-SHAKE-192f", 24, 35664),
        ("SLH-DSA-SHAKE-256f", 32, 49856),
        ("SLH-DSA-SHA2-128s", 16, 7856),
        ("SLH-DSA-SHA2-192s", 24, 16224),
        ("SLH-DSA-SHA2-256s", 32, 29792),
        ("SLH-DSA-SHAKE-128s", 16, 7856),
        ("SLH-DSA-SHAKE-192s", 24, 16224),
        ("SLH-DSA-SHAKE-256s", 32, 29792),
    ];
    for _ in 0..random.below(3).saturating_add(1) {
        let i = if random.below(10) == 0 {
            random.below(12)
        } else {
            random.below(6)
        };
        let i = usize::try_from(i).unwrap_or(0);
        let (alg, n, slen) = ALGS.get(i).copied().unwrap_or(ALGS[0]);
        let seed = random_hex(random, n.saturating_mul(3));
        let mut opts = Vec::new();
        if random.below(3) != 0 {
            opts.push(format!("det={}", random.below(3)));
        }
        if random.below(5) == 0 {
            opts.push(format!("enc={}", random.below(3)));
        }
        if random.below(4) == 0 {
            let len = match random.below(4) {
                0 => usize::try_from(random.below(40)).unwrap_or(0),
                _ => n,
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
        writeln!(out, "slhdsa {alg} {seed} {msg} {ctx} {opts} {room} {edits}")?;
    }
    Ok(())
}

/// A random session of the hybrid ML-KEM groups: keys from random seeds, and decapsulations of
/// streamed ciphertexts of the right length most often, else a little shorter or longer.
fn mlx_session(random: &mut Random, out: &mut String) -> Result {
    for _ in 0..random.below(4).saturating_add(1) {
        let alg = random.pick(&[
            "X25519MLKEM768",
            "X448MLKEM1024",
            "SecP256r1MLKEM768",
            "SecP384r1MLKEM1024",
        ]);
        let seed = random_hex(random, 64);
        let len = usize::try_from(random.below(16).saturating_add(1)).unwrap_or(1);
        let ctseed = random_hex(random, len);
        let delta = match random.below(6) {
            0 => -1 - i64::try_from(random.below(60)).unwrap_or(0),
            1 => 1 + i64::try_from(random.below(60)).unwrap_or(0),
            _ => 0,
        };
        writeln!(out, "mlx {alg} {seed} {ctseed} {delta}")?;
    }
    Ok(())
}

/// A random session of DH's checks: a named group's parameters (a part left out now and then,
/// one changed by a small amount), and public keys from small numbers, the generator, and
/// the prime.
fn dhcheck_session(random: &mut Random, out: &mut String) -> Result {
    for _ in 0..random.below(4).saturating_add(1) {
        let group = random.pick(&[
            "ffdhe2048",
            "ffdhe3072",
            "modp_1536",
            "modp_2048",
            "dh_1024_160",
            "dh_2048_224",
            "dh_2048_256",
        ]);
        let part = |random: &mut Random, name: &str| {
            if random.below(8) == 0 {
                "-".to_owned()
            } else {
                format!("{group}:{name}")
            }
        };
        let p = part(random, "p");
        let q = if random.below(3) == 0 {
            "-".to_owned()
        } else {
            part(random, "q")
        };
        let g = part(random, "g");
        let y = match random.below(5) {
            0 => "-".to_owned(),
            1 => format!("{group}:g"),
            2 => format!("{group}:p"),
            _ => format!("{:x}", random.below(64)),
        };
        let edit = match random.below(4) {
            0 => format!(
                "{}{}",
                random.pick(&["p", "q", "g", "y"]),
                random.below(5).saturating_add(1)
            ),
            _ => "-".to_owned(),
        };
        writeln!(out, "dhcheck {p} {q} {g} {y} {edit}")?;
    }
    Ok(())
}

/// A random session of DH and DHX keys from data: a named group's or RFC 5114's parameters
/// (now and then without q, or another group's; none of 3072 bits, whose prime tests are
/// slow), private keys of random lengths or at q, public
/// keys computed from them or at the bounds, private key lengths around the group's sizes, and
/// a number now and then changed.
fn dhkey_session(random: &mut Random, out: &mut String) -> Result {
    const GROUPS: [&str; 6] = [
        "ffdhe2048",
        "modp_1536",
        "modp_2048",
        "dh_1024_160",
        "dh_2048_224",
        "dh_2048_256",
    ];
    for _ in 0..random.below(4).saturating_add(1) {
        let group = random.pick(&GROUPS);
        let other = random.pick(&GROUPS);
        let type_ = random.pick(&["DH", "DHX"]);
        let part = |random: &mut Random, name: &str| match random.below(12) {
            0 => "-".to_owned(),
            1 => format!("{other}:{name}"),
            _ => format!("{group}:{name}"),
        };
        let p = part(random, "p");
        let q = if random.below(3) == 0 {
            "-".to_owned()
        } else {
            part(random, "q")
        };
        let g = part(random, "g");
        let x = match random.below(8) {
            0 => "-".to_owned(),
            1 => format!("{group}:q"),
            2 => format!("{:x}", random.below(4)),
            _ => {
                let len = usize::try_from(random.below(40))
                    .unwrap_or(0)
                    .saturating_add(1);
                random_hex(random, len)
            }
        };
        let y = match random.below(8) {
            0 => "-".to_owned(),
            1 => format!("{:x}", random.below(4)),
            2 => format!("{group}:p"),
            _ => "gx".to_owned(),
        };
        let length = match random.below(8) {
            0 => "0".to_owned(),
            1 => "160".to_owned(),
            2 => "225".to_owned(),
            3 => "4000".to_owned(),
            4 => random.below(300).to_string(),
            _ => "-".to_owned(),
        };
        let edit = match random.below(5) {
            0 => format!(
                "{}{}",
                random.pick(&["p", "q", "g", "y", "x"]),
                random.below(5).saturating_add(1)
            ),
            _ => "-".to_owned(),
        };
        writeln!(out, "dhkey {type_} {p} {q} {g} {y} {x} {length} {edit}")?;
    }
    Ok(())
}

/// A random session of the DH exchange through the provider and the legacy method: named
/// groups and RFC 5114's with random private keys, peers now and then broken, padding, rooms
/// around the secret's size, and X9.42's KDF with random digests, lengths, key-wrap
/// algorithms (now and then an unknown one), and keying material.
fn dhexch_session(random: &mut Random, out: &mut String) -> Result {
    const GROUPS: [(&str, u64); 5] = [
        ("ffdhe2048", 256),
        ("modp_1536", 192),
        ("modp_2048", 256),
        ("dh_2048_256", 256),
        ("dh_1024_160", 128),
    ];
    for _ in 0..random.below(4).saturating_add(1) {
        let i = usize::try_from(random.below(5)).unwrap_or(0);
        let (group, size) = GROUPS.get(i).copied().unwrap_or(GROUPS[0]);
        let how = random.pick(&["p", "l"]);
        let priv_hex = |random: &mut Random| {
            let len = usize::try_from(random.below(32))
                .unwrap_or(0)
                .saturating_add(1);
            let h = random_hex(random, len);
            if h.trim_start_matches('0').is_empty() {
                "1".to_owned()
            } else {
                h
            }
        };
        let (xa, xb) = (priv_hex(random), priv_hex(random));
        let edit = match random.below(8) {
            0 => "y=1".to_owned(),
            1 => "y=p".to_owned(),
            2 => format!("y{}", random.below(5).saturating_add(1)),
            _ => "-".to_owned(),
        };
        let pad = random.below(2);
        let (kdf, want) = if random.below(2) == 0 {
            ("-".to_owned(), size)
        } else {
            let md = random.pick(&["SHA1", "SHA256", "SHA512", "SHA3-256", "SHA224"]);
            let outlen = random.below(80);
            let cek = random.pick(&[
                "id-aes128-wrap",
                "id-aes192-wrap",
                "id-aes256-wrap",
                "id-smime-alg-CMS3DESwrap",
                "nonsense",
            ]);
            let ulen = usize::try_from(random.below(17)).unwrap_or(0);
            let ukm = random_hex(random, ulen);
            (format!("{md}:{outlen}:{cek}:{ukm}"), outlen)
        };
        let room = match random.below(4) {
            0 => want.saturating_sub(1),
            1 => want.saturating_add(1),
            2 => random.below(300),
            _ => want,
        };
        writeln!(
            out,
            "dhexch {how} {group} {xa} {xb} {edit} {pad} {kdf} {room}"
        )?;
    }
    Ok(())
}

/// A random session of DSA verification: RFC 6979's SHA-1 signature of "sample" with octets
/// changed, dropped, or added, over its digest (now and then changed, cut, or extended), with
/// the key now and then changed (never without its public key, which the reference reads
/// through NULL).
fn dsaverify_session(random: &mut Random, out: &mut String) -> Result {
    const SIG: &str = "302c02142e1a0c2562b2912caaf89186fb0f42001585da55021429efb6b0aff2d7a68eb70ca313022253b9a88df5";
    const DGST: &str = "8151325dcdbae9e0ff95f9f9658432dbedfdb209";
    let bytes = |h: &str| -> Vec<u8> {
        (0..h.len() / 2)
            .filter_map(|j| u8::from_str_radix(h.get(2 * j..2 * j + 2)?, 16).ok())
            .collect()
    };
    let hex = |b: &[u8]| -> String { b.iter().map(|x| format!("{x:02x}")).collect() };
    for _ in 0..random.below(4).saturating_add(1) {
        let mut sig = bytes(SIG);
        for _ in 0..random.below(3) {
            let len = u64::try_from(sig.len()).unwrap_or(1).max(1);
            let at = usize::try_from(random.below(len)).unwrap_or(0);
            match random.below(4) {
                0 if !sig.is_empty() => {
                    sig.remove(at.min(sig.len().saturating_sub(1)));
                }
                1 => sig.insert(at, u8::try_from(random.below(256)).unwrap_or(0)),
                _ => {
                    if let Some(b) = sig.get_mut(at) {
                        *b ^= u8::try_from(random.below(255).saturating_add(1)).unwrap_or(1);
                    }
                }
            }
        }
        let mut dgst = bytes(DGST);
        match random.below(6) {
            0 => {
                let at = usize::try_from(random.below(20)).unwrap_or(0);
                if let Some(b) = dgst.get_mut(at) {
                    *b ^= 1;
                }
            }
            1 => dgst.truncate(usize::try_from(random.below(20)).unwrap_or(0)),
            2 => {
                for _ in 0..random.below(44) {
                    dgst.push(u8::try_from(random.below(256)).unwrap_or(0));
                }
            }
            _ => {}
        }
        let key = match random.below(10) {
            1 => "small",
            2 => "q+2",
            3 => "even",
            _ => "k",
        };
        let d = if dgst.is_empty() {
            "-".to_owned()
        } else {
            hex(&dgst)
        };
        let s = if sig.is_empty() {
            "-".to_owned()
        } else {
            hex(&sig)
        };
        writeln!(out, "dsaverify {d} {s} {key}")?;
    }
    Ok(())
}

/// A random session of DSA decoding: small valid DSAPrivateKey, DSAparams, and DSAPublicKey
/// encodings with octets changed, dropped, or added, now and then given to another decoder.
fn dsader_session(random: &mut Random, out: &mut String) -> Result {
    const SEEDS: [(&str, &str); 6] = [
        ("k", "3012020100020117020103020105020107020102"),
        ("k", "3012020105020117020103020105020107020100"),
        ("p", "3009020117020103020105"),
        ("p", "30800201170201030201050000"),
        ("u", "300c020107020117020103020105"),
        (
            "p",
            "3020021100f7e75fdc469067ffdc4e847c51f452df02087bf3afee234833ff020105",
        ),
    ];
    for _ in 0..random.below(4).saturating_add(1) {
        let i = usize::try_from(random.below(6)).unwrap_or(0);
        let (kind, hex) = SEEDS.get(i).copied().unwrap_or(SEEDS[0]);
        let mut der: Vec<u8> = (0..hex.len() / 2)
            .filter_map(|j| u8::from_str_radix(hex.get(2 * j..2 * j + 2)?, 16).ok())
            .collect();
        for _ in 0..random.below(3) {
            let len = u64::try_from(der.len()).unwrap_or(1).max(1);
            let at = usize::try_from(random.below(len)).unwrap_or(0);
            match random.below(4) {
                0 if !der.is_empty() => {
                    der.remove(at.min(der.len().saturating_sub(1)));
                }
                1 => der.insert(at, u8::try_from(random.below(256)).unwrap_or(0)),
                _ => {
                    if let Some(b) = der.get_mut(at) {
                        *b ^= u8::try_from(random.below(255).saturating_add(1)).unwrap_or(1);
                    }
                }
            }
        }
        let kind = if random.below(5) == 0 {
            random.pick(&["k", "p", "u"])
        } else {
            kind
        };
        let hex: String = der.iter().map(|b| format!("{b:02x}")).collect();
        writeln!(out, "dsader {kind} {hex}")?;
    }
    Ok(())
}

/// A random session of PKCS#8's and X.509's structure decoders: small valid PrivateKeyInfos
/// (with attributes and a public key), DigestInfos, attributes, and SEQUENCEs OF
/// AlgorithmIdentifier with octets changed, dropped, or added, now and then given to another
/// decoder.
fn p8der_session(random: &mut Random, out: &mut String) -> Result {
    const SEEDS: [(&str, &str); 7] = [
        ("k", "3010020100300506032b6570040404020102"),
        ("k", "3015020101300506032b65700404040201028103000a0b"),
        (
            "k",
            "301d020100300506032b6570040404020102a00b30090603551d0f31020500",
        ),
        (
            "s",
            "3021300906052b0e03021a05000414000102030405060708090a0b0c0d0e0f10111213",
        ),
        ("a", "3011060a0992268993f22c6401013103160161"),
        ("a", "30090603551d0f31020500"),
        ("l", "3010300606022a03050030060602480e0500"),
    ];
    for _ in 0..random.below(4).saturating_add(1) {
        let i = usize::try_from(random.below(7)).unwrap_or(0);
        let (kind, hex) = SEEDS.get(i).copied().unwrap_or(SEEDS[0]);
        let mut der: Vec<u8> = (0..hex.len() / 2)
            .filter_map(|j| u8::from_str_radix(hex.get(2 * j..2 * j + 2)?, 16).ok())
            .collect();
        for _ in 0..random.below(3) {
            let len = u64::try_from(der.len()).unwrap_or(1).max(1);
            let at = usize::try_from(random.below(len)).unwrap_or(0);
            match random.below(4) {
                0 if !der.is_empty() => {
                    der.remove(at.min(der.len().saturating_sub(1)));
                }
                1 => der.insert(at, u8::try_from(random.below(256)).unwrap_or(0)),
                _ => {
                    if let Some(b) = der.get_mut(at) {
                        *b ^= u8::try_from(random.below(255).saturating_add(1)).unwrap_or(1);
                    }
                }
            }
        }
        let kind = if random.below(5) == 0 {
            random.pick(&["k", "s", "a", "l"])
        } else {
            kind
        };
        let hex: String = der.iter().map(|b| format!("{b:02x}")).collect();
        writeln!(out, "p8der {kind} {hex}")?;
    }
    Ok(())
}

/// A random session of keys from PEM: blocks of each kind (and several in one text) with a
/// character changed, dropped, or added, or cut short, read as private keys, public keys, or
/// parameters until the reading fails.
fn pemkey_session(random: &mut Random, out: &mut String) -> Result {
    const SEEDS: [&str; 11] = [
        "2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0a4d4949424f77494241414a42414b7a64464b48616e6d424d70642b32595550666374414849552b4c786f46612f364a32496351716755723978393472662b4f640a79466857546b384e572b6333754a4b45797076435a49477379456c66546a7854414230434177454141514a42414a45443671495a5a3947376d302f416a5870470a417568586775396267417a576a53763656447466755256787a53497236302b755a564156534a6a4c507042465a5479483852597a4c4651396f363147534b336a0a427145434951446868457a6c46767961316f74376a56447a47556b434745344f336652344e5577666e68685870412b7142514968414d51367964454e555131420a544b63426232705a45586c384443306c514c4739446c7656344d6f756c614535416942765636657a622f373133376c734865423674654179395a634d686739650a6a6b6e77546c6b4d5a45634c6c514968414b7365454f767154756e654c6266632b6f6d6b7a695a41564758782f473643544d6b7377322f4d47394f52416941630a555a4352377956743971634136644b6e414b6a627a6e5479736a6f705773386c7a4462396a6e787433513d3d0a2d2d2d2d2d454e44205253412050524956415445204b45592d2d2d2d2d0a",
        "2d2d2d2d2d424547494e2050524956415445204b45592d2d2d2d2d0a4d494748416745414d424d4742797147534d34394167454743437147534d3439417745484247307761774942415151674e5271434b37714f5330326854424d430a584e336f30384d383263787846464c56424263756f48574147354f6852414e434141512f58616154577251325661335a346a4f544b533438657347662b6854370a685279745a315662427739412b64653732374849694374647735626b7a6b707649446779764d77416c586f5a74445942344d69322f7232780a2d2d2d2d2d454e442050524956415445204b45592d2d2d2d2d0a",
        "2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741455031326d6b3171304e6c57743265497a6b796b75504872426e2f6f550a2b345563725764565777635051506e58753975787949677258634f57354d354b627941344d727a4d414a563647625132416544497476363973513d3d0a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a",
        "2d2d2d2d2d424547494e20444820504152414d45544552532d2d2d2d2d0a4d49494243414b43415145412f2f2f2f2f2f2f2f2f2f2b742b4652596f72744b6d712f635669416e50547a78324c6e46673834744e70577034545a424647517a0a2b3879546e63346b6d7a373566532f6a59324d4d64646a32676249437273526865745066487458562f5756684a445031483138476274434659325656506530610a383756584531352f56386b316d45384d634f446d69336669706f6e61382b2f6f63683378574b4532726563314d4b7a4b543067366558713843724743737954370a5964454971557579794f503775577261743244583947676454304b6a336a6c4e394b35573765646a6372735a4377656e794f344b6258436541767a687a6666690a374d4130424d306f4e4339686b584c2b6e4f6d46672f2b4f5478497937764b426738502b4f78744d6236317a4f37583876433743494158466a764744665261440a7373627a5369624273752f36694774434f47456f584a662f2f2f2f2f2f2f2f2f2f77494241673d3d0a2d2d2d2d2d454e4420444820504152414d45544552532d2d2d2d2d0a",
        "2d2d2d2d2d424547494e2050524956415445204b45592d2d2d2d2d0a4d43344341514177425159444b32567542434945494b4170445a4a37564a7470416e77476273634c65304e6f6739426434764f507865663844513750346646330a2d2d2d2d2d454e442050524956415445204b45592d2d2d2d2d0a",
        "2d2d2d2d2d424547494e2044534120504152414d45544552532d2d2d2d2d0a4d49494248674b4267514345736753554857593955752b694d4355727852492f6534662b6c59545175466c78784c45636b70594743492b31675437515250574a0a7164363672537179582b3731316a35385238334f7a646142562b57654856516f4a39654d307457686f564b452f4d6f78546f53593368724f5a6d43573136664e0a4e7465654e757277425651494e61566f2f7a7a486e4752644c57304f7950797a6f566d5a4e6c4a3630394e6c465734377353304332514956414e6665707664380a5762534355486b4b6549334935336f5a54757348416f47415852723842566f324855526b5252516b3855485877424b754a4f462f4c4e3943506d4e4e747830510a3737594f424c7a5571494d54446659796b4f545472696755734f32695a674c6a56426c514c4a7a30616f6f6378426f756c572f57713546722f6b3133326a306b0a2f56514d54476942797557574e732f332b70715a2b6d7868447969532b454b426c617a6c6d655669334b454f555a712f774543307a6a31304a44433733784c470a4a53773d0a2d2d2d2d2d454e442044534120504152414d45544552532d2d2d2d2d0a",
        "2d2d2d2d2d424547494e20525341205055424c4943204b45592d2d2d2d2d0a4d456743515143733352536832703567544b5866746d464433334c51427946506938614257762b69646948454b6f464b2f6366654b332f6a6e636859566b35500a4456766e4e376953684d7162776d5342724d684a583034385577416441674d424141453d0a2d2d2d2d2d454e4420525341205055424c4943204b45592d2d2d2d2d0a",
        "2d2d2d2d2d424547494e2045432050524956415445204b45592d2d2d2d2d0a4d4863434151454549445561676975366a6b744e6f557754416c7a64364e5044504e6e4d63525253315151584c714231674275546f416f4743437147534d34390a417745486f555144516741455031326d6b3171304e6c57743265497a6b796b75504872426e2f6f552b345563725764565777635051506e5875397578794967720a58634f57354d354b627941344d727a4d414a563647625132416544497476363973513d3d0a2d2d2d2d2d454e442045432050524956415445204b45592d2d2d2d2d0a",
        "2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d454d77425159444b325678417a6f416f4c7634724c6159564248386b57686b744548416273784342376d354f72414a62506b316d776b307572344f30456b5a0a7a726a39502b30624e7455476c757934493356707178554f5a5241410a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a",
        "2d2d2d2d2d424547494e2050524956415445204b45592d2d2d2d2d0a4d494748416745414d424d4742797147534d34394167454743437142484d39564159497442473077617749424151516746614966775262625173784e63524b450a486c574a2b6f516a35737070486968625074767a46504b73314a6d6852414e434141522b2f363170625339595436397a7738336f4d6a503451466668554f726c0a6e7a6b325958704b5a57506b442f704b4d2f386a67686d6445354c646e512f51786576332b77357473336961623832534a626f65666479340a2d2d2d2d2d454e442050524956415445204b45592d2d2d2d2d0a",
        "2d2d2d2d2d424547494e20464f4f2d2d2d2d2d0a414141410a2d2d2d2d2d454e4420464f4f2d2d2d2d2d0a2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741455031326d6b3171304e6c57743265497a6b796b75504872426e2f6f550a2b345563725764565777635051506e58753975787949677258634f57354d354b627941344d727a4d414a563647625132416544497476363973513d3d0a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0a4d4949424f77494241414a42414b7a64464b48616e6d424d70642b32595550666374414849552b4c786f46612f364a32496351716755723978393472662b4f640a79466857546b384e572b6333754a4b45797076435a49477379456c66546a7854414230434177454141514a42414a45443671495a5a3947376d302f416a5870470a417568586775396267417a576a53763656447466755256787a53497236302b755a564156534a6a4c507042465a5479483852597a4c4651396f363147534b336a0a427145434951446868457a6c46767961316f74376a56447a47556b434745344f336652344e5577666e68685870412b7142514968414d51367964454e555131420a544b63426232705a45586c384443306c514c4739446c7656344d6f756c614535416942765636657a622f373133376c734865423674654179395a634d686739650a6a6b6e77546c6b4d5a45634c6c514968414b7365454f767154756e654c6266632b6f6d6b7a695a41564758782f473643544d6b7377322f4d47394f52416941630a555a4352377956743971634136644b6e414b6a627a6e5479736a6f705773386c7a4462396a6e787433513d3d0a2d2d2d2d2d454e44205253412050524956415445204b45592d2d2d2d2d0a2d2d2d2d2d424547494e20444820504152414d45544552532d2d2d2d2d0a4d49494243414b43415145412f2f2f2f2f2f2f2f2f2f2b742b4652596f72744b6d712f635669416e50547a78324c6e46673834744e70577034545a424647517a0a2b3879546e63346b6d7a373566532f6a59324d4d64646a32676249437273526865745066487458562f5756684a445031483138476274434659325656506530610a383756584531352f56386b316d45384d634f446d69336669706f6e61382b2f6f63683378574b4532726563314d4b7a4b543067366558713843724743737954370a5964454971557579794f503775577261743244583947676454304b6a336a6c4e394b35573765646a6372735a4377656e794f344b6258436541767a687a6666690a374d4130424d306f4e4339686b584c2b6e4f6d46672f2b4f5478497937764b426738502b4f78744d6236317a4f37583876433743494158466a764744665261440a7373627a5369624273752f36694774434f47456f584a662f2f2f2f2f2f2f2f2f2f77494241673d3d0a2d2d2d2d2d454e4420444820504152414d45544552532d2d2d2d2d0a",
    ];
    for _ in 0..random.below(4).saturating_add(1) {
        let i = usize::try_from(random.below(SEEDS.len() as u64)).unwrap_or(0);
        let hex = SEEDS.get(i).copied().unwrap_or(SEEDS[0]);
        let mut data: Vec<u8> = (0..hex.len() / 2)
            .filter_map(|j| u8::from_str_radix(hex.get(2 * j..2 * j + 2)?, 16).ok())
            .collect();
        const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n-";
        for _ in 0..random.below(3) {
            let len = u64::try_from(data.len()).unwrap_or(1).max(1);
            let at = usize::try_from(random.below(len)).unwrap_or(0);
            let c = B64
                .get(usize::try_from(random.below(B64.len() as u64)).unwrap_or(0))
                .copied()
                .unwrap_or(b'A');
            match random.below(5) {
                0 if !data.is_empty() => {
                    data.remove(at.min(data.len().saturating_sub(1)));
                }
                1 => data.insert(at, c),
                2 => data.truncate(at),
                _ => {
                    if let Some(b) = data.get_mut(at) {
                        *b = c;
                    }
                }
            }
        }
        let how = random.pick(&["k", "k", "u", "p"]);
        let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
        writeln!(out, "pemkey {how} {hex}")?;
    }
    Ok(())
}

/// The keys `d2ikey` and `enckey` start from: each classic and post-quantum type's
/// PrivateKeyInfo, SubjectPublicKeyInfo, and type-specific structures.
const KEY_SEEDS: [&str; 26] = [
    "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420351a822bba8e4b4da14c13025cdde8d3c33cd9cc711452d504172ea075801b93a144034200043f5da6935ab43655add9e23393292e3c7ac19ffa14fb851cad67555b070f40f9d7bbdbb1c8882b5dc396e4ce4a6f203832bccc00957a19b43601e0c8b6febdb1",
    "3059301306072a8648ce3d020106082a8648ce3d030107034200043f5da6935ab43655add9e23393292e3c7ac19ffa14fb851cad67555b070f40f9d7bbdbb1c8882b5dc396e4ce4a6f203832bccc00957a19b43601e0c8b6febdb1",
    "30770201010420351a822bba8e4b4da14c13025cdde8d3c33cd9cc711452d504172ea075801b93a00a06082a8648ce3d030107a144034200043f5da6935ab43655add9e23393292e3c7ac19ffa14fb851cad67555b070f40f9d7bbdbb1c8882b5dc396e4ce4a6f203832bccc00957a19b43601e0c8b6febdb1",
    "302e020100300506032b6570042204200fc3dc124a0f28cd349e704b869e78ae7ebb7bceb1138c211b9df46810aab30f",
    "302a300506032b6570032100da1310d3a4a78b9c46fc1c3458e9eb7285933ed4b7ba8a5f425e6bffc42b8015",
    "3046020100300506032b656f043a0438e87e758469bfae4c4d8238fff728cd048d9ae9fe4ea98454aaff628b2ebb7ae0afa3494d89e6bb08c30cc38cc8d3b36d5fe6adc657f25cf5",
    "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b020101042015a21fc116db42cc4d7112841e5589fa8423e6ca691e285b3edbf314f2acd499a144034200047effad696d2f584faf73c3cde83233f84057e150eae59f3936617a4a6563e40ffa4a33ff2382199d1392dd9d0fd0c5ebf7fb0e6db3789a6fcd9225ba1e7ddcb8",
    "3059301306072a8648ce3d020106082a811ccf5501822d034200047effad696d2f584faf73c3cde83233f84057e150eae59f3936617a4a6563e40ffa4a33ff2382199d1392dd9d0fd0c5ebf7fb0e6db3789a6fcd9225ba1e7ddcb8",
    "3082014a0201003082012b06072a8648ce3804013082011e0281810084b204941d663d52efa230252bc5123f7b87fe9584d0b85971c4b11c929606088fb5813ed044f589a9debaad2ab25feef5d63e7c47cdcecdd68157e59e1d542827d78cd2d5a1a15284fcca314e8498de1ace666096d7a7cd36d79e36eaf005540835a568ff3cc79c645d2d6d0ec8fcb3a1599936527ad3d365156e3bb12d02d9021500d7dea6f77c59b48250790a788dc8e77a194eeb070281805d1afc055a361d4464451424f141d7c012ae24e17f2cdf423e634db71d10efb60e04bcd4a883130df63290e4d3ae2814b0eda26602e35419502c9cf46a8a1cc41a2e956fd6ab916bfe4d77da3d24fd540c4c6881cae59636cff7fa9a99fa6c610f2892f8428195ace599e562dca10e519abfc040b4ce3d742430bbdf12c6252c0416021435dd175aee48bc506c00bd2e0b38736b091416eb",
    "308201b63082012b06072a8648ce3804013082011e0281810084b204941d663d52efa230252bc5123f7b87fe9584d0b85971c4b11c929606088fb5813ed044f589a9debaad2ab25feef5d63e7c47cdcecdd68157e59e1d542827d78cd2d5a1a15284fcca314e8498de1ace666096d7a7cd36d79e36eaf005540835a568ff3cc79c645d2d6d0ec8fcb3a1599936527ad3d365156e3bb12d02d9021500d7dea6f77c59b48250790a788dc8e77a194eeb070281805d1afc055a361d4464451424f141d7c012ae24e17f2cdf423e634db71d10efb60e04bcd4a883130df63290e4d3ae2814b0eda26602e35419502c9cf46a8a1cc41a2e956fd6ab916bfe4d77da3d24fd540c4c6881cae59636cff7fa9a99fa6c610f2892f8428195ace599e562dca10e519abfc040b4ce3d742430bbdf12c6252c0381840002818030022dbf351bc61ec6980c447e82be2b8c066d66daeb5009a8ad4362a132b55bb27f8dcd52845e64551e1651af027d68b5343ffe48a30a44c58efa1186c088ac850e2d718e180db03f2cfaa7e7678ef51303ca6a271fc3f472f7c6d0bbf7f491600f91664f5a0632f1f06b48262e00c83362141b96b2e6646461f12f5fd92f1f",
    "3082013f0201003082011706092a864886f70d010301308201080282010100ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f619172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c58ef1837d1683b2c6f34a26c1b2effa886b423861285c97ffffffffffffffff020102041f021d01e4b2f88789bec729c72702ef461d3e6fe134df1a23e46e8e9f1dad64",
    "308201b63082012b06072a8648ce3e02013082011e02818100816f6521a3d18800679a8bd2d71eb5742ed8b380dc1f2bc797ea81b0beccbf60a2d2e5043a00ba59aa13374b3458a1cbbb479de8055373be5270ea68d81ca2014421180daa1ac1813349b4e9c3b7eb03d4335fedefc5479ae76cee4221b53cb37cc56ff3e042a66c7555c0088f60bc60732c9ba9970a886980369c9a64574e7f02818053e0a203251996e932968e4a860413191a8ea57fcca46839e09401748bf9a21a2dfe73aece57089c4abeda3fecfb1b216e68e5dcd0b2f5c83bda26b8a5430f97c4a36481b413e0b424956ef66b1377adf6d3340ea698a5bd9c5826315a32e91acefbe0057e24df6bf22f508933de80e08e3095aa26dbe389072c9c2725758062021500a1db994791a0746668b362284c1853c83229d4e90381840002818054c4df9e1bfc54cfb401c6c9b6fc9b1692a7012108abac130d58a1d7bdc2df3e854c07ffdcfcdd2ebbc53150708de15ae15196567ba52734bcb4ec6919261cee17d64a975666f2c0eedb8e934e45ffef10aa480909eafdb9a263b6184cd1b857fe344ebdcb7f43339c276dd84fba514ede982aa8746c8277ba998da2c76090b9",
    "3082025b02010002818100c90d21115433dc9cf9fddfe17dfcd8669d2a88f05e91498829ae8f818ab75e96a22f44e55293a39ac2a5949a8fd649c33ef6a6511924fefe84d0576ac5f21fcddd7e8280e38836a0833b929bc002e8f8e35c1d2443597e04590028eab65ee802f6acc04cf5367bc9021b8e1836ea96f76821c821648e442bd9f2baa5add70efd020301000102818060a4b6038d754c940cbb93b5e208fbc0ffc5a583de017ad6402b1002963aa4f645c9f11547077f3a725c83bd746cee92331eff3db6978917b1a230933bc9b2ad39b25f211052c11724b951dd9712386334cafb104d1b3923cef8f9069bc3b424ac1657ea14cfd4c6dfcd27384b3aebe961cc1c772a701e6c8011d2f2bbf1eb01024100e31a00cc661e75bae94716f3ac8e4d614caa8d9dec9167b8ccc3b1d706200f0ea27bf15633ecf1c5a545dda973ea41c4a8b95da287031725d738c7d6655062c1024100e2a284e94e7c57c901bb27ecc0490804467645e1fc297622a7e2225b3fe3d5ad2e99434343f9437cf777d8f87f50fbfa651095f5ddcd2758aa9c797d2d4c473d02400d9736c904ab79fc2f8db38fed99ae83ce24bec8dea96cfda0336de72254b4d1f963557405337edc8721813c6cd56e0e28d2bf09c4eea869f9514a944807e18102400d521815ce732885bc00501c6e40dca3c3b077f30c6b33725e03c099346c23c70612240df414d68ea5ccf987c193f4fb86ad2ee340a22a49dfdd4a96bceedad1024064c8254d554a0f99fd02ff8a44b8517d5a60d9f88046a28348dd80a478f5c753e6dc66c5c8efa90f747260b5c134ca2c55803970a81bb0bf73d7fc3b87fd30eb",
    "30819d300b06092a864886f70d01010a03818d0030818902818100af27de06d1715c8e2ff83e490de6a51dcbbef83323ad4a5e8f0bb70105ac7262fb5284df70f88c7049c71437e6e9a0843d950123e5c5145c1c8aee0ad9e29bc83ac125dee08428e5e5d51734c1c2d32967e4485f898a0805b334495c65dc279403650c1d9b801b4dfc5c20ccbaa83428c460e131cb3d4fbbdd83f66c7bb99d050203010001",
    "30820289020100301e06092a864886f70d01010a3011a00f300d06096086480165030402010500048202623082025e02010002818100dab0250e3d33e89cedc106abfec7939e40937234580a450c97406fcf353ccb6584872fd0d36c3e82dd1f0c3756949bcdaffbcb960d15835a74c64313c6261d139137e68f0fecc0c31ccbb75fcfeab5fd3b895782aa594868770d4dea7fe4a6bd6e90851229db7e31a5bd5a564a5709a306c791ac79b5a338de8a33cd0a829389020301000102818024d437595f8b47686e4decaeb898a9cea3f770eb49cc68f686de6e360a3433d8e3e9d46ea9bc780697f0aba1022ec2d27009caae79839efc73e013d9d7ac0187432ef7e1503eadcecf76a57e40641521a1ca4f05667a07459d81a54ef15e44afec9ec7d1dee1a25d354633876aeef7c9d20870fa930fe3eba1f1ed23222c4001024100fe0a9eee470a807572c496f48d644d4d5a42f1d3536e9cd97b4d21f43fd532ac7b2a921f5235d2e80d6becbc2882b369c2a9c743f3490579626f461126c80b89024100dc5fc000879152d908ee13cdad7dc4b502010ca5add13b3c1d251e909e578a8f84652c6304d78832922f67f38f6a5ddc12ea10f16b58640cf54eca44919c4801024100bc2ae3c3bcad23af5afe108e3db8a0a57e08fe1438c542bab860ce989b3b70985f768ddb534a78d8d7302c9ec626e17ba1eb9da4502cb33850d7f8ff35499179024100a087af59b3678d2e446f0945fe676b6f5fb25c00248a11d84c72c9bd175b35b82dfd7543fc36f523c1917eebd140ee766de0cbced11f66627a1f97003401e001024100eb959247d41a9c66d535fd96a2c440fcbb3485061c44153c3be045e40d9b79c859420c536ac8c9cccd15fe73b5c5cc5bff7259f2182573ba3ca8a1eb00830931",
    "3054020100300b060960864801650304040104428040a73ba84924e406481615b7f8f2f4d16f60b061bd6e8bc894013e3f55467a5a5c493e35c6139bb8b34199c163dfbf4c43f6a464bf507b24612be84a06a4c646c7",
    "3052020100300b06096086480165030404010440a73ba84924e406481615b7f8f2f4d16f60b061bd6e8bc894013e3f55467a5a5c493e35c6139bb8b34199c163dfbf4c43f6a464bf507b24612be84a06a4c646c7",
    "3034020100300b0609608648016503040311042280203432b88a3adca7fbd13c84ef55f283d050709d1ab1bcf89fb7ef97b4258e4018",
    "3032020100300b060960864801650304031104203432b88a3adca7fbd13c84ef55f283d050709d1ab1bcf89fb7ef97b4258e4018",
    "3052020100300b06096086480165030403150440853448786b7609ca9b1a221ea268cf50fc249cc145a7db70cf3d05eef9e7d147cea72e6fa107ce874275027f6bbbaf0165307324dd5d12d81340126fb631e9fa",
    "3030300b0609608648016503040315032100cea72e6fa107ce874275027f6bbbaf0165307324dd5d12d81340126fb631e9fa",
    "308193020100300b060960864801650304031e048180d1d8e57272bb8210ac27db0bbee06403eb15d5915416ab9d35b98748f643acec6d801e977949e86863044b0e96ff150b480cefeaaface25fa5de14bcd61c8ac262b53ec3d7b2ffd1641ad514b2bdd8c92562f3f038ab670f918370dfd4306c24955a91a04feacf7bd14df50ef4b51973814d5fa9c364ff578099a940b0bbdb1d",
    "3040300b060960864801650304031d033100e59c106b7cdcf53e345471691eefc4574e502e2ff2f4cc7ee9515c4c22e9bc0970f2d59c59a22896f4503aec367186f7",
    "30820332300b06096086480165030404010382032100dd7106db8698afa33e2147a5719400ce6ba74830bc2d2b8020929b194c97599a31e8905630e8af662186e87c2ed4f44faad225bf26367a621ff9f0849054b214d1262a8938a9d06f71250abbe09c4fdb9cfdfa40c3118003b0404f7775f6dc4c1ae14505bb83328877b4e56326c3bc423426740b9039201bd6851a6ad9753e2074d947cb08676962a1cafcf0b55ef96a9c3161cd1b85fbcb78b6570e91e03f91b91368f806e91b90e3637bb6a902ac2b4271cbaf2c57c55bf9150b510799eca20eb2372497593194062f7097d2fcc7030ac1f5ac0a57f7960529314a6b1ce6d39d8951301f17abbad3bf2979a7e27c4456d297ab3304e9d095cb95c67a1cb054f1469f54c1dd362f238c25bb05c758f8090c66a28d772673220d7119122e7c6d83563ee4524b4ccc62da86158542ccdab4c7e1894ac4050e55216901c8bdf04746342c31932c424e3b932d33bfb9c8a9b7b19d97bb94d5c157f7f65927018525229c99e70e06c56276563d889b474750ab3a3b68cbc2a2b09c8ebc695a66b876f1c417df02c7fafca46c24be6b727ace11ba9f4a7942d490f1cccfd6f9511cf731a4213c2ef48276db266864c9397528d9cc9bcddace18bb3eeccb82882352d540304581774cf9a7aa718508d72eaeaaa65619b1dc047baa027b31a6458e07985a134face9be4cbccf49c154209bb2b9159ee9ca9c8f452ddf3917eb0cc58a0127ded397ad29922972ba84e49c16623063338dfe581fc7a0ae9731370dda73a1a9c3b4599c8ae21869518f2aab5721e80fb71c0fc1d3583a7ccd897975f2c8cbf7d59a1d5535736077a793975bd66d41740245a17d6c744eadfabebdbc28af9bce4ab2a563132f90bccfbbb10f73a1200b92aa816a0d8ada0592c96f525a067b69af212abd2097982fcb4f99449efc484fe0732a705355cb6aba6bec5ffa07331df184f67b01fe512434d22c626214f6d29a23546c24e4b22f84ca8e9c14dd1083b85b5e72ea991354889684a9a979aca407313191522f28b1f30029ec68b3122448363a4a75eb5ab0c77dd10653078a40ba306708f69020a2764317a064dc06496533c3bbd30a03ae82c5b03bf9d0fb1e684a11d1880818da9050a2f464e085",
    "3054020100300b060960864801650304040204428040f6c3f7d46a5b65889889b24014bebb65e87fc0e564c8672b0b81032d6ef1ce624c2300faaab1db0d574385058b72247d9f09a2f25e2460bafe1c06e12a7906d5",
    "3034020100300b06096086480165030403120422802043ae038c791386864eacec08bff32b1e0432c7189afdef09f2af3a3d3037b559",
];

/// A random session of keys from DER: each classic key type's PrivateKeyInfo,
/// SubjectPublicKeyInfo, or traditional structure, and post-quantum ones (ML-KEM's and ML-DSA's
/// seeds, SLH-DSA's keys, an ML-KEM public key), with octets changed, dropped, or added, through
/// a random entry point (d2i_AutoPrivateKey, d2i_PrivateKey of a type, d2i_PUBKEY,
/// EVP_PKCS82PKEY, d2i_X509_PUBKEY).
fn d2ikey_session(random: &mut Random, out: &mut String) -> Result {
    const SEEDS: [&str; 26] = KEY_SEEDS;
    for _ in 0..random.below(4).saturating_add(1) {
        let i = usize::try_from(random.below(SEEDS.len() as u64)).unwrap_or(0);
        let hex = SEEDS.get(i).copied().unwrap_or(SEEDS[0]);
        let mut data: Vec<u8> = (0..hex.len() / 2)
            .filter_map(|j| u8::from_str_radix(hex.get(2 * j..2 * j + 2)?, 16).ok())
            .collect();
        for _ in 0..random.below(3) {
            let len = u64::try_from(data.len()).unwrap_or(1).max(1);
            let at = usize::try_from(random.below(len)).unwrap_or(0);
            match random.below(5) {
                0 if !data.is_empty() => {
                    data.remove(at.min(data.len().saturating_sub(1)));
                }
                1 => data.insert(at, u8::try_from(random.below(256)).unwrap_or(0)),
                2 => data.truncate(at),
                _ => {
                    if let Some(b) = data.get_mut(at) {
                        *b ^= u8::try_from(random.below(255).saturating_add(1)).unwrap_or(1);
                    }
                }
            }
        }
        let how = random.pick(&[
            "a", "a", "u", "u", "8", "x", "6", "408", "116", "28", "1172", "1034",
        ]);
        let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
        writeln!(out, "d2ikey {how} {hex}")?;
    }
    Ok(())
}

/// The seed key, with up to two octets changed, dropped, or added.
fn mutated_seed(random: &mut Random) -> Vec<u8> {
    let i = usize::try_from(random.below(KEY_SEEDS.len() as u64)).unwrap_or(0);
    let hex = KEY_SEEDS.get(i).copied().unwrap_or(KEY_SEEDS[0]);
    let mut data: Vec<u8> = (0..hex.len() / 2)
        .filter_map(|j| u8::from_str_radix(hex.get(2 * j..2 * j + 2)?, 16).ok())
        .collect();
    if random.below(3) == 0 {
        let len = u64::try_from(data.len()).unwrap_or(1).max(1);
        let at = usize::try_from(random.below(len)).unwrap_or(0);
        match random.below(3) {
            0 => data.truncate(at),
            1 => data.insert(at, u8::try_from(random.below(256)).unwrap_or(0)),
            _ => {
                if let Some(b) = data.get_mut(at) {
                    *b ^= u8::try_from(random.below(255).saturating_add(1)).unwrap_or(1);
                }
            }
        }
    }
    data
}

/// A random session of the encoders: keys of each type (now and then changed) encoded with a
/// selection, output type, and structure, each of them now and then one that doesn't fit.
fn enckey_session(random: &mut Random, out: &mut String) -> Result {
    for _ in 0..random.below(4).saturating_add(1) {
        let data = mutated_seed(random);
        let sel = random.pick(&["87", "86", "84", "1", "2", "4", "0", "80", "85"]);
        let type_ = random.pick(&["DER", "DER", "PEM", "PEM", "blob", "TEXT", "TEXT"]);
        let structure = random.pick(&[
            "-",
            "PrivateKeyInfo",
            "SubjectPublicKeyInfo",
            "type-specific",
            "EncryptedPrivateKeyInfo",
            "pkcs1",
            "rsa",
            "dh",
            "dhx",
            "pkcs3",
            "X9.42",
            "dsa",
            "ec",
            "X9.62",
        ]);
        let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
        writeln!(out, "enckey {sel} {type_} {structure} {hex}")?;
    }
    Ok(())
}

/// A random session of password-based encryption: PBES2 algorithms of a cipher, PRF,
/// iteration count, salt, and IV (now and then ones that don't fit), encrypting and decrypting a
/// text with a password.
fn pbe_session(random: &mut Random, out: &mut String) -> Result {
    for _ in 0..random.below(4).saturating_add(1) {
        let cipher = random.pick(&[
            "AES-128-CBC",
            "AES-192-CBC",
            "AES-256-CBC",
            "DES-EDE3-CBC",
            "AES-128-CTR",
            "AES-256-OFB",
            "ARIA-128-CBC",
            "CAMELLIA-256-CBC",
            "SM4-CBC",
            "AES-128-GCM",
            "NOPE",
        ]);
        let prf = random.pick(&[
            "-1", "163", "798", "799", "800", "801", "1193", "1194", "1195", "1196", "1197",
            "1198", "1281", "672", "4",
        ]);
        let iter = random.pick(&["1", "2", "100", "1000", "0", "-5"]);
        let salt_len = usize::try_from(random.below(24)).unwrap_or(8);
        let salt: String = (0..salt_len)
            .map(|_| format!("{:02x}", random.below(256)))
            .collect();
        let iv: String = (0..16)
            .map(|_| format!("{:02x}", random.below(256)))
            .collect();
        let pass = random.pick(&["password", "pw", "-", "a-longer-password-than-usual"]);
        let salt = if salt.is_empty() {
            "-".to_owned()
        } else {
            salt
        };
        writeln!(out, "pbe - {cipher} {prf} {iter} {salt} {iv} {pass}")?;
    }
    Ok(())
}

/// Microsoft key blobs and PVKs for `msblob` sessions to start from (the reference's openssl
/// rsa and dsa): a 512-bit RSA key's private and public blobs, its PVK, and its PVK encrypted
/// (strong, passphrase "pw"); a 1024-bit DSA key's private and public blobs and its PVK.
const MSBLOB_SEEDS: &[&str] = &[
    "0702000000a40000525341320002000001000100d7e6659f4a0a63d644ee3d32b83159e451ce28b7adc7ce220b48b9fa5e60e2f7ec2903e192bfb5fe51f7a92388d852b4c22f168a591bb467496fe5476297f4b1f330587b8e6597a741868913fa227367ceb8f604c3ca69b0be852c00ea552dda8d8b85e50f3d69c9acad51789878e48ab1903574a7c91efef9269cf89b39ced00794306faf03156e1324addc5c399d4bd17db6bae6c59522899420171029160d2d8cb99ba962211b6b8454441a1c7171ce7cd01ba3167699e97593f1154f538fc0e595b8f11c9997a54966b066287c9a69dec340801aa138caa61677b656204cc1b4b824c4573f21b4e44499555a2be192103fcece9faec41f21ea140c72a623a7689ab463d349a3d2cb96e2f541c775c2d6a555b6c9147f6c5a8c4e08233a83",
    "0602000000a40000525341310002000001000100d7e6659f4a0a63d644ee3d32b83159e451ce28b7adc7ce220b48b9fa5e60e2f7ec2903e192bfb5fe51f7a92388d852b4c22f168a591bb467496fe5476297f4b1",
    "1ef1b5b000000000010000000000000000000000340100000702000000a40000525341320002000001000100d7e6659f4a0a63d644ee3d32b83159e451ce28b7adc7ce220b48b9fa5e60e2f7ec2903e192bfb5fe51f7a92388d852b4c22f168a591bb467496fe5476297f4b1f330587b8e6597a741868913fa227367ceb8f604c3ca69b0be852c00ea552dda8d8b85e50f3d69c9acad51789878e48ab1903574a7c91efef9269cf89b39ced00794306faf03156e1324addc5c399d4bd17db6bae6c59522899420171029160d2d8cb99ba962211b6b8454441a1c7171ce7cd01ba3167699e97593f1154f538fc0e595b8f11c9997a54966b066287c9a69dec340801aa138caa61677b656204cc1b4b824c4573f21b4e44499555a2be192103fcece9faec41f21ea140c72a623a7689ab463d349a3d2cb96e2f541c775c2d6a555b6c9147f6c5a8c4e08233a83",
    "1ef1b5b00000000001000000010000001000000034010000ebd7e4ee2ad525a613aacbb22bb687740702000000a4000061563e4e524757d1acc7eda57531b80ba0101e2d7f10bc92c27f3f93fa1b7918e6775446e2237ed2a8edc49b13114ecf45f945c33c7e4d555c821f820a953b679f63bc06d6d89ec46ea8215de13811eb5de82218c860574fbf0ee45cc9952bd98cace4d7c9741535c1d3c27edd796f849e06ef7d788fbbfb2d53925a5a36fe2b830e25ac6ff517310293c0ac43e9165559a493600d3891a08a539198c325dc486005f599a95069ea83192fdcbcad5e2954f5a1569fc2c24f0f318e98b3d1fb882661da0da32d14bb3af5aa1aabf9b6ce855e3089f18462d47fa6fef4bc74d26bfe4b4d5d40781f66c7dfc8f6f28030b531aefc557291240478d713197876ee8d006647dff338b7fbe2f19bec3309242ee7b53fbd529629a8148be76b9210c66297076c931b4b1a70da17e5b8",
    "07020000002200004453533200040000072786b89e6b592faba082cc5bd2255d439125d126fbc9804086e9a85771533b6695bdda367d39e4c5ed63c3a47dbe1e293c4d3a430bf8f1527ac7a69345a32290c4208830651ad75163a8ddb49a012585452e029357dd79825882a5178a5f176f69d589b2c08f261fb31cb5e4ae998f9c9bbb68eab73ae633781aa0f817bde6a7272e29700c805322d4da5645d922513b02948633e342c45ba188833e9a157a6badefe30d5effbb8b465b9cd63208d2989ac99eeaa3368f274ffc45d66db60f70b6743166501cb2b5bd36c4d52281dcb0fbea4bcda22f48ed4b7ecbaefc0fc135259a9567ec5e247bfbf2aaf539ee2f79246df09a2ae773a80dcc710075dca77987acac3f7a995187313bd599f6440f583854dac151926235567fe745864a58cde0bbd6cd66c96dffffffffffffffffffffffffffffffffffffffffffffffff",
    "06020000002200004453533100040000072786b89e6b592faba082cc5bd2255d439125d126fbc9804086e9a85771533b6695bdda367d39e4c5ed63c3a47dbe1e293c4d3a430bf8f1527ac7a69345a32290c4208830651ad75163a8ddb49a012585452e029357dd79825882a5178a5f176f69d589b2c08f261fb31cb5e4ae998f9c9bbb68eab73ae633781aa0f817bde6a7272e29700c805322d4da5645d922513b02948633e342c45ba188833e9a157a6badefe30d5effbb8b465b9cd63208d2989ac99eeaa3368f274ffc45d66db60f70b6743166501cb2b5bd36c4d52281dcb0fbea4bcda22f48ed4b7ecbaefc0fc135259a9567ec5e247bfbf2aaf539ee2f79246df09a2ae773a80dcc710075dca77987acac3f7a995187313bd599f6440f583854daf538b9640bd977229980dcdf7f31a9ea852ae810ed57b357ee31b5e700eda5ecd336ff07cf68b9cce090d7176a4d38bebcbe84987094fc74023460cdc7078ea2cf8a910b6c015f842b46cc30e0ed742f72fd9cec75b35b66e948552efefe29a4d61406bbc0d80385fef58822b69a6cf350906df3f90601c35a8552bcbb2391ceffffffffffffffffffffffffffffffffffffffffffffffff",
    "1ef1b5b0000000000200000000000000000000005001000007020000002200004453533200040000072786b89e6b592faba082cc5bd2255d439125d126fbc9804086e9a85771533b6695bdda367d39e4c5ed63c3a47dbe1e293c4d3a430bf8f1527ac7a69345a32290c4208830651ad75163a8ddb49a012585452e029357dd79825882a5178a5f176f69d589b2c08f261fb31cb5e4ae998f9c9bbb68eab73ae633781aa0f817bde6a7272e29700c805322d4da5645d922513b02948633e342c45ba188833e9a157a6badefe30d5effbb8b465b9cd63208d2989ac99eeaa3368f274ffc45d66db60f70b6743166501cb2b5bd36c4d52281dcb0fbea4bcda22f48ed4b7ecbaefc0fc135259a9567ec5e247bfbf2aaf539ee2f79246df09a2ae773a80dcc710075dca77987acac3f7a995187313bd599f6440f583854dac151926235567fe745864a58cde0bbd6cd66c96dffffffffffffffffffffffffffffffffffffffffffffffff",
];

/// A random session of `msblob` commands: the seeds with octets changed, removed, or added,
/// cut short, or whole.
fn msblob_session(random: &mut Random, out: &mut String) -> Result {
    mutated_sessions_upto(random, out, "msblob", MSBLOB_SEEDS, 480)
}

/// A random session of HPKE: suites by name and number (now and then ones there aren't), each
/// mode (and one there isn't), input key material of the KEM's recommended length (now and
/// then shorter or none), info, AAD, and plaintext, and the receiver given the sender's
/// encapsulated key and ciphertext or random ones.
fn hpke_session(random: &mut Random, out: &mut String) -> Result {
    for _ in 0..random.below(4).saturating_add(1) {
        let kem = random.pick(&[
            "P-256", "P-384", "P-521", "X25519", "x448", "0x10", "32", "0x13",
        ]);
        let kdf = random.pick(&["hkdf-sha256", "hkdf-sha384", "hkdf-sha512", "1", "0x3", "4"]);
        let aead = random.pick(&[
            "aes-128-gcm",
            "aes-256-gcm",
            "chacha20-poly1305",
            "exporter",
            "2",
            "0xff",
            "5",
        ]);
        let mode = random.pick(&["0", "1", "2", "3", "0", "4"]);
        let nsk: usize = match kem {
            "P-384" => 48,
            "P-521" => 66,
            "x448" => 56,
            _ => 32,
        };
        let hexof = |random: &mut Random, len: usize, none: u64| {
            if random.below(none) == 0 {
                "-".to_owned()
            } else {
                random_hex(random, len)
            }
        };
        let short = if random.below(8) == 0 { 8 } else { nsk };
        let ikm_r = hexof(random, short, 12);
        let ikm_e = hexof(random, nsk, 4);
        let (info_len, aad_len, pt_len) = (random.below(40), random.below(20), random.below(60));
        let len = |n: u64| usize::try_from(n).unwrap_or(0).max(1);
        let info = hexof(random, len(info_len), 3);
        let aad = hexof(random, len(aad_len), 3);
        let pt = hexof(random, len(pt_len), 10);
        let (enc, ct) = match random.below(6) {
            0 => (random_hex(random, nsk * 2 + 1), "=".to_owned()),
            1 => ("=".to_owned(), random_hex(random, 40)),
            2 => (random_hex(random, nsk), "=".to_owned()),
            _ => ("=".to_owned(), "=".to_owned()),
        };
        writeln!(
            out,
            "hpke {kem},{kdf},{aead} {mode} {ikm_r} {ikm_e} {info} {aad} {pt} {enc} {ct}"
        )?;
    }
    Ok(())
}

/// Values for `v3print` sessions to start from, by NID (only extensions whose methods are in):
/// key usage, Netscape's certificate type and comment, the signing tool, the CRL number and
/// reason, inhibitAnyPolicy, the subject key identifier, basic constraints, extended key usage,
/// the private key usage period, a subject alternative name of every type, the authority key
/// identifier, the information access extensions, CRL distribution points and the freshest CRL,
/// an issuing distribution point, an invalidity date, and the attribute certificate extensions.
const V3PRINT_SEEDS: &[(u32, &[&str])] = &[
    (83, &["030205a0", "0303070080"]),
    (71, &["030200ff"]),
    (78, &["160b48656c6c6f20776f726c64"]),
    (1007, &["0c05746f6f6cc3"]),
    (
        88,
        &["02020100", "0211010000000000000000000000000000000000"],
    ),
    (141, &["0a0101", "0a012a"]),
    (748, &["020100"]),
    (82, &["0404deadbeef"]),
    (87, &["30060101ff020103", "3000"]),
    (126, &["301406082b0601050507030106082b06010505070302"]),
    (
        84,
        &["3022800f32303234303130313030303030305a810f32303235303130313030303030305a"],
    ),
    (
        90,
        &[
            "3058801454ffa67b8d3e6d5207ec8981c3096390b0e6e2b7a136a4343032310b3009060355040613024a503111300f060355040a0c08727573747973736c3110300e06035504030c075465737420434182081234567890abcdef",
        ],
    ),
    (
        177,
        &[
            "3048302006082b060105050730018614687474703a2f2f6f6373702e6578616d706c652f302406082b060105050730028618687474703a2f2f63612e6578616d706c652f63612e637274",
        ],
    ),
    (
        398,
        &["3022302006082b060105050730058614687474703a2f2f7265706f2e6578616d706c652f"],
    ),
    (
        103,
        &[
            "306c301ea01ca01a8618687474703a2f2f63726c2e6578616d706c652f612e63726c304aa029a0278618687474703a2f2f63726c2e6578616d706c652f622e63726c810b63726c406578616d706c6581020560a219a41730153113301106035504030c0a43524c20497373756572",
        ],
    ),
    (
        857,
        &["30243022a020a01e861c687474703a2f2f63726c2e6578616d706c652f64656c74612e63726c"],
    ),
    (
        85,
        &[
            "3081dc820b73616e2e6578616d706c65820d2a2e73616e2e6578616d706c658704c0000201871020010db8000000000000000000000001810b6140622e6578616d706c65861568747470733a2f2f73616e2e6578616d706c652f7888032a0304a4223020310b3009060355040613024a503111300f06035504030c08646972206e616d65a01b060a2b060104018237140203a00d0c0b75706e406578616d706c65a02006082b06010505070807a01416125f687474702e5f7463702e6578616d706c65a00d06042a030405a0051603726177a00b06042a030406a003020107",
        ],
    ),
    (770, &["30138008a0068604687474708101ff8201ff8401ff8501ff"]),
    (142, &["180f32303234303130323033303430355a"]),
    (
        89,
        &[
            "3017300506032a030430060604551d200030060604551d2000",
            "3081c630818406032a0304307d302206082b060105050702011616687474703a2f2f6370732e6578616d706c652f6f6e65302206082b060105050702011616687474703a2f2f6370732e6578616d706c652f74776f303306082b06010505070202302730151a084f7267204e616d6530090201010201020201030c0e536f6d6520555446382074657874303d0604551d20003035301606082b06010505070202300a1e08626d702074657874301b06082b06010505070202300f1a0d706c61696e2076697369626c65",
        ],
    ),
    (747, &["3016300806022a0306022a04300a0604551d200006022d06"]),
    (401, &["3006800100810102", "3003810101"]),
    (
        663,
        &[
            "301c020101301706082b06010505071500040b736f6d6520746578744142",
            "301f020103301a06082b06010505071500040e66726f6d20612073656374696f6e",
        ],
    ),
    (
        666,
        &[
            "3077a02b300d820b6578616d706c652e636f6d300e810c406578616d706c652e636f6d300a87080a000000ff000000a148300e860c2e6261642e6578616d706c653022872020010db8000000000000000000000000ffffffff0000000000000000000000003012a410300e310c300a06035504030c03646972",
        ],
    ),
    (1313, &["3014a0123010820e686f6c6465722e6578616d706c65"]),
    (
        143,
        &[
            "307c0201003077300a0201010405616c696365300a0201020405626f620078300b02047fffffff040363617230090201100404646176653045020103044075757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575",
            "300b0201053006300402000400",
        ],
    ),
    (
        1020,
        &[
            "3006020105020111",
            "3012020105020111020100020300ffff020204d2",
        ],
    ),
    (
        1008,
        &[
            "30080c000c000c000c00",
            "30230c08746f6f6c206f6e650c07636120746f6f6c0c066365727420310c06636572742032",
        ],
    ),
    (287, &["04040102abcd"]),
    (
        1298,
        &[
            "3077a02b300d820b6578616d706c652e636f6d300e810c406578616d706c652e636f6d300a87080a000000ff000000a148300e860c2e6261642e6578616d706c653022872020010db8000000000000000000000000ffffffff0000000000000000000000003012a410300e310c300a06035504030c03646972",
        ],
    ),
    (
        290,
        &[
            "304f304d040200023047031100000000000000000000000000000000010311000001000200030004000500060007000803050020010db83018030307fe80031101fe800000000000000000000000010004",
            "30193017040200013011030500010203040302000a030401c0a800",
        ],
    ),
    (
        291,
        &[
            "301ca00e300c300a020300fbf0020300fffea10a30083006020107020109",
            "3013a00d300b300602010102010502010aa1020500",
        ],
    ),
    (
        1093,
        &[
            "3082010c8612687474703a2f2f61612e6578616d706c652f3081f53081a3a0178615687474703a2f2f656e7472792e6578616d706c652fa119301706035504030c104e616d696e6720417574686f72697479306d3067a031302f06072b2408030b01011612687474703a2f2f6e612e6578616d706c652f0c104e616d696e6720417574686f7269747930170c0941706f7468656b65720c0a506861726d6163697374300e06072b2408030b0106060355040a130531323334350402010230023000304da149304706312a030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031321612687474703a2f2f6e612e6578616d706c652f3000",
            "30023000",
        ],
    ),
    (
        1299,
        &[
            "308181317f3011a10403020254a2020500a30503030480903012a106a30403020182a20403020388a30205003056a027312530003021a00c300aa003020109a10302011ea111300fa003020111a103020105a20302013ba1083106020102020106a2083106020101020103a30b310902010102010902010ca40a3108020203e7020207e8",
            "301b3013a011180f32303234303130313030303030305a0101ff0201fb",
        ],
    ),
    (
        402,
        &[
            "308181307fa22430053000020107301b0a0100300b06096086480165030403020309003006020101020102a21e3005300002010730150a0107300b06096086480165030403020303000102a23730053000020107302e0a0101302106092a864886f70d01010a3014a00d300b0609608648016503040201a2030201200306000102030405",
        ],
    ),
    (
        1295,
        &[
            "304e30163010810e6161406578616d706c652e636f6d0202303930343022a420301e311c301a06035504030c1341747472696275746520417574686f7269747902097fffffffffffffffff030300ff00",
        ],
    ),
    (
        1296,
        &[
            "3081833054a010860e75726e3a726f6c653a61646d696ea1158213726f6c652d6973737565722e6578616d706c6582012aa3268615687474703a2f2f726f6c65732e6578616d706c652f820d726f6c65732e6578616d706c65302ba00f810d78406578616d706c652e636f6da10b8209792e6578616d706c65820bff0011223344556677889a",
        ],
    ),
    (
        769,
        &[
            "30820114301d06082b060105050709013111180f31393730303130313030303030305a30818a06042a0304053181810101000101ff020201020303000f0f0402cafe050006032a036306035504030a01070a01fd0c0568656c6c6f120331323313095072696e7461626c65140774656c657465781603696135170d3235303130313030303030305a1a037669731b0767656e6572616c1e060062006d007030070201010c02696e31070201010c02696e302d060355041f312630243114301206035504030c0b536f6d65204d656d626572310c300a060355040a0c034f7267300706035504483100300e060355040d31070c056869006869300c06035504483105a50302010130100603550420310930070201010c02696e",
        ],
    ),
    (
        1301,
        &[
            "3052303130190c0b4578616d706c65204f7267300a0201010201020202fed40c144578706c69636974206e6f746963652074657874300b1a094f6e6c7920746578743010300e16074f72672054776f3003020163",
        ],
    ),
    (
        1300,
        &[
            "30490603550403040178303f06092b06010401868d1f02303230188616687474703a2f2f706f6c6963792e6578616d706c652f3016300d060960864801650304020105000305000011aabb",
        ],
    ),
    (
        1312,
        &[
            "312aa00a800355040381032a0304a11ca010060355040a0c094c6f63616c204f7267a10806032a030502014d",
        ],
    ),
    (
        1311,
        &[
            "31323030a01c8003550448a115060355040a310e0c054f726720410c054f72672042a110820e686f6c6465722e6578616d706c65",
        ],
    ),
    (
        1307,
        &["3028a019a0178615687474703a2f2f61612e6578616d706c652f63726c810204508201ff8301008401ff"],
    ),
];

/// A random session of `v3print` commands: a NID's seeds with octets changed, removed, or
/// added, cut short, or whole.
fn v3print_session(random: &mut Random, out: &mut String) -> Result {
    let i = usize::try_from(random.below(V3PRINT_SEEDS.len() as u64)).unwrap_or(0);
    let Some(&(nid, seeds)) = V3PRINT_SEEDS.get(i) else {
        return Ok(());
    };
    mutated_sessions_upto(random, out, &format!("v3print {nid}"), seeds, 480)
}

/// Names for `x509name` sessions to start from (tests/c/x509_name.c's): one with every string
/// type, multi-valued RDNs, and control octets; the same with entries deleted; the empty
/// name; a multi-valued RDN; Universal and T61 strings; and GeneralStrings.
const X509NAME_SEEDS: &[&str] = &[
    "3081d831123010060355040716096c696e650a66656564310b3009060355040613024a5031283009060355040513023432300b06035504290c04426dd090300e06035504090c074d61696e2053743110300e06035504080c0754c58d6b79c58d31163014060355040a130d4578616d706c652c20496e632e3110300e060355040b0c075226442b4f7073313d301c06035504030c15204e616d6520205769746820202053706163657320301d06092a864886f70d0109011610526f6f74404578616d706c652e434f4d3110300e06042a0304051306616e204f4944",
    "3081a2310b3009060355040613024a5031183009060355040513023432300b06035504290c04426dd0903110300e06035504080c0754c58d6b79c58d31163014060355040a130d4578616d706c652c20496e632e3110300e060355040b0c075226442b4f7073313d301c06035504030c15204e616d6520205769746820202053706163657320301d06092a864886f70d0109011610526f6f74404578616d706c652e434f4d",
    "3000",
    "30233116300a06035504030c036162633008060355040a0c014f3109300706035504061300",
    "302b3115301306035504031c0c00000041000030420000002031123010060355040714095afc72696368202058",
    "30273111300f06035504031b0800000068000000693112301006035504040a1b09782f2b80ff003d5c2c",
];

/// A random session of `x509name` commands: the seeds with octets changed, removed, or added,
/// cut short, or whole.
fn x509name_session(random: &mut Random, out: &mut String) -> Result {
    mutated_sessions_upto(random, out, "x509name", X509NAME_SEEDS, 480)
}

/// A random session of the PEM key writers: keys of each type (now and then changed) through
/// each of them.
fn pemwrite_session(random: &mut Random, out: &mut String) -> Result {
    for _ in 0..random.below(4).saturating_add(1) {
        let hex: String = mutated_seed(random)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        writeln!(out, "pemwrite {hex}")?;
    }
    Ok(())
}

/// A random session of the typed SubjectPublicKeyInfo decoders: RSA (and RSA-PSS, restricted
/// or not), DSA (with and without parameters), and EC (named and explicit curves) keys with
/// octets changed, dropped, or added, now and then given to another type's decoder.
fn spkider_session(random: &mut Random, out: &mut String) -> Result {
    const SEEDS: [(&str, &str); 8] = [
        (
            "r",
            "305d300d06092a864886f70d0101010500034c003049024200c5e1a6c9d1b9df44db57cb1c3d5dc3c6c19a63a2d5b5e0a50a9c1d36f7d3b91d2d53ddfde8f0f6b0d9c02bddb1b9e3d78b83d3cbb61b4f9b1a6dcab8c76d9bd2f70203010001",
        ),
        (
            "r",
            "308190304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402020500a203020120034b003048024100e1b325a60c7e05feeffc00ae0fc13f7bf126ffd27d373353159749fb88ab0a5782dc3a96b471992155a0c9b051cb28f376f5a1c3034d6ea0736c855997bb3d650203010001",
        ),
        (
            "r",
            "305a300b06092a864886f70d01010a034b003048024100d36ac8b93123f820f364faaf06b9c4d5ce6eecaee2b091439b2f5f4867f1f7c51e1444fb3540da370539f38367bc32c2bb05bf9a2888a2e61f69be2add14628d0203010001",
        ),
        (
            "r",
            "305c300d06092a864886f70d01010a0500034b003048024100d36ac8b93123f820f364faaf06b9c4d5ce6eecaee2b091439b2f5f4867f1f7c51e1444fb3540da370539f38367bc32c2bb05bf9a2888a2e61f69be2add14628d0203010001",
        ),
        (
            "d",
            "308201b63082012b06072a8648ce3804013082011e0281810086f5ca03dcfeb225063ff830a0c769b9dd9d6153ad91d7ce27f787c43278b447e6533b86b18bed6e8a48b784a14c252c5be0dbf60b86d6385bd2f12fb763ed8873abfd3f5ba2e0a8c0a59082eac056935e529daf7c610467899c77adedfc846c881870b7b19b2b58f9be0521a17002e3bdd6b86685ee90b3d9a1b02b782b1779021500996f967f6c8e388d9e28d01e205fba957a5698b102818007b0f92546150b62514bb771e2a0c0ce387f03bda6c56b505209ff25fd3c133d89bbcd97e904e09114d9a7defdeadfc9078ea544d2e401aeecc40bb9fbbf78fd87995a10a1c27cb7789b594ba7efb5c4326a9fe59a070e136db77175464adca417be5dce2f40d10a46a3a3943f26ab7fd9c0398ff8c76ee0a56826a8a88f1dbd038184000281805df5e01ded31d0297e274e1691c192fe5868fef9e19a84776454b100cf16f65392195a38b90523e2542ee61871c0440cb87c322fc4b4d2ec5e1e7ec766e1be8d4ce935437dc11c3c8fd426338933ebfe739cb3465f4d3668c5e473508253b1e682f65cbdc4fae93c2ea212390e54905a86e2223170b44eaa7da5dd9ffcfb7f3b",
        ),
        (
            "d",
            "308192300906072a8648ce380401038184000281805df5e01ded31d0297e274e1691c192fe5868fef9e19a84776454b100cf16f65392195a38b90523e2542ee61871c0440cb87c322fc4b4d2ec5e1e7ec766e1be8d4ce935437dc11c3c8fd426338933ebfe739cb3465f4d3668c5e473508253b1e682f65cbdc4fae93c2ea212390e54905a86e2223170b44eaa7da5dd9ffcfb7f3b",
        ),
        (
            "e",
            "3059301306072a8648ce3d020106082a8648ce3d0301070342000460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
        ),
        (
            "e",
            "3082014b3082010306072a8648ce3d02013081f7020101302c06072a8648ce3d0101022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff305b0420ffffffff00000001000000000000000000000000fffffffffffffffffffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b031500c49d360886e704936a6678e1139d26b7819f7e900441046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325510201010342000460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
        ),
    ];
    for _ in 0..random.below(4).saturating_add(1) {
        let i = usize::try_from(random.below(SEEDS.len() as u64)).unwrap_or(0);
        let (kind, hex) = SEEDS.get(i).copied().unwrap_or(SEEDS[0]);
        let mut der: Vec<u8> = (0..hex.len() / 2)
            .filter_map(|j| u8::from_str_radix(hex.get(2 * j..2 * j + 2)?, 16).ok())
            .collect();
        for _ in 0..random.below(3) {
            let len = u64::try_from(der.len()).unwrap_or(1).max(1);
            let at = usize::try_from(random.below(len)).unwrap_or(0);
            match random.below(4) {
                0 if !der.is_empty() => {
                    der.remove(at.min(der.len().saturating_sub(1)));
                }
                1 => der.insert(at, u8::try_from(random.below(256)).unwrap_or(0)),
                _ => {
                    if let Some(b) = der.get_mut(at) {
                        *b ^= u8::try_from(random.below(255).saturating_add(1)).unwrap_or(1);
                    }
                }
            }
        }
        let kind = if random.below(5) == 0 {
            random.pick(&["r", "d", "e"])
        } else {
            kind
        };
        let hex: String = der.iter().map(|b| format!("{b:02x}")).collect();
        writeln!(out, "spkider {kind} {hex}")?;
    }
    Ok(())
}

/// A random session of the decoder framework with the default provider's structural decoders:
/// PEM (a public key, a traditional RSA key, a DEK-Info encrypted one, an encrypted PKCS#8) and
/// DER (a SubjectPublicKeyInfo, an EncryptedPrivateKeyInfo) with octets changed, dropped, or
/// added, decoded with input types, structures, selections, and passphrases right and wrong.
fn decode_session(random: &mut Random, out: &mut String) -> Result {
    const SEEDS: [&str; 6] = [
        "2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d4677774451594a4b6f5a496876634e41514542425141445377417753414a42414f70484d7866387978726a6e54536a454a6d485551726f34386679506241630a43764264533836484f466630782b41326b7a4575365772474731386659514977554b63334665776f4256716d4731616134536748777373434177454141513d3d0a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a",
        "2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0a4d4949425041494241414a42414f70484d7866387978726a6e54536a454a6d485551726f343866795062416343764264533836484f466630782b41326b7a45750a365772474731386659514977554b63334665776f4256716d4731616134536748777373434177454141514a42414b703153354f3064774d466761682b7a4f456f0a4e367338634239572f644e5a564177336c615362646a396e6b6838452b6c4d55416e36527238693035504c425a32704a63374d45324c553745374472414935500a396945434951442f316c625545795271775757574d4f725479444f63752f387572454e78556a4a797a2f74355a564f6f64774968414f7074575957386b3451310a73526f6f767a39333764536c337a4f39626c79482f6348594e6b7a596632464e41694541384472784433546d466b534277705575664330616f6373364a445a6e0a6f6570414b7555335374656c78614d4349486f666678794263615056534b366b2f595231324b7348776a41314266496b556869537079372f4e645364416945410a7764544d79782f684c413663664b674e47383875546155446462372f775765714b5462735948355172656b3d0a2d2d2d2d2d454e44205253412050524956415445204b45592d2d2d2d2d0a",
        "2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0a50726f632d547970653a20342c454e435259505445440a44454b2d496e666f3a204145532d3132382d4342432c43453836374137423534393837433444424634303338363735463143333337360a0a31545236366e70744b554a78693637776d4843754c754252746475746157486e576d7957652b623967683737554e4a3253646273463177634d59484e656a56770a773150333458474c324f6d786e376151756f75624b70304834774a4c434e6d34477a756c4a71526c6d4e70797a472b45435948566c4e43466e4479437561696b0a45554c5848577336546252744c3670384b526b68484d7139334f67674b6a352f302f31574275697052787338546f30316338766d53495775316c6534333958510a70433452327a475259556a756a574a70584c536b30506c2f455752466e4c684551746a5945616e586a77755a47397852714e2b43344c51704c696c32386a792b0a62434357713643564d44704234664f516f74767271386774325859466146415967334e4f416633706531374a526572315855564a5252347742315265684e52680a70374d45357748585758733344356b38574c444234565a5a306333784f6a616e65746932374d6c67456276542f30576e39657762306b3834777672504e474f460a37682b6242573033637870626c45386a38616b433755523544637134436c68614947794c5463336f422b44546f746e663067786836374c77686c3442457945540a2d2d2d2d2d454e44205253412050524956415445204b45592d2d2d2d2d0a",
        "2d2d2d2d2d424547494e20454e435259505445442050524956415445204b45592d2d2d2d2d0a4d4949427854426642676b71686b69473977304242513077556a417842676b71686b694739773042425177774a4151514e4f344442677452614f46656d6f44680a7370684c3577494343414177444159494b6f5a496876634e41676b464144416442676c67686b67425a514d4541536f4545436652724c46334c526d4b4933306b0a4967523655435945676746674769632b7a366c41794d6b5339745641426e4a6d65362f4961304176576a58516f7970434c437841324b7652384c344d537753580a7a684f36536c4335435a715936344e57496c55734c514e6a4a4344374f522f2f5639327348732f776268454e426a664f7666787954374a50774d656c4670736b0a4f3867325969534c5552646e446459796c65344446344d313164697141485a30736232545759414c4446337943496b7368544a4156454d7670523537676e47460a5065795745577632465353666e79695a31665565494734344a6d334b2b30493751543432333767634279777436412b624b6a72654275456632455562745967510a59684a6a444c6d6e596964343161316a4630686d65624d467a4c466e3035393241534e356f4c6d36714d36627772696d4c386958796264776c3274494d4172360a312f7a5770552b527131783844784132556f4a6153316e4934666d61426f665161774768464e382b6e4850585657324d69797141675a575279434176384155430a357a4e6f55586350336678416a4c2f533854507350374955344772327769614b2f784c6b73367272566e6e42674775634952684c6e4c34784c42454631494f320a675166586b72644b6d706f33645731497663797163756c6d3872755a5965454272773d3d0a2d2d2d2d2d454e4420454e435259505445442050524956415445204b45592d2d2d2d2d0a",
        "305c300d06092a864886f70d0101010500034b003048024100ea473317fccb1ae39d34a3109987510ae8e3c7f23db01c0af05d4bce873857f4c7e03693312ee96ac61b5f1f61023050a73715ec28055aa61b569ae12807c2cb0203010001",
        "308201c5305f06092a864886f70d01050d3052303106092a864886f70d01050c3024041034ee03060b5168e15e9a80e1b2984be702020800300c06082a864886f70d02090500301d060960864801650304012a041027d1acb1772d198a237d2422047a5026048201601a273ecfa940c8c912f6d5400672667bafc86b402f5a35d0a32a422c2c40d8abd1f0be0c4b0497ce13ba4a50b9099a98eb835622552c2d03632420fb391fff57ddac1ecff06e110d0637cebdfc724fb24fc0c7a5169b243bc83662248b5117670dd63295ee03178335d5d8aa007674b1bd9359800b0c5df208892c85324054432fa51e7b8271853dec96116bf615249f9f2899d5f51e206e38266dcafb423b413e36dfb81c072c2de80f9b2a3ade06e11fd8451bb588106212630cb9a7622778d5ad6317486679b305ccb167d39f76012379a0b9baa8ce9bc2b8a62fc897c9b770976b48300afad7fcd6a54f91ab5c7c0f103652825a4b59c8e1f99a0687d06b01a114df3e9c73d7556d8c8b2a80819591c8202ff00502e7336851770fddfc408cbfd2f133ec3fb214e06af6c2268aff12e4b3aaeb5679c1806b9c21184b9cbe312c1105d483b68107d792b74a9a9a37756d48bdccaa72e966f2bb9961e101af",
    ];
    for _ in 0..random.below(4).saturating_add(1) {
        let i = usize::try_from(random.below(SEEDS.len() as u64)).unwrap_or(0);
        let hex = SEEDS.get(i).copied().unwrap_or(SEEDS[0]);
        let mut data: Vec<u8> = (0..hex.len() / 2)
            .filter_map(|j| u8::from_str_radix(hex.get(2 * j..2 * j + 2)?, 16).ok())
            .collect();
        for _ in 0..random.below(3) {
            let len = u64::try_from(data.len()).unwrap_or(1).max(1);
            let at = usize::try_from(random.below(len)).unwrap_or(0);
            match random.below(4) {
                0 if !data.is_empty() => {
                    data.remove(at.min(data.len().saturating_sub(1)));
                }
                1 => data.insert(at, u8::try_from(random.below(256)).unwrap_or(0)),
                _ => {
                    if let Some(b) = data.get_mut(at) {
                        *b ^= u8::try_from(random.below(255).saturating_add(1)).unwrap_or(1);
                    }
                }
            }
        }
        let input_type = random.pick(&["-", "-", "-", "PEM", "DER", "der"]);
        let structure = random.pick(&[
            "-",
            "-",
            "-",
            "SubjectPublicKeyInfo",
            "PrivateKeyInfo",
            "EncryptedPrivateKeyInfo",
            "type-specific",
        ]);
        let selection = random.pick(&["0", "0", "1", "2", "3", "4", "7"]);
        // Not with an encrypted PKCS#8, whose decryption comes with step 4.7d.
        let pass = if i == 3 || i == 5 {
            "-"
        } else {
            random.pick(&["-", "-", "secret", "wrong"])
        };
        let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
        writeln!(
            out,
            "decode {input_type} {structure} {selection} {pass} {hex}"
        )?;
    }
    Ok(())
}

/// A random session of DSA keys from data: RFC 6979's DSA-1024 parameters (now and then a part
/// missing or small), private keys of random lengths or at q, public keys computed from them or
/// at the bounds, and a number now and then changed.
fn dsakey_session(random: &mut Random, out: &mut String) -> Result {
    for _ in 0..random.below(4).saturating_add(1) {
        let part = |random: &mut Random, name: &str| match random.below(14) {
            0 => "-".to_owned(),
            1 => format!("{:x}", random.below(64).saturating_add(2)),
            _ => format!("k:{name}"),
        };
        let p = part(random, "p");
        let q = part(random, "q");
        let g = part(random, "g");
        let x = match random.below(8) {
            0 => "-".to_owned(),
            1 => "k:q".to_owned(),
            2 => format!("{:x}", random.below(4)),
            3 => "k:x".to_owned(),
            _ => {
                let len = usize::try_from(random.below(22))
                    .unwrap_or(0)
                    .saturating_add(1);
                random_hex(random, len)
            }
        };
        let y = match random.below(8) {
            0 => "-".to_owned(),
            1 => format!("{:x}", random.below(4)),
            2 => "k:p".to_owned(),
            3 => "k:y".to_owned(),
            _ => "gx".to_owned(),
        };
        let edit = match random.below(5) {
            0 => format!(
                "{}{}",
                random.pick(&["p", "q", "g", "y", "x"]),
                random.below(5).saturating_add(1)
            ),
            _ => "-".to_owned(),
        };
        writeln!(out, "dsakey {p} {q} {g} {y} {x} {edit}")?;
    }
    Ok(())
}

/// A random session of DSA signatures from deterministic generators with RFC 6979's DSA-1024
/// parameters: private keys of random lengths (now and then at the bounds), each kind of key
/// (from the key manager, a legacy DSA, one with an application's method), messages of every
/// length signed with each nonce type (through a digest context, as a digest, and with a
/// composite algorithm) with digests good and bad; and signatures near valid ones verified.
fn dsasig_session(random: &mut Random, out: &mut String) -> Result {
    for line in DETERMINISTIC_RAND {
        writeln!(out, "{line}")?;
    }
    for _ in 0..random.below(6).saturating_add(1) {
        let x = match random.below(8) {
            0 => format!("{:x}", random.below(4).saturating_add(1)),
            1 => "996F967F6C8E388D9E28D01E205FBA957A5698B0".to_owned(),
            2 | 3 => "k:x".to_owned(),
            _ => {
                let len = usize::try_from(random.below(20))
                    .unwrap_or(0)
                    .saturating_add(1);
                random_hex(random, len)
            }
        };
        let how = random.pick(&["p", "p", "p", "l", "f"]);
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
            "DSA-SHA256",
            "DSA-SHA1",
            "DSA-SHA384",
            "DSA-SHA3-224",
            "DSA-SHA2-512",
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
                    .saturating_add(44);
                format!("30{}", random_hex(random, len))
            }
            _ => "-".to_owned(),
        };
        writeln!(out, "dsasig {x} {how} {md} {nonce} {alg} {msg} {sig}")?;
    }
    Ok(())
}

/// A random session of DH parameter decoding: small valid PKCS #3 and X9.42 encodings with
/// octets changed, dropped, or added.
fn dhder_session(random: &mut Random, out: &mut String) -> Result {
    const SEEDS: [(&str, &str); 6] = [
        ("p", "3006020117020105"),
        ("p", "3009020117020105020164"),
        ("x", "300c02011702010502010b020102"),
        ("x", "301302011702010502010b30080303000102020107"),
        ("x", "301602011702010502010b02010230080303000102020107"),
        ("p", "3016021100f7e75fdc469067ffdc4e847c51f452df020105"),
    ];
    for _ in 0..random.below(4).saturating_add(1) {
        let i = usize::try_from(random.below(6)).unwrap_or(0);
        let (kind, hex) = SEEDS.get(i).copied().unwrap_or(SEEDS[0]);
        let mut der: Vec<u8> = (0..hex.len() / 2)
            .filter_map(|j| u8::from_str_radix(hex.get(2 * j..2 * j + 2)?, 16).ok())
            .collect();
        for _ in 0..random.below(3).saturating_add(1) {
            let len = u64::try_from(der.len()).unwrap_or(1).max(1);
            let at = usize::try_from(random.below(len)).unwrap_or(0);
            match random.below(4) {
                0 if !der.is_empty() => {
                    der.remove(at.min(der.len().saturating_sub(1)));
                }
                1 => der.insert(at, u8::try_from(random.below(256)).unwrap_or(0)),
                _ => {
                    if let Some(b) = der.get_mut(at) {
                        *b ^= u8::try_from(random.below(255).saturating_add(1)).unwrap_or(1);
                    }
                }
            }
        }
        let kind = if random.below(5) == 0 {
            if kind == "p" { "x" } else { "p" }
        } else {
            kind
        };
        let hex: String = der.iter().map(|b| format!("{b:02x}")).collect();
        writeln!(out, "dhder {kind} {hex}")?;
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
        let first = random_sessions(42, 2000, &[]).unwrap();
        assert_eq!(first, random_sessions(42, 2000, &[]).unwrap());
        assert_ne!(first, random_sessions(43, 2000, &[]).unwrap());
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
