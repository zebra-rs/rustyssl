//! `cargo xtask bench [options] [group...]`: performance against the reference (TEST_PLAN.md,
//! L10), on this machine, with both libraries built optimized.
//!
//! - `speed`: upstream's `openssl speed` (the reference's binary, `-mr`) on each library:
//!   digests, ciphers, and AEADs from 16 octets to 16 KiB; sign, verify, key exchange, and KEM
//!   operations per second.
//! - `tls`, `misc`: `tests/bench/bench.c`, built once against each library: handshakes per
//!   second (full and resumed, TLS 1.2 and 1.3, RSA and ECDSA, hybrid post-quantum), bulk
//!   throughput, heap per `SSL_CTX` and per connection, start-up cost, DRBG throughput, RSA
//!   key generation, and scaling over threads.
//!
//! Each measurement runs `--runs` times (3 by default; `--quick` is one short run), alternating
//! the libraries, and the report takes the medians and the spread (max - min over median) of
//! each. The report is `target/bench-report.md`, the numbers `target/bench.json`.
//!
//! `--compare <file>` checks rustyssl's numbers against a baseline's (`target/bench.json` from
//! an earlier run on the same machine) and fails when one is worse by more than `--threshold`
//! percent (5 by default), the gate TEST_PLAN.md L10 sets for a dedicated runner. Shared CI
//! runners are too noisy for it; see docs/PERFORMANCE.md.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::json;
use crate::test_c::{CFLAGS, LOADER_PATH, cc, modules_of, prepare};
use crate::util::{Result, fresh_dir, run_output, target_dir, workspace_root};

/// The configuration file every run is pointed at (one that doesn't exist).
const MISSING_CONFIG: &str = "/nonexistent/rustyssl-bench/openssl.cnf";

/// `openssl speed -evp` algorithms, measured at speed's six sizes.
const CIPHERS: &[&str] = &[
    "sha256",
    "sha512",
    "sha3-256",
    "aes-128-gcm",
    "aes-256-gcm",
    "aes-128-cbc",
    "aes-128-ctr",
    "chacha20-poly1305",
];

/// `openssl speed`'s block sizes, in its output's order.
const SIZES: &[u32] = &[16, 64, 256, 1024, 8192, 16384];

/// Public-key algorithms: speed's name, the `+F` line tag that carries its numbers, how many
/// fields precede them, and their names.
const PKEY: &[(&str, &str, usize, &[&str])] = &[
    ("rsa2048", "+F2", 3, &["sign", "verify"]),
    ("rsa3072", "+F2", 3, &["sign", "verify"]),
    ("ecdsap256", "+F4", 3, &["sign", "verify"]),
    ("ecdsap384", "+F4", 3, &["sign", "verify"]),
    ("ed25519", "+F6", 4, &["sign", "verify"]),
    ("ecdhp256", "+F5", 3, &["derive"]),
    ("ecdhx25519", "+F5", 3, &["derive"]),
    ("ffdh2048", "+F8", 3, &["derive"]),
    ("ML-KEM-768", "+F9", 2, &["keygen", "encaps", "decaps"]),
    ("ML-DSA-65", "+F10", 2, &["keygen", "sign", "verify"]),
];

/// The handshake measurements: protocol, server key, full or resumed, key-exchange group.
const HANDSHAKES: &[(&str, &str, &str, &str)] = &[
    ("tls1.3", "ecdsa", "full", "-"),
    ("tls1.3", "rsa", "full", "-"),
    ("tls1.3", "ecdsa", "resume", "-"),
    ("tls1.3", "ecdsa", "full", "X25519MLKEM768"),
    ("tls1.2", "ecdsa", "full", "-"),
    ("tls1.2", "rsa", "full", "-"),
    ("tls1.2", "rsa", "resume", "-"),
];

/// One measurement across runs.
#[derive(Clone, Debug)]
struct Metric {
    name: String,
    unit: String,
    higher_better: bool,
    theirs: Vec<f64>,
    ours: Vec<f64>,
}

impl Metric {
    /// How many times worse rustyssl is than the reference (above 1: slower or bigger).
    fn cost(&self) -> f64 {
        let (t, o) = (median(&self.theirs), median(&self.ours));
        if self.higher_better { t / o } else { o / t }
    }
}

fn median(v: &[f64]) -> f64 {
    let mut s = v.to_vec();
    s.sort_by(f64::total_cmp);
    match s.len() {
        0 => f64::NAN,
        n if n % 2 == 1 => s.get(n / 2).copied().unwrap_or(f64::NAN),
        n => {
            let a = s.get(n / 2 - 1).copied().unwrap_or(f64::NAN);
            let b = s.get(n / 2).copied().unwrap_or(f64::NAN);
            (a + b) / 2.0
        }
    }
}

/// (max - min) / median, as a percentage.
fn spread(v: &[f64]) -> f64 {
    let max = v.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let min = v.iter().copied().fold(f64::INFINITY, f64::min);
    let m = median(v);
    if v.len() < 2 || m == 0.0 {
        0.0
    } else {
        (max - min) / m * 100.0
    }
}

/// The libraries under test: the reference and rustyssl.
struct Side {
    lib: PathBuf,
    bench: PathBuf,
}

impl Side {
    fn command(&self, program: &Path) -> Command {
        let mut cmd = Command::new(program);
        cmd.env(LOADER_PATH, &self.lib)
            .env("OPENSSL_MODULES", modules_of(&self.lib))
            .env("OPENSSL_CONF", MISSING_CONFIG);
        cmd
    }
}

/// A collector of named numbers, keyed by metric, from each side's runs.
#[derive(Default)]
struct Results(Vec<Metric>);

impl Results {
    fn add(&mut self, name: &str, unit: &str, higher_better: bool, ours: bool, value: f64) {
        let pos = match self.0.iter().position(|m| m.name == name) {
            Some(p) => p,
            None => {
                self.0.push(Metric {
                    name: name.to_owned(),
                    unit: unit.to_owned(),
                    higher_better,
                    theirs: Vec::new(),
                    ours: Vec::new(),
                });
                self.0.len() - 1
            }
        };
        if let Some(m) = self.0.get_mut(pos) {
            if ours {
                m.ours.push(value);
            } else {
                m.theirs.push(value);
            }
        }
    }
}

struct Options {
    runs: usize,
    seconds: u32,
    groups: Vec<String>,
    compare: Option<PathBuf>,
    threshold: f64,
}

fn options(args: &[String]) -> Result<Options> {
    let mut o = Options {
        runs: 3,
        seconds: 1,
        groups: Vec::new(),
        compare: None,
        threshold: 5.0,
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = |what: &str| it.next().ok_or_else(|| format!("{what} needs a value"));
        match a.as_str() {
            "--quick" => o.runs = 1,
            "--runs" => o.runs = value("--runs")?.parse().map_err(|_| "--runs: a number")?,
            "--seconds" => {
                o.seconds = value("--seconds")?
                    .parse()
                    .map_err(|_| "--seconds: a number")?;
            }
            "--compare" => o.compare = Some(PathBuf::from(value("--compare")?)),
            "--threshold" => {
                o.threshold = value("--threshold")?
                    .parse()
                    .map_err(|_| "--threshold: a percentage")?;
            }
            g @ ("speed" | "tls" | "misc") => o.groups.push(g.to_owned()),
            other => {
                return Err(format!(
                    "unknown argument `{other}`; usage: cargo xtask bench [--quick] [--runs N] \
                     [--seconds S] [--compare FILE] [--threshold PCT] [speed|tls|misc...]"
                )
                .into());
            }
        }
    }
    if o.runs == 0 || o.seconds == 0 {
        return Err("--runs and --seconds must be at least 1".into());
    }
    Ok(o)
}

pub fn run(args: &[String]) -> Result {
    let opts = options(args)?;
    let want = |g: &str| opts.groups.is_empty() || opts.groups.iter().any(|x| x == g);
    let root = workspace_root();
    let (reference, dist) = prepare(&root)?;
    let work = target_dir(&root).join("xtask/bench");
    fresh_dir(&work)?;
    let certs = reference.join("src/test/certs");
    let build = |lib_root: &Path, name: &str| -> Result<PathBuf> {
        let exe = work.join(name);
        run_output(
            cc().args(CFLAGS)
                .arg("-O2")
                .arg("-I")
                .arg(dist.join("include"))
                .arg(root.join("tests/bench/bench.c"))
                .arg("-L")
                .arg(lib_root.join("lib"))
                .args(["-lssl", "-lcrypto", "-lpthread", "-o"])
                .arg(&exe),
        )?;
        Ok(exe)
    };
    let sides = [
        Side {
            lib: reference.join("lib"),
            bench: build(&reference, "bench-reference")?,
        },
        Side {
            lib: dist.join("lib"),
            bench: build(&dist, "bench-rustyssl")?,
        },
    ];
    let openssl = reference.join("bin/openssl");
    let mut results = Results::default();
    let secs = opts.seconds.to_string();
    let quick = opts.runs == 1;
    for run in 0..opts.runs {
        println!("Run {} of {}...", run + 1, opts.runs);
        // Alternate which library goes first, so drift over a run doesn't favour one.
        let order: [usize; 2] = if run % 2 == 0 { [0, 1] } else { [1, 0] };
        for &which in &order {
            let side = sides.get(which).ok_or("no such side")?;
            let ours = which == 1;
            if want("speed") {
                speed(&openssl, side, ours, &secs, &mut results)?;
            }
            if want("tls") {
                tls(side, ours, &secs, &certs, quick, &mut results)?;
            }
            if want("misc") {
                misc(side, ours, &secs, &certs, quick, &mut results)?;
            }
        }
    }
    let report = report(&results.0, &opts);
    let out = target_dir(&root).join("bench-report.md");
    fs::write(&out, &report)?;
    let json_out = target_dir(&root).join("bench.json");
    fs::write(&json_out, to_json(&results.0))?;
    print!("{report}");
    println!("Wrote {} and {}", out.display(), json_out.display());
    match &opts.compare {
        Some(base) => compare(&results.0, base, opts.threshold),
        None => Ok(()),
    }
}

/// Runs `openssl speed` on `side` and collects its numbers.
fn speed(openssl: &Path, side: &Side, ours: bool, secs: &str, r: &mut Results) -> Result {
    for alg in CIPHERS {
        let text = run_output(
            side.command(openssl)
                .args(["speed", "-mr", "-seconds", secs, "-evp", alg]),
        )?;
        let line = text
            .lines()
            .find(|l| l.starts_with("+F:"))
            .ok_or_else(|| format!("speed -evp {alg}: no +F line"))?;
        let nums = numbers(line, 3);
        for (size, v) in SIZES.iter().zip(nums) {
            r.add(&format!("{alg} {size} B"), "MB/s", true, ours, v / 1e6);
        }
    }
    for (alg, tag, skip, fields) in PKEY {
        let text = run_output(
            side.command(openssl)
                .args(["speed", "-mr", "-seconds", secs, alg]),
        )?;
        let line = text
            .lines()
            .find(|l| l.split(':').next() == Some(*tag))
            .ok_or_else(|| format!("speed {alg}: no {tag} line"))?;
        for (field, v) in fields.iter().zip(numbers(line, *skip)) {
            r.add(&format!("{alg} {field}"), "op/s", true, ours, v);
        }
    }
    Ok(())
}

/// The numbers of a `+F` line after its first `skip` fields.
fn numbers(line: &str, skip: usize) -> Vec<f64> {
    line.split(':')
        .skip(skip)
        .filter_map(|f| f.trim().parse::<f64>().ok())
        .collect()
}

/// Runs the bench program in one mode and returns its `<metric> <value> <unit>` lines.
fn bench(side: &Side, args: &[&str]) -> Result<Vec<(String, f64, String)>> {
    let text = run_output(side.command(&side.bench).args(args))?;
    Ok(text
        .lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            let (name, value, unit) = (w.next()?, w.next()?, w.next()?);
            Some((name.to_owned(), value.parse().ok()?, unit.to_owned()))
        })
        .collect())
}

fn tls(side: &Side, ours: bool, secs: &str, certs: &Path, quick: bool, r: &mut Results) -> Result {
    let certs = certs.to_string_lossy();
    for (version, key, how, group) in HANDSHAKES {
        let out = bench(side, &["handshake", version, key, how, group, secs, &certs])?;
        for (_, v, unit) in out {
            let g = if *group == "-" {
                String::new()
            } else {
                format!(" {group}")
            };
            r.add(
                &format!("handshake {version} {key} {how}{g}"),
                &unit,
                true,
                ours,
                v,
            );
        }
    }
    for (name, v, unit) in bench(side, &["bulk", secs, &certs])? {
        r.add(&format!("{name} tls1.3 aes-128-gcm"), &unit, true, ours, v);
    }
    let tsecs = if quick { "0.5" } else { secs };
    for (name, v, unit) in bench(side, &["threads", tsecs, &certs])? {
        r.add(&name, &unit, true, ours, v);
    }
    Ok(())
}

fn misc(side: &Side, ours: bool, secs: &str, certs: &Path, quick: bool, r: &mut Results) -> Result {
    let certs = certs.to_string_lossy();
    for (name, v, unit) in bench(side, &["memory", &certs])? {
        r.add(&name, &unit, false, ours, v);
    }
    // Start-up: OPENSSL_init_ssl in the process, and a whole process (the loader included).
    let starts = if quick { 5 } else { 20 };
    let mut inits = Vec::new();
    let mut procs = Vec::new();
    for _ in 0..starts {
        let t = Instant::now();
        for (_, v, _) in bench(side, &["init"])? {
            inits.push(v);
        }
        procs.push(t.elapsed().as_secs_f64() * 1e3);
    }
    r.add("init OPENSSL_init_ssl", "us", false, ours, median(&inits));
    r.add("init whole process", "ms", false, ours, median(&procs));
    for (name, v, unit) in bench(side, &["drbg", secs])? {
        r.add(&name, &unit, true, ours, v);
    }
    let keys = if quick { "5" } else { "20" };
    for (name, v, unit) in bench(side, &["rsa-keygen", keys])? {
        r.add(&name, &unit, false, ours, v);
    }
    Ok(())
}

fn report(metrics: &[Metric], opts: &Options) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# Performance: rustyssl against the reference\n");
    let _ = writeln!(
        s,
        "Written by `cargo xtask bench` ({} run(s) of {} s each, medians; spread is (max - min) / \
         median over the runs). **Cost** is how many times slower (or bigger) rustyssl is: \
         reference ÷ rustyssl for rates, rustyssl ÷ reference for times and sizes.\n",
        opts.runs, opts.seconds
    );
    let _ = writeln!(
        s,
        "| measurement | unit | reference | rustyssl | cost | spread ref / ours |\n|---|---|---:|---:|---:|---:|"
    );
    for m in metrics {
        let _ = writeln!(
            s,
            "| {} | {} | {} | {} | {:.2}× | {:.0}% / {:.0}% |",
            m.name,
            m.unit,
            fmt(median(&m.theirs)),
            fmt(median(&m.ours)),
            m.cost(),
            spread(&m.theirs),
            spread(&m.ours)
        );
    }
    s
}

fn fmt(v: f64) -> String {
    if v >= 100.0 {
        format!("{v:.0}")
    } else {
        format!("{v:.2}")
    }
}

fn to_json(metrics: &[Metric]) -> String {
    let mut s = String::from("{\"metrics\": [\n");
    for (i, m) in metrics.iter().enumerate() {
        let _ = writeln!(
            s,
            "  {{\"name\": \"{}\", \"unit\": \"{}\", \"higher_better\": {}, \"reference\": {}, \
             \"rustyssl\": {}}}{}",
            m.name,
            m.unit,
            m.higher_better,
            median(&m.theirs),
            median(&m.ours),
            if i + 1 < metrics.len() { "," } else { "" }
        );
    }
    s.push_str("]}\n");
    s
}

/// rustyssl's numbers against a baseline's: fails when one is worse by more than `threshold`
/// percent.
fn compare(metrics: &[Metric], base: &Path, threshold: f64) -> Result {
    let text = fs::read_to_string(base)
        .map_err(|e| format!("cannot read the baseline {}: {e}", base.display()))?;
    let doc = json::parse(&text)?;
    let list = doc
        .get("metrics")
        .and_then(json::Value::as_array)
        .ok_or("the baseline has no metrics")?;
    let mut worse = Vec::new();
    let mut compared = 0;
    for m in metrics {
        let Some(old) = list
            .iter()
            .find(|v| v.get("name").and_then(json::Value::as_str) == Some(m.name.as_str()))
            .and_then(|v| match v.get("rustyssl") {
                Some(json::Value::Number(n)) => n.parse::<f64>().ok(),
                _ => None,
            })
        else {
            continue;
        };
        compared += 1;
        let new = median(&m.ours);
        let change = if m.higher_better {
            (old - new) / old
        } else {
            (new - old) / old
        } * 100.0;
        if change > threshold {
            worse.push(format!(
                "{}: {:.1}% worse ({} -> {} {})",
                m.name,
                change,
                fmt(old),
                fmt(new),
                m.unit
            ));
        }
    }
    println!(
        "Compared {compared} measurements against {}",
        base.display()
    );
    if worse.is_empty() {
        println!("no measurement is more than {threshold}% worse than the baseline");
        Ok(())
    } else {
        for w in &worse {
            println!("WORSE {w}");
        }
        Err(format!(
            "{} measurement(s) more than {threshold}% worse than the baseline",
            worse.len()
        )
        .into())
    }
}
