//! `cargo xtask test-differential [--random N] [--seed S]`: differential testing
//! (TEST_PLAN.md, layer L5).
//!
//! The probe (`tests/differential/probe.c`) reads commands on stdin and prints what the library
//! did. It is compiled once and linked against the reference OpenSSL, then fed the same input on
//! the reference and on rustssl, and the outputs must match line for line. Unlike the C
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
                    "FAIL {name}: line {}: reference `{b}`, rustssl `{a}`",
                    i + 1
                ),
                None => println!(
                    "FAIL {name}: rustssl stopped after {} of {lines} lines ({}): {}",
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
}

/// Random `BUF_MEM` command sessions in the probe's language.
fn random_sessions(seed: u64, count: usize) -> Result<String> {
    let mut random = Random::new(seed);
    let mut out = String::new();
    for session in 0..count {
        writeln!(out, "# session {session}")?;
        writeln!(out, "new {}", random.below(2))?;
        for _ in 0..1 + random.below(40) {
            match random.below(10) {
                0..=3 => writeln!(out, "grow {}", length(&mut random))?,
                4..=6 => writeln!(out, "grow_clean {}", length(&mut random))?,
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
    }
    Ok(out)
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
        let first = random_sessions(42, 20).unwrap();
        assert_eq!(first, random_sessions(42, 20).unwrap());
        assert_ne!(first, random_sessions(43, 20).unwrap());
        assert!(first.starts_with("# session 0\nnew "));
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
