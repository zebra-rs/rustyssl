//! `cargo xtask test-timing [target...]`: the constant-time checks (TEST_PLAN.md,
//! constant-time verification) on the reference and on rustyssl.
//!
//! `tests/timing/dudect.c` times each target's operation on two classes of inputs (fixed and
//! random, or for RSA PKCS #1 v1.5, valid and invalid paddings, Marvin's split) and gives the
//! largest |t| of Welch's t-test over its croppings (dudect's method). A target passes when
//! rustyssl's |t| stays under dudect's "definitely not constant time" (10); the reference's is
//! printed beside it. Timing is noisy: a run on a loaded machine can cross the line by chance,
//! so a failing target is measured once more before it fails. The program is built with
//! optimization, against the vendored headers, once for each library.

use std::path::Path;
use std::process::Command;

use crate::test_c::{CFLAGS, LOADER_PATH, cc, prepare};
use crate::util::{Result, fresh_dir, run_output, target_dir, workspace_root};

/// The targets and how many measurements each takes (fewer for the slow operations).
const TARGETS: &[(&str, u64)] = &[
    ("aes-gcm", 400_000),
    ("ghash", 400_000),
    ("poly1305", 400_000),
    ("memcmp", 200_000),
    ("x25519", 100_000),
    ("x25519-derive", 100_000),
    ("x25519-ctx", 100_000),
    ("bn-modexp-consttime", 40_000),
    ("ml-kem-decap", 100_000),
    ("ecdsa-sign", 40_000),
    ("rsa-raw-decrypt", 40_000),
    ("rsa-pkcs1-decrypt", 40_000),
    ("tls-cbc-record", 40_000),
];

/// dudect's line: above it, "definitely not constant time".
const THRESHOLD: f64 = 10.0;

/// The configuration file both runs are pointed at (one that doesn't exist).
const MISSING_CONFIG: &str = "/nonexistent/rustyssl-tests/openssl.cnf";

/// One run's |t| for `target` with the libraries in `lib`.
fn measure(exe: &Path, target: &str, count: u64, lib: &Path) -> Result<(f64, String)> {
    let out = Command::new(exe)
        .arg(target)
        .arg(count.to_string())
        .env(LOADER_PATH, lib)
        .env("OPENSSL_MODULES", crate::test_c::modules_of(lib))
        .env("OPENSSL_CONF", MISSING_CONFIG)
        .output()
        .map_err(|e| format!("cannot run {}: {e}", exe.display()))?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if !out.status.success() {
        return Err(format!(
            "{target}: the run fails: {}{}",
            text,
            String::from_utf8_lossy(&out.stderr).trim()
        )
        .into());
    }
    let t = text
        .split_whitespace()
        .find_map(|w| w.strip_prefix("t="))
        .and_then(|v| v.parse::<f64>().ok())
        .ok_or_else(|| format!("{target}: no t in `{text}`"))?;
    Ok((t, text))
}

pub fn run(args: &[String]) -> Result {
    let root = workspace_root();
    let selected: Vec<&(&str, u64)> = TARGETS
        .iter()
        .filter(|(name, _)| args.is_empty() || args.iter().any(|a| a == name))
        .collect();
    if selected.is_empty() {
        return Err("no timing targets selected".into());
    }
    let (reference, dist) = prepare(&root)?;
    let work = target_dir(&root).join("xtask/test-timing");
    fresh_dir(&work)?;
    // Each library gets the program linked against it, as an application would be: on Apple
    // silicon a program linked against one library and run on the other can show a small
    // signal on the shortest operation (`memcmp`, branch-free on both) from its layout alone.
    let build = |lib_root: &Path, name: &str| -> Result<std::path::PathBuf> {
        let exe = work.join(name);
        run_output(
            cc().args(CFLAGS)
                .arg("-O2")
                .arg("-I")
                .arg(dist.join("include"))
                .arg(root.join("tests/timing/dudect.c"))
                .arg("-L")
                .arg(lib_root.join("lib"))
                .args(["-lssl", "-lcrypto", "-lm", "-o"])
                .arg(&exe),
        )?;
        Ok(exe)
    };
    let theirs_exe = build(&reference, "dudect-reference")?;
    let ours_exe = build(&dist, "dudect-rustyssl")?;
    let mut failures = Vec::new();
    for (name, count) in selected {
        let (theirs, _) = measure(&theirs_exe, name, *count, &reference.join("lib"))?;
        let (mut ours, mut line) = measure(&ours_exe, name, *count, &dist.join("lib"))?;
        if ours >= THRESHOLD {
            // Once more, in case the machine was busy.
            (ours, line) = measure(&ours_exe, name, *count, &dist.join("lib"))?;
        }
        let verdict = if ours < THRESHOLD { "PASS" } else { "FAIL" };
        println!("{verdict} {name}: |t| {ours:.2} (reference {theirs:.2}), {count} measurements");
        if ours >= THRESHOLD {
            failures.push(format!("{name} ({line})"));
        }
    }
    if failures.is_empty() {
        println!("no timing signal over |t| = {THRESHOLD} in rustyssl's constant-time paths");
        Ok(())
    } else {
        Err(format!("timing signals: {}", failures.join(", ")).into())
    }
}
