//! `cargo xtask test-distro [distro...]` (TEST_PLAN L11, step 12.4): the distro system tests.
//! For each distribution, rustyssl's package (`cargo xtask package <layout>`) is built in a
//! builder container, installed side by side in the distribution's own container, and
//! `tests/distro/scenarios.sh` runs every scenario on the system's OpenSSL, then again after
//! `rustyssl-select rustyssl`. A scenario passes when it passes on both (for the crypto-policy
//! probes: when rustyssl's result is the system's). On macOS, `homebrew` runs
//! `tests/distro/homebrew.sh`: Homebrew's Python on Homebrew's openssl@3, then on rustyssl's keg.
//!
//! | Distro | Image | Layout | Builder |
//! |---|---|---|---|
//! | `debian` | `debian:trixie-slim` | `debian` | `rust:<toolchain>-slim-bookworm` (glibc 2.36) |
//! | `ubuntu` | `ubuntu:24.04` | `debian` | the same |
//! | `fedora` | `fedora:latest` | `fedora` | the same |
//! | `el` | `almalinux:10` | `el` | the same |
//! | `alpine` | `alpine:latest` | `alpine` | `rust:<toolchain>-alpine` |
//!
//! The libraries are built against Debian 12's glibc so they load on every distribution's
//! (Ubuntu 24.04 and EL10 have 2.39). Needs Docker; the containers run on the host's
//! architecture. An image this command pulled is removed after its run (Docker's disk is
//! small); images that were already there stay. The reports are `target/distro/<distro>.log`
//! and `target/distro-report.md`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::targets::host;
use crate::util::{Result, target_dir, workspace_root};

/// (distro, image, layout, musl)
const DISTROS: &[(&str, &str, &str, bool)] = &[
    ("debian", "debian:trixie-slim", "debian", false),
    ("ubuntu", "ubuntu:24.04", "debian", false),
    ("fedora", "fedora:latest", "fedora", false),
    ("el", "almalinux:10", "el", false),
    ("alpine", "alpine:latest", "alpine", true),
];

pub fn run(args: &[String]) -> Result {
    let root = workspace_root();
    let (_, target) = host()?;
    let apple = target.clang.contains("apple");
    let mut selected: Vec<&str> = args.iter().map(String::as_str).collect();
    if selected.is_empty() {
        selected = DISTROS.iter().map(|d| d.0).collect();
        if apple {
            selected.push("homebrew");
        }
    }
    let out = target_dir(&root).join("distro");
    fs::create_dir_all(&out)?;
    let mut report = String::from(
        "# Distro system tests (TEST_PLAN L11)\n\nWritten by `cargo xtask test-distro`. Each \
         scenario runs on the distribution's own OpenSSL (system), then with rustyssl selected \
         (`rustyssl-select rustyssl`).\n",
    );
    let mut failed = Vec::new();
    let mut packages: BTreeMap<&str, String> = BTreeMap::new();
    // Builder images this run pulled, removed at its end.
    let mut builders = Vec::new();
    for name in selected {
        println!("== {name}");
        let log = if name == "homebrew" {
            if !apple {
                return Err("the homebrew scenarios run on macOS".into());
            }
            homebrew(&root, &out)?
        } else {
            let &(_, image, layout, musl) = DISTROS
                .iter()
                .find(|d| d.0 == name)
                .ok_or_else(|| format!("unknown distro `{name}`"))?;
            let tarball = match packages.get(layout) {
                Some(t) => t.clone(),
                None => {
                    let t = build_package(&root, &out, layout, musl, &mut builders)?;
                    packages.insert(layout, t.clone());
                    t
                }
            };
            run_distro(&root, &out, name, image, &tarball)?
        };
        fs::write(out.join(format!("{name}.log")), &log)?;
        let (table, problems) = judge(&log);
        writeln!(report, "\n## {name}\n\n{table}")?;
        if problems.is_empty() {
            println!("PASS {name}: every scenario behaves the same on rustyssl");
        } else {
            for p in &problems {
                println!("FAIL {name}: {p}");
            }
            failed.push(name.to_owned());
        }
    }
    for image in &builders {
        remove_image(image);
    }
    fs::write(target_dir(&root).join("distro-report.md"), report)?;
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("failed: {}", failed.join(", ")).into())
    }
}

/// Builds the layout's package in the builder container; returns the tarball's file name
/// (in `out`).
fn build_package(
    root: &Path,
    out: &Path,
    layout: &str,
    musl: bool,
    builders: &mut Vec<String>,
) -> Result<String> {
    let toolchain = toolchain(root)?;
    let (image, setup, volume) = if musl {
        (
            format!("rust:{toolchain}-alpine"),
            "apk add -q gcc musl-dev binutils llvm-libunwind-dev tar",
            "musl",
        )
    } else {
        (
            format!("rust:{toolchain}-slim-bookworm"),
            "true",
            "bookworm",
        )
    };
    let arch = std::env::consts::ARCH;
    println!("Building the {layout} package in {image}...");
    let script = format!(
        "set -e; {setup}; cd /src; export CARGO_TERM_COLOR=never CARGO_INCREMENTAL=0; \
         cargo xtask package {layout} > /out/build-{layout}.log 2>&1 || \
         {{ tail -30 /out/build-{layout}.log; exit 1; }}; \
         cp target/package/rustyssl-*-{layout}-*.tar.gz /out/"
    );
    if !image_present(&image) {
        builders.push(image.clone());
    }
    let status = Command::new("docker")
        .args(["run", "--rm", "--platform", platform()])
        .arg("-v")
        .arg(format!("{}:/src", root.display()))
        .arg("-v")
        .arg(format!(
            "rustyssl-distro-target-{volume}-{arch}:/src/target"
        ))
        .arg("-v")
        .arg(format!("rustyssl-cargo-{arch}:/usr/local/cargo/registry"))
        .arg("-v")
        .arg(format!("{}:/out", out.display()))
        .arg(&image)
        .args(["sh", "-c", &script])
        .status()
        .map_err(|e| format!("cannot run docker: {e}"))?;
    if !status.success() {
        return Err(format!("building the {layout} package failed").into());
    }
    let tarball = fs::read_dir(out)?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .find(|n| {
            n.starts_with("rustyssl-")
                && n.contains(&format!("-{layout}-"))
                && n.ends_with(".tar.gz")
        })
        .ok_or("the package's tarball is missing")?;
    Ok(tarball)
}

/// The pinned toolchain's version, from `rust-toolchain.toml`.
fn toolchain(root: &Path) -> Result<String> {
    let text = fs::read_to_string(root.join("rust-toolchain.toml"))?;
    crate::util::toml_value(&text, "channel")
        .map(str::to_owned)
        .ok_or_else(|| "rust-toolchain.toml has no channel".into())
}

/// The host's Docker platform: the containers run natively.
fn platform() -> &'static str {
    if std::env::consts::ARCH == "aarch64" {
        "linux/arm64"
    } else {
        "linux/amd64"
    }
}

fn image_present(image: &str) -> bool {
    Command::new("docker")
        .args(["image", "inspect", image])
        .output()
        .is_ok_and(|o| o.status.success())
}

fn remove_image(image: &str) {
    let _ = Command::new("docker").args(["rmi", image]).output();
}

/// Runs the scenarios in the distribution's container; returns their output.
fn run_distro(root: &Path, out: &Path, name: &str, image: &str, tarball: &str) -> Result<String> {
    let pulled = !image_present(image);
    let output = Command::new("docker")
        .args(["run", "--rm", "--platform", platform()])
        .arg("-v")
        .arg(format!("{}:/pkg:ro", out.display()))
        .arg("-v")
        .arg(format!("{}:/t:ro", root.join("tests/distro").display()))
        .arg(image)
        .args(["sh", "/t/scenarios.sh", name, &format!("/pkg/{tarball}")])
        .output()
        .map_err(|e| format!("cannot run docker: {e}"))?;
    if pulled {
        remove_image(image);
    }
    let mut log = String::from_utf8_lossy(&output.stdout).into_owned();
    log.push_str(&String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        log.push_str(&format!(
            "\n== the scenarios exited with {}\n",
            output.status
        ));
    }
    Ok(log)
}

/// Stages the Homebrew keg and runs the macOS scenarios.
fn homebrew(root: &Path, out: &Path) -> Result<String> {
    let keg = "/opt/homebrew/Cellar/rustyssl/test";
    crate::package::run(&["homebrew".to_owned(), "--prefix".to_owned(), keg.to_owned()])?;
    let lib = target_dir(root)
        .join("package/homebrew/root")
        .join(keg.trim_start_matches('/'))
        .join("lib");
    let work = out.join("homebrew");
    let _ = fs::remove_dir_all(&work);
    let output = Command::new("sh")
        .arg(root.join("tests/distro/homebrew.sh"))
        .arg(&lib)
        .arg(&work)
        .output()
        .map_err(|e| format!("cannot run the scenarios: {e}"))?;
    let mut log = String::from_utf8_lossy(&output.stdout).into_owned();
    log.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(log)
}

/// The report's table and the problems: a scenario must pass in both phases, except the
/// crypto-policy probes, which must give the system's result; the run must reach its end.
fn judge(log: &str) -> (String, Vec<String>) {
    let mut results: BTreeMap<String, [Option<bool>; 2]> = BTreeMap::new();
    for line in log.lines() {
        let mut words = line.split_whitespace();
        if let (Some("RESULT"), Some(name), Some(phase), Some(outcome)) =
            (words.next(), words.next(), words.next(), words.next())
        {
            let slot = usize::from(phase == "rustyssl");
            if let Some(r) = results.entry(name.to_owned()).or_default().get_mut(slot) {
                *r = Some(outcome == "pass");
            }
        }
    }
    let mut problems = Vec::new();
    if !log.contains("== done") {
        let tail: Vec<&str> = log.lines().rev().take(5).collect();
        problems.push(format!("the scenarios didn't finish: {}", tail.join(" | ")));
    }
    let show = |r: Option<bool>| match r {
        Some(true) => "pass",
        Some(false) => "fail",
        None => "",
    };
    let mut table = String::from("| Scenario | System | rustyssl | |\n|---|---|---|---|\n");
    for (name, [system, ours]) in &results {
        let policy = name.starts_with("policy-");
        // A scenario of one phase only (which libraries were loaded) must pass there.
        let ok = match (system, ours) {
            (Some(s), Some(o)) if policy => s == o,
            (Some(s), Some(o)) => *s && *o,
            (Some(only), None) | (None, Some(only)) => *only,
            (None, None) => false,
        };
        let verdict = if ok { "ok" } else { "**differs**" };
        let _ = writeln!(
            table,
            "| {name} | {} | {} | {verdict} |",
            show(*system),
            show(*ours)
        );
        if !ok {
            problems.push(format!(
                "{name}: system {}, rustyssl {}",
                show(*system),
                show(*ours)
            ));
        }
    }
    if results.is_empty() {
        problems.push("no scenario ran".to_owned());
    }
    (table, problems)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenarios_must_pass_and_policies_must_agree() {
        let log = "RESULT nginx-curl system pass\nRESULT nginx-curl rustyssl pass\n\
                   RESULT policy-FUTURE-rsa2048 system fail\nRESULT policy-FUTURE-rsa2048 rustyssl fail\n\
                   RESULT python-loads-rustyssl-libssl rustyssl pass\n== done\n";
        assert!(judge(log).1.is_empty(), "{:?}", judge(log).1);
        let log = "RESULT wget system pass\nRESULT wget rustyssl fail\n\
                   RESULT policy-LEGACY-x system pass\nRESULT policy-LEGACY-x rustyssl fail\n";
        let problems = judge(log).1;
        assert_eq!(problems.len(), 3, "{problems:?}");
    }
}
