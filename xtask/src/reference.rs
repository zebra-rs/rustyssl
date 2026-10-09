//! `cargo xtask ref-openssl [version]`: builds the reference OpenSSL that rustyssl is compared
//! against (TEST_PLAN.md, "Oracles") into `target/ref/openssl-<version>/`.
//!
//! The version defaults to the vendored one, so the reference matches the headers rustyssl is
//! built from. The build uses the same verified release tarball and the same `Configure`
//! options as the vendored ABI, plus debug info (`-g`). A finished build records its inputs
//! and is reused until they change.
//!
//! The verified source is kept, unbuilt, in `target/ref/openssl-<version>/src/`: OpenSSL's C is
//! the behavioral spec where the man pages are silent (README.md).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::targets::{OPENSSL_SERIES, host};
use crate::util::{Result, fresh_dir, run_logged, target_dir, toml_value, workspace_root};
use crate::vendor::{CONFIGURE_OPTIONS, fetch_verified};

/// Marks a finished build; holds the inputs it was built from.
const STAMP: &str = ".rustyssl-build";

pub fn run(args: &[String]) -> Result {
    let root = workspace_root();
    let version = match args {
        [] => vendored_version(&root)?,
        [version] => version.clone(),
        _ => return Err("usage: cargo xtask ref-openssl [version]".into()),
    };
    let prefix = ensure(&root, &version)?;
    println!("Reference OpenSSL {version} is in {}", prefix.display());
    Ok(())
}

/// The OpenSSL version vendored under `abi/`.
pub fn vendored_version(root: &Path) -> Result<String> {
    let path = root
        .join("abi")
        .join(format!("openssl-{OPENSSL_SERIES}"))
        .join("VERSION.toml");
    let text = fs::read_to_string(&path)?;
    Ok(toml_value(&text, "version")
        .ok_or("VERSION.toml has no version")?
        .to_owned())
}

/// Builds reference OpenSSL `version` for the host unless an up-to-date build exists, and
/// returns its install prefix (with `bin/`, `include/`, and `lib/`).
pub fn ensure(root: &Path, version: &str) -> Result<PathBuf> {
    let (_, target) = host()?;
    let prefix = target_dir(root)
        .join("ref")
        .join(format!("openssl-{version}"));
    let mut options: Vec<&str> = CONFIGURE_OPTIONS.to_vec();
    options.push("-g");
    let inputs = format!(
        "version = {version}\ntarget = {}\noptions = {}\n",
        target.configure,
        options.join(" ")
    );
    let work = target_dir(root)
        .join("xtask/ref")
        .join(format!("openssl-{version}"));
    if fs::read_to_string(prefix.join(STAMP)).is_ok_and(|built| built == inputs) {
        if !prefix.join("src").exists() {
            fresh_dir(&work)?;
            let release = fetch_verified(root, version, &work)?;
            keep_source(&release.tarball, version, &prefix, &work)?;
            fs::remove_dir_all(&work)?;
        }
        return Ok(prefix);
    }

    fresh_dir(&work)?;
    let release = fetch_verified(root, version, &work)?;
    let log = work.join("build.log");
    let mut tar = Command::new("tar");
    tar.arg("-xzf").arg(&release.tarball).arg("-C").arg(&work);
    run_logged(&mut tar, &log)?;
    let src = work.join(format!("openssl-{version}"));

    fresh_dir(&prefix)?;
    println!(
        "Building reference OpenSSL {version} for {} (log: {})...",
        target.configure,
        log.display()
    );
    // A cleared environment keeps CC, CFLAGS, and the like from changing the build.
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut configure = Command::new("perl");
    configure
        .arg("Configure")
        .arg(target.configure)
        .args(&options)
        .arg(format!("--prefix={}", prefix.display()))
        .arg("--libdir=lib")
        .current_dir(&src)
        .env_clear()
        .env("PATH", &path);
    run_logged(&mut configure, &log)?;
    let jobs = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);
    for step in [
        vec![format!("-j{jobs}"), "build_sw".to_owned()],
        vec!["install_sw".to_owned()],
    ] {
        let mut make = Command::new("make");
        make.args(step)
            .current_dir(&src)
            .env_clear()
            .env("PATH", &path);
        run_logged(&mut make, &log)?;
    }
    keep_source(&release.tarball, version, &prefix, &work)?;
    fs::write(prefix.join(STAMP), inputs)?;
    fs::remove_dir_all(&work)?;
    Ok(prefix)
}

/// Unpacks the verified release tarball, unbuilt, into `<prefix>/src/`.
fn keep_source(tarball: &Path, version: &str, prefix: &Path, work: &Path) -> Result {
    let unpacked = work.join("pristine");
    fresh_dir(&unpacked)?;
    let mut tar = Command::new("tar");
    tar.arg("-xzf").arg(tarball).arg("-C").arg(&unpacked);
    run_logged(&mut tar, &work.join("source.log"))?;
    let src = prefix.join("src");
    if src.exists() {
        fs::remove_dir_all(&src)?;
    }
    fs::rename(unpacked.join(format!("openssl-{version}")), &src)?;
    Ok(())
}
