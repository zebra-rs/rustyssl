//! `cargo xtask vendor <version>`: fetch an OpenSSL release, verify it, and vendor its ABI
//! definitions into `abi/openssl-<major>.<minor>/` (step 0.2 of the implementation plan).
//!
//! Needs `curl`, `gpg`/`gpgv`, `tar`, `perl`, and `make`. A release is trusted only if its
//! detached signature verifies against OpenSSL's published keys and chains to
//! [`TRUST_ANCHOR`], and its SHA-256 matches the published checksum and any earlier pin. Nothing
//! from the tarball runs until both checks pass.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::targets::TARGETS;
use crate::util::{
    Result, copy_file, fresh_dir, private_dir, run_logged, sha256_file, with_suffix, workspace_root,
};

const RELEASES: &str = "https://github.com/openssl/openssl/releases/download";

/// Primary key of OpenSSL's release-signing certificate: the trust anchor published at
/// <https://openssl-library.org/source/>. Releases are signed by a subkey it certifies.
const TRUST_ANCHOR: &str = "B146647E45A7B33947AB226B2A2C87D161692D40";

/// OpenSSL's signing certificates, copied from <https://openssl-library.org/source/pubkeys.asc>.
const PUBKEYS: &str = "xtask/keys/openssl-pubkeys.asc";

/// The one generated file that legitimately differs between the `Configure` targets in
/// [`TARGETS`] (for example, `RC4_INT` changes the size of `RC4_KEY`). It is installed as
/// `config/<target>/openssl/configuration.h`; the first target supplies every other file.
const PER_TARGET: &str = "include/openssl/configuration.h";

/// Single files to vendor, relative to the source root.
const FILES: &[&str] = &[
    "LICENSE.txt",
    "util/libcrypto.num",
    "util/libssl.num",
    "crypto/objects/objects.txt",
    "crypto/objects/obj_mac.num",
    "crypto/objects/obj_xref.txt",
    "crypto/err/openssl.txt",
];

/// Directories whose files with the given extension are vendored.
const DIRS: &[(&str, &str)] = &[
    ("include/openssl", "h"),
    ("doc/man3", "pod"),
    ("doc/man7", "pod"),
];

pub fn run(args: &[String]) -> Result {
    let [version] = args else {
        return Err("usage: cargo xtask vendor <version>   (for example: 3.5.9)".into());
    };
    let series = release_series(version)?;
    let root = workspace_root();
    let dest = root.join("abi").join(format!("openssl-{series}"));
    let work = root
        .join("target/xtask/vendor")
        .join(format!("openssl-{version}"));
    fresh_dir(&work)?;

    println!("Downloading OpenSSL {version}...");
    let tarball = download(version, &work)?;
    let sha256 = verify_checksum(&tarball)?;
    check_pin(&dest, version, &sha256)?;
    let signer = verify_signature(&root, &work, &tarball)?;
    println!("Verified SHA-256 {sha256}");
    println!("Verified signature by {signer} (trust anchor {TRUST_ANCHOR})");

    let mut trees = Vec::new();
    for target in TARGETS {
        println!("Generating headers for {}...", target.configure);
        trees.push(configure(&work, &tarball, version, target.configure)?);
    }
    let count = install(&trees, &dest)?;
    write_version_file(&dest, version, &sha256, &signer)?;
    fs::remove_dir_all(&work)?;
    let shown = dest.strip_prefix(&root).unwrap_or(&dest);
    println!("Vendored {count} files into {}", shown.display());
    Ok(())
}

/// `3.5.9` -> `3.5`. Rejects anything that isn't three numeric components.
fn release_series(version: &str) -> Result<String> {
    let parts: Vec<&str> = version.split('.').collect();
    let numeric = |p: &&str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit());
    match parts.as_slice() {
        [major, minor, patch] if [major, minor, patch].into_iter().all(numeric) => {
            Ok(format!("{major}.{minor}"))
        }
        _ => Err(format!("`{version}` is not a release version like 3.5.9").into()),
    }
}

/// Downloads the tarball, its signature, and its checksum. Returns the tarball's path.
fn download(version: &str, work: &Path) -> Result<PathBuf> {
    let tarball = format!("openssl-{version}.tar.gz");
    let log = work.join("download.log");
    for file in [
        tarball.clone(),
        format!("{tarball}.asc"),
        format!("{tarball}.sha256"),
    ] {
        let url = format!("{RELEASES}/openssl-{version}/{file}");
        let mut curl = Command::new("curl");
        curl.args(["--fail", "--silent", "--show-error", "--location"])
            .args(["--proto", "=https", "--tlsv1.2", "--output"])
            .arg(work.join(&file))
            .arg(&url);
        run_logged(&mut curl, &log).map_err(|e| format!("cannot download {url}: {e}"))?;
    }
    Ok(work.join(tarball))
}

/// Checks the tarball against the published `.sha256` file and returns its digest.
fn verify_checksum(tarball: &Path) -> Result<String> {
    let actual = sha256_file(tarball)?;
    let published = fs::read_to_string(with_suffix(tarball, ".sha256"))?;
    let expected = published
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if actual != expected {
        return Err(format!("SHA-256 mismatch: published {expected}, downloaded {actual}").into());
    }
    Ok(actual)
}

/// If this exact version was vendored before, its recorded SHA-256 must be unchanged. That
/// catches a release being replaced upstream after we pinned it.
fn check_pin(dest: &Path, version: &str, sha256: &str) -> Result {
    let Ok(previous) = fs::read_to_string(dest.join("VERSION.toml")) else {
        return Ok(());
    };
    if toml_value(&previous, "version") != Some(version) {
        return Ok(());
    }
    match toml_value(&previous, "sha256") {
        Some(pinned) if pinned != sha256 => Err(format!(
            "OpenSSL {version} was vendored with SHA-256 {pinned}, but the download is {sha256}"
        )
        .into()),
        _ => Ok(()),
    }
}

/// Verifies the detached signature with `gpgv` against OpenSSL's published keys, and returns
/// the fingerprint of the signing key. Only a good signature that chains to [`TRUST_ANCHOR`]
/// is accepted; other keys in the key file (expired or revoked ones) are not.
fn verify_signature(root: &Path, work: &Path, tarball: &Path) -> Result<String> {
    // A private GnuPG home keeps the user's own keyring and trust settings out of it.
    let home = work.join("gnupg");
    private_dir(&home)?;
    let keyring = work.join("openssl-keyring.gpg");
    let mut dearmor = Command::new("gpg");
    dearmor
        .arg("--homedir")
        .arg(&home)
        .args(["--batch", "--yes", "--dearmor", "--output"])
        .arg(&keyring)
        .arg(root.join(PUBKEYS));
    run_logged(&mut dearmor, &work.join("gpg.log"))?;

    let output = Command::new("gpgv")
        .arg("--homedir")
        .arg(&home)
        .arg("--keyring")
        .arg(&keyring)
        .args(["--status-fd", "1"])
        .arg(with_suffix(tarball, ".asc"))
        .arg(tarball)
        .output()
        .map_err(|e| format!("cannot run `gpgv`: {e}"))?;
    let status = String::from_utf8_lossy(&output.stdout);
    match signer_from_status(&status) {
        Some(signer) if output.status.success() => Ok(signer.to_owned()),
        _ => Err(format!(
            "no good signature chaining to {TRUST_ANCHOR}\n{status}{}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into()),
    }
}

/// Parses `gpgv --status-fd` output. Returns the signing key's fingerprint if there is a
/// `GOODSIG` (valid, unexpired, unrevoked) and a `VALIDSIG` whose primary key is the anchor.
fn signer_from_status(status: &str) -> Option<&str> {
    let good = status.lines().any(|l| l.starts_with("[GNUPG:] GOODSIG "));
    let signer = status
        .lines()
        .filter_map(|l| l.strip_prefix("[GNUPG:] VALIDSIG "))
        .find_map(|rest| {
            // VALIDSIG <signing key fpr> <date> ... <primary key fpr>
            let fields: Vec<&str> = rest.split_whitespace().collect();
            match (fields.first(), fields.last()) {
                (Some(key), Some(&primary)) if primary == TRUST_ANCHOR => Some(*key),
                _ => None,
            }
        });
    signer.filter(|_| good)
}

/// Extracts a fresh source tree for `target`, runs `Configure` with default options, and
/// generates the headers and man pages. Returns the source root.
fn configure(work: &Path, tarball: &Path, version: &str, target: &str) -> Result<PathBuf> {
    let dir = work.join(target);
    fs::create_dir_all(&dir)?;
    let log = work.join(format!("{target}.log"));
    let mut tar = Command::new("tar");
    tar.arg("-xzf").arg(tarball).arg("-C").arg(&dir);
    run_logged(&mut tar, &log)?;

    let src = dir.join(format!("openssl-{version}"));
    // A cleared environment keeps CC, CFLAGS, and the like from changing the configuration.
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut configure = Command::new("perl");
    configure
        .args(["Configure", target])
        .current_dir(&src)
        .env_clear()
        .env("PATH", &path);
    run_logged(&mut configure, &log)?;
    let mut make = Command::new("make");
    make.args(["build_generated", "build_generated_pods"])
        .current_dir(&src)
        .env_clear()
        .env("PATH", &path);
    run_logged(&mut make, &log)?;
    Ok(src)
}

/// Replaces `dest` with the vendored files and returns how many were written. Every file
/// except [`PER_TARGET`] must be byte-identical across targets; if that ever stops being
/// true, this fails instead of silently vendoring one target's copy.
fn install(trees: &[PathBuf], dest: &Path) -> Result<usize> {
    let [primary, others @ ..] = trees else {
        return Err("no targets were configured".into());
    };
    let mut files: Vec<String> = FILES.iter().map(|f| (*f).to_owned()).collect();
    for (dir, ext) in DIRS {
        let names = list_files(&primary.join(dir), ext)?;
        for other in others {
            if list_files(&other.join(dir), ext)? != names {
                return Err(format!("{dir} has different files for different targets").into());
            }
        }
        files.extend(names.into_iter().map(|name| format!("{dir}/{name}")));
    }
    files.retain(|f| f != PER_TARGET);
    for file in &files {
        let content = fs::read(primary.join(file))?;
        for other in others {
            if fs::read(other.join(file))? != content {
                return Err(format!(
                    "{file} differs between Configure targets; only {PER_TARGET} may"
                )
                .into());
            }
        }
    }

    if dest.exists() {
        fs::remove_dir_all(dest)?;
    }
    for file in &files {
        copy_file(&primary.join(file), &dest.join(file))?;
    }
    for (target, tree) in TARGETS.iter().zip(trees) {
        let to = dest
            .join("config")
            .join(target.configure)
            .join("openssl/configuration.h");
        copy_file(&tree.join(PER_TARGET), &to)?;
    }
    Ok(files.len() + trees.len())
}

/// Sorted names of the files in `dir` with extension `ext`.
fn list_files(dir: &Path, ext: &str) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_file()
            && path.extension().is_some_and(|e| e == ext)
            && let Some(name) = path.file_name().and_then(|n| n.to_str())
        {
            names.push(name.to_owned());
        }
    }
    names.sort();
    Ok(names)
}

fn write_version_file(dest: &Path, version: &str, sha256: &str, signer: &str) -> Result {
    let targets: Vec<String> = TARGETS
        .iter()
        .map(|t| format!("\"{}\"", t.configure))
        .collect();
    let targets = targets.join(", ");
    let text = format!(
        r#"# Generated by `cargo xtask vendor {version}`. Do not edit; re-run the command instead.
version = "{version}"
url = "{RELEASES}/openssl-{version}/openssl-{version}.tar.gz"
sha256 = "{sha256}"
# The subkey that signed the release, and the primary key it chains to.
signing-key = "{signer}"
trust-anchor = "{TRUST_ANCHOR}"
# Each target ran `perl Configure <target>` with no options in a cleared environment.
# Only include/openssl/configuration.h differs; it lives under config/<target>/.
configure-targets = [{targets}]
"#
    );
    fs::write(dest.join("VERSION.toml"), text)?;
    Ok(())
}

/// The string value of `key` in a flat TOML file written by [`write_version_file`].
fn toml_value<'a>(toml: &'a str, key: &str) -> Option<&'a str> {
    toml.lines().find_map(|line| {
        line.strip_prefix(key)?
            .trim_start()
            .strip_prefix('=')?
            .trim()
            .strip_prefix('"')?
            .strip_suffix('"')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_series_accepts_only_x_y_z() {
        assert_eq!(release_series("3.5.9").unwrap(), "3.5");
        assert_eq!(release_series("4.0.10").unwrap(), "4.0");
        for bad in [
            "3.5",
            "3.5.9.1",
            "3.5.x",
            "3..9",
            "",
            "openssl-3.5.9",
            "3.5.9-beta1",
        ] {
            assert!(release_series(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn toml_value_reads_exact_keys() {
        let toml = "# comment\nversion = \"3.5.9\"\nversions = \"x\"\nsha256 = \"ab\"\n";
        assert_eq!(toml_value(toml, "version"), Some("3.5.9"));
        assert_eq!(toml_value(toml, "sha256"), Some("ab"));
        assert_eq!(toml_value(toml, "url"), None);
    }

    const VALIDSIG: &str = "[GNUPG:] VALIDSIG C46ED3F2CBEFDA1FDAADA44264ED7B1DCCE71CB2 \
        2026-09-29 1790690724 0 4 0 1 10 00 B146647E45A7B33947AB226B2A2C87D161692D40";

    #[test]
    fn signer_requires_goodsig_and_the_anchor() {
        let good = format!("[GNUPG:] GOODSIG 64ED7B1DCCE71CB2 OpenSSL\n{VALIDSIG}\n");
        assert_eq!(
            signer_from_status(&good),
            Some("C46ED3F2CBEFDA1FDAADA44264ED7B1DCCE71CB2")
        );
        // A valid signature from an expired key is reported as EXPKEYSIG, not GOODSIG.
        let expired = format!("[GNUPG:] EXPKEYSIG 64ED7B1DCCE71CB2 OpenSSL\n{VALIDSIG}\n");
        assert_eq!(signer_from_status(&expired), None);
        // A good signature from some other primary key in the key file is not enough.
        let other = good.replace(TRUST_ANCHOR, "BA5473A2B0587B07FB27CF2D216094DFD0CB81EF");
        assert_eq!(signer_from_status(&other), None);
        assert_eq!(
            signer_from_status("[GNUPG:] BADSIG 64ED7B1DCCE71CB2 OpenSSL\n"),
            None
        );
    }
}
