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
    Result, copy_file, fresh_dir, private_dir, run_logged, run_output, sha256_file, target_dir,
    toml_value, with_suffix, workspace_root,
};

const RELEASES: &str = "https://github.com/openssl/openssl/releases/download";

/// Primary key of OpenSSL's release-signing certificate: the trust anchor published at
/// <https://openssl-library.org/source/>. Releases are signed by a subkey it certifies.
const TRUST_ANCHOR: &str = "B146647E45A7B33947AB226B2A2C87D161692D40";

/// OpenSSL's signing certificates, copied from <https://openssl-library.org/source/pubkeys.asc>.
const PUBKEYS: &str = "xtask/keys/openssl-pubkeys.asc";

/// Generated files that legitimately differ between the `Configure` targets in [`TARGETS`],
/// with their install path under `config/<target>/`. `configuration.h` differs (for example,
/// `RC4_INT` changes the size of `RC4_KEY`), and so may the export lists that `util/mkdef.pl`
/// resolves from each target's configuration. The first target supplies every other file.
const PER_TARGET: &[(&str, &str)] = &[
    ("include/openssl/configuration.h", "openssl/configuration.h"),
    ("libcrypto.ld", "libcrypto.ld"),
    ("libssl.ld", "libssl.ld"),
    ("build.toml", "build.toml"),
];

/// Options given to `Configure` on top of OpenSSL's defaults, so the ABI matches what the
/// major distributions ship. `enable-ec_nistp_64_gcc_128` adds the 64-bit NIST P-224, P-256,
/// and P-521 code and its exports `EC_GFp_nistp{224,256,521}_method`. Debian and Homebrew
/// enable it, so binaries built there may call those functions. It needs a 64-bit target
/// with `__uint128_t`, which every target in [`TARGETS`] is.
pub const CONFIGURE_OPTIONS: &[&str] = &["enable-ec_nistp_64_gcc_128"];

/// Single files to vendor, relative to the source root.
const FILES: &[&str] = &[
    "LICENSE.txt",
    "util/libcrypto.num",
    "util/libssl.num",
    "crypto/objects/objects.txt",
    "crypto/objects/obj_mac.num",
    "crypto/objects/obj_xref.txt",
    "crypto/err/openssl.txt",
    // The order in which OpenSSL loads libcrypto's error strings (`ossl_err_load_crypto_strings`).
    "crypto/err/err_all.c",
    // The named curves' parameters, names, and comments (`EC_get_builtin_curves`), which
    // codegen turns into rustyssl's curve table.
    "crypto/ec/ec_curve.c",
    // The curves' names and NIST names (`OSSL_EC_curve_nid2name`, `EC_curve_nid2nist`).
    "crypto/evp/ec_support.c",
    // The verification errors' text (`X509_verify_cert_error_string`), which codegen turns
    // into rustyssl's table.
    "crypto/x509/x509_txt.c",
    // Internal headers that declare functions libcrypto exports all the same (DSO_*,
    // conf_ssl_*, OPENSSL_DIR_*, ...). Codegen fails if an export has no prototype.
    "include/internal/asn1.h",
    "include/internal/dso.h",
    "include/internal/dsoerr.h",
    "include/internal/err.h",
    "include/internal/o_dir.h",
    "include/internal/sslconf.h",
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
    let work = target_dir(&root)
        .join("xtask/vendor")
        .join(format!("openssl-{version}"));
    fresh_dir(&work)?;
    let Release {
        tarball,
        sha256,
        signer,
    } = fetch_verified(&root, version, &work)?;

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

/// A downloaded OpenSSL release tarball that passed every check in the module docs.
pub struct Release {
    pub tarball: PathBuf,
    pub sha256: String,
    pub signer: String,
}

/// Downloads OpenSSL `version` into `work` and verifies it: the published SHA-256, any pin
/// recorded in `abi/openssl-<series>/VERSION.toml`, and a signature chaining to
/// [`TRUST_ANCHOR`]. Nothing from the tarball should be used before this returns.
pub fn fetch_verified(root: &Path, version: &str, work: &Path) -> Result<Release> {
    let series = release_series(version)?;
    let pinned = root.join("abi").join(format!("openssl-{series}"));
    println!("Downloading OpenSSL {version}...");
    let tarball = download(version, work)?;
    let sha256 = verify_checksum(&tarball)?;
    check_pin(&pinned, version, &sha256)?;
    let signer = verify_signature(root, work, &tarball)?;
    println!("Verified SHA-256 {sha256}");
    println!("Verified signature by {signer} (trust anchor {TRUST_ANCHOR})");
    Ok(Release {
        tarball,
        sha256,
        signer,
    })
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
        .args(CONFIGURE_OPTIONS)
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

    // The export lists, from OpenSSL's own resolver, invoked as the Linux Makefile does. Its
    // `linux` writer handles every UNIX target, macOS included (whose build has no list).
    for lib in ["libcrypto", "libssl"] {
        let mut mkdef = Command::new("perl");
        mkdef
            .arg("util/mkdef.pl")
            .args(["--version", version, "--type", "lib", "--ordinals"])
            .arg(format!("util/{lib}.num"))
            .args(["--name", lib, "--OS", "linux"])
            .current_dir(&src)
            .env_clear()
            .env("PATH", &path);
        fs::write(src.join(format!("{lib}.ld")), run_output(&mut mkdef)?)?;
    }
    fs::write(src.join("build.toml"), build_settings(&src)?)?;
    Ok(src)
}

/// The settings OpenSSL compiles into the library for a target (`-DOPENSSLDIR=...` and the
/// like), resolved from its Makefile and `dso_conf.h`, as TOML. `OpenSSL_version` and
/// `OPENSSL_info` report them.
fn build_settings(src: &Path) -> Result<String> {
    let makefile = fs::read_to_string(src.join("Makefile"))?;
    let mut variables = std::collections::HashMap::new();
    for line in makefile.lines() {
        if let Some((name, value)) = line.split_once('=')
            && !name.is_empty()
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            variables.entry(name).or_insert(value);
        }
    }
    let resolve = |name: &str| -> Result<String> {
        let mut value = (*variables
            .get(name)
            .ok_or(format!("the Makefile has no {name}"))?)
        .to_owned();
        // Expand `$(NAME)` references, which only ever nest a few deep.
        for _ in 0..8 {
            let Some((before, rest)) = value.split_once("$(") else {
                return Ok(value);
            };
            let (inner, after) = rest
                .split_once(')')
                .ok_or("unterminated $( in the Makefile")?;
            let inner = variables
                .get(inner)
                .ok_or(format!("the Makefile has no {inner}"))?;
            value = format!("{before}{inner}{after}");
        }
        Err(format!("{name} doesn't resolve").into())
    };
    let dso_conf = fs::read_to_string(src.join("include/crypto/dso_conf.h"))?;
    let extension = dso_conf
        .lines()
        .find_map(|line| {
            line.split_once("define DSO_EXTENSION ")?
                .1
                .trim()
                .strip_prefix('"')?
                .strip_suffix('"')
        })
        .ok_or("dso_conf.h defines no DSO_EXTENSION")?;
    Ok(format!(
        "# What OpenSSL's build compiles in for this target, resolved from its Makefile.\n\
         platform = \"{}\"\nopenssldir = \"{}\"\nenginesdir = \"{}\"\nmodulesdir = \"{}\"\n\
         dso_extension = \"{extension}\"\n",
        resolve("PLATFORM")?,
        resolve("OPENSSLDIR")?,
        resolve("ENGINESDIR")?,
        resolve("MODULESDIR")?,
    ))
}

/// Replaces `dest` with the vendored files and returns how many were written. Every file
/// except the [`PER_TARGET`] ones must be byte-identical across targets; if that ever stops
/// being true, this fails instead of silently vendoring one target's copy.
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
    files.extend(error_tables(primary)?);
    files.retain(|f| !PER_TARGET.iter().any(|(from, _)| f == from));
    for file in &files {
        let content = fs::read(primary.join(file))?;
        for other in others {
            if fs::read(other.join(file))? != content {
                return Err(format!(
                    "{file} differs between Configure targets; only the files in PER_TARGET may"
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
        for (from, to) in PER_TARGET {
            let config = dest.join("config").join(target.configure);
            copy_file(&tree.join(from), &config.join(to))?;
        }
    }
    Ok(files.len() + trees.len() * PER_TARGET.len())
}

/// The C sources that define error-string tables (`static const ERR_STRING_DATA x[] = {`),
/// relative to `src`. Their strings are what OpenSSL prints at run time, and a few differ from
/// `crypto/err/openssl.txt`; `err.c` also holds the library names and common reasons.
fn error_tables(src: &Path) -> Result<Vec<String>> {
    let mut found = Vec::new();
    let mut dirs: Vec<PathBuf> = ["crypto", "ssl", "providers"]
        .iter()
        .map(|d| src.join(d))
        .collect();
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|e| e == "c") {
                let text = fs::read_to_string(&path)?;
                let defines_table = text
                    .lines()
                    .any(|l| l.contains("ERR_STRING_DATA ") && l.contains("[] = {"));
                if defines_table && let Ok(relative) = path.strip_prefix(src) {
                    found.push(relative.display().to_string());
                }
            }
        }
    }
    found.sort();
    Ok(found)
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
    let options: Vec<String> = CONFIGURE_OPTIONS
        .iter()
        .map(|o| format!("\"{o}\""))
        .collect();
    let options = options.join(", ");
    let text = format!(
        r#"# Generated by `cargo xtask vendor {version}`. Do not edit; re-run the command instead.
version = "{version}"
url = "{RELEASES}/openssl-{version}/openssl-{version}.tar.gz"
sha256 = "{sha256}"
# The subkey that signed the release, and the primary key it chains to.
signing-key = "{signer}"
trust-anchor = "{TRUST_ANCHOR}"
# Each target ran `perl Configure <target> <options>` in a cleared environment: OpenSSL's
# defaults plus the options below, which the major distributions also enable.
# config/<target>/ holds the files that differ: configuration.h, and the export lists
# libcrypto.ld and libssl.ld written by util/mkdef.pl.
configure-targets = [{targets}]
configure-options = [{options}]
"#
    );
    fs::write(dest.join("VERSION.toml"), text)?;
    Ok(())
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
