//! `cargo xtask dist`: builds both libraries for the host and lays out an OpenSSL-style install
//! tree in `target/dist/` (step 0.5 of the implementation plan):
//!
//! ```text
//! target/dist/
//!   include/openssl/*.h                     the vendored headers, with the host's configuration.h
//!   lib/libcrypto.so.3, lib/libssl.so.3     (macOS: libcrypto.3.dylib, libssl.3.dylib)
//!   lib/libcrypto.so -> libcrypto.so.3      (and the same for libssl)
//!   lib/libcrypto.a, lib/libssl.a
//!   lib/pkgconfig/{libcrypto,libssl,openssl}.pc
//! ```
//!
//! Cargo builds each library as a static archive, and this links the shared library from it
//! with the C compiler (`$CC`, default `cc`). rustc gives every cdylib its own anonymous
//! version script, and GNU ld refuses to combine that with OpenSSL's named version nodes
//! ("anonymous version tag cannot be combined with other version tags"), so the shared
//! libraries can't come from Cargo directly.
//!
//! The libraries match OpenSSL's: on Linux the soname is `lib<name>.so.<major>` and every
//! export keeps its OpenSSL version node; on macOS the compatibility and current versions are
//! `<major>.0.0`, as in OpenSSL's own dylibs. libssl depends on libcrypto either way.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::targets::{OPENSSL_SERIES, TARGETS, Target};
use crate::util::{Result, copy_file, fresh_dir, run_output, toml_value, workspace_root};

const LIBRARIES: &[&str] = &["libcrypto", "libssl"];

pub fn run(args: &[String]) -> Result {
    if !args.is_empty() {
        return Err("usage: cargo xtask dist".into());
    }
    let root = workspace_root();
    let host = host_triple()?;
    let target = TARGETS
        .iter()
        .find(|t| t.rust == host)
        .ok_or_else(|| format!("no rustssl target for host {host}; see xtask/src/targets.rs"))?;
    let abi = root.join("abi").join(format!("openssl-{OPENSSL_SERIES}"));
    let version_file = fs::read_to_string(abi.join("VERSION.toml"))?;
    let version = toml_value(&version_file, "version").ok_or("VERSION.toml has no version")?;
    let major = OPENSSL_SERIES
        .split('.')
        .next()
        .ok_or("bad OPENSSL_SERIES")?;

    let target_dir =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from);
    let dist = target_dir.join("dist");
    fresh_dir(&dist)?;
    let lib_dir = dist.join("lib");
    fs::create_dir_all(lib_dir.join("pkgconfig"))?;

    let mut private_libs = Vec::new();
    for library in LIBRARIES {
        println!("Building {library}...");
        let native = build_archive(&root, library)?;
        let archive = target_dir.join("release").join(format!("{library}.a"));
        let shared = Shared::new(target, library, major);
        println!("Linking {}...", shared.file);
        link(&root, target, &shared, &archive, &native, &lib_dir, major)?;
        symlink(&shared.file, &lib_dir.join(&shared.link))?;
        copy_file(&archive, &lib_dir.join(format!("{library}.a")))?;
        if *library == "libcrypto" {
            // What static users of libcrypto must link besides it (pkg-config --static).
            private_libs = native;
        }
    }

    install_headers(&abi, target, &dist)?;
    write_pkgconfig(&lib_dir.join("pkgconfig"), version, &private_libs)?;
    println!(
        "Installed OpenSSL {version}-compatible libraries for {host} into {}",
        dist.display()
    );
    Ok(())
}

fn host_triple() -> Result<String> {
    let info = run_output(Command::new("rustc").arg("-vV"))?;
    info.lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(str::to_owned)
        .ok_or_else(|| "rustc -vV printed no host".into())
}

/// Builds `rustssl-<library>` as a release static archive and returns the system libraries
/// the archive needs, as rustc reports them.
fn build_archive(root: &Path, library: &str) -> Result<Vec<String>> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let package = format!("rustssl-{library}");
    let output = Command::new(cargo)
        .args(["rustc", "--release", "--color", "never", "-p", &package])
        .args(["--", "--print", "native-static-libs"])
        .current_dir(root)
        .output()
        .map_err(|e| format!("cannot run cargo: {e}"))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        return Err(format!("building {package} failed:\n{stderr}").into());
    }
    let libs = stderr
        .lines()
        .find_map(|line| line.split_once("native-static-libs: "))
        .map(|(_, libs)| libs)
        .ok_or_else(|| format!("cargo didn't report the native libraries of {package}"))?;
    Ok(libs.split_whitespace().map(str::to_owned).collect())
}

/// File names of one shared library.
struct Shared {
    /// `libcrypto.so.3` or `libcrypto.3.dylib`.
    file: String,
    /// The development symlink: `libcrypto.so` or `libcrypto.dylib`.
    link: String,
    /// Where the export list or version script comes from.
    exports: String,
}

impl Shared {
    fn new(target: &Target, library: &str, major: &str) -> Self {
        if is_apple(target) {
            Self {
                file: format!("{library}.{major}.dylib"),
                link: format!("{library}.dylib"),
                exports: format!("libs/{library}/exports/{}.exports", target.configure),
            }
        } else {
            Self {
                file: format!("{library}.so.{major}"),
                link: format!("{library}.so"),
                exports: format!("libs/{library}/exports/{}.map", target.configure),
            }
        }
    }
}

fn is_apple(target: &Target) -> bool {
    target.clang.contains("apple")
}

/// Links `shared` from `archive`, exporting exactly the generated export list. libssl links
/// against the libcrypto already in `lib_dir`, so it records the dependency as OpenSSL's does.
fn link(
    root: &Path,
    target: &Target,
    shared: &Shared,
    archive: &Path,
    native: &[String],
    lib_dir: &Path,
    major: &str,
) -> Result {
    let cc = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let output = lib_dir.join(&shared.file);
    let exports = root.join(&shared.exports);
    let is_libssl = shared.file.starts_with("libssl");
    let mut cmd = Command::new(cc);
    if is_apple(target) {
        let version = format!("{major}.0.0");
        cmd.arg("-dynamiclib")
            .arg("-o")
            .arg(&output)
            .arg(link_arg("-force_load,", archive))
            .arg(link_arg("-exported_symbols_list,", &exports))
            .arg(link_arg("-install_name,", &output))
            .arg(format!("-Wl,-compatibility_version,{version}"))
            .arg(format!("-Wl,-current_version,{version}"))
            .args(["-Wl,-dead_strip", "-Wl,-S"]);
        if is_libssl {
            cmd.arg(lib_dir.join(format!("libcrypto.{major}.dylib")));
        }
        // cc links libSystem itself; listing it again only draws a warning.
        cmd.args(native.iter().filter(|l| *l != "-lSystem"));
    } else {
        cmd.arg("-shared")
            .arg("-o")
            .arg(&output)
            .arg(format!("-Wl,-soname,{}", shared.file))
            .arg(link_arg("--version-script=", &exports))
            // Every name in the script must be defined, and so must everything referenced.
            .args(["-Wl,--no-undefined-version", "-Wl,--no-undefined"])
            .arg("-Wl,--whole-archive")
            .arg(archive)
            .arg("-Wl,--no-whole-archive");
        if is_libssl {
            cmd.arg("-Wl,--no-as-needed")
                .arg("-L")
                .arg(lib_dir)
                .arg("-lcrypto");
        }
        cmd.args(["-Wl,--as-needed", "-Wl,--gc-sections", "-Wl,--strip-debug"])
            .args(["-Wl,-z,relro,-z,now", "-Wl,-z,noexecstack"])
            .args(native);
    }
    run_output(&mut cmd)?;
    Ok(())
}

/// `-Wl,<option><path>`.
fn link_arg(option: &str, path: &Path) -> OsString {
    let mut arg = OsString::from("-Wl,");
    arg.push(option);
    arg.push(path);
    arg
}

#[cfg(unix)]
fn symlink(original: &str, link: &Path) -> Result {
    std::os::unix::fs::symlink(original, link)?;
    Ok(())
}

#[cfg(not(unix))]
fn symlink(_original: &str, _link: &Path) -> Result {
    Err("cargo xtask dist supports Linux and macOS only".into())
}

/// Installs the public headers, with the target's own `configuration.h`.
fn install_headers(abi: &Path, target: &Target, dist: &Path) -> Result {
    let to = dist.join("include/openssl");
    for entry in fs::read_dir(abi.join("include/openssl"))? {
        let path = entry?.path();
        if let Some(name) = path.file_name() {
            copy_file(&path, &to.join(name))?;
        }
    }
    let config = abi
        .join("config")
        .join(target.configure)
        .join("openssl/configuration.h");
    copy_file(&config, &to.join("configuration.h"))
}

/// Writes pkg-config files laid out like OpenSSL's. `${pcfiledir}` keeps the tree relocatable.
fn write_pkgconfig(dir: &Path, version: &str, private_libs: &[String]) -> Result {
    let header = "prefix=${pcfiledir}/../..\nexec_prefix=${prefix}\nlibdir=${exec_prefix}/lib\n\
                  includedir=${prefix}/include\n";
    let mut libcrypto = String::from(header);
    writeln!(
        libcrypto,
        "enginesdir=${{libdir}}/engines-3\nmodulesdir=${{libdir}}/ossl-modules\n\n\
         Name: OpenSSL-libcrypto\nDescription: OpenSSL cryptography library (rustssl)\n\
         Version: {version}\nLibs: -L${{libdir}} -lcrypto\nLibs.private: {}\n\
         Cflags: -I${{includedir}}",
        private_libs.join(" ")
    )?;
    let mut libssl = String::from(header);
    writeln!(
        libssl,
        "\nName: OpenSSL-libssl\nDescription: Secure Sockets Layer and cryptography libraries \
         (rustssl)\nVersion: {version}\nRequires.private: libcrypto\n\
         Libs: -L${{libdir}} -lssl\nCflags: -I${{includedir}}"
    )?;
    let mut openssl = String::from(header);
    writeln!(
        openssl,
        "\nName: OpenSSL\nDescription: Secure Sockets Layer and cryptography libraries and \
         tools (rustssl)\nVersion: {version}\nRequires: libssl libcrypto"
    )?;
    fs::write(dir.join("libcrypto.pc"), libcrypto)?;
    fs::write(dir.join("libssl.pc"), libssl)?;
    fs::write(dir.join("openssl.pc"), openssl)?;
    Ok(())
}
