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
//!   lib/ossl-modules/legacy.so              (macOS: legacy.dylib, a bundle) the legacy provider
//!   bin/openssl                             the `openssl` tool in Rust (crates/rustyssl-cli)
//! ```
//!
//! The Rust `openssl` tool replaced upstream's when Phase 11.1 was complete (ADR 0007, decision
//! 3); the drivers that need upstream's tool run the reference's, `target/ref/bin/openssl`. It
//! links neither library: it loads them at start-up, from `LD_LIBRARY_PATH`
//! (`DYLD_LIBRARY_PATH`) when set, else from `../lib` next to itself.
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
//!
//! libcrypto is linked from its whole archive. libssl, both shared and as `libssl.a`, is
//! built from the crate's forwarder objects alone, so it carries no second Rust runtime
//! (docs/adr/0001-library-layout.md). The legacy provider's module is `libs/legacy/legacy.c`,
//! compiled against the installed headers and linked against libcrypto, exporting only
//! `OSSL_provider_init` (docs/adr/0003-external-providers.md). Needs `ar` and `nm`; on Alpine,
//! `llvm-libunwind-dev`.

use std::collections::HashSet;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::codegen::exports::PRIVATE_PREFIX;
use crate::codegen::profiles::{self, Profile};
use crate::targets::{OPENSSL_SERIES, Target, host};
use crate::util::{
    Result, copy_file, fresh_dir, run_output, target_dir, toml_value, workspace_root,
};

pub fn run(args: &[String]) -> Result {
    let profile = match args {
        [] => None,
        [flag, name] if flag == "--profile" => Some(profiles::find(name)?),
        _ => return Err("usage: cargo xtask dist [--profile <name>]".into()),
    };
    let root = workspace_root();
    let (host, target) = host()?;
    if profile.is_some() && is_apple(target) {
        return Err("export profiles are for Linux distributions".into());
    }
    let abi = root.join("abi").join(format!("openssl-{OPENSSL_SERIES}"));
    let version_file = fs::read_to_string(abi.join("VERSION.toml"))?;
    let version = toml_value(&version_file, "version").ok_or("VERSION.toml has no version")?;
    let major = OPENSSL_SERIES
        .split('.')
        .next()
        .ok_or("bad OPENSSL_SERIES")?;

    let target_dir = target_dir(&root);
    let dist = target_dir.join("dist");
    fresh_dir(&dist)?;
    let lib_dir = dist.join("lib");
    fs::create_dir_all(lib_dir.join("pkgconfig"))?;

    let release = target_dir.join("release");
    let work = target_dir.join("xtask/dist");
    fresh_dir(&work)?;

    // libcrypto: the whole implementation, Rust runtime included.
    println!("Building libcrypto...");
    let native = build_archive(&root, "libcrypto", profile.map(|p| p.feature))?;
    let archive = release.join("libcrypto.a");
    let mut crypto = Shared::new(target, "libcrypto", major);
    let mut extra_objects = Vec::new();
    if let Some(profile) = profile {
        crypto.exports = format!(
            "libs/libcrypto/exports/{}-{}.map",
            target.configure, profile.name
        );
        if !profile.aliases.is_empty() {
            extra_objects.push(alias_object(target, profile, &work)?);
        }
    }
    println!("Linking {}...", crypto.file);
    let inputs = Inputs::Archive {
        archive: archive.clone(),
        native: native.clone(),
        extra: extra_objects,
    };
    link(&root, target, &crypto, &inputs, &lib_dir, major)?;
    symlink(&crypto.file, &lib_dir.join(&crypto.link))?;
    copy_file(&archive, &lib_dir.join("libcrypto.a"))?;

    // libssl: only the forwarders, so it carries no second copy of the Rust runtime, as a
    // shared library or as libssl.a next to libcrypto.a.
    println!("Building libssl...");
    build_archive(&root, "libssl", None)?;
    let ssl = Shared::new(target, "libssl", major);
    let objects = forwarder_objects(
        &release.join("libssl.a"),
        &root.join(&ssl.exports),
        target,
        &work,
    )?;
    println!("Linking {} from its forwarders...", ssl.file);
    link(
        &root,
        target,
        &ssl,
        &Inputs::Objects(objects.clone()),
        &lib_dir,
        major,
    )?;
    symlink(&ssl.file, &lib_dir.join(&ssl.link))?;
    run_output(
        Command::new("ar")
            .arg("rcs")
            .arg(lib_dir.join("libssl.a"))
            .args(&objects),
    )?;

    install_headers(&abi, target, &dist)?;
    println!("Linking the legacy provider's module...");
    link_legacy_module(&root, target, &dist, &lib_dir, major, &work)?;
    // What static users of libcrypto must link besides it (pkg-config --static).
    write_pkgconfig(&lib_dir.join("pkgconfig"), version, &native)?;
    println!("Building the openssl tool...");
    install_cli(&root, &release, &dist)?;
    println!(
        "Installed OpenSSL {version}-compatible libraries for {host} into {}",
        dist.display()
    );
    Ok(())
}

/// The name `cargo xtask dist` installs the Rust `openssl` tool under, in `bin/`.
pub const CLI_NAME: &str = "openssl";

/// Builds `rustyssl-cli` and installs its binary as `bin/openssl`.
///
/// On musl, Rust links executables statically by default, and a static musl program can't
/// `dlopen`, so the tool couldn't load the libraries: there it's linked dynamically. Only the
/// binary's own link changes (`cargo rustc`), not how its dependencies are built.
fn install_cli(root: &Path, release: &Path, dist: &Path) -> Result {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.args([
        "rustc",
        "--release",
        "--color",
        "never",
        "-p",
        "rustyssl-cli",
        "--bin",
        "openssl",
    ]);
    if cfg!(target_env = "musl") {
        cmd.args(["--", "-C", "target-feature=-crt-static"]);
    }
    run_output(cmd.current_dir(root))?;
    let bin = dist.join("bin");
    fs::create_dir_all(&bin)?;
    // fs::copy keeps the executable's permissions.
    copy_file(&release.join("openssl"), &bin.join(CLI_NAME))
}

/// Builds `rustyssl-<library>` as a release static archive and returns the system libraries
/// the archive needs, as rustc reports them.
fn build_archive(root: &Path, library: &str, feature: Option<&str>) -> Result<Vec<String>> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let package = format!("rustyssl-{library}");
    let mut cmd = Command::new(cargo);
    cmd.args(["rustc", "--release", "--color", "never", "-p", &package]);
    if let Some(feature) = feature {
        cmd.args(["--features", feature]);
    }
    let output = cmd
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

/// The legacy provider's module, `lib/ossl-modules/legacy.{so,dylib}`: OpenSSL's is a bundle
/// on macOS and a shared object elsewhere, linked against libcrypto, and exports
/// `OSSL_provider_init` (`providers.num`).
fn link_legacy_module(
    root: &Path,
    target: &Target,
    dist: &Path,
    lib_dir: &Path,
    major: &str,
    work: &Path,
) -> Result {
    let modules = lib_dir.join("ossl-modules");
    fs::create_dir_all(&modules)?;
    let cc = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let object = work.join("legacy.o");
    run_output(
        Command::new(&cc)
            .args(["-c", "-fPIC", "-O2", "-I"])
            .arg(dist.join("include"))
            .arg(root.join("libs/legacy/legacy.c"))
            .arg("-o")
            .arg(&object),
    )?;
    let mut cmd = Command::new(&cc);
    if is_apple(target) {
        let output = modules.join("legacy.dylib");
        cmd.arg("-bundle")
            .arg("-o")
            .arg(&output)
            .arg(&object)
            .arg("-Wl,-exported_symbol,_OSSL_provider_init")
            .arg(lib_dir.join(format!("libcrypto.{major}.dylib")));
    } else {
        let script = work.join("legacy.map");
        fs::write(
            &script,
            "{\n    global: OSSL_provider_init;\n    local: *;\n};\n",
        )?;
        cmd.arg("-shared")
            .arg("-o")
            .arg(modules.join("legacy.so"))
            .arg(&object)
            .arg(link_arg("--version-script=", &script))
            .arg("-L")
            .arg(lib_dir)
            .arg("-lcrypto");
    }
    run_output(&mut cmd)?;
    Ok(())
}

fn is_apple(target: &Target) -> bool {
    target.clang.contains("apple")
}

/// What a shared library is linked from.
enum Inputs {
    /// libcrypto: its whole static archive, plus the system libraries the archive needs.
    Archive {
        archive: PathBuf,
        native: Vec<String>,
        /// Objects linked beside it: a profile's version aliases.
        extra: Vec<PathBuf>,
    },
    /// libssl: the forwarder objects only, which need nothing but libcrypto.
    Objects(Vec<PathBuf>),
}

/// Links `shared`, exporting exactly the generated export list. libssl links against the
/// libcrypto already in `lib_dir`, so it records the dependency as OpenSSL's does.
fn link(
    root: &Path,
    target: &Target,
    shared: &Shared,
    inputs: &Inputs,
    lib_dir: &Path,
    major: &str,
) -> Result {
    let cc = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let output = lib_dir.join(&shared.file);
    let exports = root.join(&shared.exports);
    let mut cmd = Command::new(cc);
    if is_apple(target) {
        let version = format!("{major}.0.0");
        cmd.arg("-dynamiclib")
            .arg("-o")
            .arg(&output)
            .arg(link_arg("-exported_symbols_list,", &exports))
            .arg(link_arg("-install_name,", &output))
            .arg(format!("-Wl,-compatibility_version,{version}"))
            .arg(format!("-Wl,-current_version,{version}"))
            // Rust's std names libiconv, which nothing calls: drop dylibs no symbol comes
            // from, so the dependencies are OpenSSL's (abi-check, metadata).
            .args(["-Wl,-dead_strip", "-Wl,-dead_strip_dylibs", "-Wl,-S"]);
        match inputs {
            Inputs::Archive {
                archive, native, ..
            } => {
                cmd.arg(link_arg("-force_load,", archive));
                // cc links libSystem itself; listing it again only draws a warning.
                cmd.args(native.iter().filter(|l| *l != "-lSystem"));
            }
            Inputs::Objects(objects) => {
                cmd.args(objects)
                    .arg(lib_dir.join(format!("libcrypto.{major}.dylib")));
            }
        }
    } else {
        cmd.arg("-shared")
            .arg("-o")
            .arg(&output)
            .arg(format!("-Wl,-soname,{}", shared.file))
            .arg(link_arg("--version-script=", &exports))
            // Every name in the script must be defined, and so must everything referenced.
            .args(["-Wl,--no-undefined-version", "-Wl,--no-undefined"]);
        match inputs {
            Inputs::Archive { archive, extra, .. } => {
                cmd.args(extra)
                    .arg("-Wl,--whole-archive")
                    .arg(archive)
                    .arg("-Wl,--no-whole-archive");
            }
            Inputs::Objects(objects) => {
                cmd.args(objects)
                    .arg("-Wl,--no-as-needed")
                    .arg("-L")
                    .arg(lib_dir)
                    .arg("-lcrypto");
            }
        }
        cmd.args(["-Wl,--as-needed", "-Wl,--gc-sections", "-Wl,--strip-debug"])
            .args(["-Wl,-z,relro,-z,now", "-Wl,-z,noexecstack"]);
        if let Inputs::Archive { native, .. } = inputs {
            cmd.args(native);
        }
    }
    run_output(&mut cmd)?;
    Ok(())
}

/// Extracts the objects of the libssl crate that define its exports, and checks that they
/// reference nothing but libcrypto's private functions. The crate's static archive also holds
/// rustc's allocator shim and a copy of the standard library; leaving those out keeps a
/// second Rust runtime out of libssl, and out of programs that link libssl.a and libcrypto.a.
fn forwarder_objects(
    archive: &Path,
    exports: &Path,
    target: &Target,
    work: &Path,
) -> Result<Vec<PathBuf>> {
    let exported = export_names(exports, target)?;
    let dir = work.join("libssl-objects");
    fresh_dir(&dir)?;
    let members = run_output(Command::new("ar").arg("t").arg(archive))?;
    let own: Vec<&str> = members.lines().filter(|m| m.starts_with("ssl-")).collect();
    run_output(
        Command::new("ar")
            .arg("x")
            .arg(archive)
            .args(&own)
            .current_dir(&dir),
    )?;
    let mut kept = Vec::new();
    let mut defined = HashSet::new();
    for member in own {
        let path = dir.join(member);
        let symbols = symbols(&path, target)?;
        if !symbols
            .iter()
            .any(|(d, name)| *d && exported.contains(name))
        {
            continue; // the allocator shim
        }
        let foreign: Vec<&String> = symbols
            .iter()
            .filter(|(d, name)| !*d && !name.starts_with(PRIVATE_PREFIX))
            .map(|(_, name)| name)
            .collect();
        if !foreign.is_empty() {
            return Err(format!(
                "libssl's forwarders must only call libcrypto's {PRIVATE_PREFIX}* functions, \
                 but {member} also references {foreign:?}"
            )
            .into());
        }
        defined.extend(symbols.into_iter().filter(|(d, _)| *d).map(|(_, n)| n));
        kept.push(path);
    }
    let missing: Vec<&String> = exported.iter().filter(|n| !defined.contains(*n)).collect();
    if !missing.is_empty() {
        return Err(format!("no forwarder defines {missing:?}").into());
    }
    Ok(kept)
}

/// The names in a generated export list (without Mach-O's leading underscore).
fn export_names(path: &Path, target: &Target) -> Result<HashSet<String>> {
    let text = fs::read_to_string(path)?;
    let mut names = HashSet::new();
    for line in text.lines().map(str::trim) {
        let name = if is_apple(target) {
            line.strip_prefix('_')
        } else {
            line.strip_suffix(';')
        };
        if let Some(name) = name
            && !name.is_empty()
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            names.insert(name.to_owned());
        }
    }
    Ok(names)
}

/// The global symbols of an object file as (defined, name), from `nm -g`.
pub fn symbols(object: &Path, target: &Target) -> Result<Vec<(bool, String)>> {
    let listing = run_output(Command::new("nm").arg("-g").arg(object))?;
    let mut symbols = Vec::new();
    for line in listing.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (kind, name) = match fields.as_slice() {
            [kind, name] | [_, kind, name] => (*kind, *name),
            _ => continue,
        };
        let name = if is_apple(target) {
            name.strip_prefix('_').unwrap_or(name)
        } else {
            name
        };
        symbols.push((kind != "U", name.to_owned()));
    }
    Ok(symbols)
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
         Name: OpenSSL-libcrypto\nDescription: OpenSSL cryptography library (rustyssl)\n\
         Version: {version}\nLibs: -L${{libdir}} -lcrypto\nLibs.private: {}\n\
         Cflags: -I${{includedir}}",
        private_libs.join(" ")
    )?;
    let mut libssl = String::from(header);
    writeln!(
        libssl,
        "\nName: OpenSSL-libssl\nDescription: Secure Sockets Layer and cryptography libraries \
         (rustyssl)\nVersion: {version}\nRequires.private: libcrypto\n\
         Libs: -L${{libdir}} -lssl\nCflags: -I${{includedir}}"
    )?;
    let mut openssl = String::from(header);
    writeln!(
        openssl,
        "\nName: OpenSSL\nDescription: Secure Sockets Layer and cryptography libraries and \
         tools (rustyssl)\nVersion: {version}\nRequires: libssl libcrypto"
    )?;
    fs::write(dir.join("libcrypto.pc"), libcrypto)?;
    fs::write(dir.join("libssl.pc"), libssl)?;
    fs::write(dir.join("openssl.pc"), openssl)?;
    Ok(())
}

/// Assembles a profile's version aliases: for each `(name, node)`, a local entry point that
/// jumps to `name` (its default version), given the extra version `name@node` with `.symver`.
/// A jump keeps every argument and return value as they are, whatever the prototype.
fn alias_object(target: &Target, profile: &Profile, work: &Path) -> Result<PathBuf> {
    let jump = match target.configure {
        "linux-x86_64" => "jmp {name}@PLT",
        "linux-aarch64" => "b {name}",
        other => return Err(format!("no alias assembly for {other}").into()),
    };
    let mut asm = String::from(".text\n");
    for (name, node) in profile.aliases {
        let local = format!("rustyssl_{}_{name}", profile.name);
        writeln!(
            asm,
            ".globl {local}\n.type {local}, @function\n{local}:\n    {}\n\
             .size {local}, .-{local}\n.symver {local}, {name}@{node}",
            jump.replace("{name}", name)
        )?;
    }
    asm.push_str(".section .note.GNU-stack,\"\",@progbits\n");
    let source = work.join(format!("{}-aliases.s", profile.name));
    let object = work.join(format!("{}-aliases.o", profile.name));
    fs::write(&source, asm)?;
    let cc = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    run_output(
        Command::new(cc)
            .args(["-c", "-fPIC"])
            .arg(&source)
            .arg("-o")
            .arg(&object),
    )?;
    Ok(object)
}
