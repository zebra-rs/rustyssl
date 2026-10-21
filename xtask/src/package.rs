//! `cargo xtask package <layout> [--prefix DIR] [--openssldir DIR]` (step 12.3): builds rustyssl
//! for a distribution's layout and stages an install tree and a tarball of it in
//! `target/package/`:
//!
//! ```text
//! target/package/<layout>/root/...                      the tree, rooted at /
//! target/package/rustyssl-<version>-<layout>-<arch>.tar.gz
//! ```
//!
//! The libraries go **side by side** with the system's OpenSSL, in a private directory
//! `<libdir>/rustyssl/`: the shared libraries and their development links and archives,
//! `ossl-modules/legacy.so` (MODULESDIR), `engines-3/` (ENGINESDIR), `bin/openssl`, `include/`,
//! and `pkgconfig/`. OPENSSLDIR is the system's, so rustyssl reads the distribution's own
//! `openssl.cnf` (and Fedora's crypto policies). Nothing the system's packages own is
//! touched: `<libdir>/rustyssl/bin/rustyssl-select` switches between the system's OpenSSL and
//! rustyssl (the alternatives mechanism, docs/MIGRATION.md). The tree has no file in the
//! system's own directories (`/usr/sbin` is a symlink on Fedora 42 and later, and extracting a
//! directory over it would replace it): extract the tarball with GNU tar's
//! `--keep-directory-symlink`.
//!
//! | Layout | libdir | OPENSSLDIR | Profile |
//! |---|---|---|---|
//! | `debian` (Debian, Ubuntu) | `/usr/lib/<arch>-linux-gnu` | `/usr/lib/ssl` | |
//! | `fedora` | `/usr/lib64` | `/etc/pki/tls` | `fedora` |
//! | `el` (RHEL 10 and its rebuilds) | `/usr/lib64` | `/etc/pki/tls` | `fedora` |
//! | `alpine` (musl) | `/usr/lib` | `/etc/ssl` | |
//! | `homebrew` | `<prefix>/lib` | `<prefix>/etc/rustyssl` | |
//!
//! `homebrew` is a keg of its own (`--prefix`, the formula's `#{prefix}`), with the libraries in
//! `lib/` under their final install names; there's no switch, a program uses it through its
//! install names or `DYLD_LIBRARY_PATH`. The directories rustyssl reports and reads are
//! compiled in through `RUSTYSSL_OPENSSLDIR`, `RUSTYSSL_ENGINESDIR`, and `RUSTYSSL_MODULESDIR`.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::targets::{OPENSSL_SERIES, host};
use crate::util::{
    Result, copy_file, fresh_dir, run_output, target_dir, toml_value, workspace_root,
};

/// A distribution's directories, all absolute.
struct Layout {
    name: String,
    /// `/usr`, or the keg.
    prefix: String,
    /// The system's library directory.
    libdir: String,
    /// rustyssl's own directory: `<libdir>/rustyssl`, or the keg.
    home: String,
    openssldir: String,
    /// `cargo xtask dist --profile`.
    profile: Option<&'static str>,
    /// The C library's loader: how `rustyssl-select` puts `home` first.
    loader: Loader,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Loader {
    /// glibc: a drop-in in `/etc/ld.so.conf.d`, read in name order, then `ldconfig`.
    Glibc,
    /// musl: `/etc/ld-musl-<arch>.path`.
    Musl,
    /// macOS: install names; no switch.
    Apple,
}

const LAYOUTS: &[&str] = &["debian", "fedora", "el", "alpine", "homebrew"];

fn layout(
    name: &str,
    prefix: Option<&str>,
    openssldir: Option<&str>,
    arch: &str,
) -> Result<Layout> {
    let usr = prefix.unwrap_or("/usr").to_owned();
    let (libdir, system_openssldir, profile, loader) = match name {
        "debian" => (
            format!("{usr}/lib/{arch}-linux-gnu"),
            "/usr/lib/ssl".to_owned(),
            None,
            Loader::Glibc,
        ),
        "fedora" | "el" => (
            format!("{usr}/lib64"),
            "/etc/pki/tls".to_owned(),
            Some("fedora"),
            Loader::Glibc,
        ),
        "alpine" => (
            format!("{usr}/lib"),
            "/etc/ssl".to_owned(),
            None,
            Loader::Musl,
        ),
        "homebrew" => {
            let Some(keg) = prefix else {
                return Err("the homebrew layout needs --prefix (the formula's #{prefix})".into());
            };
            (
                format!("{keg}/lib"),
                format!("{keg}/etc/rustyssl"),
                None,
                Loader::Apple,
            )
        }
        other => {
            return Err(format!("unknown layout `{other}` (known: {})", LAYOUTS.join(", ")).into());
        }
    };
    let home = if loader == Loader::Apple {
        usr.clone()
    } else {
        format!("{libdir}/rustyssl")
    };
    Ok(Layout {
        name: name.to_owned(),
        prefix: usr,
        libdir,
        home,
        openssldir: openssldir.map_or(system_openssldir, str::to_owned),
        profile,
        loader,
    })
}

impl Layout {
    /// Where the libraries go: rustyssl's directory, or the keg's `lib`.
    fn lib(&self) -> String {
        if self.loader == Loader::Apple {
            self.libdir.clone()
        } else {
            self.home.clone()
        }
    }

    fn modulesdir(&self) -> String {
        format!("{}/ossl-modules", self.lib())
    }

    fn enginesdir(&self) -> String {
        format!("{}/engines-3", self.lib())
    }
}

pub fn run(args: &[String]) -> Result {
    let usage = "usage: cargo xtask package <debian|fedora|el|alpine|homebrew> [--prefix DIR] \
                 [--openssldir DIR]";
    let (name, rest) = args.split_first().ok_or(usage)?;
    let (mut prefix, mut openssldir) = (None, None);
    let mut options = rest.iter();
    while let Some(option) = options.next() {
        let value = options.next().ok_or(usage)?;
        match option.as_str() {
            "--prefix" => prefix = Some(value.as_str()),
            "--openssldir" => openssldir = Some(value.as_str()),
            _ => return Err(usage.into()),
        }
    }
    let (_, target) = host()?;
    let apple = target.clang.contains("apple");
    if apple != (name == "homebrew") {
        return Err(format!(
            "the {name} layout is built on {}",
            if apple { "Linux" } else { "macOS" }
        )
        .into());
    }
    let arch = target.clang.split('-').next().unwrap_or("x86_64");
    let layout = layout(name, prefix, openssldir, arch)?;

    // The directories are compiled in, from the environment `cargo xtask dist` builds with.
    let root = workspace_root();
    let mut dist = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    dist.args(["xtask", "dist"]).current_dir(&root);
    if let Some(profile) = layout.profile {
        dist.args(["--profile", profile]);
    }
    dist.env("RUSTYSSL_OPENSSLDIR", &layout.openssldir)
        .env("RUSTYSSL_ENGINESDIR", layout.enginesdir())
        .env("RUSTYSSL_MODULESDIR", layout.modulesdir());
    let status = dist
        .status()
        .map_err(|e| format!("cannot run cargo xtask dist: {e}"))?;
    if !status.success() {
        return Err("cargo xtask dist failed".into());
    }

    let version_file = fs::read_to_string(
        root.join("abi")
            .join(format!("openssl-{OPENSSL_SERIES}"))
            .join("VERSION.toml"),
    )?;
    let version = toml_value(&version_file, "version").ok_or("VERSION.toml has no version")?;
    let out = target_dir(&root).join("package");
    let stage = out.join(&layout.name).join("root");
    fresh_dir(&stage)?;
    stage_tree(
        &root,
        &target_dir(&root).join("dist"),
        &stage,
        &layout,
        apple,
    )?;
    let tarball = out.join(format!("rustyssl-{version}-{}-{arch}.tar.gz", layout.name));
    run_output(
        Command::new("tar")
            .arg("-czf")
            .arg(&tarball)
            .arg("-C")
            .arg(&stage)
            .arg("."),
    )?;
    println!("Staged {} and {}", stage.display(), tarball.display());
    Ok(())
}

/// `dir` under the staging root.
fn under(stage: &Path, dir: &str) -> PathBuf {
    stage.join(dir.trim_start_matches('/'))
}

fn stage_tree(root: &Path, dist: &Path, stage: &Path, layout: &Layout, apple: bool) -> Result {
    let lib = under(stage, &layout.lib());
    fs::create_dir_all(&lib)?;
    let (crypto, ssl, legacy) = if apple {
        ("libcrypto.3.dylib", "libssl.3.dylib", "legacy.dylib")
    } else {
        ("libcrypto.so.3", "libssl.so.3", "legacy.so")
    };
    for file in [crypto, ssl, "libcrypto.a", "libssl.a"] {
        copy_file(&dist.join("lib").join(file), &lib.join(file))?;
    }
    for (link, file) in [
        (
            if apple {
                "libcrypto.dylib"
            } else {
                "libcrypto.so"
            },
            crypto,
        ),
        (if apple { "libssl.dylib" } else { "libssl.so" }, ssl),
    ] {
        std::os::unix::fs::symlink(file, lib.join(link))?;
    }
    let modules = under(stage, &layout.modulesdir());
    fs::create_dir_all(&modules)?;
    copy_file(
        &dist.join("lib/ossl-modules").join(legacy),
        &modules.join(legacy),
    )?;
    fs::create_dir_all(under(stage, &layout.enginesdir()))?;

    let bin = under(stage, &format!("{}/bin", layout.home));
    fs::create_dir_all(&bin)?;
    copy_file(&dist.join("bin/openssl"), &bin.join("openssl"))?;
    copy_tree(
        &dist.join("include"),
        &under(stage, &format!("{}/include", layout.home)),
    )?;

    let pkgconfig = under(stage, &format!("{}/pkgconfig", layout.lib()));
    fs::create_dir_all(&pkgconfig)?;
    for pc in ["libcrypto.pc", "libssl.pc", "openssl.pc"] {
        let text = fs::read_to_string(dist.join("lib/pkgconfig").join(pc))?;
        fs::write(pkgconfig.join(pc), pkgconfig_for(&text, layout)?)?;
    }

    // OPENSSLDIR: the system's configuration is kept; the defaults are installed as `.dist`
    // files beside it, as `make install` does (and as the real files in a keg).
    let ssl_dir = under(stage, &layout.openssldir);
    fs::create_dir_all(&ssl_dir)?;
    let apps = root.join(format!("abi/openssl-{OPENSSL_SERIES}/apps"));
    for cnf in ["openssl.cnf", "ct_log_list.cnf"] {
        copy_file(&apps.join(cnf), &ssl_dir.join(format!("{cnf}.dist")))?;
        if apple {
            copy_file(&apps.join(cnf), &ssl_dir.join(cnf))?;
        }
    }

    if apple {
        install_names(&lib, &modules, crypto, ssl, legacy, layout)?;
    } else {
        let select = bin.join("rustyssl-select");
        fs::write(&select, select_script(layout))?;
        let mut permissions = fs::metadata(&select)?.permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
        fs::set_permissions(&select, permissions)?;
    }
    Ok(())
}

fn copy_tree(from: &Path, to: &Path) -> Result {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            copy_tree(&path, &to.join(entry.file_name()))?;
        } else {
            copy_file(&path, &to.join(entry.file_name()))?;
        }
    }
    Ok(())
}

/// A pkg-config file of `dist`'s with the layout's absolute directories.
fn pkgconfig_for(text: &str, layout: &Layout) -> Result<String> {
    let mut out = String::new();
    for line in text.lines() {
        let line = match line.split_once('=') {
            Some(("prefix", _)) => format!("prefix={}", layout.home),
            Some(("libdir", _)) => format!("libdir={}", layout.lib()),
            Some(("enginesdir", _)) => format!("enginesdir={}", layout.enginesdir()),
            Some(("modulesdir", _)) => format!("modulesdir={}", layout.modulesdir()),
            _ => line.to_owned(),
        };
        writeln!(out, "{line}")?;
    }
    Ok(out)
}

/// macOS: the libraries' install names are their final paths in the keg, as Homebrew's
/// `openssl@3` has (`<keg>/lib/libcrypto.3.dylib`), and libssl and the legacy module name
/// libcrypto by it.
fn install_names(
    lib: &Path,
    modules: &Path,
    crypto: &str,
    ssl: &str,
    legacy: &str,
    layout: &Layout,
) -> Result {
    let final_crypto = format!("{}/{crypto}", layout.libdir);
    let final_ssl = format!("{}/{ssl}", layout.libdir);
    let old_crypto = id(&lib.join(crypto))?;
    let tool = |args: &[&str], file: &Path| -> Result {
        run_output(Command::new("install_name_tool").args(args).arg(file))?;
        Ok(())
    };
    tool(&["-id", &final_crypto], &lib.join(crypto))?;
    tool(
        &["-id", &final_ssl, "-change", &old_crypto, &final_crypto],
        &lib.join(ssl),
    )?;
    tool(
        &["-change", &old_crypto, &final_crypto],
        &modules.join(legacy),
    )?;
    // install_name_tool invalidates the ad-hoc signature arm64 macOS requires.
    for file in [lib.join(crypto), lib.join(ssl), modules.join(legacy)] {
        run_output(
            Command::new("codesign")
                .args(["--force", "--sign", "-"])
                .arg(&file),
        )?;
    }
    Ok(())
}

/// A Mach-O file's install name (`otool -D`).
fn id(file: &Path) -> Result<String> {
    let out = run_output(Command::new("otool").arg("-D").arg(file))?;
    out.lines()
        .nth(1)
        .map(str::to_owned)
        .ok_or_else(|| format!("{} has no install name", file.display()).into())
}

/// `rustyssl-select rustyssl|system|status`: puts rustyssl's libraries ahead of the system's
/// for every program (the loader's search order) and its `openssl` ahead in `PATH`
/// (`/usr/local/bin/openssl`), or takes them away again. The system's files stay untouched.
fn select_script(layout: &Layout) -> String {
    let (enable, disable, check) = match layout.loader {
        Loader::Glibc => (
            "printf '%s\\n' \"$HOME_DIR\" > /etc/ld.so.conf.d/00-rustyssl.conf\n    ldconfig",
            "rm -f /etc/ld.so.conf.d/00-rustyssl.conf\n    ldconfig",
            "[ -f /etc/ld.so.conf.d/00-rustyssl.conf ]",
        ),
        Loader::Musl => (
            "arch=$(uname -m)\n    printf '%s\\n' \"$HOME_DIR\" /lib /usr/local/lib /usr/lib > \"/etc/ld-musl-$arch.path\"",
            "rm -f \"/etc/ld-musl-$(uname -m).path\"",
            "grep -qx \"$HOME_DIR\" \"/etc/ld-musl-$(uname -m).path\" 2>/dev/null",
        ),
        Loader::Apple => ("", "", "false"),
    };
    format!(
        "#!/bin/sh
# rustyssl-select: choose the OpenSSL that programs load (generated by cargo xtask package).
#   rustyssl-select rustyssl   rustyssl's libraries first for every program, and its openssl
#   rustyssl-select system     the system's OpenSSL again
#   rustyssl-select status     which one is selected
set -e
HOME_DIR='{home}'
case \"${{1:-status}}\" in
rustyssl)
    {enable}
    ln -sf \"$HOME_DIR/bin/openssl\" /usr/local/bin/openssl
    echo 'rustyssl selected'
    ;;
system)
    {disable}
    if [ \"$(readlink /usr/local/bin/openssl 2>/dev/null)\" = \"$HOME_DIR/bin/openssl\" ]; then
        rm -f /usr/local/bin/openssl
    fi
    echo 'the system OpenSSL selected'
    ;;
status)
    if {check}; then echo rustyssl; else echo system; fi
    ;;
*)
    echo 'usage: rustyssl-select rustyssl|system|status' >&2
    exit 2
    ;;
esac
",
        home = layout.home
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts_put_rustyssl_beside_the_system() {
        let debian = layout("debian", None, None, "x86_64").unwrap();
        assert_eq!(debian.home, "/usr/lib/x86_64-linux-gnu/rustyssl");
        assert_eq!(
            debian.modulesdir(),
            "/usr/lib/x86_64-linux-gnu/rustyssl/ossl-modules"
        );
        assert_eq!(debian.openssldir, "/usr/lib/ssl");
        let fedora = layout("fedora", None, None, "aarch64").unwrap();
        assert_eq!(
            (fedora.home.as_str(), fedora.profile),
            ("/usr/lib64/rustyssl", Some("fedora"))
        );
        assert_eq!(
            layout("alpine", None, None, "aarch64").unwrap().openssldir,
            "/etc/ssl"
        );
        assert!(layout("homebrew", None, None, "aarch64").is_err());
        let brew = layout(
            "homebrew",
            Some("/opt/homebrew/Cellar/rustyssl/3.6.5"),
            None,
            "aarch64",
        )
        .unwrap();
        assert_eq!(brew.lib(), "/opt/homebrew/Cellar/rustyssl/3.6.5/lib");
        assert!(layout("arch", None, None, "x86_64").is_err());
    }

    #[test]
    fn pkgconfig_names_the_layouts_directories() {
        let debian = layout("debian", None, None, "aarch64").unwrap();
        let pc = "prefix=${pcfiledir}/../..\nexec_prefix=${prefix}\nlibdir=${exec_prefix}/lib\n\
                  includedir=${prefix}/include\nmodulesdir=${libdir}/ossl-modules\n\nName: x\n";
        let out = pkgconfig_for(pc, &debian).unwrap();
        assert!(out.starts_with("prefix=/usr/lib/aarch64-linux-gnu/rustyssl\nexec_prefix=${prefix}\n\
                                 libdir=/usr/lib/aarch64-linux-gnu/rustyssl\nincludedir=${prefix}/include\n\
                                 modulesdir=/usr/lib/aarch64-linux-gnu/rustyssl/ossl-modules\n"), "{out}");
    }

    #[test]
    fn select_script_orders_the_loader() {
        let alpine = layout("alpine", None, None, "x86_64").unwrap();
        let script = select_script(&alpine);
        assert!(script.contains("HOME_DIR='/usr/lib/rustyssl'"));
        assert!(script.contains("/etc/ld-musl-$arch.path"));
        assert!(
            select_script(&layout("el", None, None, "x86_64").unwrap())
                .contains("00-rustyssl.conf")
        );
    }
}
