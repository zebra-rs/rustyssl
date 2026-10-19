//! What every generator shares: the vendored headers, how clang and bindgen are pointed at
//! them for each target, and the stand-in libc headers that make that work without a target
//! sysroot.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::targets::{OPENSSL_SERIES, Target};
use crate::util::{Result, fresh_dir, run_output};

pub const BINDGEN_VERSION: &str = "0.73.2";

/// libc typedefs the OpenSSL headers use. The stand-in headers declare each one as an
/// incomplete struct: clang then rejects any public struct that embeds one by value, so a
/// wrong layout can't slip through, and the generated Rust takes the real per-target
/// definition from the `libc` crate.
const LIBC_TYPEDEFS: &[&str] = &[
    "FILE",
    "off_t",
    "pthread_key_t",
    "pthread_once_t",
    "pthread_t",
    "ssize_t",
    "time_t",
];

/// libc struct tags the headers use, only ever through pointers.
const LIBC_STRUCTS: &[&str] = &["timeval", "tm"];

/// System headers the OpenSSL headers include. Each stand-in just includes the shared
/// declarations; clang's own freestanding headers supply `stddef.h`, `stdint.h`, and the like.
const STUB_HEADERS: &[&str] = &[
    "errno.h",
    "inttypes.h",
    "pthread.h",
    "stdio.h",
    "stdlib.h",
    "string.h",
    "sys/time.h",
    "sys/types.h",
    "time.h",
];

/// Every libc type name that can appear in generated code.
pub fn libc_types() -> Vec<&'static str> {
    [LIBC_TYPEDEFS, LIBC_STRUCTS].concat()
}

pub struct Context {
    pub root: PathBuf,
    /// The vendored release, `abi/openssl-<series>/` (canonical path).
    pub abi: PathBuf,
    /// Scratch space under `target/`.
    pub work: PathBuf,
    libc_stubs: PathBuf,
    /// Includes every public header, then the vendored internal headers, which declare the
    /// functions and types of the few internal APIs libcrypto exports (`DSO_*`, ...).
    pub wrapper: PathBuf,
}

impl Context {
    /// Points clang at the vendored headers, using `work` (emptied first) for scratch files.
    pub fn new(root: &Path, work: &Path) -> Result<Self> {
        Self::for_series(root, work, OPENSSL_SERIES)
    }

    /// Points clang at the headers of the vendored release `series` (`abi/openssl-<series>/`).
    pub fn for_series(root: &Path, work: &Path, series: &str) -> Result<Self> {
        let abi = root
            .join("abi")
            .join(format!("openssl-{series}"))
            .canonicalize()
            .map_err(|e| {
                format!("abi/openssl-{series} is missing ({e}); run `cargo xtask vendor` first")
            })?;
        fresh_dir(work)?;
        let libc_stubs = write_libc_stubs(work)?;
        let wrapper = write_wrapper(&abi, work)?;
        Ok(Self {
            root: root.to_path_buf(),
            abi,
            work: work.to_path_buf(),
            libc_stubs,
            wrapper,
        })
    }

    /// clang flags that parse the vendored headers as `target` sees them.
    pub fn clang_flags(&self, target: &Target) -> Vec<String> {
        let config = self.abi.join("config").join(target.configure);
        vec![
            "-target".into(),
            target.clang.into(),
            "-ffreestanding".into(),
            "-nostdlibinc".into(),
            "-I".into(),
            self.libc_stubs.display().to_string(),
            "-I".into(),
            config.display().to_string(),
            "-I".into(),
            self.abi.join("include").display().to_string(),
        ]
    }

    /// Runs bindgen on `wrapper` for `target` with the options every generator shares plus
    /// `extra`, and returns its output. `label` names the output file under `work`.
    pub fn bindgen(
        &self,
        target: &Target,
        wrapper: &Path,
        label: &str,
        extra: &[String],
    ) -> Result<String> {
        let out = self
            .work
            .join(format!("bindgen-{label}-{}.rs", target.module));
        let mut cmd = Command::new("bindgen");
        cmd.arg(wrapper)
            .arg("--output")
            .arg(&out)
            .args(["--no-doc-comments", "--use-core"])
            .args(["--ctypes-prefix", "core::ffi"])
            // C enums become integer constants: a Rust enum holding an unknown value is UB.
            .args(["--default-enum-style", "consts", "--no-prepend-enum-name"])
            // Macro constants are evaluated by clang instead (see abi.rs), and the headers
            // declare no exported data.
            .args(["--blocklist-var", ".*"])
            .arg("--allowlist-file")
            .arg(format!(
                "{}/.*",
                regex_escape(&self.abi.display().to_string())
            ))
            .args(extra)
            .arg("--")
            .args(self.clang_flags(target));
        run_output(&mut cmd)?;
        Ok(fs::read_to_string(out)?)
    }

    /// Object-like macros defined by the vendored headers for `target`, mapped to their
    /// bodies.
    pub fn object_like_macros(&self, target: &Target) -> Result<BTreeMap<String, String>> {
        let text = run_output(
            Command::new("clang")
                .args(self.clang_flags(target))
                .args(["-E", "-dD", "-x", "c"])
                .arg(&self.wrapper),
        )?;
        let ours = format!("{}/", self.abi.display());
        let mut in_ours = false;
        let mut macros = BTreeMap::new();
        for line in text.lines() {
            // Line markers look like `# 12 "/path/to/file.h" 2`.
            if let Some(marker) = line.strip_prefix("# ") {
                if let Some(file) = marker.split('"').nth(1) {
                    in_ours = file.starts_with(&ours);
                }
            } else if !in_ours {
                continue;
            } else if let Some(definition) = line.strip_prefix("#define ") {
                let end = definition
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(definition.len());
                let (name, body) = definition.split_at(end);
                if !body.starts_with('(') {
                    macros.insert(name.to_owned(), body.trim().to_owned());
                }
            } else if let Some(name) = line.strip_prefix("#undef ") {
                macros.remove(name.trim());
            }
        }
        Ok(macros)
    }
}

pub fn check_bindgen() -> Result {
    let version = run_output(Command::new("bindgen").arg("--version")).map_err(|e| {
        format!(
            "{e}\ninstall it with: cargo install bindgen-cli --version {BINDGEN_VERSION} --locked"
        )
    })?;
    if version.trim() == format!("bindgen {BINDGEN_VERSION}") {
        Ok(())
    } else {
        Err(format!(
            "found `{}`, but the bindings are pinned to bindgen {BINDGEN_VERSION}\n\
             install it with: cargo install bindgen-cli --version {BINDGEN_VERSION} --locked",
            version.trim()
        )
        .into())
    }
}

/// Writes the stand-in system headers and returns their include directory.
fn write_libc_stubs(work: &Path) -> Result<PathBuf> {
    let dir = work.join("libc-stubs");
    let mut shared = String::from(
        "/* Stand-ins for libc, generated by `cargo xtask codegen`. */\n\
         #ifndef RUSTYSSL_LIBC_H\n#define RUSTYSSL_LIBC_H\n#include <stddef.h>\n#include <stdint.h>\n",
    );
    for name in LIBC_TYPEDEFS {
        writeln!(shared, "typedef struct rustyssl_libc_{name} {name};")?;
    }
    for tag in LIBC_STRUCTS {
        writeln!(shared, "struct {tag};")?;
    }
    // Only needed to parse the bodies of byteorder.h's inline helpers, which bindgen skips.
    shared.push_str("void *memcpy(void *, const void *, size_t);\n#endif\n");
    fs::create_dir_all(dir.join("sys"))?;
    fs::create_dir_all(dir.join("libkern"))?;
    fs::write(dir.join("rustyssl_libc.h"), shared)?;
    for header in STUB_HEADERS {
        fs::write(dir.join(header), "#include <rustyssl_libc.h>\n")?;
    }
    // byteorder.h uses these on Apple targets, again only inside inline helper bodies.
    let mut osbyteorder = String::from("#include <rustyssl_libc.h>\n");
    for swap in ["HostToBig", "BigToHost", "HostToLittle", "LittleToHost"] {
        for bits in [16, 32, 64] {
            writeln!(osbyteorder, "#define OSSwap{swap}Int{bits}(x) (x)")?;
        }
    }
    fs::write(dir.join("libkern/OSByteOrder.h"), osbyteorder)?;
    Ok(dir)
}

/// Writes the wrapper header. Some headers declare extra functions only when another header
/// came first (`cms.h` declares `PEM_read_bio_CMS` under `#ifdef OPENSSL_PEM_H`), so every
/// header named that way is included before the rest.
fn write_wrapper(abi: &Path, work: &Path) -> Result<PathBuf> {
    let mut headers = header_names(&abi.join("include/openssl"))?;
    headers.push("configuration.h".to_owned());
    headers.sort();
    let mut first = Vec::new();
    for header in &headers {
        let path = abi.join("include/openssl").join(header);
        let Ok(text) = fs::read_to_string(&path) else {
            continue; // configuration.h lives under config/<target>/
        };
        for line in text.lines() {
            let line: String = line.chars().filter(|c| !c.is_whitespace()).collect();
            if let Some(guard) = line
                .strip_prefix("#ifdefOPENSSL_")
                .and_then(|g| g.strip_suffix("_H"))
            {
                let wanted = format!("{}.h", guard.to_ascii_lowercase());
                if headers.contains(&wanted) && !first.contains(&wanted) {
                    first.push(wanted);
                }
            }
        }
    }
    first.sort();
    let mut text = String::new();
    for header in first
        .iter()
        .chain(headers.iter().filter(|h| !first.contains(h)))
    {
        writeln!(text, "#include <openssl/{header}>")?;
    }
    for header in header_names(&abi.join("include/internal"))? {
        writeln!(text, "#include <internal/{header}>")?;
    }
    let path = work.join("openssl-all.h");
    fs::write(&path, text)?;
    Ok(path)
}

/// Sorted names of the `.h` files in `dir`.
fn header_names(dir: &Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "h")
            && let Some(name) = path.file_name().and_then(|n| n.to_str())
        {
            names.push(name.to_owned());
        }
    }
    names.sort();
    Ok(names)
}

fn regex_escape(text: &str) -> String {
    let mut escaped = String::new();
    for c in text.chars() {
        if "\\.+*?()|[]{}^$".contains(c) {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped
}

pub fn identifiers(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|t| !t.is_empty())
}

/// Writes `source` to `path` and formats it with rustfmt.
pub fn write_rust(root: &Path, path: &Path, source: &str) -> Result {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, source)?;
    run_output(
        Command::new("rustfmt")
            .args(["--edition", "2024"])
            .arg(path)
            .current_dir(root),
    )?;
    Ok(())
}
