//! Generates the `rustssl-abi` bindings, `crates/rustssl-abi/src/generated/<module>.rs`, for
//! every target in [`TARGETS`] (step 0.3 of the implementation plan).
//!
//! - **Types and enums** come from bindgen (pinned to [`BINDGEN_VERSION`]), run on the vendored
//!   headers with clang's freestanding headers plus stand-ins for the few libc headers OpenSSL
//!   includes (see [`LIBC_TYPEDEFS`]). bindgen's compile-time layout assertions are kept.
//! - **Constants** are every object-like macro the headers define, evaluated by clang itself:
//!   values and C types are exact even for casts, `sizeof`, and function-like macros such as
//!   `SSL_OP_BIT(n)`, which bindgen can't evaluate. String macros become `&CStr`.
//!
//! Needs `bindgen` (`cargo install bindgen-cli --version 0.73.2 --locked`), `clang`, `rustfmt`,
//! and the Rust targets in `rust-toolchain.toml`, which are used to check the output.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::targets::{OPENSSL_SERIES, TARGETS, Target};
use crate::util::{Result, fresh_dir, run_output};

const BINDGEN_VERSION: &str = "0.73.2";

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

/// Builtin macros whose value depends on where they're expanded. Macros that use them, even
/// indirectly like `OPENSSL_LINE`, aren't constants.
const LOCATION_MACROS: &[&str] = &[
    "__BASE_FILE__",
    "__COUNTER__",
    "__DATE__",
    "__FILE_NAME__",
    "__FILE__",
    "__FUNCTION__",
    "__LINE__",
    "__TIME__",
    "__func__",
];

/// Lint exceptions for the generated files. C names don't follow Rust's conventions, and
/// bindgen's layout assertions are written as `["Size of X"][size_of::<X>() - N]`, which
/// `indexing_slicing` flags even though they run at compile time: a mismatch fails the build,
/// it can't panic.
const GENERATED_ALLOWS: &str =
    "non_camel_case_types, non_snake_case, non_upper_case_globals, clippy::indexing_slicing";

pub fn generate(root: &Path) -> Result {
    check_bindgen()?;
    let abi = root
        .join("abi")
        .join(format!("openssl-{OPENSSL_SERIES}"))
        .canonicalize()
        .map_err(|e| {
            format!("abi/openssl-{OPENSSL_SERIES} is missing ({e}); run `cargo xtask vendor` first")
        })?;
    let work = root.join("target/xtask/codegen/abi");
    fresh_dir(&work)?;
    let stubs = write_stubs(&work)?;
    let wrapper = write_wrapper(&abi, &work)?;
    let out_dir = root.join("crates/rustssl-abi/src/generated");
    fs::create_dir_all(&out_dir)?;

    for target in TARGETS {
        println!(
            "Generating rustssl-abi bindings for {}...",
            target.configure
        );
        let flags = clang_flags(target, &abi, &stubs);
        let types = bindgen(&wrapper, &work, target, &abi, &flags)?;
        let macros = object_like_macros(&wrapper, &abi, &flags)?;
        let constants = evaluate(
            &work,
            target,
            &wrapper,
            &flags,
            &constant_candidates(&macros),
        )?;
        let path = out_dir.join(format!("{}.rs", target.module));
        let (source, skipped) = render(target, &types, &constants)?;
        fs::write(&path, source)?;
        rustfmt(root, &path)?;
        println!(
            "  {} integer and {} string constants",
            constants.ints.len(),
            constants.strings.len()
        );
        for (name, why) in skipped {
            println!("  skipped constant {name}: {why}");
        }
    }
    let mod_rs = out_dir.join("mod.rs");
    fs::write(&mod_rs, render_mod()?)?;
    rustfmt(root, &mod_rs)?;

    for target in TARGETS {
        println!("Checking rustssl-abi for {}...", target.rust);
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        run_output(
            Command::new(cargo)
                .args([
                    "check",
                    "--quiet",
                    "-p",
                    "rustssl-abi",
                    "--target",
                    target.rust,
                ])
                .current_dir(root),
        )?;
    }
    Ok(())
}

fn check_bindgen() -> Result {
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
fn write_stubs(work: &Path) -> Result<PathBuf> {
    let dir = work.join("libc-stubs");
    let mut shared = String::from(
        "/* Stand-ins for libc, generated by `cargo xtask codegen`. */\n\
         #ifndef RUSTSSL_LIBC_H\n#define RUSTSSL_LIBC_H\n#include <stddef.h>\n#include <stdint.h>\n",
    );
    for name in LIBC_TYPEDEFS {
        writeln!(shared, "typedef struct rustssl_libc_{name} {name};")?;
    }
    for tag in LIBC_STRUCTS {
        writeln!(shared, "struct {tag};")?;
    }
    // Only needed to parse the bodies of byteorder.h's inline helpers, which bindgen skips.
    shared.push_str("void *memcpy(void *, const void *, size_t);\n#endif\n");
    fs::create_dir_all(dir.join("sys"))?;
    fs::create_dir_all(dir.join("libkern"))?;
    fs::write(dir.join("rustssl_libc.h"), shared)?;
    for header in STUB_HEADERS {
        fs::write(dir.join(header), "#include <rustssl_libc.h>\n")?;
    }
    // byteorder.h uses these on Apple targets, again only inside inline helper bodies.
    let mut osbyteorder = String::from("#include <rustssl_libc.h>\n");
    for swap in ["HostToBig", "BigToHost", "HostToLittle", "LittleToHost"] {
        for bits in [16, 32, 64] {
            writeln!(osbyteorder, "#define OSSwap{swap}Int{bits}(x) (x)")?;
        }
    }
    fs::write(dir.join("libkern/OSByteOrder.h"), osbyteorder)?;
    Ok(dir)
}

/// Writes a header that includes every vendored public header, in sorted order.
fn write_wrapper(abi: &Path, work: &Path) -> Result<PathBuf> {
    let mut headers: Vec<String> = Vec::new();
    for entry in fs::read_dir(abi.join("include/openssl"))? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "h")
            && let Some(name) = path.file_name().and_then(|n| n.to_str())
        {
            headers.push(name.to_owned());
        }
    }
    headers.push("configuration.h".to_owned());
    headers.sort();
    let mut text = String::new();
    for header in headers {
        writeln!(text, "#include <openssl/{header}>")?;
    }
    let path = work.join("openssl-all.h");
    fs::write(&path, text)?;
    Ok(path)
}

fn clang_flags(target: &Target, abi: &Path, stubs: &Path) -> Vec<String> {
    let config = abi.join("config").join(target.configure);
    vec![
        "-target".into(),
        target.clang.into(),
        "-ffreestanding".into(),
        "-nostdlibinc".into(),
        "-I".into(),
        stubs.display().to_string(),
        "-I".into(),
        config.display().to_string(),
        "-I".into(),
        abi.join("include").display().to_string(),
    ]
}

/// Runs bindgen for types and enums only, and returns its output.
fn bindgen(
    wrapper: &Path,
    work: &Path,
    target: &Target,
    abi: &Path,
    flags: &[String],
) -> Result<String> {
    let out = work.join(format!("bindgen-{}.rs", target.module));
    let libc_types = [LIBC_TYPEDEFS, LIBC_STRUCTS].concat().join("|");
    let mut cmd = Command::new("bindgen");
    cmd.arg(wrapper)
        .arg("--output")
        .arg(&out)
        .args(["--ignore-functions", "--no-doc-comments", "--use-core"])
        .args(["--ctypes-prefix", "core::ffi"])
        // C enums become integer constants: a Rust enum holding an unknown value is UB.
        .args(["--default-enum-style", "consts", "--no-prepend-enum-name"])
        // Macro constants come from `evaluate`; extern data belongs with the prototypes.
        .args(["--blocklist-var", ".*"])
        .arg("--blocklist-type")
        .arg(format!("{libc_types}|rustssl_libc_.*"))
        .arg("--allowlist-file")
        .arg(format!("{}/.*", regex_escape(&abi.display().to_string())))
        .arg("--")
        .args(flags);
    run_output(&mut cmd)?;
    Ok(fs::read_to_string(out)?)
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

/// Object-like macros defined by the vendored headers, mapped to their bodies.
fn object_like_macros(
    wrapper: &Path,
    abi: &Path,
    flags: &[String],
) -> Result<BTreeMap<String, String>> {
    let text = run_output(
        Command::new("clang")
            .args(flags)
            .args(["-E", "-dD", "-x", "c"])
            .arg(wrapper),
    )?;
    let ours = format!("{}/", abi.display());
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

/// Macros worth evaluating: non-empty, and not location-dependent.
fn constant_candidates(macros: &BTreeMap<String, String>) -> Vec<String> {
    let mut tainted: HashSet<&str> = LOCATION_MACROS.iter().copied().collect();
    loop {
        let before = tainted.len();
        for (name, body) in macros {
            if identifiers(body).any(|id| tainted.contains(id)) {
                tainted.insert(name);
            }
        }
        if tainted.len() == before {
            break;
        }
    }
    macros
        .iter()
        .filter(|(name, body)| !body.is_empty() && !tainted.contains(name.as_str()))
        .map(|(name, _)| name.clone())
        .collect()
}

fn identifiers(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|t| !t.is_empty())
}

/// C integer types a macro can evaluate to, in `_Generic` order (codes 1..).
const C_TYPES: &[(&str, &str)] = &[
    ("_Bool", "bool"),
    ("char", "core::ffi::c_char"),
    ("signed char", "core::ffi::c_schar"),
    ("unsigned char", "core::ffi::c_uchar"),
    ("short", "core::ffi::c_short"),
    ("unsigned short", "core::ffi::c_ushort"),
    ("int", "core::ffi::c_int"),
    ("unsigned int", "core::ffi::c_uint"),
    ("long", "core::ffi::c_long"),
    ("unsigned long", "core::ffi::c_ulong"),
    ("long long", "core::ffi::c_longlong"),
    ("unsigned long long", "core::ffi::c_ulonglong"),
];

struct IntConst {
    name: String,
    /// Index into [`C_TYPES`].
    ctype: usize,
    /// The value converted to `unsigned long long`, as LLVM prints it (signed).
    value: i64,
}

struct Constants {
    ints: Vec<IntConst>,
    strings: Vec<(String, Vec<u8>)>,
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Int,
    Str,
}

/// Evaluates the candidates with clang. Each macro is probed both as an integer constant
/// expression and as a string literal; probes that don't compile are dropped and the rest are
/// compiled to LLVM IR, which holds the values.
fn evaluate(
    work: &Path,
    target: &Target,
    wrapper: &Path,
    flags: &[String],
    candidates: &[String],
) -> Result<Constants> {
    let source = work.join(format!("probe-{}.c", target.module));
    let ir = work.join(format!("probe-{}.ll", target.module));
    let mut probes: Vec<(&str, Kind)> = candidates
        .iter()
        .flat_map(|name| [(name.as_str(), Kind::Int), (name.as_str(), Kind::Str)])
        .collect();
    for _ in 0..4 {
        fs::write(&source, probe_source(wrapper, &probes)?)?;
        let output = Command::new("clang")
            .args(flags)
            .args(["-S", "-emit-llvm", "-ferror-limit=0", "-Wno-everything"])
            // Reject expressions clang only folds as an extension (like string addresses).
            .arg("-Werror=gnu-folding-constant")
            .arg("-o")
            .arg(&ir)
            .arg(&source)
            .output()
            .map_err(|e| format!("cannot run `clang`: {e}"))?;
        if output.status.success() {
            return parse_ir(&fs::read_to_string(&ir)?, &probes);
        }
        let failed = failed_probe_lines(&String::from_utf8_lossy(&output.stderr), &source);
        if failed.is_empty() {
            return Err(format!(
                "clang failed outside the probes:\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        let mut index = 0;
        probes.retain(|_| {
            index += 1;
            !failed.contains(&(index + PROBE_FIRST_LINE - 1))
        });
    }
    Err("constant probes still failed after 4 attempts".into())
}

/// Line number of the first probe in the generated source.
const PROBE_FIRST_LINE: usize = 3;

fn probe_source(wrapper: &Path, probes: &[(&str, Kind)]) -> Result<String> {
    let mut text = format!(
        "#include \"{}\"\n#define RUSTSSL_TYPE(x) _Generic((x)",
        wrapper.display()
    );
    for (code, (ctype, _)) in (1..).zip(C_TYPES) {
        write!(text, ", {ctype}: {code}")?;
    }
    text.push_str(", default: 0)\n");
    for (name, kind) in probes {
        match kind {
            // The array bound forces an integer constant expression.
            Kind::Int => writeln!(
                text,
                "typedef char rustssl_ice_{name}[({name}) ? 1 : 1]; \
                 const unsigned long long rustssl_v_{name} = (unsigned long long)({name}); \
                 const int rustssl_t_{name} = RUSTSSL_TYPE({name});"
            )?,
            // Pasting `""` in front only compiles if the macro is a string literal (a brace
            // initializer such as `EXT_END` would otherwise fill a char array too).
            Kind::Str => writeln!(text, "const char rustssl_s_{name}[] = \"\" {name};")?,
        }
    }
    Ok(text)
}

/// Line numbers of probes that clang reported errors for.
fn failed_probe_lines(stderr: &str, source: &Path) -> HashSet<usize> {
    let prefix = format!("{}:", source.display());
    stderr
        .lines()
        .filter_map(|line| {
            let mut parts = line.strip_prefix(&prefix)?.splitn(3, ':');
            let number = parts.next()?.parse().ok()?;
            let _column = parts.next()?;
            parts.next()?.starts_with(" error").then_some(number)
        })
        .collect()
}

fn parse_ir(ir: &str, probes: &[(&str, Kind)]) -> Result<Constants> {
    let mut values: HashMap<&str, i64> = HashMap::new();
    let mut types: HashMap<&str, usize> = HashMap::new();
    let mut strings: HashMap<&str, Vec<u8>> = HashMap::new();
    for line in ir.lines() {
        let Some((symbol, definition)) = line
            .strip_prefix("@rustssl_")
            .and_then(|rest| rest.split_once(" = "))
        else {
            continue;
        };
        if let Some(name) = symbol.strip_prefix("v_") {
            values.insert(name, ir_number(definition, "constant i64 ")?);
        } else if let Some(name) = symbol.strip_prefix("t_") {
            let code = ir_number(definition, "constant i32 ")?;
            types.insert(name, usize::try_from(code)?);
        } else if let Some(name) = symbol.strip_prefix("s_") {
            strings.insert(name, ir_string(definition)?);
        }
    }

    let mut constants = Constants {
        ints: Vec::new(),
        strings: Vec::new(),
    };
    for &(name, kind) in probes {
        match kind {
            Kind::Int => {
                let (Some(&value), Some(&code)) = (values.get(name), types.get(name)) else {
                    return Err(format!("no value for {name} in the IR").into());
                };
                // Code 0 is `default:`, a non-integer type; the folding check normally
                // rejects those already.
                if let Some(ctype) = code.checked_sub(1).filter(|i| *i < C_TYPES.len()) {
                    let name = name.to_owned();
                    constants.ints.push(IntConst { name, ctype, value });
                }
            }
            Kind::Str => {
                let bytes = strings
                    .remove(name)
                    .ok_or_else(|| format!("no string for {name} in the IR"))?;
                constants.strings.push((name.to_owned(), bytes));
            }
        }
    }
    Ok(constants)
}

/// The integer after `marker` in an IR global definition such as
/// `dso_local constant i64 672, align 8`.
fn ir_number(definition: &str, marker: &str) -> Result<i64> {
    let (_, rest) = definition
        .split_once(marker)
        .ok_or_else(|| format!("unexpected IR: {definition}"))?;
    let number = rest.split(',').next().unwrap_or_default().trim();
    Ok(number.parse()?)
}

/// The bytes of an IR string such as `constant [7 x i8] c"SHA256\00", align 1`, without the
/// terminating NUL.
fn ir_string(definition: &str) -> Result<Vec<u8>> {
    if definition.contains("[1 x i8] zeroinitializer") {
        return Ok(Vec::new());
    }
    let (_, rest) = definition
        .split_once("c\"")
        .ok_or_else(|| format!("unexpected IR: {definition}"))?;
    let (escaped, _) = rest
        .split_once('"')
        .ok_or_else(|| format!("unexpected IR: {definition}"))?;
    let mut bytes = Vec::new();
    let mut chars = escaped.bytes();
    while let Some(b) = chars.next() {
        if b == b'\\' {
            let hex = [chars.next(), chars.next()];
            let [Some(hi), Some(lo)] = hex else {
                return Err(format!("bad escape in IR string: {definition}").into());
            };
            bytes.push(u8::from_str_radix(std::str::from_utf8(&[hi, lo])?, 16)?);
        } else {
            bytes.push(b);
        }
    }
    match bytes.pop() {
        Some(0) => Ok(bytes),
        _ => Err(format!("IR string is not NUL-terminated: {definition}").into()),
    }
}

/// Renders one target's module. Returns the source and the constants that were left out,
/// with the reason.
fn render(
    target: &Target,
    types: &str,
    constants: &Constants,
) -> Result<(String, Vec<(String, &'static str)>)> {
    let mut out = String::new();
    writeln!(
        out,
        "// Generated by `cargo xtask codegen` from abi/openssl-{OPENSSL_SERIES} for Configure \
         target\n// `{}` (clang target `{}`).\n// Types and enums come from bindgen \
         {BINDGEN_VERSION}; constants are the headers' object-like\n// macros, evaluated by \
         clang. Do not edit.\n",
        target.configure, target.clang
    )?;
    writeln!(out, "#![allow({GENERATED_ALLOWS})]\n")?;

    let used: Vec<&str> = [LIBC_TYPEDEFS, LIBC_STRUCTS]
        .concat()
        .into_iter()
        .filter(|t| identifiers(types).any(|id| id == *t))
        .collect();
    if !used.is_empty() {
        writeln!(out, "use libc::{{{}}};\n", used.join(", "))?;
    }
    // Drop bindgen's own banner comment.
    let body = types
        .strip_prefix(&format!(
            "/* automatically generated by rust-bindgen {BINDGEN_VERSION} */"
        ))
        .unwrap_or(types);
    out.push_str(body.trim_start());

    let defined = defined_items(types);
    let unusable = |name: &str| {
        if defined.contains(name) {
            Some("a bindgen item has the same name")
        } else if RUST_KEYWORDS.contains(&name) {
            Some("it is a Rust keyword")
        } else {
            None
        }
    };
    let mut skipped = Vec::new();

    writeln!(
        out,
        "\n// Integer constants, with the C type clang gives each macro."
    )?;
    for c in &constants.ints {
        if let Some(why) = unusable(&c.name) {
            skipped.push((c.name.clone(), why));
            continue;
        }
        let Some((ctype, rust)) = C_TYPES.get(c.ctype) else {
            continue;
        };
        let value = if *ctype == "_Bool" {
            (c.value != 0).to_string()
        } else if ctype.starts_with("unsigned") {
            format!("{:#x}", c.value.cast_unsigned())
        } else {
            c.value.to_string()
        };
        writeln!(out, "pub const {}: {rust} = {value};", c.name)?;
    }
    writeln!(out, "\n// String constants.")?;
    for (name, bytes) in &constants.strings {
        if let Some(why) = unusable(name) {
            skipped.push((name.clone(), why));
        } else if bytes.contains(&0) {
            skipped.push((name.clone(), "the string contains a NUL byte"));
        } else {
            writeln!(
                out,
                "pub const {name}: &core::ffi::CStr = c\"{}\";",
                c_literal(bytes)
            )?;
        }
    }
    Ok((out, skipped))
}

/// Names that bindgen defined, so constants can't collide with them.
fn defined_items(types: &str) -> HashSet<String> {
    let mut names = HashSet::new();
    for line in types.lines() {
        let line = line.trim_start();
        for keyword in [
            "pub const ",
            "pub type ",
            "pub struct ",
            "pub union ",
            "pub enum ",
        ] {
            if let Some(rest) = line.strip_prefix(keyword)
                && let Some(name) = identifiers(rest).next()
            {
                names.insert(name.to_owned());
            }
        }
    }
    names
}

const RUST_KEYWORDS: &[&str] = &[
    "Self", "abstract", "as", "async", "await", "become", "box", "break", "const", "continue",
    "crate", "do", "dyn", "else", "enum", "extern", "false", "final", "fn", "for", "gen", "if",
    "impl", "in", "let", "loop", "macro", "match", "mod", "move", "mut", "override", "priv", "pub",
    "ref", "return", "self", "static", "struct", "super", "trait", "true", "try", "type", "typeof",
    "unsafe", "unsized", "use", "virtual", "where", "while", "yield",
];

/// Escapes bytes for a Rust `c"..."` literal.
fn c_literal(bytes: &[u8]) -> String {
    let mut text = String::new();
    for &b in bytes {
        match b {
            b'"' => text.push_str("\\\""),
            b'\\' => text.push_str("\\\\"),
            0x20..=0x7e => text.push(char::from(b)),
            _ => text.push_str(&format!("\\x{b:02x}")),
        }
    }
    text
}

/// Renders `generated/mod.rs`, which picks the current target's module.
fn render_mod() -> Result<String> {
    let mut out = String::from(
        "// Generated by `cargo xtask codegen`. Do not edit.\n//\n// Selects the bindings \
         for the target being compiled.\n\n",
    );
    for target in TARGETS {
        writeln!(
            out,
            "#[cfg({cfg})]\nmod {m};\n#[cfg({cfg})]\npub use {m}::*;\n",
            cfg = target.cfg,
            m = target.module
        )?;
    }
    let all: Vec<&str> = TARGETS.iter().map(|t| t.cfg).collect();
    writeln!(
        out,
        "#[cfg(not(any({})))]\ncompile_error!(\"rustssl-abi has no bindings for this target; add \
         it to TARGETS in xtask/src/targets.rs and run `cargo xtask codegen`\");",
        all.join(", ")
    )?;
    Ok(out)
}

fn rustfmt(root: &Path, path: &Path) -> Result {
    run_output(
        Command::new("rustfmt")
            .args(["--edition", "2024"])
            .arg(path)
            .current_dir(root),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn location_dependent_macros_are_excluded_transitively() {
        let macros: BTreeMap<String, String> = [
            ("OPENSSL_LINE", "__LINE__"),
            ("MY_LINE", "(OPENSSL_LINE + 1)"),
            ("NID_sha256", "672"),
            ("HEADER_GUARD", ""),
        ]
        .into_iter()
        .map(|(n, b)| (n.to_owned(), b.to_owned()))
        .collect();
        assert_eq!(constant_candidates(&macros), ["NID_sha256"]);
    }

    #[test]
    fn ir_values_and_strings_parse() {
        let v = "dso_local constant i64 -9223372036854775808, align 8";
        assert_eq!(ir_number(v, "constant i64 ").unwrap(), i64::MIN);
        assert_eq!(
            ir_number("constant i32 7, align 4", "constant i32 ").unwrap(),
            7
        );
        let s = r#"dso_local constant [9 x i8] c"a\22b\5Cc\0A\00", align 1"#;
        assert_eq!(ir_string(s).unwrap(), b"a\"b\\c\n".to_vec());
        let empty = "dso_local constant [1 x i8] zeroinitializer, align 1";
        assert_eq!(ir_string(empty).unwrap(), Vec::<u8>::new());
        assert!(ir_string(r#"constant [3 x i8] c"ab\01", align 1"#).is_err());
    }

    #[test]
    fn clang_error_lines_map_to_probes() {
        let stderr = "/w/probe.c:5:12: error: bad\n/w/probe.c:7:1: warning: meh\n\
                      /w/other.h:9:1: error: elsewhere\n/w/probe.c:8:3: error: worse\n";
        let lines = failed_probe_lines(stderr, Path::new("/w/probe.c"));
        assert_eq!(lines, HashSet::from([5, 8]));
    }

    #[test]
    fn c_literals_escape_quotes_and_non_ascii() {
        assert_eq!(c_literal(b"SHA256"), "SHA256");
        assert_eq!(c_literal(b"a\"b\\c\n\xff"), "a\\\"b\\\\c\\x0a\\xff");
    }
}
