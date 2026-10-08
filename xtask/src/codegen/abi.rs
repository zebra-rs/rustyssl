//! Generates the `rustyssl-abi` bindings, `crates/rustyssl-abi/src/generated/<module>.rs`, for
//! every target in [`TARGETS`] (step 0.3 of the implementation plan).
//!
//! - **Types and enums** come from bindgen, run on the vendored headers with clang's
//!   freestanding headers plus stand-ins for the libc headers OpenSSL includes (see
//!   `headers.rs`). bindgen's compile-time layout assertions are kept.
//! - **Constants** are every object-like macro the headers define, evaluated by clang itself:
//!   values and C types are exact even for casts, `sizeof`, and function-like macros such as
//!   `SSL_OP_BIT(n)`, which bindgen can't evaluate. String macros become `&CStr`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;

use super::headers::{BINDGEN_VERSION, Context, identifiers, libc_types, write_rust};
use crate::targets::{OPENSSL_SERIES, TARGETS, Target};
use crate::util::{Result, toml_value};

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

/// Generates every target's bindings and returns the constants of the first target. Names
/// and values of the constants are the same on every target; only some C types differ.
pub fn generate(ctx: &Context) -> Result<Constants> {
    let out_dir = ctx.root.join("crates/rustyssl-abi/src/generated");
    let mut first = None;
    for target in TARGETS {
        println!(
            "Generating rustyssl-abi bindings for {}...",
            target.configure
        );
        let libc = libc_types().join("|");
        let options = [
            "--ignore-functions".to_owned(),
            "--blocklist-type".to_owned(),
            format!("{libc}|rustyssl_libc_.*"),
        ];
        let types = ctx.bindgen(target, &ctx.wrapper, "types", &options)?;
        let macros = ctx.object_like_macros(target)?;
        let constants = evaluate(ctx, target, &constant_candidates(&macros))?;
        let build = fs::read_to_string(
            ctx.abi
                .join("config")
                .join(target.configure)
                .join("build.toml"),
        )?;
        let (mut source, skipped) = render(target, &types, &constants)?;
        source.push_str(&render_build(&build)?);
        write_rust(
            &ctx.root,
            &out_dir.join(format!("{}.rs", target.module)),
            &source,
        )?;
        println!(
            "  {} integer and {} string constants",
            constants.ints.len(),
            constants.strings.len()
        );
        for (name, why) in skipped {
            println!("  skipped constant {name}: {why}");
        }
        first.get_or_insert(constants);
    }
    write_rust(&ctx.root, &out_dir.join("mod.rs"), &render_mod()?)?;
    first.ok_or_else(|| "no targets".into())
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

pub struct IntConst {
    pub name: String,
    /// Index into [`C_TYPES`].
    pub ctype: usize,
    /// The value converted to `unsigned long long`, as LLVM prints it (signed).
    pub value: i64,
}

pub struct Constants {
    pub ints: Vec<IntConst>,
    pub strings: Vec<(String, Vec<u8>)>,
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Int,
    Str,
}

/// Evaluates the candidates with clang. Each macro is probed both as an integer constant
/// expression and as a string literal; probes that don't compile are dropped and the rest are
/// compiled to LLVM IR, which holds the values.
fn evaluate(ctx: &Context, target: &Target, candidates: &[String]) -> Result<Constants> {
    let source = ctx.work.join(format!("probe-{}.c", target.module));
    let ir = ctx.work.join(format!("probe-{}.ll", target.module));
    let wrapper = &ctx.wrapper;
    let flags = ctx.clang_flags(target);
    let mut probes: Vec<(&str, Kind)> = candidates
        .iter()
        .flat_map(|name| [(name.as_str(), Kind::Int), (name.as_str(), Kind::Str)])
        .collect();
    for _ in 0..4 {
        fs::write(&source, probe_source(wrapper, &probes)?)?;
        let output = Command::new("clang")
            .args(&flags)
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
        "#include \"{}\"\n#define RUSTYSSL_TYPE(x) _Generic((x)",
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
                "typedef char rustyssl_ice_{name}[({name}) ? 1 : 1]; \
                 const unsigned long long rustyssl_v_{name} = (unsigned long long)({name}); \
                 const int rustyssl_t_{name} = RUSTYSSL_TYPE({name});"
            )?,
            // Pasting `""` in front only compiles if the macro is a string literal (a brace
            // initializer such as `EXT_END` would otherwise fill a char array too).
            Kind::Str => writeln!(text, "const char rustyssl_s_{name}[] = \"\" {name};")?,
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
            .strip_prefix("@rustyssl_")
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

    let used: Vec<&str> = libc_types()
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

/// What OpenSSL's build compiles in for the target (`config/<target>/build.toml`), as the
/// module `build`, which `OpenSSL_version` and `OPENSSL_info` report.
fn render_build(toml: &str) -> Result<String> {
    let mut out = String::from(
        "\n/// What OpenSSL's build compiles in for this target (`-DOPENSSLDIR=...` and the like),\n\
         /// from `config/<target>/build.toml`.\npub mod build {\n",
    );
    for (key, doc) in [
        ("platform", "The `Configure` target (`PLATFORM`)."),
        (
            "openssldir",
            "The default configuration and certificate directory (`OPENSSLDIR`).",
        ),
        (
            "enginesdir",
            "The default engines directory (`ENGINESDIR`).",
        ),
        (
            "modulesdir",
            "The default provider modules directory (`MODULESDIR`).",
        ),
        (
            "dso_extension",
            "The file extension of loadable modules (`DSO_EXTENSION`).",
        ),
    ] {
        let value = toml_value(toml, key).ok_or_else(|| format!("build.toml has no {key}"))?;
        writeln!(
            out,
            "    /// {doc}\n    pub const {}: &core::ffi::CStr = c\"{}\";",
            key.to_ascii_uppercase(),
            c_literal(value.as_bytes())
        )?;
    }
    out.push_str("}\n");
    Ok(out)
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
pub(super) fn c_literal(bytes: &[u8]) -> String {
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
        "#[cfg(not(any({})))]\ncompile_error!(\"rustyssl-abi has no bindings for this target; add \
         it to TARGETS in xtask/src/targets.rs and run `cargo xtask codegen`\");",
        all.join(", ")
    )?;
    Ok(out)
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
