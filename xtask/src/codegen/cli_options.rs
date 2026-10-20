//! Generates the `openssl` command-line tool's option tables (ADR 0007, section 3), from the
//! command sources vendored as a specification in `abi/openssl-<series>/apps/`:
//!
//! - each command's `OPTIONS` array: the option names, value types, help texts, and the
//!   section and parameter markers, in upstream's order, with the shared macro groups
//!   (`OPT_V_OPTIONS`, `OPT_S_OPTIONS`, ...) expanded;
//! - the choice `enum` each array returns, as a Rust enum per command (`OPT_FOO` becomes
//!   `Opt::FOO`), with the shared groups as nested enums (`OPT_V_POLICY` becomes
//!   `Opt::OPT_V(V::POLICY)`), so the shared handlers (`opt_verify`, `opt_rand`, ...) take
//!   them;
//! - the command table of `progs.c` (`functions[]`).
//!
//! The sources are never compiled. Each file is filtered down to its preprocessor directives,
//! its `enum`s, and its arrays, and that text is run through clang's preprocessor with the
//! target's `configuration.h`, so `#ifndef OPENSSL_NO_*` and the macros of `apps/include/opt.h`
//! are evaluated exactly as upstream's build evaluates them. Every target must give the same
//! tables; codegen fails otherwise.
//!
//! Output: `crates/rustyssl-cli/src/generated/options.rs`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::process::Command;

use super::headers::{Context, write_rust};
use crate::targets::{OPENSSL_SERIES, TARGETS, Target};
use crate::util::{Result, run_output};

const OUTPUT: &str = "crates/rustyssl-cli/src/generated/options.rs";

/// The shared option groups of `opt.h`: the enum macro, the prefix of its constants, and the
/// Rust name of its enum.
const GROUPS: &[(&str, &str, &str)] = &[
    ("OPT_V_ENUM", "OPT_V_", "V"),
    ("OPT_X_ENUM", "OPT_X_", "X"),
    ("OPT_S_ENUM", "OPT_S_", "S"),
    ("OPT_R_ENUM", "OPT_R_", "R"),
    ("OPT_PROV_ENUM", "OPT_PROV_", "Prov"),
];

/// The system headers' macros the tables test (`#ifdef AF_UNIX`), whose headers are filtered
/// out with the other includes: the socket families every target's `<sys/socket.h>` defines
/// (Linux and macOS both have Unix-domain sockets and IPv6). Only their presence matters.
const SYSTEM_MACROS: &str = "#define AF_UNIX 1\n#define AF_INET6 1\n";

/// The marker names of `opt.c` (`OPT_HELP_STR` and so on), which C compares by address.
const MARKERS: &[(&str, &str, &str)] = &[
    ("OPT_HELP_STR", "-H", "Help"),
    ("OPT_MORE_STR", "-M", "More"),
    ("OPT_SECTION_STR", "-S", "Section"),
    ("OPT_PARAM_STR", "-P", "Param"),
];

pub fn generate(ctx: &Context) -> Result {
    let mut agreed: Option<String> = None;
    for target in TARGETS {
        let code = render(ctx, target)?;
        match &agreed {
            None => agreed = Some(code),
            Some(first) if *first == code => {}
            Some(_) => {
                return Err(format!(
                    "the option tables differ on {}; the CLI's tables would need a per-target \
                     cfg",
                    target.configure
                )
                .into());
            }
        }
    }
    let code = agreed.ok_or("no targets")?;
    write_rust(&ctx.root, &ctx.root.join(OUTPUT), &code)?;
    Ok(())
}

/// One option table entry.
#[derive(Debug, PartialEq)]
struct Entry {
    /// The option's name, or a marker's (`-H`, ...).
    name: String,
    /// The marker kind, for markers.
    marker: Option<&'static str>,
    retval: Retval,
    valtype: u8,
    help: Option<String>,
}

#[derive(Debug, PartialEq)]
enum Retval {
    Name(String),
    Number(i64),
}

/// Each option array by name: its entries, and the constants of its choice enum.
type Tables = BTreeMap<String, (Vec<Entry>, Vec<(String, i64)>)>;

/// One `FUNCTION` of `progs.c`.
#[derive(Debug)]
struct Function {
    kind: String,
    name: String,
    options: Option<String>,
    deprecated_alternative: Option<String>,
    deprecated_version: Option<String>,
}

fn render(ctx: &Context, target: &Target) -> Result<String> {
    let apps = ctx.abi.join("apps");
    let progs = preprocess(
        ctx,
        target,
        &fs::read_to_string(apps.join("progs.c"))?,
        "progs",
    )?;
    let functions = parse_functions(&tokens(&progs)?)?;

    // The commands' option arrays, by array name, with the file they are in.
    let mut wanted: Vec<String> = functions.iter().filter_map(|f| f.options.clone()).collect();
    wanted.sort();
    wanted.dedup();
    let mut tables: Tables = BTreeMap::new();
    let mut files: Vec<_> = fs::read_dir(&apps)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "c"))
        .collect();
    files.sort();
    for file in files {
        let stem = file
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or("bad file name")?
            .to_owned();
        if stem == "progs" {
            continue;
        }
        let source = fs::read_to_string(&file)?;
        if !wanted
            .iter()
            .any(|w| source.contains(&format!("OPTIONS {w}[]")))
        {
            continue;
        }
        let text = preprocess(ctx, target, &source, &stem)?;
        let toks = tokens(&text)?;
        let enums = parse_enums(&toks)?;
        for (name, entries) in parse_arrays(&toks)? {
            if !wanted.contains(&name) {
                continue;
            }
            let choice = choose_enum(&name, &entries, &enums)?;
            tables.insert(name, (entries, choice));
        }
    }
    let missing: Vec<&String> = wanted.iter().filter(|w| !tables.contains_key(*w)).collect();
    if !missing.is_empty() {
        return Err(format!("option arrays not found in apps/: {missing:?}").into());
    }
    let groups = group_enums(ctx, target)?;
    render_rust(&functions, &tables, &groups)
}

/// The text clang's preprocessor makes of `source`'s directives, enums, and arrays, after
/// `opt.h`.
fn preprocess(ctx: &Context, target: &Target, source: &str, label: &str) -> Result<String> {
    let wrapper = ctx.work.join(format!("cli-{label}-{}.c", target.module));
    // The apps' own headers it includes ("s_apps.h", ...), filtered the same way, for their
    // macros (`PORT`, ...).
    let mut seen = vec!["opt.h".to_owned(), "function.h".to_owned()];
    let headers = local_headers(&ctx.abi.join("apps/include"), source, &mut seen)?;
    fs::write(
        &wrapper,
        format!(
            "#include \"opt.h\"\n#include \"function.h\"\n{SYSTEM_MACROS}{headers}{}",
            filter(source)
        ),
    )?;
    let text = run_output(
        Command::new("clang")
            .args(ctx.clang_flags(target))
            .arg("-I")
            .arg(ctx.abi.join("apps/include"))
            .args(["-E", "-P", "-x", "c"])
            .arg(&wrapper),
    )?;
    // Only what follows the wrapper's two includes: their own declarations are skipped by
    // marking where the source starts.
    Ok(text)
}

/// The filtered text of the headers of `dir` that `source` includes with quotes, and the
/// headers they include, each once.
fn local_headers(dir: &std::path::Path, source: &str, seen: &mut Vec<String>) -> Result<String> {
    let mut out = String::new();
    for line in source.lines() {
        let Some(rest) = line.trim_start().strip_prefix("#include \"") else {
            continue;
        };
        let Some((name, _)) = rest.split_once('"') else {
            continue;
        };
        let path = dir.join(name);
        if seen.iter().any(|s| s == name) || !path.is_file() {
            continue;
        }
        seen.push(name.to_owned());
        let text = fs::read_to_string(&path)?;
        out.push_str(&local_headers(dir, &text, seen)?);
        out.push_str(filter(&text).trim_start_matches("\nRUSTYSSL_SOURCE_STARTS\n"));
    }
    Ok(out)
}

/// `source` without its includes and function bodies: its preprocessor directives (but
/// `#include`, `#error`, `#pragma`, `#warning`), and its top-level `enum`s and `OPTIONS` and
/// `FUNCTION` arrays.
fn filter(source: &str) -> String {
    let mut out = String::new();
    let mut lines = source.lines();
    let mut in_block = false;
    let mut depth = 0i32;
    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        if let Some(directive) = trimmed.strip_prefix('#') {
            let word = directive.trim_start();
            let skip = ["include", "error", "pragma", "warning"]
                .iter()
                .any(|w| word.starts_with(w));
            let mut l = line;
            loop {
                if !skip {
                    out.push_str(l);
                    out.push('\n');
                }
                if !l.ends_with('\\') {
                    break;
                }
                match lines.next() {
                    Some(next) => l = next,
                    None => break,
                }
            }
            continue;
        }
        if !in_block {
            let starts = line.starts_with("typedef enum")
                || line.starts_with("enum")
                || line.starts_with("const OPTIONS ")
                || line.starts_with("FUNCTION functions[]");
            if !starts {
                continue;
            }
            in_block = true;
            depth = 0;
        }
        out.push_str(line);
        out.push('\n');
        let code = strip_strings(line);
        for c in code.chars() {
            match c {
                '{' => depth += 1,
                '}' => depth -= 1,
                _ => {}
            }
        }
        if depth <= 0 && code.contains(';') {
            in_block = false;
        }
    }
    format!("\nRUSTYSSL_SOURCE_STARTS\n{out}")
}

/// A line with its string and character literals and comments blanked, for brace counting.
fn strip_strings(line: &str) -> String {
    let mut out = String::new();
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' | '\'' => {
                while let Some(d) = chars.next() {
                    if d == '\\' {
                        chars.next();
                    } else if d == c {
                        break;
                    }
                }
            }
            '/' if chars.as_str().starts_with('/') => break,
            _ => out.push(c),
        }
    }
    out
}

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Ident(String),
    Number(i64),
    Str(String),
    Char(u8),
    Punct(char),
}

/// C tokens of preprocessed text after the source marker; adjacent string literals are joined.
fn tokens(text: &str) -> Result<Vec<Tok>> {
    let text = text
        .split_once("RUSTYSSL_SOURCE_STARTS")
        .map_or(text, |(_, rest)| rest);
    let bytes = text.as_bytes();
    let mut out: Vec<Tok> = Vec::new();
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b.is_ascii_whitespace() {
            i += 1;
        } else if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
            let end = text[i + 2..].find("*/").ok_or("unterminated comment")?;
            i += end + 4;
        } else if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
            i = text[i..].find('\n').map_or(bytes.len(), |e| i + e);
        } else if b.is_ascii_alphabetic() || b == b'_' {
            let start = i;
            while bytes
                .get(i)
                .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
            {
                i += 1;
            }
            out.push(Tok::Ident(text[start..i].to_owned()));
        } else if b.is_ascii_digit() {
            let start = i;
            while bytes.get(i).is_some_and(u8::is_ascii_alphanumeric) {
                i += 1;
            }
            let lit = text[start..i].trim_end_matches(['u', 'U', 'l', 'L']);
            let value = if let Some(hex) = lit.strip_prefix("0x").or(lit.strip_prefix("0X")) {
                i64::from_str_radix(hex, 16)?
            } else {
                lit.parse()?
            };
            out.push(Tok::Number(value));
        } else if b == b'"' {
            let (s, len) = c_literal(bytes.get(i..).unwrap_or_default(), b'"')?;
            i += len;
            if let Some(Tok::Str(prev)) = out.last_mut() {
                prev.push_str(&s);
            } else {
                out.push(Tok::Str(s));
            }
        } else if b == b'\'' {
            let (s, len) = c_literal(bytes.get(i..).unwrap_or_default(), b'\'')?;
            i += len;
            let &[c] = s.as_bytes() else {
                return Err(format!("bad character literal {s:?}").into());
            };
            out.push(Tok::Char(c));
        } else {
            out.push(Tok::Punct(char::from(b)));
            i += 1;
        }
    }
    Ok(out)
}

/// A C string or character literal at the start of `bytes`: its value and its length.
fn c_literal(bytes: &[u8], quote: u8) -> Result<(String, usize)> {
    let mut value = Vec::new();
    let mut i = 1;
    loop {
        let b = *bytes.get(i).ok_or("unterminated literal")?;
        i += 1;
        if b == quote {
            break;
        }
        if b != b'\\' {
            value.push(b);
            continue;
        }
        let e = *bytes.get(i).ok_or("unterminated escape")?;
        i += 1;
        value.push(match e {
            b'n' => b'\n',
            b't' => b'\t',
            b'r' => b'\r',
            b'0'..=b'7' => {
                let mut v = u32::from(e - b'0');
                for _ in 0..2 {
                    match bytes.get(i) {
                        Some(d @ b'0'..=b'7') => {
                            v = v * 8 + u32::from(d - b'0');
                            i += 1;
                        }
                        _ => break,
                    }
                }
                u8::try_from(v)?
            }
            b'\\' | b'"' | b'\'' | b'?' => e,
            _ => return Err(format!("unsupported escape \\{}", char::from(e)).into()),
        });
    }
    Ok((String::from_utf8(value)?, i))
}

/// Every `enum { ... }` in the tokens, as its constants and values in order.
fn parse_enums(toks: &[Tok]) -> Result<Vec<Vec<(String, i64)>>> {
    let mut enums = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        if toks.get(i) != Some(&Tok::Ident("enum".into())) {
            i += 1;
            continue;
        }
        i += 1;
        if matches!(toks.get(i), Some(Tok::Ident(_))) {
            i += 1;
        }
        if toks.get(i) != Some(&Tok::Punct('{')) {
            continue;
        }
        i += 1;
        let mut constants: Vec<(String, i64)> = Vec::new();
        let mut next = 0i64;
        let mut valid = true;
        while let Some(t) = toks.get(i) {
            match t {
                Tok::Punct('}') => break,
                Tok::Punct(',') => i += 1,
                Tok::Ident(name) => {
                    i += 1;
                    if toks.get(i) == Some(&Tok::Punct('=')) {
                        i += 1;
                        let mut sign = 1;
                        if toks.get(i) == Some(&Tok::Punct('-')) {
                            sign = -1;
                            i += 1;
                        }
                        match toks.get(i) {
                            Some(Tok::Number(n)) => next = sign * n,
                            Some(Tok::Ident(other)) => {
                                match constants.iter().find(|(c, _)| c == other) {
                                    Some((_, v)) => next = sign * v,
                                    None => valid = false,
                                }
                            }
                            _ => valid = false,
                        }
                        i += 1;
                        // Anything more complex than a literal or a constant: not an option
                        // enum.
                        while !matches!(toks.get(i), Some(Tok::Punct(',' | '}')) | None) {
                            valid = false;
                            i += 1;
                        }
                    }
                    constants.push((name.clone(), next));
                    next += 1;
                }
                _ => {
                    valid = false;
                    i += 1;
                }
            }
        }
        if valid {
            enums.push(constants);
        }
    }
    Ok(enums)
}

/// Every `const OPTIONS <name>[] = { ... };` in the tokens.
fn parse_arrays(toks: &[Tok]) -> Result<Vec<(String, Vec<Entry>)>> {
    let mut arrays = Vec::new();
    let mut i = 0;
    while i + 6 < toks.len() {
        let head = toks.get(i..i + 6).unwrap_or_default();
        let [
            Tok::Ident(c),
            Tok::Ident(o),
            Tok::Ident(name),
            Tok::Punct('['),
            Tok::Punct(']'),
            Tok::Punct('='),
        ] = head
        else {
            i += 1;
            continue;
        };
        if c != "const" || o != "OPTIONS" {
            i += 1;
            continue;
        }
        i += 6;
        let (groups, end) = brace_groups(toks, i)?;
        i = end;
        let mut entries = Vec::new();
        for group in groups {
            match entry(&group).map_err(|e| format!("{name}: {e} in {group:?}"))? {
                Some(e) => entries.push(e),
                None => break,
            }
        }
        arrays.push((name.clone(), entries));
    }
    Ok(arrays)
}

/// The `{ ... }` groups, split at top-level commas, of the initializer starting at `start`
/// (a `{`), and the index after it.
fn brace_groups(toks: &[Tok], start: usize) -> Result<(Vec<Vec<Vec<Tok>>>, usize)> {
    if toks.get(start) != Some(&Tok::Punct('{')) {
        return Err("expected an initializer".into());
    }
    let mut i = start + 1;
    let mut groups = Vec::new();
    loop {
        match toks.get(i) {
            Some(Tok::Punct('}')) => return Ok((groups, i + 1)),
            Some(Tok::Punct(',')) => i += 1,
            Some(Tok::Punct('{')) => {
                i += 1;
                let mut fields = vec![Vec::new()];
                let mut depth = 0;
                loop {
                    let t = toks.get(i).ok_or("unterminated initializer")?;
                    i += 1;
                    match t {
                        Tok::Punct('}') if depth == 0 => break,
                        Tok::Punct(',') if depth == 0 => fields.push(Vec::new()),
                        _ => {
                            match t {
                                Tok::Punct('(' | '{') => depth += 1,
                                Tok::Punct(')' | '}') => depth -= 1,
                                _ => {}
                            }
                            if let Some(f) = fields.last_mut() {
                                f.push(t.clone());
                            }
                        }
                    }
                }
                if fields.last().is_some_and(Vec::is_empty) {
                    fields.pop();
                }
                groups.push(fields);
            }
            other => return Err(format!("unexpected {other:?} in an initializer").into()),
        }
    }
}

/// Whether `field` is C's `NULL` (as the preprocessor leaves it) or `0`.
fn is_null(field: &[Tok]) -> bool {
    let idents: Vec<&Tok> = field
        .iter()
        .filter(|t| !matches!(t, Tok::Punct(_)))
        .collect();
    matches!(idents.as_slice(), [Tok::Ident(v), Tok::Number(0)] if v == "void")
        || matches!(idents.as_slice(), [Tok::Number(0)])
        || matches!(idents.as_slice(), [Tok::Ident(n)] if n == "NULL")
}

/// One `{ name, retval, valtype, help }`, or `None` for the terminating `{ NULL }`.
fn entry(fields: &[Vec<Tok>]) -> Result<Option<Entry>> {
    let first = fields.first().ok_or("an empty entry")?;
    let (name, marker) = match first.as_slice() {
        [Tok::Str(s)] => (s.clone(), None),
        [Tok::Ident(m)] if MARKERS.iter().any(|(c, _, _)| c == m) => {
            let (_, text, kind) = MARKERS.iter().find(|(c, _, _)| c == m).ok_or("marker")?;
            ((*text).to_owned(), Some(*kind))
        }
        f if is_null(f) => return Ok(None),
        f => return Err(format!("unexpected name {f:?}").into()),
    };
    let retval = match fields.get(1).map(Vec::as_slice) {
        Some([Tok::Ident(n)]) => Retval::Name(n.clone()),
        Some([Tok::Number(n)]) => Retval::Number(*n),
        Some([Tok::Punct('-'), Tok::Number(n)]) => Retval::Number(-*n),
        Some(
            [
                Tok::Punct('('),
                Tok::Punct('-'),
                Tok::Number(n),
                Tok::Punct(')'),
            ],
        ) => Retval::Number(-*n),
        other => return Err(format!("unexpected retval {other:?}").into()),
    };
    let valtype = match fields.get(2).map(Vec::as_slice) {
        Some([Tok::Char(c)]) => *c,
        Some([Tok::Number(n)]) => u8::try_from(*n)?,
        None => 0,
        other => return Err(format!("unexpected value type {other:?}").into()),
    };
    let help = match fields.get(3).map(Vec::as_slice) {
        Some([Tok::Str(s)]) => Some(s.clone()),
        Some(f) if is_null(f) => None,
        None => None,
        other => return Err(format!("unexpected help {other:?}").into()),
    };
    Ok(Some(Entry {
        name,
        marker,
        retval,
        valtype,
        help,
    }))
}

/// The enum an array's named retvals come from.
fn choose_enum(
    array: &str,
    entries: &[Entry],
    enums: &[Vec<(String, i64)>],
) -> Result<Vec<(String, i64)>> {
    let names: Vec<&String> = entries
        .iter()
        .filter_map(|e| match &e.retval {
            Retval::Name(n) => Some(n),
            Retval::Number(_) => None,
        })
        .collect();
    enums
        .iter()
        .find(|constants| names.iter().all(|n| constants.iter().any(|(c, _)| c == *n)))
        .cloned()
        .ok_or_else(|| format!("{array}: no enum declares all of its choices").into())
}

/// The shared groups' constants (without `__FIRST`/`__LAST`), from `opt.h`.
fn group_enums(ctx: &Context, target: &Target) -> Result<Vec<(String, Vec<String>)>> {
    let mut source = String::new();
    for (macro_name, _, _) in GROUPS {
        writeln!(source, "enum {{ {macro_name} }};")?;
    }
    let text = preprocess(ctx, target, &source, "groups")?;
    let enums = parse_enums(&tokens(&text)?)?;
    let mut out = Vec::new();
    for ((_, prefix, rust), constants) in GROUPS.iter().zip(enums) {
        let names = constants
            .iter()
            .map(|(c, _)| c.strip_prefix(prefix).unwrap_or(c).to_owned())
            .filter(|c| !c.starts_with('_'))
            .collect();
        out.push(((*rust).to_owned(), names));
    }
    Ok(out)
}

/// A constant's variant: `OPT_V_POLICY` -> `OPT_V(V::POLICY)`, `OPT_FOO` -> `FOO`. A
/// constant is in a group only if `opt.h`'s group declares it (`s_server`'s own
/// `OPT_S_NUM_TICKETS` isn't in `OPT_S_ENUM`).
fn variant(constant: &str, groups: &[(String, Vec<String>)]) -> String {
    match group_of(constant, groups) {
        Some((rust, rest)) => {
            format!("OPT_{}({rust}::{})", rust.to_ascii_uppercase(), ident(rest))
        }
        None => ident(constant.strip_prefix("OPT_").unwrap_or(constant)),
    }
}

/// The group a constant belongs to, and its name in the group.
fn group_of<'a>(
    constant: &'a str,
    groups: &'a [(String, Vec<String>)],
) -> Option<(&'a str, &'a str)> {
    for ((_, prefix, rust), (_, names)) in GROUPS.iter().zip(groups) {
        if let Some(rest) = constant.strip_prefix(prefix)
            && names.iter().any(|n| n == rest)
        {
            return Some((rust, rest));
        }
    }
    None
}

/// A Rust identifier for a C name's rest (one starting with a digit gets an underscore).
fn ident(rest: &str) -> String {
    if rest.starts_with(|c: char| c.is_ascii_digit()) {
        format!("_{rest}")
    } else {
        rest.to_owned()
    }
}

fn render_rust(
    functions: &[Function],
    tables: &Tables,
    groups: &[(String, Vec<String>)],
) -> Result<String> {
    let mut out = format!(
        "// Generated by `cargo xtask codegen` from abi/openssl-{OPENSSL_SERIES}/apps/*.c (the \
         command sources,\n// vendored as a specification) and its progs.c. Do not edit.\n//\n\
         // Each command's option table and choice enum, as upstream's build evaluates them \
         (ADR 0007, section 3).\n\n\
         #![allow(non_camel_case_types, clippy::upper_case_acronyms, \
         clippy::enum_variant_names, dead_code)]\n\n\
         use crate::lib::opt::{{Choice, Marker, OptDef}};\n\n"
    );
    for (name, constants) in groups {
        writeln!(
            out,
            "/// The shared `{name}` options of `opt.h`.\n\
             #[derive(Clone, Copy, PartialEq, Eq, Debug)]\npub enum {name} {{"
        )?;
        for c in constants {
            writeln!(out, "    {},", ident(c))?;
        }
        out.push_str("}\n\n");
    }

    for (array, (entries, constants)) in tables {
        let module = array.strip_suffix("_options").unwrap_or(array);
        writeln!(
            out,
            "/// `{array}`.\npub mod {module} {{\n    use super::*;\n"
        )?;
        // Variants: the enum's constants, the groups once each.
        let mut variants: Vec<String> = Vec::new();
        for (c, _) in constants {
            if c.contains("__") {
                continue;
            }
            let v = match group_of(c, groups) {
                Some((rust, _)) => format!("OPT_{}({rust})", rust.to_ascii_uppercase()),
                None => variant(c, groups),
            };
            if !variants.contains(&v) {
                variants.push(v);
            }
        }
        out.push_str("    #[derive(Clone, Copy, PartialEq, Eq, Debug)]\n    pub enum Opt {\n");
        for v in &variants {
            writeln!(out, "        {v},")?;
        }
        out.push_str("    }\n\n");
        let by_value = |n: i64| -> Option<String> {
            constants
                .iter()
                .filter(|(c, _)| !c.contains("__"))
                .find(|(_, v)| *v == n)
                .map(|(c, _)| variant(c, groups))
        };
        let err = by_value(-1).ok_or_else(|| format!("{array}: no choice is -1 (OPT_ERR)"))?;
        let eof = by_value(0).ok_or_else(|| format!("{array}: no choice is 0 (OPT_EOF)"))?;
        writeln!(
            out,
            "    impl Choice for Opt {{\n        const ERR: Self = Opt::{err};\n        \
             const EOF: Self = Opt::{eof};\n    }}\n"
        )?;
        out.push_str("    pub static OPTIONS: &[OptDef<Opt>] = &[\n");
        for e in entries {
            let ret = match &e.retval {
                Retval::Name(n) => format!("Some(Opt::{})", variant(n, groups)),
                Retval::Number(-2) => "None".to_owned(),
                Retval::Number(n) => match by_value(*n) {
                    Some(v) => format!("Some(Opt::{v})"),
                    None => return Err(format!("{array}: no choice has value {n}").into()),
                },
            };
            let marker = match e.marker {
                Some(m) => format!("Some(Marker::{m})"),
                None => "None".to_owned(),
            };
            let help = match &e.help {
                Some(h) => format!("Some({h:?})"),
                None => "None".to_owned(),
            };
            writeln!(
                out,
                "        OptDef {{ name: {:?}, marker: {marker}, ret: {ret}, valtype: {}, help: {help} }},",
                e.name,
                valtype(e.valtype)
            )?;
        }
        out.push_str("    ];\n}\n\n");
    }

    out.push_str(
        "/// For a command not ported yet: prints the help of table `module` if `argv` asks for it \
         first\n/// (see `crate::lib::opt::help_only`), and returns whether it did; `None` for no \
         such table.\n\
         pub fn help_only(module: &str, argv: &[String]) -> Option<bool> {\n    match module {\n",
    );
    for array in tables.keys() {
        let module = array.strip_suffix("_options").unwrap_or(array);
        writeln!(
            out,
            "        {module:?} => Some(crate::lib::opt::help_only(argv, {module}::OPTIONS)),"
        )?;
    }
    out.push_str("        _ => None,\n    }\n}\n\n");
    out.push_str(
        "/// A command of `progs.c`, in its order.\n\
         pub struct Function {\n    pub kind: FuncType,\n    pub name: &'static str,\n    \
         /// The option table's module (`None` for the digest commands, which have none).\n    \
         pub options: Option<&'static str>,\n    \
         pub deprecated_alternative: Option<&'static str>,\n    \
         pub deprecated_version: Option<&'static str>,\n}\n\n\
         /// `FUNC_TYPE` of `function.h`.\n\
         #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]\n\
         pub enum FuncType {\n    None,\n    General,\n    Md,\n    Cipher,\n    Pkey,\n    MdAlg,\n    CipherAlg,\n}\n\n\
         /// `functions[]` of `progs.c`, as the target's configuration builds it.\n\
         pub static FUNCTIONS: &[Function] = &[\n",
    );
    for f in functions {
        let kind = match f.kind.as_str() {
            "FT_general" => "General",
            "FT_md" => "Md",
            "FT_cipher" => "Cipher",
            "FT_pkey" => "Pkey",
            "FT_md_alg" => "MdAlg",
            "FT_cipher_alg" => "CipherAlg",
            other => return Err(format!("unknown function type {other}").into()),
        };
        let opt = |s: &Option<String>| match s {
            Some(s) => format!("Some({s:?})"),
            None => "None".to_owned(),
        };
        let module = f
            .options
            .as_ref()
            .map(|o| o.strip_suffix("_options").unwrap_or(o).to_owned());
        writeln!(
            out,
            "    Function {{ kind: FuncType::{kind}, name: {:?}, options: {}, deprecated_alternative: {}, deprecated_version: {} }},",
            f.name,
            opt(&module),
            opt(&f.deprecated_alternative),
            opt(&f.deprecated_version)
        )?;
    }
    out.push_str("];\n");
    Ok(out)
}

/// A value type as Rust: `b'x'` for a character, the number otherwise (`0`, or `1` in some
/// continuation lines).
fn valtype(v: u8) -> String {
    if v.is_ascii_graphic() {
        format!("b{:?}", char::from(v))
    } else {
        v.to_string()
    }
}

/// `FUNCTION functions[] = { ... };` of `progs.c`.
fn parse_functions(toks: &[Tok]) -> Result<Vec<Function>> {
    let start = toks
        .windows(5)
        .position(|w| {
            matches!(w, [Tok::Ident(t), Tok::Ident(n), Tok::Punct('['), Tok::Punct(']'), Tok::Punct('=')]
                if t == "FUNCTION" && n == "functions")
        })
        .ok_or("progs.c has no functions[]")?;
    let (groups, _) = brace_groups(toks, start + 5)?;
    let mut out = Vec::new();
    for fields in groups {
        let field = |i: usize| fields.get(i).map(Vec::as_slice);
        let Some([Tok::Ident(kind)]) = field(0) else {
            break; // the terminating { 0, NULL, ... }
        };
        let Some([Tok::Str(name)]) = field(1) else {
            return Err(format!("progs.c: bad entry {fields:?}").into());
        };
        let ident_or_null = |i: usize| -> Result<Option<String>> {
            match field(i) {
                Some([Tok::Ident(s)]) => Ok(Some(s.clone())),
                Some([Tok::Str(s)]) => Ok(Some(s.clone())),
                Some(f) if is_null(f) => Ok(None),
                None => Ok(None),
                Some(f) => Err(format!("progs.c: bad field {f:?}").into()),
            }
        };
        out.push(Function {
            kind: kind.clone(),
            name: name.clone(),
            options: ident_or_null(3)?,
            deprecated_alternative: ident_or_null(4)?,
            deprecated_version: ident_or_null(5)?,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filtering_keeps_directives_enums_and_arrays() {
        let src = "#include <x.h>\n#ifndef A\nstatic int f(void) { return 1; }\ntypedef enum OPTION_choice {\n    OPT_COMMON, OPT_X\n} OPTION_CHOICE;\n\
                   const OPTIONS x_options[] = {\n    { \"x\", OPT_X, '-', \"a } brace\" },\n    { NULL }\n};\nint main(void) { }\n#endif\n";
        let f = filter(src);
        assert!(!f.contains("include"));
        assert!(!f.contains("return 1"));
        assert!(!f.contains("main"));
        assert!(f.contains("#ifndef A\n"));
        assert!(f.contains("OPT_COMMON, OPT_X"));
        assert!(f.contains("{ NULL }\n};\n#endif"));
    }

    #[test]
    fn entries_and_enums_parse() {
        let toks = tokens(
            "RUSTYSSL_SOURCE_STARTS enum E { OPT_ERR = -1, OPT_EOF = 0, OPT_HELP, OPT_V__FIRST = 2000, OPT_V_POLICY };\n\
             const OPTIONS x_options[] = { { OPT_HELP_STR, 1, '-', \"Usage: %s\\n\" }, \
             { \"help\", OPT_HELP, '-', \"Display\" \" this\" }, { \"p\", OPT_V_POLICY, 's', ((void*)0) }, \
             { \"d\", -2, 's', \"dup\" }, { ((void*)0) } };",
        )
        .unwrap();
        let enums = parse_enums(&toks).unwrap();
        assert_eq!(
            enums[0],
            [
                ("OPT_ERR", -1),
                ("OPT_EOF", 0),
                ("OPT_HELP", 1),
                ("OPT_V__FIRST", 2000),
                ("OPT_V_POLICY", 2001)
            ]
            .map(|(n, v)| (n.to_owned(), v))
        );
        let arrays = parse_arrays(&toks).unwrap();
        let (name, entries) = &arrays[0];
        assert_eq!(name, "x_options");
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].marker, Some("Help"));
        assert_eq!(entries[0].name, "-H");
        assert_eq!(entries[1].help.as_deref(), Some("Display this"));
        assert_eq!(entries[2].help, None);
        assert_eq!(entries[3].retval, Retval::Number(-2));
        let groups: Vec<(String, Vec<String>)> = ["V", "X", "S", "R", "Prov"]
            .iter()
            .map(|g| {
                let names = match *g {
                    "V" => vec!["POLICY".to_owned()],
                    "Prov" => vec!["PROVIDER".to_owned()],
                    _ => vec![],
                };
                ((*g).to_owned(), names)
            })
            .collect();
        assert_eq!(variant("OPT_V_POLICY", &groups), "OPT_V(V::POLICY)");
        assert_eq!(
            variant("OPT_PROV_PROVIDER", &groups),
            "OPT_PROV(Prov::PROVIDER)"
        );
        assert_eq!(variant("OPT_S_NUM_TICKETS", &groups), "S_NUM_TICKETS");
        assert_eq!(variant("OPT_3DES", &groups), "_3DES");
    }
}
