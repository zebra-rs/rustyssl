//! `cargo xtask unsafe-audit [--bless]`: the `unsafe` budget (README.md, security rule 1).
//!
//! It reads every Rust source of the crates that may hold `unsafe` (`rustyssl-capi`,
//! `rustyssl-ossl`, and `libs/*`), counts the `unsafe` sites per module, and compares the counts
//! with `docs/security/unsafe-budget.txt`. A module whose count grew, or a new module, fails the
//! command until the budget is updated with `--bless`, so growth is a reviewed change in the
//! diff. Every other crate must carry `#![forbid(unsafe_code)]`.
//!
//! It also checks security rule 3: every export written by hand (an `extern "C"` function with
//! `no_mangle` or `export_name`, outside `src/generated/`) runs its body under the panic guard,
//! through `ffi_export!` or by calling `guard` or `catch_unwind` itself. Internal callbacks (the
//! functions handed to C as pointers: stack free functions, method tables, trampolines) may run
//! unguarded: a panic there can't unwind into C, since Rust aborts the process when a panic
//! reaches an `extern "C"` frame. Their number per module is part of the budget, so a new one is
//! a reviewed change too.
//!
//! The counts are lexical: comments, strings and character literals are skipped, and a function
//! pointer type (`unsafe extern "C" fn(...)`) is not a definition.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use crate::util::{Result, workspace_root};

const BUDGET: &str = "docs/security/unsafe-budget.txt";
const USAGE: &str = "usage: cargo xtask unsafe-audit [--bless]";

/// The source directories where `unsafe` is allowed (README.md, security rule 1).
const UNSAFE_CRATES: &[&str] = &[
    "crates/rustyssl-capi/src",
    "crates/rustyssl-ossl/src",
    "libs/libcrypto/src",
    "libs/libssl/src",
];

pub fn run(args: &[String]) -> Result {
    let bless = match args {
        [] => false,
        [flag] if flag == "--bless" => true,
        _ => return Err(USAGE.into()),
    };
    let root = workspace_root();
    let mut problems = Vec::new();
    forbid_elsewhere(&root, &mut problems)?;

    let mut counts: BTreeMap<String, Counts> = BTreeMap::new();
    for dir in UNSAFE_CRATES {
        let base = root.join(dir);
        for file in rust_files(&base)? {
            let text = fs::read_to_string(&file)?;
            let rel = relative(&root, &file);
            let tokens = lex(&text).map_err(|e| format!("{rel}: {e}"))?;
            let generated = rel.contains("/generated/");
            let group = group_of(dir, &relative(&base, &file), generated);
            let mut c = count(&tokens);
            if !generated {
                for (name, exported) in unguarded(&tokens) {
                    if exported {
                        problems.push(format!(
                            "{rel}: the export `{name}` runs without the panic guard \
                             (use ffi_export!, or call guard)"
                        ));
                    } else {
                        c.callbacks += 1;
                    }
                }
            }
            counts.entry(group).or_default().add(&c);
        }
    }

    let report = render(&counts);
    let path = root.join(BUDGET);
    if bless {
        fs::create_dir_all(path.parent().ok_or("no parent")?)?;
        fs::write(&path, &report)?;
        println!("wrote {BUDGET}");
    } else {
        let budget = fs::read_to_string(&path)
            .map_err(|e| format!("{BUDGET}: {e} (run `cargo xtask unsafe-audit --bless`)"))?;
        compare(&parse_budget(&budget)?, &counts, &mut problems);
    }
    let total = counts.values().fold(Counts::default(), |mut a, c| {
        a.add(c);
        a
    });
    println!(
        "unsafe sites: {} blocks, {} functions, {} impls, {} extern blocks, and {} unguarded \
         callbacks, in {} modules",
        total.blocks,
        total.fns,
        total.impls,
        total.externs,
        total.callbacks,
        counts.len()
    );
    if problems.is_empty() {
        println!("the unsafe budget holds, and every hand-written export is guarded");
        Ok(())
    } else {
        for p in &problems {
            println!("FAIL {p}");
        }
        Err(format!("{} problem(s)", problems.len()).into())
    }
}

/// Every crate but the unsafe ones forbids `unsafe` at its root.
fn forbid_elsewhere(root: &Path, problems: &mut Vec<String>) -> Result {
    let mut crates: Vec<PathBuf> = fs::read_dir(root.join("crates"))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.join("Cargo.toml").is_file())
        .collect();
    crates.push(root.join("xtask"));
    crates.sort();
    for c in crates {
        let rel = relative(root, &c);
        if UNSAFE_CRATES
            .iter()
            .any(|u| u.starts_with(&format!("{rel}/")))
        {
            continue;
        }
        for top in ["src/lib.rs", "src/main.rs"] {
            let f = c.join(top);
            if f.is_file() && !fs::read_to_string(&f)?.contains("#![forbid(unsafe_code)]") {
                problems.push(format!("{rel}/{top}: no #![forbid(unsafe_code)]"));
            }
        }
    }
    Ok(())
}

fn rust_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d)? {
            let p = e?.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}

fn relative(base: &Path, path: &Path) -> String {
    path.strip_prefix(base)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// The budget's module: the crate and the first component under `src/` (a file's stem or a
/// directory), with generated code kept apart.
fn group_of(dir: &str, rel: &str, generated: bool) -> String {
    let krate = dir.trim_end_matches("/src");
    let first = rel.split('/').next().unwrap_or(rel).trim_end_matches(".rs");
    if generated {
        format!("{krate}/generated")
    } else {
        format!("{krate}/{first}")
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
struct Counts {
    blocks: u64,
    fns: u64,
    impls: u64,
    externs: u64,
    /// Hand-written `extern "C"` callbacks without the panic guard.
    callbacks: u64,
}

impl Counts {
    fn add(&mut self, o: &Counts) {
        self.blocks += o.blocks;
        self.fns += o.fns;
        self.impls += o.impls;
        self.externs += o.externs;
        self.callbacks += o.callbacks;
    }
}

fn render(counts: &BTreeMap<String, Counts>) -> String {
    let mut s = String::from(
        "# The unsafe budget: `cargo xtask unsafe-audit` fails when a module's count grows.\n\
         # Update it with `cargo xtask unsafe-audit --bless` and review the diff.\n\
         # module  unsafe-blocks  unsafe-fns  unsafe-impls  extern-blocks  unguarded-callbacks\n",
    );
    for (g, c) in counts {
        let _ = writeln!(
            s,
            "{g} {} {} {} {} {}",
            c.blocks, c.fns, c.impls, c.externs, c.callbacks
        );
    }
    s
}

fn parse_budget(text: &str) -> Result<BTreeMap<String, Counts>> {
    let mut out = BTreeMap::new();
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
    {
        let f: Vec<&str> = line.split_whitespace().collect();
        let [g, b, fns, i, e, cb] = f.as_slice() else {
            return Err(format!("{BUDGET}: bad line `{line}`").into());
        };
        let n = |s: &str| {
            s.parse::<u64>()
                .map_err(|e| format!("{BUDGET}: `{line}`: {e}"))
        };
        out.insert(
            (*g).to_string(),
            Counts {
                blocks: n(b)?,
                fns: n(fns)?,
                impls: n(i)?,
                externs: n(e)?,
                callbacks: n(cb)?,
            },
        );
    }
    Ok(out)
}

fn compare(
    budget: &BTreeMap<String, Counts>,
    now: &BTreeMap<String, Counts>,
    problems: &mut Vec<String>,
) {
    let mut shrank = 0;
    for (g, c) in now {
        match budget.get(g) {
            None => problems.push(format!(
                "{g}: a new module with unsafe code, not in {BUDGET}"
            )),
            Some(b) => {
                for (what, n, m) in [
                    ("unsafe blocks", c.blocks, b.blocks),
                    ("unsafe fns", c.fns, b.fns),
                    ("unsafe impls", c.impls, b.impls),
                    ("extern blocks", c.externs, b.externs),
                    ("unguarded callbacks", c.callbacks, b.callbacks),
                ] {
                    if n > m {
                        problems.push(format!("{g}: {n} {what}, over its budget of {m}"));
                    } else if n < m {
                        shrank += 1;
                    }
                }
            }
        }
    }
    if shrank > 0 {
        println!("{shrank} count(s) are under budget; `--bless` lowers the budget to match");
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Punct(char),
    Lit,
}

/// Rust's tokens, without comments, as far as counting `unsafe` needs.
fn lex(src: &str) -> std::result::Result<Vec<Tok>, String> {
    let s: Vec<char> = src.chars().collect();
    let at = |i: usize| s.get(i).copied().unwrap_or('\0');
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let c = at(i);
        if c.is_whitespace() {
            i += 1;
        } else if c == '/' && at(i + 1) == '/' {
            while i < s.len() && at(i) != '\n' {
                i += 1;
            }
        } else if c == '/' && at(i + 1) == '*' {
            let mut depth = 0;
            loop {
                if i >= s.len() {
                    return Err("an unterminated block comment".into());
                }
                if at(i) == '/' && at(i + 1) == '*' {
                    depth += 1;
                    i += 2;
                } else if at(i) == '*' && at(i + 1) == '/' {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
        } else if let Some(end) = raw_string(&s, i) {
            out.push(Tok::Lit);
            i = end;
        } else if c == '"' || ((c == 'b' || c == 'c') && at(i + 1) == '"') {
            i += if c == '"' { 1 } else { 2 };
            while i < s.len() && at(i) != '"' {
                i += if at(i) == '\\' { 2 } else { 1 };
            }
            i += 1;
            out.push(Tok::Lit);
        } else if c == '\'' || (c == 'b' && at(i + 1) == '\'') {
            let q = if c == 'b' { i + 1 } else { i };
            if at(q + 1) == '\\' {
                let mut j = q + 2;
                while j < s.len() && at(j) != '\'' {
                    j += 1;
                }
                i = j + 1;
                out.push(Tok::Lit);
            } else if at(q + 2) == '\'' {
                i = q + 3;
                out.push(Tok::Lit);
            } else {
                // A lifetime or a label.
                i = q + 1;
                while i < s.len() && (at(i).is_alphanumeric() || at(i) == '_') {
                    i += 1;
                }
            }
        } else if c == 'r' && at(i + 1) == '#' && (at(i + 2).is_alphabetic() || at(i + 2) == '_') {
            let start = i + 2;
            i = start;
            while i < s.len() && (at(i).is_alphanumeric() || at(i) == '_') {
                i += 1;
            }
            out.push(Tok::Ident(
                s.get(start..i).unwrap_or_default().iter().collect(),
            ));
        } else if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < s.len() && (at(i).is_alphanumeric() || at(i) == '_') {
                i += 1;
            }
            out.push(Tok::Ident(
                s.get(start..i).unwrap_or_default().iter().collect(),
            ));
        } else if c.is_ascii_digit() {
            while i < s.len() && (at(i).is_alphanumeric() || at(i) == '_') {
                i += 1;
            }
            out.push(Tok::Lit);
        } else {
            out.push(Tok::Punct(c));
            i += 1;
        }
    }
    Ok(out)
}

/// The end of a raw string (`r"..."`, `br#"..."#`, `cr##"..."##`) starting at `i`.
fn raw_string(s: &[char], i: usize) -> Option<usize> {
    let at = |k: usize| s.get(k).copied().unwrap_or('\0');
    let mut j = i;
    if at(j) == 'b' || at(j) == 'c' {
        j += 1;
    }
    if at(j) != 'r' {
        return None;
    }
    j += 1;
    let mut hashes = 0;
    while at(j) == '#' {
        hashes += 1;
        j += 1;
    }
    if at(j) != '"' {
        return None;
    }
    j += 1;
    loop {
        if j >= s.len() {
            return Some(j);
        }
        if at(j) == '"' && (1..=hashes).all(|k| at(j + k) == '#') {
            return Some(j + 1 + hashes);
        }
        j += 1;
    }
}

fn is(t: Option<&Tok>, word: &str) -> bool {
    matches!(t, Some(Tok::Ident(w)) if w == word)
}

fn is_punct(t: Option<&Tok>, c: char) -> bool {
    t == Some(&Tok::Punct(c))
}

/// After `extern` at `i`, the index past an optional ABI string.
fn skip_abi(t: &[Tok], i: usize) -> usize {
    if t.get(i) == Some(&Tok::Lit) {
        i + 1
    } else {
        i
    }
}

fn count(t: &[Tok]) -> Counts {
    let mut c = Counts::default();
    for i in 0..t.len() {
        if is(t.get(i), "unsafe") {
            let next = t.get(i + 1);
            if is_punct(next, '{') {
                c.blocks += 1;
            } else if is(next, "impl") || is(next, "trait") {
                c.impls += 1;
            } else if is(next, "fn") && matches!(t.get(i + 2), Some(Tok::Ident(_))) {
                c.fns += 1;
            } else if is(next, "extern") {
                let j = skip_abi(t, i + 2);
                if is(t.get(j), "fn") && matches!(t.get(j + 1), Some(Tok::Ident(_))) {
                    c.fns += 1;
                }
            }
        }
        if is(t.get(i), "extern") && is_punct(t.get(skip_abi(t, i + 1)), '{') {
            c.externs += 1;
        }
    }
    c
}

/// The hand-written `extern "ABI" fn` definitions whose bodies don't run under the guard, and
/// whether each is exported (`no_mangle` or `export_name` among its attributes).
fn unguarded(t: &[Tok]) -> Vec<(String, bool)> {
    // The token ranges of `ffi_export! { ... }` and `ffi_callback! { ... }` invocations.
    let mut wrapped: Vec<(usize, usize)> = Vec::new();
    for i in 0..t.len() {
        if (is(t.get(i), "ffi_export") || is(t.get(i), "ffi_callback"))
            && is_punct(t.get(i + 1), '!')
            && let Some(end) = matching(t, i + 2)
        {
            wrapped.push((i, end));
        }
    }
    let mut out = Vec::new();
    for i in 0..t.len() {
        if !is(t.get(i), "extern") || !matches!(t.get(i + 1), Some(Tok::Lit)) {
            continue;
        }
        let j = i + 2;
        let Some(Tok::Ident(name)) = t.get(j + 1) else {
            continue;
        };
        if !is(t.get(j), "fn") || wrapped.iter().any(|(a, b)| (*a..=*b).contains(&i)) {
            continue;
        }
        // The body: the first `{` after the signature (or `;` for a declaration).
        let Some(open) = (j..t.len()).find(|&k| is_punct(t.get(k), '{') || is_punct(t.get(k), ';'))
        else {
            continue;
        };
        if is_punct(t.get(open), ';') {
            continue;
        }
        let Some(close) = matching(t, open) else {
            continue;
        };
        let body = t.get(open..close).unwrap_or_default();
        let guarded = body.windows(2).any(|w| {
            (is(w.first(), "guard") || is(w.first(), "catch_unwind")) && is_punct(w.get(1), '(')
        });
        if !guarded {
            // The item's start: after the previous item's `;` or `}`.
            let start = (0..i)
                .rev()
                .find(|&k| is_punct(t.get(k), ';') || is_punct(t.get(k), '}'))
                .map_or(0, |k| k + 1);
            let exported =
                t.get(start..i).unwrap_or_default().iter().any(
                    |tok| matches!(tok, Tok::Ident(w) if w == "no_mangle" || w == "export_name"),
                );
            out.push((name.clone(), exported));
        }
    }
    out
}

/// The index of the bracket closing the one at `open` (`{`, `(` or `[`).
fn matching(t: &[Tok], open: usize) -> Option<usize> {
    let (o, c) = match t.get(open)? {
        Tok::Punct('{') => ('{', '}'),
        Tok::Punct('(') => ('(', ')'),
        Tok::Punct('[') => ('[', ']'),
        _ => return None,
    };
    let mut depth = 0usize;
    for (k, tok) in t.iter().enumerate().skip(open) {
        if *tok == Tok::Punct(o) {
            depth += 1;
        } else if *tok == Tok::Punct(c) {
            depth -= 1;
            if depth == 0 {
                return Some(k);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counts(src: &str) -> Counts {
        count(&lex(src).unwrap())
    }

    #[test]
    fn counts_definitions_not_types_comments_or_strings() {
        let c = counts(
            r##"
            // unsafe { in a comment }
            /* unsafe fn nested /* unsafe { */ */
            const S: &str = "unsafe { in a string }";
            const R: &str = r#"unsafe fn x() {}"#;
            type Cb = Option<unsafe extern "C" fn(c_int) -> c_int>;
            unsafe fn a() {}
            pub unsafe extern "C" fn b() { unsafe { x() } }
            unsafe impl Send for T {}
            unsafe extern "C" { fn f(); }
            fn l<'a>(x: &'a u8) -> char { let _ = '{'; unsafe { y() }; 'x' }
            "##,
        );
        assert_eq!(
            c,
            Counts {
                blocks: 2,
                fns: 2,
                impls: 1,
                externs: 1,
                callbacks: 0
            }
        );
    }

    #[test]
    fn finds_unguarded_exports() {
        let t = lex(r#"
            ffi_export! { pub unsafe extern "C" fn A() -> c_int where failure = 0, library = L { 1 } }
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn B(x: c_int) -> c_int { guard(L, "B", || 0, || x) }
            pub unsafe extern "C" fn C() -> c_int { 1 }
            unsafe extern "C" { fn D(); }
            type E = unsafe extern "C" fn();
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn F() -> c_int { 1 }
            "#)
        .unwrap();
        assert_eq!(
            unguarded(&t),
            vec![("C".to_string(), false), ("F".to_string(), true)]
        );
    }
}
