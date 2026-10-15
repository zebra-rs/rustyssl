//! Generates the named-curve table for `rustyssl-crypto`
//! (`crates/rustyssl-crypto/src/generated/curves.rs`) from the vendored
//! `crypto/ec/ec_curve.c` (each curve's parameters, its method, and its comment, in
//! `EC_get_builtin_curves` order) and `crypto/evp/ec_support.c` (the curves' names and NIST
//! names).
//!
//! `ec_curve.c` chooses between curve lists and methods with preprocessor conditions. clang
//! resolves them as OpenSSL's default build does (`FIPS_MODULE` and every `OPENSSL_NO_*`
//! undefined, so binary curves, SM2, and `enable-ec_nistp_64_gcc_128`'s methods are in), with
//! each architecture's assembler definitions from `crypto/ec/build.info`; where those give a
//! curve different methods, the table says which per architecture. The `#include` lines are
//! dropped first, so the `NID_*` names stay names, resolved here through the constants clang
//! evaluated from the headers.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::process::Command;

use super::abi::Constants;
use super::headers::{Context, write_rust};
use crate::util::{Result, run_output};

/// The architectures rustyssl targets, with the definitions `crypto/ec/build.info` gives
/// their assembler (`$ECDEF_x86_64`, `$ECDEF_aarch64`).
const ARCHES: &[(&str, &[&str])] = &[
    ("x86_64", &["ECP_NISTZ256_ASM"]),
    ("aarch64", &["ECP_NISTZ256_ASM", "ECP_SM2P256_ASM"]),
];

/// One curve's data block (`EC_CURVE_DATA` and its octets).
struct Data {
    field: String,
    seed_len: usize,
    param_len: usize,
    cofactor: u32,
    octets: Vec<u8>,
}

/// One `curve_list` entry.
struct Entry {
    nid: String,
    data: String,
    method: String,
    comment: String,
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    Number(String),
    Str(String),
    Punct(char),
}

fn tokenize(text: &str) -> Result<Vec<Token>> {
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
        } else if c.is_ascii_alphabetic() || c == '_' {
            let mut s = String::new();
            while let Some(&c) = chars
                .peek()
                .filter(|c| c.is_ascii_alphanumeric() || **c == '_')
            {
                s.push(c);
                chars.next();
            }
            out.push(Token::Ident(s));
        } else if c.is_ascii_digit() {
            let mut s = String::new();
            while let Some(&c) = chars.peek().filter(|c| c.is_ascii_alphanumeric()) {
                s.push(c);
                chars.next();
            }
            out.push(Token::Number(s));
        } else if c == '"' {
            chars.next();
            let mut s = String::new();
            loop {
                match chars.next() {
                    Some('"') => break,
                    Some('\\') => {
                        let e = chars.next().ok_or("an unfinished escape")?;
                        s.push(e);
                    }
                    Some(c) => s.push(c),
                    None => return Err("an unfinished string".into()),
                }
            }
            // Adjacent literals are one string.
            if let Some(Token::Str(prev)) = out.last_mut() {
                prev.push_str(&s);
            } else {
                out.push(Token::Str(s));
            }
        } else {
            out.push(Token::Punct(c));
            chars.next();
        }
    }
    Ok(out)
}

fn number(s: &str) -> Result<u64> {
    let t = s.trim_end_matches(['u', 'U', 'l', 'L']);
    Ok(
        match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
            Some(hex) => u64::from_str_radix(hex, 16)?,
            None => t.parse()?,
        },
    )
}

/// `ec_curve.c` preprocessed with `defines`, its `#include` lines dropped.
fn preprocess(ctx: &Context, source: &str, defines: &[&str]) -> Result<String> {
    let stripped: String = source
        .lines()
        .filter(|l| !l.trim_start().starts_with("#include"))
        .map(|l| format!("{l}\n"))
        .collect();
    let input = ctx.work.join("ec_curve.c");
    fs::write(&input, stripped)?;
    let mut cmd = Command::new("clang");
    cmd.args(["-E", "-P", "-x", "c"]);
    for d in defines {
        cmd.arg(format!("-D{d}"));
    }
    cmd.arg(&input);
    run_output(&mut cmd)
}

/// The data blocks: `} NAME = { { field, seed_len, param_len, cofactor }, { octets } };`.
fn data_blocks(tokens: &[Token]) -> Result<BTreeMap<String, Data>> {
    let mut blocks = BTreeMap::new();
    let mut i = 0;
    while i < tokens.len() {
        let name = match tokens.get(i..i + 5) {
            Some(
                [
                    Token::Punct('}'),
                    Token::Ident(n),
                    Token::Punct('='),
                    Token::Punct('{'),
                    Token::Punct('{'),
                ],
            ) if n.starts_with("_EC_") => n.clone(),
            _ => {
                i += 1;
                continue;
            }
        };
        let mut j = i + 5;
        let mut header = Vec::new();
        loop {
            match tokens.get(j) {
                Some(Token::Punct('}')) => break,
                Some(Token::Ident(s) | Token::Number(s)) => header.push(s.clone()),
                Some(Token::Punct(',')) => {}
                other => return Err(format!("{name}: unexpected {other:?} in its header").into()),
            }
            j += 1;
        }
        let [field, seed_len, param_len, cofactor] = header.as_slice() else {
            return Err(format!("{name}: a header of {} fields", header.len()).into());
        };
        // `}`, `,`, `{`, then the octets up to `}`.
        j += 3;
        let mut octets = Vec::new();
        loop {
            match tokens.get(j) {
                Some(Token::Punct('}')) => break,
                Some(Token::Number(n)) => octets.push(u8::try_from(number(n)?)?),
                Some(Token::Punct(',')) => {}
                other => return Err(format!("{name}: unexpected {other:?} in its data").into()),
            }
            j += 1;
        }
        let data = Data {
            field: field.clone(),
            seed_len: usize::try_from(number(seed_len)?)?,
            param_len: usize::try_from(number(param_len)?)?,
            cofactor: u32::try_from(number(cofactor)?)?,
            octets,
        };
        // P-256's block has Montgomery constants after the six parameters ("RR for prime",
        // "RR for order"), which OpenSSL's generic code never reads.
        if data.octets.len() < data.seed_len + 6 * data.param_len {
            return Err(format!("{name}: {} octets", data.octets.len()).into());
        }
        blocks.insert(name, data);
        i = j;
    }
    Ok(blocks)
}

/// The tokens of the initializer of the array `name` (`name [ ] = { ... }`), without the
/// outer braces.
fn initializer<'a>(tokens: &'a [Token], name: &str) -> Result<&'a [Token]> {
    let start = tokens
        .windows(4)
        .position(|w| {
            matches!(w, [Token::Ident(n), Token::Punct('['), Token::Punct(']'), Token::Punct('=')]
                if n == name)
        })
        .ok_or_else(|| format!("no `{name}[] =`"))?;
    let open = start + 4;
    let mut depth = 0;
    for (k, t) in tokens.iter().enumerate().skip(open) {
        match t {
            Token::Punct('{') => depth += 1,
            Token::Punct('}') => {
                depth -= 1;
                if depth == 0 {
                    return tokens
                        .get(open + 1..k)
                        .ok_or_else(|| "a bad initializer".into());
                }
            }
            _ => {}
        }
    }
    Err(format!("`{name}` isn't closed").into())
}

/// The braced entries of an initializer, each as its tokens without commas.
fn entries(body: &[Token]) -> Vec<Vec<Token>> {
    let mut out = Vec::new();
    let mut cur: Option<Vec<Token>> = None;
    for t in body {
        match t {
            Token::Punct('{') => cur = Some(Vec::new()),
            Token::Punct('}') => out.extend(cur.take()),
            Token::Punct(',') => {}
            t => {
                if let Some(c) = cur.as_mut() {
                    c.push(t.clone());
                }
            }
        }
    }
    out
}

fn curve_list(tokens: &[Token]) -> Result<Vec<Entry>> {
    let mut out = Vec::new();
    for e in entries(initializer(tokens, "curve_list")?) {
        // NID , & DATA . h , METHOD , "comment"
        match e.as_slice() {
            [
                Token::Ident(nid),
                Token::Punct('&'),
                Token::Ident(data),
                Token::Punct('.'),
                Token::Ident(h),
                method,
                Token::Str(comment),
            ] if h == "h" => out.push(Entry {
                nid: nid.clone(),
                data: data.clone(),
                method: match method {
                    Token::Number(n) if n == "0" => String::new(),
                    Token::Ident(m) => m.clone(),
                    other => return Err(format!("{nid}: method {other:?}").into()),
                },
                comment: comment.clone(),
            }),
            other => return Err(format!("an unexpected curve_list entry: {other:?}").into()),
        }
    }
    Ok(out)
}

fn name_list(tokens: &[Token], array: &str) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for e in entries(initializer(tokens, array)?) {
        match e.as_slice() {
            [Token::Str(name), Token::Ident(nid)] => out.push((name.clone(), nid.clone())),
            other => return Err(format!("an unexpected {array} entry: {other:?}").into()),
        }
    }
    Ok(out)
}

/// The Rust name of a method function (`""` is the field's generic method).
fn method_variant(c_name: &str) -> Result<&'static str> {
    Ok(match c_name {
        "" => "Generic",
        "EC_GFp_nistp224_method" => "Nistp224",
        "EC_GFp_nistp256_method" => "Nistp256",
        "ossl_ec_GFp_nistp384_method" => "Nistp384",
        "EC_GFp_nistp521_method" => "Nistp521",
        "EC_GFp_nistz256_method" => "Nistz256",
        "EC_GFp_sm2p256_method" => "Sm2p256",
        other => return Err(format!("an unknown curve method `{other}`").into()),
    })
}

fn bytes(out: &mut String, label: &str, b: &[u8]) {
    let _ = write!(out, "        {label}: &[");
    for (i, x) in b.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "0x{x:02x}");
    }
    out.push_str("],\n");
}

pub fn generate(ctx: &Context, constants: &Constants) -> Result {
    let nids: BTreeMap<&str, i64> = constants
        .ints
        .iter()
        .map(|c| (c.name.as_str(), c.value))
        .collect();
    let nid = |name: &str| -> Result<i64> {
        nids.get(name)
            .copied()
            .ok_or_else(|| format!("unknown {name}").into())
    };
    let source = fs::read_to_string(ctx.abi.join("crypto/ec/ec_curve.c"))?;
    let mut per_arch = Vec::new();
    for (arch, defines) in ARCHES {
        let tokens = tokenize(&preprocess(ctx, &source, defines)?)?;
        per_arch.push((*arch, data_blocks(&tokens)?, curve_list(&tokens)?));
    }
    let (_, blocks, list) = per_arch.first().ok_or("no architectures")?;
    for (arch, _, other) in &per_arch {
        let same = other.len() == list.len()
            && other
                .iter()
                .zip(list)
                .all(|(a, b)| a.nid == b.nid && a.data == b.data);
        if !same {
            return Err(format!("{arch}'s curve list differs in its curves").into());
        }
    }
    let support = tokenize(&fs::read_to_string(
        ctx.abi.join("crypto/evp/ec_support.c"),
    )?)?;
    let names = name_list(&support, "curve_list")?;
    let nist = name_list(&support, "nist_curves")?;

    let mut out = String::from(
        "// Generated by `cargo xtask codegen` from OpenSSL's crypto/ec/ec_curve.c and\n\
         // crypto/evp/ec_support.c. Do not edit.\n\n\
         use crate::ec::curves::{Curve, Field, Method};\n\n\
         /// The named curves, in `EC_get_builtin_curves` order.\n\
         pub(crate) static CURVES: &[Curve] = &[\n",
    );
    for (i, e) in list.iter().enumerate() {
        let d = blocks
            .get(&e.data)
            .ok_or_else(|| format!("no data block {}", e.data))?;
        let field = match d.field.as_str() {
            "NID_X9_62_prime_field" => "Prime",
            "NID_X9_62_characteristic_two_field" => "Binary",
            other => return Err(format!("{}: field {other}", e.data).into()),
        };
        let mut methods = Vec::new();
        for (arch, _, l) in &per_arch {
            let entry = l.get(i).ok_or("curve lists of different lengths")?;
            methods.push((*arch, method_variant(&entry.method)?));
        }
        let method = match methods.as_slice() {
            [(_, first), rest @ ..] if rest.iter().all(|(_, m)| m == first) => {
                format!("Method::{first}")
            }
            [init @ .., (_, last)] => {
                let mut s = String::new();
                for (arch, m) in init {
                    let _ = write!(
                        s,
                        "if cfg!(target_arch = \"{arch}\") {{ Method::{m} }} else "
                    );
                }
                let _ = write!(s, "{{ Method::{last} }}");
                s
            }
            [] => return Err("no architectures".into()),
        };
        let (seed, params) = d.octets.split_at(d.seed_len);
        let p: Vec<&[u8]> = params.chunks(d.param_len).take(6).collect();
        let _ = writeln!(out, "    Curve {{\n        nid: {},", nid(&e.nid)?);
        let _ = writeln!(out, "        field: Field::{field},");
        bytes(&mut out, "seed", seed);
        let _ = writeln!(out, "        cofactor: {},", d.cofactor);
        for (label, v) in ["p", "a", "b", "x", "y", "order"].iter().zip(&p) {
            bytes(&mut out, label, v);
        }
        let _ = writeln!(out, "        method: {method},");
        let _ = writeln!(out, "        comment: {:?},\n    }},", e.comment);
    }
    out.push_str("];\n\n/// The curves' names (`OSSL_EC_curve_nid2name`).\npub(crate) static NAMES: &[(&str, i32)] = &[\n");
    for (name, n) in &names {
        let _ = writeln!(out, "    ({name:?}, {}),", nid(n)?);
    }
    out.push_str("];\n\n/// The NIST names (`EC_curve_nid2nist`).\npub(crate) static NIST_NAMES: &[(&str, i32)] = &[\n");
    for (name, n) in &nist {
        let _ = writeln!(out, "    ({name:?}, {}),", nid(n)?);
    }
    out.push_str("];\n");
    let dir = ctx.root.join("crates/rustyssl-crypto/src/generated");
    fs::create_dir_all(&dir)?;
    write_rust(&ctx.root, &dir.join("curves.rs"), &out)?;
    write_rust(
        &ctx.root,
        &dir.join("mod.rs"),
        "// Generated by `cargo xtask codegen`. Do not edit.\n\npub(crate) mod curves;\n",
    )?;
    println!(
        "curves: {} named curves, {} names, {} NIST names",
        list.len(),
        names.len(),
        nist.len()
    );
    Ok(())
}
