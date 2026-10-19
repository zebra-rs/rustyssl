//! `compat35`: rustyssl follows OpenSSL 3.6 only (docs/adr/0004-openssl-3.6.md), so a binary
//! built against 3.5 must still run on it. On every target, each export in
//! `abi/openssl-3.5/`'s version scripts must be in the current release's at the same version
//! node, with the same prototype, and every struct layout bindgen derives from 3.5's headers
//! (size, alignment, field offsets) must be the same in the current headers. `symbols` checks
//! that the libraries export exactly the current lists, so this covers the libraries too.

use std::collections::{BTreeMap, HashMap};
use std::fs;

use super::{Context, Outcome};
use crate::codegen::exports::{LIBRARIES, parse_version_script};
use crate::codegen::headers::{Context as Headers, check_bindgen};
use crate::codegen::stubs::{Prototype, function_type, prototypes, rust_type};
use crate::targets::{OPENSSL_SERIES, TARGETS, Target};
use crate::util::Result;

/// The release whose binaries must keep working.
const OLD_SERIES: &str = "3.5";

pub fn compat35(cx: &Context) -> Result<Outcome> {
    check_bindgen()?;
    let old = Headers::for_series(&cx.root, &cx.work.join("compat35-old"), OLD_SERIES)?;
    let new = Headers::for_series(&cx.root, &cx.work.join("compat35-new"), OPENSSL_SERIES)?;
    let mut problems = Vec::new();
    let (mut exports, mut layouts) = (0, 0);
    for target in TARGETS {
        let old_exports = exports_of(&old, target)?;
        let new_exports = exports_of(&new, target)?;
        let old_text = old.bindgen(target, &old.wrapper, "compat35", &[])?;
        let new_text = new.bindgen(target, &new.wrapper, "compat35", &[])?;
        let old_prototypes = prototypes(&old_text)?;
        let new_prototypes = prototypes(&new_text)?;
        let (old_aliases, new_aliases) = (aliases(&old_text)?, aliases(&new_text)?);
        for (name, node) in &old_exports {
            exports += 1;
            match new_exports.get(name) {
                None => problems.push(format!(
                    "{}: {name} is no longer exported",
                    target.configure
                )),
                Some(n) if n != node => problems.push(format!(
                    "{}: {name} moved from {node} to {n}",
                    target.configure
                )),
                Some(_) => {}
            }
            let (Some(was), Some(is)) = (old_prototypes.get(name), new_prototypes.get(name)) else {
                problems.push(format!(
                    "{}: {name} has no prototype in both releases",
                    target.configure
                ));
                continue;
            };
            if resolved(was, &old_aliases) != resolved(is, &new_aliases) {
                problems.push(format!(
                    "{}: {name} was {}, is {}",
                    target.configure,
                    function_type(was),
                    function_type(is)
                ));
            }
        }
        let new_layouts = layout_assertions(&new_text);
        for (what, value) in layout_assertions(&old_text) {
            layouts += 1;
            match new_layouts.get(&what) {
                None => problems.push(format!("{}: {what} is gone", target.configure)),
                Some(v) if *v != value => {
                    problems.push(format!("{}: {what} was {value}, is {v}", target.configure))
                }
                Some(_) => {}
            }
        }
    }
    Ok(Outcome {
        summary: format!(
            "{} target(s): {exports} {OLD_SERIES} export(s) and {layouts} layout fact(s) unchanged",
            TARGETS.len()
        ),
        problems,
    })
}

/// bindgen's type aliases (`pub type OPENSSL_sk_freefunc = Option<...>;`): name -> type.
fn aliases(bindgen: &str) -> Result<HashMap<String, String>> {
    let file = syn::parse_file(bindgen)?;
    Ok(file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Type(alias) => Some((alias.ident.to_string(), rust_type(&alias.ty))),
            _ => None,
        })
        .collect())
}

/// `prototype` with each parameter and result that names an alias replaced by what it
/// stands for, so a release that names a type it used to spell out (3.6's
/// `OPENSSL_sk_freefunc`) compares equal.
fn resolved(prototype: &Prototype, aliases: &HashMap<String, String>) -> Prototype {
    let resolve = |ty: &String| {
        let mut ty = ty.clone();
        // An alias of an alias, a few deep at most; the bound stops a cycle.
        for _ in 0..8 {
            match aliases.get(&ty) {
                Some(target) if *target != ty => ty = target.clone(),
                _ => break,
            }
        }
        ty
    };
    Prototype {
        params: prototype.params.iter().map(resolve).collect(),
        variadic: prototype.variadic,
        output: prototype.output.as_ref().map(resolve),
    }
}

/// A release's exports for `target`: name -> version node.
fn exports_of(headers: &Headers, target: &Target) -> Result<BTreeMap<String, String>> {
    let mut names = BTreeMap::new();
    for library in LIBRARIES {
        let path = headers
            .abi
            .join("config")
            .join(target.configure)
            .join(format!("{library}.ld"));
        let nodes = parse_version_script(&fs::read_to_string(&path)?)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        for (node, functions) in nodes {
            for name in functions {
                names.insert(name, node.clone());
            }
        }
    }
    Ok(names)
}

/// bindgen's layout assertions, `["Size of X"][size_of::<X>() - 24usize]` and the like, as
/// what each asserts (`Size of X`, `Offset of field: X::f`) -> the number.
fn layout_assertions(bindgen: &str) -> BTreeMap<String, String> {
    let mut facts = BTreeMap::new();
    let mut rest = bindgen;
    while let Some(start) = rest.find("[\"") {
        rest = &rest[start + 2..];
        let Some(end) = rest.find("\"]") else { break };
        let what = rest[..end].to_owned();
        rest = &rest[end + 2..];
        let Some(close) = rest.find("usize]") else {
            break;
        };
        let value: String = rest[..close]
            .chars()
            .rev()
            .take_while(char::is_ascii_digit)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        facts.insert(what, value);
        rest = &rest[close..];
    }
    facts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_assertions_are_read() {
        let text = r#"const _: () = {
            ["Size of asn1_string_st"][::core::mem::size_of::<asn1_string_st>() - 24usize];
            ["Offset of field: asn1_string_st::data"]
                [::core::mem::offset_of!(asn1_string_st, data) - 8usize];
        };"#;
        let facts = layout_assertions(text);
        assert_eq!(
            facts.get("Size of asn1_string_st").map(String::as_str),
            Some("24")
        );
        assert_eq!(
            facts
                .get("Offset of field: asn1_string_st::data")
                .map(String::as_str),
            Some("8")
        );
    }
}
