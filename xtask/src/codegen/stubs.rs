//! Generates a stub for every function libcrypto and libssl export, in
//! `crates/rustssl-capi/src/generated/<lib>_stubs.rs`, with the signature from the vendored
//! headers. A stub calls `crate::stub::unimplemented`, which aborts the process.
//!
//! Functions that `rustssl-capi` already implements (any `extern "C" fn` outside
//! `src/generated/`) get no stub, so implementing a function and regenerating replaces its
//! stub. Every target must produce identical stubs; codegen fails otherwise.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use quote::ToTokens;

use super::exports::{Exports, LIBRARIES};
use super::headers::{Context, identifiers, libc_types, write_rust};
use crate::targets::{OPENSSL_SERIES, TARGETS};
use crate::util::Result;

pub fn generate(ctx: &Context, exports: &[Exports]) -> Result {
    let capi = ctx.root.join("crates/rustssl-capi/src");
    let implemented = implemented_functions(&capi)?;
    // library -> rendered stubs, which must agree across targets.
    let mut rendered: BTreeMap<&str, BTreeMap<String, String>> = BTreeMap::new();
    for target in TARGETS {
        let options = ["--blocklist-type".to_owned(), ".*".to_owned()];
        let text = ctx.bindgen(target, &ctx.wrapper, "functions", &options)?;
        let prototypes = prototypes(&text)?;
        for library_exports in exports.iter().filter(|e| e.target.module == target.module) {
            let mut stubs = BTreeMap::new();
            let mut missing = Vec::new();
            for name in library_exports.names() {
                if implemented.contains(name) {
                    continue;
                }
                match prototypes.get(name) {
                    Some(stub) => {
                        stubs.insert(name.to_owned(), stub.clone());
                    }
                    None => missing.push(name),
                }
            }
            if !missing.is_empty() {
                return Err(format!(
                    "{} exports without a prototype in the vendored headers (vendor the \
                     header that declares them): {}",
                    library_exports.library,
                    missing.join(", ")
                )
                .into());
            }
            match rendered.get(library_exports.library) {
                None => {
                    rendered.insert(library_exports.library, stubs);
                }
                Some(first) if *first == stubs => {}
                Some(first) => {
                    let differs: Vec<&String> = first
                        .iter()
                        .filter(|(name, stub)| stubs.get(*name) != Some(stub))
                        .map(|(name, _)| name)
                        .chain(stubs.keys().filter(|name| !first.contains_key(*name)))
                        .take(10)
                        .collect();
                    return Err(format!(
                        "{} stubs differ on {}: {differs:?}",
                        library_exports.library, target.configure
                    )
                    .into());
                }
            }
        }
    }

    let out_dir = capi.join("generated");
    for library in LIBRARIES {
        let stubs = rendered.get(library).ok_or("no stubs rendered")?;
        let path = out_dir.join(format!("{library}_stubs.rs"));
        write_rust(&ctx.root, &path, &render_file(library, stubs)?)?;
        let exported = exports
            .iter()
            .find(|e| e.library == *library)
            .map_or(0, |e| e.names().count());
        println!(
            "{library}: {} implemented, {} stubs",
            exported - stubs.len(),
            stubs.len()
        );
    }
    Ok(())
}

/// Names of the `extern "C"` functions implemented by hand in `rustssl-capi`.
fn implemented_functions(src: &Path) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    let mut dirs = vec![src.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                if path.file_name().is_none_or(|n| n != "generated") {
                    dirs.push(path);
                }
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = fs::read_to_string(&path)?;
                for piece in text.split("extern \"C\" fn ").skip(1) {
                    if let Some(name) = identifiers(piece).next() {
                        names.insert(name.to_owned());
                    }
                }
            }
        }
    }
    Ok(names)
}

/// Renders a stub for every prototype in bindgen's output, keyed by function name.
fn prototypes(bindgen: &str) -> Result<HashMap<String, String>> {
    let file = syn::parse_file(bindgen)?;
    let mut stubs = HashMap::new();
    for item in file.items {
        let syn::Item::ForeignMod(block) = item else {
            continue;
        };
        for foreign in block.items {
            if let syn::ForeignItem::Fn(function) = foreign {
                let name = function.sig.ident.to_string();
                stubs.insert(name, render_stub(&function.sig)?);
            }
        }
    }
    Ok(stubs)
}

fn render_stub(sig: &syn::Signature) -> Result<String> {
    let name = sig.ident.to_string();
    let mut params = Vec::new();
    for input in &sig.inputs {
        let syn::FnArg::Typed(param) = input else {
            return Err(format!("{name}: unexpected receiver").into());
        };
        params.push(format!("_: {}", rust_type(&param.ty)));
    }
    // C-variadic functions must be `unsafe` to define.
    let unsafety = if sig.variadic.is_some() {
        params.push("_: ...".to_owned());
        "unsafe "
    } else {
        ""
    };
    let output = match &sig.output {
        syn::ReturnType::Default => String::new(),
        syn::ReturnType::Type(_, ty) => format!(" -> {}", rust_type(ty)),
    };
    Ok(format!(
        "#[unsafe(no_mangle)]\npub {unsafety}extern \"C\" fn {name}({}){output} {{\n    \
         crate::stub::unimplemented(\"{name}\")\n}}\n",
        params.join(", ")
    ))
}

/// A type as Rust source. `va_list` is spelled differently on every target (x86_64 passes a
/// pointer to `__va_list_tag`), so it becomes `VaList`, which matches the C ABI everywhere.
fn rust_type(ty: &syn::Type) -> String {
    let text = ty.to_token_stream().to_string();
    match text.as_str() {
        "va_list" | "__builtin_va_list" | "* mut __va_list_tag" => {
            "core::ffi::VaList<'_>".to_owned()
        }
        _ => text,
    }
}

fn render_file(library: &str, stubs: &BTreeMap<String, String>) -> Result<String> {
    let mut out = format!(
        "// Generated by `cargo xtask codegen` from the {library} export list in \
         abi/openssl-{OPENSSL_SERIES}\n// and the prototypes in its headers. Do not edit: \
         implementing a function in rustssl-capi\n// and regenerating removes its stub.\n\n\
         // Some OpenSSL functions take many parameters; variadic stubs must be `unsafe`.\n\
         #![allow(clippy::too_many_arguments, clippy::missing_safety_doc)]\n\n"
    );
    let all: String = stubs.values().map(String::as_str).collect();
    let used: Vec<&str> = libc_types()
        .into_iter()
        .filter(|t| identifiers(&all).any(|id| id == *t))
        .collect();
    if !used.is_empty() {
        writeln!(out, "use libc::{{{}}};", used.join(", "))?;
    }
    out.push_str("use rustssl_abi::*;\n\n");
    for stub in stubs.values() {
        out.push_str(stub);
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stub_for(prototype: &str) -> String {
        let file = format!("unsafe extern \"C\" {{ {prototype} }}");
        prototypes(&file).unwrap().into_values().next().unwrap()
    }

    #[test]
    fn stubs_keep_the_signature_and_abort() {
        let stub = stub_for("pub fn SSL_CTX_new(meth: *const SSL_METHOD) -> *mut SSL_CTX;");
        assert!(stub.starts_with("#[unsafe(no_mangle)]\npub extern \"C\" fn SSL_CTX_new("));
        assert!(stub.contains("(_: * const SSL_METHOD) -> * mut SSL_CTX"));
        assert!(stub.contains("crate::stub::unimplemented(\"SSL_CTX_new\")"));
    }

    #[test]
    fn variadic_and_va_list_stubs() {
        let printf = stub_for("pub fn BIO_printf(b: *mut BIO, f: *const c_char, ...) -> c_int;");
        assert!(printf.contains("pub unsafe extern \"C\" fn BIO_printf("));
        assert!(printf.contains(", _: ...)"));
        let vprintf = stub_for("pub fn BIO_vprintf(b: *mut BIO, a: *mut __va_list_tag) -> c_int;");
        assert!(vprintf.contains("_: core::ffi::VaList<'_>"));
        assert!(vprintf.contains("pub extern \"C\" fn BIO_vprintf("));
    }

    #[test]
    fn void_functions_have_no_return_type() {
        let stub = stub_for("pub fn X509_free(a: *mut X509);");
        assert!(stub.contains("fn X509_free(_: * mut X509) {"));
    }
}
