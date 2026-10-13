//! Generates what each export compiles to, from the prototypes in the vendored headers:
//!
//! - in `rustyssl-capi`, which is linked into libcrypto: an aborting stub for every libcrypto
//!   export it doesn't implement yet, and one for every libssl export under its private name
//!   `rustyssl_private_<name>`;
//! - in `libs/libssl`: a forwarder for every libssl export, which calls libcrypto's private
//!   definition. libssl holds no implementation and no state of its own
//!   (`docs/adr/0001-library-layout.md`).
//!
//! To implement a function, write it in `rustyssl-capi` (under its own name for libcrypto, or
//! as `rustyssl_private_<name>` for libssl) and regenerate, which drops its stub. A stub calls
//! `crate::stub::unimplemented`, which aborts. Every target must produce identical code;
//! codegen fails otherwise.
//!
//! For each function written by hand, `rustyssl-capi/src/generated/signatures.rs` asserts that
//! it has exactly the header's prototype: it assigns the function to a function-pointer
//! constant of that type, so the compiler rejects any difference in a parameter or return
//! type, pointer constness, or variadics, on every target (TEST_PLAN.md, L3 item 3).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use quote::ToTokens;

use super::exports::{Exports, PRIVATE_PREFIX};
use super::headers::{Context, identifiers, libc_types, write_rust};
use crate::targets::{OPENSSL_SERIES, TARGETS};
use crate::util::Result;

pub const CAPI_SRC: &str = "crates/rustyssl-capi/src";
const LIBSSL_SRC: &str = "libs/libssl/src";

/// A C prototype as Rust types.
#[derive(Clone, PartialEq, Debug)]
struct Prototype {
    params: Vec<String>,
    variadic: bool,
    output: Option<String>,
}

pub fn generate(ctx: &Context, exports: &[Exports]) -> Result {
    // library -> name -> prototype, which must agree across targets.
    let mut agreed: Option<BTreeMap<&str, BTreeMap<String, Prototype>>> = None;
    for target in TARGETS {
        let options = ["--blocklist-type".to_owned(), ".*".to_owned()];
        let text = ctx.bindgen(target, &ctx.wrapper, "functions", &options)?;
        let prototypes = prototypes(&text)?;
        let mut libraries = BTreeMap::new();
        for library_exports in exports.iter().filter(|e| e.target.module == target.module) {
            let mut functions = BTreeMap::new();
            let mut missing = Vec::new();
            for name in library_exports.names() {
                match prototypes.get(name) {
                    Some(prototype) => {
                        functions.insert(name.to_owned(), prototype.clone());
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
            libraries.insert(library_exports.library, functions);
        }
        match &agreed {
            None => agreed = Some(libraries),
            Some(first) if *first == libraries => {}
            Some(first) => {
                let differs: Vec<&String> = first
                    .values()
                    .zip(libraries.values())
                    .flat_map(|(a, b)| {
                        a.iter()
                            .filter(|(name, p)| b.get(*name) != Some(p))
                            .map(|(name, _)| name)
                    })
                    .take(10)
                    .collect();
                return Err(
                    format!("prototypes differ on {}: {differs:?}", target.configure).into(),
                );
            }
        }
    }
    let libraries = agreed.ok_or("no targets")?;
    let crypto = libraries.get("libcrypto").ok_or("no libcrypto exports")?;
    let ssl = libraries.get("libssl").ok_or("no libssl exports")?;

    let paths = implemented_paths(&ctx.root.join(CAPI_SRC))?;
    let implemented: BTreeSet<String> = paths.keys().cloned().collect();
    let crypto_stubs: Vec<String> = crypto
        .iter()
        .filter(|(name, _)| !implemented.contains(*name))
        .map(|(name, prototype)| render_stub(name, name, prototype))
        .collect();
    let ssl_stubs: Vec<String> = ssl
        .iter()
        .filter(|(name, _)| !implemented.contains(&format!("{PRIVATE_PREFIX}{name}")))
        .map(|(name, prototype)| render_stub(&format!("{PRIVATE_PREFIX}{name}"), name, prototype))
        .collect();
    let capi = ctx.root.join(CAPI_SRC).join("generated");
    write_rust(
        &ctx.root,
        &capi.join("libcrypto_stubs.rs"),
        &render_stubs_file("libcrypto", "", &crypto_stubs)?,
    )?;
    write_rust(
        &ctx.root,
        &capi.join("libssl_stubs.rs"),
        &render_stubs_file("libssl", PRIVATE_PREFIX, &ssl_stubs)?,
    )?;
    write_rust(
        &ctx.root,
        &capi.join("signatures.rs"),
        &render_signatures_file(crypto, ssl, &paths)?,
    )?;
    let forwarders = ctx
        .root
        .join(LIBSSL_SRC)
        .join("generated/libssl_forwarders.rs");
    write_rust(&ctx.root, &forwarders, &render_forwarders_file(ssl)?)?;

    for (library, functions, stubs) in [
        ("libcrypto", crypto, crypto_stubs.len()),
        ("libssl", ssl, ssl_stubs.len()),
    ] {
        println!(
            "{library}: {} implemented, {stubs} stubs",
            functions.len() - stubs
        );
    }
    Ok(())
}

/// Names of the `extern "C"` functions implemented by hand under `src`.
pub fn implemented_functions(src: &Path) -> Result<BTreeSet<String>> {
    Ok(implemented_paths(src)?.into_keys().collect())
}

/// The `extern "C"` functions implemented by hand under `src`, each with the path of the module
/// that defines it (`crate::buffer`).
pub fn implemented_paths(src: &Path) -> Result<BTreeMap<String, String>> {
    let mut paths = BTreeMap::new();
    let mut dirs = vec![src.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                if path.file_name().is_none_or(|n| n != "generated") {
                    dirs.push(path);
                }
            } else if path.extension().is_some_and(|e| e == "rs") {
                let module = module_path(path.strip_prefix(src)?)?;
                for name in defined_functions(&fs::read_to_string(&path)?) {
                    paths.insert(name, module.clone());
                }
            }
        }
    }
    Ok(paths)
}

/// The module path of a source file, from its path relative to `src/`: `lib.rs` is `crate`,
/// `buffer.rs` is `crate::buffer`, and `a/mod.rs` and `a/b.rs` are `crate::a` and `crate::a::b`.
fn module_path(file: &Path) -> Result<String> {
    let mut parts = vec!["crate".to_owned()];
    for component in file.with_extension("").components() {
        let part = component
            .as_os_str()
            .to_str()
            .ok_or("non-UTF-8 source path")?;
        if part != "lib" && part != "mod" {
            parts.push(part.to_owned());
        }
    }
    Ok(parts.join("::"))
}

/// Names of the `extern "C" fn`s defined in Rust `source`, ignoring comment lines (whose
/// examples must not count as implementations).
fn defined_functions(source: &str) -> Vec<String> {
    let code: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .map(|line| format!("{line}\n"))
        .collect();
    code.split("extern \"C\" fn ")
        .skip(1)
        .filter_map(|piece| identifiers(piece).next())
        .map(str::to_owned)
        .collect()
}

/// Every prototype in bindgen's output, keyed by function name.
fn prototypes(bindgen: &str) -> Result<HashMap<String, Prototype>> {
    let file = syn::parse_file(bindgen)?;
    let mut prototypes = HashMap::new();
    for item in file.items {
        let syn::Item::ForeignMod(block) = item else {
            continue;
        };
        for foreign in block.items {
            if let syn::ForeignItem::Fn(function) = foreign {
                let sig = &function.sig;
                let mut params = Vec::new();
                for input in &sig.inputs {
                    let syn::FnArg::Typed(param) = input else {
                        return Err(format!("{}: unexpected receiver", sig.ident).into());
                    };
                    params.push(rust_type(&param.ty));
                }
                let output = match &sig.output {
                    syn::ReturnType::Default => None,
                    syn::ReturnType::Type(_, ty) => Some(rust_type(ty)),
                };
                let prototype = Prototype {
                    params,
                    variadic: sig.variadic.is_some(),
                    output,
                };
                prototypes.insert(sig.ident.to_string(), prototype);
            }
        }
    }
    Ok(prototypes)
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

fn output(prototype: &Prototype) -> String {
    prototype
        .output
        .as_ref()
        .map_or_else(String::new, |ty| format!(" -> {ty}"))
}

/// An exported stub named `symbol` that aborts, reporting the OpenSSL function `name`.
fn render_stub(symbol: &str, name: &str, prototype: &Prototype) -> String {
    let mut params: Vec<String> = prototype
        .params
        .iter()
        .map(|ty| format!("_: {ty}"))
        .collect();
    // C-variadic functions must be `unsafe` to define.
    let unsafety = if prototype.variadic {
        params.push("_: ...".to_owned());
        "unsafe "
    } else {
        ""
    };
    format!(
        "#[unsafe(no_mangle)]\npub {unsafety}extern \"C\" fn {symbol}({}){} {{\n    \
         crate::stub::unimplemented(\"{name}\")\n}}\n",
        params.join(", "),
        output(prototype)
    )
}

/// The `use` lines for the libc and ABI types the generated code mentions.
fn imports(code: &str) -> Result<String> {
    let mut out = String::new();
    let used: Vec<&str> = libc_types()
        .into_iter()
        .filter(|t| identifiers(code).any(|id| id == *t))
        .collect();
    if !used.is_empty() {
        writeln!(out, "use libc::{{{}}};", used.join(", "))?;
    }
    out.push_str("use rustyssl_abi::*;\n\n");
    Ok(out)
}

fn render_stubs_file(library: &str, prefix: &str, stubs: &[String]) -> Result<String> {
    let naming = if prefix.is_empty() {
        String::new()
    } else {
        format!(
            "\n//\n// Each stub carries the private name `{prefix}<function>`; libssl's export of the \
             same\n// function forwards to it (docs/adr/0001-library-layout.md)."
        )
    };
    let mut out = format!(
        "// Generated by `cargo xtask codegen` from the {library} export list in \
         abi/openssl-{OPENSSL_SERIES}\n// and the prototypes in its headers. Do not edit: \
         implementing a function in rustyssl-capi\n// and regenerating removes its stub.{naming}\n\n\
         // Some OpenSSL functions take many parameters; variadic stubs must be `unsafe`.\n\
         #![allow(clippy::too_many_arguments, clippy::missing_safety_doc)]\n\n"
    );
    let body: String = stubs.concat();
    out.push_str(&imports(&body)?);
    for stub in stubs {
        out.push_str(stub);
        out.push('\n');
    }
    Ok(out)
}

/// A function pointer type for `prototype`. A `VaList` parameter's elided lifetime becomes a
/// higher-ranked one, which the function's own late-bound lifetime coerces to.
fn function_type(prototype: &Prototype) -> String {
    let mut params = prototype.params.clone();
    if prototype.variadic {
        params.push("...".to_owned());
    }
    let signature = format!(
        "unsafe extern \"C\" fn({}){}",
        params.join(", "),
        output(prototype)
    );
    if signature.contains("'_") {
        format!("for<'a> {}", signature.replace("'_", "'a"))
    } else {
        signature
    }
}

/// One signature assertion for each function implemented by hand, under its exported name
/// (libcrypto) or private name (libssl).
fn render_signatures_file(
    crypto: &BTreeMap<String, Prototype>,
    ssl: &BTreeMap<String, Prototype>,
    paths: &BTreeMap<String, String>,
) -> Result<String> {
    let mut assertions = String::new();
    let functions = crypto.iter().map(|(name, p)| (name.clone(), p)).chain(
        ssl.iter()
            .map(|(name, p)| (format!("{PRIVATE_PREFIX}{name}"), p)),
    );
    for (symbol, prototype) in functions {
        if let Some(module) = paths.get(&symbol) {
            writeln!(
                assertions,
                "const _: {} = {module}::{symbol};",
                function_type(prototype)
            )?;
        }
    }
    let mut out = format!(
        "// Generated by `cargo xtask codegen` from the prototypes in abi/openssl-{OPENSSL_SERIES}'s \
         headers. Do not edit.\n//\n\
         // Each function rustyssl-capi implements by hand is assigned to a function pointer of its \
         C\n// prototype's type, so it doesn't compile unless the signatures match exactly \
         (TEST_PLAN.md, L3 item 3).\n\n\
         #![allow(clippy::type_complexity)]\n\n"
    );
    out.push_str(&imports(&assertions)?);
    out.push_str(&assertions);
    Ok(out)
}

/// libssl's exports, each forwarding to libcrypto's `rustyssl_private_<name>`.
fn render_forwarders_file(ssl: &BTreeMap<String, Prototype>) -> Result<String> {
    let mut declarations = String::from("unsafe extern \"C\" {\n");
    let mut forwarders = String::new();
    for (name, prototype) in ssl {
        if prototype.variadic {
            return Err(format!(
                "{name} is variadic and can't be forwarded; give its private definition a VaList"
            )
            .into());
        }
        let ret = output(prototype);
        let types: Vec<String> = prototype
            .params
            .iter()
            .map(|ty| format!("_: {ty}"))
            .collect();
        writeln!(
            declarations,
            "    fn {PRIVATE_PREFIX}{name}({}){ret};",
            types.join(", ")
        )?;
        let params: Vec<String> = prototype
            .params
            .iter()
            .enumerate()
            .map(|(i, ty)| format!("a{i}: {ty}"))
            .collect();
        let args: Vec<String> = (0..prototype.params.len())
            .map(|i| format!("a{i}"))
            .collect();
        writeln!(
            forwarders,
            "#[unsafe(no_mangle)]\npub unsafe extern \"C\" fn {name}({}){ret} {{\n    \
             // SAFETY: the arguments pass unchanged to libcrypto's definition, which has the same\n    \
             // signature and the same contract as this function.\n    \
             unsafe {{ {PRIVATE_PREFIX}{name}({}) }}\n}}\n",
            params.join(", "),
            args.join(", ")
        )?;
    }
    declarations.push_str("}\n\n");

    let mut out = format!(
        "// Generated by `cargo xtask codegen` from the libssl export list in \
         abi/openssl-{OPENSSL_SERIES}\n// and the prototypes in its headers. Do not edit.\n//\n\
         // Every libssl export forwards to libcrypto's private definition, so libssl holds no \
         state\n// or code of its own (docs/adr/0001-library-layout.md).\n\n\
         // Forwarders have their callers' contract; some take many parameters.\n\
         #![allow(clippy::missing_safety_doc, clippy::too_many_arguments)]\n\n"
    );
    out.push_str(&imports(&forwarders)?);
    out.push_str(&declarations);
    out.push_str(&forwarders);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prototype_of(declaration: &str) -> Prototype {
        let file = format!("unsafe extern \"C\" {{ {declaration} }}");
        prototypes(&file).unwrap().into_values().next().unwrap()
    }

    #[test]
    fn only_code_counts_as_an_implementation() {
        let source = "//! pub unsafe extern \"C\" fn BIO_printf(b: *mut BIO)\n\
                      /// pub unsafe extern \"C\" fn BIO_vprintf(b: *mut BIO)\n\
                      ffi_export! {\n    pub unsafe extern \"C\" fn BUF_MEM_new() -> *mut BUF_MEM\n}\n\
                      pub extern \"C\" fn rustyssl_private_SSL_free(s: *mut SSL) {}\n";
        assert_eq!(
            defined_functions(source),
            ["BUF_MEM_new", "rustyssl_private_SSL_free"]
        );
    }

    #[test]
    fn stubs_keep_the_signature_and_abort() {
        let p = prototype_of("pub fn SSL_CTX_new(meth: *const SSL_METHOD) -> *mut SSL_CTX;");
        let stub = render_stub("rustyssl_private_SSL_CTX_new", "SSL_CTX_new", &p);
        assert!(stub.starts_with(
            "#[unsafe(no_mangle)]\npub extern \"C\" fn rustyssl_private_SSL_CTX_new("
        ));
        assert!(stub.contains("(_: * const SSL_METHOD) -> * mut SSL_CTX"));
        assert!(stub.contains("crate::stub::unimplemented(\"SSL_CTX_new\")"));
    }

    #[test]
    fn variadic_and_va_list_stubs() {
        let p = prototype_of("pub fn BIO_printf(b: *mut BIO, f: *const c_char, ...) -> c_int;");
        let printf = render_stub("BIO_printf", "BIO_printf", &p);
        assert!(printf.contains("pub unsafe extern \"C\" fn BIO_printf("));
        assert!(printf.contains(", _: ...)"));
        let p = prototype_of("pub fn BIO_vprintf(b: *mut BIO, a: *mut __va_list_tag) -> c_int;");
        assert_eq!(p.params[1], "core::ffi::VaList<'_>");
        assert!(!render_stub("BIO_vprintf", "BIO_vprintf", &p).contains("unsafe extern"));
    }

    #[test]
    fn signatures_assert_the_prototype() {
        let crypto = BTreeMap::from([
            (
                "BUF_MEM_grow".to_owned(),
                prototype_of("pub fn BUF_MEM_grow(b: *mut BUF_MEM, n: usize) -> usize;"),
            ),
            (
                "BIO_vprintf".to_owned(),
                prototype_of(
                    "pub fn BIO_vprintf(b: *mut BIO, f: *const c_char, a: va_list) -> c_int;",
                ),
            ),
            (
                "BIO_printf".to_owned(),
                prototype_of("pub fn BIO_printf(b: *mut BIO, f: *const c_char, ...) -> c_int;"),
            ),
            (
                "BN_new".to_owned(),
                prototype_of("pub fn BN_new() -> *mut BIGNUM;"),
            ),
        ]);
        let ssl = BTreeMap::from([(
            "SSL_free".to_owned(),
            prototype_of("pub fn SSL_free(s: *mut SSL);"),
        )]);
        let paths = BTreeMap::from([
            ("BUF_MEM_grow".to_owned(), "crate::buffer".to_owned()),
            ("BIO_vprintf".to_owned(), "crate::bio".to_owned()),
            ("BIO_printf".to_owned(), "crate::bio".to_owned()),
            (
                "rustyssl_private_SSL_free".to_owned(),
                "crate::ssl".to_owned(),
            ),
        ]);
        let file = render_signatures_file(&crypto, &ssl, &paths).unwrap();
        assert!(file.contains("const _: unsafe extern \"C\" fn(* mut BUF_MEM, usize) -> usize = crate::buffer::BUF_MEM_grow;\n"));
        assert!(file.contains("const _: for<'a> unsafe extern \"C\" fn(* mut BIO, * const c_char, core::ffi::VaList<'a>) -> c_int = crate::bio::BIO_vprintf;\n"));
        assert!(file.contains("const _: unsafe extern \"C\" fn(* mut BIO, * const c_char, ...) -> c_int = crate::bio::BIO_printf;\n"));
        assert!(file.contains(
            "const _: unsafe extern \"C\" fn(* mut SSL) = crate::ssl::rustyssl_private_SSL_free;\n"
        ));
        assert!(!file.contains("BN_new"));
    }

    #[test]
    fn module_paths() {
        let path = |p: &str| module_path(Path::new(p)).unwrap();
        assert_eq!(path("lib.rs"), "crate");
        assert_eq!(path("buffer.rs"), "crate::buffer");
        assert_eq!(path("bio/mod.rs"), "crate::bio");
        assert_eq!(path("bio/mem.rs"), "crate::bio::mem");
    }

    #[test]
    fn forwarders_call_the_private_definition() {
        let ssl = BTreeMap::from([
            (
                "SSL_free".to_owned(),
                prototype_of("pub fn SSL_free(s: *mut SSL);"),
            ),
            (
                "SSL_read".to_owned(),
                prototype_of("pub fn SSL_read(s: *mut SSL, b: *mut c_void, n: c_int) -> c_int;"),
            ),
        ]);
        let file = render_forwarders_file(&ssl).unwrap();
        assert!(file.contains("    fn rustyssl_private_SSL_free(_: * mut SSL);\n"));
        assert!(file.contains("pub unsafe extern \"C\" fn SSL_read(a0: * mut SSL, a1: * mut c_void, a2: c_int) -> c_int {"));
        assert!(file.contains("unsafe { rustyssl_private_SSL_read(a0, a1, a2) }"));
        let variadic = BTreeMap::from([(
            "X".to_owned(),
            prototype_of("pub fn X(f: *const c_char, ...);"),
        )]);
        assert!(render_forwarders_file(&variadic).is_err());
    }
}
