//! Generates the export lists the two libraries are linked with (`libs/<lib>/exports/`), from
//! the per-target lists that OpenSSL's own `util/mkdef.pl` resolved from the `.num` files
//! (`abi/openssl-<series>/config/<target>/<lib>.ld`): an ELF version script for Linux and an
//! exported-symbols list for macOS, which has no symbol versions.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use super::headers::Context;
use crate::targets::{OPENSSL_SERIES, TARGETS, Target};
use crate::util::Result;

pub const LIBRARIES: &[&str] = &["libcrypto", "libssl"];

/// libcrypto exports `rustyssl_private_<function>` for each libssl function, for libssl's
/// forwarders only, under its own version node (docs/adr/0001-library-layout.md).
pub const PRIVATE_PREFIX: &str = "rustyssl_private_";
const PRIVATE_NODE: &str = "RUSTYSSL_PRIVATE";
const PRIVATE_GLOB: &str = "rustyssl_private_*";

/// The private functions libcrypto exports to the modules it ships beside it (`libs/<module>/`,
/// such as the legacy provider's): each `rustyssl_private_<name>` their C sources call. They
/// sit in the private node with libssl's twins (docs/adr/0003-external-providers.md).
pub fn module_imports(root: &Path) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(root.join("libs"))? {
        let dir = entry?.path();
        let is_library = dir
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| LIBRARIES.contains(&n));
        if is_library || !dir.is_dir() {
            continue;
        }
        for file in fs::read_dir(&dir)? {
            let file = file?.path();
            if file.extension().is_some_and(|e| e == "c") {
                names.extend(private_calls(&fs::read_to_string(&file)?));
            }
        }
    }
    Ok(names)
}

/// The `rustyssl_private_<name>` identifiers in C source.
fn private_calls(source: &str) -> BTreeSet<String> {
    source
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| w.len() > PRIVATE_PREFIX.len() && w.starts_with(PRIVATE_PREFIX))
        .map(str::to_owned)
        .collect()
}

/// The functions one library exports on one target, grouped by symbol version in order.
pub struct Exports {
    pub target: &'static Target,
    pub library: &'static str,
    pub nodes: Vec<(String, Vec<String>)>,
}

impl Exports {
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.nodes
            .iter()
            .flat_map(|(_, names)| names.iter().map(String::as_str))
    }
}

pub fn generate(ctx: &Context) -> Result<Vec<Exports>> {
    let mut all = Vec::new();
    for target in TARGETS {
        for library in LIBRARIES {
            let source = ctx
                .abi
                .join("config")
                .join(target.configure)
                .join(format!("{library}.ld"));
            let exports = Exports {
                target,
                library,
                nodes: parse_version_script(&fs::read_to_string(&source)?)
                    .map_err(|e| format!("{}: {e}", source.display()))?,
            };
            let dir = ctx.root.join("libs").join(library).join("exports");
            fs::create_dir_all(&dir)?;
            if target.clang.contains("apple") {
                let path = dir.join(format!("{}.exports", target.configure));
                fs::write(path, render_apple(&exports)?)?;
            } else {
                let path = dir.join(format!("{}.map", target.configure));
                fs::write(path, render_elf(&exports)?)?;
            }
            all.push(exports);
        }
    }
    for library in LIBRARIES {
        let count = all
            .iter()
            .find(|e| e.library == *library)
            .map_or(0, |e| e.names().count());
        println!("{library}: {count} exported functions");
    }
    Ok(all)
}

/// Parses the version script `mkdef.pl --OS linux` writes.
pub fn parse_version_script(text: &str) -> Result<Vec<(String, Vec<String>)>> {
    let mut nodes: Vec<(String, Vec<String>)> = Vec::new();
    let mut open = false;
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if let Some(node) = line.strip_suffix(" {") {
            if open {
                return Err(format!("node {node} opens inside another node").into());
            }
            nodes.push((node.to_owned(), Vec::new()));
            open = true;
        } else if line.starts_with('}') {
            open = false;
        } else if line == "global:" || line == "local: *;" {
            continue;
        } else if let (true, Some(name), Some((_, names))) =
            (open, line.strip_suffix(';'), nodes.last_mut())
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            names.push(name.to_owned());
        } else {
            return Err(format!("unexpected line: {line}").into());
        }
    }
    if nodes.is_empty() || open {
        return Err("not a complete version script".into());
    }
    Ok(nodes)
}

/// Where a generated list comes from, as lines of a comment.
fn provenance(exports: &Exports) -> [String; 2] {
    [
        format!(
            "Generated by `cargo xtask codegen` from abi/openssl-{OPENSSL_SERIES}/config/{}/{}.ld,",
            exports.target.configure, exports.library
        ),
        "which OpenSSL's util/mkdef.pl resolved from the .num files. Do not edit.".to_owned(),
    ]
}

/// An ELF version script. Each symbol keeps OpenSSL's version node, so binaries linked
/// against OpenSSL resolve against ours. libcrypto adds a private node for libssl.
fn render_elf(exports: &Exports) -> Result<String> {
    let [first, second] = provenance(exports);
    let mut out = format!("/* {first}\n   {second} */\n");
    let mut nodes: Vec<(&str, Vec<&str>)> = exports
        .nodes
        .iter()
        .map(|(node, names)| (node.as_str(), names.iter().map(String::as_str).collect()))
        .collect();
    if exports.library == "libcrypto" {
        nodes.push((PRIVATE_NODE, vec![PRIVATE_GLOB]));
    }
    let mut previous: Option<&str> = None;
    let last = nodes.len().saturating_sub(1);
    for (i, (node, names)) in nodes.iter().enumerate() {
        writeln!(out, "{node} {{\n    global:")?;
        for name in names {
            writeln!(out, "        {name};")?;
        }
        if i == last {
            writeln!(out, "    local: *;")?;
        }
        match previous {
            Some(parent) => writeln!(out, "}} {parent};")?,
            None => writeln!(out, "}};")?,
        }
        previous = Some(node);
    }
    Ok(out)
}

/// A list for `ld -exported_symbols_list`: Mach-O names carry a leading underscore.
fn render_apple(exports: &Exports) -> Result<String> {
    let mut out = String::new();
    for line in provenance(exports) {
        writeln!(out, "# {line}")?;
    }
    for name in exports.names() {
        writeln!(out, "_{name}")?;
    }
    if exports.library == "libcrypto" {
        writeln!(out, "_{PRIVATE_GLOB}")?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MKDEF: &str = "OPENSSL_3.0.0 {\n    global:\n        A_new;\n        A_free;\n};\n\
                         OPENSSL_3.1.0 {\n    global:\n        B_new;\n    local: *;\n} OPENSSL_3.0.0;\n";

    #[test]
    fn finds_the_private_calls_of_a_module() {
        let calls = private_calls(
            "int rustyssl_private_x_init(void);\n/* rustyssl_private_ */ int f(void)\n\
             { return rustyssl_private_x_init(); }\n",
        );
        assert_eq!(
            calls.into_iter().collect::<Vec<_>>(),
            ["rustyssl_private_x_init"]
        );
    }

    #[test]
    fn private_glob_matches_the_prefix() {
        assert_eq!(PRIVATE_GLOB, format!("{PRIVATE_PREFIX}*"));
    }

    #[test]
    fn parses_mkdef_output() {
        let nodes = parse_version_script(MKDEF).unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].0, "OPENSSL_3.0.0");
        assert_eq!(nodes[0].1, ["A_new", "A_free"]);
        assert_eq!(nodes[1].1, ["B_new"]);
        assert!(parse_version_script("OPENSSL_3.0.0 {\n    global:\n        A;\n").is_err());
        assert!(parse_version_script("garbage\n").is_err());
    }

    #[test]
    fn renders_chained_nodes_with_local_last() {
        let target = &TARGETS[0];
        let exports = Exports {
            target,
            library: "libssl",
            nodes: parse_version_script(MKDEF).unwrap(),
        };
        let script = render_elf(&exports).unwrap();
        assert!(
            script.contains("OPENSSL_3.0.0 {\n    global:\n        A_new;\n        A_free;\n};\n")
        );
        assert!(script.ends_with("        B_new;\n    local: *;\n} OPENSSL_3.0.0;\n"));
        assert!(script.starts_with("/* Generated"));
        assert!(!script.contains(PRIVATE_NODE));
    }
}
