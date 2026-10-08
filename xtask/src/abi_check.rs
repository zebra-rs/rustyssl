//! `cargo xtask abi-check [check...]`: ABI conformance (TEST_PLAN.md, layer L3). It builds
//! rustyssl's libraries (`cargo xtask dist`) and the reference OpenSSL (`cargo xtask
//! ref-openssl`), then checks ours against `abi/` and the reference. It fails if any check
//! finds a difference, and reports every difference, not just the first.
//!
//! | Check | What must hold |
//! |---|---|
//! | `symbols` | each library exports exactly its vendored export list, at the right version nodes |
//! | `metadata` | soname or install name, dependencies, version definitions, macOS versions |
//! | `signatures` | every hand-written export has a compile-time signature assertion |
//! | `layouts` | every public struct's size, alignment, and field offsets, per the C compiler |
//! | `constants` | every macro constant's value and type, per the C compiler |
//! | `binary` | a program linked against the reference loads against ours, every symbol bound |
//! | `static` | that program links statically against `libssl.a` and `libcrypto.a` and runs |
//! | `headers` | the installed headers and pkg-config files match the reference's and work |
//!
//! Name checks to run only those. The checks use the host's target: CI runs them on each
//! platform it builds.

mod library;
mod programs;
mod values;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::codegen::exports::{LIBRARIES, PRIVATE_PREFIX, parse_version_script};
use crate::codegen::stubs::{CAPI_SRC, implemented_functions};
use crate::targets::{OPENSSL_SERIES, Target, host};
use crate::test_c::prepare;
use crate::util::{Result, fresh_dir, target_dir, workspace_root};

/// What one check found.
struct Outcome {
    /// What was checked, when it passes.
    summary: String,
    problems: Vec<String>,
}

type Check = fn(&Context) -> Result<Outcome>;

const CHECKS: &[(&str, Check)] = &[
    ("symbols", library::symbols),
    ("metadata", library::metadata),
    ("signatures", signatures),
    ("layouts", values::layouts),
    ("constants", values::constants),
    ("binary", programs::binary),
    ("static", programs::static_linking),
    ("headers", programs::headers),
];

/// How many problems a failing check prints; the rest are counted.
const SHOWN: usize = 25;

/// Everything the checks read.
pub struct Context {
    root: PathBuf,
    /// `abi/openssl-<series>/`.
    abi: PathBuf,
    target: &'static Target,
    /// The reference OpenSSL's install prefix.
    reference: PathBuf,
    /// `target/dist`.
    dist: PathBuf,
    /// Scratch space, emptied first.
    work: PathBuf,
    /// Each library's exports from the vendored export list: name -> version node.
    exports: BTreeMap<&'static str, BTreeMap<String, String>>,
}

impl Context {
    fn apple(&self) -> bool {
        self.target.clang.contains("apple")
    }

    /// A library's shared object under `prefix` (`lib/libssl.so.3`, `lib/libssl.3.dylib`).
    fn shared(&self, prefix: &Path, library: &str) -> PathBuf {
        let name = if self.apple() {
            format!("{library}.3.dylib")
        } else {
            format!("{library}.so.3")
        };
        prefix.join("lib").join(name)
    }

    /// What rustyssl's library must export: the vendored list, plus, in libcrypto, the private
    /// twin of every libssl function (docs/adr/0001-library-layout.md).
    fn expected_exports(&self, library: &str) -> BTreeMap<String, String> {
        let mut expected = self.exports.get(library).cloned().unwrap_or_default();
        if library == "libcrypto" {
            for name in self
                .exports
                .get("libssl")
                .into_iter()
                .flat_map(|e| e.keys())
            {
                expected.insert(
                    format!("{PRIVATE_PREFIX}{name}"),
                    "RUSTYSSL_PRIVATE".to_owned(),
                );
            }
        }
        expected
    }

    /// Every public function of both libraries.
    fn public_functions(&self) -> impl Iterator<Item = &str> {
        self.exports
            .values()
            .flat_map(|e| e.keys().map(String::as_str))
    }
}

pub fn run(args: &[String]) -> Result {
    let selected: Vec<&(&str, Check)> = if args.is_empty() {
        CHECKS.iter().collect()
    } else {
        args.iter()
            .map(|arg| {
                CHECKS.iter().find(|(name, _)| name == arg).ok_or_else(|| {
                    let names: Vec<&str> = CHECKS.iter().map(|(name, _)| *name).collect();
                    format!(
                        "unknown check `{arg}`; the checks are: {}",
                        names.join(", ")
                    )
                })
            })
            .collect::<std::result::Result<_, _>>()?
    };
    let root = workspace_root();
    let (reference, dist) = prepare(&root)?;
    let (_, target) = host()?;
    let abi = root.join(format!("abi/openssl-{OPENSSL_SERIES}"));
    let mut exports = BTreeMap::new();
    for library in LIBRARIES {
        let path = abi
            .join("config")
            .join(target.configure)
            .join(format!("{library}.ld"));
        let nodes = parse_version_script(&fs::read_to_string(&path)?)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let mut names = BTreeMap::new();
        for (node, functions) in nodes {
            for name in functions {
                names.insert(name, node.clone());
            }
        }
        exports.insert(*library, names);
    }
    let work = target_dir(&root).join("xtask/abi-check");
    fresh_dir(&work)?;
    let cx = Context {
        root,
        abi,
        target,
        reference,
        dist,
        work,
        exports,
    };

    let mut failed = Vec::new();
    for (name, check) in selected {
        let outcome = check(&cx).map_err(|e| format!("{name}: {e}"))?;
        if outcome.problems.is_empty() {
            println!("ok    {name}: {}", outcome.summary);
            continue;
        }
        println!("FAIL  {name}: {} problem(s)", outcome.problems.len());
        for problem in outcome.problems.iter().take(SHOWN) {
            println!("        {problem}");
        }
        if outcome.problems.len() > SHOWN {
            println!("        ... and {} more", outcome.problems.len() - SHOWN);
        }
        failed.push(*name);
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("failed: {}", failed.join(", ")).into())
    }
}

/// Every hand-written export has a signature assertion in `rustyssl-capi`'s generated
/// `signatures.rs`, which the compiler checks against the header's prototype on every target.
/// A missing one means codegen wasn't rerun after implementing it.
fn signatures(cx: &Context) -> Result<Outcome> {
    let capi = cx.root.join(CAPI_SRC);
    let generated = fs::read_to_string(capi.join("generated/signatures.rs"))?;
    // Each assertion is a statement `const _: <type> = <module path>::<function>;`.
    let asserted: Vec<&str> = generated
        .split(';')
        .filter(|statement| statement.contains("const _:"))
        .filter_map(|statement| statement.rsplit("::").next())
        .map(str::trim)
        .collect();
    let mut problems = Vec::new();
    let mut checked = 0;
    for name in implemented_functions(&capi)? {
        let exported = cx
            .exports
            .get("libcrypto")
            .is_some_and(|e| e.contains_key(&name))
            || name
                .strip_prefix(PRIVATE_PREFIX)
                .is_some_and(|n| cx.exports.get("libssl").is_some_and(|e| e.contains_key(n)));
        if !exported {
            continue;
        }
        checked += 1;
        if !asserted.contains(&name.as_str()) {
            problems.push(format!(
                "{name} has no signature assertion; run `cargo xtask codegen`"
            ));
        }
    }
    Ok(Outcome {
        summary: format!(
            "{checked} hand-written export(s) asserted against the headers' prototypes"
        ),
        problems,
    })
}
