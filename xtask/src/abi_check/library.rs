//! Checks 1 and 2: what the shared libraries export, and their metadata.
//!
//! Linux libraries are read with `crate::elf`, versions included. macOS has no symbol versions,
//! so there the exported names come from `nm` and the metadata from `otool`. The vendored
//! export lists are the spec, and the reference OpenSSL built from the same release is checked
//! against them too. That validates the vendoring, and its extra exports show what the
//! platform's toolchain adds by itself (OpenSSL doesn't restrict exports on macOS, so its
//! internal `ossl_*` functions leak there).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

use super::{Context, Outcome};
use crate::codegen::exports::LIBRARIES;
use crate::elf;
use crate::util::{Result, run_output};

/// Libraries rustyssl's may depend on besides libcrypto: the C library, the threading and
/// dynamic-loading libraries, and the unwinder Rust's runtime uses.
const SYSTEM_LIBRARIES: &[&str] = &[
    "libc.so.",
    "libm.so.",
    "libpthread.so.",
    "libdl.so.",
    "librt.so.",
    "libgcc_s.so.",
    "libunwind.so.",
    "libc.musl-",
    "ld-linux",
    "ld-musl-",
    "/usr/lib/libSystem.B.dylib",
];

/// A library's exports: name -> (version node, hidden), the version empty on macOS.
type Exports = BTreeMap<String, (String, bool)>;

/// Check 1: each library exports exactly what it must, each symbol at its version node.
pub fn symbols(cx: &Context) -> Result<Outcome> {
    let mut problems = Vec::new();
    let mut counts = Vec::new();
    let mut toolchain_extras = 0;
    let versioned = !cx.apple();
    for library in LIBRARIES {
        let expected = cx.expected_exports(library);
        let public = cx.exports.get(library).cloned().unwrap_or_default();
        let (ours, aliases) = exports_and_aliases(cx, &cx.shared(&cx.dist, library))?;
        let wanted: BTreeSet<(String, String)> = cx
            .profile
            .filter(|_| *library == "libcrypto")
            .map(|p| {
                p.aliases
                    .iter()
                    .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                    .collect()
            })
            .unwrap_or_default();
        for (name, node) in wanted.difference(&aliases) {
            problems.push(format!("rustyssl's {library} doesn't export {name}@{node}"));
        }
        for (name, node) in aliases.difference(&wanted) {
            problems.push(format!("rustyssl's {library} also exports {name}@{node}"));
        }
        let theirs = exports(cx, &cx.shared(&cx.reference, library))?;
        // Whatever the reference exports beyond its list is the toolchain's doing, not ours.
        let toolchain: BTreeSet<&String> = theirs
            .keys()
            .filter(|name| !public.contains_key(*name))
            .collect();

        let mut compare = |whose: &str, actual: &Exports, expected: &BTreeMap<String, String>| {
            problems.extend(differences(
                library, whose, actual, expected, &toolchain, versioned,
            ));
        };
        compare("rustyssl", &ours, &expected);
        compare("the reference", &theirs, &public);
        counts.push(format!("{} {library}", ours.len()));
        toolchain_extras += toolchain.len();
    }
    Ok(Outcome {
        summary: format!(
            "{} exports, as listed{} (the reference also exports {toolchain_extras} symbols \
             outside the lists)",
            counts.join(" + "),
            if versioned {
                " and at the right version nodes"
            } else {
                ""
            }
        ),
        problems,
    })
}

/// The differences between a library's `actual` exports and `expected` ones (name -> node).
/// `versioned` is false on macOS, which has no symbol versions.
fn differences(
    library: &str,
    whose: &str,
    actual: &Exports,
    expected: &BTreeMap<String, String>,
    allowed_extra: &BTreeSet<&String>,
    versioned: bool,
) -> Vec<String> {
    let mut problems = Vec::new();
    for (name, node) in expected {
        match actual.get(name) {
            None => problems.push(format!("{whose}'s {library} doesn't export {name}")),
            Some((version, hidden)) if versioned => {
                if version != node {
                    problems.push(format!(
                        "{whose}'s {library} exports {name} at {version:?}, not {node}"
                    ));
                }
                if *hidden {
                    problems.push(format!(
                        "{whose}'s {library} exports {name}@{node} as a non-default version"
                    ));
                }
            }
            Some(_) => {}
        }
    }
    for name in actual.keys() {
        if !expected.contains_key(name) && !allowed_extra.contains(name) {
            problems.push(format!("{whose}'s {library} also exports {name}"));
        }
    }
    problems
}

/// The exported functions of a shared library at their default versions, and the non-default
/// versions (`name@node`) of names it also exports by default: a profile's aliases.
fn exports_and_aliases(cx: &Context, path: &Path) -> Result<(Exports, BTreeSet<(String, String)>)> {
    let all = exports_listed(cx, path)?;
    let mut exports = Exports::new();
    let mut aliases = BTreeSet::new();
    for (name, version, hidden) in all.iter().filter(|(_, _, hidden)| !*hidden) {
        exports.insert(name.clone(), (version.clone(), *hidden));
    }
    for (name, version, hidden) in all {
        if hidden && exports.contains_key(&name) {
            aliases.insert((name, version));
        } else if hidden {
            exports.insert(name, (version, hidden));
        }
    }
    Ok((exports, aliases))
}

/// The exported functions of a shared library.
fn exports(cx: &Context, path: &Path) -> Result<Exports> {
    Ok(exports_listed(cx, path)?
        .into_iter()
        .map(|(name, version, hidden)| (name, (version, hidden)))
        .collect())
}

/// Every exported function of a shared library: (name, version, non-default).
fn exports_listed(cx: &Context, path: &Path) -> Result<Vec<(String, String, bool)>> {
    if cx.apple() {
        let symbols = crate::dist::symbols(path, cx.target)?;
        return Ok(symbols
            .into_iter()
            .filter(|(defined, _)| *defined)
            .map(|(_, name)| (name, String::new(), false))
            .collect());
    }
    let library = read_elf(path)?;
    Ok(library
        .exports
        .into_iter()
        // The linker defines an absolute symbol named after each version node.
        .filter(|e| !(e.absolute && e.version.as_deref() == Some(e.name.as_str())))
        .map(|e| (e.name, e.version.unwrap_or_default(), e.hidden))
        .collect())
}

fn read_elf(path: &Path) -> Result<elf::Library> {
    let data = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    elf::library(&data)
        .ok_or_else(|| format!("{}: not a readable ELF library", path.display()).into())
}

/// Check 2: each library's name, dependencies, and versions.
pub fn metadata(cx: &Context) -> Result<Outcome> {
    let mut problems = Vec::new();
    for library in LIBRARIES {
        let ours = cx.shared(&cx.dist, library);
        let theirs = cx.shared(&cx.reference, library);
        if cx.apple() {
            problems.extend(apple_metadata(library, &ours, &theirs)?);
        } else {
            problems.extend(elf_metadata(
                library,
                &read_elf(&ours)?,
                &read_elf(&theirs)?,
            ));
        }
    }
    Ok(Outcome {
        summary: if cx.apple() {
            "install names, compatibility and current versions, and dependencies match"
        } else {
            "sonames, dependencies, and version definitions match"
        }
        .to_owned(),
        problems,
    })
}

fn elf_metadata(library: &str, ours: &elf::Library, theirs: &elf::Library) -> Vec<String> {
    let mut problems = Vec::new();
    if ours.soname != theirs.soname {
        problems.push(format!(
            "{library}'s soname is {:?}, the reference's {:?}",
            ours.soname, theirs.soname
        ));
    }
    problems.extend(dependencies(library, &ours.needed));
    // The same version nodes with the same parents, in order; rustyssl adds its private node
    // to libcrypto only.
    let describe = |versions: &[elf::VersionDefinition]| -> Vec<String> {
        versions
            .iter()
            .filter(|v| v.name != "RUSTYSSL_PRIVATE")
            .map(|v| {
                let base = if v.base { " (base)" } else { "" };
                format!("{}{base} <- [{}]", v.name, v.parents.join(", "))
            })
            .collect()
    };
    let (ours_versions, their_versions) = (describe(&ours.versions), describe(&theirs.versions));
    if ours_versions != their_versions {
        problems.push(format!(
            "{library}'s version definitions are {ours_versions:?}, the reference's {their_versions:?}"
        ));
    }
    let private = ours.versions.iter().any(|v| v.name == "RUSTYSSL_PRIVATE");
    if private != (library == "libcrypto") {
        problems.push(format!(
            "{library} {} the RUSTYSSL_PRIVATE version",
            if private { "defines" } else { "doesn't define" }
        ));
    }
    problems
}

/// Problems with a library's dependencies: libssl must depend on libcrypto, and otherwise only
/// system libraries are allowed.
fn dependencies(library: &str, needed: &[String]) -> Vec<String> {
    let mut problems = Vec::new();
    let crypto = |name: &str| {
        name.rsplit('/')
            .next()
            .is_some_and(|leaf| leaf == "libcrypto.so.3" || leaf == "libcrypto.3.dylib")
    };
    if library == "libssl" && !needed.iter().any(|n| crypto(n)) {
        problems.push("libssl doesn't depend on libcrypto".to_owned());
    }
    for name in needed {
        let allowed = (library == "libssl" && crypto(name))
            || SYSTEM_LIBRARIES
                .iter()
                .any(|system| name.starts_with(system));
        if !allowed {
            problems.push(format!("{library} depends on {name}"));
        }
    }
    problems
}

/// What `otool` says about a dylib.
#[derive(Debug, PartialEq)]
struct Dylib {
    install_name: String,
    current: String,
    compatibility: String,
    dependencies: Vec<String>,
}

fn apple_metadata(library: &str, ours: &Path, theirs: &Path) -> Result<Vec<String>> {
    let (ours, theirs) = (dylib(ours)?, dylib(theirs)?);
    let mut problems = Vec::new();
    let leaf = |name: &str| name.rsplit('/').next().unwrap_or_default().to_owned();
    if leaf(&ours.install_name) != leaf(&theirs.install_name) || !ours.install_name.starts_with('/')
    {
        problems.push(format!(
            "{library}'s install name is {}, the reference's {}",
            ours.install_name, theirs.install_name
        ));
    }
    for (what, mine, reference) in [
        ("current", &ours.current, &theirs.current),
        ("compatibility", &ours.compatibility, &theirs.compatibility),
    ] {
        if mine != reference {
            problems.push(format!(
                "{library}'s {what} version is {mine}, the reference's {reference}"
            ));
        }
    }
    problems.extend(dependencies(library, &ours.dependencies));
    Ok(problems)
}

fn dylib(path: &Path) -> Result<Dylib> {
    let load_commands = run_output(Command::new("otool").arg("-l").arg(path))?;
    let libraries = run_output(Command::new("otool").arg("-L").arg(path))?;
    parse_otool(&load_commands, &libraries)
        .ok_or_else(|| format!("{}: unexpected otool output", path.display()).into())
}

/// Reads `otool -l` (for `LC_ID_DYLIB`) and `otool -L` (for the libraries it loads).
fn parse_otool(load_commands: &str, libraries: &str) -> Option<Dylib> {
    let id = load_commands
        .split("Load command")
        .find(|command| command.contains("cmd LC_ID_DYLIB"))?;
    let field = |key: &str| {
        id.lines()
            .find_map(|line| line.trim().strip_prefix(key))
            .map(|value| value.trim().to_owned())
    };
    let install_name = field("name ")?.split(" (offset").next()?.to_owned();
    let dependencies = libraries
        .lines()
        .skip(1)
        .filter_map(|line| line.trim().split(" (compatibility").next())
        .filter(|name| !name.is_empty() && *name != install_name)
        .map(str::to_owned)
        .collect();
    Some(Dylib {
        current: field("current version")?,
        compatibility: field("compatibility version")?,
        install_name,
        dependencies,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_differences() {
        let expected: BTreeMap<String, String> =
            [("A", "V1"), ("B", "V1"), ("C", "V2"), ("D", "V2")]
                .into_iter()
                .map(|(n, v)| (n.to_owned(), v.to_owned()))
                .collect();
        let actual: Exports = [
            ("A", "V1", false),
            ("B", "V2", false),
            ("C", "V2", true),
            ("E", "V1", false),
            ("_init", "", false),
        ]
        .into_iter()
        .map(|(n, v, h)| (n.to_owned(), (v.to_owned(), h)))
        .collect();
        let init = "_init".to_owned();
        let allowed = BTreeSet::from([&init]);
        assert_eq!(
            differences("libssl", "rustyssl", &actual, &expected, &allowed, true),
            [
                "rustyssl's libssl exports B at \"V2\", not V1",
                "rustyssl's libssl exports C@V2 as a non-default version",
                "rustyssl's libssl doesn't export D",
                "rustyssl's libssl also exports E",
            ]
        );
        // Without versions only the names count.
        assert_eq!(
            differences("libssl", "rustyssl", &actual, &expected, &allowed, false).len(),
            2
        );
    }

    #[test]
    fn dependency_rules() {
        let needed = |names: &[&str]| names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>();
        assert!(dependencies("libssl", &needed(&["libcrypto.so.3", "libc.so.6"])).is_empty());
        assert!(
            dependencies(
                "libcrypto",
                &needed(&["libc.so.6", "libgcc_s.so.1", "ld-linux-x86-64.so.2"])
            )
            .is_empty()
        );
        assert_eq!(
            dependencies("libcrypto", &needed(&["libcrypto.so.3"])).len(),
            1
        );
        assert_eq!(dependencies("libssl", &needed(&["libc.so.6"])).len(), 1);
        assert_eq!(dependencies("libcrypto", &needed(&["libz.so.1"])).len(), 1);
        assert!(
            dependencies(
                "libssl",
                &needed(&["/x/lib/libcrypto.3.dylib", "/usr/lib/libSystem.B.dylib"])
            )
            .is_empty()
        );
        assert_eq!(
            dependencies("libcrypto", &needed(&["/usr/lib/libiconv.2.dylib"])).len(),
            1
        );
    }

    #[test]
    fn reads_otool() {
        let load_commands = "Load command 3\n          cmd LC_ID_DYLIB\n      cmdsize 72\n         \
                             name /p/lib/libssl.3.dylib (offset 24)\n   time stamp 1 Thu Jan  1\n      \
                             current version 3.0.0\ncompatibility version 3.0.0\nLoad command 4\n          \
                             cmd LC_LOAD_DYLIB\n         name /usr/lib/libSystem.B.dylib (offset 24)\n      \
                             current version 1359.0.0\n";
        let libraries = "/p/lib/libssl.3.dylib:\n\t/p/lib/libssl.3.dylib (compatibility version 3.0.0, \
                         current version 3.0.0)\n\t/p/lib/libcrypto.3.dylib (compatibility version 3.0.0, \
                         current version 3.0.0)\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, \
                         current version 1359.0.0)\n";
        assert_eq!(
            parse_otool(load_commands, libraries),
            Some(Dylib {
                install_name: "/p/lib/libssl.3.dylib".to_owned(),
                current: "3.0.0".to_owned(),
                compatibility: "3.0.0".to_owned(),
                dependencies: vec![
                    "/p/lib/libcrypto.3.dylib".to_owned(),
                    "/usr/lib/libSystem.B.dylib".to_owned()
                ],
            })
        );
    }
}
