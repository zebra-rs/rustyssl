//! Checks 6, 7, and 8: programs built the way applications build them.
//!
//! The test program references every public function of both libraries without calling any
//! (calling a stub would abort). Linked with immediate binding, it only starts if the dynamic
//! loader resolves every reference, at its version node on Linux. It then prints which file
//! defines a function from each library, to show which libraries it actually loaded.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::{Context, Outcome};
use crate::test_c::{LOADER_PATH, cc};
use crate::util::{Result, run_output};

/// Check 6: a program linked against the reference OpenSSL runs on rustyssl's libraries.
pub fn binary(cx: &Context) -> Result<Outcome> {
    let source = all_functions_program(cx)?;
    let exe = output(cx, "binary")?;
    let mut link = cc();
    link.arg(&source)
        .arg("-o")
        .arg(&exe)
        .arg("-w")
        .arg("-L")
        .arg(cx.reference.join("lib"))
        .args(["-lssl", "-lcrypto"]);
    if cx.apple() {
        link.arg("-Wl,-bind_at_load");
    } else {
        link.args(["-Wl,-z,now", "-ldl"]);
    }
    run_output(&mut link)?;

    let mut problems = Vec::new();
    let mut functions = 0;
    for (whose, prefix) in [("the reference", &cx.reference), ("rustyssl", &cx.dist)] {
        let output = run_with_libraries(&exe, &prefix.join("lib"))
            .map_err(|e| format!("on {whose}'s libraries: {e}"))?;
        let report = Report::parse(&output)?;
        functions = report.functions;
        for (library, file) in [("libssl", &report.libssl), ("libcrypto", &report.libcrypto)] {
            let expected = cx.shared(prefix, library).canonicalize()?;
            if Path::new(file).canonicalize().ok().as_ref() != Some(&expected) {
                problems.push(format!(
                    "on {whose}'s libraries, {library} was loaded from {file}, not {}",
                    expected.display()
                ));
            }
        }
    }
    Ok(Outcome {
        summary: format!(
            "a program linked against the reference resolves all {functions} functions on \
             rustyssl's libraries"
        ),
        problems,
    })
}

/// Check 7: the same program links against the static archives and runs.
pub fn static_linking(cx: &Context) -> Result<Outcome> {
    let source = all_functions_program(cx)?;
    let exe = output(cx, "static")?;
    let lib = cx.dist.join("lib");
    let private = pkg_config(cx, &["--static", "--libs-only-l", "libcrypto"])?;
    let mut link = cc();
    link.arg(&source)
        .arg("-o")
        .arg(&exe)
        .arg("-w")
        .arg(lib.join("libssl.a"))
        .arg(lib.join("libcrypto.a"))
        .args(
            private
                .split_whitespace()
                .filter(|flag| *flag != "-lcrypto"),
        );
    if !cx.apple() {
        link.arg("-ldl");
    }
    run_output(&mut link)?;
    let report = Report::parse(&run_output(&mut Command::new(&exe))?)?;
    Ok(Outcome {
        summary: format!(
            "a program referencing all {} functions links against libssl.a and libcrypto.a \
             and runs",
            report.functions
        ),
        problems: Vec::new(),
    })
}

/// Check 8: the installed headers equal the reference's and each compiles on its own, and the
/// pkg-config files describe the libraries correctly.
pub fn headers(cx: &Context) -> Result<Outcome> {
    let mut problems = Vec::new();
    let ours = cx.dist.join("include/openssl");
    let theirs = cx.reference.join("include/openssl");
    let names = header_names(&ours)?;
    let their_names = header_names(&theirs)?;
    for name in names.symmetric_difference(&their_names) {
        let whose = if names.contains(name) {
            "rustyssl"
        } else {
            "the reference"
        };
        problems.push(format!("only {whose} installs openssl/{name}"));
    }
    for name in names.intersection(&their_names) {
        if fs::read(ours.join(name))? != fs::read(theirs.join(name))? {
            problems.push(format!("openssl/{name} differs from the reference's"));
        }
    }

    // Each header on its own, as an application might include it. A header that fails on the
    // reference too is upstream's behavior, not ours.
    let alone = compile_alone(cx, &names, &cx.dist)?;
    let mut upstream = 0;
    for name in alone {
        if compile_alone(cx, &BTreeSet::from([name.clone()]), &cx.reference)?.is_empty() {
            problems.push(format!("openssl/{name} doesn't compile on its own"));
        } else {
            upstream += 1;
        }
    }

    for module in ["openssl", "libssl", "libcrypto"] {
        let version = pkg_config(cx, &["--modversion", module])?;
        let expected = pkg_config_at(&cx.reference, &["--modversion", module])?;
        if version != expected {
            problems.push(format!(
                "{module}.pc has version {}, the reference's {}",
                version.trim(),
                expected.trim()
            ));
        }
    }
    // A program built with pkg-config's flags compiles, links, and runs on the libraries.
    let flags = pkg_config(cx, &["--cflags", "--libs", "openssl"])?;
    let exe = output(cx, "pkg-config")?;
    let mut build = cc();
    build
        .arg(all_functions_program(cx)?)
        .arg("-o")
        .arg(&exe)
        .arg("-w")
        .args(flags.split_whitespace());
    if !cx.apple() {
        build.arg("-ldl");
    }
    run_output(&mut build)?;
    run_with_libraries(&exe, &cx.dist.join("lib"))?;

    Ok(Outcome {
        summary: format!(
            "{} headers equal the reference's and compile alone ({upstream} fail upstream too); \
             pkg-config builds a working program",
            names.len()
        ),
        problems,
    })
}

/// Where a check builds its program: `<work>/<check>/all-functions`.
fn output(cx: &Context, check: &str) -> Result<PathBuf> {
    let dir = cx.work.join(check);
    fs::create_dir_all(&dir)?;
    Ok(dir.join("all-functions"))
}

/// The C program that references every public function, written once.
fn all_functions_program(cx: &Context) -> Result<PathBuf> {
    let path = cx.work.join("all-functions.c");
    if path.exists() {
        return Ok(path);
    }
    let first = |library: &str| {
        cx.exports
            .get(library)
            .and_then(|e| e.keys().next().cloned())
            .ok_or_else(|| format!("no {library} exports"))
    };
    let (ssl, crypto) = (first("libssl")?, first("libcrypto")?);
    let functions: Vec<&str> = cx.public_functions().collect();
    let mut source = String::from(
        "/* Generated by `cargo xtask abi-check`: references every public function of libssl\n   \
         and libcrypto, and reports which file defines one function of each. */\n\
         #define _GNU_SOURCE\n#include <dlfcn.h>\n#include <stdio.h>\n\n",
    );
    for name in &functions {
        writeln!(source, "extern void {name}(void);")?;
    }
    source.push_str("\nstatic void (*const functions[])(void) = {\n");
    for name in &functions {
        writeln!(source, "    {name},")?;
    }
    write!(
        source,
        "}};\n\nstatic const char *file_of(void (*function)(void))\n{{\n    Dl_info info;\n\n    \
         if (dladdr((void *)function, &info) && info.dli_fname != NULL)\n        \
         return info.dli_fname;\n    return \"?\";\n}}\n\n\
         int main(void)\n{{\n    \
         printf(\"functions %zu\\n\", sizeof(functions) / sizeof(functions[0]));\n    \
         printf(\"libssl %s\\n\", file_of({ssl}));\n    \
         printf(\"libcrypto %s\\n\", file_of({crypto}));\n    return 0;\n}}\n"
    )?;
    fs::write(&path, source)?;
    Ok(path)
}

/// What the program printed.
#[derive(Debug, PartialEq)]
struct Report {
    functions: usize,
    libssl: String,
    libcrypto: String,
}

impl Report {
    fn parse(output: &str) -> Result<Self> {
        let field = |key: &str| {
            output
                .lines()
                .find_map(|line| line.strip_prefix(key)?.strip_prefix(' '))
                .map(str::to_owned)
                .ok_or_else(|| format!("the program printed no {key} line: {output:?}"))
        };
        Ok(Self {
            functions: field("functions")?.parse()?,
            libssl: field("libssl")?,
            libcrypto: field("libcrypto")?,
        })
    }
}

/// Runs `exe` with the dynamic loader looking in `lib` first.
fn run_with_libraries(exe: &Path, lib: &Path) -> Result<String> {
    run_output(Command::new(exe).env(LOADER_PATH, lib))
}

/// Runs pkg-config on rustyssl's `.pc` files only.
fn pkg_config(cx: &Context, args: &[&str]) -> Result<String> {
    pkg_config_at(&cx.dist, args)
}

fn pkg_config_at(prefix: &Path, args: &[&str]) -> Result<String> {
    run_output(
        Command::new("pkg-config")
            .env("PKG_CONFIG_LIBDIR", prefix.join("lib/pkgconfig"))
            .env_remove("PKG_CONFIG_PATH")
            .args(args),
    )
}

/// The `.h` files in a directory.
fn header_names(dir: &Path) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(dir)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if name.ends_with(".h") {
            names.insert(name);
        }
    }
    Ok(names)
}

/// The headers in `names` that fail to compile on their own against `prefix/include`, compiled
/// in parallel.
fn compile_alone(cx: &Context, names: &BTreeSet<String>, prefix: &Path) -> Result<Vec<String>> {
    let dir = cx.work.join("headers").join(
        prefix
            .file_name()
            .map_or_else(|| "prefix".into(), |n| n.to_string_lossy().into_owned()),
    );
    fs::create_dir_all(&dir)?;
    let names: Vec<&String> = names.iter().collect();
    let next = AtomicUsize::new(0);
    let failed = Mutex::new(Vec::new());
    let errors = Mutex::new(Vec::new());
    let jobs = std::thread::available_parallelism().map_or(4, usize::from);
    std::thread::scope(|scope| {
        for _ in 0..jobs {
            scope.spawn(|| {
                while let Some(name) = names.get(next.fetch_add(1, Ordering::Relaxed)) {
                    let file = dir.join(format!("{name}.c"));
                    let result = fs::write(&file, format!("#include <openssl/{name}>\n"))
                        .map_err(|e| e.to_string())
                        .map(|()| {
                            cc().args(["-std=c99", "-fsyntax-only", "-I"])
                                .arg(prefix.join("include"))
                                .arg(&file)
                                .output()
                        });
                    match result {
                        Ok(Ok(output)) if output.status.success() => {}
                        Ok(Ok(_)) => {
                            if let Ok(mut failed) = failed.lock() {
                                failed.push((*name).clone());
                            }
                        }
                        Ok(Err(e)) => {
                            if let Ok(mut errors) = errors.lock() {
                                errors.push(e.to_string());
                            }
                        }
                        Err(e) => {
                            if let Ok(mut errors) = errors.lock() {
                                errors.push(e);
                            }
                        }
                    }
                }
            });
        }
    });
    let errors = errors
        .into_inner()
        .map_err(|_| "a compile thread panicked")?;
    if let Some(error) = errors.first() {
        return Err(format!("cannot run the C compiler: {error}").into());
    }
    let mut failed = failed
        .into_inner()
        .map_err(|_| "a compile thread panicked")?;
    failed.sort();
    Ok(failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_program_report() {
        let report = Report::parse(
            "functions 6479\nlibssl /d/lib/libssl.so.3\nlibcrypto /d/lib/libcrypto.so.3\n",
        )
        .unwrap();
        assert_eq!(
            report,
            Report {
                functions: 6479,
                libssl: "/d/lib/libssl.so.3".to_owned(),
                libcrypto: "/d/lib/libcrypto.so.3".to_owned(),
            }
        );
        assert!(Report::parse("functions 1\n").is_err());
    }
}
