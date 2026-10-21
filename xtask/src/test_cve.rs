//! `cargo xtask test-cve [name...]`: the CVE regression suite (AGENTS.md rule 11, TEST_PLAN.md L9).
//!
//! `tests/cve/cves.txt` lists every OpenSSL CVE: those named in the reference's `CHANGES.md`
//! and on OpenSSL's vulnerabilities page. Each line says how the CVE is covered:
//!
//! - `test <file>`: a check in `tests/cve/<file>.c` whose description starts with the CVE's id;
//! - `apps <command>`: a corpus line of `tests/apps/<command>.txt` under a `# CVE-...` comment,
//!   which `cargo xtask test-apps` runs with our tool and upstream's;
//! - `covered <where>`: another suite that runs in the gates or in CI (named in the note);
//! - `n/a <reason>`: the vulnerable code has no counterpart in rustyssl's default build
//!   (removed protocol versions, platform assembly, FIPS module, scripts, ...);
//! - `gap <area>`: relevant, with no regression test yet; the note says why, and the report
//!   lists these as work left.
//!
//! The `tests/cve/*.c` programs are TAP programs like `tests/c`'s, run the same way: built
//! against the vendored headers, run on the reference and on rustyssl, passing every check
//! with identical output. They run in `tests/cve/data`, where the inputs they read live. The
//! result per CVE goes to `target/cve-report.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use crate::test_c;
use crate::util::{Result, fresh_dir, target_dir, workspace_root};

/// One line of `tests/cve/cves.txt`.
struct Entry {
    id: String,
    kind: String,
    place: String,
    note: String,
}

pub fn run(args: &[String]) -> Result {
    let root = workspace_root();
    let dir = root.join("tests/cve");
    let entries = index(&dir.join("cves.txt"))?;
    let (reference, dist) = test_c::prepare(&root)?;
    let known: BTreeSet<&str> = entries.iter().map(|e| e.id.as_str()).collect();
    let mut problems = Vec::new();

    // Every CVE the reference's changelog names is in the index.
    let changes = fs::read_to_string(reference_source(&root)?.join("CHANGES.md"))?;
    for id in cve_ids(&changes) {
        if !known.contains(id.as_str()) {
            problems.push(format!(
                "{id} (in the reference's CHANGES.md) isn't in tests/cve/cves.txt"
            ));
        }
    }

    // The programs.
    let tests = test_c::select(&dir, args)?;
    let work = target_dir(&root).join("xtask/test-cve");
    fresh_dir(&work)?;
    let data = dir.join("data");
    let mut passed: BTreeMap<String, String> = BTreeMap::new();
    let mut failed = Vec::new();
    for (name, source) in &tests {
        let exe = work.join(name);
        test_c::compile(source, &exe, &dist, &reference)?;
        let theirs = test_c::execute_in(&exe, &reference.join("lib"), &work, None, Some(&data))?;
        let ours = test_c::execute_in(&exe, &dist.join("lib"), &work, None, Some(&data))?;
        match test_c::verdict(&theirs, &ours) {
            Ok(checks) => {
                println!("PASS {name}: {checks} checks, identical on both");
                for line in ours.stdout.lines().filter(|l| l.starts_with("ok ")) {
                    for id in cve_ids(line) {
                        passed.entry(id).or_insert_with(|| name.clone());
                    }
                }
            }
            Err(problem) => {
                println!("FAIL {name}: {problem}");
                failed.push(name.clone());
            }
        }
    }

    // Each `test` and `apps` entry is really covered.
    let ran: BTreeSet<&str> = tests.iter().map(|(n, _)| n.as_str()).collect();
    for e in &entries {
        match e.kind.as_str() {
            "test" if ran.contains(e.place.as_str()) && !failed.contains(&e.place) => {
                if passed.get(&e.id) != Some(&e.place) {
                    problems.push(format!(
                        "{}: no passing check in {}.c names it",
                        e.id, e.place
                    ));
                }
            }
            "apps" => {
                let corpus = root.join("tests/apps").join(format!("{}.txt", e.place));
                let text = fs::read_to_string(&corpus).unwrap_or_default();
                if !text
                    .lines()
                    .any(|l| l.starts_with('#') && l.contains(&e.id))
                {
                    problems.push(format!(
                        "{}: no `# {}` comment in {}",
                        e.id,
                        e.id,
                        corpus.display()
                    ));
                }
            }
            _ => {}
        }
    }

    let report = report(&entries, &passed, &failed);
    let path = target_dir(&root).join("cve-report.md");
    fs::write(&path, report)?;
    for p in &problems {
        println!("FAIL {p}");
    }
    let tested = entries.iter().filter(|e| e.kind == "test").count();
    let count = |kind: &str| entries.iter().filter(|e| e.kind == kind).count();
    println!(
        "{} CVEs indexed: {tested} with tests here, {} in test-apps, {} covered elsewhere, {} not applicable, {} without a test yet; report in {}",
        entries.len(),
        count("apps"),
        count("covered"),
        count("n/a"),
        count("gap"),
        path.display()
    );
    if failed.is_empty() && problems.is_empty() {
        println!("{} CVE test programs passed", tests.len());
        Ok(())
    } else {
        Err(format!(
            "{} program(s) and {} index check(s) failed",
            failed.len(),
            problems.len()
        )
        .into())
    }
}

/// The reference's verified source tree.
fn reference_source(root: &Path) -> Result<std::path::PathBuf> {
    let version = crate::reference::vendored_version(root)?;
    Ok(target_dir(root).join(format!("ref/openssl-{version}/src")))
}

/// The CVE ids in a text, in order, each once.
fn cve_ids(text: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find("CVE-") {
        let tail = &rest[at + 4..];
        let year: String = tail.chars().take_while(char::is_ascii_digit).collect();
        let after = &tail[year.len()..];
        let number: String = after
            .strip_prefix('-')
            .map(|n| n.chars().take_while(char::is_ascii_digit).collect())
            .unwrap_or_default();
        if year.len() == 4 && !number.is_empty() {
            let id = format!("CVE-{year}-{number}");
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
        rest = tail;
    }
    ids
}

/// Reads the index: `<id> <kind> <place> <note...>`, `#` comments and blank lines skipped.
fn index(path: &Path) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    for (n, line) in fs::read_to_string(path)?.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut words = line.split_whitespace();
        let (Some(id), Some(kind), Some(place)) = (words.next(), words.next(), words.next()) else {
            return Err(format!(
                "{}:{}: expected `<id> <kind> <place> <note>`",
                path.display(),
                n + 1
            )
            .into());
        };
        if !["test", "apps", "covered", "n/a", "gap"].contains(&kind) || cve_ids(id) != [id] {
            return Err(format!("{}:{}: bad line", path.display(), n + 1).into());
        }
        if !seen.insert(id.to_owned()) {
            return Err(format!("{}:{}: {id} listed twice", path.display(), n + 1).into());
        }
        entries.push(Entry {
            id: id.to_owned(),
            kind: kind.to_owned(),
            place: place.to_owned(),
            note: words.collect::<Vec<_>>().join(" "),
        });
    }
    Ok(entries)
}

fn report(entries: &[Entry], passed: &BTreeMap<String, String>, failed: &[String]) -> String {
    let mut out = String::from(
        "# CVE regression suite\n\nWritten by `cargo xtask test-cve` from `tests/cve/cves.txt`.\n\n\
         | CVE | coverage | where | result | note |\n|---|---|---|---|---|\n",
    );
    for e in entries {
        let result = match e.kind.as_str() {
            "test" if failed.contains(&e.place) => "FAIL",
            "test" if passed.contains_key(&e.id) => "pass",
            "test" => "not run",
            _ => "",
        };
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} |",
            e.id, e.kind, e.place, result, e.note
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::cve_ids;

    #[test]
    fn ids() {
        assert_eq!(
            cve_ids("ok 3 - CVE-2014-0160: x (CVE-2016-2108, CVE-2014-0160) CVE-20 CVE-2026-"),
            ["CVE-2014-0160", "CVE-2016-2108"]
        );
    }
}
