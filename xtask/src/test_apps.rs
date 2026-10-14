//! `cargo xtask test-apps`: the reference OpenSSL's `openssl` tool on rustyssl (milestone M1:
//! "upstream `openssl dgst`/`enc`/`rand`/`speed`, built against our libs, work").
//!
//! Each line of `tests/apps/commands.txt` is run twice with the tool the reference build
//! installed: on the reference libraries, and on rustyssl's, by pointing the dynamic loader at
//! each. Both runs must print the same and exit the same, after masking what differs by design:
//! the library's version metadata (`+rustyssl...`) and the file and line in error lines. A line
//! starting with `~` (timings) must only succeed on both.

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::test_c::{LOADER_PATH, prepare};
use crate::util::{Result, fresh_dir, target_dir, workspace_root};

/// The configuration file both runs are pointed at, one that doesn't exist.
const MISSING_CONFIG: &str = "/nonexistent/rustyssl-tests/openssl.cnf";

/// One run's output: stdout, stderr, and the exit status, as one text.
fn run_tool(tool: &Path, lib: &Path, args: &[String], work: &Path) -> Result<(String, bool)> {
    let out = Command::new(tool)
        .args(args)
        .current_dir(work)
        .env(LOADER_PATH, lib)
        .env("OPENSSL_CONF", MISSING_CONFIG)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run {}: {e}", tool.display()))?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    text.push_str(&format!("[{}]\n", out.status));
    Ok((text, out.status.success()))
}

/// The output with the expected differences masked: the version's build metadata, the
/// directories the libraries were built with, and errors' `file:line:`.
fn masked(text: &str) -> String {
    text.lines()
        .map(|line| {
            let mut l = line.to_owned();
            if let Some(at) = l.find("+rustyssl") {
                let end = l[at..].find(' ').map_or(l.len(), |e| at + e);
                l.replace_range(at..end, "");
            }
            for dir in ["OPENSSLDIR: ", "ENGINESDIR: ", "MODULESDIR: "] {
                if l.starts_with(dir) {
                    l = format!("{dir}DIR");
                }
            }
            if let Some(at) = l.find(":error:") {
                // The thread's id comes first, which differs from run to run on Linux.
                if l[..at].chars().all(|c| c.is_ascii_hexdigit()) {
                    l.replace_range(..at, "THREAD");
                }
                l = mask_location(&l);
            }
            l
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// An error line's `:<file>.c:<line>:` (or `.rs`) as `:FILE:LINE:`.
fn mask_location(line: &str) -> String {
    let parts: Vec<&str> = line.split(':').collect();
    let at = parts.windows(2).position(|w| {
        matches!(w, [file, number] if (file.ends_with(".c") || file.ends_with(".rs"))
            && !number.is_empty()
            && number.chars().all(|c| c.is_ascii_digit()))
    });
    match at {
        Some(i) => {
            let mut out: Vec<&str> = parts.iter().take(i).copied().collect();
            out.push("FILE");
            out.push("LINE");
            out.extend(parts.iter().skip(i + 2));
            out.join(":")
        }
        None => line.to_owned(),
    }
}

pub fn run(_args: &[String]) -> Result {
    let root = workspace_root();
    let (reference, dist) = prepare(&root)?;
    let tool = reference.join("bin/openssl");
    let work = target_dir(&root).join("xtask/test-apps");
    fresh_dir(&work)?;
    let bin = work.join("data.bin");
    let txt = work.join("data.txt");
    // Fixed data: the same octets everywhere.
    let data: Vec<u8> = (0..100_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    fs::write(&bin, data)?;
    fs::write(&txt, "hello, rustyssl\n")?;

    // Guard: a missing library falls back to the one the tool was linked with.
    let (version, _) = run_tool(&tool, &dist.join("lib"), &["version".to_owned()], &work)?;
    if !version.contains("rustyssl") {
        return Err(format!("the tool didn't load rustyssl's library: {version}").into());
    }

    let list = fs::read_to_string(root.join("tests/apps/commands.txt"))?;
    let mut failures = Vec::new();
    let mut count = 0;
    for line in list.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (compare, line) = match line.strip_prefix('~') {
            Some(rest) => (false, rest),
            None => (true, line),
        };
        let args: Vec<String> = line
            .split_whitespace()
            .map(|a| {
                a.replace("{bin}", &bin.display().to_string())
                    .replace("{txt}", &txt.display().to_string())
                    .replace("{dir}", &work.display().to_string())
            })
            .collect();
        count += 1;
        let (theirs, theirs_ok) = run_tool(&tool, &reference.join("lib"), &args, &work)?;
        let (ours, ours_ok) = run_tool(&tool, &dist.join("lib"), &args, &work)?;
        let verdict = if compare {
            let (t, o) = (masked(&theirs), masked(&ours));
            if t == o {
                Ok(())
            } else {
                let at = t
                    .lines()
                    .zip(o.lines())
                    .position(|(a, b)| a != b)
                    .unwrap_or(0);
                let a = t.lines().nth(at).unwrap_or("(end)");
                let b = o.lines().nth(at).unwrap_or("(end)");
                Err(format!(
                    "line {}:\n  reference: {a}\n  rustyssl:  {b}",
                    at + 1
                ))
            }
        } else if theirs_ok && ours_ok {
            Ok(())
        } else {
            Err(format!(
                "exit: reference {theirs_ok}, rustyssl {ours_ok}\n{}",
                ours.lines().rev().take(3).collect::<Vec<_>>().join("\n")
            ))
        };
        match verdict {
            Ok(()) => println!("PASS openssl {line}"),
            Err(e) => {
                println!("FAIL openssl {line}: {e}");
                failures.push(line.to_owned());
            }
        }
    }
    if failures.is_empty() {
        println!("{count} commands of the reference's openssl tool behave the same on rustyssl");
        Ok(())
    } else {
        Err(format!("{} command(s) differ", failures.len()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masking() {
        assert_eq!(
            masked("OpenSSL 3.5.9 (Library: OpenSSL 3.5.9+rustyssl.0.1.0 29 Sep)"),
            "OpenSSL 3.5.9 (Library: OpenSSL 3.5.9 29 Sep)"
        );
        assert_eq!(
            masked("80:error:1C80006B:Provider routines:f:wrong final block length:a/b.c:467:"),
            "THREAD:error:1C80006B:Provider routines:f:wrong final block length:FILE:LINE:"
        );
        assert_eq!(masked("plain: 12:"), "plain: 12:");
        assert_eq!(
            masked(
                "80:error:0308010C:x:f:unsupported:crypto/evp/f.c:376:Global, Algorithm (a : 0)"
            ),
            "THREAD:error:0308010C:x:f:unsupported:FILE:LINE:Global, Algorithm (a : 0)"
        );
        assert_eq!(masked("OPENSSLDIR: \"/usr/local/ssl\""), "OPENSSLDIR: DIR");
    }
}
