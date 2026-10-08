//! The platforms rustyssl generates ABI definitions for, and how each one is named by OpenSSL's
//! `Configure`, by clang, and by Rust.

use std::process::Command;

use crate::util::{Result, run_output};

/// The vendored OpenSSL release series that codegen reads (`abi/openssl-<series>/`).
pub const OPENSSL_SERIES: &str = "3.5";

pub struct Target {
    /// OpenSSL `Configure` target; also the directory name under `abi/openssl-*/config/`.
    pub configure: &'static str,
    /// Target triple given to clang and bindgen.
    pub clang: &'static str,
    /// Rust target triple used to check the generated bindings.
    pub rust: &'static str,
    /// Module name of the generated bindings in `rustyssl-abi`.
    pub module: &'static str,
    /// Rust `cfg` predicate that selects this target's bindings.
    pub cfg: &'static str,
}

pub const TARGETS: &[Target] = &[
    Target {
        configure: "linux-x86_64",
        clang: "x86_64-unknown-linux-gnu",
        rust: "x86_64-unknown-linux-gnu",
        module: "linux_x86_64",
        cfg: r#"all(target_os = "linux", target_arch = "x86_64")"#,
    },
    Target {
        configure: "linux-aarch64",
        clang: "aarch64-unknown-linux-gnu",
        rust: "aarch64-unknown-linux-gnu",
        module: "linux_aarch64",
        cfg: r#"all(target_os = "linux", target_arch = "aarch64")"#,
    },
    Target {
        configure: "darwin64-arm64",
        clang: "arm64-apple-macosx11.0",
        rust: "aarch64-apple-darwin",
        module: "macos_aarch64",
        cfg: r#"all(target_os = "macos", target_arch = "aarch64")"#,
    },
];

/// The host's Rust triple and the target whose ABI definitions it uses.
pub fn host() -> Result<(String, &'static Target)> {
    let info = run_output(Command::new("rustc").arg("-vV"))?;
    let host = info
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .ok_or("rustc -vV printed no host")?
        .to_owned();
    let target = TARGETS
        .iter()
        .find(|t| same_platform(t.rust, &host))
        .ok_or_else(|| format!("no rustyssl target for host {host}; see xtask/src/targets.rs"))?;
    Ok((host, target))
}

/// Whether `host` uses `target`'s ABI definitions: the same architecture and OS, whatever the
/// C library (`x86_64-unknown-linux-musl` uses the `linux-x86_64` ones, as OpenSSL's
/// `Configure` does).
fn same_platform(target: &str, host: &str) -> bool {
    let platform = |triple: &str| {
        let arch = triple.split('-').next().unwrap_or_default().to_owned();
        let os = if triple.contains("-linux") {
            "linux"
        } else if triple.contains("-apple-darwin") {
            "darwin"
        } else {
            ""
        };
        (arch, os)
    };
    let (arch, os) = platform(host);
    !os.is_empty() && platform(target) == (arch, os)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_map_to_targets_by_arch_and_os() {
        let linux = "x86_64-unknown-linux-gnu";
        assert!(same_platform(linux, "x86_64-unknown-linux-gnu"));
        assert!(same_platform(linux, "x86_64-unknown-linux-musl"));
        assert!(!same_platform(linux, "aarch64-unknown-linux-gnu"));
        assert!(!same_platform(linux, "x86_64-pc-windows-msvc"));
        assert!(same_platform(
            "aarch64-apple-darwin",
            "aarch64-apple-darwin"
        ));
        assert!(!same_platform(
            "aarch64-apple-darwin",
            "aarch64-unknown-linux-gnu"
        ));
    }
}
