//! The platforms rustssl generates ABI definitions for, and how each one is named by OpenSSL's
//! `Configure`, by clang, and by Rust.

/// The vendored OpenSSL release series that codegen reads (`abi/openssl-<series>/`).
pub const OPENSSL_SERIES: &str = "3.5";

pub struct Target {
    /// OpenSSL `Configure` target; also the directory name under `abi/openssl-*/config/`.
    pub configure: &'static str,
    /// Target triple given to clang and bindgen.
    pub clang: &'static str,
    /// Rust target triple used to check the generated bindings.
    pub rust: &'static str,
    /// Module name of the generated bindings in `rustssl-abi`.
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
