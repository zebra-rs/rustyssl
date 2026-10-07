# Third-party dependencies

Every crate from outside this workspace is listed here before it's added (AGENTS.md, security
rule 8). Only pure-Rust crates are allowed: no C or assembly build scripts, `cc`, or `*-sys`
crates. `cargo deny` and `cargo vet` gates arrive in Phase 0.8.

| Crate | Version | Used by | Ships in libcrypto/libssl? | Purpose | Notes |
|---|---|---|---|---|---|
| `sha2` | 0.11 (`default-features = false`) | `xtask` | No | SHA-256 of downloaded OpenSSL release tarballs in `cargo xtask vendor` | RustCrypto, MIT OR Apache-2.0. Hashes only public data, so constant-time behavior doesn't matter here. Pulls in `digest`, `block-buffer`, `crypto-common`, `hybrid-array`, `typenum`, `cfg-if`, `cpufeatures`, and `libc` (FFI declarations only; its build script compiles no C). |
