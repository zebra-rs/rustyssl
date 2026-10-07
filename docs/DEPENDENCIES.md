# Third-party dependencies

Every crate from outside this workspace is listed here before it's added (AGENTS.md, security
rule 8). Only pure-Rust crates are allowed: no C or assembly build scripts, `cc`, or `*-sys`
crates. CI enforces it with two gates:

- **`cargo deny check`** (`deny.toml`) denies yanked crates and RustSec advisories, licenses
  other than Apache-2.0, MIT, and Unicode-3.0, crates from unknown registries or git, and
  wildcard versions. It also allows **build scripts** only for the crates named in
  `[bans.build]`, and rejects executables or scripts shipped inside a crate. A new
  dependency with a build script fails CI until its script has been read and the crate is
  added there.
- **`cargo vet --locked`** (`supply-chain/`) imports the audits published by Bytecode
  Alliance, Google, ISRG, and Mozilla. With them, `quote` is fully audited; the other 12
  crates in the graph are recorded as exemptions (a reviewed snapshot, not an audit) and
  must be audited before the 1.0 release. A crate that isn't audited or exempted fails CI.

CI pins the tools (cargo-deny 0.20.2, cargo-vet 0.10.2); use the same versions locally.
Another cargo-vet version reformats `supply-chain/`, which fails the check.

| Crate | Version | Used by | Ships in libcrypto/libssl? | Purpose | Notes |
|---|---|---|---|---|---|
| `sha2` | 0.11 (`default-features = false`) | `xtask` | No | SHA-256 of downloaded OpenSSL release tarballs in `cargo xtask vendor` | RustCrypto, MIT OR Apache-2.0. Hashes only public data, so constant-time behavior doesn't matter here. Pulls in `digest`, `block-buffer`, `crypto-common`, `hybrid-array`, `typenum`, `cfg-if`, `cpufeatures`, and `libc` (FFI declarations only; its build script compiles no C). |
| `libc` | 0.2 (`default-features = false`) | `rustssl-abi`, `rustssl-capi` | Yes | Per-target definitions of the libc types in the OpenSSL API (`pthread_once_t` behind `CRYPTO_ONCE`, `pthread_t`, `pthread_key_t`, ...) | Maintained by the Rust project, MIT OR Apache-2.0. Type declarations only; its build script compiles no C. Already in the lock file through `cpufeatures`. |
| `syn` | 3 (`default-features = false`; `full`, `parsing`, `printing`) | `xtask` | No | Parses bindgen's function prototypes to generate the stubs in `cargo xtask codegen` | MIT OR Apache-2.0. Pulls in `proc-macro2` and `unicode-ident`. |
| `quote` | 1 (`default-features = false`) | `xtask` | No | Prints the parsed parameter and return types back as Rust source | MIT OR Apache-2.0. |

## Outside the shipped workspace

`fuzz/` is a separate Cargo workspace, so the gates above don't cover it and its
dependencies never reach the libraries.

| Crate | Version | Used by | Ships in libcrypto/libssl? | Purpose | Notes |
|---|---|---|---|---|---|
| `libfuzzer-sys` | 0.4 | `fuzz/` (`cargo +nightly fuzz`) | No | The libFuzzer driver for the fuzz targets | MIT OR Apache-2.0, maintained by the rust-fuzz project. **Exception to rule 8:** its build script compiles libFuzzer (C++). That's acceptable only because the fuzz workspace is a test harness: it's built on its own, and nothing in the main workspace may depend on it. |
