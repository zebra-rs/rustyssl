# Third-party dependencies

Every crate from outside this workspace is listed here before it's added (README.md, security
rule 8). Only pure-Rust crates are allowed: no C or assembly build scripts, `cc`, or `*-sys`
crates. CI enforces it with two gates:

- **`cargo deny check`** (`deny.toml`) denies yanked crates and RustSec advisories, licenses
  other than Apache-2.0, BSD-3-Clause, MIT, and Unicode-3.0, crates from unknown registries
  or git, and wildcard versions. It also allows **build scripts** only for the crates named
  in `[bans.build]`, and rejects executables or scripts shipped inside a crate. A new
  dependency with a build script fails CI until its script has been read and the crate is
  added there.
- **`cargo vet --locked`** (`supply-chain/`) imports the audits published by Bytecode
  Alliance, Google, ISRG, and Mozilla. With them, `quote` and `subtle` are fully audited; the
  other 22 crates in the graph are recorded as exemptions (a reviewed snapshot, not an audit)
  and must be audited before the 1.0 release. A crate that isn't audited or exempted fails CI.

CI pins the tools (cargo-deny 0.20.2, cargo-vet 0.10.2); use the same versions locally.
Another cargo-vet version reformats `supply-chain/`, which fails the check.

| Crate | Version | Used by | Ships in libcrypto/libssl? | Purpose | Notes |
|---|---|---|---|---|---|
| `sha2` | 0.11 (`default-features = false`) | `xtask`, `rustyssl-crypto` | Yes | SHA-224/256/384/512 and SHA-512/224 and /256 (step 3.2); in `xtask`, SHA-256 of downloaded OpenSSL release tarballs | RustCrypto, MIT OR Apache-2.0. Pulls in `digest`, `block-buffer`, `crypto-common`, `hybrid-array`, `typenum`, `cfg-if`, `cpufeatures`, and `libc` (FFI declarations only; its build script compiles no C). Uses the x86 SHA-NI and ARMv8 SHA-2 intrinsics when `cpufeatures` detects them at run time; no assembly on our targets. **Constant time:** additions, rotations, and logic only, with no data-dependent branches or table lookups. |
| `digest` | 0.11 (`default-features = false`) | `rustyssl-crypto` | Yes | The traits the RustCrypto hashes implement (`Digest`, `FixedOutputReset`), which the digest backend's adapters use | RustCrypto, MIT OR Apache-2.0. The hashes enable its `mac` feature, which brings `ctutils`. |
| `sha1` | 0.11 (`default-features = false`) | `rustyssl-crypto` | Yes | SHA-1 (and the SHA-1 half of MD5-SHA1) | RustCrypto, MIT OR Apache-2.0. x86 SHA-NI and ARMv8 SHA-2 intrinsics when detected at run time; its `asm!` backend is for LoongArch64 only, not built for our targets. **Constant time:** as `sha2`. Not collision-resistant; offered for compatibility, as OpenSSL does. |
| `md-5` | 0.11 (`default-features = false`) | `rustyssl-crypto` | Yes | MD5 and the MD5 half of MD5-SHA1 | RustCrypto, MIT OR Apache-2.0. Portable code on our targets (its `asm!` backend is LoongArch64's). **Constant time:** as `sha2`. Broken; offered for compatibility. |
| `md4` | 0.11 (`default-features = false`) | `rustyssl-crypto` | Yes | MD4, for the legacy provider | RustCrypto, MIT OR Apache-2.0, `#![forbid(unsafe_code)]`. **Constant time:** as `sha2`. Broken; legacy provider only. |
| `sm3` | 0.5 (`default-features = false`) | `rustyssl-crypto` | Yes | SM3 | RustCrypto, MIT OR Apache-2.0, `#![forbid(unsafe_code)]`. **Constant time:** as `sha2`. |
| `blake2` | 0.11 (`default-features = false`) | `rustyssl-crypto` | Yes | BLAKE2s-256 and BLAKE2b-512 | RustCrypto, MIT OR Apache-2.0. One `unsafe` block (a byte view of its SIMD state). **Constant time:** additions, rotations, and XOR only. |
| `ripemd` | 0.2 (`default-features = false`) | `rustyssl-crypto` | Yes | RIPEMD-160 | RustCrypto, MIT OR Apache-2.0, `#![forbid(unsafe_code)]`. **Constant time:** as `sha2`. |
| `whirlpool` | 0.11 (`default-features = false`) | `rustyssl-crypto` | Yes | Whirlpool, for the legacy provider | RustCrypto, MIT OR Apache-2.0, `#![deny(unsafe_code)]`. **Not constant time:** its rounds look up S-box tables by state octets, so hashing secret data (an HMAC key) can leak through the cache, as OpenSSL's table implementation can. Legacy provider only. |
| `keccak` | 0.2 (`default-features = false`) | `rustyssl-crypto` | Yes | The Keccak-f[1600] permutation under our own sponge (SHA-3, SHAKE, KECCAK-KMAC) | RustCrypto, Apache-2.0 OR MIT. Uses the ARMv8 SHA-3 intrinsics when `cpufeatures` detects them; no assembly. **Constant time:** XOR, AND, NOT, and rotations only. |
| `ctutils` | 0.4 | `rustyssl-crypto` (through `digest`'s `mac` feature) | Yes | Constant-time equality for `digest`'s MAC verification | RustCrypto, Apache-2.0 OR MIT. One `unsafe` block. Brings `cmov`. |
| `cmov` | 0.5 | `rustyssl-crypto` (through `ctutils`) | Yes | Constant-time conditional moves and comparisons | RustCrypto, Apache-2.0 OR MIT. **Inline assembly:** on x86 and AArch64 it uses `core::arch::asm!` (`cmov`, `csel`) so the compiler can't turn the selection into a branch. Rule 8 bans C and assembly *build scripts* and `*-sys` crates, and allows `core::arch`; this is `core::arch` inline assembly used for constant-time behavior, reviewed here (pure, no memory access, `nostack`), so it's accepted. |
| `libc` | 0.2 (`default-features = false`) | `rustyssl-abi`, `rustyssl-capi` | Yes | Per-target definitions of the libc types in the OpenSSL API (`pthread_once_t` behind `CRYPTO_ONCE`, `pthread_t`, `pthread_key_t`, ...) | Maintained by the Rust project, MIT OR Apache-2.0. Type declarations only; its build script compiles no C. Already in the lock file through `cpufeatures`. |
| `syn` | 3 (`default-features = false`; `full`, `parsing`, `printing`) | `xtask` | No | Parses bindgen's function prototypes to generate the stubs in `cargo xtask codegen` | MIT OR Apache-2.0. Pulls in `proc-macro2` and `unicode-ident`. |
| `quote` | 1 (`default-features = false`) | `xtask` | No | Prints the parsed parameter and return types back as Rust source | MIT OR Apache-2.0. |
| `subtle` | 2.6 (`default-features = false`) | `rustyssl-capi` | Yes | Constant-time comparison: `CRYPTO_memcmp` now, MAC and tag checks later (security rule 4) | dalek-cryptography, BSD-3-Clause, no dependencies. Fully audited through the imported audits (`cargo vet`). **Constant time:** `ct_eq` combines byte comparisons with `Choice` values kept behind an optimization barrier, so no branch depends on the data; it's constant-time in the contents, not the length. |

## Outside the shipped workspace

`fuzz/` is a separate Cargo workspace, so the gates above don't cover it and its
dependencies never reach the libraries.

| Crate | Version | Used by | Ships in libcrypto/libssl? | Purpose | Notes |
|---|---|---|---|---|---|
| `libfuzzer-sys` | 0.4 | `fuzz/` (`cargo +nightly fuzz`) | No | The libFuzzer driver for the fuzz targets | MIT OR Apache-2.0, maintained by the rust-fuzz project. **Exception to rule 8:** its build script compiles libFuzzer (C++). That's acceptable only because the fuzz workspace is a test harness: it's built on its own, and nothing in the main workspace may depend on it. |
