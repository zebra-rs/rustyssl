# rustyssl 1.0

## 1.0.1 (security)

1.0.1 fixes one advisory in a dependency, and changes nothing else (the same OpenSSL 3.6.5 ABI;
`OpenSSL_version()` reads `OpenSSL 3.6.5+rustyssl.1.0.1 ...`). Upgrading is recommended.

- **[RUSTSEC-2026-0385](https://rustsec.org/advisories/RUSTSEC-2026-0385)** in `ctutils` (now
  0.4.5): before 0.4.4, `ctutils::Choice`'s mask functions could compile to a branch on a secret
  value, and its `u128` comparisons branched on 32-bit targets. RustCrypto's `digest` (MAC
  verification) and `universal-hash` (Poly1305, POLYVAL/GHASH) use it, so a timing side channel
  in those paths can't be ruled out for 1.0.0.

## 1.0.0

rustyssl is a memory-safe Rust reimplementation of OpenSSL's `libcrypto` and `libssl`, built as
a **drop-in binary replacement**: a program built against OpenSSL 3.x runs on it unchanged, with
no recompile. 1.0 implements **OpenSSL 3.6.5's ABI** and ships its `openssl` command-line tool,
also in Rust.

## What's in it

- `libcrypto.so.3` and `libssl.so.3` (macOS: `libcrypto.3.dylib`, `libssl.3.dylib`) with all of
  OpenSSL 3.6.5's exports (5899 and 603) under OpenSSL's symbol versions (`OPENSSL_3.0.0` to
  `OPENSSL_3.6.0`), sonames, and install names. Programs built against any OpenSSL 3.x load it.
- TLS 1.0–1.3, DTLS, and QUIC; the providers (`default`, `base`, `legacy`, `null`) and
  third-party C providers; OpenSSL's configuration files (`openssl.cnf`, distribution crypto
  policies).
- The `openssl` tool, with byte-identical output to upstream's.
- `OpenSSL_version()` reads `OpenSSL 3.6.5+rustyssl.1.0.0 ...`, so you can tell which library a
  program loaded; `OPENSSL_VERSION_NUMBER` and the rest of the ABI are 3.6.5's.

Default features match OpenSSL's default build plus `enable-ec_nistp_64_gcc_128`; what upstream
disables by default stays disabled, and legacy algorithms are in the `legacy` provider. There
is no FIPS provider.

## Platforms and what was verified where

| Platform | Verified |
|---|---|
| macOS arm64 | every gate, upstream's whole test tree (4334/4334 eligible subtests, with our tool too), the consumer suites, timing, benchmarks |
| Linux x86_64 and aarch64, glibc | CI's gates on x86_64 (and weekly on aarch64); upstream's tree with our tool (x86_64 4377/4377, aarch64 4376/4376) |
| Linux, musl (Alpine) | the distribution tests |
| Debian 13, Ubuntu 24.04, Fedora 44, AlmaLinux 10, Alpine, Homebrew | `cargo xtask test-distro` (arm64): ssh, nginx, httpd, curl, wget, git, pip, PostgreSQL, Fedora's crypto policies |
| Ubuntu 22.04 and 24.04, x86_64 and arm64 | [docs/TRY-ON-UBUNTU.md](TRY-ON-UBUNTU.md) |

**OpenSSH on Ubuntu 22.04 refuses rustyssl:** its OpenSSH 8.9 accepts only OpenSSL 3.0.x
("OpenSSL version mismatch"), as it would refuse a real OpenSSL 3.6. Don't switch a 22.04
machine's system libraries to rustyssl if you log in to it with ssh. OpenSSH 9.6 (Ubuntu 24.04)
works.

The distribution tests ran in arm64 containers; the x86_64 ones haven't been run.

## Performance

Against OpenSSL 3.6.5 (with its assembly) on arm64 macOS, rustyssl is within 1.25× on hashes
from 1 KiB, faster on Ed25519, and within 2.6–4.8× on AES and ChaCha bulk and 1.9–3.9× on
handshakes. rustyssl uses no assembly. The 1.0 targets ([docs/PERFORMANCE.md](PERFORMANCE.md))
are met: handshakes within 4×, resumption within 3×, AEAD bulk within 5×, hashes within 1.25×
from 1 KiB, and no regression past 5% (`cargo xtask bench --compare`). Closer targets are
post-1.0 work.

## Security

- `unsafe` only in the FFI layer (`rustyssl-capi`, `rustyssl-ossl`, the library shims); every
  export runs under a panic guard, and an `unsafe` budget per module is checked in CI
  ([docs/security/unsafe-review.md](security/unsafe-review.md)).
- Every OpenSSL CVE (304) is indexed in `tests/cve/cves.txt`: 235 tested, 2 in `test-apps`,
  19 covered by other suites, 47 not applicable, 1 without a test (CVE-2018-0737, RSA key
  generation's cache timing).
- Constant-time checks of secret-dependent code ([docs/security/constant-time.md](security/constant-time.md)).
- Fuzzing of every parser and the TLS, DTLS, and QUIC state machines, on each pull request
  and daily (ClusterFuzzLite).
- **No external security audit has been done.** The package for one is in
  [docs/security/audit/](security/audit/).

## Deviations from OpenSSL

About 300 behaviours differ on purpose, each for safety and each with a test
([docs/DEVIATIONS.md](DEVIATIONS.md)). Almost all are calls that crash, loop, or corrupt memory
in OpenSSL when given NULL or out-of-range arguments, which rustyssl refuses with OpenSSL's
failure value instead. A few concern behaviour: for example, `OSSL_CMP_get1_rootCaKeyUpdate`
clears its outputs on failure, and the `openssl ocsp` responder drops a connection that sends
nothing.

## Known gaps

- The external audit (above); OpenSSH's regression suite, nginx-tests, curl's TLS tests, and
  CPython's `test_ssl` haven't been run; the 24-hour EVP differential campaign hasn't run.
- Session tickets carry rustyssl's own encoding, so their length differs from OpenSSL's.
- `-starttls` is tested against scripted servers, not real ones.
- The security callback's checks run in a different order (`-security_debug_verbose`).
- No prebuilt packages for distributions' package managers; the release has tarballs.

## Installing and trying it

- Build: `cargo xtask dist` (the libraries and tool in `target/dist/`).
- Try one program: `LD_LIBRARY_PATH=target/dist/lib curl https://...`
  ([docs/TRY-ON-UBUNTU.md](TRY-ON-UBUNTU.md)).
- Install side by side: the release's tarballs, or `cargo xtask package <layout>`, and
  `rustyssl-select rustyssl|system` ([docs/MIGRATION.md](MIGRATION.md)).

## Compatibility promise

rustyssl's C ABI is OpenSSL's 3.x ABI: later 1.x releases keep every export, symbol version, and
layout, and follow OpenSSL 3.x behaviour. The Rust crates follow Semantic Versioning. A future
release adds OpenSSL 4.0's ABI (`libcrypto.so.4`) from the same core.

Licensed under Apache-2.0, as OpenSSL 3 is.
