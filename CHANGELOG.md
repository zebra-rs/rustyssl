# Changelog

All notable changes to rustyssl are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the Rust crates follow
[Semantic Versioning](https://semver.org/). The C ABI is OpenSSL's 3.x ABI and doesn't change
with rustyssl's version.

## [1.0.0] - unreleased

The first release: a memory-safe Rust reimplementation of OpenSSL 3.6.5's `libcrypto.so.3` and
`libssl.so.3` (macOS: `lib*.3.dylib`) and of the `openssl` command-line tool, as drop-in binary
replacements. Applications built against OpenSSL 3.x run on it unchanged. See
[docs/RELEASE-NOTES-1.0.md](docs/RELEASE-NOTES-1.0.md).

### Added

- **libcrypto:** all 5899 exports of OpenSSL 3.6.5's `libcrypto.num` with OpenSSL's symbol
  versions (`OPENSSL_3.0.0` to `OPENSSL_3.6.0`), sonames, and macOS install names; the provider
  architecture with the `default`, `base`, `legacy`, and `null` providers, and third-party C
  providers (`OSSL_provider_init` and the core upcalls). Phases 0–6 and 9.
- **libssl:** all 603 exports: TLS 1.0–1.3, DTLS, and QUIC (client and server, the SSL QUIC API).
  Phases 7, 8, and 10.
- **The `openssl` tool** in Rust, every command upstream's has, with byte-identical output
  (ADR 0007). Phase 11.
- **Packaging** (Phase 12.3): `cargo xtask package <debian|fedora|el|alpine|homebrew>`
  side-by-side installs with `rustyssl-select`, recipes under `packaging/`, a Fedora profile
  (`cargo xtask dist --profile fedora`) with Fedora's MD2, SCTP, and `OPENSSL_3.1.0` extras, and
  [docs/MIGRATION.md](docs/MIGRATION.md).
- **Verification:** the C conformance suite (`test-c`), the CLI suites (`test-apps`), differential
  testing against the reference, upstream's whole test tree (`test-openssl-suite --all`, with
  our tool too), Wycheproof, BoGo, tlsfuzzer, interop (OpenSSL, GnuTLS, QUIC peers), consumer
  suites (rust-openssl, Ruby, pyca/cryptography, Node.js, ngtcp2, curl over HTTP/3), third-party
  providers (oqs, PKCS#11, TPM2), distribution system tests (`test-distro`), the CVE regression
  suite (`test-cve`, all 304 OpenSSL CVEs indexed), constant-time checks (`test-timing`), fuzzing
  (`fuzz/`, ClusterFuzzLite in CI), an `unsafe` budget (`unsafe-audit`), and benchmarks
  (`bench`).
- **Security documents:** [docs/security/](docs/security/): the `unsafe` review, the
  constant-time report, and the package for an external audit.

### Milestones

| Milestone | Status |
|---|---|
| M0 Links | met |
| M1 libcrypto basics | met, except the 24-hour EVP differential campaign (on hold) |
| M2 Vertical slice | curl and nginx over TLS 1.3 on rustyssl, in the distribution tests and interop; not tested against browsers or public sites |
| M3 OpenSSH | sshd and ssh logins pass on rustyssl (distribution tests, Ubuntu 24.04); OpenSSH's own regression suite hasn't been run |
| M4 Mainstream TLS | tlsfuzzer, BoGo, and upstream's ssl recipes pass; nginx-tests, curl's TLS tests, and CPython's `test_ssl` haven't been run |
| M5 Full libssl | met |
| M6 Full libcrypto | met (macOS and Linux) |
| M7 1.0 | distribution tests, the CVE suite, the constant-time report, and the 1.0 performance targets are done; open: the external security audit (not done) and the M1, M3, and M4 items above |

[1.0.0]: https://github.com/zebra-rs/rustyssl/releases/tag/v1.0.0
