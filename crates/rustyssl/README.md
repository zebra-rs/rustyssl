# rustyssl

rustyssl is a memory-safe Rust reimplementation of OpenSSL 3.6's `libcrypto` and `libssl`, built
as a **drop-in binary replacement**: a program built against OpenSSL 3.x runs on it unchanged,
with no recompile.

**This crate has no API.** It holds the name on crates.io. rustyssl isn't used as a Rust
dependency; it replaces the shared libraries `libcrypto.so.3` and `libssl.so.3` (macOS:
`libcrypto.3.dylib`, `libssl.3.dylib`), which are built by `cargo xtask dist`, not by cargo alone.

- Packages for Debian/Ubuntu, Fedora, RHEL-compatible, Alpine, and Homebrew:
  <https://github.com/zebra-rs/rustyssl/releases>
- Source, documentation, and how to build: <https://github.com/zebra-rs/rustyssl>
- Trying it on Ubuntu without installing anything:
  [docs/TRY-ON-UBUNTU.md](https://github.com/zebra-rs/rustyssl/blob/main/docs/TRY-ON-UBUNTU.md)

Rust programs that want OpenSSL's API can keep using the [`openssl`](https://crates.io/crates/openssl)
crate and run it on rustyssl's libraries.

Licensed under Apache-2.0, as OpenSSL 3 is.
