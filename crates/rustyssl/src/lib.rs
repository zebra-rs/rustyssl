//! rustyssl is a memory-safe Rust reimplementation of OpenSSL 3.6's `libcrypto` and `libssl`, as
//! drop-in replacements for the shared libraries. This crate has no API: it holds the name on
//! crates.io and points to the releases (<https://github.com/zebra-rs/rustyssl/releases>). The
//! libraries are built by `cargo xtask dist` in the repository, not by depending on this crate.

#![forbid(unsafe_code)]
#![no_std]
