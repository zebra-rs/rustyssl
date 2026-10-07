//! The libcrypto facade, linked into `libcrypto.so.3` / `libcrypto.3.dylib` by
//! `cargo xtask dist`. All rustssl state and code lives in this library, including the TLS
//! implementation that libssl forwards to.
//!
//! The exports themselves are defined in `rustssl-capi`; this crate only links them in.

// Referencing the crate forces it to be linked, so its `#[unsafe(no_mangle)]` exports end up
// in this library.
extern crate rustssl_capi;
