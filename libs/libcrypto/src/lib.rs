//! Builds `libcrypto.so.3` / `libcrypto.a`. All rustssl state and code lives in this library,
//! including the TLS implementation that `libssl` forwards to.
//!
//! The exports themselves are defined in `rustssl-capi`; this crate only links them in.
//! Soname, install name, and symbol versions are set by `build.rs` (Phase 0.5).

// Referencing the crate forces it to be linked, so its `#[unsafe(no_mangle)]` exports end up
// in this library.
extern crate rustssl_capi;
