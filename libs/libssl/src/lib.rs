//! The libssl facade, linked into `libssl.so.3` / `libssl.3.dylib` by `cargo xtask dist`.
//!
//! It defines every `SSL_*` export, each a generated forwarder to libcrypto's private
//! `rustyssl_private_<name>`, and nothing else: no state, no implementation, and no use of the
//! standard library, so `dist` builds libssl from this crate's own objects alone
//! (docs/adr/0001-library-layout.md).

mod generated;
