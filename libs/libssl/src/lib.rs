//! The libssl facade, linked into `libssl.so.3` / `libssl.3.dylib` by `cargo xtask dist`. It
//! defines every `SSL_*` export, with OpenSSL's symbol versions applied at link time, and keeps
//! no state of its own: each export will forward to libcrypto's private `RUSTSSL_PRIVATE`
//! entry points (step 0.6 of the plan). Until a function is implemented, its export is a
//! generated stub that aborts.

mod generated;
mod stub;
