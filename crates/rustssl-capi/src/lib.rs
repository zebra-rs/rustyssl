//! The C ABI layer of rustssl: every `extern "C"` export of libcrypto and libssl, the opaque
//! handle model, BIOs, C callbacks, `OSSL_PARAM`, ex_data, the error queue, `CRYPTO_malloc`,
//! and the ASN1_ITEM template engine.
//!
//! This is the only library crate allowed to contain `unsafe` code. Every `unsafe` block needs
//! a `// SAFETY:` comment, and every export goes through `ffi_export!` so that no panic
//! crosses into C.
