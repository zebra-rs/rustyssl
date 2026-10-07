//! Builds `libssl.so.3`: a thin facade that exports the `SSL_*` symbols with OpenSSL's symbol
//! versions and forwards each call to libcrypto's private `RUSTSSL_PRIVATE` entry points.
//!
//! It keeps no state of its own. The Phase 0.6 spike validates this layout, including whether
//! a `libssl.a` is needed, before any forwarding code is written.
