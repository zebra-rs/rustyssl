//! Sans-IO TLS 1.0–1.3 and DTLS for rustyssl: the record layer, the client and server handshake
//! state machines, the key schedule, and the OpenSSL cipher-string parser (ADR 0002).
//!
//! This crate performs no I/O and knows nothing about C; `rustyssl-capi` adapts it to BIOs and
//! callbacks, and supplies the cryptography ([`crypto::Provider`]). Lengths and offsets from the
//! wire use checked arithmetic only.

#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

pub mod codec;
pub mod consts;
pub mod crypto;
pub mod error;
pub mod msgs;
