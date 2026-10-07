//! Sans-IO TLS 1.0–1.3 and DTLS for rustssl: the record layer, the client and server handshake
//! state machines, the key schedule, and the OpenSSL cipher-string parser.
//!
//! This crate performs no I/O and knows nothing about C; `rustssl-capi` adapts it to BIOs and
//! callbacks. Lengths and offsets from the wire use checked arithmetic only.

#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]
