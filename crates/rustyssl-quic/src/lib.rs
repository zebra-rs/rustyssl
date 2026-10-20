//! Sans-IO QUIC v1 for rustyssl (RFC 9000, 9001 and 9002; ADR 0006): packet and header
//! protection, frames, streams and flow control, loss detection and NewReno, connection IDs,
//! address validation, and the channel and port that tie them to a QUIC-mode TLS handshake.
//!
//! The crate performs no I/O and reads no clock: datagrams, time ([`Time`]) and the handshake's
//! output come in, datagrams and events go out. `rustyssl-capi` adapts it to OpenSSL's QUIC
//! objects and supplies the cryptography ([`crypto::Provider`]). Every length and offset from
//! the wire is checked; every collection a peer can grow is bounded.

#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

// pub mod ackm;
// pub mod cc;
// pub mod channel;
// pub mod cid;
// pub mod crypto;
pub mod error;
// pub mod fc;
// pub mod packet;
// pub mod port;
// pub mod stream;
pub mod time;
// pub mod tls;
// pub mod token;
// pub mod txp;
pub mod wire;

pub use error::{Error, Result};
pub use time::Time;

// /// A provider for this crate's tests and the fuzz targets: `rustyssl-tls`'s test provider plus
// /// header protection through `rustyssl-crypto` directly (the non-default `test-provider`
// /// feature). Never use it outside tests.
// testprov
