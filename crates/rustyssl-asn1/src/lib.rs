//! ASN.1 for rustyssl: a bounded DER/BER reader and writer, the universal types, the OID/NID
//! registry, base64, and PEM framing.
//!
//! Everything here parses attacker-controlled input, so lengths and offsets use checked
//! arithmetic only.

#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

mod generated;
pub mod objects;
pub mod oid;
