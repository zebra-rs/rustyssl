//! Public-key infrastructure for rustyssl: X.509 certificates, CRLs, and CSRs, RFC 5280 path
//! validation, PKCS#7/#8/#12, CMS, OCSP, time-stamping, and certificate transparency.
//!
//! Everything here parses attacker-controlled input, so lengths and offsets use checked
//! arithmetic only.

#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

pub mod identity;
pub mod ip;
pub mod ncons;
pub mod punycode;
