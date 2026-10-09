//! Cryptographic algorithms for rustyssl: the algorithm facade over vetted pure-Rust backends,
//! the DRBG hierarchy, BIGNUM, and the algorithms behind the built-in providers.
//!
//! Secret-dependent code must be constant-time and must zeroize secrets on drop.

#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

pub mod params;
