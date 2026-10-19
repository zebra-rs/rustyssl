//! Cryptographic algorithms for rustyssl: the algorithm facade over vetted pure-Rust backends,
//! the DRBG hierarchy, BIGNUM, and the algorithms behind the built-in providers.
//!
//! Secret-dependent code must be constant-time and must zeroize secrets on drop.

#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

pub mod bn;
pub mod dit;
pub mod ec;
pub mod ecx;
pub mod ecx448;
pub mod ffc;
mod generated;
pub mod kdf;
pub mod lowlevel;
pub mod mac;
pub mod md;
pub mod method_store;
pub mod mldsa;
pub mod mlkem;
pub mod namemap;
pub mod params;
pub mod property;
pub mod provided;
pub mod rand;
pub mod rsa;
pub mod slhdsa;
pub mod sym;
