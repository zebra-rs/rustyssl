//! OpenSSL C ABI definitions for rustyssl, generated from the headers vendored under `abi/`.
//!
//! For the target being compiled, this crate exposes:
//! - every public struct and union as `#[repr(C)]`, with compile-time assertions that each
//!   size, alignment, and field offset matches what clang computes from the C headers;
//! - opaque types (`SSL_CTX`, `X509`, ...) as zero-sized structs, used only behind pointers;
//! - C enums as integer constants, since a Rust enum holding an unknown value would be UB;
//! - every object-like macro that is a constant: integers with the exact C type clang gives
//!   them (so `NID_sha256` is a `c_int` and `SSL_OP_NO_SSLv3` a `c_ulong`), and strings as
//!   `&CStr`.
//!
//! libc types that appear in the API (`pthread_once_t` behind `CRYPTO_ONCE`, for example)
//! come from the `libc` crate. Function prototypes are not included; the C exports are defined
//! in `rustyssl-capi`.
//!
//! This crate holds no logic. Regenerate it with `cargo xtask codegen`; never edit the files
//! under `src/generated/` by hand.

#![forbid(unsafe_code)]

mod generated;

pub use generated::*;
