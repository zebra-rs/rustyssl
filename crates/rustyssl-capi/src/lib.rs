//! The C ABI layer of rustyssl: every `extern "C"` export of libcrypto, and the private
//! definitions behind libssl's exports (docs/adr/0001-library-layout.md).
//!
//! This is the only library crate allowed to contain `unsafe` code. Every `unsafe` block needs
//! a `// SAFETY:` comment, and every export goes through [`ffi::guard`], usually via
//! `ffi_export!`, so that no panic crosses into C.
//!
//! The building blocks:
//! - [`ffi`]: the panic guard, `ffi_export!`, and checked conversions at the boundary;
//! - [`handle`]: opaque C handles as tagged, reference-counted Rust objects;
//! - [`mem`]: memory C may free with `OPENSSL_free`;
//! - [`err`]: the per-thread error queue;
//! - [`stack`] and [`lhash`]: the containers applications and the rest of the library build on.
//!
//! Exports that aren't implemented yet are generated stubs that abort (see [`stub`]).

mod asn1;
mod bio;
mod bn;
mod buffer;
mod cmac;
mod dir;
mod err;
mod errno;
mod evp;
mod ex_data;
mod ffi;
mod generated;
mod handle;
mod hmac;
mod init;
mod lhash;
mod libctx;
mod lowlevel;
mod mem;
mod objects;
mod params;
mod pem;
mod pem_cipher;
mod pem_read;
mod property;
mod provider;
mod rand;
mod rand_file;
mod rand_lib;
mod secure;
mod sleep;
mod stack;
mod string;
mod stub;
mod threads;
mod trace;
mod version;
mod x509v3;
