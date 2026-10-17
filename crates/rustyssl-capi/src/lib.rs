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
mod conf;
mod decoder;
mod dh;
mod dh_asn1;
mod dh_backend;
mod dh_meth;
mod dh_ops;
mod dh_pmeth;
mod dir;
mod dsa;
mod dsa_asn1;
mod dsa_backend;
mod dsa_meth;
mod dsa_ops;
mod dsa_pmeth;
mod ec;
mod ec_pmeth;
mod ecx;
mod ecx_pmeth;
mod encoder;
mod engine;
mod err;
mod errno;
mod evp;
mod ex_data;
#[expect(
    dead_code,
    reason = "the parameter checks and DSA's use the rest (steps 4.6a2 and 4.6b)"
)]
mod ffc;
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
mod passphrase;
mod pem;
mod pem_cipher;
mod pem_pkey;
mod pem_read;
mod pkcs12;
mod pkcs8_crypt;
mod property;
mod provider;
mod pvkfmt;
mod rand;
mod rand_file;
mod rand_lib;
mod rsa;
mod rsa_asn1;
mod rsa_gen;
mod rsa_lib;
mod rsa_meth;
mod rsa_ops;
mod rsa_pmeth;
mod secure;
mod sleep;
mod ssl;
mod stack;
mod store;
mod string;
mod stub;
mod threads;
mod trace;
mod ui;
mod version;
mod x509;
mod x509v3;
