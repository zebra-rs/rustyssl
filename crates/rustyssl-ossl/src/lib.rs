//! The `openssl` command-line tool's bindings to libcrypto and libssl (ADR 0007, section 1):
//! the CLI is a C-API consumer like any other application, so it calls the public exports, and
//! all of its `unsafe` lives here.
//!
//! - [`ffi`]: every export, generated from the vendored headers and export lists, resolved
//!   from the library when first called ([`load`]). Nothing is hand-typed.
//! - The other modules: thin, safe wrappers over them, such as owned handles whose `Drop`
//!   calls `*_free`, `BIO` reads and writes over slices, and a snapshot of the error queue.
//!
//! The libraries are loaded at run time by soname, never linked at build time, so `cargo
//! build` needs neither rustyssl's libraries nor the reference's; and the crate never links
//! `rustyssl-capi`. A missing library or export stops the program (fail closed).

mod generated;
pub mod load;

pub use generated::ffi;
/// The C API's types and constants (generated from the vendored headers).
pub use rustyssl_abi as abi;

pub mod algorithm;
pub mod asn1;
pub mod bio;
pub mod bn;
pub mod crypto;
pub mod err;
pub mod evp;
pub mod params;
pub mod provider;
pub mod rand;
mod util;

pub use bio::Bio;
pub use util::cstring;
pub mod async_job;
pub mod conf;
pub mod engine;
pub mod os;
pub mod pkey;
pub mod store;
pub mod sys;
pub mod txt_db;
pub mod ui;
pub mod verify;
pub mod x509;
// The key commands' (fork G2).
pub mod encoder;
pub mod obj;
pub mod pkcs8;
pub mod skey;
