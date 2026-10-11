//! The built-in providers' algorithms with the semantics of the reference's provider
//! functions, for the dispatch tables `rustyssl-capi` builds: what each function does to an
//! algorithm context, the parameters it takes, and how it fails.

pub mod aead;
pub mod cipher;
pub mod digest;
pub mod mac;
pub mod siv;
