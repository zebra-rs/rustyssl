//! The EVP API: the base64 codec (`EVP_EncodeInit(3)` and its family), which PEM and
//! `BIO_f_base64` need ahead of the EVP phase; fetching algorithms from providers ([`fetch`]);
//! the message digest and cipher methods ([`digest`], [`cipher`]) and their contexts.

pub(crate) mod cipher;
pub(crate) mod cipher_ctx;
pub(crate) mod digest;
pub(crate) mod encode;
pub(crate) mod fetch;
pub(crate) mod legacy_cipher;
pub(crate) mod legacy_md;
pub(crate) mod md_ctx;
