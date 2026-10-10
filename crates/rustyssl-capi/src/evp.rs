//! The EVP API: the base64 codec (`EVP_EncodeInit(3)` and its family), which PEM and
//! `BIO_f_base64` need ahead of the EVP phase; fetching algorithms from providers ([`fetch`]);
//! and the message digest method object ([`digest`]).

pub(crate) mod digest;
pub(crate) mod encode;
pub(crate) mod fetch;
pub(crate) mod legacy_md;
pub(crate) mod md_ctx;
