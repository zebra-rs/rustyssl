//! The EVP API: so far only the base64 codec (`EVP_EncodeInit(3)` and its family), which PEM
//! and `BIO_f_base64` need ahead of the EVP phase.

pub(crate) mod encode;
