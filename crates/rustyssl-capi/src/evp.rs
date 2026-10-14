//! The EVP API: the base64 codec (`EVP_EncodeInit(3)` and its family), which PEM and
//! `BIO_f_base64` need ahead of the EVP phase; fetching algorithms from providers ([`fetch`]);
//! the message digest and cipher methods ([`digest`], [`cipher`]) and their contexts.

pub(crate) mod asymcipher;
pub(crate) mod cipher;
pub(crate) mod cipher_asn1;
pub(crate) mod cipher_ctx;
pub(crate) mod ctrl;
pub(crate) mod digest;
pub(crate) mod encode;
pub(crate) mod exchange;
pub(crate) mod fetch;
pub(crate) mod kdf;
pub(crate) mod kem;
pub(crate) mod key;
pub(crate) mod keymgmt;
pub(crate) mod legacy_cipher;
pub(crate) mod legacy_md;
pub(crate) mod legacy_md_fns;
pub(crate) mod mac;
pub(crate) mod md_ctx;
pub(crate) mod md_meth;
pub(crate) mod opmeth;
pub(crate) mod pkey;
pub(crate) mod pkey_ctx;
pub(crate) mod pmeth;
pub(crate) mod rand;
pub(crate) mod setters;
pub(crate) mod signature;
pub(crate) mod sigver;
pub(crate) mod skey;
pub(crate) mod skeymgmt;
