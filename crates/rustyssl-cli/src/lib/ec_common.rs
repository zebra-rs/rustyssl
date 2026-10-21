//! `apps/include/ec_common.h`: the EC key commands' option values (`ec`, `ecparam`, `pkey`).

/// `point_format_options` of `ec_common.h`.
pub const POINT_FORMAT_OPTIONS: &[&str] = &["uncompressed", "compressed", "hybrid"];

/// `asn1_encoding_options` of `ec_common.h`.
pub const ASN1_ENCODING_OPTIONS: &[&str] = &["named_curve", "explicit"];
