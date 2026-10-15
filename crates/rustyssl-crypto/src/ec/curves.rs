//! The named curves of OpenSSL's default build (`ec_curve.c`, `ec_support.c`), generated from
//! the vendored source by `cargo xtask codegen`: each curve's field, parameters (`p`, `a`,
//! `b`, the generator's `x` and `y`, and the order, all `param_len` octets, big-endian), seed,
//! cofactor, method, and comment, in `EC_get_builtin_curves` order; the curves' names; and
//! the NIST names.

use crate::generated::curves::{CURVES, NAMES, NIST_NAMES};

/// A curve's field: prime (GF(p)) or characteristic two (GF(2^m), `p` the reduction
/// polynomial's bits).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Field {
    Prime,
    Binary,
}

/// The method OpenSSL's group for the curve uses (`EC_GROUP_method_of`): the field's generic
/// one, or a curve-specific implementation of the default build.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Method {
    Generic,
    Nistp224,
    Nistp256,
    Nistp384,
    Nistp521,
    Nistz256,
    Sm2p256,
}

/// A named curve.
#[derive(Debug)]
pub struct Curve {
    pub nid: i32,
    pub field: Field,
    pub seed: &'static [u8],
    pub cofactor: u32,
    pub p: &'static [u8],
    pub a: &'static [u8],
    pub b: &'static [u8],
    pub x: &'static [u8],
    pub y: &'static [u8],
    pub order: &'static [u8],
    pub method: Method,
    pub comment: &'static str,
}

/// Every named curve, in `EC_get_builtin_curves` order.
#[must_use]
pub fn builtin() -> &'static [Curve] {
    CURVES
}

/// The named curve `nid`.
#[must_use]
pub fn by_nid(nid: i32) -> Option<&'static Curve> {
    CURVES.iter().find(|c| c.nid == nid)
}

/// `OSSL_EC_curve_nid2name`: the curve's name.
#[must_use]
pub fn name(nid: i32) -> Option<&'static str> {
    if nid <= 0 {
        return None;
    }
    NAMES.iter().find(|(_, n)| *n == nid).map(|(s, _)| *s)
}

/// `ossl_ec_curve_name2nid`: a curve by its NIST name (exactly) or its name (in any case).
#[must_use]
pub fn nid_by_name(name: &[u8]) -> Option<i32> {
    nist_nid(name).or_else(|| {
        NAMES
            .iter()
            .find(|(s, _)| s.as_bytes().eq_ignore_ascii_case(name))
            .map(|(_, n)| *n)
    })
}

/// `EC_curve_nid2nist`: the curve's NIST name.
#[must_use]
pub fn nist_name(nid: i32) -> Option<&'static str> {
    NIST_NAMES.iter().find(|(_, n)| *n == nid).map(|(s, _)| *s)
}

/// `EC_curve_nist2nid`: the curve with this NIST name (exactly).
#[must_use]
pub fn nist_nid(name: &[u8]) -> Option<i32> {
    NIST_NAMES
        .iter()
        .find(|(s, _)| s.as_bytes() == name)
        .map(|(_, n)| *n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_consistent() {
        assert!(builtin().len() > 70);
        for c in builtin() {
            let len = c.p.len();
            for v in [c.a, c.b, c.x, c.y, c.order] {
                assert_eq!(v.len(), len, "{}", c.comment);
            }
            assert!(c.cofactor >= 1);
        }
        let p256 = nist_nid(b"P-256").and_then(by_nid).expect("P-256");
        assert_eq!(p256.field, Field::Prime);
        assert_eq!(name(p256.nid), Some("prime256v1"));
        assert_eq!(nid_by_name(b"PRIME256V1"), Some(p256.nid));
        assert_eq!(nid_by_name(b"p-256"), None, "NIST names are exact");
    }
}
