//! Elliptic curves over prime fields GF(p) and characteristic-two fields GF(2^m) (`crypto/ec/`):
//! the named curves' table ([`curves`]), groups ([`group`]), points and their arithmetic
//! ([`point`], with the formulas of OpenSSL's `ecp_smpl.c` and `ec2_smpl.c` in [`gfp`] and
//! [`gf2m`]), scalar multiplication ([`mult`]: the constant-time ladder and wNAF), and the
//! points' encodings ([`oct`]).
//!
//! Everything here is a port of OpenSSL's behavior on the values the application can see: the
//! affine coordinates and also the Jacobian ones (`EC_POINT_get_Jprojective_coordinates_GFp`),
//! the random numbers each operation draws (so a known generator leaves the same state behind),
//! and the errors in the order OpenSSL raises them. OpenSSL keeps a prime field's values in
//! Montgomery form for most groups; the formulas give the same values either way, so they run
//! on plain residues here.

pub mod curves;
pub mod ecdsa;
pub mod fe;
pub mod gf2m;
pub mod gfp;
pub mod group;
pub mod mult;
pub mod oct;
pub mod point;

pub use group::{Group, Meth};
pub use point::Point;

pub use crate::bn::rand::Random;

/// Why an operation failed: OpenSSL's `EC_R_*` reasons and the library errors EC raises.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// `EC_R_INVALID_FIELD`.
    InvalidField,
    /// `EC_R_NOT_A_NIST_PRIME`.
    NotANistPrime,
    /// `EC_R_WRONG_CURVE_PARAMETERS`.
    WrongCurveParameters,
    /// `EC_R_UNSUPPORTED_FIELD`.
    UnsupportedField,
    /// `EC_R_CANNOT_INVERT`.
    CannotInvert,
    /// `EC_R_POINT_AT_INFINITY`.
    PointAtInfinity,
    /// `EC_R_POINT_IS_NOT_ON_CURVE`.
    PointIsNotOnCurve,
    /// `EC_R_UNKNOWN_ORDER`.
    UnknownOrder,
    /// `EC_R_UNKNOWN_COFACTOR`.
    UnknownCofactor,
    /// `EC_R_INVALID_GROUP_ORDER`.
    InvalidGroupOrder,
    /// `EC_R_LADDER_PRE_FAILURE`.
    LadderPreFailure,
    /// `EC_R_LADDER_STEP_FAILURE`.
    LadderStepFailure,
    /// `EC_R_LADDER_POST_FAILURE`.
    LadderPostFailure,
    /// `EC_R_INVALID_COMPRESSED_POINT`.
    InvalidCompressedPoint,
    /// `EC_R_INVALID_COMPRESSION_BIT`.
    InvalidCompressionBit,
    /// `EC_R_INVALID_ENCODING`.
    InvalidEncoding,
    /// `EC_R_INVALID_FORM`.
    InvalidForm,
    /// `EC_R_BUFFER_TOO_SMALL`.
    BufferTooSmall,
    /// `EC_R_INCOMPATIBLE_OBJECTS`.
    IncompatibleObjects,
    /// `EC_R_UNDEFINED_GENERATOR`.
    UndefinedGenerator,
    /// `EC_R_DISCRIMINANT_IS_ZERO`.
    DiscriminantIsZero,
    /// `EC_R_COORDINATES_OUT_OF_RANGE`.
    CoordinatesOutOfRange,
    /// `ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED`.
    ShouldNotHaveBeenCalled,
    /// `ERR_R_BN_LIB`.
    BnLib,
    /// `ERR_R_EC_LIB`.
    EcLib,
    /// `ERR_R_INTERNAL_ERROR`.
    InternalError,
    /// A BIGNUM error from the arithmetic (raised as BN's).
    Bn(crate::bn::Error),
}

/// One error entry: its reason and the OpenSSL function that raises it (empty for BIGNUM's,
/// which the caller names).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Raised {
    pub reason: Reason,
    pub func: &'static str,
}

/// The errors an operation raised, in the order OpenSSL raises them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub Vec<Raised>);

impl Error {
    /// An error of one reason, raised by `func`.
    #[must_use]
    pub fn new(reason: Reason, func: &'static str) -> Self {
        Self(vec![Raised { reason, func }])
    }

    /// An error with no entry (OpenSSL's silent failures).
    #[must_use]
    pub fn silent() -> Self {
        Self(Vec::new())
    }

    /// This error with `reason` raised by `func` after it.
    #[must_use]
    pub fn then(mut self, reason: Reason, func: &'static str) -> Self {
        self.0.push(Raised { reason, func });
        self
    }
}

impl From<crate::bn::Error> for Error {
    fn from(e: crate::bn::Error) -> Self {
        Self::new(Reason::Bn(e), "")
    }
}

/// An EC result.
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::curves::{self, Field};
    use super::mult::{Request, mul};
    use super::*;
    use crate::bn::BigNum;

    /// A deterministic generator: a counter's octets.
    fn counter() -> impl FnMut(&mut [u8]) -> bool {
        let mut n = 0u8;
        move |buf: &mut [u8]| {
            for b in buf.iter_mut() {
                n = n.wrapping_add(37);
                *b = n;
            }
            true
        }
    }

    fn times(g: &Group, k: &BigNum, rng: &mut Random<'_>) -> Point {
        let mut r = Point::infinity();
        mul(
            g,
            &mut r,
            &Request {
                scalar: Some(k),
                pairs: &[],
                scalar_is_order: false,
            },
            rng,
        )
        .expect("mul");
        r
    }

    #[test]
    fn every_named_curve_builds_and_its_order_kills_the_generator() {
        let mut rng = counter();
        for c in curves::builtin() {
            let g = Group::from_curve(c).unwrap_or_else(|e| panic!("{}: {e:?}", c.comment));
            let generator = g.generator.clone().expect("generator");
            assert!(
                point::is_on_curve(&g, &generator).expect("on curve"),
                "{}",
                c.comment
            );
            let mut r = Point::infinity();
            mul(
                &g,
                &mut r,
                &Request {
                    scalar: Some(&g.order),
                    pairs: &[],
                    scalar_is_order: true,
                },
                &mut rng,
            )
            .unwrap_or_else(|e| panic!("{}: {e:?}", c.comment));
            assert!(r.is_at_infinity(), "{}: n*G", c.comment);
        }
    }

    #[test]
    fn ladder_wnaf_and_addition_agree() {
        let mut rng = counter();
        for name in [&b"P-256"[..], b"P-224", b"K-163", b"B-233"] {
            let nid = curves::nist_nid(name).expect("nist");
            let c = curves::by_nid(nid).expect("curve");
            let g = Group::from_curve(c).expect("group");
            let base = g.generator.clone().expect("generator");
            let k = BigNum::from_word(12345);
            // k*G by the ladder, and by wNAF (as a point term with the generator's scalar 0).
            let a = times(&g, &k, &mut rng);
            let zero = BigNum::zero();
            let mut b = Point::infinity();
            mul(
                &g,
                &mut b,
                &Request {
                    scalar: Some(&zero),
                    pairs: &[(&base, &k)],
                    scalar_is_order: false,
                },
                &mut rng,
            )
            .expect("wnaf");
            assert!(
                point::equal(&g, &a, &b).expect("cmp")
                    || g.meth.field() == Field::Binary && {
                        let (ax, ay) = point::get_affine(&g, &a, &mut rng).expect("a");
                        let (bx, by) = point::get_affine(&g, &b, &mut rng).expect("b");
                        ax == bx && ay == by
                    }
            );
            // 2G + G = 3G.
            let mut two = Point::infinity();
            point::dbl(&g, &mut two, &base, &mut rng).expect("dbl");
            let mut three = Point::infinity();
            point::add(&g, &mut three, &two, &base, false, &mut rng).expect("add");
            let t = times(&g, &BigNum::from_word(3), &mut rng);
            let (x1, y1) = point::get_affine(&g, &three, &mut rng).expect("3G");
            let (x2, y2) = point::get_affine(&g, &t, &mut rng).expect("3G'");
            assert_eq!((x1, y1), (x2, y2), "{:?}", String::from_utf8_lossy(name));
        }
    }

    #[test]
    fn encodings_round_trip() {
        let mut rng = counter();
        for name in [&b"P-256"[..], b"P-521", b"K-233", b"B-163"] {
            let c = curves::nist_nid(name)
                .and_then(curves::by_nid)
                .expect("curve");
            let g = Group::from_curve(c).expect("group");
            let pt = times(&g, &BigNum::from_word(77), &mut rng);
            for form in [oct::COMPRESSED, oct::UNCOMPRESSED, oct::HYBRID] {
                let enc = oct::encode(&g, &pt, form, &mut rng).expect("encode");
                let mut back = Point::infinity();
                oct::decode(&g, &mut back, &enc, &mut rng).expect("decode");
                assert!(
                    point::equal(&g, &back, &{
                        let mut p = pt.clone();
                        point::make_affine(&g, &mut p, &mut rng).expect("affine");
                        p
                    })
                    .expect("cmp")
                );
            }
        }
    }
}
