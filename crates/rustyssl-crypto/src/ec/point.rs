//! Points (`EC_POINT`): coordinates `X`, `Y`, `Z` as the group's method keeps them (Jacobian
//! over GF(p), affine over GF(2^m)), `Z = 0` for the point at infinity, and the generic
//! operations, which dispatch on the field.

use super::curves::Field;
use super::group::Group;
use super::{Error, Random, Reason, Result, gf2m, gfp};
use crate::bn::{self, BigNum};

/// A point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Point {
    pub x: BigNum,
    pub y: BigNum,
    pub z: BigNum,
    pub z_is_one: bool,
}

impl Default for Point {
    fn default() -> Self {
        Self::infinity()
    }
}

impl Point {
    /// A new point: the point at infinity, all coordinates zero.
    #[must_use]
    pub fn infinity() -> Self {
        Self {
            x: BigNum::zero(),
            y: BigNum::zero(),
            z: BigNum::zero(),
            z_is_one: false,
        }
    }

    /// Whether this is the point at infinity (`Z = 0`).
    #[must_use]
    pub fn is_at_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// `EC_POINT_set_to_infinity`: `Z = 0`; `X` and `Y` stay as they were.
    pub fn set_to_infinity(&mut self) {
        self.z = BigNum::zero();
        self.z_is_one = false;
    }
}

/// `EC_POINT_set_affine_coordinates`'s work: the method's setter, then the check that the
/// point is on the curve (`Ok(false)` if it isn't, the coordinates kept).
pub fn set_affine(g: &Group, pt: &mut Point, x: &BigNum, y: &BigNum) -> Result<bool> {
    match g.meth.field() {
        Field::Prime => {
            gfp::set_jprojective(g, pt, Some(x), Some(y), Some(&BigNum::one()))?;
        }
        Field::Binary => gf2m::set_affine(pt, x, y),
    }
    is_on_curve(g, pt)
}

/// The affine coordinates (`EC_POINT_get_affine_coordinates`).
pub fn get_affine(g: &Group, pt: &Point, rng: &mut Random<'_>) -> Result<(BigNum, BigNum)> {
    match g.meth.field() {
        Field::Prime => gfp::get_affine(g, pt, rng),
        Field::Binary => gf2m::get_affine(pt),
    }
}

/// `EC_POINT_add`: `r = a + b`; `same` when `a` and `b` are one object.
pub fn add(
    g: &Group,
    r: &mut Point,
    a: &Point,
    b: &Point,
    same: bool,
    rng: &mut Random<'_>,
) -> Result<()> {
    match g.meth.field() {
        Field::Prime => gfp::add_points(g, r, a, b, same),
        Field::Binary => gf2m::add_points(g, r, a, b, rng),
    }
}

/// `EC_POINT_dbl`: `r = 2a`.
pub fn dbl(g: &Group, r: &mut Point, a: &Point, rng: &mut Random<'_>) -> Result<()> {
    match g.meth.field() {
        Field::Prime => gfp::dbl_point(g, r, a),
        Field::Binary => gf2m::add_points(g, r, a, a, rng),
    }
}

/// `EC_POINT_invert`.
pub fn invert(g: &Group, pt: &mut Point) -> Result<()> {
    match g.meth.field() {
        Field::Prime => gfp::invert(g, pt),
        Field::Binary => gf2m::invert(pt),
    }
}

/// `EC_POINT_is_on_curve`.
pub fn is_on_curve(g: &Group, pt: &Point) -> Result<bool> {
    match g.meth.field() {
        Field::Prime => gfp::is_on_curve(g, pt),
        Field::Binary => gf2m::is_on_curve(g, pt),
    }
}

/// `EC_POINT_cmp`'s work: whether the points are equal.
pub fn equal(g: &Group, a: &Point, b: &Point) -> Result<bool> {
    match g.meth.field() {
        Field::Prime => gfp::equal(g, a, b),
        Field::Binary => gf2m::equal(a, b),
    }
}

/// `EC_POINT_make_affine`. On failure `pt` may have changed, as OpenSSL's.
pub fn make_affine(g: &Group, pt: &mut Point, rng: &mut Random<'_>) -> Result<()> {
    match g.meth.field() {
        Field::Prime => {
            if pt.z_is_one || pt.is_at_infinity() {
                return Ok(());
            }
            let (x, y) = gfp::get_affine(g, pt, rng)?;
            // As `EC_POINT_set_affine_coordinates`, which keeps the coordinates of a point
            // that isn't on the curve but fails.
            gfp::set_jprojective(g, pt, Some(&x), Some(&y), Some(&BigNum::one()))?;
            if !gfp::is_on_curve(g, pt)? {
                return Err(Error::new(
                    Reason::PointIsNotOnCurve,
                    "EC_POINT_set_affine_coordinates",
                ));
            }
            if !pt.z_is_one {
                return Err(Error::new(
                    Reason::InternalError,
                    "ossl_ec_GFp_simple_make_affine",
                ));
            }
            Ok(())
        }
        Field::Binary => gf2m::make_affine(pt),
    }
}

/// `EC_POINTs_make_affine`.
pub fn points_make_affine(g: &Group, points: &mut [Point], rng: &mut Random<'_>) -> Result<()> {
    match g.meth.field() {
        Field::Prime => gfp::points_make_affine(g, points, rng),
        Field::Binary => points.iter_mut().try_for_each(gf2m::make_affine),
    }
}

/// Whether a point's coordinates are all below the field (`EC_POINT`s from the application
/// can hold anything after `set_Jprojective`'s reduction; this is for the encoders' checks).
#[must_use]
pub fn coordinates_reduced(g: &Group, pt: &Point) -> bool {
    [&pt.x, &pt.y, &pt.z]
        .into_iter()
        .all(|v| bn::ucmp(v, &g.field).is_lt())
}
