//! Points on a curve over GF(2^m) (`ec2_smpl.c`): affine coordinates, `Z` one, or zero for
//! the point at infinity; only the ladder works on projective ones.

use super::group::Group;
use super::point::Point;
use super::{Error, Random, Reason, Result};
use crate::bn::{self, BigNum, gf2m};

/// `ossl_ec_GF2m_simple_point_get_affine_coordinates`: the coordinates of an affine point.
pub fn get_affine(pt: &Point) -> Result<(BigNum, BigNum)> {
    if pt.is_at_infinity() {
        return Err(Error::new(
            Reason::PointAtInfinity,
            "ossl_ec_GF2m_simple_point_get_affine_coordinates",
        ));
    }
    if !pt.z.is_one() {
        return Err(Error::new(
            Reason::ShouldNotHaveBeenCalled,
            "ossl_ec_GF2m_simple_point_get_affine_coordinates",
        ));
    }
    Ok((pt.x.abs(), pt.y.abs()))
}

/// `ossl_ec_GF2m_simple_point_set_affine_coordinates`: `x` and `y` as they are (not reduced),
/// without signs.
pub fn set_affine(pt: &mut Point, x: &BigNum, y: &BigNum) {
    pt.x = (x).abs();
    pt.y = (y).abs();
    pt.z = BigNum::one();
    pt.z_is_one = true;
}

/// `ossl_ec_GF2m_simple_add`: `r = a + b` (doubling for the same point), in affine
/// coordinates. On failure `r` may hold the sum anyway, as OpenSSL's.
pub fn add_points(
    g: &Group,
    r: &mut Point,
    a: &Point,
    b: &Point,
    rng: &mut Random<'_>,
) -> Result<()> {
    if a.is_at_infinity() {
        *r = b.clone();
        return Ok(());
    }
    if b.is_at_infinity() {
        *r = a.clone();
        return Ok(());
    }
    let (x0, y0) = if a.z_is_one {
        (a.x.clone(), a.y.clone())
    } else {
        get_affine(a)?
    };
    let (x1, y1) = if b.z_is_one {
        (b.x.clone(), b.y.clone())
    } else {
        get_affine(b)?
    };
    let (x2, s) = if bn::cmp(&x0, &x1).is_ne() {
        let t = gf2m::add(&x0, &x1);
        let s = gf2m::add(&y0, &y1);
        let s = g.field_div(&s, &t, rng)?;
        let x2 = g.field_sqr(&s)?;
        let x2 = gf2m::add(&x2, &g.a);
        let x2 = gf2m::add(&x2, &s);
        (gf2m::add(&x2, &t), s)
    } else {
        if bn::cmp(&y0, &y1).is_ne() || x1.is_zero() {
            r.set_to_infinity();
            return Ok(());
        }
        let s = g.field_div(&y1, &x1, rng)?;
        let s = gf2m::add(&s, &x1);
        let x2 = g.field_sqr(&s)?;
        let x2 = gf2m::add(&x2, &s);
        (gf2m::add(&x2, &g.a), s)
    };
    let y2 = gf2m::add(&x1, &x2);
    let y2 = g.field_mul(&y2, &s)?;
    let y2 = gf2m::add(&y2, &x2);
    let y2 = gf2m::add(&y2, &y1);
    // OpenSSL sets the result with `EC_POINT_set_affine_coordinates`, which keeps the
    // coordinates of a sum that isn't on the curve (from points that weren't) but fails.
    set_affine(r, &x2, &y2);
    if !is_on_curve(g, r)? {
        return Err(Error::new(
            Reason::PointIsNotOnCurve,
            "EC_POINT_set_affine_coordinates",
        ));
    }
    Ok(())
}

/// `ossl_ec_GF2m_simple_invert`: `-a` (`x + y`), after making it affine.
pub fn invert(pt: &mut Point) -> Result<()> {
    if pt.is_at_infinity() || pt.y.is_zero() {
        return Ok(());
    }
    make_affine(pt)?;
    pt.y = gf2m::add(&pt.x, &pt.y);
    Ok(())
}

/// `ossl_ec_GF2m_simple_make_affine` (which fails for a point that isn't affine already, as
/// OpenSSL's does).
pub fn make_affine(pt: &mut Point) -> Result<()> {
    if pt.z_is_one || pt.is_at_infinity() {
        return Ok(());
    }
    let (x, y) = get_affine(pt)?;
    set_affine(pt, &x, &y);
    Ok(())
}

/// `ossl_ec_GF2m_simple_is_on_curve`: `y^2 + xy = x^3 + ax^2 + b`; an error for a point that
/// isn't affine.
pub fn is_on_curve(g: &Group, pt: &Point) -> Result<bool> {
    if pt.is_at_infinity() {
        return Ok(true);
    }
    if !pt.z_is_one {
        return Err(Error::silent());
    }
    let lh = gf2m::add(&pt.x, &g.a);
    let lh = g.field_mul(&lh, &pt.x)?;
    let lh = gf2m::add(&lh, &pt.y);
    let lh = g.field_mul(&lh, &pt.x)?;
    let lh = gf2m::add(&lh, &g.b);
    let y2 = g.field_sqr(&pt.y)?;
    Ok(gf2m::add(&lh, &y2).is_zero())
}

/// `ossl_ec_GF2m_simple_cmp`: whether `a` and `b` are the same point.
pub fn equal(a: &Point, b: &Point) -> Result<bool> {
    if a.is_at_infinity() {
        return Ok(b.is_at_infinity());
    }
    if b.is_at_infinity() {
        return Ok(false);
    }
    if a.z_is_one && b.z_is_one {
        return Ok(bn::cmp(&a.x, &b.x).is_eq() && bn::cmp(&a.y, &b.y).is_eq());
    }
    let (ax, ay) = get_affine(a)?;
    let (bx, by) = get_affine(b)?;
    Ok(bn::cmp(&ax, &bx).is_eq() && bn::cmp(&ay, &by).is_eq())
}

/// Random nonzero bits below the field's degree (`BN_priv_rand_ex` until nonzero).
fn nonzero(g: &Group, rng: &mut Random<'_>) -> Result<BigNum> {
    loop {
        let bits = g.field.num_bits().saturating_sub(1);
        let v = bn::rand::rand_bits(bits, rng)
            .ok_or(Error::new(Reason::BnLib, "ec_GF2m_simple_ladder_pre"))?;
        if !v.is_zero() {
            return Ok(v);
        }
    }
}

/// `ec_GF2m_simple_ladder_pre`: `s = p` and `r = 2p` in random López-Dahab coordinates.
pub fn ladder_pre(
    g: &Group,
    r: &mut Point,
    s: &mut Point,
    p: &Point,
    rng: &mut Random<'_>,
) -> Result<()> {
    if !p.z_is_one {
        return Err(Error::silent());
    }
    s.z = nonzero(g, rng)?;
    s.x = g.field_mul(&p.x, &s.z)?;
    r.y = nonzero(g, rng)?;
    r.z = g.field_sqr(&p.x)?;
    r.x = g.field_sqr(&r.z)?;
    r.x = gf2m::add(&r.x, &g.b);
    r.z = g.field_mul(&r.z, &r.y)?;
    r.x = g.field_mul(&r.x, &r.y)?;
    s.z_is_one = false;
    r.z_is_one = false;
    Ok(())
}

/// `ec_GF2m_simple_ladder_step`.
pub fn ladder_step(g: &Group, r: &mut Point, s: &mut Point, p: &Point) -> Result<()> {
    r.y = g.field_mul(&r.z, &s.x)?;
    s.x = g.field_mul(&r.x, &s.z)?;
    s.y = g.field_sqr(&r.z)?;
    r.z = g.field_sqr(&r.x)?;
    s.z = gf2m::add(&r.y, &s.x);
    s.z = g.field_sqr(&s.z)?;
    s.x = g.field_mul(&r.y, &s.x)?;
    r.y = g.field_mul(&s.z, &p.x)?;
    s.x = gf2m::add(&s.x, &r.y);
    r.y = g.field_sqr(&r.z)?;
    r.z = g.field_mul(&r.z, &s.y)?;
    s.y = g.field_sqr(&s.y)?;
    s.y = g.field_mul(&s.y, &g.b)?;
    r.x = gf2m::add(&r.y, &s.y);
    Ok(())
}

/// `ec_GF2m_simple_ladder_post`: `r` recovered in affine coordinates.
pub fn ladder_post(
    g: &Group,
    r: &mut Point,
    s: &Point,
    p: &Point,
    rng: &mut Random<'_>,
) -> Result<()> {
    if r.z.is_zero() {
        r.set_to_infinity();
        return Ok(());
    }
    if s.z.is_zero() {
        *r = p.clone();
        return invert(r).map_err(|e| e.then(Reason::EcLib, "ec_GF2m_simple_ladder_post"));
    }
    let t0 = g.field_mul(&r.z, &s.z)?;
    let t1 = g.field_mul(&p.x, &r.z)?;
    let t1 = gf2m::add(&r.x, &t1);
    let t2 = g.field_mul(&p.x, &s.z)?;
    r.z = g.field_mul(&r.x, &t2)?;
    let t2 = gf2m::add(&t2, &s.x);
    let t1 = g.field_mul(&t1, &t2)?;
    let t2 = g.field_sqr(&p.x)?;
    let t2 = gf2m::add(&p.y, &t2);
    let t2 = g.field_mul(&t2, &t0)?;
    let t1 = gf2m::add(&t2, &t1);
    let t2 = g.field_mul(&p.x, &t0)?;
    let t2 = g.field_inv(&t2, rng)?;
    let t1 = g.field_mul(&t1, &t2)?;
    r.x = g.field_mul(&r.z, &t2)?;
    let t2 = gf2m::add(&p.x, &r.x);
    let t2 = g.field_mul(&t2, &t1)?;
    r.y = gf2m::add(&p.y, &t2);
    r.z = BigNum::one();
    r.z_is_one = true;
    Ok(())
}
