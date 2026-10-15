//! Points on a curve over GF(p) in Jacobian coordinates (`X/Z^2`, `Y/Z^3`): OpenSSL's
//! `ecp_smpl.c` formulas, step for step, so the coordinates come out as the reference's.

use super::group::{Group, Meth};
use super::point::Point;
use super::{Error, Random, Reason, Result};
use crate::bn::{self, BigNum, modular};

/// `BN_mod_add_quick`.
fn add(a: &BigNum, b: &BigNum, p: &BigNum) -> BigNum {
    modular::mod_add_quick(a, b, p)
}

/// `BN_mod_sub_quick`: `a - b`, plus `p` when that's negative.
fn sub(a: &BigNum, b: &BigNum, p: &BigNum) -> Result<BigNum> {
    let r = bn::sub(a, b)?;
    Ok(if r.is_negative() { bn::add(&r, p)? } else { r })
}

/// `BN_mod_lshift1_quick`.
fn dbl(a: &BigNum, p: &BigNum) -> Result<BigNum> {
    Ok(modular::mod_lshift1_quick(a, p)?)
}

/// `BN_mod_lshift_quick`.
fn shl(a: &BigNum, n: i64, p: &BigNum) -> Result<BigNum> {
    modular::mod_lshift_quick(a, n, p).map_err(|(e, _)| e.into())
}

/// `ossl_ec_GFp_simple_add`: `r = a + b` (doubling when they're the same object, as `a == b`).
/// A sum at infinity sets only `r`'s Z, as OpenSSL's does.
pub fn add_points(g: &Group, r: &mut Point, a: &Point, b: &Point, same: bool) -> Result<()> {
    if same {
        return dbl_point(g, r, a);
    }
    if a.is_at_infinity() {
        *r = b.clone();
        return Ok(());
    }
    if b.is_at_infinity() {
        *r = a.clone();
        return Ok(());
    }
    let p = &g.field;
    let (n1, n2) = if b.z_is_one {
        (a.x.clone(), a.y.clone())
    } else {
        let n0 = g.field_sqr(&b.z)?;
        let n1 = g.field_mul(&a.x, &n0)?;
        let n0 = g.field_mul(&n0, &b.z)?;
        (n1, g.field_mul(&a.y, &n0)?)
    };
    let (n3, n4) = if a.z_is_one {
        (b.x.clone(), b.y.clone())
    } else {
        let n0 = g.field_sqr(&a.z)?;
        let n3 = g.field_mul(&b.x, &n0)?;
        let n0 = g.field_mul(&n0, &a.z)?;
        (n3, g.field_mul(&b.y, &n0)?)
    };
    let n5 = sub(&n1, &n3, p)?;
    let n6 = sub(&n2, &n4, p)?;
    if n5.is_zero() {
        if n6.is_zero() {
            return dbl_point(g, r, a);
        }
        r.z = BigNum::zero();
        r.z_is_one = false;
        return Ok(());
    }
    let n1 = add(&n1, &n3, p);
    let n2 = add(&n2, &n4, p);
    let z = if a.z_is_one && b.z_is_one {
        n5.clone()
    } else {
        let n0 = if a.z_is_one {
            b.z.clone()
        } else if b.z_is_one {
            a.z.clone()
        } else {
            g.field_mul(&a.z, &b.z)?
        };
        g.field_mul(&n0, &n5)?
    };
    let n0 = g.field_sqr(&n6)?;
    let n4 = g.field_sqr(&n5)?;
    let n3 = g.field_mul(&n1, &n4)?;
    let x = sub(&n0, &n3, p)?;
    let n0 = dbl(&x, p)?;
    let n0 = sub(&n3, &n0, p)?;
    let n0 = g.field_mul(&n0, &n6)?;
    let n5 = g.field_mul(&n4, &n5)?;
    let n1 = g.field_mul(&n2, &n5)?;
    let mut n0 = sub(&n0, &n1, p)?;
    if n0.is_odd() {
        n0 = bn::add(&n0, p)?;
    }
    *r = Point {
        x,
        y: bn::rshift1(&n0),
        z,
        z_is_one: false,
    };
    Ok(())
}

/// `ossl_ec_GFp_simple_dbl`: `r = 2a`; at infinity only `r`'s Z is set.
pub fn dbl_point(g: &Group, r: &mut Point, a: &Point) -> Result<()> {
    if a.is_at_infinity() {
        r.z = BigNum::zero();
        r.z_is_one = false;
        return Ok(());
    }
    let p = &g.field;
    let n1 = if a.z_is_one {
        let n0 = g.field_sqr(&a.x)?;
        let n1 = dbl(&n0, p)?;
        let n0 = add(&n0, &n1, p);
        add(&n0, &g.a, p)
    } else if g.a_is_minus3 {
        let n1 = g.field_sqr(&a.z)?;
        let n0 = add(&a.x, &n1, p);
        let n2 = sub(&a.x, &n1, p)?;
        let n1 = g.field_mul(&n0, &n2)?;
        let n0 = dbl(&n1, p)?;
        add(&n0, &n1, p)
    } else {
        let n0 = g.field_sqr(&a.x)?;
        let n1 = dbl(&n0, p)?;
        let n0 = add(&n0, &n1, p);
        let n1 = g.field_sqr(&a.z)?;
        let n1 = g.field_sqr(&n1)?;
        let n1 = g.field_mul(&n1, &g.a)?;
        add(&n1, &n0, p)
    };
    let n0 = if a.z_is_one {
        a.y.clone()
    } else {
        g.field_mul(&a.y, &a.z)?
    };
    let z = dbl(&n0, p)?;
    let n3 = g.field_sqr(&a.y)?;
    let n2 = g.field_mul(&a.x, &n3)?;
    let n2 = shl(&n2, 2, p)?;
    let n0 = dbl(&n2, p)?;
    let x = g.field_sqr(&n1)?;
    let x = sub(&x, &n0, p)?;
    let n0 = g.field_sqr(&n3)?;
    let n3 = shl(&n0, 3, p)?;
    let n0 = sub(&n2, &x, p)?;
    let n0 = g.field_mul(&n1, &n0)?;
    let y = sub(&n0, &n3, p)?;
    *r = Point {
        x,
        y,
        z,
        z_is_one: false,
    };
    Ok(())
}

/// `ossl_ec_GFp_simple_invert`: `-a` (`p - y`).
pub fn invert(g: &Group, a: &mut Point) -> Result<()> {
    if a.is_at_infinity() || a.y.is_zero() {
        return Ok(());
    }
    a.y = bn::usub(&g.field, &a.y)?;
    Ok(())
}

/// `ossl_ec_GFp_simple_is_on_curve`.
pub fn is_on_curve(g: &Group, pt: &Point) -> Result<bool> {
    if pt.is_at_infinity() {
        return Ok(true);
    }
    let p = &g.field;
    let rh = g.field_sqr(&pt.x)?;
    let rh = if pt.z_is_one {
        let rh = add(&rh, &g.a, p);
        let rh = g.field_mul(&rh, &pt.x)?;
        add(&rh, &g.b, p)
    } else {
        let tmp = g.field_sqr(&pt.z)?;
        let z4 = g.field_sqr(&tmp)?;
        let z6 = g.field_mul(&z4, &tmp)?;
        let rh = if g.a_is_minus3 {
            let tmp = dbl(&z4, p)?;
            let tmp = add(&tmp, &z4, p);
            let rh = sub(&rh, &tmp, p)?;
            g.field_mul(&rh, &pt.x)?
        } else {
            let tmp = g.field_mul(&z4, &g.a)?;
            let rh = add(&rh, &tmp, p);
            g.field_mul(&rh, &pt.x)?
        };
        let tmp = g.field_mul(&g.b, &z6)?;
        add(&rh, &tmp, p)
    };
    let y2 = g.field_sqr(&pt.y)?;
    Ok(bn::ucmp(&y2, &rh).is_eq())
}

/// `ossl_ec_GFp_simple_cmp`: whether `a` and `b` are the same point.
pub fn equal(g: &Group, a: &Point, b: &Point) -> Result<bool> {
    if a.is_at_infinity() {
        return Ok(b.is_at_infinity());
    }
    if b.is_at_infinity() {
        return Ok(false);
    }
    if a.z_is_one && b.z_is_one {
        return Ok(bn::cmp(&a.x, &b.x).is_eq() && bn::cmp(&a.y, &b.y).is_eq());
    }
    let zb2 = if b.z_is_one {
        None
    } else {
        Some(g.field_sqr(&b.z)?)
    };
    let za2 = if a.z_is_one {
        None
    } else {
        Some(g.field_sqr(&a.z)?)
    };
    let t1 = match &zb2 {
        Some(z) => g.field_mul(&a.x, z)?,
        None => a.x.clone(),
    };
    let t2 = match &za2 {
        Some(z) => g.field_mul(&b.x, z)?,
        None => b.x.clone(),
    };
    if !bn::cmp(&t1, &t2).is_eq() {
        return Ok(false);
    }
    let t1 = match &zb2 {
        Some(z) => g.field_mul(&a.y, &g.field_mul(z, &b.z)?)?,
        None => a.y.clone(),
    };
    let t2 = match &za2 {
        Some(z) => g.field_mul(&b.y, &g.field_mul(z, &a.z)?)?,
        None => b.y.clone(),
    };
    Ok(bn::cmp(&t1, &t2).is_eq())
}

/// `ossl_ec_GFp_simple_point_get_affine_coordinates`.
pub fn get_affine(g: &Group, pt: &Point, rng: &mut Random<'_>) -> Result<(BigNum, BigNum)> {
    if pt.is_at_infinity() {
        return Err(Error::new(
            Reason::PointAtInfinity,
            "ossl_ec_GFp_simple_point_get_affine_coordinates",
        ));
    }
    if pt.z.is_one() {
        return Ok((pt.x.clone(), pt.y.clone()));
    }
    // The NIST methods convert with their own field inversion, which draws nothing.
    let nist = matches!(
        g.meth,
        Meth::Nistp224 | Meth::Nistp256 | Meth::Nistp384 | Meth::Nistp521
    );
    let fermat;
    let inv_group = if nist {
        let mut f = g.clone();
        f.meth = Meth::Mont;
        fermat = f;
        &fermat
    } else {
        g
    };
    let z1 = inv_group.field_inv(&pt.z, rng).map_err(|e| {
        e.then(
            Reason::BnLib,
            "ossl_ec_GFp_simple_point_get_affine_coordinates",
        )
    })?;
    let z2 = g.field_sqr(&z1)?;
    let x = g.field_mul(&pt.x, &z2)?;
    let z3 = g.field_mul(&z2, &z1)?;
    let y = g.field_mul(&pt.y, &z3)?;
    Ok((x, y))
}

/// `ossl_ec_GFp_simple_set_Jprojective_coordinates_GFp`: each coordinate given, reduced.
pub fn set_jprojective(
    g: &Group,
    pt: &mut Point,
    x: Option<&BigNum>,
    y: Option<&BigNum>,
    z: Option<&BigNum>,
) -> Result<()> {
    if let Some(x) = x {
        pt.x = bn::nnmod(x, &g.field)?;
    }
    if let Some(y) = y {
        pt.y = bn::nnmod(y, &g.field)?;
    }
    if let Some(z) = z {
        pt.z = bn::nnmod(z, &g.field)?;
        pt.z_is_one = pt.z.is_one();
    }
    Ok(())
}

/// `ossl_ec_GFp_simple_points_make_affine`: every point affine, with one inversion.
pub fn points_make_affine(g: &Group, points: &mut [Point], rng: &mut Random<'_>) -> Result<()> {
    let Some(first) = points.first() else {
        return Ok(());
    };
    let mut prod: Vec<BigNum> = Vec::with_capacity(points.len());
    prod.push(if first.z.is_zero() {
        BigNum::one()
    } else {
        first.z.clone()
    });
    for pt in points.iter().skip(1) {
        let last = prod.last().cloned().unwrap_or_else(BigNum::one);
        prod.push(if pt.z.is_zero() {
            last
        } else {
            g.field_mul(&last, &pt.z)?
        });
    }
    let total = prod.last().cloned().unwrap_or_else(BigNum::one);
    let mut tmp = g
        .field_inv(&total, rng)
        .map_err(|e| e.then(Reason::BnLib, "ossl_ec_GFp_simple_points_make_affine"))?;
    for i in (1..points.len()).rev() {
        let (Some(pt), Some(before)) = (points.get_mut(i), prod.get(i.wrapping_sub(1))) else {
            continue;
        };
        if !pt.z.is_zero() {
            let tz = g.field_mul(before, &tmp)?;
            tmp = g.field_mul(&tmp, &pt.z)?;
            pt.z = tz;
        }
    }
    if let Some(p0) = points.first_mut()
        && !p0.z.is_zero()
    {
        p0.z = tmp;
    }
    for pt in points.iter_mut() {
        if !pt.z.is_zero() {
            let t = g.field_sqr(&pt.z)?;
            pt.x = g.field_mul(&pt.x, &t)?;
            let t = g.field_mul(&t, &pt.z)?;
            pt.y = g.field_mul(&pt.y, &t)?;
            pt.z = BigNum::one();
            pt.z_is_one = true;
        }
    }
    Ok(())
}

/// A nonzero random element below `p` (`BN_priv_rand_range_ex` until nonzero).
fn nonzero(p: &BigNum, rng: &mut Random<'_>) -> Result<BigNum> {
    loop {
        let v = bn::rand::rand_range(p, rng).ok_or(Error::silent())?;
        if !v.is_zero() {
            return Ok(v);
        }
    }
}

/// `ossl_ec_GFp_simple_blind_coordinates`: the point's coordinates scaled by a random `λ`
/// (`λ^2 X, λ^3 Y, λ Z`). A failing generator is ignored, as OpenSSL ignores it.
pub fn blind_coordinates(g: &Group, pt: &mut Point, rng: &mut Random<'_>) -> Result<()> {
    let lambda = loop {
        // OpenSSL pops the generator's error and goes on with what it has.
        let v = bn::rand::rand_range(&g.field, rng).unwrap_or_else(BigNum::zero);
        if !v.is_zero() {
            break v;
        }
    };
    pt.z = g.field_mul(&pt.z, &lambda)?;
    let t = g.field_sqr(&lambda)?;
    pt.x = g.field_mul(&pt.x, &t)?;
    let t = g.field_mul(&t, &lambda)?;
    pt.y = g.field_mul(&pt.y, &t)?;
    pt.z_is_one = false;
    Ok(())
}

/// `ossl_ec_GFp_simple_ladder_pre`: `r = 2p` and `s = p`, both on random projective
/// coordinates (co-Z x-only form).
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
    let f = &g.field;
    let t3 = g.field_sqr(&p.x)?;
    let t4 = sub(&t3, &g.a, f)?;
    let t4 = g.field_sqr(&t4)?;
    let t5 = g.field_mul(&p.x, &g.b)?;
    let t5 = shl(&t5, 3, f)?;
    r.x = sub(&t4, &t5, f)?;
    let t1 = add(&t3, &g.a, f);
    let t2 = g.field_mul(&p.x, &t1)?;
    let t2 = add(&g.b, &t2, f);
    r.z = shl(&t2, 2, f)?;
    s.x = t3;
    s.y = t5;
    r.y = nonzero(f, rng)?;
    s.z = nonzero(f, rng)?;
    r.z = g.field_mul(&r.z, &r.y)?;
    r.x = g.field_mul(&r.x, &r.y)?;
    s.x = g.field_mul(&p.x, &s.z)?;
    r.z_is_one = false;
    s.z_is_one = false;
    Ok(())
}

/// `ossl_ec_GFp_simple_ladder_step`: `r = 2r`, `s = r + s`, with their difference `p`.
pub fn ladder_step(g: &Group, r: &mut Point, s: &mut Point, p: &Point) -> Result<()> {
    let f = &g.field;
    let t6 = g.field_mul(&r.x, &s.x)?;
    let t0 = g.field_mul(&r.z, &s.z)?;
    let t4 = g.field_mul(&r.x, &s.z)?;
    let t3 = g.field_mul(&r.z, &s.x)?;
    let t5 = g.field_mul(&g.a, &t0)?;
    let t5 = add(&t6, &t5, f);
    let t6 = add(&t3, &t4, f);
    let t5 = g.field_mul(&t6, &t5)?;
    let t0 = g.field_sqr(&t0)?;
    let t2 = shl(&g.b, 2, f)?;
    let t0 = g.field_mul(&t2, &t0)?;
    let t5 = dbl(&t5, f)?;
    let t3 = sub(&t4, &t3, f)?;
    s.z = g.field_sqr(&t3)?;
    let t4 = g.field_mul(&s.z, &p.x)?;
    let t0 = add(&t0, &t5, f);
    s.x = sub(&t0, &t4, f)?;
    let t4 = g.field_sqr(&r.x)?;
    let t5 = g.field_sqr(&r.z)?;
    let t6 = g.field_mul(&t5, &g.a)?;
    let t1 = add(&r.x, &r.z, f);
    let t1 = g.field_sqr(&t1)?;
    let t1 = sub(&t1, &t4, f)?;
    let t1 = sub(&t1, &t5, f)?;
    let t3 = sub(&t4, &t6, f)?;
    let t3 = g.field_sqr(&t3)?;
    let t0 = g.field_mul(&t5, &t1)?;
    let t0 = g.field_mul(&t2, &t0)?;
    r.x = sub(&t3, &t0, f)?;
    let t3 = add(&t4, &t6, f);
    let t4 = g.field_sqr(&t5)?;
    let t4 = g.field_mul(&t4, &t2)?;
    let t1 = g.field_mul(&t1, &t3)?;
    let t1 = dbl(&t1, f)?;
    r.z = add(&t4, &t1, f);
    Ok(())
}

/// `ossl_ec_GFp_simple_ladder_post`: `r` recovered in affine coordinates (with its y) from
/// the ladder's `r`, `s`, and `p`.
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
        return invert(g, r);
    }
    let f = &g.field;
    let t4 = dbl(&p.y, f)?;
    let t6 = g.field_mul(&r.x, &t4)?;
    let t6 = g.field_mul(&s.z, &t6)?;
    let t5 = g.field_mul(&r.z, &t6)?;
    let t1 = dbl(&g.b, f)?;
    let t1 = g.field_mul(&s.z, &t1)?;
    let t3 = g.field_sqr(&r.z)?;
    let t2 = g.field_mul(&t3, &t1)?;
    let t6 = g.field_mul(&r.z, &g.a)?;
    let t1 = g.field_mul(&p.x, &r.x)?;
    let t1 = add(&t1, &t6, f);
    let t1 = g.field_mul(&s.z, &t1)?;
    let t0 = g.field_mul(&p.x, &r.z)?;
    let t6 = add(&r.x, &t0, f);
    let t6 = g.field_mul(&t6, &t1)?;
    let t6 = add(&t6, &t2, f);
    let t0 = sub(&t0, &r.x, f)?;
    let t0 = g.field_sqr(&t0)?;
    let t0 = g.field_mul(&t0, &s.x)?;
    let t0 = sub(&t6, &t0, f)?;
    let t1 = g.field_mul(&s.z, &t4)?;
    let t1 = g.field_mul(&t3, &t1)?;
    let t1 = g.field_inv(&t1, rng)?;
    r.x = g.field_mul(&t5, &t1)?;
    r.y = g.field_mul(&t0, &t1)?;
    r.z = BigNum::one();
    r.z_is_one = true;
    Ok(())
}
