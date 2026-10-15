//! Points' octet encodings (X9.62, SEC 1: `ecp_oct.c`, `ec2_oct.c`): `00` for the point at
//! infinity, then `02`/`03` and x (compressed), `04`, x, and y (uncompressed), or `06`/`07`, x,
//! and y (hybrid); and recovering y from x and its bit.

use super::curves::Field;
use super::group::Group;
use super::point::{self, Point};
use super::{Error, Random, Reason, Result};
use crate::bn::{self, BigNum, Endian, gf2m, modular};

/// `POINT_CONVERSION_COMPRESSED`.
pub const COMPRESSED: u8 = 2;
/// `POINT_CONVERSION_UNCOMPRESSED`.
pub const UNCOMPRESSED: u8 = 4;
/// `POINT_CONVERSION_HYBRID`.
pub const HYBRID: u8 = 6;

/// The method's `point2oct`, for its errors.
fn point2oct(g: &Group) -> &'static str {
    match g.meth.field() {
        Field::Prime => "ossl_ec_GFp_simple_point2oct",
        Field::Binary => "ossl_ec_GF2m_simple_point2oct",
    }
}

/// The method's `oct2point`, for its errors.
fn oct2point(g: &Group) -> &'static str {
    match g.meth.field() {
        Field::Prime => "ossl_ec_GFp_simple_oct2point",
        Field::Binary => "ossl_ec_GF2m_simple_oct2point",
    }
}

/// The size of a field element in octets: the prime's, or the degree's.
#[must_use]
pub fn field_len(g: &Group) -> usize {
    match g.meth.field() {
        Field::Prime => g.field.num_bytes(),
        Field::Binary => g.degree().div_ceil(8),
    }
}

/// `point2oct`'s length for `form`, or `InvalidForm` (the infinity's single octet aside).
pub fn encoded_len(g: &Group, pt: &Point, form: u8) -> Result<usize> {
    if form != COMPRESSED && form != UNCOMPRESSED && form != HYBRID {
        return Err(Error::new(Reason::InvalidForm, point2oct(g)));
    }
    if pt.is_at_infinity() {
        return Ok(1);
    }
    let fl = field_len(g);
    Ok(if form == COMPRESSED {
        fl.saturating_add(1)
    } else {
        fl.saturating_mul(2).saturating_add(1)
    })
}

/// `x` big-endian in exactly `len` octets.
fn pad(x: &BigNum, len: usize, func: &'static str) -> Result<Vec<u8>> {
    if x.num_bytes() > len {
        return Err(Error::new(Reason::InternalError, func));
    }
    x.to_bin(Some(len), Endian::Big, false)
        .map(|z| z.to_vec())
        .ok_or(Error::new(Reason::InternalError, func))
}

/// `point2oct`'s encoding of a point in `form` (the length checked by the caller).
pub fn encode(g: &Group, pt: &Point, form: u8, rng: &mut Random<'_>) -> Result<Vec<u8>> {
    let len = encoded_len(g, pt, form)?;
    if pt.is_at_infinity() {
        return Ok(vec![0]);
    }
    let fl = field_len(g);
    let (x, y) = point::get_affine(g, pt, rng)?;
    let odd = match g.meth.field() {
        Field::Prime => y.is_odd(),
        Field::Binary => {
            if form != UNCOMPRESSED && !x.is_zero() {
                g.field_div(&y, &x, rng)?.is_odd()
            } else {
                false
            }
        }
    };
    let first = if form != UNCOMPRESSED && odd {
        form.saturating_add(1)
    } else {
        form
    };
    let mut out = Vec::with_capacity(len);
    out.push(first);
    out.extend(pad(&x, fl, point2oct(g))?);
    if form != COMPRESSED {
        out.extend(pad(&y, fl, point2oct(g))?);
    }
    if out.len() != len {
        return Err(Error::new(Reason::InternalError, point2oct(g)));
    }
    Ok(out)
}

/// `oct2point`: the point an encoding gives, set on `pt` (whose coordinates stay as they were
/// if it fails part way, as OpenSSL's do).
pub fn decode(g: &Group, pt: &mut Point, buf: &[u8], rng: &mut Random<'_>) -> Result<()> {
    let Some(&first) = buf.first() else {
        return Err(Error::new(Reason::BufferTooSmall, oct2point(g)));
    };
    let y_bit = first & 1 == 1;
    let form = first & !1;
    if form != 0 && form != COMPRESSED && form != UNCOMPRESSED && form != HYBRID {
        return Err(Error::new(Reason::InvalidEncoding, oct2point(g)));
    }
    if (form == 0 || form == UNCOMPRESSED) && y_bit {
        return Err(Error::new(Reason::InvalidEncoding, oct2point(g)));
    }
    if form == 0 {
        if buf.len() != 1 {
            return Err(Error::new(Reason::InvalidEncoding, oct2point(g)));
        }
        pt.set_to_infinity();
        return Ok(());
    }
    let fl = field_len(g);
    let enc_len = if form == COMPRESSED {
        fl.saturating_add(1)
    } else {
        fl.saturating_mul(2).saturating_add(1)
    };
    if buf.len() != enc_len {
        return Err(Error::new(Reason::InvalidEncoding, oct2point(g)));
    }
    let too_big = |v: &BigNum| match g.meth.field() {
        Field::Prime => bn::ucmp(v, &g.field).is_ge(),
        Field::Binary => v.num_bits() > g.degree(),
    };
    let xs = buf
        .get(1..fl.saturating_add(1))
        .ok_or(Error::new(Reason::InvalidEncoding, oct2point(g)))?;
    let x = BigNum::from_bin(xs, Endian::Big, false)?;
    if too_big(&x) {
        return Err(Error::new(Reason::InvalidEncoding, oct2point(g)));
    }
    if form == COMPRESSED {
        return set_compressed(g, pt, &x, y_bit, rng);
    }
    let ys = buf
        .get(fl.saturating_add(1)..)
        .ok_or(Error::new(Reason::InvalidEncoding, oct2point(g)))?;
    let y = BigNum::from_bin(ys, Endian::Big, false)?;
    if too_big(&y) {
        return Err(Error::new(Reason::InvalidEncoding, oct2point(g)));
    }
    if form == HYBRID {
        let bad = match g.meth.field() {
            Field::Prime => y_bit != y.is_odd(),
            Field::Binary => {
                if x.is_zero() {
                    y_bit
                } else {
                    y_bit != g.field_div(&y, &x, rng)?.is_odd()
                }
            }
        };
        if bad {
            return Err(Error::new(Reason::InvalidEncoding, oct2point(g)));
        }
    }
    set_affine_checked(g, pt, &x, &y)
}

/// `EC_POINT_set_affine_coordinates`, which refuses a point off the curve.
fn set_affine_checked(g: &Group, pt: &mut Point, x: &BigNum, y: &BigNum) -> Result<()> {
    if point::set_affine(g, pt, x, y)? {
        Ok(())
    } else {
        Err(Error::new(
            Reason::PointIsNotOnCurve,
            "EC_POINT_set_affine_coordinates",
        ))
    }
}

/// `EC_POINT_set_compressed_coordinates`: the point with this x and y's bit (y's parity over
/// GF(p), that of `y/x` over GF(2^m)).
pub fn set_compressed(
    g: &Group,
    pt: &mut Point,
    x_: &BigNum,
    y_bit: bool,
    rng: &mut Random<'_>,
) -> Result<()> {
    match g.meth.field() {
        Field::Prime => set_compressed_gfp(g, pt, x_, y_bit, rng),
        Field::Binary => set_compressed_gf2m(g, pt, x_, y_bit, rng),
    }
}

/// `ossl_ec_GFp_simple_set_compressed_coordinates`.
fn set_compressed_gfp(
    g: &Group,
    pt: &mut Point,
    x_: &BigNum,
    y_bit: bool,
    rng: &mut Random<'_>,
) -> Result<()> {
    let p = &g.field;
    let x = bn::nnmod(x_, p)?;
    let t2 = modular::mod_sqr(x_, p)?;
    let t1 = modular::mod_mul(&t2, x_, p)?;
    let t1 = if g.a_is_minus3 {
        let t2 = modular::mod_lshift1_quick(&x, p)?;
        let t2 = modular::mod_add_quick(&t2, &x, p);
        let r = bn::sub(&t1, &t2)?;
        if r.is_negative() { bn::add(&r, p)? } else { r }
    } else {
        let t2 = modular::mod_mul(&g.a, &x, p)?;
        modular::mod_add_quick(&t1, &t2, p)
    };
    let t1 = modular::mod_add_quick(&t1, &g.b, p);
    let mut random = |bits: usize| bn::rand::rand_bits_top_one(bits, rng);
    let mut y = match modular::mod_sqrt(&t1, p, &mut random) {
        Ok(y) => y,
        Err(f) if f.error == bn::Error::NotASquare => {
            return Err(Error::new(
                Reason::InvalidCompressedPoint,
                "ossl_ec_GFp_simple_set_compressed_coordinates",
            ));
        }
        Err(f) => {
            return Err(Error::from(f.error).then(
                Reason::BnLib,
                "ossl_ec_GFp_simple_set_compressed_coordinates",
            ));
        }
    };
    if y_bit != y.is_odd() {
        if y.is_zero() {
            let kron = modular::kronecker(&x, p)?;
            let reason = if kron == 1 {
                Reason::InvalidCompressionBit
            } else {
                Reason::InvalidCompressedPoint
            };
            return Err(Error::new(
                reason,
                "ossl_ec_GFp_simple_set_compressed_coordinates",
            ));
        }
        y = bn::usub(p, &y)?;
    }
    if y_bit != y.is_odd() {
        return Err(Error::new(
            Reason::InternalError,
            "ossl_ec_GFp_simple_set_compressed_coordinates",
        ));
    }
    set_affine_checked(g, pt, &x, &y)
}

/// `BN_GF2m_mod_sqrt_arr`: `a^(2^(m-1))`.
fn gf2m_sqrt(a: &BigNum, poly: &[usize]) -> BigNum {
    let deg = poly.first().copied().unwrap_or(0);
    if deg == 0 {
        return BigNum::zero();
    }
    let mut r = gf2m::reduce(a, poly);
    for _ in 1..deg {
        r = gf2m::sqr(&r, poly);
    }
    r
}

/// `BN_GF2m_mod_solve_quad_arr`: a `z` with `z^2 + z = a`, or why there's none.
fn gf2m_solve_quad(
    a: &BigNum,
    poly: &[usize],
    rng: &mut Random<'_>,
) -> core::result::Result<BigNum, Option<bn::Error>> {
    let deg = poly.first().copied().unwrap_or(0);
    if deg == 0 {
        return Ok(BigNum::zero());
    }
    let a = gf2m::reduce(a, poly);
    if a.is_zero() {
        return Ok(BigNum::zero());
    }
    let z = if deg % 2 == 1 {
        let mut z = a.clone();
        for _ in 1..=(deg.saturating_sub(1)) / 2 {
            z = gf2m::sqr(&gf2m::sqr(&z, poly), poly);
            z = gf2m::add(&z, &a);
        }
        z
    } else {
        let mut found = None;
        for _ in 0..50 {
            let rho = bn::rand::rand_bits_top_one(deg, rng).ok_or(Some(bn::Error::Rand))?;
            let rho = gf2m::reduce(&rho, poly);
            let mut z = BigNum::zero();
            let mut w = rho.clone();
            for _ in 1..deg {
                z = gf2m::sqr(&z, poly);
                let w2 = gf2m::sqr(&w, poly);
                z = gf2m::add(&z, &gf2m::mul(&w2, &a, poly));
                w = gf2m::add(&w2, &rho);
            }
            if !w.is_zero() {
                found = Some(z);
                break;
            }
        }
        found.ok_or(Some(bn::Error::TooManyIterations))?
    };
    let w = gf2m::add(&z, &gf2m::sqr(&z, poly));
    if bn::ucmp(&w, &a).is_eq() {
        Ok(z)
    } else {
        Err(None)
    }
}

/// `ossl_ec_GF2m_simple_set_compressed_coordinates`.
fn set_compressed_gf2m(
    g: &Group,
    pt: &mut Point,
    x_: &BigNum,
    y_bit: bool,
    rng: &mut Random<'_>,
) -> Result<()> {
    let x = gf2m::reduce(x_, &g.poly);
    let y = if x.is_zero() {
        gf2m_sqrt(&g.b, &g.poly)
    } else {
        let tmp = g.field_sqr(&x)?;
        let tmp = g.field_div(&g.b, &tmp, rng)?;
        let tmp = gf2m::add(&g.a, &tmp);
        let tmp = gf2m::add(&x, &tmp);
        let z = match gf2m_solve_quad(&tmp, &g.poly, rng) {
            Ok(z) => z,
            Err(None) => {
                return Err(Error::new(
                    Reason::InvalidCompressedPoint,
                    "ossl_ec_GF2m_simple_set_compressed_coordinates",
                ));
            }
            Err(Some(e)) => {
                return Err(Error::from(e).then(
                    Reason::BnLib,
                    "ossl_ec_GF2m_simple_set_compressed_coordinates",
                ));
            }
        };
        let y = g.field_mul(&x, &z)?;
        if z.is_odd() == y_bit {
            y
        } else {
            gf2m::add(&y, &x)
        }
    };
    set_affine_checked(g, pt, &x, &y)
}
