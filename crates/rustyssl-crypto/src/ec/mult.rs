//! Scalar multiplication (`ec_mult.c`, `EC_POINTs_mul`): `r = scalar * G + Σ scalars[i] *
//! points[i]`.
//!
//! - A single secret scalar (times the generator, or one point) goes through
//!   `ossl_ec_scalar_mul_ladder`: a Montgomery ladder over the group's cardinality with
//!   constant-time swaps, on coordinates the method randomizes (`ladder_pre`).
//! - Several, or the group's own order, go through wNAF with OpenSSL's window sizes, digits,
//!   and coordinate blinding.
//! - The curve-specific methods (`nistp*`, `nistz256`, `sm2p256`) have their own constant-time
//!   multiplications in OpenSSL, which draw no random numbers. Here they run the ladder
//!   without randomized coordinates and invert without blinding, so they draw none either,
//!   and hand back a Jacobian point (Z = 2) as theirs do; its X and Y differ from theirs (the
//!   affine point is the same).

use super::curves::Field;
use super::group::Group;
use super::point::{self, Point};
use super::{Error, Random, Reason, Result, gf2m, gfp};
use crate::bn::{self, BigNum};

/// `EC_window_bits_for_scalar_size`.
fn window_bits(bits: usize) -> usize {
    match bits {
        2000.. => 6,
        800.. => 5,
        300.. => 4,
        70.. => 3,
        20.. => 2,
        _ => 1,
    }
}

/// `bn_compute_wNAF`: the modified width-(w+1) NAF of `scalar`, least significant digit first.
fn compute_wnaf(scalar: &BigNum, w: usize) -> Result<Vec<i8>> {
    if scalar.is_zero() {
        return Ok(vec![0]);
    }
    if w == 0 || w > 7 {
        return Err(Error::new(Reason::InternalError, "bn_compute_wNAF"));
    }
    let bit: i32 = 1 << w;
    let next_bit = bit << 1;
    let mask = next_bit.wrapping_sub(1);
    let sign: i32 = if scalar.is_negative() { -1 } else { 1 };
    let len = scalar.num_bits();
    let low = scalar.limbs().first().copied().unwrap_or(0);
    let mut window_val = i32::try_from(low & u64::try_from(mask).unwrap_or(0)).unwrap_or(0);
    let mut r = Vec::with_capacity(len.saturating_add(1));
    let mut j: usize = 0;
    while window_val != 0 || j.saturating_add(w).saturating_add(1) < len {
        let mut digit = 0;
        if window_val & 1 != 0 {
            if window_val & bit != 0 {
                digit = window_val.wrapping_sub(next_bit);
                if j.saturating_add(w).saturating_add(1) >= len {
                    digit = window_val & (mask >> 1);
                }
            } else {
                digit = window_val;
            }
            if digit <= bit.wrapping_neg() || digit >= bit || digit & 1 == 0 {
                return Err(Error::new(Reason::InternalError, "bn_compute_wNAF"));
            }
            window_val = window_val.wrapping_sub(digit);
            if window_val != 0 && window_val != next_bit && window_val != bit {
                return Err(Error::new(Reason::InternalError, "bn_compute_wNAF"));
            }
        }
        r.push(
            i8::try_from(sign.wrapping_mul(digit))
                .map_err(|_| Error::new(Reason::InternalError, "bn_compute_wNAF"))?,
        );
        j = j.saturating_add(1);
        window_val >>= 1;
        if scalar.is_bit_set(j.saturating_add(w)) {
            window_val = window_val.wrapping_add(bit);
        }
        if window_val > next_bit {
            return Err(Error::new(Reason::InternalError, "bn_compute_wNAF"));
        }
    }
    if j > len.saturating_add(1) {
        return Err(Error::new(Reason::InternalError, "bn_compute_wNAF"));
    }
    Ok(r)
}

/// The scalar multiplication `EC_POINTs_mul` asks for. `scalar_is_order` says the generator's
/// scalar is the group's own order object (`EC_GROUP_check`'s), which OpenSSL's wNAF tests by
/// address.
pub struct Request<'a> {
    pub scalar: Option<&'a BigNum>,
    pub pairs: &'a [(&'a Point, &'a BigNum)],
    pub scalar_is_order: bool,
}

/// `EC_POINTs_mul`'s work after its checks: the method's `mul`, or wNAF.
pub fn mul(g: &Group, r: &mut Point, req: &Request<'_>, rng: &mut Random<'_>) -> Result<()> {
    if req.scalar.is_none() && req.pairs.is_empty() {
        r.set_to_infinity();
        return Ok(());
    }
    if g.meth.specialized_mul() {
        return specialized(g, r, req);
    }
    if g.meth.field() == Field::Binary {
        return gf2m_points_mul(g, r, req, rng);
    }
    wnaf_mul(g, r, req, rng)
}

/// `ec_GF2m_simple_points_mul`.
fn gf2m_points_mul(
    g: &Group,
    r: &mut Point,
    req: &Request<'_>,
    rng: &mut Random<'_>,
) -> Result<()> {
    if req.pairs.len() > 1 || g.order.is_zero() || g.cofactor.is_zero() {
        return wnaf_mul(g, r, req, rng);
    }
    match (req.scalar, req.pairs) {
        (Some(s), []) => ladder(g, r, s, None, rng, true),
        (None, [(p, s)]) => ladder(g, r, s, Some(p), rng, true),
        (Some(s), [(p, ps)]) => {
            let mut t = Point::infinity();
            ladder(g, &mut t, s, None, rng, true)?;
            ladder(g, r, ps, Some(p), rng, true)?;
            let rr = r.clone();
            point::add(g, r, &t, &rr, false, rng)
        }
        _ => Ok(()),
    }
}

/// Swaps `a` and `b` when `c`, in constant time (`EC_POINT_CSWAP`).
fn cswap(c: bool, a: &mut Point, b: &mut Point, words: usize) -> Result<()> {
    bn::consttime_swap(c, &mut a.x, &mut b.x, words);
    bn::consttime_swap(c, &mut a.y, &mut b.y, words);
    bn::consttime_swap(c, &mut a.z, &mut b.z, words);
    let t = (a.z_is_one ^ b.z_is_one) & c;
    a.z_is_one ^= t;
    b.z_is_one ^= t;
    Ok(())
}

/// `ossl_ec_scalar_mul_ladder`: `r = scalar * point` (the generator for `None`), the scalar
/// padded with the cardinality so the ladder always runs over the same number of bits.
/// `random` is whether the method randomizes the ladder's coordinates and blinds its
/// inversion (the generic methods); the specialized ones neither.
fn ladder(
    g: &Group,
    r: &mut Point,
    scalar: &BigNum,
    pt: Option<&Point>,
    rng: &mut Random<'_>,
    random: bool,
) -> Result<()> {
    if pt.is_some_and(Point::is_at_infinity) {
        r.set_to_infinity();
        return Ok(());
    }
    if g.order.is_zero() {
        return Err(Error::new(
            Reason::UnknownOrder,
            "ossl_ec_scalar_mul_ladder",
        ));
    }
    if g.cofactor.is_zero() {
        return Err(Error::new(
            Reason::UnknownCofactor,
            "ossl_ec_scalar_mul_ladder",
        ));
    }
    let mut p = match pt {
        Some(p) => p.clone(),
        None => g
            .generator
            .clone()
            .ok_or(Error::new(Reason::EcLib, "ossl_ec_scalar_mul_ladder"))?,
    };
    let cardinality = bn::mul(&g.order, &g.cofactor)
        .map_err(|e| Error::from(e).then(Reason::BnLib, "ossl_ec_scalar_mul_ladder"))?;
    let card_bits = cardinality.num_bits();
    let top = cardinality.top();
    let mut k = scalar.clone();
    if k.num_bits() > card_bits || k.is_negative() {
        k = bn::nnmod(&k, &cardinality)
            .map_err(|e| Error::from(e).then(Reason::BnLib, "ossl_ec_scalar_mul_ladder"))?;
    }
    let mut lambda = bn::add(&k, &cardinality)
        .map_err(|e| Error::from(e).then(Reason::BnLib, "ossl_ec_scalar_mul_ladder"))?;
    let mut k = bn::add(&lambda, &cardinality)
        .map_err(|e| Error::from(e).then(Reason::BnLib, "ossl_ec_scalar_mul_ladder"))?;
    let kbit = lambda.is_bit_set(card_bits);
    bn::consttime_swap(kbit, &mut k, &mut lambda, top.saturating_add(2));
    let words = g.field.top();
    if !p.z_is_one {
        point::make_affine(g, &mut p, rng)
            .map_err(|e| e.then(Reason::EcLib, "ossl_ec_scalar_mul_ladder"))?;
    }
    let mut s = Point::infinity();
    pre(g, r, &mut s, &p, rng, random)
        .map_err(|e| e.then(Reason::LadderPreFailure, "ossl_ec_scalar_mul_ladder"))?;
    let mut pbit = true;
    for i in (0..card_bits).rev() {
        let kbit = k.is_bit_set(i) ^ pbit;
        cswap(kbit, r, &mut s, words)?;
        step(g, r, &mut s, &p, rng)
            .map_err(|e| e.then(Reason::LadderStepFailure, "ossl_ec_scalar_mul_ladder"))?;
        pbit ^= kbit;
    }
    cswap(pbit, r, &mut s, words)?;
    post(g, r, &s, &p, rng, random)
        .map_err(|e| e.then(Reason::LadderPostFailure, "ossl_ec_scalar_mul_ladder"))
}

/// The method's `ladder_pre`; without randomness, the coordinates' factors are one.
fn pre(
    g: &Group,
    r: &mut Point,
    s: &mut Point,
    p: &Point,
    rng: &mut Random<'_>,
    random: bool,
) -> Result<()> {
    if random {
        return match g.meth.field() {
            Field::Prime => gfp::ladder_pre(g, r, s, p, rng),
            Field::Binary => gf2m::ladder_pre(g, r, s, p, rng),
        };
    }
    let mut one = |buf: &mut [u8]| {
        buf.fill(0);
        if let Some(last) = buf.last_mut() {
            *last = 1;
        }
        true
    };
    match g.meth.field() {
        Field::Prime => gfp::ladder_pre(g, r, s, p, &mut one),
        Field::Binary => gf2m::ladder_pre(g, r, s, p, &mut one),
    }
}

/// The method's `ladder_step`.
fn step(g: &Group, r: &mut Point, s: &mut Point, p: &Point, _rng: &mut Random<'_>) -> Result<()> {
    match g.meth.field() {
        Field::Prime => gfp::ladder_step(g, r, s, p),
        Field::Binary => gf2m::ladder_step(g, r, s, p),
    }
}

/// The method's `ladder_post`; without randomness, inverting by Fermat's little theorem.
fn post(
    g: &Group,
    r: &mut Point,
    s: &Point,
    p: &Point,
    rng: &mut Random<'_>,
    random: bool,
) -> Result<()> {
    if random {
        return match g.meth.field() {
            Field::Prime => gfp::ladder_post(g, r, s, p, rng),
            Field::Binary => gf2m::ladder_post(g, r, s, p, rng),
        };
    }
    let mut fermat = g.clone();
    fermat.meth = super::Meth::Mont;
    let mut none = |_: &mut [u8]| false;
    gfp::ladder_post(&fermat, r, s, p, &mut none)
}

/// The curve-specific methods' multiplications: the ladder for each term, without random
/// numbers, summed, and handed back in Jacobian coordinates (Z = 2) as theirs are.
fn specialized(g: &Group, r: &mut Point, req: &Request<'_>) -> Result<()> {
    let mut none = |_: &mut [u8]| false;
    let mut acc: Option<Point> = None;
    let terms = req
        .scalar
        .map(|s| (None, s))
        .into_iter()
        .chain(req.pairs.iter().map(|(p, s)| (Some(*p), *s)));
    for (pt, s) in terms {
        let mut t = Point::infinity();
        if g.order.is_zero() || g.cofactor.is_zero() {
            return Err(Error::new(
                Reason::UnknownOrder,
                "ossl_ec_scalar_mul_ladder",
            ));
        }
        ladder(g, &mut t, s, pt, &mut none, false)?;
        acc = Some(match acc {
            None => t,
            Some(a) => {
                let mut sum = Point::infinity();
                gfp::add_points(g, &mut sum, &a, &t, false)?;
                sum
            }
        });
    }
    let mut out = acc.unwrap_or_default();
    if !out.is_at_infinity() {
        if !out.z_is_one {
            let mut fermat = g.clone();
            fermat.meth = super::Meth::Mont;
            let (x, y) = gfp::get_affine(&fermat, &out, &mut none)?;
            out = Point {
                x,
                y,
                z: BigNum::one(),
                z_is_one: true,
            };
        }
        let two = BigNum::from_word(2);
        let four = g.field_sqr(&two)?;
        let eight = g.field_mul(&four, &two)?;
        out.x = g.field_mul(&out.x, &four)?;
        out.y = g.field_mul(&out.y, &eight)?;
        out.z = two;
        out.z_is_one = false;
    }
    *r = out;
    Ok(())
}

/// `ossl_ec_wNAF_mul` (without a precomputed generator table).
fn wnaf_mul(g: &Group, r: &mut Point, req: &Request<'_>, rng: &mut Random<'_>) -> Result<()> {
    if !g.order.is_zero() && !g.cofactor.is_zero() {
        if let (Some(s), []) = (req.scalar, req.pairs)
            && !req.scalar_is_order
        {
            return ladder(g, r, s, None, rng, true);
        }
        if let (None, [(p, s)]) = (req.scalar, req.pairs) {
            return ladder(g, r, s, Some(p), rng, true);
        }
    }
    let generator = match req.scalar {
        Some(_) => Some(
            g.generator
                .as_ref()
                .ok_or(Error::new(Reason::UndefinedGenerator, "ossl_ec_wNAF_mul"))?,
        ),
        None => None,
    };
    let mut terms: Vec<(&Point, &BigNum)> = req.pairs.to_vec();
    if let (Some(base), Some(s)) = (generator, req.scalar) {
        terms.push((base, s));
    }
    let mut wsize = Vec::with_capacity(terms.len());
    let mut wnaf = Vec::with_capacity(terms.len());
    let mut max_len = 0;
    for (_, s) in &terms {
        let w = window_bits(s.num_bits());
        let digits = compute_wnaf(s, w)?;
        max_len = max_len.max(digits.len());
        wsize.push(w);
        wnaf.push(digits);
    }
    // The precomputed odd multiples of each point: P, 3P, 5P, ...
    let mut val: Vec<Point> = Vec::new();
    let mut starts = Vec::with_capacity(terms.len());
    for ((p, _), w) in terms.iter().zip(&wsize) {
        starts.push(val.len());
        let count = 1usize << w.saturating_sub(1);
        let first = (*p).clone();
        val.push(first.clone());
        if *w > 1 {
            let mut tmp = Point::infinity();
            point::dbl(g, &mut tmp, &first, rng)?;
            let mut prev = first;
            for _ in 1..count {
                let mut next = Point::infinity();
                point::add(g, &mut next, &prev, &tmp, false, rng)?;
                val.push(next.clone());
                prev = next;
            }
        }
    }
    point::points_make_affine(g, &mut val, rng)?;
    let mut at_infinity = true;
    let mut inverted = false;
    for k in (0..max_len).rev() {
        if !at_infinity {
            let rr = r.clone();
            point::dbl(g, r, &rr, rng)?;
        }
        for (i, digits) in wnaf.iter().enumerate() {
            let Some(&d) = digits.get(k) else { continue };
            if d == 0 {
                continue;
            }
            let neg = d < 0;
            let digit = usize::from(d.unsigned_abs());
            if neg != inverted {
                if !at_infinity {
                    point::invert(g, r)?;
                }
                inverted = !inverted;
            }
            let idx = starts
                .get(i)
                .copied()
                .unwrap_or(0)
                .saturating_add(digit >> 1);
            let v = val
                .get(idx)
                .ok_or(Error::new(Reason::InternalError, "ossl_ec_wNAF_mul"))?;
            if at_infinity {
                *r = v.clone();
                if g.meth.field() == Field::Prime {
                    gfp::blind_coordinates(g, r, rng)?;
                }
                at_infinity = false;
            } else {
                let rr = r.clone();
                point::add(g, r, &rr, v, false, rng)?;
            }
        }
    }
    if at_infinity {
        r.set_to_infinity();
    } else if inverted {
        point::invert(g, r)?;
    }
    Ok(())
}
