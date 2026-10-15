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
///
/// With no terms at all (`EC_POINT_mul` with a point scalar but no point), wNAF fails without
/// an error entry, as OpenSSL's does when its zero-length allocation fails; the binary method,
/// whose ladder OpenSSL runs on the missing scalar and crashes, gives infinity.
pub fn mul(g: &Group, r: &mut Point, req: &Request<'_>, rng: &mut Random<'_>) -> Result<()> {
    if g.meth.specialized_mul() {
        return specialized(g, r, req);
    }
    if g.meth.field() == Field::Binary {
        if req.scalar.is_none() && req.pairs.is_empty() {
            r.set_to_infinity();
            return Ok(());
        }
        return gf2m_points_mul(g, r, req, rng);
    }
    if req.scalar.is_none() && req.pairs.is_empty() {
        return Err(Error(Vec::new()));
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
    if !p.z_is_one && !random {
        // The specialized methods' own multiplications (for which this stands in) take a
        // point as it is, on the curve or not.
        let (x, y) = gfp::get_affine(g, &p, rng)?;
        gfp::set_jprojective(g, &mut p, Some(&x), Some(&y), Some(&BigNum::one()))?;
    } else if !p.z_is_one {
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
    // sm2p256 takes the generator's scalar's magnitude as a 256-bit field element (the
    // points' it reduces modulo the order), and its table multiplies by that magnitude.
    if g.meth == super::Meth::Sm2p256 && req.scalar.is_some_and(|s| s.num_bits() > 256) {
        return Err(Error::new(
            Reason::CoordinatesOutOfRange,
            "ecp_sm2p256_points_mul",
        ));
    }
    // Every inversion by Fermat's little theorem, so nothing random is drawn.
    let mut fermat = g.clone();
    fermat.meth = super::Meth::Mont;
    let f = &fermat;
    let mut none = |_: &mut [u8]| false;
    let sm2 = g.meth == super::Meth::Sm2p256;
    let sm2_table = sm2 && standard_generator(g);
    let mut acc: Option<Point> = None;
    // Whether sm2p256's sum so far has Z = 1 (it copies a term into an infinite sum).
    let mut sm2_affine = false;
    let magnitude = req.scalar.filter(|_| sm2_table).map(BigNum::abs);
    let terms = magnitude
        .as_ref()
        .or(req.scalar)
        .map(|s| (None, s))
        .into_iter()
        .chain(req.pairs.iter().map(|(p, s)| (Some(*p), *s)));
    for (pt, s) in terms {
        let mut t = Point::infinity();
        ladder(f, &mut t, s, pt, &mut none, false)?;
        let t_affine = sm2 && !t.is_at_infinity() && sm2_term_affine(g, pt, s, sm2_table)?;
        acc = Some(match acc {
            None => {
                sm2_affine = t_affine;
                t
            }
            Some(a) => {
                if a.is_at_infinity() {
                    sm2_affine = t_affine;
                } else if !t.is_at_infinity() {
                    sm2_affine = false;
                }
                let mut sum = Point::infinity();
                gfp::add_points(f, &mut sum, &a, &t, false)?;
                sum
            }
        });
    }
    let mut out = acc.unwrap_or_default();
    // nistz256 multiplies its standard generator alone with a table of affine points, and
    // hands back an affine point; sm2p256 hands back a term as it made it when it's the only
    // one that isn't infinity, which is affine in the cases `sm2_term_affine` names; every
    // other result is Jacobian (and converting sm2p256's draws its blinded inversion's random
    // numbers).
    let affine = (g.meth == super::Meth::Nistz256 && req.pairs.is_empty() && standard_generator(g))
        || sm2_affine;
    if !out.is_at_infinity() {
        if !out.z_is_one {
            let (x, y) = gfp::get_affine(f, &out, &mut none)?;
            out = Point {
                x,
                y,
                z: BigNum::one(),
                z_is_one: true,
            };
        }
        if affine {
            *r = out;
            return Ok(());
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

/// Whether sm2p256 makes a term `s * pt` (the generator for `None`), not infinity, with
/// Z = 1: from its generator table, a scalar with one nonzero octet (one affine table entry);
/// by its 4-bit window, a scalar (reduced modulo the order when negative or over 256 bits) of
/// one, the point itself.
fn sm2_term_affine(g: &Group, pt: Option<&Point>, s: &BigNum, table: bool) -> Result<bool> {
    if pt.is_none() && table {
        let octets = s
            .to_bin(None, crate::bn::Endian::Big, false)
            .unwrap_or_default();
        return Ok(octets.iter().filter(|b| **b != 0).count() == 1);
    }
    if s.is_negative() || s.num_bits() > 256 {
        let k = bn::nnmod(s, &g.order).map_err(Error::from)?;
        return Ok(k.is_one());
    }
    Ok(s.is_one())
}

/// Whether the group's generator is its named curve's own, in affine coordinates
/// (`ecp_nistz256_is_affine_G`, `ecp_sm2p256_is_affine_G`).
fn standard_generator(g: &Group) -> bool {
    let (Some(gen_pt), Some(c)) = (g.generator.as_ref(), super::curves::by_nid(g.curve_name))
    else {
        return false;
    };
    let num = |v: &[u8]| BigNum::from_bin(v, crate::bn::Endian::Big, false).ok();
    gen_pt.z_is_one
        && num(c.x).is_some_and(|x| bn::cmp(&x, &gen_pt.x).is_eq())
        && num(c.y).is_some_and(|y| bn::cmp(&y, &gen_pt.y).is_eq())
}

/// `EC_PRE_COMP`: odd multiples of the generator and of `2^(blocksize*i)` times it, for wNAF
/// to split the generator's scalar across, affine.
#[derive(Debug)]
pub struct PreComp {
    pub blocksize: usize,
    pub numblocks: usize,
    pub w: usize,
    pub points: Vec<Point>,
}

/// `ossl_ec_wNAF_precompute_mult`: the generator's table.
pub fn precompute(g: &Group, rng: &mut Random<'_>) -> Result<PreComp> {
    const F: &str = "ossl_ec_wNAF_precompute_mult";
    let generator = g
        .generator
        .as_ref()
        .ok_or(Error::new(Reason::UndefinedGenerator, F))?;
    if g.order.is_zero() {
        return Err(Error::new(Reason::UnknownOrder, F));
    }
    let bits = g.order.num_bits();
    let blocksize = 8;
    let w = window_bits(bits).max(4);
    let numblocks = bits.div_ceil(blocksize);
    let per_block = 1usize << w.saturating_sub(1);
    let mut points: Vec<Point> = Vec::with_capacity(per_block.saturating_mul(numblocks));
    let mut base = generator.clone();
    for i in 0..numblocks {
        let mut tmp = Point::infinity();
        point::dbl(g, &mut tmp, &base, rng)?;
        points.push(base.clone());
        for _ in 1..per_block {
            let prev = points.last().cloned().unwrap_or_default();
            let mut next = Point::infinity();
            point::add(g, &mut next, &tmp, &prev, false, rng)?;
            points.push(next);
        }
        if i.saturating_add(1) < numblocks {
            let mut b = Point::infinity();
            point::dbl(g, &mut b, &tmp, rng)?;
            for _ in 2..blocksize {
                let bb = b.clone();
                point::dbl(g, &mut b, &bb, rng)?;
            }
            base = b;
        }
    }
    point::points_make_affine(g, &mut points, rng)?;
    Ok(PreComp {
        blocksize,
        numblocks,
        w,
        points,
    })
}

/// Where a wNAF term's odd multiples are: in this multiplication's own table, from an index,
/// or in the group's precomputed one.
#[derive(Clone, Copy)]
enum Table {
    Own(usize),
    Pre(usize),
}

/// `ossl_ec_wNAF_mul`.
fn wnaf_mul(g: &Group, r: &mut Point, req: &Request<'_>, rng: &mut Random<'_>) -> Result<()> {
    const F: &str = "ossl_ec_wNAF_mul";
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
                .ok_or(Error::new(Reason::UndefinedGenerator, F))?,
        ),
        None => None,
    };
    // The group's table, when it was made for this generator.
    let mut pre: Option<(&PreComp, usize)> = None;
    if let (Some(gen_pt), Some(s)) = (generator, req.scalar)
        && let Some(pc) = g.pre_comp.as_deref()
        && pc.numblocks > 0
        && pc
            .points
            .first()
            .is_some_and(|p0| point::equal(g, gen_pt, p0).unwrap_or(false))
    {
        let per_block = 1usize << pc.w.saturating_sub(1);
        if pc.points.len() != pc.numblocks.saturating_mul(per_block) {
            return Err(Error::new(Reason::InternalError, F));
        }
        let numblocks = s
            .num_bits()
            .checked_div(pc.blocksize)
            .unwrap_or(0)
            .saturating_add(1)
            .min(pc.numblocks);
        pre = Some((pc, numblocks));
    }
    // The terms with tables of their own: the points, then the generator without a table.
    let mut own: Vec<(&Point, &BigNum)> = req.pairs.to_vec();
    if let (Some(base), Some(s), None) = (generator, req.scalar, pre) {
        own.push((base, s));
    }
    let mut entries: Vec<(Vec<i8>, Table)> = Vec::new();
    let mut wsize = Vec::with_capacity(own.len());
    let mut max_len = 0;
    for (_, s) in &own {
        let w = window_bits(s.num_bits());
        let digits = compute_wnaf(s, w)?;
        max_len = max_len.max(digits.len());
        wsize.push(w);
        entries.push((digits, Table::Own(0)));
    }
    if let (Some((pc, numblocks)), Some(s)) = (pre, req.scalar) {
        let digits = compute_wnaf(s, pc.w)?;
        let per_block = 1usize << pc.w.saturating_sub(1);
        if digits.len() <= max_len {
            entries.push((digits, Table::Pre(0)));
        } else {
            let mut numblocks = numblocks;
            if digits.len() < numblocks.saturating_mul(pc.blocksize) {
                numblocks = digits.len().div_ceil(pc.blocksize);
                if numblocks > pc.numblocks {
                    return Err(Error::new(Reason::InternalError, F));
                }
            }
            let mut rest: &[i8] = &digits;
            for i in 0..numblocks {
                let len = if i.saturating_add(1) < numblocks {
                    if rest.len() < pc.blocksize {
                        return Err(Error::new(Reason::InternalError, F));
                    }
                    pc.blocksize
                } else {
                    rest.len()
                };
                let (block, tail) = rest.split_at(len);
                max_len = max_len.max(block.len());
                entries.push((block.to_vec(), Table::Pre(i.saturating_mul(per_block))));
                rest = tail;
            }
        }
    }
    // The odd multiples of each term with its own table: P, 3P, 5P, ...
    let mut val: Vec<Point> = Vec::new();
    for ((i, (p, _)), w) in own.iter().enumerate().zip(&wsize) {
        if let Some(e) = entries.get_mut(i) {
            e.1 = Table::Own(val.len());
        }
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
    let table = |t: Table, digit: usize| -> Option<&Point> {
        match t {
            Table::Own(start) => val.get(start.saturating_add(digit >> 1)),
            Table::Pre(start) => {
                pre.and_then(|(pc, _)| pc.points.get(start.saturating_add(digit >> 1)))
            }
        }
    };
    // The sum is made apart from `r`, which it replaces only at the end, as OpenSSL's.
    let out = r;
    let mut acc = Point::infinity();
    let r = &mut acc;
    let mut at_infinity = true;
    let mut inverted = false;
    for k in (0..max_len).rev() {
        if !at_infinity {
            let rr = r.clone();
            point::dbl(g, r, &rr, rng)?;
        }
        for (digits, t) in &entries {
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
            let v = table(*t, digit).ok_or(Error::new(Reason::InternalError, F))?;
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
    *out = acc;
    Ok(())
}
