//! Groups (`EC_GROUP`): a curve `y^2 = x^3 + ax + b` over GF(p), or `y^2 + xy = x^3 + ax^2 + b`
//! over GF(2^m), with an optional generator, its order, and the cofactor; and the method
//! (`EC_METHOD`) that says how OpenSSL computes in it. The method decides only what can be seen
//! of a computation: which curves a group accepts, how a field element is inverted (with a
//! random blinding factor or by Fermat's little theorem), and which scalar multiplication runs,
//! so which random numbers are drawn and what Jacobian coordinates result.

use super::curves::{self, Field};
use super::point::Point;
use super::{Error, Random, Reason, Result};
use crate::bn::{self, BigNum, gf2m, modular};

/// A method (`EC_METHOD`): the generic ones, and the default build's curve-specific ones.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Meth {
    /// `EC_GFp_simple_method`.
    Simple,
    /// `EC_GFp_mont_method`, the generic prime-field method of named curves.
    Mont,
    /// `EC_GFp_nist_method`.
    Nist,
    /// `EC_GFp_nistp224_method`.
    Nistp224,
    /// `EC_GFp_nistp256_method`.
    Nistp256,
    /// `ossl_ec_GFp_nistp384_method`.
    Nistp384,
    /// `EC_GFp_nistp521_method`.
    Nistp521,
    /// `EC_GFp_nistz256_method`.
    Nistz256,
    /// `EC_GFp_sm2p256_method`.
    Sm2p256,
    /// `EC_GF2m_simple_method`.
    Gf2m,
}

/// How a method inverts a field element.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Inverse {
    /// `ossl_ec_GFp_simple_field_inv`: times a random nonzero element, inverted, and times it
    /// again.
    Blinded,
    /// `ossl_ec_GFp_mont_field_inv`: `a^(p-2)`.
    Fermat,
    /// `BN_GF2m_mod_inv`: blinded by random bits.
    Binary,
}

impl Meth {
    /// The field type (`EC_METHOD_get_field_type`).
    #[must_use]
    pub fn field(self) -> Field {
        match self {
            Self::Gf2m => Field::Binary,
            _ => Field::Prime,
        }
    }

    pub(crate) fn inverse(self) -> Inverse {
        match self {
            Self::Mont | Self::Nistz256 => Inverse::Fermat,
            Self::Gf2m => Inverse::Binary,
            _ => Inverse::Blinded,
        }
    }

    /// Whether the method has its own scalar multiplication (one that draws no random numbers),
    /// rather than OpenSSL's generic wNAF and ladder.
    #[must_use]
    pub fn specialized_mul(self) -> bool {
        matches!(
            self,
            Self::Nistp224
                | Self::Nistp256
                | Self::Nistp384
                | Self::Nistp521
                | Self::Nistz256
                | Self::Sm2p256
        )
    }

    /// The method a named curve's group uses (`ec_group_new_from_data`).
    #[must_use]
    pub fn for_curve(c: &curves::Curve) -> Self {
        match (c.method, c.field) {
            (curves::Method::Nistp224, _) => Self::Nistp224,
            (curves::Method::Nistp256, _) => Self::Nistp256,
            (curves::Method::Nistp384, _) => Self::Nistp384,
            (curves::Method::Nistp521, _) => Self::Nistp521,
            (curves::Method::Nistz256, _) => Self::Nistz256,
            (curves::Method::Sm2p256, _) => Self::Sm2p256,
            (curves::Method::Generic, Field::Prime) => Self::Mont,
            (curves::Method::Generic, Field::Binary) => Self::Gf2m,
        }
    }
}

/// `OPENSSL_EC_NAMED_CURVE`.
pub const NAMED_CURVE: i32 = 1;

/// `POINT_CONVERSION_UNCOMPRESSED`.
pub const UNCOMPRESSED: u8 = 4;

/// A group.
#[derive(Clone, Debug)]
pub struct Group {
    pub meth: Meth,
    /// The prime, or the reduction polynomial.
    pub field: BigNum,
    /// A binary field's polynomial's exponents (`poly`, descending), empty for a prime field.
    pub poly: Vec<usize>,
    pub a: BigNum,
    pub b: BigNum,
    /// Whether `a = p - 3`, which a doubling formula uses.
    pub a_is_minus3: bool,
    pub generator: Option<Point>,
    pub order: BigNum,
    pub cofactor: BigNum,
    /// The curve's NID, or 0.
    pub curve_name: i32,
    pub asn1_flag: i32,
    /// The conversion form points are encoded in (`point_conversion_form_t`).
    pub asn1_form: u8,
    pub seed: Option<Vec<u8>>,
    /// Whether the group came from explicit parameters.
    pub decoded_from_explicit_params: bool,
}

impl Group {
    /// An empty group of `meth` (`EC_GROUP_new`): no curve, generator, order, or name; named
    /// curve encoding, uncompressed points.
    #[must_use]
    pub fn new(meth: Meth) -> Self {
        Self {
            meth,
            field: BigNum::zero(),
            poly: Vec::new(),
            a: BigNum::zero(),
            b: BigNum::zero(),
            a_is_minus3: false,
            generator: None,
            order: BigNum::zero(),
            cofactor: BigNum::zero(),
            curve_name: 0,
            asn1_flag: NAMED_CURVE,
            asn1_form: UNCOMPRESSED,
            seed: None,
            decoded_from_explicit_params: false,
        }
    }

    /// A named curve's group (`ec_group_new_from_data`): its method, curve, name, generator,
    /// order, cofactor, and seed. Its ASN.1 flag stays `NAMED_CURVE`; a curve without an OID
    /// is encoded explicitly, which the caller, who has the object table, decides.
    pub fn from_curve(c: &curves::Curve) -> Result<Self> {
        let num = |v: &[u8]| BigNum::from_bin(v, bn::Endian::Big, false);
        let ec = |e: Error| e.then(Reason::EcLib, "ec_group_new_from_data");
        let mut g = Self::new(Meth::for_curve(c));
        let (p, a, b) = (num(c.p)?, num(c.a)?, num(c.b)?);
        g.set_curve(&p, &a, &b).map_err(ec)?;
        g.curve_name = c.nid;
        let (x, y) = (num(c.x)?, num(c.y)?);
        let mut gen_pt = Point::infinity();
        if !super::point::set_affine(&g, &mut gen_pt, &x, &y).map_err(ec)? {
            return Err(
                Error::new(Reason::PointIsNotOnCurve, "ec_group_new_from_data")
                    .then(Reason::EcLib, "ec_group_new_from_data"),
            );
        }
        let order = num(c.order)?;
        let cofactor = BigNum::from_word(u64::from(c.cofactor));
        g.set_generator(gen_pt, &order, Some(&cofactor))
            .map_err(ec)?;
        if !c.seed.is_empty() {
            g.seed = Some(c.seed.to_vec());
        }
        Ok(g)
    }

    /// Whether the field is a prime field.
    #[must_use]
    pub fn is_prime(&self) -> bool {
        self.meth.field() == Field::Prime
    }

    /// The method's `group_set_curve`: the field and the coefficients, reduced; each method
    /// refuses the curves it can't compute on.
    pub fn set_curve(&mut self, p: &BigNum, a: &BigNum, b: &BigNum) -> Result<()> {
        match self.meth {
            Meth::Gf2m => return self.set_curve_gf2m(p, a, b),
            Meth::Nist => {
                let nist = [192, 224, 256, 384, 521]
                    .into_iter()
                    .filter_map(modular::nist_prime)
                    .any(|q| bn::ucmp(&q, p).is_eq());
                if !nist {
                    return Err(Error::new(
                        Reason::NotANistPrime,
                        "ossl_ec_GFp_nist_group_set_curve",
                    ));
                }
            }
            Meth::Nistp224 | Meth::Nistp256 | Meth::Nistp384 | Meth::Nistp521 => {
                let (nid, func) = match self.meth {
                    Meth::Nistp224 => (
                        curves::nist_nid(b"P-224"),
                        "ossl_ec_GFp_nistp224_group_set_curve",
                    ),
                    Meth::Nistp256 => (
                        curves::nist_nid(b"P-256"),
                        "ossl_ec_GFp_nistp256_group_set_curve",
                    ),
                    Meth::Nistp384 => (
                        curves::nist_nid(b"P-384"),
                        "ossl_ec_GFp_nistp384_group_set_curve",
                    ),
                    _ => (
                        curves::nist_nid(b"P-521"),
                        "ossl_ec_GFp_nistp521_group_set_curve",
                    ),
                };
                let c = nid.and_then(curves::by_nid).ok_or(Error::silent())?;
                let same = |want: &[u8], have: &BigNum| {
                    BigNum::from_bin(want, bn::Endian::Big, false)
                        .is_ok_and(|w| bn::cmp(&w, have).is_eq())
                };
                if !(same(c.p, p) && same(c.a, a) && same(c.b, b)) {
                    return Err(Error::new(Reason::WrongCurveParameters, func));
                }
            }
            Meth::Mont | Meth::Nistz256 => {
                // `BN_MONT_CTX_set` fails quietly on zero, and on an even modulus when
                // inverting it modulo the word size.
                if p.is_zero() {
                    return Err(Error::new(
                        Reason::BnLib,
                        "ossl_ec_GFp_mont_group_set_curve",
                    ));
                }
                if !p.is_odd() {
                    return Err(
                        Error::new(Reason::Bn(bn::Error::NoInverse), "BN_mod_inverse")
                            .then(Reason::BnLib, "ossl_ec_GFp_mont_group_set_curve"),
                    );
                }
            }
            Meth::Simple | Meth::Sm2p256 => {}
        }
        self.set_curve_gfp(p, a, b)
    }

    /// `ossl_ec_GFp_simple_group_set_curve`.
    fn set_curve_gfp(&mut self, p: &BigNum, a: &BigNum, b: &BigNum) -> Result<()> {
        if p.num_bits() <= 2 || !p.is_odd() {
            return Err(Error::new(
                Reason::InvalidField,
                "ossl_ec_GFp_simple_group_set_curve",
            ));
        }
        let field = (p).abs();
        let a = bn::nnmod(a, &field)?;
        let b = bn::nnmod(b, &field)?;
        let a3 = bn::add(&a, &BigNum::from_word(3))?;
        self.a_is_minus3 = bn::cmp(&a3, &field).is_eq();
        self.field = field;
        self.a = a;
        self.b = b;
        Ok(())
    }

    /// `ossl_ec_GF2m_simple_group_set_curve`: a trinomial or pentanomial basis.
    fn set_curve_gf2m(&mut self, p: &BigNum, a: &BigNum, b: &BigNum) -> Result<()> {
        // `BN_GF2m_poly2arr(p, poly, 6) - 1` terms, -1 for an even or too long polynomial.
        let max = usize::try_from(rustyssl_abi::OPENSSL_ECC_MAX_FIELD_BITS).unwrap_or(0);
        let poly = match gf2m::poly2arr(p, max) {
            Some((poly, _)) if poly.len() == 5 || poly.len() == 3 => poly,
            _ => {
                return Err(Error::new(
                    Reason::UnsupportedField,
                    "ossl_ec_GF2m_simple_group_set_curve",
                ));
            }
        };
        self.field = p.clone();
        self.a = gf2m::reduce(a, &poly);
        self.b = gf2m::reduce(b, &poly);
        self.poly = poly;
        Ok(())
    }

    /// `EC_GROUP_get_degree`: the field's size in bits.
    #[must_use]
    pub fn degree(&self) -> usize {
        match self.meth.field() {
            Field::Prime => self.field.num_bits(),
            Field::Binary => self.field.num_bits().saturating_sub(1),
        }
    }

    /// `EC_GROUP_set_generator`'s checks and settings, after the generator is known to be
    /// given: the order (at most a bit longer than the field) and the cofactor, guessed when it
    /// isn't given (zero for a group too small to tell).
    pub fn set_generator(
        &mut self,
        generator: Point,
        order: &BigNum,
        cofactor: Option<&BigNum>,
    ) -> Result<()> {
        if self.field.is_zero() || self.field.is_negative() {
            return Err(Error::new(Reason::InvalidField, "EC_GROUP_set_generator"));
        }
        if order.is_zero()
            || order.is_negative()
            || order.num_bits() > self.field.num_bits().saturating_add(1)
        {
            return Err(Error::new(
                Reason::InvalidGroupOrder,
                "EC_GROUP_set_generator",
            ));
        }
        if cofactor.is_some_and(BigNum::is_negative) {
            return Err(Error::new(
                Reason::UnknownCofactor,
                "EC_GROUP_set_generator",
            ));
        }
        self.generator = Some(generator);
        self.order = order.clone();
        match cofactor.filter(|c| !c.is_zero()) {
            Some(c) => self.cofactor = c.clone(),
            None => self.cofactor = self.guess_cofactor()?,
        }
        Ok(())
    }

    /// `ec_guess_cofactor`: `(q + n/2 + 1) / n` by Hasse's bound, when the order is long
    /// enough for that to be exact; else zero.
    fn guess_cofactor(&self) -> Result<BigNum> {
        let half = self.field.num_bits().saturating_add(1) / 2;
        if self.order.num_bits() <= half.saturating_add(3) {
            return Ok(BigNum::zero());
        }
        let q = match self.meth.field() {
            Field::Binary => {
                let mut q = BigNum::zero();
                q.set_bit(self.field.num_bits().saturating_sub(1))?;
                q
            }
            Field::Prime => self.field.clone(),
        };
        let c = bn::add(&bn::rshift1(&self.order), &q)?;
        let c = bn::add(&c, &BigNum::one())?;
        Ok(bn::div_rem(&c, &self.order)?.0)
    }

    /// `check_discriminant`: whether the curve isn't singular (`4a^3 + 27b^2 != 0`, or for a
    /// binary curve `b != 0`).
    pub fn check_discriminant(&self) -> Result<bool> {
        match self.meth.field() {
            Field::Binary => Ok(!gf2m::reduce(&self.b, &self.poly).is_zero()),
            Field::Prime => {
                let p = &self.field;
                let (a, b) = (&self.a, &self.b);
                if a.is_zero() {
                    return Ok(!b.is_zero());
                }
                if b.is_zero() {
                    return Ok(true);
                }
                let t = modular::mod_mul(&modular::mod_sqr(a, p)?, a, p)?;
                let t1 = bn::lshift(&t, 2)?;
                let mut t2 = modular::mod_sqr(b, p)?;
                t2.mul_word(27)?;
                let s = bn::nnmod(&bn::add(&t1, &t2)?, p)?;
                Ok(!s.is_zero())
            }
        }
    }

    /// The field multiplication.
    pub fn field_mul(&self, a: &BigNum, b: &BigNum) -> Result<BigNum> {
        Ok(match self.meth.field() {
            Field::Prime => modular::mod_mul(a, b, &self.field)?,
            Field::Binary => gf2m::mul(a, b, &self.poly),
        })
    }

    /// The field squaring.
    pub fn field_sqr(&self, a: &BigNum) -> Result<BigNum> {
        Ok(match self.meth.field() {
            Field::Prime => modular::mod_sqr(a, &self.field)?,
            Field::Binary => gf2m::sqr(a, &self.poly),
        })
    }

    /// The method's `field_inv`, drawing what OpenSSL's draws.
    pub fn field_inv(&self, a: &BigNum, rng: &mut Random<'_>) -> Result<BigNum> {
        let p = &self.field;
        match self.meth.inverse() {
            Inverse::Fermat => {
                let e = bn::sub(p, &BigNum::from_word(2))?;
                let r = modular::exp_mod(a, &e, p)?;
                if r.is_zero() {
                    return Err(Error::new(
                        Reason::CannotInvert,
                        "ossl_ec_GFp_mont_field_inv",
                    ));
                }
                Ok(r)
            }
            Inverse::Blinded => {
                let e = loop {
                    let e = bn::rand::rand_range(p, rng).ok_or(Error::silent())?;
                    if !e.is_zero() {
                        break e;
                    }
                };
                let r = self.field_mul(a, &e)?;
                let r = bn::ct::inverse(&r, p).ok_or(Error::new(
                    Reason::CannotInvert,
                    "ossl_ec_GFp_simple_field_inv",
                ))?;
                self.field_mul(&r, &e)
            }
            Inverse::Binary => gf2m_inverse(a, p, &self.poly, rng)
                .ok_or(Error::new(Reason::CannotInvert, "ec_GF2m_simple_field_inv")),
        }
    }

    /// The binary field's division `a / b` (`BN_GF2m_mod_div`, which inverts as
    /// `BN_GF2m_mod_inv` does).
    pub fn field_div(&self, a: &BigNum, b: &BigNum, rng: &mut Random<'_>) -> Result<BigNum> {
        let inv = gf2m_inverse(b, &self.field, &self.poly, rng).ok_or(Error::silent())?;
        Ok(gf2m::mul(a, &inv, &self.poly))
    }
}

/// `BN_GF2m_mod_inv`: `a` times random nonzero bits below the degree, inverted, times them
/// again.
pub(crate) fn gf2m_inverse(
    a: &BigNum,
    p: &BigNum,
    poly: &[usize],
    rng: &mut Random<'_>,
) -> Option<BigNum> {
    let numbits = p.num_bits();
    if numbits <= 1 {
        return None;
    }
    let b = loop {
        let b = bn::rand::rand_bits(numbits.saturating_sub(1), rng)?;
        if !b.is_zero() {
            break b;
        }
    };
    let r = gf2m::mul(a, &b, poly);
    let r = gf2m::inverse(&r, p, poly)?;
    Some(gf2m::mul(&r, &b, poly))
}
