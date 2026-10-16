//! X448 and Ed448 (RFC 7748, RFC 8032) on Curve448, with OpenSSL's rules (its `curve448`
//! directory): X448's clamp and an all-zero result refused; Ed448 and Ed448ph signatures, whose
//! points decode only with `y < p`, the encoding's spare bits zero, and `x != 0`, and whose
//! verification is cofactored (`4 (S B - k A - R)` is the identity), as OpenSSL's decaf-based
//! equality makes it.
//!
//! The field and the scalars are [`Fp`]'s constant-time Montgomery arithmetic. Points are
//! projective `(X : Y : Z)` on `x^2 + y^2 = 1 + d x^2 y^2` with RFC 8032's complete formulas;
//! a secret scalar multiplies by doubling and adding at every bit and selecting in constant
//! time, X448 by the Montgomery ladder.

use std::sync::LazyLock;

use zeroize::Zeroizing;

use crate::bn::{self, BigNum};
use crate::ec::fe::{Fe, Fp};
use crate::md::{self, Algorithm};

/// X448's keys' length.
pub const X448_KEYLEN: usize = 56;
/// Ed448's keys' length.
pub const ED448_KEYLEN: usize = 57;
/// Ed448's signatures' length.
pub const ED448_SIGSIZE: usize = 114;
/// Ed448ph's prehash's length.
pub const ED448_PREHASH_LEN: usize = 64;

/// The group's order `L`, little-endian, as OpenSSL compares `S` with it.
const ORDER: [u8; ED448_KEYLEN] = [
    0xF3, 0x44, 0x58, 0xAB, 0x92, 0xC2, 0x78, 0x23, 0x55, 0x8F, 0xC5, 0x8D, 0x72, 0xC2, 0x6C, 0x21,
    0x90, 0x36, 0xD6, 0xAE, 0x49, 0xDB, 0x4E, 0xC4, 0xE9, 0x23, 0xCA, 0x7C, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F, 0x00,
];

/// RFC 8032's base point's encoding.
const BASE: &str = "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900";

/// A point `(X : Y : Z)`.
#[derive(Clone)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
}

/// The curve's constants.
struct Curve {
    /// `GF(p)`, `p = 2^448 - 2^224 - 1`.
    f: Fp,
    /// The scalars, mod `L`.
    l: Fp,
    /// `d = -39081`.
    d: Fe,
    /// X448's `a24 = 39081`.
    a24: Fe,
    /// `(p - 3) / 4`, the inverse square root's exponent.
    isr: BigNum,
    /// `2^448` and `2^896` mod `L`, for reducing 114 octets.
    r1: Fe,
    r2: Fe,
    base: Point,
}

static CURVE: LazyLock<Option<Curve>> = LazyLock::new(Curve::new);

/// Octets from hex digits (constants only).
fn hex(h: &str) -> Option<Vec<u8>> {
    let b = h.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    b.chunks(2)
        .map(|c| u8::from_str_radix(core::str::from_utf8(c).ok()?, 16).ok())
        .collect()
}

impl Curve {
    fn new() -> Option<Self> {
        let p = bn::sub(
            &bn::sub(
                &bn::lshift(&BigNum::one(), 448).ok()?,
                &bn::lshift(&BigNum::one(), 224).ok()?,
            )
            .ok()?,
            &BigNum::one(),
        )
        .ok()?;
        let l = bn::sub(
            &bn::lshift(&BigNum::one(), 446).ok()?,
            &BigNum::from_dec_digits(
                b"13818066809895115352007386748515426880336692474882178609894547503885",
            )
            .ok()?,
        )
        .ok()?;
        let f = Fp::new(&p)?;
        let lf = Fp::new(&l)?;
        let a24 = f.from_bn(&BigNum::from_word(39081))?;
        let d = f.neg(&a24);
        let isr = bn::rshift(&bn::sub(&p, &BigNum::from_word(3)).ok()?, 2);
        let r1 = lf.from_bn(&bn::nnmod(&bn::lshift(&BigNum::one(), 448).ok()?, &l).ok()?)?;
        let r2 = lf.from_bn(&bn::nnmod(&bn::lshift(&BigNum::one(), 896).ok()?, &l).ok()?)?;
        let f0 = f.zero();
        let mut c = Self {
            f,
            l: lf,
            d,
            a24,
            isr,
            r1,
            r2,
            base: Point {
                x: f0.clone(),
                y: f0.clone(),
                z: f0,
            },
        };
        let enc = <[u8; ED448_KEYLEN]>::try_from(hex(BASE)?).ok()?;
        c.base = c.decode(&enc)?;
        Some(c)
    }

    fn identity(&self) -> Point {
        Point {
            x: self.f.zero(),
            y: self.f.one(),
            z: self.f.one(),
        }
    }

    /// `p + q`, by RFC 8032's complete formulas.
    fn add(&self, p: &Point, q: &Point) -> Point {
        let f = &self.f;
        let a = f.mul(&p.z, &q.z);
        let b = f.sqr(&a);
        let c = f.mul(&p.x, &q.x);
        let d = f.mul(&p.y, &q.y);
        let e = f.mul(&self.d, &f.mul(&c, &d));
        let ff = f.sub(&b, &e);
        let g = f.add(&b, &e);
        let h = f.mul(&f.add(&p.x, &p.y), &f.add(&q.x, &q.y));
        Point {
            x: f.mul(&f.mul(&a, &ff), &f.sub(&f.sub(&h, &c), &d)),
            y: f.mul(&f.mul(&a, &g), &f.sub(&d, &c)),
            z: f.mul(&ff, &g),
        }
    }

    /// `2p`.
    fn dbl(&self, p: &Point) -> Point {
        let f = &self.f;
        let b = f.sqr(&f.add(&p.x, &p.y));
        let c = f.sqr(&p.x);
        let d = f.sqr(&p.y);
        let e = f.add(&c, &d);
        let h = f.sqr(&p.z);
        let j = f.sub(&e, &f.dbl(&h));
        Point {
            x: f.mul(&f.sub(&b, &e), &j),
            y: f.mul(&e, &f.sub(&c, &d)),
            z: f.mul(&e, &j),
        }
    }

    fn neg(&self, p: &Point) -> Point {
        Point {
            x: self.f.neg(&p.x),
            y: p.y.clone(),
            z: p.z.clone(),
        }
    }

    /// `k p` for the little-endian scalar `k`, adding at every bit and selecting in constant
    /// time.
    fn mul(&self, k: &[u8], p: &Point) -> Point {
        let mut q = self.identity();
        for byte in k.iter().rev() {
            for i in (0..8).rev() {
                q = self.dbl(&q);
                let mut t = self.add(&q, p);
                let bit = (byte >> i) & 1 == 1;
                Fp::cswap(bit, &mut q.x, &mut t.x);
                Fp::cswap(bit, &mut q.y, &mut t.y);
                Fp::cswap(bit, &mut q.z, &mut t.z);
            }
        }
        q
    }

    /// Whether `p` is the identity.
    fn is_identity(&self, p: &Point) -> bool {
        self.f.is_zero(&p.x) & self.f.eq(&p.y, &p.z)
    }

    /// RFC 8032's encoding: `y` and the sign of `x`.
    fn encode(&self, p: &Point) -> [u8; ED448_KEYLEN] {
        let f = &self.f;
        let zi = f.inv(&p.z);
        let x = f.mul(&p.x, &zi);
        let y = f.mul(&p.y, &zi);
        let mut out = [0u8; ED448_KEYLEN];
        for (o, b) in out.iter_mut().zip(f.to_le_bytes(&y, X448_KEYLEN)) {
            *o = b;
        }
        if let Some(last) = out.last_mut() {
            *last = u8::from(f.is_odd(&x)) << 7;
        }
        out
    }

    /// `ossl_curve448_point_decode_like_eddsa_and_mul_by_ratio`'s checks: `y < p`, the last
    /// octet's other bits zero, and `x^2 = (1 - y^2) / (1 - d y^2)` nonzero (public input).
    fn decode(&self, enc: &[u8; ED448_KEYLEN]) -> Option<Point> {
        let f = &self.f;
        let (ybytes, last) = enc.split_at(X448_KEYLEN);
        let last = *last.first()?;
        if last & 0x7f != 0 {
            return None;
        }
        let y = f.from_le_bytes(ybytes)?;
        if f.to_le_bytes(&y, X448_KEYLEN) != ybytes {
            return None;
        }
        let y2 = f.sqr(&y);
        let num = f.sub(&f.one(), &y2);
        let den = f.sub(&f.one(), &f.mul(&self.d, &y2));
        let nd = f.mul(&num, &den);
        let r = f.pow(&nd, &self.isr);
        if !f.eq(&f.mul(&f.sqr(&r), &nd), &f.one()) {
            return None;
        }
        let mut x = f.mul(&r, &num);
        if f.is_odd(&x) != (last & 0x80 != 0) {
            x = f.neg(&x);
        }
        Some(Point { x, y, z: f.one() })
    }

    /// A scalar of up to 114 little-endian octets, reduced mod `L`
    /// (`ossl_curve448_scalar_decode_long`).
    fn scalar(&self, b: &[u8]) -> Option<Fe> {
        let l = &self.l;
        let mut acc = l.zero();
        for (i, chunk) in b.chunks(X448_KEYLEN).enumerate() {
            let v = l.from_le_bytes(chunk)?;
            let v = match i {
                0 => v,
                1 => l.mul(&v, &self.r1),
                2 => l.mul(&v, &self.r2),
                _ => return None,
            };
            acc = l.add(&acc, &v);
        }
        Some(acc)
    }

    /// A scalar's 57 little-endian octets.
    fn scalar_bytes(&self, s: &Fe) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.l.to_le_bytes(s, ED448_KEYLEN))
    }
}

/// SHAKE256 of the parts, `len` octets.
fn shake256(parts: &[&[u8]], len: usize) -> Option<Zeroizing<Vec<u8>>> {
    let mut ctx = md::context(Algorithm::Shake256);
    for p in parts {
        ctx.update(p).ok()?;
    }
    let mut out = Zeroizing::new(vec![0u8; len]);
    ctx.finalize(out.as_mut_slice()).ok()?;
    Some(out)
}

/// Ed448ph's prehash: SHAKE256 of the message, 64 octets.
pub fn ed448_prehash(msg: &[u8]) -> Option<[u8; ED448_PREHASH_LEN]> {
    let h = shake256(&[msg], ED448_PREHASH_LEN)?;
    <[u8; ED448_PREHASH_LEN]>::try_from(h.as_slice()).ok()
}

/// `ossl_x448`: X448 of a scalar (clamped here) and a peer's `u` (reduced mod `p`), or `None`
/// for an all-zero result (from a low-order peer).
pub fn x448(
    scalar: &[u8; X448_KEYLEN],
    u: &[u8; X448_KEYLEN],
) -> Option<Zeroizing<[u8; X448_KEYLEN]>> {
    let c = CURVE.as_ref()?;
    let f = &c.f;
    let mut k = Zeroizing::new(*scalar);
    if let [first, .., last] = k.as_mut_slice() {
        *first &= 252;
        *last |= 128;
    }
    let x1 = f.from_le_bytes(u)?;
    let (mut x2, mut z2, mut x3, mut z3) = (f.one(), f.zero(), x1.clone(), f.one());
    let mut swap = false;
    for byte in k.iter().rev() {
        for i in (0..8).rev() {
            let bit = (byte >> i) & 1 == 1;
            swap ^= bit;
            Fp::cswap(swap, &mut x2, &mut x3);
            Fp::cswap(swap, &mut z2, &mut z3);
            swap = bit;
            let a = f.add(&x2, &z2);
            let aa = f.sqr(&a);
            let b = f.sub(&x2, &z2);
            let bb = f.sqr(&b);
            let e = f.sub(&aa, &bb);
            let cc = f.add(&x3, &z3);
            let d = f.sub(&x3, &z3);
            let da = f.mul(&d, &a);
            let cb = f.mul(&cc, &b);
            x3 = f.sqr(&f.add(&da, &cb));
            z3 = f.mul(&x1, &f.sqr(&f.sub(&da, &cb)));
            x2 = f.mul(&aa, &bb);
            z2 = f.mul(&e, &f.add(&aa, &f.mul(&c.a24, &e)));
        }
    }
    Fp::cswap(swap, &mut x2, &mut x3);
    Fp::cswap(swap, &mut z2, &mut z3);
    let r = f.mul(&x2, &f.inv(&z2));
    let mut out = Zeroizing::new([0u8; X448_KEYLEN]);
    for (o, b) in out.iter_mut().zip(f.to_le_bytes(&r, X448_KEYLEN)) {
        *o = b;
    }
    if f.is_zero(&r) {
        return None;
    }
    Some(out)
}

/// `ossl_x448_public_from_private`: X448 of the private key and the base point 5.
pub fn x448_public_from_private(private: &[u8; X448_KEYLEN]) -> Option<[u8; X448_KEYLEN]> {
    let mut five = [0u8; X448_KEYLEN];
    if let Some(first) = five.first_mut() {
        *first = 5;
    }
    x448(private, &five).map(|p| *p)
}

/// Secret octets, wiped when dropped.
type Secret = Zeroizing<Vec<u8>>;

/// The secret scalar's octets (SHAKE256's first 57, clamped) and the nonce prefix of a
/// private key.
fn expand(private: &[u8; ED448_KEYLEN]) -> Option<(Secret, Secret)> {
    let h = shake256(&[private], ED448_SIGSIZE)?;
    let (s, prefix) = h.split_at(ED448_KEYLEN);
    let mut s = Zeroizing::new(s.to_vec());
    if let Some(first) = s.first_mut() {
        *first &= 0xfc;
    }
    if let [.., second_last, last] = s.as_mut_slice() {
        *last = 0;
        *second_last |= 0x80;
    }
    Some((s, Zeroizing::new(prefix.to_vec())))
}

/// `ossl_ed448_public_from_private`.
pub fn ed448_public_from_private(private: &[u8; ED448_KEYLEN]) -> Option<[u8; ED448_KEYLEN]> {
    let c = CURVE.as_ref()?;
    let (s, _) = expand(private)?;
    Some(c.encode(&c.mul(&s, &c.base)))
}

/// `dom4(phflag, context)`, or `None` for a context over 255 octets.
fn dom4(ph: bool, context: &[u8]) -> Option<Vec<u8>> {
    let mut v = b"SigEd448".to_vec();
    v.push(u8::from(ph));
    v.push(u8::try_from(context.len()).ok()?);
    v.extend_from_slice(context);
    Some(v)
}

/// `ossl_ed448_sign`: the signature of `msg` (Ed448ph's prehash when `ph`) with the private
/// key and the public key given (OpenSSL doesn't check they match), or `None` for a context
/// over 255 octets.
pub fn ed448_sign(
    msg: &[u8],
    public: &[u8; ED448_KEYLEN],
    private: &[u8; ED448_KEYLEN],
    ph: bool,
    context: &[u8],
) -> Option<[u8; ED448_SIGSIZE]> {
    let c = CURVE.as_ref()?;
    let dom = dom4(ph, context)?;
    let (s, prefix) = expand(private)?;
    let s = c.scalar(&s)?;
    let r = c.scalar(&shake256(&[&dom, &prefix, msg], ED448_SIGSIZE)?)?;
    let big_r = c.encode(&c.mul(&c.scalar_bytes(&r), &c.base));
    let k = c.scalar(&shake256(&[&dom, &big_r, public, msg], ED448_SIGSIZE)?)?;
    let big_s = c.l.add(&c.l.mul(&k, &s), &r);
    let mut sig = [0u8; ED448_SIGSIZE];
    let (sr, ss) = sig.split_at_mut(ED448_KEYLEN);
    sr.copy_from_slice(&big_r);
    ss.copy_from_slice(&c.scalar_bytes(&big_s));
    Some(sig)
}

/// `ossl_ed448_verify`: whether `sig` signs `msg` for the public key: `S < L`, both points
/// decode, and `4 (S B - k A - R)` is the identity.
pub fn ed448_verify(
    msg: &[u8],
    sig: &[u8; ED448_SIGSIZE],
    public: &[u8; ED448_KEYLEN],
    ph: bool,
    context: &[u8],
) -> bool {
    let Some(c) = CURVE.as_ref() else {
        return false;
    };
    let Some(dom) = dom4(ph, context) else {
        return false;
    };
    let (r_enc, s_enc) = sig.split_at(ED448_KEYLEN);
    // S < L, compared from the top as OpenSSL compares it (public, so in variable time).
    let mut below = false;
    for (&a, &b) in s_enc.iter().rev().zip(ORDER.iter().rev()) {
        if a != b {
            below = a < b;
            break;
        }
    }
    if !below {
        return false;
    }
    let Some(a) = c.decode(public) else {
        return false;
    };
    let Ok(r_arr) = <[u8; ED448_KEYLEN]>::try_from(r_enc) else {
        return false;
    };
    let Some(r) = c.decode(&r_arr) else {
        return false;
    };
    let Some(h) = shake256(&[&dom, r_enc, public, msg], ED448_SIGSIZE) else {
        return false;
    };
    let Some(k) = c.scalar(&h) else { return false };
    let sb = c.mul(s_enc, &c.base);
    let ka = c.mul(&c.scalar_bytes(&k), &a);
    let p = c.add(&c.add(&sb, &c.neg(&ka)), &c.neg(&r));
    c.is_identity(&c.dbl(&c.dbl(&p)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h<const N: usize>(s: &str) -> [u8; N] {
        <[u8; N]>::try_from(hex(s).unwrap_or_default()).unwrap_or([0; N])
    }

    /// RFC 7748 5.2 and 6.2.
    #[test]
    fn x448_vectors() {
        let out = x448(
            &h(
                "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
            ),
            &h(
                "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
            ),
        );
        assert_eq!(
            out.map(|o| *o),
            Some(h(
                "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f"
            ))
        );
        let a = h(
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
        );
        let b = h(
            "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
        );
        let ap = x448_public_from_private(&a);
        let bp = x448_public_from_private(&b);
        assert_eq!(
            ap,
            Some(h(
                "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"
            ))
        );
        assert_eq!(
            bp,
            Some(h(
                "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"
            ))
        );
        let shared = h(
            "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d",
        );
        assert_eq!(x448(&a, &bp.unwrap_or([0; 56])).map(|o| *o), Some(shared));
        assert_eq!(x448(&b, &ap.unwrap_or([0; 56])).map(|o| *o), Some(shared));
        // A low-order peer gives zeros, refused.
        assert!(x448(&a, &[0; 56]).is_none());
    }

    /// RFC 8032 7.4 and 7.5.
    #[test]
    fn ed448_vectors() {
        let cases: [(&str, &str, &str, &str, bool, &str); 4] = [
            (
                "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b",
                "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
                "",
                "",
                false,
                "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600",
            ),
            (
                "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e",
                "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
                "03",
                "",
                false,
                "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00",
            ),
            (
                "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e",
                "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
                "03",
                "666f6f",
                false,
                "d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85741de5c8da1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d5428407e85dcbc98a49155c13764e66c3c00",
            ),
            (
                "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49",
                "259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880",
                "616263",
                "",
                true,
                "822f6901f7480f3d5f562c592994d9693602875614483256505600bbc281ae381f54d6bce2ea911574932f52a4e6cadd78769375ec3ffd1b801a0d9b3f4030cd433964b6457ea39476511214f97469b57dd32dbc560a9a94d00bff07620464a3ad203df7dc7ce360c3cd3696d9d9fab90f00",
            ),
        ];
        for (sk, pk, msg, ctx, ph, sig) in cases {
            let sk: [u8; 57] = h(sk);
            let pk: [u8; 57] = h(pk);
            let sig: [u8; 114] = h(sig);
            let msg = hex(msg).unwrap_or_default();
            let ctx = hex(ctx).unwrap_or_default();
            assert_eq!(ed448_public_from_private(&sk), Some(pk));
            let m = if ph {
                ed448_prehash(&msg).map(|p| p.to_vec()).unwrap_or_default()
            } else {
                msg.clone()
            };
            assert_eq!(ed448_sign(&m, &pk, &sk, ph, &ctx), Some(sig));
            assert!(ed448_verify(&m, &sig, &pk, ph, &ctx));
            let mut bad = sig;
            bad[0] ^= 1;
            assert!(!ed448_verify(&m, &bad, &pk, ph, &ctx));
            assert!(!ed448_verify(&m, &sig, &pk, !ph, &ctx));
        }
    }
}

#[cfg(test)]
mod torsion {
    use super::*;

    /// Verification is cofactored, as OpenSSL's (checked against the reference): a signature
    /// whose R, or whose public key, has an order-4 or order-2 point added still verifies.
    #[test]
    fn verification_is_cofactored() {
        let c = CURVE.as_ref().unwrap();
        let sk: [u8; 57] = [7; 57];
        let (s_bytes, _) = expand(&sk).unwrap();
        let s = c.scalar(&s_bytes).unwrap();
        let a = c.mul(&s_bytes, &c.base);
        let msg = b"torsion";
        let dom = dom4(false, b"").unwrap();
        let t4 = Point {
            x: c.f.one(),
            y: c.f.zero(),
            z: c.f.one(),
        };
        let t2 = Point {
            x: c.f.zero(),
            y: c.f.neg(&c.f.one()),
            z: c.f.one(),
        };
        let r = c.scalar(&[3u8; 114]).unwrap();
        let rb = c.mul(&c.scalar_bytes(&r), &c.base);
        for (tr, ta) in [
            (None, None),
            (Some(&t4), None),
            (Some(&t2), None),
            (None, Some(&t4)),
            (None, Some(&t2)),
        ] {
            let big_r = tr.map_or(rb.clone(), |t| c.add(&rb, t));
            let big_a = ta.map_or(a.clone(), |t| c.add(&a, t));
            let r_enc = c.encode(&big_r);
            let a_enc = c.encode(&big_a);
            let k = c
                .scalar(&shake256(&[&dom, &r_enc, &a_enc, msg], 114).unwrap())
                .unwrap();
            let big_s = c.l.add(&c.l.mul(&k, &s), &r);
            let mut sig = r_enc.to_vec();
            sig.extend_from_slice(&c.scalar_bytes(&big_s));
            let sig = <[u8; 114]>::try_from(sig.as_slice()).unwrap();
            assert!(ed448_verify(msg, &sig, &a_enc, false, b""));
        }
        // The identity and the order-2 point (x = 0) don't decode.
        let mut id = [0u8; 57];
        id[0] = 1;
        assert!(c.decode(&id).is_none());
        id[56] = 0x80;
        assert!(c.decode(&id).is_none());
    }
}
