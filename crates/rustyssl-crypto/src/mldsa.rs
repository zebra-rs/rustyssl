//! ML-DSA-44, ML-DSA-65, and ML-DSA-87 (FIPS 204), with OpenSSL's rules (its `ml_dsa`
//! directory): keys from a 32-octet seed, the public and private keys' encodings (the private
//! key's `s1` and `s2` checked within `eta`, and its `t0` and `tr` checked against the public key
//! they make), and signing and verifying of a message representative `mu` (made from the
//! public key's hash and the message, encoded or raw, or given).
//!
//! Polynomials are 256 coefficients mod `q = 8380417`, multiplied with Montgomery reduction;
//! additions, subtractions, rounding (`Power2Round`, `Decompose`), hints, and norms use masks,
//! so the arithmetic on secrets doesn't branch or divide. As in OpenSSL (and FIPS 204 3.6.3),
//! rejection sampling isn't constant-time: the private vectors' sampling discards candidate
//! nibbles, and signing retries until its checks pass, which reveals only that a candidate was
//! discarded.

use std::sync::LazyLock;

use zeroize::{Zeroize, Zeroizing};

use crate::md::{self, Algorithm};

/// The polynomials' degree.
const N: usize = 256;
/// The modulus `q`.
const Q: u32 = 8_380_417;
/// `-q^-1 mod 2^32`.
const Q_NEG_INV: u32 = 4_236_238_847;
/// `(q - 1) / 2`.
const HALF_Q: u32 = 4_190_208;
/// The bits `Power2Round` drops.
const D: u32 = 13;
/// `256^-1 mod q`.
const INVERSE_256: u32 = 8_347_681;

/// The seed's length.
pub const SEED_BYTES: usize = 32;
/// `mu`'s length.
pub const MU_BYTES: usize = 64;
/// The signing randomness' length.
pub const RANDOM_BYTES: usize = 32;
/// The longest context string.
pub const MAX_CONTEXT: usize = 255;

type Poly = [u32; N];

/// Why a key or signature couldn't be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The encoding's length isn't the variant's.
    Length,
    /// A private `s1` or `s2` coefficient is outside `-eta..=eta`.
    Range,
    /// The private key's `t0` or `tr` doesn't match the public key it makes.
    Mismatch,
    /// A hash failed.
    Internal,
}

/// An ML-DSA parameter set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl Variant {
    /// Its name (`ML-DSA-65`, ...).
    pub const fn name(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
        }
    }

    /// The matrix's rows `k`.
    const fn k(self) -> usize {
        match self {
            Self::MlDsa44 => 4,
            Self::MlDsa65 => 6,
            Self::MlDsa87 => 8,
        }
    }

    /// The matrix's columns `l`.
    const fn l(self) -> usize {
        match self {
            Self::MlDsa44 => 4,
            Self::MlDsa65 => 5,
            Self::MlDsa87 => 7,
        }
    }

    /// `eta`.
    const fn eta(self) -> u32 {
        match self {
            Self::MlDsa44 | Self::MlDsa87 => 2,
            Self::MlDsa65 => 4,
        }
    }

    /// `tau`.
    const fn tau(self) -> usize {
        match self {
            Self::MlDsa44 => 39,
            Self::MlDsa65 => 49,
            Self::MlDsa87 => 60,
        }
    }

    /// The collision strength `lambda` in bits.
    pub const fn lambda(self) -> u32 {
        match self {
            Self::MlDsa44 => 128,
            Self::MlDsa65 => 192,
            Self::MlDsa87 => 256,
        }
    }

    /// `c~`'s length, `lambda / 4`.
    const fn c_tilde_bytes(self) -> usize {
        match self {
            Self::MlDsa44 => 32,
            Self::MlDsa65 => 48,
            Self::MlDsa87 => 64,
        }
    }

    /// `log2(gamma1)`.
    const fn gamma1_bits(self) -> u32 {
        match self {
            Self::MlDsa44 => 17,
            Self::MlDsa65 | Self::MlDsa87 => 19,
        }
    }

    /// `gamma1`.
    const fn gamma1(self) -> u32 {
        match self {
            Self::MlDsa44 => 1 << 17,
            Self::MlDsa65 | Self::MlDsa87 => 1 << 19,
        }
    }

    /// `gamma2`.
    const fn gamma2(self) -> u32 {
        match self {
            Self::MlDsa44 => (Q - 1) / 88,
            Self::MlDsa65 | Self::MlDsa87 => (Q - 1) / 32,
        }
    }

    /// `beta = tau eta`.
    const fn beta(self) -> u32 {
        match self {
            Self::MlDsa44 => 78,
            Self::MlDsa65 => 196,
            Self::MlDsa87 => 120,
        }
    }

    /// `omega`.
    const fn omega(self) -> usize {
        match self {
            Self::MlDsa44 => 80,
            Self::MlDsa65 => 55,
            Self::MlDsa87 => 75,
        }
    }

    /// Its NIST security category.
    pub const fn security_category(self) -> u32 {
        match self {
            Self::MlDsa44 => 2,
            Self::MlDsa65 => 3,
            Self::MlDsa87 => 5,
        }
    }

    /// The public key's length.
    pub const fn public_key_bytes(self) -> usize {
        match self {
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }

    /// The private key's length.
    pub const fn private_key_bytes(self) -> usize {
        match self {
            Self::MlDsa44 => 2560,
            Self::MlDsa65 => 4032,
            Self::MlDsa87 => 4896,
        }
    }

    /// The signature's length.
    pub const fn signature_bytes(self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }

    /// The bits of an `s1` or `s2` coefficient's encoding.
    const fn eta_bits(self) -> u32 {
        match self {
            Self::MlDsa44 | Self::MlDsa87 => 3,
            Self::MlDsa65 => 4,
        }
    }

    /// The bits of a `w1` coefficient's encoding.
    const fn w1_bits(self) -> u32 {
        match self {
            Self::MlDsa44 => 6,
            Self::MlDsa65 | Self::MlDsa87 => 4,
        }
    }
}

/// The NTT's constants: `17^BitRev8(i)`'s analogue for ML-DSA, `1753^BitRev8(i)`, in Montgomery
/// form, and `2^64 mod q` (for leaving Montgomery form).
struct Tables {
    zetas: [u32; N],
    r2: u32,
}

static TABLES: LazyLock<Tables> = LazyLock::new(|| {
    let r = (1u64 << 32) % u64::from(Q);
    let r2 = u32::try_from(r.wrapping_mul(r) % u64::from(Q)).unwrap_or(0);
    let plain = |x: u64, y: u64| x.wrapping_mul(y) % u64::from(Q);
    let pow = |e: u32| (0..e).fold(1u64, |acc, _| plain(acc, 1753));
    let zetas = core::array::from_fn(|i| {
        let e = u32::from(u8::try_from(i).unwrap_or(0).reverse_bits());
        u32::try_from(plain(pow(e), r)).unwrap_or(0)
    });
    Tables { zetas, r2 }
});

/// The low 32 bits.
fn low32(x: u64) -> u32 {
    let [a, b, c, d, ..] = x.to_le_bytes();
    u32::from_le_bytes([a, b, c, d])
}

/// All ones if `a < b`, else zero, for `a, b < 2^31`.
fn lt_mask(a: u32, b: u32) -> u32 {
    0u32.wrapping_sub(a.wrapping_sub(b) >> 31)
}

/// `x mod q` for `x < 2q`.
fn reduce_once(x: u32) -> u32 {
    let m = lt_mask(x, Q);
    (x & m) | (x.wrapping_sub(Q) & !m)
}

fn add(a: u32, b: u32) -> u32 {
    reduce_once(a.wrapping_add(b))
}

fn sub(a: u32, b: u32) -> u32 {
    reduce_once(a.wrapping_add(Q).wrapping_sub(b))
}

/// Montgomery reduction: `a 2^-32 mod q` for `a < q 2^32`.
fn reduce_montgomery(a: u64) -> u32 {
    let t = u64::from(low32(a).wrapping_mul(Q_NEG_INV));
    let b = a.wrapping_add(t.wrapping_mul(u64::from(Q)));
    reduce_once(low32(b >> 32))
}

/// `a b 2^-32 mod q` (one factor in Montgomery form gives the plain product).
fn mul_montgomery(a: u32, b: u32) -> u32 {
    reduce_montgomery(u64::from(a).wrapping_mul(u64::from(b)))
}

/// `a b mod q`.
fn mul(a: u32, b: u32) -> u32 {
    mul_montgomery(mul_montgomery(a, b), TABLES.r2)
}

/// `|x|` of a coefficient as the centered representative's magnitude.
fn abs_mod(x: u32) -> u32 {
    let m = lt_mask(HALF_Q, x);
    (Q.wrapping_sub(x) & m) | (x & !m)
}

/// `|r0|` of a centered value held as two's complement.
fn abs_signed(x: u32) -> u32 {
    let m = 0u32.wrapping_sub(x >> 31);
    (x & !m) | (0u32.wrapping_sub(x) & m)
}

/// The NTT (FIPS 204 Algorithm 41), in place.
fn ntt(w: &mut Poly) {
    let mut zetas = TABLES.zetas.iter().skip(1);
    for len in [128usize, 64, 32, 16, 8, 4, 2, 1] {
        for block in w.chunks_exact_mut(len.wrapping_mul(2)) {
            let zeta = zetas.next().copied().unwrap_or(0);
            let (lo, hi) = block.split_at_mut(len);
            for (a, b) in lo.iter_mut().zip(hi.iter_mut()) {
                let t = mul_montgomery(zeta, *b);
                *b = sub(*a, t);
                *a = add(*a, t);
            }
        }
    }
}

/// The inverse NTT (FIPS 204 Algorithm 42), in place.
fn inverse_ntt(w: &mut Poly) {
    let mut zetas = TABLES.zetas.iter().rev();
    for len in [1usize, 2, 4, 8, 16, 32, 64, 128] {
        for block in w.chunks_exact_mut(len.wrapping_mul(2)) {
            let zeta = Q.wrapping_sub(zetas.next().copied().unwrap_or(0));
            let (lo, hi) = block.split_at_mut(len);
            for (a, b) in lo.iter_mut().zip(hi.iter_mut()) {
                let t = *a;
                *a = add(t, *b);
                *b = mul_montgomery(zeta, sub(t, *b));
            }
        }
    }
    for c in w.iter_mut() {
        *c = mul(*c, INVERSE_256);
    }
}

fn poly_add(a: &Poly, b: &Poly) -> Poly {
    core::array::from_fn(|i| add(at(a, i), at(b, i)))
}

fn poly_sub(a: &Poly, b: &Poly) -> Poly {
    core::array::from_fn(|i| sub(at(a, i), at(b, i)))
}

/// The pointwise product of two NTTs.
fn poly_mul(a: &Poly, b: &Poly) -> Poly {
    core::array::from_fn(|i| mul(at(a, i), at(b, i)))
}

/// Coefficient `i`.
fn at(p: &Poly, i: usize) -> u32 {
    p.get(i).copied().unwrap_or(0)
}

/// `A v` for `A` row-major `k` by `l` and `v` in the NTT domain.
fn matrix_mul(a: &[Poly], v: &[Poly]) -> Vec<Poly> {
    a.chunks_exact(v.len().max(1))
        .map(|row| {
            row.iter()
                .zip(v)
                .fold([0u32; N], |acc, (x, y)| poly_add(&acc, &poly_mul(x, y)))
        })
        .collect()
}

/// `Power2Round` (FIPS 204 Algorithm 35): `(r1, r0)` with `r0` mod `q`.
fn power2round(r: u32) -> (u32, u32) {
    let r1 = r.wrapping_add((1 << (D - 1)) - 1) >> D;
    (r1, sub(r, r1 << D))
}

/// `Decompose` (FIPS 204 Algorithm 36): `(r1, r0)` with `r0` centered, as two's complement.
fn decompose(r: u32, gamma2: u32) -> (u32, u32) {
    let mut r1 = r.wrapping_add(127) >> 7;
    if gamma2 == (Q - 1) / 32 {
        r1 = (r1.wrapping_mul(1025).wrapping_add(1 << 21) >> 22) & 15;
    } else {
        r1 = r1.wrapping_mul(11275).wrapping_add(1 << 23) >> 24;
        r1 ^= (43u32.wrapping_sub(r1) >> 31).wrapping_neg() & r1;
    }
    let mut r0 = r.wrapping_sub(r1.wrapping_mul(gamma2.wrapping_mul(2)));
    r0 = r0.wrapping_sub((HALF_Q.wrapping_sub(r0) >> 31).wrapping_neg() & Q);
    (r1, r0)
}

/// `MakeHint` (FIPS 204 Algorithm 39) of `-ct0` and `w - cs2 + ct0`: 1 if adding `ct0` to
/// `w - cs2` changes its high bits.
fn make_hint(ct0: u32, w_cs2: u32, gamma2: u32) -> u32 {
    let (a, _) = decompose(w_cs2, gamma2);
    let (b, _) = decompose(add(w_cs2, ct0), gamma2);
    let d = a ^ b;
    (d | d.wrapping_neg()) >> 31
}

/// `UseHint` (FIPS 204 Algorithm 40).
fn use_hint(h: u32, r: u32, gamma2: u32) -> u32 {
    // `(q - 1) / (2 gamma2)`.
    let m: u32 = if gamma2 == (Q - 1) / 32 { 16 } else { 44 };
    let (r1, r0) = decompose(r, gamma2);
    if h == 0 {
        return r1;
    }
    let next = if r0 != 0 && r0 >> 31 == 0 {
        r1.wrapping_add(1)
    } else {
        r1.wrapping_add(m).wrapping_sub(1)
    };
    next.checked_rem(m).unwrap_or(0)
}

/// Packs coefficients of `bits` bits, each `f(c)`, appended to `out`.
fn pack(out: &mut Vec<u8>, p: &Poly, bits: u32, f: impl Fn(u32) -> u32) {
    let mut acc = 0u64;
    let mut n = 0u32;
    for &c in p {
        acc |= u64::from(f(c)).wrapping_shl(n);
        n = n.wrapping_add(bits);
        while n >= 8 {
            out.push(low32(acc).to_le_bytes().first().copied().unwrap_or(0));
            acc >>= 8;
            n = n.wrapping_sub(8);
        }
    }
}

/// Unpacks 256 coefficients of `bits` bits from `bytes` (`32 bits` octets).
fn unpack(bytes: &[u8], bits: u32) -> Poly {
    let mask = 1u64.wrapping_shl(bits).wrapping_sub(1);
    let mut out = [0u32; N];
    let mut slots = out.iter_mut();
    let mut acc = 0u64;
    let mut n = 0u32;
    for &b in bytes {
        acc |= u64::from(b).wrapping_shl(n);
        n = n.wrapping_add(8);
        while n >= bits {
            if let Some(s) = slots.next() {
                *s = low32(acc & mask);
            }
            acc = acc.wrapping_shr(bits);
            n = n.wrapping_sub(bits);
        }
    }
    out
}

/// A SHAKE of the parts, `out.len()` octets.
fn shake(algorithm: Algorithm, parts: &[&[u8]], out: &mut [u8]) -> Option<()> {
    let mut ctx = md::context(algorithm);
    for p in parts {
        ctx.update(p).ok()?;
    }
    ctx.finalize(out).ok()
}

/// `H`: SHAKE256.
fn h(parts: &[&[u8]], out: &mut [u8]) -> Option<()> {
    shake(Algorithm::Shake256, parts, out)
}

/// `RejNTTPoly` (FIPS 204 Algorithm 30) of `rho || s || r`.
fn rej_ntt_poly(rho: &[u8; 32], s: u8, r: u8) -> Option<Poly> {
    let mut ctx = md::context(Algorithm::Shake128);
    ctx.update(rho).ok()?;
    ctx.update(&[s, r]).ok()?;
    let mut out = [0u32; N];
    let mut slots = out.iter_mut().peekable();
    let mut buf = [0u8; 168];
    while slots.peek().is_some() {
        ctx.squeeze(&mut buf).ok()?;
        let (chunks, _) = buf.as_chunks::<3>();
        for [b0, b1, b2] in chunks {
            let v = u32::from(*b0) | (u32::from(*b1) << 8) | (u32::from(b2 & 0x7f) << 16);
            if v < Q
                && let Some(slot) = slots.next()
            {
                *slot = v;
            }
        }
    }
    Some(out)
}

/// `ExpandA` (FIPS 204 Algorithm 32): `A`, row-major.
fn expand_a(rho: &[u8; 32], v: Variant) -> Option<Vec<Poly>> {
    let (k, l) = (u8::try_from(v.k()).ok()?, u8::try_from(v.l()).ok()?);
    (0..k)
        .flat_map(|r| (0..l).map(move |s| (r, s)))
        .map(|(r, s)| rej_ntt_poly(rho, s, r))
        .collect()
}

/// `RejBoundedPoly` (FIPS 204 Algorithm 31) of `rho' || n` (two octets).
fn rej_bounded_poly(rho: &[u8; 64], n: u16, eta: u32) -> Option<Poly> {
    let mut ctx = md::context(Algorithm::Shake256);
    ctx.update(rho).ok()?;
    ctx.update(&n.to_le_bytes()).ok()?;
    let mut out = [0u32; N];
    let mut slots = out.iter_mut().peekable();
    let mut buf = Zeroizing::new([0u8; 136]);
    while slots.peek().is_some() {
        ctx.squeeze(buf.as_mut_slice()).ok()?;
        for &b in buf.iter() {
            for z in [u32::from(b & 0x0f), u32::from(b >> 4)] {
                let c = match eta {
                    2 if z < 15 => Some(sub(2, z % 5)),
                    4 if z < 9 => Some(sub(4, z)),
                    _ => None,
                };
                if let Some(c) = c
                    && let Some(slot) = slots.next()
                {
                    *slot = c;
                }
            }
        }
    }
    Some(out)
}

/// `ExpandMask` (FIPS 204 Algorithm 34)'s polynomial `n`.
fn expand_mask(rho: &[u8; 64], n: u16, v: Variant) -> Option<Poly> {
    let bits = v.gamma1_bits().wrapping_add(1);
    let mut buf = Zeroizing::new(vec![0u8; usize::try_from(bits).ok()?.wrapping_mul(32)]);
    h(&[rho, &n.to_le_bytes()], buf.as_mut_slice())?;
    let gamma1 = v.gamma1();
    let mut p = unpack(&buf, bits);
    for c in p.iter_mut() {
        *c = sub(gamma1, *c);
    }
    Some(p)
}

/// `SampleInBall` (FIPS 204 Algorithm 29) of `c~`, in the NTT domain.
fn sample_in_ball(c_tilde: &[u8], tau: usize) -> Option<Poly> {
    let mut ctx = md::context(Algorithm::Shake256);
    ctx.update(c_tilde).ok()?;
    let mut block = [0u8; 136];
    ctx.squeeze(&mut block).ok()?;
    let (signs, _) = block.split_at(8);
    let mut signs = u64::from_le_bytes(<[u8; 8]>::try_from(signs).ok()?);
    let mut offset = 8usize;
    let mut c = [0u32; N];
    for end in N.wrapping_sub(tau)..N {
        let j = loop {
            if offset == block.len() {
                ctx.squeeze(&mut block).ok()?;
                offset = 0;
            }
            let j = usize::from(block.get(offset).copied().unwrap_or(0xff));
            offset = offset.wrapping_add(1);
            if j <= end {
                break j;
            }
        };
        c.swap(end, j);
        if let Some(cj) = c.get_mut(j) {
            *cj = sub(1, low32(signs & 1).wrapping_mul(2));
        }
        signs >>= 1;
    }
    ntt(&mut c);
    Some(c)
}

/// `w1Encode` (FIPS 204 Algorithm 28).
fn w1_encode(w1: &[Poly], v: Variant) -> Vec<u8> {
    let mut out = Vec::new();
    for p in w1 {
        pack(&mut out, p, v.w1_bits(), |c| c);
    }
    out
}

/// The NTTs of a vector.
fn ntt_vector(v: &[Poly]) -> Zeroizing<Vec<Poly>> {
    Zeroizing::new(
        v.iter()
            .map(|p| {
                let mut p = *p;
                ntt(&mut p);
                p
            })
            .collect(),
    )
}

/// The largest centered magnitude of a vector's coefficients.
fn max_norm(v: &[Poly]) -> u32 {
    v.iter().flatten().fold(0, |m, &c| {
        let a = abs_mod(c);
        let gt = lt_mask(m, a);
        (a & gt) | (m & !gt)
    })
}

/// `t = NTT^-1(A NTT(s1)) + s2`, as `(t1, t0)`.
fn make_t(a: &[Poly], s1: &[Poly], s2: &[Poly]) -> (Vec<Poly>, Zeroizing<Vec<Poly>>) {
    let s1_ntt = ntt_vector(s1);
    let mut t = Zeroizing::new(matrix_mul(a, &s1_ntt));
    for (ti, s2i) in t.iter_mut().zip(s2) {
        inverse_ntt(ti);
        *ti = poly_add(ti, s2i);
    }
    let mut t1 = Vec::with_capacity(t.len());
    let mut t0 = Zeroizing::new(Vec::with_capacity(t.len()));
    for p in t.iter() {
        let mut hi = [0u32; N];
        let mut lo = [0u32; N];
        for ((c, h1), l0) in p.iter().zip(hi.iter_mut()).zip(lo.iter_mut()) {
            (*h1, *l0) = power2round(*c);
        }
        t1.push(hi);
        t0.push(lo);
    }
    (t1, t0)
}

/// The message representative's input `M' = 0 || |ctx| || ctx || M` (FIPS 204's pure
/// encoding), or `None` for a context over 255 octets.
pub fn encode_message(context: &[u8], message: &[u8]) -> Option<Vec<u8>> {
    let n = u8::try_from(context.len()).ok()?;
    let mut out = Vec::with_capacity(
        context
            .len()
            .saturating_add(message.len())
            .saturating_add(2),
    );
    out.extend_from_slice(&[0, n]);
    out.extend_from_slice(context);
    out.extend_from_slice(message);
    Some(out)
}

/// An incremental `mu` (`ossl_ml_dsa_mu_init`, `_update`, and `_finalize`): SHAKE256 of the
/// key's `tr`, then, for the pure encoding, its prefix and context string, then the message in
/// pieces. Each squeeze continues the output, as `EVP_DigestSqueeze` does.
pub struct MuHasher(Box<dyn md::Context>);

impl Clone for MuHasher {
    fn clone(&self) -> Self {
        Self(self.0.clone_box())
    }
}

impl MuHasher {
    /// Absorbs the next piece of the message; `false` once squeezed.
    pub fn update(&mut self, data: &[u8]) -> bool {
        self.0.update(data).is_ok()
    }

    /// The next `MU_BYTES` octets of the output.
    pub fn squeeze(&mut self) -> Option<[u8; MU_BYTES]> {
        let mut mu = [0u8; MU_BYTES];
        self.0.squeeze(&mut mu).ok()?;
        Some(mu)
    }
}

/// An ML-DSA public key, with its encoding and hash `tr`.
#[derive(Clone)]
pub struct PublicKey {
    variant: Variant,
    rho: [u8; 32],
    t1: Vec<Poly>,
    tr: [u8; 64],
    encoding: Vec<u8>,
}

impl PublicKey {
    /// A [`MuHasher`] for this key: with `context`, the pure encoding's prefix and that context
    /// string (`None` if it's longer than [`MAX_CONTEXT`]).
    pub fn mu_hasher(&self, context: Option<&[u8]>) -> Option<MuHasher> {
        let mut ctx = md::context(Algorithm::Shake256);
        ctx.update(&self.tr).ok()?;
        if let Some(c) = context {
            let n = u8::try_from(c.len()).ok()?;
            ctx.update(&[0, n]).ok()?;
            ctx.update(c).ok()?;
        }
        Some(MuHasher(ctx))
    }

    fn new(variant: Variant, rho: [u8; 32], t1: Vec<Poly>) -> Option<Self> {
        let mut encoding = Vec::with_capacity(variant.public_key_bytes());
        encoding.extend_from_slice(&rho);
        for p in &t1 {
            pack(&mut encoding, p, 10, |c| c);
        }
        let mut tr = [0u8; 64];
        h(&[&encoding], &mut tr)?;
        Some(Self {
            variant,
            rho,
            t1,
            tr,
            encoding,
        })
    }

    /// `pkDecode` (FIPS 204 Algorithm 23).
    pub fn parse(variant: Variant, pk: &[u8]) -> Result<Self, Error> {
        if pk.len() != variant.public_key_bytes() {
            return Err(Error::Length);
        }
        let (rho, t1) = pk.split_at(32);
        let rho = <[u8; 32]>::try_from(rho).map_err(|_| Error::Length)?;
        let (chunks, _) = t1.as_chunks::<320>();
        let t1 = chunks.iter().map(|c| unpack(c, 10)).collect();
        Self::new(variant, rho, t1).ok_or(Error::Internal)
    }

    /// The parameter set.
    pub fn variant(&self) -> Variant {
        self.variant
    }

    /// The encoding.
    pub fn encode(&self) -> &[u8] {
        &self.encoding
    }

    /// `mu = H(tr || M', 64)`.
    pub fn mu(&self, m_prime: &[u8]) -> Option<[u8; MU_BYTES]> {
        let mut mu = [0u8; MU_BYTES];
        h(&[&self.tr, m_prime], &mut mu)?;
        Some(mu)
    }

    /// `ML-DSA.Verify_internal` (FIPS 204 Algorithm 8) of `sig` for `mu`.
    pub fn verify(&self, mu: &[u8; MU_BYTES], sig: &[u8]) -> bool {
        self.verify_inner(mu, sig).unwrap_or(false)
    }

    fn verify_inner(&self, mu: &[u8; MU_BYTES], sig: &[u8]) -> Option<bool> {
        let v = self.variant;
        let (k, l) = (v.k(), v.l());
        if sig.len() != v.signature_bytes() {
            return Some(false);
        }
        let (c_tilde, rest) = sig.split_at(v.c_tilde_bytes());
        let zbytes = usize::try_from(v.gamma1_bits().wrapping_add(1))
            .ok()?
            .wrapping_mul(32);
        let (zenc, hint) = rest.split_at(zbytes.wrapping_mul(l));
        let gamma1 = v.gamma1();
        let z: Vec<Poly> = zenc
            .chunks_exact(zbytes)
            .map(|c| {
                let mut p = unpack(c, v.gamma1_bits().wrapping_add(1));
                for x in p.iter_mut() {
                    *x = sub(gamma1, *x);
                }
                p
            })
            .collect();
        let Some(hints) = hint_decode(hint, k, v.omega()) else {
            return Some(false);
        };
        let a = expand_a(&self.rho, v)?;
        let c = sample_in_ball(c_tilde, v.tau())?;
        let z_max = max_norm(&z);
        let az = matrix_mul(&a, &ntt_vector(&z));
        let gamma2 = v.gamma2();
        let mut w1 = Vec::with_capacity(k);
        for ((azi, t1i), hi) in az.iter().zip(&self.t1).zip(&hints) {
            let mut t = [0u32; N];
            for (x, y) in t.iter_mut().zip(t1i) {
                *x = y << D;
            }
            ntt(&mut t);
            let mut w = poly_sub(azi, &poly_mul(&c, &t));
            inverse_ntt(&mut w);
            let mut p = [0u32; N];
            for ((o, r), hh) in p.iter_mut().zip(&w).zip(hi) {
                *o = use_hint(*hh, *r, gamma2);
            }
            w1.push(p);
        }
        let mut again = vec![0u8; v.c_tilde_bytes()];
        h(&[mu, &w1_encode(&w1, v)], &mut again)?;
        Some(z_max < gamma1.wrapping_sub(v.beta()) && again == c_tilde)
    }
}

/// `HintBitUnpack` (FIPS 204 Algorithm 21), with OpenSSL's checks: each polynomial's limit
/// within `omega` and not below the last, its indexes increasing, and the unused ones zero.
fn hint_decode(bytes: &[u8], k: usize, omega: usize) -> Option<Vec<Poly>> {
    if bytes.len() != omega.wrapping_add(k) {
        return None;
    }
    let (indexes, limits) = bytes.split_at(omega);
    let mut out = vec![[0u32; N]; k];
    let mut index = 0usize;
    for (p, &limit) in out.iter_mut().zip(limits) {
        let limit = usize::from(limit);
        if limit < index || limit > omega {
            return None;
        }
        let mut last: Option<u8> = None;
        for &b in indexes.get(index..limit)? {
            if last.is_some_and(|l| b <= l) {
                return None;
            }
            last = Some(b);
            *p.get_mut(usize::from(b))? = 1;
        }
        index = limit;
    }
    indexes.get(index..)?.iter().all(|&b| b == 0).then_some(out)
}

/// An ML-DSA private key, with its public key, its encoding, and (if made from one and kept)
/// its seed.
#[derive(Clone)]
pub struct PrivateKey {
    public: PublicKey,
    key: Zeroizing<[u8; 32]>,
    s1: Zeroizing<Vec<Poly>>,
    s2: Zeroizing<Vec<Poly>>,
    t0: Zeroizing<Vec<Poly>>,
    encoding: Zeroizing<Vec<u8>>,
    seed: Option<Zeroizing<[u8; SEED_BYTES]>>,
}

impl PrivateKey {
    /// `ML-DSA.KeyGen_internal` (FIPS 204 Algorithm 6) from the seed `xi`; the key keeps it.
    pub fn generate(variant: Variant, seed: &[u8; SEED_BYTES]) -> Option<Self> {
        crate::dit::with(|| Self::generate_dit(variant, seed))
    }

    /// [`PrivateKey::generate`]'s work.
    fn generate_dit(variant: Variant, seed: &[u8; SEED_BYTES]) -> Option<Self> {
        let (k, l) = (
            u8::try_from(variant.k()).ok()?,
            u8::try_from(variant.l()).ok()?,
        );
        let mut expanded = Zeroizing::new([0u8; 128]);
        h(&[seed, &[k, l]], expanded.as_mut_slice())?;
        let (rho, rest) = expanded.split_at(32);
        let (rho_prime, key) = rest.split_at(64);
        let rho = <[u8; 32]>::try_from(rho).ok()?;
        let rho_prime = Zeroizing::new(<[u8; 64]>::try_from(rho_prime).ok()?);
        let key = Zeroizing::new(<[u8; 32]>::try_from(key).ok()?);
        let eta = variant.eta();
        let mut s1 = Zeroizing::new(Vec::with_capacity(variant.l()));
        let mut s2 = Zeroizing::new(Vec::with_capacity(variant.k()));
        for n in 0..u16::from(l) {
            s1.push(rej_bounded_poly(&rho_prime, n, eta)?);
        }
        for n in 0..u16::from(k) {
            s2.push(rej_bounded_poly(
                &rho_prime,
                n.wrapping_add(u16::from(l)),
                eta,
            )?);
        }
        let a = expand_a(&rho, variant)?;
        let (t1, t0) = make_t(&a, &s1, &s2);
        let public = PublicKey::new(variant, rho, t1)?;
        let mut k = Self {
            public,
            key,
            s1,
            s2,
            t0,
            encoding: Zeroizing::new(Vec::new()),
            seed: Some(Zeroizing::new(*seed)),
        };
        k.encoding = k.encode();
        Some(k)
    }

    /// `skEncode` (FIPS 204 Algorithm 24).
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let v = self.public.variant;
        let mut out = Zeroizing::new(Vec::with_capacity(v.private_key_bytes()));
        out.extend_from_slice(&self.public.rho);
        out.extend_from_slice(self.key.as_slice());
        out.extend_from_slice(&self.public.tr);
        let eta = v.eta();
        for p in self.s1.iter().chain(self.s2.iter()) {
            pack(&mut out, p, v.eta_bits(), |c| sub(eta, c));
        }
        for p in self.t0.iter() {
            pack(&mut out, p, D, |c| sub(1 << (D - 1), c));
        }
        out
    }

    /// `skDecode` (FIPS 204 Algorithm 25), with OpenSSL's checks: `s1` and `s2` within `eta`,
    /// then the public key they make matching the encoding's `t0` and `tr`.
    pub fn parse(variant: Variant, sk: &[u8]) -> Result<Self, Error> {
        if sk.len() != variant.private_key_bytes() {
            return Err(Error::Length);
        }
        let (rho, rest) = sk.split_at(32);
        let (key, rest) = rest.split_at(32);
        let (tr, rest) = rest.split_at(64);
        let eta = variant.eta();
        let ebytes = usize::try_from(variant.eta_bits())
            .map_err(|_| Error::Length)?
            .wrapping_mul(32);
        let (s1e, rest) = rest.split_at(ebytes.wrapping_mul(variant.l()));
        let (s2e, t0e) = rest.split_at(ebytes.wrapping_mul(variant.k()));
        let mut bad = 0u32;
        let mut decode_s = |bytes: &[u8]| -> Zeroizing<Vec<Poly>> {
            Zeroizing::new(
                bytes
                    .chunks_exact(ebytes)
                    .map(|c| {
                        let mut p = unpack(c, variant.eta_bits());
                        for x in p.iter_mut() {
                            // In range when the encoded value is at most 2 eta.
                            bad |= !lt_mask(*x, eta.wrapping_mul(2).wrapping_add(1)) & 1;
                            *x = sub(eta, *x);
                        }
                        p
                    })
                    .collect(),
            )
        };
        let s1 = decode_s(s1e);
        let s2 = decode_s(s2e);
        if bad != 0 {
            return Err(Error::Range);
        }
        let t0 = Zeroizing::new(
            t0e.as_chunks::<416>()
                .0
                .iter()
                .map(|c| {
                    let mut p = unpack(c, D);
                    for x in p.iter_mut() {
                        *x = sub(1 << (D - 1), *x);
                    }
                    p
                })
                .collect::<Vec<Poly>>(),
        );
        let rho = <[u8; 32]>::try_from(rho).map_err(|_| Error::Length)?;
        let a = expand_a(&rho, variant).ok_or(Error::Internal)?;
        let (t1, derived_t0) = make_t(&a, &s1, &s2);
        let public = PublicKey::new(variant, rho, t1).ok_or(Error::Internal)?;
        if derived_t0.as_slice() != t0.as_slice() || public.tr.as_slice() != tr {
            return Err(Error::Mismatch);
        }
        let key = Zeroizing::new(<[u8; 32]>::try_from(key).map_err(|_| Error::Length)?);
        Ok(Self {
            public,
            key,
            s1,
            s2,
            t0,
            encoding: Zeroizing::new(sk.to_vec()),
            seed: None,
        })
    }

    /// The public key.
    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// The encoding.
    pub fn encoding(&self) -> &[u8] {
        &self.encoding
    }

    /// The seed, if the key has it.
    pub fn seed(&self) -> Option<&[u8; SEED_BYTES]> {
        self.seed.as_deref()
    }

    /// Forgets the seed.
    pub fn forget_seed(&mut self) {
        self.seed = None;
    }

    /// Whether the private key makes the public key's `t1` (and its own `t0`), as OpenSSL's
    /// pairwise check asks.
    pub fn pairwise(&self, public: &PublicKey) -> bool {
        let Some(a) = expand_a(&self.public.rho, self.public.variant) else {
            return false;
        };
        let (t1, t0) = make_t(&a, &self.s1, &self.s2);
        t1 == public.t1 && t0.as_slice() == self.t0.as_slice()
    }

    /// `ML-DSA.Sign_internal` (FIPS 204 Algorithm 7) of `mu` with the randomness `rnd` (zeros
    /// for deterministic signing).
    pub fn sign(&self, mu: &[u8; MU_BYTES], rnd: &[u8; RANDOM_BYTES]) -> Option<Vec<u8>> {
        crate::dit::with(|| self.sign_dit(mu, rnd))
    }

    /// [`PrivateKey::sign`]'s work.
    fn sign_dit(&self, mu: &[u8; MU_BYTES], rnd: &[u8; RANDOM_BYTES]) -> Option<Vec<u8>> {
        let v = self.public.variant;
        let (k, l) = (v.k(), v.l());
        let gamma1 = v.gamma1();
        let gamma2 = v.gamma2();
        let beta = v.beta();
        let a = expand_a(&self.public.rho, v)?;
        let mut rho_pp = Zeroizing::new([0u8; 64]);
        h(&[self.key.as_slice(), rnd, mu], rho_pp.as_mut_slice())?;
        let s1 = ntt_vector(&self.s1);
        let s2 = ntt_vector(&self.s2);
        let t0 = ntt_vector(&self.t0);
        let mut kappa = 0u16;
        loop {
            let mut y = Zeroizing::new(Vec::with_capacity(l));
            for r in 0..l {
                y.push(expand_mask(
                    &rho_pp,
                    kappa.wrapping_add(u16::try_from(r).ok()?),
                    v,
                )?);
            }
            kappa = kappa.wrapping_add(u16::try_from(l).ok()?);
            let mut w = Zeroizing::new(matrix_mul(&a, &ntt_vector(&y)));
            let mut w1 = Vec::with_capacity(k);
            for wi in w.iter_mut() {
                inverse_ntt(wi);
                w1.push(core::array::from_fn::<u32, N, _>(|j| {
                    decompose(at(wi, j), gamma2).0
                }));
            }
            let mut c_tilde = vec![0u8; v.c_tilde_bytes()];
            h(&[mu, &w1_encode(&w1, v)], &mut c_tilde)?;
            let c = sample_in_ball(&c_tilde, v.tau())?;
            let product = |s: &[Poly]| -> Zeroizing<Vec<Poly>> {
                Zeroizing::new(
                    s.iter()
                        .map(|p| {
                            let mut q = poly_mul(&c, p);
                            inverse_ntt(&mut q);
                            q
                        })
                        .collect(),
                )
            };
            let cs1 = product(&s1);
            let cs2 = product(&s2);
            let z: Zeroizing<Vec<Poly>> = Zeroizing::new(
                y.iter()
                    .zip(cs1.iter())
                    .map(|(a, b)| poly_add(a, b))
                    .collect(),
            );
            let w_cs2: Zeroizing<Vec<Poly>> = Zeroizing::new(
                w.iter()
                    .zip(cs2.iter())
                    .map(|(a, b)| poly_sub(a, b))
                    .collect(),
            );
            let r0_max = w_cs2.iter().flatten().fold(0u32, |m, &x| {
                let a = abs_signed(decompose(x, gamma2).1);
                let gt = lt_mask(m, a);
                (a & gt) | (m & !gt)
            });
            let z_max = max_norm(&z);
            if z_max >= gamma1.wrapping_sub(beta) || r0_max >= gamma2.wrapping_sub(beta) {
                continue;
            }
            let ct0 = product(&t0);
            let mut hints = vec![[0u32; N]; k];
            let mut ones = 0u32;
            for ((hi, c0), wc) in hints.iter_mut().zip(ct0.iter()).zip(w_cs2.iter()) {
                for ((x, a), b) in hi.iter_mut().zip(c0).zip(wc) {
                    *x = make_hint(*a, *b, gamma2);
                    ones = ones.wrapping_add(*x);
                }
            }
            if max_norm(&ct0) >= gamma2 || ones > u32::try_from(v.omega()).ok()? {
                continue;
            }
            let mut sig = Vec::with_capacity(v.signature_bytes());
            sig.extend_from_slice(&c_tilde);
            for p in z.iter() {
                pack(&mut sig, p, v.gamma1_bits().wrapping_add(1), |x| {
                    sub(gamma1, x)
                });
            }
            let mut indexes = vec![0u8; v.omega()];
            let mut limits = Vec::with_capacity(k);
            let mut n = 0usize;
            for p in &hints {
                for (j, &x) in p.iter().enumerate() {
                    if x != 0 {
                        if let Some(slot) = indexes.get_mut(n) {
                            *slot = u8::try_from(j).ok()?;
                        }
                        n = n.wrapping_add(1);
                    }
                }
                limits.push(u8::try_from(n).ok()?);
            }
            sig.extend_from_slice(&indexes);
            sig.extend_from_slice(&limits);
            w1.zeroize();
            return Some(sig);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic() {
        for (a, b) in [
            (0u32, 5u32),
            (Q - 1, Q - 1),
            (1753, 1753),
            (123_456, 7_654_321),
        ] {
            assert_eq!(
                u64::from(mul(a, b)),
                u64::from(a) * u64::from(b) % u64::from(Q)
            );
        }
        let mut f: Poly = core::array::from_fn(|i| u32::try_from(i * 7919 % 8_380_417).unwrap());
        let g = f;
        ntt(&mut f);
        inverse_ntt(&mut f);
        assert_eq!(f, g);
        for gamma2 in [(Q - 1) / 88, (Q - 1) / 32] {
            for r in (0..Q)
                .step_by(997)
                .chain([0, 1, Q - 1, Q - 2, gamma2, 2 * gamma2])
            {
                let (r1, r0) = decompose(r, gamma2);
                let r0 = i64::from(r0.cast_signed());
                assert!(
                    r0 > -i64::from(gamma2) && r0 <= i64::from(gamma2),
                    "{r} {r0}"
                );
                let back = (i64::from(r1) * 2 * i64::from(gamma2) + r0).rem_euclid(i64::from(Q));
                assert_eq!(back, i64::from(r), "{r}");
            }
        }
    }

    #[test]
    fn round_trips() {
        for v in [Variant::MlDsa44, Variant::MlDsa65, Variant::MlDsa87] {
            let k = PrivateKey::generate(v, &[7; 32]).unwrap();
            assert_eq!(k.encoding().len(), v.private_key_bytes());
            assert_eq!(k.public().encode().len(), v.public_key_bytes());
            let p = PublicKey::parse(v, k.public().encode()).unwrap();
            let k2 = PrivateKey::parse(v, k.encoding()).unwrap();
            assert_eq!(k2.encoding(), k.encoding());
            assert!(k2.pairwise(&p));
            let m = encode_message(b"ctx", b"message").unwrap();
            let mu = p.mu(&m).unwrap();
            let sig = k2.sign(&mu, &[0; 32]).unwrap();
            assert_eq!(sig.len(), v.signature_bytes());
            assert!(p.verify(&mu, &sig));
            let mut bad = sig.clone();
            bad[5] ^= 1;
            assert!(!p.verify(&mu, &bad));
            let mut sk = k.encoding().to_vec();
            let n = sk.len();
            sk[n - 1] ^= 1;
            assert_eq!(PrivateKey::parse(v, &sk).err(), Some(Error::Mismatch));
            sk[n - 1] ^= 1;
            sk[100] ^= 1;
            assert_eq!(PrivateKey::parse(v, &sk).err(), Some(Error::Mismatch));
            sk[100] ^= 1;
            sk[128] = 0xff;
            assert_eq!(PrivateKey::parse(v, &sk).err(), Some(Error::Range));
        }
    }

    fn sha256_hex(data: &[u8]) -> String {
        use sha2::Digest;
        sha2::Sha256::digest(data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Against the reference OpenSSL: keys from the seed 00..1f, and the deterministic
    /// signature of "message" with the context "ctx" (SHA-256 of each).
    #[test]
    fn matches_the_reference() {
        let cases = [
            (
                Variant::MlDsa44,
                "9f107644c1084526af3bc8098680b05499a2325a644e388fb4f970e058d19d46",
                "04bf6b9f579166a627961dfc5c3bf9717df868db88863856356c4668c8b56b0b",
                "3bb052bd420004053a6d200f368a041ad88609807e58cedbccba184e9eb4f16d",
            ),
            (
                Variant::MlDsa65,
                "d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9",
                "9f1e24f47795fe50040384e3d6183988047170fa2d866406b70fe0a3f8216063",
                "244a863431d81ee343fbdb1b4baf144e965df5b0b130258109720d83586f0071",
            ),
            (
                Variant::MlDsa87,
                "91dc389cfaa01470b7f66eee45a4ae9026d154817c754dfe22298b3fa241ffcd",
                "764d3e223ed90c07bc91a0ab6ecd170e5c66ffe39f7039298596039a36005435",
                "9a6ed4f10e6350428f89be3a1161a44513696e3d5696a49747492e73a29923ba",
            ),
        ];
        let seed: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        for (v, pk, sk, sig) in cases {
            let k = PrivateKey::generate(v, &seed).unwrap();
            assert_eq!(sha256_hex(k.public().encode()), pk, "{v:?} pk");
            assert_eq!(sha256_hex(k.encoding()), sk, "{v:?} sk");
            let mu = k
                .public()
                .mu(&encode_message(b"ctx", b"message").unwrap())
                .unwrap();
            let s = k.sign(&mu, &[0; 32]).unwrap();
            assert_eq!(sha256_hex(&s), sig, "{v:?} sig");
            assert!(k.public().verify(&mu, &s));
        }
    }
}
