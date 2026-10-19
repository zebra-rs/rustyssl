//! ML-KEM-512, ML-KEM-768, and ML-KEM-1024 (FIPS 203), with OpenSSL's rules (its `ml_kem`
//! directory): keys from a 64-octet seed `(d, z)`, the public key's and the expanded private
//! key's encodings, both checked when parsed (every 12-bit coefficient below `q`, and the
//! private key's copy of `H(ek)` matching), and the encapsulation and implicitly rejecting
//! decapsulation.
//!
//! Polynomials are 256 coefficients mod `q = 3329`, reduced with Barrett's method and masked
//! corrections, so nothing that depends on a secret branches, indexes a table, or divides: the
//! secret vector's sampling, the NTT, compression, the private key's decoding check, and the
//! decapsulation's ciphertext comparison and selection. The public matrix is sampled from
//! SHAKE128 by rejection, which depends only on the public seed `rho`.

use std::sync::LazyLock;

use zeroize::{Zeroize, Zeroizing};

use crate::md::{self, Algorithm};

/// The polynomials' degree.
const N: usize = 256;
/// The modulus `q`.
const Q: u16 = 3329;
/// `q` for 32-bit arithmetic.
const Q32: u32 = 3329;
/// `(q - 1) / 2`, for rounding in compression.
const HALF_Q: u32 = 1664;
/// `floor(2^24 / q)`, Barrett's multiplier.
const BARRETT_MULTIPLIER: u64 = 5039;
/// Barrett's shift.
const BARRETT_SHIFT: u32 = 24;
/// `128^-1 mod q`, scaling the inverse NTT.
const INVERSE_128: u16 = 3303;
/// A 12-bit coefficient vector's octets per polynomial.
const POLY_BYTES: usize = 384;

/// The length of `d`, `z`, `rho`, `sigma`, an encapsulation's entropy, and the like.
pub const RANDOM_BYTES: usize = 32;
/// The key-generation seed's length (`d || z`).
pub const SEED_BYTES: usize = 64;
/// The shared secret's length.
pub const SHARED_SECRET_BYTES: usize = 32;
/// `H(ek)`'s length.
pub const PKHASH_BYTES: usize = 32;

type Poly = [u16; N];

/// Why a key couldn't be parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The encoding's length isn't the variant's.
    Length,
    /// A public `t` coefficient isn't below `q`.
    InvalidPublicVector,
    /// A private `s` coefficient isn't below `q`.
    InvalidPrivateVector,
    /// The private key's `H(ek)` isn't its public key's.
    HashMismatch,
    /// A hash failed.
    Internal,
}

/// An ML-KEM parameter set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl Variant {
    /// Its name (`ML-KEM-768`, ...).
    pub const fn name(self) -> &'static str {
        match self {
            Self::MlKem512 => "ML-KEM-512",
            Self::MlKem768 => "ML-KEM-768",
            Self::MlKem1024 => "ML-KEM-1024",
        }
    }

    /// The module's rank `k`.
    pub const fn rank(self) -> usize {
        match self {
            Self::MlKem512 => 2,
            Self::MlKem768 => 3,
            Self::MlKem1024 => 4,
        }
    }

    /// `eta1`.
    const fn eta1(self) -> usize {
        match self {
            Self::MlKem512 => 3,
            Self::MlKem768 | Self::MlKem1024 => 2,
        }
    }

    /// `eta2`.
    const fn eta2(self) -> usize {
        2
    }

    /// `du`.
    const fn du(self) -> u32 {
        match self {
            Self::MlKem512 | Self::MlKem768 => 10,
            Self::MlKem1024 => 11,
        }
    }

    /// `dv`.
    const fn dv(self) -> u32 {
        match self {
            Self::MlKem512 | Self::MlKem768 => 4,
            Self::MlKem1024 => 5,
        }
    }

    /// Its bits (`ML_KEM_*_BITS`).
    pub const fn bits(self) -> u32 {
        match self {
            Self::MlKem512 => 512,
            Self::MlKem768 => 768,
            Self::MlKem1024 => 1024,
        }
    }

    /// Its NIST security category (FIPS 203, section 8: 1, 3, or 5).
    pub const fn security_category(self) -> u32 {
        match self {
            Self::MlKem512 => 1,
            Self::MlKem768 => 3,
            Self::MlKem1024 => 5,
        }
    }

    /// Its security bits.
    pub const fn security_bits(self) -> u32 {
        match self {
            Self::MlKem512 => 128,
            Self::MlKem768 => 192,
            Self::MlKem1024 => 256,
        }
    }

    /// A 12-bit vector's octets (`384 k`).
    const fn vector_bytes(self) -> usize {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1152,
            Self::MlKem1024 => 1536,
        }
    }

    /// The public key's length (`384 k + 32`).
    pub const fn public_key_bytes(self) -> usize {
        match self {
            Self::MlKem512 => 800,
            Self::MlKem768 => 1184,
            Self::MlKem1024 => 1568,
        }
    }

    /// The private key's length (`768 k + 96`).
    pub const fn private_key_bytes(self) -> usize {
        match self {
            Self::MlKem512 => 1632,
            Self::MlKem768 => 2400,
            Self::MlKem1024 => 3168,
        }
    }

    /// The ciphertext's length (`32 (du k + dv)`).
    pub const fn ciphertext_bytes(self) -> usize {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
        }
    }

    /// The ciphertext's `u` part's length (`32 du k`).
    const fn u_bytes(self) -> usize {
        match self {
            Self::MlKem512 => 640,
            Self::MlKem768 => 960,
            Self::MlKem1024 => 1408,
        }
    }
}

/// The NTT's constants: `zetas[i] = 17^BitRev7(i)` and `gammas[i] = 17^(2 BitRev7(i) + 1)`.
struct Tables {
    zetas: [u16; 128],
    gammas: [u16; 128],
}

static TABLES: LazyLock<Tables> = LazyLock::new(|| {
    let pow17 = |e: u32| (0..e).fold(1u16, |r, _| mul(r, 17));
    let bitrev7 = |i: usize| u32::from(u8::try_from(i).unwrap_or(0).reverse_bits() >> 1);
    Tables {
        zetas: core::array::from_fn(|i| pow17(bitrev7(i))),
        gammas: core::array::from_fn(|i| pow17(bitrev7(i).wrapping_mul(2).wrapping_add(1))),
    }
});

/// The low 16 bits, without a branch.
fn low16(x: u32) -> u16 {
    let [a, b, _, _] = x.to_le_bytes();
    u16::from_le_bytes([a, b])
}

/// The low 8 bits.
fn low8(x: u32) -> u8 {
    let [a, _, _, _] = x.to_le_bytes();
    a
}

/// `x mod q` for `x < 2q`.
fn reduce_once(x: u16) -> u16 {
    let r = x.wrapping_sub(Q);
    let m = 0u16.wrapping_sub(r >> 15);
    r.wrapping_add(m & Q)
}

/// `x mod q` for `x < q + 2 q^2` (Barrett).
fn reduce(x: u32) -> u16 {
    let product = u64::from(x).wrapping_mul(BARRETT_MULTIPLIER);
    let [a, b, c, d, ..] = (product >> BARRETT_SHIFT).to_le_bytes();
    let quotient = u32::from_le_bytes([a, b, c, d]);
    reduce_once(low16(x.wrapping_sub(quotient.wrapping_mul(Q32))))
}

fn add(a: u16, b: u16) -> u16 {
    reduce_once(a.wrapping_add(b))
}

fn sub(a: u16, b: u16) -> u16 {
    reduce_once(a.wrapping_add(Q).wrapping_sub(b))
}

fn mul(a: u16, b: u16) -> u16 {
    reduce(u32::from(a).wrapping_mul(u32::from(b)))
}

/// 1 if `a < b`, else 0, for `a, b < 2^31`.
fn lt(a: u32, b: u32) -> u32 {
    a.wrapping_sub(b) >> 31
}

/// `Compress_d`: `round(2^d x / q) mod 2^d`.
fn compress(x: u16, d: u32) -> u16 {
    let shifted = u32::from(x).wrapping_shl(d);
    let product = u64::from(shifted).wrapping_mul(BARRETT_MULTIPLIER);
    let [a, b, c, e, ..] = (product >> BARRETT_SHIFT).to_le_bytes();
    let mut quotient = u32::from_le_bytes([a, b, c, e]);
    let remainder = shifted.wrapping_sub(quotient.wrapping_mul(Q32));
    quotient = quotient.wrapping_add(lt(HALF_Q, remainder));
    quotient = quotient.wrapping_add(lt(Q32.wrapping_add(HALF_Q), remainder));
    low16(quotient & 1u32.wrapping_shl(d).wrapping_sub(1))
}

/// `Decompress_d`: `round(q y / 2^d)`.
fn decompress(y: u16, d: u32) -> u16 {
    let product = u32::from(y).wrapping_mul(Q32);
    let remainder = product & 1u32.wrapping_shl(d).wrapping_sub(1);
    low16((product.wrapping_shr(d)).wrapping_add(remainder.wrapping_shr(d.wrapping_sub(1))))
}

fn poly_add(a: &mut Poly, b: &Poly) {
    for (x, y) in a.iter_mut().zip(b) {
        *x = add(*x, *y);
    }
}

fn poly_sub(a: &mut Poly, b: &Poly) {
    for (x, y) in a.iter_mut().zip(b) {
        *x = sub(*x, *y);
    }
}

/// The NTT (FIPS 203 Algorithm 9), in place.
fn ntt(f: &mut Poly) {
    let mut zetas = TABLES.zetas.iter().skip(1);
    for len in [128usize, 64, 32, 16, 8, 4, 2] {
        for block in f.chunks_exact_mut(len.wrapping_mul(2)) {
            let zeta = zetas.next().copied().unwrap_or(0);
            let (lo, hi) = block.split_at_mut(len);
            for (a, b) in lo.iter_mut().zip(hi.iter_mut()) {
                let t = mul(zeta, *b);
                *b = sub(*a, t);
                *a = add(*a, t);
            }
        }
    }
}

/// The inverse NTT (FIPS 203 Algorithm 10), in place.
fn inverse_ntt(f: &mut Poly) {
    let mut zetas = TABLES.zetas.iter().rev();
    for len in [2usize, 4, 8, 16, 32, 64, 128] {
        for block in f.chunks_exact_mut(len.wrapping_mul(2)) {
            let zeta = zetas.next().copied().unwrap_or(0);
            let (lo, hi) = block.split_at_mut(len);
            for (a, b) in lo.iter_mut().zip(hi.iter_mut()) {
                let t = *a;
                *a = add(t, *b);
                *b = mul(zeta, sub(*b, t));
            }
        }
    }
    for c in f.iter_mut() {
        *c = mul(*c, INVERSE_128);
    }
}

/// `MultiplyNTTs` (FIPS 203 Algorithm 11), added to `acc`.
fn multiply_add(acc: &mut Poly, a: &Poly, b: &Poly) {
    let (acc, _) = acc.as_chunks_mut::<2>();
    let (a, _) = a.as_chunks::<2>();
    let (b, _) = b.as_chunks::<2>();
    for (([c0, c1], ([a0, a1], [b0, b1])), &gamma) in
        acc.iter_mut().zip(a.iter().zip(b)).zip(&TABLES.gammas)
    {
        let (a0, a1, b0, b1) = (
            u32::from(*a0),
            u32::from(*a1),
            u32::from(*b0),
            u32::from(*b1),
        );
        let odd = u32::from(mul(reduce(a1.wrapping_mul(b1)), gamma));
        let d0 = reduce(a0.wrapping_mul(b0).wrapping_add(odd));
        let d1 = reduce(a0.wrapping_mul(b1).wrapping_add(a1.wrapping_mul(b0)));
        *c0 = add(*c0, d0);
        *c1 = add(*c1, d1);
    }
}

/// `ByteEncode_d` of `p`, appended to `out`.
fn encode(out: &mut Vec<u8>, p: &Poly, d: u32) {
    let mut acc = 0u32;
    let mut n = 0u32;
    for &c in p {
        acc |= u32::from(c).wrapping_shl(n);
        n = n.wrapping_add(d);
        while n >= 8 {
            out.push(low8(acc));
            acc >>= 8;
            n = n.wrapping_sub(8);
        }
    }
}

/// `ByteDecode_d` of `32 d` octets (without reduction).
fn decode(bytes: &[u8], d: u32) -> Poly {
    let mask = 1u32.wrapping_shl(d).wrapping_sub(1);
    let mut out = [0u16; N];
    let mut slots = out.iter_mut();
    let mut acc = 0u32;
    let mut n = 0u32;
    for &b in bytes {
        acc |= u32::from(b).wrapping_shl(n);
        n = n.wrapping_add(8);
        while n >= d {
            if let Some(s) = slots.next() {
                *s = low16(acc & mask);
            }
            acc = acc.wrapping_shr(d);
            n = n.wrapping_sub(d);
        }
    }
    out
}

/// `ByteDecode_12` of a vector, each coefficient checked below `q` (in constant time, the
/// verdict at the end).
fn decode_vector12(bytes: &[u8]) -> Option<Vec<Poly>> {
    let mut bad = 0u32;
    let (chunks, _) = bytes.as_chunks::<POLY_BYTES>();
    let v: Vec<Poly> = chunks
        .iter()
        .map(|chunk| {
            let p = decode(chunk, 12);
            for &c in &p {
                bad |= lt(u32::from(c), Q32) ^ 1;
            }
            p
        })
        .collect();
    (bad == 0).then_some(v)
}

/// A vector's `ByteEncode_12`.
fn encode_vector12(out: &mut Vec<u8>, v: &[Poly]) {
    for p in v {
        encode(out, p, 12);
    }
}

/// A digest of the parts, `len` octets (a fixed-size digest's own).
fn digest(algorithm: Algorithm, parts: &[&[u8]], out: &mut [u8]) -> Option<()> {
    let mut ctx = md::context(algorithm);
    for p in parts {
        ctx.update(p).ok()?;
    }
    ctx.finalize(out).ok()
}

/// `G`: SHA3-512.
fn g(parts: &[&[u8]]) -> Option<Zeroizing<[u8; 64]>> {
    let mut out = Zeroizing::new([0u8; 64]);
    digest(Algorithm::Sha3_512, parts, out.as_mut_slice())?;
    Some(out)
}

/// `H`: SHA3-256.
fn h(data: &[u8]) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    digest(Algorithm::Sha3_256, &[data], &mut out)?;
    Some(out)
}

/// `PRF_eta(s, b)` then `SamplePolyCBD_eta` (FIPS 203 Algorithm 8).
fn sample_cbd(seed: &[u8; 32], counter: u8, eta: usize) -> Option<Poly> {
    let mut buf = Zeroizing::new(vec![0u8; eta.wrapping_mul(64)]);
    digest(Algorithm::Shake256, &[seed, &[counter]], buf.as_mut_slice())?;
    let mut bits = buf
        .iter()
        .flat_map(|&b| (0..8).map(move |k| u16::from((b >> k) & 1)));
    let mut next = || bits.next().unwrap_or(0);
    Some(core::array::from_fn(|_| {
        let x = (0..eta).fold(0u16, |s, _| s.wrapping_add(next()));
        let y = (0..eta).fold(0u16, |s, _| s.wrapping_add(next()));
        sub(x, y)
    }))
}

/// `SampleNTT` (FIPS 203 Algorithm 7) of `rho || j || i`: rejection sampling from SHAKE128.
fn sample_ntt(rho: &[u8; 32], j: u8, i: u8) -> Option<Poly> {
    let mut ctx = md::context(Algorithm::Shake128);
    ctx.update(rho).ok()?;
    ctx.update(&[j, i]).ok()?;
    let mut out = [0u16; N];
    let mut slots = out.iter_mut().peekable();
    let mut buf = [0u8; 168];
    while slots.peek().is_some() {
        ctx.squeeze(&mut buf).ok()?;
        let (chunks, _) = buf.as_chunks::<3>();
        for [b0, b1, b2] in chunks {
            let d1 = u16::from(*b0) | (u16::from(b1 & 0x0f) << 8);
            let d2 = u16::from(b1 >> 4) | (u16::from(*b2) << 4);
            for d in [d1, d2] {
                if d < Q
                    && let Some(s) = slots.next()
                {
                    *s = d;
                }
            }
        }
    }
    Some(out)
}

/// The matrix `A` (row-major, `A[i][j] = SampleNTT(rho || j || i)`).
fn expand(rho: &[u8; 32], k: usize) -> Option<Vec<Poly>> {
    let k = u8::try_from(k).ok()?;
    (0..k)
        .flat_map(|i| (0..k).map(move |j| (i, j)))
        .map(|(i, j)| sample_ntt(rho, j, i))
        .collect()
}

/// An ML-KEM public key, with its matrix and hash precomputed.
#[derive(Clone)]
pub struct PublicKey {
    variant: Variant,
    /// `t` (in the NTT domain).
    t: Vec<Poly>,
    rho: [u8; 32],
    /// `H(ek)`.
    hash: [u8; 32],
    /// `A`.
    a: Vec<Poly>,
}

impl PublicKey {
    fn new(variant: Variant, t: Vec<Poly>, rho: [u8; 32]) -> Option<Self> {
        let a = expand(&rho, variant.rank())?;
        let mut key = Self {
            variant,
            t,
            rho,
            hash: [0; 32],
            a,
        };
        key.hash = h(&key.encode())?;
        Some(key)
    }

    /// Parses an encapsulation key `ek` (FIPS 203's modulus check included).
    pub fn parse(variant: Variant, ek: &[u8]) -> Result<Self, Error> {
        if ek.len() != variant.public_key_bytes() {
            return Err(Error::Length);
        }
        let (t, rho) = ek.split_at(variant.vector_bytes());
        let t = decode_vector12(t).ok_or(Error::InvalidPublicVector)?;
        let rho = <[u8; 32]>::try_from(rho).map_err(|_| Error::Length)?;
        Self::new(variant, t, rho).ok_or(Error::Internal)
    }

    /// The parameter set.
    pub fn variant(&self) -> Variant {
        self.variant
    }

    /// `ek`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.variant.public_key_bytes());
        encode_vector12(&mut out, &self.t);
        out.extend_from_slice(&self.rho);
        out
    }

    /// `H(ek)`.
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// `K-PKE.Encrypt` (FIPS 203 Algorithm 14) of `m` with randomness `r`.
    fn encrypt(&self, m: &[u8; 32], r: &[u8; 32]) -> Option<Vec<u8>> {
        let v = self.variant;
        let k = v.rank();
        let mut counter = 0u8;
        let mut next = |eta| {
            let p = sample_cbd(r, counter, eta);
            counter = counter.wrapping_add(1);
            p
        };
        let mut y = Zeroizing::new(Vec::with_capacity(k));
        for _ in 0..k {
            let mut p = next(v.eta1())?;
            ntt(&mut p);
            y.push(p);
        }
        let mut e1 = Zeroizing::new(Vec::with_capacity(k));
        for _ in 0..k {
            e1.push(next(v.eta2())?);
        }
        let e2 = Zeroizing::new(next(v.eta2())?);
        // u = NTT^-1(A^T y) + e1.
        let mut u = Zeroizing::new(vec![[0u16; N]; k]);
        for (row, yj) in self.a.chunks_exact(k).zip(y.iter()) {
            for (ui, aji) in u.iter_mut().zip(row) {
                multiply_add(ui, aji, yj);
            }
        }
        let mut out = Vec::with_capacity(v.ciphertext_bytes());
        for (ui, e) in u.iter_mut().zip(e1.iter()) {
            inverse_ntt(ui);
            poly_add(ui, e);
            for c in ui.iter_mut() {
                *c = compress(*c, v.du());
            }
            encode(&mut out, ui, v.du());
        }
        // v = NTT^-1(t^T y) + e2 + Decompress_1(m).
        let mut w = Zeroizing::new([0u16; N]);
        for (ti, yi) in self.t.iter().zip(y.iter()) {
            multiply_add(&mut w, ti, yi);
        }
        inverse_ntt(&mut w);
        poly_add(&mut w, &e2);
        let mu = Zeroizing::new(decode(m, 1));
        for (c, b) in w.iter_mut().zip(mu.iter()) {
            *c = add(*c, decompress(*b, 1));
            *c = compress(*c, v.dv());
        }
        encode(&mut out, &w, v.dv());
        Some(out)
    }

    /// `ML-KEM.Encaps_internal` (FIPS 203 Algorithm 17) with the entropy `m`: the ciphertext
    /// and the shared secret.
    pub fn encapsulate(
        &self,
        m: &[u8; RANDOM_BYTES],
    ) -> Option<(Vec<u8>, Zeroizing<[u8; SHARED_SECRET_BYTES]>)> {
        crate::dit::with(|| {
            let kr = g(&[m, &self.hash])?;
            let (key, r) = kr.split_at(SHARED_SECRET_BYTES);
            let r = Zeroizing::new(<[u8; 32]>::try_from(r).ok()?);
            let c = self.encrypt(m, &r)?;
            let key = Zeroizing::new(<[u8; 32]>::try_from(key).ok()?);
            Some((c, key))
        })
    }
}

/// An ML-KEM private key (`dk`), with its public key and, if it was made from one and kept,
/// its seed's `d`.
#[derive(Clone)]
pub struct PrivateKey {
    public: PublicKey,
    /// `s` (in the NTT domain).
    s: Zeroizing<Vec<Poly>>,
    /// The implicit rejection secret.
    z: Zeroizing<[u8; 32]>,
    d: Option<Zeroizing<[u8; 32]>>,
}

impl PrivateKey {
    /// `ML-KEM.KeyGen_internal` (FIPS 203 Algorithm 16) from the seed `d || z`; the key keeps
    /// `d`.
    pub fn generate(variant: Variant, seed: &[u8; SEED_BYTES]) -> Option<Self> {
        crate::dit::with(|| Self::generate_dit(variant, seed))
    }

    /// [`PrivateKey::generate`]'s work.
    fn generate_dit(variant: Variant, seed: &[u8; SEED_BYTES]) -> Option<Self> {
        let (d, z) = seed.split_at(RANDOM_BYTES);
        let d = Zeroizing::new(<[u8; 32]>::try_from(d).ok()?);
        let z = Zeroizing::new(<[u8; 32]>::try_from(z).ok()?);
        let k = variant.rank();
        let hashed = g(&[d.as_slice(), &[u8::try_from(k).ok()?]])?;
        let (rho, sigma) = hashed.split_at(RANDOM_BYTES);
        let rho = <[u8; 32]>::try_from(rho).ok()?;
        let sigma = Zeroizing::new(<[u8; 32]>::try_from(sigma).ok()?);
        let a = expand(&rho, k)?;
        let mut counter = 0u8;
        let mut next = || {
            let mut p = sample_cbd(&sigma, counter, variant.eta1());
            counter = counter.wrapping_add(1);
            if let Some(p) = p.as_mut() {
                ntt(p);
            }
            p
        };
        let mut s = Zeroizing::new(Vec::with_capacity(k));
        for _ in 0..k {
            s.push(next()?);
        }
        let mut t = Vec::with_capacity(k);
        for _ in 0..k {
            t.push(next()?);
        }
        // t = A s + e.
        for (ti, row) in t.iter_mut().zip(a.chunks_exact(k)) {
            for (aij, sj) in row.iter().zip(s.iter()) {
                multiply_add(ti, aij, sj);
            }
        }
        let mut public = PublicKey {
            variant,
            t,
            rho,
            hash: [0; 32],
            a,
        };
        public.hash = h(&public.encode())?;
        Some(Self {
            public,
            s,
            z,
            d: Some(d),
        })
    }

    /// Parses a decapsulation key `dk = dk_pke || ek || H(ek) || z`: both vectors' coefficients
    /// below `q`, and `H(ek)` matching.
    pub fn parse(variant: Variant, dk: &[u8]) -> Result<Self, Error> {
        if dk.len() != variant.private_key_bytes() {
            return Err(Error::Length);
        }
        let (s, rest) = dk.split_at(variant.vector_bytes());
        let s = Zeroizing::new(decode_vector12(s).ok_or(Error::InvalidPrivateVector)?);
        let (ek, rest) = rest.split_at(variant.public_key_bytes());
        let public = PublicKey::parse(variant, ek)?;
        let (hash, z) = rest.split_at(PKHASH_BYTES);
        if hash != public.hash {
            return Err(Error::HashMismatch);
        }
        let z = Zeroizing::new(<[u8; 32]>::try_from(z).map_err(|_| Error::Length)?);
        Ok(Self {
            public,
            s,
            z,
            d: None,
        })
    }

    /// The public key.
    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// `dk`.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let v = self.public.variant;
        let mut out = Zeroizing::new(Vec::with_capacity(v.private_key_bytes()));
        encode_vector12(&mut out, &self.s);
        out.extend_from_slice(&self.public.encode());
        out.extend_from_slice(&self.public.hash);
        out.extend_from_slice(self.z.as_slice());
        out
    }

    /// The seed `d || z`, if the key has `d`.
    pub fn seed(&self) -> Option<Zeroizing<[u8; SEED_BYTES]>> {
        let d = self.d.as_ref()?;
        let mut out = Zeroizing::new([0u8; SEED_BYTES]);
        let (a, b) = out.split_at_mut(RANDOM_BYTES);
        a.copy_from_slice(d.as_slice());
        b.copy_from_slice(self.z.as_slice());
        Some(out)
    }

    /// Forgets `d`.
    pub fn forget_seed(&mut self) {
        self.d = None;
    }

    /// `K-PKE.Decrypt` (FIPS 203 Algorithm 15) of a ciphertext of the right length.
    fn decrypt(&self, c: &[u8]) -> Zeroizing<[u8; 32]> {
        let v = self.public.variant;
        let (c1, c2) = c.split_at(v.u_bytes().min(c.len()));
        let du = usize::try_from(v.du()).unwrap_or(0);
        let mut w = Zeroizing::new([0u16; N]);
        for (chunk, si) in c1.chunks_exact(du.wrapping_mul(32)).zip(self.s.iter()) {
            let mut u = decode(chunk, v.du());
            for x in u.iter_mut() {
                *x = decompress(*x, v.du());
            }
            ntt(&mut u);
            multiply_add(&mut w, si, &u);
        }
        inverse_ntt(&mut w);
        let mut m = decode(c2, v.dv());
        for x in m.iter_mut() {
            *x = decompress(*x, v.dv());
        }
        poly_sub(&mut m, &w);
        for x in m.iter_mut() {
            *x = compress(*x, 1);
        }
        let mut out = Vec::with_capacity(32);
        encode(&mut out, &m, 1);
        m.zeroize();
        let mut r = Zeroizing::new([0u8; 32]);
        r.copy_from_slice(out.get(..32).unwrap_or(&[0; 32]));
        out.zeroize();
        r
    }

    /// `ML-KEM.Decaps_internal` (FIPS 203 Algorithm 18): the shared secret, or the implicit
    /// rejection secret `J(z || c)` for a ciphertext that doesn't re-encrypt to itself; `None`
    /// for a ciphertext of the wrong length (or a failed hash).
    pub fn decapsulate(&self, c: &[u8]) -> Option<Zeroizing<[u8; SHARED_SECRET_BYTES]>> {
        crate::dit::with(|| self.decapsulate_dit(c))
    }

    /// [`PrivateKey::decapsulate`]'s work.
    fn decapsulate_dit(&self, c: &[u8]) -> Option<Zeroizing<[u8; SHARED_SECRET_BYTES]>> {
        if c.len() != self.public.variant.ciphertext_bytes() {
            return None;
        }
        let mut rejection = Zeroizing::new([0u8; 32]);
        digest(
            Algorithm::Shake256,
            &[self.z.as_slice(), c],
            rejection.as_mut_slice(),
        )?;
        let m = self.decrypt(c);
        let kr = g(&[m.as_slice(), &self.public.hash])?;
        let (key, r) = kr.split_at(SHARED_SECRET_BYTES);
        let r = Zeroizing::new(<[u8; 32]>::try_from(r).ok()?);
        let Some(again) = self.public.encrypt(&m, &r) else {
            return Some(rejection);
        };
        // 0xff when the ciphertexts are equal, else 0, without branching on the difference.
        let diff = again.iter().zip(c).fold(0u8, |acc, (a, b)| acc | (a ^ b));
        let equal = low8(u32::from(diff).wrapping_sub(1) >> 8);
        let mut out = Zeroizing::new([0u8; 32]);
        for ((o, k), j) in out.iter_mut().zip(key).zip(rejection.iter()) {
            *o = (k & equal) | (j & !equal);
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic() {
        for x in [
            0u32,
            1,
            3328,
            3329,
            3330,
            6657,
            3328 * 3328,
            3329 + 2 * 3329 * 3329 - 1,
        ] {
            assert_eq!(u32::from(reduce(x)), x % 3329, "{x}");
        }
        for d in [1u32, 4, 5, 10, 11] {
            for x in 0..3329u16 {
                // round(2^d x / q) mod 2^d, exactly.
                let exact = ((u32::from(x) << d) * 2 + 3329) / (2 * 3329) % (1 << d);
                assert_eq!(u32::from(compress(x, d)), exact, "compress {x} {d}");
            }
            for y in 0..(1u16 << d) {
                let exact = (u32::from(y) * 3329 * 2 + (1 << d)) / (2 << d);
                assert_eq!(u32::from(decompress(y, d)), exact, "decompress {y} {d}");
            }
        }
        let mut f: Poly = core::array::from_fn(|i| u16::try_from(i * 13 % 3329).unwrap());
        let g = f;
        ntt(&mut f);
        inverse_ntt(&mut f);
        assert_eq!(f, g);
    }

    #[test]
    fn round_trips() {
        for v in [Variant::MlKem512, Variant::MlKem768, Variant::MlKem1024] {
            let seed: [u8; 64] = core::array::from_fn(|i| u8::try_from(i).unwrap());
            let k = PrivateKey::generate(v, &seed).unwrap();
            let ek = k.public().encode();
            let dk = k.encode();
            assert_eq!(ek.len(), v.public_key_bytes());
            assert_eq!(dk.len(), v.private_key_bytes());
            let p = PublicKey::parse(v, &ek).unwrap();
            let k2 = PrivateKey::parse(v, &dk).unwrap();
            assert_eq!(k2.encode().as_slice(), dk.as_slice());
            assert_eq!(k.seed().unwrap().as_slice(), seed.as_slice());
            assert!(k2.seed().is_none());
            let (c, key) = p.encapsulate(&[7; 32]).unwrap();
            assert_eq!(c.len(), v.ciphertext_bytes());
            assert_eq!(k2.decapsulate(&c).unwrap(), key);
            let mut bad = c.clone();
            bad[0] ^= 1;
            let rejected = k2.decapsulate(&bad).unwrap();
            assert_ne!(rejected, key);
            assert!(k2.decapsulate(&c[1..]).is_none());
            // A coefficient of q in t, and a changed H(ek).
            let mut ek2 = ek.clone();
            ek2[0] = 0x01;
            ek2[1] = 0x0d;
            assert_eq!(
                PublicKey::parse(v, &ek2).err(),
                Some(Error::InvalidPublicVector)
            );
            let mut dk2 = dk.to_vec();
            let n = dk2.len();
            dk2[n - 33] ^= 1;
            assert_eq!(PrivateKey::parse(v, &dk2).err(), Some(Error::HashMismatch));
            dk2[n - 33] ^= 1;
            dk2[0] = 0xff;
            dk2[1] = 0xff;
            assert_eq!(
                PrivateKey::parse(v, &dk2).err(),
                Some(Error::InvalidPrivateVector)
            );
        }
    }

    fn sha256_hex(data: &[u8]) -> String {
        use sha2::Digest;
        sha2::Sha256::digest(data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Against the reference OpenSSL: keys from the seed 00..3f, an encapsulation with the
    /// entropy 40..5f, and the rejection secret of the ciphertext with octet 5 changed (SHA-256
    /// of each).
    #[test]
    fn matches_the_reference() {
        let cases = [
            (
                Variant::MlKem512,
                "3ae268dccc5456ac0d0f9b39257dc48fe081383b97c400512d712b739762daee",
                "17fb29b8c4baf74fb81eea15ffd583b3e37f5a5b8dcf6db96c72c3b3751d6f17",
                "81efe667826848514dcae46fc10cfd34f7b95ed6900e094f727c9e7cccc34df2",
                "10f3aedb1a3440f36128242e3f158ea8503f9e3b74e18e253f60c8ad0e20cac8",
                "4607603369058e947311def810df9717daf19bafe47b0262f2c8dccca10514dc",
            ),
            (
                Variant::MlKem768,
                "0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9",
                "dac268bde6a8dd238e9887117d6b664e7a7a9350ad6b7c08a948e504809572a5",
                "dbf4e9aa48b078ad46ec1c9c47bda8c2d2fec9d0e7a21bd48d2238a2abedb856",
                "3211693eed5183e918a272986290fdf7419bcae0f2f648533dcfb290ca670c19",
                "a2734f0c2121a844b9f84943f33b457607eaec235c0ca4960c6bc638bc5a9e24",
            ),
            (
                Variant::MlKem1024,
                "c7b8fa0aa471d5ae18922d6ccad5b31e1d84f92ae723abfd13747018740a8530",
                "3a2a676c5a242ee683cb6097c8f3e64fbef4d90267f9250ec2beab8f99621fad",
                "7c89743960f7c3d17bb69572e49de14fe0990c9113a0706963a8f4c7b39afcdf",
                "0bf615778a6c71e8915a2ec482a0f5a24dbdcd15ddaa55e3c0d7c5df7a4f3910",
                "f3bcee430461fc81d703c31e8370535890d8345fc6451b841835c29809e9d155",
            ),
        ];
        let seed: [u8; 64] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        let entropy: [u8; 32] = core::array::from_fn(|i| u8::try_from(64 + i).unwrap());
        for (v, ek, dk, ct, ss, rej) in cases {
            let k = PrivateKey::generate(v, &seed).unwrap();
            assert_eq!(sha256_hex(&k.public().encode()), ek, "{v:?} ek");
            assert_eq!(sha256_hex(&k.encode()), dk, "{v:?} dk");
            let (mut c, key) = k.public().encapsulate(&entropy).unwrap();
            assert_eq!(sha256_hex(&c), ct, "{v:?} ct");
            assert_eq!(sha256_hex(key.as_slice()), ss, "{v:?} ss");
            c[5] ^= 1;
            assert_eq!(
                sha256_hex(k.decapsulate(&c).unwrap().as_slice()),
                rej,
                "{v:?} rej"
            );
        }
    }
}
