//! RSA key generation and validation (`rsa_gen.c`, `rsa_sp800_56b_gen.c`,
//! `bn_rsa_fips186_4.c`, `rsa_chk.c`, `rsa_sp800_56b_check.c`).
//!
//! Two-prime keys of 2048 bits or more with a public exponent over 16 bits come from FIPS
//! 186-4's probable primes with auxiliary primes (B.3.6) and SP 800-56B's derivation; the
//! others (smaller, multi-prime, or with a small exponent) from OpenSSL's older generator,
//! which balances the primes' sizes so the modulus has exactly the bits asked for.
//!
//! Every random number is drawn as OpenSSL draws it, from the same generator, in the same
//! order and size, and the progress callback sees the same events, so a known generator gives
//! the reference's key. Validation runs OpenSSL's checks in its order with its errors; the
//! arithmetic whose failures OpenSSL reports (a division by zero, a missing inverse) goes
//! through the exported functions, so their errors are the reference's too.

use core::ffi::c_int;
use core::ptr;

use rustyssl_abi::{
    BIGNUM, BN_CTX, BN_GENCB, BN_R_NO_PRIME_CANDIDATE, BN_RAND_BOTTOM_ODD, BN_RAND_TOP_ONE,
    ERR_LIB_BN, ERR_LIB_RSA, ERR_R_BN_LIB, OPENSSL_RSA_MAX_MODULUS_BITS, OSSL_LIB_CTX,
    RSA_DEFAULT_PRIME_NUM, RSA_R_BAD_E_VALUE, RSA_R_D_E_NOT_CONGRUENT_TO_1,
    RSA_R_DMP1_NOT_CONGRUENT_TO_D, RSA_R_DMQ1_NOT_CONGRUENT_TO_D, RSA_R_INVALID_MODULUS,
    RSA_R_INVALID_MULTI_PRIME_KEY, RSA_R_IQMP_NOT_INVERSE_OF_Q, RSA_R_KEY_PRIME_NUM_INVALID,
    RSA_R_KEY_SIZE_TOO_SMALL, RSA_R_MODULUS_TOO_LARGE, RSA_R_MP_COEFFICIENT_NOT_INVERSE_OF_R,
    RSA_R_MP_EXPONENT_NOT_CONGRUENT_TO_D, RSA_R_MP_R_NOT_PRIME, RSA_R_N_DOES_NOT_EQUAL_P_Q,
    RSA_R_N_DOES_NOT_EQUAL_PRODUCT_OF_PRIMES, RSA_R_P_NOT_PRIME, RSA_R_PAIRWISE_TEST_FAILURE,
    RSA_R_PUB_EXPONENT_OUT_OF_RANGE, RSA_R_Q_NOT_PRIME, RSA_R_VALUE_MISSING,
};
use rustyssl_crypto::bn::prime::PRIMES;
use rustyssl_crypto::bn::{self as core_bn, BigNum, Endian};
use rustyssl_crypto::rsa::{ExtraPrime, Key};

use crate::bn::arith::BN_div;
use crate::bn::ctx::{BN_CTX_free, BN_CTX_new_ex};
use crate::bn::modular::{BN_mod_inverse, BN_mod_mul};
use crate::bn::prime::{
    BN_check_prime, Callback, Status, call, gencb, generate, is_prime_int, miller_rabin_status,
};
use crate::bn::rand::{BN_priv_rand_ex, BN_priv_rand_range_ex};
use crate::bn::{BN_free, new_bignum, value};
use crate::err;
use crate::rand_lib::RAND_get0_private;

/// `RSA_MIN_MODULUS_BITS` (`crypto/rsa/rsa_local.h`).
pub(crate) const MIN_MODULUS_BITS: usize = 512;

/// `RSA_FIPS1864_MIN_KEYGEN_KEYSIZE`.
const FIPS1864_MIN_KEYGEN_KEYSIZE: usize = 2048;

/// `ossl_bn_inv_sqrt_2`: ⌈2^256 / √2⌉, the low end of a FIPS 186-4 prime's range.
/// Big-endian; checked in the tests: its square is over 2^511, and its predecessor's isn't.
const INV_SQRT_2: [u8; 32] = [
    0xb5, 0x04, 0xf3, 0x33, 0xf9, 0xde, 0x64, 0x84, 0x59, 0x7d, 0x89, 0xb3, 0x75, 0x4a, 0xbe, 0x9f,
    0x1d, 0x6f, 0x60, 0xba, 0x89, 0x3b, 0xa8, 0x4c, 0xed, 0x17, 0xac, 0x85, 0x83, 0x33, 0x99, 0x16,
];

/// `ossl_bn_inv_sqrt_2` as a number.
fn inv_sqrt_2() -> BigNum {
    BigNum::from_bin(&INV_SQRT_2, Endian::Big, false).unwrap_or_default()
}

/// `ossl_bn_get0_small_factors`: the product of the primes from 3 to 751 (SP 800-89 5.3.3).
fn small_factors() -> BigNum {
    let mut v = BigNum::one();
    for &p in PRIMES.iter().skip(1).take_while(|&&p| p <= 751) {
        // The product fits: 1,037 bits.
        let _ = v.mul_word(p.into());
    }
    v
}

/// A `BIGNUM` of ours, freed when dropped, for the exported functions.
struct Bn(*mut BIGNUM);

impl Bn {
    fn new(v: &BigNum) -> Self {
        Bn(new_bignum(v.clone(), false))
    }

    fn zero() -> Self {
        Self::new(&BigNum::zero())
    }

    fn get(&self) -> BigNum {
        // SAFETY: ours, live until dropped.
        unsafe { value(self.0) }.unwrap_or_default()
    }
}

impl Drop for Bn {
    fn drop(&mut self) {
        // SAFETY: ours to free.
        unsafe { BN_free(self.0) };
    }
}

/// A `BN_CTX` of the key's library context (where the random numbers come from) and the
/// progress callback.
pub(crate) struct Env {
    ctx: *mut BN_CTX,
    cb: Callback,
}

impl Env {
    /// A context for `libctx` reporting to `cb` (NULL for none), or `None` if it can't be
    /// made.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `cb` is NULL or a live `BN_GENCB`.
    pub(crate) unsafe fn new(libctx: *mut OSSL_LIB_CTX, cb: *mut BN_GENCB) -> Option<Self> {
        // SAFETY: the caller's guarantee.
        let ctx = unsafe { BN_CTX_new_ex(libctx) };
        (!ctx.is_null()).then_some(Env { ctx, cb: gencb(cb) })
    }

    /// `BN_GENCB_call`: whether to go on.
    fn call(&self, a: c_int, b: c_int) -> bool {
        // SAFETY: the callback this was made with, live for its life.
        (unsafe { call(self.cb, a, b) }) != 0
    }

    /// `BN_priv_rand_ex(bits, top, bottom)`.
    fn rand_bits(&self, bits: usize, top: c_int, bottom: c_int) -> Option<BigNum> {
        let r = Bn::zero();
        let bits = c_int::try_from(bits).ok()?;
        // SAFETY: ours; this context.
        (unsafe { BN_priv_rand_ex(r.0, bits, top, bottom, 0, self.ctx) } == 1).then(|| r.get())
    }

    /// `BN_priv_rand_range_ex(range)`.
    fn rand_range(&self, range: &BigNum) -> Option<BigNum> {
        let (r, range) = (Bn::zero(), Bn::new(range));
        // SAFETY: ours; this context.
        (unsafe { BN_priv_rand_range_ex(r.0, range.0, 0, self.ctx) } == 1).then(|| r.get())
    }

    /// `ossl_bn_check_generated_prime`: trial division and `rounds` rounds of Miller-Rabin;
    /// 1 probably prime, 0 composite, -1 failure.
    fn check_generated_prime(&self, w: &BigNum, rounds: c_int) -> c_int {
        // SAFETY: this context and callback.
        unsafe { is_prime_int(w, rounds, self.ctx, true, self.cb) }
    }

    /// `BN_check_prime` (with no callback, as validation calls it): 1, 0, or -1.
    fn check_prime(&self, w: &BigNum) -> c_int {
        let w = Bn::new(w);
        // SAFETY: ours; this context.
        unsafe { BN_check_prime(w.0, self.ctx, ptr::null_mut()) }
    }

    /// `BN_generate_prime_ex2(bits, 0, NULL, NULL)`.
    fn generate_prime(&self, bits: usize) -> Option<BigNum> {
        let r = Bn::zero();
        let bits = c_int::try_from(bits).ok()?;
        // SAFETY: ours; this context and callback.
        (unsafe {
            generate(
                r.0,
                bits,
                false,
                ptr::null(),
                ptr::null(),
                self.cb,
                self.ctx,
            )
        } == 1)
            .then(|| r.get())
    }

    /// `BN_mod_inverse(a, n)`, raising its errors.
    fn mod_inverse(&self, a: &BigNum, n: &BigNum) -> Option<BigNum> {
        let (r, a, n) = (Bn::zero(), Bn::new(a), Bn::new(n));
        // SAFETY: ours; this context.
        (!unsafe { BN_mod_inverse(r.0, a.0, n.0, self.ctx) }.is_null()).then(|| r.get())
    }

    /// `BN_div(a, d)`: the quotient and remainder, raising its errors.
    fn div(&self, a: &BigNum, d: &BigNum) -> Option<(BigNum, BigNum)> {
        let (q, r, a, d) = (Bn::zero(), Bn::zero(), Bn::new(a), Bn::new(d));
        // SAFETY: ours; this context.
        (unsafe { BN_div(q.0, r.0, a.0, d.0, self.ctx) } == 1).then(|| (q.get(), r.get()))
    }

    /// `BN_mod_mul(a, b, m)`, raising its errors.
    fn mod_mul(&self, a: &BigNum, b: &BigNum, m: &BigNum) -> Option<BigNum> {
        let (r, a, b, m) = (Bn::zero(), Bn::new(a), Bn::new(b), Bn::new(m));
        // SAFETY: ours; this context.
        (unsafe { BN_mod_mul(r.0, a.0, b.0, m.0, self.ctx) } == 1).then(|| r.get())
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        // SAFETY: ours to free.
        unsafe { BN_CTX_free(self.ctx) };
    }
}

/// `a - 1`.
fn minus_one(a: &BigNum) -> BigNum {
    let mut v = a.clone();
    let _ = v.sub_word(1);
    v
}

/// `BN_gcd`: `gcd(|a|, |b|)`, zero only for two zeros.
fn gcd(a: &BigNum, b: &BigNum) -> BigNum {
    match (a.is_zero(), b.is_zero()) {
        (true, _) => b.abs(),
        (_, true) => a.abs(),
        _ => core_bn::ct::gcd(a, b).0,
    }
}

/// `a * b`.
fn mul(a: &BigNum, b: &BigNum) -> BigNum {
    core_bn::mul(a, b).unwrap_or_default()
}

/// The inverse of `a` modulo `m`, as `BN_mod_inverse` (reducing `a` first).
fn inverse(a: &BigNum, m: &BigNum) -> Option<BigNum> {
    if m.is_zero() || m.is_one() {
        return None;
    }
    core_bn::ct::inverse(&core_bn::nnmod(a, m).ok()?, m)
}

/// `ossl_rsa_check_public_exponent` (outside FIPS): odd and over 1.
pub(crate) fn check_public_exponent(e: &BigNum) -> bool {
    e.is_odd() && core_bn::cmp(e, &BigNum::one()).is_gt()
}

/// `ossl_rsa_multip_cap`: the most primes a key of `bits` may have.
pub(crate) fn multip_cap(bits: usize) -> usize {
    match bits {
        ..1024 => 2,
        1024..4096 => 3,
        4096..8192 => 4,
        _ => 5,
    }
}

/// `ossl_rsa_multiprime_derive` and SP 800-56B's derivation: the exponents and coefficients
/// for `factors` from `d` (and `e`, which the multi-prime case checks against `p - 1`).
pub(crate) fn derive_crt(
    e: &BigNum,
    d: &BigNum,
    factors: &[BigNum],
) -> Option<(Vec<BigNum>, Vec<BigNum>)> {
    let (p, q) = (factors.first()?, factors.get(1)?);
    if factors.len() > 2 {
        // OpenSSL inverts p - 1 modulo e first, failing if it can't.
        inverse(&minus_one(p), e)?;
    }
    let mut exps = Vec::new();
    for f in factors {
        exps.push(core_bn::nnmod(d, &minus_one(f)).ok()?);
    }
    let mut coeffs = vec![inverse(q, p)?];
    let mut pp = mul(p, q);
    for f in factors.get(2..)? {
        coeffs.push(inverse(&pp, f)?);
        pp = mul(&pp, f);
    }
    Some((exps, coeffs))
}

/// FIPS 186-5's Miller-Rabin rounds for the auxiliary primes, their minimum size, and the
/// most their sizes may sum to; and the rounds for the primes (`bn_rsa_fips186_5_*`).
fn aux_prime_mr_rounds(nbits: usize) -> c_int {
    match nbits {
        4096.. => 44,
        3072.. => 41,
        2048.. => 38,
        _ => 0,
    }
}

fn prime_mr_rounds(nbits: usize) -> c_int {
    match nbits {
        3072.. => 4,
        2048.. => 5,
        _ => 0,
    }
}

fn aux_prime_min_size(nbits: usize) -> usize {
    match nbits {
        4096.. => 201,
        3072.. => 171,
        2048.. => 141,
        _ => 0,
    }
}

fn aux_prime_max_sum_size(nbits: usize) -> usize {
    match nbits {
        4096.. => 2030,
        3072.. => 1518,
        2048.. => 1007,
        _ => 0,
    }
}

/// `bn_rsa_fips186_4_find_aux_prob_prime`: the first probable prime from `xp1` up (by twos).
fn find_aux_prob_prime(env: &Env, xp1: &BigNum, rounds: c_int) -> Option<BigNum> {
    let mut p1 = xp1.clone();
    let mut i: c_int = 0;
    loop {
        i = i.saturating_add(1);
        // OpenSSL ignores the callback's answer here.
        env.call(0, i);
        match env.check_generated_prime(&p1, rounds) {
            1.. => break,
            0 => p1.add_word(2).ok()?,
            _ => return None,
        }
    }
    env.call(2, i);
    Some(p1)
}

/// `ossl_bn_rsa_fips186_4_derive_prime` with a random X: the probable prime Y (and X) of
/// `nlen / 2` bits with `Y - 1` coprime to `e`, `Y ≡ 1 (mod 2 r1)`, and `Y ≡ -1 (mod r2)`.
fn derive_prime(
    env: &Env,
    r1: &BigNum,
    r2: &BigNum,
    nlen: usize,
    e: &BigNum,
) -> Option<(BigNum, BigNum)> {
    const F: &str = "ossl_bn_rsa_fips186_4_derive_prime";
    let bits = nlen >> 1;
    let s2 = inv_sqrt_2();
    let base = core_bn::lshift(&s2, bits.checked_sub(s2.num_bits())?).ok()?;
    let range = core_bn::sub(&core_bn::lshift(&BigNum::one(), bits).ok()?, &base).ok()?;
    let r1x2 = core_bn::lshift1(r1).ok()?;
    // R = (r2^-1 mod 2 r1) r2 - ((2 r1)^-1 mod r2) 2 r1, made positive mod 2 r1 r2.
    let tmp = mul(&inverse(&r1x2, r2)?, &r1x2);
    let mut big_r = core_bn::sub(&mul(&inverse(r2, &r1x2)?, r2), &tmp).ok()?;
    let r1r2x2 = mul(&r1x2, r2);
    if big_r.is_negative() {
        big_r = core_bn::add(&big_r, &r1r2x2).ok()?;
    }
    let rounds = prime_mr_rounds(nlen);
    let imax = bits.saturating_mul(20);
    loop {
        let x = core_bn::add(&env.rand_range(&range)?, &base).ok()?;
        let diff = core_bn::sub(&big_r, &x).ok()?;
        let mut y = core_bn::add(&core_bn::nnmod(&diff, &r1r2x2).ok()?, &x).ok()?;
        let mut i = 0usize;
        loop {
            if y.num_bits() > bits {
                // A random X: back to step 3.
                break;
            }
            env.call(0, 2);
            if gcd(&minus_one(&y), e).is_one() {
                match env.check_generated_prime(&y, rounds) {
                    1.. => {
                        env.call(3, 0);
                        return Some((y, x));
                    }
                    0 => {}
                    _ => return None,
                }
            }
            i = i.saturating_add(1);
            if i >= imax {
                err::raise(ERR_LIB_BN, BN_R_NO_PRIME_CANDIDATE, F);
                return None;
            }
            y = core_bn::add(&y, &r1r2x2).ok()?;
        }
    }
}

/// `ossl_bn_rsa_fips186_4_gen_prob_primes` with random inputs: a prime and its X.
fn gen_prob_prime(env: &Env, nlen: usize, e: &BigNum) -> Option<(BigNum, BigNum)> {
    let bitlen = aux_prime_min_size(nlen);
    if bitlen == 0 {
        return None;
    }
    let rounds = aux_prime_mr_rounds(nlen);
    let xp1 = env.rand_bits(bitlen, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD)?;
    let xp2 = env.rand_bits(bitlen, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD)?;
    let p1 = find_aux_prob_prime(env, &xp1, rounds)?;
    let p2 = find_aux_prob_prime(env, &xp2, rounds)?;
    if p1.num_bits().saturating_add(p2.num_bits()) > aux_prime_max_sum_size(nlen) {
        return None;
    }
    derive_prime(env, &p1, &p2, nlen, e)
}

/// `ossl_rsa_check_pminusq_diff`: whether `|p - q| - 1` has more than `nbits / 2 - 100`
/// bits (false for p = q).
fn pminusq_diff_ok(p: &BigNum, q: &BigNum, nbits: usize) -> bool {
    let mut diff = core_bn::sub(p, q).unwrap_or_default().abs();
    if diff.is_zero() {
        return false;
    }
    let _ = diff.sub_word(1);
    // `(nbits >> 1) - 100` as the C's int: negative for small keys, which any diff passes.
    let bitlen = i64::try_from(nbits >> 1)
        .unwrap_or(i64::MAX)
        .saturating_sub(100);
    i64::try_from(diff.num_bits()).unwrap_or(i64::MAX) > bitlen
}

/// `ossl_rsa_fips186_4_gen_prob_primes`: p and q, far enough apart.
fn fips186_4_primes(env: &Env, nbits: usize, e: &BigNum) -> Option<(BigNum, BigNum)> {
    const F: &str = "ossl_rsa_fips186_4_gen_prob_primes";
    if nbits < FIPS1864_MIN_KEYGEN_KEYSIZE {
        err::raise(ERR_LIB_RSA, RSA_R_KEY_SIZE_TOO_SMALL, F);
        return None;
    }
    if !check_public_exponent(e) {
        err::raise(ERR_LIB_RSA, RSA_R_PUB_EXPONENT_OUT_OF_RANGE, F);
        return None;
    }
    let (p, xp) = gen_prob_prime(env, nbits, e)?;
    loop {
        let (q, xq) = gen_prob_prime(env, nbits, e)?;
        if pminusq_diff_ok(&xp, &xq, nbits) && pminusq_diff_ok(&p, &q, nbits) {
            return Some((p, q));
        }
    }
}

/// `ossl_rsa_sp800_56b_derive_params_from_pq` for a generated key: `Ok(None)` when d is too
/// small (try again), `Err` on a failure.
fn derive_params_from_pq(
    p: &BigNum,
    q: &BigNum,
    e: &BigNum,
    nbits: usize,
) -> Result<Option<Key>, ()> {
    let (p1, q1) = (minus_one(p), minus_one(q));
    let lcm = core_bn::div_rem(&mul(&p1, &q1), &gcd(&p1, &q1))
        .map_err(|_| ())?
        .0;
    let d = inverse(e, &lcm).ok_or(())?;
    if d.num_bits() <= nbits >> 1 {
        return Ok(None);
    }
    let mut key = Key::new();
    key.n = Some(mul(p, q));
    key.dmp1 = Some(core_bn::nnmod(&d, &p1).map_err(|_| ())?);
    key.dmq1 = Some(core_bn::nnmod(&d, &q1).map_err(|_| ())?);
    key.iqmp = Some(inverse(q, p).ok_or(())?);
    key.e = Some(e.clone());
    key.d = Some(d);
    key.p = Some(p.clone());
    key.q = Some(q.clone());
    Ok(Some(key))
}

/// `ossl_rsa_sp800_56b_pairwise_test`: 2^(e d) mod n is 2.
fn pairwise_test(key: &Key) -> bool {
    let (Some(n), Some(e), Some(d)) = (&key.n, &key.e, &key.d) else {
        return false;
    };
    let two = BigNum::from_word(2);
    let ok = core_bn::modular::exp_mod(&two, e, n)
        .and_then(|t| core_bn::modular::exp_mod(&t, d, n))
        .is_ok_and(|t| core_bn::cmp(&t, &two).is_eq());
    if !ok {
        err::raise(
            ERR_LIB_RSA,
            RSA_R_PAIRWISE_TEST_FAILURE,
            "ossl_rsa_sp800_56b_pairwise_test",
        );
    }
    ok
}

/// `ossl_rsa_sp800_56b_generate_key`.
///
/// # Safety
/// `libctx` is NULL or a live library context.
unsafe fn sp800_56b_generate(
    env: &Env,
    libctx: *mut OSSL_LIB_CTX,
    nbits: usize,
    e: &BigNum,
) -> Option<Key> {
    // `rsa_validate_rng_strength` (outside FIPS, only that there's a generator).
    // SAFETY: the caller's guarantee.
    if unsafe { RAND_get0_private(libctx) }.is_null() {
        return None;
    }
    loop {
        let (mut p, mut q) = fips186_4_primes(env, nbits, e)?;
        if core_bn::cmp(&p, &q).is_lt() {
            core::mem::swap(&mut p, &mut q);
        }
        match derive_params_from_pq(&p, &q, e, nbits) {
            Ok(Some(key)) => return pairwise_test(&key).then_some(key),
            Ok(None) => {}
            Err(()) => return None,
        }
    }
}

/// `rsa_multiprime_keygen`'s generation, after its checks: `None` on a failure (the caller
/// raises `ERR_R_BN_LIB`).
fn multiprime_generate(env: &Env, bits: usize, primes: usize, e: &BigNum) -> Option<Key> {
    // The primes' sizes: as even as can be, the first ones a bit longer.
    let (quo, rmd) = (bits / primes, bits % primes);
    let bitsr: Vec<usize> = (0..primes).map(|i| quo + usize::from(i < rmd)).collect();
    let mut factors: Vec<BigNum> = Vec::new();
    let mut n = BigNum::zero();
    let mut bitse = 0usize;
    let mut events: c_int = 0;
    let mut next_event = || {
        let v = events;
        events = events.wrapping_add(1);
        v
    };
    let mut i = 0usize;
    'primes: while i < primes {
        let (mut adj, mut retries) = (0isize, 0);
        loop {
            // redo: a prime unlike the ones before, with p - 1 invertible modulo e.
            let size = bitsr.get(i)?.checked_add_signed(adj)?;
            let prime = loop {
                let prime = env.generate_prime(size)?;
                if factors
                    .iter()
                    .take(i)
                    .any(|f| core_bn::cmp(f, &prime).is_eq())
                {
                    continue;
                }
                if inverse(&minus_one(&prime), e).is_some() {
                    break prime;
                }
                if !env.call(2, next_event()) {
                    return None;
                }
            };
            bitse = bitse.saturating_add(*bitsr.get(i)?);
            if i == 0 {
                if !env.call(3, 0) {
                    return None;
                }
                factors.clear();
                factors.push(prime);
                i = 1;
                continue 'primes;
            }
            let product = if i == 1 {
                mul(factors.first()?, &prime)
            } else {
                mul(&n, &prime)
            };
            // The product's top four bits must be 1001 to 1111.
            let top = core_bn::rshift(&product, bitse.checked_sub(4)?).get_word();
            if !(0x9..=0xf).contains(&top) {
                bitse = bitse.saturating_sub(*bitsr.get(i)?);
                if !env.call(2, next_event()) {
                    return None;
                }
                if primes > 4 {
                    adj += if top < 0x9 { 1 } else { -1 };
                } else if retries == 4 {
                    // Start over from the first prime.
                    i = 0;
                    bitse = 0;
                    factors.clear();
                    continue 'primes;
                }
                retries += 1;
                continue;
            }
            n = product;
            if !env.call(3, c_int::try_from(i).ok()?) {
                return None;
            }
            factors.truncate(i);
            factors.push(prime);
            i += 1;
            continue 'primes;
        }
    }
    if core_bn::cmp(factors.first()?, factors.get(1)?).is_lt() {
        factors.swap(0, 1);
    }
    let mut phi = BigNum::one();
    for f in &factors {
        phi = mul(&phi, &minus_one(f));
    }
    let d = inverse(e, &phi)?;
    let (mut exps, mut coeffs) = derive_crt(e, &d, &factors)?;
    let mut key = Key::new();
    key.n = Some(n);
    key.e = Some(e.clone());
    key.d = Some(d);
    let mut f = factors.into_iter();
    key.p = f.next();
    key.q = f.next();
    let mut x = exps.drain(..2);
    key.dmp1 = x.next();
    key.dmq1 = x.next();
    drop(x);
    key.iqmp = Some(coeffs.remove(0));
    key.extra = f
        .zip(exps)
        .zip(coeffs)
        .map(|((r, d), t)| ExtraPrime { r, d, t })
        .collect();
    key.multi = primes > 2;
    Some(key)
}

/// `rsa_multiprime_keygen`.
fn multiprime_keygen(env: &Env, bits: usize, primes: usize, e: &BigNum) -> Option<Key> {
    const F: &str = "rsa_multiprime_keygen";
    if bits < MIN_MODULUS_BITS {
        err::raise(ERR_LIB_RSA, RSA_R_KEY_SIZE_TOO_SMALL, F);
        return None;
    }
    if !check_public_exponent(e) {
        err::raise(ERR_LIB_RSA, RSA_R_PUB_EXPONENT_OUT_OF_RANGE, F);
        return None;
    }
    let min = usize::try_from(RSA_DEFAULT_PRIME_NUM).unwrap_or(2);
    if primes < min || primes > multip_cap(bits) {
        err::raise(ERR_LIB_RSA, RSA_R_KEY_PRIME_NUM_INVALID, F);
        return None;
    }
    let key = multiprime_generate(env, bits, primes, e);
    if key.is_none() {
        err::raise(ERR_LIB_RSA, ERR_R_BN_LIB, F);
    }
    key
}

/// `rsa_keygen` (outside FIPS, without the pairwise test): a key of `bits` bits and `primes`
/// primes with the public exponent `e`, or `None` with OpenSSL's errors raised.
///
/// # Safety
/// `libctx` is NULL or a live library context; `cb` is NULL or a live `BN_GENCB`.
pub(crate) unsafe fn generate_key(
    libctx: *mut OSSL_LIB_CTX,
    bits: c_int,
    primes: c_int,
    e: &BigNum,
    cb: *mut BN_GENCB,
) -> Option<Key> {
    // SAFETY: the caller's guarantee.
    let env = unsafe { Env::new(libctx, cb) }?;
    // Negative sizes and counts fail the generator's checks, as OpenSSL's ints do.
    let ubits = usize::try_from(bits).unwrap_or(0);
    let uprimes = usize::try_from(primes).unwrap_or(0);
    if primes == 2 && ubits >= FIPS1864_MIN_KEYGEN_KEYSIZE && e.num_bits() > 16 {
        // SAFETY: the caller's guarantee.
        unsafe { sp800_56b_generate(&env, libctx, ubits, e) }
    } else {
        multiprime_keygen(&env, ubits, uprimes, e)
    }
}

/// `ossl_rsa_sp800_56b_check_public` (outside FIPS).
///
/// # Safety
/// `libctx` is NULL or a live library context.
pub(crate) unsafe fn validate_public(libctx: *mut OSSL_LIB_CTX, key: &Key) -> bool {
    const F: &str = "ossl_rsa_sp800_56b_check_public";
    let (Some(n), Some(e)) = (&key.n, &key.e) else {
        return false;
    };
    let nbits = n.num_bits();
    if nbits > usize::try_from(OPENSSL_RSA_MAX_MODULUS_BITS).unwrap_or(usize::MAX) {
        err::raise(ERR_LIB_RSA, RSA_R_MODULUS_TOO_LARGE, F);
        return false;
    }
    let invalid = || {
        err::raise(ERR_LIB_RSA, RSA_R_INVALID_MODULUS, F);
        false
    };
    if !n.is_odd() {
        return invalid();
    }
    if !check_public_exponent(e) {
        err::raise(ERR_LIB_RSA, RSA_R_PUB_EXPONENT_OUT_OF_RANGE, F);
        return false;
    }
    // SAFETY: the caller's guarantee.
    let Some(env) = (unsafe { Env::new(libctx, ptr::null_mut()) }) else {
        return false;
    };
    if !gcd(n, &small_factors()).is_one() {
        return invalid();
    }
    // SAFETY: this context; no callback.
    match unsafe { miller_rabin_status(n, 5, env.ctx, Callback::None, true) } {
        Some(Status::CompositeNotPowerOfPrime) => true,
        Some(Status::CompositeWithFactor) if nbits < MIN_MODULUS_BITS => true,
        _ => invalid(),
    }
}

/// `ossl_rsa_sp800_56b_check_private`: `1 <= d < n` (no error).
pub(crate) fn validate_private(key: &Key) -> bool {
    let (Some(d), Some(n)) = (&key.d, &key.n) else {
        return false;
    };
    core_bn::cmp(d, &BigNum::one()).is_ge() && core_bn::cmp(d, n).is_lt()
}

/// `rsa_validate_keypair_multiprime` (`RSA_check_key_ex` outside FIPS): 1 valid, 0 invalid
/// (each problem raised), -1 on a failure.
///
/// # Safety
/// `libctx` is NULL or a live library context; `cb` is NULL or a live `BN_GENCB`.
pub(crate) unsafe fn validate_keypair(
    libctx: *mut OSSL_LIB_CTX,
    key: &Key,
    cb: *mut BN_GENCB,
) -> c_int {
    const F: &str = "rsa_validate_keypair_multiprime";
    let (Some(p), Some(q), Some(n), Some(e), Some(d)) = (&key.p, &key.q, &key.n, &key.e, &key.d)
    else {
        err::raise(ERR_LIB_RSA, RSA_R_VALUE_MISSING, F);
        return 0;
    };
    let ex = key.extra.len();
    if key.multi && (ex == 0 || ex.saturating_add(2) > multip_cap(n.num_bits())) {
        err::raise(ERR_LIB_RSA, RSA_R_INVALID_MULTI_PRIME_KEY, F);
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let Some(env) = (unsafe { Env::new(libctx, cb) }) else {
        err::raise(ERR_LIB_RSA, ERR_R_BN_LIB, F);
        return -1;
    };
    let mut ret = 1;
    // Each problem is raised and the checks go on; an arithmetic failure ends them (-1,
    // with its errors).
    macro_rules! problem {
        ($reason:expr) => {{
            ret = 0;
            err::raise(ERR_LIB_RSA, $reason, F);
        }};
    }
    macro_rules! or_fail {
        ($v:expr) => {
            match $v {
                Some(v) => v,
                None => return -1,
            }
        };
    }
    if e.is_one() {
        problem!(RSA_R_BAD_E_VALUE);
    }
    if !e.is_odd() {
        problem!(RSA_R_BAD_E_VALUE);
    }
    if env.check_prime(p) != 1 {
        problem!(RSA_R_P_NOT_PRIME);
    }
    if env.check_prime(q) != 1 {
        problem!(RSA_R_Q_NOT_PRIME);
    }
    for x in &key.extra {
        if env.check_prime(&x.r) != 1 {
            problem!(RSA_R_MP_R_NOT_PRIME);
        }
    }
    let mut product = mul(p, q);
    for x in &key.extra {
        product = mul(&product, &x.r);
    }
    if !core_bn::cmp(&product, n).is_eq() {
        problem!(if ex > 0 {
            RSA_R_N_DOES_NOT_EQUAL_PRODUCT_OF_PRIMES
        } else {
            RSA_R_N_DOES_NOT_EQUAL_P_Q
        });
    }
    // m = lcm(p - 1, q - 1, r_i - 1...).
    let (pm1, qm1) = (minus_one(p), minus_one(q));
    let mut m = or_fail!(env.div(&mul(&pm1, &qm1), &gcd(&pm1, &qm1))).0;
    for x in &key.extra {
        let k = minus_one(&x.r);
        let l = mul(&m, &k);
        m = or_fail!(env.div(&l, &gcd(&m, &k))).0;
    }
    if !or_fail!(env.mod_mul(d, e, &m)).is_one() {
        problem!(RSA_R_D_E_NOT_CONGRUENT_TO_1);
    }
    if let (Some(dmp1), Some(dmq1), Some(iqmp)) = (&key.dmp1, &key.dmq1, &key.iqmp) {
        if !core_bn::cmp(&or_fail!(env.div(d, &pm1)).1, dmp1).is_eq() {
            problem!(RSA_R_DMP1_NOT_CONGRUENT_TO_D);
        }
        if !core_bn::cmp(&or_fail!(env.div(d, &qm1)).1, dmq1).is_eq() {
            problem!(RSA_R_DMQ1_NOT_CONGRUENT_TO_D);
        }
        if !core_bn::cmp(&or_fail!(env.mod_inverse(q, p)), iqmp).is_eq() {
            problem!(RSA_R_IQMP_NOT_INVERSE_OF_Q);
        }
    }
    let mut pp = mul(p, q);
    for x in &key.extra {
        if !core_bn::cmp(&or_fail!(env.div(d, &minus_one(&x.r))).1, &x.d).is_eq() {
            problem!(RSA_R_MP_EXPONENT_NOT_CONGRUENT_TO_D);
        }
        if !core_bn::cmp(&or_fail!(env.mod_inverse(&pp, &x.r)), &x.t).is_eq() {
            problem!(RSA_R_MP_COEFFICIENT_NOT_INVERSE_OF_R);
        }
        pp = mul(&pp, &x.r);
    }
    ret
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects, reason = "test arithmetic")]

    use super::*;

    #[test]
    fn inv_sqrt_2_is_the_ceiling() {
        let c = inv_sqrt_2();
        assert_eq!(c.num_bits(), 256);
        let two_511 = core_bn::lshift(&BigNum::one(), 511).unwrap();
        assert!(core_bn::cmp(&core_bn::sqr(&c).unwrap(), &two_511).is_gt());
        let mut c1 = c.clone();
        c1.sub_word(1).unwrap();
        assert!(core_bn::cmp(&core_bn::sqr(&c1).unwrap(), &two_511).is_le());
    }

    #[test]
    fn small_factors_are_the_primes_to_751() {
        // 3 to 751: 132 primes, a 1,037-bit product, divisible by each.
        assert_eq!(
            PRIMES.iter().skip(1).take_while(|&&p| p <= 751).count(),
            132
        );
        let v = small_factors();
        assert_eq!(v.num_bits(), 1037);
        assert_eq!(v.mod_word(751), 0);
        assert_ne!(v.mod_word(2), 0);
    }

    #[test]
    fn pminusq() {
        let a = BigNum::from_word(1 << 20);
        let b = BigNum::from_word(5);
        assert!(!pminusq_diff_ok(&a, &a, 2048));
        assert!(pminusq_diff_ok(&a, &b, 100));
        assert!(!pminusq_diff_ok(&a, &b, 2048));
    }
}
