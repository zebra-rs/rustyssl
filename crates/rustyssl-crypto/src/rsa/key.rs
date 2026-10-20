//! An RSA key and the four operations of OpenSSL's built-in method (`rsa_ossl.c`): public
//! encryption and decryption (signature verification), and private encryption (signing) and
//! decryption, each with its padding.

use super::ct::{self, add, fixed, reduce, sub_mod};
use super::pad;
use super::{
    Entry, Hash, MAX_MODULUS_BITS, MAX_PUBEXP_BITS, Outcome, Padding, Raised, Random, Reason,
    SMALL_MODULUS_BITS, fail, silent,
};
use crate::bn::modular::exp_mod;
use crate::bn::mont::{Montgomery, mul_fixed};
use crate::bn::{self, BigNum, Endian, Limb, Zeroizing};
use std::sync::{Arc, Mutex, PoisonError};

/// `RSA_MAX_PRIME_NUM`: a private operation fails on a multi-prime key of more primes.
pub const MAX_PRIMES: usize = 5;

/// A prime past the first two of a multi-prime key (`RSA_PRIME_INFO`): the prime, its
/// exponent `d mod (r - 1)`, and its CRT coefficient.
#[derive(Clone, Default)]
pub struct ExtraPrime {
    pub r: BigNum,
    pub d: BigNum,
    pub t: BigNum,
}

/// `BN_BLINDING_COUNTER`: a blinding is used this many times (squared between uses), then
/// made again.
const BLINDING_COUNTER: i32 = 32;

/// A key's blinding (`BN_BLINDING`): `a = r^e` and `ai = r^-1` for a random `r`, and how many
/// times they've been used (-1 when fresh).
struct Blind {
    a: BigNum,
    ai: BigNum,
    counter: i32,
}

/// A key's blinding, made at its first private operation and kept, as OpenSSL keeps an
/// `RSA`'s: shared by the key's copies (the snapshots of one key object), new for a new key.
#[derive(Clone, Default)]
pub struct Blinding(Arc<Mutex<Option<Blind>>>);

/// An RSA key: the modulus, the public exponent, and as much of the private key as it has.
/// Any part may be missing, as in OpenSSL's `RSA`; each operation checks what it needs.
#[derive(Clone, Default)]
pub struct Key {
    pub n: Option<BigNum>,
    pub e: Option<BigNum>,
    pub d: Option<BigNum>,
    pub p: Option<BigNum>,
    pub q: Option<BigNum>,
    pub dmp1: Option<BigNum>,
    pub dmq1: Option<BigNum>,
    pub iqmp: Option<BigNum>,
    /// The primes past the second (`RSA_ASN1_VERSION_MULTI` when there are any).
    pub extra: Vec<ExtraPrime>,
    /// Whether the key is a multi-prime one (`version == RSA_ASN1_VERSION_MULTI`).
    pub multi: bool,
    /// Whether private operations are blinded (`RSA_FLAG_NO_BLINDING` clear).
    pub blinding: bool,
    /// The blinding private operations use, once made.
    pub blinding_state: Blinding,
}

/// The number in `from`, big-endian.
fn os2ip(from: &[u8]) -> Option<BigNum> {
    BigNum::from_bin(from, Endian::Big, false).ok()
}

/// `x` in exactly `len` octets, big-endian.
fn i2osp(x: &BigNum, len: usize) -> Option<Zeroizing<Vec<u8>>> {
    x.to_bin(Some(len), Endian::Big, false)
}

impl Key {
    /// A key with blinding on.
    pub fn new() -> Self {
        Self {
            blinding: true,
            ..Self::default()
        }
    }

    /// `RSA_size`: the modulus's length in octets (0 without one).
    pub fn size(&self) -> usize {
        self.n.as_ref().map_or(0, BigNum::num_bytes)
    }

    /// `RSA_bits`.
    pub fn bits(&self) -> usize {
        self.n.as_ref().map_or(0, BigNum::num_bits)
    }

    /// Whether a private operation goes through the CRT (`rsa_ossl_mod_exp`) rather than `d`.
    fn uses_crt(&self) -> bool {
        self.multi
            || (self.p.is_some()
                && self.q.is_some()
                && self.dmp1.is_some()
                && self.dmq1.is_some()
                && self.iqmp.is_some())
    }

    /// The public operations' checks of the key (`rsa_ossl_public_encrypt`'s first three).
    fn check_public(&self) -> Result<(&BigNum, &BigNum), Reason> {
        let (Some(n), Some(e)) = (self.n.as_ref(), self.e.as_ref()) else {
            return Err(Reason::BadEValue);
        };
        if n.num_bits() > MAX_MODULUS_BITS {
            return Err(Reason::ModulusTooLarge);
        }
        if bn::ucmp(n, e).is_le() {
            return Err(Reason::BadEValue);
        }
        if n.num_bits() > SMALL_MODULUS_BITS && e.num_bits() > MAX_PUBEXP_BITS {
            return Err(Reason::BadEValue);
        }
        Ok((n, e))
    }

    /// `f^e mod n` for `f < n` and an odd `n` (the public operations' `BN_MONT_CTX_set` of `n`
    /// fails first for an even one: `BN_mod_inverse`'s `BN_R_NO_INVERSE`).
    fn public_op(n: &BigNum, e: &BigNum, f: &BigNum) -> Option<BigNum> {
        exp_mod(f, e, n).ok()
    }

    /// `BN_BLINDING_create_param`: a random invertible `r` (32 tries after the first), and
    /// `(r^e, r^-1)`.
    fn make_blinding(n: &BigNum, e: &BigNum, rng: &mut Random<'_>) -> Result<(BigNum, BigNum), ()> {
        for _ in 0..=32 {
            let r = bn::rand::rand_range(n, rng).ok_or(())?;
            if let Some(ri) = bn::ct::inverse(&r, n) {
                let a = exp_mod(&r, e, n).map_err(|_| ())?;
                return Ok((a, ri));
            }
        }
        Err(())
    }

    /// `RSA_blinding_on`'s `RSA_setup_blinding`: a fresh blinding now, drawn as the first
    /// private operation would draw it; false if it can't be made (no public exponent, or
    /// no invertible number).
    pub fn new_blinding(&self, rng: &mut Random<'_>) -> bool {
        let (Some(n), Some(e)) = (self.n.as_ref(), self.blinding_exponent()) else {
            return false;
        };
        let Ok((a, ai)) = Self::make_blinding(n, &e, rng) else {
            return false;
        };
        *self
            .blinding_state
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Blind { a, ai, counter: -1 });
        true
    }

    /// Whether the key has made its blinding (`rsa->blinding != NULL`).
    pub fn has_blinding(&self) -> bool {
        self.blinding_state
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    /// `RSA_blinding_off`: the blinding is dropped (made again if blinding is turned on).
    pub fn drop_blinding(&self) {
        *self
            .blinding_state
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// `rsa_get_blinding` and `BN_BLINDING_convert_ex`'s update: the blinding for this
    /// operation, made at the first, squared for the next 31, made again at the 33rd.
    fn next_blinding(
        &self,
        n: &BigNum,
        e: &BigNum,
        rng: &mut Random<'_>,
    ) -> Result<(BigNum, BigNum), ()> {
        let mut state = self
            .blinding_state
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let Some(b) = state.as_mut() else {
            let (a, ai) = Self::make_blinding(n, e, rng)?;
            *state = Some(Blind {
                a: a.clone(),
                ai: ai.clone(),
                counter: 0,
            });
            return Ok((a, ai));
        };
        if b.counter == -1 {
            b.counter = 0;
        } else {
            b.counter = b.counter.saturating_add(1);
            if b.counter == BLINDING_COUNTER {
                b.counter = 0;
                let (a, ai) = Self::make_blinding(n, e, rng)?;
                b.a = a;
                b.ai = ai;
            } else {
                let nl = n.limbs();
                let sq = |x: &BigNum| {
                    let xf = fixed(x, nl.len());
                    BigNum::from_limbs(false, Self::mul_mod(&xf, &xf, nl))
                };
                b.a = sq(&b.a).map_err(|_| ())?;
                b.ai = sq(&b.ai).map_err(|_| ())?;
            }
        }
        Ok((b.a.clone(), b.ai.clone()))
    }

    /// `(a * b) mod m` over fixed lengths, in constant time.
    fn mul_mod(a: &[Limb], b: &[Limb], m: &[Limb]) -> Vec<Limb> {
        reduce(&mul_fixed(a, b), m)
    }

    /// The public exponent for blinding (`RSA_setup_blinding`): `e`, or `d^-1 mod (p-1)(q-1)`.
    fn blinding_exponent(&self) -> Option<BigNum> {
        if let Some(e) = &self.e {
            return Some(e.clone());
        }
        let (d, p, q) = (self.d.as_ref()?, self.p.as_ref()?, self.q.as_ref()?);
        let mut p1 = p.clone();
        p1.sub_word(1).ok()?;
        let mut q1 = q.clone();
        q1.sub_word(1).ok()?;
        let phi = bn::mul(&p1, &q1).ok()?;
        let dr = BigNum::from_limbs(false, reduce(d.limbs(), phi.limbs())).ok()?;
        bn::ct::inverse(&dr, &phi)
    }

    /// The method's `rsa_mod_exp` (`rsa_ossl_mod_exp`): `i^d mod n`, through the CRT when the
    /// key has its numbers, else with `d`; `None` when it can't be computed.
    pub fn mod_exp(&self, i: &BigNum) -> Option<BigNum> {
        crate::dit::with(|| {
            if self.uses_crt() {
                return self.crt(i);
            }
            let (n, d) = (self.n.as_ref()?, self.d.as_ref()?);
            let i = BigNum::from_limbs(false, reduce(i.limbs(), n.limbs())).ok()?;
            Some(Montgomery::new(n).ok()?.exp_consttime(&i, d.limbs()))
        })
    }

    /// `rsa_ossl_mod_exp`: `i^d mod n` through the CRT, checked with the public exponent; `None`
    /// when it can't be computed (OpenSSL raises nothing then).
    fn crt(&self, i: &BigNum) -> Option<BigNum> {
        let n = self.n.as_ref()?;
        if self.multi && (self.extra.is_empty() || self.extra.len() > MAX_PRIMES - 2) {
            return None;
        }
        let (p, q) = (self.p.as_ref()?, self.q.as_ref()?);
        let (dmp1, dmq1, iqmp) = (
            self.dmp1.as_ref()?,
            self.dmq1.as_ref()?,
            self.iqmp.as_ref()?,
        );
        let il = i.limbs();
        let (pl, ql) = (p.limbs(), q.limbs());
        if pl.is_empty() || ql.is_empty() {
            return None;
        }
        let mont_p = Montgomery::new_consttime(p).ok()?;
        let mont_q = Montgomery::new_consttime(q).ok()?;
        let r1 = BigNum::from_limbs(false, reduce(il, pl)).ok()?;
        let m1 = BigNum::from_limbs(false, reduce(il, ql)).ok()?;
        let r0 = mont_p.exp_consttime(&r1, dmp1.limbs());
        let m1 = mont_q.exp_consttime(&m1, dmq1.limbs());
        let mut extras = Vec::with_capacity(self.extra.len());
        for ex in &self.extra {
            let rl = ex.r.limbs();
            if rl.is_empty() {
                return None;
            }
            let mont = Montgomery::new_consttime(&ex.r).ok()?;
            let base = BigNum::from_limbs(false, reduce(il, rl)).ok()?;
            extras.push(mont.exp_consttime(&base, ex.d.limbs()));
        }
        // Garner: r0 = ((r0 - m1) iqmp mod p) q + m1.
        let r0p = fixed(&r0, pl.len());
        let m1p = reduce(m1.limbs(), pl);
        let h = sub_mod(&r0p, &m1p, pl);
        let h = Self::mul_mod(&h, iqmp.limbs(), pl);
        let mut r = add(&mul_fixed(&h, ql), &fixed(&m1, ql.len()));
        // The other primes: r += ((m_i - r) t_i mod r_i) * (p q r_0 ... r_{i-1}).
        let mut pp = mul_fixed(pl, ql);
        for (ex, m) in self.extra.iter().zip(&extras) {
            let rl = ex.r.limbs();
            let rr = reduce(&r, rl);
            let diff = sub_mod(&fixed(m, rl.len()), &rr, rl);
            let t = Self::mul_mod(&diff, ex.t.limbs(), rl);
            r = add(&r, &mul_fixed(&t, &pp));
            pp = mul_fixed(&pp, rl);
        }
        let mut r0 = BigNum::from_limbs(false, r).ok()?;
        // The fault check: r0^e must give i back, or the result is computed again with d.
        if let Some(e) = &self.e {
            let vrfy = exp_mod(&r0, e, n).ok()?;
            let (il, vl) = (fixed(i, n.top()), fixed(&vrfy, n.top()));
            if ct::eq_limbs(&il, &vl) == 0 {
                let d = self.d.as_ref()?;
                let mont_n = Montgomery::new(n).ok()?;
                r0 = mont_n.exp_consttime(i, d.limbs());
            }
        }
        Some(r0)
    }

    /// The private operation on `f < n` (`rsa_ossl_private_encrypt`'s steps 4-7): blinded,
    /// through the CRT or `d`. Its errors, or `Err` with none when the CRT can't run.
    fn private_op(
        &self,
        f: &BigNum,
        rng: &mut Random<'_>,
        func: &'static str,
    ) -> Result<BigNum, Raised> {
        let Some(n) = self.n.as_ref() else {
            return Err(vec![Entry::raised(func, Reason::MissingPrivateKey)]);
        };
        let nl = n.limbs();
        let blind = if self.blinding {
            let Some(e) = self.blinding_exponent() else {
                return Err(vec![
                    Entry::raised("RSA_setup_blinding", Reason::NoPublicExponent),
                    Entry::raised(func, Reason::Internal),
                ]);
            };
            match self.next_blinding(n, &e, rng) {
                Ok(found) => Some(found),
                Err(()) => {
                    return Err(vec![
                        Entry::raised(func, Reason::BnLib),
                        Entry::raised(func, Reason::Internal),
                    ]);
                }
            }
        } else {
            None
        };
        let fb = match &blind {
            Some((a, _)) => Self::mul_mod(&fixed(f, nl.len()), &fixed(a, nl.len()), nl),
            None => fixed(f, nl.len()),
        };
        let Ok(fb) = BigNum::from_limbs(false, fb) else {
            return Err(vec![Entry::raised(func, Reason::BnLib)]);
        };
        let ret = if self.uses_crt() {
            match self.crt(&fb) {
                Some(r) => r,
                None => return Err(Vec::new()),
            }
        } else {
            let Some(d) = self.d.as_ref() else {
                return Err(vec![Entry::raised(func, Reason::MissingPrivateKey)]);
            };
            let Ok(mont) = Montgomery::new(n) else {
                return Err(vec![Entry::raised(func, Reason::BnLib)]);
            };
            mont.exp_consttime(&fb, d.limbs())
        };
        let ret = match &blind {
            Some((_, ai)) => Self::mul_mod(&fixed(&ret, nl.len()), &fixed(ai, nl.len()), nl),
            None => fixed(&ret, nl.len()),
        };
        BigNum::from_limbs(false, ret).map_err(|_| vec![Entry::raised(func, Reason::BnLib)])
    }

    /// `rsa_ossl_public_encrypt`: `from` padded into `to` (the key's size) and raised to `e`.
    /// Returns the length written.
    pub fn public_encrypt(
        &self,
        from: &[u8],
        to: &mut [u8],
        padding: Padding,
        sha1: Option<&dyn Hash>,
        rng: &mut Random<'_>,
    ) -> Outcome<usize> {
        const F: &str = "rsa_ossl_public_encrypt";
        let (n, e) = match self.check_public() {
            Ok(k) => k,
            Err(r) => return fail(F, r),
        };
        let num = n.num_bytes();
        let mut buf = Zeroizing::new(vec![0u8; num]);
        let (r, raised) = match padding {
            Padding::Pkcs1 => pad::add_pkcs1_type2(&mut buf, from, rng),
            Padding::Oaep => match sha1 {
                Some(h) => pad::add_oaep(&mut buf, from, &[], h, h, rng),
                None => silent(),
            },
            Padding::None => pad::add_none(&mut buf, from),
            _ => return fail(F, Reason::UnknownPaddingType),
        };
        if r.is_err() {
            return (Err(()), raised);
        }
        let Some(f) = os2ip(&buf) else {
            return silent();
        };
        if bn::ucmp(&f, n).is_ge() {
            return fail(F, Reason::DataTooLargeForModulus);
        }
        if !n.is_odd() {
            return fail("BN_mod_inverse", Reason::NoInverse);
        }
        let Some(ret) = Self::public_op(n, e, &f) else {
            return silent();
        };
        match (i2osp(&ret, num), to.get_mut(..num)) {
            (Some(out), Some(t)) => {
                t.copy_from_slice(&out);
                (Ok(num), Vec::new())
            }
            _ => silent(),
        }
    }

    /// `rsa_ossl_private_encrypt`: `from` padded into `to` (the key's size) and signed.
    pub fn private_encrypt(
        &self,
        from: &[u8],
        to: &mut [u8],
        padding: Padding,
        rng: &mut Random<'_>,
    ) -> Outcome<usize> {
        crate::dit::with(|| self.private_encrypt_dit(from, to, padding, rng))
    }

    /// [`Key::private_encrypt`]'s work.
    fn private_encrypt_dit(
        &self,
        from: &[u8],
        to: &mut [u8],
        padding: Padding,
        rng: &mut Random<'_>,
    ) -> Outcome<usize> {
        const F: &str = "rsa_ossl_private_encrypt";
        let Some(n) = self.n.as_ref() else {
            return fail(F, Reason::MissingPrivateKey);
        };
        let num = n.num_bytes();
        let mut buf = Zeroizing::new(vec![0u8; num]);
        let (r, raised) = match padding {
            Padding::Pkcs1 => pad::add_pkcs1_type1(&mut buf, from),
            Padding::X931 => pad::add_x931(&mut buf, from),
            Padding::None => pad::add_none(&mut buf, from),
            _ => return fail(F, Reason::UnknownPaddingType),
        };
        if r.is_err() {
            return (Err(()), raised);
        }
        let Some(f) = os2ip(&buf) else {
            return silent();
        };
        if bn::ucmp(&f, n).is_ge() {
            return fail(F, Reason::DataTooLargeForModulus);
        }
        let ret = match self.private_op(&f, rng, F) {
            Ok(r) => r,
            Err(raised) => return (Err(()), raised),
        };
        // X9.31 takes the smaller of the result and n minus it.
        let res = if padding == Padding::X931 {
            match bn::sub(n, &ret) {
                Ok(t) if bn::cmp(&ret, &t).is_gt() => t,
                _ => ret,
            }
        } else {
            ret
        };
        match (i2osp(&res, num), to.get_mut(..num)) {
            (Some(out), Some(t)) => {
                t.copy_from_slice(&out);
                (Ok(num), Vec::new())
            }
            _ => silent(),
        }
    }

    /// `derive_kdk`: implicit rejection's key-derivation key, HMAC-SHA256 under SHA-256 of
    /// `d` (in the key's size) over the ciphertext left-padded to that size.
    fn derive_kdk(
        &self,
        from: &[u8],
        num: usize,
        sha256: Option<&dyn Hash>,
    ) -> Result<Vec<u8>, Raised> {
        const F: &str = "derive_kdk";
        let Some(d) = self.d.as_ref() else {
            return Err(vec![Entry::raised(F, Reason::MissingPrivateKey)]);
        };
        let Some(dd) = i2osp(d, num) else {
            return Err(vec![Entry::raised(F, Reason::Internal)]);
        };
        let Some(h) = sha256 else {
            return Err(vec![Entry::raised(F, Reason::FetchFailed)]);
        };
        let Some(d_hash) = h.digest(&[&dd]) else {
            return Err(vec![Entry::raised(F, Reason::Internal)]);
        };
        let zeros = vec![0u8; num.saturating_sub(from.len())];
        pad::hmac(h, &d_hash, &[&zeros, from])
            .ok_or_else(|| vec![Entry::raised(F, Reason::Internal)])
    }

    /// `rsa_ossl_private_decrypt`: `from` decrypted and unpadded into `to`, which must have
    /// room for the key's size. Returns the length or -1, chosen in constant time, with the
    /// entries to raise (a padding failure's are present on success too, cleared).
    ///
    /// As in OpenSSL, `to` is written only where a padding check passed: on failure its
    /// octets stay as they were.
    pub fn private_decrypt(
        &self,
        from: &[u8],
        to: &mut [u8],
        padding: Padding,
        sha1: Option<&dyn Hash>,
        sha256: Option<&dyn Hash>,
        rng: &mut Random<'_>,
    ) -> (isize, Raised) {
        crate::dit::with(|| self.private_decrypt_dit(from, to, padding, sha1, sha256, rng))
    }

    /// [`Key::private_decrypt`]'s work.
    fn private_decrypt_dit(
        &self,
        from: &[u8],
        to: &mut [u8],
        padding: Padding,
        sha1: Option<&dyn Hash>,
        sha256: Option<&dyn Hash>,
        rng: &mut Random<'_>,
    ) -> (isize, Raised) {
        const F: &str = "rsa_ossl_private_decrypt";
        let Some(n) = self.n.as_ref() else {
            return (-1, vec![Entry::raised(F, Reason::MissingPrivateKey)]);
        };
        let num = n.num_bytes();
        if from.len() > num {
            return (-1, vec![Entry::raised(F, Reason::DataGreaterThanModLen)]);
        }
        if from.is_empty() {
            return (-1, vec![Entry::raised(F, Reason::DataTooSmall)]);
        }
        let Some(f) = os2ip(from) else {
            return (-1, Vec::new());
        };
        if bn::ucmp(&f, n).is_ge() {
            return (-1, vec![Entry::raised(F, Reason::DataTooLargeForModulus)]);
        }
        let ret = match self.private_op(&f, rng, F) {
            Ok(r) => r,
            Err(raised) => return (-1, raised),
        };
        let kdk = if padding == Padding::Pkcs1 {
            match self.derive_kdk(from, num, sha256) {
                Ok(k) => Some(k),
                Err(raised) => return (-1, raised),
            }
        } else {
            None
        };
        let Some(buf) = i2osp(&ret, num) else {
            return (-1, Vec::new());
        };
        let Some(to) = to.get_mut(..num) else {
            return (-1, vec![Entry::raised(F, Reason::Internal)]);
        };
        let (r, mut raised) = match (padding, &kdk) {
            (Padding::Pkcs1NoImplicitReject, _) => pad::check_pkcs1_type2(to, &buf, num),
            (Padding::Pkcs1, Some(kdk)) => match sha256 {
                Some(h) => pad::check_pkcs1_type2_implicit(to, &buf, num, kdk, h),
                None => (-1, vec![Entry::raised(F, Reason::Internal)]),
            },
            (Padding::Oaep, _) => match sha1 {
                Some(h) => pad::check_oaep(to, &buf, num, &[], h, h),
                None => (-1, Vec::new()),
            },
            (Padding::None, _) => {
                to.copy_from_slice(&buf);
                (isize::try_from(num).unwrap_or(-1), Vec::new())
            }
            _ => return (-1, vec![Entry::raised(F, Reason::UnknownPaddingType)]),
        };
        // PADDING_CHECK_FAILED is always pushed, then cleared unless the check failed.
        let ok = u8::from(r >= 0);
        raised.push(Entry {
            func: F,
            reason: Reason::PaddingCheckFailed,
            clear: ok,
        });
        (r, raised)
    }

    /// `rsa_ossl_public_decrypt`: the signature `from` raised to `e` and unpadded into `to`,
    /// which must have room for the key's size.
    pub fn public_decrypt(&self, from: &[u8], to: &mut [u8], padding: Padding) -> Outcome<usize> {
        const F: &str = "rsa_ossl_public_decrypt";
        let (n, e) = match self.check_public() {
            Ok(k) => k,
            Err(r) => return fail(F, r),
        };
        let num = n.num_bytes();
        if from.len() > num {
            return fail(F, Reason::DataGreaterThanModLen);
        }
        let Some(f) = os2ip(from) else {
            return silent();
        };
        if bn::ucmp(&f, n).is_ge() {
            return fail(F, Reason::DataTooLargeForModulus);
        }
        if !n.is_odd() {
            return fail("BN_mod_inverse", Reason::NoInverse);
        }
        let Some(mut ret) = Self::public_op(n, e, &f) else {
            return silent();
        };
        if padding == Padding::X931 && ret.limbs().first().copied().unwrap_or(0) & 0xf != 12 {
            match bn::sub(n, &ret) {
                Ok(t) => ret = t,
                Err(_) => return silent(),
            }
        }
        let Some(buf) = i2osp(&ret, num) else {
            return silent();
        };
        let Some(to) = to.get_mut(..num) else {
            return fail(F, Reason::Internal);
        };
        let (r, mut raised) = match padding {
            Padding::Pkcs1 => pad::check_pkcs1_type1(to, &buf, num),
            Padding::X931 => pad::check_x931(to, &buf, num),
            Padding::None => {
                to.copy_from_slice(&buf);
                (Ok(num), Vec::new())
            }
            _ => return fail(F, Reason::UnknownPaddingType),
        };
        if r.is_err() {
            raised.push(Entry::raised(F, Reason::PaddingCheckFailed));
        }
        (r, raised)
    }
}
