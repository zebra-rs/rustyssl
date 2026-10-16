//! DSA signatures, keys, and parameters (`dsa_sign.c`, `dsa_ossl.c`, `dsa_key.c`,
//! `dsa_gen.c`, `dsa_depr.c`): `DSA_SIG` (the same structure and DER as `ECDSA_SIG`), the
//! built-in method's signing, setup, and verification, the public functions that call a key's
//! method, key generation, and parameter generation (FIPS 186-2 below 2048 bits with a seed of
//! at most 20 octets, else FIPS 186-4).
//!
//! Signing follows OpenSSL's steps and draws its random numbers in the same order: the nonce
//! from `BN_generate_dsa_nonce` over the digest (a random one below q for `DSA_sign_setup`;
//! RFC 6979's for a provider's signature that asks for it, from a key made in a library context),
//! r = (g^k mod p) mod q through the method's `bn_mod_exp` if it has one, k's inverse by
//! Fermat, then a blinding value below 2^(|q|-1) (whose inverse must exist). The signature is
//! computed directly; the blinding protects nothing here, as the arithmetic is constant-time.

use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_void};
use core::ptr;

use rustyssl_abi::{
    BIGNUM, BN_CTX, BN_FLG_CONSTTIME, BN_GENCB, BN_R_CALLED_WITH_EVEN_MODULUS, BN_R_NO_INVERSE,
    BN_RAND_BOTTOM_ANY, BN_RAND_TOP_ANY, DSA, DSA_FLAG_CACHE_MONT_P, DSA_R_BAD_Q_VALUE,
    DSA_R_INVALID_PARAMETERS, DSA_R_MISSING_PARAMETERS, DSA_R_MISSING_PRIVATE_KEY,
    DSA_R_MODULUS_TOO_LARGE, DSA_R_TOO_MANY_RETRIES, DSA_SIG, ECDSA_SIG, ERR_LIB_BN, ERR_LIB_DSA,
    ERR_R_BN_LIB, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, OPENSSL_DSA_MAX_MODULUS_BITS, OSSL_LIB_CTX,
};
use rustyssl_crypto::bn::{self as core_bn, BigNum, Endian};
use rustyssl_crypto::ec::ecdsa as ecdsa_core;

use crate::bn::prime::{BN_GENCB_free, BN_GENCB_new, BN_GENCB_set_old, OldCb};
use crate::bn::{BN_clear_free, BN_free, BN_new, BN_set_flags, new_bignum, store, value};
use crate::dsa::{Dsa, DsaState, dsa};
use crate::dsa_meth::{BnModExpFn, ModExpFn, fns_of, is_default};
use crate::ec::ecdsa::{
    Deterministic, ECDSA_SIG_free, ECDSA_SIG_get0, ECDSA_SIG_new, ECDSA_SIG_set0, d2i_ECDSA_SIG,
    i2d_ECDSA_SIG,
};
use crate::err;
use crate::ffc;
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::rsa_gen::Env;

/// `MIN_DSA_SIGN_QBITS`.
const MIN_SIGN_QBITS: usize = 128;
/// `MAX_DSA_SIGN_RETRIES`.
const MAX_SIGN_RETRIES: u32 = 8;
/// `MIN_STRENGTH` of key generation (outside the FIPS module).
const MIN_STRENGTH: usize = 80;

ffi_export! {
    /// A new, empty signature.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn DSA_SIG_new() -> *mut DSA_SIG
    where failure = ptr::null_mut(), library = ERR_LIB_DSA
    {
        // SAFETY: no preconditions; the same structure.
        unsafe { ECDSA_SIG_new() }.cast()
    }
}

ffi_export! {
    /// Frees a signature and its numbers. NULL does nothing.
    ///
    /// # Safety
    /// `sig` is NULL or a live signature.
    pub unsafe extern "C" fn DSA_SIG_free(sig: *mut DSA_SIG)
    where failure = (), library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee; the same structure.
        unsafe { ECDSA_SIG_free(sig.cast()) };
    }
}

ffi_export! {
    /// The signature's numbers, each through a pointer that isn't NULL.
    ///
    /// # Safety
    /// `sig` is a live signature; `pr` and `ps` are NULL or writable.
    pub unsafe extern "C" fn DSA_SIG_get0(sig: *const DSA_SIG, pr: *mut *const BIGNUM, ps: *mut *const BIGNUM)
    where failure = (), library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee; the same structure.
        unsafe { ECDSA_SIG_get0(sig.cast(), pr, ps) };
    }
}

ffi_export! {
    /// Gives the signature `r` and `s` (both needed), freeing its old ones. 1, or 0.
    ///
    /// # Safety
    /// `sig` is a live signature; `r` and `s` are NULL or live numbers it takes.
    pub unsafe extern "C" fn DSA_SIG_set0(sig: *mut DSA_SIG, r: *mut BIGNUM, s: *mut BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee; the same structure.
        unsafe { ECDSA_SIG_set0(sig.cast(), r, s) }
    }
}

ffi_export! {
    /// The signature's DER (`i2d` conventions); -1 for a signature that can't be encoded.
    ///
    /// # Safety
    /// `sig` is a live signature; `ppout` is NULL or holds NULL or room for the encoding.
    pub unsafe extern "C" fn i2d_DSA_SIG(sig: *const DSA_SIG, ppout: *mut *mut c_uchar) -> c_int
    where failure = -1, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee; the same structure.
        unsafe { i2d_ECDSA_SIG(sig.cast(), ppout) }
    }
}

ffi_export! {
    /// Decodes a signature's DER into `*psig` if given, else a new signature; advances `*ppin`
    /// past it.
    ///
    /// # Safety
    /// `psig` is NULL or holds NULL or a live signature; `ppin` holds `len` readable octets.
    pub unsafe extern "C" fn d2i_DSA_SIG(psig: *mut *mut DSA_SIG, ppin: *mut *const c_uchar, len: c_long) -> *mut DSA_SIG
    where failure = ptr::null_mut(), library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee; the same structure.
        unsafe { d2i_ECDSA_SIG(psig.cast::<*mut ECDSA_SIG>(), ppin, len) }.cast()
    }
}

/// The DER length of a signature whose r and s are both `q`, as `DSA_size` reckons it.
fn sig_size(q: &BigNum) -> c_int {
    ecdsa_core::encode_sig(q, q)
        .and_then(|d| c_int::try_from(d.len()).ok())
        .unwrap_or(0)
}

ffi_export! {
    /// The longest DER signature the key can make (r and s the size of q), or -1 without q.
    ///
    /// # Safety
    /// `d` is a live key.
    pub unsafe extern "C" fn DSA_size(d: *const DSA) -> c_int
    where failure = -1, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { dsa(d) }) else { return -1 };
        k.snapshot().params.q.as_ref().map_or(-1, sig_size)
    }
}

/// `BN_MONT_CTX_set_locked` of the prime, for a key that caches its Montgomery form
/// (`DSA_FLAG_CACHE_MONT_P`): false, with `BN_R_NO_INVERSE`, for an even prime (which has
/// none).
fn mont_ok(k: &Dsa, p: &BigNum) -> bool {
    if k.flags() & DSA_FLAG_CACHE_MONT_P == 0 || p.is_odd() {
        return true;
    }
    if !p.is_zero() {
        err::raise(ERR_LIB_BN, BN_R_NO_INVERSE, "BN_mod_inverse");
    }
    false
}

/// A `BIGNUM` of ours for an application's function, freed when dropped.
struct Bn(*mut BIGNUM);

impl Bn {
    fn new(v: &BigNum, secret: bool) -> Self {
        let b = new_bignum(v.clone(), false);
        if secret && !b.is_null() {
            // SAFETY: just made.
            unsafe { BN_set_flags(b, BN_FLG_CONSTTIME) };
        }
        Bn(b)
    }

    fn get(&self) -> Option<BigNum> {
        // SAFETY: ours.
        unsafe { value(self.0) }
    }
}

impl Drop for Bn {
    fn drop(&mut self) {
        // SAFETY: ours to free.
        unsafe { BN_clear_free(self.0) };
    }
}

/// `a^e mod m` with the method's `bn_mod_exp`, else `BN_mod_exp_mont` (an odd `m` only), or
/// `None` with the error raised.
///
/// # Safety
/// `d` is a live key; `f` is its method's function.
unsafe fn mod_exp(
    d: *mut DSA,
    f: Option<BnModExpFn>,
    a: &BigNum,
    e: &BigNum,
    m: &BigNum,
    ctx: *mut BN_CTX,
) -> Option<BigNum> {
    let Some(f) = f else {
        if !m.is_odd() {
            err::raise(ERR_LIB_BN, BN_R_CALLED_WITH_EVEN_MODULUS, "BN_mod_exp_mont");
            return None;
        }
        return core_bn::modular::exp_mod(a, e, m).ok();
    };
    let (r, a, e, m) = (
        Bn::new(&BigNum::zero(), false),
        Bn::new(a, false),
        Bn::new(e, true),
        Bn::new(m, false),
    );
    // SAFETY: the application's function with the key and our numbers; no lock is held.
    let ok = unsafe { f(d, r.0, a.0, e.0, m.0, ctx, ptr::null_mut()) } > 0;
    if ok { r.get() } else { None }
}

/// The nonce's source.
#[derive(Clone, Copy)]
enum Nonce<'a> {
    /// Below q at random (`DSA_sign_setup`'s).
    Random,
    /// `BN_generate_dsa_nonce` over the digest.
    Dsa(&'a [u8]),
    /// RFC 6979's, from HMAC-DRBG-KDF with the digest named, fetched from `libctx` with
    /// `propq` (NULL or a string).
    Rfc6979 {
        dgst: &'a [u8],
        mdname: &'a CStr,
        libctx: *mut OSSL_LIB_CTX,
        propq: *const c_char,
    },
}

/// `dsa_sign_setup`: a nonce k and r = (g^k mod p) mod q, with k's inverse mod q. `None` with
/// the errors raised (`ERR_R_BN_LIB` after any arithmetic failure, as OpenSSL raises it).
///
/// # Safety
/// `h` is a live key with the state `st`.
unsafe fn sign_setup(
    h: *mut DSA,
    k: &Dsa,
    st: &DsaState,
    env: &Env,
    nonce: Nonce<'_>,
) -> Option<(BigNum, BigNum)> {
    const F: &str = "dsa_sign_setup";
    let (Some(p), Some(q), Some(g)) = (&st.params.p, &st.params.q, &st.params.g) else {
        err::raise(ERR_LIB_DSA, DSA_R_MISSING_PARAMETERS, F);
        return None;
    };
    if p.is_zero()
        || q.is_zero()
        || g.is_zero()
        || p.is_negative()
        || q.is_negative()
        || g.is_negative()
    {
        err::raise(ERR_LIB_DSA, DSA_R_INVALID_PARAMETERS, F);
        return None;
    }
    let Some(x) = &st.priv_key else {
        err::raise(ERR_LIB_DSA, DSA_R_MISSING_PRIVATE_KEY, F);
        return None;
    };
    let ok = (|| {
        let q_bits = q.num_bits();
        if q_bits < MIN_SIGN_QBITS {
            return None;
        }
        let kv = loop {
            let kv = match nonce {
                Nonce::Dsa(dgst) => {
                    let (out, qb, xb) = (
                        Bn::new(&BigNum::zero(), true),
                        Bn::new(q, false),
                        Bn::new(x, true),
                    );
                    // SAFETY: our numbers; the digest.
                    let r = unsafe {
                        crate::bn::modular::BN_generate_dsa_nonce(
                            out.0,
                            qb.0,
                            xb.0,
                            dgst.as_ptr(),
                            dgst.len(),
                            env_ctx(env),
                        )
                    };
                    if r != 1 {
                        return None;
                    }
                    out.get()?
                }
                Nonce::Rfc6979 {
                    dgst,
                    mdname,
                    libctx,
                    propq,
                } => {
                    // A new generator each time, as OpenSSL's: a retry gets the same nonce.
                    // SAFETY: the caller's library context and query.
                    let mut d = unsafe { Deterministic::new(q, x, dgst, mdname, libctx, propq) }?;
                    d.next()?
                }
                Nonce::Random => env.rand_range(q)?,
            };
            if !kv.is_zero() {
                break kv;
            }
        };
        if !mont_ok(k, p) {
            return None;
        }
        // k + q or k + 2q, whichever has q's bits plus one (a fixed-length exponent).
        let l = core_bn::add(&kv, q).ok()?;
        let l2 = core_bn::add(&l, q).ok()?;
        let kk = if l.is_bit_set(q_bits) { l } else { l2 };
        // SAFETY: the method's function, or none.
        let f = unsafe { fns_of(k.meth()) }.and_then(|f| f.bn_mod_exp);
        // SAFETY: the caller's key; the method's function.
        let gk = unsafe { mod_exp(h, f, g, &kk, p, env_ctx(env)) }?;
        let r = core_bn::nnmod(&gk, q).ok()?;
        // Fermat: k^(q-2) mod q.
        if !q.is_odd() {
            err::raise(ERR_LIB_BN, BN_R_CALLED_WITH_EVEN_MODULUS, "BN_mod_exp_mont");
            return None;
        }
        let mut e = q.clone();
        e.sub_word(2).ok()?;
        let kinv = core_bn::modular::exp_mod(&kk, &e, q).ok()?;
        Some((kinv, r))
    })();
    if ok.is_none() {
        err::raise(ERR_LIB_DSA, ERR_R_BN_LIB, F);
    }
    ok
}

/// The `BN_CTX` of an `Env` (for the functions that take one).
fn env_ctx(env: &Env) -> *mut BN_CTX {
    env.ctx()
}

/// `ossl_dsa_do_sign_int` (with OpenSSL's nonce): the signature of the digest, or NULL with the
/// errors raised.
///
/// # Safety
/// `h` is a live key.
pub(crate) unsafe fn do_sign_int(dgst: &[u8], h: *mut DSA) -> *mut DSA_SIG {
    // SAFETY: the caller's guarantee.
    unsafe { do_sign_with(dgst, h, Nonce::Dsa(dgst)) }
}

/// `ossl_dsa_do_sign_int` with the nonce `nonce`.
///
/// # Safety
/// `h` is a live key.
unsafe fn do_sign_with(dgst: &[u8], h: *mut DSA, nonce: Nonce<'_>) -> *mut DSA_SIG {
    const F: &str = "ossl_dsa_do_sign_int";
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { dsa(h) }) else {
        return ptr::null_mut();
    };
    let st = k.snapshot();
    let (Some(_), Some(q), Some(_)) = (&st.params.p, &st.params.q, &st.params.g) else {
        err::raise(ERR_LIB_DSA, DSA_R_MISSING_PARAMETERS, F);
        return ptr::null_mut();
    };
    let Some(x) = &st.priv_key else {
        err::raise(ERR_LIB_DSA, DSA_R_MISSING_PRIVATE_KEY, F);
        return ptr::null_mut();
    };
    let mut reason = ERR_R_BN_LIB;
    let result = (|| {
        // SAFETY: the key's library context; no callback.
        let env = unsafe { Env::new(k.libctx.0, ptr::null_mut()) }?;
        let mut retries = 0u32;
        loop {
            // SAFETY: the caller's key and its state.
            let (kinv, r) = unsafe { sign_setup(h, k, &st, &env, nonce) }?;
            let dlen = dgst.len().min(q.num_bytes());
            let m = BigNum::from_bin(dgst.get(..dlen)?, Endian::Big, false).ok()?;
            let blind = loop {
                let b = env.rand_bits(
                    q.num_bits().saturating_sub(1),
                    BN_RAND_TOP_ANY,
                    BN_RAND_BOTTOM_ANY,
                )?;
                if !b.is_zero() {
                    break b;
                }
            };
            // The blinding value must have an inverse (it always does for a prime q).
            if core_bn::ct::inverse(&core_bn::nnmod(&blind, q).ok()?, q).is_none() {
                err::raise(ERR_LIB_BN, BN_R_NO_INVERSE, "BN_mod_inverse");
                return None;
            }
            // s = k^-1 (m + x r) mod q.
            let xr = core_bn::modular::mod_mul(x, &r, q).ok()?;
            let mq = core_bn::nnmod(&m, q).ok()?;
            let sum = core_bn::modular::mod_add_quick(&xr, &mq, q);
            let s = core_bn::modular::mod_mul(&sum, &kinv, q).ok()?;
            if r.is_zero() || s.is_zero() {
                if retries > MAX_SIGN_RETRIES {
                    reason = DSA_R_TOO_MANY_RETRIES;
                    return None;
                }
                retries = retries.saturating_add(1);
                continue;
            }
            return Some((r, s));
        }
    })();
    let Some((r, s)) = result else {
        err::raise(ERR_LIB_DSA, reason, F);
        return ptr::null_mut();
    };
    // SAFETY: no preconditions.
    let sig = unsafe { DSA_SIG_new() };
    let (rb, sb) = (new_bignum(r, false), new_bignum(s, false));
    // SAFETY: the signature; numbers it takes.
    if sig.is_null() || unsafe { DSA_SIG_set0(sig, rb, sb) } != 1 {
        // SAFETY: ours, or NULL.
        unsafe { BN_free(rb) };
        // SAFETY: as above.
        unsafe { BN_free(sb) };
        // SAFETY: as above.
        unsafe { DSA_SIG_free(sig) };
        return ptr::null_mut();
    }
    sig
}

/// The digest of a call (`dlen` octets; a negative length is none).
///
/// # Safety
/// `dgst` holds `dlen` octets if positive.
unsafe fn digest<'a>(dgst: *const c_uchar, dlen: c_int) -> &'a [u8] {
    match usize::try_from(dlen) {
        Ok(n) if n > 0 && !dgst.is_null() => {
            // SAFETY: the caller's guarantee.
            unsafe { core::slice::from_raw_parts(dgst, n) }
        }
        _ => &[],
    }
}

ffi_callback! {
    /// `dsa_do_sign`: the built-in method's signing.
    ///
    /// # Safety
    /// `dgst` holds `dlen` octets; `dsa` is a live key.
    pub(crate) unsafe extern "C" fn dsa_ossl_do_sign(dgst: *const c_uchar, dlen: c_int, dsa: *mut DSA) -> *mut DSA_SIG
    where failure = ptr::null_mut(), library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let d = unsafe { digest(dgst, dlen) };
        // SAFETY: as above.
        unsafe { do_sign_int(d, dsa) }
    }
}

ffi_callback! {
    /// `dsa_sign_setup_no_digest`: a random nonce's inverse into `*kinvp` and its r into
    /// `*rp` (made if NULL; OpenSSL's writes through it), the old ones freed. 1, or 0.
    ///
    /// # Safety
    /// `dsa` is a live key; `kinvp` and `rp` are writable and hold NULL or numbers the caller
    /// owns.
    pub(crate) unsafe extern "C" fn dsa_ossl_sign_setup(dsa: *mut DSA, _ctx_in: *mut BN_CTX, kinvp: *mut *mut BIGNUM, rp: *mut *mut BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::dsa(dsa) }) else { return 0 };
        if kinvp.is_null() || rp.is_null() {
            return 0;
        }
        let st = k.snapshot();
        // SAFETY: the key's library context; no callback.
        let Some(env) = (unsafe { Env::new(k.libctx.0, ptr::null_mut()) }) else { return 0 };
        // SAFETY: the caller's key and its state.
        let Some((kinv, r)) = (unsafe { sign_setup(dsa, k, &st, &env, Nonce::Random) }) else { return 0 };
        // SAFETY: the caller's pointer.
        let mut rb = unsafe { *rp };
        if rb.is_null() {
            // SAFETY: no preconditions.
            rb = unsafe { BN_new() };
            if rb.is_null() {
                return 0;
            }
            // SAFETY: as above.
            unsafe { *rp = rb };
        }
        // SAFETY: the caller's number.
        if !unsafe { store(rb, r) } {
            return 0;
        }
        let kb = new_bignum(kinv, false);
        if kb.is_null() {
            return 0;
        }
        // SAFETY: the caller's pointer.
        let old = unsafe { *kinvp };
        // SAFETY: its old number, or NULL, freed once.
        unsafe { BN_clear_free(old) };
        // SAFETY: as above.
        unsafe { *kinvp = kb };
        1
    }
}

ffi_callback! {
    /// `dsa_do_verify`: 1 for a valid signature, 0 for an invalid one, -1 for an error (no
    /// parameters, a q of other than 160, 224, or 256 bits, a prime too long, an arithmetic
    /// failure).
    ///
    /// # Safety
    /// `dgst` holds `dgst_len` octets; `sig` is a live signature; `dsa` a live key.
    pub(crate) unsafe extern "C" fn dsa_ossl_do_verify(dgst: *const c_uchar, dgst_len: c_int, sig: *mut DSA_SIG, dsa: *mut DSA) -> c_int
    where failure = -1, library = ERR_LIB_DSA
    {
        const F: &str = "dsa_do_verify";
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::dsa(dsa) }) else { return -1 };
        let st = k.snapshot();
        let (Some(p), Some(q), Some(g)) = (&st.params.p, &st.params.q, &st.params.g) else {
            err::raise(ERR_LIB_DSA, DSA_R_MISSING_PARAMETERS, F);
            return -1;
        };
        let i = q.num_bits();
        if i != 160 && i != 224 && i != 256 {
            err::raise(ERR_LIB_DSA, DSA_R_BAD_Q_VALUE, F);
            return -1;
        }
        if p.num_bits() > usize::try_from(OPENSSL_DSA_MAX_MODULUS_BITS).unwrap_or(10000) {
            err::raise(ERR_LIB_DSA, DSA_R_MODULUS_TOO_LARGE, F);
            return -1;
        }
        let (mut rp, mut sp) = (ptr::null(), ptr::null());
        // SAFETY: the caller's signature; locals.
        unsafe { DSA_SIG_get0(sig, &raw mut rp, &raw mut sp) };
        // SAFETY: the signature's numbers, or NULL.
        let (Some(r), Some(s)) = (unsafe { value(rp) }, unsafe { value(sp) }) else { return -1 };
        let in_range = |v: &BigNum| !v.is_zero() && !v.is_negative() && core_bn::ucmp(v, q).is_lt();
        if !in_range(&r) || !in_range(&s) {
            return 0;
        }
        let ok = (|| {
            let Some(w) = core_bn::ct::inverse(&s, q) else {
                err::raise(ERR_LIB_BN, BN_R_NO_INVERSE, "BN_mod_inverse");
                return None;
            };
            // SAFETY: the caller's guarantee.
            let d = unsafe { digest(dgst, dgst_len) };
            let d = d.get(..d.len().min(i >> 3))?;
            let m = BigNum::from_bin(d, Endian::Big, false).ok()?;
            let u1 = core_bn::modular::mod_mul(&m, &w, q).ok()?;
            let u2 = core_bn::modular::mod_mul(&r, &w, q).ok()?;
            if !mont_ok(k, p) {
                return None;
            }
            let y = st.pub_key.as_ref()?;
            // SAFETY: the key's method, live.
            let f = unsafe { fns_of(k.meth()) }.and_then(|f| f.mod_exp);
            // SAFETY: the caller's key; the method's function.
            let t1 = unsafe { mod_exp2(dsa, f, g, &u1, y, &u2, p) }?;
            let v = core_bn::nnmod(&t1, q).ok()?;
            Some(core_bn::ucmp(&v, &r).is_eq())
        })();
        match ok {
            Some(v) => c_int::from(v),
            None => {
                err::raise(ERR_LIB_DSA, ERR_R_BN_LIB, F);
                -1
            }
        }
    }
}

/// `a1^p1 * a2^p2 mod m` with the method's `dsa_mod_exp`, else `BN_mod_exp2_mont` (an odd `m`
/// only), or `None` with the error raised.
///
/// # Safety
/// `d` is a live key; `f` is its method's function.
unsafe fn mod_exp2(
    d: *mut DSA,
    f: Option<ModExpFn>,
    a1: &BigNum,
    p1: &BigNum,
    a2: &BigNum,
    p2: &BigNum,
    m: &BigNum,
) -> Option<BigNum> {
    let Some(f) = f else {
        if !m.is_odd() {
            err::raise(
                ERR_LIB_BN,
                BN_R_CALLED_WITH_EVEN_MODULUS,
                "BN_mod_exp2_mont",
            );
            return None;
        }
        return core_bn::modular::exp2_mod(a1, p1, a2, p2, m, m).ok();
    };
    let r = Bn::new(&BigNum::zero(), false);
    let (a1, p1, a2, p2, m) = (
        Bn::new(a1, false),
        Bn::new(p1, false),
        Bn::new(a2, false),
        Bn::new(p2, false),
        Bn::new(m, false),
    );
    // SAFETY: the application's function with the key and our numbers; no lock is held.
    let ok = unsafe {
        f(
            d,
            r.0,
            a1.0,
            p1.0,
            a2.0,
            p2.0,
            m.0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    } > 0;
    if ok { r.get() } else { None }
}

ffi_callback! {
    /// `dsa_init`: caches the Montgomery form of p (`DSA_FLAG_CACHE_MONT_P`). 1.
    ///
    /// # Safety
    /// `dsa` is a live key.
    pub(crate) unsafe extern "C" fn dsa_init(dsa: *mut DSA) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        if let Some(k) = unsafe { self::dsa(dsa) } {
            k.set_flags_to(k.flags() | DSA_FLAG_CACHE_MONT_P);
            k.touch();
        }
        1
    }
}

ffi_callback! {
    /// `dsa_finish`: nothing to free. 1.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn dsa_finish(_dsa: *mut DSA) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        1
    }
}

ffi_export! {
    /// The signature of the digest by the key's method, or NULL.
    ///
    /// # Safety
    /// `dgst` holds `dlen` octets; `dsa` is a live key.
    pub unsafe extern "C" fn DSA_do_sign(dgst: *const c_uchar, dlen: c_int, dsa: *mut DSA) -> *mut DSA_SIG
    where failure = ptr::null_mut(), library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::dsa(dsa) }) else { return ptr::null_mut() };
        // SAFETY: the key's method, live.
        let Some(f) = unsafe { fns_of(k.meth()) }.and_then(|f| f.sign) else { return ptr::null_mut() };
        // SAFETY: the method's function with the caller's arguments; no lock is held.
        unsafe { f(dgst, dlen, dsa) }
    }
}

ffi_export! {
    /// The key's method's verification: 1, 0, or -1.
    ///
    /// # Safety
    /// `dgst` holds `dgst_len` octets; `sig` is a live signature; `dsa` a live key.
    pub unsafe extern "C" fn DSA_do_verify(dgst: *const c_uchar, dgst_len: c_int, sig: *mut DSA_SIG, dsa: *mut DSA) -> c_int
    where failure = -1, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::dsa(dsa) }) else { return -1 };
        // SAFETY: the key's method, live.
        let Some(f) = unsafe { fns_of(k.meth()) }.and_then(|f| f.verify) else { return -1 };
        // SAFETY: the method's function with the caller's arguments; no lock is held.
        unsafe { f(dgst, dgst_len, sig, dsa) }
    }
}

ffi_export! {
    /// The key's method's signing setup: a nonce's inverse and r. 1, or 0.
    ///
    /// # Safety
    /// `dsa` is a live key; `ctx_in` is NULL or a live `BN_CTX`; `kinvp` and `rp` are writable.
    pub unsafe extern "C" fn DSA_sign_setup(dsa: *mut DSA, ctx_in: *mut BN_CTX, kinvp: *mut *mut BIGNUM, rp: *mut *mut BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::dsa(dsa) }) else { return 0 };
        // SAFETY: the key's method, live.
        let Some(f) = unsafe { fns_of(k.meth()) }.and_then(|f| f.sign_setup) else { return 0 };
        // SAFETY: the method's function with the caller's arguments; no lock is held.
        unsafe { f(dsa, ctx_in, kinvp, rp) }
    }
}

ffi_export! {
    /// The DER signature of the digest into `sig` (its length in `*siglen`), or the longest
    /// one's length for NULL `sig`. 1, or 0 (`*siglen` 0).
    ///
    /// # Safety
    /// `dgst` holds `dlen` octets; `sig` is NULL or has room for `DSA_size` octets; `siglen`
    /// is writable; `dsa` is a live key.
    pub unsafe extern "C" fn DSA_sign(_type: c_int, dgst: *const c_uchar, dlen: c_int, sig: *mut c_uchar, siglen: *mut c_uint, dsa: *mut DSA) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { sign_int(dgst, dlen, sig, siglen, dsa, 0, None, ptr::null_mut(), ptr::null()) }
    }
}

/// `ossl_dsa_sign_int`: `DSA_sign` with a nonce type and the digest it names. A key made
/// outside a library context, or with an application's method, signs through its method
/// (`DSA_do_sign`); another with OpenSSL's code, whose nonce is RFC 6979's for type 1 (from
/// `mdname`'s HMAC-DRBG-KDF in `libctx` with `propq`), else the digest-seeded one.
///
/// # Safety
/// As for `DSA_sign`; `libctx` is NULL or a live library context; `propq` is NULL or a string.
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn sign_int(
    dgst: *const c_uchar,
    dlen: c_int,
    sig: *mut c_uchar,
    siglen: *mut c_uint,
    dsa: *mut DSA,
    nonce_type: c_uint,
    mdname: Option<&CStr>,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { self::dsa(dsa) }) else {
        return 0;
    };
    let put = |v: c_int| {
        if !siglen.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { siglen.write(c_uint::try_from(v).unwrap_or(0)) };
        }
    };
    if sig.is_null() {
        // SAFETY: the caller's key.
        put(unsafe { DSA_size(dsa) });
        return 1;
    }
    let s = if !k.in_libctx || !is_default(k.meth()) {
        // SAFETY: the caller's guarantee.
        unsafe { DSA_do_sign(dgst, dlen, dsa) }
    } else {
        // SAFETY: as above.
        let d = unsafe { digest(dgst, dlen) };
        let nonce = match mdname {
            Some(mdname) if nonce_type == 1 => Nonce::Rfc6979 {
                dgst: d,
                mdname,
                libctx,
                propq,
            },
            _ => Nonce::Dsa(d),
        };
        // SAFETY: as above.
        unsafe { do_sign_with(d, dsa, nonce) }
    };
    if s.is_null() {
        put(0);
        return 0;
    }
    let mut out = sig;
    // SAFETY: the signature; the caller's room.
    let n = unsafe { i2d_DSA_SIG(s, &raw mut out) };
    put(n);
    // SAFETY: made above.
    unsafe { DSA_SIG_free(s) };
    1
}

ffi_export! {
    /// Verifies a DER signature (exactly DER, nothing after it) of the digest: 1, 0, or -1.
    ///
    /// # Safety
    /// `dgst` holds `dgst_len` octets; `sigbuf` holds `siglen`; `dsa` is a live key.
    pub unsafe extern "C" fn DSA_verify(_type: c_int, dgst: *const c_uchar, dgst_len: c_int, sigbuf: *const c_uchar, siglen: c_int, dsa: *mut DSA) -> c_int
    where failure = -1, library = ERR_LIB_DSA
    {
        // SAFETY: no preconditions.
        let mut s = unsafe { DSA_SIG_new() };
        if s.is_null() {
            return -1;
        }
        let mut p = sigbuf;
        let mut ret = -1;
        // SAFETY: the signature made above; the caller's octets.
        if !unsafe { d2i_DSA_SIG(&raw mut s, &raw mut p, c_long::from(siglen)) }.is_null() {
            let mut der: *mut c_uchar = ptr::null_mut();
            // SAFETY: the decoded signature; a new allocation.
            let n = unsafe { i2d_DSA_SIG(s, &raw mut der) };
            // SAFETY: the new encoding of `n` octets, and the caller's `siglen`.
            let same = n == siglen && n > 0 && {
                // SAFETY: the new encoding of `n` octets.
                let a = unsafe { core::slice::from_raw_parts(der, usize::try_from(n).unwrap_or(0)) };
                // SAFETY: the caller's `siglen` octets.
                let b = unsafe { core::slice::from_raw_parts(sigbuf, usize::try_from(siglen).unwrap_or(0)) };
                a == b
            };
            if same {
                // SAFETY: the caller's guarantee; the signature.
                ret = unsafe { DSA_do_verify(dgst, dgst_len, s, dsa) };
            }
            // SAFETY: the encoding, freed once.
            unsafe { mem::release_clean(der.cast(), usize::try_from(n).unwrap_or(0)) };
        }
        // SAFETY: made above.
        unsafe { DSA_SIG_free(s) };
        ret
    }
}

/// `dsa_keygen`: a new private key (after the parameters' simple validation) and the public
/// key g^x mod p (`BN_mod_exp` with a constant-time exponent: an odd p only).
///
/// # Safety
/// `h` is a live key.
unsafe fn builtin_keygen(h: *mut DSA) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { dsa(h) }) else {
        return 0;
    };
    let mut st = k.snapshot();
    let libctx = k.libctx.0;
    let ok = (|| {
        // SAFETY: the key's library context; no callback.
        let env = unsafe { Env::new(libctx, ptr::null_mut()) }?;
        // SAFETY: as above.
        if !unsafe { ffc::simple_validate(libctx, &st.params, ffc::Type::Dsa, &mut 0) } {
            return None;
        }
        let q_bits = st.params.q.as_ref()?.num_bits();
        let x = ffc::generate_private_key(&env, &st.params, q_bits, MIN_STRENGTH)?;
        let (p, g) = (st.params.p.as_ref()?, st.params.g.as_ref()?);
        if !p.is_odd() {
            err::raise(
                ERR_LIB_BN,
                ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED,
                "BN_mod_exp_recp",
            );
            return None;
        }
        let y = core_bn::modular::exp_mod(g, &x, p).ok()?;
        st.priv_key = Some(x);
        st.pub_key = Some(y);
        Some(())
    })();
    if ok.is_none() {
        return 0;
    }
    k.replace(st);
    1
}

ffi_export! {
    /// Generates a key pair with the key's method's `dsa_keygen`, else OpenSSL's (a new private
    /// key below q, whatever the key had). 1, or 0.
    ///
    /// # Safety
    /// `a` is a live key.
    pub unsafe extern "C" fn DSA_generate_key(a: *mut DSA) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { dsa(a) }) else { return 0 };
        // SAFETY: the key's method, live.
        if let Some(f) = unsafe { fns_of(k.meth()) }.and_then(|f| f.keygen) {
            // SAFETY: the method's function; no lock is held.
            return unsafe { f(a) };
        }
        // SAFETY: the caller's guarantee.
        unsafe { builtin_keygen(a) }
    }
}

/// `ossl_dsa_generate_ffc_parameters`: FIPS 186-2 (`legacy`) or 186-4 parameters of `pbits`
/// and `qbits` into the key's, reporting to `cb`. 1 (2 for an unverifiable generator), or 0.
///
/// # Safety
/// `h` is a live key; `cb` is NULL or a live `BN_GENCB`.
pub(crate) unsafe fn generate_ffc_parameters(
    h: *mut DSA,
    legacy: bool,
    pbits: usize,
    qbits: usize,
    cb: *mut BN_GENCB,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { dsa(h) }) else {
        return 0;
    };
    // SAFETY: the key's library context; the caller's callback.
    let Some(env) = (unsafe { Env::new(k.libctx.0, cb) }) else {
        return 0;
    };
    let mut st = k.snapshot();
    let mut res = 0;
    let ret = if legacy {
        // SAFETY: the key's library context; the context made above.
        unsafe {
            ffc::generate_186_2(
                k.libctx.0,
                &env,
                &mut st.params,
                ffc::Type::Dsa,
                pbits,
                qbits,
                &mut res,
            )
        }
    } else {
        // SAFETY: as above.
        unsafe {
            ffc::generate_186_4(
                k.libctx.0,
                &env,
                &mut st.params,
                ffc::Type::Dsa,
                pbits,
                qbits,
                &mut res,
            )
        }
    };
    if ret > 0 {
        k.replace(st);
    }
    ret
}

ffi_export! {
    /// Generates parameters of `bits` with the key's method's `dsa_paramgen`, else FIPS 186-2
    /// (q of 160 bits) below 2048 bits with a seed of at most 20 octets, FIPS 186-4 otherwise;
    /// the seed (if given) is used, and the counter and h are returned. 1, or 0.
    ///
    /// # Safety
    /// `dsa` is a live key; `seed_in` is NULL or holds `seed_len` octets; `counter_ret` and
    /// `h_ret` are NULL or writable; `cb` is NULL or a live `BN_GENCB`.
    pub unsafe extern "C" fn DSA_generate_parameters_ex(dsa: *mut DSA, bits: c_int, seed_in: *const c_uchar, seed_len: c_int, counter_ret: *mut c_int, h_ret: *mut c_ulong, cb: *mut BN_GENCB) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::dsa(dsa) }) else { return 0 };
        // SAFETY: the key's method, live.
        if let Some(f) = unsafe { fns_of(k.meth()) }.and_then(|f| f.paramgen) {
            // SAFETY: the method's function with the caller's arguments; no lock is held.
            return unsafe { f(dsa, bits, seed_in, seed_len, counter_ret, h_ret, cb) };
        }
        if !seed_in.is_null() {
            let mut st = k.snapshot();
            let seed = match usize::try_from(seed_len) {
                // SAFETY: the caller's guarantee.
                Ok(n) if n > 0 => Some(unsafe { core::slice::from_raw_parts(seed_in, n) }),
                _ => None,
            };
            st.params.set_validate_params(seed, -1);
            k.replace(st);
        }
        let Ok(l) = usize::try_from(bits) else { return 0 };
        let ok = if bits < 2048 && seed_len <= 20 {
            // SAFETY: the caller's key and callback.
            unsafe { generate_ffc_parameters(dsa, true, l, 160, cb) }
        } else {
            // SAFETY: as above.
            unsafe { generate_ffc_parameters(dsa, false, l, 0, cb) }
        };
        if ok <= 0 {
            return 0;
        }
        let st = k.snapshot();
        if !counter_ret.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { counter_ret.write(st.params.pcounter) };
        }
        if !h_ret.is_null() {
            // `(unsigned long)` of the int.
            let h = c_ulong::try_from(st.params.h).unwrap_or_else(|_| {
                c_ulong::MAX.wrapping_sub(c_ulong::from(st.params.h.unsigned_abs()).wrapping_sub(1))
            });
            // SAFETY: as above.
            unsafe { h_ret.write(h) };
        }
        1
    }
}

ffi_export! {
    /// `DSA_generate_parameters_ex` into a new key with an old-style callback (deprecated): the
    /// key, or NULL.
    ///
    /// # Safety
    /// As for `DSA_generate_parameters_ex`; `callback` is called with `cb_arg`.
    pub unsafe extern "C" fn DSA_generate_parameters(bits: c_int, seed_in: *mut c_uchar, seed_len: c_int, counter_ret: *mut c_int, h_ret: *mut c_ulong, callback: Option<OldCb>, cb_arg: *mut c_void) -> *mut DSA
    where failure = ptr::null_mut(), library = ERR_LIB_DSA
    {
        let ret = Dsa::new_handle_in(ptr::null_mut());
        if ret.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let cb = unsafe { BN_GENCB_new() };
        if cb.is_null() {
            // SAFETY: made above.
            unsafe { crate::dsa::free(ret) };
            return ptr::null_mut();
        }
        // SAFETY: the callback just made; the caller's function and argument.
        unsafe { BN_GENCB_set_old(cb, callback, cb_arg) };
        // SAFETY: the key and callback made above; the caller's other arguments.
        let ok = unsafe { DSA_generate_parameters_ex(ret, bits, seed_in, seed_len, counter_ret, h_ret, cb) } != 0;
        // SAFETY: made above.
        unsafe { BN_GENCB_free(cb) };
        if ok {
            return ret;
        }
        // SAFETY: as above.
        unsafe { crate::dsa::free(ret) };
        ptr::null_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsa::{DSA_free, DSA_new, DSA_set0_key, DSA_set0_pqg};

    fn bn(h: &str) -> *mut BIGNUM {
        let b = BigNum::from_hex_digits(h.as_bytes()).unwrap_or_else(|_| BigNum::zero());
        new_bignum(b, false)
    }

    /// A made-up key (a 128-bit p, RFC 6979's 160-bit q) without a public key.
    fn key() -> *mut DSA {
        // SAFETY: no preconditions.
        let d = unsafe { DSA_new() };
        // SAFETY: the key; numbers it takes.
        let r = unsafe {
            DSA_set0_pqg(
                d,
                bn("F7E75FDC469067FFDC4E847C51F452DF"),
                bn("996F967F6C8E388D9E28D01E205FBA957A5698B1"),
                bn("05"),
            )
        };
        assert_eq!(r, 1);
        d
    }

    /// docs/DEVIATIONS.md: OpenSSL's verification reads the missing public key through NULL.
    #[test]
    fn verifying_without_a_public_key_fails() {
        let d = key();
        // SAFETY: no preconditions.
        let s = unsafe { DSA_SIG_new() };
        // SAFETY: the signature; numbers it takes.
        let r = unsafe { DSA_SIG_set0(s, bn("01"), bn("01")) };
        assert_eq!(r, 1);
        let dgst = [1u8; 20];
        // SAFETY: the digest; the signature; the key.
        let r = unsafe { DSA_do_verify(dgst.as_ptr(), 20, s, d) };
        assert_eq!(r, -1);
        // SAFETY: made above, each freed once.
        unsafe { DSA_SIG_free(s) };
        // SAFETY: as above.
        unsafe { DSA_free(d) };
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }

    /// docs/DEVIATIONS.md: OpenSSL's `DSA_sign_setup` writes r through a NULL `*rp`.
    #[test]
    #[cfg_attr(miri, ignore = "draws random numbers through the providers")]
    fn sign_setup_makes_r() {
        let d = key();
        // A 160-bit q with a private key, so the setup runs.
        // SAFETY: the key; a number it takes.
        let r = unsafe { DSA_set0_key(d, bn("1234"), bn("42")) };
        assert_eq!(r, 1);
        let (mut kinv, mut rr): (*mut BIGNUM, *mut BIGNUM) = (ptr::null_mut(), ptr::null_mut());
        // SAFETY: the key; places for the numbers.
        let r = unsafe { DSA_sign_setup(d, ptr::null_mut(), &raw mut kinv, &raw mut rr) };
        assert_eq!(r, 1);
        assert!(!kinv.is_null() && !rr.is_null());
        // SAFETY: made by the setup, each freed once.
        unsafe { BN_free(kinv) };
        // SAFETY: as above.
        unsafe { BN_free(rr) };
        // SAFETY: made above.
        unsafe { DSA_free(d) };
    }
}
