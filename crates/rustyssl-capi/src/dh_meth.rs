//! DH methods (`DH_METHOD`; `dh_meth.c`, `dh_key.c`'s built-in method): an application's table
//! of functions for its keys' operations, and OpenSSL's own, `DH_OpenSSL`, whose functions are
//! real (an application's method often calls them for what it doesn't change).
//!
//! The built-in key generation and shared secret run the key's method's `bn_mod_exp`, as
//! OpenSSL's do: the built-in one in Rust (constant-time for the private exponent), an
//! application's through its function with `BIGNUM`s.

use core::ffi::{CStr, c_char, c_int, c_uchar, c_void};
use core::ptr;
use std::ffi::CString;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};

use rustyssl_abi::{
    BIGNUM, BN_CTX, BN_FLG_CONSTTIME, BN_GENCB, BN_MONT_CTX, BN_R_CALLED_WITH_EVEN_MODULUS,
    BN_R_NO_INVERSE, BN_RAND_BOTTOM_ANY, BN_RAND_TOP_ONE, DH, DH_FLAG_CACHE_MONT_P,
    DH_FLAG_FIPS_METHOD, DH_METHOD, DH_R_INVALID_SECRET, DH_R_MODULUS_TOO_LARGE,
    DH_R_MODULUS_TOO_SMALL, DH_R_NO_PRIVATE_VALUE, DH_R_Q_TOO_LARGE, ERR_LIB_BN, ERR_LIB_DH,
    ERR_R_BN_LIB, OPENSSL_DH_MAX_MODULUS_BITS,
};
use rustyssl_crypto::bn::{self as core_bn, BigNum, Endian};

use crate::bn::ctx::{BN_CTX_free, BN_CTX_new_ex};
use crate::bn::modular::BN_mod_exp_mont;
use crate::bn::{BN_free, BN_set_flags, new_bignum, value};
use crate::dh::{Dh, DhState, dh};
use crate::err;
use crate::ffc;
use crate::ffi::{ffi_callback, ffi_export};
use crate::handle::{Handle, handle_type};
use crate::provider::Ptr;
use crate::rsa_gen::Env;

/// `DH_MIN_MODULUS_BITS`.
const MIN_MODULUS_BITS: usize = 512;
/// `MIN_STRENGTH` (outside the FIPS module).
const MIN_STRENGTH: usize = 80;

pub(crate) type GenerateKeyFn = unsafe extern "C" fn(*mut DH) -> c_int;
pub(crate) type ComputeKeyFn = unsafe extern "C" fn(*mut c_uchar, *const BIGNUM, *mut DH) -> c_int;
pub(crate) type BnModExpFn = unsafe extern "C" fn(
    *const DH,
    *mut BIGNUM,
    *const BIGNUM,
    *const BIGNUM,
    *const BIGNUM,
    *mut BN_CTX,
    *mut BN_MONT_CTX,
) -> c_int;
pub(crate) type InitFn = unsafe extern "C" fn(*mut DH) -> c_int;
pub(crate) type GenerateParamsFn =
    unsafe extern "C" fn(*mut DH, c_int, c_int, *mut BN_GENCB) -> c_int;

/// `struct dh_method`.
#[derive(Clone)]
pub(crate) struct Fns {
    /// The name, NUL-terminated, at a stable address while it's the method's.
    name: CString,
    pub(crate) generate_key: Option<GenerateKeyFn>,
    pub(crate) compute_key: Option<ComputeKeyFn>,
    pub(crate) bn_mod_exp: Option<BnModExpFn>,
    pub(crate) init: Option<InitFn>,
    pub(crate) finish: Option<InitFn>,
    pub(crate) flags: c_int,
    app_data: Ptr<c_void>,
    pub(crate) generate_params: Option<GenerateParamsFn>,
}

/// A DH method.
pub(crate) struct DhMethod {
    fns: Mutex<Fns>,
    /// Names a renamed method had, kept so a name returned earlier stays readable.
    old_names: Mutex<Vec<CString>>,
}

handle_type!(DH_METHOD => DhMethod);

impl DhMethod {
    fn new(fns: Fns) -> Self {
        DhMethod {
            fns: Mutex::new(fns),
            old_names: Mutex::new(Vec::new()),
        }
    }

    /// A copy of the method's functions.
    pub(crate) fn fns(&self) -> Fns {
        self.fns
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn with<R>(&self, f: impl FnOnce(&mut Fns) -> R) -> R {
        f(&mut self.fns.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

/// `dh_ossl`.
fn builtin() -> *const DH_METHOD {
    static BUILTIN: OnceLock<Ptr<DH_METHOD>> = OnceLock::new();
    BUILTIN
        .get_or_init(|| {
            Ptr(DH_METHOD::new_handle(DhMethod::new(Fns {
                name: c"OpenSSL DH Method".to_owned(),
                generate_key: Some(dh_ossl_generate_key),
                compute_key: Some(dh_ossl_compute_key),
                bn_mod_exp: Some(dh_bn_mod_exp),
                init: Some(dh_init),
                finish: Some(dh_finish),
                flags: DH_FLAG_FIPS_METHOD,
                app_data: Ptr(ptr::null_mut()),
                generate_params: None,
            })))
        })
        .0
}

/// `default_DH_method`: the built-in method until the application sets another (NULL, too).
static DEFAULT: OnceLock<AtomicPtr<DH_METHOD>> = OnceLock::new();

fn default_cell() -> &'static AtomicPtr<DH_METHOD> {
    DEFAULT.get_or_init(|| AtomicPtr::new(builtin().cast_mut()))
}

/// The method new keys get: the default, or the built-in one if the application made the
/// default NULL (OpenSSL's `DH_new` would crash).
pub(crate) fn default_or_builtin() -> *const DH_METHOD {
    let d = default_cell().load(Ordering::Acquire);
    if d.is_null() { builtin() } else { d }
}

/// The method behind `meth`.
///
/// # Safety
/// `meth` is NULL or a live method.
unsafe fn method<'a>(meth: *const DH_METHOD) -> Option<&'a DhMethod> {
    // SAFETY: the caller's guarantee.
    unsafe { DH_METHOD::get(meth) }
}

/// A method's flags (0 for NULL).
///
/// # Safety
/// `meth` is NULL or a live method.
pub(crate) unsafe fn flags(meth: *const DH_METHOD) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { method(meth) }.map_or(0, |m| m.fns().flags)
}

/// A method's functions (NULL's are all absent).
///
/// # Safety
/// `meth` is NULL or a live method.
pub(crate) unsafe fn fns_of(meth: *const DH_METHOD) -> Option<Fns> {
    // SAFETY: the caller's guarantee.
    unsafe { method(meth) }.map(DhMethod::fns)
}

/// A `BIGNUM` of ours, freed when dropped, for an application's `bn_mod_exp`.
struct Bn(*mut BIGNUM);

impl Bn {
    fn new(v: &BigNum, secret: bool) -> Self {
        let b = new_bignum(v.clone(), false);
        if secret {
            // SAFETY: just made.
            unsafe { BN_set_flags(b, BN_FLG_CONSTTIME) };
        }
        Bn(b)
    }
}

impl Drop for Bn {
    fn drop(&mut self) {
        // SAFETY: ours to free.
        unsafe { BN_free(self.0) };
    }
}

/// `dh->meth->bn_mod_exp(dh, r, a, e, m, ctx, mont)`: `a^e mod m` with the key's method's
/// function (the built-in one in Rust; `e` is secret), or `None` on its failure.
///
/// # Safety
/// `d` is a live key; `f` is its method's function.
unsafe fn mod_exp(
    d: *mut DH,
    f: Option<BnModExpFn>,
    a: &BigNum,
    e: &BigNum,
    m: &BigNum,
) -> Option<BigNum> {
    let f = f?;
    let builtin: BnModExpFn = dh_bn_mod_exp;
    if ptr::fn_addr_eq(f, builtin) {
        // `BN_mod_exp_mont` takes only an odd modulus.
        if !m.is_odd() {
            err::raise(ERR_LIB_BN, BN_R_CALLED_WITH_EVEN_MODULUS, "BN_mod_exp_mont");
            return None;
        }
        return core_bn::modular::exp_mod(a, e, m).ok();
    }
    // SAFETY: the key's library context (via the key), or NULL.
    let libctx = unsafe { dh(d) }.map_or(ptr::null_mut(), |k| k.libctx.0);
    // SAFETY: as above.
    let ctx = unsafe { BN_CTX_new_ex(libctx) };
    let (r, a, e, m) = (
        Bn::new(&BigNum::zero(), false),
        Bn::new(a, false),
        Bn::new(e, true),
        Bn::new(m, false),
    );
    // SAFETY: the application's function with the key and our numbers; no lock is held.
    let ok = unsafe { f(d, r.0, a.0, e.0, m.0, ctx, ptr::null_mut()) } > 0;
    // SAFETY: made above, or NULL.
    unsafe { BN_CTX_free(ctx) };
    // SAFETY: ours.
    ok.then(|| unsafe { value(r.0) }).flatten()
}

/// `BN_MONT_CTX_set_locked` of the prime, for a key that caches its Montgomery form
/// (`DH_FLAG_CACHE_MONT_P`): false, with `BN_R_NO_INVERSE`, for an even prime (which has
/// none), as OpenSSL fails before running the method's `bn_mod_exp`.
fn mont_ok(k: &Dh, p: &BigNum) -> bool {
    if k.flags() & DH_FLAG_CACHE_MONT_P == 0 || p.is_odd() {
        return true;
    }
    if !p.is_zero() {
        err::raise(ERR_LIB_BN, BN_R_NO_INVERSE, "BN_mod_inverse");
    }
    false
}

/// `ossl_dh_generate_public_key`: `g^x mod p` with the key's method's `bn_mod_exp`, or `None`.
///
/// # Safety
/// `d` is a live key.
pub(crate) unsafe fn generate_public_key(d: *mut DH, st: &DhState, x: &BigNum) -> Option<BigNum> {
    // SAFETY: the caller's guarantee.
    let k = unsafe { dh(d) }?;
    // SAFETY: the key's method, live.
    let f = unsafe { fns_of(k.meth()) }.and_then(|f| f.bn_mod_exp);
    let (p, g) = (st.params.p.as_ref()?, st.params.g.as_ref()?);
    if !mont_ok(k, p) {
        return None;
    }
    // SAFETY: the caller's key and its method's function.
    unsafe { mod_exp(d, f, g, x, p) }
}

/// The modulus limits both operations check first: `None` to go on, else the result to
/// return (with the error raised).
fn check_sizes(st: &DhState, f: &str, too_small: c_int) -> Option<c_int> {
    let max = usize::try_from(OPENSSL_DH_MAX_MODULUS_BITS).unwrap_or(10000);
    let pbits = st.params.p.as_ref().map_or(0, BigNum::num_bits);
    if pbits > max {
        err::raise(ERR_LIB_DH, DH_R_MODULUS_TOO_LARGE, f);
        return Some(-1);
    }
    if st.params.q.as_ref().is_some_and(|q| q.num_bits() > max) {
        err::raise(ERR_LIB_DH, DH_R_Q_TOO_LARGE, f);
        return Some(-1);
    }
    if pbits < MIN_MODULUS_BITS {
        err::raise(ERR_LIB_DH, DH_R_MODULUS_TOO_SMALL, f);
        return Some(too_small);
    }
    None
}

/// `generate_key`'s new private key: the named group's within its strength and the key
/// length, a legacy one of the key length for parameters without q, else one below q after
/// the parameters' simple validation.
///
/// # Safety
/// `libctx` is NULL or a live library context.
unsafe fn new_private_key(
    libctx: *mut rustyssl_abi::OSSL_LIB_CTX,
    env: &Env,
    st: &DhState,
) -> Option<BigNum> {
    let p = st.params.p.as_ref()?;
    let length = usize::try_from(st.length).ok();
    if st.params.nid != 0 {
        let max_strength = ffc::ifc_ffc_security_bits(p.num_bits());
        let q = st.params.q.as_ref()?;
        if length.is_none_or(|l| l > q.num_bits()) {
            return None;
        }
        return ffc::generate_private_key(env, &st.params, length.unwrap_or(0), max_strength);
    }
    let Some(q) = st.params.q.as_ref() else {
        let mut l = p.num_bits();
        let length = length.unwrap_or(usize::MAX);
        if length >= l {
            return None;
        }
        l = l.saturating_sub(2);
        if length != 0 && length < l {
            l = length;
        }
        let mut priv_key = env.rand_bits(l, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY)?;
        // g = 2 is a quadratic non-residue when p % 8 == 3: bit 0 isn't secret anyway.
        if st.params.g.as_ref().is_some_and(|g| g.is_word(2)) && !p.is_bit_set(2) {
            priv_key.clear_bit(0);
        }
        return Some(priv_key);
    };
    // SAFETY: the caller's guarantee.
    if !unsafe { ffc::simple_validate(libctx, &st.params, ffc::Type::Dh, &mut 0) } {
        return None;
    }
    ffc::generate_private_key(env, &st.params, q.num_bits(), MIN_STRENGTH)
}

ffi_callback! {
    /// `generate_key`: a private key (unless the key has one) and the public key `g^x mod p`
    /// (computed with the key's method's `bn_mod_exp`). 1, or 0 with the errors raised.
    ///
    /// # Safety
    /// `dh` is a live key.
    pub(crate) unsafe extern "C" fn dh_ossl_generate_key(dh: *mut DH) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        const F: &str = "generate_key";
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::dh(dh) }) else { return 0 };
        let mut st = k.snapshot();
        if check_sizes(&st, F, 0).is_some() {
            return 0;
        }
        // SAFETY: the key's method, live.
        let f = unsafe { fns_of(k.meth()) }.and_then(|f| f.bn_mod_exp);
        let libctx = k.libctx.0;
        let ok = (|| {
            // SAFETY: the key's library context; no callback.
            let env = unsafe { Env::new(libctx, ptr::null_mut()) }?;
            let priv_key = match st.priv_key.clone() {
                Some(x) => x,
                // SAFETY: as above.
                None => unsafe { new_private_key(libctx, &env, &st) }?,
            };
            let (Some(p), Some(g)) = (st.params.p.as_ref(), st.params.g.as_ref()) else {
                return None;
            };
            if !mont_ok(k, p) {
                return None;
            }
            // SAFETY: the caller's key and its method's function.
            let pub_key = unsafe { mod_exp(dh, f, g, &priv_key, p) }?;
            st.priv_key = Some(priv_key);
            st.pub_key = Some(pub_key);
            Some(())
        })();
        if ok.is_none() {
            err::raise(ERR_LIB_DH, ERR_R_BN_LIB, F);
            return 0;
        }
        k.replace(st);
        1
    }
}

ffi_callback! {
    /// `ossl_dh_compute_key`: `pub_key^x mod p` (with the key's method's `bn_mod_exp`),
    /// refused if 1 or less or `p - 1`, into `key` padded to the prime's length. The length,
    /// 0 for a modulus too small, or -1.
    ///
    /// # Safety
    /// `key` has room for the prime's length; `pub_key` is a live `BIGNUM`; `dh` a live key.
    pub(crate) unsafe extern "C" fn dh_ossl_compute_key(key: *mut c_uchar, pub_key: *const BIGNUM, dh: *mut DH) -> c_int
    where failure = -1, library = ERR_LIB_DH
    {
        const F: &str = "ossl_dh_compute_key";
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::dh(dh) }) else { return -1 };
        let st = k.snapshot();
        if let Some(r) = check_sizes(&st, F, 0) {
            return r;
        }
        let Some(priv_key) = st.priv_key.as_ref() else {
            err::raise(ERR_LIB_DH, DH_R_NO_PRIVATE_VALUE, F);
            return -1;
        };
        // SAFETY: the caller's guarantee.
        let Some(peer) = (unsafe { value(pub_key) }) else { return -1 };
        let Some(p) = st.params.p.as_ref() else { return -1 };
        if !mont_ok(k, p) {
            return -1;
        }
        // SAFETY: the key's method, live.
        let f = unsafe { fns_of(k.meth()) }.and_then(|f| f.bn_mod_exp);
        // SAFETY: the caller's key and its method's function.
        let Some(z) = (unsafe { mod_exp(dh, f, &peer, priv_key, p) }) else {
            err::raise(ERR_LIB_DH, ERR_R_BN_LIB, F);
            return -1;
        };
        let mut pm1 = p.clone();
        let _ = pm1.sub_word(1);
        if core_bn::cmp(&z, &BigNum::one()).is_le() || core_bn::cmp(&z, &pm1).is_eq() {
            err::raise(ERR_LIB_DH, DH_R_INVALID_SECRET, F);
            return -1;
        }
        let n = p.num_bytes();
        let Some(out) = z.to_bin(Some(n), Endian::Big, false) else { return -1 };
        if key.is_null() {
            return -1;
        }
        // SAFETY: the caller's room for the prime's length.
        unsafe { ptr::copy_nonoverlapping(out.as_ptr(), key, n) };
        c_int::try_from(n).unwrap_or(-1)
    }
}

ffi_callback! {
    /// `dh_bn_mod_exp`: `BN_mod_exp_mont`.
    ///
    /// # Safety
    /// As for `BN_mod_exp_mont`.
    pub(crate) unsafe extern "C" fn dh_bn_mod_exp(_dh: *const DH, r: *mut BIGNUM, a: *const BIGNUM, p: *const BIGNUM, m: *const BIGNUM, ctx: *mut BN_CTX, m_ctx: *mut BN_MONT_CTX) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { BN_mod_exp_mont(r, a, p, m, ctx, m_ctx) }
    }
}

ffi_callback! {
    /// `dh_init`: caches the Montgomery form of p (`DH_FLAG_CACHE_MONT_P`). 1.
    ///
    /// # Safety
    /// `dh` is a live key.
    pub(crate) unsafe extern "C" fn dh_init(dh: *mut DH) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        if let Some(k) = unsafe { self::dh(dh) } {
            k.set_flags_to(k.flags() | DH_FLAG_CACHE_MONT_P);
            k.touch();
        }
        1
    }
}

ffi_callback! {
    /// `dh_finish`: nothing to free. 1.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn dh_finish(_dh: *mut DH) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        1
    }
}

ffi_export! {
    /// Generates the key pair with the key's method (a private key unless it has one). 1, or
    /// 0.
    ///
    /// # Safety
    /// `dh` is a live key.
    pub unsafe extern "C" fn DH_generate_key(dh: *mut DH) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::dh(dh) }) else { return 0 };
        // SAFETY: the key's method, live.
        let Some(f) = (unsafe { fns_of(k.meth()) }).and_then(|f| f.generate_key) else { return 0 };
        // SAFETY: the method's function takes the key; no lock is held.
        unsafe { f(dh) }
    }
}

/// The method's `compute_key`.
///
/// # Safety
/// As for `DH_compute_key`.
unsafe fn compute(
    key: *mut c_uchar,
    pub_key: *const BIGNUM,
    dh: *mut DH,
) -> Option<(c_int, usize)> {
    // SAFETY: the caller's guarantee.
    let k = unsafe { self::dh(dh) }?;
    // SAFETY: the key's method, live.
    let f = unsafe { fns_of(k.meth()) }.and_then(|f| f.compute_key)?;
    // SAFETY: the method's function; no lock is held.
    let ret = unsafe { f(key, pub_key, dh) };
    let plen = k.snapshot().params.p.as_ref().map_or(0, BigNum::num_bytes);
    Some((ret, plen))
}

ffi_export! {
    /// The shared secret with the peer's public key, without leading zeros. Its length, or 0
    /// or -1.
    ///
    /// # Safety
    /// `key` has room for `DH_size(dh)` octets; `pub_key` is a live `BIGNUM`; `dh` a live key.
    pub unsafe extern "C" fn DH_compute_key(key: *mut c_uchar, pub_key: *const BIGNUM, dh: *mut DH) -> c_int
    where failure = -1, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some((ret, _)) = (unsafe { compute(key, pub_key, dh) }) else { return -1 };
        let Ok(n) = usize::try_from(ret) else { return ret };
        if n == 0 {
            return ret;
        }
        // SAFETY: the method wrote `n` octets.
        let k = unsafe { core::slice::from_raw_parts_mut(key, n) };
        let npad = k.iter().take_while(|&&b| b == 0).count();
        k.copy_within(npad.., 0);
        if let Some(tail) = k.get_mut(n.saturating_sub(npad)..) {
            tail.fill(0);
        }
        c_int::try_from(n.saturating_sub(npad)).unwrap_or(-1)
    }
}

ffi_export! {
    /// The shared secret, left-padded with zeros to the prime's length. That length, or 0 or
    /// -1.
    ///
    /// # Safety
    /// As for `DH_compute_key`.
    pub unsafe extern "C" fn DH_compute_key_padded(key: *mut c_uchar, pub_key: *const BIGNUM, dh: *mut DH) -> c_int
    where failure = -1, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some((ret, plen)) = (unsafe { compute(key, pub_key, dh) }) else { return -1 };
        let Ok(rv) = usize::try_from(ret) else { return ret };
        if rv == 0 {
            return ret;
        }
        let pad = plen.saturating_sub(rv);
        if pad > 0 {
            // SAFETY: the caller's room for the prime's length.
            let k = unsafe { core::slice::from_raw_parts_mut(key, plen) };
            k.copy_within(..rv, pad);
            if let Some(head) = k.get_mut(..pad) {
                head.fill(0);
            }
        }
        c_int::try_from(rv.saturating_add(pad)).unwrap_or(-1)
    }
}

ffi_export! {
    /// OpenSSL's method.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn DH_OpenSSL() -> *const DH_METHOD
    where failure = ptr::null(), library = ERR_LIB_DH
    {
        builtin()
    }
}

ffi_export! {
    /// The method new keys get.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn DH_get_default_method() -> *const DH_METHOD
    where failure = ptr::null(), library = ERR_LIB_DH
    {
        default_cell().load(Ordering::Acquire)
    }
}

ffi_export! {
    /// Sets the method new keys get. The application keeps it alive.
    ///
    /// # Safety
    /// `meth` is NULL or a method that outlives its use.
    pub unsafe extern "C" fn DH_set_default_method(meth: *const DH_METHOD)
    where failure = (), library = ERR_LIB_DH
    {
        default_cell().store(meth.cast_mut(), Ordering::Release);
    }
}

ffi_export! {
    /// A new method named `name` (copied), with `flags` and no functions, or NULL.
    ///
    /// # Safety
    /// `name` is NULL or a string.
    pub unsafe extern "C" fn DH_meth_new(name: *const c_char, flags: c_int) -> *mut DH_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_DH
    {
        if name.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's string.
        let name = unsafe { CStr::from_ptr(name) }.to_owned();
        DH_METHOD::new_handle(DhMethod::new(Fns {
            name,
            generate_key: None,
            compute_key: None,
            bn_mod_exp: None,
            init: None,
            finish: None,
            flags,
            app_data: Ptr(ptr::null_mut()),
            generate_params: None,
        }))
    }
}

ffi_export! {
    /// Frees a method. NULL (and OpenSSL's own) does nothing.
    ///
    /// # Safety
    /// `dhm` is NULL or a method the caller gives up.
    pub unsafe extern "C" fn DH_meth_free(dhm: *mut DH_METHOD)
    where failure = (), library = ERR_LIB_DH
    {
        if dhm.cast_const() == builtin() {
            // OpenSSL's would free a static object: keep the built-in one.
            return;
        }
        // SAFETY: the caller's guarantee.
        unsafe { DH_METHOD::free(dhm) };
    }
}

ffi_export! {
    /// A copy of the method, its name too, or NULL.
    ///
    /// # Safety
    /// `dhm` is NULL or a live method.
    pub unsafe extern "C" fn DH_meth_dup(dhm: *const DH_METHOD) -> *mut DH_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        match unsafe { method(dhm) } {
            Some(m) => DH_METHOD::new_handle(DhMethod::new(m.fns())),
            None => ptr::null_mut(),
        }
    }
}

ffi_export! {
    /// The method's name.
    ///
    /// # Safety
    /// `dhm` is NULL or a live method.
    pub unsafe extern "C" fn DH_meth_get0_name(dhm: *const DH_METHOD) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(dhm) }.map_or(ptr::null(), |m| m.with(|f| f.name.as_ptr()))
    }
}

ffi_export! {
    /// Renames the method (`name` copied). 1, or 0.
    ///
    /// # Safety
    /// `dhm` is NULL or a live method; `name` is NULL or a string.
    pub unsafe extern "C" fn DH_meth_set1_name(dhm: *mut DH_METHOD, name: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(dhm) }) else { return 0 };
        if name.is_null() {
            return 0;
        }
        // SAFETY: the caller's string.
        let new = unsafe { CStr::from_ptr(name) }.to_owned();
        let old = m.with(|f| core::mem::replace(&mut f.name, new));
        m.old_names.lock().unwrap_or_else(PoisonError::into_inner).push(old);
        1
    }
}

ffi_export! {
    /// The method's flags.
    ///
    /// # Safety
    /// `dhm` is NULL or a live method.
    pub unsafe extern "C" fn DH_meth_get_flags(dhm: *const DH_METHOD) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { flags(dhm) }
    }
}

ffi_export! {
    /// Sets the method's flags. 1.
    ///
    /// # Safety
    /// `dhm` is NULL or a live method.
    pub unsafe extern "C" fn DH_meth_set_flags(dhm: *mut DH_METHOD, flags: c_int) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(dhm) }) else { return 0 };
        m.with(|f| f.flags = flags);
        1
    }
}

ffi_export! {
    /// The method's application data.
    ///
    /// # Safety
    /// `dhm` is NULL or a live method.
    pub unsafe extern "C" fn DH_meth_get0_app_data(dhm: *const DH_METHOD) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(dhm) }.map_or(ptr::null_mut(), |m| m.fns().app_data.0)
    }
}

ffi_export! {
    /// Sets the method's application data. 1.
    ///
    /// # Safety
    /// `dhm` is NULL or a live method.
    pub unsafe extern "C" fn DH_meth_set0_app_data(dhm: *mut DH_METHOD, app_data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(dhm) }) else { return 0 };
        m.with(|f| f.app_data = Ptr(app_data));
        1
    }
}

ffi_export! {
    /// The method's key generation function, or NULL.
    ///
    /// # Safety
    /// `dhm` is NULL or a live method.
    pub unsafe extern "C" fn DH_meth_get_generate_key(dhm: *const DH_METHOD) -> Option<GenerateKeyFn>
    where failure = None, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(dhm) }.and_then(|m| m.fns().generate_key)
    }
}

ffi_export! {
    /// Sets the method's key generation function. 1.
    ///
    /// # Safety
    /// `dhm` is NULL or a live method.
    pub unsafe extern "C" fn DH_meth_set_generate_key(dhm: *mut DH_METHOD, f: Option<GenerateKeyFn>) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(dhm) }) else { return 0 };
        m.with(|x| x.generate_key = f);
        1
    }
}

ffi_export! {
    /// The method's shared secret function, or NULL.
    ///
    /// # Safety
    /// `dhm` is NULL or a live method.
    pub unsafe extern "C" fn DH_meth_get_compute_key(dhm: *const DH_METHOD) -> Option<ComputeKeyFn>
    where failure = None, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(dhm) }.and_then(|m| m.fns().compute_key)
    }
}

ffi_export! {
    /// Sets the method's shared secret function. 1.
    ///
    /// # Safety
    /// `dhm` is NULL or a live method.
    pub unsafe extern "C" fn DH_meth_set_compute_key(dhm: *mut DH_METHOD, f: Option<ComputeKeyFn>) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(dhm) }) else { return 0 };
        m.with(|x| x.compute_key = f);
        1
    }
}

ffi_export! {
    /// The method's modular exponentiation function, or NULL.
    ///
    /// # Safety
    /// `dhm` is NULL or a live method.
    pub unsafe extern "C" fn DH_meth_get_bn_mod_exp(dhm: *const DH_METHOD) -> Option<BnModExpFn>
    where failure = None, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(dhm) }.and_then(|m| m.fns().bn_mod_exp)
    }
}

ffi_export! {
    /// Sets the method's modular exponentiation function. 1.
    ///
    /// # Safety
    /// `dhm` is NULL or a live method.
    pub unsafe extern "C" fn DH_meth_set_bn_mod_exp(dhm: *mut DH_METHOD, f: Option<BnModExpFn>) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(dhm) }) else { return 0 };
        m.with(|x| x.bn_mod_exp = f);
        1
    }
}

ffi_export! {
    /// The method's init function, or NULL.
    ///
    /// # Safety
    /// `dhm` is NULL or a live method.
    pub unsafe extern "C" fn DH_meth_get_init(dhm: *const DH_METHOD) -> Option<InitFn>
    where failure = None, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(dhm) }.and_then(|m| m.fns().init)
    }
}

ffi_export! {
    /// Sets the method's init function. 1.
    ///
    /// # Safety
    /// `dhm` is NULL or a live method.
    pub unsafe extern "C" fn DH_meth_set_init(dhm: *mut DH_METHOD, f: Option<InitFn>) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(dhm) }) else { return 0 };
        m.with(|x| x.init = f);
        1
    }
}

ffi_export! {
    /// The method's finish function, or NULL.
    ///
    /// # Safety
    /// `dhm` is NULL or a live method.
    pub unsafe extern "C" fn DH_meth_get_finish(dhm: *const DH_METHOD) -> Option<InitFn>
    where failure = None, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(dhm) }.and_then(|m| m.fns().finish)
    }
}

ffi_export! {
    /// Sets the method's finish function. 1.
    ///
    /// # Safety
    /// `dhm` is NULL or a live method.
    pub unsafe extern "C" fn DH_meth_set_finish(dhm: *mut DH_METHOD, f: Option<InitFn>) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(dhm) }) else { return 0 };
        m.with(|x| x.finish = f);
        1
    }
}

ffi_export! {
    /// The method's parameter generation function, or NULL.
    ///
    /// # Safety
    /// `dhm` is NULL or a live method.
    pub unsafe extern "C" fn DH_meth_get_generate_params(dhm: *const DH_METHOD) -> Option<GenerateParamsFn>
    where failure = None, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(dhm) }.and_then(|m| m.fns().generate_params)
    }
}

ffi_export! {
    /// Sets the method's parameter generation function. 1.
    ///
    /// # Safety
    /// `dhm` is NULL or a live method.
    pub unsafe extern "C" fn DH_meth_set_generate_params(dhm: *mut DH_METHOD, f: Option<GenerateParamsFn>) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(dhm) }) else { return 0 };
        m.with(|x| x.generate_params = f);
        1
    }
}
