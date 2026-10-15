//! `EC_GROUP`s (`ec_lib.c`, `ec_curve.c`, `ec_cvt.c`, `ec_check.c`, and `ec_asn1.c`'s basis
//! functions): named and explicit groups, their accessors, copies, comparison, and checks.

use core::ffi::{CStr, c_char, c_int, c_uint};
use core::ptr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    BIGNUM, BN_CTX, BN_MONT_CTX, EC_GROUP, EC_METHOD, EC_POINT, EC_R_DISCRIMINANT_IS_ZERO,
    EC_R_INCOMPATIBLE_OBJECTS, EC_R_INVALID_GROUP_ORDER, EC_R_POINT_IS_NOT_ON_CURVE,
    EC_R_SLOT_FULL, EC_R_UNDEFINED_GENERATOR, EC_R_UNDEFINED_ORDER, EC_R_UNKNOWN_GROUP, ERR_LIB_EC,
    ERR_R_PASSED_NULL_PARAMETER, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, NID_X9_62_ppBasis,
    NID_X9_62_tpBasis, NID_undef, OSSL_LIB_CTX, point_conversion_form_t,
};
use rustyssl_crypto::bn::{self as core_bn, BigNum, Endian};
use rustyssl_crypto::ec::curves::{self, Field};
use rustyssl_crypto::ec::group::EXPLICIT_CURVE;
use rustyssl_crypto::ec::mult::{self, Request};
use rustyssl_crypto::ec::{Group as CoreGroup, Meth, Point as CorePoint, point as cp};

use super::point::{EC_POINT_free, new_point, point};
use super::{field_type, method_of, method_ptr, raise, random};
use crate::bn::{BN_free, store, value};
use crate::err;
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::mem;
use crate::provider::Ptr;

/// A group's state: the core group and the objects its `get0` functions hand out.
struct State {
    core: Arc<CoreGroup>,
    field: Ptr<BIGNUM>,
    order: Ptr<BIGNUM>,
    cofactor: Ptr<BIGNUM>,
    /// The generator's point, while the group has one.
    generator: Ptr<EC_POINT>,
    /// The seed's copy `EC_GROUP_get0_seed` returns (from the C allocator).
    seed: Ptr<u8>,
    /// `BN_MONT_CTX` of the order, made when first asked for.
    mont: Ptr<BN_MONT_CTX>,
    /// Whether `EC_GROUP_precompute_mult` ran.
    precomputed: bool,
}

/// What an `EC_GROUP` handle points to.
pub(crate) struct EcGroup {
    libctx: Ptr<OSSL_LIB_CTX>,
    state: Mutex<State>,
}

handle_type!(EC_GROUP => EcGroup);

impl Drop for EcGroup {
    fn drop(&mut self) {
        let s = self.state.get_mut().unwrap_or_else(PoisonError::into_inner);
        for b in [s.field.0, s.order.0, s.cofactor.0] {
            // SAFETY: the group's own numbers, freed once.
            unsafe { BN_free(b) };
        }
        // SAFETY: the group's own point, or NULL.
        unsafe { EC_POINT_free(s.generator.0) };
        // SAFETY: the group's own copy, or NULL.
        unsafe { mem::release(s.seed.0.cast()) };
        // SAFETY: the group's own, or NULL.
        unsafe { crate::bn::mont::BN_MONT_CTX_free(s.mont.0) };
    }
}

impl EcGroup {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A group as an operation sees it.
pub(crate) struct View {
    pub(crate) core: Arc<CoreGroup>,
    pub(crate) libctx: *mut OSSL_LIB_CTX,
    /// The order's `BIGNUM` (`EC_GROUP_get0_order`), which OpenSSL's wNAF recognizes by
    /// address.
    pub(crate) order_ptr: *const BIGNUM,
}

/// The group behind a handle.
///
/// # Safety
/// `g` is NULL or a live group.
unsafe fn group<'a>(g: *const EC_GROUP) -> Option<&'a EcGroup> {
    // SAFETY: the caller's guarantee.
    unsafe { EC_GROUP::get(g) }
}

/// A snapshot of the group for an operation.
///
/// # Safety
/// `g` is NULL or a live group.
pub(crate) unsafe fn view(g: *const EC_GROUP) -> Option<View> {
    // SAFETY: the caller's guarantee.
    let grp = unsafe { group(g) }?;
    let s = grp.lock();
    Some(View {
        core: Arc::clone(&s.core),
        libctx: grp.libctx.0,
        order_ptr: s.order.0.cast_const(),
    })
}

/// A new group handle around `core`.
fn new_group(core: CoreGroup, libctx: *mut OSSL_LIB_CTX) -> *mut EC_GROUP {
    let num = |v: &BigNum| Ptr(crate::bn::new_bignum(v.clone(), false));
    let state = State {
        field: num(&core.field),
        order: num(&core.order),
        cofactor: num(&core.cofactor),
        generator: Ptr(ptr::null_mut()),
        seed: Ptr(ptr::null_mut()),
        mont: Ptr(ptr::null_mut()),
        // nistz256's table of the standard generator is built in.
        precomputed: core.meth == Meth::Nistz256,
        core: Arc::new(core),
    };
    let h = EC_GROUP::new_handle(EcGroup {
        libctx: Ptr(libctx),
        state: Mutex::new(state),
    });
    // SAFETY: just made.
    if let Some(g) = unsafe { group(h) } {
        let mut s = g.lock();
        sync(&mut s);
    }
    h
}

/// Brings the handed-out objects in line with the core group: the numbers' values, the
/// generator's point (made or freed as there is one), the seed's copy, and the order's
/// Montgomery context (dropped when the order changes).
fn sync(s: &mut State) {
    let c = Arc::clone(&s.core);
    // SAFETY: the group's own numbers.
    unsafe {
        store(s.field.0, c.field.clone());
    }
    // SAFETY: as above.
    let old_order = unsafe { value(s.order.0) };
    // SAFETY: as above.
    unsafe {
        store(s.order.0, c.order.clone());
    }
    // SAFETY: as above.
    unsafe {
        store(s.cofactor.0, c.cofactor.clone());
    }
    if old_order.as_ref() != Some(&c.order) && !s.mont.0.is_null() {
        // SAFETY: the group's own context.
        unsafe { crate::bn::mont::BN_MONT_CTX_free(s.mont.0) };
        s.mont = Ptr(ptr::null_mut());
    }
    match &c.generator {
        Some(gp) => {
            if s.generator.0.is_null() {
                s.generator = Ptr(new_point(c.meth, c.curve_name, gp.clone()));
            } else {
                // SAFETY: the group's own live generator.
                if let Some(p) = unsafe { point(s.generator.0) } {
                    p.store(gp.clone());
                }
            }
        }
        None => {
            // SAFETY: the group's own point, or NULL.
            unsafe { EC_POINT_free(s.generator.0) };
            s.generator = Ptr(ptr::null_mut());
        }
    }
}

/// Replaces the seed's copy with `seed`'s (none for `None`); false if memory runs out.
fn set_seed_copy(s: &mut State, seed: Option<&[u8]>) -> bool {
    // SAFETY: the group's own copy, or NULL.
    unsafe { mem::release(s.seed.0.cast()) };
    s.seed = Ptr(ptr::null_mut());
    if let Some(bytes) = seed.filter(|b| !b.is_empty()) {
        let p: *mut u8 = mem::alloc(bytes.len()).cast();
        if p.is_null() {
            return false;
        }
        // SAFETY: a block of the seed's length.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len()) };
        s.seed = Ptr(p);
    }
    true
}

/// Marks the group as decoded from explicit parameters (`group->decoded_from_explicit_params`).
///
/// # Safety
/// `g` is NULL or a live group.
pub(crate) unsafe fn set_decoded_from_explicit(g: *const EC_GROUP, decoded: bool) {
    // SAFETY: the caller's guarantee.
    if let Some(grp) = unsafe { group(g) } {
        update(grp, |c| c.decoded_from_explicit_params = decoded);
    }
}

/// Whether the group was decoded from explicit parameters.
///
/// # Safety
/// `g` is NULL or a live group.
pub(crate) unsafe fn decoded_from_explicit(g: *const EC_GROUP) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { view(g) }.is_some_and(|v| v.core.decoded_from_explicit_params)
}

/// `ossl_ec_curve_nid_from_params`: the built-in curve with the group's parameters, `NID_undef`,
/// or -1 when they can't be read (with the errors raised).
///
/// # Safety
/// `g` is a live group; `ctx` is NULL or a live `BN_CTX`.
pub(crate) unsafe fn curve_nid_from_params(g: *const EC_GROUP, ctx: *const BN_CTX) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(v) = (unsafe { view(g) }) else {
        return -1;
    };
    // SAFETY: as above.
    let mut rng = unsafe { random(ctx, v.libctx) };
    nid_from_params(&v.core, &mut rng)
}

/// Changes the group's core with `f`; when `f` fails, the group stays as it was.
fn update<T>(g: &EcGroup, f: impl FnOnce(&mut CoreGroup) -> T) -> T {
    let mut s = g.lock();
    let mut c = (*s.core).clone();
    let r = f(&mut c);
    s.core = Arc::new(c);
    sync(&mut s);
    r
}

ffi_export! {
    /// An empty group of the method (`EC_R_SLOT_FULL` for none, as OpenSSL raises).
    ///
    /// # Safety
    /// `meth` is NULL or a method.
    pub unsafe extern "C" fn EC_GROUP_new(meth: *const EC_METHOD) -> *mut EC_GROUP
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method_of(meth) }) else {
            err::raise(ERR_LIB_EC, EC_R_SLOT_FULL, "ossl_ec_group_new_ex");
            return ptr::null_mut();
        };
        new_group(CoreGroup::new(m), ptr::null_mut())
    }
}

/// `EC_GROUP_new_curve_GFp`/`GF2m`: a group of `meth` with the curve, or NULL.
///
/// # Safety
/// The numbers are NULL or live `BIGNUM`s; `ctx` NULL or a live `BN_CTX`.
unsafe fn new_curve(
    meth: Meth,
    p: *const BIGNUM,
    a: *const BIGNUM,
    b: *const BIGNUM,
    ctx: *mut BN_CTX,
) -> *mut EC_GROUP {
    // SAFETY: the caller's guarantee.
    let (Some(pv), Some(av), Some(bv)) = (unsafe { value(p) }, unsafe { value(a) }, unsafe {
        value(b)
    }) else {
        return ptr::null_mut();
    };
    let libctx = if ctx.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: as above.
        unsafe { crate::bn::ctx::libctx_of(ctx) }
    };
    let mut g = CoreGroup::new(meth);
    if let Err(e) = g.set_curve(&pv, &av, &bv) {
        raise(&e);
        return ptr::null_mut();
    }
    new_group(g, libctx)
}

ffi_export! {
    /// A group over GF(p) with the curve (the Montgomery method). NULL on error.
    ///
    /// # Safety
    /// The numbers are live `BIGNUM`s; `ctx` NULL or a live `BN_CTX`.
    pub unsafe extern "C" fn EC_GROUP_new_curve_GFp(p: *const BIGNUM, a: *const BIGNUM, b: *const BIGNUM, ctx: *mut BN_CTX) -> *mut EC_GROUP
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { new_curve(Meth::Mont, p, a, b, ctx) }
    }
}

ffi_export! {
    /// A group over GF(2^m) with the curve. NULL on error.
    ///
    /// # Safety
    /// As for `EC_GROUP_new_curve_GFp`.
    pub unsafe extern "C" fn EC_GROUP_new_curve_GF2m(p: *const BIGNUM, a: *const BIGNUM, b: *const BIGNUM, ctx: *mut BN_CTX) -> *mut EC_GROUP
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { new_curve(Meth::Gf2m, p, a, b, ctx) }
    }
}

ffi_export! {
    /// The named curve's group in a library context, or NULL with `EC_R_UNKNOWN_GROUP`.
    ///
    /// # Safety
    /// `libctx` is NULL or live; `propq` NULL or a string.
    pub unsafe extern "C" fn EC_GROUP_new_by_curve_name_ex(libctx: *mut OSSL_LIB_CTX, propq: *const c_char, nid: c_int) -> *mut EC_GROUP
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        let _ = propq;
        let built = curves::by_nid(nid).map(CoreGroup::from_curve);
        let g = match built {
            Some(Ok(mut g)) => {
                // A curve without an OID is encoded explicitly.
                // SAFETY: a NID.
                let obj = unsafe { crate::objects::OBJ_nid2obj(nid) };
                // SAFETY: NULL or a static object.
                if !obj.is_null() && unsafe { crate::objects::OBJ_length(obj) } == 0 {
                    g.asn1_flag = EXPLICIT_CURVE;
                }
                g
            }
            other => {
                if let Some(Err(e)) = other {
                    raise(&e);
                }
                // SAFETY: a NID; NULL or a static name.
                let sn = unsafe { crate::objects::OBJ_nid2sn(nid) };
                let name = if sn.is_null() {
                    "(null)".to_owned()
                } else {
                    // SAFETY: a static name.
                    unsafe { CStr::from_ptr(sn) }.to_string_lossy().into_owned()
                };
                err::raise_with_text(
                    ERR_LIB_EC,
                    EC_R_UNKNOWN_GROUP,
                    "EC_GROUP_new_by_curve_name_ex",
                    &format!("name={name}"),
                );
                return ptr::null_mut();
            }
        };
        new_group(g, libctx)
    }
}

ffi_export! {
    /// The named curve's group, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EC_GROUP_new_by_curve_name(nid: c_int) -> *mut EC_GROUP
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the default context.
        unsafe { EC_GROUP_new_by_curve_name_ex(ptr::null_mut(), ptr::null(), nid) }
    }
}

ffi_export! {
    /// Frees a group; NULL does nothing.
    ///
    /// # Safety
    /// `group` is NULL or a live group, not used afterwards.
    pub unsafe extern "C" fn EC_GROUP_free(group: *mut EC_GROUP)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { EC_GROUP::free(group) };
    }
}

ffi_export! {
    /// Frees a group, clearing it (its numbers are cleared when dropped).
    ///
    /// # Safety
    /// As for `EC_GROUP_free`.
    pub unsafe extern "C" fn EC_GROUP_clear_free(group: *mut EC_GROUP)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { EC_GROUP::free(group) };
    }
}

ffi_export! {
    /// Copies `src` into `dest` (of the same method). 1, or 0.
    ///
    /// # Safety
    /// `dest` and `src` are live groups.
    pub unsafe extern "C" fn EC_GROUP_copy(dest: *mut EC_GROUP, src: *const EC_GROUP) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let (Some(d), Some(s)) = (unsafe { group(dest) }, unsafe { group(src) }) else {
            return 0;
        };
        if ptr::eq(dest.cast_const(), src) {
            return 1;
        }
        let (core, precomputed, seed) = {
            let st = s.lock();
            (Arc::clone(&st.core), st.precomputed, st.core.seed.clone())
        };
        let mut ds = d.lock();
        if ds.core.meth != core.meth {
            err::raise(ERR_LIB_EC, EC_R_INCOMPATIBLE_OBJECTS, "EC_GROUP_copy");
            return 0;
        }
        let mut c = (*core).clone();
        c.seed = seed.clone();
        ds.core = Arc::new(c);
        ds.precomputed = precomputed;
        sync(&mut ds);
        c_int::from(set_seed_copy(&mut ds, seed.as_deref()))
    }
}

ffi_export! {
    /// A copy of the group, or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live group.
    pub unsafe extern "C" fn EC_GROUP_dup(a: *const EC_GROUP) -> *mut EC_GROUP
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { group(a) }) else { return ptr::null_mut() };
        let meth = g.lock().core.meth;
        let t = new_group(CoreGroup::new(meth), g.libctx.0);
        // SAFETY: the new group and the caller's.
        if unsafe { EC_GROUP_copy(t, a) } == 0 {
            // SAFETY: the group made above.
            unsafe { EC_GROUP_free(t) };
            return ptr::null_mut();
        }
        t
    }
}

ffi_export! {
    /// The group's method.
    ///
    /// # Safety
    /// `group` is a live group.
    pub unsafe extern "C" fn EC_GROUP_method_of(group: *const EC_GROUP) -> *const EC_METHOD
    where failure = ptr::null(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { view(group) }.map_or(ptr::null(), |v| method_ptr(v.core.meth))
    }
}

ffi_export! {
    /// Sets the generator, its order, and the cofactor (guessed when NULL or zero). 1, or 0.
    ///
    /// # Safety
    /// `group` is live; `generator` NULL or a live point; `order` and `cofactor` NULL or live
    /// `BIGNUM`s.
    pub unsafe extern "C" fn EC_GROUP_set_generator(group: *mut EC_GROUP, generator: *const EC_POINT, order: *const BIGNUM, cofactor: *const BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        const F: &str = "EC_GROUP_set_generator";
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { self::group(group) }) else { return 0 };
        // SAFETY: as above.
        let Some(gp) = (unsafe { point(generator) }) else {
            err::raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        };
        // SAFETY: as above.
        let (ov, cv) = (unsafe { value(order) }, unsafe { value(cofactor) });
        let mut c = (*g.lock().core).clone();
        let zero = BigNum::zero();
        let r = c.set_generator(gp.load(), ov.as_ref().unwrap_or(&zero), cv.as_ref());
        if let Err(e) = r {
            raise(&e);
            return 0;
        }
        let (gm, gn) = (c.meth, c.curve_name);
        if gp.meth != gm || (gp.curve_name != gn && gp.curve_name != 0 && gn != 0) {
            // OpenSSL makes the group's generator (at infinity) before the copy is refused.
            let mut s = g.lock();
            if s.core.generator.is_none() {
                let mut kept = (*s.core).clone();
                kept.generator = Some(CorePoint::infinity());
                s.core = Arc::new(kept);
                sync(&mut s);
            }
            err::raise(ERR_LIB_EC, EC_R_INCOMPATIBLE_OBJECTS, "EC_POINT_copy");
            return 0;
        }
        let mut s = g.lock();
        s.core = Arc::new(c);
        sync(&mut s);
        1
    }
}

ffi_export! {
    /// The generator, or NULL.
    ///
    /// # Safety
    /// `group` is a live group.
    pub unsafe extern "C" fn EC_GROUP_get0_generator(group: *const EC_GROUP) -> *const EC_POINT
    where failure = ptr::null(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { self::group(group) }.map_or(ptr::null(), |g| g.lock().generator.0.cast_const())
    }
}

ffi_export! {
    /// The order's Montgomery context (an odd order's), or NULL.
    ///
    /// # Safety
    /// `group` is a live group.
    pub unsafe extern "C" fn EC_GROUP_get_mont_data(group: *const EC_GROUP) -> *mut BN_MONT_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { self::group(group) }) else { return ptr::null_mut() };
        let mut s = g.lock();
        if !s.mont.0.is_null() || s.core.generator.is_none() || !s.core.order.is_odd() {
            return s.mont.0;
        }
        // SAFETY: no preconditions.
        let m = unsafe { crate::bn::mont::BN_MONT_CTX_new() };
        // SAFETY: the new context; the group's order.
        if !m.is_null() && unsafe { crate::bn::mont::BN_MONT_CTX_set(m, s.order.0, ptr::null_mut()) } == 0 {
            // SAFETY: the context made above.
            unsafe { crate::bn::mont::BN_MONT_CTX_free(m) };
            return ptr::null_mut();
        }
        s.mont = Ptr(m);
        m
    }
}

/// Copies one of the group's numbers to `out`; the result says whether it's nonzero.
///
/// # Safety
/// `out` is NULL or a live `BIGNUM`.
unsafe fn copy_out(out: *mut BIGNUM, v: &BigNum) -> c_int {
    // SAFETY: the caller's guarantee.
    if out.is_null() || !unsafe { store(out, v.clone()) } {
        return 0;
    }
    c_int::from(!v.is_zero())
}

ffi_export! {
    /// The order into `order`: 1, or 0 if it's zero (unknown).
    ///
    /// # Safety
    /// `group` is live; `order` a live `BIGNUM`.
    pub unsafe extern "C" fn EC_GROUP_get_order(group: *const EC_GROUP, order: *mut BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { view(group) }) else { return 0 };
        // SAFETY: as above.
        unsafe { copy_out(order, &v.core.order) }
    }
}

ffi_export! {
    /// The order.
    ///
    /// # Safety
    /// `group` is a live group.
    pub unsafe extern "C" fn EC_GROUP_get0_order(group: *const EC_GROUP) -> *const BIGNUM
    where failure = ptr::null(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { self::group(group) }.map_or(ptr::null(), |g| g.lock().order.0.cast_const())
    }
}

ffi_export! {
    /// The order's size in bits.
    ///
    /// # Safety
    /// `group` is a live group.
    pub unsafe extern "C" fn EC_GROUP_order_bits(group: *const EC_GROUP) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { view(group) }.map_or(0, |v| c_int::try_from(v.core.order.num_bits()).unwrap_or(0))
    }
}

ffi_export! {
    /// The cofactor into `cofactor`: 1, or 0 if it's zero (unknown).
    ///
    /// # Safety
    /// `group` is live; `cofactor` a live `BIGNUM`.
    pub unsafe extern "C" fn EC_GROUP_get_cofactor(group: *const EC_GROUP, cofactor: *mut BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { view(group) }) else { return 0 };
        // SAFETY: as above.
        unsafe { copy_out(cofactor, &v.core.cofactor) }
    }
}

ffi_export! {
    /// The cofactor.
    ///
    /// # Safety
    /// `group` is a live group.
    pub unsafe extern "C" fn EC_GROUP_get0_cofactor(group: *const EC_GROUP) -> *const BIGNUM
    where failure = ptr::null(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { self::group(group) }.map_or(ptr::null(), |g| g.lock().cofactor.0.cast_const())
    }
}

ffi_export! {
    /// Names the group (and makes its encoding named, or explicit for `NID_undef`).
    ///
    /// # Safety
    /// `group` is a live group.
    pub unsafe extern "C" fn EC_GROUP_set_curve_name(group: *mut EC_GROUP, nid: c_int)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        if let Some(g) = unsafe { self::group(group) } {
            update(g, |c| c.set_curve_name(nid));
        }
    }
}

ffi_export! {
    /// The curve's NID, or 0.
    ///
    /// # Safety
    /// `group` is a live group.
    pub unsafe extern "C" fn EC_GROUP_get_curve_name(group: *const EC_GROUP) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { view(group) }.map_or(0, |v| v.core.curve_name)
    }
}

ffi_export! {
    /// The field: the prime, or the polynomial.
    ///
    /// # Safety
    /// `group` is a live group.
    pub unsafe extern "C" fn EC_GROUP_get0_field(group: *const EC_GROUP) -> *const BIGNUM
    where failure = ptr::null(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { self::group(group) }.map_or(ptr::null(), |g| g.lock().field.0.cast_const())
    }
}

ffi_export! {
    /// The field type.
    ///
    /// # Safety
    /// `group` is a live group.
    pub unsafe extern "C" fn EC_GROUP_get_field_type(group: *const EC_GROUP) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { view(group) }.map_or(0, |v| field_type(v.core.meth))
    }
}

ffi_export! {
    /// Sets how the group is encoded (`OPENSSL_EC_NAMED_CURVE` or explicitly).
    ///
    /// # Safety
    /// `group` is a live group.
    pub unsafe extern "C" fn EC_GROUP_set_asn1_flag(group: *mut EC_GROUP, flag: c_int)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        if let Some(g) = unsafe { self::group(group) } {
            update(g, |c| c.asn1_flag = flag);
        }
    }
}

ffi_export! {
    /// How the group is encoded.
    ///
    /// # Safety
    /// `group` is a live group.
    pub unsafe extern "C" fn EC_GROUP_get_asn1_flag(group: *const EC_GROUP) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { view(group) }.map_or(0, |v| v.core.asn1_flag)
    }
}

ffi_export! {
    /// Sets the form points are encoded in.
    ///
    /// # Safety
    /// `group` is a live group.
    pub unsafe extern "C" fn EC_GROUP_set_point_conversion_form(group: *mut EC_GROUP, form: point_conversion_form_t)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        if let Some(g) = unsafe { self::group(group) } {
            let f = u8::try_from(form).unwrap_or(u8::MAX);
            update(g, |c| c.asn1_form = f);
        }
    }
}

ffi_export! {
    /// The form points are encoded in.
    ///
    /// # Safety
    /// `group` is a live group.
    pub unsafe extern "C" fn EC_GROUP_get_point_conversion_form(group: *const EC_GROUP) -> point_conversion_form_t
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { view(group) }.map_or(0, |v| point_conversion_form_t::from(v.core.asn1_form))
    }
}

ffi_export! {
    /// Sets the seed (none for a NULL or empty one): its length, 1 for none, or 0.
    ///
    /// # Safety
    /// `group` is live; `p` NULL or `len` octets.
    pub unsafe extern "C" fn EC_GROUP_set_seed(group: *mut EC_GROUP, p: *const u8, len: usize) -> usize
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { self::group(group) }) else { return 0 };
        let seed = if p.is_null() || len == 0 {
            None
        } else {
            // SAFETY: the caller's `len` octets.
            Some(unsafe { core::slice::from_raw_parts(p, len) }.to_vec())
        };
        update(g, |c| c.seed = seed.clone());
        let mut s = g.lock();
        if !set_seed_copy(&mut s, seed.as_deref()) {
            return 0;
        }
        if seed.is_none() { 1 } else { len }
    }
}

ffi_export! {
    /// The seed, or NULL.
    ///
    /// # Safety
    /// `group` is a live group.
    pub unsafe extern "C" fn EC_GROUP_get0_seed(group: *const EC_GROUP) -> *mut u8
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { self::group(group) }) else { return ptr::null_mut() };
        let mut s = g.lock();
        if s.seed.0.is_null() && s.core.seed.is_some() {
            let seed = s.core.seed.clone();
            set_seed_copy(&mut s, seed.as_deref());
        }
        s.seed.0
    }
}

ffi_export! {
    /// The seed's length (0 for none).
    ///
    /// # Safety
    /// `group` is a live group.
    pub unsafe extern "C" fn EC_GROUP_get_seed_len(group: *const EC_GROUP) -> usize
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { view(group) }.map_or(0, |v| v.core.seed.as_ref().map_or(0, Vec::len))
    }
}

/// `EC_GROUP_set_curve`.
///
/// # Safety
/// As for the export.
unsafe fn set_curve(
    group: *mut EC_GROUP,
    p: *const BIGNUM,
    a: *const BIGNUM,
    b: *const BIGNUM,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(g) = (unsafe { self::group(group) }) else {
        return 0;
    };
    // SAFETY: as above.
    let (Some(pv), Some(av), Some(bv)) = (unsafe { value(p) }, unsafe { value(a) }, unsafe {
        value(b)
    }) else {
        return 0;
    };
    let r = update(g, |c| {
        let mut t = c.clone();
        let r = t.set_curve(&pv, &av, &bv);
        if r.is_ok() {
            *c = t;
        }
        r
    });
    match r {
        Ok(()) => 1,
        Err(e) => {
            raise(&e);
            0
        }
    }
}

/// `EC_GROUP_get_curve`.
///
/// # Safety
/// As for the export.
unsafe fn get_curve(
    group: *const EC_GROUP,
    p: *mut BIGNUM,
    a: *mut BIGNUM,
    b: *mut BIGNUM,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(v) = (unsafe { view(group) }) else {
        return 0;
    };
    for (out, val) in [(p, &v.core.field), (a, &v.core.a), (b, &v.core.b)] {
        // SAFETY: as above.
        if !out.is_null() && !unsafe { store(out, val.clone()) } {
            return 0;
        }
    }
    1
}

ffi_export! {
    /// Sets the field and curve (each method refusing the curves it can't use). 1, or 0.
    ///
    /// # Safety
    /// `group` is live; the numbers are live `BIGNUM`s.
    pub unsafe extern "C" fn EC_GROUP_set_curve(group: *mut EC_GROUP, p: *const BIGNUM, a: *const BIGNUM, b: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        unsafe { set_curve(group, p, a, b) }
    }
}

ffi_export! {
    /// `EC_GROUP_set_curve` (deprecated name).
    ///
    /// # Safety
    /// As for `EC_GROUP_set_curve`.
    pub unsafe extern "C" fn EC_GROUP_set_curve_GFp(group: *mut EC_GROUP, p: *const BIGNUM, a: *const BIGNUM, b: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        unsafe { set_curve(group, p, a, b) }
    }
}

ffi_export! {
    /// `EC_GROUP_set_curve` (deprecated name).
    ///
    /// # Safety
    /// As for `EC_GROUP_set_curve`.
    pub unsafe extern "C" fn EC_GROUP_set_curve_GF2m(group: *mut EC_GROUP, p: *const BIGNUM, a: *const BIGNUM, b: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        unsafe { set_curve(group, p, a, b) }
    }
}

ffi_export! {
    /// The field and curve, into each `BIGNUM` given. 1, or 0.
    ///
    /// # Safety
    /// `group` is live; each output is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn EC_GROUP_get_curve(group: *const EC_GROUP, p: *mut BIGNUM, a: *mut BIGNUM, b: *mut BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        unsafe { get_curve(group, p, a, b) }
    }
}

ffi_export! {
    /// `EC_GROUP_get_curve` (deprecated name).
    ///
    /// # Safety
    /// As for `EC_GROUP_get_curve`.
    pub unsafe extern "C" fn EC_GROUP_get_curve_GFp(group: *const EC_GROUP, p: *mut BIGNUM, a: *mut BIGNUM, b: *mut BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        unsafe { get_curve(group, p, a, b) }
    }
}

ffi_export! {
    /// `EC_GROUP_get_curve` (deprecated name).
    ///
    /// # Safety
    /// As for `EC_GROUP_get_curve`.
    pub unsafe extern "C" fn EC_GROUP_get_curve_GF2m(group: *const EC_GROUP, p: *mut BIGNUM, a: *mut BIGNUM, b: *mut BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        unsafe { get_curve(group, p, a, b) }
    }
}

ffi_export! {
    /// The field's size in bits (the polynomial's degree for GF(2^m)).
    ///
    /// # Safety
    /// `group` is a live group.
    pub unsafe extern "C" fn EC_GROUP_get_degree(group: *const EC_GROUP) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { view(group) }.map_or(0, |v| c_int::try_from(v.core.degree()).unwrap_or(0))
    }
}

ffi_export! {
    /// Whether the curve isn't singular: 1, or 0.
    ///
    /// # Safety
    /// `group` is a live group.
    pub unsafe extern "C" fn EC_GROUP_check_discriminant(group: *const EC_GROUP, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { view(group) }) else { return 0 };
        match v.core.check_discriminant() {
            Ok(ok) => c_int::from(ok),
            Err(e) => {
                raise(&e);
                0
            }
        }
    }
}

ffi_export! {
    /// Checks the group: the discriminant, the generator on the curve, and the order times
    /// the generator at infinity. 1, or 0.
    ///
    /// # Safety
    /// `group` is NULL or a live group; `ctx` NULL or a live `BN_CTX`.
    pub unsafe extern "C" fn EC_GROUP_check(group: *const EC_GROUP, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        const F: &str = "EC_GROUP_check";
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { view(group) }) else {
            err::raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        };
        let c = &v.core;
        if !c.check_discriminant().unwrap_or(false) {
            err::raise(ERR_LIB_EC, EC_R_DISCRIMINANT_IS_ZERO, F);
            return 0;
        }
        let Some(gen_pt) = c.generator.as_ref() else {
            err::raise(ERR_LIB_EC, EC_R_UNDEFINED_GENERATOR, F);
            return 0;
        };
        match cp::is_on_curve(c, gen_pt) {
            Ok(true) => {}
            Ok(false) => {
                err::raise(ERR_LIB_EC, EC_R_POINT_IS_NOT_ON_CURVE, F);
                return 0;
            }
            Err(e) => {
                raise(&e);
                err::raise(ERR_LIB_EC, EC_R_POINT_IS_NOT_ON_CURVE, F);
                return 0;
            }
        }
        if c.order.is_zero() {
            err::raise(ERR_LIB_EC, EC_R_UNDEFINED_ORDER, F);
            return 0;
        }
        // SAFETY: as above.
        let mut rng = unsafe { random(ctx, v.libctx) };
        let mut r = CorePoint::infinity();
        let req = Request {
            scalar: Some(&c.order),
            pairs: &[],
            scalar_is_order: true,
        };
        if let Err(e) = mult::mul(c, &mut r, &req, &mut rng) {
            raise(&e);
            return 0;
        }
        if !r.is_at_infinity() {
            err::raise(ERR_LIB_EC, EC_R_INVALID_GROUP_ORDER, F);
            return 0;
        }
        1
    }
}

/// `ossl_ec_curve_nid_from_params`: the named curve the group's parameters are, `NID_undef`,
/// or -1 when it has no generator.
fn nid_from_params(c: &CoreGroup, rng: &mut rustyssl_crypto::ec::Random<'_>) -> c_int {
    let Some(gen_pt) = c.generator.as_ref() else {
        return -1;
    };
    let (x, y) = match cp::get_affine(c, gen_pt, rng) {
        Ok(xy) => xy,
        Err(e) => {
            raise(&e);
            return -1;
        }
    };
    let param_len = c.order.num_bytes().max(c.field.num_bytes());
    let mut bytes = Vec::with_capacity(param_len.saturating_mul(6));
    for v in [&c.field, &c.a, &c.b, &x, &y, &c.order] {
        match v.to_bin(Some(param_len), Endian::Big, false) {
            Some(z) => bytes.extend_from_slice(&z),
            None => return -1,
        }
    }
    let nid = c.curve_name;
    for curve in curves::builtin() {
        let field_ok = curve.field == c.meth.field();
        let params: Vec<u8> = [curve.p, curve.a, curve.b, curve.x, curve.y, curve.order].concat();
        let cofactor_ok = c.cofactor.is_zero()
            || core_bn::cmp(&c.cofactor, &BigNum::from_word(u64::from(curve.cofactor))).is_eq();
        let seed_ok = curve.seed.is_empty()
            || c.seed
                .as_ref()
                .is_none_or(|s| s.is_empty() || s.as_slice() == curve.seed);
        if field_ok
            && curve.p.len() == param_len
            && (nid <= 0 || nid == curve.nid)
            && cofactor_ok
            && seed_ok
            && params == bytes
        {
            return curve.nid;
        }
    }
    NID_undef
}

ffi_export! {
    /// The named curve whose parameters the group has (a NIST one only, with `nist_only`), or
    /// `NID_undef`.
    ///
    /// # Safety
    /// `group` is NULL or a live group.
    pub unsafe extern "C" fn EC_GROUP_check_named_curve(group: *const EC_GROUP, nist_only: c_int, ctx: *mut BN_CTX) -> c_int
    where failure = NID_undef, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { view(group) }) else {
            err::raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER, "EC_GROUP_check_named_curve");
            return NID_undef;
        };
        // SAFETY: as above.
        let mut rng = unsafe { random(ctx, v.libctx) };
        let nid = nid_from_params(&v.core, &mut rng);
        if nid > 0 && nist_only != 0 && curves::nist_name(nid).is_none() {
            return NID_undef;
        }
        nid
    }
}

ffi_export! {
    /// 0 if the groups are the same, 1 if not, -1 on error.
    ///
    /// # Safety
    /// `a` and `b` are live groups.
    pub unsafe extern "C" fn EC_GROUP_cmp(a: *const EC_GROUP, b: *const EC_GROUP, ctx: *mut BN_CTX) -> c_int
    where failure = -1, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let (Some(va), Some(vb)) = (unsafe { view(a) }, unsafe { view(b) }) else { return -1 };
        let (x, y) = (&va.core, &vb.core);
        if x.meth.field() != y.meth.field() {
            return 1;
        }
        if x.curve_name != 0 && y.curve_name != 0 && x.curve_name != y.curve_name {
            return 1;
        }
        if core_bn::cmp(&x.field, &y.field).is_ne() || core_bn::cmp(&x.a, &y.a).is_ne() || core_bn::cmp(&x.b, &y.b).is_ne() {
            return 1;
        }
        // SAFETY: as above.
        let mut rng = unsafe { random(ctx, va.libctx) };
        let same_gen = match (&x.generator, &y.generator) {
            (Some(g1), Some(g2)) => match cp::equal(x, g1, g2) {
                Ok(eq) => eq,
                Err(e) => {
                    raise(&e);
                    false
                }
            },
            (None, None) => true,
            _ => false,
        };
        let _ = &mut rng;
        if !same_gen {
            return 1;
        }
        if core_bn::cmp(&x.order, &y.order).is_ne() {
            return 1;
        }
        if !x.cofactor.is_zero() && !y.cofactor.is_zero() && core_bn::cmp(&x.cofactor, &y.cofactor).is_ne() {
            return 1;
        }
        0
    }
}

ffi_export! {
    /// Precomputes multiples of the generator for multiplications with several terms (the
    /// generic prime-field methods' table; the NIST methods keep their own; the others have
    /// nothing to do). 1, or 0.
    ///
    /// # Safety
    /// `group` is a live group; `ctx` NULL or a live `BN_CTX`.
    pub unsafe extern "C" fn EC_GROUP_precompute_mult(group: *mut EC_GROUP, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { self::group(group) }) else { return 0 };
        let meth = g.lock().core.meth;
        match meth {
            Meth::Simple | Meth::Mont | Meth::Nist => {
                let core = update(g, |c| {
                    c.pre_comp = None;
                    c.clone()
                });
                // SAFETY: the caller's guarantee.
                let mut rng = unsafe { random(ctx, g.libctx.0) };
                match rustyssl_crypto::ec::mult::precompute(&core, &mut rng) {
                    Ok(pc) => {
                        let pc = Arc::new(pc);
                        update(g, |c| c.pre_comp = Some(pc));
                        1
                    }
                    Err(e) => {
                        raise(&e);
                        0
                    }
                }
            }
            Meth::Gf2m | Meth::Sm2p256 => 1,
            _ => {
                let mut s = g.lock();
                if s.core.generator.is_none() {
                    return 0;
                }
                s.precomputed = true;
                1
            }
        }
    }
}

ffi_export! {
    /// Whether the group has precomputed multiples of its generator.
    ///
    /// # Safety
    /// `group` is a live group.
    pub unsafe extern "C" fn EC_GROUP_have_precompute_mult(group: *const EC_GROUP) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { self::group(group) }) else { return 0 };
        let s = g.lock();
        c_int::from(match s.core.meth {
            Meth::Simple | Meth::Mont | Meth::Nist => s.core.pre_comp.is_some(),
            Meth::Gf2m | Meth::Sm2p256 => false,
            _ => s.precomputed,
        })
    }
}

/// A binary field's polynomial's nonzero exponents (`poly[]` before its 0).
fn nonzero_terms(c: &CoreGroup) -> Vec<usize> {
    if c.meth.field() != Field::Binary {
        return Vec::new();
    }
    c.poly.iter().copied().filter(|&e| e != 0).collect()
}

ffi_export! {
    /// `NID_X9_62_tpBasis` or `NID_X9_62_ppBasis` for a binary field's polynomial, else 0.
    ///
    /// # Safety
    /// `group` is a live group.
    pub unsafe extern "C" fn EC_GROUP_get_basis_type(group: *const EC_GROUP) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { view(group) }) else { return 0 };
        match nonzero_terms(&v.core).len() {
            4 => NID_X9_62_ppBasis,
            2 => NID_X9_62_tpBasis,
            _ => 0,
        }
    }
}

ffi_export! {
    /// A trinomial basis' middle exponent into `k`. 1, or 0.
    ///
    /// # Safety
    /// `group` is NULL or live; `k` NULL or room for an unsigned int.
    pub unsafe extern "C" fn EC_GROUP_get_trinomial_basis(group: *const EC_GROUP, k: *mut c_uint) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { view(group) }) else { return 0 };
        let t = nonzero_terms(&v.core);
        let [_, k1] = t.as_slice() else {
            err::raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, "EC_GROUP_get_trinomial_basis");
            return 0;
        };
        if !k.is_null() {
            // SAFETY: the caller's room.
            unsafe { k.write(c_uint::try_from(*k1).unwrap_or(0)) };
        }
        1
    }
}

ffi_export! {
    /// A pentanomial basis' exponents into `k1`, `k2`, `k3` (ascending). 1, or 0.
    ///
    /// # Safety
    /// `group` is NULL or live; each output is NULL or room for an unsigned int.
    pub unsafe extern "C" fn EC_GROUP_get_pentanomial_basis(group: *const EC_GROUP, k1: *mut c_uint, k2: *mut c_uint, k3: *mut c_uint) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { view(group) }) else { return 0 };
        let t = nonzero_terms(&v.core);
        let [_, e3, e2, e1] = t.as_slice() else {
            err::raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, "EC_GROUP_get_pentanomial_basis");
            return 0;
        };
        for (out, e) in [(k1, e1), (k2, e2), (k3, e3)] {
            if !out.is_null() {
                // SAFETY: the caller's room.
                unsafe { out.write(c_uint::try_from(*e).unwrap_or(0)) };
            }
        }
        1
    }
}
