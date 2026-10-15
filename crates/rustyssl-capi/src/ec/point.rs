//! `EC_POINT`s (`ec_lib.c`, `ec_oct.c`, `ec_print.c`, `ec_deprecated.c`): coordinates,
//! arithmetic, multiplication, and the encodings, each checked against the group as OpenSSL
//! checks it (`ec_point_is_compat`: the same method, and the same curve name unless either has
//! none).

use core::ffi::{CStr, c_char, c_int, c_uchar};
use core::ptr;
use std::sync::{Mutex, PoisonError};

use rustyssl_abi::{
    BIGNUM, BN_CTX, EC_GROUP, EC_METHOD, EC_POINT, EC_R_INCOMPATIBLE_OBJECTS,
    EC_R_POINT_AT_INFINITY, EC_R_POINT_IS_NOT_ON_CURVE, ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER,
    ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, point_conversion_form_t,
};
use rustyssl_crypto::bn::BigNum;
use rustyssl_crypto::ec::curves::Field;
use rustyssl_crypto::ec::mult::{self, Request};
use rustyssl_crypto::ec::{Meth, Point as CorePoint, gfp, oct, point as cp};

use super::group::{View, view};
use super::{method_ptr, raise, random};
use crate::bn::{store, value};
use crate::err;
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::mem;

/// What an `EC_POINT` handle points to.
pub(crate) struct EcPoint {
    pub(crate) meth: Meth,
    pub(crate) curve_name: c_int,
    inner: Mutex<CorePoint>,
}

handle_type!(EC_POINT => EcPoint);

impl EcPoint {
    /// The coordinates.
    pub(crate) fn load(&self) -> CorePoint {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Sets the coordinates.
    pub(crate) fn store(&self, p: CorePoint) {
        *self.inner.lock().unwrap_or_else(PoisonError::into_inner) = p;
    }
}

/// A new point at infinity for a group of `meth` named `curve_name`.
pub(crate) fn new_point(meth: Meth, curve_name: c_int, p: CorePoint) -> *mut EC_POINT {
    EC_POINT::new_handle(EcPoint {
        meth,
        curve_name,
        inner: Mutex::new(p),
    })
}

/// The point behind a handle.
///
/// # Safety
/// `p` is NULL or a live point.
pub(crate) unsafe fn point<'a>(p: *const EC_POINT) -> Option<&'a EcPoint> {
    // SAFETY: the caller's guarantee.
    unsafe { EC_POINT::get(p) }
}

/// `ec_point_is_compat`.
fn compat(p: &EcPoint, g: &View) -> bool {
    p.meth == g.core.meth
        && (g.core.curve_name == 0 || p.curve_name == 0 || g.core.curve_name == p.curve_name)
}

/// The group and the points, checked compatible (`EC_R_INCOMPATIBLE_OBJECTS` raised by
/// `function` if any isn't).
///
/// # Safety
/// `g` and each point are NULL or live.
unsafe fn with<'a, const N: usize>(
    g: *const EC_GROUP,
    pts: [*const EC_POINT; N],
    function: &str,
) -> Option<(View, [&'a EcPoint; N])> {
    // SAFETY: the caller's guarantee.
    let v = unsafe { view(g) }?;
    let mut out = Vec::with_capacity(N);
    for p in pts {
        // SAFETY: as above.
        let pt = unsafe { point(p) }?;
        if !compat(pt, &v) {
            err::raise(ERR_LIB_EC, EC_R_INCOMPATIBLE_OBJECTS, function);
            return None;
        }
        out.push(pt);
    }
    let arr: [&EcPoint; N] = out.try_into().ok()?;
    Some((v, arr))
}

ffi_export! {
    /// A new point of the group, at infinity.
    ///
    /// # Safety
    /// `group` is NULL or a live group.
    pub unsafe extern "C" fn EC_POINT_new(group: *const EC_GROUP) -> *mut EC_POINT
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { view(group) }) else {
            err::raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER, "EC_POINT_new");
            return ptr::null_mut();
        };
        new_point(v.core.meth, v.core.curve_name, CorePoint::infinity())
    }
}

ffi_export! {
    /// Frees a point; NULL does nothing.
    ///
    /// # Safety
    /// `point` is NULL or a live point, not used afterwards.
    pub unsafe extern "C" fn EC_POINT_free(point: *mut EC_POINT)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { EC_POINT::free(point) };
    }
}

ffi_export! {
    /// Frees a point, its coordinates cleared (as the core's numbers are, when dropped).
    ///
    /// # Safety
    /// As for `EC_POINT_free`.
    pub unsafe extern "C" fn EC_POINT_clear_free(point: *mut EC_POINT)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { EC_POINT::free(point) };
    }
}

ffi_export! {
    /// Copies `src`'s coordinates to `dest` (the same method, and the same curve unless either
    /// has none). 1, or 0.
    ///
    /// # Safety
    /// `dest` and `src` are live points.
    pub unsafe extern "C" fn EC_POINT_copy(dest: *mut EC_POINT, src: *const EC_POINT) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let (Some(d), Some(s)) = (unsafe { point(dest) }, unsafe { point(src) }) else {
            return 0;
        };
        if d.meth != s.meth
            || (d.curve_name != s.curve_name && d.curve_name != 0 && s.curve_name != 0)
        {
            err::raise(ERR_LIB_EC, EC_R_INCOMPATIBLE_OBJECTS, "EC_POINT_copy");
            return 0;
        }
        if !ptr::eq(dest.cast_const(), src) {
            d.store(s.load());
        }
        1
    }
}

ffi_export! {
    /// A new point of `group` with `a`'s coordinates, or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live point; `group` a live group.
    pub unsafe extern "C" fn EC_POINT_dup(a: *const EC_POINT, group: *const EC_GROUP) -> *mut EC_POINT
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        if a.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let t = unsafe { EC_POINT_new(group) };
        if t.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the new point and the caller's.
        if unsafe { EC_POINT_copy(t, a) } == 0 {
            // SAFETY: the point made above.
            unsafe { EC_POINT_free(t) };
            return ptr::null_mut();
        }
        t
    }
}

ffi_export! {
    /// The method of the group the point was made for.
    ///
    /// # Safety
    /// `point` is a live point.
    pub unsafe extern "C" fn EC_POINT_method_of(point: *const EC_POINT) -> *const EC_METHOD
    where failure = ptr::null(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { self::point(point) }.map_or(ptr::null(), |p| method_ptr(p.meth))
    }
}

ffi_export! {
    /// Sets the point to infinity (`Z = 0`). 1, or 0 for a point of another method.
    ///
    /// # Safety
    /// `group` and `point` are live.
    pub unsafe extern "C" fn EC_POINT_set_to_infinity(group: *const EC_GROUP, point: *mut EC_POINT) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let (Some(v), Some(p)) = (unsafe { view(group) }, unsafe { self::point(point) }) else {
            return 0;
        };
        if v.core.meth != p.meth {
            err::raise(ERR_LIB_EC, EC_R_INCOMPATIBLE_OBJECTS, "EC_POINT_set_to_infinity");
            return 0;
        }
        let mut c = p.load();
        c.set_to_infinity();
        p.store(c);
        1
    }
}

/// Stores `v` in `r` if `r` isn't NULL.
///
/// # Safety
/// `r` is NULL or a live `BIGNUM`.
unsafe fn put(r: *mut BIGNUM, v: &BigNum) -> bool {
    // SAFETY: the caller's guarantee.
    r.is_null() || unsafe { store(r, v.clone()) }
}

/// A `BIGNUM` argument's value, or NULL's `None`.
///
/// # Safety
/// `b` is NULL or a live `BIGNUM`.
unsafe fn arg(b: *const BIGNUM) -> Option<BigNum> {
    // SAFETY: the caller's guarantee.
    unsafe { value(b) }
}

ffi_export! {
    /// Sets the Jacobian coordinates (each given one, reduced) of a point over GF(p). 1, or 0.
    ///
    /// # Safety
    /// `group` and `point` are live; each coordinate is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn EC_POINT_set_Jprojective_coordinates_GFp(group: *const EC_GROUP, point: *mut EC_POINT, x: *const BIGNUM, y: *const BIGNUM, z: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        const F: &str = "EC_POINT_set_Jprojective_coordinates_GFp";
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { view(group) }) else { return 0 };
        if v.core.meth.field() != Field::Prime {
            err::raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, F);
            return 0;
        }
        // SAFETY: as above.
        let Some((v, [p])) = (unsafe { with(group, [point.cast_const()], F) }) else { return 0 };
        // SAFETY: as above.
        let xv = unsafe { arg(x) };
        // SAFETY: as above.
        let yv = unsafe { arg(y) };
        // SAFETY: as above.
        let zv = unsafe { arg(z) };
        let mut c = p.load();
        match gfp::set_jprojective(&v.core, &mut c, xv.as_ref(), yv.as_ref(), zv.as_ref()) {
            Ok(()) => {
                p.store(c);
                1
            }
            Err(e) => {
                raise(&e);
                0
            }
        }
    }
}

ffi_export! {
    /// The Jacobian coordinates of a point over GF(p), into each `BIGNUM` given. 1, or 0.
    ///
    /// # Safety
    /// `group` and `point` are live; each output is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn EC_POINT_get_Jprojective_coordinates_GFp(group: *const EC_GROUP, point: *const EC_POINT, x: *mut BIGNUM, y: *mut BIGNUM, z: *mut BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        const F: &str = "EC_POINT_get_Jprojective_coordinates_GFp";
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { view(group) }) else { return 0 };
        if v.core.meth.field() != Field::Prime {
            err::raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, F);
            return 0;
        }
        // SAFETY: as above.
        let Some((_, [p])) = (unsafe { with(group, [point], F) }) else { return 0 };
        let c = p.load();
        // SAFETY: the caller's numbers.
        let ok = unsafe { put(x, &c.x) };
        // SAFETY: as above.
        let ok = ok && unsafe { put(y, &c.y) };
        // SAFETY: as above.
        c_int::from(ok && unsafe { put(z, &c.z) })
    }
}

/// `EC_POINT_set_affine_coordinates`.
///
/// # Safety
/// As for the export.
unsafe fn set_affine(
    group: *const EC_GROUP,
    point: *mut EC_POINT,
    x: *const BIGNUM,
    y: *const BIGNUM,
) -> c_int {
    const F: &str = "EC_POINT_set_affine_coordinates";
    // SAFETY: the caller's guarantee.
    let Some((v, [p])) = (unsafe { with(group, [point.cast_const()], F) }) else {
        return 0;
    };
    // SAFETY: as above.
    let (Some(xv), Some(yv)) = (unsafe { arg(x) }, unsafe { arg(y) }) else {
        let func = match v.core.meth.field() {
            Field::Prime => "ossl_ec_GFp_simple_point_set_affine_coordinates",
            Field::Binary => "ossl_ec_GF2m_simple_point_set_affine_coordinates",
        };
        err::raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER, func);
        return 0;
    };
    let mut c = p.load();
    let on = cp::set_affine(&v.core, &mut c, &xv, &yv);
    p.store(c);
    match on {
        Ok(true) => 1,
        Ok(false) => {
            err::raise(ERR_LIB_EC, EC_R_POINT_IS_NOT_ON_CURVE, F);
            0
        }
        Err(e) => {
            raise(&e);
            err::raise(ERR_LIB_EC, EC_R_POINT_IS_NOT_ON_CURVE, F);
            0
        }
    }
}

ffi_export! {
    /// Sets a point's affine coordinates; 0 (with the coordinates set) if it isn't on the
    /// curve.
    ///
    /// # Safety
    /// `group` and `point` are live; `x` and `y` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn EC_POINT_set_affine_coordinates(group: *const EC_GROUP, point: *mut EC_POINT, x: *const BIGNUM, y: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        unsafe { set_affine(group, point, x, y) }
    }
}

ffi_export! {
    /// `EC_POINT_set_affine_coordinates` (deprecated name).
    ///
    /// # Safety
    /// As for `EC_POINT_set_affine_coordinates`.
    pub unsafe extern "C" fn EC_POINT_set_affine_coordinates_GFp(group: *const EC_GROUP, point: *mut EC_POINT, x: *const BIGNUM, y: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        unsafe { set_affine(group, point, x, y) }
    }
}

ffi_export! {
    /// `EC_POINT_set_affine_coordinates` (deprecated name).
    ///
    /// # Safety
    /// As for `EC_POINT_set_affine_coordinates`.
    pub unsafe extern "C" fn EC_POINT_set_affine_coordinates_GF2m(group: *const EC_GROUP, point: *mut EC_POINT, x: *const BIGNUM, y: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        unsafe { set_affine(group, point, x, y) }
    }
}

/// `EC_POINT_get_affine_coordinates`.
///
/// # Safety
/// As for the export.
unsafe fn get_affine(
    group: *const EC_GROUP,
    point: *const EC_POINT,
    x: *mut BIGNUM,
    y: *mut BIGNUM,
    ctx: *mut BN_CTX,
) -> c_int {
    const F: &str = "EC_POINT_get_affine_coordinates";
    // SAFETY: the caller's guarantee.
    let Some((v, [p])) = (unsafe { with(group, [point], F) }) else {
        return 0;
    };
    let c = p.load();
    if c.is_at_infinity() {
        err::raise(ERR_LIB_EC, EC_R_POINT_AT_INFINITY, F);
        return 0;
    }
    // SAFETY: as above.
    let mut rng = unsafe { random(ctx, v.libctx) };
    match cp::get_affine(&v.core, &c, &mut rng) {
        Ok((xv, yv)) => {
            // SAFETY: the caller's numbers.
            let ok = unsafe { put(x, &xv) };
            // SAFETY: as above.
            c_int::from(ok && unsafe { put(y, &yv) })
        }
        Err(e) => {
            raise(&e);
            0
        }
    }
}

ffi_export! {
    /// A point's affine coordinates, into each `BIGNUM` given. 1, or 0 (at infinity, say).
    ///
    /// # Safety
    /// `group` and `point` are live; `x` and `y` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn EC_POINT_get_affine_coordinates(group: *const EC_GROUP, point: *const EC_POINT, x: *mut BIGNUM, y: *mut BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { get_affine(group, point, x, y, ctx) }
    }
}

ffi_export! {
    /// `EC_POINT_get_affine_coordinates` (deprecated name).
    ///
    /// # Safety
    /// As for `EC_POINT_get_affine_coordinates`.
    pub unsafe extern "C" fn EC_POINT_get_affine_coordinates_GFp(group: *const EC_GROUP, point: *const EC_POINT, x: *mut BIGNUM, y: *mut BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { get_affine(group, point, x, y, ctx) }
    }
}

ffi_export! {
    /// `EC_POINT_get_affine_coordinates` (deprecated name).
    ///
    /// # Safety
    /// As for `EC_POINT_get_affine_coordinates`.
    pub unsafe extern "C" fn EC_POINT_get_affine_coordinates_GF2m(group: *const EC_GROUP, point: *const EC_POINT, x: *mut BIGNUM, y: *mut BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { get_affine(group, point, x, y, ctx) }
    }
}

/// `EC_POINT_set_compressed_coordinates`.
///
/// # Safety
/// As for the export.
unsafe fn set_compressed(
    group: *const EC_GROUP,
    point: *mut EC_POINT,
    x: *const BIGNUM,
    y_bit: c_int,
    ctx: *mut BN_CTX,
) -> c_int {
    const F: &str = "EC_POINT_set_compressed_coordinates";
    // SAFETY: the caller's guarantee.
    let Some((v, [p])) = (unsafe { with(group, [point.cast_const()], F) }) else {
        return 0;
    };
    // SAFETY: as above.
    let Some(xv) = (unsafe { arg(x) }) else {
        return 0;
    };
    // SAFETY: as above.
    let mut rng = unsafe { random(ctx, v.libctx) };
    let mut c = p.load();
    let r = oct::set_compressed(&v.core, &mut c, &xv, y_bit != 0, &mut rng);
    p.store(c);
    match r {
        Ok(()) => 1,
        Err(e) => {
            raise(&e);
            0
        }
    }
}

ffi_export! {
    /// The point with x and y's bit (its parity over GF(p), that of y/x over GF(2^m)). 1, or
    /// 0 when there's none.
    ///
    /// # Safety
    /// `group` and `point` are live; `x` a live `BIGNUM`.
    pub unsafe extern "C" fn EC_POINT_set_compressed_coordinates(group: *const EC_GROUP, point: *mut EC_POINT, x: *const BIGNUM, y_bit: c_int, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_compressed(group, point, x, y_bit, ctx) }
    }
}

ffi_export! {
    /// `EC_POINT_set_compressed_coordinates` (deprecated name).
    ///
    /// # Safety
    /// As for `EC_POINT_set_compressed_coordinates`.
    pub unsafe extern "C" fn EC_POINT_set_compressed_coordinates_GFp(group: *const EC_GROUP, point: *mut EC_POINT, x: *const BIGNUM, y_bit: c_int, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_compressed(group, point, x, y_bit, ctx) }
    }
}

ffi_export! {
    /// `EC_POINT_set_compressed_coordinates` (deprecated name).
    ///
    /// # Safety
    /// As for `EC_POINT_set_compressed_coordinates`.
    pub unsafe extern "C" fn EC_POINT_set_compressed_coordinates_GF2m(group: *const EC_GROUP, point: *mut EC_POINT, x: *const BIGNUM, y_bit: c_int, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_compressed(group, point, x, y_bit, ctx) }
    }
}

ffi_export! {
    /// `r = a + b` (doubling when `a` and `b` are one point). 1, or 0.
    ///
    /// # Safety
    /// `group` and the points are live.
    pub unsafe extern "C" fn EC_POINT_add(group: *const EC_GROUP, r: *mut EC_POINT, a: *const EC_POINT, b: *const EC_POINT, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some((v, [rp, ap, bp])) = (unsafe { with(group, [r.cast_const(), a, b], "EC_POINT_add") }) else {
            return 0;
        };
        // SAFETY: as above.
        let mut rng = unsafe { random(ctx, v.libctx) };
        let (ac, bc) = (ap.load(), bp.load());
        let mut rc = rp.load();
        // The result is kept on failure too: a binary curve's sum that isn't on the curve is
        // set before it's refused, as in OpenSSL.
        let res = cp::add(&v.core, &mut rc, &ac, &bc, ptr::eq(a, b), &mut rng);
        rp.store(rc);
        match res {
            Ok(()) => 1,
            Err(e) => {
                raise(&e);
                0
            }
        }
    }
}

ffi_export! {
    /// `r = 2a`. 1, or 0.
    ///
    /// # Safety
    /// `group` and the points are live.
    pub unsafe extern "C" fn EC_POINT_dbl(group: *const EC_GROUP, r: *mut EC_POINT, a: *const EC_POINT, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some((v, [rp, ap])) = (unsafe { with(group, [r.cast_const(), a], "EC_POINT_dbl") }) else {
            return 0;
        };
        // SAFETY: as above.
        let mut rng = unsafe { random(ctx, v.libctx) };
        let ac = ap.load();
        let mut rc = rp.load();
        // The result is kept on failure too: a binary curve's sum that isn't on the curve is
        // set before it's refused, as in OpenSSL.
        let res = cp::dbl(&v.core, &mut rc, &ac, &mut rng);
        rp.store(rc);
        match res {
            Ok(()) => 1,
            Err(e) => {
                raise(&e);
                0
            }
        }
    }
}

ffi_export! {
    /// `a = -a`. 1, or 0.
    ///
    /// # Safety
    /// `group` and `a` are live.
    pub unsafe extern "C" fn EC_POINT_invert(group: *const EC_GROUP, a: *mut EC_POINT, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let Some((v, [ap])) = (unsafe { with(group, [a.cast_const()], "EC_POINT_invert") }) else {
            return 0;
        };
        let mut c = ap.load();
        match cp::invert(&v.core, &mut c) {
            Ok(()) => {
                ap.store(c);
                1
            }
            Err(e) => {
                raise(&e);
                0
            }
        }
    }
}

ffi_export! {
    /// Whether the point is the point at infinity.
    ///
    /// # Safety
    /// `group` and `point` are live.
    pub unsafe extern "C" fn EC_POINT_is_at_infinity(group: *const EC_GROUP, point: *const EC_POINT) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some((_, [p])) = (unsafe { with(group, [point], "EC_POINT_is_at_infinity") }) else {
            return 0;
        };
        c_int::from(p.load().is_at_infinity())
    }
}

ffi_export! {
    /// Whether the point is on the curve: 1, 0, or -1 on error.
    ///
    /// # Safety
    /// `group` and `point` are live.
    pub unsafe extern "C" fn EC_POINT_is_on_curve(group: *const EC_GROUP, point: *const EC_POINT, ctx: *mut BN_CTX) -> c_int
    where failure = -1, library = ERR_LIB_EC
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let Some((v, [p])) = (unsafe { with(group, [point], "EC_POINT_is_on_curve") }) else {
            return 0;
        };
        match cp::is_on_curve(&v.core, &p.load()) {
            Ok(on) => c_int::from(on),
            Err(e) => {
                raise(&e);
                -1
            }
        }
    }
}

ffi_export! {
    /// 0 if the points are equal, 1 if not, -1 on error.
    ///
    /// # Safety
    /// `group` and the points are live.
    pub unsafe extern "C" fn EC_POINT_cmp(group: *const EC_GROUP, a: *const EC_POINT, b: *const EC_POINT, ctx: *mut BN_CTX) -> c_int
    where failure = -1, library = ERR_LIB_EC
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let Some((v, [ap, bp])) = (unsafe { with(group, [a, b], "EC_POINT_cmp") }) else {
            return -1;
        };
        match cp::equal(&v.core, &ap.load(), &bp.load()) {
            Ok(eq) => c_int::from(!eq),
            Err(e) => {
                raise(&e);
                -1
            }
        }
    }
}

ffi_export! {
    /// Makes the point's coordinates affine (`Z = 1`). 1, or 0.
    ///
    /// # Safety
    /// `group` and `point` are live.
    pub unsafe extern "C" fn EC_POINT_make_affine(group: *const EC_GROUP, point: *mut EC_POINT, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some((v, [p])) = (unsafe { with(group, [point.cast_const()], "EC_POINT_make_affine") }) else {
            return 0;
        };
        // SAFETY: as above.
        let mut rng = unsafe { random(ctx, v.libctx) };
        let mut c = p.load();
        // Kept on failure too: a point off the curve is set before it's refused.
        let res = cp::make_affine(&v.core, &mut c, &mut rng);
        p.store(c);
        match res {
            Ok(()) => 1,
            Err(e) => {
                raise(&e);
                0
            }
        }
    }
}

/// The points of a C array of `num`.
///
/// # Safety
/// `points` holds `num` live points, or `num` is 0.
unsafe fn array<'a>(
    points: *const *const EC_POINT,
    num: usize,
) -> Option<Vec<(*const EC_POINT, &'a EcPoint)>> {
    if num == 0 {
        return Some(Vec::new());
    }
    if points.is_null() {
        return None;
    }
    // SAFETY: the caller's array of `num` pointers.
    let ptrs = unsafe { core::slice::from_raw_parts(points, num) };
    ptrs.iter()
        // SAFETY: each a live point.
        .map(|&p| unsafe { point(p) }.map(|q| (p, q)))
        .collect()
}

ffi_export! {
    /// Makes `num` points affine, with one inversion over GF(p). 1, or 0.
    ///
    /// # Safety
    /// `group` is live; `points` holds `num` live points.
    pub unsafe extern "C" fn EC_POINTs_make_affine(group: *const EC_GROUP, num: usize, points: *mut *mut EC_POINT, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { view(group) }) else { return 0 };
        // SAFETY: as above.
        let Some(pts) = (unsafe { array(points.cast_const().cast(), num) }) else { return 0 };
        if pts.iter().any(|(_, p)| !compat(p, &v)) {
            err::raise(ERR_LIB_EC, EC_R_INCOMPATIBLE_OBJECTS, "EC_POINTs_make_affine");
            return 0;
        }
        let mut cs: Vec<CorePoint> = pts.iter().map(|(_, p)| p.load()).collect();
        // SAFETY: as above.
        let mut rng = unsafe { random(ctx, v.libctx) };
        match cp::points_make_affine(&v.core, &mut cs, &mut rng) {
            Ok(()) => {
                for ((_, p), c) in pts.iter().zip(cs) {
                    p.store(c);
                }
                1
            }
            Err(e) => {
                raise(&e);
                0
            }
        }
    }
}

/// `EC_POINTs_mul`'s work, with the checks done.
///
/// # Safety
/// The handles are live.
unsafe fn multiply(
    v: &View,
    r: &EcPoint,
    scalar: *const BIGNUM,
    terms: &[(&EcPoint, *const BIGNUM)],
    ctx: *mut BN_CTX,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let s = unsafe { arg(scalar) };
    let mut pairs_owned: Vec<(CorePoint, BigNum)> = Vec::with_capacity(terms.len());
    for (p, k) in terms {
        // SAFETY: as above.
        let Some(kv) = (unsafe { arg(*k) }) else {
            return 0;
        };
        pairs_owned.push((p.load(), kv));
    }
    let pairs: Vec<(&CorePoint, &BigNum)> = pairs_owned.iter().map(|(p, k)| (p, k)).collect();
    let req = Request {
        scalar: s.as_ref(),
        pairs: &pairs,
        scalar_is_order: !scalar.is_null() && ptr::eq(scalar, v.order_ptr),
    };
    // SAFETY: as above.
    let mut rng = unsafe { random(ctx, v.libctx) };
    let mut rc = r.load();
    // Kept on failure too: OpenSSL's ladders work in `r`, and a binary curve's sum that isn't
    // on the curve is set before it's refused.
    let res = mult::mul(&v.core, &mut rc, &req, &mut rng);
    r.store(rc);
    match res {
        Ok(()) => 1,
        Err(e) => {
            raise(&e);
            0
        }
    }
}

ffi_export! {
    /// `r = g_scalar * G + p_scalar * point` (either term left out when its scalar, or the
    /// point, is NULL). 1, or 0.
    ///
    /// # Safety
    /// `group` and `r` are live; `point` is NULL or a live point; each scalar is NULL or a live
    /// `BIGNUM`.
    pub unsafe extern "C" fn EC_POINT_mul(group: *const EC_GROUP, r: *mut EC_POINT, g_scalar: *const BIGNUM, point: *const EC_POINT, p_scalar: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        const F: &str = "EC_POINT_mul";
        // SAFETY: the caller's guarantee.
        let Some((v, [rp])) = (unsafe { with(group, [r.cast_const()], F) }) else { return 0 };
        let pp = if point.is_null() {
            None
        } else {
            // SAFETY: as above.
            let Some((_, [pp])) = (unsafe { with(group, [point], F) }) else { return 0 };
            Some(pp)
        };
        if g_scalar.is_null() && p_scalar.is_null() {
            let mut c = rp.load();
            c.set_to_infinity();
            rp.store(c);
            return 1;
        }
        let terms: Vec<(&EcPoint, *const BIGNUM)> = match pp {
            Some(p) if !p_scalar.is_null() => vec![(p, p_scalar)],
            _ => Vec::new(),
        };
        // SAFETY: as above.
        unsafe { multiply(&v, rp, g_scalar, &terms, ctx) }
    }
}

ffi_export! {
    /// `r = scalar * G + Σ scalars[i] * points[i]`. 1, or 0.
    ///
    /// # Safety
    /// `group` and `r` are live; `points` and `scalars` hold `num` live points and `BIGNUM`s;
    /// `scalar` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn EC_POINTs_mul(group: *const EC_GROUP, r: *mut EC_POINT, scalar: *const BIGNUM, num: usize, points: *mut *const EC_POINT, scalars: *mut *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        const F: &str = "EC_POINTs_mul";
        // SAFETY: the caller's guarantee.
        let Some((v, [rp])) = (unsafe { with(group, [r.cast_const()], F) }) else { return 0 };
        if scalar.is_null() && num == 0 {
            let mut c = rp.load();
            c.set_to_infinity();
            rp.store(c);
            return 1;
        }
        // SAFETY: as above.
        let Some(pts) = (unsafe { array(points.cast_const(), num) }) else { return 0 };
        if pts.iter().any(|(_, p)| !compat(p, &v)) {
            err::raise(ERR_LIB_EC, EC_R_INCOMPATIBLE_OBJECTS, F);
            return 0;
        }
        let ks: &[*const BIGNUM] = if num == 0 || scalars.is_null() {
            &[]
        } else {
            // SAFETY: the caller's array of `num` scalars.
            unsafe { core::slice::from_raw_parts(scalars.cast_const(), num) }
        };
        if ks.len() != num {
            return 0;
        }
        let terms: Vec<(&EcPoint, *const BIGNUM)> =
            pts.iter().map(|(_, p)| *p).zip(ks.iter().copied()).collect();
        // SAFETY: as above.
        unsafe { multiply(&v, rp, scalar, &terms, ctx) }
    }
}

/// `point2oct`'s length for `buf == NULL`, or its encoding: `Ok(len)`, or 0 on error.
///
/// # Safety
/// The handles are live; `buf` is NULL or has room for `len` octets.
unsafe fn point2oct(
    group: *const EC_GROUP,
    point: *const EC_POINT,
    form: point_conversion_form_t,
    buf: *mut c_uchar,
    len: usize,
    ctx: *mut BN_CTX,
) -> usize {
    const F: &str = "EC_POINT_point2oct";
    if point.is_null() {
        err::raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER, F);
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let Some((v, [p])) = (unsafe { with(group, [point], F) }) else {
        return 0;
    };
    let c = p.load();
    let form = u8::try_from(form).unwrap_or(0xff);
    let need = match oct::encoded_len(&v.core, &c, form) {
        Ok(n) => n,
        Err(e) => {
            raise(&e);
            return 0;
        }
    };
    if buf.is_null() {
        return need;
    }
    if len < need {
        let func = match v.core.meth.field() {
            Field::Prime => "ossl_ec_GFp_simple_point2oct",
            Field::Binary => "ossl_ec_GF2m_simple_point2oct",
        };
        err::raise(ERR_LIB_EC, rustyssl_abi::EC_R_BUFFER_TOO_SMALL, func);
        return 0;
    }
    // SAFETY: as above.
    let mut rng = unsafe { random(ctx, v.libctx) };
    match oct::encode(&v.core, &c, form, &mut rng) {
        Ok(enc) => {
            // SAFETY: the caller's room for `len` octets, at least the encoding's.
            unsafe { ptr::copy_nonoverlapping(enc.as_ptr(), buf, enc.len()) };
            enc.len()
        }
        Err(e) => {
            raise(&e);
            0
        }
    }
}

ffi_export! {
    /// Encodes the point in `form` into `buf` (or, with `buf` NULL, its length). The length,
    /// or 0.
    ///
    /// # Safety
    /// `group` and `point` are live; `buf` is NULL or has room for `len` octets.
    pub unsafe extern "C" fn EC_POINT_point2oct(group: *const EC_GROUP, point: *const EC_POINT, form: point_conversion_form_t, buf: *mut c_uchar, len: usize, ctx: *mut BN_CTX) -> usize
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { point2oct(group, point, form, buf, len, ctx) }
    }
}

ffi_export! {
    /// Decodes `len` octets into the point. 1, or 0.
    ///
    /// # Safety
    /// `group` and `point` are live; `buf` holds `len` octets.
    pub unsafe extern "C" fn EC_POINT_oct2point(group: *const EC_GROUP, point: *mut EC_POINT, buf: *const c_uchar, len: usize, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some((v, [p])) = (unsafe { with(group, [point.cast_const()], "EC_POINT_oct2point") }) else {
            return 0;
        };
        // No encoding is longer than an uncompressed point of the largest field, so a longer
        // `len` is refused for its length, as OpenSSL refuses it, from no more octets than one
        // past that (which keeps a huge `len` from becoming a slice).
        let max_field = usize::try_from(rustyssl_abi::OPENSSL_ECC_MAX_FIELD_BITS)
            .unwrap_or(0)
            .div_ceil(8);
        let read = len.min(max_field.saturating_mul(2).saturating_add(2));
        let input: &[u8] = if read == 0 {
            &[]
        } else if buf.is_null() {
            return 0;
        } else {
            // SAFETY: the caller's `len` octets, of which these are the first.
            unsafe { core::slice::from_raw_parts(buf, read) }
        };
        // SAFETY: as above.
        let mut rng = unsafe { random(ctx, v.libctx) };
        let mut c = p.load();
        let r = oct::decode(&v.core, &mut c, input, &mut rng);
        p.store(c);
        match r {
            Ok(()) => 1,
            Err(e) => {
                raise(&e);
                0
            }
        }
    }
}

ffi_export! {
    /// The point's encoding in a new buffer (`OPENSSL_free` it) into `*pbuf`. Its length, or 0.
    ///
    /// # Safety
    /// `group` and `point` are live; `pbuf` is room for a pointer.
    pub unsafe extern "C" fn EC_POINT_point2buf(group: *const EC_GROUP, point: *const EC_POINT, form: point_conversion_form_t, pbuf: *mut *mut c_uchar, ctx: *mut BN_CTX) -> usize
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let len = unsafe { point2oct(group, point, form, ptr::null_mut(), 0, ptr::null_mut()) };
        if len == 0 {
            return 0;
        }
        let buf: *mut c_uchar = mem::alloc(len).cast();
        if buf.is_null() {
            return 0;
        }
        // SAFETY: as above; a buffer of `len` octets.
        let len = unsafe { point2oct(group, point, form, buf, len, ctx) };
        if len == 0 {
            // SAFETY: the buffer made above.
            unsafe { mem::release(buf.cast()) };
            return 0;
        }
        if !pbuf.is_null() {
            // SAFETY: the caller's room for a pointer.
            unsafe { pbuf.write(buf) };
        }
        len
    }
}

/// The point's encoding, or `None` (`EC_POINT_point2buf`).
///
/// # Safety
/// As for `EC_POINT_point2buf`.
unsafe fn encoding(
    group: *const EC_GROUP,
    point: *const EC_POINT,
    form: point_conversion_form_t,
    ctx: *mut BN_CTX,
) -> Option<Vec<u8>> {
    let mut buf: *mut c_uchar = ptr::null_mut();
    // SAFETY: the caller's guarantee; a slot for the buffer.
    let len = unsafe { EC_POINT_point2buf(group, point, form, &raw mut buf, ctx) };
    if len == 0 || buf.is_null() {
        return None;
    }
    // SAFETY: the buffer of `len` octets just made.
    let v = unsafe { core::slice::from_raw_parts(buf, len) }.to_vec();
    // SAFETY: as above.
    unsafe { mem::release(buf.cast()) };
    Some(v)
}

ffi_export! {
    /// The point's encoding as a number (into `ret`, or a new `BIGNUM`), or NULL.
    ///
    /// # Safety
    /// `group` and `point` are live; `ret` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn EC_POINT_point2bn(group: *const EC_GROUP, point: *const EC_POINT, form: point_conversion_form_t, ret: *mut BIGNUM, ctx: *mut BN_CTX) -> *mut BIGNUM
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(enc) = (unsafe { encoding(group, point, form, ctx) }) else {
            return ptr::null_mut();
        };
        let len = c_int::try_from(enc.len()).unwrap_or(c_int::MAX);
        // SAFETY: the encoding's octets; the caller's number or NULL.
        unsafe { crate::bn::conv::BN_bin2bn(enc.as_ptr(), len, ret) }
    }
}

ffi_export! {
    /// The point a number encodes (into `point`, or a new one), or NULL.
    ///
    /// # Safety
    /// `group` is live; `bn` a live `BIGNUM`; `point` NULL or a live point.
    pub unsafe extern "C" fn EC_POINT_bn2point(group: *const EC_GROUP, bn: *const BIGNUM, point: *mut EC_POINT, ctx: *mut BN_CTX) -> *mut EC_POINT
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(b) = (unsafe { arg(bn) }) else { return ptr::null_mut() };
        let len = b.num_bytes().max(1);
        let Some(buf) = b.to_bin(Some(len), rustyssl_crypto::bn::Endian::Big, false) else {
            return ptr::null_mut();
        };
        let ret = if point.is_null() {
            // SAFETY: as above.
            unsafe { EC_POINT_new(group) }
        } else {
            point
        };
        if ret.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: as above; the encoding.
        if unsafe { EC_POINT_oct2point(group, ret, buf.as_ptr(), buf.len(), ctx) } == 0 {
            if ret != point {
                // SAFETY: the point made above.
                unsafe { EC_POINT_free(ret) };
            }
            return ptr::null_mut();
        }
        ret
    }
}

ffi_export! {
    /// The point's encoding in uppercase hex, in a new string (`OPENSSL_free` it), or NULL.
    ///
    /// # Safety
    /// `group` and `point` are live.
    pub unsafe extern "C" fn EC_POINT_point2hex(group: *const EC_GROUP, point: *const EC_POINT, form: point_conversion_form_t, ctx: *mut BN_CTX) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(enc) = (unsafe { encoding(group, point, form, ctx) }) else {
            return ptr::null_mut();
        };
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut s = Vec::with_capacity(enc.len().saturating_mul(2).saturating_add(1));
        for b in &enc {
            s.push(HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0'));
            s.push(HEX.get(usize::from(b & 15)).copied().unwrap_or(b'0'));
        }
        s.push(0);
        let out: *mut c_char = mem::alloc(enc.len().saturating_mul(2).saturating_add(2)).cast();
        if out.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: a buffer with room for the string and its NUL.
        unsafe { ptr::copy_nonoverlapping(s.as_ptr().cast(), out, s.len()) };
        out
    }
}

ffi_export! {
    /// The point a hex string encodes (into `point`, or a new one), or NULL.
    ///
    /// # Safety
    /// `group` is NULL or live; `hex` is NULL or a string; `point` is NULL or a live point.
    pub unsafe extern "C" fn EC_POINT_hex2point(group: *const EC_GROUP, hex: *const c_char, point: *mut EC_POINT, ctx: *mut BN_CTX) -> *mut EC_POINT
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        if group.is_null() || hex.is_null() {
            return ptr::null_mut();
        }
        let pt = if point.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { EC_POINT_new(group) }
        } else {
            point
        };
        if pt.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's string.
        let len = unsafe { CStr::from_ptr(hex) }.to_bytes().len() / 2;
        let mut buf = vec![0u8; len.max(1)];
        let mut got = 0usize;
        // SAFETY: a buffer of `len` octets; the caller's string; no separator.
        let ok = unsafe { crate::string::OPENSSL_hexstr2buf_ex(buf.as_mut_ptr(), len, &raw mut got, hex, 0) } != 0
            // SAFETY: as above; the octets decoded.
            && unsafe { EC_POINT_oct2point(group, pt, buf.as_ptr(), got, ctx) } != 0;
        // SAFETY: our buffer.
        unsafe { mem::cleanse(buf.as_mut_ptr().cast(), buf.len()) };
        if !ok {
            if pt != point {
                // SAFETY: the point made above.
                unsafe { EC_POINT_free(pt) };
            }
            return ptr::null_mut();
        }
        pt
    }
}

#[cfg(test)]
mod tests {
    use rustyssl_abi::{NID_X9_62_prime256v1, NID_sect163k1};

    use super::*;
    use crate::bn::{BN_free, new_bignum};
    use crate::ec::group::{
        EC_GROUP_cmp, EC_GROUP_free, EC_GROUP_get_curve, EC_GROUP_get_curve_name,
        EC_GROUP_get_degree, EC_GROUP_get0_generator, EC_GROUP_new_by_curve_name,
        EC_GROUP_new_curve_GFp,
    };

    /// docs/DEVIATIONS.md: OpenSSL's binary method runs its ladder on the missing scalar.
    #[test]
    fn a_point_scalar_without_a_point_on_a_binary_curve_gives_infinity() {
        // SAFETY: no preconditions.
        let g = unsafe { EC_GROUP_new_by_curve_name(NID_sect163k1) };
        assert!(!g.is_null());
        // SAFETY: a live group.
        let r = unsafe { EC_POINT_new(g) };
        // SAFETY: as above.
        let gen_pt = unsafe { EC_GROUP_get0_generator(g) };
        // SAFETY: `r` is the group's point, the generator its own.
        assert_eq!(unsafe { EC_POINT_copy(r, gen_pt) }, 1);
        let k = new_bignum(BigNum::from_word(5), false);
        let none = ptr::null_mut();
        // SAFETY: live objects; no generator scalar and no point.
        let ok = unsafe { EC_POINT_mul(g, r, ptr::null(), ptr::null(), k, none) };
        assert_eq!(ok, 1);
        // SAFETY: as above.
        assert_eq!(unsafe { EC_POINT_is_at_infinity(g, r) }, 1);
        // SAFETY: freed once.
        unsafe { BN_free(k) };
        // SAFETY: as above.
        unsafe { EC_POINT_free(r) };
        // SAFETY: as above.
        unsafe { EC_GROUP_free(g) };
    }

    /// docs/DEVIATIONS.md: OpenSSL's dereference a NULL group or point.
    #[test]
    fn a_null_group_or_point_fails() {
        // SAFETY: no preconditions.
        let g = unsafe { EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1) };
        // SAFETY: a live group.
        let p = unsafe { EC_POINT_new(g) };
        let n = ptr::null_mut();
        // SAFETY: live objects or NULL, here and below.
        assert_eq!(unsafe { EC_POINT_add(ptr::null(), p, p, p, n) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EC_POINT_add(g, p, ptr::null(), p, n) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EC_POINT_is_at_infinity(g, ptr::null()) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EC_POINT_is_on_curve(ptr::null(), p, n) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EC_POINT_cmp(g, ptr::null(), p, n) }, -1);
        // SAFETY: as above.
        assert_eq!(unsafe { EC_POINT_copy(p, ptr::null()) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EC_POINT_set_to_infinity(g, ptr::null_mut()) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EC_GROUP_get_degree(ptr::null()) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EC_GROUP_get_curve_name(ptr::null()) }, 0);
        // SAFETY: freed once.
        unsafe { EC_POINT_free(p) };
        // SAFETY: as above.
        unsafe { EC_GROUP_free(g) };
    }

    /// docs/DEVIATIONS.md: OpenSSL's compares the missing generators and crashes.
    #[test]
    fn groups_without_generators_compare() {
        // SAFETY: no preconditions.
        let named = unsafe { EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1) };
        let [p, a, b] = [(); 3].map(|()| new_bignum(BigNum::zero(), false));
        // SAFETY: a live group and numbers.
        let got = unsafe { EC_GROUP_get_curve(named, p, a, b, ptr::null_mut()) };
        assert_eq!(got, 1);
        // SAFETY: live numbers.
        let x = unsafe { EC_GROUP_new_curve_GFp(p, a, b, ptr::null_mut()) };
        // SAFETY: as above.
        let y = unsafe { EC_GROUP_new_curve_GFp(p, a, b, ptr::null_mut()) };
        assert!(!x.is_null() && !y.is_null());
        // SAFETY: live groups.
        assert_eq!(unsafe { EC_GROUP_cmp(x, y, ptr::null_mut()) }, 0);
        for g in [named, x, y] {
            // SAFETY: freed once.
            unsafe { EC_GROUP_free(g) };
        }
        for v in [p, a, b] {
            // SAFETY: as above.
            unsafe { BN_free(v) };
        }
    }
}
