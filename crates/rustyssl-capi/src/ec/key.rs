//! EC keys (`EC_KEY`; `ec_key.c`, `ec_kmeth.c`): a group, a public point, and a private
//! number, held as the `EC_GROUP`, `EC_POINT`, and `BIGNUM` handles OpenSSL's structure holds,
//! so `get0` pointers are those objects; and `EC_KEY_METHOD`, whose functions the key calls
//! (its `init`, `finish`, and setters around every change, and its key generation).
//!
//! The work goes through the public group, point, and number functions in OpenSSL's order, so
//! the errors and the random numbers drawn are the reference's. No lock is held while a
//! method's function runs: it may call any function on the key.

use core::cell::UnsafeCell;
use core::ffi::{CStr, c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicPtr, AtomicUsize, Ordering};
use std::ffi::CString;
use std::sync::{Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    BIGNUM, BN_CTX, BN_FLG_CONSTTIME, CRYPTO_EX_DATA, CRYPTO_EX_INDEX_EC_KEY, EC_FLAG_SM2_RANGE,
    EC_GROUP, EC_KEY, EC_KEY_METHOD, EC_POINT, EC_R_COORDINATES_OUT_OF_RANGE,
    EC_R_INVALID_GROUP_ORDER, EC_R_INVALID_PRIVATE_KEY, EC_R_OPERATION_NOT_SUPPORTED,
    EC_R_POINT_AT_INFINITY, EC_R_POINT_IS_NOT_ON_CURVE, EC_R_WRONG_ORDER, ECDSA_SIG, ENGINE,
    ERR_LIB_EC, ERR_LIB_PROV, ERR_R_BN_LIB, ERR_R_CRYPTO_LIB, ERR_R_EC_LIB, ERR_R_INIT_FAIL,
    ERR_R_PASSED_NULL_PARAMETER, NID_X9_62_prime_field, NID_sm2, OSSL_KEYMGMT_SELECT_ALL,
    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, OSSL_KEYMGMT_SELECT_KEYPAIR,
    OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
    OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_LIB_CTX, POINT_CONVERSION_UNCOMPRESSED,
    PROV_R_FAILED_TO_GENERATE_KEY, PROV_R_INVALID_CURVE, PROV_R_INVALID_INPUT_LENGTH,
    point_conversion_form_t,
};

use super::curves::EC_curve_nid2nist;
use super::group::{
    EC_GROUP_dup, EC_GROUP_free, EC_GROUP_get_curve_name, EC_GROUP_get_degree,
    EC_GROUP_get_field_type, EC_GROUP_get0_cofactor, EC_GROUP_get0_field, EC_GROUP_get0_order,
    EC_GROUP_new_by_curve_name_ex, EC_GROUP_order_bits, EC_GROUP_precompute_mult,
    EC_GROUP_set_asn1_flag, EC_GROUP_set_point_conversion_form, decoded_from_explicit,
};
use super::point::{
    EC_POINT_cmp, EC_POINT_copy, EC_POINT_dup, EC_POINT_free, EC_POINT_get_affine_coordinates,
    EC_POINT_is_at_infinity, EC_POINT_is_on_curve, EC_POINT_mul, EC_POINT_new, EC_POINT_oct2point,
    EC_POINT_point2buf, EC_POINT_set_affine_coordinates, EC_POINT_set_to_infinity,
};
use crate::bn::arith::BN_sub;
use crate::bn::conv::{BN_bin2bn, BN_bn2binpad};
use crate::bn::ctx::{BN_CTX_free, BN_CTX_new_ex, BN_CTX_secure_new_ex};
use crate::bn::rand::BN_priv_rand_range_ex;
use crate::bn::value;
use crate::bn::{
    BN_clear, BN_clear_free, BN_cmp, BN_copy, BN_dup, BN_free, BN_is_negative, BN_is_one,
    BN_is_zero, BN_new, BN_num_bits, BN_secure_new, BN_set_flags, BN_value_one,
};
use crate::err;
use crate::ex_data::{
    CRYPTO_dup_ex_data, CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_new_ex_data,
    CRYPTO_set_ex_data,
};
use crate::ffi::{ffi_callback, ffi_export};
use crate::handle::{Handle, handle_type};
use crate::mem;
use crate::provider::Ptr;
use rustyssl_crypto::bn::Endian;
use rustyssl_crypto::ec::dhkem;

/// Raises an EC error from `func`.
fn raise(reason: c_int, func: &'static str) {
    err::raise(ERR_LIB_EC, reason, func);
}

type InitFn = unsafe extern "C" fn(key: *mut EC_KEY) -> c_int;
type FinishFn = unsafe extern "C" fn(key: *mut EC_KEY);
type CopyFn = unsafe extern "C" fn(dest: *mut EC_KEY, src: *const EC_KEY) -> c_int;
type SetGroupFn = unsafe extern "C" fn(key: *mut EC_KEY, grp: *const EC_GROUP) -> c_int;
type SetPrivateFn = unsafe extern "C" fn(key: *mut EC_KEY, priv_key: *const BIGNUM) -> c_int;
type SetPublicFn = unsafe extern "C" fn(key: *mut EC_KEY, pub_key: *const EC_POINT) -> c_int;
type KeygenFn = unsafe extern "C" fn(key: *mut EC_KEY) -> c_int;
pub(crate) type ComputeKeyFn = unsafe extern "C" fn(
    psec: *mut *mut c_uchar,
    pseclen: *mut usize,
    pub_key: *const EC_POINT,
    ecdh: *const EC_KEY,
) -> c_int;
pub(crate) type SignFn = unsafe extern "C" fn(
    type_: c_int,
    dgst: *const c_uchar,
    dlen: c_int,
    sig: *mut c_uchar,
    siglen: *mut c_uint,
    kinv: *const BIGNUM,
    r: *const BIGNUM,
    eckey: *mut EC_KEY,
) -> c_int;
pub(crate) type SignSetupFn = unsafe extern "C" fn(
    eckey: *mut EC_KEY,
    ctx_in: *mut BN_CTX,
    kinvp: *mut *mut BIGNUM,
    rp: *mut *mut BIGNUM,
) -> c_int;
pub(crate) type SignSigFn = unsafe extern "C" fn(
    dgst: *const c_uchar,
    dgst_len: c_int,
    in_kinv: *const BIGNUM,
    in_r: *const BIGNUM,
    eckey: *mut EC_KEY,
) -> *mut ECDSA_SIG;
pub(crate) type VerifyFn = unsafe extern "C" fn(
    type_: c_int,
    dgst: *const c_uchar,
    dgst_len: c_int,
    sigbuf: *const c_uchar,
    sig_len: c_int,
    eckey: *mut EC_KEY,
) -> c_int;
pub(crate) type VerifySigFn = unsafe extern "C" fn(
    dgst: *const c_uchar,
    dgst_len: c_int,
    sig: *const ECDSA_SIG,
    eckey: *mut EC_KEY,
) -> c_int;

/// `EC_KEY_METHOD` (`struct ec_key_method_st`), which applications see only through pointers.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Method {
    name: *const c_char,
    flags: i32,
    init: Option<InitFn>,
    finish: Option<FinishFn>,
    copy: Option<CopyFn>,
    set_group: Option<SetGroupFn>,
    set_private: Option<SetPrivateFn>,
    set_public: Option<SetPublicFn>,
    keygen: Option<KeygenFn>,
    pub(crate) compute_key: Option<ComputeKeyFn>,
    pub(crate) sign: Option<SignFn>,
    pub(crate) sign_setup: Option<SignSetupFn>,
    pub(crate) sign_sig: Option<SignSigFn>,
    pub(crate) verify: Option<VerifyFn>,
    pub(crate) verify_sig: Option<VerifySigFn>,
}

// SAFETY: an immutable table of a static name and functions.
unsafe impl Sync for Method {}

/// `EC_KEY_METHOD_DYNAMIC`: a method `EC_KEY_METHOD_new` made, which `EC_KEY_METHOD_free`
/// frees.
const DYNAMIC: i32 = 1;

/// `EC_KEY_OpenSSL()`: the library's method. Its signing and agreement functions are ECDSA's
/// and ECDH's (`ecdsa.rs`).
static OPENSSL_METHOD: Method = Method {
    name: c"OpenSSL EC_KEY method".as_ptr(),
    flags: 0,
    init: None,
    finish: None,
    copy: None,
    set_group: None,
    set_private: None,
    set_public: None,
    keygen: Some(ossl_ec_key_gen),
    compute_key: Some(super::ecdsa::ossl_ecdh_compute_key),
    sign: Some(super::ecdsa::ossl_ecdsa_sign),
    sign_setup: Some(super::ecdsa::ossl_ecdsa_sign_setup),
    sign_sig: Some(super::ecdsa::ossl_ecdsa_sign_sig),
    verify: Some(super::ecdsa::ossl_ecdsa_verify),
    verify_sig: Some(super::ecdsa::ossl_ecdsa_verify_sig),
};

/// The default method for new keys: the library's unless the application set one.
static DEFAULT_METHOD: AtomicPtr<Method> = AtomicPtr::new(ptr::null_mut());

/// The library's method.
fn openssl_method() -> *const Method {
    &raw const OPENSSL_METHOD
}

/// The default method.
pub(crate) fn default_method() -> *const Method {
    let m = DEFAULT_METHOD.load(Ordering::Acquire);
    if m.is_null() {
        openssl_method()
    } else {
        m.cast_const()
    }
}

/// The method behind a pointer (a copy of its table), or `None`.
///
/// # Safety
/// `m` is NULL or a live method.
pub(crate) unsafe fn method(m: *const Method) -> Option<Method> {
    // SAFETY: the caller's guarantee.
    unsafe { m.as_ref() }.copied()
}

/// A key's fields, as OpenSSL's `EC_KEY` holds them.
#[derive(Clone, Copy)]
pub(crate) struct Fields {
    pub(crate) libctx: Ptr<OSSL_LIB_CTX>,
    pub(crate) meth: Ptr<Method>,
    pub(crate) group: Ptr<EC_GROUP>,
    pub(crate) pub_key: Ptr<EC_POINT>,
    pub(crate) priv_key: Ptr<BIGNUM>,
    pub(crate) enc_flag: c_uint,
    pub(crate) conv_form: point_conversion_form_t,
    pub(crate) version: c_int,
    pub(crate) flags: c_int,
}

/// The key's ex_data, which only the ex_data functions touch.
struct ExData(UnsafeCell<CRYPTO_EX_DATA>);

// SAFETY: the ex_data functions are the only users, and OpenSSL leaves serializing them to the
// application.
unsafe impl Send for ExData {}
// SAFETY: as above.
unsafe impl Sync for ExData {}

/// An EC key, shared by reference.
pub(crate) struct EcKey {
    references: AtomicI32,
    /// `dirty_cnt`: bumped at each change, for an `EVP_PKEY` holding the key.
    dirty: AtomicUsize,
    /// The property query the key was made with.
    propq: Option<CString>,
    fields: Mutex<Fields>,
    ex_data: ExData,
}

handle_type!(EC_KEY => EcKey);

impl Drop for EcKey {
    fn drop(&mut self) {
        let f = *self
            .fields
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        // SAFETY: the key's own objects, or NULL, each freed once.
        unsafe { EC_GROUP_free(f.group.0) };
        // SAFETY: as above.
        unsafe { EC_POINT_free(f.pub_key.0) };
        // SAFETY: as above.
        unsafe { BN_clear_free(f.priv_key.0) };
    }
}

impl EcKey {
    fn lock(&self) -> MutexGuard<'_, Fields> {
        self.fields.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A copy of the fields.
    pub(crate) fn get(&self) -> Fields {
        *self.lock()
    }

    /// Changes the fields with `f`.
    pub(crate) fn update<T>(&self, f: impl FnOnce(&mut Fields) -> T) -> T {
        f(&mut self.lock())
    }

    /// Notes a change.
    pub(crate) fn touch(&self) {
        self.dirty.fetch_add(1, Ordering::AcqRel);
    }

    /// The change count.
    pub(crate) fn dirty_count(&self) -> usize {
        self.dirty.load(Ordering::Acquire)
    }

    /// The property query, or NULL.
    pub(crate) fn propq(&self) -> *const c_char {
        self.propq.as_ref().map_or(ptr::null(), |p| p.as_ptr())
    }

    fn ex_data(&self) -> *mut CRYPTO_EX_DATA {
        self.ex_data.0.get()
    }
}

/// The key behind a handle.
///
/// # Safety
/// `k` is NULL or a live key.
pub(crate) unsafe fn key<'a>(k: *const EC_KEY) -> Option<&'a EcKey> {
    // SAFETY: the caller's guarantee.
    unsafe { EC_KEY::get(k) }
}

/// `ossl_ec_key_new_method_int`: a key with the default method (whose `init` runs), or NULL.
///
/// # Safety
/// `propq` is NULL or a string.
pub(crate) unsafe fn new_key(libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut EC_KEY {
    let propq = if propq.is_null() {
        None
    } else {
        // SAFETY: the caller's guarantee.
        Some(unsafe { CStr::from_ptr(propq) }.to_owned())
    };
    let meth = default_method();
    let h = EC_KEY::new_handle(EcKey {
        references: AtomicI32::new(1),
        dirty: AtomicUsize::new(0),
        propq,
        fields: Mutex::new(Fields {
            libctx: Ptr(libctx),
            meth: Ptr(meth.cast_mut()),
            group: Ptr(ptr::null_mut()),
            pub_key: Ptr(ptr::null_mut()),
            priv_key: Ptr(ptr::null_mut()),
            enc_flag: 0,
            conv_form: POINT_CONVERSION_UNCOMPRESSED,
            version: 1,
            flags: 0,
        }),
        ex_data: ExData(UnsafeCell::new(CRYPTO_EX_DATA {
            ctx: ptr::null_mut(),
            sk: ptr::null_mut(),
        })),
    });
    // SAFETY: just made.
    let Some(k) = (unsafe { key(h) }) else {
        return ptr::null_mut();
    };
    // SAFETY: the key's own ex_data.
    if unsafe { CRYPTO_new_ex_data(CRYPTO_EX_INDEX_EC_KEY, h.cast(), k.ex_data()) } == 0 {
        raise(ERR_R_CRYPTO_LIB, "ossl_ec_key_new_method_int");
        // SAFETY: the only reference.
        unsafe { free(h) };
        return ptr::null_mut();
    }
    // SAFETY: a live method; no lock is held while its function runs.
    if let Some(init) = unsafe { method(meth) }.and_then(|m| m.init)
        // SAFETY: the method's function takes the key.
        && unsafe { init(h) } == 0
    {
        raise(ERR_R_INIT_FAIL, "ossl_ec_key_new_method_int");
        // SAFETY: as above.
        unsafe { free(h) };
        return ptr::null_mut();
    }
    h
}

/// `EC_KEY_free`'s work.
///
/// # Safety
/// `r` is NULL or a live key whose reference the caller gives up.
pub(crate) unsafe fn free(r: *mut EC_KEY) {
    // SAFETY: the caller's guarantee.
    let Some(held) = (unsafe { EC_KEY::hold(r) }) else {
        return;
    };
    let left = held
        .references
        .fetch_sub(1, Ordering::AcqRel)
        .saturating_sub(1);
    if left != 0 {
        return;
    }
    let f = held.get();
    // SAFETY: the key's method; no lock is held while its function runs.
    if let Some(finish) = unsafe { method(f.meth.0) }.and_then(|m| m.finish) {
        // SAFETY: the method's function takes the key.
        unsafe { finish(r) };
    }
    // SAFETY: the key's own ex_data; its last reference.
    unsafe { CRYPTO_free_ex_data(CRYPTO_EX_INDEX_EC_KEY, r.cast(), held.ex_data()) };
    // SAFETY: the last reference; the hold keeps the key until this returns.
    unsafe { EC_KEY::free(r) };
}

ffi_export! {
    /// A new key without a group.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EC_KEY_new() -> *mut EC_KEY
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: no query.
        unsafe { new_key(ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// A new key in a library context, with a property query.
    ///
    /// # Safety
    /// `propq` is NULL or a string.
    pub unsafe extern "C" fn EC_KEY_new_ex(ctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut EC_KEY
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { new_key(ctx, propq) }
    }
}

ffi_export! {
    /// A new key with the default method; rustyssl has no engines.
    ///
    /// # Safety
    /// `engine` is NULL.
    pub unsafe extern "C" fn EC_KEY_new_method(engine: *mut ENGINE) -> *mut EC_KEY
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        if !engine.is_null() {
            crate::stub::unimplemented("EC_KEY_new_method with an engine (rustyssl has none)");
        }
        // SAFETY: no query.
        unsafe { new_key(ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// A new key on the named curve, or NULL.
    ///
    /// # Safety
    /// `propq` is NULL or a string.
    pub unsafe extern "C" fn EC_KEY_new_by_curve_name_ex(ctx: *mut OSSL_LIB_CTX, propq: *const c_char, nid: c_int) -> *mut EC_KEY
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let ret = unsafe { new_key(ctx, propq) };
        // SAFETY: just made.
        let Some(k) = (unsafe { key(ret) }) else { return ptr::null_mut() };
        // SAFETY: as above.
        let group = unsafe { EC_GROUP_new_by_curve_name_ex(ctx, propq, nid) };
        if group.is_null() {
            // SAFETY: the key made above.
            unsafe { free(ret) };
            return ptr::null_mut();
        }
        k.update(|f| f.group = Ptr(group));
        // SAFETY: the key's method; no lock is held while its function runs.
        if let Some(set_group) = unsafe { method(k.get().meth.0) }.and_then(|m| m.set_group)
            // SAFETY: the method's function takes the key and its group.
            && unsafe { set_group(ret, group) } == 0
        {
            // SAFETY: as above.
            unsafe { free(ret) };
            return ptr::null_mut();
        }
        ret
    }
}

ffi_export! {
    /// `EC_KEY_new_by_curve_name_ex` in the default context.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EC_KEY_new_by_curve_name(nid: c_int) -> *mut EC_KEY
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: no query.
        unsafe { EC_KEY_new_by_curve_name_ex(ptr::null_mut(), ptr::null(), nid) }
    }
}

ffi_export! {
    /// Drops a reference; at the last, the method's `finish` runs and the key is freed. NULL
    /// does nothing.
    ///
    /// # Safety
    /// `r` is NULL or a live key whose reference the caller gives up.
    pub unsafe extern "C" fn EC_KEY_free(r: *mut EC_KEY)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { free(r) };
    }
}

ffi_export! {
    /// Adds a reference. 1, or 0 for NULL.
    ///
    /// # Safety
    /// `r` is NULL or a live key.
    pub unsafe extern "C" fn EC_KEY_up_ref(r: *mut EC_KEY) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(r) }) else { return 0 };
        let n = k.references.fetch_add(1, Ordering::AcqRel).saturating_add(1);
        c_int::from(n > 1)
    }
}

ffi_export! {
    /// The key's engine: always NULL, as rustyssl has no engines.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EC_KEY_get0_engine(eckey: *const EC_KEY) -> *mut ENGINE
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        let _ = eckey;
        ptr::null_mut()
    }
}

/// A copy of a number (the key's private one, with `BN_FLG_CONSTTIME`), or NULL.
///
/// # Safety
/// `b` is a live number.
unsafe fn dup_secret(b: *const BIGNUM) -> *mut BIGNUM {
    // SAFETY: the caller's guarantee.
    let t = unsafe { BN_dup(b) };
    if !t.is_null() {
        // SAFETY: the copy.
        unsafe { BN_set_flags(t, BN_FLG_CONSTTIME) };
    }
    t
}

ffi_export! {
    /// Copies `src` into `dest` (its group, keys, flags, forms, ex_data, and method, whose
    /// `copy` runs). `dest`, or NULL.
    ///
    /// # Safety
    /// `dest` and `src` are NULL or live keys.
    pub unsafe extern "C" fn EC_KEY_copy(dest: *mut EC_KEY, src: *const EC_KEY) -> *mut EC_KEY
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let (Some(d), Some(s)) = (unsafe { key(dest) }, unsafe { key(src) }) else {
            raise(ERR_R_PASSED_NULL_PARAMETER, "EC_KEY_copy");
            return ptr::null_mut();
        };
        let sf = s.get();
        let df = d.get();
        if sf.meth.0 != df.meth.0 {
            // SAFETY: the method; no lock is held while its function runs.
            if let Some(finish) = unsafe { method(df.meth.0) }.and_then(|m| m.finish) {
                // SAFETY: the method's function takes the key.
                unsafe { finish(dest) };
            }
        }
        d.update(|f| f.libctx = sf.libctx);
        if !sf.group.0.is_null() {
            // SAFETY: the source's group.
            let g = unsafe { EC_GROUP_dup(sf.group.0) };
            let old = d.update(|f| core::mem::replace(&mut f.group, Ptr(g)));
            // SAFETY: the old group, freed once.
            unsafe { EC_GROUP_free(old.0) };
            if g.is_null() {
                return ptr::null_mut();
            }
            if !sf.pub_key.0.is_null() {
                // SAFETY: the new group.
                let p = unsafe { EC_POINT_new(g) };
                let old = d.update(|f| core::mem::replace(&mut f.pub_key, Ptr(p)));
                // SAFETY: the old point, freed once.
                unsafe { EC_POINT_free(old.0) };
                // SAFETY: the point; the source's point.
                if p.is_null() || unsafe { EC_POINT_copy(p, sf.pub_key.0) } == 0 {
                    return ptr::null_mut();
                }
            }
            if !sf.priv_key.0.is_null() {
                let mut b = d.get().priv_key.0;
                if b.is_null() {
                    // SAFETY: no preconditions.
                    b = unsafe { BN_new() };
                    if b.is_null() {
                        return ptr::null_mut();
                    }
                    d.update(|f| f.priv_key = Ptr(b));
                }
                // SAFETY: live numbers.
                if unsafe { BN_copy(b, sf.priv_key.0) }.is_null() {
                    return ptr::null_mut();
                }
            }
        }
        d.update(|f| {
            f.enc_flag = sf.enc_flag;
            f.conv_form = sf.conv_form;
            f.version = sf.version;
            f.flags = sf.flags;
        });
        // SAFETY: the keys' own ex_data.
        if unsafe { CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_EC_KEY, d.ex_data(), s.ex_data()) } == 0 {
            return ptr::null_mut();
        }
        if sf.meth.0 != df.meth.0 {
            d.update(|f| f.meth = sf.meth);
        }
        // SAFETY: the source's method; no lock is held while its function runs.
        if let Some(copy) = unsafe { method(sf.meth.0) }.and_then(|m| m.copy)
            // SAFETY: the method's function takes the keys.
            && unsafe { copy(dest, src) } == 0
        {
            return ptr::null_mut();
        }
        d.touch();
        dest
    }
}

/// `ossl_ec_key_dup`: a new key (made with the default method, whose `init` runs) with the
/// parts of `src` that `selection` names: its group (and method) for the domain parameters,
/// its public and private keys (which need the group), its forms for the other parameters, and
/// always its flags and ex_data. A method with a `copy` function needs the whole key pair
/// selected, then runs it. NULL on failure.
///
/// # Safety
/// `src` is NULL or a live key.
pub(crate) unsafe fn dup(src: *const EC_KEY, selection: c_int) -> *mut EC_KEY {
    // SAFETY: the caller's guarantee.
    let Some(s) = (unsafe { key(src) }) else {
        raise(ERR_R_PASSED_NULL_PARAMETER, "ossl_ec_key_dup");
        return ptr::null_mut();
    };
    let sf = s.get();
    // SAFETY: the source's context and query.
    let ret = unsafe { new_key(sf.libctx.0, s.propq()) };
    // SAFETY: just made.
    let Some(d) = (unsafe { key(ret) }) else {
        return ptr::null_mut();
    };
    let selected = |what: c_int| selection & what != 0;
    let ok = (|| {
        if !sf.group.0.is_null() && selected(OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
            // SAFETY: the source's group.
            let g = unsafe { EC_GROUP_dup(sf.group.0) };
            if g.is_null() {
                return false;
            }
            d.update(|f| {
                f.group = Ptr(g);
                if !sf.meth.0.is_null() {
                    f.meth = sf.meth;
                }
            });
        }
        let g = d.get().group.0;
        if !sf.pub_key.0.is_null() && selected(OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
            if g.is_null() {
                return false;
            }
            // SAFETY: the group.
            let p = unsafe { EC_POINT_new(g) };
            d.update(|f| f.pub_key = Ptr(p));
            // SAFETY: the point; the source's point.
            if p.is_null() || unsafe { EC_POINT_copy(p, sf.pub_key.0) } == 0 {
                return false;
            }
        }
        if !sf.priv_key.0.is_null() && selected(OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
            if g.is_null() {
                return false;
            }
            // SAFETY: no preconditions.
            let b = unsafe { BN_new() };
            d.update(|f| f.priv_key = Ptr(b));
            // SAFETY: live numbers.
            if b.is_null() || unsafe { BN_copy(b, sf.priv_key.0) }.is_null() {
                return false;
            }
        }
        d.update(|f| {
            if selected(OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) {
                f.enc_flag = sf.enc_flag;
                f.conv_form = sf.conv_form;
            }
            f.version = sf.version;
            f.flags = sf.flags;
        });
        // SAFETY: the keys' own ex_data.
        if unsafe { CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_EC_KEY, d.ex_data(), s.ex_data()) } == 0 {
            return false;
        }
        // SAFETY: the key's method; no lock is held while its function runs.
        if let Some(copy) = unsafe { method(d.get().meth.0) }.and_then(|m| m.copy) {
            let keypair = OSSL_KEYMGMT_SELECT_KEYPAIR;
            // SAFETY: the method's function takes the keys.
            if selection & keypair != keypair || unsafe { copy(ret, src) } == 0 {
                return false;
            }
        }
        true
    })();
    if ok {
        return ret;
    }
    // SAFETY: the key made above.
    unsafe { free(ret) };
    ptr::null_mut()
}

ffi_export! {
    /// A new key with a copy of everything in `ec_key` (`ossl_ec_key_dup` of all of it).
    ///
    /// # Safety
    /// `ec_key` is NULL or a live key.
    pub unsafe extern "C" fn EC_KEY_dup(ec_key: *const EC_KEY) -> *mut EC_KEY
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { dup(ec_key, OSSL_KEYMGMT_SELECT_ALL) }
    }
}

/// `ec_generate_key`: a private key in `[1, n-1]` (`[1, n-2]` for SM2's range) and its public
/// key, into the key's own objects; on failure the private key is zeroed and the public key
/// set to infinity.
///
/// # Safety
/// `k` is a live key with a group.
unsafe fn generate(h: *mut EC_KEY, k: &EcKey) -> bool {
    let f = k.get();
    let group = f.group.0;
    let sm2 = f.flags & EC_FLAG_SM2_RANGE != 0;
    // SAFETY: the key's context.
    let ctx = unsafe { BN_CTX_secure_new_ex(f.libctx.0) };
    let mut priv_key = f.priv_key.0;
    let mut pub_key = f.pub_key.0;
    let mut order: *mut BIGNUM = ptr::null_mut();
    let ok = (|| {
        if ctx.is_null() {
            return false;
        }
        if priv_key.is_null() {
            // SAFETY: no preconditions.
            priv_key = unsafe { BN_secure_new() };
            if priv_key.is_null() {
                return false;
            }
        }
        // SAFETY: the key's group.
        let tmp = unsafe { EC_GROUP_get0_order(group) };
        if tmp.is_null() {
            return false;
        }
        if sm2 {
            // SAFETY: no preconditions.
            order = unsafe { BN_new() };
            // SAFETY: no preconditions.
            let one = unsafe { BN_value_one() };
            // SAFETY: live numbers.
            if order.is_null() || unsafe { BN_sub(order, tmp, one) } == 0 {
                return false;
            }
        } else {
            // SAFETY: the group's order.
            order = unsafe { BN_dup(tmp) };
            if order.is_null() {
                return false;
            }
        }
        loop {
            // SAFETY: live numbers and context.
            if unsafe { BN_priv_rand_range_ex(priv_key, order, 0, ctx) } == 0 {
                return false;
            }
            // SAFETY: a live number.
            if unsafe { BN_is_zero(priv_key) } == 0 {
                break;
            }
        }
        if pub_key.is_null() {
            // SAFETY: the group.
            pub_key = unsafe { EC_POINT_new(group) };
            if pub_key.is_null() {
                return false;
            }
        }
        // SAFETY: the group, the point, the number, and the context.
        if unsafe { EC_POINT_mul(group, pub_key, priv_key, ptr::null(), ptr::null(), ctx) } == 0 {
            return false;
        }
        k.update(|f| {
            f.priv_key = Ptr(priv_key);
            f.pub_key = Ptr(pub_key);
        });
        priv_key = ptr::null_mut();
        pub_key = ptr::null_mut();
        k.touch();
        true
    })();
    if !ok {
        let f = k.get();
        // SAFETY: NULL or the key's number.
        unsafe { BN_clear(f.priv_key.0) };
        if !f.pub_key.0.is_null() {
            // SAFETY: the key's group and point.
            unsafe { EC_POINT_set_to_infinity(group, f.pub_key.0) };
        }
    }
    let f = k.get();
    if pub_key != f.pub_key.0 {
        // SAFETY: a point made above and not kept, or NULL.
        unsafe { EC_POINT_free(pub_key) };
    }
    if priv_key != f.priv_key.0 {
        // SAFETY: a number made above and not kept, or NULL.
        unsafe { BN_clear_free(priv_key) };
    }
    // SAFETY: NULL or made above.
    unsafe { BN_CTX_free(ctx) };
    // SAFETY: as above.
    unsafe { BN_free(order) };
    let _ = h;
    ok
}

/// `ossl_ec_dhkem_derive_private`: the private key RFC 9180's `DeriveKeyPair` derives from
/// `ikm` for the KEM over the group's curve, or `None`, with an error raised unless the curve
/// has no NIST name.
///
/// # Safety
/// `group` is a live group.
unsafe fn dhkem_private(group: *const EC_GROUP, ikm: &[u8]) -> Option<Vec<u8>> {
    // SAFETY: the caller's guarantee.
    let nid = unsafe { EC_GROUP_get_curve_name(group) };
    // SAFETY: no preconditions.
    let name = unsafe { EC_curve_nid2nist(nid) };
    if name.is_null() {
        return None;
    }
    // SAFETY: a static name of the table.
    let name = unsafe { CStr::from_ptr(name) };
    let Some(kem) = dhkem::kem_by_curve(name.to_bytes()) else {
        err::raise(
            ERR_LIB_PROV,
            PROV_R_INVALID_CURVE,
            "ossl_HPKE_KEM_INFO_find_curve",
        );
        return None;
    };
    // SAFETY: the caller's group.
    let order = unsafe { EC_GROUP_get0_order(group) };
    // SAFETY: the group's order.
    let order = unsafe { value(order) }?;
    const F: &str = "ossl_ec_dhkem_derive_private";
    match dhkem::derive_private(kem, &order, ikm) {
        Ok(sk) => sk
            .to_bin(Some(kem.private_len), Endian::Big, false)
            .map(|z| z.to_vec()),
        Err(dhkem::Error::ShortInput { len, min }) => {
            let text = format!("ikm length is :{len}, should be at least {min}");
            err::raise_with_text(ERR_LIB_PROV, PROV_R_INVALID_INPUT_LENGTH, F, &text);
            None
        }
        Err(dhkem::Error::Exhausted) => {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY, F);
            None
        }
        Err(dhkem::Error::Kdf(_)) => None,
    }
}

/// `ossl_ec_generate_key_dhkem`: the private key derived from `ikm` and its public key, into
/// the key's own objects; on failure the private key is freed and the public key set to
/// infinity.
///
/// # Safety
/// `h` is a live key with a group.
pub(crate) unsafe fn generate_dhkem(h: *mut EC_KEY, ikm: &[u8]) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { key(h) }) else {
        return false;
    };
    let group = k.get().group.0;
    let ok = (|| {
        let mut priv_key = k.get().priv_key.0;
        if priv_key.is_null() {
            // SAFETY: no preconditions.
            priv_key = unsafe { BN_secure_new() };
            if priv_key.is_null() {
                return false;
            }
            k.update(|f| f.priv_key = Ptr(priv_key));
        }
        // SAFETY: the key's group.
        let Some(sk) = (unsafe { dhkem_private(group, ikm) }) else {
            return false;
        };
        let Ok(len) = c_int::try_from(sk.len()) else {
            return false;
        };
        // SAFETY: the derived octets; the key's number.
        if unsafe { BN_bin2bn(sk.as_ptr(), len, priv_key) }.is_null() {
            return false;
        }
        let mut pub_key = k.get().pub_key.0;
        if pub_key.is_null() {
            // SAFETY: the key's group.
            pub_key = unsafe { EC_POINT_new(group) };
            if pub_key.is_null() {
                return false;
            }
            k.update(|f| f.pub_key = Ptr(pub_key));
        }
        // SAFETY: the key's context.
        let ctx = unsafe { BN_CTX_new_ex(k.get().libctx.0) };
        // SAFETY: the group, the point, the number, and the context.
        let ok = !ctx.is_null()
            // SAFETY: as above.
            && unsafe { EC_POINT_mul(group, pub_key, priv_key, ptr::null(), ptr::null(), ctx) } != 0;
        // SAFETY: NULL or made above.
        unsafe { BN_CTX_free(ctx) };
        ok
    })();
    if !ok {
        let old = k.update(|f| core::mem::replace(&mut f.priv_key, Ptr(ptr::null_mut())));
        // SAFETY: the key's number, freed once.
        unsafe { BN_clear_free(old.0) };
        let pub_key = k.get().pub_key.0;
        if !pub_key.is_null() {
            // SAFETY: the key's group and point.
            unsafe { EC_POINT_set_to_infinity(group, pub_key) };
        }
    }
    k.touch();
    ok
}

ffi_callback! {
    /// `ossl_ec_key_gen`, the library method's key generation: the group method's (each
    /// built-in one generates by `ec_generate_key`).
    ///
    /// # Safety
    /// `eckey` is a live key with a group.
    pub(crate) unsafe extern "C" fn ossl_ec_key_gen(eckey: *mut EC_KEY) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(eckey) }) else { return 0 };
        // SAFETY: as above.
        let ok = unsafe { generate(eckey, k) };
        if ok {
            k.touch();
        }
        c_int::from(ok)
    }
}

ffi_export! {
    /// Generates a key pair with the key's method. 1, or 0.
    ///
    /// # Safety
    /// `eckey` is NULL or a live key.
    pub unsafe extern "C" fn EC_KEY_generate_key(eckey: *mut EC_KEY) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(eckey) }).filter(|k| !k.get().group.0.is_null()) else {
            raise(ERR_R_PASSED_NULL_PARAMETER, "EC_KEY_generate_key");
            return 0;
        };
        // SAFETY: the key's method; no lock is held while its function runs.
        let Some(keygen) = (unsafe { method(k.get().meth.0) }).and_then(|m| m.keygen) else {
            raise(EC_R_OPERATION_NOT_SUPPORTED, "EC_KEY_generate_key");
            return 0;
        };
        // SAFETY: the method's function takes the key.
        let ret = unsafe { keygen(eckey) };
        if ret == 1 {
            k.touch();
        }
        ret
    }
}

/// `ec_key_public_range_check`: whether the public key's affine coordinates are field
/// elements.
///
/// # Safety
/// The objects are live.
unsafe fn public_range_check(
    group: *const EC_GROUP,
    pub_key: *const EC_POINT,
    ctx: *mut BN_CTX,
) -> bool {
    // SAFETY: no preconditions.
    let (x, y) = (unsafe { BN_new() }, unsafe { BN_new() });
    let ok = (|| {
        if x.is_null() || y.is_null() {
            return false;
        }
        // SAFETY: the caller's objects; live numbers.
        if unsafe { EC_POINT_get_affine_coordinates(group, pub_key, x, y, ctx) } == 0 {
            return false;
        }
        // SAFETY: the group.
        if unsafe { EC_GROUP_get_field_type(group) } == NID_X9_62_prime_field {
            // SAFETY: as above.
            let p = unsafe { EC_GROUP_get0_field(group) };
            // SAFETY: live numbers.
            let bad = |v: *const BIGNUM| unsafe { BN_is_negative(v) } != 0 || unsafe { BN_cmp(v, p) } >= 0;
            !bad(x) && !bad(y)
        } else {
            // SAFETY: the group.
            let m = unsafe { EC_GROUP_get_degree(group) };
            // SAFETY: live numbers.
            (unsafe { BN_num_bits(x) }) <= m && unsafe { BN_num_bits(y) } <= m
        }
    })();
    // SAFETY: made above, or NULL.
    unsafe { BN_free(x) };
    // SAFETY: as above.
    unsafe { BN_free(y) };
    ok
}

/// `ossl_ec_key_public_check_quick`: the public key isn't infinity, and is in range and on the
/// curve.
///
/// # Safety
/// `f` holds NULL or live objects.
pub(crate) unsafe fn public_check_quick(f: &Fields, ctx: *mut BN_CTX) -> bool {
    let (group, pub_key) = (f.group.0.cast_const(), f.pub_key.0.cast_const());
    if group.is_null() || pub_key.is_null() {
        raise(
            ERR_R_PASSED_NULL_PARAMETER,
            "ossl_ec_key_public_check_quick",
        );
        return false;
    }
    // SAFETY: the caller's guarantee, here and below.
    if unsafe { EC_POINT_is_at_infinity(group, pub_key) } != 0 {
        raise(EC_R_POINT_AT_INFINITY, "ossl_ec_key_public_check_quick");
        return false;
    }
    // SAFETY: as above.
    if !unsafe { public_range_check(group, pub_key, ctx) } {
        raise(
            EC_R_COORDINATES_OUT_OF_RANGE,
            "ossl_ec_key_public_check_quick",
        );
        return false;
    }
    // SAFETY: as above.
    if unsafe { EC_POINT_is_on_curve(group, pub_key, ctx) } <= 0 {
        raise(EC_R_POINT_IS_NOT_ON_CURVE, "ossl_ec_key_public_check_quick");
        return false;
    }
    true
}

/// `ossl_ec_key_public_check`: the quick checks, then (for a cofactor other than one) that the
/// public key has the group's order.
///
/// # Safety
/// `f` holds NULL or live objects.
pub(crate) unsafe fn public_check(f: &Fields, ctx: *mut BN_CTX) -> bool {
    // SAFETY: the caller's guarantee.
    if !unsafe { public_check_quick(f, ctx) } {
        return false;
    }
    let (group, pub_key) = (f.group.0.cast_const(), f.pub_key.0.cast_const());
    // SAFETY: as above.
    let cofactor = unsafe { EC_GROUP_get0_cofactor(group) };
    // SAFETY: the group's number.
    if !cofactor.is_null() && unsafe { BN_is_one(cofactor) } != 0 {
        return true;
    }
    // SAFETY: as above.
    let point = unsafe { EC_POINT_new(group) };
    if point.is_null() {
        return false;
    }
    let ok = (|| {
        // SAFETY: as above.
        let order = unsafe { EC_GROUP_get0_order(group) };
        // SAFETY: the group's number.
        if unsafe { BN_is_zero(order) } != 0 {
            raise(EC_R_INVALID_GROUP_ORDER, "ossl_ec_key_public_check");
            return false;
        }
        // SAFETY: the group, the point, the key, and the order.
        if unsafe { EC_POINT_mul(group, point, ptr::null(), pub_key, order, ctx) } == 0 {
            raise(ERR_R_EC_LIB, "ossl_ec_key_public_check");
            return false;
        }
        // SAFETY: as above.
        if unsafe { EC_POINT_is_at_infinity(group, point) } == 0 {
            raise(EC_R_WRONG_ORDER, "ossl_ec_key_public_check");
            return false;
        }
        true
    })();
    // SAFETY: made above.
    unsafe { EC_POINT_free(point) };
    ok
}

/// `ossl_ec_key_private_check`: the private key is in `[1, n-1]`.
///
/// # Safety
/// `f` holds a live group and number.
pub(crate) unsafe fn private_check(f: &Fields) -> bool {
    if f.group.0.is_null() || f.priv_key.0.is_null() {
        raise(ERR_R_PASSED_NULL_PARAMETER, "ossl_ec_key_private_check");
        return false;
    }
    // SAFETY: the caller's guarantee.
    let order = unsafe { EC_GROUP_get0_order(f.group.0) };
    // SAFETY: no preconditions.
    let one = unsafe { BN_value_one() };
    // SAFETY: live numbers.
    if unsafe { BN_cmp(f.priv_key.0, one) } < 0
        // SAFETY: as above.
        || unsafe { BN_cmp(f.priv_key.0, order) } >= 0
    {
        raise(EC_R_INVALID_PRIVATE_KEY, "ossl_ec_key_private_check");
        return false;
    }
    true
}

/// `ossl_ec_key_pairwise_check`: the generator times the private key is the public key.
///
/// # Safety
/// `f` holds a live group, point, and number.
pub(crate) unsafe fn pairwise_check(f: &Fields, ctx: *mut BN_CTX) -> bool {
    let g = f.group.0;
    if g.is_null() || f.pub_key.0.is_null() || f.priv_key.0.is_null() {
        raise(ERR_R_PASSED_NULL_PARAMETER, "ossl_ec_key_pairwise_check");
        return false;
    }
    // SAFETY: the caller's guarantee.
    let point = unsafe { EC_POINT_new(g) };
    if point.is_null() {
        return false;
    }
    let ok = (|| {
        // SAFETY: the group, the point, and the number.
        if unsafe { EC_POINT_mul(g, point, f.priv_key.0, ptr::null(), ptr::null(), ctx) } == 0 {
            raise(ERR_R_EC_LIB, "ossl_ec_key_pairwise_check");
            return false;
        }
        // SAFETY: the group and points.
        if unsafe { EC_POINT_cmp(g, point, f.pub_key.0, ctx) } != 0 {
            raise(EC_R_INVALID_PRIVATE_KEY, "ossl_ec_key_pairwise_check");
            return false;
        }
        true
    })();
    // SAFETY: made above.
    unsafe { EC_POINT_free(point) };
    ok
}

ffi_export! {
    /// Checks the key (`ossl_ec_key_simple_check_key`): the public key, and the private key's
    /// range and its pair with the public key if it has one. 1, or 0.
    ///
    /// # Safety
    /// `eckey` is NULL or a live key.
    pub unsafe extern "C" fn EC_KEY_check_key(eckey: *const EC_KEY) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let k = unsafe { key(eckey) };
        let Some(f) = k.map(EcKey::get).filter(|f| !f.group.0.is_null() && !f.pub_key.0.is_null()) else {
            raise(ERR_R_PASSED_NULL_PARAMETER, "EC_KEY_check_key");
            return 0;
        };
        // SAFETY: the key's context.
        let ctx = unsafe { BN_CTX_new_ex(f.libctx.0) };
        if ctx.is_null() {
            return 0;
        }
        // SAFETY: the key's objects; the context.
        let ok = unsafe { public_check(&f, ctx) }
            && (f.priv_key.0.is_null()
                // SAFETY: as above.
                || (unsafe { private_check(&f) } && unsafe { pairwise_check(&f, ctx) }));
        // SAFETY: made above.
        unsafe { BN_CTX_free(ctx) };
        c_int::from(ok)
    }
}

ffi_export! {
    /// Sets the public key from affine coordinates, which must be the point's own (in range),
    /// then checks the key. 1, or 0.
    ///
    /// # Safety
    /// `key` is NULL or a live key; `x` and `y` are NULL or live numbers.
    pub unsafe extern "C" fn EC_KEY_set_public_key_affine_coordinates(key: *mut EC_KEY, x: *mut BIGNUM, y: *mut BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        const F: &str = "EC_KEY_set_public_key_affine_coordinates";
        // SAFETY: the caller's guarantee.
        let k = unsafe { self::key(key) };
        let Some(f) = k.map(EcKey::get).filter(|f| !f.group.0.is_null() && !x.is_null() && !y.is_null()) else {
            raise(ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        };
        let g = f.group.0;
        // SAFETY: the key's context.
        let ctx = unsafe { BN_CTX_new_ex(f.libctx.0) };
        if ctx.is_null() {
            return 0;
        }
        // SAFETY: the group.
        let point = unsafe { EC_POINT_new(g) };
        // SAFETY: no preconditions.
        let (tx, ty) = (unsafe { BN_new() }, unsafe { BN_new() });
        let ok = (|| {
            if point.is_null() || tx.is_null() || ty.is_null() {
                return false;
            }
            // SAFETY: the group, the point, and the caller's numbers.
            if unsafe { EC_POINT_set_affine_coordinates(g, point, x, y, ctx) } == 0 {
                return false;
            }
            // SAFETY: as above.
            if unsafe { EC_POINT_get_affine_coordinates(g, point, tx, ty, ctx) } == 0 {
                return false;
            }
            // SAFETY: live numbers.
            if unsafe { BN_cmp(x, tx) } != 0 || unsafe { BN_cmp(y, ty) } != 0 {
                raise(EC_R_COORDINATES_OUT_OF_RANGE, F);
                return false;
            }
            // SAFETY: the caller's key; the point.
            if unsafe { EC_KEY_set_public_key(key, point) } == 0 {
                return false;
            }
            // SAFETY: as above.
            (unsafe { EC_KEY_check_key(key) }) != 0
        })();
        // SAFETY: made above, or NULL.
        unsafe { BN_free(tx) };
        // SAFETY: as above.
        unsafe { BN_free(ty) };
        // SAFETY: as above.
        unsafe { EC_POINT_free(point) };
        // SAFETY: as above.
        unsafe { BN_CTX_free(ctx) };
        c_int::from(ok)
    }
}

ffi_export! {
    /// The key's group, or NULL.
    ///
    /// # Safety
    /// `key` is a live key.
    pub unsafe extern "C" fn EC_KEY_get0_group(key: *const EC_KEY) -> *const EC_GROUP
    where failure = ptr::null(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { self::key(key) }.map_or(ptr::null(), |k| k.get().group.0.cast_const())
    }
}

ffi_export! {
    /// Gives the key a copy of `group` (after the method's `set_group` agrees), with SM2's
    /// range flag for SM2. 1, or 0.
    ///
    /// # Safety
    /// `key` is a live key; `group` is NULL or a live group.
    pub unsafe extern "C" fn EC_KEY_set_group(key: *mut EC_KEY, group: *const EC_GROUP) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::key(key) }) else { return 0 };
        // SAFETY: the key's method; no lock is held while its function runs.
        if let Some(set_group) = unsafe { method(k.get().meth.0) }.and_then(|m| m.set_group)
            // SAFETY: the method's function takes the key and the group.
            && unsafe { set_group(key, group) } == 0
        {
            return 0;
        }
        // SAFETY: NULL or the caller's group.
        let g = unsafe { EC_GROUP_dup(group) };
        let old = k.update(|f| core::mem::replace(&mut f.group, Ptr(g)));
        // SAFETY: the old group, freed once.
        unsafe { EC_GROUP_free(old.0) };
        // SAFETY: the new group.
        if !g.is_null() && unsafe { EC_GROUP_get_curve_name(g) } == NID_sm2 {
            k.update(|f| f.flags |= EC_FLAG_SM2_RANGE);
            k.touch();
        }
        k.touch();
        c_int::from(!g.is_null())
    }
}

ffi_export! {
    /// The key's private number, or NULL.
    ///
    /// # Safety
    /// `key` is a live key.
    pub unsafe extern "C" fn EC_KEY_get0_private_key(key: *const EC_KEY) -> *const BIGNUM
    where failure = ptr::null(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { self::key(key) }.map_or(ptr::null(), |k| k.get().priv_key.0.cast_const())
    }
}

ffi_export! {
    /// Gives the key a copy of `priv_key` (after the method's `set_private` agrees); NULL
    /// clears it and returns 0, as OpenSSL does. 1, or 0 (without a group with an order too).
    ///
    /// # Safety
    /// `key` is a live key; `priv_key` is NULL or a live number.
    pub unsafe extern "C" fn EC_KEY_set_private_key(key: *mut EC_KEY, priv_key: *const BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::key(key) }) else { return 0 };
        let f = k.get();
        if f.group.0.is_null() {
            return 0;
        }
        // SAFETY: the key's group.
        let order = unsafe { EC_GROUP_get0_order(f.group.0) };
        // SAFETY: the group's number.
        if order.is_null() || unsafe { BN_is_zero(order) } != 0 {
            return 0;
        }
        // SAFETY: the key's method; no lock is held while its function runs.
        if let Some(set_private) = unsafe { method(f.meth.0) }.and_then(|m| m.set_private)
            // SAFETY: the method's function takes the key and the number.
            && unsafe { set_private(key, priv_key) } == 0
        {
            return 0;
        }
        if priv_key.is_null() {
            let old = k.update(|f| core::mem::replace(&mut f.priv_key, Ptr(ptr::null_mut())));
            // SAFETY: the old number, freed once.
            unsafe { BN_clear_free(old.0) };
            return 0;
        }
        // SAFETY: the caller's number.
        let t = unsafe { dup_secret(priv_key) };
        if t.is_null() {
            return 0;
        }
        let old = k.update(|f| core::mem::replace(&mut f.priv_key, Ptr(t)));
        // SAFETY: as above.
        unsafe { BN_clear_free(old.0) };
        k.touch();
        1
    }
}

ffi_export! {
    /// The key's public point, or NULL.
    ///
    /// # Safety
    /// `key` is a live key.
    pub unsafe extern "C" fn EC_KEY_get0_public_key(key: *const EC_KEY) -> *const EC_POINT
    where failure = ptr::null(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { self::key(key) }.map_or(ptr::null(), |k| k.get().pub_key.0.cast_const())
    }
}

ffi_export! {
    /// Gives the key a copy of `pub_key` (after the method's `set_public` agrees). 1, or 0.
    ///
    /// # Safety
    /// `key` is a live key; `pub_key` is NULL or a live point.
    pub unsafe extern "C" fn EC_KEY_set_public_key(key: *mut EC_KEY, pub_key: *const EC_POINT) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::key(key) }) else { return 0 };
        let f = k.get();
        // SAFETY: the key's method; no lock is held while its function runs.
        if let Some(set_public) = unsafe { method(f.meth.0) }.and_then(|m| m.set_public)
            // SAFETY: the method's function takes the key and the point.
            && unsafe { set_public(key, pub_key) } == 0
        {
            return 0;
        }
        // SAFETY: NULL or the caller's point; NULL or the key's group.
        let p = unsafe { EC_POINT_dup(pub_key, f.group.0) };
        let old = k.update(|f| core::mem::replace(&mut f.pub_key, Ptr(p)));
        // SAFETY: the old point, freed once.
        unsafe { EC_POINT_free(old.0) };
        k.touch();
        c_int::from(!p.is_null())
    }
}

ffi_export! {
    /// The key's encoding flags (`EC_PKEY_NO_PARAMETERS`, `EC_PKEY_NO_PUBKEY`).
    ///
    /// # Safety
    /// `key` is a live key.
    pub unsafe extern "C" fn EC_KEY_get_enc_flags(key: *const EC_KEY) -> c_uint
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { self::key(key) }.map_or(0, |k| k.get().enc_flag)
    }
}

ffi_export! {
    /// Sets the key's encoding flags.
    ///
    /// # Safety
    /// `eckey` is a live key.
    pub unsafe extern "C" fn EC_KEY_set_enc_flags(eckey: *mut EC_KEY, flags: c_uint)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        if let Some(k) = unsafe { key(eckey) } {
            k.update(|f| f.enc_flag = flags);
        }
    }
}

ffi_export! {
    /// The form the key's public key is encoded in.
    ///
    /// # Safety
    /// `key` is a live key.
    pub unsafe extern "C" fn EC_KEY_get_conv_form(key: *const EC_KEY) -> point_conversion_form_t
    where failure = POINT_CONVERSION_UNCOMPRESSED, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { self::key(key) }.map_or(POINT_CONVERSION_UNCOMPRESSED, |k| k.get().conv_form)
    }
}

ffi_export! {
    /// Sets the form the key's public key is encoded in, and its group's.
    ///
    /// # Safety
    /// `eckey` is a live key.
    pub unsafe extern "C" fn EC_KEY_set_conv_form(eckey: *mut EC_KEY, cform: point_conversion_form_t)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(eckey) }) else { return };
        let g = k.update(|f| {
            f.conv_form = cform;
            f.group.0
        });
        if !g.is_null() {
            // SAFETY: the key's group.
            unsafe { EC_GROUP_set_point_conversion_form(g, cform) };
        }
    }
}

ffi_export! {
    /// Sets the ASN.1 flag of the key's group.
    ///
    /// # Safety
    /// `eckey` is a live key.
    pub unsafe extern "C" fn EC_KEY_set_asn1_flag(eckey: *mut EC_KEY, asn1_flag: c_int)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let g = unsafe { key(eckey) }.map_or(ptr::null_mut(), |k| k.get().group.0);
        if !g.is_null() {
            // SAFETY: the key's group.
            unsafe { EC_GROUP_set_asn1_flag(g, asn1_flag) };
        }
    }
}

ffi_export! {
    /// Precomputes multiples of the key's group's generator. 1, or 0.
    ///
    /// # Safety
    /// `key` is a live key; `ctx` is NULL or a live `BN_CTX`.
    pub unsafe extern "C" fn EC_KEY_precompute_mult(key: *mut EC_KEY, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let g = unsafe { self::key(key) }.map_or(ptr::null_mut(), |k| k.get().group.0);
        if g.is_null() {
            return 0;
        }
        // SAFETY: the key's group; the caller's context.
        unsafe { EC_GROUP_precompute_mult(g, ctx) }
    }
}

ffi_export! {
    /// The key's flags.
    ///
    /// # Safety
    /// `key` is a live key.
    pub unsafe extern "C" fn EC_KEY_get_flags(key: *const EC_KEY) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { self::key(key) }.map_or(0, |k| k.get().flags)
    }
}

ffi_export! {
    /// Sets flags on the key.
    ///
    /// # Safety
    /// `key` is a live key.
    pub unsafe extern "C" fn EC_KEY_set_flags(key: *mut EC_KEY, flags: c_int)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        if let Some(k) = unsafe { self::key(key) } {
            k.update(|f| f.flags |= flags);
            k.touch();
        }
    }
}

ffi_export! {
    /// Clears flags on the key.
    ///
    /// # Safety
    /// `key` is a live key.
    pub unsafe extern "C" fn EC_KEY_clear_flags(key: *mut EC_KEY, flags: c_int)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        if let Some(k) = unsafe { self::key(key) } {
            k.update(|f| f.flags &= !flags);
            k.touch();
        }
    }
}

ffi_export! {
    /// Whether the key's group was decoded from explicit parameters: 1 or 0, -1 for no key or
    /// group.
    ///
    /// # Safety
    /// `key` is NULL or a live key.
    pub unsafe extern "C" fn EC_KEY_decoded_from_explicit_params(key: *const EC_KEY) -> c_int
    where failure = -1, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let g = unsafe { self::key(key) }.map_or(ptr::null_mut(), |k| k.get().group.0);
        if g.is_null() {
            return -1;
        }
        // SAFETY: the key's group.
        c_int::from(unsafe { decoded_from_explicit(g) })
    }
}

ffi_export! {
    /// The public key's encoding in `form`, into a new buffer at `*pbuf`; its length, or 0.
    ///
    /// # Safety
    /// `key` is NULL or a live key; `pbuf` is NULL or writable.
    pub unsafe extern "C" fn EC_KEY_key2buf(key: *const EC_KEY, form: point_conversion_form_t, pbuf: *mut *mut c_uchar, ctx: *mut BN_CTX) -> usize
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(f) = (unsafe { self::key(key) }).map(EcKey::get) else { return 0 };
        if f.pub_key.0.is_null() || f.group.0.is_null() {
            return 0;
        }
        // SAFETY: the key's objects; the caller's buffer and context.
        unsafe { EC_POINT_point2buf(f.group.0, f.pub_key.0, form, pbuf, ctx) }
    }
}

ffi_export! {
    /// Sets the public key from its encoding, keeping the encoding's form as the key's. 1, or
    /// 0.
    ///
    /// # Safety
    /// `key` is NULL or a live key; `buf` holds `len` octets.
    pub unsafe extern "C" fn EC_KEY_oct2key(key: *mut EC_KEY, buf: *const c_uchar, len: usize, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::key(key) }) else { return 0 };
        let f = k.get();
        if f.group.0.is_null() {
            return 0;
        }
        let mut p = f.pub_key.0;
        if p.is_null() {
            // SAFETY: the key's group.
            p = unsafe { EC_POINT_new(f.group.0) };
            if p.is_null() {
                return 0;
            }
            k.update(|f| f.pub_key = Ptr(p));
        }
        // SAFETY: the key's objects; the caller's octets and context.
        if unsafe { EC_POINT_oct2point(f.group.0, p, buf, len, ctx) } == 0 {
            return 0;
        }
        k.touch();
        // A successful decoding has at least the form's octet.
        // SAFETY: as above.
        let first = unsafe { *buf };
        k.update(|f| f.conv_form = point_conversion_form_t::from(first & !1));
        1
    }
}

ffi_export! {
    /// The private key in big-endian octets of the order's length, into `buf` (its length for
    /// NULL), or 0.
    ///
    /// # Safety
    /// `eckey` is a live key; `buf` is NULL or has room for `len` octets.
    pub unsafe extern "C" fn EC_KEY_priv2oct(eckey: *const EC_KEY, buf: *mut c_uchar, len: usize) -> usize
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(f) = (unsafe { key(eckey) }).map(EcKey::get) else { return 0 };
        if f.group.0.is_null() {
            return 0;
        }
        // SAFETY: the key's group.
        let bits = unsafe { EC_GROUP_order_bits(f.group.0) };
        let buf_len = usize::try_from(bits).unwrap_or(0).saturating_add(7) / 8;
        if f.priv_key.0.is_null() {
            return 0;
        }
        if buf.is_null() {
            return buf_len;
        }
        if len < buf_len {
            return 0;
        }
        let Ok(n) = c_int::try_from(buf_len) else { return 0 };
        // SAFETY: the key's number; the caller's room.
        if unsafe { BN_bn2binpad(f.priv_key.0, buf, n) } == -1 {
            raise(rustyssl_abi::EC_R_BUFFER_TOO_SMALL, "ossl_ec_key_simple_priv2oct");
            return 0;
        }
        buf_len
    }
}

ffi_export! {
    /// Sets the private key from big-endian octets. 1, or 0.
    ///
    /// # Safety
    /// `eckey` is a live key; `buf` holds `len` octets.
    pub unsafe extern "C" fn EC_KEY_oct2priv(eckey: *mut EC_KEY, buf: *const c_uchar, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        const F: &str = "ossl_ec_key_simple_oct2priv";
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(eckey) }) else { return 0 };
        if k.get().group.0.is_null() {
            return 0;
        }
        let mut b = k.get().priv_key.0;
        if b.is_null() {
            // SAFETY: no preconditions.
            b = unsafe { BN_secure_new() };
            if b.is_null() {
                raise(ERR_R_BN_LIB, F);
                return 0;
            }
            k.update(|f| f.priv_key = Ptr(b));
        }
        let Ok(n) = c_int::try_from(len) else {
            raise(ERR_R_BN_LIB, F);
            return 0;
        };
        // SAFETY: the caller's octets; the key's number.
        if unsafe { BN_bin2bn(buf, n, b) }.is_null() {
            raise(ERR_R_BN_LIB, F);
            return 0;
        }
        k.touch();
        k.touch();
        1
    }
}

ffi_export! {
    /// The private key's octets in a new buffer at `*pbuf`; their length, or 0.
    ///
    /// # Safety
    /// `eckey` is a live key; `pbuf` is writable.
    pub unsafe extern "C" fn EC_KEY_priv2buf(eckey: *const EC_KEY, pbuf: *mut *mut c_uchar) -> usize
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let len = unsafe { EC_KEY_priv2oct(eckey, ptr::null_mut(), 0) };
        if len == 0 {
            return 0;
        }
        let buf: *mut c_uchar = mem::malloc(len, ptr::null(), 0).cast();
        if buf.is_null() {
            return 0;
        }
        // SAFETY: as above; the buffer of `len` octets.
        let n = unsafe { EC_KEY_priv2oct(eckey, buf, len) };
        if n == 0 {
            // SAFETY: the buffer made above.
            unsafe { mem::release_clean(buf.cast(), len) };
            return 0;
        }
        // SAFETY: the caller's pointer.
        unsafe { *pbuf = buf };
        n
    }
}

ffi_export! {
    /// Whether the key's group allows signing: 1 when it has a group.
    ///
    /// # Safety
    /// `eckey` is a live key.
    pub unsafe extern "C" fn EC_KEY_can_sign(eckey: *const EC_KEY) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { key(eckey) }.is_some_and(|k| !k.get().group.0.is_null()))
    }
}

ffi_export! {
    /// The application's data at `idx`, or NULL.
    ///
    /// # Safety
    /// `key` is a live key.
    pub unsafe extern "C" fn EC_KEY_get_ex_data(key: *const EC_KEY, idx: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::key(key) }) else { return ptr::null_mut() };
        // SAFETY: the key's ex_data.
        unsafe { CRYPTO_get_ex_data(k.ex_data(), idx) }
    }
}

ffi_export! {
    /// Sets the application's data at `idx`. 1, or 0.
    ///
    /// # Safety
    /// `key` is a live key.
    pub unsafe extern "C" fn EC_KEY_set_ex_data(key: *mut EC_KEY, idx: c_int, arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::key(key) }) else { return 0 };
        // SAFETY: the key's ex_data.
        unsafe { CRYPTO_set_ex_data(k.ex_data(), idx, arg) }
    }
}

ffi_export! {
    /// The library's method.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EC_KEY_OpenSSL() -> *const EC_KEY_METHOD
    where failure = ptr::null(), library = ERR_LIB_EC
    {
        openssl_method().cast()
    }
}

ffi_export! {
    /// The method new keys get.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EC_KEY_get_default_method() -> *const EC_KEY_METHOD
    where failure = ptr::null(), library = ERR_LIB_EC
    {
        default_method().cast()
    }
}

ffi_export! {
    /// Sets the method new keys get (the library's for NULL).
    ///
    /// # Safety
    /// `meth` is NULL or a method that outlives its use as the default.
    pub unsafe extern "C" fn EC_KEY_set_default_method(meth: *const EC_KEY_METHOD)
    where failure = (), library = ERR_LIB_EC
    {
        DEFAULT_METHOD.store(meth.cast::<Method>().cast_mut(), Ordering::Release);
    }
}

ffi_export! {
    /// The key's method.
    ///
    /// # Safety
    /// `key` is a live key.
    pub unsafe extern "C" fn EC_KEY_get_method(key: *const EC_KEY) -> *const EC_KEY_METHOD
    where failure = ptr::null(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { self::key(key) }.map_or(ptr::null(), |k| k.get().meth.0.cast_const().cast())
    }
}

ffi_export! {
    /// Gives the key `meth`: the old method's `finish`, then the new one's `init`, whose
    /// result is returned (1 without one).
    ///
    /// # Safety
    /// `key` is a live key; `meth` is a method that outlives the key's use of it.
    pub unsafe extern "C" fn EC_KEY_set_method(key: *mut EC_KEY, meth: *const EC_KEY_METHOD) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::key(key) }) else { return 0 };
        // SAFETY: the key's method; no lock is held while its function runs.
        if let Some(finish) = unsafe { method(k.get().meth.0) }.and_then(|m| m.finish) {
            // SAFETY: the method's function takes the key.
            unsafe { finish(key) };
        }
        k.update(|f| f.meth = Ptr(meth.cast::<Method>().cast_mut()));
        // SAFETY: the caller's method; no lock is held while its function runs.
        match unsafe { method(meth.cast()) }.and_then(|m| m.init) {
            // SAFETY: the method's function takes the key.
            Some(init) => unsafe { init(key) },
            None => 1,
        }
    }
}

ffi_export! {
    /// A new method: a copy of `meth` (or empty), freed by `EC_KEY_METHOD_free`.
    ///
    /// # Safety
    /// `meth` is NULL or a live method.
    pub unsafe extern "C" fn EC_KEY_METHOD_new(meth: *const EC_KEY_METHOD) -> *mut EC_KEY_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        let m: *mut Method = mem::zalloc(size_of::<Method>(), ptr::null(), 0).cast();
        if m.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let mut table = unsafe { method(meth.cast()) }.unwrap_or(Method {
            name: ptr::null(),
            flags: 0,
            init: None,
            finish: None,
            copy: None,
            set_group: None,
            set_private: None,
            set_public: None,
            keygen: None,
            compute_key: None,
            sign: None,
            sign_setup: None,
            sign_sig: None,
            verify: None,
            verify_sig: None,
        });
        table.flags |= DYNAMIC;
        // SAFETY: room for a method, just allocated.
        unsafe { m.write(table) };
        m.cast()
    }
}

ffi_export! {
    /// Frees a method `EC_KEY_METHOD_new` made; the library's own is kept.
    ///
    /// # Safety
    /// `meth` is a live method nothing uses any more.
    pub unsafe extern "C" fn EC_KEY_METHOD_free(meth: *mut EC_KEY_METHOD)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        if unsafe { method(meth.cast()) }.is_some_and(|m| m.flags & DYNAMIC != 0) {
            // SAFETY: a method allocated by `EC_KEY_METHOD_new`.
            unsafe { mem::release(meth.cast()) };
        }
    }
}

/// Changes an application's method with `f`.
///
/// # Safety
/// `meth` is NULL or a method `EC_KEY_METHOD_new` made.
unsafe fn edit(meth: *mut EC_KEY_METHOD, f: impl FnOnce(&mut Method)) {
    // SAFETY: the caller's guarantee.
    if let Some(m) = unsafe { meth.cast::<Method>().as_mut() } {
        f(m);
    }
}

ffi_export! {
    /// Sets a method's life-cycle and setter functions.
    ///
    /// # Safety
    /// `meth` is a method `EC_KEY_METHOD_new` made.
    pub unsafe extern "C" fn EC_KEY_METHOD_set_init(meth: *mut EC_KEY_METHOD, init: Option<InitFn>, finish: Option<FinishFn>, copy: Option<CopyFn>, set_group: Option<SetGroupFn>, set_private: Option<SetPrivateFn>, set_public: Option<SetPublicFn>)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe {
            edit(meth, |m| {
                m.init = init;
                m.finish = finish;
                m.copy = copy;
                m.set_group = set_group;
                m.set_private = set_private;
                m.set_public = set_public;
            });
        }
    }
}

ffi_export! {
    /// Sets a method's key generation.
    ///
    /// # Safety
    /// `meth` is a method `EC_KEY_METHOD_new` made.
    pub unsafe extern "C" fn EC_KEY_METHOD_set_keygen(meth: *mut EC_KEY_METHOD, keygen: Option<KeygenFn>)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { edit(meth, |m| m.keygen = keygen) };
    }
}

ffi_export! {
    /// Sets a method's key agreement.
    ///
    /// # Safety
    /// `meth` is a method `EC_KEY_METHOD_new` made.
    pub unsafe extern "C" fn EC_KEY_METHOD_set_compute_key(meth: *mut EC_KEY_METHOD, ckey: Option<ComputeKeyFn>)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { edit(meth, |m| m.compute_key = ckey) };
    }
}

ffi_export! {
    /// Sets a method's signing functions.
    ///
    /// # Safety
    /// `meth` is a method `EC_KEY_METHOD_new` made.
    pub unsafe extern "C" fn EC_KEY_METHOD_set_sign(meth: *mut EC_KEY_METHOD, sign: Option<SignFn>, sign_setup: Option<SignSetupFn>, sign_sig: Option<SignSigFn>)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe {
            edit(meth, |m| {
                m.sign = sign;
                m.sign_setup = sign_setup;
                m.sign_sig = sign_sig;
            });
        }
    }
}

ffi_export! {
    /// Sets a method's verification functions.
    ///
    /// # Safety
    /// `meth` is a method `EC_KEY_METHOD_new` made.
    pub unsafe extern "C" fn EC_KEY_METHOD_set_verify(meth: *mut EC_KEY_METHOD, verify: Option<VerifyFn>, verify_sig: Option<VerifySigFn>)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe {
            edit(meth, |m| {
                m.verify = verify;
                m.verify_sig = verify_sig;
            });
        }
    }
}

/// Writes `v` through `p` unless it's NULL.
///
/// # Safety
/// `p` is NULL or writable.
unsafe fn put<T>(p: *mut T, v: T) {
    if !p.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { p.write(v) };
    }
}

ffi_export! {
    /// A method's life-cycle and setter functions, each through a pointer that isn't NULL.
    ///
    /// # Safety
    /// `meth` is a live method; each pointer is NULL or writable.
    pub unsafe extern "C" fn EC_KEY_METHOD_get_init(meth: *const EC_KEY_METHOD, pinit: *mut Option<InitFn>, pfinish: *mut Option<FinishFn>, pcopy: *mut Option<CopyFn>, pset_group: *mut Option<SetGroupFn>, pset_private: *mut Option<SetPrivateFn>, pset_public: *mut Option<SetPublicFn>)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(meth.cast()) }) else { return };
        // SAFETY: as above, for each.
        unsafe { put(pinit, m.init) };
        // SAFETY: as above.
        unsafe { put(pfinish, m.finish) };
        // SAFETY: as above.
        unsafe { put(pcopy, m.copy) };
        // SAFETY: as above.
        unsafe { put(pset_group, m.set_group) };
        // SAFETY: as above.
        unsafe { put(pset_private, m.set_private) };
        // SAFETY: as above.
        unsafe { put(pset_public, m.set_public) };
    }
}

ffi_export! {
    /// A method's key generation.
    ///
    /// # Safety
    /// `meth` is a live method; `pkeygen` is NULL or writable.
    pub unsafe extern "C" fn EC_KEY_METHOD_get_keygen(meth: *const EC_KEY_METHOD, pkeygen: *mut Option<KeygenFn>)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        if let Some(m) = unsafe { method(meth.cast()) } {
            // SAFETY: as above.
            unsafe { put(pkeygen, m.keygen) };
        }
    }
}

ffi_export! {
    /// A method's key agreement.
    ///
    /// # Safety
    /// `meth` is a live method; `pck` is NULL or writable.
    pub unsafe extern "C" fn EC_KEY_METHOD_get_compute_key(meth: *const EC_KEY_METHOD, pck: *mut Option<ComputeKeyFn>)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        if let Some(m) = unsafe { method(meth.cast()) } {
            // SAFETY: as above.
            unsafe { put(pck, m.compute_key) };
        }
    }
}

ffi_export! {
    /// A method's signing functions.
    ///
    /// # Safety
    /// `meth` is a live method; each pointer is NULL or writable.
    pub unsafe extern "C" fn EC_KEY_METHOD_get_sign(meth: *const EC_KEY_METHOD, psign: *mut Option<SignFn>, psign_setup: *mut Option<SignSetupFn>, psign_sig: *mut Option<SignSigFn>)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(meth.cast()) }) else { return };
        // SAFETY: as above, for each.
        unsafe { put(psign, m.sign) };
        // SAFETY: as above.
        unsafe { put(psign_setup, m.sign_setup) };
        // SAFETY: as above.
        unsafe { put(psign_sig, m.sign_sig) };
    }
}

ffi_export! {
    /// A method's verification functions.
    ///
    /// # Safety
    /// `meth` is a live method; each pointer is NULL or writable.
    pub unsafe extern "C" fn EC_KEY_METHOD_get_verify(meth: *const EC_KEY_METHOD, pverify: *mut Option<VerifyFn>, pverify_sig: *mut Option<VerifySigFn>)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(meth.cast()) }) else { return };
        // SAFETY: as above, for each.
        unsafe { put(pverify, m.verify) };
        // SAFETY: as above.
        unsafe { put(pverify_sig, m.verify_sig) };
    }
}
