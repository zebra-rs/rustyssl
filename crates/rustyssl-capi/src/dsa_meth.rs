//! DSA methods (`DSA_METHOD`; `dsa_meth.c`, `dsa_ossl.c`'s built-in method): an application's
//! table of functions for its keys' operations, and OpenSSL's own, `DSA_OpenSSL`, whose
//! functions are real (an application's method often calls them for what it doesn't change).
//!
//! As OpenSSL's, the built-in method has no `dsa_mod_exp`, `bn_mod_exp`, `dsa_paramgen`, or
//! `dsa_keygen`: the operations use the built-in arithmetic when a method lacks them.

use core::ffi::{CStr, c_char, c_int, c_uchar, c_ulong, c_void};
use core::ptr;
use std::ffi::CString;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};

use rustyssl_abi::{
    BIGNUM, BN_CTX, BN_GENCB, BN_MONT_CTX, DSA, DSA_FLAG_FIPS_METHOD, DSA_METHOD, DSA_SIG,
    ERR_LIB_DSA,
};

use crate::dsa_ops::{
    dsa_finish, dsa_init, dsa_ossl_do_sign, dsa_ossl_do_verify, dsa_ossl_sign_setup,
};
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::provider::Ptr;

pub(crate) type SignFn = unsafe extern "C" fn(*const c_uchar, c_int, *mut DSA) -> *mut DSA_SIG;
pub(crate) type SignSetupFn =
    unsafe extern "C" fn(*mut DSA, *mut BN_CTX, *mut *mut BIGNUM, *mut *mut BIGNUM) -> c_int;
pub(crate) type VerifyFn =
    unsafe extern "C" fn(*const c_uchar, c_int, *mut DSA_SIG, *mut DSA) -> c_int;
pub(crate) type ModExpFn = unsafe extern "C" fn(
    *mut DSA,
    *mut BIGNUM,
    *const BIGNUM,
    *const BIGNUM,
    *const BIGNUM,
    *const BIGNUM,
    *const BIGNUM,
    *mut BN_CTX,
    *mut BN_MONT_CTX,
) -> c_int;
pub(crate) type BnModExpFn = unsafe extern "C" fn(
    *mut DSA,
    *mut BIGNUM,
    *const BIGNUM,
    *const BIGNUM,
    *const BIGNUM,
    *mut BN_CTX,
    *mut BN_MONT_CTX,
) -> c_int;
pub(crate) type InitFn = unsafe extern "C" fn(*mut DSA) -> c_int;
pub(crate) type ParamgenFn = unsafe extern "C" fn(
    *mut DSA,
    c_int,
    *const c_uchar,
    c_int,
    *mut c_int,
    *mut c_ulong,
    *mut BN_GENCB,
) -> c_int;
pub(crate) type KeygenFn = unsafe extern "C" fn(*mut DSA) -> c_int;

/// `struct dsa_method`.
#[derive(Clone)]
pub(crate) struct Fns {
    /// The name, NUL-terminated, at a stable address while it's the method's.
    name: CString,
    pub(crate) sign: Option<SignFn>,
    pub(crate) sign_setup: Option<SignSetupFn>,
    pub(crate) verify: Option<VerifyFn>,
    pub(crate) mod_exp: Option<ModExpFn>,
    pub(crate) bn_mod_exp: Option<BnModExpFn>,
    pub(crate) init: Option<InitFn>,
    pub(crate) finish: Option<InitFn>,
    pub(crate) flags: c_int,
    app_data: Ptr<c_void>,
    pub(crate) paramgen: Option<ParamgenFn>,
    pub(crate) keygen: Option<KeygenFn>,
}

impl Fns {
    fn empty(name: CString, flags: c_int) -> Self {
        Fns {
            name,
            sign: None,
            sign_setup: None,
            verify: None,
            mod_exp: None,
            bn_mod_exp: None,
            init: None,
            finish: None,
            flags,
            app_data: Ptr(ptr::null_mut()),
            paramgen: None,
            keygen: None,
        }
    }
}

/// A DSA method.
pub(crate) struct DsaMethod {
    fns: Mutex<Fns>,
    /// Names a renamed method had, kept so a name returned earlier stays readable.
    old_names: Mutex<Vec<CString>>,
}

handle_type!(DSA_METHOD => DsaMethod);

impl DsaMethod {
    fn new(fns: Fns) -> Self {
        DsaMethod {
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

/// `openssl_dsa_meth`.
fn builtin() -> *const DSA_METHOD {
    static BUILTIN: OnceLock<Ptr<DSA_METHOD>> = OnceLock::new();
    BUILTIN
        .get_or_init(|| {
            let mut f = Fns::empty(c"OpenSSL DSA method".to_owned(), DSA_FLAG_FIPS_METHOD);
            f.sign = Some(dsa_ossl_do_sign);
            f.sign_setup = Some(dsa_ossl_sign_setup);
            f.verify = Some(dsa_ossl_do_verify);
            f.init = Some(dsa_init);
            f.finish = Some(dsa_finish);
            Ptr(DSA_METHOD::new_handle(DsaMethod::new(f)))
        })
        .0
}

/// `default_DSA_method`: the built-in method until the application sets another (NULL, too).
static DEFAULT: OnceLock<AtomicPtr<DSA_METHOD>> = OnceLock::new();

fn default_cell() -> &'static AtomicPtr<DSA_METHOD> {
    DEFAULT.get_or_init(|| AtomicPtr::new(builtin().cast_mut()))
}

/// The method new keys get: the default, or the built-in one if the application made the
/// default NULL (OpenSSL's `DSA_new` would crash).
pub(crate) fn default_or_builtin() -> *const DSA_METHOD {
    let d = default_cell().load(Ordering::Acquire);
    if d.is_null() { builtin() } else { d }
}

/// Whether `meth` is the default method (`DSA_get_default_method`).
pub(crate) fn is_default(meth: *const DSA_METHOD) -> bool {
    meth == default_cell().load(Ordering::Acquire).cast_const()
}

/// The method behind `meth`.
///
/// # Safety
/// `meth` is NULL or a live method.
unsafe fn method<'a>(meth: *const DSA_METHOD) -> Option<&'a DsaMethod> {
    // SAFETY: the caller's guarantee.
    unsafe { DSA_METHOD::get(meth) }
}

/// A method's flags (0 for NULL).
///
/// # Safety
/// `meth` is NULL or a live method.
pub(crate) unsafe fn flags(meth: *const DSA_METHOD) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { method(meth) }.map_or(0, |m| m.fns().flags)
}

/// A method's functions (NULL's are all absent).
///
/// # Safety
/// `meth` is NULL or a live method.
pub(crate) unsafe fn fns_of(meth: *const DSA_METHOD) -> Option<Fns> {
    // SAFETY: the caller's guarantee.
    unsafe { method(meth) }.map(DsaMethod::fns)
}

ffi_export! {
    /// OpenSSL's method.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn DSA_OpenSSL() -> *const DSA_METHOD
    where failure = ptr::null(), library = ERR_LIB_DSA
    {
        builtin()
    }
}

ffi_export! {
    /// The method new keys get.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn DSA_get_default_method() -> *const DSA_METHOD
    where failure = ptr::null(), library = ERR_LIB_DSA
    {
        default_cell().load(Ordering::Acquire)
    }
}

ffi_export! {
    /// Sets the method new keys get. The application keeps it alive.
    ///
    /// # Safety
    /// `meth` is NULL or a method that outlives its use.
    pub unsafe extern "C" fn DSA_set_default_method(meth: *const DSA_METHOD)
    where failure = (), library = ERR_LIB_DSA
    {
        default_cell().store(meth.cast_mut(), Ordering::Release);
    }
}

ffi_export! {
    /// A new method named `name` (copied), with `flags` and no functions, or NULL.
    ///
    /// # Safety
    /// `name` is NULL or a string.
    pub unsafe extern "C" fn DSA_meth_new(name: *const c_char, flags: c_int) -> *mut DSA_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_DSA
    {
        if name.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's string.
        let name = unsafe { CStr::from_ptr(name) }.to_owned();
        DSA_METHOD::new_handle(DsaMethod::new(Fns::empty(name, flags)))
    }
}

ffi_export! {
    /// Frees a method. NULL (and OpenSSL's own) does nothing.
    ///
    /// # Safety
    /// `dsam` is NULL or a method the caller gives up.
    pub unsafe extern "C" fn DSA_meth_free(dsam: *mut DSA_METHOD)
    where failure = (), library = ERR_LIB_DSA
    {
        if dsam.cast_const() == builtin() {
            // OpenSSL's would free a static object: keep the built-in one.
            return;
        }
        // SAFETY: the caller's guarantee.
        unsafe { DSA_METHOD::free(dsam) };
    }
}

ffi_export! {
    /// A copy of the method, its name too, or NULL.
    ///
    /// # Safety
    /// `dsam` is NULL or a live method.
    pub unsafe extern "C" fn DSA_meth_dup(dsam: *const DSA_METHOD) -> *mut DSA_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        match unsafe { method(dsam) } {
            Some(m) => DSA_METHOD::new_handle(DsaMethod::new(m.fns())),
            None => ptr::null_mut(),
        }
    }
}

ffi_export! {
    /// The method's name.
    ///
    /// # Safety
    /// `dsam` is NULL or a live method.
    pub unsafe extern "C" fn DSA_meth_get0_name(dsam: *const DSA_METHOD) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(dsam) }.map_or(ptr::null(), |m| m.with(|f| f.name.as_ptr()))
    }
}

ffi_export! {
    /// Renames the method (`name` copied). 1, or 0.
    ///
    /// # Safety
    /// `dsam` is NULL or a live method; `name` is NULL or a string.
    pub unsafe extern "C" fn DSA_meth_set1_name(dsam: *mut DSA_METHOD, name: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(dsam) }) else { return 0 };
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
    /// `dsam` is NULL or a live method.
    pub unsafe extern "C" fn DSA_meth_get_flags(dsam: *const DSA_METHOD) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { flags(dsam) }
    }
}

ffi_export! {
    /// Sets the method's flags. 1.
    ///
    /// # Safety
    /// `dsam` is NULL or a live method.
    pub unsafe extern "C" fn DSA_meth_set_flags(dsam: *mut DSA_METHOD, flags: c_int) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(dsam) }) else { return 0 };
        m.with(|f| f.flags = flags);
        1
    }
}

ffi_export! {
    /// The method's application data.
    ///
    /// # Safety
    /// `dsam` is NULL or a live method.
    pub unsafe extern "C" fn DSA_meth_get0_app_data(dsam: *const DSA_METHOD) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(dsam) }.map_or(ptr::null_mut(), |m| m.fns().app_data.0)
    }
}

ffi_export! {
    /// Sets the method's application data. 1.
    ///
    /// # Safety
    /// `dsam` is NULL or a live method.
    pub unsafe extern "C" fn DSA_meth_set0_app_data(dsam: *mut DSA_METHOD, app_data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(dsam) }) else { return 0 };
        m.with(|f| f.app_data = Ptr(app_data));
        1
    }
}

ffi_export! {
    /// The method's signing function, or NULL.
    ///
    /// # Safety
    /// `dsam` is NULL or a live method.
    pub unsafe extern "C" fn DSA_meth_get_sign(dsam: *const DSA_METHOD) -> Option<SignFn>
    where failure = None, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(dsam) }.and_then(|m| m.fns().sign)
    }
}

ffi_export! {
    /// Sets the method's signing function. 1.
    ///
    /// # Safety
    /// `dsam` is NULL or a live method.
    pub unsafe extern "C" fn DSA_meth_set_sign(dsam: *mut DSA_METHOD, f: Option<SignFn>) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(dsam) }) else { return 0 };
        m.with(|x| x.sign = f);
        1
    }
}

ffi_export! {
    /// The method's signing setup function, or NULL.
    ///
    /// # Safety
    /// `dsam` is NULL or a live method.
    pub unsafe extern "C" fn DSA_meth_get_sign_setup(dsam: *const DSA_METHOD) -> Option<SignSetupFn>
    where failure = None, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(dsam) }.and_then(|m| m.fns().sign_setup)
    }
}

ffi_export! {
    /// Sets the method's signing setup function. 1.
    ///
    /// # Safety
    /// `dsam` is NULL or a live method.
    pub unsafe extern "C" fn DSA_meth_set_sign_setup(dsam: *mut DSA_METHOD, f: Option<SignSetupFn>) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(dsam) }) else { return 0 };
        m.with(|x| x.sign_setup = f);
        1
    }
}

ffi_export! {
    /// The method's verification function, or NULL.
    ///
    /// # Safety
    /// `dsam` is NULL or a live method.
    pub unsafe extern "C" fn DSA_meth_get_verify(dsam: *const DSA_METHOD) -> Option<VerifyFn>
    where failure = None, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(dsam) }.and_then(|m| m.fns().verify)
    }
}

ffi_export! {
    /// Sets the method's verification function. 1.
    ///
    /// # Safety
    /// `dsam` is NULL or a live method.
    pub unsafe extern "C" fn DSA_meth_set_verify(dsam: *mut DSA_METHOD, f: Option<VerifyFn>) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(dsam) }) else { return 0 };
        m.with(|x| x.verify = f);
        1
    }
}

ffi_export! {
    /// The method's double exponentiation function, or NULL.
    ///
    /// # Safety
    /// `dsam` is NULL or a live method.
    pub unsafe extern "C" fn DSA_meth_get_mod_exp(dsam: *const DSA_METHOD) -> Option<ModExpFn>
    where failure = None, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(dsam) }.and_then(|m| m.fns().mod_exp)
    }
}

ffi_export! {
    /// Sets the method's double exponentiation function. 1.
    ///
    /// # Safety
    /// `dsam` is NULL or a live method.
    pub unsafe extern "C" fn DSA_meth_set_mod_exp(dsam: *mut DSA_METHOD, f: Option<ModExpFn>) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(dsam) }) else { return 0 };
        m.with(|x| x.mod_exp = f);
        1
    }
}

ffi_export! {
    /// The method's exponentiation function, or NULL.
    ///
    /// # Safety
    /// `dsam` is NULL or a live method.
    pub unsafe extern "C" fn DSA_meth_get_bn_mod_exp(dsam: *const DSA_METHOD) -> Option<BnModExpFn>
    where failure = None, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(dsam) }.and_then(|m| m.fns().bn_mod_exp)
    }
}

ffi_export! {
    /// Sets the method's exponentiation function. 1.
    ///
    /// # Safety
    /// `dsam` is NULL or a live method.
    pub unsafe extern "C" fn DSA_meth_set_bn_mod_exp(dsam: *mut DSA_METHOD, f: Option<BnModExpFn>) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(dsam) }) else { return 0 };
        m.with(|x| x.bn_mod_exp = f);
        1
    }
}

ffi_export! {
    /// The method's initialization function, or NULL.
    ///
    /// # Safety
    /// `dsam` is NULL or a live method.
    pub unsafe extern "C" fn DSA_meth_get_init(dsam: *const DSA_METHOD) -> Option<InitFn>
    where failure = None, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(dsam) }.and_then(|m| m.fns().init)
    }
}

ffi_export! {
    /// Sets the method's initialization function. 1.
    ///
    /// # Safety
    /// `dsam` is NULL or a live method.
    pub unsafe extern "C" fn DSA_meth_set_init(dsam: *mut DSA_METHOD, f: Option<InitFn>) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(dsam) }) else { return 0 };
        m.with(|x| x.init = f);
        1
    }
}

ffi_export! {
    /// The method's finishing function, or NULL.
    ///
    /// # Safety
    /// `dsam` is NULL or a live method.
    pub unsafe extern "C" fn DSA_meth_get_finish(dsam: *const DSA_METHOD) -> Option<InitFn>
    where failure = None, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(dsam) }.and_then(|m| m.fns().finish)
    }
}

ffi_export! {
    /// Sets the method's finishing function. 1.
    ///
    /// # Safety
    /// `dsam` is NULL or a live method.
    pub unsafe extern "C" fn DSA_meth_set_finish(dsam: *mut DSA_METHOD, f: Option<InitFn>) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(dsam) }) else { return 0 };
        m.with(|x| x.finish = f);
        1
    }
}

ffi_export! {
    /// The method's parameter generation function, or NULL.
    ///
    /// # Safety
    /// `dsam` is NULL or a live method.
    pub unsafe extern "C" fn DSA_meth_get_paramgen(dsam: *const DSA_METHOD) -> Option<ParamgenFn>
    where failure = None, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(dsam) }.and_then(|m| m.fns().paramgen)
    }
}

ffi_export! {
    /// Sets the method's parameter generation function. 1.
    ///
    /// # Safety
    /// `dsam` is NULL or a live method.
    pub unsafe extern "C" fn DSA_meth_set_paramgen(dsam: *mut DSA_METHOD, f: Option<ParamgenFn>) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(dsam) }) else { return 0 };
        m.with(|x| x.paramgen = f);
        1
    }
}

ffi_export! {
    /// The method's key generation function, or NULL.
    ///
    /// # Safety
    /// `dsam` is NULL or a live method.
    pub unsafe extern "C" fn DSA_meth_get_keygen(dsam: *const DSA_METHOD) -> Option<KeygenFn>
    where failure = None, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(dsam) }.and_then(|m| m.fns().keygen)
    }
}

ffi_export! {
    /// Sets the method's key generation function. 1.
    ///
    /// # Safety
    /// `dsam` is NULL or a live method.
    pub unsafe extern "C" fn DSA_meth_set_keygen(dsam: *mut DSA_METHOD, f: Option<KeygenFn>) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(dsam) }) else { return 0 };
        m.with(|x| x.keygen = f);
        1
    }
}
