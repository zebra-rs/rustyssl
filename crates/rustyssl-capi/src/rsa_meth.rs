//! RSA methods (`RSA_METHOD`; `rsa_meth.c`, `rsa_ossl.c`'s built-in method): an application's
//! table of functions for its keys' operations, and OpenSSL's own, `RSA_PKCS1_OpenSSL`, whose
//! functions are real (an application's method often calls them for what it doesn't change).
//!
//! The built-in operations are `rustyssl_crypto::rsa::Key`'s, with OAEP's SHA-1 and implicit
//! rejection's SHA-256 fetched from the key's library context, as OpenSSL's are. A method that
//! replaces the modular exponentiation (`rsa_mod_exp`, `bn_mod_exp`) but keeps the built-in
//! operations would need them to call it: that isn't supported yet, and aborts (fail closed).

use core::ffi::{CStr, c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;
use std::ffi::CString;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};

use rustyssl_abi::{
    BIGNUM, BN_CTX, BN_GENCB, BN_MONT_CTX, ERR_LIB_RSA, RSA, RSA_FLAG_CACHE_PRIVATE,
    RSA_FLAG_CACHE_PUBLIC, RSA_FLAG_FIPS_METHOD, RSA_METHOD,
};
use rustyssl_crypto::rsa::{Hash, Padding};

use crate::bn::modular::BN_mod_exp_mont;
use crate::ffi::{ffi_callback, ffi_export};
use crate::handle::{Handle, handle_type};
use crate::provider::Ptr;
use crate::rsa::{Md, private_random, public_random, raise_all, rsa};

pub(crate) type EncFn =
    unsafe extern "C" fn(c_int, *const c_uchar, *mut c_uchar, *mut RSA, c_int) -> c_int;
pub(crate) type ModExpFn =
    unsafe extern "C" fn(*mut BIGNUM, *const BIGNUM, *mut RSA, *mut BN_CTX) -> c_int;
pub(crate) type BnModExpFn = unsafe extern "C" fn(
    *mut BIGNUM,
    *const BIGNUM,
    *const BIGNUM,
    *const BIGNUM,
    *mut BN_CTX,
    *mut BN_MONT_CTX,
) -> c_int;
pub(crate) type InitFn = unsafe extern "C" fn(*mut RSA) -> c_int;
pub(crate) type SignFn = unsafe extern "C" fn(
    c_int,
    *const c_uchar,
    c_uint,
    *mut c_uchar,
    *mut c_uint,
    *const RSA,
) -> c_int;
pub(crate) type VerifyFn = unsafe extern "C" fn(
    c_int,
    *const c_uchar,
    c_uint,
    *const c_uchar,
    c_uint,
    *const RSA,
) -> c_int;
pub(crate) type KeygenFn =
    unsafe extern "C" fn(*mut RSA, c_int, *mut BIGNUM, *mut BN_GENCB) -> c_int;
pub(crate) type MpKeygenFn =
    unsafe extern "C" fn(*mut RSA, c_int, c_int, *mut BIGNUM, *mut BN_GENCB) -> c_int;

/// `struct rsa_meth_st`.
#[derive(Clone)]
pub(crate) struct Fns {
    /// The name, NUL-terminated, at a stable address while it's the method's.
    name: CString,
    pub(crate) pub_enc: Option<EncFn>,
    pub(crate) pub_dec: Option<EncFn>,
    pub(crate) priv_enc: Option<EncFn>,
    pub(crate) priv_dec: Option<EncFn>,
    pub(crate) mod_exp: Option<ModExpFn>,
    pub(crate) bn_mod_exp: Option<BnModExpFn>,
    pub(crate) init: Option<InitFn>,
    pub(crate) finish: Option<InitFn>,
    pub(crate) flags: c_int,
    app_data: Ptr<c_void>,
    pub(crate) sign: Option<SignFn>,
    pub(crate) verify: Option<VerifyFn>,
    pub(crate) keygen: Option<KeygenFn>,
    pub(crate) mp_keygen: Option<MpKeygenFn>,
}

/// An RSA method.
pub(crate) struct RsaMethod {
    fns: Mutex<Fns>,
    /// Names a renamed method had, kept so a name returned earlier stays readable.
    old_names: Mutex<Vec<CString>>,
}

handle_type!(RSA_METHOD => RsaMethod);

impl RsaMethod {
    fn new(fns: Fns) -> Self {
        RsaMethod {
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

/// `rsa_pkcs1_ossl_meth`.
fn builtin() -> *const RSA_METHOD {
    static BUILTIN: OnceLock<Ptr<RSA_METHOD>> = OnceLock::new();
    BUILTIN
        .get_or_init(|| {
            Ptr(RSA_METHOD::new_handle(RsaMethod::new(Fns {
                name: c"OpenSSL PKCS#1 RSA".to_owned(),
                pub_enc: Some(rsa_ossl_public_encrypt),
                pub_dec: Some(rsa_ossl_public_decrypt),
                priv_enc: Some(rsa_ossl_private_encrypt),
                priv_dec: Some(rsa_ossl_private_decrypt),
                mod_exp: Some(rsa_ossl_mod_exp),
                bn_mod_exp: Some(BN_mod_exp_mont),
                init: Some(rsa_ossl_init),
                finish: Some(rsa_ossl_finish),
                flags: RSA_FLAG_FIPS_METHOD,
                app_data: Ptr(ptr::null_mut()),
                sign: None,
                verify: None,
                keygen: None,
                mp_keygen: None,
            })))
        })
        .0
}

/// `default_RSA_meth`: the built-in method until the application sets another (NULL, too).
static DEFAULT: OnceLock<AtomicPtr<RSA_METHOD>> = OnceLock::new();

/// The default method as set: the built-in one at first.
fn default_cell() -> &'static AtomicPtr<RSA_METHOD> {
    DEFAULT.get_or_init(|| AtomicPtr::new(builtin().cast_mut()))
}

/// The method new keys get: the default, or the built-in one if the application made the
/// default NULL (OpenSSL's `RSA_new` would crash).
pub(crate) fn default_method() -> *const RSA_METHOD {
    let d = default_cell().load(Ordering::Acquire);
    if d.is_null() { builtin() } else { d }
}

/// The method behind `meth` (any live method).
///
/// # Safety
/// `meth` is NULL or a live method.
unsafe fn method<'a>(meth: *const RSA_METHOD) -> Option<&'a RsaMethod> {
    // SAFETY: the caller's guarantee.
    unsafe { RSA_METHOD::get(meth) }
}

/// A method's flags (0 for NULL).
///
/// # Safety
/// `meth` is NULL or a live method.
pub(crate) unsafe fn flags(meth: *const RSA_METHOD) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { method(meth) }.map_or(0, |m| m.fns().flags)
}

/// A method's `init`.
///
/// # Safety
/// `meth` is NULL or a live method.
pub(crate) unsafe fn init_fn(meth: *const RSA_METHOD) -> Option<InitFn> {
    // SAFETY: the caller's guarantee.
    unsafe { method(meth) }.and_then(|m| m.fns().init)
}

/// A method's `finish`.
///
/// # Safety
/// `meth` is NULL or a live method.
pub(crate) unsafe fn finish_fn(meth: *const RSA_METHOD) -> Option<InitFn> {
    // SAFETY: the caller's guarantee.
    unsafe { method(meth) }.and_then(|m| m.fns().finish)
}

/// A method's functions (NULL's are all absent).
///
/// # Safety
/// `meth` is NULL or a live method.
pub(crate) unsafe fn fns_of(meth: *const RSA_METHOD) -> Option<Fns> {
    // SAFETY: the caller's guarantee.
    unsafe { method(meth) }.map(RsaMethod::fns)
}

/// Whether the key's method keeps the built-in modular exponentiations; the built-in
/// operations can't call an application's yet (and abort if asked to).
fn check_exps(fns: &Fns) {
    let builtin_mod_exp: ModExpFn = rsa_ossl_mod_exp;
    let builtin_bn: BnModExpFn = BN_mod_exp_mont;
    if fns
        .mod_exp
        .is_some_and(|f| !ptr::fn_addr_eq(f, builtin_mod_exp))
        || fns
            .bn_mod_exp
            .is_some_and(|f| !ptr::fn_addr_eq(f, builtin_bn))
    {
        crate::stub::unimplemented(
            "the built-in RSA operations with an application's rsa_mod_exp or bn_mod_exp",
        );
    }
}

/// The built-in operations' common start: the key, its size, and the input and output.
///
/// # Safety
/// `r` is NULL or a live key; `from` holds `flen` octets; `to` has room for the key's size.
unsafe fn op_args<'a>(
    flen: c_int,
    from: *const c_uchar,
    to: *mut c_uchar,
    r: *mut RSA,
) -> Option<(
    crate::rsa::RsaState,
    *mut rustyssl_abi::OSSL_LIB_CTX,
    &'a [u8],
    &'a mut [u8],
)> {
    // SAFETY: the caller's guarantee.
    let k = unsafe { rsa(r) }?;
    let fns = k.meth();
    // SAFETY: the key's method, live.
    if let Some(f) = unsafe { fns_of(fns) } {
        check_exps(&f);
    }
    let st = k.snapshot();
    let num = st.key.size();
    let flen = usize::try_from(flen).ok()?;
    // SAFETY: the caller's guarantee.
    let input = unsafe { crate::ffi::bytes(from, flen) }?;
    if to.is_null() {
        return None;
    }
    // SAFETY: the caller's room for the key's size.
    let output = unsafe { core::slice::from_raw_parts_mut(to, num) };
    Some((st, k.libctx.0, input, output))
}

/// A length or -1, as the built-in operations return.
fn len_or_minus_one(r: Result<usize, ()>) -> c_int {
    r.ok().and_then(|n| c_int::try_from(n).ok()).unwrap_or(-1)
}

/// SHA-1 (OAEP's default) or SHA-256 (implicit rejection's) from the key's context.
fn fetch(libctx: *mut rustyssl_abi::OSSL_LIB_CTX, name: &CStr) -> Option<Md> {
    // SAFETY: the key's library context; a name; no properties.
    unsafe { Md::fetch(libctx, name, ptr::null()) }
}

ffi_callback! {
    /// `rsa_ossl_public_encrypt`: `from` padded (PKCS #1 v1.5, OAEP with SHA-1, or none) and
    /// raised to `e`, into `to` (the key's size). The length, or -1.
    ///
    /// # Safety
    /// `rsa` is a live key; `from` holds `flen` octets; `to` has room for the key's size.
    pub(crate) unsafe extern "C" fn rsa_ossl_public_encrypt(flen: c_int, from: *const c_uchar, to: *mut c_uchar, rsa: *mut RSA, padding: c_int) -> c_int
    where failure = -1, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some((st, libctx, input, output)) = (unsafe { op_args(flen, from, to, rsa) }) else { return -1 };
        let sha1 = fetch(libctx, c"SHA1");
        let mut rng = public_random(libctx);
        let (r, raised) = st.key.public_encrypt(input, output, Padding::from_number(padding), sha1.as_ref().map(|m| m as &dyn Hash), &mut rng);
        raise_all(&raised);
        len_or_minus_one(r)
    }
}

ffi_callback! {
    /// `rsa_ossl_public_decrypt`: `from` raised to `e` and its padding (PKCS #1 v1.5 type 1,
    /// X9.31, or none) checked; the data into `to`. The length, or -1.
    ///
    /// # Safety
    /// As for `rsa_ossl_public_encrypt`.
    pub(crate) unsafe extern "C" fn rsa_ossl_public_decrypt(flen: c_int, from: *const c_uchar, to: *mut c_uchar, rsa: *mut RSA, padding: c_int) -> c_int
    where failure = -1, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some((st, _, input, output)) = (unsafe { op_args(flen, from, to, rsa) }) else { return -1 };
        let (r, raised) = st.key.public_decrypt(input, output, Padding::from_number(padding));
        raise_all(&raised);
        len_or_minus_one(r)
    }
}

ffi_callback! {
    /// `rsa_ossl_private_encrypt`: `from` padded (PKCS #1 v1.5 type 1, X9.31, or none) and
    /// raised to `d`, blinded. The length, or -1.
    ///
    /// # Safety
    /// As for `rsa_ossl_public_encrypt`.
    pub(crate) unsafe extern "C" fn rsa_ossl_private_encrypt(flen: c_int, from: *const c_uchar, to: *mut c_uchar, rsa: *mut RSA, padding: c_int) -> c_int
    where failure = -1, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some((st, libctx, input, output)) = (unsafe { op_args(flen, from, to, rsa) }) else { return -1 };
        let mut rng = private_random(libctx);
        let (r, raised) = st.key.private_encrypt(input, output, Padding::from_number(padding), &mut rng);
        raise_all(&raised);
        len_or_minus_one(r)
    }
}

ffi_callback! {
    /// `rsa_ossl_private_decrypt`: `from` raised to `d`, blinded, and its padding (PKCS #1
    /// v1.5 type 2 with implicit rejection, OAEP with SHA-1, or none) checked. The length,
    /// or -1.
    ///
    /// # Safety
    /// As for `rsa_ossl_public_encrypt`.
    pub(crate) unsafe extern "C" fn rsa_ossl_private_decrypt(flen: c_int, from: *const c_uchar, to: *mut c_uchar, rsa: *mut RSA, padding: c_int) -> c_int
    where failure = -1, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some((st, libctx, input, output)) = (unsafe { op_args(flen, from, to, rsa) }) else { return -1 };
        let sha1 = fetch(libctx, c"SHA1");
        let sha256 = fetch(libctx, c"SHA256");
        let mut rng = private_random(libctx);
        let (r, raised) = st.key.private_decrypt(
            input,
            output,
            Padding::from_number(padding),
            sha1.as_ref().map(|m| m as &dyn Hash),
            sha256.as_ref().map(|m| m as &dyn Hash),
            &mut rng,
        );
        raise_all(&raised);
        c_int::try_from(r).unwrap_or(-1)
    }
}

ffi_callback! {
    /// `rsa_ossl_mod_exp`: `r0 = i^d mod n`, through the CRT when the key has its numbers.
    /// 1, or 0.
    ///
    /// # Safety
    /// `r0` and `i` are live `BIGNUM`s; `rsa` is a live key.
    pub(crate) unsafe extern "C" fn rsa_ossl_mod_exp(r0: *mut BIGNUM, i: *const BIGNUM, rsa: *mut RSA, _ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let (Some(k), Some(iv)) = (unsafe { crate::rsa::rsa(rsa) }, unsafe { crate::bn::value(i) }) else { return 0 };
        let st = k.snapshot();
        match st.key.mod_exp(&iv) {
            // SAFETY: the caller's number.
            Some(v) => c_int::from(unsafe { crate::bn::store(r0, v) }),
            None => 0,
        }
    }
}

ffi_callback! {
    /// `rsa_ossl_init`: the key caches its Montgomery contexts (`RSA_FLAG_CACHE_*`).
    ///
    /// # Safety
    /// `rsa` is NULL or a live key.
    pub(crate) unsafe extern "C" fn rsa_ossl_init(rsa: *mut RSA) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        if let Some(k) = unsafe { crate::rsa::rsa(rsa) } {
            let f = k.flags();
            k.set_flags_to(f | RSA_FLAG_CACHE_PUBLIC | RSA_FLAG_CACHE_PRIVATE);
        }
        1
    }
}

ffi_callback! {
    /// `rsa_ossl_finish`: nothing to free (the contexts aren't kept apart from the key).
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn rsa_ossl_finish(_rsa: *mut RSA) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        1
    }
}

ffi_export! {
    /// OpenSSL's own method.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn RSA_PKCS1_OpenSSL() -> *const RSA_METHOD
    where failure = ptr::null(), library = ERR_LIB_RSA
    {
        builtin()
    }
}

ffi_export! {
    /// NULL, as OpenSSL's (there's no null method).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn RSA_null_method() -> *const RSA_METHOD
    where failure = ptr::null(), library = ERR_LIB_RSA
    {
        ptr::null()
    }
}

ffi_export! {
    /// The method new keys get.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn RSA_get_default_method() -> *const RSA_METHOD
    where failure = ptr::null(), library = ERR_LIB_RSA
    {
        default_cell().load(Ordering::Acquire)
    }
}

ffi_export! {
    /// Sets the method new keys get. The application keeps it alive.
    ///
    /// # Safety
    /// `meth` is NULL or a method that outlives its use.
    pub unsafe extern "C" fn RSA_set_default_method(meth: *const RSA_METHOD)
    where failure = (), library = ERR_LIB_RSA
    {
        default_cell().store(meth.cast_mut(), Ordering::Release);
    }
}

ffi_export! {
    /// A new method named `name` (copied), with `flags` and no functions, or NULL.
    ///
    /// # Safety
    /// `name` is NULL or a string.
    pub unsafe extern "C" fn RSA_meth_new(name: *const c_char, flags: c_int) -> *mut RSA_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_RSA
    {
        if name.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's string.
        let name = unsafe { CStr::from_ptr(name) }.to_owned();
        RSA_METHOD::new_handle(RsaMethod::new(Fns {
            name,
            pub_enc: None,
            pub_dec: None,
            priv_enc: None,
            priv_dec: None,
            mod_exp: None,
            bn_mod_exp: None,
            init: None,
            finish: None,
            flags,
            app_data: Ptr(ptr::null_mut()),
            sign: None,
            verify: None,
            keygen: None,
            mp_keygen: None,
        }))
    }
}

ffi_export! {
    /// Frees a method made by `RSA_meth_new` or `RSA_meth_dup`; NULL does nothing.
    ///
    /// # Safety
    /// `meth` is NULL or a method the caller made and gives up (no key may still use it).
    pub unsafe extern "C" fn RSA_meth_free(meth: *mut RSA_METHOD)
    where failure = (), library = ERR_LIB_RSA
    {
        if meth.cast_const() == builtin() {
            // OpenSSL's would free a static object: keep the built-in one.
            return;
        }
        // SAFETY: the caller's guarantee.
        unsafe { RSA_METHOD::free(meth) };
    }
}

ffi_export! {
    /// A copy of `meth`, its name too, or NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method.
    pub unsafe extern "C" fn RSA_meth_dup(meth: *const RSA_METHOD) -> *mut RSA_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        match unsafe { method(meth) } {
            Some(m) => RSA_METHOD::new_handle(RsaMethod::new(m.fns())),
            None => ptr::null_mut(),
        }
    }
}

ffi_export! {
    /// The method's name.
    ///
    /// # Safety
    /// `meth` is NULL or a live method.
    pub unsafe extern "C" fn RSA_meth_get0_name(meth: *const RSA_METHOD) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(meth) }.map_or(ptr::null(), |m| m.with(|f| f.name.as_ptr()))
    }
}

ffi_export! {
    /// Renames the method (`name` copied). 1, or 0.
    ///
    /// # Safety
    /// `meth` is NULL or a live method; `name` is NULL or a string.
    pub unsafe extern "C" fn RSA_meth_set1_name(meth: *mut RSA_METHOD, name: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(meth) }) else { return 0 };
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
    /// `meth` is NULL or a live method.
    pub unsafe extern "C" fn RSA_meth_get_flags(meth: *const RSA_METHOD) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { flags(meth) }
    }
}

ffi_export! {
    /// Sets the method's flags. 1, or 0 for NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method.
    pub unsafe extern "C" fn RSA_meth_set_flags(meth: *mut RSA_METHOD, flags: c_int) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(meth) }) else { return 0 };
        m.with(|f| f.flags = flags);
        1
    }
}

ffi_export! {
    /// The method's application data.
    ///
    /// # Safety
    /// `meth` is NULL or a live method.
    pub unsafe extern "C" fn RSA_meth_get0_app_data(meth: *const RSA_METHOD) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(meth) }.map_or(ptr::null_mut(), |m| m.fns().app_data.0)
    }
}

ffi_export! {
    /// Sets the method's application data. 1, or 0 for NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method.
    pub unsafe extern "C" fn RSA_meth_set0_app_data(meth: *mut RSA_METHOD, app_data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(meth) }) else { return 0 };
        m.with(|f| f.app_data = Ptr(app_data));
        1
    }
}

ffi_export! {
    /// The method's public encryption function, or NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method.
    pub unsafe extern "C" fn RSA_meth_get_pub_enc(meth: *const RSA_METHOD) -> Option<EncFn>
    where failure = None, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(meth) }.and_then(|m| m.fns().pub_enc)
    }
}

ffi_export! {
    /// Sets the method's public encryption function. 1, or 0 for NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method; the function takes what OpenSSL passes it.
    pub unsafe extern "C" fn RSA_meth_set_pub_enc(meth: *mut RSA_METHOD, f: Option<EncFn>) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(meth) }) else { return 0 };
        m.with(|x| x.pub_enc = f);
        1
    }
}

ffi_export! {
    /// The method's public decryption function, or NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method.
    pub unsafe extern "C" fn RSA_meth_get_pub_dec(meth: *const RSA_METHOD) -> Option<EncFn>
    where failure = None, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(meth) }.and_then(|m| m.fns().pub_dec)
    }
}

ffi_export! {
    /// Sets the method's public decryption function. 1, or 0 for NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method; the function takes what OpenSSL passes it.
    pub unsafe extern "C" fn RSA_meth_set_pub_dec(meth: *mut RSA_METHOD, f: Option<EncFn>) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(meth) }) else { return 0 };
        m.with(|x| x.pub_dec = f);
        1
    }
}

ffi_export! {
    /// The method's private encryption function, or NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method.
    pub unsafe extern "C" fn RSA_meth_get_priv_enc(meth: *const RSA_METHOD) -> Option<EncFn>
    where failure = None, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(meth) }.and_then(|m| m.fns().priv_enc)
    }
}

ffi_export! {
    /// Sets the method's private encryption function. 1, or 0 for NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method; the function takes what OpenSSL passes it.
    pub unsafe extern "C" fn RSA_meth_set_priv_enc(meth: *mut RSA_METHOD, f: Option<EncFn>) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(meth) }) else { return 0 };
        m.with(|x| x.priv_enc = f);
        1
    }
}

ffi_export! {
    /// The method's private decryption function, or NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method.
    pub unsafe extern "C" fn RSA_meth_get_priv_dec(meth: *const RSA_METHOD) -> Option<EncFn>
    where failure = None, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(meth) }.and_then(|m| m.fns().priv_dec)
    }
}

ffi_export! {
    /// Sets the method's private decryption function. 1, or 0 for NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method; the function takes what OpenSSL passes it.
    pub unsafe extern "C" fn RSA_meth_set_priv_dec(meth: *mut RSA_METHOD, f: Option<EncFn>) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(meth) }) else { return 0 };
        m.with(|x| x.priv_dec = f);
        1
    }
}

ffi_export! {
    /// The method's private exponentiation function, or NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method.
    pub unsafe extern "C" fn RSA_meth_get_mod_exp(meth: *const RSA_METHOD) -> Option<ModExpFn>
    where failure = None, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(meth) }.and_then(|m| m.fns().mod_exp)
    }
}

ffi_export! {
    /// Sets the method's private exponentiation function. 1, or 0 for NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method; the function takes what OpenSSL passes it.
    pub unsafe extern "C" fn RSA_meth_set_mod_exp(meth: *mut RSA_METHOD, f: Option<ModExpFn>) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(meth) }) else { return 0 };
        m.with(|x| x.mod_exp = f);
        1
    }
}

ffi_export! {
    /// The method's modular exponentiation function, or NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method.
    pub unsafe extern "C" fn RSA_meth_get_bn_mod_exp(meth: *const RSA_METHOD) -> Option<BnModExpFn>
    where failure = None, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(meth) }.and_then(|m| m.fns().bn_mod_exp)
    }
}

ffi_export! {
    /// Sets the method's modular exponentiation function. 1, or 0 for NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method; the function takes what OpenSSL passes it.
    pub unsafe extern "C" fn RSA_meth_set_bn_mod_exp(meth: *mut RSA_METHOD, f: Option<BnModExpFn>) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(meth) }) else { return 0 };
        m.with(|x| x.bn_mod_exp = f);
        1
    }
}

ffi_export! {
    /// The method's init function, or NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method.
    pub unsafe extern "C" fn RSA_meth_get_init(meth: *const RSA_METHOD) -> Option<InitFn>
    where failure = None, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(meth) }.and_then(|m| m.fns().init)
    }
}

ffi_export! {
    /// Sets the method's init function. 1, or 0 for NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method; the function takes what OpenSSL passes it.
    pub unsafe extern "C" fn RSA_meth_set_init(meth: *mut RSA_METHOD, f: Option<InitFn>) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(meth) }) else { return 0 };
        m.with(|x| x.init = f);
        1
    }
}

ffi_export! {
    /// The method's finish function, or NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method.
    pub unsafe extern "C" fn RSA_meth_get_finish(meth: *const RSA_METHOD) -> Option<InitFn>
    where failure = None, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(meth) }.and_then(|m| m.fns().finish)
    }
}

ffi_export! {
    /// Sets the method's finish function. 1, or 0 for NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method; the function takes what OpenSSL passes it.
    pub unsafe extern "C" fn RSA_meth_set_finish(meth: *mut RSA_METHOD, f: Option<InitFn>) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(meth) }) else { return 0 };
        m.with(|x| x.finish = f);
        1
    }
}

ffi_export! {
    /// The method's sign function, or NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method.
    pub unsafe extern "C" fn RSA_meth_get_sign(meth: *const RSA_METHOD) -> Option<SignFn>
    where failure = None, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(meth) }.and_then(|m| m.fns().sign)
    }
}

ffi_export! {
    /// Sets the method's sign function. 1, or 0 for NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method; the function takes what OpenSSL passes it.
    pub unsafe extern "C" fn RSA_meth_set_sign(meth: *mut RSA_METHOD, f: Option<SignFn>) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(meth) }) else { return 0 };
        m.with(|x| x.sign = f);
        1
    }
}

ffi_export! {
    /// The method's verify function, or NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method.
    pub unsafe extern "C" fn RSA_meth_get_verify(meth: *const RSA_METHOD) -> Option<VerifyFn>
    where failure = None, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(meth) }.and_then(|m| m.fns().verify)
    }
}

ffi_export! {
    /// Sets the method's verify function. 1, or 0 for NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method; the function takes what OpenSSL passes it.
    pub unsafe extern "C" fn RSA_meth_set_verify(meth: *mut RSA_METHOD, f: Option<VerifyFn>) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(meth) }) else { return 0 };
        m.with(|x| x.verify = f);
        1
    }
}

ffi_export! {
    /// The method's key generation function, or NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method.
    pub unsafe extern "C" fn RSA_meth_get_keygen(meth: *const RSA_METHOD) -> Option<KeygenFn>
    where failure = None, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(meth) }.and_then(|m| m.fns().keygen)
    }
}

ffi_export! {
    /// Sets the method's key generation function. 1, or 0 for NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method; the function takes what OpenSSL passes it.
    pub unsafe extern "C" fn RSA_meth_set_keygen(meth: *mut RSA_METHOD, f: Option<KeygenFn>) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(meth) }) else { return 0 };
        m.with(|x| x.keygen = f);
        1
    }
}

ffi_export! {
    /// The method's multi-prime key generation function, or NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method.
    pub unsafe extern "C" fn RSA_meth_get_multi_prime_keygen(meth: *const RSA_METHOD) -> Option<MpKeygenFn>
    where failure = None, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(meth) }.and_then(|m| m.fns().mp_keygen)
    }
}

ffi_export! {
    /// Sets the method's multi-prime key generation function. 1, or 0 for NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method; the function takes what OpenSSL passes it.
    pub unsafe extern "C" fn RSA_meth_set_multi_prime_keygen(meth: *mut RSA_METHOD, f: Option<MpKeygenFn>) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(meth) }) else { return 0 };
        m.with(|x| x.mp_keygen = f);
        1
    }
}
