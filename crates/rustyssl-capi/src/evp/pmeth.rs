//! Key methods (`EVP_PKEY_METHOD(3)`, `EVP_PKEY_meth_new(3)`, `EVP_PKEY_meth_get_count(3)`;
//! `pmeth_lib.c`): the built-in methods of the legacy key types and the methods an application
//! adds. A key context for a key type with an application's method uses the method instead of
//! a provider: the context has no key manager, and its operations, ctrls, and checks call the
//! method's functions (its "legacy" state).
//!
//! As in OpenSSL:
//! - Only an application's method takes a context; the built-in ones are there to be found,
//!   copied, and called by applications that wrap them.
//! - The methods are counted and indexed built-ins first, then the application's sorted by key
//!   type; a key type can have several, and the first added is the one found.
//! - `EVP_PKEY_meth_free` frees only methods `EVP_PKEY_meth_new` made, and `EVP_PKEY_meth_copy`
//!   copies the functions and keeps the key type and flags.
//!
//! The built-in methods' functions work on the key types' legacy data: RSA's and RSA-PSS's are
//! `rsa_pmeth.rs`'s, EC's `ec_pmeth.rs`'s; the other types' come with them (4.4 onwards) and abort when called until
//! then (AGENTS.md rule 10). A context keeps its method alive while it uses
//! it (OpenSSL's would use a freed method). Changing a built-in method, which OpenSSL can't do
//! (they're read-only), does nothing here, and NULL methods are refused where it would crash
//! (docs/DEVIATIONS.md).

#[cfg(test)]
use core::ffi::c_uint;
use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, EVP_MD_CTX, EVP_PKEY, EVP_PKEY_CTX, EVP_PKEY_DH,
    EVP_PKEY_DHX, EVP_PKEY_DSA, EVP_PKEY_EC, EVP_PKEY_ED448, EVP_PKEY_ED25519,
    EVP_PKEY_FLAG_AUTOARGLEN, EVP_PKEY_FLAG_SIGCTX_CUSTOM, EVP_PKEY_METHOD, EVP_PKEY_RSA,
    EVP_PKEY_RSA_PSS, EVP_PKEY_X448, EVP_PKEY_X25519, EVP_R_BUFFER_TOO_SMALL, EVP_R_INVALID_KEY,
};

use super::opmeth;
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};

/// `EVP_PKEY_FLAG_DYNAMIC` (`crypto/evp.h`, not a public header): a method
/// `EVP_PKEY_meth_new` made. tests/c/evp_pkey_meth.c shows its value.
pub(crate) const FLAG_DYNAMIC: c_int = 1;

/// The functions of a context alone (`init` and the operations' `*_init`).
pub(crate) type Init = unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> c_int;
pub(crate) type CopyFn = unsafe extern "C" fn(*mut EVP_PKEY_CTX, *const EVP_PKEY_CTX) -> c_int;
pub(crate) type Cleanup = unsafe extern "C" fn(*mut EVP_PKEY_CTX);
/// `paramgen` and `keygen`.
pub(crate) type Gen = unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY) -> c_int;
/// `sign`, `verify_recover`, `encrypt`, and `decrypt`: output, its size, and input.
pub(crate) type Transform = unsafe extern "C" fn(
    *mut EVP_PKEY_CTX,
    *mut c_uchar,
    *mut usize,
    *const c_uchar,
    usize,
) -> c_int;
pub(crate) type Verify =
    unsafe extern "C" fn(*mut EVP_PKEY_CTX, *const c_uchar, usize, *const c_uchar, usize) -> c_int;
/// `signctx_init`, `verifyctx_init`, and `digest_custom`.
pub(crate) type MdInit = unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut EVP_MD_CTX) -> c_int;
pub(crate) type SignCtx =
    unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut c_uchar, *mut usize, *mut EVP_MD_CTX) -> c_int;
pub(crate) type VerifyCtx =
    unsafe extern "C" fn(*mut EVP_PKEY_CTX, *const c_uchar, c_int, *mut EVP_MD_CTX) -> c_int;
pub(crate) type Derive = unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut c_uchar, *mut usize) -> c_int;
pub(crate) type Ctrl = unsafe extern "C" fn(*mut EVP_PKEY_CTX, c_int, c_int, *mut c_void) -> c_int;
pub(crate) type CtrlStr =
    unsafe extern "C" fn(*mut EVP_PKEY_CTX, *const c_char, *const c_char) -> c_int;
pub(crate) type DigestSign =
    unsafe extern "C" fn(*mut EVP_MD_CTX, *mut c_uchar, *mut usize, *const c_uchar, usize) -> c_int;
pub(crate) type DigestVerify =
    unsafe extern "C" fn(*mut EVP_MD_CTX, *const c_uchar, usize, *const c_uchar, usize) -> c_int;
/// `check`, `public_check`, and `param_check`.
pub(crate) type Check = unsafe extern "C" fn(*mut EVP_PKEY) -> c_int;

/// A method's functions (`struct evp_pkey_method_st`).
#[derive(Clone, Copy, Default)]
pub(crate) struct Funcs {
    pub(crate) init: Option<Init>,
    pub(crate) copy: Option<CopyFn>,
    pub(crate) cleanup: Option<Cleanup>,
    pub(crate) paramgen_init: Option<Init>,
    pub(crate) paramgen: Option<Gen>,
    pub(crate) keygen_init: Option<Init>,
    pub(crate) keygen: Option<Gen>,
    pub(crate) sign_init: Option<Init>,
    pub(crate) sign: Option<Transform>,
    pub(crate) verify_init: Option<Init>,
    pub(crate) verify: Option<Verify>,
    pub(crate) verify_recover_init: Option<Init>,
    pub(crate) verify_recover: Option<Transform>,
    pub(crate) signctx_init: Option<MdInit>,
    pub(crate) signctx: Option<SignCtx>,
    pub(crate) verifyctx_init: Option<MdInit>,
    pub(crate) verifyctx: Option<VerifyCtx>,
    pub(crate) encrypt_init: Option<Init>,
    pub(crate) encrypt: Option<Transform>,
    pub(crate) decrypt_init: Option<Init>,
    pub(crate) decrypt: Option<Transform>,
    pub(crate) derive_init: Option<Init>,
    pub(crate) derive: Option<Derive>,
    pub(crate) ctrl: Option<Ctrl>,
    pub(crate) ctrl_str: Option<CtrlStr>,
    pub(crate) digestsign: Option<DigestSign>,
    pub(crate) digestverify: Option<DigestVerify>,
    pub(crate) check: Option<Check>,
    pub(crate) public_check: Option<Check>,
    pub(crate) param_check: Option<Check>,
    pub(crate) digest_custom: Option<MdInit>,
}

/// What `EVP_PKEY_METHOD` handles point to.
pub(crate) struct Pmeth {
    pub(crate) pkey_id: c_int,
    pub(crate) flags: c_int,
    funcs: Mutex<Funcs>,
}

handle_type!(EVP_PKEY_METHOD => Pmeth);

/// A reference to a method.
pub(crate) type Ref = opmeth::Ref<EVP_PKEY_METHOD>;

impl Pmeth {
    /// The functions, as they are now (a copy: none is called with the lock held).
    pub(crate) fn funcs(&self) -> Funcs {
        *self.lock()
    }

    fn lock(&self) -> MutexGuard<'_, Funcs> {
        self.funcs.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn is_dynamic(&self) -> bool {
        self.flags & FLAG_DYNAMIC != 0
    }
}

/// The method behind `pmeth`, or `None` for NULL.
///
/// # Safety
/// `pmeth` is NULL or a live method.
unsafe fn method<'a>(pmeth: *const EVP_PKEY_METHOD) -> Option<&'a Pmeth> {
    // SAFETY: the caller's guarantee.
    unsafe { EVP_PKEY_METHOD::get(pmeth) }
}

/// Changes an application's method's functions with `f`; a built-in method stays as it is.
///
/// # Safety
/// `pmeth` is NULL or a live method.
unsafe fn update(pmeth: *mut EVP_PKEY_METHOD, f: impl FnOnce(&mut Funcs)) {
    // SAFETY: the caller's guarantee.
    if let Some(m) = unsafe { method(pmeth) }
        && m.is_dynamic()
    {
        f(&mut m.lock());
    }
}

/// Reads a method's functions with `f` (nothing for NULL).
///
/// # Safety
/// `pmeth` is NULL or a live method.
unsafe fn read(pmeth: *const EVP_PKEY_METHOD, f: impl FnOnce(&Funcs)) {
    // SAFETY: the caller's guarantee.
    if let Some(m) = unsafe { method(pmeth) } {
        f(&m.funcs());
    }
}

/// Writes `v` to `p` unless it's NULL.
///
/// # Safety
/// `p` is NULL or room for a `T`.
unsafe fn put<T>(p: *mut T, v: T) {
    if !p.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { p.write(v) };
    }
}

/// `standard_methods`: each method's key type, flags, and functions, in OpenSSL's order (by key
/// type).
fn standard_table() -> [(c_int, c_int, Funcs); 10] {
    let rsa = {
        use crate::rsa_pmeth as r;
        Funcs {
            init: Some(r::pkey_rsa_init),
            copy: Some(r::pkey_rsa_copy),
            cleanup: Some(r::pkey_rsa_cleanup),
            keygen: Some(r::pkey_rsa_keygen),
            sign: Some(r::pkey_rsa_sign),
            verify: Some(r::pkey_rsa_verify),
            verify_recover: Some(r::pkey_rsa_verifyrecover),
            encrypt: Some(r::pkey_rsa_encrypt),
            decrypt: Some(r::pkey_rsa_decrypt),
            ctrl: Some(r::pkey_rsa_ctrl),
            ctrl_str: Some(r::pkey_rsa_ctrl_str),
            ..Funcs::default()
        }
    };
    let (dh, dhx) = {
        use crate::dh_pmeth as d;
        let dh = Funcs {
            init: Some(d::pkey_dh_init),
            copy: Some(d::pkey_dh_copy),
            cleanup: Some(d::pkey_dh_cleanup),
            paramgen: Some(d::pkey_dh_paramgen),
            keygen: Some(d::pkey_dh_keygen),
            derive: Some(d::pkey_dh_derive),
            ctrl: Some(d::pkey_dh_ctrl),
            ctrl_str: Some(d::pkey_dh_ctrl_str),
            ..Funcs::default()
        };
        (
            dh,
            Funcs {
                keygen: Some(d::pkey_dhx_keygen),
                ..dh
            },
        )
    };
    let dsa = {
        use crate::dsa_pmeth as d;
        Funcs {
            init: Some(d::pkey_dsa_init),
            copy: Some(d::pkey_dsa_copy),
            cleanup: Some(d::pkey_dsa_cleanup),
            paramgen: Some(d::pkey_dsa_paramgen),
            keygen: Some(d::pkey_dsa_keygen),
            sign: Some(d::pkey_dsa_sign),
            verify: Some(d::pkey_dsa_verify),
            ctrl: Some(d::pkey_dsa_ctrl),
            ctrl_str: Some(d::pkey_dsa_ctrl_str),
            ..Funcs::default()
        }
    };
    let ec = {
        use crate::ec_pmeth as e;
        Funcs {
            init: Some(e::pkey_ec_init),
            copy: Some(e::pkey_ec_copy),
            cleanup: Some(e::pkey_ec_cleanup),
            paramgen: Some(e::pkey_ec_paramgen),
            keygen: Some(e::pkey_ec_keygen),
            sign: Some(e::pkey_ec_sign),
            verify: Some(e::pkey_ec_verify),
            derive: Some(e::pkey_ec_kdf_derive),
            ctrl: Some(e::pkey_ec_ctrl),
            ctrl_str: Some(e::pkey_ec_ctrl_str),
            ..Funcs::default()
        }
    };
    let pss = Funcs {
        sign_init: Some(crate::rsa_pmeth::pkey_pss_init),
        verify_init: Some(crate::rsa_pmeth::pkey_pss_init),
        verify_recover: None,
        encrypt: None,
        decrypt: None,
        ..rsa
    };
    let (x25519, x448, ed25519, ed448) = {
        use crate::ecx_pmeth as x;
        let x25519 = Funcs {
            keygen: Some(x::pkey_ecx_keygen),
            derive: Some(x::pkey_ecx_derive25519),
            ctrl: Some(x::pkey_ecx_ctrl),
            ..Funcs::default()
        };
        let ed25519 = Funcs {
            keygen: Some(x::pkey_ecx_keygen),
            ctrl: Some(x::pkey_ecd_ctrl),
            digestsign: Some(x::pkey_ecd_digestsign25519),
            digestverify: Some(x::pkey_ecd_digestverify25519),
            ..Funcs::default()
        };
        (
            x25519,
            Funcs {
                derive: Some(x::pkey_ecx_derive448),
                ..x25519
            },
            ed25519,
            Funcs {
                digestsign: Some(x::pkey_ecd_digestsign448),
                digestverify: Some(x::pkey_ecd_digestverify448),
                ..ed25519
            },
        )
    };
    [
        (EVP_PKEY_RSA, EVP_PKEY_FLAG_AUTOARGLEN, rsa),
        (EVP_PKEY_DH, 0, dh),
        (EVP_PKEY_DSA, EVP_PKEY_FLAG_AUTOARGLEN, dsa),
        (EVP_PKEY_EC, 0, ec),
        (EVP_PKEY_RSA_PSS, EVP_PKEY_FLAG_AUTOARGLEN, pss),
        (EVP_PKEY_DHX, 0, dhx),
        (EVP_PKEY_X25519, 0, x25519),
        (EVP_PKEY_X448, 0, x448),
        (EVP_PKEY_ED25519, EVP_PKEY_FLAG_SIGCTX_CUSTOM, ed25519),
        (EVP_PKEY_ED448, EVP_PKEY_FLAG_SIGCTX_CUSTOM, ed448),
    ]
}

/// The built-in methods, made once and never freed.
static STANDARD: LazyLock<Vec<Ref>> = LazyLock::new(|| {
    standard_table()
        .into_iter()
        .filter_map(|(pkey_id, flags, f)| {
            let h = EVP_PKEY_METHOD::new_handle(Pmeth {
                pkey_id,
                flags,
                funcs: Mutex::new(f),
            });
            // SAFETY: the new handle's reference, kept for good.
            unsafe { Ref::adopt(h) }
        })
        .collect()
});

/// `app_pkey_methods`: the application's methods, sorted by key type (in the order they were
/// added, within one).
static APP: Mutex<Vec<Ref>> = Mutex::new(Vec::new());

fn app() -> MutexGuard<'static, Vec<Ref>> {
    APP.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `evp_pkey_meth_find_added_by_application`: the application's (first) method for `type_`.
pub(crate) fn find_app(type_: c_int) -> Option<Ref> {
    app().iter().find(|m| m.get().pkey_id == type_).cloned()
}

/// `M_check_autoarg`: for a method that sizes outputs itself (`EVP_PKEY_FLAG_AUTOARGLEN`), the
/// key's size into `*arglen` when there's no output buffer, or 0 with an error if the buffer is
/// smaller (raised as `function`'s); `None` to go on to the method's function.
///
/// # Safety
/// `pkey` is NULL or a live key; `arglen` is NULL or room for a size.
pub(crate) unsafe fn check_autoarg(
    m: &Pmeth,
    pkey: *mut EVP_PKEY,
    arg_is_null: bool,
    arglen: *mut usize,
    function: &str,
) -> Option<c_int> {
    if m.flags & EVP_PKEY_FLAG_AUTOARGLEN == 0 {
        return None;
    }
    // SAFETY: the caller's guarantee.
    let size = unsafe { super::pkey::EVP_PKEY_get_size(pkey) };
    let size = usize::try_from(size).unwrap_or(0);
    if size == 0 {
        crate::err::raise(ERR_LIB_EVP, EVP_R_INVALID_KEY, function);
        return Some(0);
    }
    if arglen.is_null() {
        // The reference writes through NULL (docs/DEVIATIONS.md).
        crate::err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, function);
        return Some(0);
    }
    if arg_is_null {
        // SAFETY: the caller's guarantee.
        unsafe { arglen.write(size) };
        return Some(1);
    }
    // SAFETY: as above.
    if unsafe { arglen.read() } < size {
        crate::err::raise(ERR_LIB_EVP, EVP_R_BUFFER_TOO_SMALL, function);
        return Some(0);
    }
    None
}

/// `EVP_PKEY_meth_find`.
pub(crate) fn find(type_: c_int) -> Option<Ref> {
    find_app(type_).or_else(|| STANDARD.iter().find(|m| m.get().pkey_id == type_).cloned())
}

ffi_export! {
    /// The method of the key type `type_` (an application's first), or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_PKEY_meth_find(type_: c_int) -> *const EVP_PKEY_METHOD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // The methods live until the process ends or the application frees its own.
        find(type_).map_or(ptr::null(), |m| m.as_ptr().cast_const())
    }
}

ffi_export! {
    /// A new method for the key type `id` with `flags` and no functions; NULL if it can't be
    /// made.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_PKEY_meth_new(id: c_int, flags: c_int) -> *mut EVP_PKEY_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        EVP_PKEY_METHOD::new_handle(Pmeth {
            pkey_id: id,
            flags: flags | FLAG_DYNAMIC,
            funcs: Mutex::new(Funcs::default()),
        })
    }
}

ffi_export! {
    /// Fills in the method's key type and flags (each pointer that isn't NULL).
    ///
    /// # Safety
    /// `ppkey_id` and `pflags` are NULL or room for an int; `meth` is NULL or a live method.
    pub unsafe extern "C" fn EVP_PKEY_meth_get0_info(ppkey_id: *mut c_int, pflags: *mut c_int, meth: *const EVP_PKEY_METHOD)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(meth) }) else { return };
        // SAFETY: the caller's guarantee, here and below.
        unsafe { put(ppkey_id, m.pkey_id) };
        // SAFETY: as above.
        unsafe { put(pflags, m.flags) };
    }
}

ffi_export! {
    /// Copies `src`'s functions into `dst`, keeping `dst`'s key type and flags.
    ///
    /// # Safety
    /// `dst` and `src` are NULL or live methods.
    pub unsafe extern "C" fn EVP_PKEY_meth_copy(dst: *mut EVP_PKEY_METHOD, src: *const EVP_PKEY_METHOD)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { method(src) }) else { return };
        let f = s.funcs();
        // SAFETY: as above.
        unsafe { update(dst, |d| *d = f) };
    }
}

ffi_export! {
    /// Frees a method `EVP_PKEY_meth_new` made (the methods registry, and contexts using it,
    /// keep their own references); others are left alone.
    ///
    /// # Safety
    /// `pmeth` is NULL or a live method, not used afterwards if `EVP_PKEY_meth_new` made it.
    pub unsafe extern "C" fn EVP_PKEY_meth_free(pmeth: *mut EVP_PKEY_METHOD)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if unsafe { method(pmeth) }.is_some_and(Pmeth::is_dynamic) {
            // SAFETY: the caller's reference, given up.
            unsafe { EVP_PKEY_METHOD::free(pmeth) };
        }
    }
}

ffi_export! {
    /// Adds an application's method, after any others for its key type.
    ///
    /// # Safety
    /// `pmeth` is NULL or a live method.
    pub unsafe extern "C" fn EVP_PKEY_meth_add0(pmeth: *const EVP_PKEY_METHOD) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { Ref::new(pmeth) }) else { return 0 };
        let id = m.get().pkey_id;
        let mut app = app();
        let at = app.partition_point(|x| x.get().pkey_id <= id);
        app.insert(at, m);
        1
    }
}

ffi_export! {
    /// Removes an application's method: 1, or 0 if it wasn't added.
    ///
    /// # Safety
    /// No preconditions (the method is only compared).
    pub unsafe extern "C" fn EVP_PKEY_meth_remove(pmeth: *const EVP_PKEY_METHOD) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let removed = {
            let mut app = app();
            app.iter().position(|m| m.is(pmeth)).map(|i| app.remove(i))
        };
        c_int::from(removed.is_some())
    }
}

ffi_export! {
    /// How many methods there are: the built-in ones and the application's.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_PKEY_meth_get_count() -> usize
    where failure = 0, library = ERR_LIB_EVP
    {
        STANDARD.len() + app().len()
    }
}

ffi_export! {
    /// The method at `idx` (the built-in ones first), or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_PKEY_meth_get0(idx: usize) -> *const EVP_PKEY_METHOD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        let m = match STANDARD.get(idx) {
            Some(m) => Some(m.clone()),
            None => app().get(idx - STANDARD.len()).cloned(),
        };
        m.map_or(ptr::null(), |m| m.as_ptr().cast_const())
    }
}

/// Defines a setter of one function.
macro_rules! setter {
    (pub unsafe extern "C" fn $name:ident, $field:ident: $ty:ty) => {
        ffi_export! {
            #[doc = concat!("Sets the method's `", stringify!($field), "`.")]
            ///
            /// # Safety
            /// `pmeth` is NULL or a live method; the function is NULL or of the documented type.
            pub unsafe extern "C" fn $name(pmeth: *mut EVP_PKEY_METHOD, $field: Option<$ty>)
            where failure = (), library = ERR_LIB_EVP
            {
                // SAFETY: the caller's guarantee.
                unsafe { update(pmeth, |f| f.$field = $field) };
            }
        }
    };
    (pub unsafe extern "C" fn $name:ident, $first:ident: $t1:ty, $second:ident: $t2:ty) => {
        ffi_export! {
            #[doc = concat!("Sets the method's `", stringify!($first), "` and `", stringify!($second), "`.")]
            ///
            /// # Safety
            /// `pmeth` is NULL or a live method; the functions are NULL or of the documented types.
            pub unsafe extern "C" fn $name(pmeth: *mut EVP_PKEY_METHOD, $first: Option<$t1>, $second: Option<$t2>)
            where failure = (), library = ERR_LIB_EVP
            {
                // SAFETY: the caller's guarantee.
                unsafe {
                    update(pmeth, |f| {
                        f.$first = $first;
                        f.$second = $second;
                    });
                }
            }
        }
    };
}

/// Defines a getter of one function.
macro_rules! getter {
    (pub unsafe extern "C" fn $name:ident, $field:ident: $ty:ty) => {
        ffi_export! {
            #[doc = concat!("The method's `", stringify!($field), "`, into the pointer unless it's NULL.")]
            ///
            /// # Safety
            /// `pmeth` is NULL or a live method; the pointer is NULL or room for a function.
            pub unsafe extern "C" fn $name(pmeth: *const EVP_PKEY_METHOD, $field: *mut Option<$ty>)
            where failure = (), library = ERR_LIB_EVP
            {
                // SAFETY: the caller's guarantee, here and in the closure.
                unsafe { read(pmeth, |f| put($field, f.$field)) };
            }
        }
    };
    (pub unsafe extern "C" fn $name:ident, $first:ident: $t1:ty, $second:ident: $t2:ty) => {
        ffi_export! {
            #[doc = concat!("The method's `", stringify!($first), "` and `", stringify!($second), "`, into the pointers that aren't NULL.")]
            ///
            /// # Safety
            /// `pmeth` is NULL or a live method; the pointers are NULL or room for a function.
            pub unsafe extern "C" fn $name(pmeth: *const EVP_PKEY_METHOD, $first: *mut Option<$t1>, $second: *mut Option<$t2>)
            where failure = (), library = ERR_LIB_EVP
            {
                // SAFETY: the caller's guarantee, here and in the closure.
                unsafe {
                    read(pmeth, |f| {
                        put($first, f.$first);
                        put($second, f.$second);
                    });
                }
            }
        }
    };
}

setter!(pub unsafe extern "C" fn EVP_PKEY_meth_set_init, init: Init);
setter!(pub unsafe extern "C" fn EVP_PKEY_meth_set_copy, copy: CopyFn);
setter!(pub unsafe extern "C" fn EVP_PKEY_meth_set_cleanup, cleanup: Cleanup);
setter!(pub unsafe extern "C" fn EVP_PKEY_meth_set_paramgen, paramgen_init: Init, paramgen: Gen);
setter!(pub unsafe extern "C" fn EVP_PKEY_meth_set_keygen, keygen_init: Init, keygen: Gen);
setter!(pub unsafe extern "C" fn EVP_PKEY_meth_set_sign, sign_init: Init, sign: Transform);
setter!(pub unsafe extern "C" fn EVP_PKEY_meth_set_verify, verify_init: Init, verify: Verify);
setter!(pub unsafe extern "C" fn EVP_PKEY_meth_set_verify_recover, verify_recover_init: Init, verify_recover: Transform);
setter!(pub unsafe extern "C" fn EVP_PKEY_meth_set_signctx, signctx_init: MdInit, signctx: SignCtx);
setter!(pub unsafe extern "C" fn EVP_PKEY_meth_set_verifyctx, verifyctx_init: MdInit, verifyctx: VerifyCtx);
setter!(pub unsafe extern "C" fn EVP_PKEY_meth_set_encrypt, encrypt_init: Init, encrypt: Transform);
setter!(pub unsafe extern "C" fn EVP_PKEY_meth_set_decrypt, decrypt_init: Init, decrypt: Transform);
setter!(pub unsafe extern "C" fn EVP_PKEY_meth_set_derive, derive_init: Init, derive: Derive);
setter!(pub unsafe extern "C" fn EVP_PKEY_meth_set_ctrl, ctrl: Ctrl, ctrl_str: CtrlStr);
setter!(pub unsafe extern "C" fn EVP_PKEY_meth_set_digestsign, digestsign: DigestSign);
setter!(pub unsafe extern "C" fn EVP_PKEY_meth_set_digestverify, digestverify: DigestVerify);
setter!(pub unsafe extern "C" fn EVP_PKEY_meth_set_check, check: Check);
setter!(pub unsafe extern "C" fn EVP_PKEY_meth_set_public_check, public_check: Check);
setter!(pub unsafe extern "C" fn EVP_PKEY_meth_set_param_check, param_check: Check);
setter!(pub unsafe extern "C" fn EVP_PKEY_meth_set_digest_custom, digest_custom: MdInit);

getter!(pub unsafe extern "C" fn EVP_PKEY_meth_get_init, init: Init);
getter!(pub unsafe extern "C" fn EVP_PKEY_meth_get_copy, copy: CopyFn);
getter!(pub unsafe extern "C" fn EVP_PKEY_meth_get_cleanup, cleanup: Cleanup);
getter!(pub unsafe extern "C" fn EVP_PKEY_meth_get_paramgen, paramgen_init: Init, paramgen: Gen);
getter!(pub unsafe extern "C" fn EVP_PKEY_meth_get_keygen, keygen_init: Init, keygen: Gen);
getter!(pub unsafe extern "C" fn EVP_PKEY_meth_get_sign, sign_init: Init, sign: Transform);
getter!(pub unsafe extern "C" fn EVP_PKEY_meth_get_verify, verify_init: Init, verify: Verify);
getter!(pub unsafe extern "C" fn EVP_PKEY_meth_get_verify_recover, verify_recover_init: Init, verify_recover: Transform);
getter!(pub unsafe extern "C" fn EVP_PKEY_meth_get_signctx, signctx_init: MdInit, signctx: SignCtx);
getter!(pub unsafe extern "C" fn EVP_PKEY_meth_get_verifyctx, verifyctx_init: MdInit, verifyctx: VerifyCtx);
getter!(pub unsafe extern "C" fn EVP_PKEY_meth_get_encrypt, encrypt_init: Init, encrypt: Transform);
getter!(pub unsafe extern "C" fn EVP_PKEY_meth_get_decrypt, decrypt_init: Init, decrypt: Transform);
getter!(pub unsafe extern "C" fn EVP_PKEY_meth_get_derive, derive_init: Init, derive: Derive);
getter!(pub unsafe extern "C" fn EVP_PKEY_meth_get_ctrl, ctrl: Ctrl, ctrl_str: CtrlStr);
getter!(pub unsafe extern "C" fn EVP_PKEY_meth_get_digestsign, digestsign: DigestSign);
getter!(pub unsafe extern "C" fn EVP_PKEY_meth_get_digestverify, digestverify: DigestVerify);
getter!(pub unsafe extern "C" fn EVP_PKEY_meth_get_check, check: Check);
getter!(pub unsafe extern "C" fn EVP_PKEY_meth_get_public_check, public_check: Check);
getter!(pub unsafe extern "C" fn EVP_PKEY_meth_get_param_check, param_check: Check);
getter!(pub unsafe extern "C" fn EVP_PKEY_meth_get_digest_custom, digest_custom: MdInit);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::pkey::ameth::{
        EVP_PKEY_asn1_add0, EVP_PKEY_asn1_new, EVP_PKEY_asn1_set_free, EVP_PKEY_asn1_set_public,
    };
    use crate::evp::pkey::{EVP_PKEY_assign, EVP_PKEY_free, EVP_PKEY_get_bits, EVP_PKEY_get0};
    use crate::evp::pkey_ctx::{
        EVP_PKEY_CTX_dup, EVP_PKEY_CTX_free, EVP_PKEY_CTX_get_data, EVP_PKEY_CTX_get0_pkey,
        EVP_PKEY_CTX_new, EVP_PKEY_CTX_set_data, EVP_PKEY_CTX_set_params,
    };
    use crate::evp::signature::{EVP_PKEY_sign, EVP_PKEY_sign_init};
    use core::sync::atomic::{AtomicUsize, Ordering};

    /// A key type of the test's own (no object: only the methods know it).
    const TOY: c_int = 2100;

    static FREED: AtomicUsize = AtomicUsize::new(0);
    static CLEANED: AtomicUsize = AtomicUsize::new(0);
    static CTRLS: AtomicUsize = AtomicUsize::new(0);
    static COUNTED: AtomicUsize = AtomicUsize::new(0);
    static VERIFIED: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn am_free(pk: *mut EVP_PKEY) {
        // SAFETY: the library's live key.
        let p = unsafe { EVP_PKEY_get0(pk) }.cast::<u8>();
        if !p.is_null() {
            FREED.fetch_add(1, Ordering::SeqCst);
            // SAFETY: the box the test gave the key.
            drop(unsafe { Box::from_raw(p) });
        }
    }

    unsafe extern "C" fn am_bits(_: *const EVP_PKEY) -> c_int {
        64
    }

    unsafe extern "C" fn pm_init(ctx: *mut EVP_PKEY_CTX) -> c_int {
        let data = Box::into_raw(Box::new(5u8)).cast();
        // SAFETY: the library's live context.
        unsafe { EVP_PKEY_CTX_set_data(ctx, data) };
        1
    }

    unsafe extern "C" fn pm_copy(dst: *mut EVP_PKEY_CTX, src: *const EVP_PKEY_CTX) -> c_int {
        // SAFETY: the library's live context.
        let d = unsafe { EVP_PKEY_CTX_get_data(src) }.cast::<u8>();
        // SAFETY: the context's box.
        let v = unsafe { *d };
        let data = Box::into_raw(Box::new(v)).cast();
        // SAFETY: as above.
        unsafe { EVP_PKEY_CTX_set_data(dst, data) };
        1
    }

    unsafe extern "C" fn pm_cleanup(ctx: *mut EVP_PKEY_CTX) {
        CLEANED.fetch_add(1, Ordering::SeqCst);
        // SAFETY: the library's live context.
        let d = unsafe { EVP_PKEY_CTX_get_data(ctx) }.cast::<u8>();
        // SAFETY: its box.
        drop(unsafe { Box::from_raw(d) });
    }

    unsafe extern "C" fn pm_sign(
        ctx: *mut EVP_PKEY_CTX,
        sig: *mut c_uchar,
        siglen: *mut usize,
        tbs: *const c_uchar,
        tbslen: usize,
    ) -> c_int {
        // SAFETY: the library's live context.
        let k = unsafe { EVP_PKEY_CTX_get0_pkey(ctx) };
        // SAFETY: its key.
        let d = unsafe { EVP_PKEY_get0(k) }.cast::<u8>();
        // SAFETY: the key's data, a box of one octet.
        let k = unsafe { *d };
        for i in 0..tbslen {
            // SAFETY: the caller's buffer of `tbslen` octets.
            let b = unsafe { tbs.wrapping_add(i).read() };
            // SAFETY: as above.
            unsafe { sig.wrapping_add(i).write(b ^ k) };
        }
        // SAFETY: the caller's size.
        unsafe { siglen.write(tbslen) };
        1
    }

    unsafe extern "C" fn pm_ctrl(
        _: *mut EVP_PKEY_CTX,
        cmd: c_int,
        p1: c_int,
        _: *mut c_void,
    ) -> c_int {
        if cmd == rustyssl_abi::EVP_PKEY_CTRL_SET_DIGEST_SIZE && p1 == 16 {
            CTRLS.fetch_add(1, Ordering::SeqCst);
        }
        1
    }

    /// An application's methods for a key type of its own, through a key and its contexts:
    /// the callbacks get the library's handles (Miri checks the borrows behind them).
    #[test]
    fn applications_methods_take_their_keys_and_contexts() {
        // SAFETY: static strings.
        let a = unsafe { EVP_PKEY_asn1_new(TOY, 0, c"TOY2100".as_ptr(), c"toy".as_ptr()) };
        // SAFETY: the method above (added for good, below); the functions.
        unsafe { EVP_PKEY_asn1_set_public(a, None, None, None, None, None, Some(am_bits)) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_asn1_set_free(a, Some(am_free)) };
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_asn1_add0(a) }, 1);
        let m = added(TOY, EVP_PKEY_FLAG_AUTOARGLEN, |m| {
            // SAFETY: the method; the functions, here and below.
            unsafe { EVP_PKEY_meth_set_init(m, Some(pm_init)) };
            // SAFETY: as above.
            unsafe { EVP_PKEY_meth_set_copy(m, Some(pm_copy)) };
            // SAFETY: as above.
            unsafe { EVP_PKEY_meth_set_cleanup(m, Some(pm_cleanup)) };
            // SAFETY: as above.
            unsafe { EVP_PKEY_meth_set_sign(m, None, Some(pm_sign)) };
            // SAFETY: as above.
            unsafe { EVP_PKEY_meth_set_ctrl(m, Some(pm_ctrl), None) };
        });
        let k = crate::evp::pkey::new();
        let data = Box::into_raw(Box::new(0x5au8));
        // SAFETY: the key; the box, which the key's method frees.
        assert_eq!(unsafe { EVP_PKEY_assign(k, TOY, data.cast()) }, 1);
        // SAFETY: the key.
        assert_eq!(unsafe { EVP_PKEY_get_bits(k) }, 64);
        // SAFETY: as above.
        let c = unsafe { EVP_PKEY_CTX_new(k, ptr::null_mut()) };
        assert!(!c.is_null());
        // SAFETY: the context, here and below.
        assert_eq!(unsafe { EVP_PKEY_sign_init(c) }, 1);
        let mut out = [0u8; 4];
        // The method sizes outputs itself: the key's size, which its method doesn't give.
        let mut len = out.len();
        // SAFETY: as above; the buffers.
        let got = unsafe { EVP_PKEY_sign(c, out.as_mut_ptr(), &raw mut len, b"abcd".as_ptr(), 4) };
        assert_eq!(got, 0);
        crate::err::take_all();
        // SAFETY: as above.
        let d = unsafe { EVP_PKEY_CTX_dup(c) };
        assert!(!d.is_null());
        let mut size: c_uint = 16;
        let key = rustyssl_abi::OSSL_MAC_PARAM_SIZE.as_ptr();
        // SAFETY: a static key; the local.
        let p = unsafe { crate::params::OSSL_PARAM_construct_uint(key, &raw mut size) };
        let params = [p, crate::params::end()];
        // SAFETY: the copy; the array.
        assert_eq!(unsafe { EVP_PKEY_CTX_set_params(d, params.as_ptr()) }, 1);
        assert_eq!(CTRLS.load(Ordering::SeqCst), 1);
        // SAFETY: made above, freed once.
        unsafe { EVP_PKEY_CTX_free(d) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_CTX_free(c) };
        assert_eq!(CLEANED.load(Ordering::SeqCst), 2);
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(k) };
        assert_eq!(FREED.load(Ordering::SeqCst), 1);
        drop_method(m);
    }

    #[test]
    fn the_built_in_table() {
        assert_eq!(STANDARD.len(), 10);
        let rsa = find(EVP_PKEY_RSA).unwrap();
        assert_eq!(rsa.get().flags, EVP_PKEY_FLAG_AUTOARGLEN);
        let f = rsa.get().funcs();
        assert!(f.sign_init.is_none() && f.sign.is_some() && f.derive.is_none());
        assert!(find_app(EVP_PKEY_RSA).is_none());
    }

    #[test]
    fn built_in_methods_stay_as_they_are() {
        let ec = find(EVP_PKEY_EC).unwrap();
        // SAFETY: a built-in method, live for good; NULL is allowed.
        unsafe { EVP_PKEY_meth_set_ctrl(ec.as_ptr(), None, None) };
        assert!(ec.get().funcs().ctrl.is_some());
        // SAFETY: as above; a built-in method isn't freed.
        unsafe { EVP_PKEY_meth_free(ec.as_ptr()) };
        assert!(find(EVP_PKEY_EC).is_some());
    }

    unsafe extern "C" fn derive(_: *mut EVP_PKEY_CTX, _: *mut c_uchar, _: *mut usize) -> c_int {
        0
    }

    unsafe extern "C" fn counting_ctrl(
        _: *mut EVP_PKEY_CTX,
        _: c_int,
        _: c_int,
        _: *mut c_void,
    ) -> c_int {
        COUNTED.fetch_add(1, Ordering::SeqCst);
        1
    }

    /// A method for `id` with `f` set, added; removed and freed by the caller.
    fn added(
        id: c_int,
        flags: c_int,
        f: impl FnOnce(*mut EVP_PKEY_METHOD),
    ) -> *mut EVP_PKEY_METHOD {
        // SAFETY: no preconditions.
        let m = unsafe { EVP_PKEY_meth_new(id, flags) };
        f(m);
        // SAFETY: the method above.
        assert_eq!(unsafe { EVP_PKEY_meth_add0(m) }, 1);
        m
    }

    /// Removes and frees a method `added` made.
    fn drop_method(m: *mut EVP_PKEY_METHOD) {
        // SAFETY: the method, removed and freed once.
        unsafe { EVP_PKEY_meth_remove(m) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_meth_free(m) };
    }

    /// A context for the key type `id` (made by its application's method).
    fn ctx_for(id: c_int) -> *mut EVP_PKEY_CTX {
        // SAFETY: a key type.
        let c = unsafe { crate::evp::pkey_ctx::EVP_PKEY_CTX_new_id(id, ptr::null_mut()) };
        assert!(!c.is_null());
        c
    }

    /// docs/DEVIATIONS.md: NULL methods, and NULL places for a getter's function, are refused
    /// (the reference crashes).
    #[test]
    fn null_methods_are_refused() {
        let m: *mut EVP_PKEY_METHOD = ptr::null_mut();
        let mut id = 7;
        // SAFETY: NULL is the case under test, here and below.
        unsafe { EVP_PKEY_meth_get0_info(&raw mut id, ptr::null_mut(), m) };
        assert_eq!(id, 7);
        // SAFETY: as above.
        unsafe { EVP_PKEY_meth_set_init(m, None) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_meth_copy(m, m) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_meth_free(m) };
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_meth_add0(m) }, 0);
        let ec = find(EVP_PKEY_EC).unwrap();
        // SAFETY: a built-in method; no place for the function.
        unsafe { EVP_PKEY_meth_get_init(ec.as_ptr(), ptr::null_mut()) };
        let find_str = crate::evp::pkey::ameth::EVP_PKEY_asn1_find_str;
        // SAFETY: as above.
        let got = unsafe { find_str(ptr::null_mut(), ptr::null(), -1) };
        assert!(got.is_null());
    }

    /// docs/DEVIATIONS.md: a method freed while added stays in use (the reference frees it
    /// under the registry), and a legacy context copied without the method's `copy` fails (the
    /// reference calls through NULL).
    #[test]
    fn methods_live_while_used() {
        let m = added(2101, 0, |_| {});
        // SAFETY: the method, given up while added.
        unsafe { EVP_PKEY_meth_free(m) };
        assert!(find_app(2101).is_some_and(|f| f.is(m)));
        let c = ctx_for(2101);
        // SAFETY: the context.
        assert!(unsafe { EVP_PKEY_CTX_dup(c) }.is_null());
        // SAFETY: the method, still live (the registry's).
        assert_eq!(unsafe { EVP_PKEY_meth_remove(m) }, 1);
        // SAFETY: the context, which has the method's last reference.
        unsafe { EVP_PKEY_CTX_free(c) };
    }

    /// docs/DEVIATIONS.md: a NULL length for a method that sizes outputs itself, a NULL peer,
    /// the HKDF mode set as a parameter, and `EVP_PKEY_CTX_str2ctrl`/`hex2ctrl` without the
    /// method's ctrl fail (the reference writes or reads through NULL).
    #[test]
    fn legacy_contexts_refuse_what_the_reference_reads_through_null() {
        use crate::evp::ctrl::{EVP_PKEY_CTX_hex2ctrl, EVP_PKEY_CTX_str2ctrl};
        use crate::evp::exchange::{EVP_PKEY_derive_init, EVP_PKEY_derive_set_peer_ex};
        let m = added(2102, EVP_PKEY_FLAG_AUTOARGLEN, |m| {
            // SAFETY: the method; the functions, here and below.
            unsafe { EVP_PKEY_meth_set_sign(m, None, Some(pm_sign)) };
            // SAFETY: as above.
            unsafe { EVP_PKEY_meth_set_derive(m, None, Some(derive)) };
            // SAFETY: as above.
            unsafe { EVP_PKEY_meth_set_ctrl(m, Some(counting_ctrl), None) };
        });
        let c = ctx_for(2102);
        // SAFETY: the context, here and below.
        assert_eq!(unsafe { EVP_PKEY_sign_init(c) }, 1);
        // SAFETY: as above; no length.
        let got = unsafe { EVP_PKEY_sign(c, ptr::null_mut(), ptr::null_mut(), ptr::null(), 0) };
        assert_eq!(got, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_derive_init(c) }, 1);
        let before = COUNTED.load(Ordering::SeqCst);
        // SAFETY: as above; no peer.
        let got = unsafe { EVP_PKEY_derive_set_peer_ex(c, ptr::null_mut(), 0) };
        assert_eq!(got, -1);
        let mut mode: c_int = 1;
        // SAFETY: a static key; the local.
        let p = unsafe { crate::params::OSSL_PARAM_construct_int(c"mode".as_ptr(), &raw mut mode) };
        let params = [p, crate::params::end()];
        // SAFETY: the context; the array.
        assert_eq!(unsafe { EVP_PKEY_CTX_set_params(c, params.as_ptr()) }, 0);
        // Neither reached the ctrl.
        assert_eq!(COUNTED.load(Ordering::SeqCst), before);
        // SAFETY: the context; no string.
        let got = unsafe { EVP_PKEY_CTX_str2ctrl(c, 1, ptr::null()) };
        assert_eq!(got, -2);
        // SAFETY: as above.
        unsafe { EVP_PKEY_CTX_free(c) };
        drop_method(m);
        let m = added(2103, 0, |_| {});
        let c = ctx_for(2103);
        // SAFETY: a context whose method has no ctrl; a static string.
        let got = unsafe { EVP_PKEY_CTX_str2ctrl(c, 1, c"x".as_ptr()) };
        assert_eq!(got, -2);
        // SAFETY: as above.
        let got = unsafe { EVP_PKEY_CTX_hex2ctrl(c, 1, c"00".as_ptr()) };
        assert_eq!(got, -2);
        // SAFETY: as above.
        unsafe { EVP_PKEY_CTX_free(c) };
        drop_method(m);
        crate::err::take_all();
    }

    unsafe extern "C" fn verify(
        _: *mut EVP_PKEY_CTX,
        _: *const c_uchar,
        _: usize,
        _: *const c_uchar,
        _: usize,
    ) -> c_int {
        0
    }

    unsafe extern "C" fn verifyctx(
        _: *mut EVP_PKEY_CTX,
        _: *const c_uchar,
        _: c_int,
        _: *mut EVP_MD_CTX,
    ) -> c_int {
        VERIFIED.fetch_add(1, Ordering::SeqCst);
        1
    }

    /// docs/DEVIATIONS.md: signing through a digest context with a method that signs it itself
    /// (`EVP_PKEY_FLAG_SIGCTX_CUSTOM`) but has no `signctx` fails (the reference calls through
    /// NULL), and verifying a signature too long for `verifyctx`'s `int` fails (the reference
    /// truncates its length).
    #[test]
    fn digest_contexts_refuse_what_their_methods_cant_take() {
        use crate::evp::md_ctx::{EVP_MD_CTX_free, EVP_MD_CTX_new};
        use crate::evp::sigver::{
            EVP_DigestSignFinal, EVP_DigestSignInit, EVP_DigestVerifyFinal, EVP_DigestVerifyInit,
            EVP_MD_CTX_set_pkey_ctx,
        };
        let m = added(2104, EVP_PKEY_FLAG_SIGCTX_CUSTOM, |m| {
            // SAFETY: the method; the functions, here and below.
            unsafe { EVP_PKEY_meth_set_sign(m, None, Some(pm_sign)) };
            // SAFETY: as above.
            unsafe { EVP_PKEY_meth_set_verify(m, None, Some(verify)) };
            // SAFETY: as above.
            unsafe { EVP_PKEY_meth_set_verifyctx(m, None, Some(verifyctx)) };
            // SAFETY: as above.
            unsafe { EVP_PKEY_meth_set_ctrl(m, Some(pm_ctrl), None) };
        });
        // SAFETY: no preconditions.
        let md = unsafe { EVP_MD_CTX_new() };
        let c = ctx_for(2104);
        // SAFETY: the digest context; the key context, which it keeps (and doesn't free).
        unsafe { EVP_MD_CTX_set_pkey_ctx(md, c) };
        let none = ptr::null_mut();
        // SAFETY: the digest context; no digest, engine, or key.
        let got =
            unsafe { EVP_DigestSignInit(md, ptr::null_mut(), ptr::null(), none, none.cast()) };
        assert_eq!(got, 1);
        let mut sig = [0u8; 8];
        let mut len = sig.len();
        // SAFETY: the digest context; the buffer.
        let got = unsafe { EVP_DigestSignFinal(md, sig.as_mut_ptr(), &raw mut len) };
        assert_eq!(got, 0);
        // SAFETY: as above.
        let got =
            unsafe { EVP_DigestVerifyInit(md, ptr::null_mut(), ptr::null(), none, none.cast()) };
        assert_eq!(got, 1);
        let before = VERIFIED.load(Ordering::SeqCst);
        // SAFETY: the digest context; a signature "longer than INT_MAX", never read.
        let got = unsafe { EVP_DigestVerifyFinal(md, sig.as_ptr(), usize::MAX) };
        assert_eq!(got, 0);
        assert_eq!(VERIFIED.load(Ordering::SeqCst), before);
        // SAFETY: the digest context, giving up the key context.
        unsafe { EVP_MD_CTX_set_pkey_ctx(md, ptr::null_mut()) };
        // SAFETY: made above, freed once.
        unsafe { EVP_PKEY_CTX_free(c) };
        // SAFETY: as above.
        unsafe { EVP_MD_CTX_free(md) };
        drop_method(m);
        crate::err::take_all();
    }

    /// docs/DEVIATIONS.md: an algorithm given to a legacy context's signature init fails (the
    /// reference reads the missing key manager's name).
    #[test]
    fn legacy_contexts_take_no_algorithm() {
        use crate::evp::signature::{
            EVP_PKEY_sign_init_ex2, EVP_SIGNATURE_fetch, EVP_SIGNATURE_free,
        };
        let m = added(2105, 0, |m| {
            // SAFETY: the method; the function.
            unsafe { EVP_PKEY_meth_set_sign(m, None, Some(pm_sign)) };
        });
        // SAFETY: no preconditions.
        let lib = unsafe { crate::libctx::OSSL_LIB_CTX_new() };
        // SAFETY: the library context; a static name.
        let sig = unsafe { EVP_SIGNATURE_fetch(lib, c"HMAC".as_ptr(), ptr::null()) };
        assert!(!sig.is_null());
        let c = ctx_for(2105);
        // SAFETY: the context; the algorithm.
        let got = unsafe { EVP_PKEY_sign_init_ex2(c, sig, ptr::null()) };
        assert!(got <= 0);
        // SAFETY: made above, freed once.
        unsafe { EVP_PKEY_CTX_free(c) };
        // SAFETY: as above.
        unsafe { EVP_SIGNATURE_free(sig) };
        // SAFETY: as above.
        unsafe { crate::libctx::OSSL_LIB_CTX_free(lib) };
        drop_method(m);
        crate::err::take_all();
    }

    /// docs/DEVIATIONS.md: exporting a key typed by an application's ASN.1 method fails (the
    /// reference calls its missing `export_to`), and aliases that stand for each other are
    /// found to stand for nothing (the reference loops forever).
    #[test]
    fn application_types_fail_where_the_reference_cant_stop() {
        use crate::evp::pkey::ameth::{EVP_PKEY_asn1_add_alias, EVP_PKEY_asn1_find};
        // SAFETY: a static string.
        let a = unsafe { EVP_PKEY_asn1_new(2106, 0, c"TOY2106".as_ptr(), ptr::null()) };
        // SAFETY: the method, added for good.
        assert_eq!(unsafe { EVP_PKEY_asn1_add0(a) }, 1);
        let k = crate::evp::pkey::new();
        // SAFETY: the key; no data.
        assert_eq!(unsafe { EVP_PKEY_assign(k, 2106, ptr::null_mut()) }, 0);
        // SAFETY: the key; no callback is reached.
        let got = unsafe { crate::evp::pkey::EVP_PKEY_export(k, 0, None, ptr::null_mut()) };
        assert_eq!(got, 0);
        // SAFETY: made above.
        unsafe { EVP_PKEY_free(k) };
        // SAFETY: no preconditions, here and below.
        assert_eq!(unsafe { EVP_PKEY_asn1_add_alias(2108, 2107) }, 1);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_asn1_add_alias(2107, 2108) }, 1);
        // SAFETY: as above.
        assert!(unsafe { EVP_PKEY_asn1_find(ptr::null_mut(), 2107) }.is_null());
    }
}
