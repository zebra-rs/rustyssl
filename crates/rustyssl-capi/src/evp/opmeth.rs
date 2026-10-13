//! What the algorithms of the key operations after signing have in common (`EVP_KEYEXCH(3)`,
//! `EVP_ASYM_CIPHER(3)`, `EVP_KEM(3)`): an algorithm made from a provider's (its first name,
//! number, description, provider, and functions), references to it, fetching it, the
//! introspection functions each has, and how an operation's init finds the algorithm for a key.
//!
//! Each operation's module says which functions its algorithms have and which make a whole
//! ([`Table`]); OpenSSL's `*_from_algorithm` counts each function once, by its first entry,
//! which is what keeping the first of each id here amounts to.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;
use std::ffi::CString;
use std::sync::Arc;

use rustyssl_abi::{ERR_LIB_EVP, ERR_R_EVP_LIB, EVP_R_INVALID_PROVIDER_FUNCTIONS};
use rustyssl_abi::{OSSL_ALGORITHM, OSSL_LIB_CTX, OSSL_PARAM, OSSL_PROVIDER};

use super::fetch::{self, Kind};
use super::keymgmt;
use super::pkey::{self, KeyData, PkeyRef};
use crate::err;
use crate::handle::Handle;
use crate::provider::Ptr;

/// A dispatch table's function, as the table holds it.
pub(crate) type AnyFn = unsafe extern "C" fn();
/// `freectx`.
pub(crate) type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
/// `dupctx`.
pub(crate) type DupCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
/// `get_ctx_params`.
pub(crate) type GetParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
/// `set_ctx_params`.
pub(crate) type SetParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
/// `gettable_ctx_params` and `settable_ctx_params`: the context (or NULL) and the provider's.
pub(crate) type ListFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;
/// `newctx` of the operations that take only the provider's context.
pub(crate) type NewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;

/// A dispatch table's function as the type its id stands for.
///
/// # Safety
/// `F` is the function pointer type `f` really has.
pub(crate) unsafe fn cast<F: Copy>(f: AnyFn) -> F {
    // SAFETY: the caller's guarantee; function pointers all have one size.
    unsafe { core::mem::transmute_copy(&f) }
}

/// The functions every operation's algorithms have.
#[derive(Default, Clone, Copy)]
pub(crate) struct Common {
    pub(crate) newctx: Option<NewCtxFn>,
    pub(crate) freectx: Option<FreeCtxFn>,
    pub(crate) dupctx: Option<DupCtxFn>,
    pub(crate) get_ctx_params: Option<GetParamsFn>,
    pub(crate) gettable_ctx_params: Option<ListFn>,
    pub(crate) set_ctx_params: Option<SetParamsFn>,
    pub(crate) settable_ctx_params: Option<ListFn>,
}

impl Common {
    /// Whether the parameter functions come in pairs (both or neither).
    pub(crate) fn params_paired(&self) -> bool {
        self.get_ctx_params.is_some() == self.gettable_ctx_params.is_some()
            && self.set_ctx_params.is_some() == self.settable_ctx_params.is_some()
    }
}

/// An operation's function table.
pub(crate) trait Table: Default + Copy + 'static {
    /// The function that makes the algorithms, which names it in errors.
    const FROM_ALGORITHM: &'static str;
    /// Stores the function `f` with the id `id`, unless one with that id came first.
    fn set(&mut self, id: c_int, f: AnyFn);
    /// Whether the functions make a whole.
    fn whole(&self) -> bool;
    /// The functions every operation has.
    fn common(&self) -> &Common;
}

/// Stores `f` in `slot` if it's empty.
///
/// # Safety
/// `F` is the type of the function the id that brought `f` stands for.
pub(crate) unsafe fn keep_fn<F: Copy>(slot: &mut Option<F>, f: AnyFn) {
    if slot.is_none() {
        // SAFETY: the caller's guarantee.
        *slot = Some(unsafe { cast(f) });
    }
}

/// Stores `$f` in `$slot` unless one came first, as the type the slot holds: the provider's
/// guarantee of the function type for the id that brought it.
macro_rules! keep {
    ($slot:expr, $f:expr) => {{
        // SAFETY: the provider's guarantee of the function type for the id.
        unsafe { $crate::evp::opmeth::keep_fn(&mut $slot, $f) }
    }};
}
pub(crate) use keep;

/// An algorithm of an operation.
pub(crate) struct OpMethod<T> {
    pub(crate) name_id: u32,
    pub(crate) type_name: CString,
    /// The provider's description, a static string of its, or NULL.
    pub(crate) description: Ptr<c_char>,
    /// The provider, with a reference.
    pub(crate) prov: Ptr<OSSL_PROVIDER>,
    pub(crate) funcs: T,
}

impl<T> Drop for OpMethod<T> {
    fn drop(&mut self) {
        // SAFETY: the provider reference the method holds.
        unsafe { OSSL_PROVIDER::free(self.prov.0) };
    }
}

impl<T: Table> OpMethod<T> {
    /// The provider's context, which the provider functions take.
    pub(crate) fn provider_ctx(&self) -> *mut c_void {
        // SAFETY: the method holds a reference to its live provider.
        unsafe { crate::provider::OSSL_PROVIDER_get0_provider_ctx(self.prov.0) }
    }

    /// Whether `name` is one of the algorithm's names.
    pub(crate) fn is_a(&self, name: &[u8]) -> bool {
        fetch::number_in(self.prov.0, name) == self.name_id
    }

    /// `"<name> <what>:<description>"`, the text OpenSSL's errors name a function with.
    pub(crate) fn text(&self, what: &str) -> String {
        let desc = if self.description.0.is_null() {
            String::new()
        } else {
            // SAFETY: the provider's static string.
            unsafe { CStr::from_ptr(self.description.0) }
                .to_string_lossy()
                .into_owned()
        };
        format!("{} {what}:{desc}", self.type_name.to_string_lossy())
    }

    /// `newctx`: a new context, or NULL.
    pub(crate) fn newctx(&self) -> *mut c_void {
        match self.funcs.common().newctx {
            // SAFETY: the provider's function with its context.
            Some(f) => unsafe { f(self.provider_ctx()) },
            None => ptr::null_mut(),
        }
    }

    /// `freectx`.
    ///
    /// # Safety
    /// `algctx` is a context of this algorithm, not used afterwards.
    pub(crate) unsafe fn freectx(&self, algctx: *mut c_void) {
        if let Some(f) = self.funcs.common().freectx {
            // SAFETY: the caller's guarantee.
            unsafe { f(algctx) };
        }
    }

    /// `dupctx`, or NULL without it.
    ///
    /// # Safety
    /// `algctx` is a context of this algorithm.
    pub(crate) unsafe fn dupctx(&self, algctx: *mut c_void) -> *mut c_void {
        match self.funcs.common().dupctx {
            // SAFETY: the caller's guarantee.
            Some(f) => unsafe { f(algctx) },
            None => ptr::null_mut(),
        }
    }

    /// `set_ctx_params`, if it has one.
    ///
    /// # Safety
    /// `algctx` is a context of this algorithm; `params` is NULL or an array.
    pub(crate) unsafe fn set_ctx_params(
        &self,
        algctx: *mut c_void,
        params: *const OSSL_PARAM,
    ) -> Option<c_int> {
        // SAFETY: the caller's guarantee.
        self.funcs
            .common()
            .set_ctx_params
            .map(|f| unsafe { f(algctx, params) })
    }

    /// `get_ctx_params`, if it has one.
    ///
    /// # Safety
    /// `algctx` is a context of this algorithm; `params` is NULL or an array.
    pub(crate) unsafe fn get_ctx_params(
        &self,
        algctx: *mut c_void,
        params: *mut OSSL_PARAM,
    ) -> Option<c_int> {
        // SAFETY: the caller's guarantee.
        self.funcs
            .common()
            .get_ctx_params
            .map(|f| unsafe { f(algctx, params) })
    }

    /// `gettable_ctx_params` for `algctx` (NULL for the algorithm's), if it has one.
    ///
    /// # Safety
    /// `algctx` is NULL or a context of this algorithm.
    pub(crate) unsafe fn gettable_ctx_params(
        &self,
        algctx: *mut c_void,
    ) -> Option<*const OSSL_PARAM> {
        let provctx = self.provider_ctx();
        // SAFETY: the caller's guarantee.
        self.funcs
            .common()
            .gettable_ctx_params
            .map(|f| unsafe { f(algctx, provctx) })
    }

    /// `settable_ctx_params` for `algctx` (NULL for the algorithm's), if it has one.
    ///
    /// # Safety
    /// `algctx` is NULL or a context of this algorithm.
    pub(crate) unsafe fn settable_ctx_params(
        &self,
        algctx: *mut c_void,
    ) -> Option<*const OSSL_PARAM> {
        let provctx = self.provider_ctx();
        // SAFETY: the caller's guarantee.
        self.funcs
            .common()
            .settable_ctx_params
            .map(|f| unsafe { f(algctx, provctx) })
    }
}

/// `evp_*_from_algorithm`: an algorithm of the handle type `C` from the provider's, with one
/// reference, or NULL with an error.
///
/// # Safety
/// `algo`'s names, description, and table are the provider's, valid while it lives; `prov` is
/// a live provider.
pub(crate) unsafe fn from_algorithm<C, T>(
    name_id: u32,
    algo: &OSSL_ALGORITHM,
    prov: *mut OSSL_PROVIDER,
) -> *mut c_void
where
    C: Handle<Object = OpMethod<T>>,
    T: Table,
{
    // SAFETY: the caller's guarantee.
    let names = unsafe { CStr::from_ptr(algo.algorithm_names) }.to_bytes();
    let first = names.split(|&c| c == b':').next().unwrap_or(names);
    let Ok(type_name) = CString::new(first) else {
        err::raise(ERR_LIB_EVP, ERR_R_EVP_LIB, T::FROM_ALGORITHM);
        return ptr::null_mut();
    };
    let mut funcs = T::default();
    let mut at = algo.implementation;
    // SAFETY: the caller's guarantee: the table is ended by a zero id.
    while let Some(d) = unsafe { at.as_ref() } {
        if d.function_id == 0 {
            break;
        }
        at = at.wrapping_add(1);
        if let Some(f) = d.function {
            funcs.set(d.function_id, f);
        }
    }
    if !funcs.whole() {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_INVALID_PROVIDER_FUNCTIONS,
            T::FROM_ALGORITHM,
        );
        return ptr::null_mut();
    }
    // SAFETY: the caller's live provider; the method holds the reference.
    if !unsafe { OSSL_PROVIDER::up_ref(prov) } {
        err::raise(ERR_LIB_EVP, ERR_R_EVP_LIB, T::FROM_ALGORITHM);
        return ptr::null_mut();
    }
    C::new_handle(OpMethod {
        name_id,
        type_name,
        description: Ptr(algo.algorithm_description.cast_mut()),
        prov: Ptr(prov),
        funcs,
    })
    .cast()
}

/// Adds a reference to an algorithm in a store.
///
/// # Safety
/// `m` is a live algorithm of the handle type `C`.
pub(crate) unsafe fn up_ref<C: Handle>(m: *mut c_void) {
    // SAFETY: the caller's guarantee.
    unsafe { C::up_ref(m.cast()) };
}

/// Drops a reference to an algorithm in a store.
///
/// # Safety
/// `m` is a reference to an algorithm of the handle type `C`, given up.
pub(crate) unsafe fn free<C: Handle>(m: *mut c_void) {
    // SAFETY: the caller's guarantee.
    unsafe { C::free(m.cast()) };
}

/// A reference to an algorithm, given up when dropped.
pub(crate) struct Ref<C: Handle>(Ptr<C>);

impl<C: Handle> Ref<C> {
    /// Takes over a reference the caller holds; `None` for NULL.
    ///
    /// # Safety
    /// `m` is NULL or a live algorithm whose reference the caller gives up.
    pub(crate) unsafe fn adopt(m: *mut C) -> Option<Self> {
        (!m.is_null()).then_some(Self(Ptr(m)))
    }

    /// The algorithm.
    pub(crate) fn get(&self) -> &C::Object {
        // SAFETY: this holds a reference to a live algorithm (checked when made).
        match unsafe { C::get(self.0.0) } {
            Some(m) => m,
            None => crate::ffi::die("a held key operation algorithm is live"),
        }
    }
}

impl<C: Handle> Clone for Ref<C> {
    fn clone(&self) -> Self {
        // SAFETY: the algorithm is live (this holds a reference).
        unsafe { C::up_ref(self.0.0) };
        Self(self.0)
    }
}

impl<C: Handle> Drop for Ref<C> {
    fn drop(&mut self) {
        // SAFETY: the reference this holds, given up.
        unsafe { C::free(self.0.0) };
    }
}

/// `*_fetch`: the algorithm `name`, or `None` with the fetch's error.
///
/// # Safety
/// `libctx` is NULL or a live library context; `kind` makes algorithms of the type `C`.
pub(crate) unsafe fn fetch_by_name<C: Handle>(
    libctx: *mut OSSL_LIB_CTX,
    kind: &'static Kind,
    name: &CStr,
    properties: Option<&CStr>,
) -> Option<Ref<C>> {
    // SAFETY: the caller's guarantee.
    let m = unsafe { fetch::fetch(libctx, kind, Some(name), properties) };
    // SAFETY: a new reference, given to the `Ref`.
    unsafe { Ref::adopt(m.cast()) }
}

/// `evp_*_fetch_from_prov`.
///
/// # Safety
/// `prov` is a live provider; `kind` makes algorithms of the type `C`.
pub(crate) unsafe fn fetch_from_prov<C: Handle>(
    prov: *mut OSSL_PROVIDER,
    kind: &'static Kind,
    name: &CStr,
    properties: Option<&CStr>,
) -> Option<Ref<C>> {
    // SAFETY: the caller's guarantee.
    let m = unsafe { fetch::fetch_from_prov(prov, kind, Some(name), properties) };
    // SAFETY: a new reference, given to the `Ref`.
    unsafe { Ref::adopt(m.cast()) }
}

/// What the inits' search finds: the algorithm and the key's data in its provider's key
/// manager (which the data holds).
pub(crate) struct Found<C: Handle> {
    pub(crate) method: Ref<C>,
    pub(crate) keydata: Arc<KeyData>,
}

/// Why [`find`] found nothing.
pub(crate) enum NotFound {
    /// The key manager's provider has no such algorithm (OpenSSL's legacy path, or for KEMs an
    /// error).
    NotInProvider,
    /// No algorithm found takes the key.
    Exhausted,
}

/// The loop the operations' inits share: the algorithm the key manager names for the operation,
/// fetched from `libctx`, then from the key manager's provider, with the key exported to that
/// provider's key manager. Raises nothing itself (the fetches do).
///
/// # Safety
/// `libctx` is NULL or a live library context; `kind` makes algorithms of the type `C`.
pub(crate) unsafe fn find<C, T>(
    libctx: *mut OSSL_LIB_CTX,
    kind: &'static Kind,
    ctx_keymgmt: &keymgmt::Ref,
    pkey: &PkeyRef,
    propq: Option<&CStr>,
    supported: &CStr,
) -> Result<Found<C>, NotFound>
where
    C: Handle<Object = OpMethod<T>>,
    T: Table,
{
    for iter in 1..3 {
        let method: Option<Ref<C>> = if iter == 1 {
            // SAFETY: the caller's guarantee.
            unsafe { fetch_by_name(libctx, kind, supported, propq) }
        } else {
            let prov = ctx_keymgmt.get().prov.0;
            // SAFETY: the key manager's live provider.
            let m = unsafe { fetch_from_prov(prov, kind, supported, propq) };
            Some(m.ok_or(NotFound::NotInProvider)?)
        };
        let Some(method) = method else { continue };
        let prov = method.get().prov.0;
        // SAFETY: the algorithm's live provider.
        let km = unsafe { keymgmt::fetch_from_prov(prov, ctx_keymgmt.get().name(), propq) };
        if let Some(km) = km {
            // SAFETY: the caller's guarantee.
            if let Some((_, kd)) = unsafe { pkey::export_to_any(pkey, libctx, Some(km), propq) } {
                return Ok(Found {
                    method,
                    keydata: kd,
                });
            }
        }
    }
    Err(NotFound::Exhausted)
}

/// A C string argument, `None` for NULL.
///
/// # Safety
/// `s` is NULL or a string.
pub(crate) unsafe fn text<'a>(s: *const c_char) -> Option<&'a CStr> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) })
}

/// A names callback.
pub(crate) type NameFn = unsafe extern "C" fn(*const c_char, *mut c_void);

/// `*_names_do_all`: calls `f` with each of the algorithm's names; whether it has any.
///
/// # Safety
/// `f` is NULL or a function of the documented type.
pub(crate) unsafe fn names_do_all<T: Table>(
    m: &OpMethod<T>,
    f: Option<NameFn>,
    data: *mut c_void,
) -> c_int {
    let names = fetch::names_of(m.prov.0, m.name_id);
    for n in &names {
        let Ok(c) = CString::new(n.clone()) else {
            continue;
        };
        if let Some(f) = f {
            // SAFETY: the caller's callback with a string and its data.
            unsafe { f(c.as_ptr(), data) };
        }
    }
    c_int::from(!names.is_empty())
}

/// Defines an operation's fetching and introspection exports, in the order: fetch, up_ref, free,
/// get0_provider, get0_name, get0_description, is_a, names_do_all, do_all_provided,
/// gettable_ctx_params, settable_ctx_params. Functions given NULL fail where the reference
/// would crash (docs/DEVIATIONS.md).
macro_rules! method_exports {
    (
        $c:ident, $kind:expr;
        pub unsafe extern "C" fn $fetch:ident;
        pub unsafe extern "C" fn $up_ref:ident;
        pub unsafe extern "C" fn $free:ident;
        pub unsafe extern "C" fn $get0_provider:ident;
        pub unsafe extern "C" fn $get0_name:ident;
        pub unsafe extern "C" fn $get0_description:ident;
        pub unsafe extern "C" fn $is_a:ident;
        pub unsafe extern "C" fn $names_do_all:ident;
        pub unsafe extern "C" fn $do_all_provided:ident;
        pub unsafe extern "C" fn $gettable:ident;
        pub unsafe extern "C" fn $settable:ident;
    ) => {
        $crate::ffi::ffi_export! {
            /// The algorithm `algorithm` from the providers of `ctx` (the default context for
            /// NULL) that best matches `properties`, with a reference; NULL with an error if none
            /// does.
            ///
            /// # Safety
            /// `ctx` is NULL or a live library context; `algorithm` and `properties` are NULL or
            /// strings.
            pub unsafe extern "C" fn $fetch(ctx: *mut OSSL_LIB_CTX, algorithm: *const c_char, properties: *const c_char) -> *mut $c
            where failure = core::ptr::null_mut(), library = rustyssl_abi::ERR_LIB_EVP
            {
                // SAFETY: the caller's guarantee.
                let name = unsafe { $crate::evp::opmeth::text(algorithm) };
                // SAFETY: as above.
                let props = unsafe { $crate::evp::opmeth::text(properties) };
                // SAFETY: the caller's guarantee.
                unsafe { $crate::evp::fetch::fetch(ctx, &$kind, name, props) }.cast()
            }
        }

        $crate::ffi::ffi_export! {
            /// Adds a reference. Returns 1 (0 for NULL, where OpenSSL would crash).
            ///
            /// # Safety
            /// `m` is NULL or a live algorithm.
            pub unsafe extern "C" fn $up_ref(m: *mut $c) -> c_int
            where failure = 0, library = rustyssl_abi::ERR_LIB_EVP
            {
                // SAFETY: the caller's guarantee.
                c_int::from(unsafe { <$c as $crate::handle::Handle>::up_ref(m) })
            }
        }

        $crate::ffi::ffi_export! {
            /// Drops a reference; NULL does nothing.
            ///
            /// # Safety
            /// `m` is NULL or an algorithm the caller holds, not used afterwards.
            pub unsafe extern "C" fn $free(m: *mut $c)
            where failure = (), library = rustyssl_abi::ERR_LIB_EVP
            {
                // SAFETY: the caller's guarantee.
                unsafe { <$c as $crate::handle::Handle>::free(m) };
            }
        }

        $crate::ffi::ffi_export! {
            /// The provider the algorithm came from (NULL for NULL).
            ///
            /// # Safety
            /// `m` is NULL or a live algorithm.
            pub unsafe extern "C" fn $get0_provider(m: *const $c) -> *mut OSSL_PROVIDER
            where failure = core::ptr::null_mut(), library = rustyssl_abi::ERR_LIB_EVP
            {
                // SAFETY: the caller's guarantee.
                unsafe { <$c as $crate::handle::Handle>::get(m) }.map_or(core::ptr::null_mut(), |m| m.prov.0)
            }
        }

        $crate::ffi::ffi_export! {
            /// The algorithm's first name; NULL for NULL.
            ///
            /// # Safety
            /// `m` is NULL or a live algorithm.
            pub unsafe extern "C" fn $get0_name(m: *const $c) -> *const c_char
            where failure = core::ptr::null(), library = rustyssl_abi::ERR_LIB_EVP
            {
                // SAFETY: the caller's guarantee.
                unsafe { <$c as $crate::handle::Handle>::get(m) }.map_or(core::ptr::null(), |m| m.type_name.as_ptr())
            }
        }

        $crate::ffi::ffi_export! {
            /// The provider's description of the algorithm, or NULL.
            ///
            /// # Safety
            /// `m` is NULL or a live algorithm.
            pub unsafe extern "C" fn $get0_description(m: *const $c) -> *const c_char
            where failure = core::ptr::null(), library = rustyssl_abi::ERR_LIB_EVP
            {
                // SAFETY: the caller's guarantee.
                unsafe { <$c as $crate::handle::Handle>::get(m) }.map_or(core::ptr::null(), |m| m.description.0.cast_const())
            }
        }

        $crate::ffi::ffi_export! {
            /// Whether `name` is one of the algorithm's names. 0 for NULL.
            ///
            /// # Safety
            /// `m` is NULL or a live algorithm; `name` is NULL or a string.
            pub unsafe extern "C" fn $is_a(m: *const $c, name: *const c_char) -> c_int
            where failure = 0, library = rustyssl_abi::ERR_LIB_EVP
            {
                // SAFETY: the caller's guarantee.
                let Some(m) = (unsafe { <$c as $crate::handle::Handle>::get(m) }) else { return 0 };
                // SAFETY: the caller's guarantee.
                let n = unsafe { $crate::evp::opmeth::text(name) }.map_or(&b""[..], core::ffi::CStr::to_bytes);
                c_int::from(m.is_a(n))
            }
        }

        $crate::ffi::ffi_export! {
            /// Calls `fn_` with each of the algorithm's names. Returns 1 if it has any (0 for
            /// NULL).
            ///
            /// # Safety
            /// `m` is NULL or a live algorithm; `fn_` is a function of the documented type.
            pub unsafe extern "C" fn $names_do_all(m: *const $c, fn_: Option<$crate::evp::opmeth::NameFn>, data: *mut c_void) -> c_int
            where failure = 0, library = rustyssl_abi::ERR_LIB_EVP
            {
                // SAFETY: the caller's guarantee.
                let Some(m) = (unsafe { <$c as $crate::handle::Handle>::get(m) }) else { return 0 };
                // SAFETY: the caller's guarantee.
                unsafe { $crate::evp::opmeth::names_do_all(m, fn_, data) }
            }
        }

        $crate::ffi::ffi_export! {
            /// Calls `fn_` with each algorithm of the operation the active providers of
            /// `libctx` offer.
            ///
            /// # Safety
            /// `libctx` is NULL or a live library context; `fn_` is a function of the
            /// documented type.
            pub unsafe extern "C" fn $do_all_provided(libctx: *mut OSSL_LIB_CTX, fn_: Option<unsafe extern "C" fn(*mut $c, *mut c_void)>, arg: *mut c_void)
            where failure = (), library = rustyssl_abi::ERR_LIB_EVP
            {
                // SAFETY: the caller's guarantee.
                let all = unsafe { $crate::evp::fetch::all(libctx, &$kind) };
                for m in &all {
                    if let Some(f) = fn_ {
                        // SAFETY: the caller's callback with an algorithm held for the call.
                        unsafe { f(m.as_ptr().cast(), arg) };
                    }
                }
            }
        }

        $crate::ffi::ffi_export! {
            /// The context parameters the algorithm can report (asked without a context), or
            /// NULL.
            ///
            /// # Safety
            /// `m` is NULL or a live algorithm.
            pub unsafe extern "C" fn $gettable(m: *const $c) -> *const OSSL_PARAM
            where failure = core::ptr::null(), library = rustyssl_abi::ERR_LIB_EVP
            {
                // SAFETY: the caller's guarantee.
                let Some(m) = (unsafe { <$c as $crate::handle::Handle>::get(m) }) else { return core::ptr::null() };
                // SAFETY: no context.
                unsafe { m.gettable_ctx_params(core::ptr::null_mut()) }.unwrap_or(core::ptr::null())
            }
        }

        $crate::ffi::ffi_export! {
            /// The context parameters the algorithm can be given (asked without a context), or
            /// NULL.
            ///
            /// # Safety
            /// `m` is NULL or a live algorithm.
            pub unsafe extern "C" fn $settable(m: *const $c) -> *const OSSL_PARAM
            where failure = core::ptr::null(), library = rustyssl_abi::ERR_LIB_EVP
            {
                // SAFETY: the caller's guarantee.
                let Some(m) = (unsafe { <$c as $crate::handle::Handle>::get(m) }) else { return core::ptr::null() };
                // SAFETY: no context.
                unsafe { m.settable_ctx_params(core::ptr::null_mut()) }.unwrap_or(core::ptr::null())
            }
        }
    };
}
pub(crate) use method_exports;
