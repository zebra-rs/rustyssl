//! Signatures (`EVP_SIGNATURE(3)`, `EVP_PKEY_sign(3)`, `EVP_PKEY_verify(3)`,
//! `EVP_PKEY_verify_recover(3)`, the message-signing functions; `signature.c`): an
//! `EVP_SIGNATURE` made from a provider's signature algorithm (`evp_signature_from_algorithm`),
//! fetched by name and properties, and the key context's signature operations run through it.
//!
//! As in OpenSSL:
//! - A signature algorithm must have `newctx` and `freectx`, getters and setters of its
//!   parameters in pairs, an init function, and for each init the functions it needs; failures
//!   are `EVP_R_INVALID_PROVIDER_FUNCTIONS` with OpenSSL's text.
//! - Without an algorithm given, the init fetches the one the key manager names for signing
//!   (from the context's library context, then from the key manager's provider), and the key is
//!   exported to that provider's key manager. With one given, it must suit the key's type.
//! - The operations fail with `EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED` where the algorithm lacks
//!   the function, and `EVP_R_PROVIDER_SIGNATURE_FAILURE` where it fails.
//!
//! - A legacy context (an application's `EVP_PKEY_METHOD`) signs, verifies, and recovers with
//!   its method's functions, after its `*_init`; a method that sizes outputs itself
//!   (`EVP_PKEY_FLAG_AUTOARGLEN`) answers size queries and refuses short buffers with the key's
//!   size.
//!
//! Functions given a NULL method, and an algorithm given with a legacy context, fail here where
//! the reference would crash (docs/DEVIATIONS.md).

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    ERR_LIB_EVP, ERR_R_EVP_LIB, ERR_R_PASSED_NULL_PARAMETER, EVP_MD, EVP_PKEY_CTX,
    EVP_PKEY_OP_SIGN, EVP_PKEY_OP_SIGNMSG, EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_OP_UNDEFINED,
    EVP_PKEY_OP_VERIFY, EVP_PKEY_OP_VERIFYMSG, EVP_PKEY_OP_VERIFYRECOVER,
    EVP_R_COMMAND_NOT_SUPPORTED, EVP_R_INITIALIZATION_ERROR, EVP_R_INVALID_PROVIDER_FUNCTIONS,
    EVP_R_NO_KEY_SET, EVP_R_OPERATION_NOT_INITIALIZED,
    EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE, EVP_R_PROVIDER_SIGNATURE_FAILURE,
    EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED, EVP_R_SIGNATURE_TYPE_AND_KEY_TYPE_INCOMPATIBLE,
    EVP_SIGNATURE, OSSL_ALGORITHM, OSSL_FUNC_SIGNATURE_DIGEST_SIGN,
    OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
    OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,
    OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
    OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, OSSL_FUNC_SIGNATURE_DUPCTX,
    OSSL_FUNC_SIGNATURE_FREECTX, OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
    OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
    OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, OSSL_FUNC_SIGNATURE_NEWCTX,
    OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES, OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
    OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
    OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, OSSL_FUNC_SIGNATURE_SIGN,
    OSSL_FUNC_SIGNATURE_SIGN_INIT, OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL,
    OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT, OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE,
    OSSL_FUNC_SIGNATURE_VERIFY, OSSL_FUNC_SIGNATURE_VERIFY_INIT,
    OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL, OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,
    OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE, OSSL_FUNC_SIGNATURE_VERIFY_RECOVER,
    OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT, OSSL_LIB_CTX, OSSL_OP_SIGNATURE, OSSL_PARAM,
    OSSL_PROVIDER, OSSL_SIGNATURE_PARAM_DIGEST, OSSL_SIGNATURE_PARAM_SIGNATURE,
};

use super::fetch::{self, Kind};
use super::keymgmt;
use super::pkey::{self, KeyData, PkeyRef};
use super::pkey_ctx::{self, EVP_PKEY_CTX_get_params, EVP_PKEY_CTX_set_params, PkeyCtx};
use super::pmeth;
use crate::err::{self, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::params::{OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_utf8_string, end};
use crate::provider::Ptr;

type AnyFn = unsafe extern "C" fn();
type NewCtxFn = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
type InitFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *const OSSL_PARAM) -> c_int;
type SignFn =
    unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, usize, *const u8, usize) -> c_int;
type UpdateFn = unsafe extern "C" fn(*mut c_void, *const u8, usize) -> c_int;
type SignFinalFn = unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, usize) -> c_int;
type VerifyFn = unsafe extern "C" fn(*mut c_void, *const u8, usize, *const u8, usize) -> c_int;
type VerifyMessageFinalFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type DigestInitFn =
    unsafe extern "C" fn(*mut c_void, *const c_char, *mut c_void, *const OSSL_PARAM) -> c_int;
type DigestVerifyFinalFn = unsafe extern "C" fn(*mut c_void, *const u8, usize) -> c_int;
type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
type DupCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type GetParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
type SetParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type ListFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;
type MdListFn = unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM;
type KeyTypesFn = unsafe extern "C" fn() -> *const *const c_char;

/// A signature algorithm's functions, as its dispatch table gave them.
#[derive(Default, Clone, Copy)]
pub(crate) struct Funcs {
    newctx: Option<NewCtxFn>,
    sign_init: Option<InitFn>,
    sign: Option<SignFn>,
    sign_message_init: Option<InitFn>,
    sign_message_update: Option<UpdateFn>,
    sign_message_final: Option<SignFinalFn>,
    verify_init: Option<InitFn>,
    verify: Option<VerifyFn>,
    verify_message_init: Option<InitFn>,
    verify_message_update: Option<UpdateFn>,
    verify_message_final: Option<VerifyMessageFinalFn>,
    verify_recover_init: Option<InitFn>,
    verify_recover: Option<SignFn>,
    pub(crate) digest_sign_init: Option<DigestInitFn>,
    pub(crate) digest_sign_update: Option<UpdateFn>,
    pub(crate) digest_sign_final: Option<SignFinalFn>,
    pub(crate) digest_sign: Option<SignFn>,
    pub(crate) digest_verify_init: Option<DigestInitFn>,
    pub(crate) digest_verify_update: Option<UpdateFn>,
    pub(crate) digest_verify_final: Option<DigestVerifyFinalFn>,
    pub(crate) digest_verify: Option<VerifyFn>,
    freectx: Option<FreeCtxFn>,
    dupctx: Option<DupCtxFn>,
    get_ctx_params: Option<GetParamsFn>,
    gettable_ctx_params: Option<ListFn>,
    set_ctx_params: Option<SetParamsFn>,
    settable_ctx_params: Option<ListFn>,
    pub(crate) get_ctx_md_params: Option<GetParamsFn>,
    pub(crate) gettable_ctx_md_params: Option<MdListFn>,
    pub(crate) set_ctx_md_params: Option<SetParamsFn>,
    pub(crate) settable_ctx_md_params: Option<MdListFn>,
    query_key_types: Option<KeyTypesFn>,
}

/// A signature algorithm (`EVP_SIGNATURE`).
pub(crate) struct Signature {
    name_id: u32,
    type_name: CString,
    /// The provider's description, a static string of its, or NULL.
    description: Ptr<c_char>,
    /// The provider, with a reference.
    prov: Ptr<OSSL_PROVIDER>,
    pub(crate) funcs: Funcs,
}

handle_type!(EVP_SIGNATURE => Signature);

impl Drop for Signature {
    fn drop(&mut self) {
        // SAFETY: the provider reference the method holds.
        unsafe { OSSL_PROVIDER::free(self.prov.0) };
    }
}

impl Signature {
    /// The provider's context, which the provider functions take.
    pub(crate) fn provider_ctx(&self) -> *mut c_void {
        // SAFETY: the method holds a reference to its live provider.
        unsafe { crate::provider::OSSL_PROVIDER_get0_provider_ctx(self.prov.0) }
    }

    /// The provider.
    pub(crate) fn prov(&self) -> *mut OSSL_PROVIDER {
        self.prov.0
    }

    /// `EVP_SIGNATURE_is_a`.
    fn is_a(&self, name: &[u8]) -> bool {
        fetch::number_in(self.prov.0, name) == self.name_id
    }

    /// The text OpenSSL's errors name a function with: `"<name> <what>:<description>"`.
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

    /// Raises `reason` with the text naming `what`.
    pub(crate) fn raise(&self, reason: c_int, function: &str, what: &str) {
        err::raise_with_text(ERR_LIB_EVP, reason, function, &self.text(what));
    }

    /// `newctx`: a new algorithm context, or NULL.
    pub(crate) fn newctx(&self, propq: Option<&CStr>) -> *mut c_void {
        let q = propq.map_or(ptr::null(), CStr::as_ptr);
        match self.funcs.newctx {
            // SAFETY: the provider's function with its context and the query.
            Some(f) => unsafe { f(self.provider_ctx(), q) },
            None => ptr::null_mut(),
        }
    }

    /// `freectx`.
    ///
    /// # Safety
    /// `algctx` is a context of this algorithm, not used afterwards.
    pub(crate) unsafe fn freectx(&self, algctx: *mut c_void) {
        if let Some(f) = self.funcs.freectx {
            // SAFETY: the caller's guarantee.
            unsafe { f(algctx) };
        }
    }

    /// `dupctx`, or NULL without it.
    ///
    /// # Safety
    /// `algctx` is a context of this algorithm.
    pub(crate) unsafe fn dupctx(&self, algctx: *mut c_void) -> *mut c_void {
        match self.funcs.dupctx {
            // SAFETY: the caller's guarantee.
            Some(f) => unsafe { f(algctx) },
            None => ptr::null_mut(),
        }
    }

    /// `set_ctx_params`, if it has one.
    ///
    /// # Safety
    /// `algctx` is a context of this algorithm; `params` NULL or an array.
    pub(crate) unsafe fn set_ctx_params(
        &self,
        algctx: *mut c_void,
        params: *const OSSL_PARAM,
    ) -> Option<c_int> {
        // SAFETY: the caller's guarantee.
        self.funcs
            .set_ctx_params
            .map(|f| unsafe { f(algctx, params) })
    }

    /// `get_ctx_params`, if it has one.
    ///
    /// # Safety
    /// `algctx` is a context of this algorithm; `params` NULL or an array.
    pub(crate) unsafe fn get_ctx_params(
        &self,
        algctx: *mut c_void,
        params: *mut OSSL_PARAM,
    ) -> Option<c_int> {
        // SAFETY: the caller's guarantee.
        self.funcs
            .get_ctx_params
            .map(|f| unsafe { f(algctx, params) })
    }

    /// `gettable_ctx_params` for `algctx` (NULL for the method's), if it has one.
    ///
    /// # Safety
    /// `algctx` is NULL or a context of this algorithm.
    pub(crate) unsafe fn gettable_ctx_params(
        &self,
        algctx: *mut c_void,
    ) -> Option<*const OSSL_PARAM> {
        // SAFETY: the caller's guarantee.
        self.funcs
            .gettable_ctx_params
            .map(|f| unsafe { f(algctx, self.provider_ctx()) })
    }

    /// `settable_ctx_params` for `algctx` (NULL for the method's), if it has one.
    ///
    /// # Safety
    /// `algctx` is NULL or a context of this algorithm.
    pub(crate) unsafe fn settable_ctx_params(
        &self,
        algctx: *mut c_void,
    ) -> Option<*const OSSL_PARAM> {
        // SAFETY: the caller's guarantee.
        self.funcs
            .settable_ctx_params
            .map(|f| unsafe { f(algctx, self.provider_ctx()) })
    }
}

/// A dispatch table's function as the type its id stands for.
///
/// # Safety
/// `F` is the function pointer type `f` really has.
unsafe fn cast<F: Copy>(f: AnyFn) -> F {
    // SAFETY: the caller's guarantee; function pointers all have one size.
    unsafe { core::mem::transmute_copy(&f) }
}

/// `evp_signature_from_algorithm`: a signature algorithm from the provider's, with one
/// reference, or NULL with an error.
///
/// # Safety
/// `algo`'s names, description, and table are the provider's, valid while it lives; `prov` is
/// a live provider.
unsafe fn from_algorithm(
    name_id: u32,
    algo: &OSSL_ALGORITHM,
    prov: *mut OSSL_PROVIDER,
) -> *mut c_void {
    const F: &str = "evp_signature_from_algorithm";
    // SAFETY: the caller's guarantee.
    let names = unsafe { CStr::from_ptr(algo.algorithm_names) }.to_bytes();
    let first = names.split(|&c| c == b':').next().unwrap_or(names);
    let Ok(type_name) = CString::new(first) else {
        err::raise(ERR_LIB_EVP, ERR_R_EVP_LIB, F);
        return ptr::null_mut();
    };
    let mut f = Funcs::default();
    let (mut ctxfn, mut initfn, mut gparam, mut sparam, mut gmdparam, mut smdparam) =
        (0, 0, 0, 0, 0, 0);
    let mut at = algo.implementation;
    // SAFETY: the caller's guarantee: the table is ended by a zero id.
    while let Some(d) = unsafe { at.as_ref() } {
        if d.function_id == 0 {
            break;
        }
        at = at.wrapping_add(1);
        let Some(func) = d.function else { continue };
        /// Stores `func` as the function its id stands for, the first of each id only;
        /// evaluates to whether it was stored.
        macro_rules! set {
            ($field:ident) => {{
                let fresh = f.$field.is_none();
                if fresh {
                    // SAFETY: the provider's guarantee of the function type for this id.
                    f.$field = Some(unsafe { cast(func) });
                }
                fresh
            }};
        }
        let count = |n: &mut i32, fresh: bool| {
            if fresh {
                *n += 1;
            }
        };
        match d.function_id {
            OSSL_FUNC_SIGNATURE_NEWCTX => count(&mut ctxfn, set!(newctx)),
            OSSL_FUNC_SIGNATURE_SIGN_INIT => count(&mut initfn, set!(sign_init)),
            OSSL_FUNC_SIGNATURE_SIGN => _ = set!(sign),
            OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT => count(&mut initfn, set!(sign_message_init)),
            OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE => _ = set!(sign_message_update),
            OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL => _ = set!(sign_message_final),
            OSSL_FUNC_SIGNATURE_VERIFY_INIT => count(&mut initfn, set!(verify_init)),
            OSSL_FUNC_SIGNATURE_VERIFY => _ = set!(verify),
            OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT => {
                count(&mut initfn, set!(verify_message_init))
            }
            OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE => _ = set!(verify_message_update),
            OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL => _ = set!(verify_message_final),
            OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT => {
                count(&mut initfn, set!(verify_recover_init))
            }
            OSSL_FUNC_SIGNATURE_VERIFY_RECOVER => _ = set!(verify_recover),
            OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT => count(&mut initfn, set!(digest_sign_init)),
            OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE => _ = set!(digest_sign_update),
            OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL => _ = set!(digest_sign_final),
            OSSL_FUNC_SIGNATURE_DIGEST_SIGN => _ = set!(digest_sign),
            OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT => count(&mut initfn, set!(digest_verify_init)),
            OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE => _ = set!(digest_verify_update),
            OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL => _ = set!(digest_verify_final),
            OSSL_FUNC_SIGNATURE_DIGEST_VERIFY => _ = set!(digest_verify),
            OSSL_FUNC_SIGNATURE_FREECTX => count(&mut ctxfn, set!(freectx)),
            OSSL_FUNC_SIGNATURE_DUPCTX => _ = set!(dupctx),
            OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS => count(&mut gparam, set!(get_ctx_params)),
            OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS => {
                count(&mut gparam, set!(gettable_ctx_params))
            }
            OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS => count(&mut sparam, set!(set_ctx_params)),
            OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS => {
                count(&mut sparam, set!(settable_ctx_params))
            }
            OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS => count(&mut gmdparam, set!(get_ctx_md_params)),
            OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS => {
                count(&mut gmdparam, set!(gettable_ctx_md_params))
            }
            OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS => count(&mut smdparam, set!(set_ctx_md_params)),
            OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS => {
                count(&mut smdparam, set!(settable_ctx_md_params))
            }
            OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES => _ = set!(query_key_types),
            _ => {}
        }
    }
    let name = type_name.to_string_lossy().into_owned();
    let desc = if algo.algorithm_description.is_null() {
        String::new()
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { CStr::from_ptr(algo.algorithm_description) }
            .to_string_lossy()
            .into_owned()
    };
    let fail = |what: &str| {
        err::raise_with_text(
            ERR_LIB_EVP,
            EVP_R_INVALID_PROVIDER_FUNCTIONS,
            F,
            &format!("{what}:{desc}"),
        );
        ptr::null_mut()
    };
    let pair = |n: i32| n == 0 || n == 2;
    if ctxfn != 2 {
        return fail(&format!("missing {name} newctx or freectx"));
    }
    if !pair(gparam) || !pair(sparam) || !pair(gmdparam) || !pair(smdparam) {
        return fail(&format!("missing {name} params getter or setter"));
    }
    if initfn == 0 {
        return fail(&format!("missing {name} init"));
    }
    if (f.sign_init.is_some() && f.sign.is_none())
        || (f.sign_message_init.is_some()
            && f.sign.is_none()
            && (f.sign_message_update.is_none() || f.sign_message_final.is_none()))
    {
        return fail(&format!("missing {name} signing function"));
    }
    if (f.sign.is_some() || f.sign_message_update.is_some() || f.sign_message_final.is_some())
        && f.sign_init.is_none()
        && f.sign_message_init.is_none()
    {
        return fail(&format!("missing {name} sign_init or sign_message_init"));
    }
    if (f.verify_init.is_some() && f.verify.is_none())
        || (f.verify_message_init.is_some()
            && f.verify.is_none()
            && (f.verify_message_update.is_none() || f.verify_message_final.is_none()))
    {
        return fail(&format!("missing {name} verification function"));
    }
    if (f.verify.is_some() || f.verify_message_update.is_some() || f.verify_message_final.is_some())
        && f.verify_init.is_none()
        && f.verify_message_init.is_none()
    {
        return fail(&format!(
            "missing {name} verify_init or verify_message_init"
        ));
    }
    if f.verify_recover_init.is_some() && f.verify_recover.is_none() {
        return fail(&format!("missing {name} verify_recover"));
    }
    if f.digest_sign_init.is_some()
        && f.digest_sign.is_none()
        && (f.digest_sign_update.is_none() || f.digest_sign_final.is_none())
    {
        return fail(&format!("missing {name} digest_sign function"));
    }
    if f.digest_verify_init.is_some()
        && f.digest_verify.is_none()
        && (f.digest_verify_update.is_none() || f.digest_verify_final.is_none())
    {
        return fail(&format!("missing {name} digest_verify function"));
    }
    if (f.digest_sign.is_some() || f.digest_sign_update.is_some() || f.digest_sign_final.is_some())
        && f.digest_sign_init.is_none()
    {
        return fail(&format!("missing {name} digest_sign_init"));
    }
    if (f.digest_verify.is_some()
        || f.digest_verify_update.is_some()
        || f.digest_verify_final.is_some())
        && f.digest_verify_init.is_none()
    {
        return fail(&format!("missing {name} digest_verify_init"));
    }
    if f.sign_message_update.is_none() != f.sign_message_final.is_none() {
        return fail(&format!(
            "only one of {name} message signing update and final available"
        ));
    }
    if f.verify_message_update.is_none() != f.verify_message_final.is_none() {
        return fail(&format!(
            "only one of {name} message verification update and final available"
        ));
    }
    if f.digest_sign_update.is_none() != f.digest_sign_final.is_none() {
        return fail(&format!(
            "only one of {name} digest signing update and final available"
        ));
    }
    if f.digest_verify_update.is_none() != f.digest_verify_final.is_none() {
        return fail(&format!(
            "only one of {name} digest verification update and final available"
        ));
    }
    // SAFETY: the caller's live provider; the method holds the reference.
    if !unsafe { OSSL_PROVIDER::up_ref(prov) } {
        err::raise(ERR_LIB_EVP, ERR_R_EVP_LIB, F);
        return ptr::null_mut();
    }
    EVP_SIGNATURE::new_handle(Signature {
        name_id,
        type_name,
        description: Ptr(algo.algorithm_description.cast_mut()),
        prov: Ptr(prov),
        funcs: f,
    })
    .cast()
}

/// Adds a reference to a signature algorithm in a store.
unsafe fn up_ref(m: *mut c_void) {
    // SAFETY: a live method.
    unsafe { EVP_SIGNATURE::up_ref(m.cast()) };
}

/// Drops a reference to a signature algorithm in a store.
unsafe fn free(m: *mut c_void) {
    // SAFETY: a reference the store held.
    unsafe { EVP_SIGNATURE::free(m.cast()) };
}

/// Signature algorithms to fetching.
static SIGNATURES: Kind = Kind {
    operation: OSSL_OP_SIGNATURE,
    style: crate::evp::fetch::Style::Evp,
    from_algorithm,
    up_ref,
    free,
};

/// A reference to a signature algorithm, given up when dropped.
pub(crate) struct Ref(Ptr<EVP_SIGNATURE>);

impl Ref {
    /// Takes over a reference the caller holds; `None` for NULL.
    ///
    /// # Safety
    /// `m` is NULL or a live algorithm whose reference the caller gives up.
    pub(crate) unsafe fn adopt(m: *mut EVP_SIGNATURE) -> Option<Self> {
        // SAFETY: the caller's guarantee.
        unsafe { method(m) }.map(|_| Self(Ptr(m)))
    }

    /// A new reference to a live algorithm.
    ///
    /// # Safety
    /// `m` is NULL or a live algorithm.
    pub(crate) unsafe fn new(m: *mut EVP_SIGNATURE) -> Option<Self> {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_SIGNATURE::up_ref(m) }.then_some(Self(Ptr(m)))
    }

    /// The algorithm.
    pub(crate) fn get(&self) -> &Signature {
        // SAFETY: this holds a reference to a live algorithm (checked when made).
        match unsafe { method(self.0.0) } {
            Some(m) => m,
            None => crate::ffi::die("a held EVP_SIGNATURE is live"),
        }
    }
}

impl Clone for Ref {
    fn clone(&self) -> Self {
        // SAFETY: the method is live (this holds a reference).
        unsafe { EVP_SIGNATURE::up_ref(self.0.0) };
        Self(self.0)
    }
}

impl Drop for Ref {
    fn drop(&mut self) {
        // SAFETY: the reference this holds, given up.
        unsafe { EVP_SIGNATURE::free(self.0.0) };
    }
}

/// The algorithm behind `signature`, or `None` for NULL.
///
/// # Safety
/// `signature` is NULL or a live signature algorithm.
unsafe fn method<'a>(signature: *const EVP_SIGNATURE) -> Option<&'a Signature> {
    // SAFETY: the caller's guarantee.
    unsafe { EVP_SIGNATURE::get(signature) }
}

/// `EVP_SIGNATURE_fetch` for the context code: the algorithm `name`, or `None` with the fetch's
/// error.
///
/// # Safety
/// `libctx` is NULL or a live library context.
pub(crate) unsafe fn fetch_by_name(
    libctx: *mut OSSL_LIB_CTX,
    name: &CStr,
    properties: Option<&CStr>,
) -> Option<Ref> {
    // SAFETY: the caller's guarantee.
    let m = unsafe { fetch::fetch(libctx, &SIGNATURES, Some(name), properties) };
    // SAFETY: a new reference, given to the `Ref`.
    unsafe { Ref::adopt(m.cast()) }
}

/// `evp_signature_fetch_from_prov`.
///
/// # Safety
/// `prov` is a live provider.
unsafe fn fetch_from_prov(
    prov: *mut OSSL_PROVIDER,
    name: &CStr,
    properties: Option<&CStr>,
) -> Option<Ref> {
    // SAFETY: the caller's guarantee.
    let m = unsafe { fetch::fetch_from_prov(prov, &SIGNATURES, Some(name), properties) };
    // SAFETY: a new reference, given to the `Ref`.
    unsafe { Ref::adopt(m.cast()) }
}

/// A C string argument, `None` for NULL.
///
/// # Safety
/// `s` is NULL or a string.
unsafe fn text<'a>(s: *const c_char) -> Option<&'a CStr> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) })
}

/// What finding a signature algorithm for a key gives: the algorithm, the key manager of its
/// provider, and the key's data there.
pub(crate) struct Chosen {
    pub(crate) signature: Ref,
    pub(crate) keymgmt: Option<keymgmt::Ref>,
    pub(crate) keydata: std::sync::Arc<KeyData>,
}

/// Why [`choose`] found nothing.
pub(crate) enum NotChosen {
    /// The key manager's provider has no such algorithm: OpenSSL goes to its legacy path.
    Legacy,
    /// No algorithm found takes the key.
    Exhausted,
}

/// The loop `evp_pkey_signature_init` and `do_sigver_init` share: the signature algorithm the
/// key manager names for signing, fetched from `libctx` then from the key manager's provider,
/// with the key exported to that provider's key manager. Raises nothing itself.
///
/// # Safety
/// `libctx` is NULL or a live library context.
pub(crate) unsafe fn choose(
    libctx: *mut OSSL_LIB_CTX,
    ctx_keymgmt: &keymgmt::Ref,
    pkey: &PkeyRef,
    propq: Option<&CStr>,
    supported_sig: &CStr,
) -> Result<Chosen, NotChosen> {
    for iter in 1..3 {
        let signature = if iter == 1 {
            // SAFETY: the caller's guarantee.
            unsafe { fetch_by_name(libctx, supported_sig, propq) }
        } else {
            let prov = ctx_keymgmt.get().prov.0;
            // SAFETY: the key manager's live provider.
            let s = unsafe { fetch_from_prov(prov, supported_sig, propq) };
            Some(s.ok_or(NotChosen::Legacy)?)
        };
        let Some(signature) = signature else { continue };
        // The key, exported to the key manager of the algorithm's provider.
        let prov = signature.get().prov();
        // SAFETY: the algorithm's live provider.
        let km = unsafe { keymgmt::fetch_from_prov(prov, ctx_keymgmt.get().name(), propq) };
        if let Some(km) = km {
            // SAFETY: the caller's guarantee.
            if let Some((km, kd)) = unsafe { pkey::export_to_any(pkey, libctx, Some(km), propq) } {
                return Ok(Chosen {
                    signature,
                    keymgmt: Some(km),
                    keydata: kd,
                });
            }
        }
    }
    Err(NotChosen::Exhausted)
}

/// `evp_pkey_signature_init`: starts a signature operation with `signature` (or the one the
/// key's type names). 1, or <= 0 with an error.
///
/// # Safety
/// `ctx` is NULL or a live context; `signature` is NULL or a live algorithm; `params` is NULL or
/// an array.
unsafe fn signature_init(
    ctx: *mut EVP_PKEY_CTX,
    signature: *mut EVP_SIGNATURE,
    operation: c_int,
    params: *const OSSL_PARAM,
) -> c_int {
    const F: &str = "evp_pkey_signature_init";
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { pkey_ctx::context(ctx) }) else {
        err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, F);
        return -1;
    };
    let (libctx, keymgmt, pkey, propq) = {
        let mut s = c.lock();
        s.free_old_ops();
        s.operation = operation;
        (
            s.libctx.0,
            s.keymgmt.clone(),
            s.pkey.clone(),
            s.propquery.clone(),
        )
    };
    let fail = |ret: c_int| {
        let mut s = c.lock();
        s.free_old_ops();
        s.operation = EVP_PKEY_OP_UNDEFINED;
        ret
    };
    // SAFETY: the caller's guarantee.
    let given = unsafe { Ref::new(signature) };
    let chosen = if let Some(sig) = given {
        let Some(pkey) = pkey else {
            err::raise(ERR_LIB_EVP, EVP_R_NO_KEY_SET, F);
            return fail(0);
        };
        let Some(ctx_km) = keymgmt else {
            // A legacy context can't take an algorithm (the reference reads the missing key
            // manager's name; docs/DEVIATIONS.md).
            err::raise(
                ERR_LIB_EVP,
                EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
                F,
            );
            return fail(-2);
        };
        let prov = sig.get().prov();
        // SAFETY: the algorithm's live provider.
        let km = unsafe { keymgmt::fetch_from_prov(prov, ctx_km.get().name(), propq.as_deref()) };
        // SAFETY: the context's library context.
        let exported = km.and_then(|km| unsafe {
            pkey::export_to_any(&pkey, libctx, Some(km), propq.as_deref())
        });
        let Some((km, kd)) = exported else {
            // OpenSSL ends here without restoring the context.
            return 0;
        };
        // The algorithm must suit the key's type.
        let ok = match sig.get().funcs.query_key_types {
            Some(q) => {
                // SAFETY: the provider's function: a NULL-ended array of strings.
                let mut at = unsafe { q() };
                let mut found = false;
                // SAFETY: as above.
                while let Some(&t) = unsafe { at.as_ref() } {
                    if t.is_null() {
                        break;
                    }
                    // SAFETY: the provider's string.
                    let n = unsafe { CStr::from_ptr(t) };
                    if ctx_km.get().is_a(n.to_bytes()) {
                        found = true;
                        break;
                    }
                    at = at.wrapping_add(1);
                }
                found
            }
            None => {
                sig.get().is_a(ctx_km.get().name().to_bytes())
                    || sig.get().is_a(
                        ctx_km
                            .get()
                            .query_operation_name(OSSL_OP_SIGNATURE)
                            .to_bytes(),
                    )
            }
        };
        if !ok {
            err::raise(
                ERR_LIB_EVP,
                EVP_R_SIGNATURE_TYPE_AND_KEY_TYPE_INCOMPATIBLE,
                F,
            );
            // OpenSSL ends here without restoring the context.
            return -2;
        }
        Chosen {
            signature: sig,
            keymgmt: Some(km),
            keydata: kd,
        }
    } else {
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        let Some(ctx_km) = keymgmt else {
            // SAFETY: the mark set above.
            unsafe { ERR_pop_to_mark() };
            // SAFETY: the caller's live context.
            return unsafe { legacy_init(ctx, c, operation) };
        };
        let Some(pkey) = pkey else {
            // SAFETY: the mark set above.
            unsafe { ERR_clear_last_mark() };
            err::raise(ERR_LIB_EVP, EVP_R_NO_KEY_SET, F);
            return fail(0);
        };
        let supported = ctx_km.get().query_operation_name(OSSL_OP_SIGNATURE);
        // SAFETY: the context's library context.
        let Ok(chosen) = (unsafe { choose(libctx, &ctx_km, &pkey, propq.as_deref(), &supported) })
        else {
            // `legacy`: without an EVP_PKEY_METHOD, not supported.
            // SAFETY: the mark set above.
            unsafe { ERR_pop_to_mark() };
            err::raise(
                ERR_LIB_EVP,
                EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
                F,
            );
            // OpenSSL returns here without restoring the context.
            return -2;
        };
        // SAFETY: as above.
        unsafe { ERR_pop_to_mark() };
        chosen
    };
    let sig = chosen.signature;
    let algctx = sig.get().newctx(propq.as_deref());
    {
        let mut s = c.lock();
        s.signature = Some(sig.clone());
        s.sigctx = Ptr(algctx);
    }
    if algctx.is_null() {
        err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
        return fail(0);
    }
    let m = sig.get();
    let (init, what) = match operation {
        EVP_PKEY_OP_SIGN => (m.funcs.sign_init, "sign_init"),
        EVP_PKEY_OP_SIGNMSG => (m.funcs.sign_message_init, "sign_message_init"),
        EVP_PKEY_OP_VERIFY => (m.funcs.verify_init, "verify_init"),
        EVP_PKEY_OP_VERIFYMSG => (m.funcs.verify_message_init, "verify_message_init"),
        EVP_PKEY_OP_VERIFYRECOVER => (m.funcs.verify_recover_init, "verify_recover_init"),
        _ => {
            err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
            return fail(0);
        }
    };
    let Some(init) = init else {
        m.raise(EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED, F, what);
        return fail(-2);
    };
    // SAFETY: the provider's function with its context, the key data, and the caller's array.
    let ret = unsafe { init(algctx, chosen.keydata.ptr(), params) };
    if ret <= 0 {
        let mut s = c.lock();
        // SAFETY: the context made above, freed once.
        unsafe { m.freectx(algctx) };
        s.sigctx = Ptr(ptr::null_mut());
        drop(s);
        return fail(ret);
    }
    // The key data stays alive with the key (or its operation cache), as in OpenSSL.
    drop(chosen.keymgmt);
    // `end`: the distinguishing ID kept for the operation goes to it.
    // SAFETY: the caller's live context.
    unsafe { super::ctrl::use_cached_data(ctx) }
}

/// `evp_pkey_signature_init`'s `legacy`: the context's method starts the operation (its
/// `*_init`, if it has one, then the kept distinguishing ID). -2 with an error without the
/// operation's function.
///
/// # Safety
/// `ctx` is the live context behind `c`.
unsafe fn legacy_init(ctx: *mut EVP_PKEY_CTX, c: &PkeyCtx, operation: c_int) -> c_int {
    const F: &str = "evp_pkey_signature_init";
    let f = c.lock().pmeth_funcs().filter(|f| match operation {
        EVP_PKEY_OP_SIGN => f.sign.is_some(),
        EVP_PKEY_OP_VERIFY => f.verify.is_some(),
        EVP_PKEY_OP_VERIFYRECOVER => f.verify_recover.is_some(),
        _ => true,
    });
    let Some(f) = f else {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
            F,
        );
        // OpenSSL returns here without restoring the context.
        return -2;
    };
    let fail = |ret: c_int| {
        let mut s = c.lock();
        s.free_old_ops();
        s.operation = EVP_PKEY_OP_UNDEFINED;
        ret
    };
    let init = match operation {
        EVP_PKEY_OP_SIGN => f.sign_init,
        EVP_PKEY_OP_VERIFY => f.verify_init,
        EVP_PKEY_OP_VERIFYRECOVER => f.verify_recover_init,
        // The message operations have no legacy form.
        _ => {
            err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
            return fail(0);
        }
    };
    // Without one, OpenSSL returns before giving the operation the kept ID.
    let Some(init) = init else { return 1 };
    // SAFETY: the method's function with the caller's context.
    let ret = unsafe { init(ctx) };
    if ret <= 0 {
        return fail(ret);
    }
    // SAFETY: the caller's guarantee.
    unsafe { super::ctrl::use_cached_data(ctx) }
}

/// A signature operation: a provider's algorithm and its context, or a legacy context's
/// method.
enum Op {
    Provided(Ref, *mut c_void),
    Legacy(pmeth::Ref),
}

/// The context's signature operation, if `operation` is one of `ops`: the algorithm and its
/// context, or a legacy context's method. Otherwise the C function's error and return value:
/// -2 without either. (The message functions, which have no legacy form, read the missing
/// algorithm there and crash; they fail the same way here, docs/DEVIATIONS.md.)
///
/// # Safety
/// `ctx` is NULL or a live context.
unsafe fn sig_op(ctx: *mut EVP_PKEY_CTX, ops: &[c_int], function: &str) -> Result<Op, c_int> {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { pkey_ctx::context(ctx) }) else {
        err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, function);
        return Err(-1);
    };
    let s = c.lock();
    if !ops.contains(&s.operation) {
        err::raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_INITIALIZED, function);
        return Err(-1);
    }
    match (&s.signature, s.sigctx.0, &s.pmeth) {
        (Some(sig), algctx, _) if !algctx.is_null() => Ok(Op::Provided(sig.clone(), algctx)),
        (_, _, Some(m)) => Ok(Op::Legacy(m.clone())),
        _ => {
            drop(s);
            err::raise(
                ERR_LIB_EVP,
                EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
                function,
            );
            Err(-2)
        }
    }
}

/// A legacy context's method's function `f` (-2 with an error without it), after
/// `M_check_autoarg` for an output of `outlen` (if there is one).
///
/// # Safety
/// `ctx` is a live context; `outlen` is NULL or room for a size.
unsafe fn legacy_op(
    ctx: *mut EVP_PKEY_CTX,
    m: &pmeth::Ref,
    f: Option<impl FnOnce() -> c_int>,
    out: Option<(bool, *mut usize)>,
    function: &str,
) -> c_int {
    let Some(f) = f else {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
            function,
        );
        return -2;
    };
    if let Some((null, len)) = out {
        // SAFETY: the caller's guarantee.
        let pkey = unsafe { pkey_ctx::EVP_PKEY_CTX_get0_pkey(ctx) };
        // SAFETY: the context's key, or NULL; the caller's guarantee.
        if let Some(r) = unsafe { pmeth::check_autoarg(m.get(), pkey, null, len, function) } {
            return r;
        }
    }
    f()
}

/// The context's signature operation with a provider side, if `operation` is one of `ops`:
/// the algorithm and its context. Otherwise the C function's error and return value.
///
/// # Safety
/// `ctx` is NULL or a live context.
unsafe fn op_of(
    ctx: *mut EVP_PKEY_CTX,
    ops: &[c_int],
    function: &str,
) -> Result<(Ref, *mut c_void), c_int> {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { pkey_ctx::context(ctx) }) else {
        err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, function);
        return Err(-1);
    };
    let s = c.lock();
    if !ops.contains(&s.operation) {
        err::raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_INITIALIZED, function);
        return Err(-1);
    }
    match (&s.signature, s.sigctx.0) {
        (Some(sig), algctx) if !algctx.is_null() => Ok((sig.clone(), algctx)),
        _ => {
            drop(s);
            err::raise(
                ERR_LIB_EVP,
                EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
                function,
            );
            Err(-2)
        }
    }
}

macro_rules! init_export {
    ($(#[$attr:meta])* pub unsafe extern "C" fn $name:ident(ctx: *mut EVP_PKEY_CTX $(, $arg:ident: $ty:ty)*) -> c_int => $sig:expr, $op:expr, $params:expr) => {
        ffi_export! {
            $(#[$attr])*
            pub unsafe extern "C" fn $name(ctx: *mut EVP_PKEY_CTX $(, $arg: $ty)*) -> c_int
            where failure = 0, library = ERR_LIB_EVP
            {
                // SAFETY: the caller's guarantee.
                unsafe { signature_init(ctx, $sig, $op, $params) }
            }
        }
    };
}

init_export! {
    /// Starts signing with the signature algorithm the key's type names.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_sign_init(ctx: *mut EVP_PKEY_CTX) -> c_int => ptr::null_mut(), EVP_PKEY_OP_SIGN, ptr::null()
}

init_export! {
    /// Starts signing, giving the algorithm `params`.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `params` is NULL or an array.
    pub unsafe extern "C" fn EVP_PKEY_sign_init_ex(ctx: *mut EVP_PKEY_CTX, params: *const OSSL_PARAM) -> c_int => ptr::null_mut(), EVP_PKEY_OP_SIGN, params
}

init_export! {
    /// Starts signing with `algo` (or the key type's for NULL), giving it `params`.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `algo` is NULL or a live algorithm; `params` is NULL or
    /// an array.
    pub unsafe extern "C" fn EVP_PKEY_sign_init_ex2(ctx: *mut EVP_PKEY_CTX, algo: *mut EVP_SIGNATURE, params: *const OSSL_PARAM) -> c_int => algo, EVP_PKEY_OP_SIGN, params
}

init_export! {
    /// Starts signing a message in pieces with `algo` (or the key type's for NULL).
    ///
    /// # Safety
    /// As for `EVP_PKEY_sign_init_ex2`.
    pub unsafe extern "C" fn EVP_PKEY_sign_message_init(ctx: *mut EVP_PKEY_CTX, algo: *mut EVP_SIGNATURE, params: *const OSSL_PARAM) -> c_int => algo, EVP_PKEY_OP_SIGNMSG, params
}

init_export! {
    /// Starts verifying with the signature algorithm the key's type names.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_verify_init(ctx: *mut EVP_PKEY_CTX) -> c_int => ptr::null_mut(), EVP_PKEY_OP_VERIFY, ptr::null()
}

init_export! {
    /// Starts verifying, giving the algorithm `params`.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `params` is NULL or an array.
    pub unsafe extern "C" fn EVP_PKEY_verify_init_ex(ctx: *mut EVP_PKEY_CTX, params: *const OSSL_PARAM) -> c_int => ptr::null_mut(), EVP_PKEY_OP_VERIFY, params
}

init_export! {
    /// Starts verifying with `algo` (or the key type's for NULL), giving it `params`.
    ///
    /// # Safety
    /// As for `EVP_PKEY_sign_init_ex2`.
    pub unsafe extern "C" fn EVP_PKEY_verify_init_ex2(ctx: *mut EVP_PKEY_CTX, algo: *mut EVP_SIGNATURE, params: *const OSSL_PARAM) -> c_int => algo, EVP_PKEY_OP_VERIFY, params
}

init_export! {
    /// Starts verifying a message in pieces with `algo` (or the key type's for NULL).
    ///
    /// # Safety
    /// As for `EVP_PKEY_sign_init_ex2`.
    pub unsafe extern "C" fn EVP_PKEY_verify_message_init(ctx: *mut EVP_PKEY_CTX, algo: *mut EVP_SIGNATURE, params: *const OSSL_PARAM) -> c_int => algo, EVP_PKEY_OP_VERIFYMSG, params
}

init_export! {
    /// Starts recovering signed data with the signature algorithm the key's type names.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_verify_recover_init(ctx: *mut EVP_PKEY_CTX) -> c_int => ptr::null_mut(), EVP_PKEY_OP_VERIFYRECOVER, ptr::null()
}

init_export! {
    /// Starts recovering signed data, giving the algorithm `params`.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `params` is NULL or an array.
    pub unsafe extern "C" fn EVP_PKEY_verify_recover_init_ex(ctx: *mut EVP_PKEY_CTX, params: *const OSSL_PARAM) -> c_int => ptr::null_mut(), EVP_PKEY_OP_VERIFYRECOVER, params
}

init_export! {
    /// Starts recovering signed data with `algo` (or the key type's for NULL).
    ///
    /// # Safety
    /// As for `EVP_PKEY_sign_init_ex2`.
    pub unsafe extern "C" fn EVP_PKEY_verify_recover_init_ex2(ctx: *mut EVP_PKEY_CTX, algo: *mut EVP_SIGNATURE, params: *const OSSL_PARAM) -> c_int => algo, EVP_PKEY_OP_VERIFYRECOVER, params
}

/// Runs a provider function `f` of the operation, raising OpenSSL's errors around it.
fn run(sig: &Signature, f: Option<impl FnOnce() -> c_int>, function: &str, what: &str) -> c_int {
    let Some(f) = f else {
        sig.raise(EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED, function, what);
        return -2;
    };
    let ret = f();
    if ret <= 0 {
        sig.raise(EVP_R_PROVIDER_SIGNATURE_FAILURE, function, what);
    }
    ret
}

/// The size a caller's buffer has: `*len` for a buffer, 0 without one.
///
/// # Safety
/// `len` is NULL or valid for a read when `buf` isn't NULL.
unsafe fn room(buf: *const u8, len: *const usize) -> usize {
    if buf.is_null() || len.is_null() {
        0
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { len.read() }
    }
}

ffi_export! {
    /// Signs `tbslen` octets at `tbs` into `sig` (its room in `*siglen`, the length back); with a
    /// NULL `sig`, the size a signature needs. 1, or <= 0 with an error.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `sig` is NULL or has room for `*siglen` octets;
    /// `siglen` is room for a size; `tbs` holds `tbslen` octets.
    pub unsafe extern "C" fn EVP_PKEY_sign(ctx: *mut EVP_PKEY_CTX, sig: *mut u8, siglen: *mut usize, tbs: *const u8, tbslen: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "EVP_PKEY_sign";
        // SAFETY: the caller's guarantee.
        let (s, algctx) = match unsafe { sig_op(ctx, &[EVP_PKEY_OP_SIGN, EVP_PKEY_OP_SIGNMSG], F) } {
            Ok(Op::Provided(s, algctx)) => (s, algctx),
            Ok(Op::Legacy(m)) => {
                let f = m.get().funcs().sign;
                // SAFETY: the method's function with the caller's context and buffers.
                let call = f.map(|f| move || unsafe { f(ctx, sig, siglen, tbs, tbslen) });
                // SAFETY: the caller's guarantee.
                return unsafe { legacy_op(ctx, &m, call, Some((sig.is_null(), siglen)), F) };
            }
            Err(r) => return r,
        };
        let m = s.get();
        // SAFETY: the caller's guarantee.
        let size = unsafe { room(sig, siglen) };
        // SAFETY: the provider's function with its context and the caller's buffers.
        run(m, m.funcs.sign.map(|f| move || unsafe { f(algctx, sig, siglen, size, tbs, tbslen) }), "EVP_PKEY_sign", "sign")
    }
}

ffi_export! {
    /// Adds `inlen` octets at `in_` to the message being signed.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `in_` holds `inlen` octets.
    pub unsafe extern "C" fn EVP_PKEY_sign_message_update(ctx: *mut EVP_PKEY_CTX, in_: *const u8, inlen: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "EVP_PKEY_sign_message_update";
        // SAFETY: the caller's guarantee.
        let (s, algctx) = match unsafe { op_of(ctx, &[EVP_PKEY_OP_SIGNMSG], F) } {
            Ok(v) => v,
            Err(r) => return r,
        };
        let m = s.get();
        // SAFETY: the provider's function with its context and the caller's data.
        run(m, m.funcs.sign_message_update.map(|f| move || unsafe { f(algctx, in_, inlen) }), F, "sign_message_update")
    }
}

ffi_export! {
    /// Signs the message given in pieces into `sig`, as `EVP_PKEY_sign`.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `sig` is NULL or has room for `*siglen` octets;
    /// `siglen` is room for a size.
    pub unsafe extern "C" fn EVP_PKEY_sign_message_final(ctx: *mut EVP_PKEY_CTX, sig: *mut u8, siglen: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "EVP_PKEY_sign_message_final";
        // SAFETY: the caller's guarantee.
        let (s, algctx) = match unsafe { op_of(ctx, &[EVP_PKEY_OP_SIGNMSG], F) } {
            Ok(v) => v,
            Err(r) => return r,
        };
        let m = s.get();
        // SAFETY: the caller's guarantee.
        let size = unsafe { room(sig, siglen) };
        // SAFETY: the provider's function with its context and the caller's buffers.
        run(m, m.funcs.sign_message_final.map(|f| move || unsafe { f(algctx, sig, siglen, size) }), F, "sign_message_final")
    }
}

ffi_export! {
    /// Verifies the `siglen` octets at `sig` over `tbslen` octets at `tbs`: 1 if valid, <= 0
    /// otherwise.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `sig` holds `siglen` octets; `tbs` holds `tbslen`.
    pub unsafe extern "C" fn EVP_PKEY_verify(ctx: *mut EVP_PKEY_CTX, sig: *const u8, siglen: usize, tbs: *const u8, tbslen: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "EVP_PKEY_verify";
        // SAFETY: the caller's guarantee.
        let (s, algctx) = match unsafe { sig_op(ctx, &[EVP_PKEY_OP_VERIFY, EVP_PKEY_OP_VERIFYMSG], F) } {
            Ok(Op::Provided(s, algctx)) => (s, algctx),
            Ok(Op::Legacy(m)) => {
                let f = m.get().funcs().verify;
                // SAFETY: the method's function with the caller's context and buffers.
                let call = f.map(|f| move || unsafe { f(ctx, sig, siglen, tbs, tbslen) });
                // SAFETY: the caller's guarantee.
                return unsafe { legacy_op(ctx, &m, call, None, F) };
            }
            Err(r) => return r,
        };
        let m = s.get();
        // SAFETY: the provider's function with its context and the caller's buffers.
        run(m, m.funcs.verify.map(|f| move || unsafe { f(algctx, sig, siglen, tbs, tbslen) }), "EVP_PKEY_verify", "verify")
    }
}

ffi_export! {
    /// Adds `inlen` octets at `in_` to the message being verified.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `in_` holds `inlen` octets.
    pub unsafe extern "C" fn EVP_PKEY_verify_message_update(ctx: *mut EVP_PKEY_CTX, in_: *const u8, inlen: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "EVP_PKEY_verify_message_update";
        // SAFETY: the caller's guarantee.
        let (s, algctx) = match unsafe { op_of(ctx, &[EVP_PKEY_OP_VERIFYMSG], F) } {
            Ok(v) => v,
            Err(r) => return r,
        };
        let m = s.get();
        // SAFETY: the provider's function with its context and the caller's data.
        run(m, m.funcs.verify_message_update.map(|f| move || unsafe { f(algctx, in_, inlen) }), F, "verify_message_update")
    }
}

ffi_export! {
    /// Verifies the message given in pieces against the signature set with
    /// `EVP_PKEY_CTX_set_signature`.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_verify_message_final(ctx: *mut EVP_PKEY_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "EVP_PKEY_verify_message_final";
        // SAFETY: the caller's guarantee.
        let (s, algctx) = match unsafe { op_of(ctx, &[EVP_PKEY_OP_VERIFYMSG], F) } {
            Ok(v) => v,
            Err(r) => return r,
        };
        let m = s.get();
        // SAFETY: the provider's function with its context.
        run(m, m.funcs.verify_message_final.map(|f| move || unsafe { f(algctx) }), F, "verify_message_final")
    }
}

ffi_export! {
    /// Recovers the data signed in `siglen` octets at `sig` into `rout` (its room in
    /// `*routlen`, the length back); with a NULL `rout`, the size needed.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `rout` is NULL or has room for `*routlen` octets;
    /// `routlen` is room for a size; `sig` holds `siglen` octets.
    pub unsafe extern "C" fn EVP_PKEY_verify_recover(ctx: *mut EVP_PKEY_CTX, rout: *mut u8, routlen: *mut usize, sig: *const u8, siglen: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "EVP_PKEY_verify_recover";
        // SAFETY: the caller's guarantee.
        let (s, algctx) = match unsafe { sig_op(ctx, &[EVP_PKEY_OP_VERIFYRECOVER], F) } {
            Ok(Op::Provided(s, algctx)) => (s, algctx),
            Ok(Op::Legacy(m)) => {
                let f = m.get().funcs().verify_recover;
                // SAFETY: the method's function with the caller's context and buffers.
                let call = f.map(|f| move || unsafe { f(ctx, rout, routlen, sig, siglen) });
                // SAFETY: the caller's guarantee.
                return unsafe { legacy_op(ctx, &m, call, Some((rout.is_null(), routlen)), F) };
            }
            Err(r) => return r,
        };
        let m = s.get();
        // SAFETY: the caller's guarantee.
        let size = unsafe { room(rout, routlen) };
        // SAFETY: the provider's function with its context and the caller's buffers.
        run(m, m.funcs.verify_recover.map(|f| move || unsafe { f(algctx, rout, routlen, size, sig, siglen) }), F, "verify_recover")
    }
}

ffi_export! {
    /// Sets the signature `EVP_PKEY_verify_message_final` checks (`OSSL_SIGNATURE_PARAM_SIGNATURE`).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `sig` holds `siglen` octets.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_signature(ctx: *mut EVP_PKEY_CTX, sig: *const u8, siglen: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if ctx.is_null() {
            err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, "EVP_PKEY_CTX_set_signature");
            return 0;
        }
        // SAFETY: a static key; the caller's octets.
        let p = unsafe { OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_SIGNATURE.as_ptr(), sig.cast_mut().cast(), siglen) };
        let params = [p, end()];
        // SAFETY: the caller's context; the array above.
        unsafe { EVP_PKEY_CTX_set_params(ctx, params.as_ptr()) }
    }
}

ffi_export! {
    /// Sets the digest a signature operation uses (its name as `OSSL_SIGNATURE_PARAM_DIGEST`;
    /// "" for NULL). -2 with `EVP_R_COMMAND_NOT_SUPPORTED` outside a signature operation.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `md` is NULL or a live digest.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_signature_md(ctx: *mut EVP_PKEY_CTX, md: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let st = unsafe { pkey_ctx::context(ctx) }.map(|c| {
            let s = c.lock();
            (s.operation, s.sigctx.0.is_null())
        });
        let Some((_, fallback)) = st.filter(|(op, _)| op & EVP_PKEY_OP_TYPE_SIG != 0) else {
            err::raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED, "evp_pkey_ctx_set_md");
            return -2;
        };
        if fallback {
            // SAFETY: the caller's guarantee.
            return unsafe { super::ctrl::ctrl(ctx, -1, EVP_PKEY_OP_TYPE_SIG, rustyssl_abi::EVP_PKEY_CTRL_MD, 0, md.cast_mut().cast()) };
        }
        let name = if md.is_null() {
            c"".as_ptr()
        } else {
            // SAFETY: the caller's live digest.
            unsafe { super::digest::EVP_MD_get0_name(md) }
        };
        // SAFETY: a static key; the digest's name.
        let p = unsafe { OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST.as_ptr(), name.cast_mut(), 0) };
        let params = [p, end()];
        // SAFETY: the caller's context; the array above.
        unsafe { EVP_PKEY_CTX_set_params(ctx, params.as_ptr()) }
    }
}

ffi_export! {
    /// The digest a signature operation uses into `*md` (looked up by the name the algorithm
    /// reports). -2 with `EVP_R_COMMAND_NOT_SUPPORTED` outside a signature operation; 0 if it
    /// reports none known.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `md` is room for a pointer.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get_signature_md(ctx: *mut EVP_PKEY_CTX, md: *mut *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let st = unsafe { pkey_ctx::context(ctx) }.map(|c| {
            let s = c.lock();
            (s.operation, s.sigctx.0.is_null(), s.libctx.0)
        });
        let Some((_, fallback, libctx)) = st.filter(|(op, _, _)| op & EVP_PKEY_OP_TYPE_SIG != 0) else {
            err::raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED, "EVP_PKEY_CTX_get_signature_md");
            return -2;
        };
        if fallback {
            // SAFETY: the caller's guarantee.
            return unsafe { super::ctrl::ctrl(ctx, -1, EVP_PKEY_OP_TYPE_SIG, rustyssl_abi::EVP_PKEY_CTRL_GET_MD, 0, md.cast()) };
        }
        let mut name = [0 as c_char; 80];
        // SAFETY: a static key; the local buffer.
        let p = unsafe { OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST.as_ptr(), name.as_mut_ptr(), name.len()) };
        let mut params = [p, end()];
        // SAFETY: the caller's context; the array above.
        if unsafe { EVP_PKEY_CTX_get_params(ctx, params.as_mut_ptr()) } == 0 {
            return 0;
        }
        // SAFETY: the context's library context; the buffer, NUL-terminated (zeroed, and the
        // parameter leaves room for the NUL).
        let tmp = unsafe { super::legacy_md::get_digestbyname_ex(libctx, name.as_ptr()) };
        if tmp.is_null() {
            return 0;
        }
        if !md.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { md.write(tmp) };
        }
        1
    }
}

ffi_export! {
    /// The signature algorithm `algorithm` from the providers of `ctx` (the default context for
    /// NULL) that best matches `properties`, with a reference; NULL with an error if none does.
    ///
    /// # Safety
    /// `ctx` is NULL or a live library context; `algorithm` and `properties` are NULL or
    /// strings.
    pub unsafe extern "C" fn EVP_SIGNATURE_fetch(ctx: *mut OSSL_LIB_CTX, algorithm: *const c_char, properties: *const c_char) -> *mut EVP_SIGNATURE
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let name = unsafe { text(algorithm) };
        // SAFETY: as above.
        let props = unsafe { text(properties) };
        // SAFETY: the caller's guarantee.
        unsafe { fetch::fetch(ctx, &SIGNATURES, name, props) }.cast()
    }
}

ffi_export! {
    /// Adds a reference. Returns 1 (0 for NULL, where OpenSSL would crash).
    ///
    /// # Safety
    /// `signature` is NULL or a live algorithm.
    pub unsafe extern "C" fn EVP_SIGNATURE_up_ref(signature: *mut EVP_SIGNATURE) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { EVP_SIGNATURE::up_ref(signature) })
    }
}

ffi_export! {
    /// Drops a reference; NULL does nothing.
    ///
    /// # Safety
    /// `signature` is NULL or an algorithm the caller holds, not used afterwards.
    pub unsafe extern "C" fn EVP_SIGNATURE_free(signature: *mut EVP_SIGNATURE)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_SIGNATURE::free(signature) };
    }
}

ffi_export! {
    /// The provider the algorithm came from (NULL for NULL).
    ///
    /// # Safety
    /// `signature` is NULL or a live algorithm.
    pub unsafe extern "C" fn EVP_SIGNATURE_get0_provider(signature: *const EVP_SIGNATURE) -> *mut OSSL_PROVIDER
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(signature) }.map_or(ptr::null_mut(), Signature::prov)
    }
}

ffi_export! {
    /// The algorithm's first name; NULL for NULL.
    ///
    /// # Safety
    /// `signature` is NULL or a live algorithm.
    pub unsafe extern "C" fn EVP_SIGNATURE_get0_name(signature: *const EVP_SIGNATURE) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(signature) }.map_or(ptr::null(), |m| m.type_name.as_ptr())
    }
}

ffi_export! {
    /// The provider's description of the algorithm, or NULL.
    ///
    /// # Safety
    /// `signature` is NULL or a live algorithm.
    pub unsafe extern "C" fn EVP_SIGNATURE_get0_description(signature: *const EVP_SIGNATURE) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(signature) }.map_or(ptr::null(), |m| m.description.0.cast_const())
    }
}

ffi_export! {
    /// Whether `name` is one of the algorithm's names. 0 for NULL.
    ///
    /// # Safety
    /// `signature` is NULL or a live algorithm; `name` is NULL or a string.
    pub unsafe extern "C" fn EVP_SIGNATURE_is_a(signature: *const EVP_SIGNATURE, name: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(signature) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        let n = unsafe { text(name) }.map_or(&b""[..], CStr::to_bytes);
        c_int::from(m.is_a(n))
    }
}

/// A names callback.
type NameFn = unsafe extern "C" fn(*const c_char, *mut c_void);

ffi_export! {
    /// Calls `fn_` with each of the algorithm's names. Returns 1 if it has any (0 for NULL).
    ///
    /// # Safety
    /// `signature` is NULL or a live algorithm; `fn_` is a function of the documented type.
    pub unsafe extern "C" fn EVP_SIGNATURE_names_do_all(signature: *const EVP_SIGNATURE, fn_: Option<NameFn>, data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(signature) }) else { return 0 };
        let names = fetch::c_names_of(m.prov.0, m.name_id);
        for &n in &names {
            if let Some(f) = fn_ {
                // SAFETY: the caller's callback with a string the context keeps, and its data.
                unsafe { f(n, data) };
            }
        }
        c_int::from(!names.is_empty())
    }
}

/// `EVP_SIGNATURE_do_all_provided`'s callback.
type DoAllFn = unsafe extern "C" fn(*mut EVP_SIGNATURE, *mut c_void);

ffi_export! {
    /// Calls `fn_` with each signature algorithm the active providers of `libctx` offer.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `fn_` is a function of the documented type.
    pub unsafe extern "C" fn EVP_SIGNATURE_do_all_provided(libctx: *mut OSSL_LIB_CTX, fn_: Option<DoAllFn>, arg: *mut c_void)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let all = unsafe { fetch::all(libctx, &SIGNATURES) };
        for m in &all {
            if let Some(f) = fn_ {
                // SAFETY: the caller's callback with a method held for the call.
                unsafe { f(m.as_ptr().cast(), arg) };
            }
        }
    }
}

ffi_export! {
    /// The context parameters the algorithm can report (asked without a context), or NULL.
    ///
    /// # Safety
    /// `sig` is NULL or a live algorithm.
    pub unsafe extern "C" fn EVP_SIGNATURE_gettable_ctx_params(sig: *const EVP_SIGNATURE) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(sig) }) else { return ptr::null() };
        // SAFETY: no context.
        unsafe { m.gettable_ctx_params(ptr::null_mut()) }.unwrap_or(ptr::null())
    }
}

ffi_export! {
    /// The context parameters the algorithm can be given (asked without a context), or NULL.
    ///
    /// # Safety
    /// `sig` is NULL or a live algorithm.
    pub unsafe extern "C" fn EVP_SIGNATURE_settable_ctx_params(sig: *const EVP_SIGNATURE) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(sig) }) else { return ptr::null() };
        // SAFETY: no context.
        unsafe { m.settable_ctx_params(ptr::null_mut()) }.unwrap_or(ptr::null())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::pkey::raw::EVP_PKEY_new_raw_private_key_ex;
    use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_get_id};
    use crate::evp::pkey_ctx::{
        EVP_PKEY_CTX_free, EVP_PKEY_CTX_get_operation, EVP_PKEY_CTX_new_from_pkey,
    };
    use crate::libctx::{OSSL_LIB_CTX_free, OSSL_LIB_CTX_new};

    /// docs/DEVIATIONS.md: a NULL algorithm is refused (the reference crashes).
    #[test]
    fn null_methods_are_refused() {
        let m: *mut EVP_SIGNATURE = ptr::null_mut();
        // SAFETY: NULL is the case under test, here and below.
        assert_eq!(unsafe { EVP_SIGNATURE_up_ref(m) }, 0);
        // SAFETY: as above.
        assert!(unsafe { EVP_SIGNATURE_get0_name(m) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { EVP_SIGNATURE_get0_provider(m) }.is_null());
        // SAFETY: as above.
        let got = unsafe { EVP_SIGNATURE_names_do_all(m, None, ptr::null_mut()) };
        assert_eq!(got, 0);
        // SAFETY: as above.
        unsafe { EVP_SIGNATURE_free(m) };
        crate::err::take_all();
    }

    /// docs/DEVIATIONS.md: the message functions after an init that left the operation without
    /// an algorithm (one of another key type) fail (the reference reads the missing algorithm).
    #[test]
    fn message_functions_without_an_algorithm_fail() {
        // A context of its own: fetching from it loads no configuration, which Miri can't run.
        // SAFETY: no preconditions.
        let lib = unsafe { OSSL_LIB_CTX_new() };
        let key = [7u8; 16];
        // SAFETY: the context; a static name; the octets.
        let k = unsafe {
            EVP_PKEY_new_raw_private_key_ex(lib, c"HMAC".as_ptr(), ptr::null(), key.as_ptr(), 16)
        };
        // SAFETY: the key above.
        let got = unsafe { EVP_PKEY_get_id(k) };
        assert_eq!(got, rustyssl_abi::EVP_PKEY_KEYMGMT);
        // SAFETY: the context and key.
        let c = unsafe { EVP_PKEY_CTX_new_from_pkey(lib, k, ptr::null()) };
        // SAFETY: the context; a static name.
        let sip = unsafe { EVP_SIGNATURE_fetch(lib, c"SIPHASH".as_ptr(), ptr::null()) };
        // SAFETY: the context and algorithm, here and below.
        let got = unsafe { EVP_PKEY_sign_message_init(c, sip, ptr::null()) };
        assert_eq!(got, -2);
        // SAFETY: as above.
        let got = unsafe { EVP_PKEY_CTX_get_operation(c) };
        assert_eq!(got, EVP_PKEY_OP_SIGNMSG);
        // SAFETY: as above; one octet.
        let got = unsafe { EVP_PKEY_sign_message_update(c, key.as_ptr(), 1) };
        assert_eq!(got, -2);
        let mut len = 0usize;
        // SAFETY: as above.
        let got = unsafe { EVP_PKEY_sign_message_final(c, ptr::null_mut(), &raw mut len) };
        assert_eq!(got, -2);
        // SAFETY: as above.
        let got = unsafe { EVP_PKEY_verify_message_init(c, sip, ptr::null()) };
        assert_eq!(got, -2);
        // SAFETY: as above.
        let got = unsafe { EVP_PKEY_verify_message_update(c, key.as_ptr(), 1) };
        assert_eq!(got, -2);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_verify_message_final(c) }, -2);
        // SAFETY: made above.
        unsafe { EVP_SIGNATURE_free(sip) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_CTX_free(c) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(k) };
        // SAFETY: as above, its objects freed.
        unsafe { OSSL_LIB_CTX_free(lib) };
        crate::err::take_all();
    }
}
