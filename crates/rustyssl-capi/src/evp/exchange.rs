//! Key exchange (`EVP_KEYEXCH(3)`, `EVP_PKEY_derive(3)`; `exchange.c`): an `EVP_KEYEXCH` made
//! from a provider's key exchange algorithm, fetched and introspected, and the key context's
//! derivation through it.
//!
//! As in OpenSSL:
//! - An exchange must have `newctx`, `init`, `derive`, and `freectx`, and its parameter getters
//!   and setters in pairs; `set_peer` and `dupctx` are optional.
//! - The init finds the exchange the key manager names (from the context's library context,
//!   then from the key manager's provider) and exports the key to that provider's key manager.
//!   A context without a key (a KDF's) gets a blank key of its key manager's type, with empty
//!   data.
//! - Where no exchange takes the key, the init (and the operations) go to the legacy path: a
//!   legacy context's `EVP_PKEY_METHOD` derives (its `derive_init`, `derive`, and the
//!   `EVP_PKEY_CTRL_PEER_KEY` ctrl before and after the peer's checks); without one, -2 with
//!   `EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE`, leaving the operation set.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, EVP_KEYEXCH, EVP_PKEY, EVP_PKEY_CTRL_PEER_KEY,
    EVP_PKEY_CTX, EVP_PKEY_OP_DECRYPT, EVP_PKEY_OP_DERIVE, EVP_PKEY_OP_ENCRYPT,
    EVP_PKEY_OP_UNDEFINED, EVP_R_DIFFERENT_KEY_TYPES, EVP_R_DIFFERENT_PARAMETERS,
    EVP_R_INITIALIZATION_ERROR, EVP_R_NO_KEY_SET, EVP_R_OPERATION_NOT_INITIALIZED,
    EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE, OSSL_FUNC_KEYEXCH_DERIVE,
    OSSL_FUNC_KEYEXCH_DUPCTX, OSSL_FUNC_KEYEXCH_FREECTX, OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,
    OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, OSSL_FUNC_KEYEXCH_INIT, OSSL_FUNC_KEYEXCH_NEWCTX,
    OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, OSSL_FUNC_KEYEXCH_SET_PEER,
    OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, OSSL_LIB_CTX, OSSL_OP_KEYEXCH, OSSL_PARAM,
    OSSL_PROVIDER,
};

use super::fetch::Kind;
use super::keymgmt;
use super::opmeth::{self, AnyFn, Common, NotFound, OpMethod, Table, keep, method_exports};
use super::pkey::{self, KeyData, PkeyRef};
use super::pkey_ctx::{self, EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_pkey, EVP_PKEY_public_check};
use super::pmeth;
use crate::err::{self, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::ffi::ffi_export;
use crate::handle::handle_type;
use crate::provider::Ptr;

type InitFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *const OSSL_PARAM) -> c_int;
type SetPeerFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;
type DeriveFn = unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, usize) -> c_int;

/// A key exchange's functions.
#[derive(Default, Clone, Copy)]
pub(crate) struct Funcs {
    common: Common,
    init: Option<InitFn>,
    set_peer: Option<SetPeerFn>,
    derive: Option<DeriveFn>,
}

impl Table for Funcs {
    const FROM_ALGORITHM: &'static str = "evp_keyexch_from_algorithm";

    fn set(&mut self, id: c_int, f: AnyFn) {
        let c = &mut self.common;
        match id {
            OSSL_FUNC_KEYEXCH_NEWCTX => keep!(c.newctx, f),
            OSSL_FUNC_KEYEXCH_INIT => keep!(self.init, f),
            OSSL_FUNC_KEYEXCH_SET_PEER => keep!(self.set_peer, f),
            OSSL_FUNC_KEYEXCH_DERIVE => keep!(self.derive, f),
            OSSL_FUNC_KEYEXCH_FREECTX => keep!(c.freectx, f),
            OSSL_FUNC_KEYEXCH_DUPCTX => keep!(c.dupctx, f),
            OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS => keep!(c.get_ctx_params, f),
            OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS => keep!(c.gettable_ctx_params, f),
            OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS => keep!(c.set_ctx_params, f),
            OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS => keep!(c.settable_ctx_params, f),
            _ => {}
        }
    }

    fn whole(&self) -> bool {
        let c = &self.common;
        c.newctx.is_some()
            && self.init.is_some()
            && self.derive.is_some()
            && c.freectx.is_some()
            && c.params_paired()
    }

    fn common(&self) -> &Common {
        &self.common
    }
}

/// A key exchange (`EVP_KEYEXCH`).
pub(crate) type Exchange = OpMethod<Funcs>;

handle_type!(EVP_KEYEXCH => Exchange);

/// A reference to a key exchange.
pub(crate) type Ref = opmeth::Ref<EVP_KEYEXCH>;

/// Key exchanges to fetching.
static EXCHANGES: Kind = Kind {
    operation: OSSL_OP_KEYEXCH,
    style: crate::evp::fetch::Style::Evp,
    from_algorithm: opmeth::from_algorithm::<EVP_KEYEXCH, Funcs>,
    up_ref: opmeth::up_ref::<EVP_KEYEXCH>,
    free: opmeth::free::<EVP_KEYEXCH>,
};

method_exports! {
    EVP_KEYEXCH, EXCHANGES;
    pub unsafe extern "C" fn EVP_KEYEXCH_fetch;
    pub unsafe extern "C" fn EVP_KEYEXCH_up_ref;
    pub unsafe extern "C" fn EVP_KEYEXCH_free;
    pub unsafe extern "C" fn EVP_KEYEXCH_get0_provider;
    pub unsafe extern "C" fn EVP_KEYEXCH_get0_name;
    pub unsafe extern "C" fn EVP_KEYEXCH_get0_description;
    pub unsafe extern "C" fn EVP_KEYEXCH_is_a;
    pub unsafe extern "C" fn EVP_KEYEXCH_names_do_all;
    pub unsafe extern "C" fn EVP_KEYEXCH_do_all_provided;
    pub unsafe extern "C" fn EVP_KEYEXCH_gettable_ctx_params;
    pub unsafe extern "C" fn EVP_KEYEXCH_settable_ctx_params;
}

/// `EVP_PKEY_derive_init_ex`.
///
/// # Safety
/// `ctx` is NULL or a live context; `params` is NULL or an array.
unsafe fn derive_init(ctx: *mut EVP_PKEY_CTX, params: *const OSSL_PARAM) -> c_int {
    const F: &str = "EVP_PKEY_derive_init_ex";
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { pkey_ctx::context(ctx) }) else {
        err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, F);
        return -2;
    };
    let (libctx, keymgmt, pkey, propq) = {
        let mut s = c.lock();
        s.free_old_ops();
        s.operation = EVP_PKEY_OP_DERIVE;
        (
            s.libctx.0,
            s.keymgmt.clone(),
            s.pkey.clone(),
            s.propquery.clone(),
        )
    };
    let fail = || {
        let mut s = c.lock();
        s.free_old_ops();
        s.operation = EVP_PKEY_OP_UNDEFINED;
        0
    };
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    let Some(km) = keymgmt else {
        // A legacy context: its method derives.
        // SAFETY: the mark set above.
        unsafe { ERR_pop_to_mark() };
        let f = c.lock().pmeth_funcs().filter(|f| f.derive.is_some());
        let Some(f) = f else {
            err::raise(
                ERR_LIB_EVP,
                EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
                F,
            );
            return -2;
        };
        let Some(init) = f.derive_init else { return 1 };
        // SAFETY: the method's function with the caller's context.
        let ret = unsafe { init(ctx) };
        if ret <= 0 {
            c.lock().operation = EVP_PKEY_OP_UNDEFINED;
        }
        return ret;
    };
    let pkey = match pkey {
        Some(k) => k,
        None => {
            // Some algorithms (the KDFs) have no keys: a blank one of the key manager's type.
            let raw = pkey::new();
            // SAFETY: a new key's reference, given to the `PkeyRef`.
            let made = unsafe { PkeyRef::adopt(raw) }.filter(|k| {
                pkey::set_type_by_keymgmt(k.get(), &km)
                    && KeyData::adopt(km.clone(), km.get().newdata())
                        .map(|kd| pkey::set_keydata(k.get(), kd))
                        .is_some()
            });
            let Some(k) = made else {
                // SAFETY: the mark set above.
                unsafe { ERR_clear_last_mark() };
                err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
                return fail();
            };
            c.lock().pkey = Some(k.clone());
            k
        }
    };
    let supported = km.get().query_operation_name(OSSL_OP_KEYEXCH);
    // SAFETY: the context's library context; the exchanges' kind.
    let found = unsafe {
        opmeth::find::<EVP_KEYEXCH, Funcs>(
            libctx,
            &EXCHANGES,
            &km,
            &pkey,
            propq.as_deref(),
            &supported,
        )
    };
    let found = match found {
        Ok(f) => f,
        Err(NotFound::NotInProvider | NotFound::Exhausted) => {
            // `legacy`: without an EVP_PKEY_METHOD, not supported.
            // SAFETY: the mark set above.
            unsafe { ERR_pop_to_mark() };
            err::raise(
                ERR_LIB_EVP,
                EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
                F,
            );
            return -2;
        }
    };
    // SAFETY: the mark set above.
    unsafe { ERR_pop_to_mark() };
    let m = found.method;
    let algctx = m.get().newctx();
    {
        let mut s = c.lock();
        s.exchange = Some(m.clone());
        s.kexctx = Ptr(algctx);
    }
    if algctx.is_null() {
        err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
        return fail();
    }
    let Some(init) = m.get().funcs.init else {
        return fail();
    };
    // SAFETY: the provider's function with its context, the key's data, and the caller's array.
    let ret = unsafe { init(algctx, found.keydata.ptr(), params) };
    c_int::from(ret != 0)
}

ffi_export! {
    /// Starts a derivation with the key exchange the key's type names.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_derive_init(ctx: *mut EVP_PKEY_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { derive_init(ctx, ptr::null()) }
    }
}

ffi_export! {
    /// Starts a derivation, giving the exchange `params`.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `params` is NULL or an array.
    pub unsafe extern "C" fn EVP_PKEY_derive_init_ex(ctx: *mut EVP_PKEY_CTX, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { derive_init(ctx, params) }
    }
}

/// The context's exchange and its context, if the derivation has a provider side.
fn provider_op(c: &pkey_ctx::PkeyCtx) -> Option<(Ref, *mut c_void)> {
    let s = c.lock();
    if !s.is_derive_op() || s.kexctx.0.is_null() {
        return None;
    }
    s.exchange.clone().map(|m| (m, s.kexctx.0))
}

ffi_export! {
    /// Sets the peer's key for the derivation, checking it first if `validate_peer`. 1, or <= 0
    /// with an error.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `peer` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_derive_set_peer_ex(ctx: *mut EVP_PKEY_CTX, peer: *mut EVP_PKEY, validate_peer: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "EVP_PKEY_derive_set_peer_ex";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { pkey_ctx::context(ctx) }) else {
            err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, F);
            return -1;
        };
        // SAFETY: the caller's guarantee.
        let legacy = || unsafe { legacy_set_peer(ctx, c, peer) };
        let Some((m, algctx)) = provider_op(c) else { return legacy() };
        let Some(set_peer) = m.get().funcs.set_peer else {
            err::raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE, F);
            return -2;
        };
        let (libctx, propq, ctx_km) = {
            let s = c.lock();
            (s.libctx.0, s.propquery.clone(), s.keymgmt.clone())
        };
        if validate_peer != 0 {
            let q = propq.as_deref().map_or(ptr::null(), CStr::as_ptr);
            // SAFETY: the context's library context; the caller's key; the query.
            let check_ctx = unsafe { EVP_PKEY_CTX_new_from_pkey(libctx, peer, q) };
            if check_ctx.is_null() {
                return -1;
            }
            // SAFETY: the context made above.
            let check = unsafe { EVP_PKEY_public_check(check_ctx) };
            // SAFETY: as above, freed once.
            unsafe { EVP_PKEY_CTX_free(check_ctx) };
            if check <= 0 {
                return -1;
            }
        }
        // SAFETY: the caller's guarantee.
        let Some(peer_ref) = (unsafe { PkeyRef::new(peer) }) else { return legacy() };
        let Some(ctx_km) = ctx_km else { return legacy() };
        // SAFETY: the exchange's live provider.
        let km = unsafe { keymgmt::fetch_from_prov(m.get().prov.0, ctx_km.get().name(), propq.as_deref()) };
        // SAFETY: the context's library context.
        let exported = km.and_then(|km| unsafe { pkey::export_to_any(&peer_ref, libctx, Some(km), propq.as_deref()) });
        let Some((_, kd)) = exported else { return legacy() };
        // SAFETY: the provider's function with its context and the peer's data, which lives with
        // the peer (the context holds it below).
        let ret = unsafe { set_peer(algctx, kd.ptr()) };
        if ret <= 0 {
            return ret;
        }
        let old = c.lock().peerkey.replace(peer_ref);
        drop(old);
        1
    }
}

/// `EVP_PKEY_derive_set_peer_ex`'s `legacy`: the method's `EVP_PKEY_CTRL_PEER_KEY` ctrl with
/// 0, then (unless it answered 2) the peer's type and parameters checked against the key, then
/// the ctrl with 1. A NULL peer fails (the reference reads it; docs/DEVIATIONS.md).
///
/// # Safety
/// `ctx` is the live context behind `c`; `peer` is NULL or a live key.
unsafe fn legacy_set_peer(
    ctx: *mut EVP_PKEY_CTX,
    c: &pkey_ctx::PkeyCtx,
    peer: *mut EVP_PKEY,
) -> c_int {
    const F: &str = "EVP_PKEY_derive_set_peer_ex";
    let (f, op, pkey) = {
        let s = c.lock();
        (s.pmeth_funcs(), s.operation, s.pkey.clone())
    };
    let ctrl = f
        .filter(|f| f.derive.is_some() || f.encrypt.is_some() || f.decrypt.is_some())
        .and_then(|f| f.ctrl);
    let Some(ctrl) = ctrl else {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
            F,
        );
        return -2;
    };
    if op != EVP_PKEY_OP_DERIVE && op != EVP_PKEY_OP_ENCRYPT && op != EVP_PKEY_OP_DECRYPT {
        err::raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_INITIALIZED, F);
        return -1;
    }
    // SAFETY: the caller's guarantee.
    let Some(peer_ref) = (unsafe { PkeyRef::new(peer) }) else {
        err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, F);
        return -1;
    };
    // SAFETY: the method's function with the caller's context and key.
    let ret = unsafe { ctrl(ctx, EVP_PKEY_CTRL_PEER_KEY, 0, peer.cast()) };
    if ret <= 0 {
        return ret;
    }
    if ret != 2 {
        let Some(k) = pkey else {
            err::raise(ERR_LIB_EVP, EVP_R_NO_KEY_SET, F);
            return -1;
        };
        let p = peer_ref.get();
        if k.get().type_() != p.type_() {
            err::raise(ERR_LIB_EVP, EVP_R_DIFFERENT_KEY_TYPES, F);
            return -1;
        }
        // Parameters the peer has must match (-2, can't compare, is fine).
        if !pkey::missing_parameters(p) && pkey::parameters_eq(k.get(), p) == 0 {
            err::raise(ERR_LIB_EVP, EVP_R_DIFFERENT_PARAMETERS, F);
            return -1;
        }
        // SAFETY: as above.
        let ret = unsafe { ctrl(ctx, EVP_PKEY_CTRL_PEER_KEY, 1, peer.cast()) };
        if ret <= 0 {
            return ret;
        }
    }
    let old = c.lock().peerkey.replace(peer_ref);
    drop(old);
    1
}

ffi_export! {
    /// `EVP_PKEY_derive_set_peer_ex` checking the peer's key.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `peer` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_derive_set_peer(ctx: *mut EVP_PKEY_CTX, peer: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_PKEY_derive_set_peer_ex(ctx, peer, 1) }
    }
}

ffi_export! {
    /// Derives the shared secret into `key` (its room in `*pkeylen`, the length back); with a
    /// NULL `key`, the size it needs. 1, or <= 0 with an error.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `key` is NULL or has room for `*pkeylen` octets;
    /// `pkeylen` is NULL or room for a size.
    pub unsafe extern "C" fn EVP_PKEY_derive(ctx: *mut EVP_PKEY_CTX, key: *mut u8, pkeylen: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "EVP_PKEY_derive";
        // SAFETY: the caller's guarantee.
        let c = unsafe { pkey_ctx::context(ctx) };
        let (Some(c), false) = (c, pkeylen.is_null()) else {
            err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, F);
            return -1;
        };
        if !c.lock().is_derive_op() {
            err::raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_INITIALIZED, F);
            return -1;
        }
        let Some((m, algctx)) = provider_op(c) else {
            // A legacy context: its method derives.
            let pmeth = c.lock().pmeth.clone();
            let (Some(pm), Some(derive)) = (pmeth.as_ref(), pmeth.as_ref().and_then(|m| m.get().funcs().derive)) else {
                err::raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE, F);
                return -2;
            };
            // SAFETY: the caller's context.
            let pkey = unsafe { pkey_ctx::EVP_PKEY_CTX_get0_pkey(ctx) };
            // SAFETY: the context's key, or NULL; the caller's room for the size.
            if let Some(r) = unsafe { pmeth::check_autoarg(pm.get(), pkey, key.is_null(), pkeylen, F) } {
                return r;
            }
            // SAFETY: the method's function with the caller's context and buffers.
            return unsafe { derive(ctx, key, pkeylen) };
        };
        let Some(derive) = m.get().funcs.derive else { return 0 };
        let size = if key.is_null() {
            0
        } else {
            // SAFETY: the caller's guarantee.
            unsafe { pkeylen.read() }
        };
        // SAFETY: the provider's function with its context and the caller's buffers.
        unsafe { derive(algctx, key, pkeylen, size) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: a NULL exchange is refused (the reference crashes).
    #[test]
    fn null_methods_are_refused() {
        let m: *mut EVP_KEYEXCH = ptr::null_mut();
        // SAFETY: NULL is the case under test, here and below.
        assert_eq!(unsafe { EVP_KEYEXCH_up_ref(m) }, 0);
        // SAFETY: as above.
        assert!(unsafe { EVP_KEYEXCH_get0_name(m) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { EVP_KEYEXCH_get0_provider(m) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { EVP_KEYEXCH_gettable_ctx_params(m) }.is_null());
        // SAFETY: as above.
        let got = unsafe { EVP_KEYEXCH_names_do_all(m, None, ptr::null_mut()) };
        assert_eq!(got, 0);
        crate::err::take_all();
    }
}
