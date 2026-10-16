//! The default provider's X25519 key exchange (`ecx_exch.c`): the shared secret of a private
//! key and a peer's public key of the same length.
//!
//! As in OpenSSL (`ossl_ecx_compute_key`), a secret of all zeros (from a low-order peer) is
//! written to the caller's buffer and then refused.

use core::ffi::{c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, OSSL_FUNC_KEYEXCH_DERIVE, OSSL_FUNC_KEYEXCH_DUPCTX,
    OSSL_FUNC_KEYEXCH_FREECTX, OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,
    OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, OSSL_FUNC_KEYEXCH_INIT, OSSL_FUNC_KEYEXCH_NEWCTX,
    OSSL_FUNC_KEYEXCH_SET_PEER, OSSL_PARAM, PROV_R_FAILED_DURING_DERIVATION, PROV_R_MISSING_KEY,
    PROV_R_OUTPUT_BUFFER_TOO_SMALL,
};

use super::macs::{boxed, context, unbox, wipe};
use super::tables::{Dispatch, END, PARAM_END, Params, entry};
use crate::ecx::{self, EcxType};
use crate::err;
use crate::ffi::ffi_callback;

/// `PROV_ECX_CTX`.
struct EcxCtx {
    keylen: usize,
    /// The key and the peer's (key data, each with a reference this holds), or NULL.
    key: *mut c_void,
    peerkey: *mut c_void,
}

impl Drop for EcxCtx {
    fn drop(&mut self) {
        // SAFETY: the references this holds, or NULL.
        unsafe { ecx::free(self.key) };
        // SAFETY: as above.
        unsafe { ecx::free(self.peerkey) };
    }
}

/// The context behind `vctx`.
///
/// # Safety
/// `vctx` is NULL or a live context from `x25519_newctx`.
unsafe fn ctx<'a>(vctx: *mut c_void) -> Option<&'a mut EcxCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { context::<EcxCtx>(vctx) }
}

ffi_callback! {
    /// `x25519_newctx`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn x25519_newctx(_provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        boxed(EcxCtx {
            keylen: EcxType::X25519.keylen(),
            key: ptr::null_mut(),
            peerkey: ptr::null_mut(),
        })
    }
}

/// Takes a reference to `vkey` into `slot` if it has the context's length (`ecx_init`,
/// `ecx_set_peer`), raising an internal error if not.
///
/// # Safety
/// `vctx` is NULL or a live context; `vkey` is NULL or live ECX key data.
unsafe fn take(vctx: *mut c_void, vkey: *mut c_void, peer: bool, f: &str) -> c_int {
    // SAFETY: the caller's guarantee.
    let c = unsafe { ctx(vctx) };
    // SAFETY: the caller's guarantee.
    let k = unsafe { ecx::key(vkey) };
    let (Some(c), Some(k)) = (c, k) else {
        err::raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, f);
        return 0;
    };
    if k.keylen() != c.keylen {
        err::raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, f);
        return 0;
    }
    // SAFETY: the caller's live key.
    unsafe { ecx::up_ref(vkey) };
    let slot = if peer { &mut c.peerkey } else { &mut c.key };
    // SAFETY: the reference the context held, or NULL.
    unsafe { ecx::free(*slot) };
    *slot = vkey;
    1
}

ffi_callback! {
    /// `x25519_init`: the key (the parameters are ignored).
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `vkey` is NULL or live ECX key data.
    pub(crate) unsafe extern "C" fn x25519_init(vctx: *mut c_void, vkey: *mut c_void, _params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { take(vctx, vkey, false, "ecx_init") }
    }
}

ffi_callback! {
    /// `ecx_set_peer`.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `vkey` is NULL or live ECX key data.
    pub(crate) unsafe extern "C" fn ecx_set_peer(vctx: *mut c_void, vkey: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { take(vctx, vkey, true, "ecx_set_peer") }
    }
}

ffi_callback! {
    /// `ecx_derive` (`ossl_ecx_compute_key`): the secret's length when `secret` is NULL, else
    /// the secret.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `secret` is NULL or has room for `outlen` octets;
    /// `psecretlen` is writable.
    pub(crate) unsafe extern "C" fn ecx_derive(vctx: *mut c_void, secret: *mut c_uchar, psecretlen: *mut usize, outlen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "ossl_ecx_compute_key";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        // SAFETY: the reference the context holds, or NULL.
        let k = unsafe { ecx::key(c.key) };
        // SAFETY: as above.
        let peer = unsafe { ecx::key(c.peerkey) };
        let (Some(k), Some(peer)) = (k, peer) else {
            err::raise(ERR_LIB_PROV, PROV_R_MISSING_KEY, F);
            return 0;
        };
        let private = {
            let s = k.lock();
            s.privkey.as_deref().map(|p| <[u8; 32]>::try_from(p).ok())
        };
        let Some(private) = private else {
            err::raise(ERR_LIB_PROV, PROV_R_MISSING_KEY, F);
            return 0;
        };
        if secret.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { psecretlen.write(c.keylen) };
            return 1;
        }
        if outlen < c.keylen {
            err::raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL, F);
            return 0;
        }
        let (Some(mut s), Ok(p)) = (private, <[u8; 32]>::try_from(peer.public())) else {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_DURING_DERIVATION, F);
            return 0;
        };
        let shared = rustyssl_crypto::ecx::x25519(&s, &p);
        wipe(&mut s);
        let zeros = [0u8; 32];
        let out: &[u8; 32] = shared.as_deref().unwrap_or(&zeros);
        // SAFETY: the caller's room for `outlen` (at least 32) octets; a local.
        unsafe { ptr::copy_nonoverlapping(out.as_ptr(), secret, out.len()) };
        if shared.is_none() {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_DURING_DERIVATION, F);
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { psecretlen.write(c.keylen) };
        1
    }
}

ffi_callback! {
    /// `ecx_freectx`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context the caller gives up.
    pub(crate) unsafe extern "C" fn ecx_freectx(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<EcxCtx>(vctx) };
    }
}

ffi_callback! {
    /// `ecx_dupctx`: references to the keys.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context.
    pub(crate) unsafe extern "C" fn ecx_dupctx(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return ptr::null_mut() };
        for k in [c.key, c.peerkey] {
            if !k.is_null() {
                // SAFETY: the context's live key.
                unsafe { ecx::up_ref(k) };
            }
        }
        boxed(EcxCtx {
            keylen: c.keylen,
            key: c.key,
            peerkey: c.peerkey,
        })
    }
}

/// `known_gettable_ctx_params` (empty outside FIPS).
static GETTABLE: Params<1> = Params([PARAM_END]);

ffi_callback! {
    /// `ecx_gettable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn ecx_gettable_ctx_params(_vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        GETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `ecx_get_ctx_params`: nothing to get outside FIPS.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn ecx_get_ctx_params(_vctx: *mut c_void, _params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        1
    }
}

type NewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type InitFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *const OSSL_PARAM) -> c_int;
type SetPeerFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;
type DeriveFn = unsafe extern "C" fn(*mut c_void, *mut c_uchar, *mut usize, usize) -> c_int;
type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
type DupCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type GetParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
type ListFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;

/// `ossl_x25519_keyexch_functions`.
pub(crate) static X25519_KEYEXCH: Dispatch<9> = Dispatch([
    entry!(OSSL_FUNC_KEYEXCH_NEWCTX, x25519_newctx, NewCtxFn),
    entry!(OSSL_FUNC_KEYEXCH_INIT, x25519_init, InitFn),
    entry!(OSSL_FUNC_KEYEXCH_DERIVE, ecx_derive, DeriveFn),
    entry!(OSSL_FUNC_KEYEXCH_SET_PEER, ecx_set_peer, SetPeerFn),
    entry!(OSSL_FUNC_KEYEXCH_FREECTX, ecx_freectx, FreeCtxFn),
    entry!(OSSL_FUNC_KEYEXCH_DUPCTX, ecx_dupctx, DupCtxFn),
    entry!(
        OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,
        ecx_get_ctx_params,
        GetParamsFn
    ),
    entry!(
        OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS,
        ecx_gettable_ctx_params,
        ListFn
    ),
    END,
]);
