//! Key contexts (`EVP_PKEY_CTX_new(3)`, `EVP_PKEY_keygen(3)`, `EVP_PKEY_fromdata(3)`,
//! `EVP_PKEY_check(3)`, ...; `pmeth_lib.c`, `pmeth_gn.c`, `pmeth_check.c`): an `EVP_PKEY_CTX`
//! for a key type (by id, name, or key) with its key manager, and the operations of 4.2a: key
//! and parameter generation, making keys from parameters, and checking keys.
//!
//! As in OpenSSL:
//! - A context made by id types its keys with that id (`legacy_keytype`); one made by name, or
//!   from a provided key, with the key manager's key type, if it has one.
//! - Generation runs in the key manager's generation context; its callback reaches the
//!   application's `EVP_PKEY_gen_cb` with the progress in `EVP_PKEY_CTX_get_keygen_info`.
//! - A key type with an application's `EVP_PKEY_METHOD` (`EVP_PKEY_meth_add0`) gets a context
//!   with that method and no key manager (a "legacy" context): the method's `init`, `copy`, and
//!   `cleanup` run when the context is made, copied, and freed, and its functions generate,
//!   check keys, and take the parameters (as ctrls).
//!
//! No lock is held while a provider or application function runs. Functions given a NULL
//! context fail here where the reference would crash (docs/DEVIATIONS.md).

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;
use std::ffi::CString;
use std::sync::{Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    BIGNUM, ENGINE, ERR_LIB_EVP, ERR_R_ENGINE_LIB, ERR_R_EVP_LIB, ERR_R_INTERNAL_ERROR, EVP_PKEY,
    EVP_PKEY_CTRL_SET_MAC_KEY, EVP_PKEY_CTX, EVP_PKEY_KEYPAIR, EVP_PKEY_OP_FROMDATA,
    EVP_PKEY_OP_KEYGEN, EVP_PKEY_OP_PARAMGEN, EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_OP_TYPE_DERIVE,
    EVP_PKEY_OP_TYPE_GEN, EVP_PKEY_OP_TYPE_KEM, EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_OP_UNDEFINED,
    EVP_PKEY_gen_cb, EVP_R_COMMAND_NOT_SUPPORTED, EVP_R_INACCESSIBLE_DOMAIN_PARAMETERS,
    EVP_R_INITIALIZATION_ERROR, EVP_R_INVALID_LENGTH, EVP_R_NO_KEY_SET,
    EVP_R_OPERATION_NOT_INITIALIZED, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
    EVP_R_UNSUPPORTED_ALGORITHM, NID_undef, OSSL_GEN_PARAM_ITERATION, OSSL_GEN_PARAM_POTENTIAL,
    OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, OSSL_KEYMGMT_SELECT_KEYPAIR,
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
    OSSL_KEYMGMT_VALIDATE_FULL_CHECK, OSSL_KEYMGMT_VALIDATE_QUICK_CHECK, OSSL_LIB_CTX, OSSL_PARAM,
    OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PROVIDER,
};

use super::keymgmt;
use super::pkey::{self, KeyData, PkeyRef};
use super::pmeth;
use super::{asymcipher, ctrl, exchange, kem, signature};
use crate::err;
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::objects::OBJ_nid2sn;
use crate::params::{
    OSSL_PARAM_construct_octet_string, OSSL_PARAM_get_int, OSSL_PARAM_locate_const, end,
};
use crate::provider::Ptr;

/// The progress `EVP_PKEY_CTX_get_keygen_info` reads.
enum KeygenInfo {
    /// None (`keygen_info` NULL), with the count it was left with.
    None(c_int),
    /// The generation's own two values.
    Own([c_int; 2]),
    /// The application's (`EVP_PKEY_CTX_set0_keygen_info`).
    App(Ptr<c_int>, c_int),
}

/// What an `EVP_PKEY_CTX` handle points to.
pub(crate) struct PkeyCtx {
    state: Mutex<State>,
}

/// A context's state.
pub(crate) struct State {
    pub(crate) libctx: Ptr<OSSL_LIB_CTX>,
    pub(crate) propquery: Option<CString>,
    /// The key type's name the key manager was fetched by.
    keytype: Option<CString>,
    pub(crate) keymgmt: Option<keymgmt::Ref>,
    /// The application's method of a legacy context.
    pub(crate) pmeth: Option<pmeth::Ref>,
    /// `flag_call_digest_custom`: the method's `digest_custom` runs before the digest context's
    /// next update (or its final).
    pub(crate) call_digest_custom: bool,
    legacy_keytype: c_int,
    pub(crate) operation: c_int,
    /// The key manager's generation context, during a generation operation.
    genctx: Ptr<c_void>,
    /// The signature algorithm, during a signature operation.
    pub(crate) signature: Option<signature::Ref>,
    /// Its context.
    pub(crate) sigctx: Ptr<c_void>,
    /// The key exchange, during a derivation.
    pub(crate) exchange: Option<exchange::Ref>,
    /// Its context.
    pub(crate) kexctx: Ptr<c_void>,
    /// The asymmetric cipher, during encryption or decryption.
    pub(crate) cipher: Option<asymcipher::Ref>,
    /// Its context.
    pub(crate) ciphctx: Ptr<c_void>,
    /// The KEM, during encapsulation or decapsulation.
    pub(crate) kem: Option<kem::Ref>,
    /// Its context.
    pub(crate) kemctx: Ptr<c_void>,
    pub(crate) pkey: Option<PkeyRef>,
    pub(crate) peerkey: Option<PkeyRef>,
    /// The distinguishing ID kept for the next operation (`cached_parameters`).
    pub(crate) cached_id: Option<ctrl::CachedId>,
    /// The public exponent `EVP_PKEY_CTX_set_rsa_keygen_pubexp` gave the context, owned.
    pub(crate) rsa_pubexp: Ptr<BIGNUM>,
    app_data: Ptr<c_void>,
    data: Ptr<c_void>,
    pkey_gencb: EVP_PKEY_gen_cb,
    keygen_info: KeygenInfo,
    /// The engine the method came from, with a functional reference, or NULL.
    engine: Ptr<ENGINE>,
}

impl Drop for State {
    fn drop(&mut self) {
        // SAFETY: the context's functional reference, or NULL; its lock isn't held (the state
        // is being dropped with the context).
        unsafe { crate::engine::ENGINE_finish(self.engine.0) };
    }
}

handle_type!(EVP_PKEY_CTX => PkeyCtx);

impl PkeyCtx {
    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl State {
    /// A context's state without an operation.
    fn new(
        libctx: *mut OSSL_LIB_CTX,
        propquery: Option<CString>,
        keytype: Option<CString>,
        keymgmt: Option<keymgmt::Ref>,
        legacy_keytype: c_int,
    ) -> Self {
        Self {
            libctx: Ptr(libctx),
            propquery,
            keytype,
            keymgmt,
            pmeth: None,
            call_digest_custom: false,
            legacy_keytype,
            operation: EVP_PKEY_OP_UNDEFINED,
            genctx: Ptr(ptr::null_mut()),
            signature: None,
            sigctx: Ptr(ptr::null_mut()),
            exchange: None,
            kexctx: Ptr(ptr::null_mut()),
            cipher: None,
            ciphctx: Ptr(ptr::null_mut()),
            kem: None,
            kemctx: Ptr(ptr::null_mut()),
            pkey: None,
            peerkey: None,
            cached_id: None,
            rsa_pubexp: Ptr(ptr::null_mut()),
            app_data: Ptr(ptr::null_mut()),
            data: Ptr(ptr::null_mut()),
            pkey_gencb: None,
            keygen_info: KeygenInfo::None(0),
            engine: Ptr(ptr::null_mut()),
        }
    }

    /// `EVP_PKEY_CTX_IS_DERIVE_OP`.
    pub(crate) fn is_derive_op(&self) -> bool {
        self.operation & EVP_PKEY_OP_TYPE_DERIVE != 0
    }

    /// `EVP_PKEY_CTX_IS_ASYM_CIPHER_OP`.
    pub(crate) fn is_crypt_op(&self) -> bool {
        self.operation & EVP_PKEY_OP_TYPE_CRYPT != 0
    }

    /// `EVP_PKEY_CTX_IS_KEM_OP`.
    pub(crate) fn is_kem_op(&self) -> bool {
        self.operation & EVP_PKEY_OP_TYPE_KEM != 0
    }

    /// The key type `EVP_PKEY_CTX_new_id` (or the key manager) gave the context.
    pub(crate) fn legacy_keytype(&self) -> c_int {
        self.legacy_keytype
    }

    /// The key type's name the key manager was fetched by.
    pub(crate) fn keytype(&self) -> Option<&CStr> {
        self.keytype.as_deref()
    }

    /// `EVP_PKEY_CTX_IS_GEN_OP`.
    pub(crate) fn is_gen_op(&self) -> bool {
        self.operation & EVP_PKEY_OP_TYPE_GEN != 0
    }

    /// `EVP_PKEY_CTX_IS_SIGNATURE_OP`.
    pub(crate) fn is_sig_op(&self) -> bool {
        self.operation & EVP_PKEY_OP_TYPE_SIG != 0
    }

    /// The functions of the context's method (a legacy context's), if it has one.
    pub(crate) fn pmeth_funcs(&self) -> Option<pmeth::Funcs> {
        self.pmeth.as_ref().map(|m| m.get().funcs())
    }

    /// `evp_pkey_ctx_free_old_ops`: ends the operation's provider side.
    pub(crate) fn free_old_ops(&mut self) {
        if self.is_sig_op() {
            if let Some(sig) = self.signature.take()
                && !self.sigctx.0.is_null()
            {
                // SAFETY: the algorithm's context, freed once.
                unsafe { sig.get().freectx(self.sigctx.0) };
            }
            self.sigctx = Ptr(ptr::null_mut());
        } else if self.is_derive_op() {
            if let Some(m) = self.exchange.take()
                && !self.kexctx.0.is_null()
            {
                // SAFETY: the algorithm's context, freed once.
                unsafe { m.get().freectx(self.kexctx.0) };
            }
            self.kexctx = Ptr(ptr::null_mut());
        } else if self.is_kem_op() {
            if let Some(m) = self.kem.take()
                && !self.kemctx.0.is_null()
            {
                // SAFETY: the algorithm's context, freed once.
                unsafe { m.get().freectx(self.kemctx.0) };
            }
            self.kemctx = Ptr(ptr::null_mut());
        } else if self.is_crypt_op() {
            if let Some(m) = self.cipher.take()
                && !self.ciphctx.0.is_null()
            {
                // SAFETY: the algorithm's context, freed once.
                unsafe { m.get().freectx(self.ciphctx.0) };
            }
            self.ciphctx = Ptr(ptr::null_mut());
        }
        if self.is_gen_op()
            && !self.genctx.0.is_null()
            && let Some(km) = &self.keymgmt
        {
            // SAFETY: the key manager's generation context, freed once.
            unsafe { km.get().gen_cleanup(self.genctx.0) };
        }
        self.genctx = Ptr(ptr::null_mut());
    }

    /// Whether the context has a provider-side operation (`EVP_PKEY_STATE_PROVIDER`); otherwise
    /// one that's set has a legacy state.
    pub(crate) fn provider_state(&self) -> bool {
        (self.is_derive_op() && !self.kexctx.0.is_null())
            || (self.is_sig_op() && !self.sigctx.0.is_null())
            || (self.is_crypt_op() && !self.ciphctx.0.is_null())
            || (self.is_gen_op() && !self.genctx.0.is_null())
            || (self.is_kem_op() && !self.kemctx.0.is_null())
    }

    /// The algorithm context of the operation, if it has a provider side.
    pub(crate) fn algctx(&self) -> *mut c_void {
        if self.is_sig_op() {
            self.sigctx.0
        } else if self.is_derive_op() {
            self.kexctx.0
        } else if self.is_crypt_op() {
            self.ciphctx.0
        } else if self.is_kem_op() {
            self.kemctx.0
        } else if self.is_gen_op() {
            self.genctx.0
        } else {
            ptr::null_mut()
        }
    }
}

/// The operation's algorithm (or key manager, for generation) and its context, which the
/// parameter functions reach.
pub(crate) enum OpAlg {
    Sig(signature::Ref, *mut c_void),
    Kex(exchange::Ref, *mut c_void),
    Ciph(asymcipher::Ref, *mut c_void),
    Kem(kem::Ref, *mut c_void),
    Gen(keymgmt::Ref, *mut c_void),
    None,
}

impl State {
    /// The operation's algorithm and its context (NULL if it has none).
    pub(crate) fn op_alg(&self) -> OpAlg {
        if self.is_derive_op() {
            if let Some(m) = &self.exchange {
                return OpAlg::Kex(m.clone(), self.kexctx.0);
            }
        } else if self.is_sig_op() {
            if let Some(m) = &self.signature {
                return OpAlg::Sig(m.clone(), self.sigctx.0);
            }
        } else if self.is_crypt_op() {
            if let Some(m) = &self.cipher {
                return OpAlg::Ciph(m.clone(), self.ciphctx.0);
            }
        } else if self.is_kem_op() {
            if let Some(m) = &self.kem {
                return OpAlg::Kem(m.clone(), self.kemctx.0);
            }
        } else if self.is_gen_op()
            && let Some(m) = &self.keymgmt
        {
            return OpAlg::Gen(m.clone(), self.genctx.0);
        }
        OpAlg::None
    }
}

impl OpAlg {
    /// The algorithm's `set_ctx_params` (the key manager's `gen_set_params`), if it has one.
    ///
    /// # Safety
    /// The context is the algorithm's; `params` is NULL or an array.
    pub(crate) unsafe fn set_params(&self, params: *const OSSL_PARAM) -> Option<c_int> {
        match self {
            // SAFETY: the caller's guarantee.
            Self::Sig(m, c) => unsafe { m.get().set_ctx_params(*c, params) },
            // SAFETY: the caller's guarantee.
            Self::Kex(m, c) => unsafe { m.get().set_ctx_params(*c, params) },
            // SAFETY: the caller's guarantee.
            Self::Ciph(m, c) => unsafe { m.get().set_ctx_params(*c, params) },
            // SAFETY: the caller's guarantee.
            Self::Kem(m, c) => unsafe { m.get().set_ctx_params(*c, params) },
            // SAFETY: the caller's guarantee.
            Self::Gen(m, c) => m
                .get()
                .has_gen_set_params()
                .then(|| unsafe { m.get().gen_set_params(*c, params) }),
            Self::None => None,
        }
    }

    /// The algorithm's `get_ctx_params` (the key manager's `gen_get_params`), if it has one.
    ///
    /// # Safety
    /// The context is the algorithm's; `params` is NULL or an array.
    pub(crate) unsafe fn get_params(&self, params: *mut OSSL_PARAM) -> Option<c_int> {
        match self {
            // SAFETY: the caller's guarantee.
            Self::Sig(m, c) => unsafe { m.get().get_ctx_params(*c, params) },
            // SAFETY: the caller's guarantee.
            Self::Kex(m, c) => unsafe { m.get().get_ctx_params(*c, params) },
            // SAFETY: the caller's guarantee.
            Self::Ciph(m, c) => unsafe { m.get().get_ctx_params(*c, params) },
            // SAFETY: the caller's guarantee.
            Self::Kem(m, c) => unsafe { m.get().get_ctx_params(*c, params) },
            // SAFETY: the caller's guarantee.
            Self::Gen(m, c) => m
                .get()
                .has_gen_get_params()
                .then(|| unsafe { m.get().gen_get_params(*c, params) }),
            Self::None => None,
        }
    }

    /// The algorithm's gettable parameters, if it says.
    ///
    /// # Safety
    /// The context is NULL or the algorithm's.
    pub(crate) unsafe fn gettable(&self) -> Option<*const OSSL_PARAM> {
        match self {
            // SAFETY: the caller's guarantee.
            Self::Sig(m, c) => unsafe { m.get().gettable_ctx_params(*c) },
            // SAFETY: the caller's guarantee.
            Self::Kex(m, c) => unsafe { m.get().gettable_ctx_params(*c) },
            // SAFETY: the caller's guarantee.
            Self::Ciph(m, c) => unsafe { m.get().gettable_ctx_params(*c) },
            // SAFETY: the caller's guarantee.
            Self::Kem(m, c) => unsafe { m.get().gettable_ctx_params(*c) },
            // SAFETY: the caller's guarantee.
            Self::Gen(m, c) => Some(unsafe { m.get().gen_gettable_params(*c) }),
            Self::None => None,
        }
    }

    /// The algorithm's settable parameters, if it says.
    ///
    /// # Safety
    /// The context is NULL or the algorithm's.
    pub(crate) unsafe fn settable(&self) -> Option<*const OSSL_PARAM> {
        match self {
            // SAFETY: the caller's guarantee.
            Self::Sig(m, c) => unsafe { m.get().settable_ctx_params(*c) },
            // SAFETY: the caller's guarantee.
            Self::Kex(m, c) => unsafe { m.get().settable_ctx_params(*c) },
            // SAFETY: the caller's guarantee.
            Self::Ciph(m, c) => unsafe { m.get().settable_ctx_params(*c) },
            // SAFETY: the caller's guarantee.
            Self::Kem(m, c) => unsafe { m.get().settable_ctx_params(*c) },
            // SAFETY: the caller's guarantee.
            Self::Gen(m, c) => Some(unsafe { m.get().gen_settable_params(*c) }),
            Self::None => None,
        }
    }
}

impl Drop for PkeyCtx {
    fn drop(&mut self) {
        let mut s = self.lock();
        s.free_old_ops();
        let e = core::mem::replace(&mut s.rsa_pubexp, Ptr(ptr::null_mut()));
        drop(s);
        // SAFETY: the exponent the context owns, or NULL.
        unsafe { crate::bn::BN_free(e.0) };
    }
}

/// The context behind `ctx`, or `None` for NULL.
///
/// # Safety
/// `ctx` is NULL or a live context.
pub(crate) unsafe fn context<'a>(ctx: *const EVP_PKEY_CTX) -> Option<&'a PkeyCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { EVP_PKEY_CTX::get(ctx) }
}

/// A C string argument, `None` for NULL.
///
/// # Safety
/// `s` is NULL or a string.
unsafe fn text<'a>(s: *const c_char) -> Option<&'a CStr> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) })
}

/// What `int_ctx_new` decides: the key manager (or the application's method) and the key type.
struct Resolved {
    keytype: Option<CString>,
    keymgmt: Option<keymgmt::Ref>,
    pmeth: Option<pmeth::Ref>,
    id: c_int,
    /// The engine `pmeth` came from, with a functional reference the context takes, or NULL.
    engine: *mut ENGINE,
}

/// `int_ctx_new`'s choice of key type and key manager, or `None` with an error.
///
/// # Safety
/// `libctx` is NULL or a live library context.
unsafe fn resolve(
    libctx: *mut OSSL_LIB_CTX,
    pkey: Option<&PkeyRef>,
    mut e: *mut ENGINE,
    keytype: Option<&CStr>,
    propq: Option<&CStr>,
    mut id: c_int,
) -> Option<Resolved> {
    const F: &str = "int_ctx_new";
    let mut keytype = keytype.map(CStr::to_owned);
    let mut app_pmeth = None;
    let mut builtin_pmeth = None;
    if id == -1 {
        match pkey {
            Some(k) if !k.get().is_provided() => id = k.get().type_(),
            _ => {
                if let Some(k) = pkey {
                    keytype = k.get().provided().0.map(|m| m.get().name().to_owned());
                }
                if let Some(t) = &keytype {
                    id = pkey::ameth::name2type(t.to_bytes());
                    if id == NID_undef {
                        id = -1;
                    }
                }
            }
        }
    }
    if id == -1 {
        if !e.is_null() {
            err::raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_ALGORITHM, F);
            return None;
        }
    } else {
        // An engine makes the context entirely legacy: no key type name to fetch by.
        if !e.is_null() {
            keytype = None;
        }
        // A foreign key (its legacy data an application method's) keeps to the type's
        // `EVP_PKEY_METHOD`; any other key goes to the providers by its type's name.
        let foreign = pkey.is_some_and(|k| k.get().lock().foreign);
        if e.is_null() && !foreign {
            // SAFETY: a type number.
            let sn = unsafe { OBJ_nid2sn(id) };
            // SAFETY: NULL or a static string.
            keytype = unsafe { text(sn) }.map(CStr::to_owned);
        }
        if e.is_null()
            && let Some(k) = pkey
        {
            e = k.get().pmeth_engine();
        }
        if e.is_null() {
            // OpenSSL searches for an engine implementing the type first.
            pkey::ameth::engine_lookup();
            // SAFETY: no preconditions; a functional reference, or NULL.
            e = unsafe { crate::engine::table::ENGINE_get_pkey_meth_engine(id) };
        } else {
            // SAFETY: the caller's live engine, or the key's; its `init` may run.
            if unsafe { crate::engine::ENGINE_init(e) } == 0 {
                err::raise(ERR_LIB_EVP, ERR_R_ENGINE_LIB, F);
                return None;
            }
        }
        if !e.is_null() {
            // SAFETY: an initialized engine; its method callback may run.
            let m = unsafe { crate::engine::table::ENGINE_get_pkey_meth(e, id) };
            // SAFETY: the engine's method, or NULL; the context takes a reference.
            builtin_pmeth = unsafe { pmeth::Ref::new(m) };
        } else if foreign {
            builtin_pmeth = pmeth::find(id);
        } else {
            app_pmeth = pmeth::find_app(id);
        }
    }
    let mut keymgmt = None;
    if let Some(t) = keytype
        .as_ref()
        .filter(|_| app_pmeth.is_none() && e.is_null())
    {
        let km = match pkey.and_then(|k| k.get().provided().0) {
            Some(m) => Some(m),
            // SAFETY: the caller's guarantee.
            None => unsafe { keymgmt::fetch_by_name(libctx, t, propq) },
        };
        let km = km?;
        let tmp_id = km.get().legacy_alg;
        if tmp_id != NID_undef {
            if id == -1 {
                id = tmp_id;
            } else if id != tmp_id {
                // OpenSSL asserts the id and the key manager's agree.
                err::raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR, F);
                return None;
            }
        }
        keymgmt = Some(km);
    }
    let pmeth = app_pmeth.or(builtin_pmeth);
    if keymgmt.is_none() && pmeth.is_none() {
        err::raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_ALGORITHM, F);
    }
    if pmeth.is_none() && !e.is_null() {
        // SAFETY: the functional reference taken above.
        unsafe { crate::engine::ENGINE_finish(e) };
        e = ptr::null_mut();
    }
    if keymgmt.is_none() && pmeth.is_none() {
        return None;
    }
    Some(Resolved {
        keytype,
        keymgmt,
        pmeth,
        id,
        engine: e,
    })
}

/// `int_ctx_new`: a context, or NULL with an error.
///
/// # Safety
/// `libctx` is NULL or a live library context.
unsafe fn int_ctx_new(
    libctx: *mut OSSL_LIB_CTX,
    pkey: Option<PkeyRef>,
    e: *mut ENGINE,
    keytype: Option<&CStr>,
    propq: Option<&CStr>,
    id: c_int,
) -> *mut EVP_PKEY_CTX {
    // SAFETY: the caller's guarantee.
    let Some(r) = (unsafe { resolve(libctx, pkey.as_ref(), e, keytype, propq, id) }) else {
        return ptr::null_mut();
    };
    let mut state = State::new(
        libctx,
        propq.map(CStr::to_owned),
        r.keytype,
        r.keymgmt,
        r.id,
    );
    state.pkey = pkey;
    state.engine = Ptr(r.engine);
    let init = r.pmeth.as_ref().and_then(|m| m.get().funcs().init);
    state.pmeth = r.pmeth;
    let ctx = EVP_PKEY_CTX::new_handle(PkeyCtx {
        state: Mutex::new(state),
    });
    if let Some(init) = init {
        // SAFETY: the method's function with the new context.
        if unsafe { init(ctx) } <= 0 {
            // SAFETY: the context made above.
            if let Some(c) = unsafe { context(ctx) } {
                // Its cleanup doesn't run.
                c.lock().pmeth = None;
            }
            // SAFETY: as above.
            unsafe { EVP_PKEY_CTX_free(ctx) };
            return ptr::null_mut();
        }
    }
    ctx
}

/// The key manager a context for `pkey` would have (as `evp_pkey_export_to_provider` takes it
/// from `EVP_PKEY_CTX_new_from_pkey`), or `None`.
///
/// # Safety
/// `libctx` is NULL or a live library context.
pub(crate) unsafe fn keymgmt_for(
    libctx: *mut OSSL_LIB_CTX,
    pkey: &PkeyRef,
    propq: Option<&CStr>,
) -> Option<keymgmt::Ref> {
    // SAFETY: the caller's guarantee.
    let r = unsafe { resolve(libctx, Some(pkey), ptr::null_mut(), None, propq, -1) }?;
    // SAFETY: the reference the resolution took (for the key's engine), or NULL.
    unsafe { crate::engine::ENGINE_finish(r.engine) };
    r.keymgmt
}

ffi_export! {
    /// A context for `pkey`'s type (its key manager, or one fetched for its type); NULL with an
    /// error if there's none.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `e` must be NULL (there are no engines).
    pub unsafe extern "C" fn EVP_PKEY_CTX_new(pkey: *mut EVP_PKEY, e: *mut ENGINE) -> *mut EVP_PKEY_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let k = unsafe { PkeyRef::new(pkey) };
        // SAFETY: the default context.
        unsafe { int_ctx_new(ptr::null_mut(), k, e, None, None, -1) }
    }
}

ffi_export! {
    /// A context for the key type `id`, whose keys it types by `id`; NULL with an error if
    /// there's no key manager for it.
    ///
    /// # Safety
    /// `e` must be NULL (there are no engines).
    pub unsafe extern "C" fn EVP_PKEY_CTX_new_id(id: c_int, e: *mut ENGINE) -> *mut EVP_PKEY_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the default context.
        unsafe { int_ctx_new(ptr::null_mut(), None, e, None, None, id) }
    }
}

ffi_export! {
    /// A context for the key type `name`, with the key manager fetched from `libctx` with
    /// `propquery`; NULL with the fetch's error.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `name` and `propquery` are NULL or strings.
    pub unsafe extern "C" fn EVP_PKEY_CTX_new_from_name(libctx: *mut OSSL_LIB_CTX, name: *const c_char, propquery: *const c_char) -> *mut EVP_PKEY_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let n = unsafe { text(name) };
        // SAFETY: as above.
        let q = unsafe { text(propquery) };
        // SAFETY: the caller's guarantee.
        unsafe { int_ctx_new(libctx, None, ptr::null_mut(), n, q, -1) }
    }
}

ffi_export! {
    /// A context for `pkey`, in `libctx` with `propquery`.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `pkey` is NULL or a live key; `propquery` is
    /// NULL or a string.
    pub unsafe extern "C" fn EVP_PKEY_CTX_new_from_pkey(libctx: *mut OSSL_LIB_CTX, pkey: *mut EVP_PKEY, propquery: *const c_char) -> *mut EVP_PKEY_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let k = unsafe { PkeyRef::new(pkey) };
        // SAFETY: as above.
        let q = unsafe { text(propquery) };
        // SAFETY: the caller's guarantee.
        unsafe { int_ctx_new(libctx, k, ptr::null_mut(), None, q, -1) }
    }
}

ffi_export! {
    /// Frees the context (its method's `cleanup` first), ending its operation; NULL does
    /// nothing.
    ///
    /// # Safety
    /// `ctx` is NULL or a context the caller owns, not used afterwards.
    pub unsafe extern "C" fn EVP_PKEY_CTX_free(ctx: *mut EVP_PKEY_CTX)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let cleanup = unsafe { context(ctx) }.and_then(|c| c.lock().pmeth_funcs()).and_then(|f| f.cleanup);
        if let Some(cleanup) = cleanup {
            // SAFETY: the method's function with the caller's context.
            unsafe { cleanup(ctx) };
        }
        // SAFETY: the caller's guarantee.
        unsafe { EVP_PKEY_CTX::free(ctx) };
    }
}

ffi_export! {
    /// A copy of the context; NULL (without an error) during a generation operation, which
    /// can't be copied.
    ///
    /// # Safety
    /// `pctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_dup(pctx: *const EVP_PKEY_CTX) -> *mut EVP_PKEY_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(pctx) }) else { return ptr::null_mut() };
        // The copy takes its own functional reference to the context's engine.
        let engine = c.lock().engine.0;
        // SAFETY: the context's engine; its `init` may run (no lock is held).
        if !engine.is_null() && unsafe { crate::engine::ENGINE_init(engine) } == 0 {
            err::raise(ERR_LIB_EVP, ERR_R_ENGINE_LIB, "EVP_PKEY_CTX_dup");
            return ptr::null_mut();
        }
        let s = c.lock();
        let mut new = State::new(
            s.libctx.0,
            s.propquery.clone(),
            s.keytype.clone(),
            s.keymgmt.clone(),
            s.legacy_keytype,
        );
        new.operation = s.operation;
        new.pkey = s.pkey.clone();
        // An operation with a provider side: the copy gets a copy of the algorithm's context
        // (and, as in OpenSSL, nothing else: no peer key).
        if s.is_sig_op() && !s.sigctx.0.is_null() {
            let (Some(m), algctx) = (s.signature.clone(), s.sigctx.0) else { return ptr::null_mut() };
            drop(s);
            // SAFETY: the algorithm's context.
            let dup = unsafe { m.get().dupctx(algctx) };
            if dup.is_null() {
                return ptr::null_mut();
            }
            new.signature = Some(m);
            new.sigctx = Ptr(dup);
            return EVP_PKEY_CTX::new_handle(PkeyCtx { state: Mutex::new(new) });
        }
        if s.is_derive_op() && !s.kexctx.0.is_null() {
            let (Some(m), algctx) = (s.exchange.clone(), s.kexctx.0) else { return ptr::null_mut() };
            drop(s);
            // SAFETY: the algorithm's context.
            let dup = unsafe { m.get().dupctx(algctx) };
            if dup.is_null() {
                return ptr::null_mut();
            }
            new.exchange = Some(m);
            new.kexctx = Ptr(dup);
            return EVP_PKEY_CTX::new_handle(PkeyCtx { state: Mutex::new(new) });
        }
        if s.is_crypt_op() && !s.ciphctx.0.is_null() {
            let (Some(m), algctx) = (s.cipher.clone(), s.ciphctx.0) else { return ptr::null_mut() };
            drop(s);
            // SAFETY: the algorithm's context.
            let dup = unsafe { m.get().dupctx(algctx) };
            if dup.is_null() {
                return ptr::null_mut();
            }
            new.cipher = Some(m);
            new.ciphctx = Ptr(dup);
            return EVP_PKEY_CTX::new_handle(PkeyCtx { state: Mutex::new(new) });
        }
        if s.is_kem_op() && !s.kemctx.0.is_null() {
            let (Some(m), algctx) = (s.kem.clone(), s.kemctx.0) else { return ptr::null_mut() };
            drop(s);
            // SAFETY: the algorithm's context.
            let dup = unsafe { m.get().dupctx(algctx) };
            if dup.is_null() {
                return ptr::null_mut();
            }
            new.kem = Some(m);
            new.kemctx = Ptr(dup);
            return EVP_PKEY_CTX::new_handle(PkeyCtx { state: Mutex::new(new) });
        }
        // A generation can't be copied (it would need the key manager's `gen_dupctx`).
        if s.is_gen_op() {
            return ptr::null_mut();
        }
        // The copy holds the engine from here on. The returns above keep the reference taken
        // for it without holding it, as OpenSSL's do (they come before `rctx->engine` is set).
        new.engine = Ptr(engine);
        new.peerkey = s.peerkey.clone();
        if let Some(m) = s.pmeth.clone() {
            drop(s);
            // A legacy context: its method copies its part. Without a `copy` (which the
            // reference calls through NULL; docs/DEVIATIONS.md) it can't be copied.
            let Some(copy) = m.get().funcs().copy else { return ptr::null_mut() };
            new.pmeth = Some(m);
            let rctx = EVP_PKEY_CTX::new_handle(PkeyCtx { state: Mutex::new(new) });
            // SAFETY: the method's function with the new context and the caller's.
            if unsafe { copy(rctx, pctx) } > 0 {
                return rctx;
            }
            // SAFETY: made above.
            if let Some(r) = unsafe { context(rctx) } {
                // Its cleanup doesn't run.
                r.lock().pmeth = None;
            }
            // SAFETY: as above.
            unsafe { EVP_PKEY_CTX_free(rctx) };
            return ptr::null_mut();
        }
        // Without a method, an operation without a provider context can't be copied.
        if s.operation != EVP_PKEY_OP_UNDEFINED {
            return ptr::null_mut();
        }
        let (libctx, propq) = (s.libctx.0, s.propquery.clone());
        drop(s);
        if let Some(k) = new.pkey.clone() {
            // The copy gets the key manager the key's data is in.
            // SAFETY: the context's library context.
            let Some((km, _)) = (unsafe { pkey::export_to_any(&k, libctx, new.keymgmt.clone(), propq.as_deref()) }) else {
                return ptr::null_mut();
            };
            new.keymgmt = Some(km);
        }
        EVP_PKEY_CTX::new_handle(PkeyCtx { state: Mutex::new(new) })
    }
}

ffi_export! {
    /// Whether the context's key type is `keytype` (one of its key manager's names).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `keytype` is NULL or a string.
    pub unsafe extern "C" fn EVP_PKEY_CTX_is_a(ctx: *mut EVP_PKEY_CTX, keytype: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        // SAFETY: as above.
        let n = unsafe { text(keytype) }.map_or(&b""[..], CStr::to_bytes);
        let (km, pm) = {
            let s = c.lock();
            (s.keymgmt.clone(), s.pmeth.clone())
        };
        match (km, pm) {
            (Some(m), _) => c_int::from(m.get().is_a(n)),
            // A legacy context: its method's key type.
            (None, Some(m)) => c_int::from(m.get().pkey_id == pkey::ameth::name2type(n)),
            (None, None) => 0,
        }
    }
}

ffi_export! {
    /// The operation the context was initialized for (`EVP_PKEY_OP_*`).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get_operation(ctx: *mut EVP_PKEY_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { context(ctx) }.map_or(0, |c| c.lock().operation)
    }
}

ffi_export! {
    /// The library context the context was made in (NULL for the default).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get0_libctx(ctx: *mut EVP_PKEY_CTX) -> *mut OSSL_LIB_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { context(ctx) }.map_or(ptr::null_mut(), |c| c.lock().libctx.0)
    }
}

ffi_export! {
    /// The property query the context was made with, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get0_propq(ctx: *const EVP_PKEY_CTX) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return ptr::null() };
        // The string lives as long as the context.
        c.lock().propquery.as_ref().map_or(ptr::null(), |q| q.as_ptr())
    }
}

ffi_export! {
    /// The provider of the context's operation (its key manager's, for generation), or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get0_provider(ctx: *const EVP_PKEY_CTX) -> *const OSSL_PROVIDER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return ptr::null() };
        let s = c.lock();
        if s.is_sig_op() {
            return s.signature.as_ref().map_or(ptr::null(), |m| m.get().prov().cast_const());
        }
        if s.is_derive_op() {
            return s.exchange.as_ref().map_or(ptr::null(), |m| m.get().prov.0.cast_const());
        }
        if s.is_kem_op() {
            return s.kem.as_ref().map_or(ptr::null(), |m| m.get().prov.0.cast_const());
        }
        if s.is_crypt_op() {
            return s.cipher.as_ref().map_or(ptr::null(), |m| m.get().prov.0.cast_const());
        }
        if s.is_gen_op() {
            return s.keymgmt.as_ref().map_or(ptr::null(), |m| m.get().prov.0.cast_const());
        }
        ptr::null()
    }
}

ffi_export! {
    /// The context's key (no reference is taken), or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get0_pkey(ctx: *mut EVP_PKEY_CTX) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { context(ctx) }.and_then(|c| c.lock().pkey.as_ref().map(PkeyRef::as_ptr)).unwrap_or(ptr::null_mut())
    }
}

ffi_export! {
    /// The context's peer key (no reference is taken), or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get0_peerkey(ctx: *mut EVP_PKEY_CTX) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { context(ctx) }.and_then(|c| c.lock().peerkey.as_ref().map(PkeyRef::as_ptr)).unwrap_or(ptr::null_mut())
    }
}

ffi_export! {
    /// Sets the application's data.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_app_data(ctx: *mut EVP_PKEY_CTX, data: *mut c_void)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { context(ctx) } {
            c.lock().app_data = Ptr(data);
        }
    }
}

ffi_export! {
    /// The application's data, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get_app_data(ctx: *mut EVP_PKEY_CTX) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { context(ctx) }.map_or(ptr::null_mut(), |c| c.lock().app_data.0)
    }
}

ffi_export! {
    /// Sets the method's data (`EVP_PKEY_CTX_set_data`).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_data(ctx: *mut EVP_PKEY_CTX, data: *mut c_void)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { context(ctx) } {
            c.lock().data = Ptr(data);
        }
    }
}

ffi_export! {
    /// The method's data, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get_data(ctx: *const EVP_PKEY_CTX) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { context(ctx) }.map_or(ptr::null_mut(), |c| c.lock().data.0)
    }
}

ffi_export! {
    /// Sets the generation callback.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `cb` is NULL or a function of the documented type.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_cb(ctx: *mut EVP_PKEY_CTX, cb: EVP_PKEY_gen_cb)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { context(ctx) } {
            c.lock().pkey_gencb = cb;
        }
    }
}

ffi_export! {
    /// The generation callback, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get_cb(ctx: *mut EVP_PKEY_CTX) -> EVP_PKEY_gen_cb
    where failure = None, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { context(ctx) }.and_then(|c| c.lock().pkey_gencb)
    }
}

ffi_export! {
    /// Sets the array `EVP_PKEY_CTX_get_keygen_info` reads (`datlen` values at `dat`).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `dat` holds `datlen` ints for as long as it's read.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set0_keygen_info(ctx: *mut EVP_PKEY_CTX, dat: *mut c_int, datlen: c_int)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { context(ctx) } {
            c.lock().keygen_info = KeygenInfo::App(Ptr(dat), datlen);
        }
    }
}

ffi_export! {
    /// The generation's progress value `idx`, or with -1 how many there are. 0 for an index out
    /// of range (OpenSSL reads one past the end, or through NULL; docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get_keygen_info(ctx: *mut EVP_PKEY_CTX, idx: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        let s = c.lock();
        let count = match s.keygen_info {
            KeygenInfo::None(n) | KeygenInfo::App(_, n) => n,
            KeygenInfo::Own(_) => 2,
        };
        if idx == -1 {
            return count;
        }
        let Ok(i) = usize::try_from(idx) else { return 0 };
        if idx >= count {
            return 0;
        }
        match &s.keygen_info {
            KeygenInfo::None(_) => 0,
            KeygenInfo::Own(v) => v.get(i).copied().unwrap_or(0),
            KeygenInfo::App(p, _) if p.0.is_null() => 0,
            // SAFETY: the application's array of `count` ints.
            KeygenInfo::App(p, _) => unsafe { p.0.wrapping_add(i).read() },
        }
    }
}

ffi_export! {
    /// Gives the operation's provider context `params`. 0 without an operation that takes them
    /// (an operation without a provider side translates them to ctrls of its EVP_PKEY_METHOD,
    /// which a context with a key manager hasn't).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `params` is NULL or an array.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_params(ctx: *mut EVP_PKEY_CTX, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        let s = c.lock();
        if s.provider_state() {
            let op = s.op_alg();
            drop(s);
            // SAFETY: the operation's context; the caller's array.
            return unsafe { op.set_params(params) }.unwrap_or(0);
        }
        if s.operation == EVP_PKEY_OP_UNDEFINED || s.keymgmt.is_some() {
            return 0;
        }
        drop(s);
        // A legacy context: through the ctrls of its method.
        // SAFETY: the caller's guarantee.
        unsafe { ctrl::params_to_ctrl(ctx, params.cast_mut(), true) }
    }
}

ffi_export! {
    /// Asks the operation's provider context for `params`. 0 without an operation that reports
    /// them.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `params` is NULL or an array.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get_params(ctx: *mut EVP_PKEY_CTX, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        let s = c.lock();
        if s.provider_state() {
            let op = s.op_alg();
            drop(s);
            // SAFETY: the operation's context; the caller's array.
            return unsafe { op.get_params(params) }.unwrap_or(0);
        }
        if s.operation == EVP_PKEY_OP_UNDEFINED || s.keymgmt.is_some() {
            return 0;
        }
        drop(s);
        // A legacy context: through the ctrls of its method.
        // SAFETY: the caller's guarantee.
        unsafe { ctrl::params_to_ctrl(ctx, params, false) }
    }
}

ffi_export! {
    /// The parameters the operation reports, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_gettable_params(ctx: *const EVP_PKEY_CTX) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return ptr::null() };
        let op = c.lock().op_alg();
        // SAFETY: the operation's context, or NULL.
        unsafe { op.gettable() }.unwrap_or(ptr::null())
    }
}

ffi_export! {
    /// The parameters the operation can be given, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_settable_params(ctx: *const EVP_PKEY_CTX) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return ptr::null() };
        let op = c.lock().op_alg();
        // SAFETY: the operation's context, or NULL.
        unsafe { op.settable() }.unwrap_or(ptr::null())
    }
}

// -------------------------------------------------------------------------------------------
// Generation (pmeth_gn.c)

/// `gen_init`: starts a generation operation. 1, or -2 with an error if the key manager can't
/// generate, or 0 if it fails to start.
///
/// # Safety
/// `ctx` is NULL or a live context.
unsafe fn gen_init(ctx: *mut EVP_PKEY_CTX, operation: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { context(ctx) }) else {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
            "gen_init",
        );
        return -2;
    };
    let (km, pm) = {
        let mut s = c.lock();
        s.free_old_ops();
        s.operation = operation;
        (s.keymgmt.clone(), s.pmeth_funcs())
    };
    let end = |ret: c_int| {
        if ret <= 0 {
            let mut s = c.lock();
            s.free_old_ops();
            s.operation = EVP_PKEY_OP_UNDEFINED;
        }
        ret
    };
    let Some(km) = km.filter(|m| m.get().has_gen_init()) else {
        // A legacy context: its method generates.
        let f = pm.filter(|f| {
            if operation == EVP_PKEY_OP_PARAMGEN {
                f.paramgen.is_some()
            } else {
                f.keygen.is_some()
            }
        });
        let Some(f) = f else {
            err::raise(
                ERR_LIB_EVP,
                EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
                "gen_init",
            );
            return end(-2);
        };
        let init = if operation == EVP_PKEY_OP_PARAMGEN {
            f.paramgen_init
        } else {
            f.keygen_init
        };
        // SAFETY: the method's function with the caller's context.
        return end(init.map_or(1, |i| unsafe { i(ctx) }));
    };
    let selection = if operation == EVP_PKEY_OP_PARAMGEN {
        OSSL_KEYMGMT_SELECT_ALL_PARAMETERS
    } else {
        OSSL_KEYMGMT_SELECT_KEYPAIR
    } as c_int;
    // SAFETY: no parameters.
    let genctx = unsafe { km.get().gen_init(selection, ptr::null()) };
    let mut s = c.lock();
    s.genctx = Ptr(genctx);
    if genctx.is_null() {
        err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, "gen_init");
        s.free_old_ops();
        s.operation = EVP_PKEY_OP_UNDEFINED;
        return 0;
    }
    1
}

ffi_export! {
    /// Starts parameter generation.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_paramgen_init(ctx: *mut EVP_PKEY_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { gen_init(ctx, EVP_PKEY_OP_PARAMGEN) }
    }
}

ffi_export! {
    /// Starts key generation.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_keygen_init(ctx: *mut EVP_PKEY_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { gen_init(ctx, EVP_PKEY_OP_KEYGEN) }
    }
}

/// A context without a key, method, or key manager, for testing a method's functions alone
/// (making one the usual way loads the configuration, which Miri can't).
#[cfg(test)]
pub(crate) fn bare_context() -> *mut EVP_PKEY_CTX {
    EVP_PKEY_CTX::new_handle(PkeyCtx {
        state: Mutex::new(State::new(ptr::null_mut(), None, None, None, 0)),
    })
}

/// `trans_cb` (`evp_pkey_set_cb_translate`): a legacy method's generation progress `a`, `b`
/// into the context's `keygen_info` (the first two values), then the application's callback
/// (1 without one).
///
/// # Safety
/// `ctx` is NULL or a live context.
pub(crate) unsafe fn legacy_gen_progress(ctx: *mut EVP_PKEY_CTX, a: c_int, b: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { context(ctx) }) else {
        return 0;
    };
    let cb = {
        let mut s = c.lock();
        match &mut s.keygen_info {
            KeygenInfo::Own(v) => *v = [a, b],
            KeygenInfo::App(p, n) if !p.0.is_null() && *n >= 2 => {
                // SAFETY: the array of at least two ints the context was given.
                unsafe { p.0.write(a) };
                // SAFETY: as above.
                unsafe { p.0.wrapping_add(1).write(b) };
            }
            _ => {}
        }
        s.pkey_gencb
    };
    let Some(cb) = cb else { return 1 };
    // SAFETY: the application's callback with its context; no lock is held.
    unsafe { cb(ctx) }
}

/// The operation a context is set up for (`EVP_PKEY_OP_*`), and the key type of its legacy
/// method (`ctx->pmeth->pkey_id`; 0 without one).
///
/// # Safety
/// `ctx` is NULL or a live context.
pub(crate) unsafe fn legacy_op(ctx: *const EVP_PKEY_CTX) -> (c_int, c_int) {
    // SAFETY: the caller's guarantee.
    unsafe { context(ctx) }.map_or((0, 0), |c| {
        let s = c.lock();
        (s.operation, s.pmeth.as_ref().map_or(0, |m| m.get().pkey_id))
    })
}

/// `ossl_callback_to_pkey_gencb`: the provider's progress to the application's callback.
///
/// # Safety
/// `params` is a parameter array; `arg` is a live context.
unsafe extern "C" fn to_pkey_gencb(params: *const OSSL_PARAM, arg: *mut c_void) -> c_int {
    let ctx = arg.cast::<EVP_PKEY_CTX>();
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { context(ctx) }) else {
        return 0;
    };
    let Some(cb) = c.lock().pkey_gencb else {
        return 1;
    };
    let (mut p, mut n): (c_int, c_int) = (-1, -1);
    // SAFETY: the caller's array; a static key.
    let param = unsafe { OSSL_PARAM_locate_const(params, OSSL_GEN_PARAM_POTENTIAL.as_ptr()) };
    // SAFETY: a parameter of the array, or NULL.
    if param.is_null() || unsafe { OSSL_PARAM_get_int(param, &raw mut p) } == 0 {
        return 0;
    }
    // SAFETY: as above.
    let param = unsafe { OSSL_PARAM_locate_const(params, OSSL_GEN_PARAM_ITERATION.as_ptr()) };
    // SAFETY: as above.
    if param.is_null() || unsafe { OSSL_PARAM_get_int(param, &raw mut n) } == 0 {
        return 0;
    }
    c.lock().keygen_info = KeygenInfo::Own([p, n]);
    // SAFETY: the application's callback with its context; no lock is held.
    unsafe { cb(ctx) }
}

ffi_export! {
    /// Generates a key (or parameters) into `*ppkey` (a new key if NULL): 1, or <= 0 with an
    /// error.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `ppkey` is NULL or room for a pointer, holding NULL or a
    /// live key.
    pub unsafe extern "C" fn EVP_PKEY_generate(ctx: *mut EVP_PKEY_CTX, ppkey: *mut *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "EVP_PKEY_generate";
        if ppkey.is_null() {
            return -1;
        }
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else {
            err::raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE, F);
            return -2;
        };
        let (operation, km, genctx, template, libctx, propq, legacy_keytype, pm) = {
            let s = c.lock();
            (s.operation, s.keymgmt.clone(), s.genctx.0, s.pkey.clone(), s.libctx.0, s.propquery.clone(), s.legacy_keytype, s.pmeth_funcs())
        };
        if operation & EVP_PKEY_OP_TYPE_GEN == 0 {
            err::raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_INITIALIZED, F);
            return -1;
        }
        // SAFETY: the caller's guarantee.
        let mut target = unsafe { ppkey.read() };
        let mut allocated = None;
        if target.is_null() {
            target = pkey::new();
            if target.is_null() {
                err::raise(ERR_LIB_EVP, ERR_R_EVP_LIB, F);
                return -1;
            }
            // SAFETY: the caller's guarantee.
            unsafe { ppkey.write(target) };
            // SAFETY: the new key's reference.
            allocated = unsafe { PkeyRef::adopt(target) };
        }
        let (Some(km), false) = (km, genctx.is_null()) else {
            // A legacy context: its method generates.
            let ret = if template.as_ref().is_some_and(|t| t.get().is_provided()) {
                err::raise(ERR_LIB_EVP, EVP_R_INACCESSIBLE_DOMAIN_PARAMETERS, F);
                -1
            } else {
                let generate = pm.and_then(|f| if operation == EVP_PKEY_OP_PARAMGEN { f.paramgen } else { f.keygen });
                match generate {
                    // SAFETY: the method's function with the caller's context and the key.
                    Some(generate) => unsafe { generate(ctx, target) },
                    None => {
                        err::raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE, F);
                        -2
                    }
                }
            };
            if ret <= 0 {
                if let Some(a) = allocated {
                    // SAFETY: the caller's guarantee.
                    unsafe { ppkey.write(ptr::null_mut()) };
                    drop(a);
                }
            } else if let Some(a) = allocated {
                // The caller has the reference.
                a.into_raw();
            }
            return ret;
        };
        c.lock().keygen_info = KeygenInfo::Own([0, 0]);
        let mut ret = 1;
        let mut not_supported = false;
        if let Some(t) = &template {
            // SAFETY: the context's library context.
            match unsafe { pkey::export_to_any(t, libctx, Some(km.clone()), propq.as_deref()) } {
                // SAFETY: the key manager's generation context and data.
                Some((_, kd)) => ret = unsafe { km.get().gen_set_template(genctx, kd.ptr()) },
                None => not_supported = true,
            }
        }
        if !not_supported {
            // SAFETY: the caller's guarantee.
            let k = unsafe { pkey::pkey(target) };
            if ret != 0 {
                // `evp_keymgmt_util_gen`.
                // SAFETY: the key manager's generation context; the callback takes the context.
                let kd = unsafe { km.get().generate(genctx, Some(to_pkey_gencb), ctx.cast()) };
                let ok = match (KeyData::adopt(km.clone(), kd), k) {
                    (Some(kd), Some(k)) => pkey::assign(k, kd),
                    _ => false,
                };
                ret = c_int::from(ok);
            }
            c.lock().keygen_info = KeygenInfo::None(2);
            // The key gets the context's key type, whatever happened.
            if let Some(k) = k {
                k.lock().type_ = legacy_keytype;
            }
        } else {
            c.lock().keygen_info = KeygenInfo::None(2);
            err::raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE, F);
            ret = -2;
        }
        if ret <= 0 {
            if let Some(a) = allocated {
                // SAFETY: the caller's guarantee.
                unsafe { ppkey.write(ptr::null_mut()) };
                drop(a);
            }
        } else if let Some(a) = allocated {
            // The caller has the reference.
            a.into_raw();
        }
        ret
    }
}

ffi_export! {
    /// `EVP_PKEY_generate` for a parameter generation operation.
    ///
    /// # Safety
    /// As for `EVP_PKEY_generate`.
    pub unsafe extern "C" fn EVP_PKEY_paramgen(ctx: *mut EVP_PKEY_CTX, ppkey: *mut *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let op = unsafe { context(ctx) }.map(|c| c.lock().operation);
        if op != Some(EVP_PKEY_OP_PARAMGEN) {
            err::raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_INITIALIZED, "EVP_PKEY_paramgen");
            return -1;
        }
        // SAFETY: the caller's guarantee.
        unsafe { EVP_PKEY_generate(ctx, ppkey) }
    }
}

ffi_export! {
    /// `EVP_PKEY_generate` for a key generation operation.
    ///
    /// # Safety
    /// As for `EVP_PKEY_generate`.
    pub unsafe extern "C" fn EVP_PKEY_keygen(ctx: *mut EVP_PKEY_CTX, ppkey: *mut *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let op = unsafe { context(ctx) }.map(|c| c.lock().operation);
        if op != Some(EVP_PKEY_OP_KEYGEN) {
            err::raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_INITIALIZED, "EVP_PKEY_keygen");
            return -1;
        }
        // SAFETY: the caller's guarantee.
        unsafe { EVP_PKEY_generate(ctx, ppkey) }
    }
}

ffi_export! {
    /// Sets the MAC key a key generation operation gives its key: `keylen` octets of `key`.
    /// -2 with `EVP_R_COMMAND_NOT_SUPPORTED` outside key generation, 0 for a negative length.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `key` holds `keylen` octets.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_mac_key(ctx: *mut EVP_PKEY_CTX, key: *const u8, keylen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "evp_pkey_ctx_set1_octet_string";
        // SAFETY: the caller's guarantee.
        let st = unsafe { context(ctx) }.map(|c| {
            let s = c.lock();
            (s.operation, s.genctx.0.is_null())
        });
        let Some((operation, fallback)) = st.filter(|(op, _)| op & EVP_PKEY_OP_KEYGEN != 0) else {
            err::raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED, F);
            return -2;
        };
        let _ = operation;
        if fallback {
            // SAFETY: the caller's guarantee: the command's octets.
            return unsafe { ctrl::ctrl(ctx, -1, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_SET_MAC_KEY, keylen, key.cast_mut().cast()) };
        }
        let Ok(len) = usize::try_from(keylen) else {
            err::raise(ERR_LIB_EVP, EVP_R_INVALID_LENGTH, F);
            return 0;
        };
        // SAFETY: a static key; the caller's octets.
        let p = unsafe { OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY.as_ptr(), key.cast_mut().cast(), len) };
        let params = [p, end()];
        // SAFETY: the caller's context; the array above.
        unsafe { EVP_PKEY_CTX_set_params(ctx, params.as_ptr()) }
    }
}

ffi_export! {
    /// A MAC key of `type_` with the `keylen` octets of `key`, made by key generation; NULL on
    /// failure.
    ///
    /// # Safety
    /// `e` must be NULL (there are no engines); `key` holds `keylen` octets.
    pub unsafe extern "C" fn EVP_PKEY_new_mac_key(type_: c_int, e: *mut ENGINE, key: *const u8, keylen: c_int) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let c = unsafe { EVP_PKEY_CTX_new_id(type_, e) };
        if c.is_null() {
            return ptr::null_mut();
        }
        let mut k: *mut EVP_PKEY = ptr::null_mut();
        // SAFETY: the context made above.
        let _ = unsafe { EVP_PKEY_keygen_init(c) } > 0
            // SAFETY: as above; the caller's key.
            && unsafe { EVP_PKEY_CTX_set_mac_key(c, key, keylen) } > 0
            // SAFETY: as above; the local.
            && unsafe { EVP_PKEY_keygen(c, &raw mut k) } > 0;
        // SAFETY: made above.
        unsafe { EVP_PKEY_CTX_free(c) };
        k
    }
}

/// `evp_pkey_keygen` and `EVP_PKEY_Q_keygen`: a key of type `name` generated with `params`.
///
/// # Safety
/// `libctx` is NULL or a live library context; `params` is an array.
pub(crate) unsafe fn quick_keygen(
    libctx: *mut OSSL_LIB_CTX,
    name: *const c_char,
    propq: *const c_char,
    params: *const OSSL_PARAM,
) -> *mut EVP_PKEY {
    let mut k: *mut EVP_PKEY = ptr::null_mut();
    // SAFETY: the caller's guarantee.
    let c = unsafe { EVP_PKEY_CTX_new_from_name(libctx, name, propq) };
    // SAFETY: the context made above (or NULL, checked).
    if !c.is_null() && unsafe { EVP_PKEY_keygen_init(c) } > 0
        // SAFETY: as above; the caller's array.
        && unsafe { EVP_PKEY_CTX_set_params(c, params) } != 0
    {
        // SAFETY: as above.
        unsafe { EVP_PKEY_generate(c, &raw mut k) };
    }
    // SAFETY: made above, or NULL.
    unsafe { EVP_PKEY_CTX_free(c) };
    k
}

/// Generates a key of `type_`: an RSA key of the `size_t` bits that follow, an EC key on the
/// group named by the string that follows, or another type's key without arguments.
///
/// # Safety
/// `libctx` is NULL or a live library context; `propq` is NULL or a string; `type_` is a
/// string; the arguments are as the type needs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_PKEY_Q_keygen(
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
    type_: *const c_char,
    args: ...
) -> *mut EVP_PKEY {
    crate::ffi::guard(ERR_LIB_EVP, "EVP_PKEY_Q_keygen", ptr::null_mut, move || {
        let mut args = args;
        // SAFETY: the caller's guarantee.
        let Some(t) = (unsafe { text(type_) }) else {
            return ptr::null_mut();
        };
        let mut bits: usize = 0;
        let mut params = [end(), end()];
        if t.to_bytes().eq_ignore_ascii_case(b"RSA") {
            // SAFETY: the caller's guarantee: a `size_t` follows.
            bits = unsafe { args.next_arg::<usize>() };
            // SAFETY: a static key; the local value.
            params[0] = unsafe {
                crate::params::OSSL_PARAM_construct_size_t(
                    rustyssl_abi::OSSL_PKEY_PARAM_RSA_BITS.as_ptr(),
                    &raw mut bits,
                )
            };
        } else if t.to_bytes().eq_ignore_ascii_case(b"EC") {
            // SAFETY: the caller's guarantee: a string follows.
            let name = unsafe { args.next_arg::<*mut c_char>() };
            // SAFETY: a static key; the caller's string.
            params[0] = unsafe {
                crate::params::OSSL_PARAM_construct_utf8_string(
                    rustyssl_abi::OSSL_PKEY_PARAM_GROUP_NAME.as_ptr(),
                    name,
                    0,
                )
            };
        }
        // SAFETY: the caller's guarantee; the array above.
        let k = unsafe { quick_keygen(libctx, type_, propq, params.as_ptr()) };
        let _ = bits;
        k
    })
}

/// `fromdata_init`: starts making keys from parameters. 1, or -2 with an error.
///
/// # Safety
/// `ctx` is NULL or a live context.
unsafe fn fromdata_init(ctx: *mut EVP_PKEY_CTX, operation: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { context(ctx) }) else {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
            "fromdata_init",
        );
        return -2;
    };
    let mut s = c.lock();
    if s.keytype.is_some() {
        s.free_old_ops();
        if s.keymgmt.is_some() {
            s.operation = operation;
            return 1;
        }
    }
    s.operation = EVP_PKEY_OP_UNDEFINED;
    drop(s);
    err::raise(
        ERR_LIB_EVP,
        EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
        "fromdata_init",
    );
    -2
}

ffi_export! {
    /// Starts making keys from parameters (`EVP_PKEY_fromdata`).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_fromdata_init(ctx: *mut EVP_PKEY_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { fromdata_init(ctx, EVP_PKEY_OP_FROMDATA) }
    }
}

ffi_export! {
    /// Makes a key into `*ppkey` (a new one if NULL) from the selected parts in `params`: 1, 0
    /// if the key manager refuses them, or -2/-1 with an error.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `ppkey` is NULL or room for a pointer, holding NULL or a
    /// live key; `params` is NULL or an array.
    pub unsafe extern "C" fn EVP_PKEY_fromdata(ctx: *mut EVP_PKEY_CTX, ppkey: *mut *mut EVP_PKEY, selection: c_int, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "EVP_PKEY_fromdata";
        // SAFETY: the caller's guarantee.
        let st = unsafe { context(ctx) }.map(|c| {
            let s = c.lock();
            (s.operation, s.keymgmt.clone())
        });
        let Some((_, Some(km))) = st.filter(|(op, _)| op & EVP_PKEY_OP_FROMDATA != 0) else {
            err::raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE, F);
            return -2;
        };
        if ppkey.is_null() {
            return -1;
        }
        // SAFETY: the caller's guarantee.
        let mut target = unsafe { ppkey.read() };
        let mut allocated = None;
        if target.is_null() {
            target = pkey::new();
            if target.is_null() {
                err::raise(ERR_LIB_EVP, ERR_R_EVP_LIB, F);
                return -1;
            }
            // SAFETY: the new key's reference.
            allocated = unsafe { PkeyRef::adopt(target) };
        }
        // `evp_keymgmt_util_fromdata`.
        let m = km.get();
        let kd = m.newdata();
        // SAFETY: the key manager's new data; the caller's array.
        let ok = !kd.is_null() && unsafe { m.import(kd, selection, params) } != 0;
        let ok = if ok {
            // SAFETY: the caller's key, or the new one.
            match (KeyData::adopt(km.clone(), kd), unsafe { pkey::pkey(target) }) {
                (Some(d), Some(k)) => pkey::assign(k, d),
                _ => false,
            }
        } else {
            // SAFETY: the key manager's data, freed once (NULL is fine).
            unsafe { m.freedata(kd) };
            false
        };
        if !ok {
            return 0;
        }
        if let Some(a) = allocated {
            // SAFETY: the caller's guarantee.
            unsafe { ppkey.write(a.into_raw()) };
        }
        1
    }
}

ffi_export! {
    /// The parameters `EVP_PKEY_fromdata` takes for the selection (the key manager's import
    /// types), or NULL. It ends the context's operation, as OpenSSL's does.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_fromdata_settable(ctx: *mut EVP_PKEY_CTX, selection: c_int) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if unsafe { fromdata_init(ctx, EVP_PKEY_OP_UNDEFINED) } != 1 {
            return ptr::null();
        }
        // SAFETY: as above.
        let km = unsafe { context(ctx) }.and_then(|c| c.lock().keymgmt.clone());
        km.map_or(ptr::null(), |m| m.get().import_types(selection))
    }
}

// -------------------------------------------------------------------------------------------
// Checks (pmeth_check.c)

/// `try_provided_check`: the key manager's validation of the context's key (exported to the
/// context's key manager), or 0 with `EVP_R_INITIALIZATION_ERROR` if it can't be exported;
/// `None` for a legacy context.
fn provided_check(
    c: &PkeyCtx,
    pkey: &PkeyRef,
    selection: c_int,
    checktype: c_int,
) -> Option<c_int> {
    let (km, libctx, propq) = {
        let s = c.lock();
        (s.keymgmt.clone(), s.libctx.0, s.propquery.clone())
    };
    km.as_ref()?;
    // SAFETY: the context's library context.
    let Some((km, kd)) = (unsafe { pkey::export_to_any(pkey, libctx, km, propq.as_deref()) })
    else {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_INITIALIZATION_ERROR,
            "try_provided_check",
        );
        return Some(0);
    };
    // SAFETY: the key manager's data.
    Some(unsafe { km.get().validate(kd.ptr(), selection, checktype) })
}

/// A legacy context's check of its key: the method's check, else the key's ASN.1 method's;
/// -2 with an error without either (and always for the private key, which they can't check).
fn legacy_check(c: &PkeyCtx, pkey: &PkeyRef, selection: c_int, function: &str) -> c_int {
    let k = pkey.get();
    let pm = c.lock().pmeth_funcs();
    let am = k.ameth_funcs();
    let (own, key): (Option<pmeth::Check>, Option<pkey::ameth::KeyFn>) = match selection {
        OSSL_KEYMGMT_SELECT_KEYPAIR => (pm.and_then(|f| f.check), am.and_then(|f| f.pkey_check)),
        OSSL_KEYMGMT_SELECT_PUBLIC_KEY => (
            pm.and_then(|f| f.public_check),
            am.and_then(|f| f.pkey_public_check),
        ),
        OSSL_KEYMGMT_SELECT_ALL_PARAMETERS => (
            pm.and_then(|f| f.param_check),
            am.and_then(|f| f.pkey_param_check),
        ),
        _ => (None, None),
    };
    if k.type_() != rustyssl_abi::EVP_PKEY_NONE {
        if let Some(f) = own {
            // SAFETY: the method's function with the context's key.
            return unsafe { f(pkey.as_ptr()) };
        }
        if let Some(f) = key {
            // SAFETY: the key's method's function with the key.
            return unsafe { f(pkey.as_ptr()) };
        }
    }
    err::raise(
        ERR_LIB_EVP,
        EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
        function,
    );
    -2
}

/// The checks' common part: 0 with `EVP_R_NO_KEY_SET` without a key.
///
/// # Safety
/// `ctx` is NULL or a live context.
unsafe fn check(
    ctx: *mut EVP_PKEY_CTX,
    selection: c_int,
    checktype: c_int,
    function: &str,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { context(ctx) }) else {
        return 0;
    };
    let Some(k) = c.lock().pkey.clone() else {
        err::raise(ERR_LIB_EVP, EVP_R_NO_KEY_SET, function);
        return 0;
    };
    provided_check(c, &k, selection, checktype)
        .unwrap_or_else(|| legacy_check(c, &k, selection, function))
}

ffi_export! {
    /// Checks the key pair (`EVP_PKEY_pairwise_check`).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_check(ctx: *mut EVP_PKEY_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { check(ctx, OSSL_KEYMGMT_SELECT_KEYPAIR, OSSL_KEYMGMT_VALIDATE_FULL_CHECK, "EVP_PKEY_pairwise_check") }
    }
}

ffi_export! {
    /// Checks the key pair: 1 if valid, 0 if not, -2 if it can't be checked.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_pairwise_check(ctx: *mut EVP_PKEY_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { check(ctx, OSSL_KEYMGMT_SELECT_KEYPAIR, OSSL_KEYMGMT_VALIDATE_FULL_CHECK, "EVP_PKEY_pairwise_check") }
    }
}

ffi_export! {
    /// Checks the public key fully.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_public_check(ctx: *mut EVP_PKEY_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { check(ctx, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_KEYMGMT_VALIDATE_FULL_CHECK, "evp_pkey_public_check_combined") }
    }
}

ffi_export! {
    /// Checks the public key quickly.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_public_check_quick(ctx: *mut EVP_PKEY_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { check(ctx, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_KEYMGMT_VALIDATE_QUICK_CHECK, "evp_pkey_public_check_combined") }
    }
}

ffi_export! {
    /// Checks the parameters fully.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_param_check(ctx: *mut EVP_PKEY_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { check(ctx, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, OSSL_KEYMGMT_VALIDATE_FULL_CHECK, "evp_pkey_param_check_combined") }
    }
}

ffi_export! {
    /// Checks the parameters quickly.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_param_check_quick(ctx: *mut EVP_PKEY_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { check(ctx, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, OSSL_KEYMGMT_VALIDATE_QUICK_CHECK, "evp_pkey_param_check_combined") }
    }
}

ffi_export! {
    /// Checks the private key.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_private_check(ctx: *mut EVP_PKEY_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { check(ctx, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_VALIDATE_FULL_CHECK, "EVP_PKEY_private_check") }
    }
}

/// `EVP_PKEY_KEYPAIR`, as an `int` selection.
pub(crate) const KEYPAIR: c_int = EVP_PKEY_KEYPAIR as c_int;

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: a NULL context is refused (the reference crashes).
    #[test]
    fn null_contexts_are_refused() {
        let c: *mut EVP_PKEY_CTX = ptr::null_mut();
        // SAFETY: NULL is the case under test, here and below.
        assert!(unsafe { EVP_PKEY_CTX_dup(c) }.is_null());
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_CTX_is_a(c, c"HMAC".as_ptr()) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_CTX_get_operation(c) }, 0);
        // SAFETY: as above.
        assert!(unsafe { EVP_PKEY_CTX_get0_propq(c) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { EVP_PKEY_CTX_get0_pkey(c) }.is_null());
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_CTX_get_keygen_info(c, -1) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_CTX_set_params(c, ptr::null()) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_CTX_set_mac_key(c, ptr::null(), 0) }, -2);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_keygen(c, ptr::null_mut()) }, -1);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_paramgen_init(c) }, -2);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_check(c) }, 0);
        // SAFETY: as above.
        assert!(unsafe { EVP_PKEY_fromdata_settable(c, 0) }.is_null());
        // SAFETY: as above.
        unsafe { EVP_PKEY_CTX_set_app_data(c, ptr::null_mut()) };
        crate::err::take_all();
    }
}
