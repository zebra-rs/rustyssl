//! Cipher methods (`EVP_CIPHER_fetch(3)`, `EVP_EncryptInit(3)`'s method functions): an
//! `EVP_CIPHER` made from a provider's cipher algorithm (`evp_cipher_from_algorithm` in
//! `crypto/evp/evp_enc.c`), fetched by name and properties, and its names, provider, lengths,
//! flags, and parameters (`evp_lib.c`).
//!
//! As in OpenSSL, a cipher algorithm must offer `newctx` and `freectx`, and a complete set of
//! encrypting or decrypting functions (an init with `update` and `final`), or `cipher` alone,
//! or the pipeline functions; its block size, IV and key lengths, mode, and flags are read
//! from its parameters when it's made, and its NID from the legacy cipher its names map to
//! (`set_legacy_nid`). The static legacy ciphers (`EVP_aes_128_cbc()`, `legacy_cipher.rs`)
//! are methods too, without a provider and with references that aren't counted, as OpenSSL's
//! `EVP_ORIG_GLOBAL` ones, and so are the ciphers applications make (`EVP_CIPHER_meth_new(3)`,
//! `cipher_meth.rs`; `EVP_ORIG_METH`), whose lengths, flags, and C functions are set after
//! they're made.

use core::ffi::{CStr, c_char, c_int, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::ffi::CString;
use std::sync::{Mutex, PoisonError};

use rustyssl_abi::{
    ERR_LIB_EVP, ERR_R_EVP_LIB, ERR_R_INTERNAL_ERROR, EVP_CIPH_CUSTOM_IV,
    EVP_CIPH_FLAG_AEAD_CIPHER, EVP_CIPH_FLAG_CTS, EVP_CIPH_FLAG_CUSTOM_ASN1,
    EVP_CIPH_FLAG_CUSTOM_CIPHER, EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK, EVP_CIPH_MODE, EVP_CIPH_RAND_KEY,
    EVP_CIPHER, EVP_R_CACHE_CONSTANTS_FAILED, EVP_R_CANNOT_GET_PARAMETERS,
    EVP_R_INVALID_PROVIDER_FUNCTIONS, NID_aes_128_cfb1, NID_aes_128_cfb8, NID_aes_128_cfb128,
    NID_aes_192_cfb1, NID_aes_192_cfb8, NID_aes_192_cfb128, NID_aes_256_cfb1, NID_aes_256_cfb8,
    NID_aes_256_cfb128, NID_des_cfb1, NID_des_cfb8, NID_des_cfb64, NID_des_ede3_cfb1,
    NID_des_ede3_cfb8, NID_des_ede3_cfb64, NID_rc2_40_cbc, NID_rc2_64_cbc, NID_rc2_cbc, NID_rc4,
    NID_rc4_40, NID_undef, OBJ_NAME_TYPE_CIPHER_METH, OSSL_ALGORITHM, OSSL_CIPHER_PARAM_AEAD,
    OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS, OSSL_CIPHER_PARAM_BLOCK_SIZE, OSSL_CIPHER_PARAM_CTS,
    OSSL_CIPHER_PARAM_CUSTOM_IV, OSSL_CIPHER_PARAM_HAS_RAND_KEY, OSSL_CIPHER_PARAM_IVLEN,
    OSSL_CIPHER_PARAM_KEYLEN, OSSL_CIPHER_PARAM_MODE, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK,
    OSSL_FUNC_CIPHER_CIPHER, OSSL_FUNC_CIPHER_DECRYPT_INIT, OSSL_FUNC_CIPHER_DECRYPT_SKEY_INIT,
    OSSL_FUNC_CIPHER_DUPCTX, OSSL_FUNC_CIPHER_ENCRYPT_INIT, OSSL_FUNC_CIPHER_ENCRYPT_SKEY_INIT,
    OSSL_FUNC_CIPHER_FINAL, OSSL_FUNC_CIPHER_FREECTX, OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
    OSSL_FUNC_CIPHER_GET_PARAMS, OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
    OSSL_FUNC_CIPHER_GETTABLE_PARAMS, OSSL_FUNC_CIPHER_NEWCTX,
    OSSL_FUNC_CIPHER_PIPELINE_DECRYPT_INIT, OSSL_FUNC_CIPHER_PIPELINE_ENCRYPT_INIT,
    OSSL_FUNC_CIPHER_PIPELINE_FINAL, OSSL_FUNC_CIPHER_PIPELINE_UPDATE,
    OSSL_FUNC_CIPHER_SET_CTX_PARAMS, OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, OSSL_FUNC_CIPHER_UPDATE,
    OSSL_LIB_CTX, OSSL_OP_CIPHER, OSSL_PARAM, OSSL_PROVIDER,
};

use super::fetch::{self, Kind};
use crate::err;
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::params::{OSSL_PARAM_locate_const, construct, end};
use crate::provider::Ptr;

type GetParamsFn = unsafe extern "C" fn(*mut OSSL_PARAM) -> c_int;
type GettableParamsFn = unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM;
type AnyFn = unsafe extern "C" fn();
pub(crate) type NewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
pub(crate) type InitFn = unsafe extern "C" fn(
    *mut c_void,
    *const u8,
    usize,
    *const u8,
    usize,
    *const OSSL_PARAM,
) -> c_int;
pub(crate) type SkeyInitFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *const u8, usize, *const OSSL_PARAM) -> c_int;
pub(crate) type UpdateFn =
    unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, usize, *const u8, usize) -> c_int;
pub(crate) type FinalFn = unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, usize) -> c_int;
pub(crate) type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
pub(crate) type DupCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
pub(crate) type SetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
pub(crate) type GetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
pub(crate) type CtxParamsListFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;

/// A cipher algorithm's context functions, as its dispatch table gave them.
#[derive(Default, Clone, Copy)]
pub(crate) struct Funcs {
    pub(crate) newctx: Option<NewCtxFn>,
    pub(crate) einit: Option<InitFn>,
    pub(crate) dinit: Option<InitFn>,
    pub(crate) einit_skey: Option<SkeyInitFn>,
    pub(crate) dinit_skey: Option<SkeyInitFn>,
    pub(crate) cupdate: Option<UpdateFn>,
    pub(crate) cfinal: Option<FinalFn>,
    pub(crate) ccipher: Option<UpdateFn>,
    pub(crate) freectx: Option<FreeCtxFn>,
    pub(crate) dupctx: Option<DupCtxFn>,
    pub(crate) get_ctx_params: Option<GetCtxParamsFn>,
    pub(crate) set_ctx_params: Option<SetCtxParamsFn>,
    pub(crate) gettable_ctx_params: Option<CtxParamsListFn>,
    pub(crate) settable_ctx_params: Option<CtxParamsListFn>,
    /// The pipeline functions (a later step), which only `EVP_CIPHER_can_pipeline` looks at.
    pub(crate) p_einit: Option<AnyFn>,
    pub(crate) p_dinit: Option<AnyFn>,
    pub(crate) p_cupdate: Option<AnyFn>,
    pub(crate) p_cfinal: Option<AnyFn>,
}

/// Where a cipher method came from (`EVP_ORIG_*`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    /// Fetched from a provider, reference counted.
    Dynamic,
    /// One of the static legacy ciphers (`EVP_aes_128_cbc()`): references aren't counted.
    Global,
    /// Made by an application (`EVP_CIPHER_meth_new`): references aren't counted, and
    /// `EVP_CIPHER_meth_free` frees it.
    Meth,
}

/// A legacy cipher's `init`: the context, key, IV, and direction.
pub(crate) type LegacyInitFn =
    unsafe extern "C" fn(*mut rustyssl_abi::EVP_CIPHER_CTX, *const u8, *const u8, c_int) -> c_int;
/// A legacy cipher's `do_cipher`.
pub(crate) type LegacyDoCipherFn =
    unsafe extern "C" fn(*mut rustyssl_abi::EVP_CIPHER_CTX, *mut u8, *const u8, usize) -> c_int;
/// A legacy cipher's `cleanup`.
pub(crate) type LegacyCleanupFn = unsafe extern "C" fn(*mut rustyssl_abi::EVP_CIPHER_CTX) -> c_int;
/// A legacy cipher's `set_asn1_parameters` and `get_asn1_parameters`.
pub(crate) type LegacyAsn1Fn =
    unsafe extern "C" fn(*mut rustyssl_abi::EVP_CIPHER_CTX, *mut rustyssl_abi::ASN1_TYPE) -> c_int;
/// A legacy cipher's `ctrl`.
pub(crate) type LegacyCtrlFn =
    unsafe extern "C" fn(*mut rustyssl_abi::EVP_CIPHER_CTX, c_int, c_int, *mut c_void) -> c_int;

/// A cipher's C functions and the size of their state (`cipher_data`), as OpenSSL's
/// `EVP_CIPHER` holds them.
#[derive(Default, Clone, Copy)]
pub(crate) struct Legacy {
    pub(crate) ctx_size: c_int,
    pub(crate) init: Option<LegacyInitFn>,
    pub(crate) do_cipher: Option<LegacyDoCipherFn>,
    pub(crate) cleanup: Option<LegacyCleanupFn>,
    pub(crate) set_asn1: Option<LegacyAsn1Fn>,
    pub(crate) get_asn1: Option<LegacyAsn1Fn>,
    pub(crate) ctrl: Option<LegacyCtrlFn>,
}

/// The lengths and flags `EVP_CIPHER_meth_set_*` set once.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Field {
    IvLen,
    Flags,
}

/// A cipher method (`EVP_CIPHER`): made from a provider's algorithm, or a static legacy one.
pub(crate) struct Cipher {
    pub(crate) origin: Origin,
    name_id: u32,
    /// The first name, for fetched methods; a static one's is its NID's short name.
    type_name: Option<CString>,
    /// The provider's description, a static string of its, or NULL.
    description: Ptr<c_char>,
    /// The provider, with a reference.
    pub(crate) prov: Ptr<OSSL_PROVIDER>,
    pub(crate) nid: c_int,
    block_size: AtomicI32,
    key_len: AtomicI32,
    iv_len: AtomicI32,
    flags: AtomicU64,
    /// The C functions (`EVP_CIPHER_meth_set_*` sets an application's).
    legacy: Mutex<Legacy>,
    get_params: Option<GetParamsFn>,
    gettable_params: Option<GettableParamsFn>,
    /// The context functions.
    pub(crate) funcs: Funcs,
}

impl Cipher {
    /// A static legacy cipher: no provider, the NID, lengths, and flags of OpenSSL's
    /// `EVP_aes_128_cbc()`-style definitions.
    pub(crate) fn legacy(
        nid: c_int,
        block_size: c_int,
        key_len: c_int,
        iv_len: c_int,
        flags: c_ulong,
    ) -> Self {
        Self {
            origin: Origin::Global,
            name_id: 0,
            type_name: None,
            description: Ptr(ptr::null_mut()),
            prov: Ptr(ptr::null_mut()),
            nid,
            block_size: AtomicI32::new(block_size),
            key_len: AtomicI32::new(key_len),
            iv_len: AtomicI32::new(iv_len),
            flags: AtomicU64::new(flags),
            legacy: Mutex::new(Legacy::default()),
            get_params: None,
            gettable_params: None,
            funcs: Funcs::default(),
        }
    }

    /// An application's cipher (`EVP_CIPHER_meth_new`), or a copy of `from`
    /// (`EVP_CIPHER_meth_dup`).
    pub(crate) fn meth(nid: c_int, block_size: c_int, key_len: c_int, from: Option<&Self>) -> Self {
        let mut c = Self::legacy(nid, block_size, key_len, 0, 0);
        c.origin = Origin::Meth;
        if let Some(f) = from {
            c.iv_len = AtomicI32::new(f.iv_len());
            c.flags = AtomicU64::new(f.flags());
            c.legacy = Mutex::new(f.legacy_fns());
            c.description = Ptr(f.description.0);
        }
        c
    }

    /// The block size.
    pub(crate) fn block_size(&self) -> c_int {
        self.block_size.load(Ordering::Relaxed)
    }

    /// The key length.
    pub(crate) fn key_len(&self) -> c_int {
        self.key_len.load(Ordering::Relaxed)
    }

    /// The IV length.
    pub(crate) fn iv_len(&self) -> c_int {
        self.iv_len.load(Ordering::Relaxed)
    }

    /// The flags (mode included).
    pub(crate) fn flags(&self) -> c_ulong {
        self.flags.load(Ordering::Relaxed)
    }

    /// The C functions, as they are now.
    pub(crate) fn legacy_fns(&self) -> Legacy {
        *self.legacy.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Changes the C functions (an application's cipher only).
    pub(crate) fn set_legacy(&self, change: impl FnOnce(&mut Legacy) -> bool) -> bool {
        change(&mut self.legacy.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// `EVP_CIPHER_meth_set_iv_length` or `_set_flags`: sets `field` if it is still 0.
    pub(crate) fn set_once(&self, field: Field, value: u64) -> bool {
        match field {
            Field::IvLen => {
                let Ok(v) = c_int::try_from(i64::from_ne_bytes(value.to_ne_bytes())) else {
                    return false;
                };
                self.iv_len
                    .compare_exchange(0, v, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
            }
            Field::Flags => self
                .flags
                .compare_exchange(0, value, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok(),
        }
    }

    /// The provider's context, which the parameter-list functions take.
    pub(crate) fn provider_ctx(&self) -> *mut c_void {
        if self.prov.0.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the method holds a reference to its live provider.
        unsafe { crate::provider::OSSL_PROVIDER_get0_provider_ctx(self.prov.0) }
    }
}

handle_type!(EVP_CIPHER => Cipher);

impl Drop for Cipher {
    fn drop(&mut self) {
        // SAFETY: the provider reference the method holds.
        unsafe { OSSL_PROVIDER::free(self.prov.0) };
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

/// An `EVP_CIPH_*` flag as the flags' type.
const fn flag(f: c_int) -> c_ulong {
    f.cast_unsigned() as c_ulong
}

/// `evp_cipher_cache_constants`: reads the lengths, mode, and flags. False if that fails.
fn cache_constants(c: &mut Cipher) -> bool {
    let (mut blksz, mut ivlen, mut keylen): (usize, usize, usize) = (0, 0, 0);
    let mut mode: core::ffi::c_uint = 0;
    let (mut aead, mut custom_iv, mut cts, mut multiblock, mut randkey): (
        c_int,
        c_int,
        c_int,
        c_int,
        c_int,
    ) = (0, 0, 0, 0, 0);
    let size = |key: &'static CStr, v: *mut usize| {
        construct(
            key.as_ptr(),
            rustyssl_crypto::params::UNSIGNED_INTEGER,
            v.cast(),
            size_of::<usize>(),
        )
    };
    let int = |key: &'static CStr, v: *mut c_int| {
        construct(
            key.as_ptr(),
            rustyssl_crypto::params::INTEGER,
            v.cast(),
            size_of::<c_int>(),
        )
    };
    let mut params = [
        size(OSSL_CIPHER_PARAM_BLOCK_SIZE, &raw mut blksz),
        size(OSSL_CIPHER_PARAM_IVLEN, &raw mut ivlen),
        size(OSSL_CIPHER_PARAM_KEYLEN, &raw mut keylen),
        construct(
            OSSL_CIPHER_PARAM_MODE.as_ptr(),
            rustyssl_crypto::params::UNSIGNED_INTEGER,
            (&raw mut mode).cast(),
            size_of::<core::ffi::c_uint>(),
        ),
        int(OSSL_CIPHER_PARAM_AEAD, &raw mut aead),
        int(OSSL_CIPHER_PARAM_CUSTOM_IV, &raw mut custom_iv),
        int(OSSL_CIPHER_PARAM_CTS, &raw mut cts),
        int(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, &raw mut multiblock),
        int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, &raw mut randkey),
        end(),
    ];
    // `evp_do_ciph_getparams`.
    let ok = match c.get_params {
        // SAFETY: the provider's function with the array.
        Some(get) => (unsafe { get(params.as_mut_ptr()) }) > 0,
        None => {
            err::raise(
                ERR_LIB_EVP,
                EVP_R_CANNOT_GET_PARAMETERS,
                "evp_do_ciph_getparams",
            );
            false
        }
    };
    if !ok {
        return false;
    }
    let (Ok(b), Ok(i), Ok(k)) = (
        c_int::try_from(blksz),
        c_int::try_from(ivlen),
        c_int::try_from(keylen),
    ) else {
        return false;
    };
    c.block_size = AtomicI32::new(b);
    c.iv_len = AtomicI32::new(i);
    c.key_len = AtomicI32::new(k);
    let mut flags = c_ulong::from(mode);
    for (on, f) in [
        (aead != 0, EVP_CIPH_FLAG_AEAD_CIPHER),
        (custom_iv != 0, EVP_CIPH_CUSTOM_IV),
        (cts != 0, EVP_CIPH_FLAG_CTS),
        (multiblock != 0, EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK),
        (c.funcs.ccipher.is_some(), EVP_CIPH_FLAG_CUSTOM_CIPHER),
        (randkey != 0, EVP_CIPH_RAND_KEY),
    ] {
        if on {
            flags |= flag(f);
        }
    }
    if let Some(list) = c.funcs.gettable_ctx_params {
        // SAFETY: the provider's function with no context and its own context.
        let gettable = unsafe { list(ptr::null_mut(), c.provider_ctx()) };
        let key = OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS.as_ptr();
        // SAFETY: the provider's list, or NULL.
        if !unsafe { OSSL_PARAM_locate_const(gettable, key) }.is_null() {
            flags |= flag(EVP_CIPH_FLAG_CUSTOM_ASN1);
        }
    }
    c.flags = AtomicU64::new(flags);
    true
}

/// `set_legacy_nid` over each of the algorithm's names: the NID of the legacy cipher any of
/// them has, 0 for none, `None` for a clash between two.
fn legacy_nid(prov: *const OSSL_PROVIDER, name_id: u32) -> Option<c_int> {
    let mut nid = NID_undef;
    for n in fetch::names_of(prov, name_id) {
        let Ok(c) = CString::new(n) else { continue };
        // SAFETY: a string and a type.
        let legacy =
            unsafe { crate::objects::name::OBJ_NAME_get(c.as_ptr(), OBJ_NAME_TYPE_CIPHER_METH) };
        // SAFETY: the table holds cipher methods for this type.
        let Some(m) = (unsafe { method(legacy.cast()) }) else {
            continue;
        };
        if nid != NID_undef && nid != m.nid {
            return None;
        }
        nid = m.nid;
    }
    Some(nid)
}

/// `evp_cipher_from_algorithm`: a cipher method from the provider's algorithm, with one
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
    let Some(nid) = legacy_nid(prov, name_id) else {
        err::raise(
            ERR_LIB_EVP,
            ERR_R_INTERNAL_ERROR,
            "evp_cipher_from_algorithm",
        );
        return ptr::null_mut();
    };
    // SAFETY: the caller's guarantee.
    let names = unsafe { CStr::from_ptr(algo.algorithm_names) }.to_bytes();
    let first = names.split(|&c| c == b':').next().unwrap_or(names);
    let Ok(type_name) = CString::new(first) else {
        err::raise(ERR_LIB_EVP, ERR_R_EVP_LIB, "evp_cipher_from_algorithm");
        return ptr::null_mut();
    };
    let mut funcs = Funcs::default();
    let mut get_params_fn = None;
    let mut gettable_params = None;
    let (mut fnciphcnt, mut encinit, mut decinit, mut fnpipecnt, mut fnctxcnt) =
        (0u32, 0u32, 0u32, 0u32, 0u32);
    let mut at = algo.implementation;
    // SAFETY: the caller's guarantee: the table is ended by a zero id.
    while let Some(d) = unsafe { at.as_ref() } {
        if d.function_id == 0 {
            break;
        }
        at = at.wrapping_add(1);
        let Some(f) = d.function else { continue };
        /// Stores `f` as the function its id stands for, if it's the first of its id, and
        /// evaluates to whether it was.
        macro_rules! set {
            ($field:expr) => {
                if $field.is_none() {
                    // SAFETY: the provider's guarantee of the function type for this id.
                    $field = Some(unsafe { cast(f) });
                    true
                } else {
                    false
                }
            };
        }
        match d.function_id {
            OSSL_FUNC_CIPHER_NEWCTX => fnctxcnt += u32::from(set!(funcs.newctx)),
            OSSL_FUNC_CIPHER_ENCRYPT_INIT => {
                if set!(funcs.einit) {
                    encinit = 1;
                }
            }
            OSSL_FUNC_CIPHER_DECRYPT_INIT => {
                if set!(funcs.dinit) {
                    decinit = 1;
                }
            }
            OSSL_FUNC_CIPHER_ENCRYPT_SKEY_INIT => {
                if set!(funcs.einit_skey) {
                    encinit = 1;
                }
            }
            OSSL_FUNC_CIPHER_DECRYPT_SKEY_INIT => {
                if set!(funcs.dinit_skey) {
                    decinit = 1;
                }
            }
            OSSL_FUNC_CIPHER_UPDATE => fnciphcnt += u32::from(set!(funcs.cupdate)),
            OSSL_FUNC_CIPHER_FINAL => fnciphcnt += u32::from(set!(funcs.cfinal)),
            OSSL_FUNC_CIPHER_CIPHER => {
                set!(funcs.ccipher);
            }
            OSSL_FUNC_CIPHER_PIPELINE_ENCRYPT_INIT => fnpipecnt += u32::from(set!(funcs.p_einit)),
            OSSL_FUNC_CIPHER_PIPELINE_DECRYPT_INIT => fnpipecnt += u32::from(set!(funcs.p_dinit)),
            OSSL_FUNC_CIPHER_PIPELINE_UPDATE => fnpipecnt += u32::from(set!(funcs.p_cupdate)),
            OSSL_FUNC_CIPHER_PIPELINE_FINAL => fnpipecnt += u32::from(set!(funcs.p_cfinal)),
            OSSL_FUNC_CIPHER_FREECTX => fnctxcnt += u32::from(set!(funcs.freectx)),
            OSSL_FUNC_CIPHER_DUPCTX => {
                set!(funcs.dupctx);
            }
            OSSL_FUNC_CIPHER_GET_PARAMS => {
                set!(get_params_fn);
            }
            OSSL_FUNC_CIPHER_GET_CTX_PARAMS => {
                set!(funcs.get_ctx_params);
            }
            OSSL_FUNC_CIPHER_SET_CTX_PARAMS => {
                set!(funcs.set_ctx_params);
            }
            OSSL_FUNC_CIPHER_GETTABLE_PARAMS => {
                set!(gettable_params);
            }
            OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS => {
                set!(funcs.gettable_ctx_params);
            }
            OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS => {
                set!(funcs.settable_ctx_params);
            }
            _ => {}
        }
    }
    let fnciphcnt = fnciphcnt.saturating_add(encinit).saturating_add(decinit);
    if (fnciphcnt != 0 && fnciphcnt != 3 && fnciphcnt != 4)
        || (fnciphcnt == 0 && funcs.ccipher.is_none() && fnpipecnt == 0)
        || (fnpipecnt != 0
            && (fnpipecnt < 3 || funcs.p_cupdate.is_none() || funcs.p_cfinal.is_none()))
        || fnctxcnt != 2
    {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_INVALID_PROVIDER_FUNCTIONS,
            "evp_cipher_from_algorithm",
        );
        return ptr::null_mut();
    }
    // SAFETY: the caller's live provider; the method holds the reference.
    if !unsafe { OSSL_PROVIDER::up_ref(prov) } {
        return ptr::null_mut();
    }
    let mut c = Cipher {
        origin: Origin::Dynamic,
        name_id,
        type_name: Some(type_name),
        description: Ptr(algo.algorithm_description.cast_mut()),
        prov: Ptr(prov),
        nid,
        block_size: AtomicI32::new(0),
        key_len: AtomicI32::new(0),
        iv_len: AtomicI32::new(0),
        flags: AtomicU64::new(0),
        legacy: Mutex::new(Legacy::default()),
        get_params: get_params_fn,
        gettable_params,
        funcs,
    };
    if !cache_constants(&mut c) {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_CACHE_CONSTANTS_FAILED,
            "evp_cipher_from_algorithm",
        );
        return ptr::null_mut();
    }
    EVP_CIPHER::new_handle(c).cast()
}

/// Adds a reference to a cipher method in a store.
unsafe fn up_ref(c: *mut c_void) {
    // SAFETY: a live method.
    unsafe { EVP_CIPHER::up_ref(c.cast()) };
}

/// Drops a reference to a cipher method in a store.
unsafe fn free(c: *mut c_void) {
    // SAFETY: a reference the store held.
    unsafe { EVP_CIPHER::free(c.cast()) };
}

/// Cipher methods to fetching.
static CIPHERS: Kind = Kind {
    operation: OSSL_OP_CIPHER,
    from_algorithm,
    up_ref,
    free,
};

/// The method behind `cipher`, or `None` for NULL.
///
/// # Safety
/// `cipher` is NULL or a live cipher method.
pub(crate) unsafe fn method<'a>(cipher: *const EVP_CIPHER) -> Option<&'a Cipher> {
    // SAFETY: the caller's guarantee.
    unsafe { EVP_CIPHER::get(cipher) }
}

/// A C string argument, `None` for NULL.
///
/// # Safety
/// `s` is NULL or a string.
unsafe fn text<'a>(s: *const c_char) -> Option<&'a CStr> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) })
}

ffi_export! {
    /// The cipher `algorithm` from the providers of `ctx` (the thread's default context for
    /// NULL) that best matches `properties`, with a reference; NULL with an error if none does.
    ///
    /// # Safety
    /// `ctx` is NULL or a live library context; `algorithm` and `properties` are NULL or
    /// strings.
    pub unsafe extern "C" fn EVP_CIPHER_fetch(ctx: *mut OSSL_LIB_CTX, algorithm: *const c_char, properties: *const c_char) -> *mut EVP_CIPHER
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let name = unsafe { text(algorithm) };
        // SAFETY: as above.
        let props = unsafe { text(properties) };
        // SAFETY: the caller's guarantee.
        unsafe { fetch::fetch(ctx, &CIPHERS, name, props) }.cast()
    }
}

ffi_export! {
    /// Adds a reference (none to a static cipher). Returns 1.
    ///
    /// # Safety
    /// `cipher` is a live cipher method.
    pub unsafe extern "C" fn EVP_CIPHER_up_ref(cipher: *mut EVP_CIPHER) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if unsafe { method(cipher) }.is_some_and(|m| m.origin == Origin::Dynamic) {
            // SAFETY: as above.
            unsafe { EVP_CIPHER::up_ref(cipher) };
        }
        1
    }
}

ffi_export! {
    /// Drops a reference; NULL and static ciphers do nothing.
    ///
    /// # Safety
    /// `cipher` is NULL or a cipher method the caller holds, not used afterwards.
    pub unsafe extern "C" fn EVP_CIPHER_free(cipher: *mut EVP_CIPHER)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if unsafe { method(cipher) }.is_some_and(|m| m.origin == Origin::Dynamic) {
            // SAFETY: as above.
            unsafe { EVP_CIPHER::free(cipher) };
        }
    }
}

ffi_export! {
    /// The algorithm's first name, as its provider gave it (a static cipher's NID's short
    /// name); NULL for NULL.
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method.
    pub unsafe extern "C" fn EVP_CIPHER_get0_name(cipher: *const EVP_CIPHER) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(cipher) }) else { return ptr::null() };
        match &m.type_name {
            Some(name) => name.as_ptr(),
            // SAFETY: no preconditions.
            None => unsafe { crate::objects::OBJ_nid2sn(m.nid) },
        }
    }
}

ffi_export! {
    /// The provider's description of the algorithm, or else its NID's long name. NULL for NULL
    /// (OpenSSL would crash, docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method.
    pub unsafe extern "C" fn EVP_CIPHER_get0_description(cipher: *const EVP_CIPHER) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(cipher) }) else { return ptr::null() };
        if !m.description.0.is_null() {
            return m.description.0;
        }
        // SAFETY: no preconditions.
        unsafe { crate::objects::OBJ_nid2ln(m.nid) }
    }
}

ffi_export! {
    /// Whether `name` is one of the algorithm's names (compared as the context's names are; a
    /// static cipher's name number in the default context).
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method; `name` is NULL or a string.
    pub unsafe extern "C" fn EVP_CIPHER_is_a(cipher: *const EVP_CIPHER, name: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(cipher) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        let n = unsafe { text(name) }.map_or(&b""[..], CStr::to_bytes);
        if m.prov.0.is_null() {
            // SAFETY: the caller's live method.
            let own_name = unsafe { EVP_CIPHER_get0_name(cipher) };
            // SAFETY: a static string or NULL.
            let own = unsafe { text(own_name) }.map_or(&b""[..], CStr::to_bytes);
            return c_int::from(fetch::number_in(ptr::null(), own) == fetch::number_in(ptr::null(), n));
        }
        c_int::from(fetch::number_in(m.prov.0, n) == m.name_id)
    }
}

/// `EVP_CIPHER_names_do_all`'s callback.
type NameFn = unsafe extern "C" fn(*const c_char, *mut c_void);

ffi_export! {
    /// Calls `fn_` with each of the algorithm's names, in the order the context learned them.
    /// Returns 1 if it has any, and for a static cipher, which has none to list (0 for NULL,
    /// where OpenSSL would crash; docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method; `fn_` is a function of the documented type.
    pub unsafe extern "C" fn EVP_CIPHER_names_do_all(cipher: *const EVP_CIPHER, fn_: Option<NameFn>, data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(cipher) }) else { return 0 };
        if m.prov.0.is_null() {
            return 1;
        }
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

ffi_export! {
    /// The provider the method came from (NULL for a static cipher, and for NULL;
    /// docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method.
    pub unsafe extern "C" fn EVP_CIPHER_get0_provider(cipher: *const EVP_CIPHER) -> *const OSSL_PROVIDER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(cipher) }.map_or(ptr::null(), |m| m.prov.0.cast_const())
    }
}

/// `EVP_CIPHER_do_all_provided`'s callback.
type DoAllFn = unsafe extern "C" fn(*mut EVP_CIPHER, *mut c_void);

ffi_export! {
    /// Calls `fn_` with each cipher method the active providers of `libctx` offer, in the
    /// store's order.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `fn_` is a function of the documented type.
    pub unsafe extern "C" fn EVP_CIPHER_do_all_provided(libctx: *mut OSSL_LIB_CTX, fn_: Option<DoAllFn>, arg: *mut c_void)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let all = unsafe { fetch::all(libctx, &CIPHERS) };
        for m in &all {
            if let Some(f) = fn_ {
                // SAFETY: the caller's callback with a method held for the call.
                unsafe { f(m.as_ptr().cast(), arg) };
            }
        }
    }
}

ffi_export! {
    /// Asks the algorithm for `params`: its result, or 0 for NULL and for a cipher without
    /// `get_params`.
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method; `params` is an array the algorithm may fill.
    pub unsafe extern "C" fn EVP_CIPHER_get_params(cipher: *mut EVP_CIPHER, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(cipher) }) else { return 0 };
        match m.get_params {
            // SAFETY: the provider's function with the caller's array.
            Some(get) => unsafe { get(params) },
            None => 0,
        }
    }
}

ffi_export! {
    /// The parameters the algorithm can report, or NULL.
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method.
    pub unsafe extern "C" fn EVP_CIPHER_gettable_params(cipher: *const EVP_CIPHER) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(cipher) }) else { return ptr::null() };
        let Some(gettable) = m.gettable_params else { return ptr::null() };
        // SAFETY: the provider's function with its context.
        unsafe { gettable(m.provider_ctx()) }
    }
}

ffi_export! {
    /// The context parameters the algorithm can set, or NULL.
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method.
    pub unsafe extern "C" fn EVP_CIPHER_settable_ctx_params(cipher: *const EVP_CIPHER) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(cipher) }) else { return ptr::null() };
        let Some(list) = m.funcs.settable_ctx_params else { return ptr::null() };
        // SAFETY: the provider's function with no context and its own.
        unsafe { list(ptr::null_mut(), m.provider_ctx()) }
    }
}

ffi_export! {
    /// The context parameters the algorithm can report, or NULL.
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method.
    pub unsafe extern "C" fn EVP_CIPHER_gettable_ctx_params(cipher: *const EVP_CIPHER) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(cipher) }) else { return ptr::null() };
        let Some(list) = m.funcs.gettable_ctx_params else { return ptr::null() };
        // SAFETY: the provider's function with no context and its own.
        unsafe { list(ptr::null_mut(), m.provider_ctx()) }
    }
}

ffi_export! {
    /// The cipher's NID: a static cipher's own, a fetched one's from the legacy cipher any of
    /// its names has (`NID_undef` if none, and for NULL).
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method.
    pub unsafe extern "C" fn EVP_CIPHER_get_nid(cipher: *const EVP_CIPHER) -> c_int
    where failure = NID_undef, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(cipher) }.map_or(NID_undef, |m| m.nid)
    }
}

ffi_export! {
    /// The NID an AlgorithmIdentifier would use: the CFB variants and RC2's and RC4's key
    /// lengths collapse to one, and a NID without an OID is `NID_undef`.
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method.
    pub unsafe extern "C" fn EVP_CIPHER_get_type(cipher: *const EVP_CIPHER) -> c_int
    where failure = NID_undef, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let nid = unsafe { EVP_CIPHER_get_nid(cipher) };
        let collapsed: [(&[c_int], c_int); 7] = [
            (&[NID_rc2_cbc, NID_rc2_64_cbc, NID_rc2_40_cbc], NID_rc2_cbc),
            (&[NID_rc4, NID_rc4_40], NID_rc4),
            (&[NID_aes_128_cfb128, NID_aes_128_cfb8, NID_aes_128_cfb1], NID_aes_128_cfb128),
            (&[NID_aes_192_cfb128, NID_aes_192_cfb8, NID_aes_192_cfb1], NID_aes_192_cfb128),
            (&[NID_aes_256_cfb128, NID_aes_256_cfb8, NID_aes_256_cfb1], NID_aes_256_cfb128),
            (&[NID_des_cfb64, NID_des_cfb8, NID_des_cfb1], NID_des_cfb64),
            (&[NID_des_ede3_cfb64, NID_des_ede3_cfb8, NID_des_ede3_cfb1], NID_des_ede3_cfb64),
        ];
        if let Some((_, to)) = collapsed.iter().find(|(from, _)| from.contains(&nid)) {
            return *to;
        }
        // SAFETY: no preconditions.
        let obj = unsafe { crate::objects::OBJ_nid2obj(nid) };
        // SAFETY: an object or NULL; the table's objects aren't freed.
        if unsafe { crate::objects::OBJ_get0_data(obj) }.is_null() {
            NID_undef
        } else {
            nid
        }
    }
}

ffi_export! {
    /// The block size in octets (1 for stream ciphers), 0 for NULL.
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method.
    pub unsafe extern "C" fn EVP_CIPHER_get_block_size(cipher: *const EVP_CIPHER) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(cipher) }.map_or(0, Cipher::block_size)
    }
}

ffi_export! {
    /// The default key length in octets; 0 for NULL (OpenSSL would crash,
    /// docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method.
    pub unsafe extern "C" fn EVP_CIPHER_get_key_length(cipher: *const EVP_CIPHER) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(cipher) }.map_or(0, Cipher::key_len)
    }
}

ffi_export! {
    /// The default IV length in octets, 0 for NULL.
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method.
    pub unsafe extern "C" fn EVP_CIPHER_get_iv_length(cipher: *const EVP_CIPHER) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(cipher) }.map_or(0, Cipher::iv_len)
    }
}

ffi_export! {
    /// The cipher's flags: its mode and `EVP_CIPH_*` flags; 0 for NULL.
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method.
    pub unsafe extern "C" fn EVP_CIPHER_get_flags(cipher: *const EVP_CIPHER) -> c_ulong
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(cipher) }.map_or(0, Cipher::flags)
    }
}

ffi_export! {
    /// The cipher's mode (`EVP_CIPH_CBC_MODE`, ...): its flags' mode bits.
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method.
    pub unsafe extern "C" fn EVP_CIPHER_get_mode(cipher: *const EVP_CIPHER) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let flags = unsafe { EVP_CIPHER_get_flags(cipher) };
        c_int::try_from(flags & flag(EVP_CIPH_MODE)).unwrap_or(0)
    }
}

ffi_export! {
    /// Whether the cipher has the pipeline functions for the direction (none of the built-in
    /// providers' do); 0 for NULL (OpenSSL would crash, docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method.
    pub unsafe extern "C" fn EVP_CIPHER_can_pipeline(cipher: *const EVP_CIPHER, enc: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(cipher) }) else { return 0 };
        let f = &m.funcs;
        let init = if enc != 0 { f.p_einit.is_some() } else { f.p_dinit.is_some() };
        c_int::from(init && f.p_cupdate.is_some() && f.p_cfinal.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: NULL ciphers.
    #[test]
    fn null_ciphers() {
        // SAFETY: NULL is the case under test, here and below.
        assert!(unsafe { EVP_CIPHER_get0_description(ptr::null()) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { EVP_CIPHER_get0_provider(ptr::null()) }.is_null());
        // SAFETY: as above.
        let r = unsafe { EVP_CIPHER_names_do_all(ptr::null(), None, ptr::null_mut()) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_CIPHER_get_key_length(ptr::null()) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_CIPHER_can_pipeline(ptr::null(), 1) }, 0);
        // SAFETY: as above.
        assert!(unsafe { EVP_CIPHER_get0_name(ptr::null()) }.is_null());
    }
}
