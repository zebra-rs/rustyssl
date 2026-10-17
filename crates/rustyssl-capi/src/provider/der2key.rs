//! The default and base providers' key decoders (`decode_der2key.c`): DER of each key type in
//! each structure — PrivateKeyInfo, SubjectPublicKeyInfo, and the type-specific ones
//! (RSAPrivateKey and RSAPublicKey, DSA's, DHparams and DHxparams, ECPrivateKey and
//! ECParameters) — to the type's provider key, passed on by reference.
//!
//! As OpenSSL's:
//! - A decoder given a selection tries the structures it allows in order (private key, public
//!   key, parameters) and succeeds without passing anything on when none decodes, so the walk
//!   tries the next decoder; the errors of the failed attempts stay only when the selection
//!   was the caller's (none decoded).
//! - A decoded key is checked (an RSA key's kind and factors, an EC key's SM2 range against
//!   the decoder's type) and takes the provider's library context.
//! - `export_object` gives a key decoded by one provider to another's key manager.
//!
//! The post-quantum key decoders (ML-KEM, ML-DSA, SLH-DSA) come with step 4.7b2b: until then
//! theirs abort when given a key of their type (AGENTS.md rule 10), and pass on anything else.

use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    EC_FLAG_SM2_RANGE, ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT, EVP_PKEY_DH, EVP_PKEY_DHX,
    EVP_PKEY_DSA, EVP_PKEY_EC, EVP_PKEY_ED448, EVP_PKEY_ED25519, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS,
    EVP_PKEY_SM2, EVP_PKEY_X448, EVP_PKEY_X25519, NID_X9_62_id_ecPublicKey, OSSL_CALLBACK,
    OSSL_CORE_BIO, OSSL_DECODER_PARAM_PROPERTIES, OSSL_FUNC_DECODER_DECODE,
    OSSL_FUNC_DECODER_DOES_SELECTION, OSSL_FUNC_DECODER_EXPORT_OBJECT, OSSL_FUNC_DECODER_FREECTX,
    OSSL_FUNC_DECODER_NEWCTX, OSSL_FUNC_DECODER_SET_CTX_PARAMS,
    OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS, OSSL_KEYMGMT_SELECT_ALL,
    OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, OSSL_KEYMGMT_SELECT_KEYPAIR,
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_OBJECT_PARAM_DATA_TYPE,
    OSSL_OBJECT_PARAM_REFERENCE, OSSL_OBJECT_PARAM_TYPE, OSSL_OBJECT_PKEY, OSSL_PARAM,
    OSSL_PASSPHRASE_CALLBACK, RSA_FLAG_TYPE_MASK, RSA_FLAG_TYPE_RSA, RSA_FLAG_TYPE_RSASSAPSS,
};

use super::builtin::libctx_of;
use super::decoders::{props_settable_ctx_params, read_der, read_into};
use super::tables::{Dispatch, END, entry};
use crate::err::{self, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::ffi::ffi_callback;
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OSSL_PARAM_construct_octet_string,
    OSSL_PARAM_construct_utf8_string,
};

/// `OSSL_MAX_PROPQUERY_SIZE` (`internal/sizes.h`).
const MAX_PROPQUERY: usize = 256;

type NewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
type DoesSelectionFn = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
type DecodeFn = unsafe extern "C" fn(
    *mut c_void,
    *mut OSSL_CORE_BIO,
    c_int,
    OSSL_CALLBACK,
    *mut c_void,
    OSSL_PASSPHRASE_CALLBACK,
    *mut c_void,
) -> c_int;
type ExportObjectFn =
    unsafe extern "C" fn(*mut c_void, *const c_void, usize, OSSL_CALLBACK, *mut c_void) -> c_int;
type ListFn = unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM;
type SetParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
/// A key manager's `export`.
type ExportFn = unsafe extern "C" fn(*mut c_void, c_int, OSSL_CALLBACK, *mut c_void) -> c_int;

/// A `d2i_of_void` decoder with no key to reuse.
type D2iFn = unsafe fn(*mut *const c_uchar, c_long) -> *mut c_void;
/// A decoder of a PrivateKeyInfo or SubjectPublicKeyInfo, given the decoder's context.
type D2iCtxFn = unsafe fn(*mut *const c_uchar, c_long, &KeyCtx) -> *mut c_void;

/// A key type's functions (`keytype_desc_st` without the structure's choice of them).
struct Type {
    name: &'static CStr,
    evp_type: c_int,
    export: ExportFn,
    private: Option<D2iFn>,
    public: Option<D2iFn>,
    params: Option<D2iFn>,
    pkcs8: Option<D2iCtxFn>,
    pubkey: Option<D2iCtxFn>,
    check: Option<unsafe fn(*mut c_void, &KeyCtx) -> bool>,
    adjust: unsafe fn(*mut c_void, &KeyCtx),
    free: unsafe fn(*mut c_void),
}

/// The structures a decoder reads (`DO_*` in `decode_der2key.c`).
#[derive(Clone, Copy)]
enum Kind {
    PrivateKeyInfo,
    SubjectPublicKeyInfo,
    /// `type_specific_keypair` and `RSA`.
    Keypair,
    /// `type_specific_params`, `DH`, and `DHX`.
    Params,
    /// `type_specific` and `DSA`.
    All,
    /// `type_specific_no_pub` and `EC`.
    NoPub,
}

/// A decoder's description (`keytype_desc_st`): its key type and the structures it reads.
pub(super) struct Desc {
    t: &'static Type,
    selection_mask: c_int,
    private: Option<D2iFn>,
    public: Option<D2iFn>,
    params: Option<D2iFn>,
    pkcs8: Option<D2iCtxFn>,
    pubkey: Option<D2iCtxFn>,
}

/// The description of `t`'s decoder of `kind`.
const fn desc(t: &'static Type, kind: Kind) -> Desc {
    let none = Desc {
        t,
        selection_mask: 0,
        private: None,
        public: None,
        params: None,
        pkcs8: None,
        pubkey: None,
    };
    match kind {
        Kind::PrivateKeyInfo => Desc {
            selection_mask: OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
            pkcs8: t.pkcs8,
            ..none
        },
        Kind::SubjectPublicKeyInfo => Desc {
            selection_mask: OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
            pubkey: t.pubkey,
            ..none
        },
        Kind::Keypair => Desc {
            selection_mask: OSSL_KEYMGMT_SELECT_KEYPAIR,
            private: t.private,
            public: t.public,
            ..none
        },
        Kind::Params => Desc {
            selection_mask: OSSL_KEYMGMT_SELECT_ALL_PARAMETERS,
            params: t.params,
            ..none
        },
        Kind::All => Desc {
            selection_mask: OSSL_KEYMGMT_SELECT_ALL,
            private: t.private,
            public: t.public,
            params: t.params,
            ..none
        },
        Kind::NoPub => Desc {
            selection_mask: OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS,
            private: t.private,
            params: t.params,
            ..none
        },
    }
}

/// A key decoder's context (`der2key_ctx_st`).
pub(super) struct KeyCtx {
    provctx: *mut c_void,
    propq: [c_char; MAX_PROPQUERY],
    desc: &'static Desc,
    /// The selection of the last decoding, for `export_object`.
    selection: c_int,
}

impl KeyCtx {
    /// The provider's library context.
    fn libctx(&self) -> *mut rustyssl_abi::OSSL_LIB_CTX {
        // SAFETY: the provider's context, live while the provider is.
        unsafe { libctx_of(self.provctx) }
    }

    /// The properties set, as a C string.
    fn propq(&self) -> *const c_char {
        self.propq.as_ptr()
    }
}

/// `der2key_newctx`.
fn newctx(provctx: *mut c_void, desc: &'static Desc) -> *mut c_void {
    Box::into_raw(Box::new(KeyCtx {
        provctx,
        propq: [0; MAX_PROPQUERY],
        desc,
        selection: 0,
    }))
    .cast()
}

/// `der2key_check_selection`: whether the decoder's structures hold the first of the private
/// key, the public key, and the parameters the selection asks for (any, for none).
fn check_selection(selection: c_int, desc: &Desc) -> c_int {
    if selection == 0 {
        return 1;
    }
    for check in [
        OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
        OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
        OSSL_KEYMGMT_SELECT_ALL_PARAMETERS,
    ] {
        if selection & check != 0 {
            return c_int::from(desc.selection_mask & check != 0);
        }
    }
    0
}

/// The context behind `vctx`.
///
/// # Safety
/// `vctx` is NULL or a live context from `newctx`.
unsafe fn kctx<'a>(vctx: *mut c_void) -> Option<&'a mut KeyCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { vctx.cast::<KeyCtx>().as_mut() }
}

ffi_callback! {
    /// `der2key_freectx`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context from `newctx` the caller gives up.
    pub(crate) unsafe extern "C" fn der2key_freectx(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        if !vctx.is_null() {
            // SAFETY: the caller's guarantee.
            drop(unsafe { Box::from_raw(vctx.cast::<KeyCtx>()) });
        }
    }
}

ffi_callback! {
    /// `der2key_set_ctx_params`: the properties.
    ///
    /// # Safety
    /// `vctx` is a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn der2key_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { kctx(vctx) }) else { return 0 };
        // SAFETY: as above.
        c_int::from(unsafe { read_into(params, OSSL_DECODER_PARAM_PROPERTIES, &mut c.propq) })
    }
}

/// Runs `d2i` from the start of `der` (whose octets it's given, with their length).
fn run(der: &[u8], d2i: impl FnOnce(*mut *const c_uchar, c_long) -> *mut c_void) -> *mut c_void {
    let Ok(len) = c_long::try_from(der.len()) else {
        return ptr::null_mut();
    };
    let mut p = der.as_ptr();
    d2i(&raw mut p, len)
}

/// `der2key_decode`'s attempts: the structures the selection asks for, each from the start;
/// NULL with the errors marked as OpenSSL leaves them, or `Err` to pass nothing on (a
/// structure the caller selected didn't decode).
///
/// # Safety
/// As for `der2key_decode`.
unsafe fn attempt(c: &KeyCtx, der: &[u8], selection: c_int) -> Result<*mut c_void, ()> {
    let d = c.desc;
    let mut key = ptr::null_mut();
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    let give_up = || {
        // SAFETY: the mark set above.
        unsafe { ERR_clear_last_mark() };
        Err(())
    };
    if selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY != 0 {
        if let Some(f) = d.pkcs8 {
            // SAFETY: the decoder reads within the octets it's given.
            key = run(der, |p, l| unsafe { f(p, l, c) });
        } else if let Some(f) = d.private {
            // SAFETY: as above.
            key = run(der, |p, l| unsafe { f(p, l) });
        }
        if key.is_null() && c.selection != 0 {
            return give_up();
        }
    }
    if key.is_null() && selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY != 0 {
        if let Some(f) = d.pubkey {
            // SAFETY: the decoder reads within the octets it's given.
            key = run(der, |p, l| unsafe { f(p, l, c) });
        } else if let Some(f) = d.public {
            // SAFETY: as above.
            key = run(der, |p, l| unsafe { f(p, l) });
        }
        if key.is_null() && c.selection != 0 {
            return give_up();
        }
    }
    if key.is_null() && selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS != 0 {
        if let Some(f) = d.params {
            // SAFETY: as above.
            key = run(der, |p, l| unsafe { f(p, l) });
        }
        if key.is_null() && c.selection != 0 {
            return give_up();
        }
    }
    if key.is_null() {
        // SAFETY: the mark set above.
        unsafe { ERR_clear_last_mark() };
    } else {
        // SAFETY: as above.
        unsafe { ERR_pop_to_mark() };
    }
    Ok(key)
}

ffi_callback! {
    /// `der2key_decode`: the key of the first structure that decodes, checked and in the
    /// provider's library context, passed on by reference (as SM2's for an EC key in SM2's
    /// range); success with nothing passed on when none does.
    ///
    /// # Safety
    /// As for a decoder's `decode`.
    pub(crate) unsafe extern "C" fn der2key_decode(vctx: *mut c_void, cin: *mut OSSL_CORE_BIO, selection: c_int, data_cb: OSSL_CALLBACK, data_cbarg: *mut c_void, _pw_cb: OSSL_PASSPHRASE_CALLBACK, _pw_cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { kctx(vctx) }) else { return 0 };
        let t = c.desc.t;
        c.selection = selection;
        let selection = if selection == 0 { c.desc.selection_mask } else { selection };
        if selection & c.desc.selection_mask == 0 {
            err::raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT, "der2key_decode");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(der) = (unsafe { read_der(cin) }) else { return 1 };
        // SAFETY: as above.
        let Ok(mut key) = (unsafe { attempt(c, &der, selection) }) else { return 1 };
        drop(der);
        if !key.is_null() && let Some(check) = t.check {
            // SAFETY: the decoded key.
            if !unsafe { check(key, c) } {
                // SAFETY: as above, freed once.
                unsafe { (t.free)(key) };
                key = ptr::null_mut();
            }
        }
        if key.is_null() {
            return 1;
        }
        // SAFETY: as above.
        unsafe { (t.adjust)(key, c) };
        // SAFETY: as above.
        let sm2 = t.evp_type == EVP_PKEY_EC && unsafe { is_sm2(key) };
        let data_type = if sm2 {
            c"SM2"
        } else {
            t.name
        };
        let mut object_type = OSSL_OBJECT_PKEY;
        let params = [
            // SAFETY: a static name; a local that outlives the call.
            unsafe { OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE.as_ptr(), &raw mut object_type) },
            // SAFETY: static strings.
            unsafe { OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE.as_ptr(), data_type.as_ptr().cast_mut(), 0) },
            // SAFETY: a static name; the key's pointer, a local the construct may take the key
            // from (as a key manager's `load` does, leaving NULL).
            unsafe { OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE.as_ptr(), (&raw mut key).cast(), size_of::<*mut c_void>()) },
            // SAFETY: no preconditions.
            unsafe { OSSL_PARAM_construct_end() },
        ];
        let ok = match data_cb {
            // SAFETY: the decoding's callback with the parameters and its argument.
            Some(cb) => unsafe { cb(params.as_ptr(), data_cbarg) },
            None => 0,
        };
        if !key.is_null() {
            // SAFETY: the key, not taken by the callback.
            unsafe { (t.free)(key) };
        }
        ok
    }
}

ffi_callback! {
    /// `der2key_export_object`: the referenced key's selected parts (all, for the last
    /// decoding's none) through its key manager's `export`.
    ///
    /// # Safety
    /// `reference` points to `reference_sz` octets; the callback takes its argument.
    pub(crate) unsafe extern "C" fn der2key_export_object(vctx: *mut c_void, reference: *const c_void, reference_sz: usize, export_cb: OSSL_CALLBACK, export_cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { kctx(vctx) }) else { return 0 };
        if reference.is_null() || reference_sz != size_of::<*mut c_void>() {
            return 0;
        }
        let selection = if c.selection == 0 { OSSL_KEYMGMT_SELECT_ALL } else { c.selection };
        // SAFETY: the caller's guarantee: a key's pointer.
        let keydata = unsafe { reference.cast::<*mut c_void>().read_unaligned() };
        // SAFETY: the key manager's export of its key.
        unsafe { (c.desc.t.export)(keydata, selection, export_cb, export_cbarg) }
    }
}

/// A key decoder's dispatch table, with its own `newctx` and `does_selection`.
macro_rules! decoder {
    ($table:ident, $desc:ident, $newctx:ident, $does:ident, $t:expr, $kind:expr) => {
        static $desc: Desc = desc(&$t, $kind);

        ffi_callback! {
            /// The decoder's `newctx`.
            ///
            /// # Safety
            /// `provctx` is the provider's context.
            pub(crate) unsafe extern "C" fn $newctx(provctx: *mut c_void) -> *mut c_void
            where failure = ptr::null_mut(), library = ERR_LIB_PROV
            {
                newctx(provctx, &$desc)
            }
        }

        ffi_callback! {
            /// The decoder's `does_selection`.
            ///
            /// # Safety
            /// No preconditions.
            pub(crate) unsafe extern "C" fn $does(_provctx: *mut c_void, selection: c_int) -> c_int
            where failure = 0, library = ERR_LIB_PROV
            {
                check_selection(selection, &$desc)
            }
        }

        pub(super) static $table: Dispatch<8> = Dispatch([
            entry!(OSSL_FUNC_DECODER_NEWCTX, $newctx, NewCtxFn),
            entry!(OSSL_FUNC_DECODER_FREECTX, der2key_freectx, FreeCtxFn),
            entry!(OSSL_FUNC_DECODER_DOES_SELECTION, $does, DoesSelectionFn),
            entry!(OSSL_FUNC_DECODER_DECODE, der2key_decode, DecodeFn),
            entry!(
                OSSL_FUNC_DECODER_EXPORT_OBJECT,
                der2key_export_object,
                ExportObjectFn
            ),
            entry!(
                OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS,
                props_settable_ctx_params,
                ListFn
            ),
            entry!(
                OSSL_FUNC_DECODER_SET_CTX_PARAMS,
                der2key_set_ctx_params,
                SetParamsFn
            ),
            END,
        ]);
    };
}

// The key types' functions.

/// `der2key_decode_p8`: a PrivateKeyInfo of the decoder's type (an EC one for SM2), made a key
/// by `from_p8`.
///
/// # Safety
/// `pp` holds a pointer to `len` octets.
unsafe fn decode_p8(
    pp: *mut *const c_uchar,
    len: c_long,
    c: &KeyCtx,
    from_p8: unsafe fn(*const rustyssl_abi::PKCS8_PRIV_KEY_INFO, &KeyCtx) -> *mut c_void,
) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    let p8 = unsafe { crate::x509::p8::d2i_PKCS8_PRIV_KEY_INFO(ptr::null_mut(), pp, len) };
    if p8.is_null() {
        return ptr::null_mut();
    }
    let mut alg = ptr::null();
    // SAFETY: the decoded structure; a local.
    let got = unsafe {
        crate::x509::p8::PKCS8_pkey_get0(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut alg,
            p8,
        )
    } != 0;
    let key = if got {
        // SAFETY: the structure's AlgorithmIdentifier.
        let obj = unsafe { (*alg).algorithm };
        // SAFETY: its AlgorithmIdentifier's object.
        let nid = unsafe { crate::objects::OBJ_obj2nid(obj) };
        let evp_type = c.desc.t.evp_type;
        if nid == evp_type || (nid == NID_X9_62_id_ecPublicKey && evp_type == EVP_PKEY_SM2) {
            // SAFETY: the structure.
            unsafe { from_p8(p8, c) }
        } else {
            ptr::null_mut()
        }
    } else {
        ptr::null_mut()
    };
    // SAFETY: decoded above, freed once.
    unsafe { crate::x509::p8::PKCS8_PRIV_KEY_INFO_free(p8) };
    key
}

/// Whether an EC key is in SM2's range (`EC_FLAG_SM2_RANGE`).
///
/// # Safety
/// `key` is a live EC key.
unsafe fn is_sm2(key: *mut c_void) -> bool {
    // SAFETY: the caller's guarantee.
    (unsafe { crate::ec::key::EC_KEY_get_flags(key.cast()) } & EC_FLAG_SM2_RANGE) != 0
}

/// `ec_check`: an EC key in SM2's range for SM2's decoders (and EC's), else not SM2's.
///
/// # Safety
/// `key` is a live EC key.
unsafe fn ec_check(key: *mut c_void, c: &KeyCtx) -> bool {
    let evp_type = c.desc.t.evp_type;
    // SAFETY: the caller's guarantee.
    if unsafe { is_sm2(key) } {
        evp_type == EVP_PKEY_SM2 || evp_type == NID_X9_62_id_ecPublicKey
    } else {
        evp_type != EVP_PKEY_SM2
    }
}

/// `rsa_check`: an RSA key of the decoder's kind, with no factor longer than its modulus.
///
/// # Safety
/// `key` is a live RSA key.
unsafe fn rsa_check(key: *mut c_void, c: &KeyCtx) -> bool {
    // SAFETY: the caller's guarantee.
    let kind = unsafe { crate::rsa_lib::RSA_test_flags(key.cast(), RSA_FLAG_TYPE_MASK) };
    let valid = match kind {
        RSA_FLAG_TYPE_RSA => c.desc.t.evp_type == EVP_PKEY_RSA,
        RSA_FLAG_TYPE_RSASSAPSS => c.desc.t.evp_type == EVP_PKEY_RSA_PSS,
        _ => false,
    };
    // SAFETY: as above.
    valid
        && unsafe { crate::rsa::rsa(key.cast()) }
            .is_some_and(|r| super::rsa_kmgmt::check_factors(&r.snapshot().key))
}

/// A decoded key's ECX key of `type_`; `pkey` is the live key `legacy_pubkey` gives.
fn get1_ecx(pkey: *mut rustyssl_abi::EVP_PKEY, type_: c_int) -> *mut c_void {
    // SAFETY: the decoded key.
    unsafe { crate::evp::pkey::ecx::get1_ecx_key(pkey, type_) }
}

/// A SubjectPublicKeyInfo's legacy key (`ossl_d2i_PUBKEY_legacy`), made the type's by `get1`
/// (NULL for another type) from the live key it's given; `*pp` moves past it.
///
/// # Safety
/// `pp` holds a pointer to `len` octets.
unsafe fn legacy_pubkey(
    pp: *mut *const c_uchar,
    len: c_long,
    get1: impl FnOnce(*mut rustyssl_abi::EVP_PKEY) -> *mut c_void,
) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    let mut q = unsafe { pp.read() };
    // SAFETY: as above.
    let pkey = unsafe { crate::x509::pubkey::d2i_pubkey_legacy(&raw mut q, len) };
    if pkey.is_null() {
        return ptr::null_mut();
    }
    let key = get1(pkey);
    // SAFETY: made above, freed once.
    unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
    if !key.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { pp.write(q) };
    }
    key
}

/// A decoded key's `DH` when the key is of `type_` (`ossl_d2i_DH_PUBKEY`,
/// `ossl_d2i_DHx_PUBKEY`); `pkey` is the live key `legacy_pubkey` gives.
fn get1_dh(pkey: *mut rustyssl_abi::EVP_PKEY, type_: c_int) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    if unsafe { crate::evp::pkey::EVP_PKEY_get_id(pkey) } != type_ {
        return ptr::null_mut();
    }
    // SAFETY: as above.
    unsafe { crate::evp::pkey::dh::EVP_PKEY_get1_DH(pkey) }.cast()
}

mod fns {
    //! Each key type's decoding functions, as `decode_der2key.c` names them.

    use super::*;
    use crate::dh_asn1::{d2i_DHparams, d2i_DHxparams};
    use crate::dsa_asn1::{d2i_DSAPrivateKey, d2i_DSAPublicKey, d2i_DSAparams};
    use crate::ec::key_asn1::{d2i_ECParameters, d2i_ECPrivateKey};
    use crate::rsa_asn1::{d2i_RSAPrivateKey, d2i_RSAPublicKey};

    pub(super) unsafe fn rsa_private(p: *mut *const c_uchar, l: c_long) -> *mut c_void {
        // SAFETY: the caller's octets.
        unsafe { d2i_RSAPrivateKey(ptr::null_mut(), p, l) }.cast()
    }
    pub(super) unsafe fn rsa_public(p: *mut *const c_uchar, l: c_long) -> *mut c_void {
        // SAFETY: as above.
        unsafe { d2i_RSAPublicKey(ptr::null_mut(), p, l) }.cast()
    }
    pub(super) unsafe fn dsa_private(p: *mut *const c_uchar, l: c_long) -> *mut c_void {
        // SAFETY: as above.
        unsafe { d2i_DSAPrivateKey(ptr::null_mut(), p, l) }.cast()
    }
    pub(super) unsafe fn dsa_public(p: *mut *const c_uchar, l: c_long) -> *mut c_void {
        // SAFETY: as above.
        unsafe { d2i_DSAPublicKey(ptr::null_mut(), p, l) }.cast()
    }
    pub(super) unsafe fn dsa_params(p: *mut *const c_uchar, l: c_long) -> *mut c_void {
        // SAFETY: as above.
        unsafe { d2i_DSAparams(ptr::null_mut(), p, l) }.cast()
    }
    pub(super) unsafe fn dh_params(p: *mut *const c_uchar, l: c_long) -> *mut c_void {
        // SAFETY: as above.
        unsafe { d2i_DHparams(ptr::null_mut(), p, l) }.cast()
    }
    pub(super) unsafe fn dhx_params(p: *mut *const c_uchar, l: c_long) -> *mut c_void {
        // SAFETY: as above.
        unsafe { d2i_DHxparams(ptr::null_mut(), p, l) }.cast()
    }
    pub(super) unsafe fn ec_private(p: *mut *const c_uchar, l: c_long) -> *mut c_void {
        // SAFETY: as above.
        unsafe { d2i_ECPrivateKey(ptr::null_mut(), p, l) }.cast()
    }
    pub(super) unsafe fn ec_params(p: *mut *const c_uchar, l: c_long) -> *mut c_void {
        // SAFETY: as above.
        unsafe { d2i_ECParameters(ptr::null_mut(), p, l) }.cast()
    }

    pub(super) unsafe fn rsa_p8(p: *mut *const c_uchar, l: c_long, c: &KeyCtx) -> *mut c_void {
        /// `ossl_rsa_key_from_pkcs8`.
        unsafe fn from(p8: *const rustyssl_abi::PKCS8_PRIV_KEY_INFO, _: &KeyCtx) -> *mut c_void {
            // SAFETY: the caller's structure.
            unsafe { crate::evp::pkey::rsa::key_from_pkcs8(p8) }.cast()
        }
        // SAFETY: the caller's octets.
        unsafe { decode_p8(p, l, c, from) }
    }
    pub(super) unsafe fn dsa_p8(p: *mut *const c_uchar, l: c_long, c: &KeyCtx) -> *mut c_void {
        /// `ossl_dsa_key_from_pkcs8`.
        unsafe fn from(p8: *const rustyssl_abi::PKCS8_PRIV_KEY_INFO, _: &KeyCtx) -> *mut c_void {
            // SAFETY: the caller's structure.
            unsafe { crate::evp::pkey::dsa::key_from_pkcs8(p8) }.cast()
        }
        // SAFETY: the caller's octets.
        unsafe { decode_p8(p, l, c, from) }
    }
    pub(super) unsafe fn dh_p8(p: *mut *const c_uchar, l: c_long, c: &KeyCtx) -> *mut c_void {
        /// `ossl_dh_key_from_pkcs8`.
        unsafe fn from(p8: *const rustyssl_abi::PKCS8_PRIV_KEY_INFO, _: &KeyCtx) -> *mut c_void {
            // SAFETY: the caller's structure.
            unsafe { crate::evp::pkey::dh::key_from_pkcs8(p8) }.cast()
        }
        // SAFETY: the caller's octets.
        unsafe { decode_p8(p, l, c, from) }
    }
    pub(super) unsafe fn ec_p8(p: *mut *const c_uchar, l: c_long, c: &KeyCtx) -> *mut c_void {
        /// `ossl_ec_key_from_pkcs8`, in the provider's library context.
        unsafe fn from(p8: *const rustyssl_abi::PKCS8_PRIV_KEY_INFO, c: &KeyCtx) -> *mut c_void {
            // SAFETY: the caller's structure; the context's properties.
            unsafe { crate::evp::pkey::ec::key_from_pkcs8(p8, c.libctx(), c.propq()) }.cast()
        }
        // SAFETY: the caller's octets.
        unsafe { decode_p8(p, l, c, from) }
    }
    pub(super) unsafe fn ecx_p8(p: *mut *const c_uchar, l: c_long, c: &KeyCtx) -> *mut c_void {
        /// `ossl_ecx_key_from_pkcs8`, in the provider's library context.
        unsafe fn from(p8: *const rustyssl_abi::PKCS8_PRIV_KEY_INFO, c: &KeyCtx) -> *mut c_void {
            // SAFETY: the context's NUL-terminated buffer.
            let propq = unsafe { CStr::from_ptr(c.propq()) };
            // SAFETY: the caller's structure.
            unsafe { crate::evp::pkey::ecx::key_from_pkcs8(p8, c.libctx(), Some(propq)) }
        }
        // SAFETY: the caller's octets.
        unsafe { decode_p8(p, l, c, from) }
    }

    pub(super) unsafe fn rsa_pubkey(p: *mut *const c_uchar, l: c_long, _: &KeyCtx) -> *mut c_void {
        // SAFETY: the caller's octets.
        unsafe { crate::x509::pubkey::d2i_RSA_PUBKEY(ptr::null_mut(), p, l) }.cast()
    }
    pub(super) unsafe fn ec_pubkey(p: *mut *const c_uchar, l: c_long, _: &KeyCtx) -> *mut c_void {
        // SAFETY: as above.
        unsafe { crate::x509::pubkey::d2i_EC_PUBKEY(ptr::null_mut(), p, l) }.cast()
    }
    /// `ossl_d2i_DSA_PUBKEY`: a DSA key with all its parameters.
    pub(super) unsafe fn dsa_pubkey(pp: *mut *const c_uchar, l: c_long, _: &KeyCtx) -> *mut c_void {
        // SAFETY: the caller's guarantee.
        let mut q = unsafe { pp.read() };
        // SAFETY: as above.
        let key = unsafe { crate::x509::pubkey::d2i_DSA_PUBKEY(ptr::null_mut(), &raw mut q, l) };
        if key.is_null() {
            return ptr::null_mut();
        }
        let (mut dp, mut dq, mut dg) = (ptr::null(), ptr::null(), ptr::null());
        // SAFETY: the decoded key; locals.
        unsafe { crate::dsa::DSA_get0_pqg(key, &raw mut dp, &raw mut dq, &raw mut dg) };
        if dp.is_null() || dq.is_null() || dg.is_null() {
            // SAFETY: decoded above.
            unsafe { crate::dsa::DSA_free(key) };
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        unsafe { pp.write(q) };
        key.cast()
    }
    pub(super) unsafe fn dh_pubkey(p: *mut *const c_uchar, l: c_long, _: &KeyCtx) -> *mut c_void {
        // SAFETY: the caller's octets.
        unsafe { legacy_pubkey(p, l, |k| get1_dh(k, EVP_PKEY_DH)) }
    }
    pub(super) unsafe fn dhx_pubkey(p: *mut *const c_uchar, l: c_long, _: &KeyCtx) -> *mut c_void {
        // SAFETY: the caller's octets.
        unsafe { legacy_pubkey(p, l, |k| get1_dh(k, EVP_PKEY_DHX)) }
    }
    /// `ossl_d2i_X25519_PUBKEY` and the others: the key's ECX key of the decoder's type.
    pub(super) unsafe fn ecx_pubkey(p: *mut *const c_uchar, l: c_long, c: &KeyCtx) -> *mut c_void {
        let t = c.desc.t.evp_type;
        // SAFETY: the caller's octets.
        unsafe { legacy_pubkey(p, l, |k| get1_ecx(k, t)) }
    }

    pub(super) unsafe fn rsa_adjust(key: *mut c_void, c: &KeyCtx) {
        // SAFETY: the caller's live key.
        if let Some(r) = unsafe { crate::rsa::rsa(key.cast()) } {
            r.libctx.set(c.libctx());
        }
    }
    pub(super) unsafe fn dsa_adjust(key: *mut c_void, c: &KeyCtx) {
        // SAFETY: as above.
        if let Some(d) = unsafe { crate::dsa::dsa(key.cast()) } {
            d.set0_libctx(c.libctx());
        }
    }
    pub(super) unsafe fn dh_adjust(key: *mut c_void, c: &KeyCtx) {
        // SAFETY: as above.
        if let Some(d) = unsafe { crate::dh::dh(key.cast()) } {
            d.libctx.set(c.libctx());
        }
    }
    pub(super) unsafe fn ec_adjust(key: *mut c_void, c: &KeyCtx) {
        let libctx = c.libctx();
        // SAFETY: as above.
        if let Some(k) = unsafe { crate::ec::key::key(key.cast()) } {
            k.update(|f| f.libctx = crate::provider::Ptr(libctx));
        }
    }
    pub(super) unsafe fn ecx_adjust(key: *mut c_void, c: &KeyCtx) {
        // SAFETY: as above.
        if let Some(k) = unsafe { crate::ecx::key(key) } {
            k.libctx.set(c.libctx());
        }
    }

    pub(super) unsafe fn rsa_free(key: *mut c_void) {
        // SAFETY: the caller's key, freed once.
        unsafe { crate::rsa_lib::RSA_free(key.cast()) };
    }
    pub(super) unsafe fn dsa_free(key: *mut c_void) {
        // SAFETY: as above.
        unsafe { crate::dsa::DSA_free(key.cast()) };
    }
    pub(super) unsafe fn dh_free(key: *mut c_void) {
        // SAFETY: as above.
        unsafe { crate::dh::DH_free(key.cast()) };
    }
    pub(super) unsafe fn ec_free(key: *mut c_void) {
        // SAFETY: as above.
        unsafe { crate::ec::key::EC_KEY_free(key.cast()) };
    }
    pub(super) unsafe fn ecx_free(key: *mut c_void) {
        // SAFETY: as above.
        unsafe { crate::ecx::free(key) };
    }
}

use super::dh_kmgmt::dh_export;
use super::dsa_kmgmt::dsa_export;
use super::ec_kmgmt::ec_export;
use super::ecx_kmgmt::ecx_export;
use super::rsa_kmgmt::rsa_export;

const DH: Type = Type {
    name: c"DH",
    evp_type: EVP_PKEY_DH,
    export: dh_export,
    private: None,
    public: None,
    params: Some(fns::dh_params),
    pkcs8: Some(fns::dh_p8),
    pubkey: Some(fns::dh_pubkey),
    check: None,
    adjust: fns::dh_adjust,
    free: fns::dh_free,
};

const DHX: Type = Type {
    name: c"DHX",
    evp_type: EVP_PKEY_DHX,
    params: Some(fns::dhx_params),
    pubkey: Some(fns::dhx_pubkey),
    ..DH
};

const DSA: Type = Type {
    name: c"DSA",
    evp_type: EVP_PKEY_DSA,
    export: dsa_export,
    private: Some(fns::dsa_private),
    public: Some(fns::dsa_public),
    params: Some(fns::dsa_params),
    pkcs8: Some(fns::dsa_p8),
    pubkey: Some(fns::dsa_pubkey),
    check: None,
    adjust: fns::dsa_adjust,
    free: fns::dsa_free,
};

const EC: Type = Type {
    name: c"EC",
    evp_type: EVP_PKEY_EC,
    export: ec_export,
    private: Some(fns::ec_private),
    public: None,
    params: Some(fns::ec_params),
    pkcs8: Some(fns::ec_p8),
    pubkey: Some(fns::ec_pubkey),
    check: Some(ec_check),
    adjust: fns::ec_adjust,
    free: fns::ec_free,
};

const SM2: Type = Type {
    name: c"SM2",
    evp_type: EVP_PKEY_SM2,
    ..EC
};

const X25519: Type = Type {
    name: c"X25519",
    evp_type: EVP_PKEY_X25519,
    export: ecx_export,
    private: None,
    public: None,
    params: None,
    pkcs8: Some(fns::ecx_p8),
    pubkey: Some(fns::ecx_pubkey),
    check: None,
    adjust: fns::ecx_adjust,
    free: fns::ecx_free,
};

const X448: Type = Type {
    name: c"X448",
    evp_type: EVP_PKEY_X448,
    ..X25519
};

const ED25519: Type = Type {
    name: c"ED25519",
    evp_type: EVP_PKEY_ED25519,
    ..X25519
};

const ED448: Type = Type {
    name: c"ED448",
    evp_type: EVP_PKEY_ED448,
    ..X25519
};

const RSA: Type = Type {
    name: c"RSA",
    evp_type: EVP_PKEY_RSA,
    export: rsa_export,
    private: Some(fns::rsa_private),
    public: Some(fns::rsa_public),
    params: None,
    pkcs8: Some(fns::rsa_p8),
    pubkey: Some(fns::rsa_pubkey),
    check: Some(rsa_check),
    adjust: fns::rsa_adjust,
    free: fns::rsa_free,
};

const RSA_PSS: Type = Type {
    name: c"RSA-PSS",
    evp_type: EVP_PKEY_RSA_PSS,
    ..RSA
};

decoder!(
    P8_DH,
    P8_DH_DESC,
    p8_dh_newctx,
    p8_dh_does_selection,
    DH,
    Kind::PrivateKeyInfo
);
decoder!(
    SPKI_DH,
    SPKI_DH_DESC,
    spki_dh_newctx,
    spki_dh_does_selection,
    DH,
    Kind::SubjectPublicKeyInfo
);
decoder!(
    TS_DH,
    TS_DH_DESC,
    ts_dh_newctx,
    ts_dh_does_selection,
    DH,
    Kind::Params
);
decoder!(
    DH_DH,
    DH_DH_DESC,
    dh_dh_newctx,
    dh_dh_does_selection,
    DH,
    Kind::Params
);
decoder!(
    P8_DHX,
    P8_DHX_DESC,
    p8_dhx_newctx,
    p8_dhx_does_selection,
    DHX,
    Kind::PrivateKeyInfo
);
decoder!(
    SPKI_DHX,
    SPKI_DHX_DESC,
    spki_dhx_newctx,
    spki_dhx_does_selection,
    DHX,
    Kind::SubjectPublicKeyInfo
);
decoder!(
    TS_DHX,
    TS_DHX_DESC,
    ts_dhx_newctx,
    ts_dhx_does_selection,
    DHX,
    Kind::Params
);
decoder!(
    DHX_DHX,
    DHX_DHX_DESC,
    dhx_dhx_newctx,
    dhx_dhx_does_selection,
    DHX,
    Kind::Params
);
decoder!(
    P8_DSA,
    P8_DSA_DESC,
    p8_dsa_newctx,
    p8_dsa_does_selection,
    DSA,
    Kind::PrivateKeyInfo
);
decoder!(
    SPKI_DSA,
    SPKI_DSA_DESC,
    spki_dsa_newctx,
    spki_dsa_does_selection,
    DSA,
    Kind::SubjectPublicKeyInfo
);
decoder!(
    TS_DSA,
    TS_DSA_DESC,
    ts_dsa_newctx,
    ts_dsa_does_selection,
    DSA,
    Kind::All
);
decoder!(
    DSA_DSA,
    DSA_DSA_DESC,
    dsa_dsa_newctx,
    dsa_dsa_does_selection,
    DSA,
    Kind::All
);
decoder!(
    P8_EC,
    P8_EC_DESC,
    p8_ec_newctx,
    p8_ec_does_selection,
    EC,
    Kind::PrivateKeyInfo
);
decoder!(
    SPKI_EC,
    SPKI_EC_DESC,
    spki_ec_newctx,
    spki_ec_does_selection,
    EC,
    Kind::SubjectPublicKeyInfo
);
decoder!(
    TS_EC,
    TS_EC_DESC,
    ts_ec_newctx,
    ts_ec_does_selection,
    EC,
    Kind::NoPub
);
decoder!(
    EC_EC,
    EC_EC_DESC,
    ec_ec_newctx,
    ec_ec_does_selection,
    EC,
    Kind::NoPub
);
decoder!(
    P8_X25519,
    P8_X25519_DESC,
    p8_x25519_newctx,
    p8_x25519_does_selection,
    X25519,
    Kind::PrivateKeyInfo
);
decoder!(
    SPKI_X25519,
    SPKI_X25519_DESC,
    spki_x25519_newctx,
    spki_x25519_does_selection,
    X25519,
    Kind::SubjectPublicKeyInfo
);
decoder!(
    P8_X448,
    P8_X448_DESC,
    p8_x448_newctx,
    p8_x448_does_selection,
    X448,
    Kind::PrivateKeyInfo
);
decoder!(
    SPKI_X448,
    SPKI_X448_DESC,
    spki_x448_newctx,
    spki_x448_does_selection,
    X448,
    Kind::SubjectPublicKeyInfo
);
decoder!(
    P8_ED25519,
    P8_ED25519_DESC,
    p8_ed25519_newctx,
    p8_ed25519_does_selection,
    ED25519,
    Kind::PrivateKeyInfo
);
decoder!(
    SPKI_ED25519,
    SPKI_ED25519_DESC,
    spki_ed25519_newctx,
    spki_ed25519_does_selection,
    ED25519,
    Kind::SubjectPublicKeyInfo
);
decoder!(
    P8_ED448,
    P8_ED448_DESC,
    p8_ed448_newctx,
    p8_ed448_does_selection,
    ED448,
    Kind::PrivateKeyInfo
);
decoder!(
    SPKI_ED448,
    SPKI_ED448_DESC,
    spki_ed448_newctx,
    spki_ed448_does_selection,
    ED448,
    Kind::SubjectPublicKeyInfo
);
decoder!(
    P8_SM2,
    P8_SM2_DESC,
    p8_sm2_newctx,
    p8_sm2_does_selection,
    SM2,
    Kind::PrivateKeyInfo
);
decoder!(
    SPKI_SM2,
    SPKI_SM2_DESC,
    spki_sm2_newctx,
    spki_sm2_does_selection,
    SM2,
    Kind::SubjectPublicKeyInfo
);
decoder!(
    TS_SM2,
    TS_SM2_DESC,
    ts_sm2_newctx,
    ts_sm2_does_selection,
    SM2,
    Kind::NoPub
);
decoder!(
    P8_RSA,
    P8_RSA_DESC,
    p8_rsa_newctx,
    p8_rsa_does_selection,
    RSA,
    Kind::PrivateKeyInfo
);
decoder!(
    SPKI_RSA,
    SPKI_RSA_DESC,
    spki_rsa_newctx,
    spki_rsa_does_selection,
    RSA,
    Kind::SubjectPublicKeyInfo
);
decoder!(
    TS_RSA,
    TS_RSA_DESC,
    ts_rsa_newctx,
    ts_rsa_does_selection,
    RSA,
    Kind::Keypair
);
decoder!(
    RSA_RSA,
    RSA_RSA_DESC,
    rsa_rsa_newctx,
    rsa_rsa_does_selection,
    RSA,
    Kind::Keypair
);
decoder!(
    P8_RSAPSS,
    P8_RSAPSS_DESC,
    p8_rsapss_newctx,
    p8_rsapss_does_selection,
    RSA_PSS,
    Kind::PrivateKeyInfo
);
decoder!(
    SPKI_RSAPSS,
    SPKI_RSAPSS_DESC,
    spki_rsapss_newctx,
    spki_rsapss_does_selection,
    RSA_PSS,
    Kind::SubjectPublicKeyInfo
);
