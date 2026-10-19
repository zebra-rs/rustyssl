//! The default and base providers' encoders (`encoders.inc`; `encode_key2any.c`,
//! `encode_key2blob.c`): each key type to DER or PEM in each structure — EncryptedPrivateKeyInfo,
//! PrivateKeyInfo, SubjectPublicKeyInfo, and the type-specific ones (RSAPrivateKey and
//! RSAPublicKey, DSA's, DHparams and DHxparams, ECPrivateKey and ECParameters) — and an EC key's
//! public point as a blob.
//!
//! As OpenSSL's:
//! - An encoder writes the first of the private key, the public key, and the parameters the
//!   selection asks for that its structure holds.
//! - A PrivateKeyInfo encoder given a cipher writes an EncryptedPrivateKeyInfo (PBES2 of the
//!   cipher), and an EncryptedPrivateKeyInfo encoder given none writes nothing.
//! - A type-specific PEM private key given a cipher is a traditional encrypted PEM.
//! - `import_object` makes a key of the encoder's type from another provider's key's parameters.
//!
//! The text encoders' text is `key2text`'s; MSBLOB's and PVK's encoders are `key2ms`'s.

use core::ffi::{CStr, c_char, c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_OBJECT, BIO, DH_FLAG_TYPE_DHX, EC_PKEY_NO_PARAMETERS, ERR_LIB_PROV, ERR_R_ASN1_LIB,
    ERR_R_PASSED_INVALID_ARGUMENT, ERR_R_PASSED_NULL_PARAMETER, ERR_R_PROV_LIB, ERR_R_X509_LIB,
    EVP_CIPHER, EVP_PKEY_DH, EVP_PKEY_DHX, EVP_PKEY_DSA, EVP_PKEY_EC, EVP_PKEY_ED448,
    EVP_PKEY_ED25519, EVP_PKEY_PUBLIC_KEY, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS, EVP_PKEY_X448,
    EVP_PKEY_X25519, NID_ML_DSA_44, NID_ML_DSA_65, NID_ML_DSA_87, NID_ML_KEM_512, NID_ML_KEM_768,
    NID_ML_KEM_1024, NID_SLH_DSA_SHA2_128f, NID_SLH_DSA_SHA2_128s, NID_SLH_DSA_SHA2_192f,
    NID_SLH_DSA_SHA2_192s, NID_SLH_DSA_SHA2_256f, NID_SLH_DSA_SHA2_256s, NID_SLH_DSA_SHAKE_128f,
    NID_SLH_DSA_SHAKE_128s, NID_SLH_DSA_SHAKE_192f, NID_SLH_DSA_SHAKE_192s, NID_SLH_DSA_SHAKE_256f,
    NID_SLH_DSA_SHAKE_256s, NID_undef, OPENSSL_EC_NAMED_CURVE, OSSL_ALGORITHM, OSSL_CORE_BIO,
    OSSL_DISPATCH, OSSL_ENCODER_PARAM_CIPHER, OSSL_ENCODER_PARAM_PROPERTIES,
    OSSL_ENCODER_PARAM_SAVE_PARAMETERS, OSSL_FUNC_ENCODER_DOES_SELECTION, OSSL_FUNC_ENCODER_ENCODE,
    OSSL_FUNC_ENCODER_FREE_OBJECT, OSSL_FUNC_ENCODER_FREECTX, OSSL_FUNC_ENCODER_IMPORT_OBJECT,
    OSSL_FUNC_ENCODER_NEWCTX, OSSL_FUNC_ENCODER_SET_CTX_PARAMS,
    OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS, OSSL_FUNC_KEYMGMT_FREE, OSSL_FUNC_KEYMGMT_IMPORT,
    OSSL_FUNC_KEYMGMT_NEW, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
    OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_PARAM, OSSL_PARAM_INTEGER, OSSL_PARAM_UTF8_STRING,
    OSSL_PASSPHRASE_CALLBACK, PEM_BUFSIZE, PKCS8_PRIV_KEY_INFO, PROV_R_BN_ERROR,
    PROV_R_MISSING_OID, PROV_R_NOT_A_PRIVATE_KEY, PROV_R_NOT_A_PUBLIC_KEY,
    PROV_R_UNABLE_TO_GET_PASSPHRASE, V_ASN1_NULL, V_ASN1_OBJECT, V_ASN1_SEQUENCE, V_ASN1_UNDEF,
    X509_PUBKEY, X509_SIG,
};

use super::builtin::libctx_of;
use super::tables::{ALG_END, Algorithms, Dispatch, END, PARAM_END, Params, defn, entry};
use crate::asn1::string::{
    ASN1_STRING_clear_free, ASN1_STRING_free, ASN1_STRING_new, ASN1_STRING_set0,
};
use crate::bio::{BIO_free, BIO_write};
use crate::decoder::ctx::bio_new_from_core_bio;
use crate::err;
use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free};
use crate::ffi::ffi_callback;
use crate::mem;
use crate::objects::{ASN1_OBJECT_free, OBJ_length, OBJ_nid2obj};
use crate::params::{OSSL_PARAM_get_int, OSSL_PARAM_get_utf8_string_ptr, OSSL_PARAM_locate_const};
use crate::passphrase::{PwData, pw_pem_password};
use rustyssl_crypto::bn::Zeroizing;

/// A key's DER (`OSSL_i2d_of_void_ctx`), given the encoder's context: its length, with `*pder`
/// set to a new buffer when it holds NULL; 0 or less on failure.
type K2d = unsafe extern "C" fn(*const c_void, *mut *mut c_uchar, *mut c_void) -> c_int;
/// `key_to_paramstring_fn`: the AlgorithmIdentifier parameters of a key (with whether to save
/// the domain parameters) and their ASN.1 type; `None` on failure.
type P2s = unsafe fn(*const c_void, c_int, bool) -> Option<(*mut c_void, c_int)>;
/// `check_key_type_fn`: whether a key is of the encoder's type.
type Check = unsafe fn(*const c_void, c_int) -> bool;

type NewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
type ListFn = unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM;
type SetParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type DoesSelectionFn = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
type ImportObjectFn = unsafe extern "C" fn(*mut c_void, c_int, *const OSSL_PARAM) -> *mut c_void;
type FreeObjectFn = unsafe extern "C" fn(*mut c_void);
type EncodeFn = unsafe extern "C" fn(
    *mut c_void,
    *mut OSSL_CORE_BIO,
    *const c_void,
    *const OSSL_PARAM,
    c_int,
    OSSL_PASSPHRASE_CALLBACK,
    *mut c_void,
) -> c_int;

/// A key family's functions (`type` in `MAKE_ENCODER`: what `rsa`, `dh`, `ec`, … supply).
struct Family {
    check: Option<Check>,
    params: Option<P2s>,
    /// The PrivateKeyInfo's (and EncryptedPrivateKeyInfo's) private key.
    pki: Option<K2d>,
    /// The SubjectPublicKeyInfo's public key.
    spki: Option<K2d>,
    private: Option<K2d>,
    public: Option<K2d>,
    domain: Option<K2d>,
    /// The key's text (`type##_to_text`).
    to_text: super::key2text::ToText,
}

/// A key type (`impl` in `MAKE_ENCODER`).
struct Impl {
    family: &'static Family,
    evp_type: c_int,
    /// The type-specific PEM names (`impl##_pem_type " PRIVATE KEY"` and the others).
    private_pem: &'static CStr,
    public_pem: &'static CStr,
    params_pem: &'static CStr,
    /// The type's key manager (`ossl_##impl##_keymgmt_functions`).
    keymgmt: &'static [OSSL_DISPATCH],
}

// SAFETY: static tables of functions and strings only; never written.
unsafe impl Sync for Impl {}

/// The structures an encoder writes (`DO_*` in `encode_key2any.c`).
#[derive(Clone, Copy)]
enum Kind {
    EncryptedPrivateKeyInfo,
    PrivateKeyInfo,
    SubjectPublicKeyInfo,
    /// `type_specific_keypair`, `RSA`, and `PKCS1`.
    Keypair,
    /// `type_specific_params`, `DH`, `DHX`, `PKCS3`, and `X9_42`.
    Params,
    /// `type_specific` and `DSA`.
    All,
    /// `type_specific_no_pub`, `EC`, `SM2`, and `X9_62`.
    NoPub,
}

impl Kind {
    /// `DO_##kind##_selection_mask`.
    const fn mask(self) -> c_int {
        match self {
            Self::EncryptedPrivateKeyInfo | Self::PrivateKeyInfo => OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
            Self::SubjectPublicKeyInfo => OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
            Self::Keypair => OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
            Self::Params => OSSL_KEYMGMT_SELECT_ALL_PARAMETERS,
            Self::All => {
                OSSL_KEYMGMT_SELECT_PRIVATE_KEY
                    | OSSL_KEYMGMT_SELECT_PUBLIC_KEY
                    | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS
            }
            Self::NoPub => OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS,
        }
    }
}

/// An encoder's output.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Output {
    Der,
    Pem,
}

/// An encoder's description: its key type, structures, and output.
struct Desc {
    imp: &'static Impl,
    kind: Kind,
    output: Output,
}

/// `KEY2ANY_CTX`, with the encoder's description.
struct Key2Any {
    provctx: *mut c_void,
    save_parameters: c_int,
    cipher_intent: bool,
    cipher: *mut EVP_CIPHER,
    pwdata: PwData,
    desc: &'static Desc,
}

/// `key2any_newctx`: saving the parameters, with no cipher.
fn newctx(provctx: *mut c_void, desc: &'static Desc) -> *mut c_void {
    Box::into_raw(Box::new(Key2Any {
        provctx,
        save_parameters: 1,
        cipher_intent: false,
        cipher: ptr::null_mut(),
        pwdata: PwData::default(),
        desc,
    }))
    .cast()
}

/// The context behind `vctx`.
///
/// # Safety
/// `vctx` is NULL or a live context from `newctx`.
unsafe fn kctx<'a>(vctx: *mut c_void) -> Option<&'a mut Key2Any> {
    // SAFETY: the caller's guarantee.
    unsafe { vctx.cast::<Key2Any>().as_mut() }
}

ffi_callback! {
    /// `key2any_freectx`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context from `newctx` the caller gives up.
    pub(crate) unsafe extern "C" fn key2any_freectx(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        if vctx.is_null() {
            return;
        }
        // SAFETY: the caller's guarantee.
        let mut c = unsafe { Box::from_raw(vctx.cast::<Key2Any>()) };
        c.pwdata.clear();
        // SAFETY: the context's cipher, or NULL.
        unsafe { EVP_CIPHER_free(c.cipher) };
    }
}

/// `key2any_settable_ctx_params`'s table.
static SETTABLE: Params<4> = Params([
    defn(OSSL_ENCODER_PARAM_CIPHER, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_ENCODER_PARAM_PROPERTIES, OSSL_PARAM_UTF8_STRING, 0),
    defn(
        OSSL_ENCODER_PARAM_SAVE_PARAMETERS,
        OSSL_PARAM_INTEGER,
        size_of::<c_int>(),
    ),
    PARAM_END,
]);

ffi_callback! {
    /// `key2any_settable_ctx_params`: the cipher, its properties, and whether to save a key's
    /// parameters (listed from 3.6).
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn key2any_settable_ctx_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        SETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `key2any_set_ctx_params`: the cipher (fetched with the properties, NULL for none) and
    /// whether to save the parameters.
    ///
    /// # Safety
    /// `vctx` is a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn key2any_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { kctx(vctx) }) else { return 0 };
        // SAFETY: the provider's context.
        let libctx = unsafe { libctx_of(c.provctx) };
        // SAFETY: the caller's array; static names.
        let cipherp = unsafe { OSSL_PARAM_locate_const(params, OSSL_ENCODER_PARAM_CIPHER.as_ptr()) };
        // SAFETY: as above.
        let propsp = unsafe { OSSL_PARAM_locate_const(params, OSSL_ENCODER_PARAM_PROPERTIES.as_ptr()) };
        // SAFETY: as above.
        let savep = unsafe { OSSL_PARAM_locate_const(params, OSSL_ENCODER_PARAM_SAVE_PARAMETERS.as_ptr()) };
        if !cipherp.is_null() {
            let mut ciphername: *const c_char = ptr::null();
            let mut props: *const c_char = ptr::null();
            // SAFETY: a parameter of the array.
            if unsafe { OSSL_PARAM_get_utf8_string_ptr(cipherp, &raw mut ciphername) } == 0 {
                return 0;
            }
            // SAFETY: as above.
            if !propsp.is_null() && unsafe { OSSL_PARAM_get_utf8_string_ptr(propsp, &raw mut props) } == 0 {
                return 0;
            }
            // SAFETY: the context's cipher, or NULL.
            unsafe { EVP_CIPHER_free(c.cipher) };
            c.cipher = ptr::null_mut();
            c.cipher_intent = !ciphername.is_null();
            if !ciphername.is_null() {
                // SAFETY: the provider's library context; the parameters' strings.
                c.cipher = unsafe { EVP_CIPHER_fetch(libctx, ciphername, props) };
                if c.cipher.is_null() {
                    return 0;
                }
            }
        }
        // SAFETY: as above.
        if !savep.is_null() && unsafe { OSSL_PARAM_get_int(savep, &raw mut c.save_parameters) } == 0 {
            return 0;
        }
        1
    }
}

/// `key2any_check_selection`: whether the structures hold the first of the private key, the
/// public key, and the parameters the selection asks for (any, for none).
fn check_selection(selection: c_int, mask: c_int) -> c_int {
    if selection == 0 {
        return 1;
    }
    for check in [
        OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
        OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
        OSSL_KEYMGMT_SELECT_ALL_PARAMETERS,
    ] {
        if selection & check != 0 {
            return c_int::from(mask & check != 0);
        }
    }
    0
}

/// `ossl_prov_import_key`: a new key of the key manager `fns` (with the provider's context),
/// imported from `params`; NULL if it can't.
///
/// # Safety
/// `fns` is one of the built-in key managers' tables; `params` is NULL or an array.
pub(super) unsafe fn import_key(
    fns: &[OSSL_DISPATCH],
    provctx: *mut c_void,
    selection: c_int,
    params: *const OSSL_PARAM,
) -> *mut c_void {
    type NewFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
    type ImportFn = unsafe extern "C" fn(*mut c_void, c_int, *const OSSL_PARAM) -> c_int;
    let find = |id: c_int| {
        fns.iter()
            .take_while(|d| d.function_id != 0)
            .find(|d| d.function_id == id)
            .and_then(|d| d.function)
    };
    let (Some(new), Some(import), Some(free)) = (
        find(OSSL_FUNC_KEYMGMT_NEW),
        find(OSSL_FUNC_KEYMGMT_IMPORT),
        find(OSSL_FUNC_KEYMGMT_FREE),
    ) else {
        return ptr::null_mut();
    };
    // SAFETY: the table's function for this id, of this type.
    let new: NewFn = unsafe { core::mem::transmute_copy(&new) };
    // SAFETY: as above.
    let import: ImportFn = unsafe { core::mem::transmute_copy(&import) };
    // SAFETY: as above.
    let free: FreeObjectFn = unsafe { core::mem::transmute_copy(&free) };
    // SAFETY: the provider's context.
    let key = unsafe { new(provctx) };
    // SAFETY: the new key; the caller's array.
    if key.is_null() || unsafe { import(key, selection, params) } == 0 {
        // SAFETY: the new key, or NULL.
        unsafe { free(key) };
        return ptr::null_mut();
    }
    key
}

/// `ossl_prov_free_key`.
///
/// # Safety
/// As for `import_key`, with `key` NULL or a key of that key manager the caller gives up.
unsafe fn free_key(fns: &[OSSL_DISPATCH], key: *mut c_void) {
    let free = fns
        .iter()
        .take_while(|d| d.function_id != 0)
        .find(|d| d.function_id == OSSL_FUNC_KEYMGMT_FREE)
        .and_then(|d| d.function);
    if let Some(free) = free {
        // SAFETY: the table's function for this id, of this type.
        let free: FreeObjectFn = unsafe { core::mem::transmute_copy(&free) };
        // SAFETY: the caller's guarantee.
        unsafe { free(key) };
    }
}

ffi_callback! {
    /// The key-to-DER encoders' `import_object`: a key of the encoder's type.
    ///
    /// # Safety
    /// `vctx` is a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn key2any_import_object(vctx: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { kctx(vctx) }) else { return ptr::null_mut() };
        // SAFETY: a built-in table; the caller's array.
        unsafe { import_key(c.desc.imp.keymgmt, c.provctx, selection, params) }
    }
}

/// Frees what `free_asn1_data` frees: AlgorithmIdentifier parameters of type `t`.
///
/// # Safety
/// `data` is NULL, or an `ASN1_OBJECT` or `ASN1_STRING` (by `t`) the caller gives up.
unsafe fn free_asn1_data(t: c_int, data: *mut c_void) {
    match t {
        // SAFETY: the caller's guarantee.
        V_ASN1_OBJECT => unsafe { ASN1_OBJECT_free(data.cast()) },
        // SAFETY: as above.
        V_ASN1_SEQUENCE => unsafe { ASN1_STRING_free(data.cast()) },
        _ => {}
    }
}

/// The parameters `p2s` makes of the key (none, `V_ASN1_UNDEF`, without it); `None` on
/// failure.
///
/// # Safety
/// `key` is a key of the family `p2s` belongs to.
unsafe fn params_of(
    p2s: Option<P2s>,
    key: *const c_void,
    nid: c_int,
    c: &Key2Any,
) -> Option<(*mut c_void, c_int)> {
    match p2s {
        // SAFETY: the caller's guarantee.
        Some(f) => unsafe { f(key, nid, c.save_parameters != 0) },
        None => Some((ptr::null_mut(), V_ASN1_UNDEF)),
    }
}

/// `key_to_p8info`: a PrivateKeyInfo of the key, taking the parameters only on success.
///
/// # Safety
/// `key` is a key `k2d` takes; `c` is the live context `k2d` is given.
unsafe fn key_to_p8info(
    key: *const c_void,
    nid: c_int,
    params: (*mut c_void, c_int),
    k2d: K2d,
    c: *mut Key2Any,
) -> *mut PKCS8_PRIV_KEY_INFO {
    // SAFETY: no preconditions.
    let p8info = unsafe { crate::x509::p8::PKCS8_PRIV_KEY_INFO_new() };
    let mut der: *mut c_uchar = ptr::null_mut();
    let mut ok = false;
    if !p8info.is_null() {
        // SAFETY: the caller's guarantee; a new buffer into `der`.
        let derlen = unsafe { k2d(key, &raw mut der, c.cast()) };
        // SAFETY: a built-in NID.
        let obj = unsafe { OBJ_nid2obj(nid) };
        // SAFETY: the new structure takes the object, the parameters, and the DER.
        ok = derlen > 0
            && unsafe {
                crate::x509::p8::PKCS8_pkey_set0(p8info, obj, 0, params.1, params.0, der, derlen)
            } != 0;
    }
    if !ok {
        err::raise(ERR_LIB_PROV, ERR_R_ASN1_LIB, "key_to_p8info");
        // SAFETY: made above, or NULL.
        unsafe { crate::x509::p8::PKCS8_PRIV_KEY_INFO_free(p8info) };
        // SAFETY: the DER, or NULL.
        unsafe { mem::release(der.cast()) };
        return ptr::null_mut();
    }
    p8info
}

/// `p8info_to_encp8`: the PrivateKeyInfo encrypted with the context's cipher and passphrase;
/// NULL if there's no cipher.
///
/// # Safety
/// `c` is a live context.
unsafe fn p8info_to_encp8(p8info: *mut PKCS8_PRIV_KEY_INFO, c: *mut Key2Any) -> *mut X509_SIG {
    // SAFETY: the caller's guarantee.
    let Some(cx) = (unsafe { c.as_mut() }) else {
        return ptr::null_mut();
    };
    if cx.cipher.is_null() {
        return ptr::null_mut();
    }
    let mut kstr = Zeroizing::new([0 as c_char; PEM_BUFSIZE as usize]);
    let mut klen = 0usize;
    // SAFETY: room for the buffer's size; the context's passphrase data.
    if !unsafe {
        PwData::get(
            &raw mut cx.pwdata,
            kstr.as_mut_ptr(),
            kstr.len(),
            &raw mut klen,
            ptr::null(),
            true,
        )
    } {
        err::raise(
            ERR_LIB_PROV,
            PROV_R_UNABLE_TO_GET_PASSPHRASE,
            "p8info_to_encp8",
        );
        return ptr::null_mut();
    }
    let klen = c_int::try_from(klen).unwrap_or(0);
    // SAFETY: the provider's context.
    let libctx = unsafe { libctx_of(cx.provctx) };
    // SAFETY: the context's cipher; the passphrase; the caller's PrivateKeyInfo.
    unsafe {
        crate::pkcs8_crypt::PKCS8_encrypt_ex(
            -1,
            cx.cipher,
            kstr.as_ptr(),
            klen,
            ptr::null_mut(),
            0,
            0,
            p8info,
            libctx,
            ptr::null(),
        )
    }
}

/// `key_to_encp8`: an EncryptedPrivateKeyInfo of the key, freeing the parameters if no
/// PrivateKeyInfo takes them.
///
/// # Safety
/// As for `key_to_p8info`.
unsafe fn key_to_encp8(
    key: *const c_void,
    nid: c_int,
    params: (*mut c_void, c_int),
    k2d: K2d,
    c: *mut Key2Any,
) -> *mut X509_SIG {
    // SAFETY: the caller's guarantee.
    let p8info = unsafe { key_to_p8info(key, nid, params, k2d, c) };
    if p8info.is_null() {
        // SAFETY: the parameters, not taken.
        unsafe { free_asn1_data(params.1, params.0) };
        return ptr::null_mut();
    }
    // SAFETY: the new structure; the caller's context.
    let p8 = unsafe { p8info_to_encp8(p8info, c) };
    // SAFETY: made above.
    unsafe { crate::x509::p8::PKCS8_PRIV_KEY_INFO_free(p8info) };
    p8
}

/// `key_to_pubkey`: a SubjectPublicKeyInfo of the key, taking the parameters only on success.
///
/// # Safety
/// As for `key_to_p8info`.
unsafe fn key_to_pubkey(
    key: *const c_void,
    nid: c_int,
    params: (*mut c_void, c_int),
    k2d: K2d,
    c: *mut Key2Any,
) -> *mut X509_PUBKEY {
    use crate::x509::pubkey::{X509_PUBKEY_free, X509_PUBKEY_new, X509_PUBKEY_set0_param};
    // SAFETY: no preconditions.
    let xpk = unsafe { X509_PUBKEY_new() };
    let mut der: *mut c_uchar = ptr::null_mut();
    let mut ok = false;
    if !xpk.is_null() {
        // SAFETY: the caller's guarantee; a new buffer into `der`.
        let derlen = unsafe { k2d(key, &raw mut der, c.cast()) };
        // SAFETY: a built-in NID.
        let obj = unsafe { OBJ_nid2obj(nid) };
        // SAFETY: the new structure takes the object, the parameters, and the DER.
        ok = derlen > 0
            && unsafe { X509_PUBKEY_set0_param(xpk, obj, params.1, params.0, der, derlen) } != 0;
    }
    if !ok {
        err::raise(ERR_LIB_PROV, ERR_R_X509_LIB, "key_to_pubkey");
        // SAFETY: made above, or NULL.
        unsafe { X509_PUBKEY_free(xpk) };
        // SAFETY: the DER, or NULL.
        unsafe { mem::release(der.cast()) };
        return ptr::null_mut();
    }
    xpk
}

/// How an encoder writes what it writes (`key_to_##kind##_##output##_*_bio`).
#[derive(Clone, Copy)]
enum Writer {
    EncryptedPrivateKeyInfo,
    PrivateKeyInfo,
    SubjectPublicKeyInfo,
    /// A type-specific private key (in PEM, asking for a passphrase to encrypt it).
    Private,
    /// A type-specific public key or parameters.
    Plain,
}

/// The arguments of a `key_to_der_fn`.
struct Job {
    out: *mut BIO,
    key: *const c_void,
    nid: c_int,
    pemname: &'static CStr,
    p2s: Option<P2s>,
    k2d: K2d,
    ctx: *mut Key2Any,
}

/// The writer's `key_to_der_fn`.
///
/// # Safety
/// The job's BIO and context are live and its key is one its functions take.
unsafe fn write(w: Writer, output: Output, j: &Job) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { j.ctx.as_mut() }) else {
        return 0;
    };
    match w {
        Writer::EncryptedPrivateKeyInfo => {
            if !c.cipher_intent {
                return 0;
            }
            // SAFETY: the caller's guarantee.
            let Some(params) = (unsafe { params_of(j.p2s, j.key, j.nid, c) }) else {
                return 0;
            };
            // SAFETY: as above.
            let p8 = unsafe { key_to_encp8(j.key, j.nid, params, j.k2d, j.ctx) };
            let mut ret = 0;
            if !p8.is_null() {
                ret = match output {
                    // SAFETY: the BIO; the new structure.
                    Output::Der => unsafe { crate::x509::sig::i2d_PKCS8_bio(j.out, p8) },
                    // SAFETY: as above.
                    Output::Pem => unsafe { crate::pem_pkey::PEM_write_bio_PKCS8(j.out, p8) },
                };
            }
            // SAFETY: made above, or NULL.
            unsafe { crate::x509::sig::X509_SIG_free(p8) };
            ret
        }
        Writer::PrivateKeyInfo => {
            if c.cipher_intent {
                // SAFETY: the caller's guarantee.
                return unsafe { write(Writer::EncryptedPrivateKeyInfo, output, j) };
            }
            // SAFETY: as above.
            let Some(params) = (unsafe { params_of(j.p2s, j.key, j.nid, c) }) else {
                return 0;
            };
            // SAFETY: as above.
            let p8info = unsafe { key_to_p8info(j.key, j.nid, params, j.k2d, j.ctx) };
            let mut ret = 0;
            if p8info.is_null() {
                // SAFETY: the parameters, not taken.
                unsafe { free_asn1_data(params.1, params.0) };
            } else {
                ret = match output {
                    // SAFETY: the BIO; the new structure.
                    Output::Der => unsafe {
                        crate::x509::p8::i2d_PKCS8_PRIV_KEY_INFO_bio(j.out, p8info)
                    },
                    // SAFETY: as above.
                    Output::Pem => unsafe {
                        crate::pem_pkey::PEM_write_bio_PKCS8_PRIV_KEY_INFO(j.out, p8info)
                    },
                };
            }
            // SAFETY: made above, or NULL.
            unsafe { crate::x509::p8::PKCS8_PRIV_KEY_INFO_free(p8info) };
            ret
        }
        Writer::SubjectPublicKeyInfo => {
            // SAFETY: the caller's guarantee.
            let Some(params) = (unsafe { params_of(j.p2s, j.key, j.nid, c) }) else {
                return 0;
            };
            // SAFETY: as above.
            let xpk = unsafe { key_to_pubkey(j.key, j.nid, params, j.k2d, j.ctx) };
            let mut ret = 0;
            if xpk.is_null() {
                // SAFETY: the parameters, not taken.
                unsafe { free_asn1_data(params.1, params.0) };
            } else {
                ret = match output {
                    // SAFETY: the BIO; the new structure.
                    Output::Der => unsafe { crate::x509::pubkey::i2d_X509_PUBKEY_bio(j.out, xpk) },
                    // SAFETY: as above.
                    Output::Pem => unsafe {
                        crate::pem_pkey::PEM_write_bio_X509_PUBKEY(j.out, xpk)
                    },
                };
            }
            // SAFETY: made above, or NULL.
            unsafe { crate::x509::pubkey::X509_PUBKEY_free(xpk) };
            ret
        }
        Writer::Private | Writer::Plain if output == Output::Der => {
            let mut der: *mut c_uchar = ptr::null_mut();
            // SAFETY: the caller's guarantee; a new buffer into `der`.
            let derlen = unsafe { (j.k2d)(j.key, &raw mut der, j.ctx.cast()) };
            let Some(len) = usize::try_from(derlen).ok().filter(|&l| l > 0) else {
                err::raise(ERR_LIB_PROV, ERR_R_PROV_LIB, "key_to_type_specific_der_bio");
                return 0;
            };
            // SAFETY: the BIO; the DER's `derlen` octets.
            let ret = unsafe { BIO_write(j.out, der.cast(), derlen) };
            // SAFETY: the DER, which may hold a private key.
            unsafe { mem::release_clean(der.cast(), len) };
            c_int::from(ret > 0)
        }
        Writer::Private | Writer::Plain => {
            let (cb, cbarg): (rustyssl_abi::pem_password_cb, *mut c_void) = match w {
                Writer::Private => (Some(pw_pem_password), (&raw mut c.pwdata).cast()),
                _ => (None, ptr::null_mut()),
            };
            // SAFETY: the job's function, context, name, BIO, and key; the context's cipher
            // (or NULL); the passphrase callback over the context's data.
            let ret = unsafe {
                crate::pem_cipher::PEM_ASN1_write_bio_ctx(
                    Some(j.k2d),
                    j.ctx.cast(),
                    j.pemname.as_ptr(),
                    j.out,
                    j.key,
                    c.cipher,
                    ptr::null(),
                    0,
                    cb,
                    cbarg,
                )
            };
            c_int::from(ret > 0)
        }
    }
}

/// `key2any_encode`: the key written by `w`, if it's of the type (`check`).
///
/// # Safety
/// `c` is a live context; `cout` a core BIO; `key` NULL or a key the family's functions take.
#[allow(clippy::too_many_arguments, reason = "key2any_encode's")]
unsafe fn key2any_encode(
    c: *mut Key2Any,
    cout: *mut OSSL_CORE_BIO,
    key: *const c_void,
    w: Writer,
    pemname: &'static CStr,
    k2d: Option<K2d>,
    p2s: Option<P2s>,
    pw: (OSSL_PASSPHRASE_CALLBACK, *mut c_void),
) -> c_int {
    const F: &str = "key2any_encode";
    // SAFETY: the caller's guarantee.
    let Some(cx) = (unsafe { c.as_mut() }) else {
        return 0;
    };
    let imp = cx.desc.imp;
    if key.is_null() {
        err::raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER, F);
        return 0;
    }
    // SAFETY: the caller's key.
    let of_type = imp
        .family
        .check
        .is_none_or(|f| unsafe { f(key, imp.evp_type) });
    let Some(k2d) = k2d.filter(|_| of_type) else {
        err::raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT, F);
        return 0;
    };
    // SAFETY: the caller's core BIO.
    let out = unsafe { bio_new_from_core_bio(cout) };
    let mut ret = 0;
    if !out.is_null() && (pw.0.is_none() || cx.pwdata.set_ossl_passphrase_cb(pw.0, pw.1)) {
        let job = Job {
            out,
            key,
            nid: imp.evp_type,
            pemname,
            p2s,
            k2d,
            ctx: c,
        };
        // SAFETY: the BIO made here; the caller's context and key.
        ret = unsafe { write(w, cx.desc.output, &job) };
    }
    // SAFETY: made above, or NULL.
    unsafe { BIO_free(out) };
    ret
}

ffi_callback! {
    /// The key-to-DER encoders' `encode` (`impl##_to_##kind##_##output##_encode`): the first of
    /// the private key, the public key, and the parameters the selection asks for that the
    /// structures hold.
    ///
    /// # Safety
    /// `vctx` is a live context; `cout` a core BIO; `key` NULL or a key of the encoder's type.
    pub(crate) unsafe extern "C" fn key2any_encode_cb(vctx: *mut c_void, cout: *mut OSSL_CORE_BIO, key: *const c_void, key_abstract: *const OSSL_PARAM, selection: c_int, cb: OSSL_PASSPHRASE_CALLBACK, cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "key2any_encode";
        let c: *mut Key2Any = vctx.cast();
        // SAFETY: the caller's guarantee.
        let Some(cx) = (unsafe { c.as_ref() }) else { return 0 };
        if !key_abstract.is_null() {
            err::raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT, F);
            return 0;
        }
        let (imp, kind) = (cx.desc.imp, cx.desc.kind);
        let fam = imp.family;
        let pw = (cb, cbarg);
        let private = |w: Writer, k2d: Option<K2d>| (OSSL_KEYMGMT_SELECT_PRIVATE_KEY, w, imp.private_pem, k2d, fam.params, pw);
        let public = |w: Writer, k2d: Option<K2d>| (OSSL_KEYMGMT_SELECT_PUBLIC_KEY, w, imp.public_pem, k2d, fam.params, pw);
        let domain = (OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, Writer::Plain, imp.params_pem, fam.domain, None, (None, ptr::null_mut()));
        let steps = match kind {
            Kind::EncryptedPrivateKeyInfo => vec![private(Writer::EncryptedPrivateKeyInfo, fam.pki)],
            Kind::PrivateKeyInfo => vec![private(Writer::PrivateKeyInfo, fam.pki)],
            Kind::SubjectPublicKeyInfo => vec![public(Writer::SubjectPublicKeyInfo, fam.spki)],
            Kind::Keypair => vec![private(Writer::Private, fam.private), public(Writer::Plain, fam.public)],
            Kind::Params => vec![domain],
            Kind::All => vec![private(Writer::Private, fam.private), public(Writer::Plain, fam.public), domain],
            Kind::NoPub => vec![private(Writer::Private, fam.private), domain],
        };
        for (mask, w, pemname, k2d, p2s, pw) in steps {
            if selection & mask != 0 {
                // SAFETY: the caller's guarantee.
                return unsafe { key2any_encode(c, cout, key, w, pemname, k2d, p2s, pw) };
            }
        }
        err::raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT, F);
        0
    }
}

/// A key-to-DER encoder's dispatch table, with its own `newctx`.
macro_rules! encoder {
    ($table:ident, $newctx:ident, $imp:ident, $kind:ident, $output:ident) => {
        ffi_callback! {
            /// The encoder's `newctx`.
            ///
            /// # Safety
            /// `provctx` is the provider's context.
            pub(crate) unsafe extern "C" fn $newctx(provctx: *mut c_void) -> *mut c_void
            where failure = ptr::null_mut(), library = ERR_LIB_PROV
            {
                static DESC: Desc = Desc { imp: &$imp, kind: Kind::$kind, output: Output::$output };
                newctx(provctx, &DESC)
            }
        }

        static $table: Dispatch<9> = Dispatch([
            entry!(OSSL_FUNC_ENCODER_NEWCTX, $newctx, NewCtxFn),
            entry!(OSSL_FUNC_ENCODER_FREECTX, key2any_freectx, FreeCtxFn),
            entry!(
                OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                key2any_settable_ctx_params,
                ListFn
            ),
            entry!(
                OSSL_FUNC_ENCODER_SET_CTX_PARAMS,
                key2any_set_ctx_params,
                SetParamsFn
            ),
            entry!(
                OSSL_FUNC_ENCODER_DOES_SELECTION,
                does::$kind,
                DoesSelectionFn
            ),
            entry!(
                OSSL_FUNC_ENCODER_IMPORT_OBJECT,
                key2any_import_object,
                ImportObjectFn
            ),
            entry!(OSSL_FUNC_ENCODER_FREE_OBJECT, free::$imp, FreeObjectFn),
            entry!(OSSL_FUNC_ENCODER_ENCODE, key2any_encode_cb, EncodeFn),
            END,
        ]);
    };
}

/// The encoders' `does_selection`, one per structure kind.
#[allow(non_snake_case, reason = "named for the kinds")]
mod does {
    use core::ffi::{c_int, c_void};

    use rustyssl_abi::ERR_LIB_PROV;

    use super::{Kind, check_selection};
    use crate::ffi::ffi_callback;

    macro_rules! does {
        ($($kind:ident),*) => {$(
            ffi_callback! {
                /// `does_selection` of the kind's encoders.
                ///
                /// # Safety
                /// No preconditions.
                pub(crate) unsafe extern "C" fn $kind(_ctx: *mut c_void, selection: c_int) -> c_int
                where failure = 0, library = ERR_LIB_PROV
                {
                    check_selection(selection, Kind::$kind.mask())
                }
            }
        )*};
    }
    does!(
        EncryptedPrivateKeyInfo,
        PrivateKeyInfo,
        SubjectPublicKeyInfo,
        Keypair,
        Params,
        All,
        NoPub
    );
}

/// The encoders' `free_object`, one per key type (`ossl_prov_free_key` with its key manager).
#[allow(non_snake_case, reason = "named for the key types")]
mod free {
    use core::ffi::c_void;

    use rustyssl_abi::ERR_LIB_PROV;

    use super::*;

    macro_rules! free {
        ($($imp:ident),*) => {$(
            ffi_callback! {
                /// `free_object` of the key type's encoders.
                ///
                /// # Safety
                /// `key` is NULL or a key of the type the caller gives up.
                pub(crate) unsafe extern "C" fn $imp(key: *mut c_void)
                where failure = (), library = ERR_LIB_PROV
                {
                    // SAFETY: a built-in table; the caller's guarantee.
                    unsafe { free_key(super::$imp.keymgmt, key) }
                }
            }
        )*};
    }
    free!(
        RSA,
        RSAPSS,
        DH,
        DHX,
        DSA,
        EC,
        SM2,
        ED25519,
        ED448,
        X25519,
        X448,
        ML_KEM_512,
        ML_KEM_768,
        ML_KEM_1024,
        ML_DSA_44,
        ML_DSA_65,
        ML_DSA_87,
        SLH_DSA_SHA2_128S,
        SLH_DSA_SHA2_128F,
        SLH_DSA_SHA2_192S,
        SLH_DSA_SHA2_192F,
        SLH_DSA_SHA2_256S,
        SLH_DSA_SHA2_256F,
        SLH_DSA_SHAKE_128S,
        SLH_DSA_SHAKE_128F,
        SLH_DSA_SHAKE_192S,
        SLH_DSA_SHAKE_192F,
        SLH_DSA_SHAKE_256S,
        SLH_DSA_SHAKE_256F
    );
}

// The key families' functions.

/// The octets as an `i2d` gives them: their length, written to `*pder` (moved past them) or a
/// new buffer there when it holds NULL; just the length for a NULL `pder`; 0 if it can't.
///
/// # Safety
/// `pder` is NULL, or holds NULL or room for the octets.
unsafe fn give(bytes: &[u8], pder: *mut *mut c_uchar) -> c_int {
    let Ok(len) = c_int::try_from(bytes.len()) else {
        return 0;
    };
    if pder.is_null() {
        return len;
    }
    // SAFETY: the caller's guarantee.
    let at = unsafe { pder.read() };
    if at.is_null() {
        let buf: *mut c_uchar = mem::malloc(bytes.len(), ptr::null(), 0).cast();
        if buf.is_null() {
            return 0;
        }
        // SAFETY: a new buffer of the octets' length.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len()) };
        // SAFETY: the caller's guarantee.
        unsafe { pder.write(buf) };
    } else {
        // SAFETY: the caller's room for the octets.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), at, bytes.len()) };
        // SAFETY: as above.
        unsafe { pder.write(at.wrapping_add(bytes.len())) };
    }
    len
}

/// The key's AlgorithmIdentifier parameters as a SEQUENCE string made by `i2d`; `None` (with
/// `ERR_R_ASN1_LIB` from `f`) on failure.
///
/// # Safety
/// `i2d` takes `key`.
unsafe fn seq_params(
    key: *const c_void,
    f: &str,
    i2d: impl FnOnce(*const c_void, *mut *mut c_uchar) -> c_int,
    set_type: bool,
) -> Option<(*mut c_void, c_int)> {
    // SAFETY: no preconditions.
    let params = unsafe { ASN1_STRING_new() };
    // SAFETY: made here, or NULL.
    let Some(s) = (unsafe { params.as_mut() }) else {
        err::raise(ERR_LIB_PROV, ERR_R_ASN1_LIB, f);
        return None;
    };
    s.length = i2d(key, &raw mut s.data);
    if s.length <= 0 {
        err::raise(ERR_LIB_PROV, ERR_R_ASN1_LIB, f);
        // SAFETY: made above.
        unsafe { ASN1_STRING_free(params) };
        return None;
    }
    if set_type {
        s.type_ = V_ASN1_SEQUENCE;
    }
    Some((params.cast(), V_ASN1_SEQUENCE))
}

/// A BIGNUM as the DER of an INTEGER (`dh_spki_pub_to_der` and the others), or 0 (with
/// `missing` from `f` when there's none).
///
/// # Safety
/// `bn` is NULL or a live BIGNUM; `pder` as for an `i2d`.
unsafe fn bn_der(
    bn: *const rustyssl_abi::BIGNUM,
    pder: *mut *mut c_uchar,
    missing: c_int,
    f: &str,
) -> c_int {
    if bn.is_null() {
        err::raise(ERR_LIB_PROV, missing, f);
        return 0;
    }
    // SAFETY: the caller's BIGNUM.
    let int = unsafe { crate::bn::conv::BN_to_ASN1_INTEGER(bn, ptr::null_mut()) };
    if int.is_null() {
        err::raise(ERR_LIB_PROV, PROV_R_BN_ERROR, f);
        return 0;
    }
    // SAFETY: the new INTEGER; the caller's output.
    let ret = unsafe { crate::asn1::tpl::items::i2d_ASN1_INTEGER(int, pder) };
    // SAFETY: made above.
    unsafe { ASN1_STRING_clear_free(int) };
    ret
}

/// An `i2d` of a key type as a `K2d` that ignores the context (`k2d_NOCTX`).
macro_rules! k2d_noctx {
    ($($name:ident = $f:path : $t:ty),* $(,)?) => {$(
        ffi_callback! {
            /// The `i2d` as a key family's function.
            ///
            /// # Safety
            /// As for the `i2d`.
            pub(crate) unsafe extern "C" fn $name(key: *const c_void, pder: *mut *mut c_uchar, _ctx: *mut c_void) -> c_int
            where failure = 0, library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                unsafe { $f(key.cast::<$t>(), pder) }
            }
        }
    )*};
}

k2d_noctx!(
    rsa_prv_k2d = crate::rsa_asn1::i2d_RSAPrivateKey: rustyssl_abi::RSA,
    rsa_pub_k2d = crate::rsa_asn1::i2d_RSAPublicKey: rustyssl_abi::RSA,
    dsa_prv_k2d = crate::dsa_asn1::i2d_DSAPrivateKey: rustyssl_abi::DSA,
    dsa_pub_k2d = crate::dsa_asn1::i2d_DSAPublicKey: rustyssl_abi::DSA,
    dsa_param_k2d = crate::dsa_asn1::i2d_DSAparams: rustyssl_abi::DSA,
    ec_param_k2d = crate::ec::key_asn1::i2d_ECParameters: rustyssl_abi::EC_KEY,
    ec_prv_k2d = crate::ec::key_asn1::i2d_ECPrivateKey: rustyssl_abi::EC_KEY,
);

// RSA.

/// `rsa_check_key_type`.
unsafe fn rsa_check(key: *const c_void, expected: c_int) -> bool {
    // SAFETY: the caller's RSA key.
    let Some(r) = (unsafe { crate::rsa::rsa(key.cast()) }) else {
        return false;
    };
    match r.lock().kind {
        crate::rsa::Kind::Rsa => expected == EVP_PKEY_RSA,
        crate::rsa::Kind::RsaPss => expected == EVP_PKEY_RSA_PSS,
    }
}

/// `prepare_rsa_params`: NULL for RSA, none for an unrestricted RSA-PSS key, and a restricted
/// one's RSASSA-PSS-params.
unsafe fn rsa_params(key: *const c_void, _nid: c_int, _save: bool) -> Option<(*mut c_void, c_int)> {
    // SAFETY: the caller's RSA key.
    let r = unsafe { crate::rsa::rsa(key.cast()) }?;
    let (kind, pss) = {
        let s = r.lock();
        (s.kind, s.pss)
    };
    match kind {
        crate::rsa::Kind::Rsa => Some((ptr::null_mut(), V_ASN1_NULL)),
        crate::rsa::Kind::RsaPss if !pss.restricted() => Some((ptr::null_mut(), V_ASN1_UNDEF)),
        crate::rsa::Kind::RsaPss => {
            let der = super::rsa_sig::pss_params(&pss)?;
            let len = c_int::try_from(der.len()).ok()?;
            let mut data: *mut c_uchar = ptr::null_mut();
            // SAFETY: a new buffer into `data`.
            if unsafe { give(&der, &raw mut data) } == 0 {
                return None;
            }
            // SAFETY: no preconditions.
            let astr = unsafe { ASN1_STRING_new() };
            if astr.is_null() {
                // SAFETY: made above.
                unsafe { mem::release(data.cast()) };
                return None;
            }
            // SAFETY: the new string takes the buffer.
            unsafe { ASN1_STRING_set0(astr, data.cast(), len) };
            Some((astr.cast(), V_ASN1_SEQUENCE))
        }
    }
}

static RSA_FAMILY: Family = Family {
    check: Some(rsa_check),
    params: Some(rsa_params),
    pki: Some(rsa_prv_k2d),
    spki: Some(rsa_pub_k2d),
    private: Some(rsa_prv_k2d),
    public: Some(rsa_pub_k2d),
    domain: None,
    to_text: super::key2text::rsa_to_text,
};

// DH.

/// Whether a DH key is an X9.42 one.
unsafe fn is_dhx(key: *const c_void) -> bool {
    // SAFETY: the caller's DH key.
    (unsafe { crate::dh::DH_test_flags(key.cast(), DH_FLAG_TYPE_DHX) }) != 0
}

/// `dh_check_key_type`.
unsafe fn dh_check(key: *const c_void, expected: c_int) -> bool {
    // SAFETY: the caller's DH key.
    let t = if unsafe { is_dhx(key) } {
        EVP_PKEY_DHX
    } else {
        EVP_PKEY_DH
    };
    t == expected
}

/// `prepare_dh_params`: the DHparams, or the DHxparams for the DHX type.
unsafe fn dh_params(key: *const c_void, nid: c_int, _save: bool) -> Option<(*mut c_void, c_int)> {
    let i2d = |k: *const c_void, p: *mut *mut c_uchar| {
        if nid == EVP_PKEY_DHX {
            // SAFETY: the caller's DH key; a new buffer.
            unsafe { crate::dh_asn1::i2d_DHxparams(k.cast(), p) }
        } else {
            // SAFETY: as above.
            unsafe { crate::dh_asn1::i2d_DHparams(k.cast(), p) }
        }
    };
    // SAFETY: the caller's DH key.
    unsafe { seq_params(key, "prepare_dh_params", i2d, true) }
}

ffi_callback! {
    /// `dh_spki_pub_to_der`.
    ///
    /// # Safety
    /// `key` is a DH key; `pder` as for an `i2d`.
    pub(crate) unsafe extern "C" fn dh_spki_pub_k2d(key: *const c_void, pder: *mut *mut c_uchar, _ctx: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let bn = unsafe { crate::dh::DH_get0_pub_key(key.cast()) };
        // SAFETY: the key's BIGNUM, or NULL.
        unsafe { bn_der(bn, pder, PROV_R_NOT_A_PUBLIC_KEY, "dh_spki_pub_to_der") }
    }
}

ffi_callback! {
    /// `dh_pki_priv_to_der`.
    ///
    /// # Safety
    /// `key` is a DH key; `pder` as for an `i2d`.
    pub(crate) unsafe extern "C" fn dh_pki_priv_k2d(key: *const c_void, pder: *mut *mut c_uchar, _ctx: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let bn = unsafe { crate::dh::DH_get0_priv_key(key.cast()) };
        // SAFETY: the key's BIGNUM, or NULL.
        unsafe { bn_der(bn, pder, PROV_R_NOT_A_PRIVATE_KEY, "dh_pki_priv_to_der") }
    }
}

ffi_callback! {
    /// `dh_type_specific_params_to_der`: DHxparams for an X9.42 key, DHparams otherwise.
    ///
    /// # Safety
    /// `key` is a DH key; `pder` as for an `i2d`.
    pub(crate) unsafe extern "C" fn dh_params_k2d(key: *const c_void, pder: *mut *mut c_uchar, _ctx: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { is_dhx(key) } {
            // SAFETY: as above.
            unsafe { crate::dh_asn1::i2d_DHxparams(key.cast(), pder) }
        } else {
            // SAFETY: as above.
            unsafe { crate::dh_asn1::i2d_DHparams(key.cast(), pder) }
        }
    }
}

static DH_FAMILY: Family = Family {
    check: Some(dh_check),
    params: Some(dh_params),
    pki: Some(dh_pki_priv_k2d),
    spki: Some(dh_spki_pub_k2d),
    private: None,
    public: None,
    domain: Some(dh_params_k2d),
    to_text: super::key2text::dh_to_text,
};

// DSA.

/// `prepare_dsa_params`: the Dss-Parms when saving them and the key has them, none otherwise.
unsafe fn dsa_params(key: *const c_void, _nid: c_int, save: bool) -> Option<(*mut c_void, c_int)> {
    use crate::dsa::{DSA_get0_g, DSA_get0_p, DSA_get0_q};
    // SAFETY: the caller's DSA key.
    let p = unsafe { DSA_get0_p(key.cast()) };
    // SAFETY: as above.
    let q = unsafe { DSA_get0_q(key.cast()) };
    // SAFETY: as above.
    let g = unsafe { DSA_get0_g(key.cast()) };
    if save && !p.is_null() && !q.is_null() && !g.is_null() {
        // SAFETY: as above; a new buffer.
        let i2d = |k: *const c_void, d: *mut *mut c_uchar| unsafe {
            crate::dsa_asn1::i2d_DSAparams(k.cast(), d)
        };
        // SAFETY: as above.
        return unsafe { seq_params(key, "encode_dsa_params", i2d, false) };
    }
    Some((ptr::null_mut(), V_ASN1_UNDEF))
}

ffi_callback! {
    /// `dsa_spki_pub_to_der`.
    ///
    /// # Safety
    /// `key` is a DSA key; `pder` as for an `i2d`.
    pub(crate) unsafe extern "C" fn dsa_spki_pub_k2d(key: *const c_void, pder: *mut *mut c_uchar, _ctx: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let bn = unsafe { crate::dsa::DSA_get0_pub_key(key.cast()) };
        // SAFETY: the key's BIGNUM, or NULL.
        unsafe { bn_der(bn, pder, PROV_R_NOT_A_PUBLIC_KEY, "dsa_spki_pub_to_der") }
    }
}

ffi_callback! {
    /// `dsa_pki_priv_to_der`.
    ///
    /// # Safety
    /// `key` is a DSA key; `pder` as for an `i2d`.
    pub(crate) unsafe extern "C" fn dsa_pki_priv_k2d(key: *const c_void, pder: *mut *mut c_uchar, _ctx: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let bn = unsafe { crate::dsa::DSA_get0_priv_key(key.cast()) };
        // SAFETY: the key's BIGNUM, or NULL.
        unsafe { bn_der(bn, pder, PROV_R_NOT_A_PRIVATE_KEY, "dsa_pki_priv_to_der") }
    }
}

static DSA_FAMILY: Family = Family {
    check: None,
    params: Some(dsa_params),
    pki: Some(dsa_pki_priv_k2d),
    spki: Some(dsa_spki_pub_k2d),
    private: Some(dsa_prv_k2d),
    public: Some(dsa_pub_k2d),
    domain: Some(dsa_param_k2d),
    to_text: super::key2text::dsa_to_text,
};

// EC (and SM2).

/// `prepare_ec_params`: a named curve's OID (when the group says to name it), the explicit
/// ECParameters otherwise.
unsafe fn ec_params(key: *const c_void, _nid: c_int, _save: bool) -> Option<(*mut c_void, c_int)> {
    use crate::ec::group::{EC_GROUP_get_asn1_flag, EC_GROUP_get_curve_name};
    // SAFETY: the caller's EC key.
    let group = unsafe { crate::ec::key::EC_KEY_get0_group(key.cast()) };
    if group.is_null() {
        return None;
    }
    // SAFETY: the key's group.
    let curve_nid = unsafe { EC_GROUP_get_curve_name(group) };
    let mut params: *mut ASN1_OBJECT = ptr::null_mut();
    if curve_nid != NID_undef {
        // SAFETY: a NID.
        params = unsafe { OBJ_nid2obj(curve_nid) };
        if params.is_null() {
            return None;
        }
    }
    // SAFETY: the key's group.
    let flag = unsafe { EC_GROUP_get_asn1_flag(group) };
    if curve_nid != NID_undef && flag & OPENSSL_EC_NAMED_CURVE != 0 {
        // SAFETY: the curve's object.
        if unsafe { OBJ_length(params) } == 0 {
            err::raise(ERR_LIB_PROV, PROV_R_MISSING_OID, "prepare_ec_params");
            // SAFETY: as above.
            unsafe { ASN1_OBJECT_free(params) };
            return None;
        }
        return Some((params.cast(), V_ASN1_OBJECT));
    }
    // SAFETY: the caller's EC key; a new buffer.
    let i2d = |k: *const c_void, d: *mut *mut c_uchar| unsafe {
        crate::ec::key_asn1::i2d_ECParameters(k.cast(), d)
    };
    // SAFETY: as above.
    unsafe { seq_params(key, "prepare_ec_explicit_params", i2d, false) }
}

ffi_callback! {
    /// `ec_spki_pub_to_der`: the public point.
    ///
    /// # Safety
    /// `key` is an EC key; `pder` as for an `i2d`.
    pub(crate) unsafe extern "C" fn ec_spki_pub_k2d(key: *const c_void, pder: *mut *mut c_uchar, _ctx: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { crate::ec::key::EC_KEY_get0_public_key(key.cast()) }.is_null() {
            err::raise(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY, "ec_spki_pub_to_der");
            return 0;
        }
        // SAFETY: as above.
        unsafe { crate::ec::key_asn1::i2o_ECPublicKey(key.cast(), pder) }
    }
}

ffi_callback! {
    /// `ec_pki_priv_to_der`: the ECPrivateKey without the parameters, which the
    /// AlgorithmIdentifier carries.
    ///
    /// # Safety
    /// `key` is an EC key; `pder` as for an `i2d`.
    pub(crate) unsafe extern "C" fn ec_pki_priv_k2d(key: *const c_void, pder: *mut *mut c_uchar, _ctx: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        use crate::ec::key::{EC_KEY_get_enc_flags, EC_KEY_set_enc_flags};
        let eckey: *mut rustyssl_abi::EC_KEY = key.cast_mut().cast();
        // SAFETY: the caller's guarantee.
        let old_flags = unsafe { EC_KEY_get_enc_flags(eckey) };
        // SAFETY: as above (OpenSSL changes the key's flags for the encoding too).
        unsafe { EC_KEY_set_enc_flags(eckey, old_flags | EC_PKEY_NO_PARAMETERS.cast_unsigned()) };
        // SAFETY: as above.
        let ret = unsafe { crate::ec::key_asn1::i2d_ECPrivateKey(eckey, pder) };
        // SAFETY: as above.
        unsafe { EC_KEY_set_enc_flags(eckey, old_flags) };
        ret
    }
}

static EC_FAMILY: Family = Family {
    check: None,
    params: Some(ec_params),
    pki: Some(ec_pki_priv_k2d),
    spki: Some(ec_spki_pub_k2d),
    private: Some(ec_prv_k2d),
    public: None,
    domain: Some(ec_param_k2d),
    to_text: super::key2text::ec_to_text,
};

// X25519, X448, Ed25519, and Ed448.

ffi_callback! {
    /// `ecx_spki_pub_to_der`: the public key's octets.
    ///
    /// # Safety
    /// `key` is NULL or an ECX key; `pder` holds NULL.
    pub(crate) unsafe extern "C" fn ecx_spki_pub_k2d(key: *const c_void, pder: *mut *mut c_uchar, _ctx: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { crate::ecx::key(key) }) else {
            err::raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER, "ecx_spki_pub_to_der");
            return 0;
        };
        let public = k.public();
        // SAFETY: as above.
        unsafe { give(&public, pder) }
    }
}

ffi_callback! {
    /// `ecx_pki_priv_to_der`: the private key as a CurvePrivateKey (an OCTET STRING).
    ///
    /// # Safety
    /// `key` is NULL or an ECX key; `pder` holds NULL.
    pub(crate) unsafe extern "C" fn ecx_pki_priv_k2d(key: *const c_void, pder: *mut *mut c_uchar, _ctx: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "ecx_pki_priv_to_der";
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { crate::ecx::key(key) }) else {
            err::raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        };
        let der = {
            let s = k.lock();
            let Some(private) = s.privkey.as_deref() else {
                err::raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER, F);
                return 0;
            };
            let Some(len) = u8::try_from(private.len()).ok().filter(|&l| l < 0x80) else { return 0 };
            let mut der = Zeroizing::new(vec![0x04, len]);
            der.extend_from_slice(private);
            der
        };
        // SAFETY: as above.
        unsafe { give(&der, pder) }
    }
}

static ECX_FAMILY: Family = Family {
    check: None,
    params: None,
    pki: Some(ecx_pki_priv_k2d),
    spki: Some(ecx_spki_pub_k2d),
    private: None,
    public: None,
    domain: None,
    to_text: super::key2text::ecx_to_text,
};

// ML-DSA and ML-KEM.

/// The key's octets from one of its key manager's codecs, as a `K2d` gives them.
///
/// # Safety
/// `pder` as for an `i2d`.
unsafe fn give_codec(octets: Option<Vec<u8>>, pder: *mut *mut c_uchar) -> c_int {
    let Some(v) = octets.map(Zeroizing::new) else {
        return 0;
    };
    // SAFETY: the caller's guarantee.
    unsafe { give(&v, pder) }
}

/// The provider's context of the encoder's context.
///
/// # Safety
/// `ctx` is NULL or a live `Key2Any`.
unsafe fn provctx_of(ctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    unsafe { ctx.cast::<Key2Any>().as_ref() }.map_or(ptr::null_mut(), |c| c.provctx)
}

ffi_callback! {
    /// `ml_dsa_spki_pub_to_der` (`ossl_ml_dsa_i2d_pubkey`).
    ///
    /// # Safety
    /// `key` is an ML-DSA key; `pder` as for an `i2d`.
    pub(crate) unsafe extern "C" fn ml_dsa_spki_pub_k2d(key: *const c_void, pder: *mut *mut c_uchar, _ctx: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let octets = unsafe { super::ml_dsa_kmgmt::i2d_pubkey(key) };
        // SAFETY: as above.
        unsafe { give_codec(octets, pder) }
    }
}

ffi_callback! {
    /// `ml_dsa_pki_priv_to_der` (`ossl_ml_dsa_i2d_prvkey`, in the provider's output format).
    ///
    /// # Safety
    /// `key` is an ML-DSA key; `pder` as for an `i2d`; `ctx` the encoder's context.
    pub(crate) unsafe extern "C" fn ml_dsa_pki_priv_k2d(key: *const c_void, pder: *mut *mut c_uchar, ctx: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let provctx = unsafe { provctx_of(ctx) };
        // SAFETY: as above.
        let octets = unsafe { super::ml_dsa_kmgmt::i2d_prvkey(key, provctx) };
        // SAFETY: as above.
        unsafe { give_codec(octets, pder) }
    }
}

ffi_callback! {
    /// `ml_kem_spki_pub_to_der` (`ossl_ml_kem_i2d_pubkey`).
    ///
    /// # Safety
    /// `key` is an ML-KEM key; `pder` as for an `i2d`.
    pub(crate) unsafe extern "C" fn ml_kem_spki_pub_k2d(key: *const c_void, pder: *mut *mut c_uchar, _ctx: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let octets = unsafe { super::ml_kem_kmgmt::i2d_pubkey(key) };
        // SAFETY: as above.
        unsafe { give_codec(octets, pder) }
    }
}

ffi_callback! {
    /// `ml_kem_pki_priv_to_der` (`ossl_ml_kem_i2d_prvkey`, in the provider's output format).
    ///
    /// # Safety
    /// `key` is an ML-KEM key; `pder` as for an `i2d`; `ctx` the encoder's context.
    pub(crate) unsafe extern "C" fn ml_kem_pki_priv_k2d(key: *const c_void, pder: *mut *mut c_uchar, ctx: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let provctx = unsafe { provctx_of(ctx) };
        // SAFETY: as above.
        let octets = unsafe { super::ml_kem_kmgmt::i2d_prvkey(key, provctx) };
        // SAFETY: as above.
        unsafe { give_codec(octets, pder) }
    }
}

static ML_DSA_FAMILY: Family = Family {
    check: None,
    params: None,
    pki: Some(ml_dsa_pki_priv_k2d),
    spki: Some(ml_dsa_spki_pub_k2d),
    private: None,
    public: None,
    domain: None,
    to_text: super::key2text::ml_dsa_to_text,
};

static ML_KEM_FAMILY: Family = Family {
    check: None,
    params: None,
    pki: Some(ml_kem_pki_priv_k2d),
    spki: Some(ml_kem_spki_pub_k2d),
    private: None,
    public: None,
    domain: None,
    to_text: super::key2text::ml_kem_to_text,
};

// SLH-DSA.

ffi_callback! {
    /// `slh_dsa_spki_pub_to_der`: the public key's octets (0 for a key without one).
    ///
    /// # Safety
    /// `key` is NULL or an SLH-DSA key; `pder` holds NULL.
    pub(crate) unsafe extern "C" fn slh_dsa_spki_pub_k2d(key: *const c_void, pder: *mut *mut c_uchar, _ctx: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { super::slh_dsa_kmgmt::key(key) }) else {
            err::raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER, "slh_dsa_spki_pub_to_der");
            return 0;
        };
        let public = k.lock().public().map(|p| p.encoding().to_vec());
        let Some(public) = public else { return 0 };
        // SAFETY: as above.
        unsafe { give(&public, pder) }
    }
}

ffi_callback! {
    /// `slh_dsa_pki_priv_to_der`: the private key's octets.
    ///
    /// # Safety
    /// `key` is an SLH-DSA key; `pder` is NULL or holds NULL.
    pub(crate) unsafe extern "C" fn slh_dsa_pki_priv_k2d(key: *const c_void, pder: *mut *mut c_uchar, _ctx: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let private = unsafe { super::slh_dsa_kmgmt::key(key) }
            .and_then(|k| k.lock().private().map(|p| Zeroizing::new(p.encoding().to_vec())));
        let Some(private) = private else {
            err::raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER, "slh_dsa_pki_priv_to_der");
            return 0;
        };
        // SAFETY: as above.
        unsafe { give(&private, pder) }
    }
}

static SLH_DSA_FAMILY: Family = Family {
    check: None,
    params: None,
    pki: Some(slh_dsa_pki_priv_k2d),
    spki: Some(slh_dsa_spki_pub_k2d),
    private: None,
    public: None,
    domain: None,
    to_text: super::key2text::slh_dsa_to_text,
};

// An EC key's public point as a blob (`encode_key2blob.c`).

ffi_callback! {
    /// `key2blob_newctx`: the provider's context.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn key2blob_newctx(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        provctx
    }
}

ffi_callback! {
    /// `key2blob_freectx` (and `key2text_freectx`): nothing to free.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn key2blob_freectx(_vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
    }
}

ffi_callback! {
    /// `ec2blob_does_selection` (and SM2's): the public key, or the parameters.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn key2blob_does_selection(_ctx: *mut c_void, selection: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        check_selection(selection, EVP_PKEY_PUBLIC_KEY)
    }
}

ffi_callback! {
    /// `ec2blob_import_object`.
    ///
    /// # Safety
    /// `ctx` is the provider's context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ec2blob_import_object(ctx: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: a built-in table; the caller's guarantee.
        unsafe { import_key(&super::ec_kmgmt::EC_KEYMGMT.0, ctx, selection, params) }
    }
}

ffi_callback! {
    /// `sm2blob_import_object`.
    ///
    /// # Safety
    /// `ctx` is the provider's context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn sm22blob_import_object(ctx: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: a built-in table; the caller's guarantee.
        unsafe { import_key(&super::ec_kmgmt::SM2_KEYMGMT.0, ctx, selection, params) }
    }
}

ffi_callback! {
    /// `key2blob_encode`: the public point, as `i2o_ECPublicKey` writes it.
    ///
    /// # Safety
    /// `vctx` is the provider's context; `cout` a core BIO; `key` an EC key.
    pub(crate) unsafe extern "C" fn key2blob_encode(_vctx: *mut c_void, cout: *mut OSSL_CORE_BIO, key: *const c_void, key_abstract: *const OSSL_PARAM, _selection: c_int, _cb: OSSL_PASSPHRASE_CALLBACK, _cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        if !key_abstract.is_null() {
            err::raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT, "key2blob_encode");
            return 0;
        }
        let mut pubkey: *mut c_uchar = ptr::null_mut();
        // SAFETY: the caller's key; a new buffer.
        let len = unsafe { crate::ec::key_asn1::i2o_ECPublicKey(key.cast(), &raw mut pubkey) };
        let mut ok = 0;
        if len > 0 && !pubkey.is_null() {
            // SAFETY: the caller's core BIO.
            let out = unsafe { bio_new_from_core_bio(cout) };
            if !out.is_null() {
                // SAFETY: the BIO; the point's `len` octets.
                ok = unsafe { BIO_write(out, pubkey.cast(), len) };
                // SAFETY: made above.
                unsafe { BIO_free(out) };
            }
        }
        // SAFETY: the point, or NULL.
        unsafe { mem::release(pubkey.cast()) };
        ok
    }
}

static EC_TO_BLOB: Dispatch<7> = Dispatch([
    entry!(OSSL_FUNC_ENCODER_NEWCTX, key2blob_newctx, NewCtxFn),
    entry!(OSSL_FUNC_ENCODER_FREECTX, key2blob_freectx, FreeCtxFn),
    entry!(
        OSSL_FUNC_ENCODER_DOES_SELECTION,
        key2blob_does_selection,
        DoesSelectionFn
    ),
    entry!(
        OSSL_FUNC_ENCODER_IMPORT_OBJECT,
        ec2blob_import_object,
        ImportObjectFn
    ),
    entry!(OSSL_FUNC_ENCODER_FREE_OBJECT, free::EC, FreeObjectFn),
    entry!(OSSL_FUNC_ENCODER_ENCODE, key2blob_encode, EncodeFn),
    END,
]);

static SM2_TO_BLOB: Dispatch<7> = Dispatch([
    entry!(OSSL_FUNC_ENCODER_NEWCTX, key2blob_newctx, NewCtxFn),
    entry!(OSSL_FUNC_ENCODER_FREECTX, key2blob_freectx, FreeCtxFn),
    entry!(
        OSSL_FUNC_ENCODER_DOES_SELECTION,
        key2blob_does_selection,
        DoesSelectionFn
    ),
    entry!(
        OSSL_FUNC_ENCODER_IMPORT_OBJECT,
        sm22blob_import_object,
        ImportObjectFn
    ),
    entry!(OSSL_FUNC_ENCODER_FREE_OBJECT, free::SM2, FreeObjectFn),
    entry!(OSSL_FUNC_ENCODER_ENCODE, key2blob_encode, EncodeFn),
    END,
]);

// The text encoders (`MAKE_TEXT_ENCODER` in `encode_key2text.c`).

/// `key2text_encode`: the key's text, through a BIO on the core BIO.
///
/// # Safety
/// `cout` is a core BIO; `key` is NULL or a key `to_text` takes.
unsafe fn key2text_encode(
    cout: *mut OSSL_CORE_BIO,
    key: *const c_void,
    key_abstract: *const OSSL_PARAM,
    selection: c_int,
    to_text: super::key2text::ToText,
) -> c_int {
    if !key_abstract.is_null() {
        err::raise(
            ERR_LIB_PROV,
            ERR_R_PASSED_INVALID_ARGUMENT,
            "key2text_encode",
        );
        return 0;
    }
    // SAFETY: the caller's core BIO.
    let out = unsafe { bio_new_from_core_bio(cout) };
    if out.is_null() {
        return 0;
    }
    // SAFETY: the BIO made here; the caller's key.
    let ret = unsafe { to_text(out, key, selection) };
    // SAFETY: made above.
    unsafe { BIO_free(out) };
    ret
}

/// A text encoder's dispatch table, with its own `import_object` and `encode`.
macro_rules! text_encoder {
    ($table:ident, $import:ident, $encode:ident, $imp:ident) => {
        ffi_callback! {
            /// The text encoder's `encode`: the key's text (`type##_to_text`).
            ///
            /// # Safety
            /// `cout` is a core BIO; `key` is NULL or a key of the encoder's type.
            pub(crate) unsafe extern "C" fn $encode(_vctx: *mut c_void, cout: *mut OSSL_CORE_BIO, key: *const c_void, key_abstract: *const OSSL_PARAM, selection: c_int, _cb: OSSL_PASSPHRASE_CALLBACK, _cbarg: *mut c_void) -> c_int
            where failure = 0, library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee; the type's function.
                unsafe { key2text_encode(cout, key, key_abstract, selection, $imp.family.to_text) }
            }
        }

        ffi_callback! {
            /// The text encoder's `import_object` (with the provider's context).
            ///
            /// # Safety
            /// `ctx` is the provider's context; `params` is NULL or an array.
            pub(crate) unsafe extern "C" fn $import(ctx: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> *mut c_void
            where failure = ptr::null_mut(), library = ERR_LIB_PROV
            {
                // SAFETY: a built-in table; the caller's guarantee.
                unsafe { import_key($imp.keymgmt, ctx, selection, params) }
            }
        }

        static $table: Dispatch<6> = Dispatch([
            entry!(OSSL_FUNC_ENCODER_NEWCTX, key2blob_newctx, NewCtxFn),
            entry!(OSSL_FUNC_ENCODER_FREECTX, key2blob_freectx, FreeCtxFn),
            entry!(OSSL_FUNC_ENCODER_IMPORT_OBJECT, $import, ImportObjectFn),
            entry!(OSSL_FUNC_ENCODER_FREE_OBJECT, free::$imp, FreeObjectFn),
            entry!(OSSL_FUNC_ENCODER_ENCODE, $encode, EncodeFn),
            END,
        ]);
    };
}

/// An algorithm of an encoder table: its names, properties, and dispatch table.
const fn encoder<const N: usize>(
    names: &'static CStr,
    props: &'static CStr,
    table: &'static Dispatch<N>,
) -> OSSL_ALGORITHM {
    OSSL_ALGORITHM {
        algorithm_names: names.as_ptr(),
        property_definition: props.as_ptr(),
        implementation: table.0.as_ptr(),
        algorithm_description: ptr::null(),
    }
}

use super::key2ms::{DSA_TO_MSBLOB, DSA_TO_PVK, RSA_TO_MSBLOB, RSA_TO_PVK};

/// `deflt_encoder`.
pub(crate) fn default_encoders() -> *const OSSL_ALGORITHM {
    DEFAULT_ENCODERS.0.as_ptr()
}

/// `base_encoder`.
pub(crate) fn base_encoders() -> *const OSSL_ALGORITHM {
    BASE_ENCODERS.0.as_ptr()
}

// The key types (`impl` in `MAKE_ENCODER`).

static RSA: Impl = Impl {
    family: &RSA_FAMILY,
    evp_type: EVP_PKEY_RSA,
    private_pem: c"RSA PRIVATE KEY",
    public_pem: c"RSA PUBLIC KEY",
    params_pem: c"RSA PARAMETERS",
    keymgmt: &super::rsa_kmgmt::RSA_KEYMGMT.0,
};

static RSAPSS: Impl = Impl {
    family: &RSA_FAMILY,
    evp_type: EVP_PKEY_RSA_PSS,
    private_pem: c"RSA-PSS PRIVATE KEY",
    public_pem: c"RSA-PSS PUBLIC KEY",
    params_pem: c"RSA-PSS PARAMETERS",
    keymgmt: &super::rsa_kmgmt::RSAPSS_KEYMGMT.0,
};

static DH: Impl = Impl {
    family: &DH_FAMILY,
    evp_type: EVP_PKEY_DH,
    private_pem: c"DH PRIVATE KEY",
    public_pem: c"DH PUBLIC KEY",
    params_pem: c"DH PARAMETERS",
    keymgmt: &super::dh_kmgmt::DH_KEYMGMT.0,
};

static DHX: Impl = Impl {
    family: &DH_FAMILY,
    evp_type: EVP_PKEY_DHX,
    private_pem: c"X9.42 DH PRIVATE KEY",
    public_pem: c"X9.42 DH PUBLIC KEY",
    params_pem: c"X9.42 DH PARAMETERS",
    keymgmt: &super::dh_kmgmt::DHX_KEYMGMT.0,
};

static DSA: Impl = Impl {
    family: &DSA_FAMILY,
    evp_type: EVP_PKEY_DSA,
    private_pem: c"DSA PRIVATE KEY",
    public_pem: c"DSA PUBLIC KEY",
    params_pem: c"DSA PARAMETERS",
    keymgmt: &super::dsa_kmgmt::DSA_KEYMGMT.0,
};

static EC: Impl = Impl {
    family: &EC_FAMILY,
    evp_type: EVP_PKEY_EC,
    private_pem: c"EC PRIVATE KEY",
    public_pem: c"EC PUBLIC KEY",
    params_pem: c"EC PARAMETERS",
    keymgmt: &super::ec_kmgmt::EC_KEYMGMT.0,
};

static SM2: Impl = Impl {
    family: &EC_FAMILY,
    evp_type: EVP_PKEY_EC,
    private_pem: c"SM2 PRIVATE KEY",
    public_pem: c"SM2 PUBLIC KEY",
    params_pem: c"SM2 PARAMETERS",
    keymgmt: &super::ec_kmgmt::SM2_KEYMGMT.0,
};

static ED25519: Impl = Impl {
    family: &ECX_FAMILY,
    evp_type: EVP_PKEY_ED25519,
    private_pem: c"ED25519 PRIVATE KEY",
    public_pem: c"ED25519 PUBLIC KEY",
    params_pem: c"ED25519 PARAMETERS",
    keymgmt: &super::ecx_kmgmt::ED25519_KEYMGMT.0,
};

static ED448: Impl = Impl {
    family: &ECX_FAMILY,
    evp_type: EVP_PKEY_ED448,
    private_pem: c"ED448 PRIVATE KEY",
    public_pem: c"ED448 PUBLIC KEY",
    params_pem: c"ED448 PARAMETERS",
    keymgmt: &super::ecx_kmgmt::ED448_KEYMGMT.0,
};

static X25519: Impl = Impl {
    family: &ECX_FAMILY,
    evp_type: EVP_PKEY_X25519,
    private_pem: c"X25519 PRIVATE KEY",
    public_pem: c"X25519 PUBLIC KEY",
    params_pem: c"X25519 PARAMETERS",
    keymgmt: &super::ecx_kmgmt::X25519_KEYMGMT.0,
};

static X448: Impl = Impl {
    family: &ECX_FAMILY,
    evp_type: EVP_PKEY_X448,
    private_pem: c"X448 PRIVATE KEY",
    public_pem: c"X448 PUBLIC KEY",
    params_pem: c"X448 PARAMETERS",
    keymgmt: &super::ecx_kmgmt::X448_KEYMGMT.0,
};

static ML_KEM_512: Impl = Impl {
    family: &ML_KEM_FAMILY,
    evp_type: NID_ML_KEM_512,
    private_pem: c"ML-KEM-512 PRIVATE KEY",
    public_pem: c"ML-KEM-512 PUBLIC KEY",
    params_pem: c"ML-KEM-512 PARAMETERS",
    keymgmt: &super::ml_kem_kmgmt::ML_KEM_512_KEYMGMT.0,
};

static ML_KEM_768: Impl = Impl {
    family: &ML_KEM_FAMILY,
    evp_type: NID_ML_KEM_768,
    private_pem: c"ML-KEM-768 PRIVATE KEY",
    public_pem: c"ML-KEM-768 PUBLIC KEY",
    params_pem: c"ML-KEM-768 PARAMETERS",
    keymgmt: &super::ml_kem_kmgmt::ML_KEM_768_KEYMGMT.0,
};

static ML_KEM_1024: Impl = Impl {
    family: &ML_KEM_FAMILY,
    evp_type: NID_ML_KEM_1024,
    private_pem: c"ML-KEM-1024 PRIVATE KEY",
    public_pem: c"ML-KEM-1024 PUBLIC KEY",
    params_pem: c"ML-KEM-1024 PARAMETERS",
    keymgmt: &super::ml_kem_kmgmt::ML_KEM_1024_KEYMGMT.0,
};

static ML_DSA_44: Impl = Impl {
    family: &ML_DSA_FAMILY,
    evp_type: NID_ML_DSA_44,
    private_pem: c"ML-DSA-44 PRIVATE KEY",
    public_pem: c"ML-DSA-44 PUBLIC KEY",
    params_pem: c"ML-DSA-44 PARAMETERS",
    keymgmt: &super::ml_dsa_kmgmt::ML_DSA_44_KEYMGMT.0,
};

static ML_DSA_65: Impl = Impl {
    family: &ML_DSA_FAMILY,
    evp_type: NID_ML_DSA_65,
    private_pem: c"ML-DSA-65 PRIVATE KEY",
    public_pem: c"ML-DSA-65 PUBLIC KEY",
    params_pem: c"ML-DSA-65 PARAMETERS",
    keymgmt: &super::ml_dsa_kmgmt::ML_DSA_65_KEYMGMT.0,
};

static ML_DSA_87: Impl = Impl {
    family: &ML_DSA_FAMILY,
    evp_type: NID_ML_DSA_87,
    private_pem: c"ML-DSA-87 PRIVATE KEY",
    public_pem: c"ML-DSA-87 PUBLIC KEY",
    params_pem: c"ML-DSA-87 PARAMETERS",
    keymgmt: &super::ml_dsa_kmgmt::ML_DSA_87_KEYMGMT.0,
};

static SLH_DSA_SHA2_128S: Impl = Impl {
    family: &SLH_DSA_FAMILY,
    evp_type: NID_SLH_DSA_SHA2_128s,
    private_pem: c"SLH-DSA-SHA2-128s PRIVATE KEY",
    public_pem: c"SLH-DSA-SHA2-128s PUBLIC KEY",
    params_pem: c"SLH-DSA-SHA2-128s PARAMETERS",
    keymgmt: &super::slh_dsa_kmgmt::SHA2_128S_KEYMGMT.0,
};

static SLH_DSA_SHA2_128F: Impl = Impl {
    family: &SLH_DSA_FAMILY,
    evp_type: NID_SLH_DSA_SHA2_128f,
    private_pem: c"SLH-DSA-SHA2-128f PRIVATE KEY",
    public_pem: c"SLH-DSA-SHA2-128f PUBLIC KEY",
    params_pem: c"SLH-DSA-SHA2-128f PARAMETERS",
    keymgmt: &super::slh_dsa_kmgmt::SHA2_128F_KEYMGMT.0,
};

static SLH_DSA_SHA2_192S: Impl = Impl {
    family: &SLH_DSA_FAMILY,
    evp_type: NID_SLH_DSA_SHA2_192s,
    private_pem: c"SLH-DSA-SHA2-192s PRIVATE KEY",
    public_pem: c"SLH-DSA-SHA2-192s PUBLIC KEY",
    params_pem: c"SLH-DSA-SHA2-192s PARAMETERS",
    keymgmt: &super::slh_dsa_kmgmt::SHA2_192S_KEYMGMT.0,
};

static SLH_DSA_SHA2_192F: Impl = Impl {
    family: &SLH_DSA_FAMILY,
    evp_type: NID_SLH_DSA_SHA2_192f,
    private_pem: c"SLH-DSA-SHA2-192f PRIVATE KEY",
    public_pem: c"SLH-DSA-SHA2-192f PUBLIC KEY",
    params_pem: c"SLH-DSA-SHA2-192f PARAMETERS",
    keymgmt: &super::slh_dsa_kmgmt::SHA2_192F_KEYMGMT.0,
};

static SLH_DSA_SHA2_256S: Impl = Impl {
    family: &SLH_DSA_FAMILY,
    evp_type: NID_SLH_DSA_SHA2_256s,
    private_pem: c"SLH-DSA-SHA2-256s PRIVATE KEY",
    public_pem: c"SLH-DSA-SHA2-256s PUBLIC KEY",
    params_pem: c"SLH-DSA-SHA2-256s PARAMETERS",
    keymgmt: &super::slh_dsa_kmgmt::SHA2_256S_KEYMGMT.0,
};

static SLH_DSA_SHA2_256F: Impl = Impl {
    family: &SLH_DSA_FAMILY,
    evp_type: NID_SLH_DSA_SHA2_256f,
    private_pem: c"SLH-DSA-SHA2-256f PRIVATE KEY",
    public_pem: c"SLH-DSA-SHA2-256f PUBLIC KEY",
    params_pem: c"SLH-DSA-SHA2-256f PARAMETERS",
    keymgmt: &super::slh_dsa_kmgmt::SHA2_256F_KEYMGMT.0,
};

static SLH_DSA_SHAKE_128S: Impl = Impl {
    family: &SLH_DSA_FAMILY,
    evp_type: NID_SLH_DSA_SHAKE_128s,
    private_pem: c"SLH-DSA-SHAKE-128s PRIVATE KEY",
    public_pem: c"SLH-DSA-SHAKE-128s PUBLIC KEY",
    params_pem: c"SLH-DSA-SHAKE-128s PARAMETERS",
    keymgmt: &super::slh_dsa_kmgmt::SHAKE_128S_KEYMGMT.0,
};

static SLH_DSA_SHAKE_128F: Impl = Impl {
    family: &SLH_DSA_FAMILY,
    evp_type: NID_SLH_DSA_SHAKE_128f,
    private_pem: c"SLH-DSA-SHAKE-128f PRIVATE KEY",
    public_pem: c"SLH-DSA-SHAKE-128f PUBLIC KEY",
    params_pem: c"SLH-DSA-SHAKE-128f PARAMETERS",
    keymgmt: &super::slh_dsa_kmgmt::SHAKE_128F_KEYMGMT.0,
};

static SLH_DSA_SHAKE_192S: Impl = Impl {
    family: &SLH_DSA_FAMILY,
    evp_type: NID_SLH_DSA_SHAKE_192s,
    private_pem: c"SLH-DSA-SHAKE-192s PRIVATE KEY",
    public_pem: c"SLH-DSA-SHAKE-192s PUBLIC KEY",
    params_pem: c"SLH-DSA-SHAKE-192s PARAMETERS",
    keymgmt: &super::slh_dsa_kmgmt::SHAKE_192S_KEYMGMT.0,
};

static SLH_DSA_SHAKE_192F: Impl = Impl {
    family: &SLH_DSA_FAMILY,
    evp_type: NID_SLH_DSA_SHAKE_192f,
    private_pem: c"SLH-DSA-SHAKE-192f PRIVATE KEY",
    public_pem: c"SLH-DSA-SHAKE-192f PUBLIC KEY",
    params_pem: c"SLH-DSA-SHAKE-192f PARAMETERS",
    keymgmt: &super::slh_dsa_kmgmt::SHAKE_192F_KEYMGMT.0,
};

static SLH_DSA_SHAKE_256S: Impl = Impl {
    family: &SLH_DSA_FAMILY,
    evp_type: NID_SLH_DSA_SHAKE_256s,
    private_pem: c"SLH-DSA-SHAKE-256s PRIVATE KEY",
    public_pem: c"SLH-DSA-SHAKE-256s PUBLIC KEY",
    params_pem: c"SLH-DSA-SHAKE-256s PARAMETERS",
    keymgmt: &super::slh_dsa_kmgmt::SHAKE_256S_KEYMGMT.0,
};

static SLH_DSA_SHAKE_256F: Impl = Impl {
    family: &SLH_DSA_FAMILY,
    evp_type: NID_SLH_DSA_SHAKE_256f,
    private_pem: c"SLH-DSA-SHAKE-256f PRIVATE KEY",
    public_pem: c"SLH-DSA-SHAKE-256f PUBLIC KEY",
    params_pem: c"SLH-DSA-SHAKE-256f PARAMETERS",
    keymgmt: &super::slh_dsa_kmgmt::SHAKE_256F_KEYMGMT.0,
};

// The key-to-DER encoders (`MAKE_ENCODER` in `encode_key2any.c`).

encoder!(
    RSA_TO_TYPE_SPECIFIC_KEYPAIR_DER,
    rsa_to_type_specific_keypair_der_newctx,
    RSA,
    Keypair,
    Der
);
encoder!(
    RSA_TO_TYPE_SPECIFIC_KEYPAIR_PEM,
    rsa_to_type_specific_keypair_pem_newctx,
    RSA,
    Keypair,
    Pem
);
encoder!(
    DH_TO_TYPE_SPECIFIC_PARAMS_DER,
    dh_to_type_specific_params_der_newctx,
    DH,
    Params,
    Der
);
encoder!(
    DH_TO_TYPE_SPECIFIC_PARAMS_PEM,
    dh_to_type_specific_params_pem_newctx,
    DH,
    Params,
    Pem
);
encoder!(
    DHX_TO_TYPE_SPECIFIC_PARAMS_DER,
    dhx_to_type_specific_params_der_newctx,
    DHX,
    Params,
    Der
);
encoder!(
    DHX_TO_TYPE_SPECIFIC_PARAMS_PEM,
    dhx_to_type_specific_params_pem_newctx,
    DHX,
    Params,
    Pem
);
encoder!(
    DSA_TO_TYPE_SPECIFIC_DER,
    dsa_to_type_specific_der_newctx,
    DSA,
    All,
    Der
);
encoder!(
    DSA_TO_TYPE_SPECIFIC_PEM,
    dsa_to_type_specific_pem_newctx,
    DSA,
    All,
    Pem
);
encoder!(
    EC_TO_TYPE_SPECIFIC_NO_PUB_DER,
    ec_to_type_specific_no_pub_der_newctx,
    EC,
    NoPub,
    Der
);
encoder!(
    EC_TO_TYPE_SPECIFIC_NO_PUB_PEM,
    ec_to_type_specific_no_pub_pem_newctx,
    EC,
    NoPub,
    Pem
);
encoder!(
    SM2_TO_TYPE_SPECIFIC_NO_PUB_DER,
    sm2_to_type_specific_no_pub_der_newctx,
    SM2,
    NoPub,
    Der
);
encoder!(
    SM2_TO_TYPE_SPECIFIC_NO_PUB_PEM,
    sm2_to_type_specific_no_pub_pem_newctx,
    SM2,
    NoPub,
    Pem
);
encoder!(
    RSA_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    rsa_to_encryptedprivatekeyinfo_der_newctx,
    RSA,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    RSA_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    rsa_to_encryptedprivatekeyinfo_pem_newctx,
    RSA,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    RSA_TO_PRIVATEKEYINFO_DER,
    rsa_to_privatekeyinfo_der_newctx,
    RSA,
    PrivateKeyInfo,
    Der
);
encoder!(
    RSA_TO_PRIVATEKEYINFO_PEM,
    rsa_to_privatekeyinfo_pem_newctx,
    RSA,
    PrivateKeyInfo,
    Pem
);
encoder!(
    RSA_TO_SUBJECTPUBLICKEYINFO_DER,
    rsa_to_subjectpublickeyinfo_der_newctx,
    RSA,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    RSA_TO_SUBJECTPUBLICKEYINFO_PEM,
    rsa_to_subjectpublickeyinfo_pem_newctx,
    RSA,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    RSAPSS_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    rsapss_to_encryptedprivatekeyinfo_der_newctx,
    RSAPSS,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    RSAPSS_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    rsapss_to_encryptedprivatekeyinfo_pem_newctx,
    RSAPSS,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    RSAPSS_TO_PRIVATEKEYINFO_DER,
    rsapss_to_privatekeyinfo_der_newctx,
    RSAPSS,
    PrivateKeyInfo,
    Der
);
encoder!(
    RSAPSS_TO_PRIVATEKEYINFO_PEM,
    rsapss_to_privatekeyinfo_pem_newctx,
    RSAPSS,
    PrivateKeyInfo,
    Pem
);
encoder!(
    RSAPSS_TO_SUBJECTPUBLICKEYINFO_DER,
    rsapss_to_subjectpublickeyinfo_der_newctx,
    RSAPSS,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    RSAPSS_TO_SUBJECTPUBLICKEYINFO_PEM,
    rsapss_to_subjectpublickeyinfo_pem_newctx,
    RSAPSS,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    DH_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    dh_to_encryptedprivatekeyinfo_der_newctx,
    DH,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    DH_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    dh_to_encryptedprivatekeyinfo_pem_newctx,
    DH,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    DH_TO_PRIVATEKEYINFO_DER,
    dh_to_privatekeyinfo_der_newctx,
    DH,
    PrivateKeyInfo,
    Der
);
encoder!(
    DH_TO_PRIVATEKEYINFO_PEM,
    dh_to_privatekeyinfo_pem_newctx,
    DH,
    PrivateKeyInfo,
    Pem
);
encoder!(
    DH_TO_SUBJECTPUBLICKEYINFO_DER,
    dh_to_subjectpublickeyinfo_der_newctx,
    DH,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    DH_TO_SUBJECTPUBLICKEYINFO_PEM,
    dh_to_subjectpublickeyinfo_pem_newctx,
    DH,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    DHX_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    dhx_to_encryptedprivatekeyinfo_der_newctx,
    DHX,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    DHX_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    dhx_to_encryptedprivatekeyinfo_pem_newctx,
    DHX,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    DHX_TO_PRIVATEKEYINFO_DER,
    dhx_to_privatekeyinfo_der_newctx,
    DHX,
    PrivateKeyInfo,
    Der
);
encoder!(
    DHX_TO_PRIVATEKEYINFO_PEM,
    dhx_to_privatekeyinfo_pem_newctx,
    DHX,
    PrivateKeyInfo,
    Pem
);
encoder!(
    DHX_TO_SUBJECTPUBLICKEYINFO_DER,
    dhx_to_subjectpublickeyinfo_der_newctx,
    DHX,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    DHX_TO_SUBJECTPUBLICKEYINFO_PEM,
    dhx_to_subjectpublickeyinfo_pem_newctx,
    DHX,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    DSA_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    dsa_to_encryptedprivatekeyinfo_der_newctx,
    DSA,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    DSA_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    dsa_to_encryptedprivatekeyinfo_pem_newctx,
    DSA,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    DSA_TO_PRIVATEKEYINFO_DER,
    dsa_to_privatekeyinfo_der_newctx,
    DSA,
    PrivateKeyInfo,
    Der
);
encoder!(
    DSA_TO_PRIVATEKEYINFO_PEM,
    dsa_to_privatekeyinfo_pem_newctx,
    DSA,
    PrivateKeyInfo,
    Pem
);
encoder!(
    DSA_TO_SUBJECTPUBLICKEYINFO_DER,
    dsa_to_subjectpublickeyinfo_der_newctx,
    DSA,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    DSA_TO_SUBJECTPUBLICKEYINFO_PEM,
    dsa_to_subjectpublickeyinfo_pem_newctx,
    DSA,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    EC_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ec_to_encryptedprivatekeyinfo_der_newctx,
    EC,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    EC_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ec_to_encryptedprivatekeyinfo_pem_newctx,
    EC,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    EC_TO_PRIVATEKEYINFO_DER,
    ec_to_privatekeyinfo_der_newctx,
    EC,
    PrivateKeyInfo,
    Der
);
encoder!(
    EC_TO_PRIVATEKEYINFO_PEM,
    ec_to_privatekeyinfo_pem_newctx,
    EC,
    PrivateKeyInfo,
    Pem
);
encoder!(
    EC_TO_SUBJECTPUBLICKEYINFO_DER,
    ec_to_subjectpublickeyinfo_der_newctx,
    EC,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    EC_TO_SUBJECTPUBLICKEYINFO_PEM,
    ec_to_subjectpublickeyinfo_pem_newctx,
    EC,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    SM2_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    sm2_to_encryptedprivatekeyinfo_der_newctx,
    SM2,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    SM2_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    sm2_to_encryptedprivatekeyinfo_pem_newctx,
    SM2,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    SM2_TO_PRIVATEKEYINFO_DER,
    sm2_to_privatekeyinfo_der_newctx,
    SM2,
    PrivateKeyInfo,
    Der
);
encoder!(
    SM2_TO_PRIVATEKEYINFO_PEM,
    sm2_to_privatekeyinfo_pem_newctx,
    SM2,
    PrivateKeyInfo,
    Pem
);
encoder!(
    SM2_TO_SUBJECTPUBLICKEYINFO_DER,
    sm2_to_subjectpublickeyinfo_der_newctx,
    SM2,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    SM2_TO_SUBJECTPUBLICKEYINFO_PEM,
    sm2_to_subjectpublickeyinfo_pem_newctx,
    SM2,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    X25519_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    x25519_to_encryptedprivatekeyinfo_der_newctx,
    X25519,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    X25519_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    x25519_to_encryptedprivatekeyinfo_pem_newctx,
    X25519,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    X25519_TO_PRIVATEKEYINFO_DER,
    x25519_to_privatekeyinfo_der_newctx,
    X25519,
    PrivateKeyInfo,
    Der
);
encoder!(
    X25519_TO_PRIVATEKEYINFO_PEM,
    x25519_to_privatekeyinfo_pem_newctx,
    X25519,
    PrivateKeyInfo,
    Pem
);
encoder!(
    X25519_TO_SUBJECTPUBLICKEYINFO_DER,
    x25519_to_subjectpublickeyinfo_der_newctx,
    X25519,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    X25519_TO_SUBJECTPUBLICKEYINFO_PEM,
    x25519_to_subjectpublickeyinfo_pem_newctx,
    X25519,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    X448_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    x448_to_encryptedprivatekeyinfo_der_newctx,
    X448,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    X448_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    x448_to_encryptedprivatekeyinfo_pem_newctx,
    X448,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    X448_TO_PRIVATEKEYINFO_DER,
    x448_to_privatekeyinfo_der_newctx,
    X448,
    PrivateKeyInfo,
    Der
);
encoder!(
    X448_TO_PRIVATEKEYINFO_PEM,
    x448_to_privatekeyinfo_pem_newctx,
    X448,
    PrivateKeyInfo,
    Pem
);
encoder!(
    X448_TO_SUBJECTPUBLICKEYINFO_DER,
    x448_to_subjectpublickeyinfo_der_newctx,
    X448,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    X448_TO_SUBJECTPUBLICKEYINFO_PEM,
    x448_to_subjectpublickeyinfo_pem_newctx,
    X448,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    ED25519_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ed25519_to_encryptedprivatekeyinfo_der_newctx,
    ED25519,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    ED25519_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ed25519_to_encryptedprivatekeyinfo_pem_newctx,
    ED25519,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    ED25519_TO_PRIVATEKEYINFO_DER,
    ed25519_to_privatekeyinfo_der_newctx,
    ED25519,
    PrivateKeyInfo,
    Der
);
encoder!(
    ED25519_TO_PRIVATEKEYINFO_PEM,
    ed25519_to_privatekeyinfo_pem_newctx,
    ED25519,
    PrivateKeyInfo,
    Pem
);
encoder!(
    ED25519_TO_SUBJECTPUBLICKEYINFO_DER,
    ed25519_to_subjectpublickeyinfo_der_newctx,
    ED25519,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    ED25519_TO_SUBJECTPUBLICKEYINFO_PEM,
    ed25519_to_subjectpublickeyinfo_pem_newctx,
    ED25519,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    ED448_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ed448_to_encryptedprivatekeyinfo_der_newctx,
    ED448,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    ED448_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ed448_to_encryptedprivatekeyinfo_pem_newctx,
    ED448,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    ED448_TO_PRIVATEKEYINFO_DER,
    ed448_to_privatekeyinfo_der_newctx,
    ED448,
    PrivateKeyInfo,
    Der
);
encoder!(
    ED448_TO_PRIVATEKEYINFO_PEM,
    ed448_to_privatekeyinfo_pem_newctx,
    ED448,
    PrivateKeyInfo,
    Pem
);
encoder!(
    ED448_TO_SUBJECTPUBLICKEYINFO_DER,
    ed448_to_subjectpublickeyinfo_der_newctx,
    ED448,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    ED448_TO_SUBJECTPUBLICKEYINFO_PEM,
    ed448_to_subjectpublickeyinfo_pem_newctx,
    ED448,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHA2_128S_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    slh_dsa_sha2_128s_to_encryptedprivatekeyinfo_der_newctx,
    SLH_DSA_SHA2_128S,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHA2_128F_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    slh_dsa_sha2_128f_to_encryptedprivatekeyinfo_der_newctx,
    SLH_DSA_SHA2_128F,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHA2_192S_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    slh_dsa_sha2_192s_to_encryptedprivatekeyinfo_der_newctx,
    SLH_DSA_SHA2_192S,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHA2_192F_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    slh_dsa_sha2_192f_to_encryptedprivatekeyinfo_der_newctx,
    SLH_DSA_SHA2_192F,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHA2_256S_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    slh_dsa_sha2_256s_to_encryptedprivatekeyinfo_der_newctx,
    SLH_DSA_SHA2_256S,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHA2_256F_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    slh_dsa_sha2_256f_to_encryptedprivatekeyinfo_der_newctx,
    SLH_DSA_SHA2_256F,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHAKE_128S_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    slh_dsa_shake_128s_to_encryptedprivatekeyinfo_der_newctx,
    SLH_DSA_SHAKE_128S,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHAKE_128F_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    slh_dsa_shake_128f_to_encryptedprivatekeyinfo_der_newctx,
    SLH_DSA_SHAKE_128F,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHAKE_192S_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    slh_dsa_shake_192s_to_encryptedprivatekeyinfo_der_newctx,
    SLH_DSA_SHAKE_192S,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHAKE_192F_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    slh_dsa_shake_192f_to_encryptedprivatekeyinfo_der_newctx,
    SLH_DSA_SHAKE_192F,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHAKE_256S_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    slh_dsa_shake_256s_to_encryptedprivatekeyinfo_der_newctx,
    SLH_DSA_SHAKE_256S,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHAKE_256F_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    slh_dsa_shake_256f_to_encryptedprivatekeyinfo_der_newctx,
    SLH_DSA_SHAKE_256F,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHA2_128S_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    slh_dsa_sha2_128s_to_encryptedprivatekeyinfo_pem_newctx,
    SLH_DSA_SHA2_128S,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHA2_128F_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    slh_dsa_sha2_128f_to_encryptedprivatekeyinfo_pem_newctx,
    SLH_DSA_SHA2_128F,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHA2_192S_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    slh_dsa_sha2_192s_to_encryptedprivatekeyinfo_pem_newctx,
    SLH_DSA_SHA2_192S,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHA2_192F_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    slh_dsa_sha2_192f_to_encryptedprivatekeyinfo_pem_newctx,
    SLH_DSA_SHA2_192F,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHA2_256S_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    slh_dsa_sha2_256s_to_encryptedprivatekeyinfo_pem_newctx,
    SLH_DSA_SHA2_256S,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHA2_256F_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    slh_dsa_sha2_256f_to_encryptedprivatekeyinfo_pem_newctx,
    SLH_DSA_SHA2_256F,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHAKE_128S_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    slh_dsa_shake_128s_to_encryptedprivatekeyinfo_pem_newctx,
    SLH_DSA_SHAKE_128S,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHAKE_128F_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    slh_dsa_shake_128f_to_encryptedprivatekeyinfo_pem_newctx,
    SLH_DSA_SHAKE_128F,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHAKE_192S_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    slh_dsa_shake_192s_to_encryptedprivatekeyinfo_pem_newctx,
    SLH_DSA_SHAKE_192S,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHAKE_192F_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    slh_dsa_shake_192f_to_encryptedprivatekeyinfo_pem_newctx,
    SLH_DSA_SHAKE_192F,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHAKE_256S_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    slh_dsa_shake_256s_to_encryptedprivatekeyinfo_pem_newctx,
    SLH_DSA_SHAKE_256S,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHAKE_256F_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    slh_dsa_shake_256f_to_encryptedprivatekeyinfo_pem_newctx,
    SLH_DSA_SHAKE_256F,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHA2_128S_TO_PRIVATEKEYINFO_DER,
    slh_dsa_sha2_128s_to_privatekeyinfo_der_newctx,
    SLH_DSA_SHA2_128S,
    PrivateKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHA2_128F_TO_PRIVATEKEYINFO_DER,
    slh_dsa_sha2_128f_to_privatekeyinfo_der_newctx,
    SLH_DSA_SHA2_128F,
    PrivateKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHA2_192S_TO_PRIVATEKEYINFO_DER,
    slh_dsa_sha2_192s_to_privatekeyinfo_der_newctx,
    SLH_DSA_SHA2_192S,
    PrivateKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHA2_192F_TO_PRIVATEKEYINFO_DER,
    slh_dsa_sha2_192f_to_privatekeyinfo_der_newctx,
    SLH_DSA_SHA2_192F,
    PrivateKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHA2_256S_TO_PRIVATEKEYINFO_DER,
    slh_dsa_sha2_256s_to_privatekeyinfo_der_newctx,
    SLH_DSA_SHA2_256S,
    PrivateKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHA2_256F_TO_PRIVATEKEYINFO_DER,
    slh_dsa_sha2_256f_to_privatekeyinfo_der_newctx,
    SLH_DSA_SHA2_256F,
    PrivateKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHAKE_128S_TO_PRIVATEKEYINFO_DER,
    slh_dsa_shake_128s_to_privatekeyinfo_der_newctx,
    SLH_DSA_SHAKE_128S,
    PrivateKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHAKE_128F_TO_PRIVATEKEYINFO_DER,
    slh_dsa_shake_128f_to_privatekeyinfo_der_newctx,
    SLH_DSA_SHAKE_128F,
    PrivateKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHAKE_192S_TO_PRIVATEKEYINFO_DER,
    slh_dsa_shake_192s_to_privatekeyinfo_der_newctx,
    SLH_DSA_SHAKE_192S,
    PrivateKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHAKE_192F_TO_PRIVATEKEYINFO_DER,
    slh_dsa_shake_192f_to_privatekeyinfo_der_newctx,
    SLH_DSA_SHAKE_192F,
    PrivateKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHAKE_256S_TO_PRIVATEKEYINFO_DER,
    slh_dsa_shake_256s_to_privatekeyinfo_der_newctx,
    SLH_DSA_SHAKE_256S,
    PrivateKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHAKE_256F_TO_PRIVATEKEYINFO_DER,
    slh_dsa_shake_256f_to_privatekeyinfo_der_newctx,
    SLH_DSA_SHAKE_256F,
    PrivateKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHA2_128S_TO_PRIVATEKEYINFO_PEM,
    slh_dsa_sha2_128s_to_privatekeyinfo_pem_newctx,
    SLH_DSA_SHA2_128S,
    PrivateKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHA2_128F_TO_PRIVATEKEYINFO_PEM,
    slh_dsa_sha2_128f_to_privatekeyinfo_pem_newctx,
    SLH_DSA_SHA2_128F,
    PrivateKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHA2_192S_TO_PRIVATEKEYINFO_PEM,
    slh_dsa_sha2_192s_to_privatekeyinfo_pem_newctx,
    SLH_DSA_SHA2_192S,
    PrivateKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHA2_192F_TO_PRIVATEKEYINFO_PEM,
    slh_dsa_sha2_192f_to_privatekeyinfo_pem_newctx,
    SLH_DSA_SHA2_192F,
    PrivateKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHA2_256S_TO_PRIVATEKEYINFO_PEM,
    slh_dsa_sha2_256s_to_privatekeyinfo_pem_newctx,
    SLH_DSA_SHA2_256S,
    PrivateKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHA2_256F_TO_PRIVATEKEYINFO_PEM,
    slh_dsa_sha2_256f_to_privatekeyinfo_pem_newctx,
    SLH_DSA_SHA2_256F,
    PrivateKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHAKE_128S_TO_PRIVATEKEYINFO_PEM,
    slh_dsa_shake_128s_to_privatekeyinfo_pem_newctx,
    SLH_DSA_SHAKE_128S,
    PrivateKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHAKE_128F_TO_PRIVATEKEYINFO_PEM,
    slh_dsa_shake_128f_to_privatekeyinfo_pem_newctx,
    SLH_DSA_SHAKE_128F,
    PrivateKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHAKE_192S_TO_PRIVATEKEYINFO_PEM,
    slh_dsa_shake_192s_to_privatekeyinfo_pem_newctx,
    SLH_DSA_SHAKE_192S,
    PrivateKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHAKE_192F_TO_PRIVATEKEYINFO_PEM,
    slh_dsa_shake_192f_to_privatekeyinfo_pem_newctx,
    SLH_DSA_SHAKE_192F,
    PrivateKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHAKE_256S_TO_PRIVATEKEYINFO_PEM,
    slh_dsa_shake_256s_to_privatekeyinfo_pem_newctx,
    SLH_DSA_SHAKE_256S,
    PrivateKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHAKE_256F_TO_PRIVATEKEYINFO_PEM,
    slh_dsa_shake_256f_to_privatekeyinfo_pem_newctx,
    SLH_DSA_SHAKE_256F,
    PrivateKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHA2_128S_TO_SUBJECTPUBLICKEYINFO_DER,
    slh_dsa_sha2_128s_to_subjectpublickeyinfo_der_newctx,
    SLH_DSA_SHA2_128S,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHA2_128F_TO_SUBJECTPUBLICKEYINFO_DER,
    slh_dsa_sha2_128f_to_subjectpublickeyinfo_der_newctx,
    SLH_DSA_SHA2_128F,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHA2_192S_TO_SUBJECTPUBLICKEYINFO_DER,
    slh_dsa_sha2_192s_to_subjectpublickeyinfo_der_newctx,
    SLH_DSA_SHA2_192S,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHA2_192F_TO_SUBJECTPUBLICKEYINFO_DER,
    slh_dsa_sha2_192f_to_subjectpublickeyinfo_der_newctx,
    SLH_DSA_SHA2_192F,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHA2_256S_TO_SUBJECTPUBLICKEYINFO_DER,
    slh_dsa_sha2_256s_to_subjectpublickeyinfo_der_newctx,
    SLH_DSA_SHA2_256S,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHA2_256F_TO_SUBJECTPUBLICKEYINFO_DER,
    slh_dsa_sha2_256f_to_subjectpublickeyinfo_der_newctx,
    SLH_DSA_SHA2_256F,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHAKE_128S_TO_SUBJECTPUBLICKEYINFO_DER,
    slh_dsa_shake_128s_to_subjectpublickeyinfo_der_newctx,
    SLH_DSA_SHAKE_128S,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHAKE_128F_TO_SUBJECTPUBLICKEYINFO_DER,
    slh_dsa_shake_128f_to_subjectpublickeyinfo_der_newctx,
    SLH_DSA_SHAKE_128F,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHAKE_192S_TO_SUBJECTPUBLICKEYINFO_DER,
    slh_dsa_shake_192s_to_subjectpublickeyinfo_der_newctx,
    SLH_DSA_SHAKE_192S,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHAKE_192F_TO_SUBJECTPUBLICKEYINFO_DER,
    slh_dsa_shake_192f_to_subjectpublickeyinfo_der_newctx,
    SLH_DSA_SHAKE_192F,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHAKE_256S_TO_SUBJECTPUBLICKEYINFO_DER,
    slh_dsa_shake_256s_to_subjectpublickeyinfo_der_newctx,
    SLH_DSA_SHAKE_256S,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHAKE_256F_TO_SUBJECTPUBLICKEYINFO_DER,
    slh_dsa_shake_256f_to_subjectpublickeyinfo_der_newctx,
    SLH_DSA_SHAKE_256F,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    SLH_DSA_SHA2_128S_TO_SUBJECTPUBLICKEYINFO_PEM,
    slh_dsa_sha2_128s_to_subjectpublickeyinfo_pem_newctx,
    SLH_DSA_SHA2_128S,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHA2_128F_TO_SUBJECTPUBLICKEYINFO_PEM,
    slh_dsa_sha2_128f_to_subjectpublickeyinfo_pem_newctx,
    SLH_DSA_SHA2_128F,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHA2_192S_TO_SUBJECTPUBLICKEYINFO_PEM,
    slh_dsa_sha2_192s_to_subjectpublickeyinfo_pem_newctx,
    SLH_DSA_SHA2_192S,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHA2_192F_TO_SUBJECTPUBLICKEYINFO_PEM,
    slh_dsa_sha2_192f_to_subjectpublickeyinfo_pem_newctx,
    SLH_DSA_SHA2_192F,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHA2_256S_TO_SUBJECTPUBLICKEYINFO_PEM,
    slh_dsa_sha2_256s_to_subjectpublickeyinfo_pem_newctx,
    SLH_DSA_SHA2_256S,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHA2_256F_TO_SUBJECTPUBLICKEYINFO_PEM,
    slh_dsa_sha2_256f_to_subjectpublickeyinfo_pem_newctx,
    SLH_DSA_SHA2_256F,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHAKE_128S_TO_SUBJECTPUBLICKEYINFO_PEM,
    slh_dsa_shake_128s_to_subjectpublickeyinfo_pem_newctx,
    SLH_DSA_SHAKE_128S,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHAKE_128F_TO_SUBJECTPUBLICKEYINFO_PEM,
    slh_dsa_shake_128f_to_subjectpublickeyinfo_pem_newctx,
    SLH_DSA_SHAKE_128F,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHAKE_192S_TO_SUBJECTPUBLICKEYINFO_PEM,
    slh_dsa_shake_192s_to_subjectpublickeyinfo_pem_newctx,
    SLH_DSA_SHAKE_192S,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHAKE_192F_TO_SUBJECTPUBLICKEYINFO_PEM,
    slh_dsa_shake_192f_to_subjectpublickeyinfo_pem_newctx,
    SLH_DSA_SHAKE_192F,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHAKE_256S_TO_SUBJECTPUBLICKEYINFO_PEM,
    slh_dsa_shake_256s_to_subjectpublickeyinfo_pem_newctx,
    SLH_DSA_SHAKE_256S,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    SLH_DSA_SHAKE_256F_TO_SUBJECTPUBLICKEYINFO_PEM,
    slh_dsa_shake_256f_to_subjectpublickeyinfo_pem_newctx,
    SLH_DSA_SHAKE_256F,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    ML_KEM_512_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ml_kem_512_to_encryptedprivatekeyinfo_der_newctx,
    ML_KEM_512,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    ML_KEM_512_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ml_kem_512_to_encryptedprivatekeyinfo_pem_newctx,
    ML_KEM_512,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    ML_KEM_512_TO_PRIVATEKEYINFO_DER,
    ml_kem_512_to_privatekeyinfo_der_newctx,
    ML_KEM_512,
    PrivateKeyInfo,
    Der
);
encoder!(
    ML_KEM_512_TO_PRIVATEKEYINFO_PEM,
    ml_kem_512_to_privatekeyinfo_pem_newctx,
    ML_KEM_512,
    PrivateKeyInfo,
    Pem
);
encoder!(
    ML_KEM_512_TO_SUBJECTPUBLICKEYINFO_DER,
    ml_kem_512_to_subjectpublickeyinfo_der_newctx,
    ML_KEM_512,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    ML_KEM_512_TO_SUBJECTPUBLICKEYINFO_PEM,
    ml_kem_512_to_subjectpublickeyinfo_pem_newctx,
    ML_KEM_512,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    ML_KEM_768_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ml_kem_768_to_encryptedprivatekeyinfo_der_newctx,
    ML_KEM_768,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    ML_KEM_768_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ml_kem_768_to_encryptedprivatekeyinfo_pem_newctx,
    ML_KEM_768,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    ML_KEM_768_TO_PRIVATEKEYINFO_DER,
    ml_kem_768_to_privatekeyinfo_der_newctx,
    ML_KEM_768,
    PrivateKeyInfo,
    Der
);
encoder!(
    ML_KEM_768_TO_PRIVATEKEYINFO_PEM,
    ml_kem_768_to_privatekeyinfo_pem_newctx,
    ML_KEM_768,
    PrivateKeyInfo,
    Pem
);
encoder!(
    ML_KEM_768_TO_SUBJECTPUBLICKEYINFO_DER,
    ml_kem_768_to_subjectpublickeyinfo_der_newctx,
    ML_KEM_768,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    ML_KEM_768_TO_SUBJECTPUBLICKEYINFO_PEM,
    ml_kem_768_to_subjectpublickeyinfo_pem_newctx,
    ML_KEM_768,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    ML_KEM_1024_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ml_kem_1024_to_encryptedprivatekeyinfo_der_newctx,
    ML_KEM_1024,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    ML_KEM_1024_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ml_kem_1024_to_encryptedprivatekeyinfo_pem_newctx,
    ML_KEM_1024,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    ML_KEM_1024_TO_PRIVATEKEYINFO_DER,
    ml_kem_1024_to_privatekeyinfo_der_newctx,
    ML_KEM_1024,
    PrivateKeyInfo,
    Der
);
encoder!(
    ML_KEM_1024_TO_PRIVATEKEYINFO_PEM,
    ml_kem_1024_to_privatekeyinfo_pem_newctx,
    ML_KEM_1024,
    PrivateKeyInfo,
    Pem
);
encoder!(
    ML_KEM_1024_TO_SUBJECTPUBLICKEYINFO_DER,
    ml_kem_1024_to_subjectpublickeyinfo_der_newctx,
    ML_KEM_1024,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    ML_KEM_1024_TO_SUBJECTPUBLICKEYINFO_PEM,
    ml_kem_1024_to_subjectpublickeyinfo_pem_newctx,
    ML_KEM_1024,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    ML_DSA_44_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ml_dsa_44_to_encryptedprivatekeyinfo_der_newctx,
    ML_DSA_44,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    ML_DSA_44_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ml_dsa_44_to_encryptedprivatekeyinfo_pem_newctx,
    ML_DSA_44,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    ML_DSA_44_TO_PRIVATEKEYINFO_DER,
    ml_dsa_44_to_privatekeyinfo_der_newctx,
    ML_DSA_44,
    PrivateKeyInfo,
    Der
);
encoder!(
    ML_DSA_44_TO_PRIVATEKEYINFO_PEM,
    ml_dsa_44_to_privatekeyinfo_pem_newctx,
    ML_DSA_44,
    PrivateKeyInfo,
    Pem
);
encoder!(
    ML_DSA_44_TO_SUBJECTPUBLICKEYINFO_DER,
    ml_dsa_44_to_subjectpublickeyinfo_der_newctx,
    ML_DSA_44,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    ML_DSA_44_TO_SUBJECTPUBLICKEYINFO_PEM,
    ml_dsa_44_to_subjectpublickeyinfo_pem_newctx,
    ML_DSA_44,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    ML_DSA_65_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ml_dsa_65_to_encryptedprivatekeyinfo_der_newctx,
    ML_DSA_65,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    ML_DSA_65_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ml_dsa_65_to_encryptedprivatekeyinfo_pem_newctx,
    ML_DSA_65,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    ML_DSA_65_TO_PRIVATEKEYINFO_DER,
    ml_dsa_65_to_privatekeyinfo_der_newctx,
    ML_DSA_65,
    PrivateKeyInfo,
    Der
);
encoder!(
    ML_DSA_65_TO_PRIVATEKEYINFO_PEM,
    ml_dsa_65_to_privatekeyinfo_pem_newctx,
    ML_DSA_65,
    PrivateKeyInfo,
    Pem
);
encoder!(
    ML_DSA_65_TO_SUBJECTPUBLICKEYINFO_DER,
    ml_dsa_65_to_subjectpublickeyinfo_der_newctx,
    ML_DSA_65,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    ML_DSA_65_TO_SUBJECTPUBLICKEYINFO_PEM,
    ml_dsa_65_to_subjectpublickeyinfo_pem_newctx,
    ML_DSA_65,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(
    ML_DSA_87_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ml_dsa_87_to_encryptedprivatekeyinfo_der_newctx,
    ML_DSA_87,
    EncryptedPrivateKeyInfo,
    Der
);
encoder!(
    ML_DSA_87_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ml_dsa_87_to_encryptedprivatekeyinfo_pem_newctx,
    ML_DSA_87,
    EncryptedPrivateKeyInfo,
    Pem
);
encoder!(
    ML_DSA_87_TO_PRIVATEKEYINFO_DER,
    ml_dsa_87_to_privatekeyinfo_der_newctx,
    ML_DSA_87,
    PrivateKeyInfo,
    Der
);
encoder!(
    ML_DSA_87_TO_PRIVATEKEYINFO_PEM,
    ml_dsa_87_to_privatekeyinfo_pem_newctx,
    ML_DSA_87,
    PrivateKeyInfo,
    Pem
);
encoder!(
    ML_DSA_87_TO_SUBJECTPUBLICKEYINFO_DER,
    ml_dsa_87_to_subjectpublickeyinfo_der_newctx,
    ML_DSA_87,
    SubjectPublicKeyInfo,
    Der
);
encoder!(
    ML_DSA_87_TO_SUBJECTPUBLICKEYINFO_PEM,
    ml_dsa_87_to_subjectpublickeyinfo_pem_newctx,
    ML_DSA_87,
    SubjectPublicKeyInfo,
    Pem
);
encoder!(RSA_TO_RSA_DER, rsa_to_rsa_der_newctx, RSA, Keypair, Der);
encoder!(RSA_TO_RSA_PEM, rsa_to_rsa_pem_newctx, RSA, Keypair, Pem);
encoder!(DH_TO_DH_DER, dh_to_dh_der_newctx, DH, Params, Der);
encoder!(DH_TO_DH_PEM, dh_to_dh_pem_newctx, DH, Params, Pem);
encoder!(DHX_TO_DHX_DER, dhx_to_dhx_der_newctx, DHX, Params, Der);
encoder!(DHX_TO_DHX_PEM, dhx_to_dhx_pem_newctx, DHX, Params, Pem);
encoder!(DSA_TO_DSA_DER, dsa_to_dsa_der_newctx, DSA, All, Der);
encoder!(DSA_TO_DSA_PEM, dsa_to_dsa_pem_newctx, DSA, All, Pem);
encoder!(EC_TO_EC_DER, ec_to_ec_der_newctx, EC, NoPub, Der);
encoder!(EC_TO_EC_PEM, ec_to_ec_pem_newctx, EC, NoPub, Pem);
encoder!(RSA_TO_PKCS1_DER, rsa_to_pkcs1_der_newctx, RSA, Keypair, Der);
encoder!(RSA_TO_PKCS1_PEM, rsa_to_pkcs1_pem_newctx, RSA, Keypair, Pem);
encoder!(
    RSAPSS_TO_PKCS1_DER,
    rsapss_to_pkcs1_der_newctx,
    RSAPSS,
    Keypair,
    Der
);
encoder!(
    RSAPSS_TO_PKCS1_PEM,
    rsapss_to_pkcs1_pem_newctx,
    RSAPSS,
    Keypair,
    Pem
);
encoder!(DH_TO_PKCS3_DER, dh_to_pkcs3_der_newctx, DH, Params, Der);
encoder!(DH_TO_PKCS3_PEM, dh_to_pkcs3_pem_newctx, DH, Params, Pem);
encoder!(DHX_TO_X9_42_DER, dhx_to_x9_42_der_newctx, DHX, Params, Der);
encoder!(DHX_TO_X9_42_PEM, dhx_to_x9_42_pem_newctx, DHX, Params, Pem);
encoder!(EC_TO_X9_62_DER, ec_to_x9_62_der_newctx, EC, NoPub, Der);
encoder!(EC_TO_X9_62_PEM, ec_to_x9_62_pem_newctx, EC, NoPub, Pem);

// The text encoders, which come with step 4.7c2 (`MAKE_TEXT_ENCODER` in `encode_key2text.c`).

text_encoder!(
    RSA_TO_TEXT,
    rsa_to_text_import_object,
    rsa_to_text_encode,
    RSA
);
text_encoder!(
    RSAPSS_TO_TEXT,
    rsapss_to_text_import_object,
    rsapss_to_text_encode,
    RSAPSS
);
text_encoder!(DH_TO_TEXT, dh_to_text_import_object, dh_to_text_encode, DH);
text_encoder!(
    DHX_TO_TEXT,
    dhx_to_text_import_object,
    dhx_to_text_encode,
    DHX
);
text_encoder!(
    DSA_TO_TEXT,
    dsa_to_text_import_object,
    dsa_to_text_encode,
    DSA
);
text_encoder!(EC_TO_TEXT, ec_to_text_import_object, ec_to_text_encode, EC);
text_encoder!(
    ED25519_TO_TEXT,
    ed25519_to_text_import_object,
    ed25519_to_text_encode,
    ED25519
);
text_encoder!(
    ED448_TO_TEXT,
    ed448_to_text_import_object,
    ed448_to_text_encode,
    ED448
);
text_encoder!(
    X25519_TO_TEXT,
    x25519_to_text_import_object,
    x25519_to_text_encode,
    X25519
);
text_encoder!(
    X448_TO_TEXT,
    x448_to_text_import_object,
    x448_to_text_encode,
    X448
);
text_encoder!(
    SM2_TO_TEXT,
    sm2_to_text_import_object,
    sm2_to_text_encode,
    SM2
);
text_encoder!(
    ML_KEM_512_TO_TEXT,
    ml_kem_512_to_text_import_object,
    ml_kem_512_to_text_encode,
    ML_KEM_512
);
text_encoder!(
    ML_KEM_768_TO_TEXT,
    ml_kem_768_to_text_import_object,
    ml_kem_768_to_text_encode,
    ML_KEM_768
);
text_encoder!(
    ML_KEM_1024_TO_TEXT,
    ml_kem_1024_to_text_import_object,
    ml_kem_1024_to_text_encode,
    ML_KEM_1024
);
text_encoder!(
    ML_DSA_44_TO_TEXT,
    ml_dsa_44_to_text_import_object,
    ml_dsa_44_to_text_encode,
    ML_DSA_44
);
text_encoder!(
    ML_DSA_65_TO_TEXT,
    ml_dsa_65_to_text_import_object,
    ml_dsa_65_to_text_encode,
    ML_DSA_65
);
text_encoder!(
    ML_DSA_87_TO_TEXT,
    ml_dsa_87_to_text_import_object,
    ml_dsa_87_to_text_encode,
    ML_DSA_87
);
text_encoder!(
    SLH_DSA_SHA2_128S_TO_TEXT,
    slh_dsa_sha2_128s_to_text_import_object,
    slh_dsa_sha2_128s_to_text_encode,
    SLH_DSA_SHA2_128S
);
text_encoder!(
    SLH_DSA_SHA2_128F_TO_TEXT,
    slh_dsa_sha2_128f_to_text_import_object,
    slh_dsa_sha2_128f_to_text_encode,
    SLH_DSA_SHA2_128F
);
text_encoder!(
    SLH_DSA_SHA2_192S_TO_TEXT,
    slh_dsa_sha2_192s_to_text_import_object,
    slh_dsa_sha2_192s_to_text_encode,
    SLH_DSA_SHA2_192S
);
text_encoder!(
    SLH_DSA_SHA2_192F_TO_TEXT,
    slh_dsa_sha2_192f_to_text_import_object,
    slh_dsa_sha2_192f_to_text_encode,
    SLH_DSA_SHA2_192F
);
text_encoder!(
    SLH_DSA_SHA2_256S_TO_TEXT,
    slh_dsa_sha2_256s_to_text_import_object,
    slh_dsa_sha2_256s_to_text_encode,
    SLH_DSA_SHA2_256S
);
text_encoder!(
    SLH_DSA_SHA2_256F_TO_TEXT,
    slh_dsa_sha2_256f_to_text_import_object,
    slh_dsa_sha2_256f_to_text_encode,
    SLH_DSA_SHA2_256F
);
text_encoder!(
    SLH_DSA_SHAKE_128S_TO_TEXT,
    slh_dsa_shake_128s_to_text_import_object,
    slh_dsa_shake_128s_to_text_encode,
    SLH_DSA_SHAKE_128S
);
text_encoder!(
    SLH_DSA_SHAKE_128F_TO_TEXT,
    slh_dsa_shake_128f_to_text_import_object,
    slh_dsa_shake_128f_to_text_encode,
    SLH_DSA_SHAKE_128F
);
text_encoder!(
    SLH_DSA_SHAKE_192S_TO_TEXT,
    slh_dsa_shake_192s_to_text_import_object,
    slh_dsa_shake_192s_to_text_encode,
    SLH_DSA_SHAKE_192S
);
text_encoder!(
    SLH_DSA_SHAKE_192F_TO_TEXT,
    slh_dsa_shake_192f_to_text_import_object,
    slh_dsa_shake_192f_to_text_encode,
    SLH_DSA_SHAKE_192F
);
text_encoder!(
    SLH_DSA_SHAKE_256S_TO_TEXT,
    slh_dsa_shake_256s_to_text_import_object,
    slh_dsa_shake_256s_to_text_encode,
    SLH_DSA_SHAKE_256S
);
text_encoder!(
    SLH_DSA_SHAKE_256F_TO_TEXT,
    slh_dsa_shake_256f_to_text_import_object,
    slh_dsa_shake_256f_to_text_encode,
    SLH_DSA_SHAKE_256F
);

static DEFAULT_ENCODERS: Algorithms<242> = Algorithms([
    encoder(
        c"RSA",
        c"provider=default,fips=yes,output=text",
        &RSA_TO_TEXT,
    ),
    encoder(
        c"RSA-PSS",
        c"provider=default,fips=yes,output=text",
        &RSAPSS_TO_TEXT,
    ),
    encoder(c"DH", c"provider=default,fips=yes,output=text", &DH_TO_TEXT),
    encoder(
        c"DHX",
        c"provider=default,fips=yes,output=text",
        &DHX_TO_TEXT,
    ),
    encoder(
        c"DSA",
        c"provider=default,fips=yes,output=text",
        &DSA_TO_TEXT,
    ),
    encoder(c"EC", c"provider=default,fips=yes,output=text", &EC_TO_TEXT),
    encoder(
        c"ED25519",
        c"provider=default,fips=yes,output=text",
        &ED25519_TO_TEXT,
    ),
    encoder(
        c"ED448",
        c"provider=default,fips=yes,output=text",
        &ED448_TO_TEXT,
    ),
    encoder(
        c"X25519",
        c"provider=default,fips=yes,output=text",
        &X25519_TO_TEXT,
    ),
    encoder(
        c"X448",
        c"provider=default,fips=yes,output=text",
        &X448_TO_TEXT,
    ),
    encoder(
        c"SM2",
        c"provider=default,fips=no,output=text",
        &SM2_TO_TEXT,
    ),
    encoder(
        c"ML-KEM-512",
        c"provider=default,fips=yes,output=text",
        &ML_KEM_512_TO_TEXT,
    ),
    encoder(
        c"ML-KEM-768",
        c"provider=default,fips=yes,output=text",
        &ML_KEM_768_TO_TEXT,
    ),
    encoder(
        c"ML-KEM-1024",
        c"provider=default,fips=yes,output=text",
        &ML_KEM_1024_TO_TEXT,
    ),
    encoder(
        c"ML-DSA-44",
        c"provider=default,fips=yes,output=text",
        &ML_DSA_44_TO_TEXT,
    ),
    encoder(
        c"ML-DSA-65",
        c"provider=default,fips=yes,output=text",
        &ML_DSA_65_TO_TEXT,
    ),
    encoder(
        c"ML-DSA-87",
        c"provider=default,fips=yes,output=text",
        &ML_DSA_87_TO_TEXT,
    ),
    encoder(
        c"SLH-DSA-SHA2-128s",
        c"provider=default,fips=yes,output=text",
        &SLH_DSA_SHA2_128S_TO_TEXT,
    ),
    encoder(
        c"SLH-DSA-SHA2-128f",
        c"provider=default,fips=yes,output=text",
        &SLH_DSA_SHA2_128F_TO_TEXT,
    ),
    encoder(
        c"SLH-DSA-SHA2-192s",
        c"provider=default,fips=yes,output=text",
        &SLH_DSA_SHA2_192S_TO_TEXT,
    ),
    encoder(
        c"SLH-DSA-SHA2-192f",
        c"provider=default,fips=yes,output=text",
        &SLH_DSA_SHA2_192F_TO_TEXT,
    ),
    encoder(
        c"SLH-DSA-SHA2-256s",
        c"provider=default,fips=yes,output=text",
        &SLH_DSA_SHA2_256S_TO_TEXT,
    ),
    encoder(
        c"SLH-DSA-SHA2-256f",
        c"provider=default,fips=yes,output=text",
        &SLH_DSA_SHA2_256F_TO_TEXT,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128s",
        c"provider=default,fips=yes,output=text",
        &SLH_DSA_SHAKE_128S_TO_TEXT,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128f",
        c"provider=default,fips=yes,output=text",
        &SLH_DSA_SHAKE_128F_TO_TEXT,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192s",
        c"provider=default,fips=yes,output=text",
        &SLH_DSA_SHAKE_192S_TO_TEXT,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192f",
        c"provider=default,fips=yes,output=text",
        &SLH_DSA_SHAKE_192F_TO_TEXT,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256s",
        c"provider=default,fips=yes,output=text",
        &SLH_DSA_SHAKE_256S_TO_TEXT,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256f",
        c"provider=default,fips=yes,output=text",
        &SLH_DSA_SHAKE_256F_TO_TEXT,
    ),
    encoder(
        c"RSA",
        c"provider=default,fips=yes,output=der,structure=type-specific",
        &RSA_TO_TYPE_SPECIFIC_KEYPAIR_DER,
    ),
    encoder(
        c"RSA",
        c"provider=default,fips=yes,output=pem,structure=type-specific",
        &RSA_TO_TYPE_SPECIFIC_KEYPAIR_PEM,
    ),
    encoder(
        c"DH",
        c"provider=default,fips=yes,output=der,structure=type-specific",
        &DH_TO_TYPE_SPECIFIC_PARAMS_DER,
    ),
    encoder(
        c"DH",
        c"provider=default,fips=yes,output=pem,structure=type-specific",
        &DH_TO_TYPE_SPECIFIC_PARAMS_PEM,
    ),
    encoder(
        c"DHX",
        c"provider=default,fips=yes,output=der,structure=type-specific",
        &DHX_TO_TYPE_SPECIFIC_PARAMS_DER,
    ),
    encoder(
        c"DHX",
        c"provider=default,fips=yes,output=pem,structure=type-specific",
        &DHX_TO_TYPE_SPECIFIC_PARAMS_PEM,
    ),
    encoder(
        c"DSA",
        c"provider=default,fips=yes,output=der,structure=type-specific",
        &DSA_TO_TYPE_SPECIFIC_DER,
    ),
    encoder(
        c"DSA",
        c"provider=default,fips=yes,output=pem,structure=type-specific",
        &DSA_TO_TYPE_SPECIFIC_PEM,
    ),
    encoder(
        c"EC",
        c"provider=default,fips=yes,output=der,structure=type-specific",
        &EC_TO_TYPE_SPECIFIC_NO_PUB_DER,
    ),
    encoder(
        c"EC",
        c"provider=default,fips=yes,output=pem,structure=type-specific",
        &EC_TO_TYPE_SPECIFIC_NO_PUB_PEM,
    ),
    encoder(c"EC", c"provider=default,fips=yes,output=blob", &EC_TO_BLOB),
    encoder(
        c"SM2",
        c"provider=default,fips=no,output=der,structure=type-specific",
        &SM2_TO_TYPE_SPECIFIC_NO_PUB_DER,
    ),
    encoder(
        c"SM2",
        c"provider=default,fips=no,output=pem,structure=type-specific",
        &SM2_TO_TYPE_SPECIFIC_NO_PUB_PEM,
    ),
    encoder(
        c"SM2",
        c"provider=default,fips=no,output=blob",
        &SM2_TO_BLOB,
    ),
    encoder(
        c"RSA",
        c"provider=default,fips=yes,output=msblob",
        &RSA_TO_MSBLOB,
    ),
    encoder(c"RSA", c"provider=default,fips=yes,output=pvk", &RSA_TO_PVK),
    encoder(
        c"DSA",
        c"provider=default,fips=yes,output=msblob",
        &DSA_TO_MSBLOB,
    ),
    encoder(c"DSA", c"provider=default,fips=yes,output=pvk", &DSA_TO_PVK),
    encoder(
        c"RSA",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &RSA_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"RSA",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &RSA_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"RSA",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &RSA_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"RSA",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &RSA_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"RSA",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &RSA_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"RSA",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &RSA_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"RSA-PSS",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &RSAPSS_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"RSA-PSS",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &RSAPSS_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"RSA-PSS",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &RSAPSS_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"RSA-PSS",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &RSAPSS_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"RSA-PSS",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &RSAPSS_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"RSA-PSS",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &RSAPSS_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"DH",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &DH_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"DH",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &DH_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"DH",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &DH_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"DH",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &DH_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"DH",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &DH_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"DH",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &DH_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"DHX",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &DHX_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"DHX",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &DHX_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"DHX",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &DHX_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"DHX",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &DHX_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"DHX",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &DHX_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"DHX",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &DHX_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"DSA",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &DSA_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"DSA",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &DSA_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"DSA",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &DSA_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"DSA",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &DSA_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"DSA",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &DSA_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"DSA",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &DSA_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"EC",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &EC_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"EC",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &EC_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"EC",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &EC_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"EC",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &EC_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"EC",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &EC_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"EC",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &EC_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"SM2",
        c"provider=default,fips=no,output=der,structure=EncryptedPrivateKeyInfo",
        &SM2_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SM2",
        c"provider=default,fips=no,output=pem,structure=EncryptedPrivateKeyInfo",
        &SM2_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SM2",
        c"provider=default,fips=no,output=der,structure=PrivateKeyInfo",
        &SM2_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SM2",
        c"provider=default,fips=no,output=pem,structure=PrivateKeyInfo",
        &SM2_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SM2",
        c"provider=default,fips=no,output=der,structure=SubjectPublicKeyInfo",
        &SM2_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"SM2",
        c"provider=default,fips=no,output=pem,structure=SubjectPublicKeyInfo",
        &SM2_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"X25519",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &X25519_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"X25519",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &X25519_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"X25519",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &X25519_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"X25519",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &X25519_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"X25519",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &X25519_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"X25519",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &X25519_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"X448",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &X448_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"X448",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &X448_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"X448",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &X448_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"X448",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &X448_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"X448",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &X448_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"X448",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &X448_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"ED25519",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &ED25519_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ED25519",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &ED25519_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ED25519",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &ED25519_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ED25519",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &ED25519_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ED25519",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &ED25519_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"ED25519",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &ED25519_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"ED448",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &ED448_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ED448",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &ED448_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ED448",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &ED448_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ED448",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &ED448_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ED448",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &ED448_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"ED448",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &ED448_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-128s",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHA2_128S_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-128f",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHA2_128F_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-192s",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHA2_192S_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-192f",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHA2_192F_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-256s",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHA2_256S_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-256f",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHA2_256F_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128s",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHAKE_128S_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128f",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHAKE_128F_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192s",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHAKE_192S_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192f",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHAKE_192F_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256s",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHAKE_256S_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256f",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHAKE_256F_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-128s",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHA2_128S_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-128f",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHA2_128F_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-192s",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHA2_192S_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-192f",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHA2_192F_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-256s",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHA2_256S_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-256f",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHA2_256F_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128s",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHAKE_128S_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128f",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHAKE_128F_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192s",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHAKE_192S_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192f",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHAKE_192F_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256s",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHAKE_256S_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256f",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHAKE_256F_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-128s",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &SLH_DSA_SHA2_128S_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-128f",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &SLH_DSA_SHA2_128F_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-192s",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &SLH_DSA_SHA2_192S_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-192f",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &SLH_DSA_SHA2_192F_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-256s",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &SLH_DSA_SHA2_256S_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-256f",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &SLH_DSA_SHA2_256F_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128s",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &SLH_DSA_SHAKE_128S_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128f",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &SLH_DSA_SHAKE_128F_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192s",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &SLH_DSA_SHAKE_192S_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192f",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &SLH_DSA_SHAKE_192F_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256s",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &SLH_DSA_SHAKE_256S_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256f",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &SLH_DSA_SHAKE_256F_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-128s",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &SLH_DSA_SHA2_128S_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-128f",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &SLH_DSA_SHA2_128F_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-192s",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &SLH_DSA_SHA2_192S_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-192f",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &SLH_DSA_SHA2_192F_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-256s",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &SLH_DSA_SHA2_256S_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-256f",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &SLH_DSA_SHA2_256F_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128s",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &SLH_DSA_SHAKE_128S_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128f",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &SLH_DSA_SHAKE_128F_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192s",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &SLH_DSA_SHAKE_192S_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192f",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &SLH_DSA_SHAKE_192F_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256s",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &SLH_DSA_SHAKE_256S_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256f",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &SLH_DSA_SHAKE_256F_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-128s",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHA2_128S_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-128f",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHA2_128F_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-192s",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHA2_192S_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-192f",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHA2_192F_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-256s",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHA2_256S_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-256f",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHA2_256F_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128s",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHAKE_128S_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128f",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHAKE_128F_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192s",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHAKE_192S_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192f",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHAKE_192F_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256s",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHAKE_256S_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256f",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHAKE_256F_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-128s",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHA2_128S_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-128f",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHA2_128F_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-192s",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHA2_192S_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-192f",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHA2_192F_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-256s",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHA2_256S_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-256f",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHA2_256F_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128s",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHAKE_128S_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128f",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHAKE_128F_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192s",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHAKE_192S_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192f",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHAKE_192F_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256s",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHAKE_256S_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256f",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHAKE_256F_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"ML-KEM-512",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &ML_KEM_512_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ML-KEM-512",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &ML_KEM_512_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ML-KEM-512",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &ML_KEM_512_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ML-KEM-512",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &ML_KEM_512_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ML-KEM-512",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &ML_KEM_512_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"ML-KEM-512",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &ML_KEM_512_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"ML-KEM-768",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &ML_KEM_768_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ML-KEM-768",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &ML_KEM_768_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ML-KEM-768",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &ML_KEM_768_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ML-KEM-768",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &ML_KEM_768_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ML-KEM-768",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &ML_KEM_768_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"ML-KEM-768",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &ML_KEM_768_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"ML-KEM-1024",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &ML_KEM_1024_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ML-KEM-1024",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &ML_KEM_1024_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ML-KEM-1024",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &ML_KEM_1024_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ML-KEM-1024",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &ML_KEM_1024_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ML-KEM-1024",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &ML_KEM_1024_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"ML-KEM-1024",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &ML_KEM_1024_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"ML-DSA-44",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &ML_DSA_44_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ML-DSA-44",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &ML_DSA_44_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ML-DSA-44",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &ML_DSA_44_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ML-DSA-44",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &ML_DSA_44_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ML-DSA-44",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &ML_DSA_44_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"ML-DSA-44",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &ML_DSA_44_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"ML-DSA-65",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &ML_DSA_65_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ML-DSA-65",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &ML_DSA_65_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ML-DSA-65",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &ML_DSA_65_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ML-DSA-65",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &ML_DSA_65_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ML-DSA-65",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &ML_DSA_65_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"ML-DSA-65",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &ML_DSA_65_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"ML-DSA-87",
        c"provider=default,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &ML_DSA_87_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ML-DSA-87",
        c"provider=default,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &ML_DSA_87_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ML-DSA-87",
        c"provider=default,fips=yes,output=der,structure=PrivateKeyInfo",
        &ML_DSA_87_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ML-DSA-87",
        c"provider=default,fips=yes,output=pem,structure=PrivateKeyInfo",
        &ML_DSA_87_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ML-DSA-87",
        c"provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &ML_DSA_87_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"ML-DSA-87",
        c"provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &ML_DSA_87_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"RSA",
        c"provider=default,fips=yes,output=der,structure=rsa",
        &RSA_TO_RSA_DER,
    ),
    encoder(
        c"RSA",
        c"provider=default,fips=yes,output=pem,structure=rsa",
        &RSA_TO_RSA_PEM,
    ),
    encoder(
        c"DH",
        c"provider=default,fips=yes,output=der,structure=dh",
        &DH_TO_DH_DER,
    ),
    encoder(
        c"DH",
        c"provider=default,fips=yes,output=pem,structure=dh",
        &DH_TO_DH_PEM,
    ),
    encoder(
        c"DHX",
        c"provider=default,fips=yes,output=der,structure=dhx",
        &DHX_TO_DHX_DER,
    ),
    encoder(
        c"DHX",
        c"provider=default,fips=yes,output=pem,structure=dhx",
        &DHX_TO_DHX_PEM,
    ),
    encoder(
        c"DSA",
        c"provider=default,fips=yes,output=der,structure=dsa",
        &DSA_TO_DSA_DER,
    ),
    encoder(
        c"DSA",
        c"provider=default,fips=yes,output=pem,structure=dsa",
        &DSA_TO_DSA_PEM,
    ),
    encoder(
        c"EC",
        c"provider=default,fips=yes,output=der,structure=ec",
        &EC_TO_EC_DER,
    ),
    encoder(
        c"EC",
        c"provider=default,fips=yes,output=pem,structure=ec",
        &EC_TO_EC_PEM,
    ),
    encoder(
        c"RSA",
        c"provider=default,fips=yes,output=der,structure=pkcs1",
        &RSA_TO_PKCS1_DER,
    ),
    encoder(
        c"RSA",
        c"provider=default,fips=yes,output=pem,structure=pkcs1",
        &RSA_TO_PKCS1_PEM,
    ),
    encoder(
        c"RSA-PSS",
        c"provider=default,fips=yes,output=der,structure=pkcs1",
        &RSAPSS_TO_PKCS1_DER,
    ),
    encoder(
        c"RSA-PSS",
        c"provider=default,fips=yes,output=pem,structure=pkcs1",
        &RSAPSS_TO_PKCS1_PEM,
    ),
    encoder(
        c"DH",
        c"provider=default,fips=yes,output=der,structure=pkcs3",
        &DH_TO_PKCS3_DER,
    ),
    encoder(
        c"DH",
        c"provider=default,fips=yes,output=pem,structure=pkcs3",
        &DH_TO_PKCS3_PEM,
    ),
    encoder(
        c"DHX",
        c"provider=default,fips=yes,output=der,structure=X9.42",
        &DHX_TO_X9_42_DER,
    ),
    encoder(
        c"DHX",
        c"provider=default,fips=yes,output=pem,structure=X9.42",
        &DHX_TO_X9_42_PEM,
    ),
    encoder(
        c"EC",
        c"provider=default,fips=yes,output=der,structure=X9.62",
        &EC_TO_X9_62_DER,
    ),
    encoder(
        c"EC",
        c"provider=default,fips=yes,output=pem,structure=X9.62",
        &EC_TO_X9_62_PEM,
    ),
    ALG_END,
]);

static BASE_ENCODERS: Algorithms<242> = Algorithms([
    encoder(c"RSA", c"provider=base,fips=yes,output=text", &RSA_TO_TEXT),
    encoder(
        c"RSA-PSS",
        c"provider=base,fips=yes,output=text",
        &RSAPSS_TO_TEXT,
    ),
    encoder(c"DH", c"provider=base,fips=yes,output=text", &DH_TO_TEXT),
    encoder(c"DHX", c"provider=base,fips=yes,output=text", &DHX_TO_TEXT),
    encoder(c"DSA", c"provider=base,fips=yes,output=text", &DSA_TO_TEXT),
    encoder(c"EC", c"provider=base,fips=yes,output=text", &EC_TO_TEXT),
    encoder(
        c"ED25519",
        c"provider=base,fips=yes,output=text",
        &ED25519_TO_TEXT,
    ),
    encoder(
        c"ED448",
        c"provider=base,fips=yes,output=text",
        &ED448_TO_TEXT,
    ),
    encoder(
        c"X25519",
        c"provider=base,fips=yes,output=text",
        &X25519_TO_TEXT,
    ),
    encoder(
        c"X448",
        c"provider=base,fips=yes,output=text",
        &X448_TO_TEXT,
    ),
    encoder(c"SM2", c"provider=base,fips=no,output=text", &SM2_TO_TEXT),
    encoder(
        c"ML-KEM-512",
        c"provider=base,fips=yes,output=text",
        &ML_KEM_512_TO_TEXT,
    ),
    encoder(
        c"ML-KEM-768",
        c"provider=base,fips=yes,output=text",
        &ML_KEM_768_TO_TEXT,
    ),
    encoder(
        c"ML-KEM-1024",
        c"provider=base,fips=yes,output=text",
        &ML_KEM_1024_TO_TEXT,
    ),
    encoder(
        c"ML-DSA-44",
        c"provider=base,fips=yes,output=text",
        &ML_DSA_44_TO_TEXT,
    ),
    encoder(
        c"ML-DSA-65",
        c"provider=base,fips=yes,output=text",
        &ML_DSA_65_TO_TEXT,
    ),
    encoder(
        c"ML-DSA-87",
        c"provider=base,fips=yes,output=text",
        &ML_DSA_87_TO_TEXT,
    ),
    encoder(
        c"SLH-DSA-SHA2-128s",
        c"provider=base,fips=yes,output=text",
        &SLH_DSA_SHA2_128S_TO_TEXT,
    ),
    encoder(
        c"SLH-DSA-SHA2-128f",
        c"provider=base,fips=yes,output=text",
        &SLH_DSA_SHA2_128F_TO_TEXT,
    ),
    encoder(
        c"SLH-DSA-SHA2-192s",
        c"provider=base,fips=yes,output=text",
        &SLH_DSA_SHA2_192S_TO_TEXT,
    ),
    encoder(
        c"SLH-DSA-SHA2-192f",
        c"provider=base,fips=yes,output=text",
        &SLH_DSA_SHA2_192F_TO_TEXT,
    ),
    encoder(
        c"SLH-DSA-SHA2-256s",
        c"provider=base,fips=yes,output=text",
        &SLH_DSA_SHA2_256S_TO_TEXT,
    ),
    encoder(
        c"SLH-DSA-SHA2-256f",
        c"provider=base,fips=yes,output=text",
        &SLH_DSA_SHA2_256F_TO_TEXT,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128s",
        c"provider=base,fips=yes,output=text",
        &SLH_DSA_SHAKE_128S_TO_TEXT,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128f",
        c"provider=base,fips=yes,output=text",
        &SLH_DSA_SHAKE_128F_TO_TEXT,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192s",
        c"provider=base,fips=yes,output=text",
        &SLH_DSA_SHAKE_192S_TO_TEXT,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192f",
        c"provider=base,fips=yes,output=text",
        &SLH_DSA_SHAKE_192F_TO_TEXT,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256s",
        c"provider=base,fips=yes,output=text",
        &SLH_DSA_SHAKE_256S_TO_TEXT,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256f",
        c"provider=base,fips=yes,output=text",
        &SLH_DSA_SHAKE_256F_TO_TEXT,
    ),
    encoder(
        c"RSA",
        c"provider=base,fips=yes,output=der,structure=type-specific",
        &RSA_TO_TYPE_SPECIFIC_KEYPAIR_DER,
    ),
    encoder(
        c"RSA",
        c"provider=base,fips=yes,output=pem,structure=type-specific",
        &RSA_TO_TYPE_SPECIFIC_KEYPAIR_PEM,
    ),
    encoder(
        c"DH",
        c"provider=base,fips=yes,output=der,structure=type-specific",
        &DH_TO_TYPE_SPECIFIC_PARAMS_DER,
    ),
    encoder(
        c"DH",
        c"provider=base,fips=yes,output=pem,structure=type-specific",
        &DH_TO_TYPE_SPECIFIC_PARAMS_PEM,
    ),
    encoder(
        c"DHX",
        c"provider=base,fips=yes,output=der,structure=type-specific",
        &DHX_TO_TYPE_SPECIFIC_PARAMS_DER,
    ),
    encoder(
        c"DHX",
        c"provider=base,fips=yes,output=pem,structure=type-specific",
        &DHX_TO_TYPE_SPECIFIC_PARAMS_PEM,
    ),
    encoder(
        c"DSA",
        c"provider=base,fips=yes,output=der,structure=type-specific",
        &DSA_TO_TYPE_SPECIFIC_DER,
    ),
    encoder(
        c"DSA",
        c"provider=base,fips=yes,output=pem,structure=type-specific",
        &DSA_TO_TYPE_SPECIFIC_PEM,
    ),
    encoder(
        c"EC",
        c"provider=base,fips=yes,output=der,structure=type-specific",
        &EC_TO_TYPE_SPECIFIC_NO_PUB_DER,
    ),
    encoder(
        c"EC",
        c"provider=base,fips=yes,output=pem,structure=type-specific",
        &EC_TO_TYPE_SPECIFIC_NO_PUB_PEM,
    ),
    encoder(c"EC", c"provider=base,fips=yes,output=blob", &EC_TO_BLOB),
    encoder(
        c"SM2",
        c"provider=base,fips=no,output=der,structure=type-specific",
        &SM2_TO_TYPE_SPECIFIC_NO_PUB_DER,
    ),
    encoder(
        c"SM2",
        c"provider=base,fips=no,output=pem,structure=type-specific",
        &SM2_TO_TYPE_SPECIFIC_NO_PUB_PEM,
    ),
    encoder(c"SM2", c"provider=base,fips=no,output=blob", &SM2_TO_BLOB),
    encoder(
        c"RSA",
        c"provider=base,fips=yes,output=msblob",
        &RSA_TO_MSBLOB,
    ),
    encoder(c"RSA", c"provider=base,fips=yes,output=pvk", &RSA_TO_PVK),
    encoder(
        c"DSA",
        c"provider=base,fips=yes,output=msblob",
        &DSA_TO_MSBLOB,
    ),
    encoder(c"DSA", c"provider=base,fips=yes,output=pvk", &DSA_TO_PVK),
    encoder(
        c"RSA",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &RSA_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"RSA",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &RSA_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"RSA",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &RSA_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"RSA",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &RSA_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"RSA",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &RSA_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"RSA",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &RSA_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"RSA-PSS",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &RSAPSS_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"RSA-PSS",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &RSAPSS_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"RSA-PSS",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &RSAPSS_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"RSA-PSS",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &RSAPSS_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"RSA-PSS",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &RSAPSS_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"RSA-PSS",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &RSAPSS_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"DH",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &DH_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"DH",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &DH_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"DH",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &DH_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"DH",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &DH_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"DH",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &DH_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"DH",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &DH_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"DHX",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &DHX_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"DHX",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &DHX_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"DHX",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &DHX_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"DHX",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &DHX_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"DHX",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &DHX_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"DHX",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &DHX_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"DSA",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &DSA_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"DSA",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &DSA_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"DSA",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &DSA_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"DSA",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &DSA_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"DSA",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &DSA_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"DSA",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &DSA_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"EC",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &EC_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"EC",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &EC_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"EC",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &EC_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"EC",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &EC_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"EC",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &EC_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"EC",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &EC_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"SM2",
        c"provider=base,fips=no,output=der,structure=EncryptedPrivateKeyInfo",
        &SM2_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SM2",
        c"provider=base,fips=no,output=pem,structure=EncryptedPrivateKeyInfo",
        &SM2_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SM2",
        c"provider=base,fips=no,output=der,structure=PrivateKeyInfo",
        &SM2_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SM2",
        c"provider=base,fips=no,output=pem,structure=PrivateKeyInfo",
        &SM2_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SM2",
        c"provider=base,fips=no,output=der,structure=SubjectPublicKeyInfo",
        &SM2_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"SM2",
        c"provider=base,fips=no,output=pem,structure=SubjectPublicKeyInfo",
        &SM2_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"X25519",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &X25519_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"X25519",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &X25519_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"X25519",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &X25519_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"X25519",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &X25519_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"X25519",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &X25519_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"X25519",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &X25519_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"X448",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &X448_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"X448",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &X448_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"X448",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &X448_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"X448",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &X448_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"X448",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &X448_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"X448",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &X448_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"ED25519",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &ED25519_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ED25519",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &ED25519_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ED25519",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &ED25519_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ED25519",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &ED25519_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ED25519",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &ED25519_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"ED25519",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &ED25519_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"ED448",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &ED448_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ED448",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &ED448_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ED448",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &ED448_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ED448",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &ED448_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ED448",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &ED448_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"ED448",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &ED448_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-128s",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHA2_128S_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-128f",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHA2_128F_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-192s",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHA2_192S_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-192f",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHA2_192F_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-256s",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHA2_256S_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-256f",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHA2_256F_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128s",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHAKE_128S_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128f",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHAKE_128F_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192s",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHAKE_192S_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192f",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHAKE_192F_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256s",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHAKE_256S_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256f",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHAKE_256F_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-128s",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHA2_128S_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-128f",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHA2_128F_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-192s",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHA2_192S_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-192f",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHA2_192F_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-256s",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHA2_256S_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-256f",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHA2_256F_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128s",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHAKE_128S_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128f",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHAKE_128F_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192s",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHAKE_192S_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192f",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHAKE_192F_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256s",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHAKE_256S_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256f",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &SLH_DSA_SHAKE_256F_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-128s",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &SLH_DSA_SHA2_128S_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-128f",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &SLH_DSA_SHA2_128F_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-192s",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &SLH_DSA_SHA2_192S_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-192f",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &SLH_DSA_SHA2_192F_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-256s",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &SLH_DSA_SHA2_256S_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-256f",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &SLH_DSA_SHA2_256F_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128s",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &SLH_DSA_SHAKE_128S_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128f",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &SLH_DSA_SHAKE_128F_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192s",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &SLH_DSA_SHAKE_192S_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192f",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &SLH_DSA_SHAKE_192F_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256s",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &SLH_DSA_SHAKE_256S_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256f",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &SLH_DSA_SHAKE_256F_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-128s",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &SLH_DSA_SHA2_128S_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-128f",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &SLH_DSA_SHA2_128F_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-192s",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &SLH_DSA_SHA2_192S_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-192f",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &SLH_DSA_SHA2_192F_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-256s",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &SLH_DSA_SHA2_256S_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-256f",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &SLH_DSA_SHA2_256F_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128s",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &SLH_DSA_SHAKE_128S_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128f",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &SLH_DSA_SHAKE_128F_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192s",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &SLH_DSA_SHAKE_192S_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192f",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &SLH_DSA_SHAKE_192F_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256s",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &SLH_DSA_SHAKE_256S_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256f",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &SLH_DSA_SHAKE_256F_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-128s",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHA2_128S_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-128f",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHA2_128F_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-192s",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHA2_192S_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-192f",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHA2_192F_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-256s",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHA2_256S_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-256f",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHA2_256F_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128s",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHAKE_128S_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128f",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHAKE_128F_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192s",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHAKE_192S_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192f",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHAKE_192F_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256s",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHAKE_256S_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256f",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHAKE_256F_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"SLH-DSA-SHA2-128s",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHA2_128S_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-128f",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHA2_128F_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-192s",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHA2_192S_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-192f",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHA2_192F_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-256s",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHA2_256S_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHA2-256f",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHA2_256F_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128s",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHAKE_128S_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-128f",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHAKE_128F_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192s",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHAKE_192S_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-192f",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHAKE_192F_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256s",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHAKE_256S_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"SLH-DSA-SHAKE-256f",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &SLH_DSA_SHAKE_256F_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"ML-KEM-512",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &ML_KEM_512_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ML-KEM-512",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &ML_KEM_512_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ML-KEM-512",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &ML_KEM_512_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ML-KEM-512",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &ML_KEM_512_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ML-KEM-512",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &ML_KEM_512_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"ML-KEM-512",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &ML_KEM_512_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"ML-KEM-768",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &ML_KEM_768_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ML-KEM-768",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &ML_KEM_768_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ML-KEM-768",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &ML_KEM_768_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ML-KEM-768",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &ML_KEM_768_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ML-KEM-768",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &ML_KEM_768_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"ML-KEM-768",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &ML_KEM_768_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"ML-KEM-1024",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &ML_KEM_1024_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ML-KEM-1024",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &ML_KEM_1024_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ML-KEM-1024",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &ML_KEM_1024_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ML-KEM-1024",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &ML_KEM_1024_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ML-KEM-1024",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &ML_KEM_1024_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"ML-KEM-1024",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &ML_KEM_1024_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"ML-DSA-44",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &ML_DSA_44_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ML-DSA-44",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &ML_DSA_44_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ML-DSA-44",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &ML_DSA_44_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ML-DSA-44",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &ML_DSA_44_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ML-DSA-44",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &ML_DSA_44_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"ML-DSA-44",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &ML_DSA_44_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"ML-DSA-65",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &ML_DSA_65_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ML-DSA-65",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &ML_DSA_65_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ML-DSA-65",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &ML_DSA_65_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ML-DSA-65",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &ML_DSA_65_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ML-DSA-65",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &ML_DSA_65_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"ML-DSA-65",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &ML_DSA_65_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"ML-DSA-87",
        c"provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo",
        &ML_DSA_87_TO_ENCRYPTEDPRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ML-DSA-87",
        c"provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo",
        &ML_DSA_87_TO_ENCRYPTEDPRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ML-DSA-87",
        c"provider=base,fips=yes,output=der,structure=PrivateKeyInfo",
        &ML_DSA_87_TO_PRIVATEKEYINFO_DER,
    ),
    encoder(
        c"ML-DSA-87",
        c"provider=base,fips=yes,output=pem,structure=PrivateKeyInfo",
        &ML_DSA_87_TO_PRIVATEKEYINFO_PEM,
    ),
    encoder(
        c"ML-DSA-87",
        c"provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo",
        &ML_DSA_87_TO_SUBJECTPUBLICKEYINFO_DER,
    ),
    encoder(
        c"ML-DSA-87",
        c"provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo",
        &ML_DSA_87_TO_SUBJECTPUBLICKEYINFO_PEM,
    ),
    encoder(
        c"RSA",
        c"provider=base,fips=yes,output=der,structure=rsa",
        &RSA_TO_RSA_DER,
    ),
    encoder(
        c"RSA",
        c"provider=base,fips=yes,output=pem,structure=rsa",
        &RSA_TO_RSA_PEM,
    ),
    encoder(
        c"DH",
        c"provider=base,fips=yes,output=der,structure=dh",
        &DH_TO_DH_DER,
    ),
    encoder(
        c"DH",
        c"provider=base,fips=yes,output=pem,structure=dh",
        &DH_TO_DH_PEM,
    ),
    encoder(
        c"DHX",
        c"provider=base,fips=yes,output=der,structure=dhx",
        &DHX_TO_DHX_DER,
    ),
    encoder(
        c"DHX",
        c"provider=base,fips=yes,output=pem,structure=dhx",
        &DHX_TO_DHX_PEM,
    ),
    encoder(
        c"DSA",
        c"provider=base,fips=yes,output=der,structure=dsa",
        &DSA_TO_DSA_DER,
    ),
    encoder(
        c"DSA",
        c"provider=base,fips=yes,output=pem,structure=dsa",
        &DSA_TO_DSA_PEM,
    ),
    encoder(
        c"EC",
        c"provider=base,fips=yes,output=der,structure=ec",
        &EC_TO_EC_DER,
    ),
    encoder(
        c"EC",
        c"provider=base,fips=yes,output=pem,structure=ec",
        &EC_TO_EC_PEM,
    ),
    encoder(
        c"RSA",
        c"provider=base,fips=yes,output=der,structure=pkcs1",
        &RSA_TO_PKCS1_DER,
    ),
    encoder(
        c"RSA",
        c"provider=base,fips=yes,output=pem,structure=pkcs1",
        &RSA_TO_PKCS1_PEM,
    ),
    encoder(
        c"RSA-PSS",
        c"provider=base,fips=yes,output=der,structure=pkcs1",
        &RSAPSS_TO_PKCS1_DER,
    ),
    encoder(
        c"RSA-PSS",
        c"provider=base,fips=yes,output=pem,structure=pkcs1",
        &RSAPSS_TO_PKCS1_PEM,
    ),
    encoder(
        c"DH",
        c"provider=base,fips=yes,output=der,structure=pkcs3",
        &DH_TO_PKCS3_DER,
    ),
    encoder(
        c"DH",
        c"provider=base,fips=yes,output=pem,structure=pkcs3",
        &DH_TO_PKCS3_PEM,
    ),
    encoder(
        c"DHX",
        c"provider=base,fips=yes,output=der,structure=X9.42",
        &DHX_TO_X9_42_DER,
    ),
    encoder(
        c"DHX",
        c"provider=base,fips=yes,output=pem,structure=X9.42",
        &DHX_TO_X9_42_PEM,
    ),
    encoder(
        c"EC",
        c"provider=base,fips=yes,output=der,structure=X9.62",
        &EC_TO_X9_62_DER,
    ),
    encoder(
        c"EC",
        c"provider=base,fips=yes,output=pem,structure=X9.62",
        &EC_TO_X9_62_PEM,
    ),
    ALG_END,
]);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selections_are_the_first_part_asked_for() {
        let (private, public, params) = (
            OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
            OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
            OSSL_KEYMGMT_SELECT_ALL_PARAMETERS,
        );
        assert_eq!(check_selection(0, Kind::Params.mask()), 1);
        assert_eq!(
            check_selection(private | public, Kind::SubjectPublicKeyInfo.mask()),
            0
        );
        assert_eq!(
            check_selection(public | params, Kind::SubjectPublicKeyInfo.mask()),
            1
        );
        assert_eq!(check_selection(params, Kind::NoPub.mask()), 1);
        assert_eq!(check_selection(public, Kind::NoPub.mask()), 0);
        assert_eq!(check_selection(0x100, Kind::All.mask()), 0);
        assert_eq!(check_selection(public, EVP_PKEY_PUBLIC_KEY), 1);
    }

    #[test]
    fn give_is_an_i2d() {
        let bytes = [1u8, 2, 3];
        // SAFETY: no output.
        assert_eq!(unsafe { give(&bytes, ptr::null_mut()) }, 3);
        let mut fresh: *mut c_uchar = ptr::null_mut();
        // SAFETY: a new buffer into `fresh`.
        assert_eq!(unsafe { give(&bytes, &raw mut fresh) }, 3);
        // SAFETY: the new buffer's three octets.
        assert_eq!(unsafe { core::slice::from_raw_parts(fresh, 3) }, &bytes);
        // SAFETY: made above.
        unsafe { mem::release(fresh.cast()) };
        let mut buf = [0u8; 4];
        let mut at = buf.as_mut_ptr();
        // SAFETY: room for the octets.
        assert_eq!(unsafe { give(&bytes, &raw mut at) }, 3);
        assert_eq!(at.wrapping_sub(3), buf.as_mut_ptr());
        assert_eq!(buf, [1, 2, 3, 0]);
    }

    #[test]
    fn the_tables_are_encoders_incs() {
        for table in [&DEFAULT_ENCODERS.0[..], &BASE_ENCODERS.0[..]] {
            assert_eq!(table.len(), 242);
            assert!(table.last().is_some_and(|a| a.algorithm_names.is_null()));
            for a in table.iter().take(241) {
                // SAFETY: the table's static strings.
                let props = unsafe { CStr::from_ptr(a.property_definition) }
                    .to_str()
                    .unwrap_or("");
                assert!(props.contains(",output="), "{props}");
            }
        }
    }
}
