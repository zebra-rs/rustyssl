//! ASN.1 methods (`EVP_PKEY_ASN1_METHOD(3)`, `EVP_PKEY_asn1_new(3)`, `EVP_PKEY_asn1_get_count(3)`;
//! `ameth_lib.c`): the built-in methods of `crypto/asn1/standard_methods.h` (each key type, the
//! type an alias stands for, its flags, PEM name, and description, in the table's order) and the
//! methods an application adds. `EVP_PKEY_type`, the lookup by PEM name, and
//! `evp_pkey_name2type` work from them, and a key typed by a method (`EVP_PKEY_assign`,
//! `EVP_PKEY_set_type`) reaches the method's functions for its legacy data.
//!
//! As in OpenSSL:
//! - An application's method for a key type takes the place of the built-in one, and the
//!   methods are counted and indexed built-ins first, then the application's sorted by key type.
//! - Adding a second method for a key type fails, as does an alias with a PEM name or a method
//!   with neither; `EVP_PKEY_asn1_free` frees only methods `EVP_PKEY_asn1_new` made, and
//!   `EVP_PKEY_asn1_copy` copies the functions and keeps the rest.
//!
//! The built-in methods' functions work on the key types' legacy data, which comes with the key
//! types (4.3 onwards): until then they abort when called (AGENTS.md rule 10), as a key typed
//! without data reaches them only where OpenSSL would use data it doesn't have. Changing a
//! built-in method, which OpenSSL can't do (they're read-only), does nothing here, and NULL
//! methods are refused where it would crash (docs/DEVIATIONS.md).

use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use core::ptr;
use std::ffi::CString;
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    ASN1_BIT_STRING, ASN1_ITEM, ASN1_PCTX, ASN1_PKEY_ALIAS, ASN1_PKEY_DYNAMIC,
    ASN1_PKEY_SIGPARAM_NULL, ASN1_STRING, BIO, ENGINE, ERR_LIB_EVP, ERR_R_PASSED_INVALID_ARGUMENT,
    EVP_MD_CTX, EVP_PKEY, EVP_PKEY_ASN1_METHOD, EVP_PKEY_DH, EVP_PKEY_DHX, EVP_PKEY_DSA,
    EVP_PKEY_DSA1, EVP_PKEY_DSA2, EVP_PKEY_DSA3, EVP_PKEY_DSA4, EVP_PKEY_EC, EVP_PKEY_ED448,
    EVP_PKEY_ED25519, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS, EVP_PKEY_RSA2, EVP_PKEY_SM2, EVP_PKEY_X448,
    EVP_PKEY_X25519, EVP_R_PKEY_APPLICATION_ASN1_METHOD_ALREADY_REGISTERED, NID_undef,
    OSSL_LIB_CTX, OSSL_PARAM, PKCS8_PRIV_KEY_INFO, X509_ALGOR, X509_PUBKEY, X509_SIG_INFO,
};

use crate::err;
use crate::evp::opmeth;
use crate::ffi::{ffi_callback, ffi_export};
use crate::handle::{Handle, handle_type};
use crate::objects::{OBJ_ln2nid, OBJ_sn2nid};

pub(crate) type PubDecode = unsafe extern "C" fn(*mut EVP_PKEY, *const X509_PUBKEY) -> c_int;
pub(crate) type PubEncode = unsafe extern "C" fn(*mut X509_PUBKEY, *const EVP_PKEY) -> c_int;
/// `pub_cmp` and `param_cmp`.
pub(crate) type Cmp = unsafe extern "C" fn(*const EVP_PKEY, *const EVP_PKEY) -> c_int;
/// The print functions.
pub(crate) type Print =
    unsafe extern "C" fn(*mut BIO, *const EVP_PKEY, c_int, *mut ASN1_PCTX) -> c_int;
pub(crate) type PrivDecode =
    unsafe extern "C" fn(*mut EVP_PKEY, *const PKCS8_PRIV_KEY_INFO) -> c_int;
pub(crate) type PrivEncode =
    unsafe extern "C" fn(*mut PKCS8_PRIV_KEY_INFO, *const EVP_PKEY) -> c_int;
/// The functions of a key alone (sizes, checks, `param_missing`).
pub(crate) type KeyFn = unsafe extern "C" fn(*const EVP_PKEY) -> c_int;
pub(crate) type ParamDecode =
    unsafe extern "C" fn(*mut EVP_PKEY, *mut *const c_uchar, c_int) -> c_int;
pub(crate) type ParamEncode = unsafe extern "C" fn(*const EVP_PKEY, *mut *mut c_uchar) -> c_int;
pub(crate) type ParamCopy = unsafe extern "C" fn(*mut EVP_PKEY, *const EVP_PKEY) -> c_int;
pub(crate) type Free = unsafe extern "C" fn(*mut EVP_PKEY);
pub(crate) type Ctrl = unsafe extern "C" fn(*mut EVP_PKEY, c_int, c_long, *mut c_void) -> c_int;
pub(crate) type ItemVerify = unsafe extern "C" fn(
    *mut EVP_MD_CTX,
    *const ASN1_ITEM,
    *const c_void,
    *const X509_ALGOR,
    *const ASN1_BIT_STRING,
    *mut EVP_PKEY,
) -> c_int;
pub(crate) type ItemSign = unsafe extern "C" fn(
    *mut EVP_MD_CTX,
    *const ASN1_ITEM,
    *const c_void,
    *mut X509_ALGOR,
    *mut X509_ALGOR,
    *mut ASN1_BIT_STRING,
) -> c_int;
pub(crate) type SiginfSet =
    unsafe extern "C" fn(*mut X509_SIG_INFO, *const X509_ALGOR, *const ASN1_STRING) -> c_int;
pub(crate) type SetRaw = unsafe extern "C" fn(*mut EVP_PKEY, *const c_uchar, usize) -> c_int;
pub(crate) type GetRaw = unsafe extern "C" fn(*const EVP_PKEY, *mut c_uchar, *mut usize) -> c_int;
/// The built-in methods' `copy` (`EVP_PKEY_dup`), which applications can't set.
pub(crate) type Copy = unsafe extern "C" fn(*mut EVP_PKEY, *mut EVP_PKEY) -> c_int;
/// The built-in methods' `old_priv_decode` (the traditional private key formats, `RSA PRIVATE
/// KEY` ...), which applications can't set.
pub(crate) type OldPrivDecode =
    unsafe extern "C" fn(*mut EVP_PKEY, *mut *const c_uchar, c_int) -> c_int;

/// `dirty_cnt`: the legacy data's change count.
pub(crate) type DirtyCnt = unsafe fn(*const EVP_PKEY) -> usize;
/// `export_to`: the legacy data's parameters given to `importer(selection, params)`.
pub(crate) type ExportTo =
    unsafe fn(*const EVP_PKEY, &mut dyn FnMut(c_int, *const OSSL_PARAM) -> c_int) -> c_int;
/// `import_from`: legacy data made from `params` (in a library context) and assigned to the key.
pub(crate) type ImportFrom =
    unsafe fn(*const OSSL_PARAM, *mut EVP_PKEY, *mut OSSL_LIB_CTX) -> c_int;

/// A method's functions (those of `struct evp_pkey_asn1_method_st` the API reaches).
#[derive(Clone, core::marker::Copy, Default)]
pub(crate) struct Funcs {
    pub(crate) pub_decode: Option<PubDecode>,
    pub(crate) pub_encode: Option<PubEncode>,
    pub(crate) pub_cmp: Option<Cmp>,
    pub(crate) pub_print: Option<Print>,
    pub(crate) priv_decode: Option<PrivDecode>,
    pub(crate) priv_encode: Option<PrivEncode>,
    pub(crate) priv_print: Option<Print>,
    pub(crate) pkey_size: Option<KeyFn>,
    pub(crate) pkey_bits: Option<KeyFn>,
    pub(crate) pkey_security_bits: Option<KeyFn>,
    pub(crate) param_decode: Option<ParamDecode>,
    pub(crate) param_encode: Option<ParamEncode>,
    pub(crate) param_missing: Option<KeyFn>,
    pub(crate) param_copy: Option<ParamCopy>,
    pub(crate) param_cmp: Option<Cmp>,
    pub(crate) param_print: Option<Print>,
    pub(crate) pkey_free: Option<Free>,
    pub(crate) pkey_ctrl: Option<Ctrl>,
    pub(crate) item_verify: Option<ItemVerify>,
    pub(crate) item_sign: Option<ItemSign>,
    pub(crate) siginf_set: Option<SiginfSet>,
    pub(crate) pkey_check: Option<KeyFn>,
    pub(crate) pkey_public_check: Option<KeyFn>,
    pub(crate) pkey_param_check: Option<KeyFn>,
    pub(crate) set_priv_key: Option<SetRaw>,
    pub(crate) set_pub_key: Option<SetRaw>,
    pub(crate) get_priv_key: Option<GetRaw>,
    pub(crate) get_pub_key: Option<GetRaw>,
    pub(crate) copy: Option<Copy>,
    pub(crate) old_priv_decode: Option<OldPrivDecode>,
    /// The built-in methods' bridge to the providers (applications' methods have none).
    pub(crate) dirty_cnt: Option<DirtyCnt>,
    pub(crate) export_to: Option<ExportTo>,
    pub(crate) import_from: Option<ImportFrom>,
}

/// What `EVP_PKEY_ASN1_METHOD` handles point to.
pub(crate) struct Ameth {
    pub(crate) pkey_id: c_int,
    pub(crate) base_id: c_int,
    pub(crate) flags: c_ulong,
    /// The PEM name (NULL for an alias).
    pub(crate) pem_str: Option<CString>,
    /// The description.
    pub(crate) info: Option<CString>,
    funcs: Mutex<Funcs>,
}

handle_type!(EVP_PKEY_ASN1_METHOD => Ameth);

/// A reference to a method.
pub(crate) type Ref = opmeth::Ref<EVP_PKEY_ASN1_METHOD>;

impl Ameth {
    /// The functions, as they are now (a copy: none is called with the lock held).
    pub(crate) fn funcs(&self) -> Funcs {
        *self.lock()
    }

    fn lock(&self) -> MutexGuard<'_, Funcs> {
        self.funcs.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether it's an alias for another type.
    pub(crate) fn is_alias(&self) -> bool {
        self.flags & ASN1_PKEY_ALIAS.cast_unsigned() as c_ulong != 0
    }

    /// Whether `EVP_PKEY_asn1_new` made it (`ASN1_PKEY_DYNAMIC`).
    pub(crate) fn is_dynamic(&self) -> bool {
        self.flags & ASN1_PKEY_DYNAMIC.cast_unsigned() as c_ulong != 0
    }
}

/// The method behind `ameth`, or `None` for NULL.
///
/// # Safety
/// `ameth` is NULL or a live method.
unsafe fn method<'a>(ameth: *const EVP_PKEY_ASN1_METHOD) -> Option<&'a Ameth> {
    // SAFETY: the caller's guarantee.
    unsafe { EVP_PKEY_ASN1_METHOD::get(ameth) }
}

/// Changes an application's method's functions with `f`; a built-in method stays as it is.
///
/// # Safety
/// `ameth` is NULL or a live method.
unsafe fn update(ameth: *mut EVP_PKEY_ASN1_METHOD, f: impl FnOnce(&mut Funcs)) {
    // SAFETY: the caller's guarantee.
    if let Some(m) = unsafe { method(ameth) }
        && m.is_dynamic()
    {
        f(&mut m.lock());
    }
}

// The built-in methods' functions, which need the key types' legacy data (4.3 onwards).

extern "C" fn builtin_cmp(_: *const EVP_PKEY, _: *const EVP_PKEY) -> c_int {
    crate::stub::unimplemented("comparing keys through a built-in ASN.1 method")
}

extern "C" fn builtin_key(_: *const EVP_PKEY) -> c_int {
    crate::stub::unimplemented("a built-in ASN.1 method's function of a key")
}

extern "C" fn builtin_param_copy(_: *mut EVP_PKEY, _: *const EVP_PKEY) -> c_int {
    crate::stub::unimplemented("copying parameters through a built-in ASN.1 method")
}

extern "C" fn builtin_ctrl(_: *mut EVP_PKEY, _: c_int, _: c_long, _: *mut c_void) -> c_int {
    crate::stub::unimplemented("a built-in ASN.1 method's ctrl")
}

extern "C" fn builtin_get_raw(_: *const EVP_PKEY, _: *mut c_uchar, _: *mut usize) -> c_int {
    crate::stub::unimplemented("a raw key through a built-in ASN.1 method")
}

extern "C" fn builtin_copy(_: *mut EVP_PKEY, _: *mut EVP_PKEY) -> c_int {
    crate::stub::unimplemented("copying a key through a built-in ASN.1 method")
}

extern "C" fn builtin_old_priv_decode(_: *mut EVP_PKEY, _: *mut *const c_uchar, _: c_int) -> c_int {
    crate::stub::unimplemented("decoding a traditional private key through a built-in ASN.1 method")
}

extern "C" fn builtin_print(_: *mut BIO, _: *const EVP_PKEY, _: c_int, _: *mut ASN1_PCTX) -> c_int {
    crate::stub::unimplemented("printing a key through a built-in ASN.1 method")
}

extern "C" fn builtin_param_decode(_: *mut EVP_PKEY, _: *mut *const c_uchar, _: c_int) -> c_int {
    crate::stub::unimplemented("decoding parameters through a built-in ASN.1 method")
}

ffi_callback! {
    /// The built-in methods' `pkey_free`: there's nothing to free for a key typed without data
    /// (data needs the key types, 4.3 onwards).
    pub(crate) unsafe extern "C" fn builtin_free(pkey: *mut EVP_PKEY)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's live key.
        if !unsafe { super::EVP_PKEY_get0(pkey) }.is_null() {
            crate::stub::unimplemented("freeing a key's data through a built-in ASN.1 method");
        }
    }
}

/// Which functions a built-in method has.
#[derive(Clone, core::marker::Copy)]
enum Kind {
    Rsa,
    RsaPss,
    /// DH and DHX.
    Dh,
    /// DSA and EC.
    DsaEc,
    Ecx,
    Alias,
}

impl Kind {
    fn funcs(self) -> Funcs {
        if matches!(self, Self::Alias) {
            return Funcs::default();
        }
        let mut f = Funcs {
            pub_cmp: Some(builtin_cmp),
            pkey_size: Some(builtin_key),
            pkey_bits: Some(builtin_key),
            pkey_security_bits: Some(builtin_key),
            pkey_free: Some(builtin_free),
            pkey_ctrl: Some(builtin_ctrl),
            copy: Some(builtin_copy),
            pub_print: Some(builtin_print),
            priv_print: Some(builtin_print),
            ..Funcs::default()
        };
        match self {
            Self::Dh | Self::DsaEc => {
                f.param_decode = Some(builtin_param_decode);
                f.param_print = Some(builtin_print);
                f.param_missing = Some(builtin_key);
                f.param_copy = Some(builtin_param_copy);
                f.param_cmp = Some(builtin_cmp);
            }
            Self::Ecx => {
                f.param_cmp = Some(builtin_cmp);
                f.get_priv_key = Some(builtin_get_raw);
                f.get_pub_key = Some(builtin_get_raw);
            }
            Self::Rsa | Self::RsaPss => {
                use super::rsa as r;
                f.pub_cmp = Some(r::rsa_pub_cmp);
                f.pkey_size = Some(r::int_rsa_size);
                f.pkey_bits = Some(r::rsa_bits);
                f.pkey_security_bits = Some(r::rsa_security_bits);
                f.pkey_free = Some(r::int_rsa_free);
                f.pub_print = Some(r::rsa_pub_print);
                f.priv_print = Some(r::rsa_priv_print);
                f.pkey_ctrl = Some(r::rsa_pkey_ctrl);
                f.pkey_check = Some(r::rsa_pkey_check);
                f.copy = Some(r::rsa_pkey_copy);
                f.dirty_cnt = Some(r::rsa_pkey_dirty_cnt);
                f.export_to = Some(r::rsa_pkey_export_to);
                f.import_from = Some(if matches!(self, Self::Rsa) {
                    r::rsa_pkey_import_from
                } else {
                    r::rsa_pss_pkey_import_from
                });
            }
            Self::Alias => {}
        }
        if matches!(self, Self::Rsa | Self::DsaEc) {
            f.old_priv_decode = Some(builtin_old_priv_decode);
        }
        f
    }
}

/// An entry of `standard_methods`.
struct Std {
    pkey_id: c_int,
    base_id: c_int,
    flags: c_int,
    pem_str: Option<&'static CStr>,
    info: Option<&'static CStr>,
    kind: Kind,
}

const fn entry(
    pkey_id: c_int,
    flags: c_int,
    pem_str: &'static CStr,
    info: &'static CStr,
    kind: Kind,
) -> Std {
    Std {
        pkey_id,
        base_id: pkey_id,
        flags,
        pem_str: Some(pem_str),
        info: Some(info),
        kind,
    }
}

const fn alias(pkey_id: c_int, base_id: c_int) -> Std {
    Std {
        pkey_id,
        base_id,
        flags: ASN1_PKEY_ALIAS,
        pem_str: None,
        info: None,
        kind: Kind::Alias,
    }
}

/// `standard_methods`, in OpenSSL's order (sorted by key type).
static STANDARD_TABLE: [Std; 15] = [
    entry(
        EVP_PKEY_RSA,
        ASN1_PKEY_SIGPARAM_NULL,
        c"RSA",
        c"OpenSSL RSA method",
        Kind::Rsa,
    ),
    alias(EVP_PKEY_RSA2, EVP_PKEY_RSA),
    entry(EVP_PKEY_DH, 0, c"DH", c"OpenSSL PKCS#3 DH method", Kind::Dh),
    alias(EVP_PKEY_DSA1, EVP_PKEY_DSA),
    alias(EVP_PKEY_DSA4, EVP_PKEY_DSA2),
    alias(EVP_PKEY_DSA3, EVP_PKEY_DSA2),
    entry(EVP_PKEY_DSA, 0, c"DSA", c"OpenSSL DSA method", Kind::DsaEc),
    entry(EVP_PKEY_EC, 0, c"EC", c"OpenSSL EC algorithm", Kind::DsaEc),
    entry(
        EVP_PKEY_RSA_PSS,
        ASN1_PKEY_SIGPARAM_NULL,
        c"RSA-PSS",
        c"OpenSSL RSA-PSS method",
        Kind::RsaPss,
    ),
    entry(
        EVP_PKEY_DHX,
        0,
        c"X9.42 DH",
        c"OpenSSL X9.42 DH method",
        Kind::Dh,
    ),
    entry(
        EVP_PKEY_X25519,
        0,
        c"X25519",
        c"OpenSSL X25519 algorithm",
        Kind::Ecx,
    ),
    entry(
        EVP_PKEY_X448,
        0,
        c"X448",
        c"OpenSSL X448 algorithm",
        Kind::Ecx,
    ),
    entry(
        EVP_PKEY_ED25519,
        0,
        c"ED25519",
        c"OpenSSL ED25519 algorithm",
        Kind::Ecx,
    ),
    entry(
        EVP_PKEY_ED448,
        0,
        c"ED448",
        c"OpenSSL ED448 algorithm",
        Kind::Ecx,
    ),
    alias(EVP_PKEY_SM2, EVP_PKEY_EC),
];

/// The built-in methods, made once and never freed.
static STANDARD: LazyLock<Vec<Ref>> = LazyLock::new(|| {
    STANDARD_TABLE
        .iter()
        .filter_map(|s| {
            let h = EVP_PKEY_ASN1_METHOD::new_handle(Ameth {
                pkey_id: s.pkey_id,
                base_id: s.base_id,
                flags: s.flags.cast_unsigned() as c_ulong,
                pem_str: s.pem_str.map(CStr::to_owned),
                info: s.info.map(CStr::to_owned),
                funcs: Mutex::new(s.kind.funcs()),
            });
            // SAFETY: the new handle's reference, kept for good.
            unsafe { Ref::adopt(h) }
        })
        .collect()
});

/// `app_methods`: the application's methods, sorted by key type.
static APP: Mutex<Vec<Ref>> = Mutex::new(Vec::new());

fn app() -> MutexGuard<'static, Vec<Ref>> {
    APP.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `EVP_PKEY_asn1_get_count`.
fn count() -> usize {
    STANDARD.len() + app().len()
}

/// `EVP_PKEY_asn1_get0`.
fn get0(idx: usize) -> Option<Ref> {
    match STANDARD.get(idx) {
        Some(m) => Some(m.clone()),
        None => app().get(idx - STANDARD.len()).cloned(),
    }
}

/// `pkey_asn1_find`: the method of exactly key type `type_`, the application's first.
pub(crate) fn find_exact(type_: c_int) -> Option<Ref> {
    if let Some(m) = app().iter().find(|m| m.get().pkey_id == type_) {
        return Some(m.clone());
    }
    STANDARD.iter().find(|m| m.get().pkey_id == type_).cloned()
}

/// `EVP_PKEY_asn1_find`: the method of `type_`, following aliases to the type they stand for.
pub(crate) fn find(mut type_: c_int) -> Option<Ref> {
    // An application's aliases can loop, as OpenSSL's would; the chain can't be longer than
    // the methods there are.
    for _ in 0..=count() {
        let m = find_exact(type_)?;
        if !m.get().is_alias() {
            return Some(m);
        }
        type_ = m.get().base_id;
    }
    None
}

/// `EVP_PKEY_asn1_find_str`: the (non-alias) method whose PEM name is `name`, ignoring case,
/// searching from the last method.
pub(crate) fn find_str(name: &[u8]) -> Option<Ref> {
    (0..count()).rev().filter_map(get0).find(|m| {
        let m = m.get();
        !m.is_alias()
            && m.pem_str
                .as_deref()
                .is_some_and(|p| p.to_bytes().eq_ignore_ascii_case(name))
    })
}

/// What the reference's search for an engine implementing a key type does here, where there are
/// no engines: `ossl_engine_table_select` loads the configuration file first. Its result doesn't
/// matter, as it doesn't there. (Miri can't run the system calls that find the file with.)
pub(crate) fn engine_lookup() {
    if cfg!(miri) {
        return;
    }
    let flag = u64::try_from(rustyssl_abi::OPENSSL_INIT_LOAD_CONFIG).unwrap_or(0);
    // SAFETY: no settings.
    let _ = unsafe { crate::init::OPENSSL_init_crypto(flag, ptr::null()) };
}

/// `EVP_PKEY_type`: the key type `type_` stands for, `NID_undef` if none (after the engine
/// search OpenSSL makes).
pub(crate) fn pkey_type(type_: c_int) -> c_int {
    let m = find(type_);
    engine_lookup();
    m.map_or(NID_undef, |m| m.get().pkey_id)
}

/// `standard_name2type`.
const NAME2TYPE: [(c_int, &[u8]); 12] = [
    (EVP_PKEY_RSA, b"RSA"),
    (EVP_PKEY_RSA_PSS, b"RSA-PSS"),
    (EVP_PKEY_EC, b"EC"),
    (EVP_PKEY_ED25519, b"ED25519"),
    (EVP_PKEY_ED448, b"ED448"),
    (EVP_PKEY_X25519, b"X25519"),
    (EVP_PKEY_X448, b"X448"),
    (EVP_PKEY_SM2, b"SM2"),
    (EVP_PKEY_DH, b"DH"),
    (EVP_PKEY_DHX, b"X9.42 DH"),
    (EVP_PKEY_DHX, b"DHX"),
    (EVP_PKEY_DSA, b"DSA"),
];

/// `evp_pkey_name2type`: the key type a name stands for (the standard names ignoring case,
/// then an object's short and long name), `NID_undef` if none.
pub(crate) fn name2type(name: &[u8]) -> c_int {
    if let Some((t, _)) = NAME2TYPE.iter().find(|(_, n)| n.eq_ignore_ascii_case(name)) {
        return *t;
    }
    let Ok(c) = CString::new(name) else {
        return NID_undef;
    };
    // SAFETY: a string.
    let t = pkey_type(unsafe { OBJ_sn2nid(c.as_ptr()) });
    if t != NID_undef {
        return t;
    }
    // SAFETY: as above.
    pkey_type(unsafe { OBJ_ln2nid(c.as_ptr()) })
}

/// `evp_pkey_type2name`: the first standard name of a key type, else its object's short name
/// (empty if it has none).
pub(crate) fn type2name(type_: c_int) -> Vec<u8> {
    if let Some((_, n)) = NAME2TYPE.iter().find(|(t, _)| *t == type_) {
        return n.to_vec();
    }
    // SAFETY: a number.
    let sn = unsafe { crate::objects::OBJ_nid2sn(type_) };
    if sn.is_null() {
        return Vec::new();
    }
    // SAFETY: a static string.
    unsafe { CStr::from_ptr(sn) }.to_bytes().to_vec()
}

/// The pre-filled names of the key types (`get_legacy_pkey_meth_names`), in table order: for
/// each built-in method, the base type (aliases other than SM2) and the type, as numbers, with
/// the PEM name, and DHX's extra name.
pub(crate) fn prefill_entries() -> Vec<(c_int, c_int, Option<&'static [u8]>)> {
    let mut out = Vec::new();
    for m in &STANDARD_TABLE {
        let pem = m.pem_str.map(CStr::to_bytes);
        if !matches!(m.kind, Kind::Alias) {
            if m.pkey_id == EVP_PKEY_DHX {
                out.push((NID_undef, m.pkey_id, Some(&b"DHX"[..])));
            }
            out.push((NID_undef, m.pkey_id, pem));
        } else if m.pkey_id == EVP_PKEY_SM2 {
            out.push((NID_undef, m.pkey_id, pem));
        } else {
            out.push((m.base_id, m.pkey_id, pem));
        }
    }
    out
}

/// A copy of a C string argument, `None` for NULL.
///
/// # Safety
/// `s` is NULL or a string.
unsafe fn owned(s: *const c_char) -> Option<CString> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) }.to_owned())
}

/// `EVP_PKEY_asn1_new` with the base type.
fn new_method(
    id: c_int,
    base_id: c_int,
    flags: c_int,
    pem_str: Option<CString>,
    info: Option<CString>,
) -> *mut EVP_PKEY_ASN1_METHOD {
    EVP_PKEY_ASN1_METHOD::new_handle(Ameth {
        pkey_id: id,
        base_id,
        flags: (flags | ASN1_PKEY_DYNAMIC).cast_unsigned() as c_ulong,
        pem_str,
        info,
        funcs: Mutex::new(Funcs::default()),
    })
}

/// `EVP_PKEY_asn1_add0`.
fn add0(m: Ref) -> bool {
    const F: &str = "EVP_PKEY_asn1_add0";
    let a = m.get();
    // A PEM name, or else the alias flag.
    if a.pem_str.is_some() == a.is_alias() {
        err::raise(ERR_LIB_EVP, ERR_R_PASSED_INVALID_ARGUMENT, F);
        return false;
    }
    let mut app = app();
    if app.iter().any(|x| x.get().pkey_id == a.pkey_id) {
        drop(app);
        err::raise(
            ERR_LIB_EVP,
            EVP_R_PKEY_APPLICATION_ASN1_METHOD_ALREADY_REGISTERED,
            F,
        );
        return false;
    }
    let at = app.partition_point(|x| x.get().pkey_id <= a.pkey_id);
    app.insert(at, m);
    true
}

ffi_export! {
    /// How many ASN.1 methods there are: the built-in ones and the application's.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_PKEY_asn1_get_count() -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        c_int::try_from(count()).unwrap_or(c_int::MAX)
    }
}

ffi_export! {
    /// The method at `idx` (the built-in ones first), or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_PKEY_asn1_get0(idx: c_int) -> *const EVP_PKEY_ASN1_METHOD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // The methods live until the process ends or the application frees its own.
        usize::try_from(idx).ok().and_then(get0).map_or(ptr::null(), |m| m.as_ptr().cast_const())
    }
}

ffi_export! {
    /// The method of the key type `type_` (an application's first), following aliases; NULL if
    /// there's none. `*pe`, if given, is set to NULL: there are no engines.
    ///
    /// # Safety
    /// `pe` is NULL or room for a pointer.
    pub unsafe extern "C" fn EVP_PKEY_asn1_find(pe: *mut *mut ENGINE, type_: c_int) -> *const EVP_PKEY_ASN1_METHOD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        let m = find(type_);
        if !pe.is_null() {
            engine_lookup();
            // SAFETY: the caller's guarantee.
            unsafe { pe.write(ptr::null_mut()) };
        }
        m.map_or(ptr::null(), |m| m.as_ptr().cast_const())
    }
}

ffi_export! {
    /// The method whose PEM name is the `len` characters of `str_` (all of it for -1), ignoring
    /// case; NULL if there's none. `*pe`, if given, is set to NULL: there are no engines.
    ///
    /// # Safety
    /// `pe` is NULL or room for a pointer; `str_` is NULL or holds `len` characters (or is a
    /// string, for -1).
    pub unsafe extern "C" fn EVP_PKEY_asn1_find_str(pe: *mut *mut ENGINE, str_: *const c_char, len: c_int) -> *const EVP_PKEY_ASN1_METHOD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        if !pe.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { pe.write(ptr::null_mut()) };
        }
        if str_.is_null() {
            return ptr::null();
        }
        let name: Vec<u8> = if len == -1 {
            // SAFETY: the caller's guarantee.
            unsafe { CStr::from_ptr(str_) }.to_bytes().to_vec()
        } else {
            let Ok(n) = usize::try_from(len) else { return ptr::null() };
            // `strncasecmp` stops at a NUL: the characters up to one, which then can't match.
            let mut v = Vec::new();
            for i in 0..n {
                // SAFETY: the caller's guarantee: `len` characters, read up to a NUL.
                let c = unsafe { str_.wrapping_add(i).read() };
                let [b] = c.to_ne_bytes();
                if b == 0 {
                    return ptr::null();
                }
                v.push(b);
            }
            v
        };
        find_str(&name).map_or(ptr::null(), |m| m.as_ptr().cast_const())
    }
}

ffi_export! {
    /// Adds an application's method: 0 if there's one for its key type already, or if it has a
    /// PEM name and is an alias (or neither).
    ///
    /// # Safety
    /// `ameth` is NULL or a live method.
    pub unsafe extern "C" fn EVP_PKEY_asn1_add0(ameth: *const EVP_PKEY_ASN1_METHOD) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { Ref::new(ameth) }) else { return 0 };
        c_int::from(add0(m))
    }
}

ffi_export! {
    /// Adds an alias making the key type `from` stand for `to`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_PKEY_asn1_add_alias(to: c_int, from: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let h = new_method(from, to, ASN1_PKEY_ALIAS, None, None);
        // SAFETY: the new handle's reference.
        let Some(m) = (unsafe { Ref::adopt(h) }) else { return 0 };
        c_int::from(add0(m))
    }
}

ffi_export! {
    /// Fills in the method's key type, base type, flags, description, and PEM name (each
    /// pointer that isn't NULL). 0 for a NULL method.
    ///
    /// # Safety
    /// Each pointer is NULL or room for its value; `ameth` is NULL or a live method.
    pub unsafe extern "C" fn EVP_PKEY_asn1_get0_info(ppkey_id: *mut c_int, ppkey_base_id: *mut c_int, ppkey_flags: *mut c_int, pinfo: *mut *const c_char, ppem_str: *mut *const c_char, ameth: *const EVP_PKEY_ASN1_METHOD) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(ameth) }) else { return 0 };
        if !ppkey_id.is_null() {
            // SAFETY: the caller's guarantee, here and below.
            unsafe { ppkey_id.write(m.pkey_id) };
        }
        if !ppkey_base_id.is_null() {
            // SAFETY: as above.
            unsafe { ppkey_base_id.write(m.base_id) };
        }
        if !ppkey_flags.is_null() {
            // `int` holds the flags (they're small).
            // SAFETY: as above.
            unsafe { ppkey_flags.write(c_int::try_from(m.flags).unwrap_or(c_int::MAX)) };
        }
        // The strings live as long as the method.
        if !pinfo.is_null() {
            // SAFETY: as above.
            unsafe { pinfo.write(m.info.as_deref().map_or(ptr::null(), CStr::as_ptr)) };
        }
        if !ppem_str.is_null() {
            // SAFETY: as above.
            unsafe { ppem_str.write(m.pem_str.as_deref().map_or(ptr::null(), CStr::as_ptr)) };
        }
        1
    }
}

ffi_export! {
    /// The ASN.1 method of a key typed by one (a legacy key), else NULL.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_get0_asn1(pkey: *const EVP_PKEY) -> *const EVP_PKEY_ASN1_METHOD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { super::pkey(pkey) }) else { return ptr::null() };
        // The key keeps a reference to the method.
        k.lock().ameth.as_ref().map_or(ptr::null(), |m| m.as_ptr().cast_const())
    }
}

ffi_export! {
    /// A new method for the key type `id`, with `flags`, the PEM name `pem_str`, and the
    /// description `info` (copied), and no functions; NULL if it can't be made.
    ///
    /// # Safety
    /// `pem_str` and `info` are NULL or strings.
    pub unsafe extern "C" fn EVP_PKEY_asn1_new(id: c_int, flags: c_int, pem_str: *const c_char, info: *const c_char) -> *mut EVP_PKEY_ASN1_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let pem = unsafe { owned(pem_str) };
        // SAFETY: as above.
        let info = unsafe { owned(info) };
        new_method(id, id, flags, pem, info)
    }
}

ffi_export! {
    /// Copies `src`'s functions into `dst`, keeping `dst`'s key types, flags, and names.
    ///
    /// # Safety
    /// `dst` and `src` are NULL or live methods.
    pub unsafe extern "C" fn EVP_PKEY_asn1_copy(dst: *mut EVP_PKEY_ASN1_METHOD, src: *const EVP_PKEY_ASN1_METHOD)
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
    /// Frees a method `EVP_PKEY_asn1_new` made (the methods registry keeps its own reference to
    /// one that was added); others are left alone.
    ///
    /// # Safety
    /// `ameth` is NULL or a live method, not used afterwards if `EVP_PKEY_asn1_new` made it.
    pub unsafe extern "C" fn EVP_PKEY_asn1_free(ameth: *mut EVP_PKEY_ASN1_METHOD)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if unsafe { method(ameth) }.is_some_and(Ameth::is_dynamic) {
            // SAFETY: the caller's reference, given up.
            unsafe { EVP_PKEY_ASN1_METHOD::free(ameth) };
        }
    }
}

ffi_export! {
    /// Sets the public key functions.
    ///
    /// # Safety
    /// `ameth` is NULL or a live method; the functions are NULL or of the documented types.
    pub unsafe extern "C" fn EVP_PKEY_asn1_set_public(ameth: *mut EVP_PKEY_ASN1_METHOD, pub_decode: Option<PubDecode>, pub_encode: Option<PubEncode>, pub_cmp: Option<Cmp>, pub_print: Option<Print>, pkey_size: Option<KeyFn>, pkey_bits: Option<KeyFn>)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe {
            update(ameth, |f| {
                f.pub_decode = pub_decode;
                f.pub_encode = pub_encode;
                f.pub_cmp = pub_cmp;
                f.pub_print = pub_print;
                f.pkey_size = pkey_size;
                f.pkey_bits = pkey_bits;
            });
        }
    }
}

ffi_export! {
    /// Sets the private key functions.
    ///
    /// # Safety
    /// As for `EVP_PKEY_asn1_set_public`.
    pub unsafe extern "C" fn EVP_PKEY_asn1_set_private(ameth: *mut EVP_PKEY_ASN1_METHOD, priv_decode: Option<PrivDecode>, priv_encode: Option<PrivEncode>, priv_print: Option<Print>)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe {
            update(ameth, |f| {
                f.priv_decode = priv_decode;
                f.priv_encode = priv_encode;
                f.priv_print = priv_print;
            });
        }
    }
}

ffi_export! {
    /// Sets the parameter functions.
    ///
    /// # Safety
    /// As for `EVP_PKEY_asn1_set_public`.
    pub unsafe extern "C" fn EVP_PKEY_asn1_set_param(ameth: *mut EVP_PKEY_ASN1_METHOD, param_decode: Option<ParamDecode>, param_encode: Option<ParamEncode>, param_missing: Option<KeyFn>, param_copy: Option<ParamCopy>, param_cmp: Option<Cmp>, param_print: Option<Print>)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe {
            update(ameth, |f| {
                f.param_decode = param_decode;
                f.param_encode = param_encode;
                f.param_missing = param_missing;
                f.param_copy = param_copy;
                f.param_cmp = param_cmp;
                f.param_print = param_print;
            });
        }
    }
}

ffi_export! {
    /// Sets the function that frees a key's data.
    ///
    /// # Safety
    /// As for `EVP_PKEY_asn1_set_public`.
    pub unsafe extern "C" fn EVP_PKEY_asn1_set_free(ameth: *mut EVP_PKEY_ASN1_METHOD, pkey_free: Option<Free>)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { update(ameth, |f| f.pkey_free = pkey_free) };
    }
}

ffi_export! {
    /// Sets the ctrl.
    ///
    /// # Safety
    /// As for `EVP_PKEY_asn1_set_public`.
    pub unsafe extern "C" fn EVP_PKEY_asn1_set_ctrl(ameth: *mut EVP_PKEY_ASN1_METHOD, pkey_ctrl: Option<Ctrl>)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { update(ameth, |f| f.pkey_ctrl = pkey_ctrl) };
    }
}

ffi_export! {
    /// Sets the function giving a key's security bits.
    ///
    /// # Safety
    /// As for `EVP_PKEY_asn1_set_public`.
    pub unsafe extern "C" fn EVP_PKEY_asn1_set_security_bits(ameth: *mut EVP_PKEY_ASN1_METHOD, pkey_security_bits: Option<KeyFn>)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { update(ameth, |f| f.pkey_security_bits = pkey_security_bits) };
    }
}

ffi_export! {
    /// Sets the functions verifying and signing ASN.1 items.
    ///
    /// # Safety
    /// As for `EVP_PKEY_asn1_set_public`.
    pub unsafe extern "C" fn EVP_PKEY_asn1_set_item(ameth: *mut EVP_PKEY_ASN1_METHOD, item_verify: Option<ItemVerify>, item_sign: Option<ItemSign>)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe {
            update(ameth, |f| {
                f.item_verify = item_verify;
                f.item_sign = item_sign;
            });
        }
    }
}

ffi_export! {
    /// Sets the function filling in a signature's information.
    ///
    /// # Safety
    /// As for `EVP_PKEY_asn1_set_public`.
    pub unsafe extern "C" fn EVP_PKEY_asn1_set_siginf(ameth: *mut EVP_PKEY_ASN1_METHOD, siginf_set: Option<SiginfSet>)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { update(ameth, |f| f.siginf_set = siginf_set) };
    }
}

ffi_export! {
    /// Sets the key check.
    ///
    /// # Safety
    /// As for `EVP_PKEY_asn1_set_public`.
    pub unsafe extern "C" fn EVP_PKEY_asn1_set_check(ameth: *mut EVP_PKEY_ASN1_METHOD, pkey_check: Option<KeyFn>)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { update(ameth, |f| f.pkey_check = pkey_check) };
    }
}

ffi_export! {
    /// Sets the public key check.
    ///
    /// # Safety
    /// As for `EVP_PKEY_asn1_set_public`.
    pub unsafe extern "C" fn EVP_PKEY_asn1_set_public_check(ameth: *mut EVP_PKEY_ASN1_METHOD, pkey_pub_check: Option<KeyFn>)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { update(ameth, |f| f.pkey_public_check = pkey_pub_check) };
    }
}

ffi_export! {
    /// Sets the parameter check.
    ///
    /// # Safety
    /// As for `EVP_PKEY_asn1_set_public`.
    pub unsafe extern "C" fn EVP_PKEY_asn1_set_param_check(ameth: *mut EVP_PKEY_ASN1_METHOD, pkey_param_check: Option<KeyFn>)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { update(ameth, |f| f.pkey_param_check = pkey_param_check) };
    }
}

ffi_export! {
    /// Sets the function giving a key a raw private key.
    ///
    /// # Safety
    /// As for `EVP_PKEY_asn1_set_public`.
    pub unsafe extern "C" fn EVP_PKEY_asn1_set_set_priv_key(ameth: *mut EVP_PKEY_ASN1_METHOD, set_priv_key: Option<SetRaw>)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { update(ameth, |f| f.set_priv_key = set_priv_key) };
    }
}

ffi_export! {
    /// Sets the function giving a key a raw public key.
    ///
    /// # Safety
    /// As for `EVP_PKEY_asn1_set_public`.
    pub unsafe extern "C" fn EVP_PKEY_asn1_set_set_pub_key(ameth: *mut EVP_PKEY_ASN1_METHOD, set_pub_key: Option<SetRaw>)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { update(ameth, |f| f.set_pub_key = set_pub_key) };
    }
}

ffi_export! {
    /// Sets the function getting a key's raw private key.
    ///
    /// # Safety
    /// As for `EVP_PKEY_asn1_set_public`.
    pub unsafe extern "C" fn EVP_PKEY_asn1_set_get_priv_key(ameth: *mut EVP_PKEY_ASN1_METHOD, get_priv_key: Option<GetRaw>)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { update(ameth, |f| f.get_priv_key = get_priv_key) };
    }
}

ffi_export! {
    /// Sets the function getting a key's raw public key.
    ///
    /// # Safety
    /// As for `EVP_PKEY_asn1_set_public`.
    pub unsafe extern "C" fn EVP_PKEY_asn1_set_get_pub_key(ameth: *mut EVP_PKEY_ASN1_METHOD, get_pub_key: Option<GetRaw>)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { update(ameth, |f| f.get_pub_key = get_pub_key) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_built_in_table() {
        assert_eq!(STANDARD.len(), 15);
        assert_eq!(pkey_type(EVP_PKEY_RSA2), EVP_PKEY_RSA);
        assert_eq!(pkey_type(EVP_PKEY_DSA3), NID_undef);
        assert_eq!(pkey_type(EVP_PKEY_SM2), EVP_PKEY_EC);
        assert!(find_str(b"x9.42 dh").is_some());
        assert!(find_str(b"DHX").is_none());
        assert_eq!(name2type(b"dhx"), EVP_PKEY_DHX);
        assert_eq!(name2type(b"HMAC"), NID_undef);
    }

    #[test]
    fn built_in_methods_stay_as_they_are() {
        let rsa = find(EVP_PKEY_RSA).unwrap();
        // SAFETY: a built-in method, live for good; NULL is allowed.
        unsafe { EVP_PKEY_asn1_set_ctrl(rsa.as_ptr(), None) };
        assert!(rsa.get().funcs().pkey_ctrl.is_some());
        // SAFETY: as above; a built-in method isn't freed.
        unsafe { EVP_PKEY_asn1_free(rsa.as_ptr()) };
        assert!(find(EVP_PKEY_RSA).is_some());
    }
}
