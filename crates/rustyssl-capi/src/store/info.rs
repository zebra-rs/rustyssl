//! What a store gives (`OSSL_STORE_INFO(3)`; `store_lib.c`, `store_strings.c`) and what to
//! search it for (`OSSL_STORE_SEARCH(3)`).
//!
//! An `OSSL_STORE_INFO` owns what it holds: a name (and its description) from `CRYPTO_malloc`,
//! or a reference to a key, parameters, a certificate, or a CRL.

use core::ffi::{CStr, c_char, c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_INTEGER, ERR_LIB_OSSL_STORE, ERR_R_OSSL_STORE_LIB, ERR_R_PASSED_INVALID_ARGUMENT, EVP_MD,
    EVP_PKEY, OSSL_STORE_INFO, OSSL_STORE_INFO_CERT, OSSL_STORE_INFO_CRL, OSSL_STORE_INFO_NAME,
    OSSL_STORE_INFO_PARAMS, OSSL_STORE_INFO_PKEY, OSSL_STORE_INFO_PUBKEY,
    OSSL_STORE_R_FINGERPRINT_SIZE_DOES_NOT_MATCH_DIGEST, OSSL_STORE_R_NOT_A_CERTIFICATE,
    OSSL_STORE_R_NOT_A_CRL, OSSL_STORE_R_NOT_A_NAME, OSSL_STORE_R_NOT_A_PRIVATE_KEY,
    OSSL_STORE_R_NOT_A_PUBLIC_KEY, OSSL_STORE_R_NOT_PARAMETERS, OSSL_STORE_SEARCH,
    OSSL_STORE_SEARCH_BY_ALIAS, OSSL_STORE_SEARCH_BY_ISSUER_SERIAL,
    OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT, OSSL_STORE_SEARCH_BY_NAME, X509, X509_CRL, X509_NAME,
};

use crate::err;
use crate::evp::digest::{EVP_MD_get_size, EVP_MD_get0_name};
use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_up_ref};
use crate::ffi::ffi_export;
use crate::mem;
use crate::string::CRYPTO_strdup;
use crate::x509::cert::{X509_free, X509_up_ref};
use crate::x509::crl::{X509_CRL_free, X509_CRL_up_ref};

/// `ossl_store_info_st`: the type and what it holds.
pub(crate) struct Info {
    pub(crate) type_: c_int,
    /// The name (`CRYPTO_malloc`), key, parameters, certificate, or CRL.
    pub(crate) data: *mut c_void,
    /// A name's description (`CRYPTO_malloc`), or NULL.
    pub(crate) desc: *mut c_char,
}

/// The information behind a pointer.
///
/// # Safety
/// `p` is NULL or a live `OSSL_STORE_INFO`.
pub(crate) unsafe fn info_of<'a>(p: *const OSSL_STORE_INFO) -> Option<&'a mut Info> {
    // SAFETY: the caller's guarantee.
    unsafe { p.cast::<Info>().cast_mut().as_mut() }
}

fn raise(reason: c_int, f: &str) {
    err::raise(ERR_LIB_OSSL_STORE, reason, f);
}

/// A copy of the C string from `CRYPTO_malloc`, or NULL.
///
/// # Safety
/// `s` is a C string.
pub(crate) unsafe fn strdup(s: *const c_char) -> *mut c_char {
    // SAFETY: the caller's string.
    unsafe { CRYPTO_strdup(s, c"store_lib.c".as_ptr(), 0) }
}

ffi_export! {
    /// A new information of the type, holding `data` (taken over): it, or NULL.
    ///
    /// # Safety
    /// `data` is NULL or what the type holds, which the information then owns.
    pub unsafe extern "C" fn OSSL_STORE_INFO_new(type_: c_int, data: *mut c_void) -> *mut OSSL_STORE_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        Box::into_raw(Box::new(Info { type_, data, desc: ptr::null_mut() })).cast()
    }
}

/// [`OSSL_STORE_INFO_new`] of the type, raising `ERR_R_OSSL_STORE_LIB` on failure.
fn new_of(type_: c_int, data: *mut c_void, f: &str) -> *mut OSSL_STORE_INFO {
    // SAFETY: the caller's object, which the information takes.
    let info = unsafe { OSSL_STORE_INFO_new(type_, data) };
    if info.is_null() {
        raise(ERR_R_OSSL_STORE_LIB, f);
    }
    info
}

ffi_export! {
    /// A name (taken over, from `CRYPTO_malloc`), with no description.
    ///
    /// # Safety
    /// `name` is a C string from `CRYPTO_malloc` the information then owns.
    pub unsafe extern "C" fn OSSL_STORE_INFO_new_NAME(name: *mut c_char) -> *mut OSSL_STORE_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        new_of(OSSL_STORE_INFO_NAME, name.cast(), "OSSL_STORE_INFO_new_NAME")
    }
}

ffi_export! {
    /// Sets a name's description (taken over): 1, or 0 for another type.
    ///
    /// # Safety
    /// `info` is a live information; `desc` NULL or a C string from `CRYPTO_malloc`.
    pub unsafe extern "C" fn OSSL_STORE_INFO_set0_NAME_description(info: *mut OSSL_STORE_INFO, desc: *mut c_char) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        let Some(i) = (unsafe { info_of(info) }).filter(|i| i.type_ == OSSL_STORE_INFO_NAME) else {
            raise(ERR_R_PASSED_INVALID_ARGUMENT, "OSSL_STORE_INFO_set0_NAME_description");
            return 0;
        };
        i.desc = desc;
        1
    }
}

ffi_export! {
    /// Parameters (taken over).
    ///
    /// # Safety
    /// `params` is NULL or a live key the information then owns.
    pub unsafe extern "C" fn OSSL_STORE_INFO_new_PARAMS(params: *mut EVP_PKEY) -> *mut OSSL_STORE_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        new_of(OSSL_STORE_INFO_PARAMS, params.cast(), "OSSL_STORE_INFO_new_PARAMS")
    }
}

ffi_export! {
    /// A public key (taken over).
    ///
    /// # Safety
    /// `pkey` is NULL or a live key the information then owns.
    pub unsafe extern "C" fn OSSL_STORE_INFO_new_PUBKEY(pkey: *mut EVP_PKEY) -> *mut OSSL_STORE_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        new_of(OSSL_STORE_INFO_PUBKEY, pkey.cast(), "OSSL_STORE_INFO_new_PUBKEY")
    }
}

ffi_export! {
    /// A private key (taken over).
    ///
    /// # Safety
    /// `pkey` is NULL or a live key the information then owns.
    pub unsafe extern "C" fn OSSL_STORE_INFO_new_PKEY(pkey: *mut EVP_PKEY) -> *mut OSSL_STORE_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        new_of(OSSL_STORE_INFO_PKEY, pkey.cast(), "OSSL_STORE_INFO_new_PKEY")
    }
}

ffi_export! {
    /// A certificate (taken over).
    ///
    /// # Safety
    /// `x509` is NULL or a live certificate the information then owns.
    pub unsafe extern "C" fn OSSL_STORE_INFO_new_CERT(x509: *mut X509) -> *mut OSSL_STORE_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        new_of(OSSL_STORE_INFO_CERT, x509.cast(), "OSSL_STORE_INFO_new_CERT")
    }
}

ffi_export! {
    /// A CRL (taken over).
    ///
    /// # Safety
    /// `crl` is NULL or a live CRL the information then owns.
    pub unsafe extern "C" fn OSSL_STORE_INFO_new_CRL(crl: *mut X509_CRL) -> *mut OSSL_STORE_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        new_of(OSSL_STORE_INFO_CRL, crl.cast(), "OSSL_STORE_INFO_new_CRL")
    }
}

ffi_export! {
    /// The information's type.
    ///
    /// # Safety
    /// `info` is a live information.
    pub unsafe extern "C" fn OSSL_STORE_INFO_get_type(info: *const OSSL_STORE_INFO) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { info_of(info) }.map_or(0, |i| i.type_)
    }
}

ffi_export! {
    /// What the information holds if it is of the type, else NULL.
    ///
    /// # Safety
    /// `info` is a live information.
    pub unsafe extern "C" fn OSSL_STORE_INFO_get0_data(type_: c_int, info: *const OSSL_STORE_INFO) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { info_of(info) }.filter(|i| i.type_ == type_).map_or(ptr::null_mut(), |i| i.data)
    }
}

/// What the information holds if it is of the type.
///
/// # Safety
/// `info` is NULL or a live information.
unsafe fn get0(info: *const OSSL_STORE_INFO, type_: c_int) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    unsafe { OSSL_STORE_INFO_get0_data(type_, info) }
}

ffi_export! {
    /// The name, or NULL for another type.
    ///
    /// # Safety
    /// `info` is a live information.
    pub unsafe extern "C" fn OSSL_STORE_INFO_get0_NAME(info: *const OSSL_STORE_INFO) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { get0(info, OSSL_STORE_INFO_NAME) }.cast_const().cast()
    }
}

ffi_export! {
    /// A copy of the name (from `CRYPTO_malloc`), or NULL with `OSSL_STORE_R_NOT_A_NAME`.
    ///
    /// # Safety
    /// `info` is a live information.
    pub unsafe extern "C" fn OSSL_STORE_INFO_get1_NAME(info: *const OSSL_STORE_INFO) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        match unsafe { info_of(info) }.filter(|i| i.type_ == OSSL_STORE_INFO_NAME) {
            // SAFETY: its name, a C string.
            Some(i) => unsafe { strdup(i.data.cast()) },
            None => {
                raise(OSSL_STORE_R_NOT_A_NAME, "OSSL_STORE_INFO_get1_NAME");
                ptr::null_mut()
            }
        }
    }
}

ffi_export! {
    /// The name's description, or NULL (for none, or another type).
    ///
    /// # Safety
    /// `info` is a live information.
    pub unsafe extern "C" fn OSSL_STORE_INFO_get0_NAME_description(info: *const OSSL_STORE_INFO) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { info_of(info) }
            .filter(|i| i.type_ == OSSL_STORE_INFO_NAME)
            .map_or(ptr::null(), |i| i.desc.cast_const())
    }
}

ffi_export! {
    /// A copy of the name's description ("" for none), or NULL with `OSSL_STORE_R_NOT_A_NAME`.
    ///
    /// # Safety
    /// `info` is a live information.
    pub unsafe extern "C" fn OSSL_STORE_INFO_get1_NAME_description(info: *const OSSL_STORE_INFO) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        match unsafe { info_of(info) }.filter(|i| i.type_ == OSSL_STORE_INFO_NAME) {
            Some(i) => {
                let d = if i.desc.is_null() { c"".as_ptr() } else { i.desc.cast_const() };
                // SAFETY: a C string.
                unsafe { strdup(d) }
            }
            None => {
                raise(OSSL_STORE_R_NOT_A_NAME, "OSSL_STORE_INFO_get1_NAME_description");
                ptr::null_mut()
            }
        }
    }
}

/// The key the information holds if it is of the type, up-referenced, or NULL with `reason`.
///
/// # Safety
/// `info` is NULL or a live information.
unsafe fn get1_pkey(
    info: *const OSSL_STORE_INFO,
    type_: c_int,
    reason: c_int,
    f: &str,
) -> *mut EVP_PKEY {
    // SAFETY: the caller's guarantee.
    let Some(i) = (unsafe { info_of(info) }).filter(|i| i.type_ == type_) else {
        raise(reason, f);
        return ptr::null_mut();
    };
    // SAFETY: its key.
    if unsafe { EVP_PKEY_up_ref(i.data.cast()) } == 0 {
        return ptr::null_mut();
    }
    i.data.cast()
}

ffi_export! {
    /// The parameters, or NULL for another type.
    ///
    /// # Safety
    /// `info` is a live information.
    pub unsafe extern "C" fn OSSL_STORE_INFO_get0_PARAMS(info: *const OSSL_STORE_INFO) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { get0(info, OSSL_STORE_INFO_PARAMS) }.cast()
    }
}

ffi_export! {
    /// The parameters, up-referenced, or NULL with `OSSL_STORE_R_NOT_PARAMETERS`.
    ///
    /// # Safety
    /// `info` is a live information.
    pub unsafe extern "C" fn OSSL_STORE_INFO_get1_PARAMS(info: *const OSSL_STORE_INFO) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { get1_pkey(info, OSSL_STORE_INFO_PARAMS, OSSL_STORE_R_NOT_PARAMETERS, "OSSL_STORE_INFO_get1_PARAMS") }
    }
}

ffi_export! {
    /// The public key, or NULL for another type.
    ///
    /// # Safety
    /// `info` is a live information.
    pub unsafe extern "C" fn OSSL_STORE_INFO_get0_PUBKEY(info: *const OSSL_STORE_INFO) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { get0(info, OSSL_STORE_INFO_PUBKEY) }.cast()
    }
}

ffi_export! {
    /// The public key, up-referenced, or NULL with `OSSL_STORE_R_NOT_A_PUBLIC_KEY`.
    ///
    /// # Safety
    /// `info` is a live information.
    pub unsafe extern "C" fn OSSL_STORE_INFO_get1_PUBKEY(info: *const OSSL_STORE_INFO) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { get1_pkey(info, OSSL_STORE_INFO_PUBKEY, OSSL_STORE_R_NOT_A_PUBLIC_KEY, "OSSL_STORE_INFO_get1_PUBKEY") }
    }
}

ffi_export! {
    /// The private key, or NULL for another type.
    ///
    /// # Safety
    /// `info` is a live information.
    pub unsafe extern "C" fn OSSL_STORE_INFO_get0_PKEY(info: *const OSSL_STORE_INFO) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { get0(info, OSSL_STORE_INFO_PKEY) }.cast()
    }
}

ffi_export! {
    /// The private key, up-referenced, or NULL with `OSSL_STORE_R_NOT_A_PRIVATE_KEY`.
    ///
    /// # Safety
    /// `info` is a live information.
    pub unsafe extern "C" fn OSSL_STORE_INFO_get1_PKEY(info: *const OSSL_STORE_INFO) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { get1_pkey(info, OSSL_STORE_INFO_PKEY, OSSL_STORE_R_NOT_A_PRIVATE_KEY, "OSSL_STORE_INFO_get1_PKEY") }
    }
}

ffi_export! {
    /// The certificate, or NULL for another type.
    ///
    /// # Safety
    /// `info` is a live information.
    pub unsafe extern "C" fn OSSL_STORE_INFO_get0_CERT(info: *const OSSL_STORE_INFO) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { get0(info, OSSL_STORE_INFO_CERT) }.cast()
    }
}

ffi_export! {
    /// The certificate, up-referenced, or NULL with `OSSL_STORE_R_NOT_A_CERTIFICATE`.
    ///
    /// # Safety
    /// `info` is a live information.
    pub unsafe extern "C" fn OSSL_STORE_INFO_get1_CERT(info: *const OSSL_STORE_INFO) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        let Some(i) = (unsafe { info_of(info) }).filter(|i| i.type_ == OSSL_STORE_INFO_CERT) else {
            raise(OSSL_STORE_R_NOT_A_CERTIFICATE, "OSSL_STORE_INFO_get1_CERT");
            return ptr::null_mut();
        };
        // SAFETY: its certificate.
        if unsafe { X509_up_ref(i.data.cast()) } == 0 {
            return ptr::null_mut();
        }
        i.data.cast()
    }
}

ffi_export! {
    /// The CRL, or NULL for another type.
    ///
    /// # Safety
    /// `info` is a live information.
    pub unsafe extern "C" fn OSSL_STORE_INFO_get0_CRL(info: *const OSSL_STORE_INFO) -> *mut X509_CRL
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { get0(info, OSSL_STORE_INFO_CRL) }.cast()
    }
}

ffi_export! {
    /// The CRL, up-referenced, or NULL with `OSSL_STORE_R_NOT_A_CRL`.
    ///
    /// # Safety
    /// `info` is a live information.
    pub unsafe extern "C" fn OSSL_STORE_INFO_get1_CRL(info: *const OSSL_STORE_INFO) -> *mut X509_CRL
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        let Some(i) = (unsafe { info_of(info) }).filter(|i| i.type_ == OSSL_STORE_INFO_CRL) else {
            raise(OSSL_STORE_R_NOT_A_CRL, "OSSL_STORE_INFO_get1_CRL");
            return ptr::null_mut();
        };
        // SAFETY: its CRL.
        if unsafe { X509_CRL_up_ref(i.data.cast()) } == 0 {
            return ptr::null_mut();
        }
        i.data.cast()
    }
}

ffi_export! {
    /// Frees the information and what it holds.
    ///
    /// # Safety
    /// `info` is NULL or a live information, not used again.
    pub unsafe extern "C" fn OSSL_STORE_INFO_free(info: *mut OSSL_STORE_INFO)
    where failure = (), library = ERR_LIB_OSSL_STORE
    {
        if info.is_null() {
            return;
        }
        // SAFETY: made by `OSSL_STORE_INFO_new`, freed once.
        let i = unsafe { Box::from_raw(info.cast::<Info>()) };
        match i.type_ {
            OSSL_STORE_INFO_NAME => {
                // SAFETY: its own strings from `CRYPTO_malloc`, or NULL.
                unsafe { mem::release(i.data) };
                // SAFETY: as above.
                unsafe { mem::release(i.desc.cast()) };
            }
            // SAFETY: its own key.
            OSSL_STORE_INFO_PARAMS | OSSL_STORE_INFO_PUBKEY | OSSL_STORE_INFO_PKEY => unsafe { EVP_PKEY_free(i.data.cast()) },
            // SAFETY: its own certificate.
            OSSL_STORE_INFO_CERT => unsafe { X509_free(i.data.cast()) },
            // SAFETY: its own CRL.
            OSSL_STORE_INFO_CRL => unsafe { X509_CRL_free(i.data.cast()) },
            _ => {}
        }
    }
}

const TYPE_STRINGS: [&CStr; 6] = [
    c"Name",
    c"Parameters",
    c"Public key",
    c"Pkey",
    c"Certificate",
    c"CRL",
];

ffi_export! {
    /// The type's name (`Name`, `Parameters`, `Public key`, `Pkey`, `Certificate`, `CRL`), or
    /// NULL for another.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OSSL_STORE_INFO_type_string(type_: c_int) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_OSSL_STORE
    {
        usize::try_from(type_)
            .ok()
            .and_then(|t| t.checked_sub(1))
            .and_then(|t| TYPE_STRINGS.get(t))
            .map_or(ptr::null(), |s| s.as_ptr())
    }
}

/// `ossl_store_search_st`.
pub(crate) struct Search {
    pub(crate) search_type: c_int,
    pub(crate) name: *mut X509_NAME,
    pub(crate) serial: *const ASN1_INTEGER,
    pub(crate) digest: *const EVP_MD,
    pub(crate) string: *const c_uchar,
    pub(crate) stringlength: usize,
}

/// The search behind a pointer.
///
/// # Safety
/// `p` is NULL or a live search.
pub(crate) unsafe fn search_of<'a>(p: *const OSSL_STORE_SEARCH) -> Option<&'a Search> {
    // SAFETY: the caller's guarantee.
    unsafe { p.cast::<Search>().as_ref() }
}

fn new_search(s: Search) -> *mut OSSL_STORE_SEARCH {
    Box::into_raw(Box::new(s)).cast()
}

fn empty(search_type: c_int) -> Search {
    Search {
        search_type,
        name: ptr::null_mut(),
        serial: ptr::null(),
        digest: ptr::null(),
        string: ptr::null(),
        stringlength: 0,
    }
}

ffi_export! {
    /// A search by subject name (the name not copied).
    ///
    /// # Safety
    /// `name` is NULL or a name that outlives the search.
    pub unsafe extern "C" fn OSSL_STORE_SEARCH_by_name(name: *mut X509_NAME) -> *mut OSSL_STORE_SEARCH
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        new_search(Search { name, ..empty(OSSL_STORE_SEARCH_BY_NAME) })
    }
}

ffi_export! {
    /// A search by issuer and serial number (neither copied).
    ///
    /// # Safety
    /// `name` and `serial` are NULL or outlive the search.
    pub unsafe extern "C" fn OSSL_STORE_SEARCH_by_issuer_serial(name: *mut X509_NAME, serial: *const ASN1_INTEGER) -> *mut OSSL_STORE_SEARCH
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        new_search(Search { name, serial, ..empty(OSSL_STORE_SEARCH_BY_ISSUER_SERIAL) })
    }
}

ffi_export! {
    /// A search by a key's fingerprint, which must be the digest's size (not copied), or NULL.
    ///
    /// # Safety
    /// `digest` is NULL or a live digest; `bytes` points to `len` octets that outlive the search.
    pub unsafe extern "C" fn OSSL_STORE_SEARCH_by_key_fingerprint(digest: *const EVP_MD, bytes: *const c_uchar, len: usize) -> *mut OSSL_STORE_SEARCH
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's digest, or NULL.
        let md_size = unsafe { EVP_MD_get_size(digest) };
        if md_size <= 0 {
            return ptr::null_mut();
        }
        if !digest.is_null() && usize::try_from(md_size).ok() != Some(len) {
            // SAFETY: as above.
            let name = unsafe { EVP_MD_get0_name(digest) };
            let name = if name.is_null() {
                "(null)".into()
            } else {
                // SAFETY: the digest's name.
                unsafe { CStr::from_ptr(name) }.to_string_lossy()
            };
            err::raise_with_text(
                ERR_LIB_OSSL_STORE,
                OSSL_STORE_R_FINGERPRINT_SIZE_DOES_NOT_MATCH_DIGEST,
                "OSSL_STORE_SEARCH_by_key_fingerprint",
                &format!("{name} size is {md_size}, fingerprint size is {len}"),
            );
            return ptr::null_mut();
        }
        new_search(Search { digest, string: bytes, stringlength: len, ..empty(OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT) })
    }
}

ffi_export! {
    /// A search by alias (not copied).
    ///
    /// # Safety
    /// `alias` is a C string that outlives the search.
    pub unsafe extern "C" fn OSSL_STORE_SEARCH_by_alias(alias: *const c_char) -> *mut OSSL_STORE_SEARCH
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's string.
        let len = if alias.is_null() { 0 } else { unsafe { CStr::from_ptr(alias) }.to_bytes().len() };
        new_search(Search { string: alias.cast(), stringlength: len, ..empty(OSSL_STORE_SEARCH_BY_ALIAS) })
    }
}

ffi_export! {
    /// Frees the search.
    ///
    /// # Safety
    /// `search` is NULL or a live search, not used again.
    pub unsafe extern "C" fn OSSL_STORE_SEARCH_free(search: *mut OSSL_STORE_SEARCH)
    where failure = (), library = ERR_LIB_OSSL_STORE
    {
        if !search.is_null() {
            // SAFETY: made by a constructor here, freed once.
            drop(unsafe { Box::from_raw(search.cast::<Search>()) });
        }
    }
}

ffi_export! {
    /// The search's type.
    ///
    /// # Safety
    /// `criterion` is a live search.
    pub unsafe extern "C" fn OSSL_STORE_SEARCH_get_type(criterion: *const OSSL_STORE_SEARCH) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { search_of(criterion) }.map_or(0, |s| s.search_type)
    }
}

ffi_export! {
    /// The search's name.
    ///
    /// # Safety
    /// `criterion` is a live search.
    pub unsafe extern "C" fn OSSL_STORE_SEARCH_get0_name(criterion: *const OSSL_STORE_SEARCH) -> *mut X509_NAME
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { search_of(criterion) }.map_or(ptr::null_mut(), |s| s.name)
    }
}

ffi_export! {
    /// The search's serial number.
    ///
    /// # Safety
    /// `criterion` is a live search.
    pub unsafe extern "C" fn OSSL_STORE_SEARCH_get0_serial(criterion: *const OSSL_STORE_SEARCH) -> *const ASN1_INTEGER
    where failure = ptr::null(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { search_of(criterion) }.map_or(ptr::null(), |s| s.serial)
    }
}

ffi_export! {
    /// The search's octets (a fingerprint or an alias), with their length in `*length`.
    ///
    /// # Safety
    /// `criterion` is a live search; `length` room for a `size_t`.
    pub unsafe extern "C" fn OSSL_STORE_SEARCH_get0_bytes(criterion: *const OSSL_STORE_SEARCH, length: *mut usize) -> *const c_uchar
    where failure = ptr::null(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { search_of(criterion) }) else { return ptr::null() };
        // SAFETY: the caller's room, or NULL.
        if let Some(l) = unsafe { length.as_mut() } {
            *l = s.stringlength;
        }
        s.string
    }
}

ffi_export! {
    /// The search's alias.
    ///
    /// # Safety
    /// `criterion` is a live search.
    pub unsafe extern "C" fn OSSL_STORE_SEARCH_get0_string(criterion: *const OSSL_STORE_SEARCH) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { search_of(criterion) }.map_or(ptr::null(), |s| s.string.cast())
    }
}

ffi_export! {
    /// The search's digest.
    ///
    /// # Safety
    /// `criterion` is a live search.
    pub unsafe extern "C" fn OSSL_STORE_SEARCH_get0_digest(criterion: *const OSSL_STORE_SEARCH) -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { search_of(criterion) }.map_or(ptr::null(), |s| s.digest)
    }
}
