//! Certificate Transparency (`crypto/ct`): signed certificate timestamps (`SCT`, their TLS
//! encodings over `rustyssl-pki`'s `ct`, and the DER of a list), logs and log stores (loaded
//! from `ct_log_list.cnf`), the policy evaluation context, SCT validation against a log's key
//! (for a certificate or a precertificate), printing, and the X.509 extensions that carry
//! SCT lists and the precertificate poison.
//!
//! The types are opaque in the headers; their layouts are OpenSSL's. A NULL object, which
//! OpenSSL reads through, fails or does nothing (docs/DEVIATIONS.md).

use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    BIO, CT_LOG_ENTRY_TYPE_NOT_SET, CT_LOG_ENTRY_TYPE_PRECERT, CT_LOG_ENTRY_TYPE_X509,
    CT_POLICY_EVAL_CTX, CT_R_INVALID_LOG_ID_LENGTH, CT_R_LOG_CONF_INVALID,
    CT_R_LOG_CONF_INVALID_KEY, CT_R_LOG_CONF_MISSING_DESCRIPTION, CT_R_LOG_CONF_MISSING_KEY,
    CT_R_LOG_KEY_INVALID, CT_R_SCT_FUTURE_TIMESTAMP, CT_R_SCT_INVALID, CT_R_SCT_INVALID_SIGNATURE,
    CT_R_SCT_LIST_INVALID, CT_R_SCT_LOG_ID_MISMATCH, CT_R_SCT_NOT_SET,
    CT_R_SCT_UNSUPPORTED_VERSION, CT_R_UNRECOGNIZED_SIGNATURE_NID, CT_R_UNSUPPORTED_ENTRY_TYPE,
    CT_R_UNSUPPORTED_VERSION, CTLOG, CTLOG_STORE, ERR_LIB_CT, ERR_R_CRYPTO_LIB, ERR_R_CT_LIB,
    ERR_R_EVP_LIB, ERR_R_PASSED_INVALID_ARGUMENT, EVP_PKEY, NID_ct_cert_scts,
    NID_ct_precert_poison, NID_ct_precert_scts, NID_ecdsa_with_SHA256, NID_sha256WithRSAEncryption,
    NID_undef, OSSL_LIB_CTX, SCT, SCT_SOURCE_OCSP_STAPLED_RESPONSE, SCT_SOURCE_TLS_EXTENSION,
    SCT_SOURCE_UNKNOWN, SCT_SOURCE_X509V3_EXTENSION, SCT_VALIDATION_STATUS_INVALID,
    SCT_VALIDATION_STATUS_NOT_SET, SCT_VALIDATION_STATUS_UNKNOWN_LOG,
    SCT_VALIDATION_STATUS_UNKNOWN_VERSION, SCT_VALIDATION_STATUS_UNVERIFIED,
    SCT_VALIDATION_STATUS_VALID, SCT_VERSION_NOT_SET, SCT_VERSION_V1, TLSEXT_hash_sha256,
    TLSEXT_signature_ecdsa, TLSEXT_signature_rsa, X509, X509_PUBKEY, X509V3_CTX, X509V3_EXT_METHOD,
    ct_log_entry_type_t, sct_source_t, sct_validation_status_t, sct_version_t, stack_st_SCT,
};
use rustyssl_pki::ct as core_ct;

use crate::asn1::string::{ASN1_OCTET_STRING_free, ASN1_STRING_get0_data};
use crate::asn1::time::{
    ASN1_GENERALIZEDTIME_adj, ASN1_GENERALIZEDTIME_print, ASN1_GENERALIZEDTIME_set_string,
};
use crate::asn1::tpl::items::{
    ASN1_NULL_it, ASN1_NULL_new, d2i_ASN1_OCTET_STRING, i2d_ASN1_OCTET_STRING,
};
use crate::bio::dump::BIO_hex_string;
use crate::bio::print::BIO_printf;
use crate::conf::{CONF_parse_list, NCONF_free, NCONF_get_string, NCONF_load, NCONF_new};
use crate::err;
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free};
use crate::evp::encode::EVP_DecodeBlock;
use crate::evp::md_ctx::{EVP_Digest, EVP_MD_CTX_free, EVP_MD_CTX_new};
use crate::evp::sigver::{EVP_DigestVerifyFinal, EVP_DigestVerifyInit_ex};
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::objects::OBJ_nid2ln;
use crate::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    OPENSSL_sk_value,
};
use crate::string::CRYPTO_strdup;
use crate::x509::cert::{
    X509_delete_ext, X509_dup, X509_free, X509_get_ext_by_NID, X509_get0_pubkey, X509_up_ref,
    i2d_X509, i2d_re_X509_tbs,
};
use crate::x509::ext::X509_EXTENSION_free;
use crate::x509::pubkey::{
    X509_PUBKEY_free, X509_PUBKEY_get, X509_PUBKEY_set, d2i_PUBKEY_ex, i2d_PUBKEY, i2d_X509_PUBKEY,
};
use crate::x509v3::registry::{Method, method};

/// `BIO_printf`'s result.
macro_rules! printf {
    ($bp:expr, $fmt:expr $(, $arg:expr)*) => {
        // SAFETY: a live BIO; a format with matching arguments.
        unsafe { BIO_printf($bp, $fmt.as_ptr() $(, $arg)*) }
    };
}

/// An empty C string, for `%*s` padding.
const E: *const c_char = c"".as_ptr();

fn raise(reason: c_int, f: &str) {
    err::raise(ERR_LIB_CT, reason, f);
}

/// A version 1 log identifier's length (`CT_V1_HASHLEN`).
const HASH_LEN: usize = core_ct::HASH_LEN;

// SCTs.

/// `struct sct_st`.
#[repr(C)]
pub(crate) struct Sct {
    version: sct_version_t,
    sct: *mut u8,
    sct_len: usize,
    log_id: *mut u8,
    log_id_len: usize,
    timestamp: u64,
    ext: *mut u8,
    ext_len: usize,
    hash_alg: u8,
    sig_alg: u8,
    sig: *mut u8,
    sig_len: usize,
    entry_type: ct_log_entry_type_t,
    source: sct_source_t,
    validation_status: sct_validation_status_t,
}

/// The SCT behind a pointer, or `None` for NULL.
///
/// # Safety
/// `p` is NULL or a live SCT no one else is using.
unsafe fn sct_of<'a>(p: *const SCT) -> Option<&'a mut Sct> {
    // SAFETY: the caller's guarantee; an SCT is an `Sct`.
    unsafe { p.cast::<Sct>().cast_mut().as_mut() }
}

/// The octets of a buffer the SCT holds (none for NULL).
fn held<'a>(p: *const u8, len: usize) -> &'a [u8] {
    if p.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: an SCT's buffer holds its length.
    unsafe { core::slice::from_raw_parts(p, len) }
}

/// `OPENSSL_memdup`: a C copy of `s` (NULL for none, or if it can't be made).
fn memdup(s: &[u8]) -> *mut u8 {
    let p = mem::alloc(s.len()).cast::<u8>();
    if !p.is_null() {
        // SAFETY: new and as long as `s`.
        unsafe { ptr::copy_nonoverlapping(s.as_ptr(), p, s.len()) };
    }
    p
}

/// Replaces a held buffer (freeing the old one).
fn replace(slot: &mut *mut u8, len: &mut usize, new: *mut u8, new_len: usize) {
    // SAFETY: the SCT's own buffer, or NULL.
    unsafe { mem::release(slot.cast()) };
    *slot = new;
    *len = new_len;
}

/// Copies `src` into a held buffer (none if empty): whether it could.
///
/// # Safety
/// `src` is NULL or holds `n` octets.
unsafe fn set1(slot: &mut *mut u8, len: &mut usize, src: *const u8, n: usize) -> bool {
    replace(slot, len, ptr::null_mut(), 0);
    if src.is_null() || n == 0 {
        return true;
    }
    // SAFETY: the caller's guarantee.
    let p = memdup(unsafe { core::slice::from_raw_parts(src, n) });
    if p.is_null() {
        return false;
    }
    *slot = p;
    *len = n;
    true
}

/// `SCT_get_signature_nid` of the algorithms.
fn signature_nid(version: sct_version_t, hash_alg: u8, sig_alg: u8) -> c_int {
    if version != SCT_VERSION_V1 || c_int::from(hash_alg) != TLSEXT_hash_sha256 {
        return NID_undef;
    }
    let sig = c_int::from(sig_alg);
    if sig == TLSEXT_signature_ecdsa {
        NID_ecdsa_with_SHA256
    } else if sig == TLSEXT_signature_rsa {
        NID_sha256WithRSAEncryption
    } else {
        NID_undef
    }
}

/// Whether the algorithms are a version 1 signature OpenSSL knows.
fn known(hash_alg: u8, sig_alg: u8) -> bool {
    signature_nid(SCT_VERSION_V1, hash_alg, sig_alg) != NID_undef
}

impl Sct {
    fn signature_is_complete(&self) -> bool {
        signature_nid(self.version, self.hash_alg, self.sig_alg) != NID_undef
            && !self.sig.is_null()
            && self.sig_len > 0
    }

    fn is_complete(&self) -> bool {
        match self.version {
            SCT_VERSION_NOT_SET => false,
            SCT_VERSION_V1 => !self.log_id.is_null() && self.signature_is_complete(),
            _ => !self.sct.is_null(),
        }
    }

    /// The core's view of it.
    fn to_core(&self) -> core_ct::Sct {
        core_ct::Sct {
            version: u8::try_from(self.version).unwrap_or(u8::MAX),
            raw: held(self.sct, self.sct_len).to_vec(),
            log_id: held(self.log_id, self.log_id_len).to_vec(),
            timestamp: self.timestamp,
            extensions: held(self.ext, self.ext_len).to_vec(),
            hash_alg: self.hash_alg,
            sig_alg: self.sig_alg,
            signature: held(self.sig, self.sig_len).to_vec(),
        }
    }
}

/// A new SCT from the core's, or NULL.
fn from_core(s: &core_ct::Sct) -> *mut SCT {
    // SAFETY: no preconditions.
    let p = unsafe { SCT_new() };
    // SAFETY: new.
    let Some(c) = (unsafe { sct_of(p) }) else {
        return ptr::null_mut();
    };
    c.version = sct_version_t::from(s.version);
    let mut ok = true;
    let mut put = |slot: &mut *mut u8, len: &mut usize, b: &[u8]| {
        if !b.is_empty() {
            let d = memdup(b);
            ok &= !d.is_null();
            replace(slot, len, d, if d.is_null() { 0 } else { b.len() });
        }
    };
    if s.version == core_ct::V1 {
        put(&mut c.log_id, &mut c.log_id_len, &s.log_id);
        c.timestamp = s.timestamp;
        put(&mut c.ext, &mut c.ext_len, &s.extensions);
        c.hash_alg = s.hash_alg;
        c.sig_alg = s.sig_alg;
        put(&mut c.sig, &mut c.sig_len, &s.signature);
    } else {
        put(&mut c.sct, &mut c.sct_len, &s.raw);
    }
    if !ok {
        // SAFETY: made above.
        unsafe { SCT_free(p) };
        return ptr::null_mut();
    }
    p
}

/// Raises the core's errors.
fn raise_all(errors: &[core_ct::Error], f: &str) {
    for e in errors {
        raise(
            match e {
                core_ct::Error::Invalid => CT_R_SCT_INVALID,
                core_ct::Error::InvalidSignature => CT_R_SCT_INVALID_SIGNATURE,
                core_ct::Error::ListInvalid => CT_R_SCT_LIST_INVALID,
            },
            f,
        );
    }
}

ffi_export! {
    /// A new SCT, its version and entry type not set, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn SCT_new() -> *mut SCT
    where failure = ptr::null_mut(), library = ERR_LIB_CT
    {
        let p = mem::alloc_zeroed(size_of::<Sct>()).cast::<SCT>();
        // SAFETY: new and zeroed (a valid `Sct`), or NULL.
        if let Some(c) = unsafe { sct_of(p) } {
            c.entry_type = CT_LOG_ENTRY_TYPE_NOT_SET;
            c.version = SCT_VERSION_NOT_SET;
        }
        p
    }
}

ffi_export! {
    /// Frees the SCT (nothing for NULL).
    ///
    /// # Safety
    /// `sct` is NULL or an SCT not used after.
    pub unsafe extern "C" fn SCT_free(sct: *mut SCT)
    where failure = (), library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { sct_of(sct) }) else { return };
        for p in [c.log_id, c.ext, c.sig, c.sct] {
            // SAFETY: its own buffers, or NULL.
            unsafe { mem::release(p.cast()) };
        }
        // SAFETY: made by `SCT_new`.
        unsafe { mem::release(sct.cast()) };
    }
}

/// `SCT_free` as a stack's free function.
unsafe extern "C" fn sct_free(p: *mut c_void) {
    // SAFETY: an SCT of the stack, which the stack owned.
    unsafe { SCT_free(p.cast()) };
}

ffi_export! {
    /// Frees the list and its SCTs (nothing for NULL).
    ///
    /// # Safety
    /// `a` is NULL or a list of SCTs not used after.
    pub unsafe extern "C" fn SCT_LIST_free(a: *mut stack_st_SCT)
    where failure = (), library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        unsafe { OPENSSL_sk_pop_free(a.cast(), Some(sct_free)) };
    }
}

ffi_export! {
    /// Sets the version: 1 for version 1, else 0 (`CT_R_UNSUPPORTED_VERSION`).
    ///
    /// # Safety
    /// `sct` is NULL or a live SCT.
    pub unsafe extern "C" fn SCT_set_version(sct: *mut SCT, version: sct_version_t) -> c_int
    where failure = 0, library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { sct_of(sct) }) else { return 0 };
        if version != SCT_VERSION_V1 {
            raise(CT_R_UNSUPPORTED_VERSION, "SCT_set_version");
            return 0;
        }
        c.version = version;
        c.validation_status = SCT_VALIDATION_STATUS_NOT_SET;
        1
    }
}

ffi_export! {
    /// Sets the log entry type (X.509 or precertificate): 1, or 0 (`CT_R_UNSUPPORTED_ENTRY_TYPE`).
    ///
    /// # Safety
    /// `sct` is NULL or a live SCT.
    pub unsafe extern "C" fn SCT_set_log_entry_type(sct: *mut SCT, entry_type: ct_log_entry_type_t) -> c_int
    where failure = 0, library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { sct_of(sct) }) else { return 0 };
        c.validation_status = SCT_VALIDATION_STATUS_NOT_SET;
        if entry_type == CT_LOG_ENTRY_TYPE_X509 || entry_type == CT_LOG_ENTRY_TYPE_PRECERT {
            c.entry_type = entry_type;
            return 1;
        }
        raise(CT_R_UNSUPPORTED_ENTRY_TYPE, "SCT_set_log_entry_type");
        0
    }
}

ffi_export! {
    /// Takes `log_id` (of `log_id_len` octets, 32 for version 1) as the log identifier: 1, or 0
    /// (`CT_R_INVALID_LOG_ID_LENGTH`, not taking it).
    ///
    /// # Safety
    /// `sct` is NULL or a live SCT; `log_id` is NULL or `OPENSSL_malloc`ed memory of the length.
    pub unsafe extern "C" fn SCT_set0_log_id(sct: *mut SCT, log_id: *mut c_uchar, log_id_len: usize) -> c_int
    where failure = 0, library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { sct_of(sct) }) else { return 0 };
        if c.version == SCT_VERSION_V1 && log_id_len != HASH_LEN {
            raise(CT_R_INVALID_LOG_ID_LENGTH, "SCT_set0_log_id");
            return 0;
        }
        replace(&mut c.log_id, &mut c.log_id_len, log_id, log_id_len);
        c.validation_status = SCT_VALIDATION_STATUS_NOT_SET;
        1
    }
}

ffi_export! {
    /// Copies the log identifier (none if NULL or empty): 1, or 0.
    ///
    /// # Safety
    /// `sct` is NULL or a live SCT; `log_id` is NULL or holds `log_id_len` octets.
    pub unsafe extern "C" fn SCT_set1_log_id(sct: *mut SCT, log_id: *const c_uchar, log_id_len: usize) -> c_int
    where failure = 0, library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { sct_of(sct) }) else { return 0 };
        if c.version == SCT_VERSION_V1 && log_id_len != HASH_LEN {
            raise(CT_R_INVALID_LOG_ID_LENGTH, "SCT_set1_log_id");
            return 0;
        }
        c.validation_status = SCT_VALIDATION_STATUS_NOT_SET;
        // SAFETY: as above.
        c_int::from(unsafe { set1(&mut c.log_id, &mut c.log_id_len, log_id, log_id_len) })
    }
}

ffi_export! {
    /// Sets the timestamp (milliseconds since the epoch).
    ///
    /// # Safety
    /// `sct` is NULL or a live SCT.
    pub unsafe extern "C" fn SCT_set_timestamp(sct: *mut SCT, timestamp: u64)
    where failure = (), library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { sct_of(sct) } {
            c.timestamp = timestamp;
            c.validation_status = SCT_VALIDATION_STATUS_NOT_SET;
        }
    }
}

ffi_export! {
    /// Sets the signature algorithms from `nid` (`sha256WithRSAEncryption` or
    /// `ecdsa-with-SHA256`): 1, or 0 (`CT_R_UNRECOGNIZED_SIGNATURE_NID`).
    ///
    /// # Safety
    /// `sct` is NULL or a live SCT.
    pub unsafe extern "C" fn SCT_set_signature_nid(sct: *mut SCT, nid: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { sct_of(sct) }) else { return 0 };
        let sig = if nid == NID_sha256WithRSAEncryption {
            TLSEXT_signature_rsa
        } else if nid == NID_ecdsa_with_SHA256 {
            TLSEXT_signature_ecdsa
        } else {
            raise(CT_R_UNRECOGNIZED_SIGNATURE_NID, "SCT_set_signature_nid");
            return 0;
        };
        c.hash_alg = u8::try_from(TLSEXT_hash_sha256).unwrap_or(0);
        c.sig_alg = u8::try_from(sig).unwrap_or(0);
        c.validation_status = SCT_VALIDATION_STATUS_NOT_SET;
        1
    }
}

ffi_export! {
    /// Takes `ext` as the extensions.
    ///
    /// # Safety
    /// `sct` is NULL or a live SCT; `ext` is NULL or `OPENSSL_malloc`ed memory of `ext_len`
    /// octets.
    pub unsafe extern "C" fn SCT_set0_extensions(sct: *mut SCT, ext: *mut c_uchar, ext_len: usize)
    where failure = (), library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { sct_of(sct) } {
            replace(&mut c.ext, &mut c.ext_len, ext, ext_len);
            c.validation_status = SCT_VALIDATION_STATUS_NOT_SET;
        }
    }
}

ffi_export! {
    /// Copies the extensions (none if NULL or empty): 1, or 0.
    ///
    /// # Safety
    /// `sct` is NULL or a live SCT; `ext` is NULL or holds `ext_len` octets.
    pub unsafe extern "C" fn SCT_set1_extensions(sct: *mut SCT, ext: *const c_uchar, ext_len: usize) -> c_int
    where failure = 0, library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { sct_of(sct) }) else { return 0 };
        c.validation_status = SCT_VALIDATION_STATUS_NOT_SET;
        // SAFETY: as above.
        c_int::from(unsafe { set1(&mut c.ext, &mut c.ext_len, ext, ext_len) })
    }
}

ffi_export! {
    /// Takes `sig` as the signature.
    ///
    /// # Safety
    /// `sct` is NULL or a live SCT; `sig` is NULL or `OPENSSL_malloc`ed memory of `sig_len`
    /// octets.
    pub unsafe extern "C" fn SCT_set0_signature(sct: *mut SCT, sig: *mut c_uchar, sig_len: usize)
    where failure = (), library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { sct_of(sct) } {
            replace(&mut c.sig, &mut c.sig_len, sig, sig_len);
            c.validation_status = SCT_VALIDATION_STATUS_NOT_SET;
        }
    }
}

ffi_export! {
    /// Copies the signature (none if NULL or empty): 1, or 0.
    ///
    /// # Safety
    /// `sct` is NULL or a live SCT; `sig` is NULL or holds `sig_len` octets.
    pub unsafe extern "C" fn SCT_set1_signature(sct: *mut SCT, sig: *const c_uchar, sig_len: usize) -> c_int
    where failure = 0, library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { sct_of(sct) }) else { return 0 };
        c.validation_status = SCT_VALIDATION_STATUS_NOT_SET;
        // SAFETY: as above.
        c_int::from(unsafe { set1(&mut c.sig, &mut c.sig_len, sig, sig_len) })
    }
}

/// The getters: a field of a live SCT, or the failure value for NULL.
macro_rules! getter {
    ($($(#[$doc:meta])* pub unsafe extern "C" fn $name:ident(sct: *const SCT) -> $ret:ty = $fail:expr, |$c:ident| $body:expr;)*) => {$(
        ffi_export! {
            $(#[$doc])*
            ///
            /// # Safety
            /// `sct` is NULL or a live SCT.
            pub unsafe extern "C" fn $name(sct: *const SCT) -> $ret
            where failure = $fail, library = ERR_LIB_CT
            {
                // SAFETY: the caller's guarantee.
                unsafe { sct_of(sct) }.map_or($fail, |$c| $body)
            }
        }
    )*};
}

getter! {
    /// The version (`SCT_VERSION_NOT_SET` for NULL).
    pub unsafe extern "C" fn SCT_get_version(sct: *const SCT) -> sct_version_t = SCT_VERSION_NOT_SET, |c| c.version;
    /// The log entry type (`CT_LOG_ENTRY_TYPE_NOT_SET` for NULL).
    pub unsafe extern "C" fn SCT_get_log_entry_type(sct: *const SCT) -> ct_log_entry_type_t = CT_LOG_ENTRY_TYPE_NOT_SET, |c| c.entry_type;
    /// The timestamp (0 for NULL).
    pub unsafe extern "C" fn SCT_get_timestamp(sct: *const SCT) -> u64 = 0, |c| c.timestamp;
    /// The signature's NID (`NID_undef` for unknown algorithms, or NULL).
    pub unsafe extern "C" fn SCT_get_signature_nid(sct: *const SCT) -> c_int = NID_undef, |c| signature_nid(c.version, c.hash_alg, c.sig_alg);
    /// Where the SCT came from (`SCT_SOURCE_UNKNOWN` for NULL).
    pub unsafe extern "C" fn SCT_get_source(sct: *const SCT) -> sct_source_t = SCT_SOURCE_UNKNOWN, |c| c.source;
    /// The result of its validation (`SCT_VALIDATION_STATUS_NOT_SET` for NULL).
    pub unsafe extern "C" fn SCT_get_validation_status(sct: *const SCT) -> sct_validation_status_t = SCT_VALIDATION_STATUS_NOT_SET, |c| c.validation_status;
}

/// The buffer getters: the length, with the buffer in `*out` (NULL and 0 for a NULL SCT).
macro_rules! buffer_getter {
    ($($(#[$doc:meta])* pub unsafe extern "C" fn $name:ident = $p:ident, $len:ident;)*) => {$(
        ffi_export! {
            $(#[$doc])*
            ///
            /// # Safety
            /// `sct` is NULL or a live SCT; `out` is writable.
            pub unsafe extern "C" fn $name(sct: *const SCT, out: *mut *mut c_uchar) -> usize
            where failure = 0, library = ERR_LIB_CT
            {
                // SAFETY: the caller's guarantee.
                let (p, n) = unsafe { sct_of(sct) }.map_or((ptr::null_mut(), 0), |c| (c.$p, c.$len));
                if !out.is_null() {
                    // SAFETY: as above.
                    unsafe { out.write(p) };
                }
                n
            }
        }
    )*};
}

buffer_getter! {
    /// The log identifier.
    pub unsafe extern "C" fn SCT_get0_log_id = log_id, log_id_len;
    /// The extensions.
    pub unsafe extern "C" fn SCT_get0_extensions = ext, ext_len;
    /// The signature.
    pub unsafe extern "C" fn SCT_get0_signature = sig, sig_len;
}

ffi_export! {
    /// Sets where the SCT came from, and from that the log entry type (X.509 for a TLS
    /// extension or OCSP response, precertificate for an X.509 extension): 1, or 0.
    ///
    /// # Safety
    /// `sct` is NULL or a live SCT.
    pub unsafe extern "C" fn SCT_set_source(sct: *mut SCT, source: sct_source_t) -> c_int
    where failure = 0, library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { sct_of(sct) }) else { return 0 };
        c.source = source;
        c.validation_status = SCT_VALIDATION_STATUS_NOT_SET;
        let entry = match source {
            SCT_SOURCE_TLS_EXTENSION | SCT_SOURCE_OCSP_STAPLED_RESPONSE => CT_LOG_ENTRY_TYPE_X509,
            SCT_SOURCE_X509V3_EXTENSION => CT_LOG_ENTRY_TYPE_PRECERT,
            _ => return 1,
        };
        // SAFETY: as above.
        unsafe { SCT_set_log_entry_type(sct, entry) }
    }
}

ffi_export! {
    /// The validation status as text ("valid", "unknown log", ...).
    ///
    /// # Safety
    /// `sct` is NULL or a live SCT.
    pub unsafe extern "C" fn SCT_validation_status_string(sct: *const SCT) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        let status = unsafe { SCT_get_validation_status(sct) };
        let s: &CStr = match status {
            SCT_VALIDATION_STATUS_NOT_SET => c"not set",
            SCT_VALIDATION_STATUS_UNKNOWN_VERSION => c"unknown version",
            SCT_VALIDATION_STATUS_UNKNOWN_LOG => c"unknown log",
            SCT_VALIDATION_STATUS_UNVERIFIED => c"unverified",
            SCT_VALIDATION_STATUS_INVALID => c"invalid",
            SCT_VALIDATION_STATUS_VALID => c"valid",
            _ => c"unknown status",
        };
        s.as_ptr()
    }
}

// Encodings.

/// The octets at `*pp` (`len` of them), after checking the pointers.
///
/// # Safety
/// `pp` is NULL or points to NULL or `len` readable octets.
unsafe fn input<'a>(pp: *mut *const c_uchar, len: usize) -> Option<&'a [u8]> {
    // SAFETY: the caller's guarantee.
    let p = unsafe { pp.as_ref() }.copied()?;
    if p.is_null() {
        return None;
    }
    // SAFETY: as above.
    Some(unsafe { core::slice::from_raw_parts(p, len) })
}

/// Advances `*pp` by `n` octets.
///
/// # Safety
/// As for [`input`], `n` being at most its length.
unsafe fn advance(pp: *mut *const c_uchar, n: usize) {
    // SAFETY: the caller's guarantee.
    let p = unsafe { pp.read() };
    // SAFETY: as above.
    let p = unsafe { p.add(n) };
    // SAFETY: as above.
    unsafe { pp.write(p) };
}

ffi_export! {
    /// Decodes an SCT from the `len` octets at `*in_` (all of them, advancing `*in_` past
    /// them), replacing `*psct` (if `psct`): the SCT, or NULL.
    ///
    /// # Safety
    /// `psct` is NULL or holds NULL or an SCT; `in_` points to `len` readable octets.
    pub unsafe extern "C" fn o2i_SCT(psct: *mut *mut SCT, in_: *mut *const c_uchar, len: usize) -> *mut SCT
    where failure = ptr::null_mut(), library = ERR_LIB_CT
    {
        const F: &str = "o2i_SCT";
        if len == 0 || len > core_ct::MAX_SIZE {
            raise(CT_R_SCT_INVALID, F);
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let Some(data) = (unsafe { input(in_, len) }) else { return ptr::null_mut() };
        let s = match core_ct::parse_sct(data, known) {
            Ok(s) => s,
            Err(errors) => {
                raise_all(&errors, F);
                return ptr::null_mut();
            }
        };
        let sct = from_core(&s);
        if sct.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        unsafe { advance(in_, len) };
        if !psct.is_null() {
            // SAFETY: the caller's slot.
            let old = unsafe { psct.read() };
            // SAFETY: its SCT, or NULL.
            unsafe { SCT_free(old) };
            // SAFETY: as above.
            unsafe { psct.write(sct) };
        }
        sct
    }
}

/// `i2o_SCT`'s output: the encoding written at `*out` (advancing it) or to a new buffer in
/// `*out`, or just its length.
///
/// # Safety
/// `out` is NULL or points to NULL or room for the encoding.
unsafe fn emit(enc: &[u8], out: *mut *mut c_uchar) -> c_int {
    let Ok(len) = c_int::try_from(enc.len()) else {
        return -1;
    };
    if out.is_null() {
        return len;
    }
    // SAFETY: the caller's guarantee.
    let p = unsafe { *out };
    if p.is_null() {
        let q = memdup(enc);
        if q.is_null() {
            return -1;
        }
        // SAFETY: as above.
        unsafe { out.write(q) };
    } else {
        // SAFETY: the caller's room for it.
        unsafe { ptr::copy_nonoverlapping(enc.as_ptr(), p, enc.len()) };
        // SAFETY: as above.
        let end = unsafe { p.add(enc.len()) };
        // SAFETY: as above.
        unsafe { out.write(end) };
    }
    len
}

ffi_export! {
    /// Encodes a complete SCT: its length (writing it as for `i2d_*`), or -1
    /// (`CT_R_SCT_NOT_SET`).
    ///
    /// # Safety
    /// `sct` is NULL or a live SCT; `out` is NULL or points to NULL or room for the encoding.
    pub unsafe extern "C" fn i2o_SCT(sct: *const SCT, out: *mut *mut c_uchar) -> c_int
    where failure = -1, library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { sct_of(sct) }) else { return -1 };
        if !c.is_complete() {
            raise(CT_R_SCT_NOT_SET, "i2o_SCT");
            return -1;
        }
        let enc = core_ct::encode_sct(&c.to_core());
        // SAFETY: as above.
        unsafe { emit(&enc, out) }
    }
}

ffi_export! {
    /// Decodes a list of SCTs from the `len` octets at `*pp` (advancing it), into `*a` (emptied
    /// first) if `a` holds one: the list, or NULL.
    ///
    /// # Safety
    /// `a` is NULL or holds NULL or a list of SCTs; `pp` points to `len` readable octets.
    pub unsafe extern "C" fn o2i_SCT_LIST(a: *mut *mut stack_st_SCT, pp: *mut *const c_uchar, len: usize) -> *mut stack_st_SCT
    where failure = ptr::null_mut(), library = ERR_LIB_CT
    {
        const F: &str = "o2i_SCT_LIST";
        if !(2..=core_ct::MAX_SIZE).contains(&len) {
            raise(CT_R_SCT_LIST_INVALID, F);
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let Some(data) = (unsafe { input(pp, len) }) else { return ptr::null_mut() };
        let (scts, failure) = match core_ct::parse_sct_list(data, known) {
            Ok(s) => (s, None),
            Err(e) => (e.parsed, Some((e.errors, e.consumed))),
        };
        // A mismatched list length fails before the list is touched.
        if let Some((errors, 2)) = &failure
            && scts.is_empty()
            && be16_mismatch(data)
        {
            raise_all(errors, F);
            // SAFETY: as above.
            unsafe { advance(pp, 2) };
            return ptr::null_mut();
        }
        // SAFETY: the caller's slot, or NULL.
        let existing = unsafe { a.as_ref() }.copied().unwrap_or(ptr::null_mut());
        let sk = if existing.is_null() {
            // SAFETY: no preconditions.
            let sk = unsafe { OPENSSL_sk_new_null() }.cast::<stack_st_SCT>();
            if sk.is_null() {
                return ptr::null_mut();
            }
            sk
        } else {
            loop {
                // SAFETY: the caller's list.
                let s = unsafe { OPENSSL_sk_pop(existing.cast()) };
                if s.is_null() {
                    break;
                }
                // SAFETY: an SCT the list owned.
                unsafe { SCT_free(s.cast()) };
            }
            existing
        };
        let mut ok = failure.is_none();
        for s in &scts {
            let sct = from_core(s);
            // SAFETY: the list; a new SCT.
            if sct.is_null() || unsafe { OPENSSL_sk_push(sk.cast(), sct.cast()) } == 0 {
                // SAFETY: made above, or NULL.
                unsafe { SCT_free(sct) };
                ok = false;
                break;
            }
        }
        if let Some((errors, consumed)) = failure {
            raise_all(&errors, F);
            // SAFETY: as above; within the input.
            unsafe { advance(pp, consumed) };
        } else if ok {
            // SAFETY: as above.
            unsafe { advance(pp, len) };
        }
        if !ok {
            if existing.is_null() {
                // SAFETY: made above.
                unsafe { SCT_LIST_free(sk) };
            }
            return ptr::null_mut();
        }
        if !a.is_null() && existing.is_null() {
            // SAFETY: the caller's slot.
            unsafe { a.write(sk) };
        }
        sk
    }
}

/// Whether the list's length field disagrees with its size.
fn be16_mismatch(data: &[u8]) -> bool {
    let n = data
        .first()
        .zip(data.get(1))
        .map(|(&h, &l)| usize::from(u16::from_be_bytes([h, l])));
    n != data.len().checked_sub(2)
}

ffi_export! {
    /// Encodes the list (each SCT complete): its length (writing it as for `i2d_*`), or -1.
    ///
    /// # Safety
    /// `a` is NULL or a live list of SCTs; `pp` is NULL or points to NULL or room for the
    /// encoding.
    pub unsafe extern "C" fn i2o_SCT_LIST(a: *const stack_st_SCT, pp: *mut *mut c_uchar) -> c_int
    where failure = -1, library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        let n = unsafe { OPENSSL_sk_num(a.cast()) };
        let mut encs = Vec::new();
        for i in 0..n {
            // SAFETY: an index within the list.
            let s = unsafe { OPENSSL_sk_value(a.cast(), i) }.cast::<SCT>();
            // SAFETY: a list's SCT.
            let complete = unsafe { sct_of(s) }.filter(|c| c.is_complete());
            let Some(c) = complete else {
                raise(CT_R_SCT_NOT_SET, "i2o_SCT");
                // SAFETY: the caller's slot, or NULL.
                if !pp.is_null() && unsafe { *pp }.is_null() {
                    raise(CT_R_SCT_LIST_INVALID, "i2o_SCT_LIST");
                }
                return -1;
            };
            encs.push(core_ct::encode_sct(&c.to_core()));
        }
        let Some(enc) = core_ct::encode_sct_list(&encs) else {
            // SAFETY: as above.
            if !pp.is_null() && unsafe { *pp }.is_null() {
                raise(CT_R_SCT_LIST_INVALID, "i2o_SCT_LIST");
            }
            return -1;
        };
        // SAFETY: as above.
        unsafe { emit(&enc, pp) }
    }
}

ffi_export! {
    /// Decodes a DER OCTET STRING holding a list of SCTs (advancing `*pp` by `len`): the list,
    /// or NULL.
    ///
    /// # Safety
    /// As for `o2i_SCT_LIST`, with `len` octets of DER at `*pp`.
    pub unsafe extern "C" fn d2i_SCT_LIST(a: *mut *mut stack_st_SCT, pp: *mut *const c_uchar, len: c_long) -> *mut stack_st_SCT
    where failure = ptr::null_mut(), library = ERR_LIB_CT
    {
        // SAFETY: the caller's slot.
        let Some(mut p) = (unsafe { pp.as_ref() }).copied() else { return ptr::null_mut() };
        // SAFETY: the caller's DER.
        let oct = unsafe { d2i_ASN1_OCTET_STRING(ptr::null_mut(), &raw mut p, len) };
        // SAFETY: the string, or NULL.
        let Some(o) = (unsafe { oct.as_ref() }) else { return ptr::null_mut() };
        let mut q = o.data.cast_const();
        let n = usize::try_from(o.length).unwrap_or(0);
        // SAFETY: the caller's slot; the string's octets.
        let sk = unsafe { o2i_SCT_LIST(a, &raw mut q, n) };
        if !sk.is_null()
            && let Ok(l) = usize::try_from(len)
        {
            // SAFETY: the caller's DER, `len` long.
            unsafe { advance(pp, l) };
        }
        // SAFETY: decoded above.
        unsafe { ASN1_OCTET_STRING_free(oct) };
        sk
    }
}

ffi_export! {
    /// Encodes the list as a DER OCTET STRING: its length (writing it as for `i2d_*`), or -1.
    ///
    /// # Safety
    /// As for `i2o_SCT_LIST`.
    pub unsafe extern "C" fn i2d_SCT_LIST(a: *const stack_st_SCT, out: *mut *mut c_uchar) -> c_int
    where failure = -1, library = ERR_LIB_CT
    {
        let mut data = ptr::null_mut();
        // SAFETY: the caller's list; a new buffer.
        let n = unsafe { i2o_SCT_LIST(a, &raw mut data) };
        if n == -1 {
            return -1;
        }
        // SAFETY: an all-zero string is an empty one.
        let mut oct: rustyssl_abi::ASN1_OCTET_STRING = unsafe { core::mem::zeroed() };
        oct.length = n;
        oct.type_ = rustyssl_abi::V_ASN1_OCTET_STRING;
        oct.data = data;
        // SAFETY: a string over the encoding; the caller's output.
        let len = unsafe { i2d_ASN1_OCTET_STRING(&raw const oct, out) };
        // SAFETY: made above.
        unsafe { mem::release(data.cast()) };
        len
    }
}

// Base64.

/// `ct_base64_decode`: the octets of a base64 string (`None` and 0 for an empty one), or -1.
///
/// # Safety
/// `in_` is a C string.
unsafe fn base64_decode(in_: *const c_char) -> Result<(*mut u8, usize), ()> {
    if in_.is_null() {
        return Err(());
    }
    // SAFETY: the caller's guarantee.
    let s = unsafe { CStr::from_ptr(in_) }.to_bytes();
    if s.is_empty() {
        return Ok((ptr::null_mut(), 0));
    }
    let cap = (s.len() / 4) * 3;
    let out = mem::alloc(cap).cast::<u8>();
    if out.is_null() {
        return Err(());
    }
    let Ok(inlen) = c_int::try_from(s.len()) else {
        // SAFETY: allocated above.
        unsafe { mem::release(out.cast()) };
        return Err(());
    };
    // SAFETY: room for the decoding of `s`.
    let n = unsafe { EVP_DecodeBlock(out, s.as_ptr(), inlen) };
    let Ok(mut n) = usize::try_from(n) else {
        raise(rustyssl_abi::CT_R_BASE64_DECODE_ERROR, "ct_base64_decode");
        // SAFETY: as above.
        unsafe { mem::release(out.cast()) };
        return Err(());
    };
    // The padding's octets aren't data.
    let pad = s.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 || pad > n {
        // SAFETY: as above.
        unsafe { mem::release(out.cast()) };
        return Err(());
    }
    n -= pad;
    Ok((out, n))
}

ffi_export! {
    /// A version 1 SCT from base64 parts: NULL (with an error) if any is bad.
    ///
    /// # Safety
    /// The strings are C strings.
    pub unsafe extern "C" fn SCT_new_from_base64(version: c_uchar, logid_base64: *const c_char, entry_type: ct_log_entry_type_t, timestamp: u64, extensions_base64: *const c_char, signature_base64: *const c_char) -> *mut SCT
    where failure = ptr::null_mut(), library = ERR_LIB_CT
    {
        const F: &str = "SCT_new_from_base64";
        // SAFETY: no preconditions.
        let sct = unsafe { SCT_new() };
        if sct.is_null() {
            raise(ERR_R_CT_LIB, F);
            return ptr::null_mut();
        }
        let fail = || {
            // SAFETY: made above.
            unsafe { SCT_free(sct) };
            ptr::null_mut()
        };
        // SAFETY: the SCT.
        if unsafe { SCT_set_version(sct, sct_version_t::from(version)) } == 0 {
            raise(rustyssl_abi::CT_R_SCT_UNSUPPORTED_VERSION, F);
            return fail();
        }
        // SAFETY: the caller's string.
        let Ok((dec, n)) = (unsafe { base64_decode(logid_base64) }) else {
            raise(rustyssl_abi::CT_R_BASE64_DECODE_ERROR, F);
            return fail();
        };
        // SAFETY: the SCT; a buffer it takes.
        if unsafe { SCT_set0_log_id(sct, dec, n) } == 0 {
            // SAFETY: not taken.
            unsafe { mem::release(dec.cast()) };
            return fail();
        }
        // SAFETY: as above.
        let Ok((dec, n)) = (unsafe { base64_decode(extensions_base64) }) else {
            raise(rustyssl_abi::CT_R_BASE64_DECODE_ERROR, F);
            return fail();
        };
        // SAFETY: as above.
        unsafe { SCT_set0_extensions(sct, dec, n) };
        // SAFETY: as above.
        let Ok((dec, n)) = (unsafe { base64_decode(signature_base64) }) else {
            raise(rustyssl_abi::CT_R_BASE64_DECODE_ERROR, F);
            return fail();
        };
        let ok = 'sig: {
            // SAFETY: the SCT, version 1.
            let Some(c) = (unsafe { sct_of(sct) }) else { break 'sig false };
            let mut s = c.to_core();
            match core_ct::parse_signature(&mut s, held(dec, n), known) {
                Ok(_) => {
                    c.hash_alg = s.hash_alg;
                    c.sig_alg = s.sig_alg;
                    // SAFETY: the signature's octets.
                    unsafe { set1(&mut c.sig, &mut c.sig_len, s.signature.as_ptr(), s.signature.len()) }
                }
                Err(e) => {
                    c.hash_alg = s.hash_alg;
                    c.sig_alg = s.sig_alg;
                    raise_all(&[e], "o2i_SCT_signature");
                    false
                }
            }
        };
        // SAFETY: decoded above.
        unsafe { mem::release(dec.cast()) };
        if !ok {
            return fail();
        }
        // SAFETY: the SCT.
        unsafe { SCT_set_timestamp(sct, timestamp) };
        // SAFETY: as above.
        if unsafe { SCT_set_log_entry_type(sct, entry_type) } == 0 {
            return fail();
        }
        sct
    }
}

// Logs.

/// `struct ctlog_st`.
#[repr(C)]
struct Log {
    libctx: *mut OSSL_LIB_CTX,
    propq: *mut c_char,
    name: *mut c_char,
    log_id: [u8; HASH_LEN],
    public_key: *mut EVP_PKEY,
}

/// The log behind a pointer.
///
/// # Safety
/// `p` is NULL or a live log.
unsafe fn log_of<'a>(p: *const CTLOG) -> Option<&'a mut Log> {
    // SAFETY: the caller's guarantee.
    unsafe { p.cast::<Log>().cast_mut().as_mut() }
}

/// A copy of `propq`, or NULL for NULL; `Err` if it can't be made.
///
/// # Safety
/// `propq` is NULL or a C string.
unsafe fn dup_propq(propq: *const c_char) -> Result<*mut c_char, ()> {
    if propq.is_null() {
        return Ok(ptr::null_mut());
    }
    // SAFETY: the caller's guarantee.
    let p = unsafe { CRYPTO_strdup(propq, ptr::null(), 0) };
    if p.is_null() { Err(()) } else { Ok(p) }
}

/// SHA-256 of `data` in `libctx` (`EVP_MD_fetch` of "SHA2-256"), or `None` (with
/// `ERR_R_EVP_LIB` if the digest can't be fetched and `raise_fetch`).
///
/// # Safety
/// `propq` is NULL or a C string.
unsafe fn sha256(
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
    data: &[u8],
    raise_fetch: bool,
) -> Option<[u8; 32]> {
    // SAFETY: a name; the caller's properties.
    let md = unsafe { EVP_MD_fetch(libctx, c"SHA2-256".as_ptr(), propq) };
    if md.is_null() {
        if raise_fetch {
            raise(ERR_R_EVP_LIB, "ct_v1_log_id_from_pkey");
        }
        return None;
    }
    let mut out = [0u8; 32];
    let none = ptr::null_mut();
    // SAFETY: the data; the digest's room; the digest.
    let ok = unsafe {
        EVP_Digest(
            data.as_ptr().cast(),
            data.len(),
            out.as_mut_ptr(),
            none,
            md,
            none.cast(),
        )
    };
    // SAFETY: fetched above.
    unsafe { EVP_MD_free(md) };
    (ok != 0).then_some(out)
}

/// A DER encoding made by an `i2d_*` into a new buffer, copied out.
fn der_of(f: impl FnOnce(*mut *mut c_uchar) -> c_int) -> Option<Vec<u8>> {
    let mut p = ptr::null_mut();
    let n = f(&raw mut p);
    let out = usize::try_from(n)
        .ok()
        .filter(|&n| n > 0)
        .map(|n| held(p, n).to_vec());
    // SAFETY: the buffer made, or NULL.
    unsafe { mem::release(p.cast()) };
    out
}

ffi_export! {
    /// A log named `name` with `public_key` (which it takes on success), its identifier the
    /// SHA-256 of the key's DER, or NULL.
    ///
    /// # Safety
    /// `public_key` is a live key; `name` and `propq` are NULL or C strings.
    pub unsafe extern "C" fn CTLOG_new_ex(public_key: *mut EVP_PKEY, name: *const c_char, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut CTLOG
    where failure = ptr::null_mut(), library = ERR_LIB_CT
    {
        let p = mem::alloc_zeroed(size_of::<Log>()).cast::<CTLOG>();
        // SAFETY: new and zeroed (a valid `Log`), or NULL.
        let Some(l) = (unsafe { log_of(p) }) else { return ptr::null_mut() };
        l.libctx = libctx;
        let ok = 'err: {
            // SAFETY: the caller's guarantee.
            let Ok(q) = (unsafe { dup_propq(propq) }) else { break 'err false };
            l.propq = q;
            if name.is_null() {
                break 'err false;
            }
            // SAFETY: as above.
            l.name = unsafe { CRYPTO_strdup(name, ptr::null(), 0) };
            if l.name.is_null() {
                break 'err false;
            }
            // SAFETY: the caller's key, for each.
            let Some(der) = der_of(|pp| unsafe { i2d_PUBKEY(public_key, pp) }) else {
                raise(CT_R_LOG_KEY_INVALID, "ct_v1_log_id_from_pkey");
                break 'err false;
            };
            // SAFETY: the log's properties.
            let Some(id) = (unsafe { sha256(libctx, l.propq, &der, true) }) else { break 'err false };
            l.log_id = id;
            l.public_key = public_key;
            true
        };
        if !ok {
            // SAFETY: made above, without the key.
            unsafe { CTLOG_free(p) };
            return ptr::null_mut();
        }
        p
    }
}

ffi_export! {
    /// `CTLOG_new_ex` in the default library context.
    ///
    /// # Safety
    /// As for `CTLOG_new_ex`.
    pub unsafe extern "C" fn CTLOG_new(public_key: *mut EVP_PKEY, name: *const c_char) -> *mut CTLOG
    where failure = ptr::null_mut(), library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        unsafe { CTLOG_new_ex(public_key, name, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Frees the log and its key (nothing for NULL).
    ///
    /// # Safety
    /// `log` is NULL or a log not used after.
    pub unsafe extern "C" fn CTLOG_free(log: *mut CTLOG)
    where failure = (), library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        let Some(l) = (unsafe { log_of(log) }) else { return };
        // SAFETY: its own.
        unsafe { mem::release(l.name.cast()) };
        // SAFETY: as above.
        unsafe { crate::evp::pkey::EVP_PKEY_free(l.public_key) };
        // SAFETY: as above.
        unsafe { mem::release(l.propq.cast()) };
        // SAFETY: made by `CTLOG_new_ex`.
        unsafe { mem::release(log.cast()) };
    }
}

/// `CTLOG_free` as a stack's free function.
unsafe extern "C" fn log_free(p: *mut c_void) {
    // SAFETY: a log of the stack, which the stack owned.
    unsafe { CTLOG_free(p.cast()) };
}

ffi_export! {
    /// Decodes a base64 SubjectPublicKeyInfo into a new log in `*ct_log`: 1, or 0.
    ///
    /// # Safety
    /// `ct_log` is NULL or writable; the strings are NULL or C strings.
    pub unsafe extern "C" fn CTLOG_new_from_base64_ex(ct_log: *mut *mut CTLOG, pkey_base64: *const c_char, name: *const c_char, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_CT
    {
        const F: &str = "CTLOG_new_from_base64_ex";
        if ct_log.is_null() {
            raise(ERR_R_PASSED_INVALID_ARGUMENT, F);
            return 0;
        }
        // SAFETY: the caller's string.
        let Ok((der, n)) = (unsafe { base64_decode(pkey_base64) }) else {
            raise(CT_R_LOG_CONF_INVALID_KEY, F);
            return 0;
        };
        let mut p = der.cast_const();
        let n = c_long::try_from(n).unwrap_or(0);
        // SAFETY: the decoded DER; the caller's properties.
        let pkey = unsafe { d2i_PUBKEY_ex(ptr::null_mut(), &raw mut p, n, libctx, propq) };
        // SAFETY: decoded above.
        unsafe { mem::release(der.cast()) };
        if pkey.is_null() {
            raise(CT_R_LOG_CONF_INVALID_KEY, F);
            return 0;
        }
        // SAFETY: the key; the caller's strings.
        let log = unsafe { CTLOG_new_ex(pkey, name, libctx, propq) };
        // SAFETY: the caller's slot.
        unsafe { ct_log.write(log) };
        if log.is_null() {
            // SAFETY: not taken.
            unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
            return 0;
        }
        1
    }
}

ffi_export! {
    /// `CTLOG_new_from_base64_ex` in the default library context.
    ///
    /// # Safety
    /// As for `CTLOG_new_from_base64_ex`.
    pub unsafe extern "C" fn CTLOG_new_from_base64(ct_log: *mut *mut CTLOG, pkey_base64: *const c_char, name: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        unsafe { CTLOG_new_from_base64_ex(ct_log, pkey_base64, name, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// The log's name (NULL for NULL).
    ///
    /// # Safety
    /// `log` is NULL or a live log.
    pub unsafe extern "C" fn CTLOG_get0_name(log: *const CTLOG) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        unsafe { log_of(log) }.map_or(ptr::null(), |l| l.name.cast_const())
    }
}

ffi_export! {
    /// The log's identifier (32 octets) in `*log_id` and `*log_id_len`.
    ///
    /// # Safety
    /// `log` is NULL or a live log; the outputs are writable.
    pub unsafe extern "C" fn CTLOG_get0_log_id(log: *const CTLOG, log_id: *mut *const u8, log_id_len: *mut usize)
    where failure = (), library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        let Some(l) = (unsafe { log_of(log) }) else { return };
        if !log_id.is_null() {
            // SAFETY: as above.
            unsafe { log_id.write(l.log_id.as_ptr()) };
        }
        if !log_id_len.is_null() {
            // SAFETY: as above.
            unsafe { log_id_len.write(HASH_LEN) };
        }
    }
}

ffi_export! {
    /// The log's public key (NULL for NULL).
    ///
    /// # Safety
    /// `log` is NULL or a live log.
    pub unsafe extern "C" fn CTLOG_get0_public_key(log: *const CTLOG) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        unsafe { log_of(log) }.map_or(ptr::null_mut(), |l| l.public_key)
    }
}

/// `struct ctlog_store_st`.
#[repr(C)]
struct Store {
    libctx: *mut OSSL_LIB_CTX,
    propq: *mut c_char,
    logs: *mut c_void,
}

/// The store behind a pointer.
///
/// # Safety
/// `p` is NULL or a live store.
unsafe fn store_of<'a>(p: *const CTLOG_STORE) -> Option<&'a mut Store> {
    // SAFETY: the caller's guarantee.
    unsafe { p.cast::<Store>().cast_mut().as_mut() }
}

ffi_export! {
    /// A new, empty log store, or NULL.
    ///
    /// # Safety
    /// `propq` is NULL or a C string.
    pub unsafe extern "C" fn CTLOG_STORE_new_ex(libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut CTLOG_STORE
    where failure = ptr::null_mut(), library = ERR_LIB_CT
    {
        let p = mem::alloc_zeroed(size_of::<Store>()).cast::<CTLOG_STORE>();
        // SAFETY: new and zeroed, or NULL.
        let Some(s) = (unsafe { store_of(p) }) else { return ptr::null_mut() };
        s.libctx = libctx;
        let ok = 'err: {
            // SAFETY: the caller's guarantee.
            let Ok(q) = (unsafe { dup_propq(propq) }) else { break 'err false };
            s.propq = q;
            // SAFETY: no preconditions.
            s.logs = unsafe { OPENSSL_sk_new_null() }.cast();
            if s.logs.is_null() {
                raise(ERR_R_CRYPTO_LIB, "CTLOG_STORE_new_ex");
                break 'err false;
            }
            true
        };
        if !ok {
            // SAFETY: made above.
            unsafe { CTLOG_STORE_free(p) };
            return ptr::null_mut();
        }
        p
    }
}

ffi_export! {
    /// `CTLOG_STORE_new_ex` in the default library context.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn CTLOG_STORE_new() -> *mut CTLOG_STORE
    where failure = ptr::null_mut(), library = ERR_LIB_CT
    {
        // SAFETY: no property query.
        unsafe { CTLOG_STORE_new_ex(ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Frees the store and its logs (nothing for NULL).
    ///
    /// # Safety
    /// `store` is NULL or a store not used after.
    pub unsafe extern "C" fn CTLOG_STORE_free(store: *mut CTLOG_STORE)
    where failure = (), library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { store_of(store) }) else { return };
        // SAFETY: its own.
        unsafe { mem::release(s.propq.cast()) };
        // SAFETY: as above.
        unsafe { OPENSSL_sk_pop_free(s.logs.cast(), Some(log_free)) };
        // SAFETY: made by `CTLOG_STORE_new_ex`.
        unsafe { mem::release(store.cast()) };
    }
}

ffi_export! {
    /// The store's first log whose identifier starts with the `log_id_len` octets at `log_id`
    /// (as OpenSSL compares; past 32, none), or NULL.
    ///
    /// # Safety
    /// `store` is NULL or a live store; `log_id` is NULL or holds `log_id_len` octets.
    pub unsafe extern "C" fn CTLOG_STORE_get0_log_by_id(store: *const CTLOG_STORE, log_id: *const u8, log_id_len: usize) -> *const CTLOG
    where failure = ptr::null(), library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { store_of(store) }) else { return ptr::null() };
        if log_id_len > HASH_LEN || (log_id.is_null() && log_id_len > 0) {
            return ptr::null();
        }
        let id = held(log_id, log_id_len);
        // SAFETY: its logs.
        for i in 0..unsafe { OPENSSL_sk_num(s.logs.cast()) } {
            // SAFETY: an index within them.
            let l = unsafe { OPENSSL_sk_value(s.logs.cast(), i) }.cast::<CTLOG>();
            // SAFETY: a log of the store.
            if unsafe { log_of(l) }.is_some_and(|l| l.log_id.starts_with(id)) {
                return l;
            }
        }
        ptr::null()
    }
}

/// `CTLOG_STORE_LOAD_CTX`.
struct LoadCtx {
    store: *mut CTLOG_STORE,
    conf: *mut rustyssl_abi::CONF,
    invalid_log_entries: usize,
}

ffi_callback! {
    /// `ctlog_store_load_log`: adds the log of the configuration's section `log_name` (a bad
    /// one counted): 1, or -1.
    ///
    /// # Safety
    /// `log_name` is NULL or holds `log_name_len` octets; `arg` is a [`LoadCtx`].
    pub(crate) unsafe extern "C" fn load_log(log_name: *const c_char, log_name_len: c_int, arg: *mut c_void) -> c_int
    where failure = -1, library = ERR_LIB_CT
    {
        if log_name.is_null() {
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { arg.cast::<LoadCtx>().as_mut() }) else { return -1 };
        let n = usize::try_from(log_name_len).unwrap_or(0);
        // SAFETY: as above.
        let name = unsafe { core::slice::from_raw_parts(log_name.cast::<u8>(), n) };
        let Ok(section) = std::ffi::CString::new(name) else { return -1 };
        // SAFETY: the store; the configuration; a section.
        let Some(log) = (unsafe { log_from_conf(ctx.store, ctx.conf, &section) }) else {
            ctx.invalid_log_entries += 1;
            return 1;
        };
        // SAFETY: the store.
        let Some(s) = (unsafe { store_of(ctx.store) }) else { return -1 };
        // SAFETY: its logs; a new log.
        if unsafe { OPENSSL_sk_push(s.logs.cast(), log.cast()) } == 0 {
            // SAFETY: not taken.
            unsafe { CTLOG_free(log) };
            raise(ERR_R_CRYPTO_LIB, "ctlog_store_load_log");
            return -1;
        }
        1
    }
}

/// `ctlog_new_from_conf`: the log of a section ("description" and "key"), or `None`.
///
/// # Safety
/// `store` is a live store; `conf` a live configuration.
unsafe fn log_from_conf(
    store: *mut CTLOG_STORE,
    conf: *mut rustyssl_abi::CONF,
    section: &CStr,
) -> Option<*mut CTLOG> {
    // SAFETY: the caller's guarantee.
    let description = unsafe { NCONF_get_string(conf, section.as_ptr(), c"description".as_ptr()) };
    if description.is_null() {
        raise(CT_R_LOG_CONF_MISSING_DESCRIPTION, "ctlog_new_from_conf");
        return None;
    }
    // SAFETY: as above.
    let key = unsafe { NCONF_get_string(conf, section.as_ptr(), c"key".as_ptr()) };
    if key.is_null() {
        raise(CT_R_LOG_CONF_MISSING_KEY, "ctlog_new_from_conf");
        return None;
    }
    // SAFETY: as above.
    let (libctx, propq) = unsafe { store_of(store) }
        .map_or((ptr::null_mut(), ptr::null_mut()), |s| (s.libctx, s.propq));
    let mut log = ptr::null_mut();
    // SAFETY: the configuration's strings; the store's properties.
    let ok = unsafe { CTLOG_new_from_base64_ex(&raw mut log, key, description, libctx, propq) };
    (ok == 1).then_some(log)
}

ffi_export! {
    /// Adds the logs of the configuration file `file` (its "enabled_logs" list of sections):
    /// 1, or 0 (`CT_R_LOG_CONF_INVALID`, also if any log is bad).
    ///
    /// # Safety
    /// `store` is NULL or a live store; `file` is NULL or a C string.
    pub unsafe extern "C" fn CTLOG_STORE_load_file(store: *mut CTLOG_STORE, file: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_CT
    {
        const F: &str = "CTLOG_STORE_load_file";
        if store.is_null() {
            return 0;
        }
        // SAFETY: the default method.
        let conf = unsafe { NCONF_new(ptr::null_mut()) };
        if conf.is_null() {
            return 0;
        }
        let ok = 'end: {
            // SAFETY: the configuration; the caller's file name; no line output.
            if unsafe { NCONF_load(conf, file, ptr::null_mut()) } <= 0 {
                raise(CT_R_LOG_CONF_INVALID, F);
                break 'end false;
            }
            // SAFETY: as above.
            let enabled = unsafe { NCONF_get_string(conf, ptr::null(), c"enabled_logs".as_ptr()) };
            if enabled.is_null() {
                raise(CT_R_LOG_CONF_INVALID, F);
                break 'end false;
            }
            let mut ctx = LoadCtx { store, conf, invalid_log_entries: 0 };
            // SAFETY: the list; the callback and its context.
            let r = unsafe { CONF_parse_list(enabled, c_int::from(b','), 1, Some(load_log), (&raw mut ctx).cast()) };
            if r == 0 || ctx.invalid_log_entries > 0 {
                raise(CT_R_LOG_CONF_INVALID, F);
                break 'end false;
            }
            true
        };
        // SAFETY: made above.
        unsafe { NCONF_free(conf) };
        c_int::from(ok)
    }
}

ffi_export! {
    /// Loads `$CTLOG_FILE`, or `OPENSSLDIR/ct_log_list.cnf`, as `CTLOG_STORE_load_file`.
    ///
    /// # Safety
    /// `store` is NULL or a live store.
    pub unsafe extern "C" fn CTLOG_STORE_load_default_file(store: *mut CTLOG_STORE) -> c_int
    where failure = 0, library = ERR_LIB_CT
    {
        let path = crate::init::safe_getenv(c"CTLOG_FILE").unwrap_or_else(|| {
            let mut p = crate::version::openssldir().to_bytes().to_vec();
            p.extend_from_slice(b"/ct_log_list.cnf");
            std::ffi::CString::new(p).unwrap_or_default()
        });
        // SAFETY: the caller's store; a C string.
        unsafe { CTLOG_STORE_load_file(store, path.as_ptr()) }
    }
}

// The policy evaluation context.

/// `struct ct_policy_eval_ctx_st`.
#[repr(C)]
struct PolicyCtx {
    cert: *mut X509,
    issuer: *mut X509,
    log_store: *mut CTLOG_STORE,
    epoch_time_in_ms: u64,
    libctx: *mut OSSL_LIB_CTX,
    propq: *mut c_char,
}

/// The context behind a pointer.
///
/// # Safety
/// `p` is NULL or a live context.
unsafe fn pctx_of<'a>(p: *const CT_POLICY_EVAL_CTX) -> Option<&'a mut PolicyCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { p.cast::<PolicyCtx>().cast_mut().as_mut() }
}

/// The clock drift tolerated for timestamps (`SCT_CLOCK_DRIFT_TOLERANCE`), in milliseconds.
const DRIFT_MS: u64 = 300_000;

ffi_export! {
    /// A new context, its time now plus five minutes, or NULL.
    ///
    /// # Safety
    /// `propq` is NULL or a C string.
    pub unsafe extern "C" fn CT_POLICY_EVAL_CTX_new_ex(libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut CT_POLICY_EVAL_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_CT
    {
        let p = mem::alloc_zeroed(size_of::<PolicyCtx>()).cast::<CT_POLICY_EVAL_CTX>();
        // SAFETY: new and zeroed, or NULL.
        let Some(c) = (unsafe { pctx_of(p) }) else { return ptr::null_mut() };
        c.libctx = libctx;
        // SAFETY: the caller's guarantee.
        let Ok(q) = (unsafe { dup_propq(propq) }) else {
            // SAFETY: made above.
            unsafe { mem::release(p.cast()) };
            return ptr::null_mut();
        };
        c.propq = q;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        c.epoch_time_in_ms = now.saturating_add(DRIFT_MS);
        p
    }
}

ffi_export! {
    /// `CT_POLICY_EVAL_CTX_new_ex` in the default library context.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn CT_POLICY_EVAL_CTX_new() -> *mut CT_POLICY_EVAL_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_CT
    {
        // SAFETY: no property query.
        unsafe { CT_POLICY_EVAL_CTX_new_ex(ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Frees the context and its certificates' references (nothing for NULL).
    ///
    /// # Safety
    /// `ctx` is NULL or a context not used after.
    pub unsafe extern "C" fn CT_POLICY_EVAL_CTX_free(ctx: *mut CT_POLICY_EVAL_CTX)
    where failure = (), library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { pctx_of(ctx) }) else { return };
        // SAFETY: its own references, or NULL.
        unsafe { X509_free(c.cert) };
        // SAFETY: as above.
        unsafe { X509_free(c.issuer) };
        // SAFETY: its own.
        unsafe { mem::release(c.propq.cast()) };
        // SAFETY: made by `CT_POLICY_EVAL_CTX_new_ex`.
        unsafe { mem::release(ctx.cast()) };
    }
}

ffi_export! {
    /// Sets the certificate the SCTs are for (with a reference; a previous one's reference is
    /// kept, as OpenSSL does): 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `cert` is NULL or a live certificate.
    pub unsafe extern "C" fn CT_POLICY_EVAL_CTX_set1_cert(ctx: *mut CT_POLICY_EVAL_CTX, cert: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { pctx_of(ctx) }) else { return 0 };
        // SAFETY: as above.
        if unsafe { X509_up_ref(cert) } == 0 {
            return 0;
        }
        c.cert = cert;
        1
    }
}

ffi_export! {
    /// Sets the certificate's issuer (with a reference, as for the certificate): 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `issuer` is NULL or a live certificate.
    pub unsafe extern "C" fn CT_POLICY_EVAL_CTX_set1_issuer(ctx: *mut CT_POLICY_EVAL_CTX, issuer: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { pctx_of(ctx) }) else { return 0 };
        // SAFETY: as above.
        if unsafe { X509_up_ref(issuer) } == 0 {
            return 0;
        }
        c.issuer = issuer;
        1
    }
}

ffi_export! {
    /// Sets the log store (not a reference).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `log_store` is NULL or a store that outlives its use.
    pub unsafe extern "C" fn CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE(ctx: *mut CT_POLICY_EVAL_CTX, log_store: *mut CTLOG_STORE)
    where failure = (), library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { pctx_of(ctx) } {
            c.log_store = log_store;
        }
    }
}

ffi_export! {
    /// Sets the time (milliseconds since the epoch) SCTs mustn't be later than.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn CT_POLICY_EVAL_CTX_set_time(ctx: *mut CT_POLICY_EVAL_CTX, time_in_ms: u64)
    where failure = (), library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { pctx_of(ctx) } {
            c.epoch_time_in_ms = time_in_ms;
        }
    }
}

ffi_export! {
    /// The certificate (NULL for none, or NULL).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn CT_POLICY_EVAL_CTX_get0_cert(ctx: *const CT_POLICY_EVAL_CTX) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        unsafe { pctx_of(ctx) }.map_or(ptr::null_mut(), |c| c.cert)
    }
}

ffi_export! {
    /// The issuer (NULL for none, or NULL).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn CT_POLICY_EVAL_CTX_get0_issuer(ctx: *const CT_POLICY_EVAL_CTX) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        unsafe { pctx_of(ctx) }.map_or(ptr::null_mut(), |c| c.issuer)
    }
}

ffi_export! {
    /// The log store (NULL for none, or NULL).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn CT_POLICY_EVAL_CTX_get0_log_store(ctx: *const CT_POLICY_EVAL_CTX) -> *const CTLOG_STORE
    where failure = ptr::null(), library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        unsafe { pctx_of(ctx) }.map_or(ptr::null(), |c| c.log_store.cast_const())
    }
}

ffi_export! {
    /// The time (0 for NULL).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn CT_POLICY_EVAL_CTX_get_time(ctx: *const CT_POLICY_EVAL_CTX) -> u64
    where failure = 0, library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        unsafe { pctx_of(ctx) }.map_or(0, |c| c.epoch_time_in_ms)
    }
}

// Validation.

/// `SCT_CTX`: what one SCT's signature is checked with.
struct SctCtx {
    pkey: *mut EVP_PKEY,
    pkeyhash: Option<[u8; 32]>,
    ihash: Option<[u8; 32]>,
    certder: Option<Vec<u8>>,
    preder: Option<Vec<u8>>,
    epoch_time_in_ms: u64,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
}

impl Drop for SctCtx {
    fn drop(&mut self) {
        // SAFETY: its own key, or NULL.
        unsafe { crate::evp::pkey::EVP_PKEY_free(self.pkey) };
    }
}

impl SctCtx {
    /// `ct_public_key_hash`: SHA-256 of the key's DER.
    fn key_hash(&self, pubkey: *mut X509_PUBKEY) -> Option<[u8; 32]> {
        // SAFETY: a live key, for each.
        let der = der_of(|pp| unsafe { i2d_X509_PUBKEY(pubkey, pp) })?;
        // SAFETY: the context's properties.
        unsafe { sha256(self.libctx, self.propq, &der, false) }
    }

    /// `SCT_CTX_set1_pubkey`: the log's key and its hash.
    fn set_pubkey(&mut self, pubkey: *mut X509_PUBKEY) -> bool {
        // SAFETY: a live key.
        let pkey = unsafe { X509_PUBKEY_get(pubkey) };
        if pkey.is_null() {
            return false;
        }
        let Some(h) = self.key_hash(pubkey) else {
            // SAFETY: the reference taken above.
            unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
            return false;
        };
        self.pkeyhash = Some(h);
        // SAFETY: its own key, or NULL.
        unsafe { crate::evp::pkey::EVP_PKEY_free(self.pkey) };
        self.pkey = pkey;
        true
    }

    /// `SCT_CTX_set1_cert` (no presigner): the certificate's DER, and the precertificate's TBS
    /// (without the SCT list or poison extension).
    ///
    /// # Safety
    /// `cert` is a live certificate.
    unsafe fn set_cert(&mut self, cert: *mut X509) -> bool {
        let get = |x: *mut X509, nid| {
            // SAFETY: a live certificate.
            let i = unsafe { X509_get_ext_by_NID(x, nid, -1) };
            // SAFETY: as above.
            let dup = i >= 0 && unsafe { X509_get_ext_by_NID(x, nid, i) } >= 0;
            (i, dup)
        };
        let (poison, poison_dup) = get(cert, NID_ct_precert_poison);
        if poison_dup {
            return false;
        }
        let mut certder = None;
        if poison == -1 {
            // SAFETY: the caller's certificate, for each.
            certder = der_of(|pp| unsafe { i2d_X509(cert, pp) });
            if certder.is_none() {
                return false;
            }
        }
        let (mut idx, sct_dup) = get(cert, NID_ct_precert_scts);
        if sct_dup || (idx >= 0 && poison >= 0) {
            return false;
        }
        if idx == -1 {
            idx = poison;
        }
        let mut preder = None;
        if idx >= 0 {
            // SAFETY: as above.
            let pretmp = unsafe { X509_dup(cert) };
            if pretmp.is_null() {
                return false;
            }
            // SAFETY: the copy; its extension at `idx`.
            let ext = unsafe { X509_delete_ext(pretmp, idx) };
            // SAFETY: the extension taken out.
            unsafe { X509_EXTENSION_free(ext) };
            // SAFETY: the copy, for each.
            preder = der_of(|pp| unsafe { i2d_re_X509_tbs(pretmp, pp) });
            // SAFETY: made above.
            unsafe { X509_free(pretmp) };
            if preder.is_none() {
                return false;
            }
        }
        self.certder = certder;
        self.preder = preder;
        true
    }

    /// `SCT_CTX_verify`: 1 if the SCT's signature verifies, else 0 (or a negative error).
    fn verify(&self, sct: &Sct) -> c_int {
        const F: &str = "SCT_CTX_verify";
        let precert = sct.entry_type == CT_LOG_ENTRY_TYPE_PRECERT;
        if !sct.is_complete()
            || self.pkey.is_null()
            || sct.entry_type == CT_LOG_ENTRY_TYPE_NOT_SET
            || (precert && self.ihash.is_none())
        {
            raise(CT_R_SCT_NOT_SET, F);
            return 0;
        }
        if sct.version != SCT_VERSION_V1 {
            raise(CT_R_SCT_UNSUPPORTED_VERSION, F);
            return 0;
        }
        let id = held(sct.log_id, sct.log_id_len);
        if self.pkeyhash.as_ref().map(<[u8; 32]>::as_slice) != Some(id) {
            raise(CT_R_SCT_LOG_ID_MISMATCH, F);
            return 0;
        }
        if sct.timestamp > self.epoch_time_in_ms {
            raise(CT_R_SCT_FUTURE_TIMESTAMP, F);
            return 0;
        }
        // SAFETY: no preconditions.
        let ctx = unsafe { EVP_MD_CTX_new() };
        if ctx.is_null() {
            return 0;
        }
        let ret = 'end: {
            let none = ptr::null_mut();
            // SAFETY: the context; a digest name; the properties; the log's key.
            if unsafe {
                EVP_DigestVerifyInit_ex(
                    ctx,
                    none,
                    c"SHA2-256".as_ptr(),
                    self.libctx,
                    self.propq,
                    self.pkey,
                    ptr::null(),
                )
            } == 0
            {
                break 'end 0;
            }
            let (entry, der) = if precert {
                (core_ct::EntryType::Precert, self.preder.as_deref())
            } else {
                (core_ct::EntryType::X509, self.certder.as_deref())
            };
            let Some(der) = der else { break 'end 0 };
            let ihash = self.ihash.as_ref().map_or(&[][..], <[u8; 32]>::as_slice);
            let data = core_ct::signed_data(&sct.to_core(), entry, ihash, der);
            // SAFETY: the context; the data.
            if unsafe {
                crate::evp::md_ctx::EVP_DigestUpdate(ctx, data.as_ptr().cast(), data.len())
            } == 0
            {
                break 'end 0;
            }
            // SAFETY: as above; the signature.
            let r = unsafe { EVP_DigestVerifyFinal(ctx, sct.sig, sct.sig_len) };
            if r == 0 {
                raise(CT_R_SCT_INVALID_SIGNATURE, F);
            }
            r
        };
        // SAFETY: made above.
        unsafe { EVP_MD_CTX_free(ctx) };
        ret
    }
}

/// An `X509_PUBKEY` of the key (`X509_PUBKEY_set`), freed on drop.
struct Pubkey(*mut X509_PUBKEY);

impl Drop for Pubkey {
    fn drop(&mut self) {
        // SAFETY: its own, or NULL.
        unsafe { X509_PUBKEY_free(self.0) };
    }
}

/// `X509_PUBKEY_set` of a key, or `None`.
///
/// # Safety
/// `pkey` is NULL or a live key.
unsafe fn pubkey_of(pkey: *mut EVP_PKEY) -> Option<Pubkey> {
    let mut p = Pubkey(ptr::null_mut());
    // SAFETY: a local slot; the caller's key.
    (unsafe { X509_PUBKEY_set(&raw mut p.0, pkey) } == 1).then_some(p)
}

ffi_export! {
    /// Validates the SCT against the context's certificate, issuer, log store, and time,
    /// setting its validation status: 1 if valid, 0 if not, or -1 for an error.
    ///
    /// # Safety
    /// `sct` is NULL or a live SCT; `ctx` is NULL or a live context.
    pub unsafe extern "C" fn SCT_validate(sct: *mut SCT, ctx: *const CT_POLICY_EVAL_CTX) -> c_int
    where failure = -1, library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        let (Some(s), Some(c)) = (unsafe { sct_of(sct) }, unsafe { pctx_of(ctx) }) else { return -1 };
        if s.version != SCT_VERSION_V1 {
            s.validation_status = SCT_VALIDATION_STATUS_UNKNOWN_VERSION;
            return 0;
        }
        // SAFETY: the context's store, or NULL; the SCT's identifier.
        let log = unsafe { CTLOG_STORE_get0_log_by_id(c.log_store, s.log_id, s.log_id_len) };
        if log.is_null() {
            s.validation_status = SCT_VALIDATION_STATUS_UNKNOWN_LOG;
            return 0;
        }
        let mut sctx = SctCtx {
            pkey: ptr::null_mut(),
            pkeyhash: None,
            ihash: None,
            certder: None,
            preder: None,
            epoch_time_in_ms: 0,
            libctx: c.libctx,
            propq: c.propq,
        };
        // SAFETY: the log's key.
        let key = unsafe { CTLOG_get0_public_key(log) };
        // SAFETY: the log's key.
        let Some(log_pkey) = (unsafe { pubkey_of(key) }) else { return -1 };
        if !sctx.set_pubkey(log_pkey.0) {
            return -1;
        }
        if s.entry_type == CT_LOG_ENTRY_TYPE_PRECERT {
            if c.issuer.is_null() {
                s.validation_status = SCT_VALIDATION_STATUS_UNVERIFIED;
                return 0;
            }
            // SAFETY: the issuer's key.
            let key = unsafe { X509_get0_pubkey(c.issuer) };
            // SAFETY: the issuer's key, or NULL.
            let Some(pub_) = (unsafe { pubkey_of(key) }) else { return -1 };
            let Some(h) = sctx.key_hash(pub_.0) else { return -1 };
            sctx.ihash = Some(h);
        }
        sctx.epoch_time_in_ms = c.epoch_time_in_ms;
        // SAFETY: the context's certificate, or NULL.
        s.validation_status = if c.cert.is_null() || !unsafe { sctx.set_cert(c.cert) } {
            SCT_VALIDATION_STATUS_UNVERIFIED
        } else if sctx.verify(s) == 1 {
            SCT_VALIDATION_STATUS_VALID
        } else {
            SCT_VALIDATION_STATUS_INVALID
        };
        c_int::from(s.validation_status == SCT_VALIDATION_STATUS_VALID)
    }
}

ffi_export! {
    /// Validates each SCT of the list: 1 if all are valid, 0 if any isn't, or the first error
    /// (negative).
    ///
    /// # Safety
    /// `scts` is NULL or a live list of SCTs; `ctx` is NULL or a live context.
    pub unsafe extern "C" fn SCT_LIST_validate(scts: *const stack_st_SCT, ctx: *mut CT_POLICY_EVAL_CTX) -> c_int
    where failure = -1, library = ERR_LIB_CT
    {
        let mut all = 1;
        // SAFETY: the caller's guarantee.
        for i in 0..unsafe { OPENSSL_sk_num(scts.cast()) } {
            // SAFETY: an index within the list.
            let s = unsafe { OPENSSL_sk_value(scts.cast(), i) }.cast::<SCT>();
            if s.is_null() {
                continue;
            }
            // SAFETY: a list's SCT; the caller's context.
            let v = unsafe { SCT_validate(s, ctx) };
            if v < 0 {
                return v;
            }
            all &= v;
        }
        all
    }
}

// Printing.

/// `BIO_hex_string` of a held buffer.
fn hex(out: *mut BIO, indent: c_int, p: *const u8, len: usize) {
    let n = c_int::try_from(len).unwrap_or(c_int::MAX);
    // SAFETY: a live BIO; the buffer.
    unsafe { BIO_hex_string(out, indent, 16, p.cast(), n) };
}

/// `timestamp_print`: the time as a GeneralizedTime with milliseconds, or nothing if it
/// can't be one.
fn timestamp_print(timestamp: u64, out: *mut BIO) {
    // SAFETY: no preconditions.
    let gtime = unsafe { crate::asn1::string::ASN1_GENERALIZEDTIME_new() };
    if gtime.is_null() {
        return;
    }
    // OpenSSL's `(int)` of the days, and the seconds of the day.
    let days = (timestamp / 86_400_000) & u64::from(u32::MAX);
    let days = u32::try_from(days).unwrap_or(0).cast_signed();
    let secs = c_long::try_from((timestamp % 86_400_000) / 1000).unwrap_or(0);
    // SAFETY: the time; offsets from the epoch.
    let adjusted = !unsafe { ASN1_GENERALIZEDTIME_adj(gtime, 0, days, secs) }.is_null();
    if adjusted {
        // SAFETY: its data, at least 14 octets once set.
        let d = unsafe { ASN1_STRING_get0_data(gtime.cast()) };
        // SAFETY: as above.
        let len = usize::try_from(unsafe { (*gtime).length }).unwrap_or(0);
        let digits = held(d, len.min(14));
        let mut s = digits.to_vec();
        s.extend_from_slice(format!(".{:03}Z", timestamp % 1000).as_bytes());
        if let Ok(c) = std::ffi::CString::new(s) {
            // SAFETY: the time; a C string.
            if unsafe { ASN1_GENERALIZEDTIME_set_string(gtime, c.as_ptr()) } != 0 {
                // SAFETY: a live BIO; the time.
                unsafe { ASN1_GENERALIZEDTIME_print(out, gtime) };
            }
        }
    }
    // SAFETY: made above.
    unsafe { crate::asn1::string::ASN1_GENERALIZEDTIME_free(gtime) };
}

ffi_export! {
    /// Prints the SCT at `indent` (with its log's name if `log_store` has the log).
    ///
    /// # Safety
    /// `sct` is NULL or a live SCT; `out` is a live BIO; `log_store` is NULL or a live store.
    pub unsafe extern "C" fn SCT_print(sct: *const SCT, out: *mut BIO, indent: c_int, log_store: *const CTLOG_STORE)
    where failure = (), library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { sct_of(sct) }) else { return };
        let log = if log_store.is_null() {
            ptr::null()
        } else {
            // SAFETY: as above.
            unsafe { CTLOG_STORE_get0_log_by_id(log_store, s.log_id, s.log_id_len) }
        };
        let i4 = indent.saturating_add(4);
        let i16 = indent.saturating_add(16);
        printf!(out, c"%*sSigned Certificate Timestamp:", indent, E);
        printf!(out, c"\n%*sVersion   : ", i4, E);
        if s.version != SCT_VERSION_V1 {
            printf!(out, c"unknown\n%*s", i16, E);
            hex(out, i16, s.sct, s.sct_len);
            return;
        }
        printf!(out, c"v1 (0x0)");
        if !log.is_null() {
            // SAFETY: the store's log.
            let name = unsafe { CTLOG_get0_name(log) };
            printf!(out, c"\n%*sLog       : %s", i4, E, name);
        }
        printf!(out, c"\n%*sLog ID    : ", i4, E);
        hex(out, i16, s.log_id, s.log_id_len);
        printf!(out, c"\n%*sTimestamp : ", i4, E);
        timestamp_print(s.timestamp, out);
        printf!(out, c"\n%*sExtensions: ", i4, E);
        if s.ext_len == 0 {
            printf!(out, c"none");
        } else {
            hex(out, i16, s.ext, s.ext_len);
        }
        printf!(out, c"\n%*sSignature : ", i4, E);
        let nid = signature_nid(s.version, s.hash_alg, s.sig_alg);
        if nid == NID_undef {
            printf!(out, c"%02X%02X", c_int::from(s.hash_alg), c_int::from(s.sig_alg));
        } else {
            // SAFETY: a NID.
            let ln = unsafe { OBJ_nid2ln(nid) };
            printf!(out, c"%s", ln);
        }
        printf!(out, c"\n%*s            ", i4, E);
        hex(out, i16, s.sig, s.sig_len);
    }
}

ffi_export! {
    /// Prints each SCT of the list, `separator` between them.
    ///
    /// # Safety
    /// `sct_list` is NULL or a live list of SCTs; `out` is a live BIO; `separator` is NULL or a
    /// C string; `log_store` is NULL or a live store.
    pub unsafe extern "C" fn SCT_LIST_print(sct_list: *const stack_st_SCT, out: *mut BIO, indent: c_int, separator: *const c_char, log_store: *const CTLOG_STORE)
    where failure = (), library = ERR_LIB_CT
    {
        // SAFETY: the caller's guarantee.
        let n = unsafe { OPENSSL_sk_num(sct_list.cast()) };
        for i in 0..n {
            // SAFETY: an index within the list.
            let s = unsafe { OPENSSL_sk_value(sct_list.cast(), i) }.cast::<SCT>();
            // SAFETY: a list's SCT; the caller's BIO and store.
            unsafe { SCT_print(s, out, indent, log_store) };
            if i < n - 1 {
                printf!(out, c"%s", separator);
            }
        }
    }
}

// The X.509 extensions.

/// Sets each SCT's source: whether all could be.
///
/// # Safety
/// `s` is NULL or a live list of SCTs.
unsafe fn set_source(s: *mut stack_st_SCT, source: sct_source_t) -> bool {
    // SAFETY: the caller's guarantee.
    (0..unsafe { OPENSSL_sk_num(s.cast()) }).all(|i| {
        // SAFETY: an index within the list.
        let sct = unsafe { OPENSSL_sk_value(s.cast(), i) }.cast::<SCT>();
        // SAFETY: a list's SCT.
        let r = unsafe { SCT_set_source(sct, source) };
        r == 1
    })
}

/// `x509_ext_d2i_SCT_LIST` and `ocsp_ext_d2i_SCT_LIST`: the list with its SCTs' source.
///
/// # Safety
/// As for `d2i_SCT_LIST`.
unsafe fn d2i_with_source(
    a: *mut c_void,
    pp: *mut *const c_uchar,
    len: c_long,
    source: sct_source_t,
) -> *mut c_void {
    let a = a.cast::<*mut stack_st_SCT>();
    // SAFETY: the caller's guarantee.
    let s = unsafe { d2i_SCT_LIST(a, pp, len) };
    // SAFETY: the list, or NULL.
    if !unsafe { set_source(s, source) } {
        // SAFETY: as above.
        unsafe { SCT_LIST_free(s) };
        if !a.is_null() {
            // SAFETY: the caller's slot.
            unsafe { a.write(ptr::null_mut()) };
        }
        return ptr::null_mut();
    }
    s.cast()
}

unsafe extern "C" fn ext_d2i_x509(
    a: *mut c_void,
    pp: *mut *const c_uchar,
    len: c_long,
) -> *mut c_void {
    // SAFETY: the method's caller's guarantee.
    unsafe { d2i_with_source(a, pp, len, SCT_SOURCE_X509V3_EXTENSION) }
}

unsafe extern "C" fn ext_d2i_ocsp(
    a: *mut c_void,
    pp: *mut *const c_uchar,
    len: c_long,
) -> *mut c_void {
    // SAFETY: as above.
    unsafe { d2i_with_source(a, pp, len, SCT_SOURCE_OCSP_STAPLED_RESPONSE) }
}

unsafe extern "C" fn ext_i2d(a: *const c_void, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: as above.
    unsafe { i2d_SCT_LIST(a.cast(), out) }
}

unsafe extern "C" fn ext_free(a: *mut c_void) {
    // SAFETY: as above.
    unsafe { SCT_LIST_free(a.cast()) };
}

unsafe extern "C" fn ext_i2r(
    _: *const X509V3_EXT_METHOD,
    list: *mut c_void,
    out: *mut BIO,
    indent: c_int,
) -> c_int {
    // SAFETY: as above.
    unsafe { SCT_LIST_print(list.cast(), out, indent, c"\n".as_ptr(), ptr::null()) };
    1
}

unsafe extern "C" fn i2s_poison(_: *const X509V3_EXT_METHOD, _: *mut c_void) -> *mut c_char {
    // SAFETY: a static string.
    unsafe { CRYPTO_strdup(c"NULL".as_ptr(), ptr::null(), 0) }
}

unsafe extern "C" fn s2i_poison(
    _: *const X509V3_EXT_METHOD,
    _: *mut X509V3_CTX,
    _: *const c_char,
) -> *mut c_void {
    // SAFETY: no preconditions.
    unsafe { ASN1_NULL_new() }.cast()
}

/// A method for an SCT list extension.
const fn scts(nid: c_int, d2i: rustyssl_abi::X509V3_EXT_D2I) -> Method {
    let mut m = method(nid, 0);
    m.ext_free = Some(ext_free);
    m.d2i = d2i;
    m.i2d = Some(ext_i2d);
    m.i2r = Some(ext_i2r);
    Method(m)
}

/// The precertificate SCTs extension (`ossl_v3_ct_scts[0]`).
pub(crate) static PRECERT_SCTS: Method = scts(NID_ct_precert_scts, Some(ext_d2i_x509));
/// The OCSP SCTs extension (`ossl_v3_ct_scts[2]`).
pub(crate) static CERT_SCTS: Method = scts(NID_ct_cert_scts, Some(ext_d2i_ocsp));
/// The precertificate poison (`ossl_v3_ct_scts[1]`): a NULL, printed as "NULL".
pub(crate) static POISON: Method = {
    let mut m = method(NID_ct_precert_poison, 0);
    m.it = Some(ASN1_NULL_it);
    m.i2s = Some(i2s_poison);
    m.s2i = Some(s2i_poison);
    Method(m)
};

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: the CT functions on NULL objects, which OpenSSL reads through.
    #[test]
    fn null_objects_are_refused() {
        let s = ptr::null_mut();
        // SAFETY: NULL objects, which they refuse.
        unsafe {
            assert_eq!(SCT_set_version(s, SCT_VERSION_V1), 0);
        }
        // SAFETY: as above.
        assert_eq!(unsafe { SCT_get_version(s) }, SCT_VERSION_NOT_SET);
        // SAFETY: as above.
        assert_eq!(unsafe { i2o_SCT(s, ptr::null_mut()) }, -1);
        // SAFETY: as above.
        assert_eq!(unsafe { SCT_validate(s, ptr::null()) }, -1);
        // SAFETY: as above.
        assert!(unsafe { CTLOG_get0_name(ptr::null()) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { CTLOG_STORE_get0_log_by_id(ptr::null(), ptr::null(), 0) }.is_null());
        // SAFETY: as above.
        assert_eq!(unsafe { CT_POLICY_EVAL_CTX_get_time(ptr::null()) }, 0);
    }

    /// docs/DEVIATIONS.md: a log identifier longer than 32 octets matches no log (OpenSSL
    /// reads past the log's).
    #[test]
    fn long_log_ids_match_nothing() {
        // SAFETY: a new store, freed below.
        let store = unsafe { CTLOG_STORE_new() };
        let id = [0u8; 40];
        // SAFETY: the store; the identifier.
        assert!(unsafe { CTLOG_STORE_get0_log_by_id(store, id.as_ptr(), 40) }.is_null());
        // SAFETY: made above.
        unsafe { CTLOG_STORE_free(store) };
    }
}
