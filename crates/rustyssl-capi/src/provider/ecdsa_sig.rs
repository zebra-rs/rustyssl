//! The default provider's ECDSA signatures (`ecdsa_sig.c`): `ECDSA` (sign and verify a digest,
//! and digest-sign and digest-verify a message with any digest) and the composite algorithms
//! `ECDSA-SHA256` and the others (a fixed digest, over a digest or a message).
//!
//! A signature's nonce is random (`ECDSA_sign_ex`) unless the `nonce-type` parameter asks for
//! RFC 6979's (1) or the digest-seeded one (any other value), which need a digest named
//! (`crate::ec::ecdsa::deterministic_sign`). The algorithm identifier is that of ECDSA with the
//! digest, for SHA-1, SHA-2 (but SHA-512/224 and SHA-512/256), and SHA-3; other digests have
//! none.
//!
//! The context follows OpenSSL's step for step: which calls reset what (an init keeps the
//! digest and its flags), the digest's checks and their errors, a known-answer test's setup
//! values (`kat`), which a copy refuses, and the empty properties a digest named through
//! parameters is fetched with.

use core::ffi::{CStr, c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    BIGNUM, EC_KEY, ERR_LIB_PROV, EVP_MD_CTX, EVP_PKEY_OP_SIGN, EVP_PKEY_OP_SIGNMSG,
    EVP_PKEY_OP_VERIFY, EVP_PKEY_OP_VERIFYMSG, NID_ecdsa_with_SHA1, NID_ecdsa_with_SHA3_224,
    NID_ecdsa_with_SHA3_256, NID_ecdsa_with_SHA3_384, NID_ecdsa_with_SHA3_512,
    NID_ecdsa_with_SHA224, NID_ecdsa_with_SHA256, NID_ecdsa_with_SHA384, NID_ecdsa_with_SHA512,
    NID_sha1, NID_sha3_224, NID_sha3_256, NID_sha3_384, NID_sha3_512, NID_sha224, NID_sha256,
    NID_sha384, NID_sha512, NID_sha512_224, NID_sha512_256, NID_undef, OSSL_DIGEST_NAME_SHA1,
    OSSL_DIGEST_NAME_SHA2_224, OSSL_DIGEST_NAME_SHA2_256, OSSL_DIGEST_NAME_SHA2_384,
    OSSL_DIGEST_NAME_SHA2_512, OSSL_DIGEST_NAME_SHA2_512_224, OSSL_DIGEST_NAME_SHA2_512_256,
    OSSL_DIGEST_NAME_SHA3_224, OSSL_DIGEST_NAME_SHA3_256, OSSL_DIGEST_NAME_SHA3_384,
    OSSL_DIGEST_NAME_SHA3_512, OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
    OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
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
    OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE, OSSL_LIB_CTX, OSSL_PARAM, OSSL_PARAM_OCTET_STRING,
    OSSL_PARAM_UNSIGNED_INTEGER, OSSL_PARAM_UTF8_STRING, OSSL_SIGNATURE_PARAM_ALGORITHM_ID,
    OSSL_SIGNATURE_PARAM_DIGEST, OSSL_SIGNATURE_PARAM_DIGEST_SIZE, OSSL_SIGNATURE_PARAM_KAT,
    OSSL_SIGNATURE_PARAM_NONCE_TYPE, OSSL_SIGNATURE_PARAM_PROPERTIES,
    OSSL_SIGNATURE_PARAM_SIGNATURE, PROV_R_DIGEST_NOT_ALLOWED, PROV_R_INVALID_DIGEST,
    PROV_R_NO_KEY_SET, PROV_R_XOF_DIGESTS_NOT_ALLOWED,
};
use rustyssl_asn1::objects;

use super::builtin::libctx_of;
use super::macs::{SIZE_T, boxed, context, is_empty, locate, unbox};
use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::bn::BN_clear_free;
use crate::ec::ecdsa::{
    ECDSA_sign_ex, ECDSA_sign_setup, ECDSA_size, ECDSA_verify, deterministic_sign,
};
use crate::ec::key::{EC_KEY_free, EC_KEY_up_ref};
use crate::err;
use crate::evp::digest::{EVP_MD_get_size, EVP_MD_get0_name, EVP_MD_is_a};
use crate::evp::md_ctx::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex2, EVP_DigestUpdate, EVP_MD_CTX_copy_ex, EVP_MD_CTX_free,
    EVP_MD_CTX_get_params, EVP_MD_CTX_new, EVP_MD_CTX_set_params, EVP_MD_gettable_ctx_params,
    EVP_MD_settable_ctx_params, EVP_MD_xof,
};
use crate::ffi::{bytes, ffi_callback};
use crate::mem;
use crate::params::{
    OSSL_PARAM_get_octet_string, OSSL_PARAM_get_size_t, OSSL_PARAM_get_uint,
    OSSL_PARAM_get_utf8_string, OSSL_PARAM_locate, OSSL_PARAM_set_octet_string,
    OSSL_PARAM_set_size_t, OSSL_PARAM_set_uint, OSSL_PARAM_set_utf8_string,
};
use crate::rsa::Md;

/// `OSSL_MAX_NAME_SIZE` and `OSSL_MAX_PROPQUERY_SIZE` (`internal/sizes.h`).
const MAX_NAME: usize = 50;
const MAX_PROPQUERY: usize = 256;

/// The size of an `unsigned int` parameter.
const UINT: usize = size_of::<c_uint>();

/// `ossl_digest_get_approved_nid`: the digests with a NID here.
const APPROVED_DIGESTS: [(c_int, &CStr); 11] = [
    (NID_sha1, OSSL_DIGEST_NAME_SHA1),
    (NID_sha224, OSSL_DIGEST_NAME_SHA2_224),
    (NID_sha256, OSSL_DIGEST_NAME_SHA2_256),
    (NID_sha384, OSSL_DIGEST_NAME_SHA2_384),
    (NID_sha512, OSSL_DIGEST_NAME_SHA2_512),
    (NID_sha512_224, OSSL_DIGEST_NAME_SHA2_512_224),
    (NID_sha512_256, OSSL_DIGEST_NAME_SHA2_512_256),
    (NID_sha3_224, OSSL_DIGEST_NAME_SHA3_224),
    (NID_sha3_256, OSSL_DIGEST_NAME_SHA3_256),
    (NID_sha3_384, OSSL_DIGEST_NAME_SHA3_384),
    (NID_sha3_512, OSSL_DIGEST_NAME_SHA3_512),
];

/// `ossl_DER_w_algorithmIdentifier_ECDSA_with_MD`'s digests and their signature OIDs.
const ECDSA_WITH_MD: [(c_int, c_int); 9] = [
    (NID_sha1, NID_ecdsa_with_SHA1),
    (NID_sha224, NID_ecdsa_with_SHA224),
    (NID_sha256, NID_ecdsa_with_SHA256),
    (NID_sha384, NID_ecdsa_with_SHA384),
    (NID_sha512, NID_ecdsa_with_SHA512),
    (NID_sha3_224, NID_ecdsa_with_SHA3_224),
    (NID_sha3_256, NID_ecdsa_with_SHA3_256),
    (NID_sha3_384, NID_ecdsa_with_SHA3_384),
    (NID_sha3_512, NID_ecdsa_with_SHA3_512),
];

/// `PROV_ECDSA_CTX`.
struct SigCtx {
    libctx: *mut OSSL_LIB_CTX,
    propq: Option<CString>,
    /// The key, with a reference this holds.
    ec: *mut EC_KEY,
    operation: c_int,
    flag_sigalg: bool,
    flag_allow_md: bool,
    /// The algorithm identifier of ECDSA with the digest (empty without one).
    aid: Vec<u8>,
    /// The digest's name as given (at most 49 octets).
    mdname: Vec<u8>,
    md: Option<Md>,
    mdctx: *mut EVP_MD_CTX,
    mdsize: usize,
    /// The signature a message verification checks.
    sig: Option<Vec<u8>>,
    /// A known-answer test's setup values (each a number this owns, or NULL).
    kinv: *mut BIGNUM,
    r: *mut BIGNUM,
    kattest: c_uint,
    nonce_type: c_uint,
}

impl Drop for SigCtx {
    fn drop(&mut self) {
        // SAFETY: the context this holds, or NULL.
        unsafe { EVP_MD_CTX_free(self.mdctx) };
        // SAFETY: the reference this holds, or NULL.
        unsafe { EC_KEY_free(self.ec) };
        // SAFETY: numbers this owns, or NULL.
        unsafe { BN_clear_free(self.kinv) };
        // SAFETY: as above.
        unsafe { BN_clear_free(self.r) };
    }
}

/// The context behind `vctx`.
///
/// # Safety
/// `vctx` is NULL or a live context from `ecdsa_newctx`.
unsafe fn ctx<'a>(vctx: *mut c_void) -> Option<&'a mut SigCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { context::<SigCtx>(vctx) }
}

/// Raises a provider error from `func`.
#[track_caller]
fn prov(reason: c_int, func: &str) {
    err::raise(ERR_LIB_PROV, reason, func);
}

/// Raises a provider error with text from `func`.
fn prov_text(reason: c_int, func: &str, text: &str) {
    err::raise_with_text(ERR_LIB_PROV, reason, func, text);
}

/// A name as text (lossy only for invalid UTF-8, which only error texts show).
fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// `ossl_digest_get_approved_nid`.
///
/// # Safety
/// `md` is a live digest.
unsafe fn approved_nid(md: &Md) -> c_int {
    APPROVED_DIGESTS
        .iter()
        // SAFETY: the digest; a static name.
        .find(|(_, name)| unsafe { EVP_MD_is_a(md.ptr(), name.as_ptr()) } != 0)
        .map_or(NID_undef, |&(nid, _)| nid)
}

/// A DER element (the identifiers here are short).
fn der(tag: u8, content: &[u8]) -> Option<Vec<u8>> {
    let mut out = vec![tag, u8::try_from(content.len()).ok().filter(|&l| l < 0x80)?];
    out.extend_from_slice(content);
    Some(out)
}

/// `ossl_DER_w_algorithmIdentifier_ECDSA_with_MD`: `SEQUENCE { OID }` (no parameters), for the
/// digests with one.
fn ecdsa_aid(md_nid: c_int) -> Option<Vec<u8>> {
    let (_, sig) = ECDSA_WITH_MD.iter().find(|(md, _)| *md == md_nid)?;
    der(0x30, &der(0x06, objects::object(*sig)?.der)?)
}

impl SigCtx {
    /// `ecdsa_setup_md`: the digest `mdname` (with `mdprops`, or the context's query), checked.
    fn setup_md(&mut self, mdname: &CStr, mdprops: Option<&CStr>) -> bool {
        const F: &str = "ecdsa_setup_md";
        let name = mdname.to_bytes();
        if name.len() >= MAX_NAME {
            prov_text(
                PROV_R_INVALID_DIGEST,
                F,
                &format!("{} exceeds name buffer length", text(name)),
            );
            return false;
        }
        let props = mdprops.map_or_else(
            || self.propq.as_deref().map_or(ptr::null(), CStr::as_ptr),
            CStr::as_ptr,
        );
        // SAFETY: the context's library context; a name and a query.
        let Some(md) = (unsafe { Md::fetch(self.libctx, mdname, props) }) else {
            prov_text(
                PROV_R_INVALID_DIGEST,
                F,
                &format!("{} could not be fetched", text(name)),
            );
            return false;
        };
        // SAFETY: the digest.
        let md_size = unsafe { EVP_MD_get_size(md.ptr()) };
        let Some(mdsize) = usize::try_from(md_size).ok().filter(|&s| s > 0) else {
            prov_text(
                PROV_R_INVALID_DIGEST,
                F,
                &format!("{} has invalid md size {md_size}", text(name)),
            );
            return false;
        };
        // SAFETY: the digest.
        let md_nid = unsafe { approved_nid(&md) };
        // SAFETY: the digest.
        if unsafe { EVP_MD_xof(md.ptr()) } != 0 {
            prov(PROV_R_XOF_DIGESTS_NOT_ALLOWED, F);
            return false;
        }
        if !self.flag_allow_md {
            if !self.mdname.is_empty() {
                let current = CString::new(self.mdname.clone()).unwrap_or_default();
                // SAFETY: the digest; a string.
                if unsafe { EVP_MD_is_a(md.ptr(), current.as_ptr()) } == 0 {
                    prov_text(
                        PROV_R_DIGEST_NOT_ALLOWED,
                        F,
                        &format!("digest {} != {}", text(name), text(&self.mdname)),
                    );
                    return false;
                }
            }
            return true;
        }
        // SAFETY: the context this holds, or NULL.
        unsafe { EVP_MD_CTX_free(self.mdctx) };
        self.mdctx = ptr::null_mut();
        self.aid = if md_nid == NID_undef {
            Vec::new()
        } else {
            ecdsa_aid(md_nid).unwrap_or_default()
        };
        self.md = Some(md);
        self.mdsize = mdsize;
        self.mdname = name.to_vec();
        true
    }
}

ffi_callback! {
    /// `ecdsa_newctx`.
    ///
    /// # Safety
    /// `provctx` is the default provider's context; `propq` is NULL or a string.
    pub(crate) unsafe extern "C" fn ecdsa_newctx(provctx: *mut c_void, propq: *const c_char) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        boxed(SigCtx {
            // SAFETY: the caller's guarantee.
            libctx: unsafe { libctx_of(provctx) },
            // SAFETY: the caller's guarantee.
            propq: (!propq.is_null()).then(|| unsafe { CStr::from_ptr(propq) }.to_owned()),
            ec: ptr::null_mut(),
            operation: 0,
            flag_sigalg: false,
            flag_allow_md: true,
            aid: Vec::new(),
            mdname: Vec::new(),
            md: None,
            mdctx: ptr::null_mut(),
            mdsize: 0,
            sig: None,
            kinv: ptr::null_mut(),
            r: ptr::null_mut(),
            kattest: 0,
            nonce_type: 0,
        })
    }
}

/// Which `set_ctx_params` an init applies.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Setter {
    Normal,
    Sigalg,
}

/// `ecdsa_signverify_init`: the key (or the one the context has), the operation, and the
/// parameters.
///
/// # Safety
/// `vctx` is NULL or a live context; `vec` is NULL or a live EC key; `params` is NULL or an
/// array.
unsafe fn signverify_init(
    vctx: *mut c_void,
    vec: *mut c_void,
    setter: Setter,
    params: *const OSSL_PARAM,
    operation: c_int,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx(vctx) }) else {
        return 0;
    };
    if vec.is_null() && c.ec.is_null() {
        prov(PROV_R_NO_KEY_SET, "ecdsa_signverify_init");
        return 0;
    }
    if !vec.is_null() {
        // SAFETY: the caller's live key.
        if unsafe { EC_KEY_up_ref(vec.cast()) } == 0 {
            return 0;
        }
        // SAFETY: the reference the context held, or NULL.
        unsafe { EC_KEY_free(c.ec) };
        c.ec = vec.cast();
    }
    c.operation = operation;
    match setter {
        // SAFETY: the caller's guarantee.
        Setter::Normal => unsafe { ecdsa_set_ctx_params(vctx, params) },
        // SAFETY: the caller's guarantee.
        Setter::Sigalg => unsafe { ecdsa_sigalg_set_ctx_params(vctx, params) },
    }
}

ffi_callback! {
    /// `ecdsa_sign_init`.
    ///
    /// # Safety
    /// As for `signverify_init`.
    pub(crate) unsafe extern "C" fn ecdsa_sign_init(vctx: *mut c_void, vec: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { signverify_init(vctx, vec, Setter::Normal, params, EVP_PKEY_OP_SIGN) }
    }
}

ffi_callback! {
    /// `ecdsa_verify_init`.
    ///
    /// # Safety
    /// As for `signverify_init`.
    pub(crate) unsafe extern "C" fn ecdsa_verify_init(vctx: *mut c_void, vec: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { signverify_init(vctx, vec, Setter::Normal, params, EVP_PKEY_OP_VERIFY) }
    }
}

/// `ecdsa_sign_directly`: `tbs` (a digest of the digest's size when one is set) signed into
/// `sig`, or just the size for NULL `sig`.
///
/// # Safety
/// `sig` is NULL or has room for `sigsize` octets; `siglen` is writable; `tbs` holds `tbslen`
/// octets.
unsafe fn sign_directly(
    c: &mut SigCtx,
    sig: *mut c_uchar,
    siglen: *mut usize,
    sigsize: usize,
    tbs: *const c_uchar,
    tbslen: usize,
) -> c_int {
    // SAFETY: the context's key, or NULL.
    let ecsize = usize::try_from(unsafe { ECDSA_size(c.ec) }).unwrap_or(0);
    if sig.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { siglen.write(ecsize) };
        return 1;
    }
    if c.kattest != 0 {
        // SAFETY: the context's key; its own setup values (NULL or numbers it owns).
        let setup =
            unsafe { ECDSA_sign_setup(c.ec, ptr::null_mut(), &raw mut c.kinv, &raw mut c.r) };
        if setup == 0 {
            return 0;
        }
    }
    if sigsize < ecsize {
        return 0;
    }
    if c.mdsize != 0 && tbslen != c.mdsize {
        return 0;
    }
    // OpenSSL passes the length as an int, cut short past INT_MAX; this fails instead.
    let Ok(dlen) = c_int::try_from(tbslen) else {
        return 0;
    };
    let mut sltmp: c_uint = 0;
    if c.nonce_type != 0 {
        // SAFETY: the caller's guarantee.
        let Some(dgst) = (unsafe { bytes(tbs, tbslen) }) else {
            return 0;
        };
        let mdname =
            (!c.mdname.is_empty()).then(|| CString::new(c.mdname.clone()).unwrap_or_default());
        let propq = c.propq.as_deref().map_or(ptr::null(), CStr::as_ptr);
        // SAFETY: the caller's room for the signature (at least the key's size); the key; the
        // context's library context and query.
        match unsafe {
            deterministic_sign(
                dgst,
                sig,
                c.ec,
                c.nonce_type,
                mdname.as_deref(),
                c.libctx,
                propq,
            )
        } {
            Some(n) => sltmp = n,
            None => return 0,
        }
    } else {
        // SAFETY: the caller's digest and room; the key; the context's setup values.
        if unsafe { ECDSA_sign_ex(0, tbs, dlen, sig, &raw mut sltmp, c.kinv, c.r, c.ec) } <= 0 {
            return 0;
        }
    }
    // SAFETY: the caller's guarantee.
    unsafe { siglen.write(sltmp as usize) };
    1
}

ffi_callback! {
    /// `ecdsa_signverify_message_update`.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `data` holds `datalen` octets.
    pub(crate) unsafe extern "C" fn ecdsa_signverify_message_update(vctx: *mut c_void, data: *const c_uchar, datalen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        // SAFETY: the context's digest context, or NULL; the caller's data.
        unsafe { EVP_DigestUpdate(c.mdctx, data.cast(), datalen) }
    }
}

/// The message's digest, finishing the digest context.
fn finish_digest(c: &mut SigCtx) -> Option<([u8; 64], usize)> {
    let mut digest = [0u8; 64];
    let mut dlen: c_uint = 0;
    // SAFETY: the context's digest context; room for any digest.
    if unsafe { EVP_DigestFinal_ex(c.mdctx, digest.as_mut_ptr(), &raw mut dlen) } != 1 {
        return None;
    }
    Some((digest, usize::try_from(dlen).ok()?))
}

ffi_callback! {
    /// `ecdsa_sign_message_final`: the message's digest signed (only the size for NULL `sig`).
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `sig` is NULL or has room for `sigsize` octets;
    /// `siglen` is writable.
    pub(crate) unsafe extern "C" fn ecdsa_sign_message_final(vctx: *mut c_void, sig: *mut c_uchar, siglen: *mut usize, sigsize: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if c.mdctx.is_null() {
            return 0;
        }
        let (digest, dlen) = if sig.is_null() {
            ([0u8; 64], 0)
        } else {
            let Some(d) = finish_digest(c) else { return 0 };
            d
        };
        // SAFETY: the caller's guarantee; the digest's octets.
        unsafe { sign_directly(c, sig, siglen, sigsize, digest.as_ptr(), dlen) }
    }
}

ffi_callback! {
    /// `ecdsa_sign`: a one-shot signature, of a digest (or, after a message init, a message).
    ///
    /// # Safety
    /// `vctx` is a live context; `sig` is NULL or has room for `sigsize` octets; `siglen` is
    /// writable; `tbs` holds `tbslen` octets.
    pub(crate) unsafe extern "C" fn ecdsa_sign(vctx: *mut c_void, sig: *mut c_uchar, siglen: *mut usize, sigsize: usize, tbs: *const c_uchar, tbslen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if c.operation == EVP_PKEY_OP_SIGNMSG {
            // A size query doesn't take the input.
            // SAFETY: the caller's guarantee.
            if !sig.is_null() && unsafe { ecdsa_signverify_message_update(vctx, tbs, tbslen) } <= 0 {
                return 0;
            }
            // SAFETY: as above.
            return unsafe { ecdsa_sign_message_final(vctx, sig, siglen, sigsize) };
        }
        // SAFETY: as above.
        unsafe { sign_directly(c, sig, siglen, sigsize, tbs, tbslen) }
    }
}

/// `ecdsa_verify_directly`: `ECDSA_verify` of `tbs` (a digest of the digest's size when one is
/// set).
///
/// # Safety
/// `sig` holds `siglen` octets; `tbs` holds `tbslen`.
unsafe fn verify_directly(
    c: &SigCtx,
    sig: *const c_uchar,
    siglen: usize,
    tbs: *const c_uchar,
    tbslen: usize,
) -> c_int {
    if c.mdsize != 0 && tbslen != c.mdsize {
        return 0;
    }
    // OpenSSL passes the lengths as ints, cut short past INT_MAX; this fails instead.
    let (Ok(dlen), Ok(slen)) = (c_int::try_from(tbslen), c_int::try_from(siglen)) else {
        return 0;
    };
    // SAFETY: the caller's guarantee; the context's key.
    unsafe { ECDSA_verify(0, tbs, dlen, sig, slen, c.ec) }
}

/// `ecdsa_verify_set_sig`: the signature a message verification checks.
///
/// # Safety
/// `vctx` is a live context; `sig` holds `siglen` octets.
unsafe fn verify_set_sig(vctx: *mut c_void, sig: *const c_uchar, siglen: usize) -> c_int {
    // SAFETY: a parameter over the caller's signature, which outlives the call.
    let params = [
        unsafe {
            crate::params::OSSL_PARAM_construct_octet_string(
                OSSL_SIGNATURE_PARAM_SIGNATURE.as_ptr(),
                sig.cast_mut().cast(),
                siglen,
            )
        },
        crate::params::end(),
    ];
    // SAFETY: the caller's context; the array.
    unsafe { ecdsa_sigalg_set_ctx_params(vctx, params.as_ptr()) }
}

ffi_callback! {
    /// `ecdsa_verify_message_final`: the stored signature checked against the message's digest.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context.
    pub(crate) unsafe extern "C" fn ecdsa_verify_message_final(vctx: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if c.mdctx.is_null() {
            return 0;
        }
        let Some((digest, dlen)) = finish_digest(c) else { return 0 };
        let (s, n) = c.sig.as_deref().map_or((ptr::null(), 0), |s| (s.as_ptr(), s.len()));
        // SAFETY: the context's signature, or none; the digest.
        unsafe { verify_directly(c, s, n, digest.as_ptr(), dlen) }
    }
}

ffi_callback! {
    /// `ecdsa_verify`: a one-shot verification, of a digest (or, after a message init, a
    /// message).
    ///
    /// # Safety
    /// `vctx` is a live context; `sig` holds `siglen` octets; `tbs` holds `tbslen`.
    pub(crate) unsafe extern "C" fn ecdsa_verify(vctx: *mut c_void, sig: *const c_uchar, siglen: usize, tbs: *const c_uchar, tbslen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if c.operation == EVP_PKEY_OP_VERIFYMSG {
            // SAFETY: the caller's guarantee.
            if unsafe { verify_set_sig(vctx, sig, siglen) } <= 0 {
                return 0;
            }
            // SAFETY: as above.
            if unsafe { ecdsa_signverify_message_update(vctx, tbs, tbslen) } <= 0 {
                return 0;
            }
            // SAFETY: as above.
            return unsafe { ecdsa_verify_message_final(vctx) };
        }
        // SAFETY: as above.
        unsafe { verify_directly(c, sig, siglen, tbs, tbslen) }
    }
}

/// Starts the digest context with the context's digest (freeing it on failure).
fn start_digest(c: &mut SigCtx, params: *const OSSL_PARAM) -> c_int {
    if c.mdctx.is_null() {
        // SAFETY: no preconditions.
        c.mdctx = unsafe { EVP_MD_CTX_new() };
        if c.mdctx.is_null() {
            return 0;
        }
    }
    let md = c.md.as_ref().map_or(ptr::null(), |m| m.ptr().cast_const());
    // SAFETY: the context's digest context; the digest, or NULL; the caller's parameters.
    if unsafe { EVP_DigestInit_ex2(c.mdctx, md, params) } != 1 {
        // SAFETY: the context made above.
        unsafe { EVP_MD_CTX_free(c.mdctx) };
        c.mdctx = ptr::null_mut();
        return 0;
    }
    1
}

/// `ecdsa_digest_signverify_init`.
///
/// # Safety
/// `vctx` is NULL or a live context; `mdname` is NULL or a string; `vec` is NULL or a live EC
/// key; `params` is NULL or an array.
unsafe fn digest_signverify_init(
    vctx: *mut c_void,
    mdname: *const c_char,
    vec: *mut c_void,
    params: *const OSSL_PARAM,
    operation: c_int,
) -> c_int {
    // SAFETY: the caller's guarantee.
    if unsafe { signverify_init(vctx, vec, Setter::Normal, params, operation) } != 1 {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx(vctx) }) else {
        return 0;
    };
    if !mdname.is_null() {
        // SAFETY: the caller's string.
        let name = unsafe { CStr::from_ptr(mdname) };
        // Not again for the digest the parameters just set.
        let same = name.to_bytes().eq_ignore_ascii_case(&c.mdname);
        if (name.is_empty() || !same) && !c.setup_md(name, None) {
            return 0;
        }
    }
    c.flag_allow_md = false;
    start_digest(c, params)
}

ffi_callback! {
    /// `ecdsa_digest_sign_init`.
    ///
    /// # Safety
    /// As for `digest_signverify_init`.
    pub(crate) unsafe extern "C" fn ecdsa_digest_sign_init(vctx: *mut c_void, mdname: *const c_char, vec: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { digest_signverify_init(vctx, mdname, vec, params, EVP_PKEY_OP_SIGNMSG) }
    }
}

ffi_callback! {
    /// `ecdsa_digest_verify_init`.
    ///
    /// # Safety
    /// As for `digest_signverify_init`.
    pub(crate) unsafe extern "C" fn ecdsa_digest_verify_init(vctx: *mut c_void, mdname: *const c_char, vec: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { digest_signverify_init(vctx, mdname, vec, params, EVP_PKEY_OP_VERIFYMSG) }
    }
}

ffi_callback! {
    /// `ecdsa_digest_signverify_update`: not for a composite algorithm.
    ///
    /// # Safety
    /// As for `ecdsa_signverify_message_update`.
    pub(crate) unsafe extern "C" fn ecdsa_digest_signverify_update(vctx: *mut c_void, data: *const c_uchar, datalen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if c.mdctx.is_null() || c.flag_sigalg {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { ecdsa_signverify_message_update(vctx, data, datalen) }
    }
}

ffi_callback! {
    /// `ecdsa_digest_sign_final`: as `ecdsa_sign_message_final`; digests may be set again
    /// after.
    ///
    /// # Safety
    /// As for `ecdsa_sign_message_final`.
    pub(crate) unsafe extern "C" fn ecdsa_digest_sign_final(vctx: *mut c_void, sig: *mut c_uchar, siglen: *mut usize, sigsize: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if c.flag_sigalg {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let ok = unsafe { ecdsa_sign_message_final(vctx, sig, siglen, sigsize) };
        c.flag_allow_md = true;
        ok
    }
}

ffi_callback! {
    /// `ecdsa_digest_verify_final`.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `sig` holds `siglen` octets.
    pub(crate) unsafe extern "C" fn ecdsa_digest_verify_final(vctx: *mut c_void, sig: *const c_uchar, siglen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if c.mdctx.is_null() || c.flag_sigalg {
            return 0;
        }
        let mut ok = 0;
        // SAFETY: the caller's guarantee.
        if unsafe { verify_set_sig(vctx, sig, siglen) } != 0 {
            // SAFETY: as above.
            ok = unsafe { ecdsa_verify_message_final(vctx) };
        }
        c.flag_allow_md = true;
        ok
    }
}

ffi_callback! {
    /// `ecdsa_freectx`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context the caller gives up.
    pub(crate) unsafe extern "C" fn ecdsa_freectx(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<SigCtx>(vctx) };
    }
}

ffi_callback! {
    /// `ecdsa_dupctx`: references to the key and digest, a copy of the digest context; not of a
    /// context holding a known-answer test's setup values.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context.
    pub(crate) unsafe extern "C" fn ecdsa_dupctx(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return ptr::null_mut() };
        if !c.kinv.is_null() || !c.r.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the context's key, or NULL.
        if !c.ec.is_null() && unsafe { EC_KEY_up_ref(c.ec) } == 0 {
            return ptr::null_mut();
        }
        let mut copy = SigCtx {
            libctx: c.libctx,
            propq: c.propq.clone(),
            ec: c.ec,
            operation: c.operation,
            flag_sigalg: c.flag_sigalg,
            flag_allow_md: c.flag_allow_md,
            aid: c.aid.clone(),
            mdname: c.mdname.clone(),
            md: c.md.clone(),
            mdctx: ptr::null_mut(),
            mdsize: c.mdsize,
            sig: c.sig.clone(),
            kinv: ptr::null_mut(),
            r: ptr::null_mut(),
            kattest: c.kattest,
            nonce_type: c.nonce_type,
        };
        if !c.mdctx.is_null() {
            // SAFETY: no preconditions.
            copy.mdctx = unsafe { EVP_MD_CTX_new() };
            // SAFETY: the new context; the context's.
            if copy.mdctx.is_null() || unsafe { EVP_MD_CTX_copy_ex(copy.mdctx, c.mdctx) } != 1 {
                return ptr::null_mut();
            }
        }
        boxed(copy)
    }
}

ffi_callback! {
    /// `ecdsa_get_ctx_params`: the algorithm identifier (failing without one), the digest's
    /// size and name, and the nonce type.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ecdsa_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        let find = |key: &CStr| {
            // SAFETY: the caller's array; a static name.
            unsafe { OSSL_PARAM_locate(params, key.as_ptr()) }
        };
        let p = find(OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
        if !p.is_null() {
            let aid = if c.aid.is_empty() { ptr::null() } else { c.aid.as_ptr() };
            // SAFETY: a parameter of the array; the identifier, or NULL (which fails).
            if unsafe { OSSL_PARAM_set_octet_string(p, aid.cast(), c.aid.len()) } != 1 {
                return 0;
            }
        }
        let p = find(OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
        // SAFETY: a parameter of the array.
        if !p.is_null() && unsafe { OSSL_PARAM_set_size_t(p, c.mdsize) } != 1 {
            return 0;
        }
        let p = find(OSSL_SIGNATURE_PARAM_DIGEST);
        if !p.is_null() {
            let given = CString::new(c.mdname.clone()).unwrap_or_default();
            let name = match &c.md {
                // SAFETY: the context's digest.
                Some(m) => unsafe { EVP_MD_get0_name(m.ptr()) },
                None => given.as_ptr(),
            };
            // SAFETY: a parameter of the array; a string.
            if unsafe { OSSL_PARAM_set_utf8_string(p, name) } != 1 {
                return 0;
            }
        }
        let p = find(OSSL_SIGNATURE_PARAM_NONCE_TYPE);
        // SAFETY: a parameter of the array.
        if !p.is_null() && unsafe { OSSL_PARAM_set_uint(p, c.nonce_type) } != 1 {
            return 0;
        }
        1
    }
}

/// `known_gettable_ctx_params`.
static GETTABLE: Params<5> = Params([
    defn(
        OSSL_SIGNATURE_PARAM_ALGORITHM_ID,
        OSSL_PARAM_OCTET_STRING,
        0,
    ),
    defn(
        OSSL_SIGNATURE_PARAM_DIGEST_SIZE,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_SIGNATURE_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING, 0),
    defn(
        OSSL_SIGNATURE_PARAM_NONCE_TYPE,
        OSSL_PARAM_UNSIGNED_INTEGER,
        UINT,
    ),
    PARAM_END,
]);

ffi_callback! {
    /// `ecdsa_gettable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn ecdsa_gettable_ctx_params(_vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        GETTABLE.0.as_ptr()
    }
}

/// `ecdsa_common_set_ctx_params`: the known-answer test flag and the nonce type.
///
/// # Safety
/// `params` is an array.
unsafe fn common_set_ctx_params(c: &mut SigCtx, params: *const OSSL_PARAM) -> c_int {
    // SAFETY: the caller's array; a static name.
    if let Some(p) = unsafe { locate(params, OSSL_SIGNATURE_PARAM_KAT) } {
        // SAFETY: a parameter of the array; the context's field.
        if unsafe { OSSL_PARAM_get_uint(p, &raw mut c.kattest) } != 1 {
            return 0;
        }
    }
    // SAFETY: as above.
    if let Some(p) = unsafe { locate(params, OSSL_SIGNATURE_PARAM_NONCE_TYPE) } {
        // SAFETY: as above.
        if unsafe { OSSL_PARAM_get_uint(p, &raw mut c.nonce_type) } != 1 {
            return 0;
        }
    }
    1
}

/// `OSSL_PARAM_get_utf8_string` into a buffer of `N` (OpenSSL's fixed buffers).
///
/// # Safety
/// `p` is a parameter.
unsafe fn read_string<const N: usize>(p: &OSSL_PARAM) -> Option<CString> {
    let mut buf = [0 as c_char; N];
    let mut s = buf.as_mut_ptr();
    // SAFETY: the parameter; the buffer of N.
    if unsafe { OSSL_PARAM_get_utf8_string(p, &raw mut s, N) } != 1 {
        return None;
    }
    // SAFETY: NUL-terminated by the call.
    Some(unsafe { CStr::from_ptr(buf.as_ptr()) }.to_owned())
}

ffi_callback! {
    /// `ecdsa_set_ctx_params`: the common parameters, the digest (fetched with the properties
    /// given, empty if none are), and the digest's size.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ecdsa_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: the caller's array.
        let ret = unsafe { common_set_ctx_params(c, params) };
        if ret <= 0 {
            return ret;
        }
        let find = |key: &CStr| {
            // SAFETY: the caller's array; a static name.
            unsafe { locate(params, key) }
        };
        if let Some(p) = find(OSSL_SIGNATURE_PARAM_DIGEST) {
            // SAFETY: a parameter of the array.
            let Some(mdname) = (unsafe { read_string::<MAX_NAME>(p) }) else { return 0 };
            let mdprops = match find(OSSL_SIGNATURE_PARAM_PROPERTIES) {
                // SAFETY: as above.
                Some(q) => match unsafe { read_string::<MAX_PROPQUERY>(q) } {
                    Some(v) => v,
                    None => return 0,
                },
                None => CString::default(),
            };
            if !c.setup_md(&mdname, Some(&mdprops)) {
                return 0;
            }
        }
        if let Some(p) = find(OSSL_SIGNATURE_PARAM_DIGEST_SIZE) {
            let mut mdsize: usize = 0;
            // SAFETY: a parameter of the array; a local.
            if unsafe { OSSL_PARAM_get_size_t(p, &raw mut mdsize) } != 1
                || (!c.flag_allow_md && mdsize != c.mdsize)
            {
                return 0;
            }
            c.mdsize = mdsize;
        }
        1
    }
}

/// `settable_ctx_params`.
static SETTABLE: Params<6> = Params([
    defn(OSSL_SIGNATURE_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING, 0),
    defn(
        OSSL_SIGNATURE_PARAM_DIGEST_SIZE,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_SIGNATURE_PARAM_PROPERTIES, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_SIGNATURE_PARAM_KAT, OSSL_PARAM_UNSIGNED_INTEGER, UINT),
    defn(
        OSSL_SIGNATURE_PARAM_NONCE_TYPE,
        OSSL_PARAM_UNSIGNED_INTEGER,
        UINT,
    ),
    PARAM_END,
]);

ffi_callback! {
    /// `ecdsa_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn ecdsa_settable_ctx_params(_vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        SETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `ecdsa_get_ctx_md_params`.
    ///
    /// # Safety
    /// `vctx` is a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ecdsa_get_ctx_md_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if c.mdctx.is_null() {
            return 0;
        }
        // SAFETY: the context's digest context; the caller's array.
        unsafe { EVP_MD_CTX_get_params(c.mdctx, params) }
    }
}

ffi_callback! {
    /// `ecdsa_set_ctx_md_params`.
    ///
    /// # Safety
    /// `vctx` is a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ecdsa_set_ctx_md_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if c.mdctx.is_null() {
            return 0;
        }
        // SAFETY: the context's digest context; the caller's array.
        unsafe { EVP_MD_CTX_set_params(c.mdctx, params) }
    }
}

ffi_callback! {
    /// `ecdsa_gettable_ctx_md_params`.
    ///
    /// # Safety
    /// `vctx` is a live context.
    pub(crate) unsafe extern "C" fn ecdsa_gettable_ctx_md_params(vctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        match unsafe { ctx(vctx) }.and_then(|c| c.md.as_ref()) {
            // SAFETY: the context's digest.
            Some(m) => unsafe { EVP_MD_gettable_ctx_params(m.ptr()) },
            None => ptr::null(),
        }
    }
}

ffi_callback! {
    /// `ecdsa_settable_ctx_md_params`.
    ///
    /// # Safety
    /// `vctx` is a live context.
    pub(crate) unsafe extern "C" fn ecdsa_settable_ctx_md_params(vctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        match unsafe { ctx(vctx) }.and_then(|c| c.md.as_ref()) {
            // SAFETY: the context's digest.
            Some(m) => unsafe { EVP_MD_settable_ctx_params(m.ptr()) },
            None => ptr::null(),
        }
    }
}

ffi_callback! {
    /// `ecdsa_sigalg_set_ctx_params`: the common parameters, and a message verification's
    /// signature (which mustn't be empty).
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ecdsa_sigalg_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: the caller's array.
        let ret = unsafe { common_set_ctx_params(c, params) };
        if ret <= 0 {
            return ret;
        }
        if c.operation == EVP_PKEY_OP_VERIFYMSG {
            // SAFETY: the caller's array; a static name.
            if let Some(p) = unsafe { locate(params, OSSL_SIGNATURE_PARAM_SIGNATURE) } {
                c.sig = None;
                let mut data: *mut c_void = ptr::null_mut();
                let mut n: usize = 0;
                // SAFETY: a parameter of the array; a place for a new allocation.
                if unsafe { OSSL_PARAM_get_octet_string(p, &raw mut data, 0, &raw mut n) } != 1 {
                    return 0;
                }
                // SAFETY: the allocation just made holds `n` octets.
                let sig = unsafe { bytes(data.cast::<u8>(), n) }.unwrap_or_default().to_vec();
                // SAFETY: the allocation just made, freed once.
                unsafe { mem::release(data) };
                if sig.is_empty() {
                    return 0;
                }
                c.sig = Some(sig);
            }
        }
        1
    }
}

/// `settable_sigalg_ctx_params`.
static SIGALG_SETTABLE: Params<4> = Params([
    defn(OSSL_SIGNATURE_PARAM_SIGNATURE, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_SIGNATURE_PARAM_KAT, OSSL_PARAM_UNSIGNED_INTEGER, UINT),
    defn(
        OSSL_SIGNATURE_PARAM_NONCE_TYPE,
        OSSL_PARAM_UNSIGNED_INTEGER,
        UINT,
    ),
    PARAM_END,
]);

ffi_callback! {
    /// `ecdsa_sigalg_settable_ctx_params`: for a message verification only.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context.
    pub(crate) unsafe extern "C" fn ecdsa_sigalg_settable_ctx_params(vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        match unsafe { ctx(vctx) } {
            Some(c) if c.operation == EVP_PKEY_OP_VERIFYMSG => SIGALG_SETTABLE.0.as_ptr(),
            _ => ptr::null(),
        }
    }
}

/// `ecdsa_sigalg_query_key_types`'s list.
struct KeyTypes([*const c_char; 2]);
// SAFETY: pointers to static strings.
unsafe impl Sync for KeyTypes {}
static KEY_TYPES: KeyTypes = KeyTypes([c"EC".as_ptr(), ptr::null()]);

ffi_callback! {
    /// `ecdsa_sigalg_query_key_types`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn ecdsa_sigalg_query_key_types() -> *const *const c_char
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        KEY_TYPES.0.as_ptr()
    }
}

/// `ecdsa_sigalg_signverify_init`: the key, the fixed digest, and the digest context started.
///
/// # Safety
/// As for `signverify_init`.
unsafe fn sigalg_init(
    vctx: *mut c_void,
    vec: *mut c_void,
    params: *const OSSL_PARAM,
    mdname: &CStr,
    operation: c_int,
) -> c_int {
    // SAFETY: the caller's guarantee.
    if unsafe { signverify_init(vctx, vec, Setter::Sigalg, params, operation) } != 1 {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx(vctx) }) else {
        return 0;
    };
    if !c.setup_md(mdname, None) {
        return 0;
    }
    c.flag_sigalg = true;
    c.flag_allow_md = false;
    start_digest(c, params)
}

type NewCtxFn = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
type InitFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *const OSSL_PARAM) -> c_int;
type SignFn = unsafe extern "C" fn(
    *mut c_void,
    *mut c_uchar,
    *mut usize,
    usize,
    *const c_uchar,
    usize,
) -> c_int;
type VerifyFn =
    unsafe extern "C" fn(*mut c_void, *const c_uchar, usize, *const c_uchar, usize) -> c_int;
type DigestInitFn =
    unsafe extern "C" fn(*mut c_void, *const c_char, *mut c_void, *const OSSL_PARAM) -> c_int;
type UpdateFn = unsafe extern "C" fn(*mut c_void, *const c_uchar, usize) -> c_int;
type SignFinalFn = unsafe extern "C" fn(*mut c_void, *mut c_uchar, *mut usize, usize) -> c_int;
type VerifyFinalFn = unsafe extern "C" fn(*mut c_void, *const c_uchar, usize) -> c_int;
type MessageFinalFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
type DupCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type GetParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
type SetParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type ListFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;
type MdListFn = unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM;
type KeyTypesFn = unsafe extern "C" fn() -> *const *const c_char;

/// `ossl_ecdsa_signature_functions`.
pub(crate) static ECDSA_SIGNATURE: Dispatch<22> = Dispatch([
    entry!(OSSL_FUNC_SIGNATURE_NEWCTX, ecdsa_newctx, NewCtxFn),
    entry!(OSSL_FUNC_SIGNATURE_SIGN_INIT, ecdsa_sign_init, InitFn),
    entry!(OSSL_FUNC_SIGNATURE_SIGN, ecdsa_sign, SignFn),
    entry!(OSSL_FUNC_SIGNATURE_VERIFY_INIT, ecdsa_verify_init, InitFn),
    entry!(OSSL_FUNC_SIGNATURE_VERIFY, ecdsa_verify, VerifyFn),
    entry!(
        OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
        ecdsa_digest_sign_init,
        DigestInitFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
        ecdsa_digest_signverify_update,
        UpdateFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
        ecdsa_digest_sign_final,
        SignFinalFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
        ecdsa_digest_verify_init,
        DigestInitFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
        ecdsa_digest_signverify_update,
        UpdateFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
        ecdsa_digest_verify_final,
        VerifyFinalFn
    ),
    entry!(OSSL_FUNC_SIGNATURE_FREECTX, ecdsa_freectx, FreeCtxFn),
    entry!(OSSL_FUNC_SIGNATURE_DUPCTX, ecdsa_dupctx, DupCtxFn),
    entry!(
        OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
        ecdsa_get_ctx_params,
        GetParamsFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
        ecdsa_gettable_ctx_params,
        ListFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        ecdsa_set_ctx_params,
        SetParamsFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        ecdsa_settable_ctx_params,
        ListFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
        ecdsa_get_ctx_md_params,
        GetParamsFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
        ecdsa_gettable_ctx_md_params,
        MdListFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
        ecdsa_set_ctx_md_params,
        SetParamsFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
        ecdsa_settable_ctx_md_params,
        MdListFn
    ),
    END,
]);

/// `IMPL_ECDSA_SIGALG`: a composite algorithm's inits and dispatch table.
macro_rules! ecdsa_sigalg {
    ($table:ident, $md:expr, $sign:ident, $sign_msg:ident, $verify:ident, $verify_msg:ident) => {
        ffi_callback! {
            /// The composite algorithm's `sign_init`.
            ///
            /// # Safety
            /// As for `signverify_init`.
            pub(crate) unsafe extern "C" fn $sign(vctx: *mut c_void, vec: *mut c_void, params: *const OSSL_PARAM) -> c_int
            where failure = 0, library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                unsafe { sigalg_init(vctx, vec, params, $md, EVP_PKEY_OP_SIGN) }
            }
        }
        ffi_callback! {
            /// The composite algorithm's `sign_message_init`.
            ///
            /// # Safety
            /// As for `signverify_init`.
            pub(crate) unsafe extern "C" fn $sign_msg(vctx: *mut c_void, vec: *mut c_void, params: *const OSSL_PARAM) -> c_int
            where failure = 0, library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                unsafe { sigalg_init(vctx, vec, params, $md, EVP_PKEY_OP_SIGNMSG) }
            }
        }
        ffi_callback! {
            /// The composite algorithm's `verify_init`.
            ///
            /// # Safety
            /// As for `signverify_init`.
            pub(crate) unsafe extern "C" fn $verify(vctx: *mut c_void, vec: *mut c_void, params: *const OSSL_PARAM) -> c_int
            where failure = 0, library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                unsafe { sigalg_init(vctx, vec, params, $md, EVP_PKEY_OP_VERIFY) }
            }
        }
        ffi_callback! {
            /// The composite algorithm's `verify_message_init`.
            ///
            /// # Safety
            /// As for `signverify_init`.
            pub(crate) unsafe extern "C" fn $verify_msg(vctx: *mut c_void, vec: *mut c_void, params: *const OSSL_PARAM) -> c_int
            where failure = 0, library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                unsafe { sigalg_init(vctx, vec, params, $md, EVP_PKEY_OP_VERIFYMSG) }
            }
        }
        /// The composite algorithm's dispatch table.
        pub(crate) static $table: Dispatch<19> = Dispatch([
            entry!(OSSL_FUNC_SIGNATURE_NEWCTX, ecdsa_newctx, NewCtxFn),
            entry!(OSSL_FUNC_SIGNATURE_SIGN_INIT, $sign, InitFn),
            entry!(OSSL_FUNC_SIGNATURE_SIGN, ecdsa_sign, SignFn),
            entry!(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT, $sign_msg, InitFn),
            entry!(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE, ecdsa_signverify_message_update, UpdateFn),
            entry!(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL, ecdsa_sign_message_final, SignFinalFn),
            entry!(OSSL_FUNC_SIGNATURE_VERIFY_INIT, $verify, InitFn),
            entry!(OSSL_FUNC_SIGNATURE_VERIFY, ecdsa_verify, VerifyFn),
            entry!(OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT, $verify_msg, InitFn),
            entry!(OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE, ecdsa_signverify_message_update, UpdateFn),
            entry!(OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL, ecdsa_verify_message_final, MessageFinalFn),
            entry!(OSSL_FUNC_SIGNATURE_FREECTX, ecdsa_freectx, FreeCtxFn),
            entry!(OSSL_FUNC_SIGNATURE_DUPCTX, ecdsa_dupctx, DupCtxFn),
            entry!(OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES, ecdsa_sigalg_query_key_types, KeyTypesFn),
            entry!(OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, ecdsa_get_ctx_params, GetParamsFn),
            entry!(OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, ecdsa_gettable_ctx_params, ListFn),
            entry!(OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, ecdsa_sigalg_set_ctx_params, SetParamsFn),
            entry!(OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, ecdsa_sigalg_settable_ctx_params, ListFn),
            END,
        ]);
    };
}

ecdsa_sigalg!(
    ECDSA_SHA1_SIGNATURE,
    c"SHA1",
    sha1_sign_init,
    sha1_sign_message_init,
    sha1_verify_init,
    sha1_verify_message_init
);
ecdsa_sigalg!(
    ECDSA_SHA224_SIGNATURE,
    c"SHA2-224",
    sha224_sign_init,
    sha224_sign_message_init,
    sha224_verify_init,
    sha224_verify_message_init
);
ecdsa_sigalg!(
    ECDSA_SHA256_SIGNATURE,
    c"SHA2-256",
    sha256_sign_init,
    sha256_sign_message_init,
    sha256_verify_init,
    sha256_verify_message_init
);
ecdsa_sigalg!(
    ECDSA_SHA384_SIGNATURE,
    c"SHA2-384",
    sha384_sign_init,
    sha384_sign_message_init,
    sha384_verify_init,
    sha384_verify_message_init
);
ecdsa_sigalg!(
    ECDSA_SHA512_SIGNATURE,
    c"SHA2-512",
    sha512_sign_init,
    sha512_sign_message_init,
    sha512_verify_init,
    sha512_verify_message_init
);
ecdsa_sigalg!(
    ECDSA_SHA3_224_SIGNATURE,
    c"SHA3-224",
    sha3_224_sign_init,
    sha3_224_sign_message_init,
    sha3_224_verify_init,
    sha3_224_verify_message_init
);
ecdsa_sigalg!(
    ECDSA_SHA3_256_SIGNATURE,
    c"SHA3-256",
    sha3_256_sign_init,
    sha3_256_sign_message_init,
    sha3_256_verify_init,
    sha3_256_verify_message_init
);
ecdsa_sigalg!(
    ECDSA_SHA3_384_SIGNATURE,
    c"SHA3-384",
    sha3_384_sign_init,
    sha3_384_sign_message_init,
    sha3_384_verify_init,
    sha3_384_verify_message_init
);
ecdsa_sigalg!(
    ECDSA_SHA3_512_SIGNATURE,
    c"SHA3-512",
    sha3_512_sign_init,
    sha3_512_sign_message_init,
    sha3_512_verify_init,
    sha3_512_verify_message_init
);
