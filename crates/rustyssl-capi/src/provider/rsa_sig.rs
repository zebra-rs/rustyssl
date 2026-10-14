//! The default provider's RSA signatures (`rsa_sig.c`): `RSA` (sign, verify, and recover a
//! digest with PKCS #1 v1.5, PSS, X9.31, or no padding, and digest-sign and digest-verify a
//! message) and the composite signature algorithms `RSA-SHA256` and the others (PKCS #1 v1.5
//! with a fixed digest, over a digest or a message).
//!
//! The context follows OpenSSL's step for step: the digests a signature may use, the order in
//! which parameters are checked and committed (a failed call can leave the pad mode and salt
//! length changed, as OpenSSL's does), a PSS key's restrictions, and each error with its text.

use core::ffi::{CStr, c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, ERR_R_RSA_LIB, ERR_R_UNSUPPORTED, EVP_MD_CTX,
    EVP_PKEY_OP_DECAPSULATE, EVP_PKEY_OP_DECRYPT, EVP_PKEY_OP_ENCAPSULATE, EVP_PKEY_OP_ENCRYPT,
    EVP_PKEY_OP_SIGN, EVP_PKEY_OP_SIGNMSG, EVP_PKEY_OP_VERIFY, EVP_PKEY_OP_VERIFYMSG,
    EVP_PKEY_OP_VERIFYRECOVER, NID_RSA_SHA3_224, NID_RSA_SHA3_256, NID_RSA_SHA3_384,
    NID_RSA_SHA3_512, NID_md2, NID_md2WithRSAEncryption, NID_md4, NID_md4WithRSAEncryption,
    NID_md5, NID_md5_sha1, NID_md5WithRSAEncryption, NID_mdc2, NID_mdc2WithRSA, NID_mgf1,
    NID_ripemd160, NID_ripemd160WithRSA, NID_rsassaPss, NID_sha1, NID_sha1WithRSAEncryption,
    NID_sha3_224, NID_sha3_256, NID_sha3_384, NID_sha3_512, NID_sha224,
    NID_sha224WithRSAEncryption, NID_sha256, NID_sha256WithRSAEncryption, NID_sha384,
    NID_sha384WithRSAEncryption, NID_sha512, NID_sha512_224, NID_sha512_224WithRSAEncryption,
    NID_sha512_256, NID_sha512_256WithRSAEncryption, NID_sha512WithRSAEncryption, NID_sm3,
    NID_undef, OSSL_DIGEST_NAME_MD2, OSSL_DIGEST_NAME_MD4, OSSL_DIGEST_NAME_MD5,
    OSSL_DIGEST_NAME_MD5_SHA1, OSSL_DIGEST_NAME_MDC2, OSSL_DIGEST_NAME_RIPEMD160,
    OSSL_DIGEST_NAME_SHA1, OSSL_DIGEST_NAME_SHA2_224, OSSL_DIGEST_NAME_SHA2_256,
    OSSL_DIGEST_NAME_SHA2_384, OSSL_DIGEST_NAME_SHA2_512, OSSL_DIGEST_NAME_SHA2_512_224,
    OSSL_DIGEST_NAME_SHA2_512_256, OSSL_DIGEST_NAME_SHA3_224, OSSL_DIGEST_NAME_SHA3_256,
    OSSL_DIGEST_NAME_SHA3_384, OSSL_DIGEST_NAME_SHA3_512, OSSL_DIGEST_NAME_SM3,
    OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
    OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
    OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
    OSSL_FUNC_SIGNATURE_DUPCTX, OSSL_FUNC_SIGNATURE_FREECTX, OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
    OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
    OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, OSSL_FUNC_SIGNATURE_NEWCTX,
    OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES, OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
    OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
    OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, OSSL_FUNC_SIGNATURE_SIGN,
    OSSL_FUNC_SIGNATURE_SIGN_INIT, OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL,
    OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT, OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE,
    OSSL_FUNC_SIGNATURE_VERIFY, OSSL_FUNC_SIGNATURE_VERIFY_INIT,
    OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL, OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,
    OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE, OSSL_FUNC_SIGNATURE_VERIFY_RECOVER,
    OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT, OSSL_LIB_CTX, OSSL_PARAM, OSSL_PARAM_INTEGER,
    OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UTF8_STRING, OSSL_PKEY_RSA_PAD_MODE_NONE,
    OSSL_PKEY_RSA_PAD_MODE_PKCSV15, OSSL_PKEY_RSA_PAD_MODE_PSS, OSSL_PKEY_RSA_PAD_MODE_X931,
    OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX,
    OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST, OSSL_PKEY_RSA_PSS_SALT_LEN_MAX,
    OSSL_SIGNATURE_PARAM_ALGORITHM_ID, OSSL_SIGNATURE_PARAM_DIGEST,
    OSSL_SIGNATURE_PARAM_MGF1_DIGEST, OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES,
    OSSL_SIGNATURE_PARAM_PAD_MODE, OSSL_SIGNATURE_PARAM_PROPERTIES,
    OSSL_SIGNATURE_PARAM_PSS_SALTLEN, OSSL_SIGNATURE_PARAM_SIGNATURE, PROV_R_ALGORITHM_MISMATCH,
    PROV_R_DIGEST_NOT_ALLOWED, PROV_R_FINAL_CALL_OUT_OF_ORDER,
    PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE, PROV_R_INVALID_DIGEST,
    PROV_R_INVALID_DIGEST_LENGTH, PROV_R_INVALID_KEY, PROV_R_INVALID_MGF1_MD,
    PROV_R_INVALID_PADDING_MODE, PROV_R_INVALID_SALT_LENGTH, PROV_R_INVALID_SIGNATURE_SIZE,
    PROV_R_INVALID_X931_DIGEST, PROV_R_KEY_SIZE_TOO_SMALL, PROV_R_NO_KEY_SET, PROV_R_NOT_SUPPORTED,
    PROV_R_ONESHOT_CALL_OUT_OF_ORDER, PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
    PROV_R_OUTPUT_BUFFER_TOO_SMALL, PROV_R_PSS_SALTLEN_TOO_SMALL, PROV_R_UPDATE_CALL_OUT_OF_ORDER,
    PROV_R_XOF_DIGESTS_NOT_ALLOWED, RSA,
};
use rustyssl_asn1::objects;
use rustyssl_crypto::rsa::{self as core_rsa, Hash, Padding, x931_hash_id};

use super::builtin::libctx_of;
use super::macs::{boxed, context, is_empty, locate, unbox};
use super::rsa_kmgmt::{PSS_DEFAULTS, oaeppss_nid2name};
use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::err;
use crate::evp::digest::{EVP_MD_get_size, EVP_MD_is_a};
use crate::evp::md_ctx::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex2, EVP_DigestUpdate, EVP_MD_CTX_copy_ex, EVP_MD_CTX_free,
    EVP_MD_CTX_get_params, EVP_MD_CTX_new, EVP_MD_CTX_set_params, EVP_MD_gettable_ctx_params,
    EVP_MD_settable_ctx_params, EVP_MD_xof,
};
use crate::ffi::{bytes, ffi_callback};
use crate::handle::Handle;
use crate::mem;
use crate::params::{
    OSSL_PARAM_get_int, OSSL_PARAM_get_octet_string, OSSL_PARAM_get_utf8_string, OSSL_PARAM_locate,
    OSSL_PARAM_set_int, OSSL_PARAM_set_octet_string, OSSL_PARAM_set_utf8_string,
};
use crate::rsa::{Kind, Md, Pss30, RsaState, private_random, raise_all, rsa};

/// `OSSL_MAX_NAME_SIZE` and `OSSL_MAX_PROPQUERY_SIZE` (`internal/sizes.h`).
const MAX_NAME: usize = 50;
const MAX_PROPQUERY: usize = 256;

/// `RSA_DEFAULT_DIGEST_NAME` (`rsa_sig.c`): PSS's digest when none is set.
const RSA_DEFAULT_DIGEST_NAME: &CStr = c"SHA1";

/// The RSA padding modes' numbers (`RSA_*_PADDING`).
const PKCS1: c_int = 1;
const NONE: c_int = 3;
const OAEP: c_int = 4;
const X931: c_int = 5;
const PSS: c_int = 6;

/// The PSS salt lengths' special values (`RSA_PSS_SALTLEN_*`).
const SALTLEN_DIGEST: c_int = -1;
const SALTLEN_AUTO: c_int = -2;
const SALTLEN_MAX: c_int = -3;
const SALTLEN_AUTO_DIGEST_MAX: c_int = -4;

/// `padding_item`: the pad modes by name.
const PADDING_ITEMS: [(c_int, &CStr); 4] = [
    (PKCS1, OSSL_PKEY_RSA_PAD_MODE_PKCSV15),
    (NONE, OSSL_PKEY_RSA_PAD_MODE_NONE),
    (X931, OSSL_PKEY_RSA_PAD_MODE_X931),
    (PSS, OSSL_PKEY_RSA_PAD_MODE_PSS),
];

/// `ossl_digest_rsa_sign_get_md_nid`: the approved digests, then the others RSA may sign.
const SIGN_DIGESTS: [(c_int, &CStr); 18] = [
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
    (NID_md5, OSSL_DIGEST_NAME_MD5),
    (NID_md5_sha1, OSSL_DIGEST_NAME_MD5_SHA1),
    (NID_md2, OSSL_DIGEST_NAME_MD2),
    (NID_md4, OSSL_DIGEST_NAME_MD4),
    (NID_mdc2, OSSL_DIGEST_NAME_MDC2),
    (NID_ripemd160, OSSL_DIGEST_NAME_RIPEMD160),
    (NID_sm3, OSSL_DIGEST_NAME_SM3),
];

/// `ossl_DER_w_algorithmIdentifier_MDWithRSAEncryption`'s digests and their signature OIDs.
const MD_WITH_RSA: [(c_int, c_int); 16] = [
    (NID_md2, NID_md2WithRSAEncryption),
    (NID_md4, NID_md4WithRSAEncryption),
    (NID_md5, NID_md5WithRSAEncryption),
    (NID_mdc2, NID_mdc2WithRSA),
    (NID_ripemd160, NID_ripemd160WithRSA),
    (NID_sha1, NID_sha1WithRSAEncryption),
    (NID_sha224, NID_sha224WithRSAEncryption),
    (NID_sha256, NID_sha256WithRSAEncryption),
    (NID_sha384, NID_sha384WithRSAEncryption),
    (NID_sha512, NID_sha512WithRSAEncryption),
    (NID_sha512_224, NID_sha512_224WithRSAEncryption),
    (NID_sha512_256, NID_sha512_256WithRSAEncryption),
    (NID_sha3_224, NID_RSA_SHA3_224),
    (NID_sha3_256, NID_RSA_SHA3_256),
    (NID_sha3_384, NID_RSA_SHA3_384),
    (NID_sha3_512, NID_RSA_SHA3_512),
];

/// `PROV_RSA_CTX` (signature).
struct SigCtx {
    libctx: *mut OSSL_LIB_CTX,
    propq: Option<CString>,
    /// The key, with a reference this holds.
    rsa: *mut RSA,
    operation: c_int,
    flag_sigalg: bool,
    flag_allow_md: bool,
    mgf1_md_set: bool,
    flag_allow_update: bool,
    flag_allow_final: bool,
    flag_allow_oneshot: bool,
    md: Option<Md>,
    mdctx: *mut EVP_MD_CTX,
    mdnid: c_int,
    /// The digest's name as given (at most 49 octets).
    mdname: Vec<u8>,
    pad_mode: c_int,
    mgf1_md: Option<Md>,
    mgf1_mdnid: c_int,
    mgf1_mdname: Vec<u8>,
    saltlen: c_int,
    /// A PSS key's minimum salt length, or -1 when unrestricted.
    min_saltlen: c_int,
    /// The signature a message verification checks.
    sig: Option<Vec<u8>>,
}

impl Drop for SigCtx {
    fn drop(&mut self) {
        // SAFETY: the context this holds, or NULL.
        unsafe { EVP_MD_CTX_free(self.mdctx) };
        // SAFETY: the reference this holds, or NULL.
        unsafe { RSA::free(self.rsa) };
    }
}

/// The context behind `vctx`.
///
/// # Safety
/// `vctx` is NULL or a live context from `rsa_newctx`.
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

/// `ossl_digest_rsa_sign_get_md_nid`.
///
/// # Safety
/// `md` is a live digest.
unsafe fn sign_md_nid(md: &Md) -> c_int {
    SIGN_DIGESTS
        .iter()
        // SAFETY: the digest; a static name.
        .find(|(_, name)| unsafe { EVP_MD_is_a(md.ptr(), name.as_ptr()) } != 0)
        .map_or(NID_undef, |&(nid, _)| nid)
}

impl SigCtx {
    /// The key's state, if there's a key.
    fn key(&self) -> Option<RsaState> {
        // SAFETY: the reference this holds, or NULL.
        unsafe { rsa(self.rsa) }.map(|r| r.snapshot())
    }

    /// The key's kind.
    fn kind(&self) -> Option<Kind> {
        // SAFETY: as above.
        unsafe { rsa(self.rsa) }.map(|r| r.lock().kind)
    }

    /// The key's library context (the context's without a key).
    fn key_libctx(&self) -> *mut OSSL_LIB_CTX {
        // SAFETY: as above.
        unsafe { rsa(self.rsa) }.map_or(self.libctx, |r| r.libctx.0)
    }

    /// `rsa_get_md_size`: the digest's size, 0 without one.
    fn md_size(&self) -> usize {
        self.md.as_ref().map_or(0, Hash::size)
    }

    /// `EVP_MD_get_size` of the digest (-1 without one, as OpenSSL's NULL gives).
    fn md_size_int(&self) -> c_int {
        // SAFETY: the digest, or NULL.
        unsafe { EVP_MD_get_size(self.md.as_ref().map_or(ptr::null(), |m| m.ptr())) }
    }

    /// `rsa_pss_restricted`.
    fn restricted(&self) -> bool {
        self.min_saltlen != -1
    }

    /// `rsa_check_padding`.
    fn check_padding(
        &self,
        mdname: Option<&CStr>,
        mgf1_mdname: Option<&CStr>,
        mdnid: c_int,
    ) -> bool {
        const F: &str = "rsa_check_padding";
        match self.pad_mode {
            NONE if mdname.is_some() || mdnid != NID_undef => {
                prov(PROV_R_INVALID_PADDING_MODE, F);
                false
            }
            X931 if x931_hash_id(mdnid) == -1 => {
                prov(PROV_R_INVALID_X931_DIGEST, F);
                false
            }
            PSS if self.restricted() => {
                let is = |md: &Option<Md>, name: &CStr| {
                    // SAFETY: the digest, or NULL; a string.
                    (unsafe {
                        EVP_MD_is_a(md.as_ref().map_or(ptr::null(), |m| m.ptr()), name.as_ptr())
                    } != 0)
                };
                if mdname.is_some_and(|n| !is(&self.md, n))
                    || mgf1_mdname.is_some_and(|n| !is(&self.mgf1_md, n))
                {
                    prov(PROV_R_DIGEST_NOT_ALLOWED, F);
                    return false;
                }
                true
            }
            _ => true,
        }
    }

    /// `rsa_setup_md`: the digest `mdname` (with `mdprops`, or the context's query), checked.
    fn setup_md(&mut self, mdname: &CStr, mdprops: Option<&CStr>) -> bool {
        const F: &str = "rsa_setup_md";
        let props = mdprops.map_or_else(
            || self.propq.as_deref().map_or(ptr::null(), CStr::as_ptr),
            CStr::as_ptr,
        );
        // SAFETY: the context's library context; a name and a query.
        let Some(md) = (unsafe { Md::fetch(self.libctx, mdname, props) }) else {
            prov_text(
                PROV_R_INVALID_DIGEST,
                F,
                &format!("{} could not be fetched", text(mdname.to_bytes())),
            );
            return false;
        };
        // SAFETY: the digest.
        let md_nid = unsafe { sign_md_nid(&md) };
        if md_nid == NID_undef {
            prov_text(
                PROV_R_DIGEST_NOT_ALLOWED,
                F,
                &format!("digest={}", text(mdname.to_bytes())),
            );
            return false;
        }
        // SAFETY: the digest.
        if unsafe { EVP_MD_xof(md.ptr()) } != 0 {
            prov(PROV_R_XOF_DIGESTS_NOT_ALLOWED, F);
            return false;
        }
        if !self.check_padding(Some(mdname), None, md_nid) {
            return false;
        }
        if mdname.to_bytes().len() >= MAX_NAME {
            prov_text(
                PROV_R_INVALID_DIGEST,
                F,
                &format!("{} exceeds name buffer length", text(mdname.to_bytes())),
            );
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
                        &format!(
                            "digest {} != {}",
                            text(mdname.to_bytes()),
                            text(&self.mdname)
                        ),
                    );
                    return false;
                }
            }
            return true;
        }
        if !self.mgf1_md_set {
            self.mgf1_md = Some(md.clone());
            self.mgf1_mdnid = md_nid;
            self.mgf1_mdname = mdname.to_bytes().to_vec();
        }
        // SAFETY: the context this holds, or NULL.
        unsafe { EVP_MD_CTX_free(self.mdctx) };
        self.mdctx = ptr::null_mut();
        self.md = Some(md);
        self.mdnid = md_nid;
        self.mdname = mdname.to_bytes().to_vec();
        true
    }

    /// `rsa_setup_mgf1_md`.
    fn setup_mgf1_md(&mut self, mdname: &CStr, mdprops: Option<&CStr>) -> bool {
        const F: &str = "rsa_setup_mgf1_md";
        let props = mdprops.map_or_else(
            || self.propq.as_deref().map_or(ptr::null(), CStr::as_ptr),
            CStr::as_ptr,
        );
        // SAFETY: the context's library context; a name and a query.
        let Some(md) = (unsafe { Md::fetch(self.libctx, mdname, props) }) else {
            prov_text(
                PROV_R_INVALID_DIGEST,
                F,
                &format!("{} could not be fetched", text(mdname.to_bytes())),
            );
            return false;
        };
        // SAFETY: the digest.
        let mdnid = unsafe { sign_md_nid(&md) };
        if mdnid <= 0 {
            prov_text(
                PROV_R_DIGEST_NOT_ALLOWED,
                F,
                &format!("digest={}", text(mdname.to_bytes())),
            );
            return false;
        }
        if !self.check_padding(None, Some(mdname), mdnid) {
            return false;
        }
        // As `OPENSSL_strlcpy`: the name is cut to the buffer before the length is checked.
        let name = mdname.to_bytes();
        self.mgf1_mdname = name
            .get(..name.len().min(MAX_NAME - 1))
            .unwrap_or_default()
            .to_vec();
        if name.len() >= MAX_NAME {
            prov_text(
                PROV_R_INVALID_DIGEST,
                F,
                &format!("{} exceeds name buffer length", text(name)),
            );
            return false;
        }
        self.mgf1_md = Some(md);
        self.mgf1_mdnid = mdnid;
        self.mgf1_md_set = true;
        true
    }

    /// `rsa_check_parameters`: a PSS key's minimum salt length against the key and digest.
    fn check_parameters(&mut self, min_saltlen: c_int) -> bool {
        if self.pad_mode == PSS {
            let Some(st) = self.key() else { return false };
            let mut max = c_int::try_from(st.key.size())
                .unwrap_or(0)
                .saturating_sub(self.md_size_int());
            if st.key.bits() & 7 == 1 {
                max = max.saturating_sub(1);
            }
            if min_saltlen < 0 || min_saltlen > max {
                prov(PROV_R_INVALID_SALT_LENGTH, "rsa_check_parameters");
                return false;
            }
            self.min_saltlen = min_saltlen;
        }
        true
    }

    /// `rsa_pss_compute_saltlen`: the salt length a PSS signature gets, or -1.
    fn pss_compute_saltlen(&self) -> c_int {
        const F: &str = "rsa_pss_compute_saltlen";
        let mut saltlen = self.saltlen;
        let mut saltlen_max = -1;
        if saltlen == SALTLEN_DIGEST {
            saltlen = self.md_size_int();
            if saltlen <= 0 {
                prov(PROV_R_INVALID_DIGEST, F);
                return -1;
            }
        } else if saltlen == SALTLEN_AUTO_DIGEST_MAX {
            saltlen = SALTLEN_MAX;
            saltlen_max = self.md_size_int();
            if saltlen_max <= 0 {
                prov(PROV_R_INVALID_DIGEST, F);
                return -1;
            }
        }
        if saltlen == SALTLEN_MAX || saltlen == SALTLEN_AUTO {
            let mdsize = self.md_size_int();
            if mdsize <= 0 {
                prov(PROV_R_INVALID_DIGEST, F);
                return -1;
            }
            let Some(st) = self.key() else { return -1 };
            let rsasize = c_int::try_from(st.key.size()).unwrap_or(0);
            if rsasize <= 2 || rsasize - 2 < mdsize {
                prov(PROV_R_INVALID_KEY, F);
                return -1;
            }
            saltlen = rsasize - mdsize - 2;
            if st.key.bits() & 7 == 1 {
                saltlen -= 1;
            }
            if saltlen_max >= 0 && saltlen > saltlen_max {
                saltlen = saltlen_max;
            }
        }
        if saltlen < 0 {
            prov(ERR_R_INTERNAL_ERROR, F);
            return -1;
        }
        if saltlen < self.min_saltlen {
            prov_text(
                PROV_R_PSS_SALTLEN_TOO_SMALL,
                F,
                &format!(
                    "minimum salt length: {}, actual salt length: {saltlen}",
                    self.min_saltlen
                ),
            );
            return -1;
        }
        saltlen
    }
}

/// A DER length.
fn der_len(len: usize) -> Vec<u8> {
    match len {
        0..0x80 => vec![u8::try_from(len).unwrap_or(0)],
        0x80..0x100 => vec![0x81, u8::try_from(len).unwrap_or(0)],
        _ => {
            let [hi, lo] = u16::try_from(len).unwrap_or(0).to_be_bytes();
            vec![0x82, hi, lo]
        }
    }
}

/// A DER element.
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// An AlgorithmIdentifier of the object `nid` with NULL parameters.
fn alg_with_null(nid: c_int) -> Option<Vec<u8>> {
    let oid = objects::object(nid)?.der;
    let mut content = der(0x06, oid);
    content.extend_from_slice(&[0x05, 0x00]);
    Some(der(0x30, &content))
}

/// `ossl_DER_w_algorithmIdentifier_RSA_PSS` for a restricted key's parameters: the RSASSA-PSS
/// OID and its parameters, each left out when it's the default.
fn pss_aid(p: &Pss30) -> Option<Vec<u8>> {
    let encodable = |nid: c_int| oaeppss_nid2name(nid).is_some();
    if !encodable(p.hash) || !encodable(p.mask_gen_hash) {
        return None;
    }
    let mut params = Vec::new();
    if p.hash != PSS_DEFAULTS.hash {
        params.extend(der(0xa0, &alg_with_null(p.hash)?));
    }
    if p.mask_gen_hash != PSS_DEFAULTS.mask_gen_hash {
        let mut mgf = der(0x06, objects::object(NID_mgf1)?.der);
        mgf.extend(alg_with_null(p.mask_gen_hash)?);
        params.extend(der(0xa1, &der(0x30, &mgf)));
    }
    if p.salt_len != PSS_DEFAULTS.salt_len {
        let s = u32::try_from(p.salt_len).ok()?;
        let mut v: Vec<u8> = s
            .to_be_bytes()
            .into_iter()
            .skip_while(|&b| b == 0)
            .collect();
        if v.first().is_none_or(|&b| b & 0x80 != 0) {
            v.insert(0, 0);
        }
        params.extend(der(0xa2, &der(0x02, &v)));
    }
    let mut content = der(0x06, objects::object(NID_rsassaPss)?.der);
    content.extend(der(0x30, &params));
    Some(der(0x30, &content))
}

/// `rsa_generate_signature_aid`.
fn signature_aid(c: &SigCtx) -> Option<Vec<u8>> {
    const F: &str = "rsa_generate_signature_aid";
    match c.pad_mode {
        PKCS1 => {
            let sig = MD_WITH_RSA
                .iter()
                .find(|(md, _)| *md == c.mdnid)
                .map(|&(_, s)| s);
            match sig.and_then(alg_with_null) {
                Some(d) => Some(d),
                None => {
                    prov_text(
                        ERR_R_UNSUPPORTED,
                        F,
                        &format!("Algorithm ID generation - md NID: {}", c.mdnid),
                    );
                    None
                }
            }
        }
        PSS => {
            let saltlen = c.pss_compute_saltlen();
            if saltlen < 0 {
                return None;
            }
            let p = Pss30 {
                hash: c.mdnid,
                mask_gen: NID_mgf1,
                mask_gen_hash: c.mgf1_mdnid,
                salt_len: saltlen,
                trailer: 1,
            };
            let d = pss_aid(&p);
            if d.is_none() {
                prov(ERR_R_INTERNAL_ERROR, F);
            }
            d
        }
        m => {
            prov_text(
                ERR_R_UNSUPPORTED,
                F,
                &format!("Algorithm ID generation - pad mode: {m}"),
            );
            None
        }
    }
}

ffi_callback! {
    /// `rsa_newctx`.
    ///
    /// # Safety
    /// `provctx` is the default provider's context; `propq` is NULL or a string.
    pub(crate) unsafe extern "C" fn rsa_sig_newctx(provctx: *mut c_void, propq: *const c_char) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        boxed(SigCtx {
            // SAFETY: the caller's guarantee.
            libctx: unsafe { libctx_of(provctx) },
            // SAFETY: the caller's guarantee.
            propq: (!propq.is_null()).then(|| unsafe { CStr::from_ptr(propq) }.to_owned()),
            rsa: ptr::null_mut(),
            operation: 0,
            flag_sigalg: false,
            flag_allow_md: true,
            mgf1_md_set: false,
            flag_allow_update: false,
            flag_allow_final: false,
            flag_allow_oneshot: false,
            md: None,
            mdctx: ptr::null_mut(),
            mdnid: NID_undef,
            mdname: Vec::new(),
            pad_mode: 0,
            mgf1_md: None,
            mgf1_mdnid: NID_undef,
            mgf1_mdname: Vec::new(),
            saltlen: SALTLEN_AUTO_DIGEST_MAX,
            min_saltlen: -1,
            sig: None,
        })
    }
}

/// `ossl_rsa_key_op_get_protect`: RSA-PSS keys can't recover, encrypt, or decrypt.
fn key_op_allowed(kind: Kind, operation: c_int) -> bool {
    const F: &str = "ossl_rsa_key_op_get_protect";
    match operation {
        EVP_PKEY_OP_SIGN | EVP_PKEY_OP_SIGNMSG | EVP_PKEY_OP_VERIFY | EVP_PKEY_OP_VERIFYMSG => true,
        EVP_PKEY_OP_ENCAPSULATE
        | EVP_PKEY_OP_ENCRYPT
        | EVP_PKEY_OP_VERIFYRECOVER
        | EVP_PKEY_OP_DECAPSULATE
        | EVP_PKEY_OP_DECRYPT => {
            if kind == Kind::RsaPss {
                prov_text(
                    PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
                    F,
                    &format!("operation: {operation}"),
                );
                return false;
            }
            true
        }
        _ => {
            prov_text(
                ERR_R_INTERNAL_ERROR,
                F,
                &format!("invalid operation: {operation}"),
            );
            false
        }
    }
}

/// Which `set_ctx_params` an init applies.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Setter {
    Normal,
    Sigalg,
}

/// `rsa_signverify_init`.
///
/// # Safety
/// `vctx` is NULL or a live context; `vrsa` is NULL or live RSA key data; `params` is NULL or
/// an array.
unsafe fn signverify_init(
    vctx: *mut c_void,
    vrsa: *mut c_void,
    setter: Setter,
    params: *const OSSL_PARAM,
    operation: c_int,
) -> c_int {
    const F: &str = "rsa_signverify_init";
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx(vctx) }) else {
        return 0;
    };
    if vrsa.is_null() && c.rsa.is_null() {
        prov(PROV_R_NO_KEY_SET, F);
        return 0;
    }
    if !vrsa.is_null() {
        // SAFETY: the caller's live key data.
        if unsafe { rsa(vrsa.cast()) }.is_none() || !unsafe { RSA::up_ref(vrsa.cast()) } {
            return 0;
        }
        // SAFETY: the reference the context held, or NULL.
        unsafe { RSA::free(c.rsa) };
        c.rsa = vrsa.cast();
    }
    let Some(st) = c.key() else { return 0 };
    if !key_op_allowed(st.kind, operation) {
        return 0;
    }
    c.operation = operation;
    c.flag_allow_update = true;
    c.flag_allow_final = true;
    c.flag_allow_oneshot = true;
    c.saltlen = SALTLEN_AUTO_DIGEST_MAX;
    c.min_saltlen = -1;
    match st.kind {
        Kind::Rsa => c.pad_mode = PKCS1,
        Kind::RsaPss => {
            c.pad_mode = PSS;
            if st.pss.restricted() {
                let Some(mdname) = oaeppss_nid2name(st.pss.hash) else {
                    prov_text(
                        PROV_R_INVALID_DIGEST,
                        F,
                        "PSS restrictions lack hash algorithm",
                    );
                    return 0;
                };
                let Some(mgf1mdname) = oaeppss_nid2name(st.pss.mask_gen_hash) else {
                    prov_text(
                        PROV_R_INVALID_DIGEST,
                        F,
                        "PSS restrictions lack MGF1 hash algorithm",
                    );
                    return 0;
                };
                c.mdname = mdname.to_bytes().to_vec();
                c.mgf1_mdname = mgf1mdname.to_bytes().to_vec();
                c.saltlen = st.pss.salt_len;
                let propq = c.propq.clone();
                if !c.setup_mgf1_md(mgf1mdname, propq.as_deref())
                    || !c.setup_md(mdname, propq.as_deref())
                    || !c.check_parameters(st.pss.salt_len)
                {
                    return 0;
                }
            }
        }
    }
    match setter {
        // SAFETY: the caller's guarantee.
        Setter::Normal => unsafe { rsa_sig_set_ctx_params(vctx, params) },
        // SAFETY: the caller's guarantee.
        Setter::Sigalg => unsafe { rsa_sigalg_set_ctx_params(vctx, params) },
    }
}

ffi_callback! {
    /// `rsa_sign_init`.
    ///
    /// # Safety
    /// As for `signverify_init`.
    pub(crate) unsafe extern "C" fn rsa_sign_init(vctx: *mut c_void, vrsa: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { signverify_init(vctx, vrsa, Setter::Normal, params, EVP_PKEY_OP_SIGN) }
    }
}

ffi_callback! {
    /// `rsa_verify_init`.
    ///
    /// # Safety
    /// As for `signverify_init`.
    pub(crate) unsafe extern "C" fn rsa_verify_init(vctx: *mut c_void, vrsa: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { signverify_init(vctx, vrsa, Setter::Normal, params, EVP_PKEY_OP_VERIFY) }
    }
}

ffi_callback! {
    /// `rsa_verify_recover_init`.
    ///
    /// # Safety
    /// As for `signverify_init`.
    pub(crate) unsafe extern "C" fn rsa_verify_recover_init(vctx: *mut c_void, vrsa: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { signverify_init(vctx, vrsa, Setter::Normal, params, EVP_PKEY_OP_VERIFYRECOVER) }
    }
}

/// `rsa_sign_directly`: `tbs` (a digest when one is set) signed into `sig`.
///
/// # Safety
/// `sig` is NULL or has room for `sigsize` octets; `siglen` is writable.
unsafe fn sign_directly(
    c: &mut SigCtx,
    sig: *mut c_uchar,
    siglen: *mut usize,
    sigsize: usize,
    tbs: &[u8],
) -> c_int {
    const F: &str = "rsa_sign_directly";
    let Some(st) = c.key() else { return 0 };
    let rsasize = st.key.size();
    let mdsize = c.md_size();
    if sig.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { siglen.write(rsasize) };
        return 1;
    }
    if sigsize < rsasize {
        prov_text(
            PROV_R_INVALID_SIGNATURE_SIZE,
            F,
            &format!("is {sigsize}, should be at least {rsasize}"),
        );
        return 0;
    }
    // SAFETY: the caller's room for `sigsize` octets.
    let out = unsafe { core::slice::from_raw_parts_mut(sig, sigsize) };
    let mut rng = private_random(c.key_libctx());
    let outcome = if let (true, Some(md)) = (mdsize != 0, c.md.clone()) {
        if tbs.len() != mdsize {
            prov(PROV_R_INVALID_DIGEST_LENGTH, F);
            return 0;
        }
        // SAFETY: the digest; a static name.
        if unsafe { EVP_MD_is_a(md.ptr(), OSSL_DIGEST_NAME_MDC2.as_ptr()) } != 0 {
            if c.pad_mode != PKCS1 {
                prov_text(
                    PROV_R_INVALID_PADDING_MODE,
                    F,
                    "only PKCS#1 padding supported with MDC2",
                );
                return 0;
            }
            let (r, raised) = core_rsa::sign_octet_string(&st.key, tbs, out, &mut rng);
            raise_all(&raised);
            if r.is_err() {
                prov(ERR_R_RSA_LIB, F);
                return 0;
            }
            (r, Vec::new())
        } else {
            match c.pad_mode {
                X931 => {
                    if rsasize < tbs.len().saturating_add(1) {
                        prov_text(
                            PROV_R_KEY_SIZE_TOO_SMALL,
                            F,
                            &format!(
                                "RSA key size = {rsasize}, expected minimum = {}",
                                tbs.len().saturating_add(1)
                            ),
                        );
                        return 0;
                    }
                    let mut tbuf = tbs.to_vec();
                    tbuf.push(u8::try_from(x931_hash_id(c.mdnid) & 0xff).unwrap_or(0));
                    st.key.private_encrypt(&tbuf, out, Padding::X931, &mut rng)
                }
                PKCS1 => {
                    let (r, raised) = core_rsa::sign(&st.key, c.mdnid, tbs, out, &mut rng);
                    raise_all(&raised);
                    if r.is_err() {
                        prov(ERR_R_RSA_LIB, F);
                        return 0;
                    }
                    (r, Vec::new())
                }
                PSS => {
                    if c.restricted() {
                        let digest = c.md_size_int();
                        if c.saltlen == SALTLEN_DIGEST && c.min_saltlen > digest {
                            prov_text(
                                PROV_R_PSS_SALTLEN_TOO_SMALL,
                                F,
                                &format!(
                                    "minimum salt length set to {}, but the digest only gives {digest}",
                                    c.min_saltlen
                                ),
                            );
                            return 0;
                        }
                        if c.saltlen >= 0 && c.saltlen < c.min_saltlen {
                            prov_text(
                                PROV_R_PSS_SALTLEN_TOO_SMALL,
                                F,
                                &format!(
                                    "minimum salt length set to {}, but theactual salt length is only set to {}",
                                    c.min_saltlen, c.saltlen
                                ),
                            );
                            return 0;
                        }
                    }
                    let mut tbuf = vec![0u8; rsasize];
                    let mgf1 = c.mgf1_md.clone().unwrap_or_else(|| md.clone());
                    let (r, raised) = core_rsa::add_pss(
                        &mut tbuf,
                        st.key.bits(),
                        tbs,
                        &md,
                        &mgf1,
                        c.saltlen,
                        &mut rng,
                    );
                    raise_all(&raised);
                    if r.is_err() {
                        prov(ERR_R_RSA_LIB, F);
                        return 0;
                    }
                    st.key.private_encrypt(&tbuf, out, Padding::None, &mut rng)
                }
                _ => {
                    prov_text(
                        PROV_R_INVALID_PADDING_MODE,
                        F,
                        "Only X.931, PKCS#1 v1.5 or PSS padding allowed",
                    );
                    return 0;
                }
            }
        }
    } else {
        st.key
            .private_encrypt(tbs, out, Padding::from_number(c.pad_mode), &mut rng)
    };
    raise_all(&outcome.1);
    match outcome.0 {
        Ok(n) if n > 0 => {
            // SAFETY: the caller's guarantee.
            unsafe { siglen.write(n) };
            1
        }
        _ => {
            prov(ERR_R_RSA_LIB, F);
            0
        }
    }
}

ffi_callback! {
    /// `rsa_sign`: a one-shot signature, of a digest (or, after a message init, a message).
    ///
    /// # Safety
    /// `vctx` is a live context; `sig` is NULL or has room for `sigsize` octets; `siglen` is
    /// writable; `tbs` holds `tbslen` octets.
    pub(crate) unsafe extern "C" fn rsa_sign(vctx: *mut c_void, sig: *mut c_uchar, siglen: *mut usize, sigsize: usize, tbs: *const c_uchar, tbslen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if !c.flag_allow_oneshot {
            prov(PROV_R_ONESHOT_CALL_OUT_OF_ORDER, "rsa_sign");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(input) = (unsafe { bytes(tbs, tbslen) }) else { return 0 };
        if c.operation == EVP_PKEY_OP_SIGNMSG {
            if sig.is_null() {
                // SAFETY: the caller's guarantee.
                return unsafe { rsa_sign_message_final(vctx, sig, siglen, sigsize) };
            }
            // SAFETY: as above.
            return c_int::from(unsafe { rsa_signverify_message_update(vctx, tbs, tbslen) } == 1
                // SAFETY: as above.
                && unsafe { rsa_sign_message_final(vctx, sig, siglen, sigsize) } == 1);
        }
        // SAFETY: the caller's guarantee.
        unsafe { sign_directly(c, sig, siglen, sigsize, input) }
    }
}

/// `rsa_verify_recover`'s work: the digest (or data) recovered from `sig`. `internal` is the
/// X9.31 verification's own use, which takes no output size.
fn recover(
    c: &SigCtx,
    sig: &[u8],
    routsize: Option<usize>,
    rout: Option<&mut [u8]>,
) -> Option<usize> {
    const F: &str = "rsa_verify_recover";
    let st = c.key()?;
    let rsasize = st.key.size();
    if let Some(md) = c.md.clone() {
        match c.pad_mode {
            X931 => {
                let mut tbuf = vec![0u8; rsasize];
                let (r, raised) = st.key.public_decrypt(sig, &mut tbuf, Padding::X931);
                raise_all(&raised);
                let ret = match r {
                    Ok(n) if n > 0 => n - 1,
                    _ => {
                        prov(ERR_R_RSA_LIB, F);
                        return None;
                    }
                };
                if c_int::from(tbuf.get(ret).copied().unwrap_or(0)) != x931_hash_id(c.mdnid) {
                    prov(PROV_R_ALGORITHM_MISMATCH, F);
                    return None;
                }
                if ret != md.size() {
                    prov_text(
                        PROV_R_INVALID_DIGEST_LENGTH,
                        F,
                        &format!("Should be {}, but got {ret}", c.md_size_int()),
                    );
                    return None;
                }
                match (routsize, rout) {
                    (Some(size), Some(out)) => {
                        if size < ret {
                            prov_text(
                                PROV_R_OUTPUT_BUFFER_TOO_SMALL,
                                F,
                                &format!("buffer size is {size}, should be {ret}"),
                            );
                            return None;
                        }
                        out.get_mut(..ret)?.copy_from_slice(tbuf.get(..ret)?);
                    }
                    (_, Some(out)) => out.get_mut(..ret)?.copy_from_slice(tbuf.get(..ret)?),
                    _ => {}
                }
                Some(ret)
            }
            PKCS1 => {
                let mdsize = c.md_size_int();
                if mdsize <= 0 {
                    prov(PROV_R_INVALID_DIGEST_LENGTH, F);
                    return None;
                }
                let size = routsize.unwrap_or(0);
                if size < usize::try_from(mdsize).ok()? {
                    prov_text(
                        PROV_R_OUTPUT_BUFFER_TOO_SMALL,
                        F,
                        &format!("buffer size is {size}, should be {mdsize}"),
                    );
                    return None;
                }
                let (r, raised) = core_rsa::verify(&st.key, c.mdnid, None, sig);
                raise_all(&raised);
                let Ok(m) = r else {
                    prov(ERR_R_RSA_LIB, F);
                    return None;
                };
                if let Some(out) = rout {
                    out.get_mut(..m.len())?.copy_from_slice(&m);
                }
                Some(m.len())
            }
            _ => {
                prov_text(
                    PROV_R_INVALID_PADDING_MODE,
                    F,
                    "Only X.931 or PKCS#1 v1.5 padding allowed",
                );
                None
            }
        }
    } else {
        let size = routsize.unwrap_or(0);
        if size < rsasize {
            prov_text(
                PROV_R_OUTPUT_BUFFER_TOO_SMALL,
                F,
                &format!("buffer size is {size}, should be {rsasize}"),
            );
            return None;
        }
        let out = rout?;
        let (r, raised) = st
            .key
            .public_decrypt(sig, out, Padding::from_number(c.pad_mode));
        raise_all(&raised);
        match r {
            Ok(n) => Some(n),
            Err(()) => {
                prov(ERR_R_RSA_LIB, F);
                None
            }
        }
    }
}

ffi_callback! {
    /// `rsa_verify_recover`: the digest (or data) recovered from a signature.
    ///
    /// # Safety
    /// `vctx` is a live context; `rout` is NULL or has room for `routsize` octets; `routlen` is
    /// writable; `sig` holds `siglen` octets.
    pub(crate) unsafe extern "C" fn rsa_verify_recover(vctx: *mut c_void, rout: *mut c_uchar, routlen: *mut usize, routsize: usize, sig: *const c_uchar, siglen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if rout.is_null() {
            let Some(st) = c.key() else { return 0 };
            // SAFETY: the caller's guarantee.
            unsafe { routlen.write(st.key.size()) };
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { bytes(sig, siglen) }) else { return 0 };
        // SAFETY: the caller's room for `routsize` octets.
        let out = unsafe { core::slice::from_raw_parts_mut(rout, routsize) };
        match recover(c, s, Some(routsize), Some(out)) {
            Some(n) => {
                // SAFETY: the caller's guarantee.
                unsafe { routlen.write(n) };
                1
            }
            None => 0,
        }
    }
}

/// `rsa_verify_directly`: whether `sig` signs `tbs` (a digest when one is set).
fn verify_directly(c: &SigCtx, sig: &[u8], tbs: &[u8]) -> c_int {
    const F: &str = "rsa_verify_directly";
    let Some(st) = c.key() else { return 0 };
    let rsasize = st.key.size();
    let recovered: Vec<u8> = if let Some(md) = c.md.clone() {
        match c.pad_mode {
            PKCS1 => {
                let (r, raised) = core_rsa::verify(&st.key, c.mdnid, Some(tbs), sig);
                raise_all(&raised);
                if r.is_err() {
                    prov(ERR_R_RSA_LIB, F);
                    return 0;
                }
                return 1;
            }
            X931 => {
                let mut tbuf = vec![0u8; rsasize];
                let Some(n) = recover(c, sig, None, Some(&mut tbuf)) else {
                    return 0;
                };
                tbuf.truncate(n);
                tbuf
            }
            PSS => {
                let mdsize = c.md_size();
                if tbs.len() != mdsize {
                    prov_text(
                        PROV_R_INVALID_DIGEST_LENGTH,
                        F,
                        &format!("Should be {mdsize}, but got {}", tbs.len()),
                    );
                    return 0;
                }
                let mut tbuf = vec![0u8; rsasize];
                let (r, raised) = st.key.public_decrypt(sig, &mut tbuf, Padding::None);
                raise_all(&raised);
                if !matches!(r, Ok(n) if n > 0) {
                    prov(ERR_R_RSA_LIB, F);
                    return 0;
                }
                let mgf1 = c.mgf1_md.clone().unwrap_or_else(|| md.clone());
                let (r, raised) =
                    core_rsa::verify_pss(tbs, &md, &mgf1, &tbuf, st.key.bits(), c.saltlen);
                raise_all(&raised);
                if r.is_err() {
                    prov(ERR_R_RSA_LIB, F);
                    return 0;
                }
                return 1;
            }
            _ => {
                prov_text(
                    PROV_R_INVALID_PADDING_MODE,
                    F,
                    "Only X.931, PKCS#1 v1.5 or PSS padding allowed",
                );
                return 0;
            }
        }
    } else {
        let mut tbuf = vec![0u8; rsasize];
        let (r, raised) = st
            .key
            .public_decrypt(sig, &mut tbuf, Padding::from_number(c.pad_mode));
        raise_all(&raised);
        let n = match r {
            Ok(n) if n > 0 => n,
            _ => {
                prov(ERR_R_RSA_LIB, F);
                return 0;
            }
        };
        tbuf.truncate(n);
        tbuf
    };
    // A mismatch fails without an error, as OpenSSL's does.
    c_int::from(recovered == tbs)
}

ffi_callback! {
    /// `rsa_verify`: a one-shot verification, of a digest (or, after a message init, a
    /// message).
    ///
    /// # Safety
    /// `vctx` is a live context; `sig` holds `siglen` octets; `tbs` holds `tbslen`.
    pub(crate) unsafe extern "C" fn rsa_verify(vctx: *mut c_void, sig: *const c_uchar, siglen: usize, tbs: *const c_uchar, tbslen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if !c.flag_allow_oneshot {
            prov(PROV_R_ONESHOT_CALL_OUT_OF_ORDER, "rsa_verify");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let (Some(s), Some(t)) = (unsafe { bytes(sig, siglen) }, unsafe { bytes(tbs, tbslen) }) else { return 0 };
        if c.operation == EVP_PKEY_OP_VERIFYMSG {
            // SAFETY: the caller's guarantee, for each.
            return c_int::from(unsafe { verify_set_sig(vctx, s) }
                && unsafe { rsa_signverify_message_update(vctx, tbs, tbslen) } == 1
                && unsafe { rsa_verify_message_final(vctx) } == 1);
        }
        verify_directly(c, s, t)
    }
}

/// `rsa_verify_set_sig`: the signature a message verification checks.
///
/// # Safety
/// `vctx` is a live context.
unsafe fn verify_set_sig(vctx: *mut c_void, sig: &[u8]) -> bool {
    // SAFETY: a parameter over the caller's signature, which outlives the call.
    let params = [
        unsafe {
            crate::params::OSSL_PARAM_construct_octet_string(
                OSSL_SIGNATURE_PARAM_SIGNATURE.as_ptr(),
                sig.as_ptr().cast_mut().cast(),
                sig.len(),
            )
        },
        crate::params::end(),
    ];
    // SAFETY: the caller's context; the array.
    unsafe { rsa_sigalg_set_ctx_params(vctx, params.as_ptr()) == 1 }
}

/// `rsa_digest_signverify_init` and the composite algorithms' message inits: the digest
/// context started with `md`.
fn start_digest(c: &mut SigCtx, params: *const OSSL_PARAM) -> c_int {
    if c.mdctx.is_null() {
        // SAFETY: no preconditions.
        c.mdctx = unsafe { EVP_MD_CTX_new() };
        if c.mdctx.is_null() {
            return 0;
        }
    }
    let md = c.md.as_ref().map_or(ptr::null(), |m| m.ptr().cast_const());
    // SAFETY: the context's digest context; the digest; the caller's parameters.
    if unsafe { EVP_DigestInit_ex2(c.mdctx, md, params) } != 1 {
        // SAFETY: the context made above.
        unsafe { EVP_MD_CTX_free(c.mdctx) };
        c.mdctx = ptr::null_mut();
        return 0;
    }
    1
}

/// `rsa_digest_signverify_init`.
///
/// # Safety
/// `vctx` is NULL or a live context; `mdname` is NULL or a string; `vrsa` is NULL or live key
/// data; `params` is NULL or an array.
unsafe fn digest_signverify_init(
    vctx: *mut c_void,
    mdname: *const c_char,
    vrsa: *mut c_void,
    params: *const OSSL_PARAM,
    operation: c_int,
) -> c_int {
    // SAFETY: the caller's guarantee.
    if unsafe { signverify_init(vctx, vrsa, Setter::Normal, params, operation) } != 1 {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx(vctx) }) else {
        return 0;
    };
    if !mdname.is_null() {
        // SAFETY: the caller's string.
        let name = unsafe { CStr::from_ptr(mdname) };
        let same = name.to_bytes().eq_ignore_ascii_case(&c.mdname);
        if name.is_empty() || !same {
            let propq = c.propq.clone();
            if !c.setup_md(name, propq.as_deref()) {
                return 0;
            }
        }
    }
    c.flag_allow_md = false;
    start_digest(c, params)
}

ffi_callback! {
    /// `rsa_digest_sign_init`.
    ///
    /// # Safety
    /// As for `digest_signverify_init`.
    pub(crate) unsafe extern "C" fn rsa_digest_sign_init(vctx: *mut c_void, mdname: *const c_char, vrsa: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { digest_signverify_init(vctx, mdname, vrsa, params, EVP_PKEY_OP_SIGNMSG) }
    }
}

ffi_callback! {
    /// `rsa_digest_verify_init`.
    ///
    /// # Safety
    /// As for `digest_signverify_init`.
    pub(crate) unsafe extern "C" fn rsa_digest_verify_init(vctx: *mut c_void, mdname: *const c_char, vrsa: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { digest_signverify_init(vctx, mdname, vrsa, params, EVP_PKEY_OP_VERIFYMSG) }
    }
}

ffi_callback! {
    /// `rsa_signverify_message_update`.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `data` holds `datalen` octets.
    pub(crate) unsafe extern "C" fn rsa_signverify_message_update(vctx: *mut c_void, data: *const c_uchar, datalen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if c.mdctx.is_null() {
            return 0;
        }
        if !c.flag_allow_update {
            prov(PROV_R_UPDATE_CALL_OUT_OF_ORDER, "rsa_signverify_message_update");
            return 0;
        }
        c.flag_allow_oneshot = false;
        // SAFETY: the context's digest context; the caller's data.
        unsafe { EVP_DigestUpdate(c.mdctx, data.cast(), datalen) }
    }
}

ffi_callback! {
    /// `rsa_digest_sign_update` and `rsa_digest_verify_update`: not for a composite algorithm.
    ///
    /// # Safety
    /// As for `rsa_signverify_message_update`.
    pub(crate) unsafe extern "C" fn rsa_digest_signverify_update(vctx: *mut c_void, data: *const c_uchar, datalen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if c.flag_sigalg {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { rsa_signverify_message_update(vctx, data, datalen) }
    }
}

/// The message's digest, finishing the digest context; the update and final calls are spent.
fn finish_digest(c: &mut SigCtx) -> Option<Vec<u8>> {
    let mut digest = [0u8; 64];
    let mut dlen: c_uint = 0;
    // SAFETY: the context's digest context; room for any digest.
    if unsafe { EVP_DigestFinal_ex(c.mdctx, digest.as_mut_ptr(), &raw mut dlen) } != 1 {
        return None;
    }
    c.flag_allow_update = false;
    c.flag_allow_oneshot = false;
    c.flag_allow_final = false;
    digest
        .get(..usize::try_from(dlen).ok()?)
        .map(<[u8]>::to_vec)
}

ffi_callback! {
    /// `rsa_sign_message_final`: the message's digest signed (only the size for NULL `sig`).
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `sig` is NULL or has room for `sigsize` octets;
    /// `siglen` is writable.
    pub(crate) unsafe extern "C" fn rsa_sign_message_final(vctx: *mut c_void, sig: *mut c_uchar, siglen: *mut usize, sigsize: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if c.mdctx.is_null() {
            return 0;
        }
        if !c.flag_allow_final {
            prov(PROV_R_FINAL_CALL_OUT_OF_ORDER, "rsa_sign_message_final");
            return 0;
        }
        let digest = if sig.is_null() {
            Vec::new()
        } else {
            let Some(d) = finish_digest(c) else { return 0 };
            d
        };
        // SAFETY: the caller's guarantee.
        unsafe { sign_directly(c, sig, siglen, sigsize, &digest) }
    }
}

ffi_callback! {
    /// `rsa_digest_sign_final`: as `rsa_sign_message_final`; digests may be set again after.
    ///
    /// # Safety
    /// As for `rsa_sign_message_final`.
    pub(crate) unsafe extern "C" fn rsa_digest_sign_final(vctx: *mut c_void, sig: *mut c_uchar, siglen: *mut usize, sigsize: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if c.flag_sigalg {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let ok = unsafe { rsa_sign_message_final(vctx, sig, siglen, sigsize) } == 1;
        c.flag_allow_md = true;
        c_int::from(ok)
    }
}

ffi_callback! {
    /// `rsa_verify_message_final`: the stored signature checked against the message's digest.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context.
    pub(crate) unsafe extern "C" fn rsa_verify_message_final(vctx: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if c.mdctx.is_null() {
            return 0;
        }
        if !c.flag_allow_final {
            prov(PROV_R_FINAL_CALL_OUT_OF_ORDER, "rsa_verify_message_final");
            return 0;
        }
        let Some(digest) = finish_digest(c) else { return 0 };
        let sig = c.sig.clone().unwrap_or_default();
        verify_directly(c, &sig, &digest)
    }
}

ffi_callback! {
    /// `rsa_digest_verify_final`.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `sig` holds `siglen` octets.
    pub(crate) unsafe extern "C" fn rsa_digest_verify_final(vctx: *mut c_void, sig: *const c_uchar, siglen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if c.flag_sigalg {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let ok = unsafe { bytes(sig, siglen) }.is_some_and(|s| {
            // SAFETY: the caller's context.
            let set = unsafe { verify_set_sig(vctx, s) };
            // SAFETY: as above.
            set && unsafe { rsa_verify_message_final(vctx) } == 1
        });
        c.flag_allow_md = true;
        c_int::from(ok)
    }
}

ffi_callback! {
    /// `rsa_freectx`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context the caller gives up.
    pub(crate) unsafe extern "C" fn rsa_sig_freectx(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<SigCtx>(vctx) };
    }
}

ffi_callback! {
    /// `rsa_dupctx`: references to the key and digests, a copy of the digest context.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context.
    pub(crate) unsafe extern "C" fn rsa_sig_dupctx(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return ptr::null_mut() };
        // SAFETY: the context's key, or NULL.
        if !c.rsa.is_null() && !unsafe { RSA::up_ref(c.rsa) } {
            return ptr::null_mut();
        }
        let mut copy = SigCtx {
            libctx: c.libctx,
            propq: c.propq.clone(),
            rsa: c.rsa,
            operation: c.operation,
            flag_sigalg: c.flag_sigalg,
            flag_allow_md: c.flag_allow_md,
            mgf1_md_set: c.mgf1_md_set,
            flag_allow_update: c.flag_allow_update,
            flag_allow_final: c.flag_allow_final,
            flag_allow_oneshot: c.flag_allow_oneshot,
            md: c.md.clone(),
            mdctx: ptr::null_mut(),
            mdnid: c.mdnid,
            mdname: c.mdname.clone(),
            pad_mode: c.pad_mode,
            mgf1_md: c.mgf1_md.clone(),
            mgf1_mdnid: c.mgf1_mdnid,
            mgf1_mdname: c.mgf1_mdname.clone(),
            saltlen: c.saltlen,
            min_saltlen: c.min_saltlen,
            sig: c.sig.clone(),
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

/// A name as a C string for `OSSL_PARAM_set_utf8_string`.
fn c_name(b: &[u8]) -> CString {
    CString::new(b.to_vec()).unwrap_or_default()
}

ffi_callback! {
    /// `rsa_get_ctx_params`.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn rsa_sig_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "rsa_get_ctx_params";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        let find = |key: &CStr| {
            // SAFETY: the caller's array; a static name.
            unsafe { OSSL_PARAM_locate(params, key.as_ptr()) }
        };
        let p = find(OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
        if !p.is_null() {
            let Some(aid) = signature_aid(c) else { return 0 };
            // SAFETY: a parameter of the array; the octets.
            if unsafe { OSSL_PARAM_set_octet_string(p, aid.as_ptr().cast(), aid.len()) } != 1 {
                return 0;
            }
        }
        let p = find(OSSL_SIGNATURE_PARAM_PAD_MODE);
        // SAFETY: a parameter of the array, or NULL.
        if let Some(pm) = unsafe { p.as_mut() } {
            if pm.data_type == OSSL_PARAM_INTEGER as u32 {
                // SAFETY: as above.
                if unsafe { OSSL_PARAM_set_int(pm, c.pad_mode) } != 1 {
                    return 0;
                }
            } else if pm.data_type == OSSL_PARAM_UTF8_STRING as u32 {
                match PADDING_ITEMS.iter().find(|(id, _)| *id == c.pad_mode) {
                    // SAFETY: as above; a static string.
                    Some((_, word)) => if unsafe { OSSL_PARAM_set_utf8_string(pm, word.as_ptr()) } != 1 {
                        return 0;
                    },
                    None => prov(ERR_R_INTERNAL_ERROR, F),
                }
            } else {
                return 0;
            }
        }
        for (key, value) in [
            (OSSL_SIGNATURE_PARAM_DIGEST, c_name(&c.mdname)),
            (OSSL_SIGNATURE_PARAM_MGF1_DIGEST, c_name(&c.mgf1_mdname)),
        ] {
            let p = find(key);
            // SAFETY: a parameter of the array; a string.
            if !p.is_null() && unsafe { OSSL_PARAM_set_utf8_string(p, value.as_ptr()) } != 1 {
                return 0;
            }
        }
        let p = find(OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
        // SAFETY: a parameter of the array, or NULL.
        if let Some(pm) = unsafe { p.as_mut() } {
            if pm.data_type == OSSL_PARAM_INTEGER as u32 {
                // SAFETY: as above.
                if unsafe { OSSL_PARAM_set_int(pm, c.saltlen) } != 1 {
                    return 0;
                }
            } else if pm.data_type == OSSL_PARAM_UTF8_STRING as u32 {
                let word = match c.saltlen {
                    SALTLEN_DIGEST => Some(OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST),
                    SALTLEN_MAX => Some(OSSL_PKEY_RSA_PSS_SALT_LEN_MAX),
                    SALTLEN_AUTO => Some(OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO),
                    SALTLEN_AUTO_DIGEST_MAX => Some(OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX),
                    _ => None,
                };
                match word {
                    // SAFETY: as above; a static string.
                    Some(w) => if unsafe { OSSL_PARAM_set_utf8_string(pm, w.as_ptr()) } != 1 {
                        return 0;
                    },
                    None => {
                        // `BIO_snprintf(p->data, p->data_size, "%d")`: the number, cut to
                        // the buffer, and a failure when it doesn't fit.
                        let digits = c.saltlen.to_string();
                        if pm.data.is_null() || pm.data_size == 0 {
                            return 0;
                        }
                        // SAFETY: the parameter's buffer of `data_size` octets.
                        let buf = unsafe { core::slice::from_raw_parts_mut(pm.data.cast::<u8>(), pm.data_size) };
                        let n = digits.len().min(buf.len() - 1);
                        let text = digits.as_bytes().iter().take(n).chain(core::iter::once(&0));
                        for (b, &d) in buf.iter_mut().zip(text) {
                            *b = d;
                        }
                        if n < digits.len() {
                            return 0;
                        }
                        pm.return_size = n;
                    }
                }
            }
        }
        1
    }
}

/// `known_gettable_ctx_params`.
static GETTABLE: Params<6> = Params([
    defn(
        OSSL_SIGNATURE_PARAM_ALGORITHM_ID,
        OSSL_PARAM_OCTET_STRING,
        0,
    ),
    defn(OSSL_SIGNATURE_PARAM_PAD_MODE, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_SIGNATURE_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, OSSL_PARAM_UTF8_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `rsa_gettable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn rsa_sig_gettable_ctx_params(_vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        GETTABLE.0.as_ptr()
    }
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

/// A UTF-8 string parameter's text, or `None`.
fn utf8_data(p: &OSSL_PARAM) -> Option<&CStr> {
    if p.data.is_null() {
        return None;
    }
    // SAFETY: a UTF-8 string parameter's data is a string.
    Some(unsafe { CStr::from_ptr(p.data.cast()) })
}

ffi_callback! {
    /// `rsa_set_ctx_params`: the digest (and properties), pad mode, salt length, and MGF1
    /// digest (and properties), checked in that order; the pad mode and salt length are
    /// committed before the digests are set up.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn rsa_sig_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "rsa_set_ctx_params";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        let find = |key: &CStr| {
            // SAFETY: the caller's array; a static name.
            unsafe { locate(params, key) }
        };
        let mut pad_mode = c.pad_mode;
        let mut saltlen = c.saltlen;
        let mut mdname = None;
        let mut mdprops = None;
        if let Some(p) = find(OSSL_SIGNATURE_PARAM_DIGEST) {
            // SAFETY: a parameter of the array.
            let Some(n) = (unsafe { read_string::<MAX_NAME>(p) }) else { return 0 };
            mdname = Some(n);
            if let Some(q) = find(OSSL_SIGNATURE_PARAM_PROPERTIES) {
                // SAFETY: as above.
                let Some(v) = (unsafe { read_string::<MAX_PROPQUERY>(q) }) else { return 0 };
                mdprops = Some(v);
            }
        }
        if let Some(p) = find(OSSL_SIGNATURE_PARAM_PAD_MODE) {
            if p.data_type == OSSL_PARAM_INTEGER as u32 {
                // SAFETY: a parameter of the array; a local.
                if unsafe { OSSL_PARAM_get_int(p, &raw mut pad_mode) } != 1 {
                    return 0;
                }
            } else if p.data_type == OSSL_PARAM_UTF8_STRING as u32 {
                let Some(word) = utf8_data(p) else { return 0 };
                // An unknown name leaves the mode as it was.
                if let Some((id, _)) = PADDING_ITEMS.iter().find(|(_, w)| *w == word) {
                    pad_mode = *id;
                }
            } else {
                return 0;
            }
            let kind_is_rsa = c.kind() == Some(Kind::Rsa);
            let bad = match pad_mode {
                OAEP => Some(Some("OAEP padding not allowed for signing / verifying")),
                PSS => (c.operation & (EVP_PKEY_OP_SIGN | EVP_PKEY_OP_SIGNMSG | EVP_PKEY_OP_VERIFY | EVP_PKEY_OP_VERIFYMSG) == 0)
                    .then_some(Some("PSS padding only allowed for sign and verify operations")),
                PKCS1 => (!kind_is_rsa).then_some(Some("PKCS#1 padding not allowed with RSA-PSS")),
                NONE => (!kind_is_rsa).then_some(Some("No padding not allowed with RSA-PSS")),
                X931 => (!kind_is_rsa).then_some(Some("X.931 padding not allowed with RSA-PSS")),
                _ => Some(None),
            };
            match bad {
                Some(Some(t)) => {
                    prov_text(PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE, F, t);
                    return 0;
                }
                Some(None) => {
                    prov(PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE, F);
                    return 0;
                }
                None => {}
            }
        }
        if let Some(p) = find(OSSL_SIGNATURE_PARAM_PSS_SALTLEN) {
            if pad_mode != PSS {
                prov_text(PROV_R_NOT_SUPPORTED, F, "PSS saltlen can only be specified if PSS padding has been specified first");
                return 0;
            }
            if p.data_type == OSSL_PARAM_INTEGER as u32 {
                // SAFETY: a parameter of the array; a local.
                if unsafe { OSSL_PARAM_get_int(p, &raw mut saltlen) } != 1 {
                    return 0;
                }
            } else if p.data_type == OSSL_PARAM_UTF8_STRING as u32 {
                let Some(word) = utf8_data(p) else { return 0 };
                saltlen = if word == OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST {
                    SALTLEN_DIGEST
                } else if word == OSSL_PKEY_RSA_PSS_SALT_LEN_MAX {
                    SALTLEN_MAX
                } else if word == OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO {
                    SALTLEN_AUTO
                } else if word == OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX {
                    SALTLEN_AUTO_DIGEST_MAX
                } else {
                    // SAFETY: a string.
                    unsafe { libc::atoi(word.as_ptr()) }
                };
            } else {
                return 0;
            }
            if saltlen < SALTLEN_AUTO_DIGEST_MAX {
                prov(PROV_R_INVALID_SALT_LENGTH, F);
                return 0;
            }
            if c.restricted() {
                match saltlen {
                    SALTLEN_AUTO | SALTLEN_AUTO_DIGEST_MAX => {
                        if c.operation & (EVP_PKEY_OP_VERIFY | EVP_PKEY_OP_VERIFYMSG) == 0 {
                            prov_text(PROV_R_INVALID_SALT_LENGTH, F, "Cannot use autodetected salt length");
                            return 0;
                        }
                    }
                    SALTLEN_DIGEST => {
                        let d = c.md_size_int();
                        if c.min_saltlen > d {
                            prov_text(
                                PROV_R_PSS_SALTLEN_TOO_SMALL,
                                F,
                                &format!("Should be more than {}, but would be set to match digest size ({d})", c.min_saltlen),
                            );
                            return 0;
                        }
                    }
                    s => {
                        if s >= 0 && s < c.min_saltlen {
                            prov_text(
                                PROV_R_PSS_SALTLEN_TOO_SMALL,
                                F,
                                &format!("Should be more than {}, but would be set to {s}", c.min_saltlen),
                            );
                            return 0;
                        }
                    }
                }
            }
        }
        let mut mgf1name = None;
        let mut mgf1props = None;
        if let Some(p) = find(OSSL_SIGNATURE_PARAM_MGF1_DIGEST) {
            // SAFETY: a parameter of the array.
            let Some(n) = (unsafe { read_string::<MAX_NAME>(p) }) else { return 0 };
            mgf1name = Some(n);
            if let Some(q) = find(OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES) {
                // SAFETY: as above.
                let Some(v) = (unsafe { read_string::<MAX_PROPQUERY>(q) }) else { return 0 };
                mgf1props = Some(v);
            }
            if pad_mode != PSS {
                prov(PROV_R_INVALID_MGF1_MD, F);
                return 0;
            }
        }
        c.saltlen = saltlen;
        c.pad_mode = pad_mode;
        if c.md.is_none() && mdname.is_none() && pad_mode == PSS {
            mdname = Some(RSA_DEFAULT_DIGEST_NAME.to_owned());
        }
        if let Some(n) = &mgf1name
            && !c.setup_mgf1_md(n, mgf1props.as_deref())
        {
            return 0;
        }
        match &mdname {
            Some(n) => {
                if !c.setup_md(n, mdprops.as_deref()) {
                    return 0;
                }
            }
            None => {
                if !c.check_padding(None, None, c.mdnid) {
                    return 0;
                }
            }
        }
        1
    }
}

/// `settable_ctx_params` and, inside a digest operation, `settable_ctx_params_no_digest`.
static SETTABLE: Params<7> = Params([
    defn(OSSL_SIGNATURE_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_SIGNATURE_PARAM_PROPERTIES, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_SIGNATURE_PARAM_PAD_MODE, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, OSSL_PARAM_UTF8_STRING, 0),
    defn(
        OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES,
        OSSL_PARAM_UTF8_STRING,
        0,
    ),
    defn(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, OSSL_PARAM_UTF8_STRING, 0),
    PARAM_END,
]);
static SETTABLE_NO_DIGEST: Params<5> = Params([
    defn(OSSL_SIGNATURE_PARAM_PAD_MODE, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, OSSL_PARAM_UTF8_STRING, 0),
    defn(
        OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES,
        OSSL_PARAM_UTF8_STRING,
        0,
    ),
    defn(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, OSSL_PARAM_UTF8_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `rsa_settable_ctx_params`.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context.
    pub(crate) unsafe extern "C" fn rsa_sig_settable_ctx_params(vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        match unsafe { ctx(vctx) } {
            Some(c) if !c.flag_allow_md => SETTABLE_NO_DIGEST.0.as_ptr(),
            _ => SETTABLE.0.as_ptr(),
        }
    }
}

ffi_callback! {
    /// `rsa_get_ctx_md_params`.
    ///
    /// # Safety
    /// `vctx` is a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn rsa_get_ctx_md_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
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
    /// `rsa_set_ctx_md_params`.
    ///
    /// # Safety
    /// `vctx` is a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn rsa_set_ctx_md_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
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
    /// `rsa_gettable_ctx_md_params`.
    ///
    /// # Safety
    /// `vctx` is a live context.
    pub(crate) unsafe extern "C" fn rsa_gettable_ctx_md_params(vctx: *mut c_void) -> *const OSSL_PARAM
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
    /// `rsa_settable_ctx_md_params`.
    ///
    /// # Safety
    /// `vctx` is a live context.
    pub(crate) unsafe extern "C" fn rsa_settable_ctx_md_params(vctx: *mut c_void) -> *const OSSL_PARAM
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
    /// `rsa_sigalg_set_ctx_params`: only a message verification's signature.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn rsa_sigalg_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
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
                c.sig = Some(unsafe { bytes(data.cast::<u8>(), n) }.unwrap_or_default().to_vec());
                // SAFETY: the allocation just made, freed once.
                unsafe { mem::release(data) };
            }
        }
        1
    }
}

/// `settable_sigalg_ctx_params`.
static SIGALG_SETTABLE: Params<2> = Params([
    defn(OSSL_SIGNATURE_PARAM_SIGNATURE, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `rsa_sigalg_settable_ctx_params`: the signature, for a message verification only.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context.
    pub(crate) unsafe extern "C" fn rsa_sigalg_settable_ctx_params(vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        match unsafe { ctx(vctx) } {
            Some(c) if c.operation == EVP_PKEY_OP_VERIFYMSG => SIGALG_SETTABLE.0.as_ptr(),
            _ => ptr::null(),
        }
    }
}

/// `rsa_sigalg_query_key_types`'s list.
struct KeyTypes([*const c_char; 2]);
// SAFETY: pointers to static strings.
unsafe impl Sync for KeyTypes {}
static KEY_TYPES: KeyTypes = KeyTypes([c"RSA".as_ptr(), ptr::null()]);

ffi_callback! {
    /// `rsa_sigalg_query_key_types`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn rsa_sigalg_query_key_types() -> *const *const c_char
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        KEY_TYPES.0.as_ptr()
    }
}

/// `rsa_sigalg_signverify_init`: an RSA key, the fixed digest, PKCS #1 v1.5, and the digest
/// context started.
///
/// # Safety
/// As for `signverify_init`.
unsafe fn sigalg_init(
    vctx: *mut c_void,
    vrsa: *mut c_void,
    params: *const OSSL_PARAM,
    mdname: &CStr,
    operation: c_int,
) -> c_int {
    // SAFETY: the caller's guarantee.
    if unsafe { signverify_init(vctx, vrsa, Setter::Sigalg, params, operation) } != 1 {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx(vctx) }) else {
        return 0;
    };
    if c.pad_mode == PSS {
        prov(
            PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
            "rsa_sigalg_signverify_init",
        );
        return 0;
    }
    if !c.setup_md(mdname, None) {
        return 0;
    }
    c.pad_mode = PKCS1;
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

/// `ossl_rsa_signature_functions`.
pub(crate) static RSA_SIGNATURE: Dispatch<24> = Dispatch([
    entry!(OSSL_FUNC_SIGNATURE_NEWCTX, rsa_sig_newctx, NewCtxFn),
    entry!(OSSL_FUNC_SIGNATURE_SIGN_INIT, rsa_sign_init, InitFn),
    entry!(OSSL_FUNC_SIGNATURE_SIGN, rsa_sign, SignFn),
    entry!(OSSL_FUNC_SIGNATURE_VERIFY_INIT, rsa_verify_init, InitFn),
    entry!(OSSL_FUNC_SIGNATURE_VERIFY, rsa_verify, VerifyFn),
    entry!(
        OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT,
        rsa_verify_recover_init,
        InitFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_VERIFY_RECOVER,
        rsa_verify_recover,
        SignFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
        rsa_digest_sign_init,
        DigestInitFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
        rsa_digest_signverify_update,
        UpdateFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
        rsa_digest_sign_final,
        SignFinalFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
        rsa_digest_verify_init,
        DigestInitFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
        rsa_digest_signverify_update,
        UpdateFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
        rsa_digest_verify_final,
        VerifyFinalFn
    ),
    entry!(OSSL_FUNC_SIGNATURE_FREECTX, rsa_sig_freectx, FreeCtxFn),
    entry!(OSSL_FUNC_SIGNATURE_DUPCTX, rsa_sig_dupctx, DupCtxFn),
    entry!(
        OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
        rsa_sig_get_ctx_params,
        GetParamsFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
        rsa_sig_gettable_ctx_params,
        ListFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        rsa_sig_set_ctx_params,
        SetParamsFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        rsa_sig_settable_ctx_params,
        ListFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
        rsa_get_ctx_md_params,
        GetParamsFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
        rsa_gettable_ctx_md_params,
        MdListFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
        rsa_set_ctx_md_params,
        SetParamsFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
        rsa_settable_ctx_md_params,
        MdListFn
    ),
    END,
]);

/// `IMPL_RSA_SIGALG`: a composite algorithm's inits and dispatch table.
macro_rules! rsa_sigalg {
    ($table:ident, $md:expr, $sign:ident, $sign_msg:ident, $verify:ident, $verify_msg:ident, $recover:ident) => {
        ffi_callback! {
            /// The composite algorithm's `sign_init`.
            ///
            /// # Safety
            /// As for `signverify_init`.
            pub(crate) unsafe extern "C" fn $sign(vctx: *mut c_void, vrsa: *mut c_void, params: *const OSSL_PARAM) -> c_int
            where failure = 0, library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                unsafe { sigalg_init(vctx, vrsa, params, $md, EVP_PKEY_OP_SIGN) }
            }
        }
        ffi_callback! {
            /// The composite algorithm's `sign_message_init`.
            ///
            /// # Safety
            /// As for `signverify_init`.
            pub(crate) unsafe extern "C" fn $sign_msg(vctx: *mut c_void, vrsa: *mut c_void, params: *const OSSL_PARAM) -> c_int
            where failure = 0, library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                unsafe { sigalg_init(vctx, vrsa, params, $md, EVP_PKEY_OP_SIGNMSG) }
            }
        }
        ffi_callback! {
            /// The composite algorithm's `verify_init`.
            ///
            /// # Safety
            /// As for `signverify_init`.
            pub(crate) unsafe extern "C" fn $verify(vctx: *mut c_void, vrsa: *mut c_void, params: *const OSSL_PARAM) -> c_int
            where failure = 0, library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                unsafe { sigalg_init(vctx, vrsa, params, $md, EVP_PKEY_OP_VERIFY) }
            }
        }
        ffi_callback! {
            /// The composite algorithm's `verify_message_init`.
            ///
            /// # Safety
            /// As for `signverify_init`.
            pub(crate) unsafe extern "C" fn $verify_msg(vctx: *mut c_void, vrsa: *mut c_void, params: *const OSSL_PARAM) -> c_int
            where failure = 0, library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                unsafe { sigalg_init(vctx, vrsa, params, $md, EVP_PKEY_OP_VERIFYMSG) }
            }
        }
        ffi_callback! {
            /// The composite algorithm's `verify_recover_init`.
            ///
            /// # Safety
            /// As for `signverify_init`.
            pub(crate) unsafe extern "C" fn $recover(vctx: *mut c_void, vrsa: *mut c_void, params: *const OSSL_PARAM) -> c_int
            where failure = 0, library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                unsafe { sigalg_init(vctx, vrsa, params, $md, EVP_PKEY_OP_VERIFYRECOVER) }
            }
        }
        /// The composite algorithm's dispatch table.
        pub(crate) static $table: Dispatch<21> = Dispatch([
            entry!(OSSL_FUNC_SIGNATURE_NEWCTX, rsa_sig_newctx, NewCtxFn),
            entry!(OSSL_FUNC_SIGNATURE_SIGN_INIT, $sign, InitFn),
            entry!(OSSL_FUNC_SIGNATURE_SIGN, rsa_sign, SignFn),
            entry!(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT, $sign_msg, InitFn),
            entry!(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE, rsa_signverify_message_update, UpdateFn),
            entry!(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL, rsa_sign_message_final, SignFinalFn),
            entry!(OSSL_FUNC_SIGNATURE_VERIFY_INIT, $verify, InitFn),
            entry!(OSSL_FUNC_SIGNATURE_VERIFY, rsa_verify, VerifyFn),
            entry!(OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT, $verify_msg, InitFn),
            entry!(OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE, rsa_signverify_message_update, UpdateFn),
            entry!(OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL, rsa_verify_message_final, MessageFinalFn),
            entry!(OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT, $recover, InitFn),
            entry!(OSSL_FUNC_SIGNATURE_VERIFY_RECOVER, rsa_verify_recover, SignFn),
            entry!(OSSL_FUNC_SIGNATURE_FREECTX, rsa_sig_freectx, FreeCtxFn),
            entry!(OSSL_FUNC_SIGNATURE_DUPCTX, rsa_sig_dupctx, DupCtxFn),
            entry!(OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES, rsa_sigalg_query_key_types, KeyTypesFn),
            entry!(OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, rsa_sig_get_ctx_params, GetParamsFn),
            entry!(OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, rsa_sig_gettable_ctx_params, ListFn),
            entry!(OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, rsa_sigalg_set_ctx_params, SetParamsFn),
            entry!(OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, rsa_sigalg_settable_ctx_params, ListFn),
            END,
        ]);
    };
}

rsa_sigalg!(
    RSA_RIPEMD160_SIGNATURE,
    c"RIPEMD160",
    ripemd160_sign_init,
    ripemd160_sign_message_init,
    ripemd160_verify_init,
    ripemd160_verify_message_init,
    ripemd160_verify_recover_init
);
rsa_sigalg!(
    RSA_SHA1_SIGNATURE,
    c"SHA1",
    sha1_sign_init,
    sha1_sign_message_init,
    sha1_verify_init,
    sha1_verify_message_init,
    sha1_verify_recover_init
);
rsa_sigalg!(
    RSA_SHA224_SIGNATURE,
    c"SHA2-224",
    sha224_sign_init,
    sha224_sign_message_init,
    sha224_verify_init,
    sha224_verify_message_init,
    sha224_verify_recover_init
);
rsa_sigalg!(
    RSA_SHA256_SIGNATURE,
    c"SHA2-256",
    sha256_sign_init,
    sha256_sign_message_init,
    sha256_verify_init,
    sha256_verify_message_init,
    sha256_verify_recover_init
);
rsa_sigalg!(
    RSA_SHA384_SIGNATURE,
    c"SHA2-384",
    sha384_sign_init,
    sha384_sign_message_init,
    sha384_verify_init,
    sha384_verify_message_init,
    sha384_verify_recover_init
);
rsa_sigalg!(
    RSA_SHA512_SIGNATURE,
    c"SHA2-512",
    sha512_sign_init,
    sha512_sign_message_init,
    sha512_verify_init,
    sha512_verify_message_init,
    sha512_verify_recover_init
);
rsa_sigalg!(
    RSA_SHA512_224_SIGNATURE,
    c"SHA2-512/224",
    sha512_224_sign_init,
    sha512_224_sign_message_init,
    sha512_224_verify_init,
    sha512_224_verify_message_init,
    sha512_224_verify_recover_init
);
rsa_sigalg!(
    RSA_SHA512_256_SIGNATURE,
    c"SHA2-512/256",
    sha512_256_sign_init,
    sha512_256_sign_message_init,
    sha512_256_verify_init,
    sha512_256_verify_message_init,
    sha512_256_verify_recover_init
);
rsa_sigalg!(
    RSA_SHA3_224_SIGNATURE,
    c"SHA3-224",
    sha3_224_sign_init,
    sha3_224_sign_message_init,
    sha3_224_verify_init,
    sha3_224_verify_message_init,
    sha3_224_verify_recover_init
);
rsa_sigalg!(
    RSA_SHA3_256_SIGNATURE,
    c"SHA3-256",
    sha3_256_sign_init,
    sha3_256_sign_message_init,
    sha3_256_verify_init,
    sha3_256_verify_message_init,
    sha3_256_verify_recover_init
);
rsa_sigalg!(
    RSA_SHA3_384_SIGNATURE,
    c"SHA3-384",
    sha3_384_sign_init,
    sha3_384_sign_message_init,
    sha3_384_verify_init,
    sha3_384_verify_message_init,
    sha3_384_verify_recover_init
);
rsa_sigalg!(
    RSA_SHA3_512_SIGNATURE,
    c"SHA3-512",
    sha3_512_sign_init,
    sha3_512_sign_message_init,
    sha3_512_verify_init,
    sha3_512_verify_message_init,
    sha3_512_verify_recover_init
);
rsa_sigalg!(
    RSA_SM3_SIGNATURE,
    c"SM3",
    sm3_sign_init,
    sm3_sign_message_init,
    sm3_verify_init,
    sm3_verify_message_init,
    sm3_verify_recover_init
);
