//! RSA keys (`RSA`; `crypto/rsa/`): the object the default provider's RSA and RSA-PSS key
//! managers keep as their key data, as OpenSSL's are, so the legacy `RSA_*` functions (step
//! 4.3d) and `EVP_PKEY_get0_RSA` see the same key. The arithmetic and paddings are
//! `rustyssl_crypto::rsa`'s; this module gives them OpenSSL's digests (fetched with a library
//! context and properties), random octets, and error queue.

use core::ffi::{CStr, c_char, c_int, c_uint};
use core::ptr;
use std::sync::{Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    ERR_LIB_RSA, ERR_R_BN_LIB, ERR_R_FETCH_FAILED, ERR_R_INTERNAL_ERROR, EVP_MD, EVP_MD_CTX,
    OSSL_LIB_CTX, RSA, RSA_R_BAD_E_VALUE, RSA_R_BAD_FIXED_HEADER_DECRYPT, RSA_R_BAD_PAD_BYTE_COUNT,
    RSA_R_BAD_SIGNATURE, RSA_R_BLOCK_TYPE_IS_NOT_01, RSA_R_DATA_GREATER_THAN_MOD_LEN,
    RSA_R_DATA_TOO_LARGE, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE, RSA_R_DATA_TOO_LARGE_FOR_MODULUS,
    RSA_R_DATA_TOO_SMALL, RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE, RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY,
    RSA_R_FIRST_OCTET_INVALID, RSA_R_INVALID_DIGEST_LENGTH, RSA_R_INVALID_HEADER,
    RSA_R_INVALID_LENGTH, RSA_R_INVALID_MESSAGE_LENGTH, RSA_R_INVALID_PADDING,
    RSA_R_INVALID_TRAILER, RSA_R_KEY_SIZE_TOO_SMALL, RSA_R_LAST_OCTET_INVALID,
    RSA_R_MISSING_PRIVATE_KEY, RSA_R_MODULUS_TOO_LARGE, RSA_R_NO_PUBLIC_EXPONENT,
    RSA_R_NULL_BEFORE_BLOCK_MISSING, RSA_R_OAEP_DECODING_ERROR, RSA_R_PADDING_CHECK_FAILED,
    RSA_R_PKCS_DECODING_ERROR, RSA_R_SLEN_CHECK_FAILED, RSA_R_SLEN_RECOVERY_FAILED,
    RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD, RSA_R_UNKNOWN_ALGORITHM_TYPE,
    RSA_R_UNKNOWN_PADDING_TYPE, RSA_R_WRONG_SIGNATURE_LENGTH,
};
use rustyssl_crypto::rsa::{Entry, Hash, Key, Reason};

use crate::err;
use crate::evp::digest::{
    EVP_MD_fetch, EVP_MD_free, EVP_MD_get_block_size, EVP_MD_get_size, EVP_MD_up_ref,
};
use crate::evp::md_ctx::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_new,
};
use crate::handle::{Handle, handle_type};
use crate::provider::Ptr;
use crate::rand_lib::{RAND_bytes_ex, RAND_priv_bytes_ex};

/// The kind of key (`RSA_FLAG_TYPE_*`): RSA, or RSA-PSS, whose key type allows only PSS
/// signatures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Rsa,
    RsaPss,
}

/// A PSS key's restrictions (`RSA_PSS_PARAMS_30`): unrestricted when all zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Pss30 {
    pub(crate) hash: c_int,
    pub(crate) mask_gen: c_int,
    pub(crate) mask_gen_hash: c_int,
    pub(crate) salt_len: c_int,
    pub(crate) trailer: c_int,
}

impl Pss30 {
    /// Whether the key is restricted.
    pub(crate) fn restricted(&self) -> bool {
        *self != Self::default()
    }
}

/// An RSA key's state: the numbers, its kind, and its PSS restrictions.
#[derive(Clone)]
pub(crate) struct RsaState {
    pub(crate) key: Key,
    pub(crate) kind: Kind,
    pub(crate) pss: Pss30,
}

/// An RSA key (`RSA`), shared by reference.
pub(crate) struct Rsa {
    pub(crate) libctx: Ptr<OSSL_LIB_CTX>,
    state: Mutex<RsaState>,
}

handle_type!(RSA => Rsa);

impl Rsa {
    /// `ossl_rsa_new_with_ctx`: an empty key of `kind` in `libctx`.
    pub(crate) fn new_handle_in(libctx: *mut OSSL_LIB_CTX, kind: Kind) -> *mut RSA {
        RSA::new_handle(Rsa {
            libctx: Ptr(libctx),
            state: Mutex::new(RsaState {
                key: Key::new(),
                kind,
                pss: Pss30::default(),
            }),
        })
    }

    /// The key's state, locked.
    pub(crate) fn lock(&self) -> MutexGuard<'_, RsaState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A copy of the key's state, so an operation runs without holding the lock.
    pub(crate) fn snapshot(&self) -> RsaState {
        self.lock().clone()
    }
}

/// The key behind an `RSA` pointer (key data).
///
/// # Safety
/// `rsa` is NULL or a live handle.
pub(crate) unsafe fn rsa<'a>(rsa: *const RSA) -> Option<&'a Rsa> {
    // SAFETY: the caller's guarantee.
    unsafe { RSA::get(rsa) }
}

/// The `RSA_R_*` (or `ERR_R_*`) code of a reason.
pub(crate) fn reason_code(reason: Reason) -> c_int {
    match reason {
        Reason::ModulusTooLarge => RSA_R_MODULUS_TOO_LARGE,
        Reason::BadEValue => RSA_R_BAD_E_VALUE,
        Reason::UnknownPaddingType => RSA_R_UNKNOWN_PADDING_TYPE,
        Reason::DataTooLargeForModulus => RSA_R_DATA_TOO_LARGE_FOR_MODULUS,
        Reason::DataTooLargeForKeySize => RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE,
        Reason::DataTooSmallForKeySize => RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE,
        Reason::DataGreaterThanModLen => RSA_R_DATA_GREATER_THAN_MOD_LEN,
        Reason::DataTooSmall => RSA_R_DATA_TOO_SMALL,
        Reason::DataTooLarge => RSA_R_DATA_TOO_LARGE,
        Reason::MissingPrivateKey => RSA_R_MISSING_PRIVATE_KEY,
        Reason::NoPublicExponent => RSA_R_NO_PUBLIC_EXPONENT,
        Reason::PaddingCheckFailed => RSA_R_PADDING_CHECK_FAILED,
        Reason::PkcsDecodingError => RSA_R_PKCS_DECODING_ERROR,
        Reason::OaepDecodingError => RSA_R_OAEP_DECODING_ERROR,
        Reason::InvalidPadding => RSA_R_INVALID_PADDING,
        Reason::BlockTypeIsNot01 => RSA_R_BLOCK_TYPE_IS_NOT_01,
        Reason::BadFixedHeaderDecrypt => RSA_R_BAD_FIXED_HEADER_DECRYPT,
        Reason::NullBeforeBlockMissing => RSA_R_NULL_BEFORE_BLOCK_MISSING,
        Reason::BadPadByteCount => RSA_R_BAD_PAD_BYTE_COUNT,
        Reason::InvalidLength => RSA_R_INVALID_LENGTH,
        Reason::KeySizeTooSmall => RSA_R_KEY_SIZE_TOO_SMALL,
        Reason::SlenCheckFailed(_) => RSA_R_SLEN_CHECK_FAILED,
        Reason::FirstOctetInvalid => RSA_R_FIRST_OCTET_INVALID,
        Reason::LastOctetInvalid => RSA_R_LAST_OCTET_INVALID,
        Reason::SlenRecoveryFailed => RSA_R_SLEN_RECOVERY_FAILED,
        Reason::BadSignature => RSA_R_BAD_SIGNATURE,
        Reason::InvalidHeader => RSA_R_INVALID_HEADER,
        Reason::InvalidTrailer => RSA_R_INVALID_TRAILER,
        Reason::WrongSignatureLength => RSA_R_WRONG_SIGNATURE_LENGTH,
        Reason::InvalidMessageLength => RSA_R_INVALID_MESSAGE_LENGTH,
        Reason::InvalidDigestLength => RSA_R_INVALID_DIGEST_LENGTH,
        Reason::UnknownAlgorithmType => RSA_R_UNKNOWN_ALGORITHM_TYPE,
        Reason::AsnObjectNotKnownForMd => RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD,
        Reason::DigestTooBigForRsaKey => RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY,
        Reason::Internal => ERR_R_INTERNAL_ERROR,
        Reason::FetchFailed => ERR_R_FETCH_FAILED,
        Reason::BnLib => ERR_R_BN_LIB,
    }
}

/// Raises the entries an RSA operation left, in order, each from the OpenSSL function that
/// raises it; each is cleared afterwards when its entry says so, without a branch on that.
pub(crate) fn raise_all(raised: &[Entry]) {
    for e in raised {
        match e.reason {
            Reason::SlenCheckFailed(Some((expected, retrieved))) => err::raise_with_text(
                ERR_LIB_RSA,
                RSA_R_SLEN_CHECK_FAILED,
                e.func,
                &format!("expected: {expected} retrieved: {retrieved}"),
            ),
            r => err::raise(ERR_LIB_RSA, reason_code(r), e.func),
        }
        err::clear_last_constant_time(e.clear);
    }
}

/// A digest for the RSA paddings: a fetched `EVP_MD`, with a reference this holds.
pub(crate) struct Md(*mut EVP_MD);

impl Md {
    /// `EVP_MD_fetch(libctx, name, properties)`, or `None` (the fetch's errors raised).
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `properties` is NULL or a string.
    pub(crate) unsafe fn fetch(
        libctx: *mut OSSL_LIB_CTX,
        name: &CStr,
        properties: *const c_char,
    ) -> Option<Self> {
        // SAFETY: the caller's guarantee; a string.
        let md = unsafe { EVP_MD_fetch(libctx, name.as_ptr(), properties) };
        (!md.is_null()).then_some(Self(md))
    }

    /// The digest.
    pub(crate) fn ptr(&self) -> *mut EVP_MD {
        self.0
    }
}

impl Clone for Md {
    fn clone(&self) -> Self {
        // SAFETY: this holds a reference to a live digest.
        unsafe { EVP_MD_up_ref(self.0) };
        Self(self.0)
    }
}

impl Drop for Md {
    fn drop(&mut self) {
        // SAFETY: the reference this holds.
        unsafe { EVP_MD_free(self.0) };
    }
}

// SAFETY: a fetched digest is shared between threads in OpenSSL; this only holds a reference.
unsafe impl Send for Md {}
// SAFETY: as above.
unsafe impl Sync for Md {}

impl Hash for Md {
    fn size(&self) -> usize {
        // SAFETY: a live digest.
        usize::try_from(unsafe { EVP_MD_get_size(self.0) }).unwrap_or(0)
    }

    fn block_size(&self) -> usize {
        // SAFETY: a live digest.
        usize::try_from(unsafe { EVP_MD_get_block_size(self.0) }).unwrap_or(0)
    }

    fn digest(&self, parts: &[&[u8]]) -> Option<Vec<u8>> {
        struct Ctx(*mut EVP_MD_CTX);
        impl Drop for Ctx {
            fn drop(&mut self) {
                // SAFETY: the context made below, or NULL.
                unsafe { EVP_MD_CTX_free(self.0) };
            }
        }
        // SAFETY: no preconditions.
        let ctx = Ctx(unsafe { EVP_MD_CTX_new() });
        // SAFETY: the context; the digest.
        if ctx.0.is_null() || unsafe { EVP_DigestInit_ex(ctx.0, self.0, ptr::null_mut()) } != 1 {
            return None;
        }
        for p in parts {
            // SAFETY: the context; the part's octets.
            if unsafe { EVP_DigestUpdate(ctx.0, p.as_ptr().cast(), p.len()) } != 1 {
                return None;
            }
        }
        let mut out = vec![0u8; 64.max(self.size())];
        let mut n: c_uint = 0;
        // SAFETY: the context; room for the digest.
        if unsafe { EVP_DigestFinal_ex(ctx.0, out.as_mut_ptr(), &raw mut n) } != 1 {
            return None;
        }
        out.truncate(usize::try_from(n).ok()?);
        Some(out)
    }
}

/// Random octets from `libctx`'s public generator (`RAND_bytes_ex`, strength 0).
pub(crate) fn public_random(libctx: *mut OSSL_LIB_CTX) -> impl FnMut(&mut [u8]) -> bool {
    move |buf: &mut [u8]| {
        // SAFETY: the library context; the buffer.
        (unsafe { RAND_bytes_ex(libctx, buf.as_mut_ptr(), buf.len(), 0) }) == 1
    }
}

/// Random octets from `libctx`'s private generator (`RAND_priv_bytes_ex`, strength 0).
pub(crate) fn private_random(libctx: *mut OSSL_LIB_CTX) -> impl FnMut(&mut [u8]) -> bool {
    move |buf: &mut [u8]| {
        // SAFETY: the library context; the buffer.
        (unsafe { RAND_priv_bytes_ex(libctx, buf.as_mut_ptr(), buf.len(), 0) }) == 1
    }
}
