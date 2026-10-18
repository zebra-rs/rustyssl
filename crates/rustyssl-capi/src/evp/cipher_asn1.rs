//! A cipher context's AlgorithmIdentifier parameters (`EVP_CIPHER_param_to_asn1(3)`, `evp_lib.c`):
//! the IV as an OCTET STRING for the block and stream modes, nothing (or NULL) for the key
//! wraps, and the provider's own DER for a cipher whose context parameters include
//! `alg_id_param` (`EVP_CIPH_FLAG_CUSTOM_ASN1`); GCM's needs the CMS layer's tag length, which the
//! public functions don't have, and CCM, XTS, and OCB have none. Also the provider's whole
//! AlgorithmIdentifier (`EVP_CIPHER_CTX_get_algor`).
//!
//! What the reference would crash on (a NULL `X509_ALGOR`) or abort on (an IV longer than 16
//! octets in `EVP_CIPHER_set_asn1_iv`) fails here instead (docs/DEVIATIONS.md).

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_TYPE, ERR_LIB_EVP, EVP_CIPH_CCM_MODE, EVP_CIPH_FLAG_CUSTOM_ASN1, EVP_CIPH_GCM_MODE,
    EVP_CIPH_OCB_MODE, EVP_CIPH_WRAP_MODE, EVP_CIPH_XTS_MODE, EVP_CIPHER_CTX, EVP_MAX_IV_LENGTH,
    EVP_R_CIPHER_PARAMETER_ERROR, EVP_R_GETTING_ALGORITHMIDENTIFIER_NOT_SUPPORTED,
    EVP_R_UNSUPPORTED_CIPHER, OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS,
    OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS_OLD, OSSL_PARAM, OSSL_SIGNATURE_PARAM_ALGORITHM_ID,
    SN_id_smime_alg_CMS3DESwrap, V_ASN1_NULL, X509_ALGOR,
};

use super::cipher::{EVP_CIPHER_get_flags, EVP_CIPHER_get_mode, EVP_CIPHER_is_a};
use super::cipher_ctx::{
    EVP_CIPHER_CTX_get_iv_length, EVP_CIPHER_CTX_get_params, EVP_CIPHER_CTX_get0_cipher,
    EVP_CIPHER_CTX_original_iv, EVP_CIPHER_CTX_set_params, EVP_CipherInit_ex,
};
use crate::asn1::any::{ASN1_TYPE_get_octetstring, ASN1_TYPE_set, ASN1_TYPE_set_octetstring};
use crate::asn1::tpl::items::{d2i_ASN1_TYPE, d2i_X509_ALGOR, i2d_ASN1_TYPE};
use crate::err;
use crate::ffi::ffi_export;
use crate::mem;
use crate::params::{OSSL_PARAM_construct_octet_string, OSSL_PARAM_modified, end};

/// The IV's room (`EVP_MAX_IV_LENGTH`).
const MAX_IV: usize = EVP_MAX_IV_LENGTH as usize;

ffi_export! {
    /// Sets the context's IV from `type`'s OCTET STRING, which must be the IV's length.
    /// Returns that length (0 for a NULL `type`), or -1.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context; `type_` is NULL or a live `ASN1_TYPE`.
    pub unsafe extern "C" fn EVP_CIPHER_get_asn1_iv(ctx: *mut EVP_CIPHER_CTX, type_: *mut ASN1_TYPE) -> c_int
    where failure = -1, library = ERR_LIB_EVP
    {
        if type_.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let l = unsafe { EVP_CIPHER_CTX_get_iv_length(ctx) };
        if usize::try_from(l).map_or(true, |l| l > MAX_IV) {
            return -1;
        }
        let mut iv = [0u8; MAX_IV];
        // SAFETY: the caller's guarantee; room for `l` octets.
        let i = unsafe { ASN1_TYPE_get_octetstring(type_, iv.as_mut_ptr(), l) };
        if i != l {
            return -1;
        }
        // SAFETY: the caller's guarantee; the IV of the context's length.
        if unsafe { EVP_CipherInit_ex(ctx, ptr::null(), ptr::null_mut(), ptr::null(), iv.as_ptr(), -1) } == 0 {
            return -1;
        }
        i
    }
}

ffi_export! {
    /// Sets `type` to the context's original IV as an OCTET STRING. Returns 1, or 0 (and 0 for
    /// a NULL `type`).
    ///
    /// # Safety
    /// `c` is NULL or a live cipher context; `type_` is NULL or a live `ASN1_TYPE`.
    pub unsafe extern "C" fn EVP_CIPHER_set_asn1_iv(c: *mut EVP_CIPHER_CTX, type_: *mut ASN1_TYPE) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if type_.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let oiv = unsafe { EVP_CIPHER_CTX_original_iv(c) };
        // SAFETY: as above.
        let j = unsafe { EVP_CIPHER_CTX_get_iv_length(c) };
        if usize::try_from(j).map_or(true, |j| j > MAX_IV) || (oiv.is_null() && j > 0) {
            // The reference asserts the IV fits its 16 octets (docs/DEVIATIONS.md).
            return 0;
        }
        // SAFETY: the caller's guarantee; the context's IV holds `j` octets.
        unsafe { ASN1_TYPE_set_octetstring(type_, oiv.cast_mut(), j) }
    }
}

/// How `evp_cipher_param_to_asn1_ex` and its inverse end: -2 is an unsupported cipher, and
/// anything not positive a parameter error, both raised; -1 at worst.
fn conclude(ret: c_int) -> c_int {
    if ret == -2 {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_UNSUPPORTED_CIPHER,
            "evp_cipher_param_to_asn1_ex",
        );
    } else if ret <= 0 {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_CIPHER_PARAMETER_ERROR,
            "evp_cipher_param_to_asn1_ex",
        );
    }
    ret.max(-1)
}

/// An `X509_ALGOR` with no OID, carrying `type` as its parameters, as the reference "cheats".
fn cheat(type_: *mut ASN1_TYPE) -> X509_ALGOR {
    X509_ALGOR {
        algorithm: ptr::null_mut(),
        parameter: type_,
    }
}

ffi_export! {
    /// Sets `type` to the context's AlgorithmIdentifier parameters. Returns 1 (or the like),
    /// or -1 (for an unsupported cipher) or 0 with an error.
    ///
    /// # Safety
    /// `c` is NULL or a live cipher context; `type_` is NULL or a live `ASN1_TYPE`.
    pub unsafe extern "C" fn EVP_CIPHER_param_to_asn1(c: *mut EVP_CIPHER_CTX, type_: *mut ASN1_TYPE) -> c_int
    where failure = -1, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { param_to_asn1_ex(c, type_, None) }
    }
}

/// `evp_cipher_aead_asn1_params`: GCM's IV and tag length, which CMS's AuthEnvelopedData
/// carries in the algorithm's parameters.
#[derive(Clone, Copy)]
pub(crate) struct AeadParams {
    pub(crate) iv: [u8; MAX_IV],
    pub(crate) iv_len: u32,
    pub(crate) tag_len: u32,
}

impl Default for AeadParams {
    fn default() -> Self {
        Self {
            iv: [0; MAX_IV],
            iv_len: 0,
            tag_len: 0,
        }
    }
}

/// `evp_cipher_set_asn1_aead_params`.
///
/// # Safety
/// `type_` is NULL or a live `ASN1_TYPE`.
unsafe fn set_aead(type_: *mut ASN1_TYPE, aead: Option<&mut AeadParams>) -> c_int {
    let Some(p) = aead.filter(|_| !type_.is_null()) else {
        return 0;
    };
    let n = usize::try_from(p.iv_len).unwrap_or(0).min(MAX_IV);
    let len = c_int::try_from(n).unwrap_or(0);
    // SAFETY: the caller's type; the IV's `n` octets.
    c_int::from(unsafe {
        crate::asn1::tpl::util::set_octetstring_int(
            type_,
            c_long::from(p.tag_len),
            p.iv.as_mut_ptr(),
            len,
        )
    })
}

/// `evp_cipher_get_asn1_aead_params`: the IV (the tag length isn't kept, as in OpenSSL).
///
/// # Safety
/// `type_` is NULL or a live `ASN1_TYPE`.
unsafe fn get_aead(type_: *mut ASN1_TYPE, aead: Option<&mut AeadParams>) -> c_int {
    let Some(p) = aead.filter(|_| !type_.is_null()) else {
        return 0;
    };
    let mut iv = [0u8; MAX_IV];
    let mut tl: c_long = 0;
    // SAFETY: the caller's type.
    let i = unsafe { crate::asn1::tpl::util::get_octetstring_int(type_, &mut tl, &mut iv) };
    let Some(n) = usize::try_from(i).ok().filter(|&n| n > 0 && n <= MAX_IV) else {
        return -1;
    };
    let (dst, src) = (p.iv.get_mut(..n), iv.get(..n));
    if let (Some(d), Some(s)) = (dst, src) {
        d.copy_from_slice(s);
    }
    p.iv_len = u32::try_from(n).unwrap_or(0);
    i
}

/// `evp_cipher_param_to_asn1_ex`: [`EVP_CIPHER_param_to_asn1`], GCM's parameters from `aead`.
///
/// # Safety
/// As for [`EVP_CIPHER_param_to_asn1`].
pub(crate) unsafe fn param_to_asn1_ex(
    c: *mut EVP_CIPHER_CTX,
    type_: *mut ASN1_TYPE,
    aead: Option<&mut AeadParams>,
) -> c_int {
    {
        // SAFETY: the caller's guarantee.
        let cipher = unsafe { EVP_CIPHER_CTX_get0_cipher(c) };
        if cipher.is_null() {
            return conclude(-1);
        }
        // An application's cipher's own function first.
        // SAFETY: the caller's guarantee.
        if let Some(f) = unsafe { super::cipher_ctx::legacy_asn1_fn(c, true) } {
            // SAFETY: the cipher's function with the caller's context and type.
            return conclude(unsafe { f(c, type_) });
        }
        // SAFETY: a live cipher.
        let flags = unsafe { EVP_CIPHER_get_flags(cipher) };
        let ret = if flags & EVP_CIPH_FLAG_CUSTOM_ASN1 as core::ffi::c_ulong == 0 {
            // SAFETY: as above.
            match unsafe { EVP_CIPHER_get_mode(cipher) } {
                EVP_CIPH_WRAP_MODE => {
                    // SAFETY: as above; a static name.
                    if unsafe { EVP_CIPHER_is_a(cipher, SN_id_smime_alg_CMS3DESwrap.as_ptr()) } != 0
                        && !type_.is_null()
                    {
                        // SAFETY: the caller's guarantee.
                        unsafe { ASN1_TYPE_set(type_, V_ASN1_NULL, ptr::null_mut()) };
                    }
                    1
                }
                // SAFETY: the caller's guarantee.
                EVP_CIPH_GCM_MODE => unsafe { set_aead(type_, aead) },
                EVP_CIPH_CCM_MODE | EVP_CIPH_XTS_MODE | EVP_CIPH_OCB_MODE => -2,
                // SAFETY: the caller's guarantee.
                _ => unsafe { EVP_CIPHER_set_asn1_iv(c, type_) },
            }
        } else {
            let mut alg = cheat(type_);
            // SAFETY: the caller's context; a local AlgorithmIdentifier.
            unsafe { EVP_CIPHER_CTX_get_algor_params(c, &raw mut alg) }
        };
        conclude(ret)
    }
}

ffi_export! {
    /// Sets the context's parameters from `type`, its AlgorithmIdentifier parameters. Returns 1
    /// (or the IV's length), or -1 (for an unsupported cipher) or 0 with an error.
    ///
    /// # Safety
    /// `c` is NULL or a live cipher context; `type_` is NULL or a live `ASN1_TYPE`.
    pub unsafe extern "C" fn EVP_CIPHER_asn1_to_param(c: *mut EVP_CIPHER_CTX, type_: *mut ASN1_TYPE) -> c_int
    where failure = -1, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { asn1_to_param_ex(c, type_, None) }
    }
}

/// `evp_cipher_asn1_to_param_ex`: [`EVP_CIPHER_asn1_to_param`], GCM's parameters into `aead`.
///
/// # Safety
/// As for [`EVP_CIPHER_asn1_to_param`].
pub(crate) unsafe fn asn1_to_param_ex(
    c: *mut EVP_CIPHER_CTX,
    type_: *mut ASN1_TYPE,
    aead: Option<&mut AeadParams>,
) -> c_int {
    {
        // SAFETY: the caller's guarantee.
        let cipher = unsafe { EVP_CIPHER_CTX_get0_cipher(c) };
        if cipher.is_null() {
            return conclude(-1);
        }
        // An application's cipher's own function first.
        // SAFETY: the caller's guarantee.
        if let Some(f) = unsafe { super::cipher_ctx::legacy_asn1_fn(c, false) } {
            // SAFETY: the cipher's function with the caller's context and type.
            return conclude(unsafe { f(c, type_) });
        }
        // SAFETY: a live cipher.
        let flags = unsafe { EVP_CIPHER_get_flags(cipher) };
        let ret = if flags & EVP_CIPH_FLAG_CUSTOM_ASN1 as core::ffi::c_ulong == 0 {
            // SAFETY: as above.
            match unsafe { EVP_CIPHER_get_mode(cipher) } {
                EVP_CIPH_WRAP_MODE => 1,
                // SAFETY: the caller's guarantee.
                EVP_CIPH_GCM_MODE => unsafe { get_aead(type_, aead) },
                EVP_CIPH_CCM_MODE | EVP_CIPH_XTS_MODE | EVP_CIPH_OCB_MODE => -2,
                _ => {
                    // SAFETY: the caller's guarantee.
                    let r = unsafe { EVP_CIPHER_get_asn1_iv(c, type_) };
                    // SAFETY: as above.
                    if r == 0 && unsafe { EVP_CIPHER_CTX_get_iv_length(c) } == 0 {
                        1
                    } else {
                        r
                    }
                }
            }
        } else {
            let alg = cheat(type_);
            // SAFETY: the caller's context; a local AlgorithmIdentifier.
            unsafe { EVP_CIPHER_CTX_set_algor_params(c, &raw const alg) }
        };
        conclude(ret)
    }
}

ffi_export! {
    /// Gives the context's provider `alg`'s parameters, DER-encoded, as `alg_id_param` (and its
    /// old name). Returns what setting them returns, or -1.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context; `alg` is NULL or a live `X509_ALGOR`.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_set_algor_params(ctx: *mut EVP_CIPHER_CTX, alg: *const X509_ALGOR) -> c_int
    where failure = -1, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(alg) = (unsafe { alg.as_ref() }) else {
            // The reference reads through NULL (docs/DEVIATIONS.md).
            return -1;
        };
        let mut der: *mut c_uchar = ptr::null_mut();
        // SAFETY: the caller's parameters; the encoding is allocated for us.
        let derl = unsafe { i2d_ASN1_TYPE(alg.parameter, &raw mut der) };
        let mut ret = -1;
        if let Ok(len) = usize::try_from(derl) {
            let params = [
                // SAFETY: a static key; the encoding.
                unsafe { OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS_OLD.as_ptr(), der.cast(), len) },
                // SAFETY: as above.
                unsafe { OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS.as_ptr(), der.cast(), len) },
                end(),
            ];
            // SAFETY: the caller's context; an ended array.
            ret = unsafe { EVP_CIPHER_CTX_set_params(ctx, params.as_ptr()) };
        }
        // SAFETY: from `i2d_ASN1_TYPE`'s allocator, or NULL.
        unsafe { mem::release(der.cast()) };
        ret
    }
}

/// Asks the context's provider for octet-string parameters by `keys`, with no room first: the
/// index of the one it answered with a length (the last, if several), and that length.
///
/// # Safety
/// `ctx` is NULL or a live cipher context.
unsafe fn sized(
    ctx: *mut EVP_CIPHER_CTX,
    params: &mut [OSSL_PARAM],
) -> Result<(usize, usize), c_int> {
    // SAFETY: the caller's guarantee; an ended array.
    if unsafe { EVP_CIPHER_CTX_get_params(ctx, params.as_mut_ptr()) } <= 0 {
        return Err(-1);
    }
    let mut found = None;
    for (i, p) in params.iter().enumerate() {
        if p.key.is_null() {
            break;
        }
        // SAFETY: a parameter of the array.
        if unsafe { OSSL_PARAM_modified(p) } != 0 && p.return_size != 0 {
            found = Some((i, p.return_size));
        }
    }
    found.ok_or(-1)
}

ffi_export! {
    /// Sets `alg`'s parameters to the context's provider's `alg_id_param` (or its old name),
    /// decoded. Returns 1, or -1.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context; `alg` is NULL or a live `X509_ALGOR`.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_get_algor_params(ctx: *mut EVP_CIPHER_CTX, alg: *mut X509_ALGOR) -> c_int
    where failure = -1, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(alg) = (unsafe { alg.as_mut() }) else {
            // The reference writes through NULL (docs/DEVIATIONS.md).
            return -1;
        };
        let keys = [OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS_OLD, OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS];
        let mut params = [
            // SAFETY: a static key, no room.
            unsafe { OSSL_PARAM_construct_octet_string(keys[0].as_ptr(), ptr::null_mut(), 0) },
            // SAFETY: as above.
            unsafe { OSSL_PARAM_construct_octet_string(keys[1].as_ptr(), ptr::null_mut(), 0) },
            end(),
        ];
        // SAFETY: the caller's guarantee.
        let (i, derl) = match unsafe { sized(ctx, &mut params) } {
            Ok(found) => found,
            Err(r) => return r,
        };
        let Some(key) = keys.get(i) else { return -1 };
        let der: *mut c_uchar = mem::alloc(derl).cast();
        let mut ret = -1;
        if !der.is_null() {
            if let Some(slot) = params.get_mut(i) {
                // SAFETY: a static key; room for `derl` octets.
                *slot = unsafe { OSSL_PARAM_construct_octet_string(key.as_ptr(), der.cast(), derl) };
            }
            let mut type_ = alg.parameter;
            let mut p = der.cast_const();
            // SAFETY: the caller's context; the array; the encoding of `derl` octets.
            let ok = unsafe { EVP_CIPHER_CTX_get_params(ctx, params.as_mut_ptr()) } != 0
                && params.get(i).is_some_and(|q| {
                    // SAFETY: a parameter of the array.
                    (unsafe { OSSL_PARAM_modified(q) }) != 0
                })
                && c_long::try_from(derl).is_ok_and(|l| {
                    // SAFETY: the parameters (reused if there are any) and the encoding.
                    !unsafe { d2i_ASN1_TYPE(&raw mut type_, &raw mut p, l) }.is_null()
                });
            if ok {
                alg.parameter = type_;
                ret = 1;
            }
        }
        // SAFETY: from `mem::alloc`, or NULL.
        unsafe { mem::release(der.cast::<c_void>()) };
        ret
    }
}

ffi_export! {
    /// The context's whole AlgorithmIdentifier from its provider (`algorithm-id`), decoded into
    /// `*alg` (a new one if NULL; none at all for a NULL `alg`, only whether there is one).
    /// Returns 1; -2 with `EVP_R_GETTING_ALGORITHMIDENTIFIER_NOT_SUPPORTED` if the provider has
    /// none; or -1.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context; `alg` is NULL or points to NULL or a live
    /// `X509_ALGOR`.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_get_algor(ctx: *mut EVP_CIPHER_CTX, alg: *mut *mut X509_ALGOR) -> c_int
    where failure = -1, library = ERR_LIB_EVP
    {
        let key = OSSL_SIGNATURE_PARAM_ALGORITHM_ID;
        let mut params = [
            // SAFETY: a static key, no room.
            unsafe { OSSL_PARAM_construct_octet_string(key.as_ptr(), ptr::null_mut(), 0) },
            end(),
        ];
        // SAFETY: the caller's guarantee; an ended array.
        if unsafe { EVP_CIPHER_CTX_get_params(ctx, params.as_mut_ptr()) } <= 0 {
            return -1;
        }
        // SAFETY: a parameter of the array.
        let aid_len = if unsafe { OSSL_PARAM_modified(&raw const params[0]) } != 0 {
            params[0].return_size
        } else {
            0
        };
        if aid_len == 0 {
            err::raise(ERR_LIB_EVP, EVP_R_GETTING_ALGORITHMIDENTIFIER_NOT_SUPPORTED, "EVP_CIPHER_CTX_get_algor");
            return -2;
        }
        if alg.is_null() {
            return -1;
        }
        let aid: *mut c_uchar = mem::alloc(aid_len).cast();
        let mut ret = -1;
        if !aid.is_null() {
            // SAFETY: a static key; room for `aid_len` octets.
            params[0] = unsafe { OSSL_PARAM_construct_octet_string(key.as_ptr(), aid.cast(), aid_len) };
            let mut p = aid.cast_const();
            // SAFETY: the caller's context and `alg`; the encoding of `aid_len` octets.
            let ok = unsafe { EVP_CIPHER_CTX_get_params(ctx, params.as_mut_ptr()) } != 0
                // SAFETY: a parameter of the array.
                && unsafe { OSSL_PARAM_modified(&raw const params[0]) } != 0
                && c_long::try_from(aid_len).is_ok_and(|l| {
                    // SAFETY: as above.
                    !unsafe { d2i_X509_ALGOR(alg, &raw mut p, l) }.is_null()
                });
            if ok {
                ret = 1;
            }
        }
        // SAFETY: from `mem::alloc`, or NULL.
        unsafe { mem::release(aid.cast::<c_void>()) };
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::tpl::items::{ASN1_TYPE_free, ASN1_TYPE_new};
    use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free};
    use crate::evp::cipher_ctx::{EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new};
    use rustyssl_abi::EVP_CTRL_AEAD_SET_IVLEN;

    /// docs/DEVIATIONS.md: a NULL `X509_ALGOR` fails (the reference reads or writes through
    /// NULL).
    #[test]
    fn null_algors_fail() {
        // SAFETY: no preconditions.
        let ctx = unsafe { EVP_CIPHER_CTX_new() };
        // SAFETY: a live context and NULL, the case under test.
        let r = unsafe { EVP_CIPHER_CTX_set_algor_params(ctx, ptr::null()) };
        assert_eq!(r, -1);
        // SAFETY: as above.
        let r = unsafe { EVP_CIPHER_CTX_get_algor_params(ctx, ptr::null_mut()) };
        assert_eq!(r, -1);
        // SAFETY: the context made here.
        unsafe { EVP_CIPHER_CTX_free(ctx) };
    }

    /// docs/DEVIATIONS.md: an IV longer than 16 octets isn't written (the reference asserts).
    #[test]
    #[cfg_attr(miri, ignore = "loads the configuration, which calls getgid")]
    fn long_ivs_fail() {
        // SAFETY: no preconditions.
        let ctx = unsafe { EVP_CIPHER_CTX_new() };
        // SAFETY: the default context and static strings.
        let c = unsafe { EVP_CIPHER_fetch(ptr::null_mut(), c"AES-128-GCM".as_ptr(), ptr::null()) };
        assert!(!c.is_null());
        let key = [1u8; 16];
        // SAFETY: a live context and cipher, a key of its length.
        let r = unsafe { EVP_CipherInit_ex(ctx, c, ptr::null_mut(), key.as_ptr(), ptr::null(), 1) };
        assert_eq!(r, 1);
        // SAFETY: a live context; no pointer needed.
        let r = unsafe { EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 60, ptr::null_mut()) };
        assert_eq!(r, 1);
        // SAFETY: no preconditions.
        let t = unsafe { ASN1_TYPE_new() };
        // SAFETY: a live context and type.
        assert_eq!(unsafe { EVP_CIPHER_set_asn1_iv(ctx, t) }, 0);
        // SAFETY: what was made here.
        unsafe { ASN1_TYPE_free(t) };
        // SAFETY: as above.
        unsafe { EVP_CIPHER_free(c) };
        // SAFETY: as above.
        unsafe { EVP_CIPHER_CTX_free(ctx) };
    }
}
