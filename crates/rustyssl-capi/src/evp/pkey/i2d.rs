//! The key-to-DER functions (`i2d_evp.c`, and their BIO and `FILE` forms from `x_all.c`):
//! `i2d_PrivateKey` (the type-specific structure, or a PrivateKeyInfo), `i2d_PublicKey` (the
//! type-specific structure, or an EC key's point), and `i2d_KeyParams`. A legacy key goes
//! through its ASN.1 method; a provided one through the encoders, as OpenSSL's does.

use core::ffi::{CStr, c_int, c_uchar, c_void};
use core::ptr;

use libc::FILE;
use rustyssl_abi::{
    ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE, ASN1_R_UNSUPPORTED_TYPE, BIO, ERR_LIB_ASN1, EVP_PKEY,
    EVP_PKEY_DSA, EVP_PKEY_EC, EVP_PKEY_KEY_PARAMETERS, EVP_PKEY_KEYPAIR, EVP_PKEY_PUBLIC_KEY,
    EVP_PKEY_RSA,
};

use super::{EVP_PKEY_get_base_id, legacy_data, pkey};
use crate::asn1::tpl::io::{ASN1_i2d_bio, ASN1_i2d_fp};
use crate::encoder::ctx::{OSSL_ENCODER_CTX_free, OSSL_ENCODER_to_data};
use crate::encoder::pkey::OSSL_ENCODER_CTX_new_for_pkey;
use crate::err;
use crate::ffi::{ffi_callback, ffi_export};

/// `i2d_provided`: the key encoded by the first of the output types and structures that
/// encodes it, as an `i2d` gives it; -1 (with `ASN1_R_UNSUPPORTED_TYPE`) if none does.
///
/// # Safety
/// `a` is a live provided key; `pp` as for an `i2d`.
unsafe fn i2d_provided(
    a: *const EVP_PKEY,
    selection: c_int,
    outputs: &[(&CStr, Option<&CStr>)],
    pp: *mut *mut c_uchar,
) -> c_int {
    let mut ret = -1;
    for &(output_type, output_structure) in outputs {
        if ret != -1 {
            break;
        }
        let mut len = usize::try_from(c_int::MAX).unwrap_or(0);
        // SAFETY: the caller's guarantee.
        let pp_was_null = pp.is_null() || unsafe { pp.read() }.is_null();
        let structure = output_structure.map_or(ptr::null(), CStr::as_ptr);
        // SAFETY: the caller's key; static strings.
        let ctx = unsafe {
            OSSL_ENCODER_CTX_new_for_pkey(
                a,
                selection,
                output_type.as_ptr(),
                structure,
                ptr::null(),
            )
        };
        if ctx.is_null() {
            return -1;
        }
        // SAFETY: the new context; the caller's output.
        if unsafe { OSSL_ENCODER_to_data(ctx, pp, &raw mut len) } != 0 {
            let len = c_int::try_from(len).unwrap_or(c_int::MAX);
            ret = if pp_was_null { len } else { c_int::MAX - len };
        }
        // SAFETY: made above.
        unsafe { OSSL_ENCODER_CTX_free(ctx) };
    }
    if ret == -1 {
        err::raise(ERR_LIB_ASN1, ASN1_R_UNSUPPORTED_TYPE, "i2d_provided");
    }
    ret
}

ffi_export! {
    /// Encodes the key's parameters (the type-specific structure): the length, or -1.
    ///
    /// # Safety
    /// `a` is a live key; `pp` is NULL, or holds NULL (for a new buffer) or room for the
    /// encoding, which it moves past.
    pub unsafe extern "C" fn i2d_KeyParams(a: *const EVP_PKEY, pp: *mut *mut c_uchar) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { pkey(a) }) else { return -1 };
        if k.is_provided() {
            // SAFETY: as above.
            return unsafe { i2d_provided(a, EVP_PKEY_KEY_PARAMETERS, &[(c"DER", Some(c"type-specific"))], pp) };
        }
        if let Some(encode) = k.ameth_funcs().and_then(|f| f.param_encode) {
            // SAFETY: the method's function with the caller's key and output.
            return unsafe { encode(a, pp) };
        }
        err::raise(ERR_LIB_ASN1, ASN1_R_UNSUPPORTED_TYPE, "i2d_KeyParams");
        -1
    }
}

/// `i2d_PrivateKey_impl`: the type-specific structure when `traditional` (or, for a type
/// without one, a PrivateKeyInfo), else a PrivateKeyInfo. The length, or -1 (0 when making the
/// PrivateKeyInfo fails).
///
/// # Safety
/// As for `i2d_KeyParams`.
unsafe fn i2d_private_key(a: *const EVP_PKEY, pp: *mut *mut c_uchar, traditional: bool) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { pkey(a) }) else {
        return -1;
    };
    if k.is_provided() {
        let outputs = [
            (c"DER", Some(c"type-specific")),
            (c"DER", Some(c"PrivateKeyInfo")),
        ];
        let outputs = if traditional {
            &outputs[..]
        } else {
            outputs.get(1..).unwrap_or_default()
        };
        // SAFETY: as above.
        return unsafe { i2d_provided(a, EVP_PKEY_KEYPAIR, outputs, pp) };
    }
    let funcs = k.ameth_funcs();
    if traditional && let Some(encode) = funcs.and_then(|f| f.old_priv_encode) {
        // SAFETY: the method's function with the caller's key and output.
        return unsafe { encode(a, pp) };
    }
    if funcs.is_some_and(|f| f.priv_encode.is_some()) {
        // SAFETY: the caller's key.
        let p8 = unsafe { super::d2i::EVP_PKEY2PKCS8(a) };
        let mut ret = 0;
        if !p8.is_null() {
            // SAFETY: the new structure; the caller's output.
            ret = unsafe { crate::x509::p8::i2d_PKCS8_PRIV_KEY_INFO(p8, pp) };
            // SAFETY: made above.
            unsafe { crate::x509::p8::PKCS8_PRIV_KEY_INFO_free(p8) };
        }
        return ret;
    }
    // 3.6 raises it from the shared function.
    err::raise(
        ERR_LIB_ASN1,
        ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE,
        "i2d_PrivateKey_impl",
    );
    -1
}

ffi_export! {
    /// Encodes the private key: the type-specific structure, or (for a type without one) a
    /// PrivateKeyInfo. The length, or -1 (0 when making the PrivateKeyInfo fails).
    ///
    /// # Safety
    /// As for `i2d_KeyParams`.
    pub unsafe extern "C" fn i2d_PrivateKey(a: *const EVP_PKEY, pp: *mut *mut c_uchar) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { i2d_private_key(a, pp, true) }
    }
}

ffi_export! {
    /// Encodes the private key as a PKCS #8 PrivateKeyInfo (3.6), whatever its type. The length,
    /// or -1 (0 when making the PrivateKeyInfo fails).
    ///
    /// # Safety
    /// As for `i2d_KeyParams`.
    pub unsafe extern "C" fn i2d_PKCS8PrivateKey(a: *const EVP_PKEY, pp: *mut *mut c_uchar) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { i2d_private_key(a, pp, false) }
    }
}

ffi_export! {
    /// Encodes the public key: RSAPublicKey, DSAPublicKey, or an EC key's point (and a provided
    /// key's type-specific structure or blob). The length, or -1.
    ///
    /// # Safety
    /// As for `i2d_KeyParams`.
    pub unsafe extern "C" fn i2d_PublicKey(a: *const EVP_PKEY, pp: *mut *mut c_uchar) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { pkey(a) }) else { return -1 };
        if k.is_provided() {
            let outputs = [(c"DER", Some(c"type-specific")), (c"blob", None)];
            // SAFETY: as above.
            return unsafe { i2d_provided(a, EVP_PKEY_PUBLIC_KEY, &outputs, pp) };
        }
        // SAFETY: as above.
        let data = unsafe { legacy_data(a) };
        // SAFETY: as above.
        match unsafe { EVP_PKEY_get_base_id(a) } {
            // SAFETY: the key's RSA (or NULL); the caller's output.
            EVP_PKEY_RSA => unsafe { crate::rsa_asn1::i2d_RSAPublicKey(data.cast(), pp) },
            // SAFETY: as above, a DSA.
            EVP_PKEY_DSA => unsafe { crate::dsa_asn1::i2d_DSAPublicKey(data.cast(), pp) },
            // SAFETY: as above, an EC key.
            EVP_PKEY_EC => unsafe { crate::ec::key_asn1::i2o_ECPublicKey(data.cast(), pp) },
            _ => {
                err::raise(ERR_LIB_ASN1, ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE, "i2d_PublicKey");
                -1
            }
        }
    }
}

/// The key-to-DER functions as `i2d_of_void`s, for `ASN1_i2d_bio_of`.
macro_rules! as_void {
    ($($name:ident = $f:ident),*) => {$(
        ffi_callback! {
            /// The function over an `EVP_PKEY` given as `void`.
            ///
            /// # Safety
            /// As for the function.
            pub(crate) unsafe extern "C" fn $name(a: *const c_void, pp: *mut *mut c_uchar) -> c_int
            where failure = -1, library = ERR_LIB_ASN1
            {
                // SAFETY: the caller's guarantee.
                unsafe { $f(a.cast(), pp) }
            }
        }
    )*};
}

as_void!(
    key_params_void = i2d_KeyParams,
    private_key_void = i2d_PrivateKey
);

ffi_export! {
    /// Writes the key's parameters (`i2d_KeyParams`) to a BIO. 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `pkey` is a live key.
    pub unsafe extern "C" fn i2d_KeyParams_bio(bp: *mut BIO, pkey: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_i2d_bio(Some(key_params_void), bp, pkey.cast()) }
    }
}

ffi_export! {
    /// Writes the private key (`i2d_PrivateKey`) to a BIO. 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `pkey` is a live key.
    pub unsafe extern "C" fn i2d_PrivateKey_bio(bp: *mut BIO, pkey: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_i2d_bio(Some(private_key_void), bp, pkey.cast()) }
    }
}

ffi_export! {
    /// Writes the private key (`i2d_PrivateKey`) to a `FILE`. 1, or 0.
    ///
    /// # Safety
    /// `fp` is an open `FILE`; `pkey` is a live key.
    pub unsafe extern "C" fn i2d_PrivateKey_fp(fp: *mut FILE, pkey: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_i2d_fp(Some(private_key_void), fp, pkey.cast()) }
    }
}

ffi_export! {
    /// Writes the key's PrivateKeyInfo (`EVP_PKEY2PKCS8`) to a BIO. 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `key` is a live key.
    pub unsafe extern "C" fn i2d_PKCS8PrivateKeyInfo_bio(bp: *mut BIO, key: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let p8inf = unsafe { super::d2i::EVP_PKEY2PKCS8(key) };
        if p8inf.is_null() {
            return 0;
        }
        // SAFETY: the caller's BIO; the new structure.
        let ret = unsafe { crate::x509::p8::i2d_PKCS8_PRIV_KEY_INFO_bio(bp, p8inf) };
        // SAFETY: made above.
        unsafe { crate::x509::p8::PKCS8_PRIV_KEY_INFO_free(p8inf) };
        ret
    }
}

ffi_export! {
    /// Writes the key's PrivateKeyInfo (`EVP_PKEY2PKCS8`) to a `FILE`. 1, or 0.
    ///
    /// # Safety
    /// `fp` is an open `FILE`; `key` is a live key.
    pub unsafe extern "C" fn i2d_PKCS8PrivateKeyInfo_fp(fp: *mut FILE, key: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let p8inf = unsafe { super::d2i::EVP_PKEY2PKCS8(key) };
        if p8inf.is_null() {
            return 0;
        }
        // SAFETY: the caller's `FILE`; the new structure.
        let ret = unsafe { crate::x509::p8::i2d_PKCS8_PRIV_KEY_INFO_fp(fp, p8inf) };
        // SAFETY: made above.
        unsafe { crate::x509::p8::PKCS8_PRIV_KEY_INFO_free(p8inf) };
        ret
    }
}
