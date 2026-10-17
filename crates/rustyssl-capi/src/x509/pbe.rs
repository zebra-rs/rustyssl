//! The password-based encryption parameters (`p5_pbe.c`, `p5_pbev2.c`, `p5_scrypt.c`): PKCS#5's
//! PBEParameter, PBES2-params, PBKDF2-params, PBMAC1-params, and RFC 7914's scrypt-params, as
//! public-layout structures over ASN.1 templates, with their DER functions.

use core::ffi::{c_int, c_uchar};
use core::mem::offset_of;
use core::ptr;

use rustyssl_abi::{
    ASN1_ITEM, ASN1_TFLG_OPTIONAL, ERR_LIB_ASN1, PBE2PARAM, PBEPARAM, PBKDF2PARAM, PBMAC1PARAM,
    SCRYPT_PARAMS,
};
use rustyssl_abi::{
    ASN1_STRING, ERR_R_ASN1_LIB, ERR_R_PASSED_INVALID_ARGUMENT, ERR_R_PASSED_NULL_PARAMETER,
    ERR_R_X509_LIB, EVP_CIPHER, NID_undef, OSSL_LIB_CTX, PKCS5_DEFAULT_ITER, V_ASN1_OCTET_STRING,
    V_ASN1_SEQUENCE, X509_ALGOR,
};

use crate::asn1::tpl::items::{
    ASN1_ANY_it, ASN1_INTEGER_it, ASN1_OCTET_STRING_it, X509_ALGOR_it, d2i, i2d, new_free,
};
use crate::asn1::tpl::items::{X509_ALGOR_free, X509_ALGOR_new};
use crate::asn1::tpl::statics::{Templates, sequence};
use crate::asn1::tpl::{item_fns, template_at};
use crate::err;
use crate::ffi::ffi_export;

static PBEPARAM_TT: Templates<2> = Templates([
    template_at(
        0,
        0,
        offset_of!(PBEPARAM, salt),
        c"salt",
        ASN1_OCTET_STRING_it,
    ),
    template_at(0, 0, offset_of!(PBEPARAM, iter), c"iter", ASN1_INTEGER_it),
]);

item_fns! {
    /// PBEParameter: SEQUENCE { salt OCTET STRING, iterationCount INTEGER }.
    pub unsafe extern "C" fn PBEPARAM_it = sequence::<PBEPARAM, 2>(&PBEPARAM_TT, None, c"PBEPARAM");
}

new_free! {
    pub unsafe extern "C" fn PBEPARAM_new, pub unsafe extern "C" fn PBEPARAM_free(PBEPARAM) = PBEPARAM_it;
}

i2d! {
    /// Encodes a PBEParameter.
    pub unsafe extern "C" fn i2d_PBEPARAM(PBEPARAM) = PBEPARAM_it;
}

d2i! {
    /// Decodes a PBEParameter.
    pub unsafe extern "C" fn d2i_PBEPARAM(PBEPARAM) = PBEPARAM_it;
}

static PBE2PARAM_TT: Templates<2> = Templates([
    template_at(
        0,
        0,
        offset_of!(PBE2PARAM, keyfunc),
        c"keyfunc",
        X509_ALGOR_it,
    ),
    template_at(
        0,
        0,
        offset_of!(PBE2PARAM, encryption),
        c"encryption",
        X509_ALGOR_it,
    ),
]);

item_fns! {
    /// PBES2-params: SEQUENCE { keyDerivationFunc AlgorithmIdentifier, encryptionScheme
    /// AlgorithmIdentifier }.
    pub unsafe extern "C" fn PBE2PARAM_it = sequence::<PBE2PARAM, 2>(&PBE2PARAM_TT, None, c"PBE2PARAM");
}

new_free! {
    pub unsafe extern "C" fn PBE2PARAM_new, pub unsafe extern "C" fn PBE2PARAM_free(PBE2PARAM) = PBE2PARAM_it;
}

i2d! {
    /// Encodes a PBES2-params.
    pub unsafe extern "C" fn i2d_PBE2PARAM(PBE2PARAM) = PBE2PARAM_it;
}

d2i! {
    /// Decodes a PBES2-params.
    pub unsafe extern "C" fn d2i_PBE2PARAM(PBE2PARAM) = PBE2PARAM_it;
}

static PBKDF2PARAM_TT: Templates<4> = Templates([
    template_at(0, 0, offset_of!(PBKDF2PARAM, salt), c"salt", ASN1_ANY_it),
    template_at(
        0,
        0,
        offset_of!(PBKDF2PARAM, iter),
        c"iter",
        ASN1_INTEGER_it,
    ),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(PBKDF2PARAM, keylength),
        c"keylength",
        ASN1_INTEGER_it,
    ),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(PBKDF2PARAM, prf),
        c"prf",
        X509_ALGOR_it,
    ),
]);

item_fns! {
    /// PBKDF2-params: SEQUENCE { salt ANY, iterationCount INTEGER, keyLength INTEGER OPTIONAL,
    /// prf AlgorithmIdentifier OPTIONAL }.
    pub unsafe extern "C" fn PBKDF2PARAM_it = sequence::<PBKDF2PARAM, 4>(&PBKDF2PARAM_TT, None, c"PBKDF2PARAM");
}

new_free! {
    pub unsafe extern "C" fn PBKDF2PARAM_new, pub unsafe extern "C" fn PBKDF2PARAM_free(PBKDF2PARAM) = PBKDF2PARAM_it;
}

i2d! {
    /// Encodes a PBKDF2-params.
    pub unsafe extern "C" fn i2d_PBKDF2PARAM(PBKDF2PARAM) = PBKDF2PARAM_it;
}

d2i! {
    /// Decodes a PBKDF2-params.
    pub unsafe extern "C" fn d2i_PBKDF2PARAM(PBKDF2PARAM) = PBKDF2PARAM_it;
}

static PBMAC1PARAM_TT: Templates<2> = Templates([
    template_at(
        0,
        0,
        offset_of!(PBMAC1PARAM, keyDerivationFunc),
        c"keyDerivationFunc",
        X509_ALGOR_it,
    ),
    template_at(
        0,
        0,
        offset_of!(PBMAC1PARAM, messageAuthScheme),
        c"messageAuthScheme",
        X509_ALGOR_it,
    ),
]);

item_fns! {
    /// PBMAC1-params: SEQUENCE { keyDerivationFunc AlgorithmIdentifier, messageAuthScheme
    /// AlgorithmIdentifier }.
    pub unsafe extern "C" fn PBMAC1PARAM_it = sequence::<PBMAC1PARAM, 2>(&PBMAC1PARAM_TT, None, c"PBMAC1PARAM");
}

new_free! {
    pub unsafe extern "C" fn PBMAC1PARAM_new, pub unsafe extern "C" fn PBMAC1PARAM_free(PBMAC1PARAM) = PBMAC1PARAM_it;
}

i2d! {
    /// Encodes a PBMAC1-params.
    pub unsafe extern "C" fn i2d_PBMAC1PARAM(PBMAC1PARAM) = PBMAC1PARAM_it;
}

d2i! {
    /// Decodes a PBMAC1-params.
    pub unsafe extern "C" fn d2i_PBMAC1PARAM(PBMAC1PARAM) = PBMAC1PARAM_it;
}

static SCRYPT_PARAMS_TT: Templates<5> = Templates([
    template_at(
        0,
        0,
        offset_of!(SCRYPT_PARAMS, salt),
        c"salt",
        ASN1_OCTET_STRING_it,
    ),
    template_at(
        0,
        0,
        offset_of!(SCRYPT_PARAMS, costParameter),
        c"costParameter",
        ASN1_INTEGER_it,
    ),
    template_at(
        0,
        0,
        offset_of!(SCRYPT_PARAMS, blockSize),
        c"blockSize",
        ASN1_INTEGER_it,
    ),
    template_at(
        0,
        0,
        offset_of!(SCRYPT_PARAMS, parallelizationParameter),
        c"parallelizationParameter",
        ASN1_INTEGER_it,
    ),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(SCRYPT_PARAMS, keyLength),
        c"keyLength",
        ASN1_INTEGER_it,
    ),
]);

item_fns! {
    /// scrypt-params: SEQUENCE { salt OCTET STRING, costParameter INTEGER, blockSize INTEGER,
    /// parallelizationParameter INTEGER, keyLength INTEGER OPTIONAL }.
    pub unsafe extern "C" fn SCRYPT_PARAMS_it = sequence::<SCRYPT_PARAMS, 5>(&SCRYPT_PARAMS_TT, None, c"SCRYPT_PARAMS");
}

new_free! {
    pub unsafe extern "C" fn SCRYPT_PARAMS_new, pub unsafe extern "C" fn SCRYPT_PARAMS_free(SCRYPT_PARAMS) = SCRYPT_PARAMS_it;
}

i2d! {
    /// Encodes a scrypt-params.
    pub unsafe extern "C" fn i2d_SCRYPT_PARAMS(SCRYPT_PARAMS) = SCRYPT_PARAMS_it;
}

d2i! {
    /// Decodes a scrypt-params.
    pub unsafe extern "C" fn d2i_SCRYPT_PARAMS(SCRYPT_PARAMS) = SCRYPT_PARAMS_it;
}

// The algorithm builders (`p5_pbe.c`, `p5_pbev2.c`, `p5_scrypt.c`).

/// `PKCS5_DEFAULT_PBE1_SALT_LEN` and `PKCS5_DEFAULT_PBE2_SALT_LEN` (`crypto/evp.h`).
const PBE1_SALT_LEN: c_int = rustyssl_abi::PKCS5_SALT_LEN;
const PBE2_SALT_LEN: c_int = 16;

/// `len` octets: copies of `salt`'s, else random ones (from `libctx`), in a buffer from
/// `CRYPTO_malloc`; NULL (with the RAND error) on failure.
///
/// # Safety
/// `salt` is NULL or `len` octets; `libctx` is NULL or live.
unsafe fn salt_or_random(
    salt: *const c_uchar,
    len: usize,
    libctx: *mut OSSL_LIB_CTX,
) -> *mut c_uchar {
    let buf: *mut c_uchar = crate::mem::malloc(len, ptr::null(), 0).cast();
    if buf.is_null() {
        return buf;
    }
    if !salt.is_null() {
        // SAFETY: the caller's `len` octets; the new buffer.
        unsafe { ptr::copy_nonoverlapping(salt, buf, len) };
    // SAFETY: the new buffer of `len`.
    } else if unsafe { crate::rand_lib::RAND_bytes_ex(libctx, buf, len, 0) } <= 0 {
        // SAFETY: made above.
        unsafe { crate::mem::release(buf.cast()) };
        return ptr::null_mut();
    }
    buf
}

ffi_export! {
    /// Sets the AlgorithmIdentifier to the PBES1 (or PKCS#12) algorithm `alg` with a
    /// PBEParameter: `iter` iterations (`PKCS5_DEFAULT_ITER` for none), the salt (8 random
    /// octets for none). 1, or 0.
    ///
    /// # Safety
    /// `algor` is a live AlgorithmIdentifier; `salt` is NULL or `saltlen` octets; `ctx` is NULL
    /// or live.
    pub unsafe extern "C" fn PKCS5_pbe_set0_algor_ex(algor: *mut X509_ALGOR, alg: c_int, iter: c_int, salt: *const c_uchar, saltlen: c_int, ctx: *mut OSSL_LIB_CTX) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        const F: &str = "PKCS5_pbe_set0_algor_ex";
        // SAFETY: no preconditions.
        let pbe: *mut PBEPARAM = unsafe { PBEPARAM_new() };
        let mut pbe_str: *mut ASN1_STRING = ptr::null_mut();
        let fail = |pbe: *mut PBEPARAM, pbe_str: *mut ASN1_STRING| {
            // SAFETY: made here, or NULL.
            unsafe { PBEPARAM_free(pbe) };
            // SAFETY: as above.
            unsafe { crate::asn1::string::ASN1_STRING_free(pbe_str) };
            0
        };
        // SAFETY: made above, or NULL.
        let Some(p) = (unsafe { pbe.as_mut() }) else {
            err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, F);
            return 0;
        };
        let iter = if iter <= 0 { PKCS5_DEFAULT_ITER } else { iter };
        // SAFETY: the new parameters' INTEGER.
        if unsafe { crate::asn1::integer::ASN1_INTEGER_set(p.iter, iter.into()) } == 0 {
            err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, F);
            return fail(pbe, pbe_str);
        }
        let saltlen = if saltlen == 0 { PBE1_SALT_LEN } else { saltlen };
        let Ok(len) = usize::try_from(saltlen) else { return fail(pbe, pbe_str) };
        // SAFETY: the caller's salt, or none; the caller's library context.
        let sstr = unsafe { salt_or_random(salt, len, ctx) };
        if sstr.is_null() {
            return fail(pbe, pbe_str);
        }
        // SAFETY: the new parameters' OCTET STRING takes the buffer.
        unsafe { crate::asn1::string::ASN1_STRING_set0(p.salt, sstr.cast(), saltlen) };
        // SAFETY: no preconditions.
        let it = unsafe { PBEPARAM_it() };
        // SAFETY: the parameters; a place for the new string.
        if unsafe { crate::asn1::tpl::util::ASN1_item_pack(pbe.cast(), it, &raw mut pbe_str) }.is_null() {
            err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, F);
            return fail(pbe, pbe_str);
        }
        // SAFETY: made above.
        unsafe { PBEPARAM_free(pbe) };
        // SAFETY: a built-in NID.
        let obj = unsafe { crate::objects::OBJ_nid2obj(alg) };
        // SAFETY: the caller's AlgorithmIdentifier takes the object and string.
        if unsafe { crate::x509::algor::X509_ALGOR_set0(algor, obj, V_ASN1_SEQUENCE, pbe_str.cast()) } != 0 {
            return 1;
        }
        fail(ptr::null_mut(), pbe_str)
    }
}

ffi_export! {
    /// `PKCS5_pbe_set0_algor_ex` with the default library context.
    ///
    /// # Safety
    /// As for `PKCS5_pbe_set0_algor_ex`.
    pub unsafe extern "C" fn PKCS5_pbe_set0_algor(algor: *mut X509_ALGOR, alg: c_int, iter: c_int, salt: *const c_uchar, saltlen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS5_pbe_set0_algor_ex(algor, alg, iter, salt, saltlen, ptr::null_mut()) }
    }
}

ffi_export! {
    /// A new AlgorithmIdentifier set by `PKCS5_pbe_set0_algor_ex`, or NULL.
    ///
    /// # Safety
    /// As for `PKCS5_pbe_set0_algor_ex`.
    pub unsafe extern "C" fn PKCS5_pbe_set_ex(alg: c_int, iter: c_int, salt: *const c_uchar, saltlen: c_int, ctx: *mut OSSL_LIB_CTX) -> *mut X509_ALGOR
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let ret = unsafe { X509_ALGOR_new() };
        if ret.is_null() {
            err::raise(ERR_LIB_ASN1, ERR_R_X509_LIB, "PKCS5_pbe_set_ex");
            return ret;
        }
        // SAFETY: the new AlgorithmIdentifier; the caller's guarantee.
        if unsafe { PKCS5_pbe_set0_algor_ex(ret, alg, iter, salt, saltlen, ctx) } != 0 {
            return ret;
        }
        // SAFETY: made above.
        unsafe { X509_ALGOR_free(ret) };
        ptr::null_mut()
    }
}

ffi_export! {
    /// `PKCS5_pbe_set_ex` with the default library context.
    ///
    /// # Safety
    /// As for `PKCS5_pbe_set_ex`.
    pub unsafe extern "C" fn PKCS5_pbe_set(alg: c_int, iter: c_int, salt: *const c_uchar, saltlen: c_int) -> *mut X509_ALGOR
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS5_pbe_set_ex(alg, iter, salt, saltlen, ptr::null_mut()) }
    }
}

/// `ossl_X509_ALGOR_from_nid`: an AlgorithmIdentifier of `nid` with a NULL parameter, or NULL.
unsafe fn algor_null(nid: c_int) -> *mut X509_ALGOR {
    // SAFETY: no preconditions.
    let alg = unsafe { X509_ALGOR_new() };
    if alg.is_null() {
        return alg;
    }
    // SAFETY: a built-in NID.
    let obj = unsafe { crate::objects::OBJ_nid2obj(nid) };
    // SAFETY: the new AlgorithmIdentifier takes the object.
    if unsafe {
        crate::x509::algor::X509_ALGOR_set0(alg, obj, rustyssl_abi::V_ASN1_NULL, ptr::null_mut())
    } == 0
    {
        // SAFETY: made above.
        unsafe { X509_ALGOR_free(alg) };
        return ptr::null_mut();
    }
    alg
}

ffi_export! {
    /// A PBKDF2 AlgorithmIdentifier: `iter` iterations (`PKCS5_DEFAULT_ITER` for none), the salt
    /// (16 random octets for none), the key length when positive, and the PRF unless it's
    /// HMAC-SHA1. NULL on failure.
    ///
    /// # Safety
    /// `salt` is NULL or `saltlen` octets; `libctx` is NULL or live.
    pub unsafe extern "C" fn PKCS5_pbkdf2_set_ex(iter: c_int, salt: *mut c_uchar, saltlen: c_int, prf_nid: c_int, keylen: c_int, libctx: *mut OSSL_LIB_CTX) -> *mut X509_ALGOR
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        use crate::asn1::integer::ASN1_INTEGER_set;
        const F: &str = "PKCS5_pbkdf2_set_ex";
        // SAFETY: no preconditions.
        let kdf: *mut PBKDF2PARAM = unsafe { PBKDF2PARAM_new() };
        let mut keyfunc: *mut X509_ALGOR = ptr::null_mut();
        let fail = |kdf: *mut PBKDF2PARAM, keyfunc: *mut X509_ALGOR| {
            // SAFETY: made here, or NULL.
            unsafe { PBKDF2PARAM_free(kdf) };
            // SAFETY: as above.
            unsafe { X509_ALGOR_free(keyfunc) };
            ptr::null_mut()
        };
        // SAFETY: made above, or NULL.
        let Some(k) = (unsafe { kdf.as_mut() }) else {
            err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, F);
            return ptr::null_mut();
        };
        // SAFETY: no preconditions.
        let osalt = unsafe { crate::asn1::string::ASN1_OCTET_STRING_new() };
        if osalt.is_null() {
            err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, F);
            return fail(kdf, keyfunc);
        }
        // SAFETY: the new parameters' salt, an `ASN1_TYPE`.
        let st = unsafe { &mut *k.salt };
        st.value.octet_string = osalt;
        st.type_ = V_ASN1_OCTET_STRING;
        if saltlen < 0 {
            err::raise(ERR_LIB_ASN1, ERR_R_PASSED_INVALID_ARGUMENT, F);
            return fail(kdf, keyfunc);
        }
        let saltlen = if saltlen == 0 { PBE2_SALT_LEN } else { saltlen };
        let len = usize::try_from(saltlen).unwrap_or(0);
        let data: *mut c_uchar = crate::mem::malloc(len, ptr::null(), 0).cast();
        if data.is_null() {
            return fail(kdf, keyfunc);
        }
        // SAFETY: the new OCTET STRING, which takes the buffer.
        let os = unsafe { &mut *osalt };
        os.data = data;
        os.length = saltlen;
        if !salt.is_null() {
            // SAFETY: the caller's `saltlen` octets; the new buffer.
            unsafe { ptr::copy_nonoverlapping(salt, data, len) };
        // SAFETY: the new buffer.
        } else if unsafe { crate::rand_lib::RAND_bytes_ex(libctx, data, len, 0) } <= 0 {
            err::raise(ERR_LIB_ASN1, rustyssl_abi::ERR_R_RAND_LIB, F);
            return fail(kdf, keyfunc);
        }
        let iter = if iter <= 0 { PKCS5_DEFAULT_ITER } else { iter };
        // SAFETY: the parameters' INTEGER.
        if unsafe { ASN1_INTEGER_set(k.iter, iter.into()) } == 0 {
            err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, F);
            return fail(kdf, keyfunc);
        }
        if keylen > 0 {
            // SAFETY: no preconditions.
            k.keylength = unsafe { crate::asn1::string::ASN1_INTEGER_new() };
            // SAFETY: the new INTEGER, or NULL.
            if k.keylength.is_null() || unsafe { ASN1_INTEGER_set(k.keylength, keylen.into()) } == 0 {
                err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, F);
                return fail(kdf, keyfunc);
            }
        }
        if prf_nid > 0 && prf_nid != rustyssl_abi::NID_hmacWithSHA1 {
            // SAFETY: a NID.
            k.prf = unsafe { algor_null(prf_nid) };
            if k.prf.is_null() {
                err::raise(ERR_LIB_ASN1, ERR_R_X509_LIB, F);
                return fail(kdf, keyfunc);
            }
        }
        // SAFETY: no preconditions.
        keyfunc = unsafe { X509_ALGOR_new() };
        // SAFETY: made above, or NULL.
        let Some(kf) = (unsafe { keyfunc.as_mut() }) else {
            err::raise(ERR_LIB_ASN1, ERR_R_X509_LIB, F);
            return fail(kdf, keyfunc);
        };
        // SAFETY: a built-in NID.
        kf.algorithm = unsafe { crate::objects::OBJ_nid2obj(rustyssl_abi::NID_id_pbkdf2) };
        // SAFETY: no preconditions.
        let it = unsafe { PBKDF2PARAM_it() };
        // SAFETY: the parameters; the AlgorithmIdentifier's parameter.
        if unsafe { crate::asn1::tpl::util::ASN1_TYPE_pack_sequence(it, kdf.cast(), &raw mut kf.parameter) }.is_null() {
            err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, F);
            return fail(kdf, keyfunc);
        }
        // SAFETY: made above.
        unsafe { PBKDF2PARAM_free(kdf) };
        keyfunc
    }
}

ffi_export! {
    /// `PKCS5_pbkdf2_set_ex` with the default library context.
    ///
    /// # Safety
    /// As for `PKCS5_pbkdf2_set_ex`.
    pub unsafe extern "C" fn PKCS5_pbkdf2_set(iter: c_int, salt: *mut c_uchar, saltlen: c_int, prf_nid: c_int, keylen: c_int) -> *mut X509_ALGOR
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS5_pbkdf2_set_ex(iter, salt, saltlen, prf_nid, keylen, ptr::null_mut()) }
    }
}

/// The PBES2 encryption scheme of `cipher` (with its IV, `aiv`'s or random) and the key
/// derivation `keyfunc` makes (given the key length for RC2, -1 otherwise), as a PBES2
/// AlgorithmIdentifier: `PKCS5_pbe2_set_iv_ex`'s and `PKCS5_pbe2_set_scrypt`'s common part.
/// The PRF NID, when `prf_nid` holds -1, is the cipher's (`EVP_CTRL_PBE_PRF_NID`), else
/// HMAC-SHA256.
///
/// # Safety
/// `cipher` is live; `aiv` is NULL or the cipher's IV length of octets; `libctx` is NULL or
/// live.
unsafe fn pbe2_set(
    cipher: *const EVP_CIPHER,
    aiv: *const c_uchar,
    libctx: *mut OSSL_LIB_CTX,
    prf_nid: Option<&mut c_int>,
    keyfunc: impl FnOnce(c_int, c_int) -> *mut X509_ALGOR,
) -> *mut X509_ALGOR {
    use crate::evp::cipher_ctx::{
        EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new, EVP_CipherInit_ex,
    };
    const F: &str = "PKCS5_pbe2_set_iv_ex";
    let mut ctx = ptr::null_mut();
    let mut ret: *mut X509_ALGOR = ptr::null_mut();
    let mut pbe2: *mut PBE2PARAM = ptr::null_mut();
    'go: {
        // SAFETY: the caller's cipher.
        let alg_nid = unsafe { crate::evp::cipher::EVP_CIPHER_get_type(cipher) };
        if alg_nid == NID_undef {
            err::raise(
                ERR_LIB_ASN1,
                rustyssl_abi::ASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER,
                F,
            );
            break 'go;
        }
        // SAFETY: no preconditions.
        pbe2 = unsafe { PBE2PARAM_new() };
        // SAFETY: made above, or NULL.
        let Some(p) = (unsafe { pbe2.as_mut() }) else {
            err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, F);
            break 'go;
        };
        // SAFETY: the new parameters' AlgorithmIdentifier.
        let scheme = unsafe { &mut *p.encryption };
        // SAFETY: a built-in NID.
        scheme.algorithm = unsafe { crate::objects::OBJ_nid2obj(alg_nid) };
        // SAFETY: no preconditions.
        scheme.parameter = unsafe { crate::asn1::tpl::items::ASN1_TYPE_new() };
        if scheme.parameter.is_null() {
            err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, F);
            break 'go;
        }
        let mut iv = [0u8; rustyssl_abi::EVP_MAX_IV_LENGTH as usize];
        // SAFETY: the caller's cipher.
        let ivlen =
            usize::try_from(unsafe { crate::evp::cipher::EVP_CIPHER_get_iv_length(cipher) })
                .unwrap_or(0)
                .min(iv.len());
        if ivlen > 0 {
            if aiv.is_null() {
                // SAFETY: the IV buffer.
                if unsafe { crate::rand_lib::RAND_bytes_ex(libctx, iv.as_mut_ptr(), ivlen, 0) } <= 0
                {
                    break 'go;
                }
            } else {
                // SAFETY: the caller's IV of the cipher's length.
                unsafe { ptr::copy_nonoverlapping(aiv, iv.as_mut_ptr(), ivlen) };
            }
        }
        // SAFETY: no preconditions.
        ctx = unsafe { EVP_CIPHER_CTX_new() };
        if ctx.is_null() {
            err::raise(ERR_LIB_ASN1, rustyssl_abi::ERR_R_EVP_LIB, F);
            break 'go;
        }
        // SAFETY: the new context; the cipher; the IV.
        if unsafe { EVP_CipherInit_ex(ctx, cipher, ptr::null_mut(), ptr::null(), iv.as_ptr(), 0) }
            == 0
        {
            break 'go;
        }
        // SAFETY: the context; the scheme's parameter.
        if unsafe { crate::evp::cipher_asn1::EVP_CIPHER_param_to_asn1(ctx, scheme.parameter) } <= 0
        {
            err::raise(
                ERR_LIB_ASN1,
                rustyssl_abi::ASN1_R_ERROR_SETTING_CIPHER_PARAMS,
                F,
            );
            break 'go;
        }
        if let Some(prf) = prf_nid {
            // SAFETY: no preconditions.
            unsafe { crate::err::ERR_set_mark() };
            if *prf == -1
                // SAFETY: the context; the NID's slot.
                && unsafe {
                    EVP_CIPHER_CTX_ctrl(
                        ctx,
                        rustyssl_abi::EVP_CTRL_PBE_PRF_NID,
                        0,
                        ptr::from_mut(prf).cast(),
                    )
                } <= 0
            {
                *prf = rustyssl_abi::NID_hmacWithSHA256;
            }
            // SAFETY: as above.
            unsafe { crate::err::ERR_pop_to_mark() };
        }
        // SAFETY: made above.
        unsafe { EVP_CIPHER_CTX_free(ctx) };
        ctx = ptr::null_mut();
        let keylen = if alg_nid == rustyssl_abi::NID_rc2_cbc {
            // SAFETY: the caller's cipher.
            unsafe { crate::evp::cipher::EVP_CIPHER_get_key_length(cipher) }
        } else {
            -1
        };
        // SAFETY: the parameters' old AlgorithmIdentifier.
        unsafe { X509_ALGOR_free(p.keyfunc) };
        p.keyfunc = keyfunc(alg_nid, keylen);
        if p.keyfunc.is_null() {
            err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, F);
            break 'go;
        }
        // SAFETY: no preconditions.
        ret = unsafe { X509_ALGOR_new() };
        // SAFETY: made above, or NULL.
        let Some(r) = (unsafe { ret.as_mut() }) else {
            err::raise(ERR_LIB_ASN1, ERR_R_X509_LIB, F);
            break 'go;
        };
        // SAFETY: a built-in NID.
        r.algorithm = unsafe { crate::objects::OBJ_nid2obj(rustyssl_abi::NID_pbes2) };
        // SAFETY: no preconditions.
        let it = unsafe { PBE2PARAM_it() };
        // SAFETY: the parameters; the AlgorithmIdentifier's parameter.
        if unsafe {
            crate::asn1::tpl::util::ASN1_TYPE_pack_sequence(it, pbe2.cast(), &raw mut r.parameter)
        }
        .is_null()
        {
            err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, F);
            break 'go;
        }
        // SAFETY: made above.
        unsafe { PBE2PARAM_free(pbe2) };
        return ret;
    }
    // SAFETY: made here, or NULL.
    unsafe { EVP_CIPHER_CTX_free(ctx) };
    // SAFETY: as above.
    unsafe { PBE2PARAM_free(pbe2) };
    // SAFETY: as above.
    unsafe { X509_ALGOR_free(ret) };
    ptr::null_mut()
}

ffi_export! {
    /// A PBES2 AlgorithmIdentifier: `cipher` (its IV `aiv`'s or random) keyed by PBKDF2 with
    /// `iter` iterations, the salt, and the PRF `prf_nid` (-1 for the cipher's, else
    /// HMAC-SHA256). NULL on failure.
    ///
    /// # Safety
    /// `cipher` is live; `salt` is NULL or `saltlen` octets; `aiv` is NULL or the cipher's IV
    /// length; `libctx` is NULL or live.
    pub unsafe extern "C" fn PKCS5_pbe2_set_iv_ex(cipher: *const EVP_CIPHER, iter: c_int, salt: *mut c_uchar, saltlen: c_int, aiv: *mut c_uchar, prf_nid: c_int, libctx: *mut OSSL_LIB_CTX) -> *mut X509_ALGOR
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        let mut prf = prf_nid;
        let prf_ptr: *const c_int = &raw const prf;
        let keyfunc = |_alg, keylen| {
            // SAFETY: the PRF settled by `pbe2_set` before it calls this.
            let prf = unsafe { prf_ptr.read() };
            // SAFETY: the caller's salt and library context.
            unsafe { PKCS5_pbkdf2_set_ex(iter, salt, saltlen, prf, keylen, libctx) }
        };
        // SAFETY: the caller's guarantee.
        unsafe { pbe2_set(cipher, aiv, libctx, Some(&mut prf), keyfunc) }
    }
}

ffi_export! {
    /// `PKCS5_pbe2_set_iv_ex` with the default library context.
    ///
    /// # Safety
    /// As for `PKCS5_pbe2_set_iv_ex`.
    pub unsafe extern "C" fn PKCS5_pbe2_set_iv(cipher: *const EVP_CIPHER, iter: c_int, salt: *mut c_uchar, saltlen: c_int, aiv: *mut c_uchar, prf_nid: c_int) -> *mut X509_ALGOR
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS5_pbe2_set_iv_ex(cipher, iter, salt, saltlen, aiv, prf_nid, ptr::null_mut()) }
    }
}

ffi_export! {
    /// `PKCS5_pbe2_set_iv_ex` with a random IV and the cipher's (or the default) PRF.
    ///
    /// # Safety
    /// As for `PKCS5_pbe2_set_iv_ex`.
    pub unsafe extern "C" fn PKCS5_pbe2_set(cipher: *const EVP_CIPHER, iter: c_int, salt: *mut c_uchar, saltlen: c_int) -> *mut X509_ALGOR
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS5_pbe2_set_iv_ex(cipher, iter, salt, saltlen, ptr::null_mut(), -1, ptr::null_mut()) }
    }
}

/// `pkcs5_scrypt_set`: an scrypt AlgorithmIdentifier of the salt (16 random octets for none),
/// N, r, p, and the key length when positive. NULL on failure.
///
/// # Safety
/// `salt` is NULL or `saltlen` octets.
unsafe fn scrypt_set(
    salt: *const c_uchar,
    saltlen: usize,
    keylen: usize,
    n: u64,
    r: u64,
    p: u64,
) -> *mut X509_ALGOR {
    use crate::asn1::integer::{ASN1_INTEGER_set_int64, ASN1_INTEGER_set_uint64};
    const F: &str = "pkcs5_scrypt_set";
    // SAFETY: no preconditions.
    let sparam: *mut SCRYPT_PARAMS = unsafe { SCRYPT_PARAMS_new() };
    let mut keyfunc: *mut X509_ALGOR = ptr::null_mut();
    'go: {
        // SAFETY: made above, or NULL.
        let Some(s) = (unsafe { sparam.as_mut() }) else {
            err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, F);
            break 'go;
        };
        let saltlen = if saltlen == 0 {
            usize::try_from(PBE2_SALT_LEN).unwrap_or(16)
        } else {
            saltlen
        };
        let Ok(len) = c_int::try_from(saltlen) else {
            err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, F);
            break 'go;
        };
        // SAFETY: the new parameters' OCTET STRING; the caller's salt, or NULL (zeros).
        if unsafe { crate::asn1::string::ASN1_STRING_set(s.salt, salt.cast(), len) } == 0 {
            err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, F);
            break 'go;
        }
        // SAFETY: the parameters' OCTET STRING.
        let sdata = unsafe { (*s.salt).data };
        // SAFETY: its buffer of `saltlen` octets.
        if salt.is_null() && unsafe { crate::rand_lib::RAND_bytes(sdata, len) } <= 0 {
            break 'go;
        }
        // SAFETY: the new parameters' INTEGERs.
        let set = unsafe { ASN1_INTEGER_set_uint64(s.costParameter, n) } != 0
            // SAFETY: as above.
            && unsafe { ASN1_INTEGER_set_uint64(s.blockSize, r) } != 0
            // SAFETY: as above.
            && unsafe { ASN1_INTEGER_set_uint64(s.parallelizationParameter, p) } != 0;
        if !set {
            err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, F);
            break 'go;
        }
        if keylen > 0 {
            // SAFETY: no preconditions.
            s.keyLength = unsafe { crate::asn1::string::ASN1_INTEGER_new() };
            let kl = i64::try_from(keylen).unwrap_or(i64::MAX);
            // SAFETY: the new INTEGER, or NULL.
            if s.keyLength.is_null() || unsafe { ASN1_INTEGER_set_int64(s.keyLength, kl) } == 0 {
                err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, F);
                break 'go;
            }
        }
        // SAFETY: no preconditions.
        keyfunc = unsafe { X509_ALGOR_new() };
        // SAFETY: made above, or NULL.
        let Some(kf) = (unsafe { keyfunc.as_mut() }) else {
            err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, F);
            break 'go;
        };
        // SAFETY: a built-in NID.
        kf.algorithm = unsafe { crate::objects::OBJ_nid2obj(rustyssl_abi::NID_id_scrypt) };
        // SAFETY: no preconditions.
        let it = unsafe { SCRYPT_PARAMS_it() };
        // SAFETY: the parameters; the AlgorithmIdentifier's parameter.
        if unsafe {
            crate::asn1::tpl::util::ASN1_TYPE_pack_sequence(
                it,
                sparam.cast(),
                &raw mut kf.parameter,
            )
        }
        .is_null()
        {
            err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, F);
            break 'go;
        }
        // SAFETY: made above.
        unsafe { SCRYPT_PARAMS_free(sparam) };
        return keyfunc;
    }
    // SAFETY: made here, or NULL.
    unsafe { SCRYPT_PARAMS_free(sparam) };
    // SAFETY: as above.
    unsafe { X509_ALGOR_free(keyfunc) };
    ptr::null_mut()
}

ffi_export! {
    /// A PBES2 AlgorithmIdentifier: `cipher` (its IV `aiv`'s or random) keyed by scrypt with the
    /// salt and N, r, and p (validated first). NULL on failure.
    ///
    /// # Safety
    /// `cipher` is NULL or live; `salt` is NULL or `saltlen` octets; `aiv` is NULL or the
    /// cipher's IV length.
    pub unsafe extern "C" fn PKCS5_pbe2_set_scrypt(cipher: *const EVP_CIPHER, salt: *const c_uchar, saltlen: c_int, aiv: *mut c_uchar, n: u64, r: u64, p: u64) -> *mut X509_ALGOR
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        const F: &str = "PKCS5_pbe2_set_scrypt";
        if cipher.is_null() {
            err::raise(ERR_LIB_ASN1, ERR_R_PASSED_NULL_PARAMETER, F);
            return ptr::null_mut();
        }
        // SAFETY: a validation only (no password or output).
        if unsafe { crate::evp::kdf::EVP_PBE_scrypt(ptr::null(), 0, ptr::null(), 0, n, r, p, 0, ptr::null_mut(), 0) } == 0 {
            err::raise(ERR_LIB_ASN1, rustyssl_abi::ASN1_R_INVALID_SCRYPT_PARAMETERS, F);
            return ptr::null_mut();
        }
        // OpenSSL passes the length as a `size_t`: a negative one is huge, and fails.
        let saltlen = usize::try_from(saltlen).unwrap_or(usize::MAX);
        let keyfunc = |alg_nid: c_int, _keylen| {
            let keylen = if alg_nid == rustyssl_abi::NID_rc2_cbc {
                // SAFETY: the caller's cipher.
                usize::try_from(unsafe { crate::evp::cipher::EVP_CIPHER_get_key_length(cipher) }).unwrap_or(0)
            } else {
                0
            };
            // SAFETY: the caller's salt.
            unsafe { scrypt_set(salt, saltlen, keylen, n, r, p) }
        };
        // SAFETY: the caller's guarantee.
        unsafe { pbe2_set(cipher, aiv, ptr::null_mut(), None, keyfunc) }
    }
}
