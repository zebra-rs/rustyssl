//! Password-based encryption (`evp_pbe.c`, `p5_crpt.c`, `p5_crpt2.c`, `p5_scrypt.c`,
//! `p12_crpt.c`): the table of PBE algorithms (`EVP_PBE_*`, the built-in one in OpenSSL's order
//! and the application's additions), `EVP_PBE_CipherInit` over it, and the key and IV
//! derivations it calls (PKCS#5 v1 over PBKDF1, PBES2 with PBKDF2 or scrypt, and PKCS#12's).
//!
//! As OpenSSL's, a cipher or digest is fetched by its short name and, failing that, taken from
//! the legacy tables; PBKDF1 and the ciphers PBES1 uses (DES, RC2) are the legacy provider's, so
//! without it (9.1) their PBEs fail as the reference's do with only the default provider.

use core::ffi::{CStr, c_char, c_int};
use core::ptr;
use std::sync::{Mutex, PoisonError};

use rustyssl_abi::{
    ASN1_TYPE, ERR_LIB_EVP, ERR_LIB_PKCS12, EVP_CIPHER, EVP_CIPHER_CTX, EVP_MAX_IV_LENGTH,
    EVP_MAX_KEY_LENGTH, EVP_MAX_MD_SIZE, EVP_MD, EVP_PBE_KEYGEN, EVP_PBE_KEYGEN_EX,
    EVP_PBE_TYPE_KDF, EVP_PBE_TYPE_OUTER, EVP_PBE_TYPE_PRF, EVP_R_CIPHER_PARAMETER_ERROR,
    EVP_R_DECODE_ERROR, EVP_R_ILLEGAL_SCRYPT_PARAMETERS, EVP_R_INVALID_IV_LENGTH,
    EVP_R_INVALID_KEY_LENGTH, EVP_R_NO_CIPHER_SET, EVP_R_UNKNOWN_CIPHER, EVP_R_UNKNOWN_DIGEST,
    EVP_R_UNKNOWN_PBE_ALGORITHM, EVP_R_UNSUPPORTED_CIPHER,
    EVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION, EVP_R_UNSUPPORTED_KEYLENGTH, EVP_R_UNSUPPORTED_PRF,
    EVP_R_UNSUPPORTED_SALT_TYPE, NID_undef, OSSL_KDF_PARAM_DIGEST, OSSL_KDF_PARAM_ITER,
    OSSL_KDF_PARAM_PASSWORD, OSSL_KDF_PARAM_SALT, OSSL_LIB_CTX, PBE2PARAM, PBEPARAM, PBKDF2PARAM,
    PKCS12_IV_ID, PKCS12_KEY_ID, PKCS12_R_DECODE_ERROR, PKCS12_R_IV_GEN_ERROR,
    PKCS12_R_KEY_GEN_ERROR, SCRYPT_PARAMS, V_ASN1_OCTET_STRING, V_ASN1_SEQUENCE,
};
use rustyssl_crypto::bn::Zeroizing;

use crate::asn1::integer::{ASN1_INTEGER_get, ASN1_INTEGER_get_uint64};
use crate::asn1::tpl::util::ASN1_TYPE_unpack_sequence;
use crate::err::{self, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::evp::cipher::{
    EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_get_iv_length, EVP_CIPHER_get_key_length,
};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_get_key_length, EVP_CIPHER_CTX_get0_cipher, EVP_CipherInit_ex,
};
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free, EVP_MD_get_size, EVP_MD_get0_name};
use crate::ffi::{ffi_callback, ffi_export};
use crate::objects::{OBJ_nid2sn, OBJ_obj2nid, OBJ_obj2txt, i2t_ASN1_OBJECT};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OSSL_PARAM_construct_octet_string,
    OSSL_PARAM_construct_utf8_string,
};
use crate::x509::pbe::{
    PBE2PARAM_free, PBE2PARAM_it, PBEPARAM_free, PBEPARAM_it, PBKDF2PARAM_free, PBKDF2PARAM_it,
    SCRYPT_PARAMS_free, SCRYPT_PARAMS_it,
};

type Keygen = unsafe extern "C" fn(
    *mut EVP_CIPHER_CTX,
    *const c_char,
    c_int,
    *mut ASN1_TYPE,
    *const EVP_CIPHER,
    *const EVP_MD,
    c_int,
) -> c_int;
type KeygenEx = unsafe extern "C" fn(
    *mut EVP_CIPHER_CTX,
    *const c_char,
    c_int,
    *mut ASN1_TYPE,
    *const EVP_CIPHER,
    *const EVP_MD,
    c_int,
    *mut OSSL_LIB_CTX,
    *const c_char,
) -> c_int;

/// A PBE algorithm (`struct evp_pbe_st`).
#[derive(Clone, Copy)]
struct Ctl {
    pbe_type: c_int,
    pbe_nid: c_int,
    cipher_nid: c_int,
    md_nid: c_int,
    keygen: Option<Keygen>,
    keygen_ex: Option<KeygenEx>,
}

const fn outer(nid: c_int, cipher: c_int, md: c_int, keygen: Keygen, keygen_ex: KeygenEx) -> Ctl {
    Ctl {
        pbe_type: EVP_PBE_TYPE_OUTER,
        pbe_nid: nid,
        cipher_nid: cipher,
        md_nid: md,
        keygen: Some(keygen),
        keygen_ex: Some(keygen_ex),
    }
}

const fn prf(nid: c_int, md: c_int) -> Ctl {
    Ctl {
        pbe_type: EVP_PBE_TYPE_PRF,
        pbe_nid: nid,
        cipher_nid: -1,
        md_nid: md,
        keygen: None,
        keygen_ex: None,
    }
}

const fn kdf(nid: c_int, keygen: Keygen, keygen_ex: KeygenEx) -> Ctl {
    Ctl {
        pbe_type: EVP_PBE_TYPE_KDF,
        pbe_nid: nid,
        cipher_nid: -1,
        md_nid: -1,
        keygen: Some(keygen),
        keygen_ex: Some(keygen_ex),
    }
}

/// `builtin_pbe`, in OpenSSL's order (sorted by type and NID, which `EVP_PBE_get` numbers).
static BUILTIN: [Ctl; 34] = {
    use rustyssl_abi::*;
    [
        outer(
            NID_pbeWithMD2AndDES_CBC,
            NID_des_cbc,
            NID_md2,
            PKCS5_PBE_keyivgen,
            PKCS5_PBE_keyivgen_ex,
        ),
        outer(
            NID_pbeWithMD5AndDES_CBC,
            NID_des_cbc,
            NID_md5,
            PKCS5_PBE_keyivgen,
            PKCS5_PBE_keyivgen_ex,
        ),
        outer(
            NID_pbeWithSHA1AndRC2_CBC,
            NID_rc2_64_cbc,
            NID_sha1,
            PKCS5_PBE_keyivgen,
            PKCS5_PBE_keyivgen_ex,
        ),
        outer(NID_id_pbkdf2, -1, -1, pbkdf2_keyivgen, pbkdf2_keyivgen_ex),
        outer(
            NID_pbe_WithSHA1And128BitRC4,
            NID_rc4,
            NID_sha1,
            PKCS12_PBE_keyivgen,
            PKCS12_PBE_keyivgen_ex,
        ),
        outer(
            NID_pbe_WithSHA1And40BitRC4,
            NID_rc4_40,
            NID_sha1,
            PKCS12_PBE_keyivgen,
            PKCS12_PBE_keyivgen_ex,
        ),
        outer(
            NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
            NID_des_ede3_cbc,
            NID_sha1,
            PKCS12_PBE_keyivgen,
            PKCS12_PBE_keyivgen_ex,
        ),
        outer(
            NID_pbe_WithSHA1And2_Key_TripleDES_CBC,
            NID_des_ede_cbc,
            NID_sha1,
            PKCS12_PBE_keyivgen,
            PKCS12_PBE_keyivgen_ex,
        ),
        outer(
            NID_pbe_WithSHA1And128BitRC2_CBC,
            NID_rc2_cbc,
            NID_sha1,
            PKCS12_PBE_keyivgen,
            PKCS12_PBE_keyivgen_ex,
        ),
        outer(
            NID_pbe_WithSHA1And40BitRC2_CBC,
            NID_rc2_40_cbc,
            NID_sha1,
            PKCS12_PBE_keyivgen,
            PKCS12_PBE_keyivgen_ex,
        ),
        outer(
            NID_pbes2,
            -1,
            -1,
            PKCS5_v2_PBE_keyivgen,
            PKCS5_v2_PBE_keyivgen_ex,
        ),
        outer(
            NID_pbeWithMD2AndRC2_CBC,
            NID_rc2_64_cbc,
            NID_md2,
            PKCS5_PBE_keyivgen,
            PKCS5_PBE_keyivgen_ex,
        ),
        outer(
            NID_pbeWithMD5AndRC2_CBC,
            NID_rc2_64_cbc,
            NID_md5,
            PKCS5_PBE_keyivgen,
            PKCS5_PBE_keyivgen_ex,
        ),
        outer(
            NID_pbeWithSHA1AndDES_CBC,
            NID_des_cbc,
            NID_sha1,
            PKCS5_PBE_keyivgen,
            PKCS5_PBE_keyivgen_ex,
        ),
        prf(NID_hmacWithSHA1, NID_sha1),
        prf(NID_hmac_md5, NID_md5),
        prf(NID_hmac_sha1, NID_sha1),
        prf(NID_hmacWithMD5, NID_md5),
        prf(NID_hmacWithSHA224, NID_sha224),
        prf(NID_hmacWithSHA256, NID_sha256),
        prf(NID_hmacWithSHA384, NID_sha384),
        prf(NID_hmacWithSHA512, NID_sha512),
        prf(NID_id_HMACGostR3411_94, NID_id_GostR3411_94),
        prf(
            NID_id_tc26_hmac_gost_3411_2012_256,
            NID_id_GostR3411_2012_256,
        ),
        prf(
            NID_id_tc26_hmac_gost_3411_2012_512,
            NID_id_GostR3411_2012_512,
        ),
        prf(NID_hmac_sha3_224, NID_sha3_224),
        prf(NID_hmac_sha3_256, NID_sha3_256),
        prf(NID_hmac_sha3_384, NID_sha3_384),
        prf(NID_hmac_sha3_512, NID_sha3_512),
        prf(NID_hmacWithSHA512_224, NID_sha512_224),
        prf(NID_hmacWithSHA512_256, NID_sha512_256),
        prf(NID_hmacWithSM3, NID_sm3),
        kdf(NID_id_pbkdf2, pbkdf2_keyivgen, pbkdf2_keyivgen_ex),
        kdf(
            NID_id_scrypt,
            PKCS5_v2_scrypt_keyivgen,
            PKCS5_v2_scrypt_keyivgen_ex,
        ),
    ]
};

/// `pbe_algs`: the application's additions (`EVP_PBE_alg_add_type`).
static ADDED: Mutex<Vec<Ctl>> = Mutex::new(Vec::new());

/// `EVP_PBE_find_ex`'s lookup: an addition of the type and NID (the first, once sorted), else
/// the built-in one.
fn find(pbe_type: c_int, pbe_nid: c_int) -> Option<Ctl> {
    if pbe_nid == NID_undef {
        return None;
    }
    let added = {
        let mut a = ADDED.lock().unwrap_or_else(PoisonError::into_inner);
        a.sort_by_key(|c| (c.pbe_type, c.pbe_nid));
        a.iter()
            .find(|c| c.pbe_type == pbe_type && c.pbe_nid == pbe_nid)
            .copied()
    };
    added.or_else(|| {
        BUILTIN
            .iter()
            .find(|c| c.pbe_type == pbe_type && c.pbe_nid == pbe_nid)
            .copied()
    })
}

/// Writes `v` where asked for.
///
/// # Safety
/// `p` is NULL or writable.
unsafe fn put<T>(p: *mut T, v: T) {
    if !p.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { p.write(v) };
    }
}

ffi_export! {
    /// Looks up the PBE algorithm of `type` and `pbe_nid`: its cipher's and digest's NIDs and
    /// its key and IV derivations, each where asked for. 1, or 0 for none.
    ///
    /// # Safety
    /// The out pointers are NULL or writable.
    pub unsafe extern "C" fn EVP_PBE_find_ex(type_: c_int, pbe_nid: c_int, pcnid: *mut c_int, pmnid: *mut c_int, pkeygen: *mut EVP_PBE_KEYGEN, pkeygen_ex: *mut EVP_PBE_KEYGEN_EX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let Some(c) = find(type_, pbe_nid) else { return 0 };
        // SAFETY: the caller's guarantee (here and below).
        unsafe { put(pcnid, c.cipher_nid) };
        // SAFETY: as above.
        unsafe { put(pmnid, c.md_nid) };
        // SAFETY: as above.
        unsafe { put(pkeygen, c.keygen) };
        // SAFETY: as above.
        unsafe { put(pkeygen_ex, c.keygen_ex) };
        1
    }
}

ffi_export! {
    /// `EVP_PBE_find_ex` without the library-context derivation.
    ///
    /// # Safety
    /// As for `EVP_PBE_find_ex`.
    pub unsafe extern "C" fn EVP_PBE_find(type_: c_int, pbe_nid: c_int, pcnid: *mut c_int, pmnid: *mut c_int, pkeygen: *mut EVP_PBE_KEYGEN) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_PBE_find_ex(type_, pbe_nid, pcnid, pmnid, pkeygen, ptr::null_mut()) }
    }
}

ffi_export! {
    /// Adds a PBE algorithm of `pbe_type` (overriding a built-in one of the same type and NID).
    /// 1, or 0.
    ///
    /// # Safety
    /// `keygen` is NULL or a derivation the table may call.
    pub unsafe extern "C" fn EVP_PBE_alg_add_type(pbe_type: c_int, pbe_nid: c_int, cipher_nid: c_int, md_nid: c_int, keygen: EVP_PBE_KEYGEN) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        ADDED.lock().unwrap_or_else(PoisonError::into_inner).push(Ctl { pbe_type, pbe_nid, cipher_nid, md_nid, keygen, keygen_ex: None });
        1
    }
}

ffi_export! {
    /// Adds an outer PBE algorithm `nid` with the cipher's and digest's NIDs (-1 for none).
    /// 1, or 0.
    ///
    /// # Safety
    /// `cipher` and `md` are NULL or live; `keygen` as for `EVP_PBE_alg_add_type`.
    pub unsafe extern "C" fn EVP_PBE_alg_add(nid: c_int, cipher: *const EVP_CIPHER, md: *const EVP_MD, keygen: EVP_PBE_KEYGEN) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let cipher_nid = if cipher.is_null() {
            -1
        } else {
            // SAFETY: the caller's cipher.
            unsafe { super::cipher::EVP_CIPHER_get_nid(cipher) }
        };
        let md_nid = if md.is_null() {
            -1
        } else {
            // SAFETY: the caller's digest.
            unsafe { super::digest::EVP_MD_get_type(md) }
        };
        // SAFETY: the caller's guarantee.
        unsafe { EVP_PBE_alg_add_type(EVP_PBE_TYPE_OUTER, nid, cipher_nid, md_nid, keygen) }
    }
}

ffi_export! {
    /// Removes the application's PBE algorithms.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_PBE_cleanup()
    where failure = (), library = ERR_LIB_EVP
    {
        ADDED.lock().unwrap_or_else(PoisonError::into_inner).clear();
    }
}

ffi_export! {
    /// The type and NID of the `num`th built-in PBE algorithm, each where asked for. 1, or 0
    /// past the end.
    ///
    /// # Safety
    /// The out pointers are NULL or writable.
    pub unsafe extern "C" fn EVP_PBE_get(ptype: *mut c_int, ppbe_nid: *mut c_int, num: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let Some(c) = BUILTIN.get(num) else { return 0 };
        // SAFETY: the caller's guarantee.
        unsafe { put(ptype, c.pbe_type) };
        // SAFETY: as above.
        unsafe { put(ppbe_nid, c.pbe_nid) };
        1
    }
}

/// The cipher of `nid`: fetched by its short name, else the legacy table's (`EVP_get_cipherbynid`),
/// and the fetched one to free; `None` if neither has it.
///
/// # Safety
/// `libctx` is NULL or live; `propq` is NULL or a C string.
unsafe fn cipher_of(
    libctx: *mut OSSL_LIB_CTX,
    name: *const c_char,
    propq: *const c_char,
) -> Option<(*const EVP_CIPHER, *mut EVP_CIPHER)> {
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    // SAFETY: the caller's guarantee; the name.
    let fetched = unsafe { EVP_CIPHER_fetch(libctx, name, propq) };
    let cipher = if fetched.is_null() {
        // SAFETY: as above.
        unsafe { super::legacy_cipher::EVP_get_cipherbyname(name) }
    } else {
        fetched.cast_const()
    };
    if cipher.is_null() {
        // SAFETY: no preconditions.
        unsafe { ERR_clear_last_mark() };
        return None;
    }
    // SAFETY: as above.
    unsafe { ERR_pop_to_mark() };
    Some((cipher, fetched))
}

/// The digest of `nid`, as [`cipher_of`] finds a cipher.
///
/// # Safety
/// As for [`cipher_of`].
unsafe fn md_of(
    libctx: *mut OSSL_LIB_CTX,
    nid: c_int,
    propq: *const c_char,
) -> Option<(*const EVP_MD, *mut EVP_MD)> {
    // SAFETY: a number.
    let name = unsafe { OBJ_nid2sn(nid) };
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    // SAFETY: the caller's guarantee; the name.
    let fetched = unsafe { EVP_MD_fetch(libctx, name, propq) };
    let md = if fetched.is_null() {
        // SAFETY: as above.
        unsafe { super::legacy_md::EVP_get_digestbyname(name) }
    } else {
        fetched.cast_const()
    };
    if md.is_null() {
        // SAFETY: no preconditions.
        unsafe { ERR_clear_last_mark() };
        return None;
    }
    // SAFETY: as above.
    unsafe { ERR_pop_to_mark() };
    Some((md, fetched))
}

ffi_export! {
    /// Sets the cipher context up for the PBE algorithm `pbe_obj` with its parameters and the
    /// password (`passlen` -1 for a C string, NULL for none): 1, or 0.
    ///
    /// # Safety
    /// `pbe_obj` is NULL or an object; `pass` is NULL or `passlen` octets (a C string for -1);
    /// `param` is NULL or a live `ASN1_TYPE`; `ctx` is a live context; `libctx` is NULL or live;
    /// `propq` is NULL or a C string.
    pub unsafe extern "C" fn EVP_PBE_CipherInit_ex(pbe_obj: *mut rustyssl_abi::ASN1_OBJECT, pass: *const c_char, passlen: c_int, param: *mut ASN1_TYPE, ctx: *mut EVP_CIPHER_CTX, en_de: c_int, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "EVP_PBE_CipherInit_ex";
        // SAFETY: the caller's object.
        let nid = unsafe { OBJ_obj2nid(pbe_obj) };
        let Some(c) = find(EVP_PBE_TYPE_OUTER, nid) else {
            let mut tmp = [0 as c_char; 80];
            let name = if pbe_obj.is_null() {
                "NULL".to_owned()
            } else {
                // SAFETY: room for 80; the caller's object.
                unsafe { i2t_ASN1_OBJECT(tmp.as_mut_ptr(), 80, pbe_obj) };
                // SAFETY: NUL-terminated within the buffer.
                unsafe { CStr::from_ptr(tmp.as_ptr()) }.to_string_lossy().into_owned()
            };
            err::raise_with_text(ERR_LIB_EVP, EVP_R_UNKNOWN_PBE_ALGORITHM, F, &format!("TYPE={name}"));
            return 0;
        };
        let passlen = if pass.is_null() {
            0
        } else if passlen == -1 {
            // SAFETY: the caller's C string.
            c_int::try_from(unsafe { CStr::from_ptr(pass) }.count_bytes()).unwrap_or(c_int::MAX)
        } else {
            passlen
        };
        let (mut cipher, mut cipher_fetch) = (ptr::null::<EVP_CIPHER>(), ptr::null_mut::<EVP_CIPHER>());
        let (mut md, mut md_fetch) = (ptr::null::<EVP_MD>(), ptr::null_mut::<EVP_MD>());
        let free = |cf: *mut EVP_CIPHER, mf: *mut EVP_MD| {
            // SAFETY: fetched here, or NULL.
            unsafe { EVP_CIPHER_free(cf) };
            // SAFETY: as above.
            unsafe { EVP_MD_free(mf) };
        };
        if c.cipher_nid != -1 {
            // SAFETY: a number.
            let name = unsafe { OBJ_nid2sn(c.cipher_nid) };
            // SAFETY: the caller's library context and properties.
            let Some((ci, cf)) = (unsafe { cipher_of(libctx, name, propq) }) else {
                // SAFETY: NULL or a static name.
                let text = unsafe { name.as_ref() }.map(|_| unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned()).unwrap_or_default();
                err::raise_with_text(ERR_LIB_EVP, EVP_R_UNKNOWN_CIPHER, F, &text);
                return 0;
            };
            (cipher, cipher_fetch) = (ci, cf);
        }
        if c.md_nid != -1 {
            // SAFETY: as above.
            let Some((m, mf)) = (unsafe { md_of(libctx, c.md_nid, propq) }) else {
                err::raise(ERR_LIB_EVP, EVP_R_UNKNOWN_DIGEST, F);
                free(cipher_fetch, ptr::null_mut());
                return 0;
            };
            (md, md_fetch) = (m, mf);
        }
        let ret = match (c.keygen_ex, c.keygen) {
            // SAFETY: the table's derivation with the caller's context, password, and parameters.
            (Some(kex), _) => unsafe { kex(ctx, pass, passlen, param, cipher, md, en_de, libctx, propq) },
            // SAFETY: as above.
            (None, Some(k)) => unsafe { k(ctx, pass, passlen, param, cipher, md, en_de) },
            (None, None) => 0,
        };
        free(cipher_fetch, md_fetch);
        ret
    }
}

ffi_export! {
    /// `EVP_PBE_CipherInit_ex` with the default library context.
    ///
    /// # Safety
    /// As for `EVP_PBE_CipherInit_ex`.
    pub unsafe extern "C" fn EVP_PBE_CipherInit(pbe_obj: *mut rustyssl_abi::ASN1_OBJECT, pass: *const c_char, passlen: c_int, param: *mut ASN1_TYPE, ctx: *mut EVP_CIPHER_CTX, en_de: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_PBE_CipherInit_ex(pbe_obj, pass, passlen, param, ctx, en_de, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Does nothing (the PBE algorithms are built in).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn PKCS5_PBE_add()
    where failure = (), library = ERR_LIB_EVP
    {
    }
}

ffi_export! {
    /// Does nothing (the PBE algorithms are built in).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn PKCS12_PBE_add()
    where failure = (), library = ERR_LIB_PKCS12
    {
    }
}

/// An OCTET STRING's data and length.
///
/// # Safety
/// `s` is a live `ASN1_STRING`.
unsafe fn octets(s: *const rustyssl_abi::ASN1_STRING) -> (*mut core::ffi::c_uchar, c_int) {
    // SAFETY: the caller's guarantee.
    let s = unsafe { &*s };
    (s.data, s.length)
}

/// The password's length: 0 for none, its C string's for -1.
///
/// # Safety
/// `pass` is NULL, or a C string when `passlen` is -1.
unsafe fn pass_len(pass: *const c_char, passlen: c_int) -> c_int {
    if pass.is_null() {
        0
    } else if passlen == -1 {
        // SAFETY: the caller's guarantee.
        c_int::try_from(unsafe { CStr::from_ptr(pass) }.count_bytes()).unwrap_or(c_int::MAX)
    } else {
        passlen
    }
}

ffi_export! {
    /// PKCS#5 v1 (PBES1): the key and IV from PBKDF1 over the password and the parameters'
    /// PBEParameter, set on the context with the cipher. 1, or 0.
    ///
    /// # Safety
    /// `cctx` is a live context; `pass` as for `EVP_PBE_CipherInit_ex`; `param` is NULL or a
    /// live `ASN1_TYPE`; `cipher` and `md` are live; `libctx` and `propq` as for the fetches.
    pub unsafe extern "C" fn PKCS5_PBE_keyivgen_ex(cctx: *mut EVP_CIPHER_CTX, pass: *const c_char, passlen: c_int, param: *mut ASN1_TYPE, cipher: *const EVP_CIPHER, md: *const EVP_MD, en_de: c_int, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        use crate::evp::kdf::{EVP_KDF_CTX_free, EVP_KDF_CTX_new, EVP_KDF_derive, EVP_KDF_fetch, EVP_KDF_free};
        const F: &str = "PKCS5_PBE_keyivgen_ex";
        // SAFETY: the caller's guarantee.
        let ok_param = unsafe { param.as_ref() }.is_some_and(|t| t.type_ == V_ASN1_SEQUENCE && !unsafe { t.value.sequence }.is_null());
        if !ok_param {
            err::raise(ERR_LIB_EVP, EVP_R_DECODE_ERROR, F);
            return 0;
        }
        // SAFETY: no preconditions.
        let it = unsafe { PBEPARAM_it() };
        // SAFETY: the caller's SEQUENCE.
        let pbe: *mut PBEPARAM = unsafe { ASN1_TYPE_unpack_sequence(it, param) }.cast();
        // SAFETY: decoded, or NULL.
        let Some(p) = (unsafe { pbe.as_ref() }) else {
            err::raise(ERR_LIB_EVP, EVP_R_DECODE_ERROR, F);
            return 0;
        };
        let fail = |reason: Option<c_int>| {
            if let Some(r) = reason {
                err::raise(ERR_LIB_EVP, r, F);
            }
            // SAFETY: decoded above.
            unsafe { PBEPARAM_free(pbe) };
            0
        };
        // SAFETY: the caller's cipher.
        let ivl = unsafe { EVP_CIPHER_get_iv_length(cipher) };
        if !(0..=16).contains(&ivl) {
            return fail(Some(EVP_R_INVALID_IV_LENGTH));
        }
        // SAFETY: as above.
        let kl = unsafe { EVP_CIPHER_get_key_length(cipher) };
        let md_max = c_int::try_from(EVP_MAX_MD_SIZE).unwrap_or(0);
        if !(0..=md_max).contains(&kl) {
            return fail(Some(EVP_R_INVALID_KEY_LENGTH));
        }
        let mut iter = if p.iter.is_null() {
            1
        } else {
            // SAFETY: the parameters' INTEGER.
            c_int::try_from(unsafe { ASN1_INTEGER_get(p.iter) }).unwrap_or(-1)
        };
        // SAFETY: the parameters' OCTET STRING.
        let (salt, saltlen) = unsafe { octets(p.salt) };
        // SAFETY: the caller's guarantee.
        let passlen = unsafe { pass_len(pass, passlen) };
        // SAFETY: the caller's digest.
        let mdsize = unsafe { EVP_MD_get_size(md) };
        if mdsize <= 0 {
            return fail(None);
        }
        // SAFETY: the caller's library context and properties; a static name.
        let kdf = unsafe { EVP_KDF_fetch(libctx, c"PBKDF1".as_ptr(), propq) };
        // SAFETY: the method fetched, or NULL.
        let kctx = unsafe { EVP_KDF_CTX_new(kdf) };
        // SAFETY: as above.
        unsafe { EVP_KDF_free(kdf) };
        if kctx.is_null() {
            return fail(None);
        }
        // SAFETY: the caller's digest.
        let mdname = unsafe { EVP_MD_get0_name(md) };
        let params = [
            // SAFETY: the caller's password, the parameters' salt, and locals, read during the
            // derivation.
            unsafe { OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD.as_ptr(), pass.cast_mut().cast(), usize::try_from(passlen).unwrap_or(0)) },
            // SAFETY: as above.
            unsafe { OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT.as_ptr(), salt.cast(), usize::try_from(saltlen).unwrap_or(0)) },
            // SAFETY: as above.
            unsafe { OSSL_PARAM_construct_int(OSSL_KDF_PARAM_ITER.as_ptr(), &raw mut iter) },
            // SAFETY: as above.
            unsafe { OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST.as_ptr(), mdname.cast_mut(), 0) },
            // SAFETY: no preconditions.
            unsafe { OSSL_PARAM_construct_end() },
        ];
        let mut md_tmp = Zeroizing::new([0u8; EVP_MAX_MD_SIZE as usize]);
        let mut rv = 0;
        // SAFETY: the context; room for the digest's size; the parameters above.
        if unsafe { EVP_KDF_derive(kctx, md_tmp.as_mut_ptr(), usize::try_from(mdsize).unwrap_or(0), params.as_ptr()) } == 1 {
            let mut key = Zeroizing::new([0u8; EVP_MAX_KEY_LENGTH as usize]);
            let mut iv = Zeroizing::new([0u8; EVP_MAX_IV_LENGTH as usize]);
            let (kl, ivl) = (usize::try_from(kl).unwrap_or(0), usize::try_from(ivl).unwrap_or(0));
            if let (Some(k), Some(from)) = (key.get_mut(..kl), md_tmp.get(..kl)) {
                k.copy_from_slice(from);
            }
            if let (Some(v), Some(from)) = (iv.get_mut(..ivl), md_tmp.get(16 - ivl..16)) {
                v.copy_from_slice(from);
            }
            // SAFETY: the caller's context and cipher; the key and IV.
            rv = c_int::from(unsafe { EVP_CipherInit_ex(cctx, cipher, ptr::null_mut(), key.as_ptr(), iv.as_ptr(), en_de) } != 0);
        }
        // SAFETY: made above.
        unsafe { EVP_KDF_CTX_free(kctx) };
        // SAFETY: decoded above.
        unsafe { PBEPARAM_free(pbe) };
        rv
    }
}

ffi_export! {
    /// `PKCS5_PBE_keyivgen_ex` with the default library context.
    ///
    /// # Safety
    /// As for `PKCS5_PBE_keyivgen_ex`.
    pub unsafe extern "C" fn PKCS5_PBE_keyivgen(cctx: *mut EVP_CIPHER_CTX, pass: *const c_char, passlen: c_int, param: *mut ASN1_TYPE, cipher: *const EVP_CIPHER, md: *const EVP_MD, en_de: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS5_PBE_keyivgen_ex(cctx, pass, passlen, param, cipher, md, en_de, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// PBES2: the cipher of the parameters' encryption scheme (with its parameters) set on the
    /// context, then its key from the key derivation function's. 1, or 0.
    ///
    /// # Safety
    /// As for `PKCS5_PBE_keyivgen_ex` (the cipher and digest are unused).
    pub unsafe extern "C" fn PKCS5_v2_PBE_keyivgen_ex(ctx: *mut EVP_CIPHER_CTX, pass: *const c_char, passlen: c_int, param: *mut ASN1_TYPE, _c: *const EVP_CIPHER, _md: *const EVP_MD, en_de: c_int, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "PKCS5_v2_PBE_keyivgen_ex";
        // SAFETY: no preconditions.
        let it = unsafe { PBE2PARAM_it() };
        // SAFETY: the caller's `ASN1_TYPE`, or NULL.
        let pbe2: *mut PBE2PARAM = unsafe { ASN1_TYPE_unpack_sequence(it, param) }.cast();
        // SAFETY: decoded, or NULL.
        let Some(p) = (unsafe { pbe2.as_ref() }) else {
            err::raise(ERR_LIB_EVP, EVP_R_DECODE_ERROR, F);
            return 0;
        };
        let mut cipher_fetch = ptr::null_mut();
        let mut rv = 0;
        'go: {
            // SAFETY: the decoded AlgorithmIdentifiers.
            let keyfunc = unsafe { &*p.keyfunc };
            // SAFETY: as above.
            let encryption = unsafe { &*p.encryption };
            // SAFETY: the key derivation's object.
            let nid = unsafe { OBJ_obj2nid(keyfunc.algorithm) };
            let Some(Ctl { keygen_ex: Some(kdf), .. }) = find(EVP_PBE_TYPE_KDF, nid) else {
                err::raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION, F);
                break 'go;
            };
            let mut ciph_name = [0 as c_char; 80];
            // SAFETY: room for 80; the encryption scheme's object.
            if unsafe { OBJ_obj2txt(ciph_name.as_mut_ptr(), 80, encryption.algorithm, 0) } <= 0 {
                err::raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_CIPHER, F);
                break 'go;
            }
            // SAFETY: the caller's library context and properties; the name.
            let Some((cipher, cf)) = (unsafe { cipher_of(libctx, ciph_name.as_ptr(), propq) }) else {
                err::raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_CIPHER, F);
                break 'go;
            };
            cipher_fetch = cf;
            // SAFETY: the caller's context; the cipher.
            if unsafe { EVP_CipherInit_ex(ctx, cipher, ptr::null_mut(), ptr::null(), ptr::null(), en_de) } == 0 {
                break 'go;
            }
            // SAFETY: the context; the scheme's parameters.
            if unsafe { super::cipher_asn1::EVP_CIPHER_asn1_to_param(ctx, encryption.parameter) } <= 0 {
                err::raise(ERR_LIB_EVP, EVP_R_CIPHER_PARAMETER_ERROR, F);
                break 'go;
            }
            // SAFETY: the key derivation with the caller's password and its parameters.
            rv = unsafe { kdf(ctx, pass, passlen, keyfunc.parameter, ptr::null(), ptr::null(), en_de, libctx, propq) };
        }
        // SAFETY: fetched above, or NULL.
        unsafe { EVP_CIPHER_free(cipher_fetch) };
        // SAFETY: decoded above.
        unsafe { PBE2PARAM_free(pbe2) };
        rv
    }
}

ffi_export! {
    /// `PKCS5_v2_PBE_keyivgen_ex` with the default library context.
    ///
    /// # Safety
    /// As for `PKCS5_v2_PBE_keyivgen_ex`.
    pub unsafe extern "C" fn PKCS5_v2_PBE_keyivgen(ctx: *mut EVP_CIPHER_CTX, pass: *const c_char, passlen: c_int, param: *mut ASN1_TYPE, c: *const EVP_CIPHER, md: *const EVP_MD, en_de: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS5_v2_PBE_keyivgen_ex(ctx, pass, passlen, param, c, md, en_de, ptr::null_mut(), ptr::null()) }
    }
}

ffi_callback! {
    /// `PKCS5_v2_PBKDF2_keyivgen_ex`: the context's key from PBKDF2 over the password and the
    /// PBKDF2-params (its key length checked, its PRF's digest fetched). 1, or 0.
    ///
    /// # Safety
    /// As for `PKCS5_PBE_keyivgen_ex`, with the cipher set on the context.
    pub(crate) unsafe extern "C" fn pbkdf2_keyivgen_ex(ctx: *mut EVP_CIPHER_CTX, pass: *const c_char, passlen: c_int, param: *mut ASN1_TYPE, _c: *const EVP_CIPHER, _md: *const EVP_MD, en_de: c_int, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "PKCS5_v2_PBKDF2_keyivgen_ex";
        // SAFETY: the caller's context.
        if unsafe { EVP_CIPHER_CTX_get0_cipher(ctx) }.is_null() {
            err::raise(ERR_LIB_EVP, EVP_R_NO_CIPHER_SET, F);
            return 0;
        }
        // SAFETY: no preconditions.
        let it = unsafe { PBKDF2PARAM_it() };
        // SAFETY: the caller's `ASN1_TYPE`, or NULL.
        let kdfp: *mut PBKDF2PARAM = unsafe { ASN1_TYPE_unpack_sequence(it, param) }.cast();
        // SAFETY: decoded, or NULL.
        let Some(k) = (unsafe { kdfp.as_ref() }) else {
            err::raise(ERR_LIB_EVP, EVP_R_DECODE_ERROR, F);
            return 0;
        };
        let mut key = Zeroizing::new([0u8; EVP_MAX_KEY_LENGTH as usize]);
        let mut prfmd_fetch = ptr::null_mut();
        let mut rv = 0;
        'go: {
            // SAFETY: the caller's context.
            let t = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) };
            let Some(keylen) = usize::try_from(t).ok().filter(|&l| l <= key.len()) else {
                err::raise(ERR_LIB_EVP, EVP_R_INVALID_KEY_LENGTH, F);
                break 'go;
            };
            // SAFETY: the parameters' INTEGER.
            if !k.keylength.is_null() && unsafe { ASN1_INTEGER_get(k.keylength) } != i64::from(t) {
                err::raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_KEYLENGTH, F);
                break 'go;
            }
            let prf_nid = if k.prf.is_null() {
                rustyssl_abi::NID_hmacWithSHA1
            } else {
                // SAFETY: the parameters' AlgorithmIdentifier.
                let alg = unsafe { (*k.prf).algorithm };
                // SAFETY: its object.
                unsafe { OBJ_obj2nid(alg) }
            };
            let Some(Ctl { md_nid, .. }) = find(EVP_PBE_TYPE_PRF, prf_nid) else {
                err::raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_PRF, F);
                break 'go;
            };
            // SAFETY: the caller's library context and properties.
            let Some((prfmd, pf)) = (unsafe { md_of(libctx, md_nid, propq) }) else {
                err::raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_PRF, F);
                break 'go;
            };
            prfmd_fetch = pf;
            // SAFETY: the parameters' salt, an `ASN1_TYPE`.
            let salt_t = unsafe { &*k.salt };
            if salt_t.type_ != V_ASN1_OCTET_STRING {
                err::raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_SALT_TYPE, F);
                break 'go;
            }
            // SAFETY: a union read of the type's member, an OCTET STRING.
            let os = unsafe { salt_t.value.octet_string };
            // SAFETY: its OCTET STRING.
            let (salt, saltlen) = unsafe { octets(os) };
            // SAFETY: the parameters' INTEGER.
            let iter = c_int::try_from(unsafe { ASN1_INTEGER_get(k.iter) }).unwrap_or(-1);
            // SAFETY: the password; the salt; room for the key's length.
            if unsafe { super::kdf::pbkdf2_hmac_ex(pass, passlen, salt, saltlen, iter, prfmd, t, key.as_mut_ptr(), libctx, propq) } == 0 {
                break 'go;
            }
            let _ = keylen;
            // SAFETY: the caller's context; the key.
            rv = unsafe { EVP_CipherInit_ex(ctx, ptr::null(), ptr::null_mut(), key.as_ptr(), ptr::null(), en_de) };
        }
        // SAFETY: decoded above.
        unsafe { PBKDF2PARAM_free(kdfp) };
        // SAFETY: fetched above, or NULL.
        unsafe { EVP_MD_free(prfmd_fetch) };
        rv
    }
}

ffi_callback! {
    /// `PKCS5_v2_PBKDF2_keyivgen`: `pbkdf2_keyivgen_ex` with the default library context.
    ///
    /// # Safety
    /// As for `pbkdf2_keyivgen_ex`.
    pub(crate) unsafe extern "C" fn pbkdf2_keyivgen(ctx: *mut EVP_CIPHER_CTX, pass: *const c_char, passlen: c_int, param: *mut ASN1_TYPE, c: *const EVP_CIPHER, md: *const EVP_MD, en_de: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { pbkdf2_keyivgen_ex(ctx, pass, passlen, param, c, md, en_de, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// The context's key from scrypt over the password and the scrypt-params (its key length
    /// checked, its N, r, and p validated). 1, or 0.
    ///
    /// # Safety
    /// As for `PKCS5_PBE_keyivgen_ex`, with the cipher set on the context.
    pub unsafe extern "C" fn PKCS5_v2_scrypt_keyivgen_ex(ctx: *mut EVP_CIPHER_CTX, pass: *const c_char, passlen: c_int, param: *mut ASN1_TYPE, _c: *const EVP_CIPHER, _md: *const EVP_MD, en_de: c_int, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        use crate::evp::kdf::EVP_PBE_scrypt_ex;
        const F: &str = "PKCS5_v2_scrypt_keyivgen_ex";
        // SAFETY: the caller's context.
        if unsafe { EVP_CIPHER_CTX_get0_cipher(ctx) }.is_null() {
            err::raise(ERR_LIB_EVP, EVP_R_NO_CIPHER_SET, F);
            return 0;
        }
        // SAFETY: no preconditions.
        let it = unsafe { SCRYPT_PARAMS_it() };
        // SAFETY: the caller's `ASN1_TYPE`, or NULL.
        let sparam: *mut SCRYPT_PARAMS = unsafe { ASN1_TYPE_unpack_sequence(it, param) }.cast();
        // SAFETY: decoded, or NULL.
        let Some(s) = (unsafe { sparam.as_ref() }) else {
            err::raise(ERR_LIB_EVP, EVP_R_DECODE_ERROR, F);
            return 0;
        };
        let mut key = Zeroizing::new([0u8; EVP_MAX_KEY_LENGTH as usize]);
        let mut rv = 0;
        'go: {
            // SAFETY: the caller's context.
            let t = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) };
            let Some(keylen) = usize::try_from(t).ok().filter(|&l| l <= key.len()) else {
                err::raise(ERR_LIB_EVP, EVP_R_INVALID_KEY_LENGTH, F);
                break 'go;
            };
            if !s.keyLength.is_null() {
                let mut spkeylen = 0u64;
                // SAFETY: the parameters' INTEGER; a local.
                let got = unsafe { ASN1_INTEGER_get_uint64(&raw mut spkeylen, s.keyLength) } != 0;
                if !got || u64::try_from(keylen).ok() != Some(spkeylen) {
                    err::raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_KEYLENGTH, F);
                    break 'go;
                }
            }
            let (mut n, mut r, mut p) = (0u64, 0u64, 0u64);
            // SAFETY: the parameters' INTEGERs; locals.
            let read = unsafe { ASN1_INTEGER_get_uint64(&raw mut n, s.costParameter) } != 0
                // SAFETY: as above.
                && unsafe { ASN1_INTEGER_get_uint64(&raw mut r, s.blockSize) } != 0
                // SAFETY: as above.
                && unsafe { ASN1_INTEGER_get_uint64(&raw mut p, s.parallelizationParameter) } != 0;
            // SAFETY: a validation only (no password or output).
            if !read || unsafe { EVP_PBE_scrypt_ex(ptr::null(), 0, ptr::null(), 0, n, r, p, 0, ptr::null_mut(), 0, libctx, propq) } == 0 {
                err::raise(ERR_LIB_EVP, EVP_R_ILLEGAL_SCRYPT_PARAMETERS, F);
                break 'go;
            }
            // SAFETY: the parameters' OCTET STRING.
            let (salt, saltlen) = unsafe { octets(s.salt) };
            let plen = usize::try_from(passlen).unwrap_or(0);
            // SAFETY: the password; the salt; room for the key's length.
            if unsafe { EVP_PBE_scrypt_ex(pass, plen, salt, usize::try_from(saltlen).unwrap_or(0), n, r, p, 0, key.as_mut_ptr(), keylen, libctx, propq) } == 0 {
                break 'go;
            }
            // SAFETY: the caller's context; the key.
            rv = unsafe { EVP_CipherInit_ex(ctx, ptr::null(), ptr::null_mut(), key.as_ptr(), ptr::null(), en_de) };
        }
        // SAFETY: decoded above.
        unsafe { SCRYPT_PARAMS_free(sparam) };
        rv
    }
}

ffi_export! {
    /// `PKCS5_v2_scrypt_keyivgen_ex` with the default library context.
    ///
    /// # Safety
    /// As for `PKCS5_v2_scrypt_keyivgen_ex`.
    pub unsafe extern "C" fn PKCS5_v2_scrypt_keyivgen(ctx: *mut EVP_CIPHER_CTX, pass: *const c_char, passlen: c_int, param: *mut ASN1_TYPE, c: *const EVP_CIPHER, md: *const EVP_MD, en_de: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS5_v2_scrypt_keyivgen_ex(ctx, pass, passlen, param, c, md, en_de, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// PKCS#12's PBE: the key and IV from PKCS12KDF over the password (as UTF-8) and the
    /// parameters' PBEParameter, set on the context with the cipher. 1, or 0.
    ///
    /// # Safety
    /// As for `PKCS5_PBE_keyivgen_ex`.
    pub unsafe extern "C" fn PKCS12_PBE_keyivgen_ex(ctx: *mut EVP_CIPHER_CTX, pass: *const c_char, passlen: c_int, param: *mut ASN1_TYPE, cipher: *const EVP_CIPHER, md: *const EVP_MD, en_de: c_int, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        use crate::pkcs12::PKCS12_key_gen_utf8_ex;
        const F: &str = "PKCS12_PBE_keyivgen_ex";
        if cipher.is_null() {
            return 0;
        }
        // SAFETY: no preconditions.
        let it = unsafe { PBEPARAM_it() };
        // SAFETY: the caller's `ASN1_TYPE`, or NULL.
        let pbe: *mut PBEPARAM = unsafe { ASN1_TYPE_unpack_sequence(it, param) }.cast();
        // SAFETY: decoded, or NULL.
        let Some(p) = (unsafe { pbe.as_ref() }) else {
            err::raise(ERR_LIB_PKCS12, PKCS12_R_DECODE_ERROR, F);
            return 0;
        };
        let iter = if p.iter.is_null() {
            1
        } else {
            // SAFETY: the parameters' INTEGER.
            c_int::try_from(unsafe { ASN1_INTEGER_get(p.iter) }).unwrap_or(-1)
        };
        // SAFETY: the parameters' OCTET STRING.
        let (salt, saltlen) = unsafe { octets(p.salt) };
        let mut key = Zeroizing::new([0u8; EVP_MAX_KEY_LENGTH as usize]);
        let mut iv = Zeroizing::new([0u8; EVP_MAX_IV_LENGTH as usize]);
        // SAFETY: the caller's cipher.
        let kl = unsafe { EVP_CIPHER_get_key_length(cipher) };
        // SAFETY: as above.
        let ivl = unsafe { EVP_CIPHER_get_iv_length(cipher) };
        // SAFETY: the password; the salt; room for the key; the caller's digest.
        if unsafe { PKCS12_key_gen_utf8_ex(pass, passlen, salt, saltlen, PKCS12_KEY_ID, iter, kl, key.as_mut_ptr(), md, libctx, propq) } == 0 {
            err::raise(ERR_LIB_PKCS12, PKCS12_R_KEY_GEN_ERROR, F);
            // SAFETY: decoded above.
            unsafe { PBEPARAM_free(pbe) };
            return 0;
        }
        let mut piv = iv.as_ptr();
        if ivl > 0 {
            // SAFETY: as above, for the IV.
            if unsafe { PKCS12_key_gen_utf8_ex(pass, passlen, salt, saltlen, PKCS12_IV_ID, iter, ivl, iv.as_mut_ptr(), md, libctx, propq) } == 0 {
                err::raise(ERR_LIB_PKCS12, PKCS12_R_IV_GEN_ERROR, F);
                // SAFETY: decoded above.
                unsafe { PBEPARAM_free(pbe) };
                return 0;
            }
        } else {
            piv = ptr::null();
        }
        // SAFETY: decoded above.
        unsafe { PBEPARAM_free(pbe) };
        // SAFETY: the caller's context and cipher; the key and IV.
        unsafe { EVP_CipherInit_ex(ctx, cipher, ptr::null_mut(), key.as_ptr(), piv, en_de) }
    }
}

ffi_export! {
    /// `PKCS12_PBE_keyivgen_ex` with the default library context.
    ///
    /// # Safety
    /// As for `PKCS12_PBE_keyivgen_ex`.
    pub unsafe extern "C" fn PKCS12_PBE_keyivgen(ctx: *mut EVP_CIPHER_CTX, pass: *const c_char, passlen: c_int, param: *mut ASN1_TYPE, cipher: *const EVP_CIPHER, md: *const EVP_MD, en_de: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS12_PBE_keyivgen_ex(ctx, pass, passlen, param, cipher, md, en_de, ptr::null_mut(), ptr::null()) }
    }
}
