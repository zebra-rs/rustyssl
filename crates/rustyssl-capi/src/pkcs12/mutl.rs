//! The PFX's integrity MAC (`p12_mutl.c`): HMAC with a PKCS#12-derived key (and GOST's
//! PBKDF2 one), and PBMAC1 (RFC 9879) with PBKDF2, the key length checked as RFC 9879
//! requires. The MAC is compared in constant time.

use core::ffi::{c_char, c_int, c_uchar, c_uint};
use core::ptr;

use rustyssl_abi::{
    ASN1_INTEGER, ASN1_OCTET_STRING, ERR_LIB_PKCS12, ERR_R_ASN1_LIB, ERR_R_FETCH_FAILED,
    ERR_R_INTERNAL_ERROR, ERR_R_PASSED_INVALID_ARGUMENT, ERR_R_RAND_LIB, ERR_R_UNSUPPORTED,
    EVP_MAX_MD_SIZE, EVP_MD, NID_hmac_sha3_224, NID_hmac_sha3_256, NID_hmac_sha3_384,
    NID_hmac_sha3_512, NID_hmacWithMD5, NID_hmacWithSHA1, NID_hmacWithSHA224, NID_hmacWithSHA256,
    NID_hmacWithSHA384, NID_hmacWithSHA512, NID_hmacWithSHA512_224, NID_hmacWithSHA512_256,
    NID_id_GostR3411_94, NID_id_GostR3411_2012_256, NID_id_GostR3411_2012_512,
    NID_id_HMACGostR3411_94, NID_id_pbkdf2, NID_id_tc26_hmac_gost_3411_2012_256,
    NID_id_tc26_hmac_gost_3411_2012_512, NID_md5, NID_pbmac1, NID_pkcs7_data, NID_sha1,
    NID_sha3_224, NID_sha3_256, NID_sha3_384, NID_sha3_512, NID_sha224, NID_sha256, NID_sha384,
    NID_sha512, NID_sha512_224, NID_sha512_256, NID_undef, PBKDF2PARAM, PBMAC1PARAM, PKCS12,
    PKCS12_DEFAULT_ITER, PKCS12_ERROR, PKCS12_MAC_ID, PKCS12_R_CONTENT_TYPE_NOT_DATA,
    PKCS12_R_DECODE_ERROR, PKCS12_R_KEY_GEN_ERROR, PKCS12_R_MAC_ABSENT,
    PKCS12_R_MAC_GENERATION_ERROR, PKCS12_R_MAC_SETUP_ERROR, PKCS12_R_MAC_STRING_SET_ERROR,
    PKCS12_R_PARSE_ERROR, PKCS12_R_UNKNOWN_DIGEST_ALGORITHM, PKCS12_SALT_LEN, V_ASN1_NULL,
    V_ASN1_OCTET_STRING, X509_ALGOR,
};
use subtle::ConstantTimeEq;

use super::asn::{MacData, PKCS12_MAC_DATA_free, PKCS12_MAC_DATA_new, pfx_of};
use crate::asn1::integer::{ASN1_INTEGER_get, ASN1_INTEGER_set};
use crate::asn1::string::{ASN1_INTEGER_new, ASN1_OCTET_STRING_set};
use crate::asn1::tpl::items::{X509_ALGOR_free, X509_ALGOR_new};
use crate::asn1::tpl::util::{ASN1_TYPE_pack_sequence, ASN1_TYPE_unpack_sequence};
use crate::err::{self, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free, EVP_MD_get_size, EVP_MD_get_type};
use crate::evp::kdf::PKCS5_PBKDF2_HMAC;
use crate::evp::legacy_md::{EVP_get_digestbyname, EVP_sha256};
use crate::ffi::ffi_export;
use crate::hmac::{HMAC_CTX_free, HMAC_CTX_new, HMAC_Final, HMAC_Init_ex, HMAC_Update};
use crate::mem;
use crate::objects::{OBJ_nid2obj, OBJ_nid2sn, OBJ_obj2nid, OBJ_obj2txt, OBJ_txt2nid};
use crate::rand_lib::RAND_bytes_ex;
use crate::x509::algor::{X509_ALGOR_get0, X509_ALGOR_set0};
use crate::x509::pbe::{
    PBKDF2PARAM_free, PBKDF2PARAM_it, PBMAC1PARAM_free, PBMAC1PARAM_it, PBMAC1PARAM_new,
    PKCS5_pbkdf2_set,
};
use crate::x509::sig::{X509_SIG_get0, X509_SIG_getm};

fn raise(reason: c_int, f: &str) {
    err::raise(ERR_LIB_PKCS12, reason, f);
}

/// The size of GOST's MAC key (TK26).
const TK26_MAC_KEY_LEN: usize = 32;

/// `ossl_hmacmd_pairs`: the digests and their HMACs' NIDs.
const HMAC_MD: [(c_int, c_int); 15] = [
    (NID_sha1, NID_hmacWithSHA1),
    (NID_md5, NID_hmacWithMD5),
    (NID_sha224, NID_hmacWithSHA224),
    (NID_sha256, NID_hmacWithSHA256),
    (NID_sha384, NID_hmacWithSHA384),
    (NID_sha512, NID_hmacWithSHA512),
    (NID_id_GostR3411_94, NID_id_HMACGostR3411_94),
    (
        NID_id_GostR3411_2012_256,
        NID_id_tc26_hmac_gost_3411_2012_256,
    ),
    (
        NID_id_GostR3411_2012_512,
        NID_id_tc26_hmac_gost_3411_2012_512,
    ),
    (NID_sha3_224, NID_hmac_sha3_224),
    (NID_sha3_256, NID_hmac_sha3_256),
    (NID_sha3_384, NID_hmac_sha3_384),
    (NID_sha3_512, NID_hmac_sha3_512),
    (NID_sha512_224, NID_hmacWithSHA512_224),
    (NID_sha512_256, NID_hmacWithSHA512_256),
];

/// `ossl_hmac2mdnid`.
fn hmac2md(hmac_nid: c_int) -> c_int {
    HMAC_MD
        .iter()
        .find(|p| p.1 == hmac_nid)
        .map_or(NID_undef, |p| p.0)
}

/// `ossl_md2hmacnid`.
fn md2hmac(md_nid: c_int) -> c_int {
    HMAC_MD
        .iter()
        .find(|p| p.0 == md_nid)
        .map_or(NID_undef, |p| p.1)
}

/// The PFX's MAC data.
fn mac_of<'a>(p12: *const PKCS12) -> Option<&'a mut MacData> {
    // SAFETY: NULL or a live PFX; its MAC, NULL or live.
    unsafe { pfx_of(p12) }.and_then(|p| unsafe { p.mac.as_mut() })
}

/// The MAC's algorithm.
fn mac_alg(m: &MacData) -> *const X509_ALGOR {
    let mut alg: *const X509_ALGOR = ptr::null();
    // SAFETY: its DigestInfo, made with it; room for the algorithm.
    unsafe { X509_SIG_get0(m.dinfo, &mut alg, ptr::null_mut()) };
    alg
}

/// An AlgorithmIdentifier's object.
fn alg_obj(alg: *const X509_ALGOR) -> *const rustyssl_abi::ASN1_OBJECT {
    let mut o: *const rustyssl_abi::ASN1_OBJECT = ptr::null();
    if !alg.is_null() {
        // SAFETY: room for the object; the AlgorithmIdentifier, live.
        unsafe { X509_ALGOR_get0(&mut o, ptr::null_mut(), ptr::null_mut(), alg) };
    }
    o
}

ffi_export! {
    /// Whether the PFX has a MAC.
    ///
    /// # Safety
    /// `p12` is NULL or a live PFX.
    pub unsafe extern "C" fn PKCS12_mac_present(p12: *const PKCS12) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        c_int::from(mac_of(p12).is_some())
    }
}

ffi_export! {
    /// The PFX's MAC, its algorithm, salt, and iteration count (all NULL without a MAC).
    ///
    /// # Safety
    /// The pointers are NULL or room for a pointer; `p12` NULL or a live PFX.
    pub unsafe extern "C" fn PKCS12_get0_mac(pmac: *mut *const ASN1_OCTET_STRING, pmacalg: *mut *const X509_ALGOR, psalt: *mut *const ASN1_OCTET_STRING, piter: *mut *const ASN1_INTEGER, p12: *const PKCS12)
    where failure = (), library = ERR_LIB_PKCS12
    {
        if let Some(m) = mac_of(p12) {
            // SAFETY: its DigestInfo; the caller's room.
            unsafe { X509_SIG_get0(m.dinfo, pmacalg, pmac) };
            // SAFETY: the caller's room, or NULL.
            if let Some(p) = unsafe { psalt.as_mut() } {
                *p = m.salt;
            }
            // SAFETY: as above.
            if let Some(p) = unsafe { piter.as_mut() } {
                *p = m.iter;
            }
            return;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { pmac.as_mut() } {
            *p = ptr::null();
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { pmacalg.as_mut() } {
            *p = ptr::null();
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { psalt.as_mut() } {
            *p = ptr::null();
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { piter.as_mut() } {
            *p = ptr::null();
        }
    }
}

/// `pkcs12_gen_gost_mac_key`: the last 32 octets of a 96-octet PBKDF2.
///
/// # Safety
/// `pass` holds `passlen` octets; `digest` is live.
unsafe fn gost_mac_key(
    pass: *const c_char,
    passlen: c_int,
    salt: &[u8],
    iter: c_int,
    key: &mut [u8],
    digest: *const EVP_MD,
) -> bool {
    let Some(k) = key.get_mut(..TK26_MAC_KEY_LEN) else {
        return false;
    };
    let mut out = rustyssl_crypto::bn::Zeroizing::new([0u8; 96]);
    let Ok(saltlen) = c_int::try_from(salt.len()) else {
        return false;
    };
    // SAFETY: the caller's password and digest; the salt; room for the key.
    if unsafe {
        PKCS5_PBKDF2_HMAC(
            pass,
            passlen,
            salt.as_ptr(),
            saltlen,
            iter,
            digest,
            96,
            out.as_mut_ptr(),
        )
    } == 0
    {
        return false;
    }
    let Some(tail) = out.get(96 - TK26_MAC_KEY_LEN..) else {
        return false;
    };
    k.copy_from_slice(tail);
    true
}

/// `PBMAC1_get1_pbkdf2_param`: PBMAC1's PBKDF2 parameters, or NULL.
///
/// # Safety
/// `macalg` is a live AlgorithmIdentifier.
unsafe fn pbmac1_pbkdf2_param(macalg: *const X509_ALGOR) -> *mut PBKDF2PARAM {
    const F: &str = "PBMAC1_get1_pbkdf2_param";
    // SAFETY: no preconditions.
    let it = unsafe { PBMAC1PARAM_it() };
    // SAFETY: the caller's AlgorithmIdentifier.
    let parameter = unsafe { (*macalg).parameter };
    // SAFETY: its parameter, NULL or live.
    let param = unsafe { ASN1_TYPE_unpack_sequence(it, parameter) }.cast::<PBMAC1PARAM>();
    // SAFETY: the parameters, or NULL.
    let Some(p) = (unsafe { param.as_ref() }) else {
        raise(ERR_R_PASSED_INVALID_ARGUMENT, F);
        return ptr::null_mut();
    };
    // SAFETY: its KDF's object.
    if unsafe { OBJ_obj2nid(alg_obj(p.keyDerivationFunc)) } != NID_id_pbkdf2 {
        raise(ERR_R_PASSED_INVALID_ARGUMENT, F);
        // SAFETY: the parameters decoded here.
        unsafe { PBMAC1PARAM_free(param) };
        return ptr::null_mut();
    }
    // SAFETY: no preconditions.
    let kit = unsafe { PBKDF2PARAM_it() };
    // SAFETY: the KDF's parameter, NULL or live.
    let kp = unsafe { p.keyDerivationFunc.as_ref() }.map_or(ptr::null_mut(), |k| unsafe {
        ASN1_TYPE_unpack_sequence(kit, k.parameter)
    });
    // SAFETY: as above.
    unsafe { PBMAC1PARAM_free(param) };
    kp.cast()
}

/// `PBMAC1_PBKDF2_HMAC`: PBMAC1's key from the password by PBKDF2, of the length it gives
/// (20 to 64 octets), or -1.
///
/// # Safety
/// `pass` holds `passlen` octets; `macalg` is live; `ctx` NULL or live; `propq` NULL or a C
/// string.
unsafe fn pbmac1_key(
    ctx: *mut rustyssl_abi::OSSL_LIB_CTX,
    propq: *const c_char,
    pass: *const c_char,
    passlen: c_int,
    macalg: *const X509_ALGOR,
    key: &mut [u8; EVP_MAX_MD_SIZE as usize],
) -> c_int {
    const F: &str = "PBMAC1_PBKDF2_HMAC";
    // SAFETY: the caller's guarantee.
    let param = unsafe { pbmac1_pbkdf2_param(macalg) };
    let mut kdf_md: *mut EVP_MD = ptr::null_mut();
    let ret = 'err: {
        // SAFETY: the parameters, or NULL.
        let Some(p) = (unsafe { param.as_ref() }) else {
            raise(ERR_R_UNSUPPORTED, F);
            break 'err -1;
        };
        let kdf_hmac_nid = if p.prf.is_null() {
            NID_hmacWithSHA1
        } else {
            // SAFETY: its PRF's object.
            unsafe { OBJ_obj2nid(alg_obj(p.prf)) }
        };
        // SAFETY: any NID.
        let sn = unsafe { OBJ_nid2sn(hmac2md(kdf_hmac_nid)) };
        // SAFETY: the name, or NULL; the caller's context and properties.
        kdf_md = unsafe { EVP_MD_fetch(ctx, sn, propq) };
        if kdf_md.is_null() {
            raise(ERR_R_FETCH_FAILED, F);
            break 'err -1;
        }
        // The salt must be the OCTET STRING choice.
        // SAFETY: its salt, NULL or live.
        let Some(salt) = (unsafe { p.salt.as_ref() }).filter(|s| s.type_ == V_ASN1_OCTET_STRING)
        else {
            raise(PKCS12_R_PARSE_ERROR, F);
            break 'err -1;
        };
        // SAFETY: the OCTET STRING's value.
        let os = unsafe { salt.value.octet_string };
        // SAFETY: the parameters' string, NULL or live.
        let salt = unsafe { super::asn::octets(os) };
        // RFC 9879: a missing or too short key length is invalid.
        let keylen = if p.keylength.is_null() {
            0
        } else {
            // SAFETY: its INTEGER.
            c_int::try_from(unsafe { ASN1_INTEGER_get(p.keylength) }).unwrap_or(0)
        };
        if !(20..=EVP_MAX_MD_SIZE as c_int).contains(&keylen) {
            err::raise_with_text(
                ERR_LIB_PKCS12,
                PKCS12_R_PARSE_ERROR,
                F,
                &format!("Invalid Key length ({keylen} is not in the range 20..64)"),
            );
            break 'err -1;
        }
        // SAFETY: its iteration count.
        let iter = c_int::try_from(unsafe { ASN1_INTEGER_get(p.iter) }).unwrap_or(0);
        let Ok(saltlen) = c_int::try_from(salt.len()) else {
            break 'err -1;
        };
        // SAFETY: the password; the salt; the digest; room for `keylen` octets.
        if unsafe {
            PKCS5_PBKDF2_HMAC(
                pass,
                passlen,
                salt.as_ptr(),
                saltlen,
                iter,
                kdf_md,
                keylen,
                key.as_mut_ptr(),
            )
        } <= 0
        {
            raise(ERR_R_INTERNAL_ERROR, F);
            break 'err -1;
        }
        keylen
    };
    // SAFETY: the digest fetched here, or NULL.
    unsafe { EVP_MD_free(kdf_md) };
    // SAFETY: the parameters decoded here, or NULL.
    unsafe { PBKDF2PARAM_free(param) };
    ret
}

/// How the MAC key is derived.
#[derive(Clone, Copy)]
enum KeyGen {
    /// PKCS#12's KDF (or GOST's PBKDF2), or for PBMAC1 its parameters.
    Default,
    /// PBMAC1 being set up: PBKDF2 with the PRF's digest.
    Pbkdf2,
}

/// `pkcs12_gen_mac`: the HMAC of the authenticated safe's data with the password's key,
/// into `mac`.
///
/// # Safety
/// `p12` is a live PFX with a MAC; `pass` holds `passlen` octets (a C string if -1).
#[expect(clippy::too_many_arguments, reason = "OpenSSL's function's arguments")]
unsafe fn gen_mac(
    p12: *mut PKCS12,
    pass: *const c_char,
    passlen: c_int,
    mac: &mut [u8; EVP_MAX_MD_SIZE as usize],
    maclen: &mut c_uint,
    pbmac1_md_nid: c_int,
    pbmac1_kdf_nid: c_int,
    keygen: KeyGen,
) -> bool {
    const F: &str = "pkcs12_gen_mac";
    // SAFETY: the caller's guarantee; its authenticated safe.
    let Some(a) = (unsafe { pfx_of(p12) }).and_then(|p| unsafe { p.authsafes.as_ref() }) else {
        return false;
    };
    // SAFETY: its object, or NULL.
    if unsafe { OBJ_obj2nid(a.type_) } != NID_pkcs7_data {
        raise(PKCS12_R_CONTENT_TYPE_NOT_DATA, F);
        return false;
    }
    // SAFETY: the content of its type.
    let data = unsafe { a.d.data };
    if data.is_null() {
        raise(PKCS12_R_DECODE_ERROR, F);
        return false;
    }
    let Some(m) = mac_of(p12) else { return false };
    // SAFETY: the MAC's salt, made with it.
    let salt = unsafe { super::asn::octets(m.salt) };
    let iter = if m.iter.is_null() {
        1
    } else {
        // SAFETY: its INTEGER.
        c_int::try_from(unsafe { ASN1_INTEGER_get(m.iter) }).unwrap_or(0)
    };
    let macalg = mac_alg(m);
    let macoid = alg_obj(macalg);
    let mut md_name = [0 as c_char; 80];
    // SAFETY: the object: PBMAC1's digest, or the MAC's own.
    let name_obj = if unsafe { OBJ_obj2nid(macoid) } == NID_pbmac1 {
        // SAFETY: any NID.
        unsafe { OBJ_nid2obj(pbmac1_md_nid) }
    } else {
        macoid
    };
    // SAFETY: room for the name; the object.
    if unsafe { OBJ_obj2txt(md_name.as_mut_ptr(), 80, name_obj, 0) } < 0 {
        return false;
    }
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    // SAFETY: the name; the safe's context and properties.
    let md_fetch = unsafe { EVP_MD_fetch(a.ctx.libctx, md_name.as_ptr(), a.ctx.propq) };
    let md: *const EVP_MD = if md_fetch.is_null() {
        // SAFETY: the object.
        let nid = unsafe { OBJ_obj2nid(macoid) };
        // SAFETY: any NID.
        let sn = unsafe { OBJ_nid2sn(nid) };
        // SAFETY: NULL or a static name.
        unsafe { EVP_get_digestbyname(sn) }
    } else {
        md_fetch
    };
    if md.is_null() {
        // SAFETY: no preconditions.
        unsafe { ERR_clear_last_mark() };
        raise(PKCS12_R_UNKNOWN_DIGEST_ALGORITHM, F);
        return false;
    }
    // SAFETY: no preconditions.
    unsafe { ERR_pop_to_mark() };
    let mut key = rustyssl_crypto::bn::Zeroizing::new([0u8; EVP_MAX_MD_SIZE as usize]);
    let mut hmac = ptr::null_mut();
    let ok = 'err: {
        // SAFETY: a live digest.
        let mut keylen = unsafe { EVP_MD_get_size(md) };
        // SAFETY: as above.
        let md_nid = unsafe { EVP_MD_get_type(md) };
        if keylen <= 0 {
            break 'err false;
        }
        let Ok(saltlen) = c_int::try_from(salt.len()) else {
            break 'err false;
        };
        if pbmac1_md_nid != NID_undef && matches!(keygen, KeyGen::Default) {
            // PBMAC1 when verifying: the key from its parameters.
            // SAFETY: the safe's context; the password; the MAC's algorithm.
            keylen =
                unsafe { pbmac1_key(a.ctx.libctx, a.ctx.propq, pass, passlen, macalg, &mut key) };
            if keylen < 0 {
                break 'err false;
            }
        } else if [
            NID_id_GostR3411_94,
            NID_id_GostR3411_2012_256,
            NID_id_GostR3411_2012_512,
        ]
        .contains(&md_nid)
            && crate::init::safe_getenv(c"LEGACY_GOST_PKCS12").is_none()
        {
            keylen = c_int::try_from(TK26_MAC_KEY_LEN).unwrap_or(0);
            // SAFETY: the password; the digest.
            if !unsafe { gost_mac_key(pass, passlen, salt, iter, &mut key[..], md) } {
                raise(PKCS12_R_KEY_GEN_ERROR, F);
                break 'err false;
            }
        } else {
            let mut hmac_md = md.cast_mut();
            let mut fetched = false;
            if pbmac1_kdf_nid != NID_undef {
                let mut name = [0 as c_char; 128];
                // SAFETY: any NID.
                let o = unsafe { OBJ_nid2obj(pbmac1_kdf_nid) };
                // SAFETY: room for the name; the object.
                if unsafe { OBJ_obj2txt(name.as_mut_ptr(), 128, o, 0) } < 0 {
                    break 'err false;
                }
                // SAFETY: the name.
                hmac_md = unsafe { EVP_MD_fetch(ptr::null_mut(), name.as_ptr(), ptr::null()) };
                if hmac_md.is_null() {
                    break 'err false;
                }
                fetched = true;
            }
            let res = match keygen {
                KeyGen::Pbkdf2 => {
                    // SAFETY: the password; the salt; room for the key; the PRF's digest.
                    (unsafe {
                        PKCS5_PBKDF2_HMAC(
                            pass,
                            passlen,
                            salt.as_ptr(),
                            saltlen,
                            iter,
                            hmac_md,
                            keylen,
                            key.as_mut_ptr(),
                        )
                    }) == 1
                }
                KeyGen::Default => {
                    // Passwords are UTF-8.
                    // SAFETY: as above; the safe's context.
                    (unsafe {
                        super::PKCS12_key_gen_utf8_ex(
                            pass,
                            passlen,
                            salt.as_ptr().cast_mut(),
                            saltlen,
                            PKCS12_MAC_ID as c_int,
                            iter,
                            keylen,
                            key.as_mut_ptr(),
                            md,
                            a.ctx.libctx,
                            a.ctx.propq,
                        )
                    }) != 0
                }
            };
            if fetched {
                // SAFETY: the digest fetched here.
                unsafe { EVP_MD_free(hmac_md) };
            }
            if !res {
                raise(PKCS12_R_KEY_GEN_ERROR, F);
                break 'err false;
            }
        }
        // SAFETY: no preconditions.
        hmac = unsafe { HMAC_CTX_new() };
        // SAFETY: the safe's data.
        let content = unsafe { super::asn::octets(data) };
        !hmac.is_null()
            // SAFETY: a live context; the key; the digest.
            && unsafe { HMAC_Init_ex(hmac, key.as_ptr().cast(), keylen, md, ptr::null_mut()) } != 0
            // SAFETY: as above; the data.
            && unsafe { HMAC_Update(hmac, content.as_ptr(), content.len()) } != 0
            // SAFETY: as above; room for the MAC.
            && unsafe { HMAC_Final(hmac, mac.as_mut_ptr(), maclen) } != 0
    };
    // SAFETY: the context made here, or NULL.
    unsafe { HMAC_CTX_free(hmac) };
    // SAFETY: the digest fetched here, or NULL.
    unsafe { EVP_MD_free(md_fetch) };
    ok
}

ffi_export! {
    /// The MAC of the PFX's data with the password into `mac` (of `*maclen` octets): 1, or 0.
    ///
    /// # Safety
    /// `p12` is a live PFX with a MAC; `pass` holds `passlen` octets (a C string if -1); `mac`
    /// has room for `EVP_MAX_MD_SIZE` octets; `maclen` room for the length.
    pub unsafe extern "C" fn PKCS12_gen_mac(p12: *mut PKCS12, pass: *const c_char, passlen: c_int, mac: *mut c_uchar, maclen: *mut c_uint) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        if mac.is_null() || maclen.is_null() || mac_of(p12).is_none() {
            return 0;
        }
        let mut out = [0u8; EVP_MAX_MD_SIZE as usize];
        let mut n: c_uint = 0;
        // SAFETY: the caller's guarantee.
        if !unsafe { gen_mac(p12, pass, passlen, &mut out, &mut n, NID_undef, NID_undef, KeyGen::Default) } {
            return 0;
        }
        let len = usize::try_from(n).unwrap_or(0).min(out.len());
        // SAFETY: the caller's room for the MAC.
        unsafe { ptr::copy_nonoverlapping(out.as_ptr(), mac, len) };
        // SAFETY: the caller's room.
        unsafe { *maclen = n };
        1
    }
}

ffi_export! {
    /// Whether the PFX's MAC is the password's (HMAC or PBMAC1): 1, or 0.
    ///
    /// # Safety
    /// `p12` is a live PFX; `pass` holds `passlen` octets (a C string if -1).
    pub unsafe extern "C" fn PKCS12_verify_mac(p12: *mut PKCS12, pass: *const c_char, passlen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        const F: &str = "PKCS12_verify_mac";
        let Some(m) = mac_of(p12) else {
            raise(PKCS12_R_MAC_ABSENT, F);
            return 0;
        };
        let macalg = mac_alg(m);
        let mut mac = [0u8; EVP_MAX_MD_SIZE as usize];
        let mut maclen: c_uint = 0;
        // SAFETY: the MAC's object.
        let md_nid = if unsafe { OBJ_obj2nid(alg_obj(macalg)) } == NID_pbmac1 {
            // SAFETY: no preconditions.
            let it = unsafe { PBMAC1PARAM_it() };
            // SAFETY: the MAC's algorithm, live with it.
            let parameter = unsafe { (*macalg).parameter };
            // SAFETY: its parameter, NULL or live.
            let param = unsafe { ASN1_TYPE_unpack_sequence(it, parameter) }.cast::<PBMAC1PARAM>();
            // SAFETY: the parameters, or NULL.
            let Some(p) = (unsafe { param.as_ref() }) else {
                raise(ERR_R_UNSUPPORTED, F);
                return 0;
            };
            // SAFETY: its MAC scheme's object.
            let n = hmac2md(unsafe { OBJ_obj2nid(alg_obj(p.messageAuthScheme)) });
            // SAFETY: the parameters decoded here.
            unsafe { PBMAC1PARAM_free(param) };
            n
        } else {
            NID_undef
        };
        // SAFETY: the caller's guarantee.
        if !unsafe { gen_mac(p12, pass, passlen, &mut mac, &mut maclen, md_nid, NID_undef, KeyGen::Default) } {
            raise(PKCS12_R_MAC_GENERATION_ERROR, F);
            return 0;
        }
        let mut macoct: *const ASN1_OCTET_STRING = ptr::null();
        // SAFETY: its DigestInfo; room for the digest.
        unsafe { X509_SIG_get0(m.dinfo, ptr::null_mut(), &mut macoct) };
        // SAFETY: the digest, made with it.
        let want = unsafe { super::asn::octets(macoct) };
        let got = mac.get(..usize::try_from(maclen).unwrap_or(0)).unwrap_or(&[]);
        c_int::from(got.len() == want.len() && bool::from(crate::dit::with(|| got.ct_eq(want))))
    }
}

/// `pkcs12_setup_mac`: a new MAC (algorithm `nid`) with the salt (random when NULL; 8 octets
/// for 0) and iteration count (absent for 1). 1, or 0 (`PKCS12_ERROR`).
///
/// # Safety
/// `p12` is a live PFX; `salt` NULL or `saltlen` octets.
unsafe fn setup_mac(
    p12: *mut PKCS12,
    iter: c_int,
    salt: *const c_uchar,
    saltlen: c_int,
    nid: c_int,
) -> c_int {
    const F: &str = "pkcs12_setup_mac";
    // SAFETY: the caller's guarantee.
    let Some(p) = (unsafe { pfx_of(p12) }) else {
        return PKCS12_ERROR;
    };
    // SAFETY: its MAC, or NULL.
    unsafe { PKCS12_MAC_DATA_free(p.mac.cast()) };
    // SAFETY: no preconditions.
    p.mac = unsafe { PKCS12_MAC_DATA_new() }.cast();
    // SAFETY: the new MAC, or NULL.
    let Some(m) = (unsafe { p.mac.as_mut() }) else {
        return PKCS12_ERROR;
    };
    if iter > 1 {
        // SAFETY: no preconditions.
        m.iter = unsafe { ASN1_INTEGER_new() };
        // SAFETY: the new INTEGER.
        if m.iter.is_null() || unsafe { ASN1_INTEGER_set(m.iter, iter.into()) } == 0 {
            raise(ERR_R_ASN1_LIB, F);
            return 0;
        }
    }
    let saltlen = match saltlen {
        0 => PKCS12_SALT_LEN as c_int,
        n if n < 0 => return 0,
        n => n,
    };
    let Ok(n) = usize::try_from(saltlen) else {
        return 0;
    };
    let buf = mem::alloc(n).cast::<u8>();
    if buf.is_null() {
        return 0;
    }
    // SAFETY: the MAC's salt, made with it.
    let s = unsafe { &mut *m.salt };
    s.data = buf;
    s.length = saltlen;
    if salt.is_null() {
        // SAFETY: the safe's context, or NULL.
        let libctx = unsafe { p.authsafes.as_ref() }.map_or(ptr::null_mut(), |a| a.ctx.libctx);
        // SAFETY: room for the salt.
        if unsafe { RAND_bytes_ex(libctx, buf, n, 0) } <= 0 {
            return 0;
        }
    } else {
        // SAFETY: the caller's salt; room for it.
        unsafe { ptr::copy_nonoverlapping(salt, buf, n) };
    }
    let mut macalg: *mut X509_ALGOR = ptr::null_mut();
    // SAFETY: its DigestInfo; room for the algorithm.
    unsafe { X509_SIG_getm(m.dinfo, &mut macalg, ptr::null_mut()) };
    // SAFETY: any NID.
    let obj = unsafe { OBJ_nid2obj(nid) };
    // SAFETY: the algorithm; a static object.
    if unsafe { X509_ALGOR_set0(macalg, obj, V_ASN1_NULL, ptr::null_mut()) } == 0 {
        raise(ERR_R_ASN1_LIB, F);
        return 0;
    }
    1
}

ffi_export! {
    /// Sets up a MAC with the digest, salt, and iteration count, but no value: 1, or 0.
    ///
    /// # Safety
    /// `p12` is a live PFX; `salt` NULL or `saltlen` octets; `md_type` live.
    pub unsafe extern "C" fn PKCS12_setup_mac(p12: *mut PKCS12, iter: c_int, salt: *mut c_uchar, saltlen: c_int, md_type: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's digest.
        let nid = unsafe { EVP_MD_get_type(md_type) };
        // SAFETY: the caller's guarantee.
        unsafe { setup_mac(p12, iter, salt, saltlen, nid) }
    }
}

/// The MAC's value set to `mac`.
fn set_mac_value(p12: *mut PKCS12, mac: &[u8]) -> bool {
    let Some(m) = mac_of(p12) else { return false };
    let mut macoct: *mut ASN1_OCTET_STRING = ptr::null_mut();
    // SAFETY: its DigestInfo; room for the digest.
    unsafe { X509_SIG_getm(m.dinfo, ptr::null_mut(), &mut macoct) };
    let Ok(n) = c_int::try_from(mac.len()) else {
        return false;
    };
    // SAFETY: the digest; the MAC.
    (unsafe { ASN1_OCTET_STRING_set(macoct, mac.as_ptr(), n) }) != 0
}

ffi_export! {
    /// Sets the PFX's MAC: HMAC with the digest (SHA-256 if NULL) and a key from the password
    /// (as UTF-8). 1, or 0.
    ///
    /// # Safety
    /// `p12` is a live PFX; `pass` holds `passlen` octets (a C string if -1); `salt` NULL or
    /// `saltlen` octets; `md_type` NULL or live.
    pub unsafe extern "C" fn PKCS12_set_mac(p12: *mut PKCS12, pass: *const c_char, passlen: c_int, salt: *mut c_uchar, saltlen: c_int, iter: c_int, md_type: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        const F: &str = "PKCS12_set_mac";
        // Only its NID is used, so no fetch is needed.
        // SAFETY: no preconditions.
        let md_type = if md_type.is_null() { unsafe { EVP_sha256() } } else { md_type };
        let iter = if iter == 0 { PKCS12_DEFAULT_ITER as c_int } else { iter };
        // SAFETY: the caller's guarantee.
        if unsafe { PKCS12_setup_mac(p12, iter, salt, saltlen, md_type) } == PKCS12_ERROR {
            raise(PKCS12_R_MAC_SETUP_ERROR, F);
            return 0;
        }
        let mut mac = [0u8; EVP_MAX_MD_SIZE as usize];
        let mut maclen: c_uint = 0;
        // SAFETY: as above.
        if !unsafe { gen_mac(p12, pass, passlen, &mut mac, &mut maclen, NID_undef, NID_undef, KeyGen::Default) } {
            raise(PKCS12_R_MAC_GENERATION_ERROR, F);
            return 0;
        }
        if !set_mac_value(p12, mac.get(..usize::try_from(maclen).unwrap_or(0)).unwrap_or(&[])) {
            raise(PKCS12_R_MAC_STRING_SET_ERROR, F);
            return 0;
        }
        1
    }
}

ffi_export! {
    /// Sets the PFX's MAC to PBMAC1: HMAC with the digest (SHA-256 if NULL), its key by
    /// PBKDF2 with the PRF `prf_md_name` (the digest's if NULL). 1, or 0.
    ///
    /// # Safety
    /// `p12` is a live PFX; `pass` holds `passlen` octets (a C string if -1); `salt` NULL or
    /// `saltlen` octets; `md_type` NULL or live; `prf_md_name` NULL or a C string.
    pub unsafe extern "C" fn PKCS12_set_pbmac1_pbkdf2(p12: *mut PKCS12, pass: *const c_char, passlen: c_int, salt: *mut c_uchar, saltlen: c_int, iter: c_int, md_type: *const EVP_MD, prf_md_name: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        const F: &str = "PKCS12_set_pbmac1_pbkdf2";
        // SAFETY: no preconditions.
        let md_type = if md_type.is_null() { unsafe { EVP_sha256() } } else { md_type };
        // SAFETY: a live digest.
        let md_nid = unsafe { EVP_MD_get_type(md_type) };
        let prf_md_nid = if prf_md_name.is_null() {
            md_nid
        } else {
            // SAFETY: the caller's C string.
            unsafe { OBJ_txt2nid(prf_md_name) }
        };
        let iter = if iter == 0 { PKCS12_DEFAULT_ITER as c_int } else { iter };
        // SAFETY: a live digest.
        let keylen = unsafe { EVP_MD_get_size(md_type) };
        let prf_nid = md2hmac(prf_md_nid);
        let hmac_nid = md2hmac(md_nid);
        let mut known_salt: Option<Vec<u8>> = None;
        let mut param: *mut PBMAC1PARAM = ptr::null_mut();
        let mut hmac_alg: *mut X509_ALGOR = ptr::null_mut();
        let mut alg: *mut X509_ALGOR = ptr::null_mut();
        let ok = 'err: {
            if prf_nid == NID_undef || hmac_nid == NID_undef {
                raise(PKCS12_R_UNKNOWN_DIGEST_ALGORITHM, F);
                break 'err false;
            }
            let salt = if salt.is_null() {
                // OpenSSL can't allocate no octets.
                let Some(n) = usize::try_from(saltlen).ok().filter(|&n| n > 0) else { break 'err false };
                let mut s = vec![0u8; n];
                // SAFETY: room for the salt.
                if unsafe { RAND_bytes_ex(ptr::null_mut(), s.as_mut_ptr(), n, 0) } <= 0 {
                    raise(ERR_R_RAND_LIB, F);
                    break 'err false;
                }
                known_salt.insert(s).as_mut_ptr()
            } else {
                salt
            };
            // SAFETY: no preconditions.
            param = unsafe { PBMAC1PARAM_new() };
            // SAFETY: as above.
            hmac_alg = unsafe { X509_ALGOR_new() };
            // SAFETY: the salt, of `saltlen` octets.
            alg = unsafe { PKCS5_pbkdf2_set(iter, salt, saltlen, prf_nid, keylen) };
            if param.is_null() || hmac_alg.is_null() || alg.is_null() {
                break 'err false;
            }
            // SAFETY: the caller's PFX; the salt.
            if unsafe { setup_mac(p12, iter, salt, saltlen, NID_pbmac1) } == PKCS12_ERROR {
                raise(PKCS12_R_MAC_SETUP_ERROR, F);
                break 'err false;
            }
            // SAFETY: any NID.
            let obj = unsafe { OBJ_nid2obj(hmac_nid) };
            // SAFETY: the new AlgorithmIdentifier; a static object.
            if unsafe { X509_ALGOR_set0(hmac_alg, obj, V_ASN1_NULL, ptr::null_mut()) } == 0 {
                raise(PKCS12_R_MAC_SETUP_ERROR, F);
                break 'err false;
            }
            // SAFETY: the new parameters.
            let p = unsafe { &mut *param };
            // SAFETY: their empty AlgorithmIdentifiers, replaced.
            unsafe { X509_ALGOR_free(p.keyDerivationFunc) };
            // SAFETY: as above.
            unsafe { X509_ALGOR_free(p.messageAuthScheme) };
            p.keyDerivationFunc = alg;
            p.messageAuthScheme = hmac_alg;
            alg = ptr::null_mut();
            hmac_alg = ptr::null_mut();
            let Some(m) = mac_of(p12) else { break 'err false };
            let mut macalg: *mut X509_ALGOR = ptr::null_mut();
            // SAFETY: its DigestInfo; room for the algorithm.
            unsafe { X509_SIG_getm(m.dinfo, &mut macalg, ptr::null_mut()) };
            // SAFETY: no preconditions.
            let it = unsafe { PBMAC1PARAM_it() };
            // SAFETY: the MAC's algorithm, live with it.
            let slot = unsafe { &raw mut (*macalg).parameter };
            // SAFETY: the parameters; the algorithm's parameter slot.
            if unsafe { ASN1_TYPE_pack_sequence(it, param.cast(), slot) }.is_null() {
                break 'err false;
            }
            let mut mac = [0u8; EVP_MAX_MD_SIZE as usize];
            let mut maclen: c_uint = 0;
            // Passwords are UTF-8.
            // SAFETY: the caller's guarantee.
            if !unsafe { gen_mac(p12, pass, passlen, &mut mac, &mut maclen, md_nid, prf_md_nid, KeyGen::Pbkdf2) } {
                raise(PKCS12_R_MAC_GENERATION_ERROR, F);
                break 'err false;
            }
            if !set_mac_value(p12, mac.get(..usize::try_from(maclen).unwrap_or(0)).unwrap_or(&[])) {
                raise(PKCS12_R_MAC_STRING_SET_ERROR, F);
                break 'err false;
            }
            true
        };
        // SAFETY: made here, or NULL.
        unsafe { X509_ALGOR_free(alg) };
        // SAFETY: as above.
        unsafe { X509_ALGOR_free(hmac_alg) };
        // SAFETY: as above.
        unsafe { PBMAC1PARAM_free(param) };
        c_int::from(ok)
    }
}
