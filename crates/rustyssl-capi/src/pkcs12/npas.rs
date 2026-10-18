//! Changing a PFX's password (`p12_npas.c`): each encrypted content and shrouded key
//! decrypted with the old one and encrypted again with the new, as before, and the MAC made
//! again. On failure the PFX is as it was.

use core::ffi::{c_char, c_int, c_uint};
use core::ptr;

use rustyssl_abi::{
    ASN1_OCTET_STRING, ERR_LIB_PKCS12, EVP_CIPHER, EVP_MAX_MD_SIZE, NID_hmacWithSHA1, NID_pbes2,
    NID_pkcs7_data, NID_pkcs7_encrypted, NID_pkcs8ShroudedKeyBag, NID_undef, OSSL_LIB_CTX,
    PBE2PARAM, PBEPARAM, PBKDF2PARAM, PKCS7, PKCS12, PKCS12_R_INVALID_NULL_PKCS12_POINTER,
    PKCS12_R_MAC_VERIFY_FAILURE, PKCS12_R_PARSE_ERROR, V_ASN1_OCTET_STRING, V_ASN1_SEQUENCE,
    X509_ALGOR, stack_st_PKCS12_SAFEBAG,
};

use super::add::{
    PKCS12_pack_authsafes, PKCS12_pack_p7data, PKCS12_pack_p7encdata_ex, PKCS12_unpack_authsafes,
    PKCS12_unpack_p7data, PKCS12_unpack_p7encdata, p7_free,
};
use super::asn::{PKCS12_SAFEBAG_free, bag_of, pfx_of};
use super::bags::PKCS12_SAFEBAG_get_nid;
use super::mutl::{PKCS12_gen_mac, PKCS12_verify_mac};
use crate::asn1::integer::ASN1_INTEGER_get;
use crate::asn1::string::{ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set};
use crate::asn1::tpl::util::{ASN1_TYPE_unpack_sequence, ASN1_item_unpack};
use crate::err;
use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free};
use crate::ffi::ffi_export;
use crate::objects::{OBJ_nid2sn, OBJ_obj2nid};
use crate::pkcs8_crypt::{PKCS8_decrypt_ex, PKCS8_encrypt_ex};
use crate::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value,
};
use crate::x509::algor::X509_ALGOR_get0;
use crate::x509::p8::PKCS8_PRIV_KEY_INFO_free;
use crate::x509::pbe::{
    PBE2PARAM_free, PBE2PARAM_it, PBEPARAM_free, PBEPARAM_it, PBKDF2PARAM_free, PBKDF2PARAM_it,
};
use crate::x509::sig::{X509_SIG_free, X509_SIG_get0, X509_SIG_getm};

fn raise(reason: c_int, f: &str) {
    err::raise(ERR_LIB_PKCS12, reason, f);
}

/// `PKCS12_SAFEBAG_free` as a stack's free function.
unsafe extern "C" fn bag_free(p: *mut core::ffi::c_void) {
    // SAFETY: an element of a list of safe bags.
    unsafe { PKCS12_SAFEBAG_free(p.cast()) };
}

/// The PBE's parameters, as `alg_get` finds them: (the PBE's NID, or PBES2's PRF; iterations;
/// salt length; PBES2's cipher, or `NID_undef`).
#[derive(Clone, Copy, Default)]
struct Pbe {
    nid: c_int,
    iter: c_int,
    saltlen: c_int,
    cipherid: c_int,
}

/// `alg_get`: a PBE AlgorithmIdentifier's parameters, or `None`.
///
/// # Safety
/// `alg` is a live AlgorithmIdentifier.
unsafe fn alg_get(alg: *const X509_ALGOR) -> Option<Pbe> {
    let mut aoid = ptr::null();
    let mut ptype: c_int = 0;
    let mut pval: *const core::ffi::c_void = ptr::null();
    // SAFETY: room for each; the caller's AlgorithmIdentifier.
    unsafe { X509_ALGOR_get0(&mut aoid, &mut ptype, &mut pval, alg) };
    // SAFETY: its object.
    if unsafe { OBJ_obj2nid(aoid) } == NID_pbes2 {
        if ptype != V_ASN1_SEQUENCE {
            return None;
        }
        // SAFETY: no preconditions.
        let it = unsafe { PBE2PARAM_it() };
        // SAFETY: the SEQUENCE's string.
        let pbe2 = unsafe { ASN1_item_unpack(pval.cast(), it) }.cast::<PBE2PARAM>();
        let mut kdf: *mut PBKDF2PARAM = ptr::null_mut();
        let out = 'done: {
            // SAFETY: the parameters, or NULL.
            let Some(p) = (unsafe { pbe2.as_ref() }) else {
                break 'done None;
            };
            let (mut kptype, mut kpval) = (0, ptr::null());
            // SAFETY: its KDF.
            unsafe { X509_ALGOR_get0(ptr::null_mut(), &mut kptype, &mut kpval, p.keyfunc) };
            let mut eoid = ptr::null();
            // SAFETY: its cipher.
            unsafe { X509_ALGOR_get0(&mut eoid, ptr::null_mut(), ptr::null_mut(), p.encryption) };
            // SAFETY: the cipher's object.
            let encnid = unsafe { OBJ_obj2nid(eoid) };
            if kptype == V_ASN1_SEQUENCE {
                // SAFETY: no preconditions.
                let kit = unsafe { PBKDF2PARAM_it() };
                // SAFETY: the SEQUENCE's string.
                kdf = unsafe { ASN1_item_unpack(kpval.cast(), kit) }.cast();
            }
            // SAFETY: the KDF's parameters, or NULL.
            let Some(k) = (unsafe { kdf.as_ref() }) else {
                break 'done None;
            };
            // Only the OCTET STRING salt.
            // SAFETY: its salt, made with it.
            let salt = unsafe { &*k.salt };
            if salt.type_ != V_ASN1_OCTET_STRING {
                break 'done None;
            }
            let prfnid = if k.prf.is_null() {
                NID_hmacWithSHA1
            } else {
                let mut o = ptr::null();
                // SAFETY: its PRF.
                unsafe { X509_ALGOR_get0(&mut o, ptr::null_mut(), ptr::null_mut(), k.prf) };
                // SAFETY: the PRF's object.
                unsafe { OBJ_obj2nid(o) }
            };
            // SAFETY: the salt's OCTET STRING.
            let os = unsafe { salt.value.octet_string };
            // SAFETY: NULL or live with the parameters.
            let saltlen = unsafe { os.as_ref() }.map_or(0, |s| s.length);
            // SAFETY: its iteration count.
            let iter = c_int::try_from(unsafe { ASN1_INTEGER_get(k.iter) }).unwrap_or(-1);
            Some(Pbe {
                nid: prfnid,
                iter,
                saltlen,
                cipherid: encnid,
            })
        };
        // SAFETY: decoded here, or NULL.
        unsafe { PBKDF2PARAM_free(kdf) };
        // SAFETY: as above.
        unsafe { PBE2PARAM_free(pbe2) };
        return out;
    }
    // SAFETY: no preconditions.
    let it = unsafe { PBEPARAM_it() };
    // SAFETY: the caller's AlgorithmIdentifier.
    let a = unsafe { &*alg };
    let (aobj, parameter) = (a.algorithm, a.parameter);
    // SAFETY: its parameter, NULL or live.
    let pbe = unsafe { ASN1_TYPE_unpack_sequence(it, parameter) }.cast::<PBEPARAM>();
    // SAFETY: the parameters, or NULL.
    let out = unsafe { pbe.as_ref() }.map(|p| Pbe {
        // SAFETY: the algorithm's object.
        nid: unsafe { OBJ_obj2nid(aobj) },
        // SAFETY: its iteration count.
        iter: c_int::try_from(unsafe { ASN1_INTEGER_get(p.iter) }).unwrap_or(-1),
        // SAFETY: its salt, made with it.
        saltlen: unsafe { p.salt.as_ref() }.map_or(0, |s| s.length),
        cipherid: NID_undef,
    });
    // SAFETY: decoded here, or NULL.
    unsafe { PBEPARAM_free(pbe) };
    out
}

/// `newpass_bag`: a shrouded key's encryption again with the new password, as before.
///
/// # Safety
/// `bag` is a live bag; the passwords C strings or NULL.
unsafe fn newpass_bag(
    bag: *mut rustyssl_abi::PKCS12_SAFEBAG,
    oldpass: *const c_char,
    newpass: *const c_char,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> bool {
    // SAFETY: the caller's guarantee.
    if unsafe { PKCS12_SAFEBAG_get_nid(bag) } != NID_pkcs8ShroudedKeyBag {
        return true;
    }
    // SAFETY: as above.
    let Some(b) = (unsafe { bag_of(bag) }) else {
        return false;
    };
    // SAFETY: the shrouded key; the old password.
    let p8 = unsafe { PKCS8_decrypt_ex(b.value.cast(), oldpass, -1, libctx, propq) };
    if p8.is_null() {
        return false;
    }
    let mut shalg: *const X509_ALGOR = ptr::null();
    // SAFETY: the shrouded key; room for its algorithm.
    unsafe { X509_SIG_get0(b.value.cast(), &mut shalg, ptr::null_mut()) };
    // SAFETY: its algorithm.
    let Some(pbe) = (unsafe { alg_get(shalg) }) else {
        // SAFETY: the key decrypted here.
        unsafe { PKCS8_PRIV_KEY_INFO_free(p8) };
        return false;
    };
    let mut cipher: *mut EVP_CIPHER = ptr::null_mut();
    if pbe.cipherid != NID_undef {
        // SAFETY: any NID.
        let sn = unsafe { OBJ_nid2sn(pbe.cipherid) };
        // SAFETY: the name; the context and properties.
        cipher = unsafe { EVP_CIPHER_fetch(libctx, sn, propq) };
        if cipher.is_null() {
            // SAFETY: as above.
            unsafe { PKCS8_PRIV_KEY_INFO_free(p8) };
            return false;
        }
    }
    // SAFETY: the key; the cipher, or NULL; the new password.
    let p8new = unsafe {
        PKCS8_encrypt_ex(
            pbe.nid,
            cipher,
            newpass,
            -1,
            ptr::null_mut(),
            pbe.saltlen,
            pbe.iter,
            p8,
            libctx,
            propq,
        )
    };
    // SAFETY: as above.
    unsafe { PKCS8_PRIV_KEY_INFO_free(p8) };
    // SAFETY: the cipher fetched here, or NULL.
    unsafe { EVP_CIPHER_free(cipher) };
    if p8new.is_null() {
        return false;
    }
    // SAFETY: the bag's old shrouded key.
    unsafe { X509_SIG_free(b.value.cast()) };
    b.value = p8new.cast();
    true
}

/// `newpass_p12`: every content's bags with the new password, packed as before, and the MAC.
///
/// # Safety
/// `p12` is a live PFX; the passwords C strings or NULL.
unsafe fn newpass_p12(p12: *mut PKCS12, oldpass: *const c_char, newpass: *const c_char) -> bool {
    // SAFETY: the caller's guarantee.
    let asafes = unsafe { PKCS12_unpack_authsafes(p12) };
    let mut newsafes = ptr::null_mut();
    let mut bags: *mut stack_st_PKCS12_SAFEBAG = ptr::null_mut();
    let mut old_data: *mut ASN1_OCTET_STRING = ptr::null_mut();
    let mut pbe = Pbe::default();
    // SAFETY: the PFX's authenticated safe, made with it.
    let Some(a) = (unsafe { pfx_of(p12) }).and_then(|p| unsafe { p.authsafes.as_mut() }) else {
        return false;
    };
    let ok = 'err: {
        if asafes.is_null() {
            break 'err false;
        }
        // SAFETY: no preconditions.
        newsafes = unsafe { OPENSSL_sk_new_null() };
        if newsafes.is_null() {
            break 'err false;
        }
        // SAFETY: the contents.
        for i in 0..unsafe { OPENSSL_sk_num(asafes.cast()) } {
            // SAFETY: an index within them.
            let p7 = unsafe { OPENSSL_sk_value(asafes.cast(), i) }.cast::<PKCS7>();
            // SAFETY: a content, decoded.
            let p = unsafe { &*p7 };
            // SAFETY: its type.
            let bagnid = unsafe { OBJ_obj2nid(p.type_) };
            if bagnid == NID_pkcs7_data {
                // SAFETY: the content.
                bags = unsafe { PKCS12_unpack_p7data(p7) };
            } else if bagnid == NID_pkcs7_encrypted {
                // SAFETY: as above; the old password.
                bags = unsafe { PKCS12_unpack_p7encdata(p7, oldpass, -1) };
                // SAFETY: the content of its type.
                let enc = unsafe { p.d.encrypted };
                // SAFETY: NULL or live; its encrypted content.
                let alg = unsafe { enc.as_ref() }
                    .and_then(|e| unsafe { e.enc_data.as_ref() })
                    .map(|e| e.algorithm);
                // SAFETY: the content's algorithm.
                match alg.and_then(|alg| unsafe { alg_get(alg) }) {
                    Some(found) => pbe = found,
                    None => break 'err false,
                }
            } else {
                continue;
            }
            if bags.is_null() {
                break 'err false;
            }
            // SAFETY: the bags.
            for j in 0..unsafe { OPENSSL_sk_num(bags.cast()) } {
                // SAFETY: an index within them.
                let bag = unsafe { OPENSSL_sk_value(bags.cast(), j) }.cast();
                // SAFETY: a bag; the passwords; the content's context.
                if !unsafe { newpass_bag(bag, oldpass, newpass, p.ctx.libctx, p.ctx.propq) } {
                    break 'err false;
                }
            }
            // Pack the bags in the same form with the new password.
            let p7new = if bagnid == NID_pkcs7_data {
                // SAFETY: the bags.
                unsafe { PKCS12_pack_p7data(bags) }
            } else {
                // SAFETY: as above; the new password; the content's context.
                unsafe {
                    PKCS12_pack_p7encdata_ex(
                        pbe.nid,
                        newpass,
                        -1,
                        ptr::null_mut(),
                        pbe.saltlen,
                        pbe.iter,
                        bags,
                        p.ctx.libctx,
                        p.ctx.propq,
                    )
                }
            };
            // SAFETY: the new contents; the new content.
            if p7new.is_null() || unsafe { OPENSSL_sk_push(newsafes, p7new.cast()) } == 0 {
                // SAFETY: the content made here, or NULL.
                unsafe { crate::pkcs7::PKCS7_free(p7new) };
                break 'err false;
            }
            // SAFETY: the bags, packed.
            unsafe { OPENSSL_sk_pop_free(bags.cast(), Some(bag_free)) };
            bags = ptr::null_mut();
        }
        // Repack the safe, keeping the old one in case of failure.
        // SAFETY: the safe's data.
        old_data = unsafe { a.d.data };
        // SAFETY: no preconditions.
        a.d.data = unsafe { ASN1_OCTET_STRING_new() };
        // SAFETY: the content of its type.
        if unsafe { a.d.data }.is_null() {
            break 'err false;
        }
        // SAFETY: the PFX; the new contents.
        if unsafe { PKCS12_pack_authsafes(p12, newsafes.cast()) } == 0 {
            break 'err false;
        }
        // SAFETY: the PFX's MAC, NULL or live.
        if let Some(m) = (unsafe { pfx_of(p12) }).and_then(|p| unsafe { p.mac.as_ref() }) {
            let mut mac = [0u8; EVP_MAX_MD_SIZE as usize];
            let mut maclen: c_uint = 0;
            // SAFETY: the PFX; the new password; room for the MAC.
            if unsafe { PKCS12_gen_mac(p12, newpass, -1, mac.as_mut_ptr(), &mut maclen) } == 0 {
                break 'err false;
            }
            let mut macoct: *mut ASN1_OCTET_STRING = ptr::null_mut();
            // SAFETY: its DigestInfo; room for the digest.
            unsafe { X509_SIG_getm(m.dinfo, ptr::null_mut(), &mut macoct) };
            let Ok(n) = c_int::try_from(maclen) else {
                break 'err false;
            };
            // SAFETY: the digest; the MAC.
            if unsafe { ASN1_OCTET_STRING_set(macoct, mac.as_ptr(), n) } == 0 {
                break 'err false;
            }
        }
        true
    };
    if ok {
        // SAFETY: the old data, replaced.
        unsafe { ASN1_OCTET_STRING_free(old_data) };
    } else if !old_data.is_null() {
        // SAFETY: the content of its type.
        let new_data = unsafe { a.d.data };
        // SAFETY: the new data, or NULL.
        unsafe { ASN1_OCTET_STRING_free(new_data) };
        a.d.data = old_data;
    }
    // SAFETY: made here, or NULL.
    unsafe { OPENSSL_sk_pop_free(bags.cast(), Some(bag_free)) };
    // SAFETY: as above.
    unsafe { OPENSSL_sk_pop_free(asafes.cast(), Some(p7_free)) };
    // SAFETY: as above.
    unsafe { OPENSSL_sk_pop_free(newsafes, Some(p7_free)) };
    ok
}

ffi_export! {
    /// Changes the PFX's password (checking its MAC with the old one): 1, or 0.
    ///
    /// # Safety
    /// `p12` is NULL or a live PFX; the passwords NULL or C strings.
    pub unsafe extern "C" fn PKCS12_newpass(p12: *mut PKCS12, oldpass: *const c_char, newpass: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        const F: &str = "PKCS12_newpass";
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { pfx_of(p12) }) else {
            raise(PKCS12_R_INVALID_NULL_PKCS12_POINTER, F);
            return 0;
        };
        // SAFETY: as above; the old password.
        if !p.mac.is_null() && unsafe { PKCS12_verify_mac(p12, oldpass, -1) } == 0 {
            raise(PKCS12_R_MAC_VERIFY_FAILURE, F);
            return 0;
        }
        // SAFETY: as above.
        if !unsafe { newpass_p12(p12, oldpass, newpass) } {
            raise(PKCS12_R_PARSE_ERROR, F);
            return 0;
        }
        1
    }
}
