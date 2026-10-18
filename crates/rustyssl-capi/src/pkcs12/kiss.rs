//! Reading a PFX (`p12_kiss.c`): `PKCS12_parse`, the key, its certificate, and the others.
//!
//! The bags' nesting is bounded by the ASN.1 decoder's depth limit.

use core::ffi::{c_char, c_int};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_EVP, ERR_LIB_PKCS12, ERR_R_CRYPTO_LIB, EVP_PKEY, EVP_R_UNSUPPORTED_ALGORITHM,
    NID_certBag, NID_friendlyName, NID_keyBag, NID_localKeyID, NID_pkcs7_data, NID_pkcs7_encrypted,
    NID_pkcs8ShroudedKeyBag, NID_safeContentsBag, NID_x509Certificate, OSSL_LIB_CTX, PKCS7, PKCS12,
    PKCS12_R_INVALID_NULL_PKCS12_POINTER, PKCS12_R_MAC_VERIFY_FAILURE, PKCS12_R_PARSE_ERROR,
    PKCS12_SAFEBAG, V_ASN1_BMPSTRING, V_ASN1_OCTET_STRING, X509, X509_ADD_FLAG_DEFAULT,
    stack_st_PKCS12_SAFEBAG, stack_st_X509,
};

use super::add::{PKCS12_unpack_authsafes, PKCS12_unpack_p7data, PKCS12_unpack_p7encdata, p7_free};
use super::asn::PKCS12_SAFEBAG_free;
use super::bags::{
    PKCS12_SAFEBAG_get_bag_nid, PKCS12_SAFEBAG_get_nid, PKCS12_SAFEBAG_get0_attr,
    PKCS12_SAFEBAG_get0_p8inf, PKCS12_SAFEBAG_get0_safes, PKCS12_SAFEBAG_get1_cert_ex,
};
use super::mutl::{PKCS12_mac_present, PKCS12_verify_mac};
use crate::asn1::text::ASN1_STRING_to_UTF8;
use crate::err::{self, ERR_peek_last_error, ERR_pop_to_mark, ERR_set_mark};
use crate::evp::pkey::EVP_PKEY_free;
use crate::evp::pkey::d2i::EVP_PKCS82PKEY_ex;
use crate::ffi::ffi_export;
use crate::mem;
use crate::objects::OBJ_obj2nid;
use crate::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    OPENSSL_sk_shift, OPENSSL_sk_value,
};
use crate::x509::cert::{OSSL_STACK_OF_X509_free, X509_check_private_key, X509_free};
use crate::x509::p8::PKCS8_PRIV_KEY_INFO_free;
use crate::x509::purpose::X509_add_cert;
use crate::x509::trust::{X509_alias_set1, X509_keyid_set1};

fn raise(reason: c_int, f: &str) {
    err::raise(ERR_LIB_PKCS12, reason, f);
}

/// `PKCS12_SAFEBAG_free` as a stack's free function.
unsafe extern "C" fn bag_free(p: *mut core::ffi::c_void) {
    // SAFETY: an element of a list of safe bags.
    unsafe { PKCS12_SAFEBAG_free(p.cast()) };
}

/// `parse_bag`: the key (if none yet) or a certificate (with its local key identifier and
/// friendly name) from the bag, or its nested bags'. `false` on failure.
///
/// # Safety
/// `bag` is a live bag; `pass` NULL or holding `passlen` octets (a C string if -1); `ocerts`
/// NULL or a live list.
unsafe fn parse_bag(
    bag: *mut PKCS12_SAFEBAG,
    pass: *const c_char,
    passlen: c_int,
    pkey: *mut *mut EVP_PKEY,
    ocerts: *mut stack_st_X509,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> bool {
    // SAFETY: the caller's bag.
    let fname = unsafe { PKCS12_SAFEBAG_get0_attr(bag, NID_friendlyName) };
    // SAFETY: the attribute's value, NULL or live with the bag.
    let fname = unsafe { fname.as_ref() };
    if fname.is_some_and(|a| a.type_ != V_ASN1_BMPSTRING) {
        return false;
    }
    // SAFETY: as above.
    let lkid = unsafe { PKCS12_SAFEBAG_get0_attr(bag, NID_localKeyID) };
    // SAFETY: as above.
    let lkid = unsafe { lkid.as_ref() };
    if lkid.is_some_and(|a| a.type_ != V_ASN1_OCTET_STRING) {
        return false;
    }
    // SAFETY: the caller's room for the key, or NULL.
    let want_key = unsafe { pkey.as_ref() }.is_some_and(|k| k.is_null());
    // SAFETY: as above.
    match unsafe { PKCS12_SAFEBAG_get_nid(bag) } {
        n if n == NID_keyBag => {
            if !want_key {
                return true;
            }
            // SAFETY: the caller's bag.
            let p8 = unsafe { PKCS12_SAFEBAG_get0_p8inf(bag) };
            // SAFETY: the bag's key; the context and properties.
            let k = unsafe { EVP_PKCS82PKEY_ex(p8, libctx, propq) };
            // SAFETY: the caller's room.
            unsafe { *pkey = k };
            !k.is_null()
        }
        n if n == NID_pkcs8ShroudedKeyBag => {
            if !want_key {
                return true;
            }
            // SAFETY: the bag; the password; the context and properties.
            let p8 =
                unsafe { super::add::PKCS12_decrypt_skey_ex(bag, pass, passlen, libctx, propq) };
            if p8.is_null() {
                return false;
            }
            // SAFETY: the decrypted key.
            let k = unsafe { EVP_PKCS82PKEY_ex(p8, libctx, propq) };
            // SAFETY: as above.
            unsafe { PKCS8_PRIV_KEY_INFO_free(p8) };
            // SAFETY: the caller's room.
            unsafe { *pkey = k };
            !k.is_null()
        }
        n if n == NID_certBag => {
            // SAFETY: the bag.
            if ocerts.is_null() || unsafe { PKCS12_SAFEBAG_get_bag_nid(bag) } != NID_x509Certificate
            {
                return true;
            }
            // SAFETY: as above; the context and properties.
            let x509 = unsafe { PKCS12_SAFEBAG_get1_cert_ex(bag, libctx, propq) };
            if x509.is_null() {
                return false;
            }
            if let Some(a) = lkid {
                // SAFETY: an OCTET STRING's value.
                let os = unsafe { a.value.octet_string };
                // SAFETY: the attribute's string, live with it.
                let s = unsafe { &*os };
                // SAFETY: the new certificate; the identifier's octets.
                if unsafe { X509_keyid_set1(x509, s.data, s.length) } == 0 {
                    // SAFETY: the certificate made here.
                    unsafe { X509_free(x509) };
                    return false;
                }
            }
            if let Some(a) = fname {
                let mut data: *mut u8 = ptr::null_mut();
                // SAFETY: a BMPString's value.
                let bmp = unsafe { a.value.bmpstring };
                // SAFETY: room for the text; the BMPString.
                let len = unsafe { ASN1_STRING_to_UTF8(&mut data, bmp) };
                if len >= 0 {
                    // SAFETY: the new certificate; the name's octets.
                    let r = unsafe { X509_alias_set1(x509, data, len) };
                    // SAFETY: the text made above.
                    unsafe { mem::release(data.cast()) };
                    if r == 0 {
                        // SAFETY: as above.
                        unsafe { X509_free(x509) };
                        return false;
                    }
                }
            }
            // SAFETY: the caller's list; the certificate, which it takes.
            if unsafe { OPENSSL_sk_push(ocerts.cast(), x509.cast()) } == 0 {
                // SAFETY: as above.
                unsafe { X509_free(x509) };
                return false;
            }
            true
        }
        n if n == NID_safeContentsBag => {
            // SAFETY: the bag's nested bags.
            let safes = unsafe { PKCS12_SAFEBAG_get0_safes(bag) };
            // SAFETY: as above.
            unsafe { parse_bags(safes, pass, passlen, pkey, ocerts, libctx, propq) }
        }
        _ => true,
    }
}

/// `parse_bags`.
///
/// # Safety
/// As for [`parse_bag`], with `bags` NULL or a live list.
unsafe fn parse_bags(
    bags: *const stack_st_PKCS12_SAFEBAG,
    pass: *const c_char,
    passlen: c_int,
    pkey: *mut *mut EVP_PKEY,
    ocerts: *mut stack_st_X509,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> bool {
    // SAFETY: the caller's list, or NULL.
    for i in 0..unsafe { OPENSSL_sk_num(bags.cast()) } {
        // SAFETY: an index within it.
        let bag = unsafe { OPENSSL_sk_value(bags.cast(), i) }.cast();
        // SAFETY: a bag of the list.
        if !unsafe { parse_bag(bag, pass, passlen, pkey, ocerts, libctx, propq) } {
            return false;
        }
    }
    true
}

/// `parse_pk12`: each Data and EncryptedData content's bags.
///
/// # Safety
/// `p12` is a live PFX; the others as for [`parse_bag`].
unsafe fn parse_pk12(
    p12: *mut PKCS12,
    pass: *const c_char,
    passlen: c_int,
    pkey: *mut *mut EVP_PKEY,
    ocerts: *mut stack_st_X509,
) -> bool {
    // SAFETY: the caller's guarantee.
    let asafes = unsafe { PKCS12_unpack_authsafes(p12) };
    if asafes.is_null() {
        return false;
    }
    let mut ok = true;
    // SAFETY: the contents.
    for i in 0..unsafe { OPENSSL_sk_num(asafes.cast()) } {
        // SAFETY: an index within them.
        let p7 = unsafe { OPENSSL_sk_value(asafes.cast(), i) }.cast::<PKCS7>();
        // SAFETY: a content, decoded.
        let p = unsafe { &*p7 };
        // SAFETY: its type.
        let bags = match unsafe { OBJ_obj2nid(p.type_) } {
            // SAFETY: the content.
            n if n == NID_pkcs7_data => unsafe { PKCS12_unpack_p7data(p7) },
            // SAFETY: as above; the password.
            n if n == NID_pkcs7_encrypted => unsafe { PKCS12_unpack_p7encdata(p7, pass, passlen) },
            _ => continue,
        };
        if bags.is_null() {
            ok = false;
            break;
        }
        // SAFETY: the bags; the content's context and properties.
        let parsed =
            unsafe { parse_bags(bags, pass, passlen, pkey, ocerts, p.ctx.libctx, p.ctx.propq) };
        // SAFETY: the bags unpacked here.
        unsafe { OPENSSL_sk_pop_free(bags.cast(), Some(bag_free)) };
        if !parsed {
            ok = false;
            break;
        }
    }
    // SAFETY: the contents unpacked here.
    unsafe { OPENSSL_sk_pop_free(asafes.cast(), Some(p7_free)) };
    ok
}

/// `ossl_x509_add_cert_new`: the certificate onto `*p_sk`, made if NULL.
///
/// # Safety
/// `p_sk` holds NULL or a live list; `cert` is live.
unsafe fn add_cert_new(p_sk: *mut *mut stack_st_X509, cert: *mut X509) -> bool {
    // SAFETY: the caller's guarantee.
    let slot = unsafe { &mut *p_sk };
    if slot.is_null() {
        // SAFETY: no preconditions.
        *slot = unsafe { OPENSSL_sk_new_null() }.cast();
        if slot.is_null() {
            err::raise(
                rustyssl_abi::ERR_LIB_X509,
                ERR_R_CRYPTO_LIB,
                "ossl_x509_add_cert_new",
            );
            return false;
        }
    }
    // SAFETY: the list; the certificate.
    unsafe { X509_add_cert(*slot, cert, X509_ADD_FLAG_DEFAULT) != 0 }
}

ffi_export! {
    /// Reads the PFX with the password (checking its MAC; NULL and "" tried for either): its
    /// key, the certificate matching the key, and the other certificates (added to `*ca`).
    /// 1, or 0.
    ///
    /// # Safety
    /// `p12` is NULL or a live PFX; `pass` NULL or a C string; the others NULL or room for a
    /// pointer (`*ca` NULL or a live list).
    pub unsafe extern "C" fn PKCS12_parse(p12: *mut PKCS12, pass: *const c_char, pkey: *mut *mut EVP_PKEY, cert: *mut *mut X509, ca: *mut *mut stack_st_X509) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        const F: &str = "PKCS12_parse";
        // SAFETY: the caller's room, or NULL.
        if let Some(p) = unsafe { pkey.as_mut() } {
            *p = ptr::null_mut();
        }
        // SAFETY: as above.
        if let Some(c) = unsafe { cert.as_mut() } {
            *c = ptr::null_mut();
        }
        if p12.is_null() {
            raise(PKCS12_R_INVALID_NULL_PKCS12_POINTER, F);
            return 0;
        }
        // SAFETY: the caller's string, or NULL.
        let empty = pass.is_null() || unsafe { *pass } == 0;
        let mut pass = pass;
        let mut ocerts: *mut stack_st_X509 = ptr::null_mut();
        let mut x: *mut X509 = ptr::null_mut();
        let ok = 'err: {
            // SAFETY: a live PFX.
            if unsafe { PKCS12_mac_present(p12) } != 0 {
                // With no or an empty password, try both: under PKCS#12 they differ.
                if empty {
                    // SAFETY: as above.
                    if unsafe { PKCS12_verify_mac(p12, ptr::null(), 0) } != 0 {
                        pass = ptr::null();
                    // SAFETY: as above.
                    } else if unsafe { PKCS12_verify_mac(p12, c"".as_ptr(), 0) } != 0 {
                        pass = c"".as_ptr();
                    } else {
                        raise(PKCS12_R_MAC_VERIFY_FAILURE, F);
                        break 'err false;
                    }
                // SAFETY: as above; the password.
                } else if unsafe { PKCS12_verify_mac(p12, pass, -1) } == 0 {
                    raise(PKCS12_R_MAC_VERIFY_FAILURE, F);
                    break 'err false;
                }
            } else if empty {
                pass = ptr::null();
            }
            // A list for the other certificates, if they're wanted.
            if !cert.is_null() || !ca.is_null() {
                // SAFETY: no preconditions.
                ocerts = unsafe { OPENSSL_sk_new_null() }.cast();
                if ocerts.is_null() {
                    raise(ERR_R_CRYPTO_LIB, F);
                    break 'err false;
                }
            }
            // SAFETY: as above; the caller's room.
            if !unsafe { parse_pk12(p12, pass, -1, pkey, ocerts) } {
                // SAFETY: no preconditions.
                let e = unsafe { ERR_peek_last_error() };
                if err::library_of(e) != ERR_LIB_EVP && err::reason_of(e) != EVP_R_UNSUPPORTED_ALGORITHM {
                    raise(PKCS12_R_PARSE_ERROR, F);
                }
                break 'err false;
            }
            // Split the certificates over `*cert` and `*ca` as asked.
            loop {
                // SAFETY: the list, or NULL.
                x = unsafe { OPENSSL_sk_shift(ocerts.cast()) }.cast();
                if x.is_null() {
                    break;
                }
                // SAFETY: the caller's room, or NULL.
                let key = unsafe { pkey.as_ref() }.map_or(ptr::null_mut(), |&k| k);
                // SAFETY: as above.
                if !key.is_null() && unsafe { cert.as_ref() }.is_some_and(|c| c.is_null()) {
                    // SAFETY: no preconditions.
                    unsafe { ERR_set_mark() };
                    // SAFETY: the certificate; the key.
                    let matched = unsafe { X509_check_private_key(x, key) } != 0;
                    // SAFETY: no preconditions.
                    unsafe { ERR_pop_to_mark() };
                    if matched {
                        // SAFETY: the caller's room.
                        unsafe { *cert = x };
                        continue;
                    }
                }
                if !ca.is_null() {
                    // SAFETY: the caller's list's slot; the certificate.
                    if !unsafe { add_cert_new(ca, x) } {
                        break 'err false;
                    }
                    continue;
                }
                // SAFETY: the certificate, unwanted.
                unsafe { X509_free(x) };
            }
            // SAFETY: the list, emptied.
            unsafe { OPENSSL_sk_free(ocerts.cast()) };
            ocerts = ptr::null_mut();
            true
        };
        if ok {
            return 1;
        }
        // SAFETY: the caller's room, or NULL.
        if let Some(p) = unsafe { pkey.as_mut() } {
            // SAFETY: the key made here, or NULL.
            unsafe { EVP_PKEY_free(*p) };
            *p = ptr::null_mut();
        }
        // SAFETY: as above.
        if let Some(c) = unsafe { cert.as_mut() } {
            // SAFETY: the certificate found here, or NULL.
            unsafe { X509_free(*c) };
            *c = ptr::null_mut();
        }
        // SAFETY: the certificate being placed, or NULL.
        unsafe { X509_free(x) };
        // SAFETY: the list made here, or NULL.
        unsafe { OSSL_STACK_OF_X509_free(ocerts) };
        0
    }
}
